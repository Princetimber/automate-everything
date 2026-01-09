$ErrorActionPreference = "Stop"
#Requires -Version 7.5
#Requires -RunAsAdministrator

#region logging setup
$Global:Logfile = "$env:TEMP\ADCS_CRL_AIA_Config_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
<#
.SYNOPSIS
Writes a message to the log file with timestamp and log level.
.DESCRIPTION
Supports multiple log levels: INFO, DEBUG, WARN, ERROR.
#>
  param (
    [Parameter(Mandatory)][string]$Message,
    [Parameter()][ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')][string]$Level = 'INFO'
  )
  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $entry = "[$timestamp] [$Level] $Message"
  Add-Content -Path $Global:LogFile -Value $entry
  if ($Level -eq 'ERROR') { Write-Error $Message }
  elseif ($Level -eq 'WARN') { Write-Warning $Message }
  elseif ($Level -eq 'DEBUG') { Write-Verbose $Message }
  else { Write-Host $Message }
}
#endregion

#region  Preflight Checks
function Invoke-PreflightChecks {
  Write-Host "Performing preflight checks..." -ForegroundColor Cyan
  Write-Log "Starting preflight checks..."
  # OS Check
  $os = Get-CimInstance Win32_OperatingSystem
  if ($os.Caption -notmatch "Windows Server 2022|Windows Server 2025") {
      Write-Log "Unsupported OS detected: $($os.Caption)" "ERROR"
      throw "Must be Windows Server 2022 or 2025."
  }

  # Domain Check
  $sys = Get-CimInstance Win32_ComputerSystem
  if ($sys.PartOfDomain) {
      Write-Log "Server is domain joined to $($sys.Domain). Must be standalone." "ERROR"
      throw "Server must NOT be domain joined."
  }
  # Admin Check
  $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Write-Log "Script not run as administrator." "ERROR"
      throw "Script must be run as administrator."
  }
}
#endregion

#region  Install ADCS Windows Feature if not present
function Install-ADCSFeature {
  param(
    [string]$Name = "ADCS-Cert-Authority"
  )
  Write-Log "Checking for ADCS feature..."
  $feature = Get-WindowsFeature -Name $Name
  if(-not $feature.Installed) {
    Write-Log "ADCS feature not found. Installing..."
    Install-WindowsFeature -Name $Name -IncludeManagementTools -ErrorAction Stop
    Write-Log "ADCS feature installed successfully."
  } else {
    Write-Log "ADCS feature already installed."
  }
}
#endregion

#region Configure Root Standalone Root CA
function Invoke-RootCAConfiguration {
  [CmdletBinding()]
  param(
    [Parameter()][ValidateSet('StandaloneRootCA', 'EnterpriseRootCA')][string]$CAType = 'StandaloneRootCA',
    [Parameter()][ValidateSet('512', '1024', '2048', '4096')][int]$KeyLength = 4096,
    [Parameter()][ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512')][string]$HashAlgorithm = 'SHA256',
    [Parameter()][string]$CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider',
    [Parameter(Mandatory)][string]$CACommonName,
    [Parameter()][ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')][string]$ValidityPeriod = 'Years',
    [Parameter()][int]$ValidityPeriodUnits = 10,
    [Parameter()][string]$DatabaseDirectory = "$env:SystemRoot\System32\Certlog",
    [Parameter()][string]$LogDirectory = "$env:SystemRoot\System32\Certlog"
    # Credential parameter removed
    )
    Write-Log "Configuring $CAType..." INFO
    $caParams = @{
      CAType = $CAType
      KeyLength = $KeyLength
      HashAlgorithm = $HashAlgorithm
      CryptoProviderName = $CryptoProviderName
      CACommonName = $CACommonName
      ValidityPeriod = $ValidityPeriod
      ValidityPeriodUnits = $ValidityPeriodUnits
      DatabaseDirectory = $DatabaseDirectory
      LogDirectory = $LogDirectory
    }
    try {
      Install-AdcsCertificationAuthority @caParams -Force -ErrorAction Stop
      Write-Log "$CAType configured successfully." INFO
    } catch {
      Write-Log "Failed to configure $CAType : $_" "ERROR"
      throw $_
    }
}
#endregion

#region Backup existing CRL and AIA settings
$logPath = Split-Path -Parent $Global:Logfile
$Global:CrlBackupPath = Join-Path -Path $logPath -ChildPath "CRL_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$Global:AiaBackupPath = Join-Path -Path $logPath -ChildPath "AIA_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$systembase = "$env:SystemRoot\System32\CertSrv\CertEnroll"
#endregion

#region Backup existing CRL and AIA settings
function Invoke-BackupCurrentCrlAia {
  param(
    [string]$localCRLPath = "$($systembase)\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl",
    [string]$localAIAPath = "$($systembase)\<ServerDNSName>_<CAName><CertificateName>.crt",
    [string]$CrlBackupPath = $Global:CrlBackupPath,
    [string]$AiaBackupPath = $Global:AiaBackupPath
  )
  if ([string]::IsNullOrWhiteSpace($CrlBackupPath) -or [string]::IsNullOrWhiteSpace($AiaBackupPath)) {
      Write-Log "Backup path(s) not specified." "ERROR"
      throw "Backup path(s) not specified."
  }
  Write-Log "Backing up existing CRL and AIA settings..."
  try {
    $crlSettings = Get-CACrlDistributionPoint
    $crlSettings | Out-File -FilePath $CrlBackupPath -Encoding UTF8
    Write-Log "CRL settings backed up to $CrlBackupPath"
  } catch {
    Write-Log "Failed to back up CRL settings: $_" "ERROR"
  }
  try {
    $aiaSettings = Get-CAAuthorityInformationAccess
    $aiaSettings | Out-File -FilePath $AiaBackupPath -Encoding UTF8
    Write-Log "AIA settings backed up to $AiaBackupPath"
  } catch {
    Write-Log "Failed to back up AIA settings: $_" "ERROR"
  }
}
#endregion

#region Configure CRLsettings

function Invoke-ConfigureCrl {
  [CmdletBinding()]
  param(
    [Parameter()][string]$computerName,
    [string[]]$crlTargets = @($httpCrlUri, $localCRLPath),
    [string]$fqdn = "intheclouds365.internal"
  )

  $httpBase = "http://$computerName.$($fqdn)/pki"
  $localCRLPath = "$($systembase)\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl"
  $httpCrlUri = "$httpBase/$(Split-Path -Leaf $localCRLPath)"

  Write-Log "Configuring CRL Distribution Points..." INFO
  foreach($obj in (Get-CACrlDistributionPoint | Where-Object {$_.Uri -ne $localCRLPath})) {
    Write-Log "Existing CRL DP: $($obj.Uri)" INFO
    if ($crlTargets -notcontains $obj.Uri) {
      Write-Log "Removing obsolete CRL DP: $($obj.Uri)" WARN
      try {
        Remove-CACrlDistributionPoint -Uri $obj.Uri -Confirm:$false
      }
      catch {
        Write-Log "Failed to remove CRL DP: $($obj.Uri). Error: $_" ERROR
      }
    }
  }
  Write-Log "Adding required CRL Distribution Points..." INFO
  foreach($obj in (Get-CACrlDistributionPoint | Where-Object {$_.Uri -ne $httpCrlUri})) {
    Write-Log "Existing CRL DP: $($obj.Uri)" INFO
    if ($crlTargets -notcontains $obj.Uri) {
      if ([string]::IsNullOrWhiteSpace($httpCrlUri)) { continue } # Guard clause to skip null or empty URIs
      Write-Log "Adding CRL DP: $httpCrlUri" INFO
      try {
        Add-CACrlDistributionPoint -Uri $httpCrlUri -AddToCertificateCdp -AddToFreshestCrl -Confirm:$false
        Write-Log "Added CRL DP: $httpCrlUri" INFO
      }
      catch {
        Write-Log "Failed to add CRL DP: $httpCrlUri. Error: $_" ERROR
      }
    } else {
      Write-Log "CRL DP already present: $httpCrlUri" INFO
    }
  }
}
#endregion

#region Configure AIA settings
function Invoke-ConfigureAia {
  [CmdletBinding()]
  param(
    [Parameter()][string]$computerName,
    [string[]]$aiaTargets = @($httpAiaUri, $localAIAPath),
    [string]$fqdn = "intheclouds365.internal"
  )
  $localAIAPath = "$($systembase)\<ServerDNSName>_<CAName><CertificateName>.crt"
  $httpBase = "http://$computerName.$($fqdn)/pki"
  $httpAiaUri = "$httpBase/$(Split-Path -Leaf $localAIAPath)"

  Write-Log "Configuring Authority Information Access..." INFO
  foreach($obj in (Get-CAAuthorityInformationAccess | Where-Object {$_.Uri -ne $localAIAPath})) {
    Write-Log "Existing AIA DP: $($obj.Uri)" INFO
    if ($aiaTargets -notcontains $obj.Uri) {
      Write-Log "Removing obsolete AIA DP: $($obj.Uri)" WARN
      try {
        Remove-CAAuthorityInformationAccess -Uri $obj.Uri -Confirm:$false
      }
      catch {
        Write-Log "Failed to remove AIA DP: $($obj.Uri). Error: $_" ERROR
      }
    }
  }
  Write-Log "Adding required AIA Distribution Points..." INFO
  foreach($obj in (Get-CAAuthorityInformationAccess | Where-Object {$_.Uri -ne $httpAiaUri})) {
    Write-Log "Existing AIA DP: $($obj.Uri)" INFO
    if ($aiaTargets -notcontains $obj.Uri) {
      if ([string]::IsNullOrWhiteSpace($httpAiaUri)) { continue } # Guard clause to skip null or empty URIs
      Write-Log "Adding AIA DP: $httpAiaUri" INFO
      try {
        Add-CAAuthorityInformationAccess -Uri $httpAiaUri -AddToCertificateAia -Confirm:$false
        Write-Log "Added AIA DP: $httpAiaUri" INFO
      }
      catch {
        Write-Log "Failed to add AIA DP: $httpAiaUri. Error: $_" ERROR
      }
    } else {
      Write-Log "AIA DP already present: $httpAiaUri" INFO
    }
  }
}
#endregion

#region Helper Functions
function Invoke-ADCSConfig {
  [CmdletBinding()]
  param(
    [Parameter()][string]$fqdn = "intheclouds365.internal",
    [Parameter(Mandatory)][string]$computerName,
    [Parameter()][ValidateSet('StandaloneRootCA', 'EnterpriseRootCA')][string]$CAType = 'StandaloneRootCA',
    [Parameter()][ValidateSet('512', '1024', '2048', '4096')][int]$KeyLength = 4096,
    [Parameter()][ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512')][string]$HashAlgorithm = 'SHA256',
    [Parameter()][string]$CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider',
    [Parameter(Mandatory)][string]$CACommonName,
    [Parameter()][ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')][string]$ValidityPeriod = 'Years',
    [Parameter()][int]$ValidityPeriodUnits = 10,
    [Parameter()][string]$DatabaseDirectory = "$env:SystemRoot\System32\Certlog",
    [Parameter()][string]$LogDirectory = "$env:SystemRoot\System32\Certlog",
    [switch]$ConfigureRootCA,
    [switch]$BackupCrlAiA,
    [switch]$ConfigureCRL,
    [switch]$ConfigureAIA
  )
  Write-Log "Installing required ADCS features..." INFO
  Install-ADCSFeature
  Invoke-PreflightChecks
  Write-Log "Backing up existing ADCS settings..." INFO
  try {
    if ($ConfigureRootCA.IsPresent) {
      Write-Log "Starting Root CA configuration..." INFO
      Invoke-RootCAConfiguration -CACommonName $CACommonName
      Write-Log "Root CA configuration completed." INFO
      Start-Sleep -Seconds 10 # Wait for CA service to stabilize
    }

    if ($BackupCrlAiA.IsPresent) {
      Write-Log "Starting backup of current CRL and AIA settings..." INFO
      Invoke-BackupCurrentCrlAia
      Write-Log "Backup of current CRL and AIA settings completed." INFO
    }

    if ($ConfigureCRL.IsPresent) {
      Write-Log "Starting CRL configuration..." INFO
      Invoke-ConfigureCrl -fqdn $fqdn -computerName $computerName
      Write-Log "CRL configuration completed." INFO

    }
    if ($ConfigureAIA.IsPresent) {
      Write-Log "Starting AIA configuration..." INFO
      Invoke-ConfigureAia -fqdn $fqdn -computerName $computerName
      Write-Log "AIA configuration completed." INFO
    }
  }
  catch {
    Write-Log "An error occurred during configuration: $_" ERROR
    throw $_
  }
  finally {
    Write-Log "Configuration process completed." INFO
    Write-Log "Restarting Certificate Services to apply changes..." INFO
    Restart-Service CertSvc -PassThru | Out-Null
    Write-Log "Certificate Services restarted to apply changes." INFO
    Write-Log "Verifying ADCS configuration..." INFO
    Get-CACrlDistributionPoint | Select-Object -Property Uri | Format-List
    Get-CAAuthorityInformationAccess | Select-Object -Property Uri | Format-List
    Write-Log "ADCS configuration verification completed." INFO
  }
}
#endregion
