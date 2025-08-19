$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues = @{
  'Invoke-ADDSForest:DatabasePath'           = "$env:SYSTEMDRIVE\Windows"
  'Invoke-ADDSForest:LogPath'                = "$env:SYSTEMDRIVE\Windows\NTDS\"
  'Invoke-ADDSForest:SYSVOLPATH'             = "$env:SYSTEMDRIVE\Windows"
  'Invoke-ADDSDomainController:SiteName'     = 'Default-First-Site-Name'
  'Invoke-ADDSDomainController:DatabasePath' = "$env:SYSTEMDRIVE\Windows"
  'Invoke-ADDSDomainController:LogPath'      = "$env:SYSTEMDRIVE\Windows\NTDS\"
  'Invoke-ADDSDomainController:SYSVOLPath'   = "$env:SYSTEMDRIVE\Windows"
}

#region Logging Setup
$Global:LogFile = "$env:TEMP\ADDeployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
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

#region Pre-flight Checks
function Test-Prerequisites {
  <#
.SYNOPSIS
Tests that the prerequisites for AD installation are met.
#>
  param (
    [Parameter()][string[]]$RequiredFeatures = @('AD-Domain-Services'),
    [Parameter()][string[]]$RequiredPaths = @(),
    [int]$MinDiskGB = 4
  )
  Write-Log "Running pre-flight checks..." 'INFO'
  foreach ($feature in $RequiredFeatures) {
    $f = Get-WindowsFeature -Name $feature
    if (-not $f) {
      Write-Log "Feature $feature not found on server." 'ERROR'
      throw "Feature $feature not found."
    }
    elseif (-not $f.Installed) {
      Write-Log "Feature $feature is not installed." 'WARN'
    }
    else {
      Write-Log "Feature $feature is installed." 'DEBUG'
    }
  }
  foreach ($Path in $RequiredPaths) {
    if (-not (Test-Path $Path)) {
      Write-Log "Required path $Path does not exist." 'ERROR'
      throw "Required path $Path does not exist."
    }
    else {
      Write-Log "Required path $Path exists." 'DEBUG'
    }
    $driveLetter = [System.IO.Path]::GetPathRoot($Path) -replace '\\$',''
    $drive = Get-PSDrive | Where-Object { $_.Root -eq "$driveLetter\" }
    if ($null -ne $drive -and $drive.Free -lt $MinDiskGB * 1GB) {
      Write-Log "Insufficient disk space on $($drive.Name): $([math]::Round($drive.Free/1GB,2)) GB free." 'ERROR'
      throw "Insufficient disk space on $($drive.Name)."
    }
  }
  Write-Log "Pre-flight checks passed." 'INFO'
}
#endregion

#region Installing required PS Modules
function Invoke-PSModules {
  <#
.SYNOPSIS
Installs required PowerShell modules.
.DESCRIPTION
Idempotent install; only installs if not present.
#>
  param (
    [string[]]$Name = @('Microsoft.PowerShell.SecretManagement', 'az.KeyVault')
  )
  Write-Log "Installing required PowerShell modules from PSGallery...." 'INFO'
  try {
    $Name | ForEach-Object {
      if (-not (Get-Module -Name $_ -ListAvailable)) {
        Write-Log "Setting PSGallery to a trusted repository" 'DEBUG'
        Set-PSResourceRepository -Name PSGallery -Trusted
        Write-Log "Installing required module $_ from PSGallery." 'INFO'
        Install-PSResource -Name $_ -Repository PSGallery -Scope AllUsers -Confirm:$false
        Write-Log "$_ module installed successfully." 'INFO'
      }
      else {
        Write-Log "$_ module is already installed." 'DEBUG'
      }
    }
  }
  catch {
    Write-Log "Failed to install module(s): $_" 'ERROR'
    throw $_
  }
}
#endregion

#region Installing required AD Module(s)
function Invoke-ADModule {
  <#
.SYNOPSIS
Ensures AD-Domain-Services is installed.
#>
  param (
    [string]$Name = 'AD-Domain-Services'
  )
  try {
    Write-Log "Checking if module $Name is installed....." 'INFO'
    $feature = Get-WindowsFeature -Name $Name
    if (-not $feature.Installed) {
      Write-Log "Installing module $Name...." 'INFO'
      Install-WindowsFeature -Name $Name -IncludeAllSubFeature -IncludeManagementTools
      Write-Log "$Name module installed successfully." 'INFO'
    }
    else {
      Write-Log "$Name module is already installed." 'DEBUG'
    }
  }
  catch {
    Write-Log "Failed to install $Name module: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region creating new environment path
function New-EnvPath {
  <#
.SYNOPSIS
Joins a base path and a child path.
#>
  param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ChildPath
  )
  return Join-Path $Path $ChildPath
}
#endregion

function Test-Paths {
  <#
.SYNOPSIS
Tests that all provided paths exist.
#>
  param (
    [Parameter(Mandatory)][string[]]$Paths
  )
  foreach ($Path in $Paths) {
    if (-not (Test-Path -Path $Path)) {
      Write-Log "Path $Path does not exist." 'ERROR'
      throw "Path $Path does not exist."
    }
    else {
      Write-Log "Path $Path exists." 'DEBUG'
    }
  }
}

#region Secure Credential Handling
function Get-SafeModePassword {
  <#
.SYNOPSIS
Gets Safe Mode Administrator password securely.
.DESCRIPTION
Allows parameter or prompt.
#>
  param (
    [Parameter()][securestring]$Password
  )
  if ($Password) { return $Password }
  return Read-Host -AsSecureString -Prompt "Enter Safe Mode Administrator password"
}
#endregion

#region adding function to create new forest
function New-ADDSForest {
  <#
.SYNOPSIS
Creates a new AD DS forest.
#>
  param(
    [string]$DomainName,
    [string]$DomainNetbiosName,
    [securestring]$SafeModeAdministratorPassword,
    [ValidateSet("Win2008", "Win2008R2", "Win2012", "Win2012R2", "Win2025", "Default", "WinThreshold")][string]$DomainMode = "Win2025",
    [ValidateSet("Win2008", "Win2008R2", "Win2012", "Win2012R2", "Win2025", "Default", "WinThreshold")][string]$ForestMode = "Win2025",
    [string]$DatabasePath,
    [string]$LogPath,
    [string]$SYSVOLPATH,
    [switch]$InstallDNS,
    [switch]$Force
  )
  try {
    Write-Log "Starting AD DS Forest creation with parameters: $($PSBoundParameters | Out-String)" 'DEBUG'
    Test-Prerequisites -RequiredFeatures @('AD-Domain-Services') -RequiredPaths @($DatabasePath, $LogPath, $SYSVOLPATH)
    Invoke-PSModules
    Invoke-ADModule

    $LOG_PATH = New-EnvPath -Path $LogPath -ChildPath 'logs'
    $DATABASE_PATH = New-EnvPath -Path $DatabasePath -ChildPath 'ntds'
    $SYSVOL_PATH = New-EnvPath -Path $SYSVOLPATH -ChildPath 'sysvol'
    $SafePwd = Get-SafeModePassword -Password $SafeModeAdministratorPassword

    $CommonParams = @{
      DomainName                    = $DomainName
      DataBasePath                  = $DATABASE_PATH
      LogPath                       = $LOG_PATH
      SysvolPath                    = $SYSVOL_PATH
      SafeModeAdministratorPassword = $SafePwd
      InstallDNS                    = $InstallDNS.IsPresent
    }
    foreach ($p in 'DomainMode', 'ForestMode', 'DomainNetBiosName', 'Force') {
      if ($PSBoundParameters.ContainsKey($p)) { $CommonParams[$p] = $PSBoundParameters[$p] }
    }
    Install-ADDSForest @CommonParams
    Write-Log "AD DS Forest creation for $DomainName started." 'INFO'
  }
  catch {
    Write-Log "Failed to install AD DS Forest: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region Invoke ADDS Forest Install
function Invoke-ADDSForest {
  <#
.SYNOPSIS
Invokes AD DS forest creation.
#>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param (
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$DomainName,
    [Parameter()][securestring]$SafeModeAdministratorPassword,
    [Parameter()][string]$DomainNetBiosName,
    [Parameter()][string]$DomainMode = 'Win2025',
    [Parameter()][string]$ForestMode = 'Win2025',
    [Parameter()][string]$DatabasePath,
    [Parameter()][string]$SysvolPath,
    [Parameter()][string]$LogPath,
    [switch]$InstallDNS,
    [switch]$Force
  )
  try {
    Write-Log "Invoking AD DS Forest creation for $DomainName." 'INFO'
    if ($PSCmdlet.ShouldProcess("Install new AD DS Forest for $DomainName")) {
      $params = @{
        DomainName                    = $DomainName
        SafeModeAdministratorPassword = $SafeModeAdministratorPassword
        DomainNetBiosName             = $DomainNetBiosName
        DomainMode                    = $DomainMode
        ForestMode                    = $ForestMode
        DatabasePath                  = $DatabasePath
        SysvolPath                    = $SysvolPath
        LogPath                       = $LogPath
        InstallDNS                    = $InstallDNS.IsPresent
        Force                         = $Force.IsPresent
      }
      New-ADDSForest @params
      Write-Log "Installation of new ADDS Forest completed successfully." 'INFO'
    }
  }
  catch {
    Write-Log "Failed to install new AD DS Forest.: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region Installing additional domain controller
function New-ADDSDomainController {
  <#
.SYNOPSIS
Installs additional domain controller in existing forest.
#>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DomainName,
    [Parameter()][string]$SiteName = 'Default-First-Site-Name',
    [Parameter()][ValidateNotNullOrEmpty()][string]$DomainAdministrator,
    [Parameter()][securestring]$SafeModeAdministratorPassword,
    [Parameter()][ValidateNotNullOrEmpty()][string]$DatabasePath,
    [Parameter()][ValidateNotNullOrEmpty()][string]$LogPath,
    [Parameter()][ValidateNotNullOrEmpty()][string]$SysvolPath,
    [switch]$InstallDNS,
    [switch]$Force
  )
  try {
    Write-Log "Starting additional domain controller installation with parameters: $($PSBoundParameters | Out-String)" 'DEBUG'
    Test-Prerequisites -RequiredFeatures @('AD-Domain-Services') -RequiredPaths @($DatabasePath, $LogPath, $SysvolPath)
    Invoke-PSModules
    Invoke-ADModule

    $LOG_PATH = New-EnvPath -Path $LogPath -ChildPath 'logs'
    $DATABASE_PATH = New-EnvPath -Path $DatabasePath -ChildPath 'ntds'
    $SYSVOL_PATH = New-EnvPath -Path $SysvolPath -ChildPath 'sysvol'

    Write-Log "Creating credential object for the domain administrator." 'DEBUG'
    $CredPassword = Read-Host -AsSecureString -Prompt "Enter Secure password for $DomainAdministrator"
    $DomainCredential = New-Object System.Management.Automation.PSCredential($DomainAdministrator, $CredPassword)
    $SafePwd = Get-SafeModePassword -Password $SafeModeAdministratorPassword

    $CommonParams = @{
      DomainName                    = $DomainName
      SiteName                      = $SiteName
      SafeModeAdministratorPassword = $SafePwd
      DatabasePath                  = $DATABASE_PATH
      LogPath                       = $LOG_PATH
      SysvolPath                    = $SYSVOL_PATH
      InstallDNS                    = $InstallDNS.IsPresent
      Credential                    = $DomainCredential
    }
    if ($Force.IsPresent) { $CommonParams['Force'] = $true }

    if ($PSCmdlet.ShouldProcess("Install additional domain controller for $DomainName")) {
      Install-ADDSDomainController @CommonParams
      Write-Log "Installation of additional domain controller completed successfully." 'INFO'
    }

  }
  catch {
    Write-Log "Failed to install additional domain controller: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region Invoke additional domain controller installation.
function Invoke-ADDSDomainController {
  <#
.SYNOPSIS
Invokes installation of additional domain controller.
#>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DomainName,
    [Parameter()][string]$SiteName = 'Default-First-Site-Name',
    [Parameter()][ValidateNotNullOrEmpty()][string]$DomainAdministrator,
    [Parameter()][securestring]$SafeModeAdministratorPassword,
    [Parameter()][string]$DatabasePath,
    [Parameter()][string]$SysvolPath,
    [Parameter()][string]$LogPath,
    [switch]$InstallDNS,
    [switch]$Force
  )
  try {
    Write-Log "Invoking additional domain controller installation for $DomainName." 'INFO'
    if ($PSCmdlet.ShouldProcess("Install additional domain controller for $DomainName")) {
      $params = @{
        DomainName                    = $DomainName
        SiteName                      = $SiteName
        DomainAdministrator           = $DomainAdministrator
        SafeModeAdministratorPassword = $SafeModeAdministratorPassword
        DatabasePath                  = $DatabasePath
        SysvolPath                    = $SysvolPath
        LogPath                       = $LogPath
        InstallDNS                    = $InstallDNS.IsPresent
        Force                         = $Force.IsPresent
      }
      New-ADDSDomainController @params
      Write-Log "Additional domain controller installation completed." 'INFO'
    }
  }
  catch {
    Write-Log "Failed to install additional domain controller: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region Export Module function
Export-ModuleMember -Function Write-Log, Test-Prerequisites, Invoke-PSModules, Invoke-ADModule, New-EnvPath, Test-Paths, Get-SafeModePassword, New-ADDSForest, Invoke-ADDSForest, New-ADDSDomainController, Invoke-ADDSDomainController
#endregion