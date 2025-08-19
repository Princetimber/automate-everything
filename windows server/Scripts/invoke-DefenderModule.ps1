$ErrorActionPreference = 'Stop'
#Requires -Version 7.5
#Requires -RunAsAdministrator

#region Logging Setup
$Global:LogFile = "$env:TEMP\DefenderDeployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
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
Tests that the prerequisites for Defender installation are met.
#>
  param (
    [Parameter()][string[]]$RequiredFeatures = @('Windows-Defender'),
    [Parameter()][string[]]$RequiredPaths = @(),
    [int]$MinDiskGB = 4
  )
  Write-Log "Running pre-flight checks..." 'INFO'

  # Block Windows Server 2012 and 2012 R2 (version 6.2* and 6.3*)
  $os = Get-CimInstance Win32_OperatingSystem
  if (
    ($os.Caption -like '*2012*') -or
    ($os.Version -like '6.2*') -or
    ($os.Version -like '6.3*')
  ) {
    Write-Log "This script must not be run on Windows Server 2012 or 2012 R2. Aborting." 'ERROR'
    throw "Script execution prevented: Windows Server 2012 and 2012 R2 are not supported."
  }
  else {
    Write-Log "OS is $($os.Caption) ($($os.Version)) - supported for this script." 'DEBUG'
  }

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
    $drive = Get-PSDrive -Name $Path[0]
    if ($drive.Free -lt $MinDiskGB * 1GB) {
      Write-Log "Insufficient disk space on $($drive.Name): $([math]::Round($drive.Free/1GB,2)) GB free." 'ERROR'
      throw "Insufficient disk space on $($drive.Name)."
    }
  }
  Write-Log "Pre-flight checks passed." 'INFO'
}
#endregion

#region Installing required Defender Module
function Invoke-DefenderModule {
  <#
.SYNOPSIS
Ensures Windows Defender feature is installed.
#>
  param (
    [string]$Name = 'Windows-Defender'
  )
  Write-Log "Invoking Pre-Flight Checks..." 'INFO'
  Test-Prerequisites -RequiredFeatures @('Windows-Defender') -MinDiskGB 4
  try {
    Write-Log "Checking if feature $Name is installed....." 'INFO'
    $feature = Get-WindowsFeature -Name $Name
    if (-not $feature.Installed) {
      Write-Log "Installing feature $Name...." 'INFO'
      Install-WindowsFeature -Name $Name -IncludeAllSubFeature -IncludeManagementTools
      Write-Log "$Name feature installed successfully." 'INFO'
    }
    else {
      Write-Log "$Name feature is already installed." 'DEBUG'
    }
  }
  catch {
    Write-Log "Failed to install $Name feature: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region Main Script Execution
try {
  Write-Log "Starting installation of Windows feature 'Windows-Defender'..." 'INFO'
  Invoke-DefenderModule
  Write-Log "Windows Defender feature installed successfully." 'INFO'
  Write-Log "Script execution completed successfully." 'INFO'
}
catch {
  Write-Log "An error occurred during script execution: $_" 'ERROR'
  throw $_
}
#endregion