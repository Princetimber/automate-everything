<#
 # This script sets up logging for OS configuration tasks on Windows Server 2025.
 # It ensures required modules are installed/updated, then applies baseline configs
 # based on whether the machine is a Member Server or Domain Controller.
 # If a restart is required, the server will reboot automatically.
#>

#region Logging Setup
$Global:LogFile = "$env:TEMP\PostInstallTasks_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
  param (
    [string]$Message,
    [string]$Level = 'INFO'
  )
  $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
  Add-Content -Path $Global:LogFile -Value $entry
  Write-Verbose $entry
}
#endregion

  #region Module Management
function Initialize-Modules {
    param (
        [string[]]$Modules = @('Microsoft.OSConfig')
    )

    foreach ($module in $Modules) {
        try {
            $installed = Get-PSResource -Name $module -ErrorAction SilentlyContinue

            if (-not $installed) {
                Write-Log "Module [$module] not found. Installing..." 'INFO'
                Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction SilentlyContinue
                Install-PSResource -Name $module -Repository PSGallery -Scope AllUsers -Confirm:$false
                Write-Log "Module [$module] installed successfully." 'INFO'
            }
            else {
                $latest = Find-PSResource -Name $module -Repository PSGallery -ErrorAction Stop
                if ($installed.Version -lt $latest.Version) {
                    Write-Log "Module [$module] is outdated (Installed: $($installed.Version), Latest: $($latest.Version)). Updating..." 'INFO'
                    Update-PSResource -Name $module -Scope AllUsers -Confirm:$false
                    Write-Log "Module [$module] updated to version $($latest.Version)." 'INFO'
                }
                else {
                    Write-Log "Module [$module] is up to date (Version: $($installed.Version))." 'DEBUG'
                }
            }

            Import-Module $module -Force
        }
        catch {
            Write-Log "Failed to install/update module [$module]: $_" 'ERROR'
            throw
        }
    }
}
#endregion

#region Role Detection Helper
function Get-ServerRole {
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $domainRole = $cs.DomainRole
    switch ($domainRole) {
      4 { return "DomainController" }
      5 { return "DomainController" }
      default { return "MemberServer" }
    }
  }
  catch {
    Write-Log "Failed to determine server role: $_" 'ERROR'
    throw
  }
}
#endregion

#region Baseline Configurations
function Start-BaselineConfigurations {
  [CmdletBinding(SupportsShouldProcess=$true)]
  param ()

  Write-Log "Starting baseline configuration application..." 'INFO'
  Initialize-Modules -Modules 'Microsoft.OSConfig'

  $role = Get-ServerRole
  Write-Log "Detected server role: $role" 'INFO'

  if ($role -eq "MemberServer") {
    if(-not (Get-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/MemberServer -ErrorAction SilentlyContinue)){
      Write-Log "Applying baseline configuration for Member Server..." 'INFO'
      try {
        Set-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/MemberServer -Default
        Set-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/MemberServer -Name AuditDetailedFileShare -Value 3
        Set-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/MemberServer -Name RemoteDesktopServicesDoNotAllowDriveRedirection -Value 0
        Set-OSConfigDesiredConfiguration -Scenario SecuredCore -Default
        Set-OSConfigDesiredConfiguration -Scenario Defender/Antivirus -Default
        Write-Log "Baseline configuration applied for Member Server." 'INFO'
      }
      catch {
        Write-Log "Failed to set OSConfig Desired Configuration: $_" 'ERROR'
        throw
      }
    }
    else {
      Write-Log "Member Server baseline already configured." 'DEBUG'
    }
  }
  elseif ($role -eq "DomainController") {
    if(-not (Get-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/DomainController -ErrorAction SilentlyContinue)){
      Write-Log "Applying baseline configuration for Domain Controller..." 'INFO'
      try {
        Set-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/DomainController -Default
        Set-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/DomainController -Name RemoteDesktopServicesDoNotAllowDriveRedirection -Value 0
        Set-OSConfigDesiredConfiguration -Scenario SecuredCore -Default
        Set-OSConfigDesiredConfiguration -Scenario Defender/Antivirus -Default
        Write-Log "Baseline configuration applied for Domain Controller." 'INFO'
      }
      catch {
        Write-Log "Failed to set OSConfig Desired Configuration: $_" 'ERROR'
        throw
      }
    }
    else {
      Write-Log "Domain Controller baseline already configured." 'DEBUG'
    }
  }
  else {
    Write-Log "Unknown server role detected. No baseline configuration applied." 'WARN'
  }
}
#endregion

#region Restart Handling
function Test-PendingRestart {
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM\PendingReboot') { return $true }
        $component = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($component) { return $true }
        return $false
    }
    catch {
        Write-Log "Failed to check pending restart status: $_" 'WARN'
        return $false
    }
}

function Invoke-RestartIfRequired {
    if (Test-PendingRestart) {
        Write-Log "A restart is required to complete configuration. Restarting now..." 'WARN'
        Restart-Computer -Force
    }
    else {
        Write-Log "No restart is required." 'INFO'
    }
}
#endregion

#region Helper Wrapper
function Invoke-OSConfigDesiredConfiguration {
  [CmdletBinding(SupportsShouldProcess=$true)]
  param()

  try {
    Write-Log "Starting OSConfig Desired Configuration application..." 'INFO'
    if($PSCmdlet.ShouldProcess("Apply OSConfig Desired Configuration")){
      Start-BaselineConfigurations
    }
    else {
      Write-Log "OSConfig Desired Configuration skipped (WhatIf mode)." 'INFO'
    }
    Write-Log "OSConfig Desired Configuration applied successfully." 'INFO'
  }
  catch {
    Write-Log "Failed to apply OSConfig Desired Configuration: $_" 'ERROR'
    throw
  }
}
#endregion

#region Main Script Execution
try {
  Write-Log "Script execution started." 'INFO'

  Invoke-OSConfigDesiredConfiguration
  Invoke-RestartIfRequired  # Auto-restart enabled by default
  Write-Log "Script execution completed successfully." 'INFO'
}
catch {
  Write-Log "Script execution failed: $_" 'ERROR'
  throw
}
#endregion

