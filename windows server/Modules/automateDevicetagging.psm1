<#
.SYNOPSIS
  Adds, resets, or removes a device tag for Microsoft Defender for Endpoint.

.DESCRIPTION
  Sets the device tag based on the OU of the device's distinguished name and writes it to:
  'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\DeviceTagging'.

.PARAMETER Tag
  Adds the current OU as a device tag.

.PARAMETER ResetTag
  Resets the tag to the current OU if different.

.PARAMETER RemoveTag
  Removes the tag and deletes the registry key.

.NOTES
  This function must be run with elevated privileges. It is not supported on non-Windows platforms.

.EXAMPLE
  Invoke-DeviceTagging -Tag
  Adds the device tag to the Defender registry key based on the current OU.

.EXAMPLE
  Invoke-DeviceTagging -ResetTag
  Resets the device tag if the current OU has changed.

.EXAMPLE
  Invoke-DeviceTagging -RemoveTag
  Removes the Defender device tag registry entry.
#>

$ErrorActionPreference = 'Stop'

#region Logging Setup
$Global:LogFile = "$env:TEMP\DeviceTagging_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
  param (
    [string]$Message,
    [string]$Level = 'INFO'
  )
  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $entry = "[$timestamp] [$Level] $Message"
  Add-Content -Path $Global:LogFile -Value $entry
  if ($Level -eq 'ERROR') { Write-Error $Message }
  elseif ($Level -eq 'WARN') { Write-Warning $Message }
  else { Write-Verbose $Message }
}
#endregion

#region Preflight Checks
function Test-PreflightChecks {
  param(
    [string]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\DeviceTagging',
    [string]$OUPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine'
  )
  Write-Log "Running preflight checks..." 'INFO'

  # Check if running on Windows
  if ($env:OS -notlike "*Windows*") {
    Write-Log "This script is only supported on Windows operating systems." 'ERROR'
    throw "Unsupported OS: $($env:OS)"
  }

  # Check for elevated privileges
  $IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $IsElevated) {
    Write-Log "Script must be run as administrator." 'ERROR'
    throw "Script must be run with elevated privileges."
  }

  # Check registry paths exist (OUPath must exist for tagging)
  if (-not (Test-Path $OUPath)) {
    Write-Log "OU registry path $OUPath not found." 'ERROR'
    throw "OU registry path $OUPath not found."
  }

  # Check if onboarded to Microsoft Defender for Endpoint (MDE)
  $MDEOnboarded = $false

  # Check if Sense service is running
  $senseService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
  if ($senseService -and $senseService.Status -eq "Running") {
    $MDEOnboarded = $true
    Write-Log "Sense service is running." 'INFO'
  } else {
    Write-Log "Sense service is not running." 'WARN'
  }

  # Check registry for OrgId or onboardingState == 1
  $StatusPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
  if (Test-Path $StatusPath) {
    $StatusProps = Get-ItemProperty -Path $StatusPath -ErrorAction SilentlyContinue
    if ($StatusProps.PSObject.Properties.Name -contains "OrgId" -and $StatusProps.OrgId) {
      $MDEOnboarded = $true
      Write-Log "OrgId found in registry." 'INFO'
    }
    if ($StatusProps.PSObject.Properties.Name -contains "onboardingState" -and $StatusProps.onboardingState -eq 1) {
      $MDEOnboarded = $true
      Write-Log "onboardingState registry value equals 1." 'INFO'
    }
  } else {
    Write-Log "MDE status registry path not found." 'WARN'
  }

  if (-not $MDEOnboarded) {
    Write-Log "Machine is NOT onboarded to Microsoft Defender for Endpoint. Tagging operation aborted." 'ERROR'
    throw "Machine is NOT onboarded to Microsoft Defender for Endpoint. Tagging operation aborted."
  }

  Write-Log "Preflight checks passed." 'INFO'
}
#endregion

#region Set-DeviceTag Function
function Set-Devicetag {
  param(
    [string]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\DeviceTagging',
    [string]$OUPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine',
    [string]$Value = 'Group',
    [switch]$Tag,
    [switch]$ResetTag,
    [switch]$RemoveTag
  )

  try {
    # Preflight checks
    Test-PreflightChecks -RegistryPath $RegistryPath -OUPath $OUPath

    # Validate only one switch is used
    $switchCount = @($Tag.IsPresent, $ResetTag.IsPresent, $RemoveTag.IsPresent) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    if ($switchCount -ne 1) {
      Write-Log "Only one of the switches -Tag, -ResetTag, or -RemoveTag can be used at a time." 'ERROR'
      throw "Only one of the switches -Tag, -ResetTag, or -RemoveTag can be used at a time."
    }

    # Retrieve OU from registry
    Write-Log "Getting the Distinguished Name and extracting OU values..." 'DEBUG'
    $DN = (Get-ItemProperty -Path $OUPath -Name 'Distinguished-Name' -ErrorAction Stop)."Distinguished-Name"
    $OUS = $DN -split ',' | Where-Object { $_ -like 'OU=*' }
    $TagValue = ($OUS[0] -split '=')[1]

    if ($Tag.IsPresent) {
      if (-not (Test-Path -Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
        Write-Log "Created registry key: $RegistryPath"
      }

      $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $Value -ErrorAction SilentlyContinue).$Value
      if ($CurrentValue -ne $TagValue) {
        Set-ItemProperty -Path $RegistryPath -Name $Value -Value $TagValue -Force
        Write-Log "Set registry value: $Value = '$TagValue' (was: '$CurrentValue')"
        Write-Output "Device tag set to: $TagValue"
        Write-Log "Device tag set to: $TagValue"
      }
      else {
        Write-Log "No change: Device tag already set to '$TagValue'"
        Write-Output "Device tag already set to: $TagValue"
      }
    }

    elseif ($ResetTag.IsPresent) {
      if (-not (Test-Path -Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
        Write-Log "Created registry key: $RegistryPath"
      }

      $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $Value -ErrorAction SilentlyContinue).$Value
      if ($null -eq $CurrentValue -or $CurrentValue -ne $TagValue) {
        Set-ItemProperty -Path $RegistryPath -Name $Value -Value $TagValue -Force
        Write-Log "Reset registry value: $Value = '$TagValue' (was: '$CurrentValue')"
        Write-Output "Device tag reset to: $TagValue"
        Write-Log "Device tag reset to: $TagValue"
      }
      else {
        Write-Log "No change: Device tag already up to date ('$TagValue')"
        Write-Output "Device tag already up to date: $TagValue"
      }
    }

    elseif ($RemoveTag.IsPresent) {
      if ((Test-Path -Path $RegistryPath) -and (Get-ItemProperty -Path $RegistryPath -Name $Value -ErrorAction SilentlyContinue)) {
        $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $Value -ErrorAction SilentlyContinue).$Value
        Remove-ItemProperty -Path $RegistryPath -Name $Value -Force
        Write-Log "Removed registry value: $Value (was: '$CurrentValue')"
        Write-Output "Device tag removed (was: $CurrentValue)"
        Write-Log "Device tag removed (was: $CurrentValue)"

        # Optionally remove the key if empty
        if ((Get-ItemProperty -Path $RegistryPath | Get-Member -MemberType NoteProperty).Count -eq 0) {
          Remove-Item -Path $RegistryPath -Force
          Write-Log "Deleted empty registry key: $RegistryPath"
        }
      }
      else {
        Write-Log "No change: No tag found to remove or registry key does not exist."
        Write-Output "No device tag found to remove or registry key does not exist."
      }
    }

  }
  catch {
    Write-Log "Failed to execute tagging command: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region Invoke-DeviceTagging Function
function Invoke-DeviceTagging {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $false)]
    [string]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\DeviceTagging',
    [Parameter(Mandatory = $false)]
    [string]$OUPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine',
    [Parameter(Mandatory = $false)]
    [string]$Value = 'Group',
    [switch]$Tag,
    [switch]$ResetTag,
    [switch]$RemoveTag
  )

  try {
    if ($PSCmdlet.ShouldProcess("Device tagging operation")) {
      if ($Tag.IsPresent) {
        Set-Devicetag -RegistryPath $RegistryPath -OUPath $OUPath -Value $Value -Tag
      }
      elseif ($ResetTag.IsPresent) {
        Set-Devicetag -RegistryPath $RegistryPath -OUPath $OUPath -Value $Value -ResetTag
      }
      elseif ($RemoveTag.IsPresent) {
        Set-Devicetag -RegistryPath $RegistryPath -OUPath $OUPath -Value $Value -RemoveTag
      }
    }
  }
  catch {
    Write-Log "Failed to set specified tagging operation on device: $_" 'ERROR'
    throw $_
  }
}
#endregion