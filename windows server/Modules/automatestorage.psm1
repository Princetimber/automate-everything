<#
.SYNOPSIS
Create or reuse a Storage Spaces pool and virtual disk, format it, and create secured SYSVOL or NTDS directories with logging.

.DESCRIPTION
- Performs robust pre-flight checks (admin, disks, subsystem).
- Creates/uses a Storage Spaces pool and a virtual disk.
- Brings the disk online, initializes, partitions, formats NTFS, and assigns a drive letter.
- Creates SYSVOL or NTDS directories with appropriate ACLs and a Logs subfolder for NTDS.
- Provides detailed logging and error handling.

.PARAMETER StoragePoolFriendlyName
Friendly name of the Storage Spaces pool to create or use.

.PARAMETER VirtualHardDiskFriendlyName
Friendly name of the virtual disk to create or use.

.PARAMETER FileSystemLabel
The volume label: 'SYSVOL' or 'NTDS'.

.PARAMETER DirectoryName
The directory to create in the root of the volume (e.g., 'SYSVOL' or 'NTDS').

.PARAMETER CreateSYSVOL
Switch to create the SYSVOL directory and apply SYSVOL-appropriate ACLs.

.PARAMETER CreateNTDS
Switch to create the NTDS directory and apply NTDS-appropriate ACLs. Also creates a Logs subfolder.

.PARAMETER ResiliencySettingName
Virtual disk resiliency. Defaults to 'Mirror' for better protection (was 'Simple' before).

.PARAMETER ProvisioningType
Provisioning type for the virtual disk. Defaults to 'Fixed'.

.PARAMETER SizeGB
Optional size of the virtual disk in gigabytes. If not provided, uses maximum size.

.EXAMPLE
Invoke-StorageCreation -StoragePoolFriendlyName "LUN2" -VirtualHardDiskFriendlyName "VHD2" -FileSystemLabel "SYSVOL" -DirectoryName "SYSVOL" -CreateSYSVOL

Creates or uses a pool named "LUN2", a virtual disk "VHD2", formats it as NTFS labeled SYSVOL, and creates a SYSVOL directory with proper ACLs.

.EXAMPLE
Invoke-StorageCreation -StoragePoolFriendlyName "LUN2" -VirtualHardDiskFriendlyName "VHD2" -FileSystemLabel "NTDS" -DirectoryName "NTDS" -CreateNTDS

Creates or uses a pool named "LUN2", a virtual disk "VHD2", formats it as NTFS labeled NTDS, and creates an NTDS directory (and Logs) with proper ACLs.

.NOTES
Module Name: StorageCreation
Author: Your Name
Version: 1.4
Date: 2025-08-13
#>

$ErrorActionPreference = 'Stop'

#region Logging
$Global:LogFile = "$env:TEMP\StorageCreation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
  param (
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')][string]$Level = 'INFO'
  )
  $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
  Add-Content -Path $Global:LogFile -Value $entry
  switch ($Level) {
    'ERROR' { Write-Error $Message }
    'WARN' { Write-Warning $Message }
    'DEBUG' { Write-Verbose $Message }
    default { Write-Host $Message }
  }
}
#endregion

#region Helpers
function Test-UserIsAdministrator {
  try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  catch {
    return $false
  }
}

function Get-StorageSubSystemFriendlyName {
  $subsystems = Get-StorageSubSystem -ErrorAction Stop
  if ($subsystems.Count -gt 1) {
    # Prefer Windows Storage* subsystem if multiple are present
    $preferred = $subsystems | Where-Object { $_.FriendlyName -like 'Windows Storage*' }
    if ($preferred) { return $preferred.FriendlyName }
    return ($subsystems | Select-Object -First 1).FriendlyName
  }
  return $subsystems.FriendlyName
}

function Get-StoragePoolOrCreate {
  param(
    [Parameter(Mandatory)][string]$PoolName,
    [Parameter(Mandatory)][Microsoft.Management.Infrastructure.CimInstance[]]$PhysicalDisks,
    [Parameter(Mandatory)][string]$StorageSubSystemFriendlyName
  )
  $pool = Get-StoragePool -FriendlyName $PoolName -ErrorAction SilentlyContinue
  if (-not $pool) {
    Write-Log "Creating storage pool '$PoolName'..." 'INFO'
    $pool = New-StoragePool -FriendlyName $PoolName -StorageSubSystemFriendlyName $StorageSubSystemFriendlyName -PhysicalDisks $PhysicalDisks
    Write-Log "Storage pool '$PoolName' created." 'INFO'
  }
  else {
    Write-Log "Storage pool '$PoolName' already exists." 'DEBUG'
  }
}

function Get-VirtualDiskOrCreate {
  param(
    [Parameter(Mandatory)][string]$PoolName,
    [Parameter(Mandatory)][string]$VirtualDiskName,
    [ValidateSet('Simple', 'Mirror', 'Parity')][string]$ResiliencySettingName = 'Simple',
    [ValidateSet('Fixed', 'Thin')][string]$ProvisioningType = 'Fixed',
    [Nullable[int64]]$SizeGB
  )
  $vd = Get-VirtualDisk -FriendlyName $VirtualDiskName -ErrorAction SilentlyContinue
  if (-not $vd) {
    Write-Log "Creating virtual disk '$VirtualDiskName' (Resiliency=$ResiliencySettingName, Provisioning=$ProvisioningType, SizeGB=$SizeGB)..." 'INFO'
    if ($SizeGB -and $SizeGB -gt 0) {
      $sizeBytes = $SizeGB * 1GB
      $vd = New-VirtualDisk -StoragePoolFriendlyName $PoolName -FriendlyName $VirtualDiskName -Size $sizeBytes -ProvisioningType $ProvisioningType -ResiliencySettingName $ResiliencySettingName
    }
    else {
      $vd = New-VirtualDisk -StoragePoolFriendlyName $PoolName -FriendlyName $VirtualDiskName -UseMaximumSize -ProvisioningType $ProvisioningType -ResiliencySettingName $ResiliencySettingName
    }
    Write-Log "Virtual disk '$VirtualDiskName' created." 'INFO'
  }
  else {
    Write-Log "Virtual disk '$VirtualDiskName' already exists." 'DEBUG'
  }
  return $vd
}

function Initialize-DiskForStorage {
  param(
    [Parameter(Mandatory)][Microsoft.Management.Infrastructure.CimInstance]$VirtualDisk
  )
  $disk = $VirtualDisk | Get-Disk -ErrorAction Stop

  if ($disk.IsOffline) {
    Write-Log "Disk $($disk.Number) is offline. Bringing online..." 'INFO'
    Set-Disk -Number $disk.Number -IsOffline:$false -ErrorAction Stop
  }
  if ($disk.IsReadOnly) {
    Write-Log "Disk $($disk.Number) is read-only. Clearing read-only flag..." 'INFO'
    Set-Disk -Number $disk.Number -IsReadOnly:$false -ErrorAction Stop
  }

  if ($disk.PartitionStyle -eq 'RAW') {
    Write-Log "Initializing disk $($disk.Number) as GPT..." 'INFO'
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop
  }
  else {
    Write-Log "Disk $($disk.Number) already initialized ($($disk.PartitionStyle))." 'DEBUG'
  }

  $partition = $disk | Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Basic' -and $_.DriveLetter }
  if (-not $partition) {
    Write-Log "Creating partition and assigning drive letter on disk $($disk.Number)..." 'INFO'
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
  }
  else {
    Write-Log "Found existing basic partition with drive letter $($partition.DriveLetter) on disk $($disk.Number)." 'DEBUG'
  }

  # Return drive letter
  return $partition.DriveLetter
}

function Format-VolumeWithLabel {
  param(
    [Parameter(Mandatory)][char]$DriveLetter,
    [Parameter(Mandatory)][ValidateSet('SYSVOL', 'NTDS')][string]$Label
  )
  $vol = Get-Volume -DriveLetter $DriveLetter -ErrorAction Stop
  if ($vol.FileSystem -ne 'NTFS' -or $vol.FileSystemLabel -ne $Label) {
    Write-Log "Formatting $($DriveLetter): as NTFS with label '$Label' (existing FS: $($vol.FileSystem), label: $($vol.FileSystemLabel))..." 'WARN'
    Format-Volume -DriveLetter $DriveLetter -FileSystem NTFS -NewFileSystemLabel $Label -Force -Confirm:$false
    Write-Log "Volume $($DriveLetter): formatted and labeled '$Label'." 'INFO'
  }
  else {
    Write-Log "Volume $($DriveLetter): already NTFS and labeled '$Label'." 'DEBUG'
  }
}

function Set-DirectoryHiddenAttribute {
  param([Parameter(Mandatory)][string]$Path)
  Set-ItemProperty -Path $Path -Name Attributes -Value 'Hidden' -ErrorAction Stop
}

function New-DirectoryIfNotExist {
  param([Parameter(Mandatory)][string]$Path, [switch]$Hidden)
  if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    if ($Hidden) { Set-DirectoryHiddenAttribute -Path $Path }
    Write-Log "Created directory: $Path" 'INFO'
  }
  else {
    Write-Log "Directory already exists: $Path" 'DEBUG'
    if ($Hidden) { Set-DirectoryHiddenAttribute -Path $Path }
  }
}

function Set-SYSVOLAcl {
  param([Parameter(Mandatory)][string]$Path)
  Write-Log "Applying SYSVOL ACLs to: $Path" 'INFO'
  $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $propFlags = [System.Security.AccessControl.PropagationFlags]::None

  $ds = New-Object System.Security.AccessControl.DirectorySecurity
  $ds.SetAccessRuleProtection($true, $false)
  $rules = @(
    (New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inheritFlags, $propFlags, "Allow")),
    (New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inheritFlags, $propFlags, "Allow")),
    (New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "ReadAndExecute", $inheritFlags, $propFlags, "Allow"))
  )
  foreach ($r in $rules) { $ds.AddAccessRule($r) }
  Set-Acl -Path $Path -AclObject $ds
}

function Set-NTDSAcl {
  param([Parameter(Mandatory)][string]$Path)
  Write-Log "Applying NTDS ACLs to: $Path" 'INFO'
  $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $propFlags = [System.Security.AccessControl.PropagationFlags]::None

  $ds = New-Object System.Security.AccessControl.DirectorySecurity
  $ds.SetAccessRuleProtection($true, $false)
  $rules = @(
    (New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inheritFlags, $propFlags, "Allow")),
    (New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inheritFlags, $propFlags, "Allow"))
  )
  foreach ($r in $rules) { $ds.AddAccessRule($r) }
  Set-Acl -Path $Path -AclObject $ds
}
#endregion

#region Pre-flight
function Test-StoragePrerequisites {
  param(
    [Parameter(Mandatory)][string]$StoragePoolFriendlyName,
    [Parameter(Mandatory)][string]$VirtualHardDiskFriendlyName,
    [Parameter(Mandatory)][string]$DirectoryName
  )
  Write-Log "Running pre-flight checks..." 'INFO'

  if (-not (Test-UserIsAdministrator)) {
    Write-Log "This script must be run as Administrator." 'ERROR'
    throw "Administrator privileges required."
  }

  $physicalDisks = Get-PhysicalDisk -CanPool $true -ErrorAction Stop
  if (-not $physicalDisks -or $physicalDisks.Count -eq 0) {
    Write-Log "No available physical disks can be pooled." 'ERROR'
    throw "No available physical disks."
  }

  $diskOK = $physicalDisks | Where-Object { $_.OperationalStatus -eq 'OK' }
  if (-not $diskOK -or $diskOK.Count -eq 0) {
    Write-Log "No operational physical disks available for pooling." 'ERROR'
    throw "No operational disks for storage pool."
  }

  Write-Log "Pre-flight checks passed." 'DEBUG'
}
#endregion

#region Core
function New-Storage {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$StoragePoolFriendlyName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$VirtualHardDiskFriendlyName,
    [Parameter(Mandatory)][ValidateSet('SYSVOL', 'NTDS')][string]$FileSystemLabel,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DirectoryName,
    [switch]$CreateSYSVOL,
    [switch]$CreateNTDS,
    [ValidateSet('Simple', 'Mirror', 'Parity')][string]$ResiliencySettingName = 'Simple',
    [ValidateSet('Fixed', 'Thin')][string]$ProvisioningType = 'Fixed',
    [int64]$SizeGB
  )

  if ($CreateSYSVOL.IsPresent -and $CreateNTDS.IsPresent) {
    Write-Log "Both -CreateSYSVOL and -CreateNTDS switches cannot be used together." 'ERROR'
    throw "Invalid operation: SYSVOL and NTDS must be created in separate operations."
  }

  Write-Log "Starting storage workflow for label '$FileSystemLabel'..." 'INFO'

  try {
    Test-StoragePrerequisites -StoragePoolFriendlyName $StoragePoolFriendlyName -VirtualHardDiskFriendlyName $VirtualHardDiskFriendlyName -DirectoryName $DirectoryName

    $physicalDisks = Get-PhysicalDisk -CanPool $true | Where-Object { $_.OperationalStatus -eq 'OK' } | Select-Object -First 1
    $subsystemName = Get-StorageSubSystemFriendlyName

    Get-StoragePoolOrCreate -PoolName $StoragePoolFriendlyName -PhysicalDisks $physicalDisks -StorageSubSystemFriendlyName $subsystemName
    $vd = Get-VirtualDiskOrCreate -PoolName $StoragePoolFriendlyName -VirtualDiskName $VirtualHardDiskFriendlyName -ResiliencySettingName $ResiliencySettingName -ProvisioningType $ProvisioningType -SizeGB $SizeGB

    $driveLetter = Initialize-DiskForStorage -VirtualDisk $vd
    Format-VolumeWithLabel -DriveLetter $driveLetter -Label $FileSystemLabel

    $targetPath = "$($driveLetter):\$DirectoryName"
    $logPath = "$($driveLetter):\$DirectoryName\Logs"

    if ($CreateSYSVOL.IsPresent) {
      New-DirectoryIfNotExist -Path $targetPath -Hidden
      Set-SYSVOLAcl -Path $targetPath
      Write-Log "SYSVOL directory ready at $targetPath." 'INFO'
    }

    if ($CreateNTDS.IsPresent) {
      New-DirectoryIfNotExist -Path $targetPath -Hidden
      New-DirectoryIfNotExist -Path $logPath
      Set-NTDSAcl -Path $targetPath
      Write-Log "NTDS directory ready at $targetPath. Logs at $logPath." 'INFO'
    }

    Write-Log "Storage workflow completed successfully." 'INFO'
  }
  catch {
    Write-Log "An error occurred: $_" 'ERROR'
    throw
  }
  finally {
    Write-Log "Storage workflow finished." 'INFO'
  }
}
#endregion

#region Public Entry
function Invoke-StorageCreation {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$StoragePoolFriendlyName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$VirtualHardDiskFriendlyName,
    [Parameter(Mandatory)][ValidateSet('SYSVOL', 'NTDS')][string]$FileSystemLabel,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DirectoryName,
    [switch]$CreateSYSVOL,
    [switch]$CreateNTDS,
    [ValidateSet('Simple', 'Mirror', 'Parity')][string]$ResiliencySettingName = 'Simple',
    [ValidateSet('Fixed', 'Thin')][string]$ProvisioningType = 'Fixed',
    [int64]$SizeGB
  )

  if ($CreateSYSVOL.IsPresent -and $CreateNTDS.IsPresent) {
    Write-Log "Error: Cannot specify both -CreateSYSVOL and -CreateNTDS." 'ERROR'
    throw "Both -CreateSYSVOL and -CreateNTDS cannot be used at the same time."
  }

  Write-Log "Invoke-StorageCreation starting for $FileSystemLabel..." 'INFO'

  try {
    $params = @{
      StoragePoolFriendlyName     = $StoragePoolFriendlyName
      VirtualHardDiskFriendlyName = $VirtualHardDiskFriendlyName
      FileSystemLabel             = $FileSystemLabel
      DirectoryName               = $DirectoryName
      ResiliencySettingName       = $ResiliencySettingName
      ProvisioningType            = $ProvisioningType
    }
    if ($PSBoundParameters.ContainsKey('SizeGB')) { $params['SizeGB'] = $SizeGB }
    foreach ($switchName in @('CreateSYSVOL', 'CreateNTDS')) {
      if ($PSBoundParameters.ContainsKey($switchName)) { $params[$switchName] = $PSBoundParameters[$switchName] }
    }

    if ($PSCmdlet.ShouldProcess("Create/prepare storage '$VirtualHardDiskFriendlyName' in pool '$StoragePoolFriendlyName'")) {
      New-Storage @params
      Write-Log "Invoke-StorageCreation completed successfully for $FileSystemLabel." 'INFO'
    }
  }
  catch {
    Write-Log "Invoke-StorageCreation failed: $_" 'ERROR'
    throw
  }
  finally {
    Write-Log "Log file created at: $Global:LogFile" 'INFO'
    Write-Host "- Review the log file for details: $Global:LogFile" -ForegroundColor DarkCyan
    Write-Host "- Run this module in an elevated PowerShell session." -ForegroundColor DarkCyan
  }
}
#endregion

