<#
.SYNOPSIS
  creates and configures storage pools and virtual disks for Configuration Manager (SCCM) installations.
.DESCRIPTION
  This module provides functions to create and manage storage pools and virtual disks tailored for Configuration Manager (SCCM) installations. It includes functionality to initialize disks, format volumes, and set up specific directories required by SCCM.
  - This module is designed to simplify the deployment and management of storage resources in SCCM environments.
  - It aims to automate repetitive tasks and ensure best practices are followed during storage configuration.
  - Performs robust preflight checks to validate the environment before making changes.
  - Brings disk management capabilities to the forefront, allowing for seamless integration with existing SCCM workflows.
  - Ensures that all storage configurations adhere to Microsoft's best practices for SCCM.
  - Provides detailed logging and reporting features to track storage configuration changes.

.PARAMETER StoragePoolFriendlyName
  The friendly name of the storage pool to create or manage.

.PARAMETER VirtualDiskFriendlyName
  The friendly name of the virtual disk to create or manage.

.PARAMETER FileSystemLabel
  The file system type to use for the virtual disk (e.g., NTFS, ReFS).

.PARAMETER CreateConfigMgrInstall
  Indicates whether to create the necessary directory structure for a Configuration Manager installation.

.PARAMETER CreateSCCMDSQLMDF
  Indicates whether to create the SQL Server data file for Configuration Manager.

.PARAMETER CreateSCCMDSQLLDF
  Indicates whether to create the SQL Server log file directory for Configuration Manager.

.NOTES
  Information or caveats about the function e.g. 'This function is not supported in Linux'
.LINK
  Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
  Test-MyTestFunction -Verbose
  Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
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
    [Parameter(Mandatory)][ValidateSet('ConfigMgr Install', 'SCCM SQL MDF', 'SCCM SQL LDF', 'TempDB', 'SQL WSUS DB', 'SCCM APPLICATION SOURCES', 'SCCM CONTENT LIBRARY')][string]$Label
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
#endregion
#region Pre-flight
function Test-StoragePrerequisites {
  param(
    [Parameter(Mandatory)][string]$StoragePoolFriendlyName,
    [Parameter(Mandatory)][string]$VirtualHardDiskFriendlyName
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
    [Parameter(Mandatory)][ValidateSet('ConfigMgr Install', 'SCCM SQL MDF', 'SCCM SQL LDF', 'TempDB', 'SQL WSUS DB', 'SCCM APPLICATION SOURCES', 'SCCM CONTENT LIBRARY')][string]$FileSystemLabel,
    [switch]$CreateConfigMgrInstall,
    [switch]$CreateSCCMSQLMDF,
    [switch]$CreateSCCMSQLLDF,
    [switch]$CreateSCCMTempDB,
    [switch]$CreateSCCMSQLWSUSDB,
    [switch]$CreateSCCMApplicationSources,
    [switch]$CreateSCCMContentLibrary,
    [ValidateSet('Simple', 'Mirror', 'Parity')][string]$ResiliencySettingName = 'Simple',
    [ValidateSet('Fixed', 'Thin')][string]$ProvisioningType = 'Fixed',
    [int64]$SizeGB
  )

  if ($CreateConfigMgrInstall.IsPresent -and $CreateSCCMSQLMDF.IsPresent -and $CreateSCCMSQLLDF.IsPresent -and $CreateSCCMTempDB.IsPresent -and $CreateSCCMSQLWSUSDB.IsPresent -and $CreateSCCMApplicationSources.IsPresent -and $CreateSCCMContentLibrary.IsPresent) {
    Write-Log "All storage creation switches cannot be used together." 'ERROR'
    throw "Invalid operation: Multiple storage types must be created in separate operations."
  }

  Write-Log "Starting storage workflow for label '$FileSystemLabel'..." 'INFO'

  try {
    Test-StoragePrerequisites -StoragePoolFriendlyName $StoragePoolFriendlyName -VirtualHardDiskFriendlyName $VirtualHardDiskFriendlyName

    $physicalDisks = Get-PhysicalDisk -CanPool $true | Where-Object { $_.OperationalStatus -eq 'OK' } | Select-Object -First 1
    $subsystemName = Get-StorageSubSystemFriendlyName

    Get-StoragePoolOrCreate -PoolName $StoragePoolFriendlyName -PhysicalDisks $physicalDisks -StorageSubSystemFriendlyName $subsystemName
    $vd = Get-VirtualDiskOrCreate -PoolName $StoragePoolFriendlyName -VirtualDiskName $VirtualHardDiskFriendlyName -ResiliencySettingName $ResiliencySettingName -ProvisioningType $ProvisioningType -SizeGB $SizeGB

    $driveLetter = Initialize-DiskForStorage -VirtualDisk $vd
    Format-VolumeWithLabel -DriveLetter $driveLetter -Label $FileSystemLabel

    $fileName = "no_sms_on_drive.sms"
    $DrivePath = "$($driveLetter):\$fileName"

    if ($CreateSCCMSQLMDF.IsPresent) {
      New-Item -Path $DrivePath -ItemType File -Force | Out-Null
      Write-Log "Created marker file '$fileName' for SCCM SQL MDF on $($driveLetter):\" 'INFO'
      New-Item -Path "$($driveLetter):\Database" -ItemType Directory -Force | Out-Null
      Write-Log "Created directory '$($driveLetter):\Database' for SCCM SQL MDF on $($driveLetter):\" 'INFO'
    }
    if ($CreateSCCMSQLLDF.IsPresent) {
      New-Item -Path $DrivePath -ItemType File -Force | Out-Null
      Write-Log "Created marker file '$fileName' for SCCM SQL LDF on $($driveLetter):\" 'INFO'
      New-Item -Path "$($driveLetter):\Database" -ItemType Directory -Force | Out-Null
      Write-Log "Created directory '$($driveLetter):\Database' for SCCM SQL LDF on $($driveLetter):\" 'INFO'
    }
    if ($CreateSCCMTempDB.IsPresent) {
      New-Item -Path $DrivePath -ItemType File -Force | Out-Null
      Write-Log "Created marker file '$fileName' for SCCM TempDB on $($driveLetter):\" 'INFO'
      New-Item -Path "$($driveLetter):\database" -ItemType Directory -Force | Out-Null
      Write-Log "Created directory '$($driveLetter):\database' for SCCM TempDB on $($driveLetter):\" 'INFO'
    }
    if ($CreateSCCMSQLWSUSDB.IsPresent) {
      New-Item -Path $DrivePath -ItemType File -Force | Out-Null
      Write-Log "Created marker file '$fileName' for SCCM WSUS DB on $($driveLetter):\" 'INFO'
      New-Item -Path "$($driveLetter):\Database" -ItemType Directory -Force | Out-Null
      Write-Log "Created directory '$($driveLetter):\Database' for SCCM WSUS DB on $($driveLetter):\" 'INFO'
    }
    if ($CreateSCCMApplicationSources.IsPresent) {
      New-Item -Path $DrivePath -ItemType File -Force | Out-Null
      Write-Log "Created marker file '$fileName' for SCCM Application Sources on $($driveLetter):\" 'INFO'
    }
    if ($CreateConfigMgrInstall.IsPresent) {
      New-Item -Path $DrivePath -ItemType File -Force | Out-Null
      Write-Log "Created marker file '$fileName' for ConfigMgr Install on $($driveLetter):\" 'INFO'
    }
    if ($CreateSCCMContentLibrary.IsPresent) {
      New-Item -Path "$($driveLetter):\wsus" -ItemType Directory -Force | Out-Null
      Write-Log "Created directory '$($driveLetter):\wsus' for SCCM Content Library on $($driveLetter):\" 'INFO'
    }

    Write-Log "Storage workflow completed successfully." 'INFO'
  }
  catch {
    Write-Log "An error occurred: $_" 'ERROR'
    throw
  }
  finally {
    New-Item -Path C:\no_sms_on_drive.sms -ItemType File -Force | Out-Null
    Write-Log "Created marker file 'C:\no_sms_on_drive.sms' to prevent SCCM installation on C: drive." 'INFO'
    Write-Log "Storage workflow finished." 'INFO'
  }
}
#endregion

#region Public Functions
function Invoke-ConfigMgrStorageCreation {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$StoragePoolFriendlyName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$VirtualHardDiskFriendlyName,
    [Parameter(Mandatory)][ValidateSet('ConfigMgr Install', 'SCCM SQL MDF', 'SCCM SQL LDF', 'TempDB', 'SQL WSUS DB', 'SCCM APPLICATION SOURCES', 'SCCM CONTENT LIBRARY')][string]$FileSystemLabel,
    [switch]$CreateConfigMgrInstall,
    [switch]$CreateSCCMSQLMDF,
    [switch]$CreateSCCMSQLLDF,
    [switch]$CreateSCCMTempDB,
    [switch]$CreateSCCMSQLWSUSDB,
    [switch]$CreateSCCMApplicationSources,
    [switch]$CreateSCCMContentLibrary,
    [ValidateSet('Simple', 'Mirror', 'Parity')][string]$ResiliencySettingName = 'Simple',
    [ValidateSet('Fixed', 'Thin')][string]$ProvisioningType = 'Fixed',
    [int64]$SizeGB
  )
  if ($CreateConfigMgrInstall.IsPresent -and $CreateSCCMSQLMDF.IsPresent -and $CreateSCCMSQLLDF.IsPresent -and $CreateSCCMTempDB.IsPresent -and $CreateSCCMSQLWSUSDB.IsPresent -and $CreateSCCMApplicationSources.IsPresent -and $CreateSCCMContentLibrary.IsPresent) {
    Write-Log "All storage creation switches cannot be used together." 'ERROR'
    throw "Invalid operation: Multiple storage types must be created in separate operations."
  }
  Write-Log "Invoke-ConfigMgrStorageCreation starting for $FileSystemLabel..." 'INFO'
  try {
    $params = @{
      StoragePoolFriendlyName     = $StoragePoolFriendlyName
      VirtualHardDiskFriendlyName = $VirtualHardDiskFriendlyName
      FileSystemLabel             = $FileSystemLabel
      ResiliencySettingName       = $ResiliencySettingName
      ProvisioningType            = $ProvisioningType
    }
    if($PSBoundParameters.ContainsKey('SizeGB')) {
      $params['SizeGB'] = $SizeGB
    }
    foreach($switchName in @('CreateConfigMgrInstall', 'CreateSCCMSQLMDF', 'CreateSCCMSQLLDF', 'CreateSCCMTempDB', 'CreateSCCMSQLWSUSDB', 'CreateSCCMApplicationSources', 'CreateSCCMContentLibrary', 'CreateFileonly')) {
      if($PSBoundParameters.ContainsKey($switchName)) {
        $params[$switchName] = $PSBoundParameters[$switchName]
      }
    }
    if ($PSCmdlet.ShouldProcess("Storage Creation for $FileSystemLabel", "Create or reuse storage pool and virtual disk")) {
      New-Storage @params
      Write-Log "Storage creation for $FileSystemLabel completed successfully." 'INFO'
    }
  }
  catch {
    Write-Log "An error occurred: $_" 'ERROR'
    throw
  }
  finally {
    New-Item -Path C:\no_sms_on_drive.sms -ItemType File -Force | Out-Null
    Write-Log "Created marker file 'C:\no_sms_on_drive.sms' to prevent SCCM installation on C: drive." 'INFO'
    Write-Log "Invoke-ConfigMgrStorageCreation finished." 'INFO'
  }
}
#endregion