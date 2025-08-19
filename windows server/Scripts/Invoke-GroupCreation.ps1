$ErrorActionPreference = 'Stop'
$Global:LogFile = "$env:TEMP\GroupManagement_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

#region Logging Functions
function Write-Log {
  <#
    .SYNOPSIS
    Writes a message to the log file with timestamp and log level.
    #>
  param(
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

#region Pre-Flight Checks
function Test-GroupPrerequisites {
  <#
    .SYNOPSIS
    Performs pre-flight checks for group creation and membership management.
    #>
  param(
    [Parameter(Mandatory = $true)][string]$Path
  )
  Write-Log "Running pre-flight checks..." 'INFO'

  # Check for AD module
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory PowerShell module is not available. Please install RSAT tools." 'ERROR'
    throw "ActiveDirectory PowerShell module is not available. Please install RSAT tools."
  }
  Write-Log "ActiveDirectory module is available." 'DEBUG'

  # Check for admin privileges
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Log "Script must be run as administrator." 'ERROR'
    throw "Script must be run as administrator."
  }
  Write-Log "Administrative privileges confirmed." 'DEBUG'

  # Simple regex for DN format
  if ($Path -notmatch '^((OU|DC)=[^,]+,)*((OU|DC)=[^,]+)$') {
    Write-Log "The Path parameter must be in the format 'OU=...,DC=...,DC=...'" 'ERROR'
    throw "The Path parameter must be in the format 'OU=...,DC=...,DC=...'"
  }
  Write-Log "Path format validated: $Path" 'DEBUG'
  Write-Log "Pre-flight checks passed." 'INFO'
}

function Test-ADModuleAndAdmin {
  <#
    .SYNOPSIS
    Checks AD module and admin; used for membership management
    #>
  Write-Log "Running pre-flight checks for group membership update..." 'INFO'
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory PowerShell module is not available. Please install RSAT tools." 'ERROR'
    throw "ActiveDirectory PowerShell module is not available. Please install RSAT tools."
  }
  Write-Log "ActiveDirectory module is available." 'DEBUG'
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Log "Script must be run as administrator." 'ERROR'
    throw "Script must be run as administrator."
  }
  Write-Log "Administrative privileges confirmed." 'DEBUG'
  Write-Log "Pre-flight checks passed." 'INFO'
}
#endregion

#region Group Creation Functions
function New-Group {
  <#
    .SYNOPSIS
    Creates a new Active Directory group with validation and error handling.
    .PARAMETER Name
        The name of the group to create.
    .PARAMETER Path
        The distinguished name (DN) path where the group will be created.
    .PARAMETER GroupCategory
        The category of the group. Supports 'Security' or 'Distribution'.
    .PARAMETER GroupScope
        The scope of the group. Supports 'Global', 'DomainLocal', or 'Universal'.
    .PARAMETER DisplayName
        The display name of the group.
    .PARAMETER SamAccountName
        The sAMAccountName of the group.
    .PARAMETER Description
        The description of the group.
    .EXAMPLE
        New-Group -Name "MyGroup" -Path "OU=Groups,DC=contoso,DC=com"
    #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
    [string]$Name,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
    [string]$Path,
    [Parameter()][ValidateSet('Security', 'Distribution')]
    [string]$GroupCategory = 'Security',
    [Parameter()][ValidateSet('Global', 'DomainLocal', 'Universal')]
    [string]$GroupScope = 'Global',
    [Parameter()][string]$DisplayName,
    [Parameter()][string]$SamAccountName,
    [Parameter()][string]$Description
  )
  Test-GroupPrerequisites -Path $Path

  Write-Log "Checking if group '$Name' exists at '$Path'..." 'INFO'
  if (Get-ADGroup -Filter "Name -eq '$Name'" -SearchBase $Path -ErrorAction SilentlyContinue) {
    Write-Log "Group '$Name' already exists." 'ERROR'
    throw "Group '$Name' already exists."
  }

  $createParams = @{
    Name          = $Name
    Path          = $Path
    GroupCategory = $GroupCategory
    GroupScope    = $GroupScope
  }
  if ($PSBoundParameters.ContainsKey('Description')) { $createParams['Description'] = $Description }
  if ($PSBoundParameters.ContainsKey('DisplayName')) { $createParams['DisplayName'] = $DisplayName }
  if ($PSBoundParameters.ContainsKey('SamAccountName')) { $createParams['SamAccountName'] = $SamAccountName }

  try {
    if ($PSCmdlet.ShouldProcess($Name, 'Create a new group')) {
      Write-Log "Creating group '$Name' in '$Path'..." 'INFO'
      $result = New-ADGroup @createParams
      Write-Log "Successfully created group '$Name'." 'INFO'
      return $result
    }
  }
  catch {
    Write-Log "Failed to create group '$Name' in '$Path'. Error: $($_ | Out-String)" 'ERROR'
    throw "Failed to create group '$Name' in '$Path'. Error: $($_.Exception.Message)"
  }
}
#endregion

#region Group creation helper functions
function Invoke-GroupCreation {
  <#
    .SYNOPSIS
    Helper to invoke group creation with logging and error handling.
    .PARAMETER GroupName
        The group name to create.
    .PARAMETER Path
        The DN path where to create the group.
    .PARAMETER GroupCategory
        The group category. Default is 'Security'.
    .PARAMETER GroupScope
        The group scope. Default is 'Global'.
    .PARAMETER DisplayName
        Optional display name.
    .PARAMETER SamAccountName
        Optional sAMAccountName.
    .PARAMETER Description
        Optional description.
    .EXAMPLE
        Invoke-GroupCreation -GroupName "MyGroup" -Path "OU=Groups,DC=contoso,DC=com"
    #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true)]
    [string]$GroupName,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
    [string]$Path,
    [Parameter()][ValidateSet('Security', 'Distribution')]
    [string]$GroupCategory = 'Security',
    [Parameter()][ValidateSet('Global', 'DomainLocal', 'Universal')]
    [string]$GroupScope = 'Global',
    [Parameter()][string]$DisplayName,
    [Parameter()][string]$SamAccountName,
    [Parameter()][string]$Description
  )
  Write-Log -Message "Invoking group creation for '$GroupName' at '$Path'..." -Level 'INFO'
  try {
    if ($PSCmdlet.ShouldProcess($GroupName, "Create group at $Path")) {
      $params = @{
        Name          = $GroupName
        Path          = $Path
        GroupCategory = $GroupCategory
        GroupScope    = $GroupScope
      }
      if ($PSBoundParameters.ContainsKey('Description')) { $params['Description'] = $Description }
      if ($PSBoundParameters.ContainsKey('DisplayName')) { $params['DisplayName'] = $DisplayName }
      if ($PSBoundParameters.ContainsKey('SamAccountName')) { $params['SamAccountName'] = $SamAccountName }
      $results = New-Group @params
      Write-Log -Message "Successfully created group '$GroupName' at '$Path'." -Level 'INFO'
      return $results
    }
  }
  catch {
    Write-Log -Message "Failed to create group '$GroupName' at '$Path'. Error: $($_ | Out-String)" -Level 'ERROR'
    return $null
  }
}
#endregion

#region Group Management Functions
# List of privileged security groups as a global variable for easy maintenance
$Global:PrivilegedSecurityGroups = @(
  'Domain Admins',
  'Enterprise Admins',
  'Group Policy Creator Owners',
  'Schema Admins'
)

function Update-ADPrincipalGroupMembership {
  <#
    .SYNOPSIS
    Adds or removes a group to/from one or more privileged security groups.
    .PARAMETER GroupName
        The group to add/remove as a member.
    .PARAMETER SecurityGroup
        One or more privileged group(s) to update. Defaults to all privileged groups if not specified.
    .PARAMETER Add
        Switch to add group.
    .PARAMETER Remove
        Switch to remove group.
    .EXAMPLE
        Update-ADPrincipalGroupMembership -GroupName "Helpdesk" -Add
        Update-ADPrincipalGroupMembership -GroupName "Helpdesk" -SecurityGroup "Domain Admins" -Remove
    #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
    [string]$GroupName,
    [Parameter()][string[]]$SecurityGroup = $Global:PrivilegedSecurityGroups,
    [Parameter(Mandatory = $true, ParameterSetName = 'Add')]
    [switch]$Add,
    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [switch]$Remove
  )
  Test-ADModuleAndAdmin

  foreach ($secGroup in $SecurityGroup) {
    Write-Log "Validating existence of group '$GroupName' and security group '$secGroup'..." 'INFO'
    try {
      $targetGroup = Get-ADGroup -Identity $secGroup -ErrorAction Stop
      $memberGroup = Get-ADGroup -Identity $GroupName -ErrorAction Stop
    }
    catch {
      Write-Log "Group '$secGroup' or '$GroupName' not found. Skipping. Error: $($_ | Out-String)" 'WARN'
      continue
    }

    if ($Add.IsPresent) {
      # Defensive: Check if already a member
      $alreadyMember = Get-ADGroupMember -Identity $targetGroup | Where-Object { $_.DistinguishedName -eq $memberGroup.DistinguishedName }
      if ($alreadyMember) {
        Write-Log "'$GroupName' is already a member of '$secGroup'. Skipping add." 'WARN'
        continue
      }
      if ($PSCmdlet.ShouldProcess($GroupName, "Add to $secGroup")) {
        try {
          Write-Log "Adding group '$GroupName' to '$secGroup'..." 'INFO'
          Add-ADGroupMember -Identity $targetGroup -Members $memberGroup
          Write-Log "Added '$GroupName' to '$secGroup'." 'INFO'
          Write-Output "Added '$GroupName' to '$secGroup'"
        }
        catch {
          Write-Log "Failed to add group '$GroupName' to '$secGroup'. Error: $($_ | Out-String)" 'ERROR'
          throw "Failed to add group '$GroupName' to '$secGroup'. Error: $($_.Exception.Message)"
        }
      }
    }
    elseif ($Remove.IsPresent) {
      # Defensive: Check if not a member
      $isMember = Get-ADGroupMember -Identity $targetGroup | Where-Object { $_.DistinguishedName -eq $memberGroup.DistinguishedName }
      if (-not $isMember) {
        Write-Log "'$GroupName' is not a member of '$secGroup'. Skipping remove." 'WARN'
        continue
      }
      if ($PSCmdlet.ShouldProcess($GroupName, "Remove from $secGroup")) {
        try {
          Write-Log "Removing group '$GroupName' from '$secGroup'..." 'INFO'
          Remove-ADGroupMember -Identity $targetGroup -Members $memberGroup
          Write-Log "Removed '$GroupName' from '$secGroup'." 'INFO'
          Write-Output "Removed '$GroupName' from '$secGroup'"
        }
        catch {
          Write-Log "Failed to remove group '$GroupName' from '$secGroup'. Error: $($_ | Out-String)" 'ERROR'
          throw "Failed to remove group '$GroupName' from '$secGroup'. Error: $($_.Exception.Message)"
        }
      }
    }
  }
}
#endregion