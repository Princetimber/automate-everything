function Write-Log {
  param(
    [Parameter(Mandatory)][string]$Message,
    [Parameter()][ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')][string]$Level = 'INFO'
  )
  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $entry = "[$timestamp] [$Level] $Message"
  Write-Host $entry
  try {
    Add-Content -Path "$env:TEMP\NewOU_$(Get-Date -Format 'yyyyMMdd').log" -Value $entry
  }
  catch {}
}

function Test-OUPrerequisites {
  param(
    [Parameter(Mandatory)][string]$Path
  )
  Write-Log "Running pre-flight checks for New-OrganizationalUnit..." 'INFO'
  # Check if ActiveDirectory module is available
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory PowerShell module is not available." 'ERROR'
    throw "ActiveDirectory PowerShell module is not available."
  }
  else {
    Write-Log "ActiveDirectory module is available." 'DEBUG'
  }
  # Check if running as admin
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Script is not running with administrative privileges." 'ERROR'
    throw "Please run this script as an administrator."
  }
  else {
    Write-Log "Administrative privileges confirmed." 'DEBUG'
  }
  # Check if Path is not empty and looks like a DN
  if ([string]::IsNullOrWhiteSpace($Path) -or ($Path -notmatch '^((OU|DC)=[^,]+,)*((OU|DC)=[^,]+)$')) {
    Write-Log "The Path parameter is not in the expected DN format." 'ERROR'
    throw "The Path parameter must be in the format 'OU=...,DC=...,DC=...'"
  }
  else {
    Write-Log "Path parameter validated: $Path" 'DEBUG'
  }
  Write-Log "Pre-flight checks passed." 'INFO'
}

function Test-OUExists {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Path
  )
  $exists = Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $Path -ErrorAction SilentlyContinue
  if ($exists) {
    Write-Log "Organizational unit '$Name' already exists at path '$Path'." 'ERROR'
    throw "Organizational unit '$Name' already exists at path '$Path'."
  }
}

function New-OrganizationalUnit {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
    [string]$Name,

    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter()][string]$Description,
    [Parameter()][string]$City,
    [Parameter()][ValidatePattern('^[A-Z]{2,3}$')][string]$Country,
    [Parameter()][ValidatePattern('^(^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$)|(^\d{5}(-\d{4})?$)')][string]$PostalCode,
    [Parameter()][ValidatePattern('^[A-Z][a-z]+$')][string]$State,
    [Parameter()][string]$StreetAddress,
    [Parameter()][string]$ManagedBy,
    [Parameter()][switch]$ProtectedFromAccidentalDeletion
  )

  process {
    try {
      Test-OUPrerequisites -Path $Path
      Test-OUExists -Name $Name -Path $Path

      $createParams = @{
        Name = $Name
        Path = $Path
      }
      if ($PSBoundParameters.ContainsKey('Description')) { $createParams['Description'] = $Description }
      if ($PSBoundParameters.ContainsKey('City')) { $createParams['City'] = $City }
      if ($PSBoundParameters.ContainsKey('Country')) { $createParams['Country'] = $Country }
      if ($PSBoundParameters.ContainsKey('PostalCode')) { $createParams['PostalCode'] = $PostalCode }
      if ($PSBoundParameters.ContainsKey('State')) { $createParams['State'] = $State }
      if ($PSBoundParameters.ContainsKey('StreetAddress')) { $createParams['StreetAddress'] = $StreetAddress }
      if ($PSBoundParameters.ContainsKey('ManagedBy')) { $createParams['ManagedBy'] = $ManagedBy }
      if ($ProtectedFromAccidentalDeletion.IsPresent) { $createParams['ProtectedFromAccidentalDeletion'] = $true }

      Write-Log "Creating Organizational Unit '$Name' at '$Path'..." 'INFO'
      $ou = New-ADOrganizationalUnit @createParams
      Write-Log "Organizational Unit '$Name' created successfully at '$Path'." 'INFO'
      return $ou
    }
    catch {
      Write-Log "Failed to create organizational unit '$Name' in '$Path'. Error: $($_.Exception.Message)" 'ERROR'
      throw "Failed to create organizational unit '$Name' in '$Path'. Error: $($_.Exception.Message)"
    }
  }
}