$ErrorActionPreference = "Stop"
# This will stop the script if any command fails

#region Logging Setup
$Global:LogFile = "$env:TEMP\USERCREATION_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"

function Write-Log {
  <#
  .SYNOPSIS
    Writes a message to the log file with timestamp and log level.
  .DESCRIPTION
    Supports multiple log levels: INFO, WARNING, ERROR, DEBUG.
  #>
  param (
    [Parameter(Mandatory)][string]$Message,
    [Parameter()][ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')][string]$Level = 'INFO'
  )
  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $entry = "[$timestamp] [$Level] $Message"
  Add-Content -Path $Global:LogFile -Value $entry

  switch ($Level) {
    'ERROR' { Write-Error $Message }
    'WARN'  { Write-Warning $Message }
    'DEBUG' { Write-Verbose $Message }
    Default { Write-Host $Message }
  }
}
#endregion

#region Pre-flight Checks
function Test-UserCreationPrerequisites {
  param(
    [Parameter(Mandatory)][string]$CsvFilePath,
    [Parameter(Mandatory)][string]$OUIdentifier
  )
  Write-Log -Message "Running pre-flight checks..." -Level 'INFO'

  # Check for AD module
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log -Message "ActiveDirectory PowerShell module is not available. Please install RSAT tools." -Level 'ERROR'
    throw "ActiveDirectory PowerShell module is not available. Please install RSAT tools."
  }
  Write-Log -Message "ActiveDirectory module is available." -Level 'DEBUG'

  # Check for admin privileges
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Log -Message "Script must be run as administrator." -Level 'ERROR'
    throw "Script must be run as administrator."
  }
  Write-Log -Message "Administrative privileges confirmed." -Level 'DEBUG'

  # Check CSV file
  if (-not (Test-Path $CsvFilePath)) {
    Write-Log -Message "CSV file not found: $CsvFilePath" -Level 'ERROR'
    throw "CSV file not found: $CsvFilePath"
  }
  Write-Log -Message "CSV file found: $CsvFilePath" -Level 'DEBUG'

  # Check CSV schema
  $requiredHeaders = @('GivenName','Surname','SamAccountName')
  $csvHeaders = (Get-Content $CsvFilePath -First 1).Split(',')
  foreach ($h in $requiredHeaders) {
    if ($h -notin $csvHeaders) {
      Write-Log -Message "Missing required column in CSV: $h" -Level 'ERROR'
      throw "CSV file missing required column: $h"
    }
  }
  Write-Log -Message "CSV schema validated." -Level 'DEBUG'

  # Check OU
  if ($OUIdentifier -match '^OU=.*') {
    $ou = Get-ADOrganizationalUnit -Identity $OUIdentifier -ErrorAction SilentlyContinue
  } else {
    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OUIdentifier'" -ErrorAction SilentlyContinue
  }
  if (-not $ou) {
    Write-Log -Message "Organizational Unit not found: $OUIdentifier" -Level 'ERROR'
    throw "Organizational Unit not found: $OUIdentifier"
  }
  Write-Log -Message "Organizational Unit validated: $($ou.DistinguishedName)" -Level 'DEBUG'
}
#endregion

#region Import Csv files that contains users
function Import-UsersFromCsv {
  <#
  .SYNOPSIS
    Imports users from a CSV file.
  .DESCRIPTION
    The CSV file should contain headers like 'GivenName', 'Surname', 'SamAccountName'.
  #>
  param (
    [Parameter(Mandatory)][string]$CsvFilePath
  )

  $users = Import-Csv -Path $CsvFilePath
  if (-not $users) {
    Write-Log -Message "No users found in CSV file: $CsvFilePath" -Level 'ERROR'
    return $null
  }
  Write-Log -Message "$($users.Count) users loaded from CSV." -Level 'INFO'
  return $users
}
#endregion

#region User Creation
function New-User {
  param(
    [Parameter(Mandatory)][string]$OUIdentifier,
    [Parameter(Mandatory)][SecureString]$AccountPassword,
    [Parameter(Mandatory)][string]$CsvFilePath
  )

  $domain = (Get-ADDomain).DNSRoot
  if ($OUIdentifier -match '^OU=.*') {
    $ou = Get-ADOrganizationalUnit -Identity $OUIdentifier
  } else {
    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OUIdentifier'"
  }

  Write-Log -Message "Importing users from CSV: $CsvFilePath" -Level 'INFO'
  $users = Import-UsersFromCsv -CsvFilePath $CsvFilePath
  if (-not $users) {
    throw "No users to create from CSV."
  }

  foreach ($user in $users) {
    try {
      $sam = $user.SamAccountName
      $upn = "$($user.SamAccountName)@$domain"
      $name = "$($user.GivenName) $($user.Surname)"

      # Existence check by SamAccountName
      if (-not (Get-ADUser -Filter {SamAccountName -eq $sam} -ErrorAction SilentlyContinue)) {
        $param = @{
          Name                   = $name
          GivenName              = $user.GivenName
          Surname                = $user.Surname
          DisplayName            = $name
          SamAccountName         = $sam
          UserPrincipalName      = $upn
          AccountPassword        = $AccountPassword
          Path                   = $ou.DistinguishedName
          Company                = $user.Company
          Department             = $user.Department
          Enabled                = $true
          ChangePasswordAtLogon  = $true
          KerberosEncryptionType = "AES256"
        }
        Write-Log -Message "Creating user: $sam" -Level 'INFO'
        New-ADUser @param
        Write-Log -Message "User created successfully: $sam" -Level 'INFO'
      }
      else {
        Write-Log -Message "User already exists: $sam" -Level 'WARN'
      }
    }
    catch {
      Write-Log -Message "Failed to create user $($user.SamAccountName): $_" -Level 'ERROR'
    }
  }
}
#endregion

#region User Creation Invocation
function Invoke-UserCreation {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param (
    [Parameter(Mandatory)][string]$CsvFilePath,
    [Parameter(Mandatory)][string]$OUIdentifier,
    [Parameter(Mandatory)][SecureString]$AccountPassword
  )
  Write-Log -Message "Starting user creation process" -Level 'INFO'
  try {
    Test-UserCreationPrerequisites -CsvFilePath $CsvFilePath -OUIdentifier $OUIdentifier
    if ($PSCmdlet.ShouldProcess("Creating users from: $CsvFilePath")) {
      New-User -OUIdentifier $OUIdentifier -AccountPassword $AccountPassword -CsvFilePath $CsvFilePath
    }
  }
  catch {
    Write-Log -Message "Failed to create users: $_" -Level 'ERROR'
    throw
  }
}
#endregion
