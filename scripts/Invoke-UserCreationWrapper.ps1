<#[
.SYNOPSIS
  Wrapper for Invoke-UserCreation to make execution more user-friendly.
.DESCRIPTION
  - Prompts the admin to select a CSV file via file picker.
  - Prompts for the OU (name or DN).
  - Prompts for a default account password.
  - Calls Invoke-UserCreation from your main script.
#>

# Import main script (make sure the path is correct)
. "$PSScriptRoot\UserCreation.ps1"

# Select CSV file via file picker
Add-Type -AssemblyName System.Windows.Forms
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.Filter = "CSV files (*.csv)|*.csv"
$OpenFileDialog.Title = "Select the CSV file containing user details"

if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $CsvFile = $OpenFileDialog.FileName
    Write-Host "Selected CSV file: $CsvFile"
} else {
    Write-Host "No file selected. Exiting."
    exit
}

# Prompt for OU (Name or DistinguishedName)
$OUIdentifier = Read-Host "Enter the OU (e.g., 'TestOU' or 'OU=TestOU,DC=contoso,DC=com')"

# Prompt for password
$Password = Read-Host "Enter a default password for all new accounts" -AsSecureString

# Confirm execution
Write-Host "`nReady to create users from: $CsvFile in OU: $OUIdentifier"
$confirm = Read-Host "Proceed? (Y/N)"
if ($confirm -ne 'Y') {
    Write-Host "Aborted by user."
    exit
}

# Run with progress bar
Write-Host "`nStarting user creation..."
Invoke-UserCreation -CsvFilePath $CsvFile -OUIdentifier $OUIdentifier -AccountPassword $Password -Verbose
Write-Host "`nProcess complete. Log file saved to: $Global:LogFile"