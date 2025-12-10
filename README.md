# automate-everything

This repository contains PowerShell scripts and modules to automate and configure various aspects of Windows infrastructure. It is designed to help administrators streamline deployment, configuration, and post-installation tasks for Windows Server environments.

---

## Features

- **Active Directory automation:**  
  Automated installation, configuration, and post-installation of AD DS and related components.

- **Centralized Logging:**  
  Consistent logging across all modules using the centralized `Logging.psm1` module with support for multiple log levels (INFO, DEBUG, WARN, ERROR).

- **Storage automation:**  
  Scripts and modules for preparing, configuring, and securing storage pools and volumes.

- **User and Group Management:**  
  Tools for bulk user and group creation, management, and access control.

- **Post-Install Tasks:**  
  Automated tasks to finalize server setup after OS and role installation with idempotency checks.

- **SecretManagement Integration:**  
  Support for secure credential handling using PowerShell SecretManagement module.

- **Pre-flight/Prerequisite Checks:**  
  Thorough validation for required privileges, modules/features, and input data before making changes.

- **Pester Test Coverage:**  
  Unit tests included for critical modules and helper functions.

- **Continuous Integration:**  
  Automated testing with GitHub Actions on every push and pull request.

---

## Directory Structure

```
.github/
  workflows/
    pester.yml          # CI workflow for automated Pester testing
windows server/
  Modules/
    Logging.psm1        # Centralized logging module
    automateADInstall.psm1
    automatestorage.psm1
  Pester/
    automateADInstall.Tests.ps1
  PostInstall/
    Invoke-PostInstallTasks.ps1
  Scripts/
    Invoke-GroupCreation.ps1
    Invoke-UserCreation.ps1
Post-Install/
  automateServerPostInstall.ps1
GEMINI.md
README.md
```

---

## Prerequisites

- **Windows Server 2016 or later**
- **PowerShell 5.1+** (PowerShell 7+ recommended)
- **RSAT / Active Directory Module for Windows PowerShell**
- **Administrator privileges** for most operations
- **PowerShell Modules:**
  - `Microsoft.PowerShell.SecretManagement` (optional, for secure credential handling)
  - `Pester` (for running tests)

---

## Usage

### Import Modules

```powershell
# Import the centralized logging module
Import-Module ".\windows server\Modules\Logging.psm1" -Force

# Import the AD installation module
Import-Module ".\windows server\Modules\automateADInstall.psm1" -Force
```

### Centralized Logging

The `Logging.psm1` module provides consistent logging across all scripts:

```powershell
# Set a custom log file path
Set-LogFilePath -Path "C:\Logs\MyDeployment.log"

# Write log entries
Write-Log "Starting deployment process" -Level INFO
Write-Log "Configuration validated" -Level DEBUG
Write-Log "Non-critical issue detected" -Level WARN
Write-Log "Critical error occurred" -Level ERROR

# Get current log file path
$logPath = Get-LogFilePath
```

### Active Directory Deployment with Splatting

Using parameter splatting for cleaner, more maintainable code:

```powershell
# Create a new AD DS Forest
$forestParams = @{
    DomainName                    = "contoso.local"
    DomainNetBiosName             = "CONTOSO"
    SafeModeAdministratorPassword = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
    DomainMode                    = "Win2019"
    ForestMode                    = "Win2019"
    DatabasePath                  = "C:\Windows"
    LogPath                       = "C:\Windows\NTDS"
    SYSVOLPath                    = "C:\Windows"
    InstallDNS                    = $true
    Force                         = $true
}

Invoke-ADDSForest @forestParams
```

### Using SecretManagement for Secure Credentials

```powershell
# Install and configure SecretManagement
Install-Module Microsoft.PowerShell.SecretManagement -Force
Install-Module Microsoft.PowerShell.SecretStore -Force

# Register a secret vault
Register-SecretVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

# Store a secret
$password = Read-Host -AsSecureString -Prompt "Enter Safe Mode password"
Set-Secret -Name ADSafeModePassword -Secret $password -Vault LocalStore

# Retrieve and use the secret
$safeModePassword = Get-Secret -Name ADSafeModePassword -Vault LocalStore -AsSecureString

$forestParams = @{
    DomainName                    = "contoso.local"
    SafeModeAdministratorPassword = $safeModePassword
    DomainMode                    = "Default"
    ForestMode                    = "Default"
    InstallDNS                    = $true
}

Invoke-ADDSForest @forestParams
```

### Post-Install Tasks with Splatting

```powershell
# Configure network settings
$networkParams = @{
    IPAddress         = '192.168.1.100'
    PrefixLength      = '24'
    NextHop           = '192.168.1.1'
    DnsServer         = @('192.168.1.1', '8.8.8.8')
    AssignStaticIP    = $true
    SetDnsServer      = $true
    RouteToInternet   = $true
    DisableIPv6       = $true
    EnableRDP         = $true
}

.\Post-Install\automateServerPostInstall.ps1
# Or call Invoke-PostInstallTasks @networkParams if imported as a module
```

### Bulk User Creation

```powershell
.\windows server\Scripts\Invoke-UserCreation.ps1 -CsvFilePath .\users.csv
```

### Bulk Group Creation

```powershell
.\windows server\Scripts\Invoke-GroupCreation.ps1 -CsvFilePath .\groups.csv
```

### Run Pester Tests

```powershell
# Install Pester if not already installed
Install-Module -Name Pester -Force -SkipPublisherCheck

# Run all tests
Invoke-Pester -Path ".\windows server\Pester"

# Run with detailed output
$config = New-PesterConfiguration
$config.Run.Path = "windows server/Pester"
$config.Output.Verbosity = "Detailed"
Invoke-Pester -Configuration $config
```

---

## Continuous Integration

This repository includes a GitHub Actions workflow that automatically runs Pester tests on:
- Every push to the `main` branch
- Every pull request to the `main` branch
- Pushes to branches matching `copilot/**`

The workflow:
1. Runs on `windows-latest` GitHub-hosted runners
2. Installs the latest version of Pester
3. Executes all tests in `windows server/Pester`
4. Uploads test results as artifacts

View the workflow file at `.github/workflows/pester.yml`.

---

## Valid AD DS Domain/Forest Modes

The following values are supported for `DomainMode` and `ForestMode` parameters:
- `Default` - Uses the default mode for the current OS version
- `Win2008` - Windows Server 2008
- `Win2008R2` - Windows Server 2008 R2
- `Win2012` - Windows Server 2012
- `Win2012R2` - Windows Server 2012 R2
- `Win2016` - Windows Server 2016
- `Win2019` - Windows Server 2019
- `Win2022` - Windows Server 2022

---

## Logging

- All scripts produce log files in your `%TEMP%` directory by default, named with the script/module and timestamp.
- You can set a custom log file path using `Set-LogFilePath`.
- Examine log files for detailed execution steps, warnings, and errors.
- Log entries include timestamps and severity levels for easy troubleshooting.

---

## Contributing

Contributions are welcome! Please submit issues or pull requests for improvements, bug fixes, or new automation scenarios.

---

## License

[MIT License](LICENSE)

---

## Support

For questions, issues, or feature requests, please open an issue in this repository.

---

**Thank you for using `automate-everything`!**
