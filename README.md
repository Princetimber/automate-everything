# automate-everything

This repository contains PowerShell scripts and modules to automate and configure various aspects of Windows infrastructure. It is designed to help administrators streamline deployment, configuration, and post-installation tasks for Windows Server environments.

---

## Features

- **Active Directory automation:**  
  Automated installation, configuration, and post-installation of AD DS and related components.

- **Storage automation:**  
  Scripts and modules for preparing, configuring, and securing storage pools and volumes.

- **User and Group Management:**  
  Tools for bulk user and group creation, management, and access control.

- **Post-Install Tasks:**  
  Automated tasks to finalize server setup after OS and role installation.

- **Logging and Error Handling:**  
  Consistent, timestamped logging with multiple log levels (INFO, WARN, ERROR, DEBUG) for all major scripts.

- **Pre-flight/Prerequisite Checks:**  
  Thorough validation for required privileges, modules/features, and input data before making changes.

- **Pester Test Coverage:**  
  Unit tests included for critical modules and helper functions.

---

## Directory Structure

```
windows server/
  Modules/
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
- **PowerShell 5.1+**
- **RSAT / Active Directory Module for Windows PowerShell**
- **Administrator privileges** for most operations

---

## Usage

### Import a Module

```powershell
Import-Module "windows server/Modules/automateADInstall.psm1" -Force
```

### Run a Script

```powershell
# Example: Run post-install tasks
.\windows server\PostInstall\Invoke-PostInstallTasks.ps1
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
Invoke-Pester -Script .\windows server\Pester\automateADInstall.Tests.ps1
```

---

## Logging

- All scripts produce log files in your `%TEMP%` directory, named with the script/module and timestamp.
- Examine log files for detailed execution steps, warnings, and errors.

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
