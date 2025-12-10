<#
.SYNOPSIS
Centralized logging module for PowerShell scripts.

.DESCRIPTION
Provides consistent logging functionality across all scripts and modules.
Supports setting a custom log file path and writing log entries with different levels.
#>

$ErrorActionPreference = 'Stop'

# Module-scoped variable for the log file path
$script:LogFilePath = $null

function Set-LogFilePath {
  <#
  .SYNOPSIS
  Sets the log file path for the current session.
  
  .DESCRIPTION
  Sets the module-scoped log file path that will be used by Write-Log.
  
  .PARAMETER Path
  The full path to the log file.
  
  .EXAMPLE
  Set-LogFilePath -Path "C:\Logs\MyScript.log"
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )
  
  $script:LogFilePath = $Path
  Write-Verbose "Log file path set to: $Path"
}

function Get-LogFilePath {
  <#
  .SYNOPSIS
  Gets the current log file path.
  
  .DESCRIPTION
  Returns the current log file path. If not set, returns a default path.
  
  .EXAMPLE
  $logPath = Get-LogFilePath
  #>
  [CmdletBinding()]
  param ()
  
  if (-not $script:LogFilePath) {
    $script:LogFilePath = "$env:TEMP\PowerShellLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
  }
  
  return $script:LogFilePath
}

function Write-Log {
  <#
  .SYNOPSIS
  Writes a message to the log file with timestamp and log level.
  
  .DESCRIPTION
  Supports multiple log levels: INFO, DEBUG, WARN, ERROR.
  Automatically writes to the configured log file path.
  
  .PARAMETER Message
  The message to write to the log.
  
  .PARAMETER Level
  The log level (INFO, DEBUG, WARN, ERROR). Default is INFO.
  
  .EXAMPLE
  Write-Log "Starting process" -Level INFO
  
  .EXAMPLE
  Write-Log "An error occurred" -Level ERROR
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$Message,
    
    [Parameter()]
    [ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')]
    [string]$Level = 'INFO'
  )
  
  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $entry = "[$timestamp] [$Level] $Message"
  $logPath = Get-LogFilePath
  
  Add-Content -Path $logPath -Value $entry
  
  if ($Level -eq 'ERROR') { 
    Write-Error $Message 
  }
  elseif ($Level -eq 'WARN') { 
    Write-Warning $Message 
  }
  elseif ($Level -eq 'DEBUG') { 
    Write-Verbose $Message 
  }
  else { 
    Write-Host $Message 
  }
}

# Export module members
Export-ModuleMember -Function Set-LogFilePath, Get-LogFilePath, Write-Log
