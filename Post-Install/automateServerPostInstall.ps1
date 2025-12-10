<#
 # This script sets up logging for the Active Directory deployment process.
 # It enables optional features like RDP, static IP, DNS, IPv6 disablement, and default gateway routing.
 # Usage: Call Invoke-PostInstallTasks with the appropriate parameters.
#>

#region Import centralized logging module
$modulePath = Join-Path $PSScriptRoot '..\windows server\Modules\Logging.psm1'
Import-Module $modulePath -Force
Set-LogFilePath -Path "$env:TEMP\PostInstallTasks_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
#endregion

#region RDP Enablement
function Invoke-RDPEnablement {
  param(
    [string[]]$name = @('fDenyTSConnections', 'UserAuthentication'),
    [string[]]$Path = @(
      'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
      'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    ),
    [string[]]$Value = @('0', '1')
  )

  Write-Log "Enabling Remote Desktop Protocol (RDP)..."

  if (($name.Length -ne $Path.Length) -or ($name.Length -ne $Value.Length)) {
    Write-Log "Parameter arrays must be the same length." 'ERROR'
    return
  }

  try {
    for ($i = 0; $i -lt $name.Length; $i++) {
      if (Test-Path $Path[$i]) {
        $setItemParams = @{
          Path  = $Path[$i]
          Name  = $name[$i]
          Value = ([int]$Value[$i])
        }
        Set-ItemProperty @setItemParams
      }
      else {
        Write-Log "Registry path not found: $($Path[$i])" 'ERROR'
      }
    }
    Write-Log "RDP enabled successfully."
  }
  catch {
    Write-Log "Failed to enable RDP: $_" 'ERROR'
  }
  finally {
    Write-Log "Enabling RDP firewall rules..."
    try {
      $firewallParams = @{
        DisplayGroup = 'Remote Desktop'
        Enabled      = $true
        Action       = 'Allow'
        Profile      = 'Private'
        Direction    = 'Inbound'
      }
      Set-NetFirewallRule @firewallParams
      Write-Log "RDP firewall rules enabled successfully."
    }
    catch {
      Write-Log "Failed to enable RDP firewall rules: $_" 'ERROR'
    }

    try {
      Set-Service -Name TermService -StartupType Automatic
      Start-Service -Name TermService
      Write-Log "TermService started successfully."
    }
    catch {
      Write-Log "Failed to start TermService: $_" 'ERROR'
    }
  }
}
#endregion

#region Network Configuration
function Invoke-NetworkInterfaceConfigurations {
  param(
    [string]$InterfaceIndex = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).InterfaceIndex,
    [string]$IPAddress,
    [string]$PrefixLength,
    [string]$NextHop,
    [string]$DestinationPrefix,
    [string[]]$DnsServer,
    [switch]$AssignStaticIP,
    [switch]$DisableIPv6,
    [switch]$SetDnsServer,
    [switch]$RouteToInternet
  )

  Write-Log "Starting network interface configuration..."

  try {
    if ($AssignStaticIP.IsPresent) {
      if (-not $IPAddress -or -not $PrefixLength) {
        throw "AssignStaticIP was specified, but IPAddress or PrefixLength is missing."
      }

      Write-Log "Assigning static IP configuration..."
      
      # Idempotency check: Only assign if IP is not already configured
      $existingIP = Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
        Where-Object { $_.IPAddress -eq $IPAddress }
      
      if ($null -eq $existingIP) {
        $ipParams = @{
          IPAddress      = $IPAddress
          PrefixLength   = $PrefixLength
          InterfaceIndex = $InterfaceIndex
          ErrorAction    = 'Stop'
        }
        New-NetIPAddress @ipParams
        Write-Log "Static IP configuration applied to $IPAddress/$PrefixLength."
      }
      else {
        Write-Log "IP address $IPAddress is already configured on interface." 'INFO'
      }

      $IpConfig = Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $IPAddress }
      if ($null -eq $IpConfig) {
        Write-Log "Failed to validate IP assignment." 'ERROR'
      }
      else {
        Write-Log "IP address validation passed for $IPAddress."
      }
    }

    if ($RouteToInternet.IsPresent) {
      if (-not $NextHop) {
        throw "To use -RouteToInternet, you must also provide -NextHop."
      }

      if (-not $DestinationPrefix) {
        $DestinationPrefix = '0.0.0.0/0'
        Write-Log "No DestinationPrefix provided. Defaulting to $DestinationPrefix"
      }

      Write-Log "Checking for existing route to $DestinationPrefix..."
      $existingRoute = Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $DestinationPrefix -ErrorAction SilentlyContinue

      if ($null -ne $existingRoute) {
        Write-Log "Existing route found. Removing..."
        $removeRouteParams = @{
          Confirm     = $false
          ErrorAction = 'Stop'
        }
        $existingRoute | Remove-NetRoute @removeRouteParams
        Write-Log "Old route removed."
      }

      Write-Log "Adding route via $NextHop..."
      $routeParams = @{
        InterfaceIndex    = $InterfaceIndex
        NextHop           = $NextHop
        DestinationPrefix = $DestinationPrefix
        ErrorAction       = 'Stop'
      }
      New-NetRoute @routeParams
      Write-Log "Route to internet configured."
    }

    if ($SetDnsServer.IsPresent) {
      if (-not $DnsServer) {
        throw "SetDnsServer was specified but no DnsServer value provided."
      }

      Write-Log "Configuring DNS servers: $($DnsServer -join ', ')"
      
      # Idempotency check: Only set if DNS servers are different
      $currentDns = (Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4).ServerAddresses
      $dnsChanged = $false
      
      if ($null -eq $currentDns -or $currentDns.Count -ne $DnsServer.Count) {
        $dnsChanged = $true
      }
      else {
        for ($i = 0; $i -lt $DnsServer.Count; $i++) {
          if ($currentDns[$i] -ne $DnsServer[$i]) {
            $dnsChanged = $true
            break
          }
        }
      }
      
      if ($dnsChanged) {
        $dnsParams = @{
          InterfaceIndex  = $InterfaceIndex
          ServerAddresses = $DnsServer
          ErrorAction     = 'Stop'
        }
        Set-DnsClientServerAddress @dnsParams
        Write-Log "DNS configuration complete."
      }
      else {
        Write-Log "DNS servers are already configured correctly." 'INFO'
      }
    }

    if ($DisableIPv6.IsPresent) {
      Write-Log "Disabling IPv6..."
      $adapterName = (Get-NetAdapter -InterfaceIndex $InterfaceIndex).Name
      $bindingParams = @{
        Name        = $adapterName
        ComponentID = 'ms_tcpip6'
        Enabled     = $false
        ErrorAction = 'Stop'
      }
      Set-NetAdapterBinding @bindingParams
      Write-Log "IPv6 disabled on adapter $adapterName."
    }

  }
  catch {
    Write-Log "Network configuration error: $_" 'ERROR'
    throw
  }
  finally {
    Write-Log "Network interface configuration complete."
    $logPath = Get-LogFilePath
    Write-Log "Log file location: $logPath"
  }
}
#endregion

#region Post Install Orchestration
function Invoke-PostInstallTasks {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [string]$InterfaceIndex = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).InterfaceIndex,
    [Parameter(Mandatory = $false)]
    [string]$IPAddress,
    [Parameter(Mandatory = $false)]
    [string]$PrefixLength,
    [Parameter(Mandatory = $false)]
    [string]$NextHop,
    [Parameter(Mandatory = $false)]
    [string]$DestinationPrefix = '0.0.0.0/0',
    [Parameter(Mandatory = $false)]
    [string[]]$DnsServer,
    [switch]$AssignStaticIP,
    [switch]$DisableIPv6,
    [switch]$SetDnsServer,
    [switch]$RouteToInternet,
    [switch]$EnableRDP
  )

  Write-Log "Starting post-install tasks..."

  try {
    $networkParams = @{
      IPAddress         = $IPAddress
      PrefixLength      = $PrefixLength
      NextHop           = $NextHop
      DestinationPrefix = $DestinationPrefix
      DnsServer         = $DnsServer
    }
    foreach ($param in @('AssignStaticIP', 'DisableIPv6', 'SetDnsServer', 'RouteToInternet', 'InterfaceIndex', 'EnableRDP')) {
      if ($PSBoundParameters.ContainsKey($param)) {
        $networkParams[$param] = $PSBoundParameters[$param]
      }
    }

    Invoke-NetworkInterfaceConfigurations @networkParams
    Write-Log "Network interface configurations applied successfully."
    if ($AssignStaticIP.IsPresent) {
      Write-Log "Static IP assigned: $IPAddress/$PrefixLength"
    }
    else {
      Write-Log "Static IP assignment skipped."
    }

    if ($EnableRDP.IsPresent) {
      Invoke-RDPEnablement
      Write-Log "RDP enabled successfully."
    }
    else {
      Write-Log "RDP enablement skipped."
    }

    Write-Log "Post-install tasks completed successfully."
  }
  catch {
    Write-Log "Post-install tasks failed: $_" 'ERROR'
  }
  finally {
    Write-Log "All tasks finished."
  }
}
#endregion
# End of PostInstall.ps1

#region Post Install Function Invocation
try {
  $IPAddress = '192.168.3.3'
  $PrefixLength = '24'
  $NextHop = '192.168.3.1'
  $DestinationPrefix = '0.0.0.0/0'
  $DnsServer = @('192.168.3.1','127.0.0.1')

  $postInstallParams = @{
    IPAddress         = $IPAddress
    PrefixLength      = $PrefixLength
    NextHop           = $NextHop
    DestinationPrefix = $DestinationPrefix
    DnsServer         = $DnsServer
    AssignStaticIP    = $true
    DisableIPv6       = $true
    SetDnsServer      = $true
    RouteToInternet   = $true
    EnableRDP         = $true
  }
  
  Invoke-PostInstallTasks @postInstallParams
  Write-Log "Post-install tasks invoked successfully."
  $logPath = Get-LogFilePath
  Write-Host "Post-install tasks completed. Check the log file at $logPath for details." -ForegroundColor Green
}
catch {
  Write-Log "An error occurred during post-install tasks: $_" 'ERROR'
  $logPath = Get-LogFilePath
  Write-Host "An error occurred during post-install tasks. Please check the log file at $logPath for details." -ForegroundColor Red
  throw "Post-install tasks failed. Check the log file for more information."
}
finally {
  Write-Log "Post-install tasks completed."
  $logPath = Get-LogFilePath
  Write-Host "Post-install tasks completed. Log file created at: $logPath" -ForegroundColor Cyan
}
#endregion
