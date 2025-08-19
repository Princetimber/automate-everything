#region Logging Setup
$Global:LogFile = "$env:TEMP\PostInstallTasks_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
  param (
    [string]$Message,
    [string]$Level = 'INFO'
  )
  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $entry = "[$timestamp] [$Level] $Message"
  Add-Content -Path $Global:LogFile -Value $entry
  if ($Level -eq 'ERROR') { Write-Error $Message }
  elseif ($Level -eq 'WARN') { Write-Warning $Message }
  else { Write-Verbose $Message }
}
#endregion

#region Preflight Checks
function Invoke-PreflightChecks {
  Write-Log "Starting preflight checks..." 'INFO'

  # Check for Administrator privileges
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Script is not running with Administrator privileges." 'ERROR'
    throw "Administrator privileges are required to run this script."
  }
  else {
    Write-Log "Administrator privileges confirmed." 'INFO'
  }

  # Check required modules
  $requiredModules = @("ActiveDirectory", "DnsServer", "BestPractices", "CimCmdlets")
  foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
      Write-Log "Required module '$module' is not available." 'ERROR'
      throw "Required module '$module' is not installed."
    }
    else {
      Write-Log "Module '$module' is available." 'INFO'
    }
  }

  # Check network connectivity
  $testDns = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet
  if (-not $testDns) {
    Write-Log "Network connectivity check failed (unable to reach 8.8.8.8)." 'ERROR'
    throw "Network connectivity check failed."
  }
  else {
    Write-Log "Network connectivity confirmed (able to reach 8.8.8.8)." 'INFO'
  }

  # Check if AD DS role is installed
  $adDsInstalled = Get-WindowsFeature -Name AD-Domain-Services | Where-Object { $_.InstallState -eq 'Installed' }
  if (-not $adDsInstalled) {
    Write-Log "Active Directory Domain Services role is not installed." 'ERROR'
    throw "Active Directory Domain Services role must be installed."
  }
  else {
    Write-Log "Active Directory Domain Services role is installed." 'INFO'
  }

  # Check for required commands
  $requiredCmdlets = @("Get-NetIPAddress", "Set-DNSClientServerAddress", "Add-DnsServerPrimaryZone", "Enable-ADOptionalFeature")
  foreach ($cmdlet in $requiredCmdlets) {
    if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
      Write-Log "Required cmdlet '$cmdlet' is not available." 'ERROR'
      throw "Required cmdlet '$cmdlet' is missing."
    }
    else {
      Write-Log "Cmdlet '$cmdlet' is available." 'INFO'
    }
  }

  # Check if Recycle Bin Feature is installed
  $forest = Get-ADForest
  $forestDN = $forest.DistinguishedName
  $recycleBinFeature = Get-ADOptionalFeature -Filter 'name -eq "Recycle Bin Feature"'
  $enabled = $recycleBinFeature.EnabledScopes -contains $forestDN
  if ($enabled) {
    Write-Log "Recycle Bin Feature is already enabled for forest $($forest.Name)." 'INFO'
  }
  else {
    Write-Log "Recycle Bin Feature is not enabled for forest $($forest.Name). It will be enabled during setup if requested." 'WARN'
  }

  Write-Log "Preflight checks completed successfully." 'INFO'
}
#endregion

#region NetworkCIDR

function Get-NetworkCIDR {
  # Get first valid IPv4 address (not loopback, not APIPA)
  $ipObj = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*'
  } | Select-Object -First 1

  if (-not $ipObj) {
    Write-Output "No valid IPv4 address found."
    return
  }

  $ipBytes = [System.Net.IPAddress]::Parse($ipObj.IPAddress).GetAddressBytes()
  $prefix = $ipObj.PrefixLength

  # Build subnet mask bytes from prefix
  $maskBytes = @(0, 0, 0, 0)
  for ($i = 0; $i -lt 4; $i++) {
    $bits = [Math]::Min([Math]::Max($prefix - ($i * 8), 0), 8)
    if ($bits -eq 0) {
      $maskBytes[$i] = 0
    }
    else {
      $maskBytes[$i] = [byte]((0xFF -shl (8 - $bits)) -band 0xFF)
    }
  }

  # Calculate network address bytes
  $networkBytes = @(0, 0, 0, 0)
  for ($i = 0; $i -lt 4; $i++) {
    $networkBytes[$i] = $ipBytes[$i] -band $maskBytes[$i]
  }
  $networkAddress = $networkBytes -join '.'

  "$networkAddress/$prefix"
}
#endregion

#region  Post-AD Install Setup
function Invoke-PostInstallTasks {
  [CmdletBinding()]
  param(
    [switch]$SetDnsServer,
    [switch]$TriggerBpa,
    [switch]$SetW32tm,
    [switch]$SetDnsZone,
    [switch]$EnableRecycleBin
  )
  Write-Log "Starting post-AD install setup..." 'INFO'
  # Run preflight checks before proceeding
  Invoke-PreflightChecks

  try {
    $IpAddress = Get-NetIPAddress | Where-Object { $_.PrefixLength -notin @(128, 8) }
    $loopback = Get-NetIPAddress | Where-Object { $_.IPAddress -eq '127.0.0.1' }
    $InterfaceIndex = $IpAddress.InterfaceIndex | Select-Object -First 1
    if (-not $IpAddress -and -not $loopback) {
      Write-Log "No valid IP address found." 'ERROR'
      return
    }
    if ($IpAddress) {
      Write-Log "IP Address found: $($IpAddress.IPAddress)" 'INFO'
    }
    else {
      Write-Log "No valid IP address found." 'WARN'
    }
    if ($loopback) {
      Write-Log "Loopback address found: $($loopback.IPAddress)" 'INFO'
    }
    else {
      Write-Log "No loopback address found." 'WARN'
    }
    $ServerAddress = @($IpAddress.IPAddress, $loopback.IPAddress)

    if ($SetDnsServer.IsPresent) {
      $currentDns = Get-DNSClientServerAddress -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue
      # Compare to first IP only, for proper logic
      if (-not ($currentDns.ServerAddresses -contains $ServerAddress[0])) {
        Write-Log "Setting DNS server address to $($ServerAddress[0])..." 'INFO'
        Set-DNSClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $ServerAddress
      }
      else {
        Write-Log "DNS server address already set." 'INFO'
      }
    }
    if ($TriggerBpa.IsPresent) {
      Write-Log "Triggering BPA scan..." 'INFO'
      $ModelId = @("Microsoft/Windows/DirectoryServices", "Microsoft/Windows/DNSServer")
      $ModelId | ForEach-Object {
        Invoke-BpaModel -ModelId $_ -Mode All
        Write-Log "BPA scan completed for model $_." 'INFO'
      }
      Write-Log "Excluding Error and Warning results from BPA scan." 'INFO'
      $ModelId | ForEach-Object {
        $results = Get-BpaResult -ModelId $_ -Filter NonCompliant
        if ($results) {
          $results | Where-Object { $_.Severity -in @('Error', 'Warning') } | Set-BpaResult -Exclude:$true | ForEach-Object {
            Write-Log "BPA Result: $($_.Message) - Severity: $($_.Severity)" 'WARN'
          }
        }
      }

    }
    if ($SetW32tm.IsPresent) {
      $fqdn = (Get-CimInstance Win32_ComputerSystem).DNSHostName + '.' + (Get-CimInstance Win32_ComputerSystem).Domain
      Write-Log "Configuring W32Time service..." 'INFO'
      w32tm /config /Computer:$fqdn /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /reliable:YES /update
      Restart-Service w32time -Force
      Write-Log "W32Time service configured and restarted." 'INFO'
    }

    if ($SetDnsZone.IsPresent) {
      Write-Log "Creating reverse lookup zone..." 'INFO'
      $NetworkId = Get-NetworkCIDR
      if ($NetworkId) {
        Write-Log "Network CIDR: $NetworkId" 'INFO'
      }
      else {
        Write-Log "Failed to retrieve Network CIDR." 'ERROR'
      }

      # Calculate reverse zone name
      $ip, $prefix = $NetworkId -split '/'
      $octets = $ip -split '\.'
      $reverseZone = "$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"

      # Check if reverse zone already exists
      if (-not (Get-DnsServerZone -Name $reverseZone -ErrorAction SilentlyContinue)) {
        $params = @{
          NetworkId        = $NetworkId
          Dynamicupdate    = 'Secure'
          ReplicationScope = 'Forest'
        }
        Add-DnsServerPrimaryZone @params
        Write-Log "Reverse lookup zone created successfully." 'INFO'
      }
      else {
        Write-Log "Reverse zone $reverseZone already exists. Skipping creation." 'WARN'
      }

      $timespan = New-TimeSpan -Days 30 -Hours 0 -Minutes 0 -Seconds 0
      $params = @{
        ApplyOnAllZones    = $true
        RefreshInterval    = $timespan
        ScavengingInterval = $timespan
        NoRefreshInterval  = $timespan
      }
      Set-DnsServerScavenging @params
      Write-Log "DNS scavenging settings applied." 'INFO'
      Write-Log "Adding DNS trust anchor..." 'INFO'
      Add-DnsServerTrustAnchor -Root
      Write-Log "DNS trust anchor added successfully." 'INFO'
      Write-Log "Signing DNS zones..." 'INFO'
      $zoneName = (get-ADForest).Name
      $zone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue

      if (-not $zone) {
        Write-Log "DNS zone $zoneName does not exist." 'ERROR'
        return
      }

      # Check if zone is already signed
      $zoneSigned = $zone.IsSigned
      if (-not $zoneSigned) {
        $signParams = @{
          ZoneName        = $zoneName
          SignWithDefault = $true
          Force           = $true
        }
        Invoke-DnsServerZoneSign @signParams
        Write-Log "DNS zones signed successfully." 'INFO'
      }
      else {
        Write-Log "DNS zone $zoneName is already signed. Skipping signing." 'WARN'
      }

      Write-Log "Configuring DNS server forwarders..." 'INFO'
      $forwarders = @('8.8.8.8', '8.8.4.4')
      Set-DnsServerForwarder -IPAddress $forwarders -PassThru
      Write-Log "DNS server forwarders $forwarders configured successfully." 'INFO'
    }
    if ($EnableRecycleBin.IsPresent) {
      Write-Log "Checking Active Directory Recycle Bin status..." 'INFO'
      $forest = Get-ADForest
      $forestDN = $forest.DistinguishedName
      $recycleBinFeature = Get-ADOptionalFeature -Filter 'name -eq "Recycle Bin Feature"'
      $enabled = $recycleBinFeature.EnabledScopes -contains $forestDN
      if (-not $enabled) {
        Write-Log "Enabling Active Directory Recycle Bin..." 'INFO'
        Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forest.Name -confirm:$false
        Write-Log "Active Directory Recycle Bin enabled successfully." 'INFO'
      }
      else {
        Write-Log "Active Directory Recycle Bin is already enabled for forest $($forest.Name)." 'INFO'
      }
    }

  }
  catch {
    Write-Log "Exception during post-AD install setup: $_" 'ERROR'
    throw $_
  }
}
#endregion

#region start postinstall tasks

function Start-Tasks {
  [CmdletBinding()]
  param(
    [switch]$SetDnsServer,
    [switch]$TriggerBpa,
    [switch]$SetW32tm,
    [switch]$SetDnsZone,
    [switch]$EnableRecycleBin
  )
  Write-Log "Starting post-install tasks..." 'INFO'
  Invoke-PostInstallTasks @PSBoundParameters
  Write-Log "Post-install tasks completed." 'INFO'
}

#endregion