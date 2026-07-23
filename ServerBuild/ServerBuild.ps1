& {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function Test-IPv4Address {
        param(
            [Parameter(Mandatory)]
            [string]$Value
        )

        $parsedAddress = $null

        return (
            [System.Net.IPAddress]::TryParse($Value, [ref]$parsedAddress) -and
            $parsedAddress.AddressFamily -eq
                [System.Net.Sockets.AddressFamily]::InterNetwork
        )
    }

    function Read-IPv4Address {
        param(
            [Parameter(Mandatory)]
            [string]$Prompt,

            [switch]$Optional
        )

        while ($true) {
            $value = (Read-Host $Prompt).Trim()

            if ($Optional -and [string]::IsNullOrWhiteSpace($value)) {
                return $null
            }

            if (Test-IPv4Address -Value $value) {
                return $value
            }

            Write-Warning "'$value' is not a valid IPv4 address."
        }
    }

    function Read-PrefixLength {
        while ($true) {
            $value = (Read-Host 'IPv4 subnet prefix length [24]').Trim()

            if ([string]::IsNullOrWhiteSpace($value)) {
                return 24
            }

            $prefixLength = 0

            if (
                [int]::TryParse($value, [ref]$prefixLength) -and
                $prefixLength -ge 1 -and
                $prefixLength -le 32
            ) {
                return $prefixLength
            }

            Write-Warning 'Enter a prefix length between 1 and 32.'
        }
    }

    function Read-ComputerName {
        while ($true) {
            $value = (Read-Host 'New hostname').Trim().ToUpperInvariant()

            $isValid = (
                $value.Length -ge 1 -and
                $value.Length -le 15 -and
                $value -match '^[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -and
                $value -notmatch '^\d+$'
            )

            if ($isValid) {
                return $value
            }

            Write-Warning @'
Use 1-15 letters, numbers, or hyphens. The name cannot begin or end
with a hyphen and cannot contain only numbers.
'@
        }
    }

    function Read-DomainName {
        while ($true) {
            $value = (Read-Host 'AD DNS domain, such as corp.contoso.com').Trim()

            $isValid = (
                $value.Length -le 253 -and
                $value -match '^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
            )

            if ($isValid) {
                return $value.ToLowerInvariant()
            }

            Write-Warning 'Enter the DNS name of the Active Directory domain.'
        }
    }

    function Read-DnsServers {
        while ($true) {
            $rawValue = (
                Read-Host 'DNS server IP address(es), separated by commas'
            ).Trim()

            $servers = @(
                $rawValue -split '[,;\s]+' |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )

            $invalidServers = @(
                $servers |
                    Where-Object { -not (Test-IPv4Address -Value $_) }
            )

            if ($servers.Count -gt 0 -and $invalidServers.Count -eq 0) {
                return $servers
            }

            Write-Warning 'Enter at least one valid IPv4 DNS server address.'
        }
    }

    # Verify administrator rights.
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = [Security.Principal.WindowsPrincipal]::new(
        $currentIdentity
    )

    $administratorRole = [Security.Principal.WindowsBuiltInRole]::Administrator

    if (-not $currentPrincipal.IsInRole($administratorRole)) {
        throw 'Open Windows PowerShell using Run as administrator.'
    }

    # This script is intended for a fresh, workgroup-based VM.
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem

    if ($computerSystem.PartOfDomain) {
        throw "This server is already joined to '$($computerSystem.Domain)'."
    }

    Write-Host ''
    Write-Host 'Available connected network adapters:' -ForegroundColor Cyan

    $adapters = @(
        Get-NetAdapter |
            Where-Object { $_.Status -eq 'Up' } |
            Sort-Object -Property ifIndex
    )

    if ($adapters.Count -eq 0) {
        throw 'No connected network adapter was found.'
    }

    $adapters |
        Format-Table ifIndex, Name, InterfaceDescription, MacAddress, LinkSpeed |
        Out-Host

    if ($adapters.Count -eq 1) {
        $adapter = $adapters[0]

        Write-Host "Using adapter '$($adapter.Name)'." -ForegroundColor Green
    }
    else {
        while ($true) {
            $selection = (Read-Host 'Enter the interface index to configure').Trim()
            $interfaceIndex = 0

            if ([int]::TryParse($selection, [ref]$interfaceIndex)) {
                $adapter = $adapters |
                    Where-Object { $_.ifIndex -eq $interfaceIndex } |
                    Select-Object -First 1

                if ($null -ne $adapter) {
                    break
                }
            }

            Write-Warning 'Select one of the interface indexes shown above.'
        }
    }

    Write-Host ''
    Write-Host 'Current network configuration:' -ForegroundColor Cyan

    Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex |
        Format-List |
        Out-Host

    Write-Host ''
    Write-Host 'Enter the new server configuration.' -ForegroundColor Cyan
    Write-Host ''

    $newHostname = Read-ComputerName
    $ipAddress = Read-IPv4Address -Prompt 'Static IPv4 address'
    $prefixLength = Read-PrefixLength

    $defaultGateway = Read-IPv4Address `
        -Prompt 'Default gateway IPv4 address [leave blank for none]' `
        -Optional

    $dnsServers = @(Read-DnsServers)
    $domainName = Read-DomainName

    Write-Host ''
    Write-Host 'Proposed configuration' -ForegroundColor Cyan
    Write-Host '----------------------'
    Write-Host "Adapter:       $($adapter.Name)"
    Write-Host "Hostname:      $newHostname"
    Write-Host "IPv4 address:  $ipAddress/$prefixLength"

    if ($defaultGateway) {
        Write-Host "Gateway:       $defaultGateway"
    }
    else {
        Write-Host 'Gateway:       None'
    }

    Write-Host "DNS servers:   $($dnsServers -join ', ')"
    Write-Host "Domain:        $domainName"
    Write-Host ''

    $confirmation = (
        Read-Host 'Type APPLY to configure the server and join the domain'
    ).Trim()

    if ($confirmation -cne 'APPLY') {
        Write-Warning 'Setup canceled. No changes were made.'
        return
    }

    Write-Host ''
    Write-Host 'Enter an account authorized to join the domain.' `
        -ForegroundColor Cyan

    $domainCredential = Get-Credential `
        -Message "Credentials for joining $domainName"

    if ($null -eq $domainCredential) {
        throw 'No domain credentials were supplied.'
    }

    Write-Host ''
    Write-Host 'Enabling Remote Desktop...' -ForegroundColor Cyan

    try {
        # Allow incoming Remote Desktop connections.
        Set-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
            -Name 'fDenyTSConnections' `
            -Value 0

        # Require Network Level Authentication.
        Set-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name 'UserAuthentication' `
            -Value 1

        # Enable the built-in Windows Defender Firewall rules for RDP.
        Get-NetFirewallRule -Name 'RemoteDesktop*' |
            Enable-NetFirewallRule

        # Ensure the Remote Desktop service is available.
        Set-Service -Name 'TermService' -StartupType Automatic
        Start-Service -Name 'TermService' -ErrorAction SilentlyContinue

        Write-Host 'Remote Desktop enabled with NLA.' `
            -ForegroundColor Green
    }
    catch {
        throw "Failed to enable Remote Desktop: $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Host 'Setting time zone to Central Time...' -ForegroundColor Cyan

    try {
        # Windows time-zone ID for U.S. Central Time.
        # Daylight Saving Time is handled automatically.
        Set-TimeZone -Id 'Central Standard Time'

        $currentTimeZone = Get-TimeZone

        Write-Host "Time zone set to '$($currentTimeZone.DisplayName)'." `
            -ForegroundColor Green
    }
    catch {
        throw "Failed to set the time zone: $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Host 'Applying static network configuration...' `
        -ForegroundColor Cyan

    try {
        # Disable DHCP on the selected interface.
        Set-NetIPInterface `
            -InterfaceIndex $adapter.ifIndex `
            -AddressFamily IPv4 `
            -Dhcp Disabled

        # Remove existing IPv4 default routes from this interface.
        Get-NetRoute `
            -InterfaceIndex $adapter.ifIndex `
            -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' `
            -ErrorAction SilentlyContinue |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        # Remove existing non-loopback IPv4 addresses from this interface.
        Get-NetIPAddress `
            -InterfaceIndex $adapter.ifIndex `
            -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -ne '127.0.0.1' } |
                Remove-NetIPAddress `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue

        $newIpParameters = @{
            InterfaceIndex = $adapter.ifIndex
            AddressFamily  = 'IPv4'
            IPAddress      = $ipAddress
            PrefixLength   = $prefixLength
        }

        if ($defaultGateway) {
            $newIpParameters.DefaultGateway = $defaultGateway
        }

        New-NetIPAddress @newIpParameters | Out-Null

        Set-DnsClientServerAddress `
            -InterfaceIndex $adapter.ifIndex `
            -ServerAddresses $dnsServers

        Clear-DnsClientCache

        Write-Host 'Static network configuration applied.' `
            -ForegroundColor Green
    }
    catch {
        Write-Warning 'The static network configuration failed.'
        Write-Warning 'Attempting to return the adapter to DHCP.'

        try {
            Get-NetIPAddress `
                -InterfaceIndex $adapter.ifIndex `
                -AddressFamily IPv4 `
                -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -ne '127.0.0.1' } |
                    Remove-NetIPAddress `
                        -Confirm:$false `
                        -ErrorAction SilentlyContinue

            Set-NetIPInterface `
                -InterfaceIndex $adapter.ifIndex `
                -AddressFamily IPv4 `
                -Dhcp Enabled `
                -ErrorAction SilentlyContinue

            Set-DnsClientServerAddress `
                -InterfaceIndex $adapter.ifIndex `
                -ResetServerAddresses `
                -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning 'The automatic DHCP rollback also encountered an error.'
        }

        throw
    }

    Write-Host ''
    Write-Host 'Sleeping for 10 seconds for NLA to pick up network settings...'
    Start-Sleep 10

    Write-Host ''
    Write-Host 'Testing Active Directory DNS discovery...' `
        -ForegroundColor Cyan

    $domainLocatorRecord = "_ldap._tcp.dc._msdcs.$domainName"

    try {
        $domainControllers = @(
            Resolve-DnsName `
                -Name $domainLocatorRecord `
                -Type SRV `
                -DnsOnly `
                -ErrorAction Stop
        )

        $dcTargets = @(
            $domainControllers |
                Where-Object { $_.Type -eq 'SRV' } |
                Select-Object -ExpandProperty NameTarget -Unique
        )

        if ($dcTargets.Count -eq 0) {
            throw "No domain controller SRV records were returned."
        }

        Write-Host "Domain controllers discovered:" -ForegroundColor Green

        $dcTargets |
            ForEach-Object {
                Write-Host "  $($_.TrimEnd('.'))"
            }
    }
    catch {
        throw @"
Static networking was applied, but Active Directory DNS discovery failed.

Record queried: $domainLocatorRecord
DNS servers:    $($dnsServers -join ', ')

The server was not renamed, joined, or restarted.

Underlying error:
$($_.Exception.Message)
"@
    }

    Write-Host ''
    Write-Host "Joining '$domainName' as '$newHostname'..." `
        -ForegroundColor Cyan

    try {
        Add-Computer `
            -DomainName $domainName `
            -Credential $domainCredential `
            -NewName $newHostname `
            -Force `
            -PassThru `
            -ErrorAction Stop |
                Format-List |
                Out-Host
    }
    catch {
        throw @"
The static network configuration remains in place, but the domain join failed.
The server will not be restarted.

Underlying error:
$($_.Exception.Message)
"@
    }

    Write-Host ''
    Write-Host 'Domain join completed successfully.' -ForegroundColor Green
    Write-Host 'Restarting the server now...' -ForegroundColor Yellow

    Restart-Computer -Force
}