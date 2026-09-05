# Runs ON the DC VM after promotion. Creates lab OU and users.
# Args: -Password <pw>
param(
    [string]$Password,
    [ValidateScript({
        $address = $null
        if ($_ -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or
            -not [System.Net.IPAddress]::TryParse($_, [ref]$address) -or
            $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
            $address.IPAddressToString -ne $_ -or
            $address.GetAddressBytes()[0] -in @(0, 127) -or
            $address.GetAddressBytes()[0] -ge 224) {
            throw 'EvidenceClientAddress must be one unicast IPv4 address, not a subnet or wildcard.'
        }
        $true
    })]
    [string]$EvidenceClientAddress = '10.100.0.5'
)
$ErrorActionPreference = 'Stop'

# Fails until AD web services are up after reboot -> deploy.ps1 retries.
Import-Module ActiveDirectory
$domainDn = (Get-ADDomain).DistinguishedName

# --- DNS forwarder: the lab's only path to the public internet -------------
# The VNet hands every VM this DC as its ONLY DNS server (template dhcpOptions),
# so nothing in the lab resolves a public name unless this DNS server forwards.
# Install-ADDSForest -InstallDns leaves no forwarder here - it inherits the DC's
# own NIC setting, which by then already points at itself - so resolution falls
# back to root hints. That is slow and unreliable in Azure, and it fails in ways
# that look like anything but DNS:
#   - dsregcmd /join  -> 0x80072ee7 (name not resolved) -> 0x801c003d, no hybrid join
#   - tool downloads  -> "The remote name could not be resolved"
# 168.63.129.16 is Azure's platform DNS: reachable from inside every VNet, needs
# no NSG rule, and never leaves the Azure fabric.
try {
    $fwd = @(Get-DnsServerForwarder -ErrorAction SilentlyContinue).IPAddress.IPAddressToString
    if ($fwd -notcontains '168.63.129.16') {
        Set-DnsServerForwarder -IPAddress '168.63.129.16' -PassThru -ErrorAction Stop | Out-Null
        Write-Output 'DNS forwarder set to 168.63.129.16 (Azure platform DNS)'
    } else {
        Write-Output 'DNS forwarder already set'
    }
    # Prove it end to end rather than trusting the config.
    $probe = Resolve-DnsName 'login.microsoftonline.com' -Server 127.0.0.1 -ErrorAction Stop
    Write-Output "DNS forward test OK (login.microsoftonline.com -> $(@($probe)[0].IPAddress -join ','))"
} catch {
    Write-Output "WARNING: DNS forwarder setup/probe failed - $($_.Exception.Message.Split([char]10)[0])"
    Write-Output 'WARNING: public-name resolution will fail on both VMs; Session 2 hybrid join CANNOT work.'
}

$ouName = 'AzureFilesLab'
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $ouName -Path $domainDn -ProtectedFromAccidentalDeletion $false
}
$ouDn = "OU=$ouName,$domainDn"

$sec = ConvertTo-SecureString $Password -AsPlainText -Force
foreach ($u in 'labuser1', 'labuser2') {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$u'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $u -SamAccountName $u `
            -UserPrincipalName "$u@$((Get-ADDomain).DNSRoot)" `
            -AccountPassword $sec -Enabled $true -Path $ouDn `
            -PasswordNeverExpires $true
    }
}
# --- Read-only DC evidence for the two lab users, from the client only ---
$readerName = 'AzureFilesLabEvidenceReaders'
$readers = Get-ADGroup -Filter "SamAccountName -eq '$readerName'"
if (-not $readers) {
    $readers = New-ADGroup -Name $readerName -SamAccountName $readerName `
        -GroupScope DomainLocal -GroupCategory Security -Path $ouDn -PassThru
}
if ($readers.GroupScope -ne 'DomainLocal' -or $readers.GroupCategory -ne 'Security' -or
    $readers.DistinguishedName -ne "CN=$readerName,$ouDn") {
    throw "Existing $readerName must be a DomainLocal security group in $ouDn."
}
$members = @(Get-ADGroupMember -Identity $readers | Select-Object -ExpandProperty DistinguishedName)
foreach ($u in 'labuser1', 'labuser2') {
    $user = Get-ADUser -Identity $u
    if ($members -notcontains $user.DistinguishedName) {
        Add-ADGroupMember -Identity $readers -Members $user
    }
}
# BUILTIN Event Log Readers cannot contain the domain's DomainLocal group.
# Add users directly; retain the DomainLocal group for the Security channel ACE.
$eventReaders = Get-ADGroup -Identity 'S-1-5-32-573'
$eventReaderMembers = @(Get-ADGroupMember -Identity $eventReaders |
    Select-Object -ExpandProperty DistinguishedName)
foreach ($u in 'labuser1', 'labuser2') {
    $user = Get-ADUser -Identity $u
    if ($eventReaderMembers -notcontains $user.DistinguishedName) {
        Add-ADGroupMember -Identity $eventReaders -Members $user
    }
}

function Invoke-EventUtility {
    param([string]$Executable, [string[]]$Arguments)
    $result = & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed (exit $LASTEXITCODE): $($Arguments -join ' ')"
    }
    $result
}

$channelXml = [xml]((Invoke-EventUtility wevtutil @('gl', 'Security', '/f:xml')) -join "`n")
# wevtutil XML puts channelAccess on the channel element as an attribute.
$channelAccess = $channelXml.SelectSingleNode("/*[local-name()='channel' and @name='Security']/@channelAccess")
if (-not $channelAccess -or [string]::IsNullOrWhiteSpace($channelAccess.Value)) {
    throw 'Security configuration XML is missing its channelAccess attribute; existing permissions were not changed.'
}
$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($channelAccess.Value)
if ($null -eq $descriptor.DiscretionaryAcl) {
    throw 'Security channel has no DACL; refusing to replace its access policy.'
}
$readerSid = [System.Security.Principal.SecurityIdentifier]::new($readers.SID.Value)
$hasReadAce = @($descriptor.DiscretionaryAcl | Where-Object {
    $_ -is [System.Security.AccessControl.CommonAce] -and
    $_.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and
    $_.AceFlags -eq [System.Security.AccessControl.AceFlags]::None -and
    $_.SecurityIdentifier -eq $readerSid -and $_.AccessMask -eq 0x1
}).Count -gt 0
if (-not $hasReadAce) {
    # Keep every existing ACE, owner, group and SACL; add only event-log READ (0x1).
    $readAce = [System.Security.AccessControl.CommonAce]::new(
        [System.Security.AccessControl.AceFlags]::None,
        [System.Security.AccessControl.AceQualifier]::AccessAllowed,
        0x1, $readerSid, $false, $null)
    $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count, $readAce)
    $sddl = $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
    Invoke-EventUtility wevtutil @('sl', 'Security', "/ca:$sddl") | Out-Null
}

# Dedicated service-bound RPC rules; do not enable the broad built-in rule group.
foreach ($rule in @(
    @{ Name = 'AzureFilesLab-Evidence-EventLog-RPC'; Port = 'RPC'; Service = 'eventlog' },
    @{ Name = 'AzureFilesLab-Evidence-RPC-EPMap'; Port = 'RPC-EPMap'; Service = 'RpcSs' }
)) {
    $settings = @{
        PolicyStore = 'PersistentStore'
        Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Domain'
        Protocol = 'TCP'; LocalPort = $rule.Port; RemoteAddress = $EvidenceClientAddress
        Program = "$env:SystemRoot\System32\svchost.exe"; Service = $rule.Service
    }
    if (Get-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $rule.Name @settings | Out-Null
    } else {
        New-NetFirewallRule -Name $rule.Name -DisplayName $rule.Name @settings | Out-Null
    }
}

# Native commands do not throw on a nonzero exit in Windows PowerShell 5.1.
Invoke-EventUtility auditpol @('/set', '/subcategory:Kerberos Service Ticket Operations', '/success:enable', '/failure:enable') | Out-Null
Invoke-EventUtility auditpol @('/set', '/subcategory:Kerberos Authentication Service', '/success:enable', '/failure:enable') | Out-Null
$kdcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
$extraLogLevel = (Get-ItemProperty -Path $kdcPath -ErrorAction Stop).KdcExtraLogLevel
# An absent override uses the KDC default (0x2, PKINIT logging).
if ($null -eq $extraLogLevel) { $extraLogLevel = 0x2 }
New-ItemProperty -Path $kdcPath -Name KdcExtraLogLevel -PropertyType DWord `
    -Value ([int]$extraLogLevel -bor 0x11) -Force | Out-Null
foreach ($channel in 'Microsoft-Windows-Kerberos/Operational', 'Microsoft-Windows-SMBClient/Operational') {
    try {
        Invoke-EventUtility wevtutil @('sl', $channel, '/e:true') | Out-Null
    } catch {
        # These optional DC channels are not the Security events collected remotely.
        Write-Warning "Optional DC channel ${channel}: $($_.Exception.Message)"
    }
}

Write-Output 'DC_AUDITING_READY (Security events 4768/4769/4771 incl. failures)'
Write-Output 'USERS_READY'
Write-Output 'DC_EVIDENCE_READY'
