# Runs ON the DC VM after promotion. Creates lab OU and users.
# Args: -Password <pw>
param([string]$Password)
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
# --- Kerberos auditing + operational logs, folded in here on purpose ---
# Every Run Command invocation costs ~60s of fixed overhead, so these four
# commands don't get their own step. The labs depend on them: event 4769
# (service-ticket ops incl. FAILURES - success-only is the DC default) is the
# KDC-side evidence for the AES-256 migration and etype labs.
try {
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
    wevtutil sl Microsoft-Windows-Kerberos/Operational /e:true 2>$null
    wevtutil sl Microsoft-Windows-SMBClient/Operational /e:true 2>$null
    Write-Output 'DC_AUDITING_READY (events 4768/4769 incl. failures + operational logs)'
} catch {
    Write-Output "DC auditing warning: $($_.Exception.Message)"
}

Write-Output 'USERS_READY'
