# Runs ON the DC VM after promotion. Creates lab OU and users.
# Args: -Password <pw>
param([string]$Password)
$ErrorActionPreference = 'Stop'

# Fails until AD web services are up after reboot -> deploy.ps1 retries.
Import-Module ActiveDirectory
$domainDn = (Get-ADDomain).DistinguishedName

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
