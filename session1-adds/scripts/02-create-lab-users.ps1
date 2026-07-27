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
Write-Output 'USERS_READY'
