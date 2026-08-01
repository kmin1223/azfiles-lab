# Runs ON the DC VM. Creates the AD computer account that represents the
# storage account (the "manual enablement" path of AD DS auth), using the
# storage account kerb1 key as the account password, and registers the SPN.
# Outputs a JSON blob the deployer parses to call Set-AzStorageAccount.
# Args: -StorageAccountName <sa> -KerbKey <kerb1 value>
param(
    [string]$StorageAccountName,
    [string]$KerbKey,
    # AES256 = modern/correct. RC4 = the "legacy 2023 vintage" state the lab
    # starts from, so attendees can perform the AES-256 migration themselves.
    [ValidateSet('AES256', 'RC4')]
    [string]$KerberosEncryptionType = 'AES256'
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain = Get-ADDomain
$forest = Get-ADForest
$domainDn = $domain.DistinguishedName

$ouName = 'AzureFilesLab'
$ouDn = "OU=$ouName,$domainDn"
$spn = "cifs/$StorageAccountName.file.core.windows.net"
$sec = ConvertTo-SecureString $KerbKey -AsPlainText -Force

# Order matters - set the encryption type BEFORE the final password reset,
# because the AES keys are derived from the password (and the salt) at set time.
$existing = Get-ADComputer -Filter "Name -eq '$StorageAccountName'" -ErrorAction SilentlyContinue
if (-not $existing) {
    New-ADComputer -Name $StorageAccountName `
        -Path $ouDn `
        -ServicePrincipalNames $spn `
        -AccountPassword $sec `
        -Enabled $true `
        -Description "Computer account for Azure storage account $StorageAccountName" `
        -PasswordNeverExpires $true
}
Set-ADComputer -Identity $StorageAccountName `
    -ServicePrincipalNames @{Replace = $spn } `
    -KerberosEncryptionType $KerberosEncryptionType
Write-Output "KerberosEncryptionType set to $KerberosEncryptionType"

# NOTE: computer accounts' SamAccountName ends with '$'. Set-ADAccountPassword
# does NOT auto-append it (unlike the *-ADComputer cmdlets), so resolve the
# object first and pass its DN.
$compObj = Get-ADComputer -Identity $StorageAccountName
Set-ADAccountPassword -Identity $compObj.DistinguishedName -NewPassword $sec -Reset

$comp = Get-ADComputer -Identity $StorageAccountName

# JSON handed back to deploy.ps1 (marker-delimited to survive Run Command noise)
$result = [pscustomobject]@{
    DomainName        = $domain.DNSRoot
    NetBiosDomainName = $domain.NetBIOSName
    ForestName        = $forest.Name
    DomainGuid        = $domain.ObjectGUID.ToString()
    DomainSid         = $domain.DomainSID.Value
    AzureStorageSid   = $comp.SID.Value
    SamAccountName    = ($comp.SamAccountName -replace '\$$','')
}
Write-Output "===JSON_BEGIN===$(($result | ConvertTo-Json -Compress))===JSON_END==="
