# Runs ON the DC VM as the FINAL auth step. Resets the storage computer
# account password to the (freshly rotated) kerb1 key. Running this after the
# storage account is fully configured makes the deployment immune to the
# kerb-key propagation race that causes error 1396 / KRB5KRB_AP_ERR_MODIFIED.
# Args: -StorageAccountName <sa> -KerbKey <kerb1 value>
param(
    [string]$StorageAccountName,
    [string]$KerbKey
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$sec = ConvertTo-SecureString $KerbKey -AsPlainText -Force
# Computer SamAccountName ends with '$' - resolve via *-ADComputer, pass DN.
$comp = Get-ADComputer -Identity $StorageAccountName
Set-ADAccountPassword -Identity $comp.DistinguishedName -NewPassword $sec -Reset
Write-Output 'KERB_KEY_SYNCED'
