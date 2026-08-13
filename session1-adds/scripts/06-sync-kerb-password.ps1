# Runs ON the DC VM as the FINAL auth step. Resets the storage computer
# account password to the (freshly rotated) kerb1 key. Running this after the
# storage account is fully configured makes the deployment immune to the
# kerb-key propagation race that causes error 1396 / KRB5KRB_AP_ERR_MODIFIED.
#
# When -StorageKey/-NetBios are supplied it ALSO sets the NTFS ACLs (what
# 05-set-ntfs-perms.ps1 does standalone) - one Run Command round-trip costs
# ~60s regardless of payload, so the deployment sends both jobs in one call.
# Args: -StorageAccountName <sa> -KerbKey <kerb1 value> [-StorageKey <key1> -NetBios <CONTOSO>]
param(
    [string]$StorageAccountName,
    [string]$KerbKey,
    [string]$StorageKey,
    [string]$NetBios
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$sec = ConvertTo-SecureString $KerbKey -AsPlainText -Force
# Computer SamAccountName ends with '$' - resolve via *-ADComputer, pass DN.
$comp = Get-ADComputer -Identity $StorageAccountName
Set-ADAccountPassword -Identity $comp.DistinguishedName -NewPassword $sec -Reset
Write-Output 'KERB_KEY_SYNCED'

if ($StorageKey -and $NetBios) {
    # NTFS layer: mount once with the STORAGE KEY (superuser path, no Kerberos
    # involved) and grant the lab users their permissions.
    $uncPath = "\\$StorageAccountName.file.core.windows.net\labshare"
    net use Z: $uncPath /user:"localhost\$StorageAccountName" $StorageKey | Out-Null
    try {
        icacls Z: /grant "$NetBios\Domain Users:(OI)(CI)M" | Out-Null
        icacls Z: /grant "$NetBios\Domain Admins:(OI)(CI)F" | Out-Null
        'Welcome to the Azure Files identity-based auth lab!' |
            Out-File Z:\hello-from-setup.txt -Encoding utf8
        Write-Output 'NTFS_PERMS_SET'
    } finally {
        net use Z: /delete /y | Out-Null
    }
}
