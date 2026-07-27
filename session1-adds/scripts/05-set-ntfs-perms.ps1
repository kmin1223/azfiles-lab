# Runs ON the DC VM. Mounts the share once with the storage key (superuser
# path) and grants NTFS Modify to Domain Users - demonstrating security
# layer 3 configuration.
# Args: -StorageAccountName <sa> -StorageKey <key1> -NetBios <CONTOSO>
param(
    [string]$StorageAccountName,
    [string]$StorageKey,
    [string]$NetBios
)
$ErrorActionPreference = 'Stop'

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
