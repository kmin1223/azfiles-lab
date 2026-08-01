# Runs ON the client VM. Verifies that a Kerberos mount actually works and
# reports the ticket's encryption type. Used by deploy.ps1 as a gate: if the
# legacy (RC4) state can't mount in this environment, the deployment falls back
# to the modern AES-256 configuration instead of leaving attendees stuck.
# Args: -StorageAccountName <sa> -Share labshare
param(
    [string]$StorageAccountName,
    [string]$Share = 'labshare'
)
$ErrorActionPreference = 'Continue'
$fqdn = "$StorageAccountName.file.core.windows.net"

# Always start from a clean slate: existing SMB sessions survive key changes,
# and a cached ticket would mask the real result.
cmd /c "net use * /delete /y" 2>&1 | Out-Null
klist purge | Out-Null

$mount = cmd /c "net use T: \\$fqdn\$Share 2>&1"
$ok = $LASTEXITCODE -eq 0

$etype = 'none'
$tickets = klist 2>&1 | Out-String
if ($tickets -match "cifs/$([regex]::Escape($StorageAccountName))[^\r\n]*[\s\S]{0,200}?KerbTicket Encryption Type:\s*(.+)") {
    $etype = $Matches[1].Trim()
}

cmd /c "net use T: /delete /y" 2>&1 | Out-Null

if ($ok) {
    Write-Output "MOUNT_OK etype=$etype"
} else {
    Write-Output "MOUNT_FAILED $($mount -join ' ')"
}
