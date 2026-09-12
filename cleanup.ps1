<#
.SYNOPSIS
  Tear down the whole lab (both sessions).

.DESCRIPTION
  1. Deletes the resource group (VMs, VNet, storage, everything Azure-side).
  2. Optionally cleans Entra artifacts from Session 2:
       - the storage account app / service principal
       - the stale hybrid-joined device object
     Retire the lab's Connect Sync scope BEFORE deleting its DC/sync host.
     See session2-entra-kerberos/MANUAL-STEP-connect-sync.md.

.EXAMPLE
  # Only after completing the Connect Sync retirement checklist:
  .\cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra -ConnectSyncRetired
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [switch]$IncludeEntra,
    [switch]$ConnectSyncRetired,
    [string]$Prefix = 'azflab'
)
$ErrorActionPreference = 'Stop'

if ($IncludeEntra -and -not $ConnectSyncRetired) {
    throw @'
Retire Connect Sync for this lab before deleting its AD/sync infrastructure.
Follow session2-entra-kerberos/MANUAL-STEP-connect-sync.md: remove only the lab
objects from synchronization and verify deletion exports while AD and Connect
are running, then retire the lab-only sync host. Do not stop shared sync or
disable tenant-wide directory synchronization. Re-run with -ConnectSyncRetired
only after completing that checklist. No resources have been deleted.
'@
}

# Same helpers the Session 2 scripts use: a Cloud-Shell-friendly Graph sign-in
# (no 120-second device code) and a storage-account lookup that ignores the
# second account Test-Coexistence creates.
. (Join-Path $PSScriptRoot 'session2-entra-kerberos/scripts/Connect-LabGraph.ps1')

$saName = $null
if ($IncludeEntra) {
    $sa = Get-LabStorageAccount -ResourceGroupName $ResourceGroupName -Prefix $Prefix -ErrorAction SilentlyContinue
    $saName = $sa.StorageAccountName
}

Write-Host "Deleting resource group $ResourceGroupName (async)..." -ForegroundColor Yellow
Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob | Out-Null

if ($IncludeEntra) {
    Connect-LabGraph -Scopes 'Application.ReadWrite.All', 'Device.ReadWrite.All'

    if ($saName) {
        Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $saName.file.core.windows.net'" |
            ForEach-Object {
                Write-Host "Removing service principal $($_.DisplayName)"
                Remove-MgServicePrincipal -ServicePrincipalId $_.Id
            }
        Get-MgApplication -Filter "displayName eq '[Storage Account] $saName.file.core.windows.net'" |
            ForEach-Object { Remove-MgApplication -ApplicationId $_.Id }
    }

    Get-MgDevice -Filter "displayName eq '$Prefix-cli'" | ForEach-Object {
        Write-Host "Removing stale device object $($_.DisplayName)"
        Remove-MgDevice -DeviceId $_.Id
    }

    Write-Host 'NOTE: this script does not uninstall Connect Sync or remove synced users.' -ForegroundColor Yellow
    Write-Host '  Confirm the pre-deletion retirement checklist is complete; retire any separate lab sync host.'
}

Write-Host 'Cleanup initiated. RG deletion continues in the background.' -ForegroundColor Green
