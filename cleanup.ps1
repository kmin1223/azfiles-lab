<#
.SYNOPSIS
  Tear down the whole lab (both sessions).

.DESCRIPTION
  1. Deletes the resource group (VMs, VNet, storage, everything Azure-side).
  2. Optionally cleans Entra artifacts from Session 2:
       - the storage account app / service principal
       - the stale hybrid-joined device object
     (Cloud Sync config + provisioning agent must be removed in the portal.)

.EXAMPLE
  .\cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [switch]$IncludeEntra,
    [string]$Prefix = 'azflab'
)
$ErrorActionPreference = 'Stop'

$saName = $null
if ($IncludeEntra) {
    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue |
        Where-Object StorageAccountName -like "$Prefix*" | Select-Object -First 1
    $saName = $sa.StorageAccountName
}

Write-Host "Deleting resource group $ResourceGroupName (async)..." -ForegroundColor Yellow
Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob | Out-Null

if ($IncludeEntra) {
    Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Device.ReadWrite.All' -NoWelcome

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

    Write-Host 'NOTE: remove the Cloud Sync configuration manually:' -ForegroundColor Yellow
    Write-Host '  entra.microsoft.com -> Entra Connect -> Cloud sync -> delete config & agent.'
}

Write-Host 'Cleanup initiated. RG deletion continues in the background.' -ForegroundColor Green
