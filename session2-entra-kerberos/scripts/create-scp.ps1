# Runs ON the DC VM. Creates the Service Connection Point (SCP) that tells
# domain-joined devices which Entra tenant to hybrid-join to. This replaces
# the SCP step Entra Connect's wizard would normally do.
# Args: -TenantId <guid> -TenantDomain <verified domain, e.g. x.onmicrosoft.com>
param(
    [string]$TenantId,
    [string]$TenantDomain
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$configNC = (Get-ADRootDSE).configurationNamingContext
$svcPath = "CN=Services,$configNC"
$drcName = 'Device Registration Configuration'
$drcPath = "CN=$drcName,$svcPath"

if (-not (Get-ADObject -Filter "Name -eq '$drcName'" -SearchBase $svcPath -ErrorAction SilentlyContinue)) {
    New-ADObject -Name $drcName -Type container -Path $svcPath | Out-Null
}

$scpName = '62a0ff2e-97b9-4513-943f-0d221bd30080'  # well-known Entra DRS SCP
$existing = Get-ADObject -Filter "Name -eq '$scpName'" -SearchBase $drcPath -ErrorAction SilentlyContinue
if ($existing) { $existing | Remove-ADObject -Recursive -Confirm:$false }

New-ADObject -Name $scpName -Type serviceConnectionPoint -Path $drcPath `
    -OtherAttributes @{ keywords = @("azureADId:$TenantId", "azureADName:$TenantDomain") } | Out-Null

Write-Output "SCP_CREATED tenant=$TenantId domain=$TenantDomain"
