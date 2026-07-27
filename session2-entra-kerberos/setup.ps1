<#
.SYNOPSIS
  Session 2 setup: switch the lab storage account to Microsoft Entra Kerberos
  and prepare the client for cloud TGT retrieval + hybrid join.

.DESCRIPTION
  Builds ON TOP of the Session 1 environment (same resource group).
  Automated steps:
    1. Enable Entra Kerberos (AADKERB) on the storage account
    2. Grant admin consent (openid/profile/User.Read) to the auto-created
       app '[Storage Account] <sa>.file.core.windows.net' via Microsoft Graph
    3. Create the hybrid-join SCP in AD (via Run Command on the DC)
    4. Client VM: CloudKerberosTicketRetrievalEnabled=1 + dsregcmd /join + reboot

  ONE MANUAL STEP remains (interactive by design - Global Admin sign-in):
    Install & configure Entra Cloud Sync so labuser1/labuser2 become hybrid
    identities. See MANUAL-STEP-cloud-sync.md. Do it while slides run.

.EXAMPLE
  Connect-AzAccount
  .\setup.ps1 -ResourceGroupName azfiles-lab
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Prefix = 'azflab'
)
$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

foreach ($m in 'Az.Accounts', 'Az.Storage', 'Az.Compute', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Authentication') {
    if (-not (Get-Module -ListAvailable $m)) {
        throw "Missing module '$m'. Install-Module Az,Microsoft.Graph -Scope CurrentUser"
    }
}
if (-not (Get-AzContext)) { throw 'Run Connect-AzAccount first.' }

$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
    Where-Object StorageAccountName -like "$Prefix*" | Select-Object -First 1
if (-not $sa) { throw "No $Prefix* storage account found in $ResourceGroupName." }
$saName = $sa.StorageAccountName
$dsOption = $sa.AzureFilesIdentityBasedAuth.DirectoryServiceOptions
$adProps = $sa.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
if ($dsOption -ne 'AADKERB' -and -not $adProps) {
    throw 'Session 1 must be completed first (AD DS auth not configured on the storage account).'
}
# Keep the domain details before we change anything (disabling AD DS clears them).
$domainName = $adProps.DomainName
$domainGuid = $adProps.DomainGuid

# ------------------------------------------------ 1. Enable Entra Kerberos
Step "1/4 Enabling Entra Kerberos on $saName"
if ($dsOption -eq 'AADKERB') {
    Write-Host 'Entra Kerberos already enabled - skipping this step.'
}
else {
    # Azure does NOT allow flipping AD DS -> Entra Kerberos directly; the storage
    # account must have AD DS auth disabled first, then AADKERB enabled.
    if ($dsOption -eq 'AD') {
        Write-Host 'Disabling AD DS auth first (required before enabling Entra Kerberos)...'
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
            -EnableActiveDirectoryDomainServicesForFile $false | Out-Null
    }
    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
        -EnableAzureActiveDirectoryKerberosForFile $true `
        -ActiveDirectoryDomainName $domainName `
        -ActiveDirectoryDomainGuid $domainGuid | Out-Null
    Write-Host "directoryServiceOptions is now AADKERB (domain: $domainName)"
}

# --------------------------------------------------- 2. Grant admin consent
Step '2/4 Granting admin consent to the storage account app (Graph)'
Connect-MgGraph -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All' -NoWelcome
$spn = Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $saName.file.core.windows.net'"
if (-not $spn) {
    Start-Sleep 30  # app creation can lag the storage config
    $spn = Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $saName.file.core.windows.net'"
}
if (-not $spn) { throw "Service principal for $saName not found yet - retry in a minute." }

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$existingGrant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($spn.Id)'" -ErrorAction SilentlyContinue
if ($existingGrant) { $existingGrant | Remove-MgOauth2PermissionGrant }
New-MgOauth2PermissionGrant -BodyParameter @{
    clientId    = $spn.Id
    consentType = 'AllPrincipals'
    resourceId  = $graphSp.Id
    scope       = 'openid profile User.Read'
} | Out-Null
Write-Host 'Admin consent granted: openid profile User.Read'

# --------------------------------------------------------- 3. SCP in AD
Step '3/4 Creating hybrid-join SCP in AD (Run Command on DC)'
$org = Get-MgOrganization | Select-Object -First 1
$tenantId = $org.Id
$tenantDomain = ($org.VerifiedDomains | Where-Object IsInitial).Name
$r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName "$Prefix-dc" `
    -CommandId 'RunPowerShellScript' `
    -ScriptPath (Join-Path (Join-Path $PSScriptRoot 'scripts') 'create-scp.ps1') `
    -Parameter @{ TenantId = $tenantId; TenantDomain = $tenantDomain }
($r.Value | Where-Object Code -like '*StdOut*').Message | Write-Host

# --------------------------------------------------------- 4. Client config
Step '4/4 Configuring client (cloud TGT policy + hybrid join, reboots)'
$r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName "$Prefix-cli" `
    -CommandId 'RunPowerShellScript' `
    -ScriptPath (Join-Path (Join-Path $PSScriptRoot 'scripts') 'client-config.ps1')
($r.Value | Where-Object Code -like '*StdOut*').Message | Write-Host

Write-Host @"

==============================================================
 AUTOMATED SETUP COMPLETE
==============================================================
 REMAINING MANUAL STEP (do it now, ~10 min, needs Global Admin):
   -> MANUAL-STEP-cloud-sync.md
   Install the Entra provisioning agent on the DC and create a
   Cloud Sync config scoping OU=AzureFilesLab. Wait for labuser1
   to appear as a synced (hybrid) user.

 Then, verify on the CLIENT VM (as CONTOSO\labuser1):
   dsregcmd /status        # AzureAdJoined: YES (hybrid)
   klist purge ; klist get krbtgt
   klist cloud_debug       # cloud TGT present?
   net use Z: \\$saName.file.core.windows.net\labshare
==============================================================
"@ -ForegroundColor Green
