<#
.SYNOPSIS
  Session 2 setup: switch the lab storage account to Microsoft Entra Kerberos
  and prepare an already hybrid-joined client for cloud TGT retrieval.

.DESCRIPTION
  Builds ON TOP of the Session 1 environment (same resource group).
  Prerequisites (presenter prework, BEFORE running this script):
    Session 1 base -> manual Connect Sync users/PHS + computer sync ->
    Connect wizard device options/SCP -> healthy hybrid join.
    See MANUAL-STEP-connect-sync.md. Do not initialize this during the session.

  Automated steps (SCP is owned by the Connect wizard, never this script):
    0. Verify healthy hybrid join in the subscription's tenant before mutations
    1. Enable Entra Kerberos (AADKERB) on the storage account
    2. Grant admin consent (openid/profile/User.Read) to the auto-created
       app '[Storage Account] <sa>.file.core.windows.net' via Microsoft Graph
    3. Client VM: CloudKerberosTicketRetrievalEnabled=1 + tools + reboot
  Then sign in again as the synchronized lab user and verify PRT, cloud TGT,
  CIFS ticket and a successful share mount. A SYSTEM check cannot prove the PRT.

.EXAMPLE
  # Azure Cloud Shell (PowerShell) - already signed in, Az + Graph preinstalled
  .\setup.ps1 -ResourceGroupName azfiles-lab
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Prefix = 'azflab'
)
$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Invoke-LabClientConfiguration {
    param(
        [ValidateSet('Check', 'Configure')] [string]$Mode,
        [string]$TenantId
    )
    $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName "$Prefix-cli" `
        -CommandId 'RunPowerShellScript' `
        -ScriptPath (Join-Path (Join-Path $PSScriptRoot 'scripts') 'client-config.ps1') `
        -Parameter @{ Mode = $Mode; ExpectedTenantId = $TenantId } -ErrorAction Stop
    $stdout = (($r.Value | Where-Object Code -like '*StdOut*').Message) -join "`n"
    $stderr = (($r.Value | Where-Object Code -like '*StdErr*').Message) -join "`n"
    $stdout | Write-Host
    $marker = if ($Mode -eq 'Check') { 'CLIENT_HYBRID_JOIN_READY' } else { 'CLIENT_CONFIG_DONE_REBOOTING' }
    if ($stderr.Trim() -or $stdout -notmatch "(?m)^$marker\s*$") {
        throw "Client $Mode did not finish successfully. $stderr`nSee MANUAL-STEP-connect-sync.md; do not treat pending registration as ready."
    }
}

foreach ($m in 'Az.Accounts', 'Az.Storage', 'Az.Compute', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Authentication') {
    if (-not (Get-Module -ListAvailable $m)) {
        throw "Missing module '$m'. Install-Module Az,Microsoft.Graph -Scope CurrentUser"
    }
}
$context = Get-AzContext
if (-not $context) {
    throw 'No Azure context. Run this in Azure Cloud Shell (PowerShell), where you are already signed in.'
}

. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'Connect-LabGraph.ps1')

Step '0/3 Checking hybrid join before changing storage (Connect wizard owns SCP)'
$tenantId = $context.Tenant.Id
if (-not $tenantId) { throw 'The current Azure context has no tenant ID.' }
Invoke-LabClientConfiguration -Mode Check -TenantId $tenantId

$sa = Get-LabStorageAccount -ResourceGroupName $ResourceGroupName -Prefix $Prefix
if (-not $sa) { throw "No $Prefix* storage account found in $ResourceGroupName." }
$saName = $sa.StorageAccountName
$dsOption = $sa.AzureFilesIdentityBasedAuth.DirectoryServiceOptions
# States we handle: 'AD' (from Session 1 - disable then enable AADKERB),
# 'None' (mid-transition, e.g. a prior run disabled AD DS but the enable failed),
# 'AADKERB' (already done - skip). All are fine to proceed from.
Write-Host "Current storage identity option: $dsOption"

# ------------------------------------------------ 1. Enable Entra Kerberos
Step "1/3 Enabling Entra Kerberos on $saName"
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

        # Wait for the disable to propagate before enabling AADKERB, otherwise the
        # next call can fail with BadRequest during the state transition.
        Write-Host 'Waiting for AD DS to fully disable...'
        for ($i = 0; $i -lt 12; $i++) {
            Start-Sleep -Seconds 15
            $cur = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).AzureFilesIdentityBasedAuth.DirectoryServiceOptions
            if ($cur -eq 'None') { break }
        }
    }

    # Enable Entra Kerberos, with a short retry for transient BadRequest.
    $enabled = $false
    for ($i = 1; $i -le 4; $i++) {
        try {
            Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
                -EnableAzureActiveDirectoryKerberosForFile $true -ErrorAction Stop | Out-Null
            $enabled = $true
            break
        } catch {
            $msg = $_.Exception.Message
            # Tenant app management policy blocks the symmetric key the storage app
            # needs - this is NOT transient, so stop and explain rather than retry.
            if ($msg -match 'AppManagementPolicy' -or $msg -match 'Credential type not allowed') {
                Write-Host ''
                Write-Warning @'
Entra Kerberos is blocked by a tenant App Management Policy (it forbids the
symmetric key the storage account's app needs).

Fix (needs a Global Admin), then re-run this script:
  - Entra admin center: https://aka.ms/app-mgmt-policy-ux
  - Grant an exception for the "Storage Resource Provider"
    (app ID a6aa9161-5291-40bb-8c5c-923b567bee3b) on the
    "Block password addition" and "Restrict max password lifetime" settings.
  Docs: https://learn.microsoft.com/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable#prerequisites

If you can't change tenant policy, run the whole lab in a subscription whose
tenant has no such policy (a personal/dev tenant).
'@
                throw 'Entra Kerberos enablement blocked by tenant app management policy (see guidance above).'
            }
            Write-Host "  enable attempt $i failed ($($msg.Split("`n")[0])); retrying in 30s..."
            Start-Sleep -Seconds 30
        }
    }
    if (-not $enabled) { throw 'Could not enable Entra Kerberos after several attempts.' }
    Write-Host 'directoryServiceOptions is now AADKERB'
}

# --------------------------------------------------- 2. Grant admin consent
Step '2/3 Granting admin consent to the storage account app (Graph)'

Connect-LabGraph -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All'

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

# --------------------------------------------------------- 3. Client config
Step '3/3 Configuring client (cloud TGT policy + tools, reboots)'
Invoke-LabClientConfiguration -Mode Configure -TenantId $tenantId

Write-Host @"

==============================================================
 STORAGE/CLIENT CONFIGURATION APPLIED - USER BASELINE STILL REQUIRED
==============================================================
 Connect Sync and hybrid join were prerequisites; the wizard's
 SCP was not changed. See MANUAL-STEP-connect-sync.md.

 After reboot, sign in again on the CLIENT as the synchronized
 lab user (not labadmin). In that user's normal, non-elevated shell:
   dsregcmd /status        # DomainJoined: YES, AzureAdJoined: YES,
                          # DeviceAuthStatus: SUCCESS, AzureAdPrt: YES
   klist cloud_debug       # Cloud Kerberos retrieval enabled
   klist                  # confirm cloud TGT after fresh logon
   klist get cifs/$saName.file.core.windows.net
   net use Z: \\$saName.file.core.windows.net\labshare
 Rehearse healthy access before any fault injection. Do not
 continue while join, PRT, ticket retrieval or the mount is failing.
==============================================================
"@ -ForegroundColor Green
