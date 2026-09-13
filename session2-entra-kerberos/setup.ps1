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
    1. Optionally grant the specified user SMB Share Contributor on labshare
    2. Enable Entra Kerberos (AADKERB) on the storage account
    3. Restore missing openid/profile/User.Read API permission declarations
       on '[Storage Account] <sa>.file.core.windows.net', preserving other
       declarations; keep or create the exact admin consent baseline.
       Requires Application.ReadWrite.All plus DelegatedPermissionGrant.ReadWrite.All
       and caller authorization to edit the app and grant tenant-wide consent.
    4. Client VM: CloudKerberosTicketRetrievalEnabled=1 + tools + reboot
  Then sign in again as the synchronized lab user and verify PRT, cloud TGT,
  CIFS ticket and a successful share mount. A SYSTEM check cannot prove the PRT.

.PARAMETER ShareUserPrincipalName
  Optional exact Entra UPN of the synchronized lab user. Grants only
  Storage File Data SMB Share Contributor on labshare; leaves default share
  permissions, NTFS ACLs and other identities unchanged. Requires Az.Resources,
  directory user read access and roleAssignments/write at the share or above.
  Omit to manage share permissions manually. RBAC propagation is asynchronous.

.PARAMETER PrepareRbacLab
  Opt-in presenter prework. Requires ShareUserPrincipalName. Creates a separate
  rbac-lab SMB share with labshare's root DACL, leaves it without applicable user
  data RBAC, and disables default share permission on this dedicated lab account.
  Does not delete assignments or automatically reset a previously repaired lab.
  Requires share creation, key listing, DC Run Command and role/group read access.

.EXAMPLE
  # Azure Cloud Shell (PowerShell) - already signed in, Az + Graph preinstalled
  .\setup.ps1 -ResourceGroupName azfiles-lab `
      -ShareUserPrincipalName 'hybrid-labuser1@yourtenant.onmicrosoft.com'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Prefix = 'azflab',
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$ShareUserPrincipalName,
    [switch]$PrepareRbacLab
)
$ErrorActionPreference = 'Stop'
if ($PrepareRbacLab -and -not $ShareUserPrincipalName) {
    throw 'PrepareRbacLab requires ShareUserPrincipalName; no lab user is guessed.'
}
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

function Grant-LabShareAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[^@\s]+@[^@\s]+$')]
        [string]$UserPrincipalName,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()]
        [ValidatePattern('^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}$')]
        [string]$StorageAccountId
    )

    # Resolve by exact cloud UPN, never a shared display name such as "labuser1".
    $users = @(Get-AzADUser -UserPrincipalName $UserPrincipalName -ErrorAction Stop)
    $objectId = [guid]::Empty
    if ($users.Count -ne 1 -or $users[0].UserPrincipalName -ne $UserPrincipalName -or
        -not [guid]::TryParse([string]$users[0].Id, [ref]$objectId) -or $objectId -eq [guid]::Empty) {
        throw "SHARE_RBAC_USER_NOT_FOUND: could not resolve exactly one user with UPN '$UserPrincipalName' and a valid object ID in the current Azure tenant. Confirm Connect Sync and the cloud UPN; no role was assigned."
    }

    $scope = "$StorageAccountId/fileServices/default/fileshares/labshare"
    $role = 'Storage File Data SMB Share Contributor'
    $parameters = @{ ObjectId = $objectId.ToString(); Scope = $scope; RoleDefinitionName = $role; ErrorAction = 'Stop' }
    $existing = @(Get-AzRoleAssignment @parameters | Where-Object {
        $_.ObjectId -eq $objectId.ToString() -and $_.Scope -eq $scope -and $_.RoleDefinitionName -eq $role
    })
    if ($existing.Count -gt 0) {
        Write-Host "RBAC: '$role' already assigned to '$UserPrincipalName' ($objectId) at $scope"
    } else {
        $assignment = New-AzRoleAssignment @parameters
        if (-not $assignment -or $assignment.ObjectId -ne $objectId.ToString() -or
            $assignment.Scope -ne $scope -or $assignment.RoleDefinitionName -ne $role) {
            throw 'SHARE_RBAC_NOT_CONFIRMED: Azure did not return the expected user, role and share scope. Inspect the role assignments before retrying; do not assume share access is ready.'
        }
        Write-Host "RBAC: assigned '$role' to '$UserPrincipalName' ($objectId) at $scope"
    }
    Write-Warning 'RBAC control-plane assignment is not an SMB access check. Share permissions usually propagate within 30 minutes, but can take longer. Retry user-session access before changing credentials or adding broader roles.'
    [pscustomobject]@{ ObjectId = $objectId.ToString(); UserPrincipalName = $UserPrincipalName; Scope = $scope }
}

$modules = @('Az.Accounts', 'Az.Storage', 'Az.Compute', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.SignIns')
if ($ShareUserPrincipalName) { $modules += 'Az.Resources' }
foreach ($m in $modules) {
    if (-not (Get-Module -ListAvailable $m)) {
        throw "Missing module '$m'. Install-Module Az,Microsoft.Graph -Scope CurrentUser"
    }
}
$context = Get-AzContext
if (-not $context) {
    throw 'No Azure context. Run this in Azure Cloud Shell (PowerShell), where you are already signed in.'
}

. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'Connect-LabGraph.ps1')
. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'LabGraphConsent.ps1')
if ($PrepareRbacLab) {
    . (Join-Path (Join-Path $PSScriptRoot 'scripts') 'Initialize-RbacFirstLab.ps1')
}

Step '0/4 Checking hybrid join before changing storage (Connect wizard owns SCP)'
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

# Resolve and assign before the storage transition so RBAC failures stop early.
Step '1/4 Configuring share-level RBAC (optional)'
if ($ShareUserPrincipalName) {
    $shareAccess = Grant-LabShareAccess -UserPrincipalName $ShareUserPrincipalName -StorageAccountId $sa.Id
} else {
    Write-Warning 'No ShareUserPrincipalName supplied; share RBAC is unchanged. Configure share-level access manually (SMB data role or an intentional default share permission) before testing the user baseline.'
}
if ($PrepareRbacLab) {
    $rbacLabPlan = Get-RbacFirstLabPlan -ResourceGroupName $ResourceGroupName `
        -StorageAccount $sa -UserObjectId $shareAccess.ObjectId
}

# ------------------------------------------------ 2. Enable Entra Kerberos
Step "2/4 Enabling Entra Kerberos on $saName"
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

if ($PrepareRbacLab) {
    Step '2b/4 Preparing the isolated first RBAC lab'
    Initialize-RbacFirstLab -Plan $rbacLabPlan -DcVmName "$Prefix-dc"
}

# --------------------------------------------------- 3. Grant admin consent
Step '3/4 Granting admin consent to the storage account app (Graph)'

Connect-LabGraph -Scopes 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All'

Initialize-LabGraphConsent -StorageAccountName $saName

# --------------------------------------------------------- 4. Client config
Step '4/4 Configuring client (cloud TGT policy + tools, reboots)'
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
   klist                  # initial cache may be empty before a ticket request
   klist get cifs/$saName.file.core.windows.net
   klist                  # verify the retrieved cloud/CIFS tickets
   net use Z: \\$saName.file.core.windows.net\labshare
 Share RBAC can take 30 minutes or longer to propagate. Role assignment
 success is not proof of effective SMB access; NTFS ACLs still apply.
 Rehearse healthy access before any fault injection. Do not
 continue while join, PRT, ticket retrieval or the mount is failing.
==============================================================
"@ -ForegroundColor Green
