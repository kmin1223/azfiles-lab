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

foreach ($m in 'Az.Accounts', 'Az.Storage', 'Az.Compute', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Authentication') {
    if (-not (Get-Module -ListAvailable $m)) {
        throw "Missing module '$m'. Install-Module Az,Microsoft.Graph -Scope CurrentUser"
    }
}
if (-not (Get-AzContext)) {
    throw 'No Azure context. Run this in Azure Cloud Shell (PowerShell), where you are already signed in.'
}

. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'Connect-LabGraph.ps1')

$sa = Get-LabStorageAccount -ResourceGroupName $ResourceGroupName -Prefix $Prefix
if (-not $sa) { throw "No $Prefix* storage account found in $ResourceGroupName." }
$saName = $sa.StorageAccountName
$dsOption = $sa.AzureFilesIdentityBasedAuth.DirectoryServiceOptions
# States we handle: 'AD' (from Session 1 - disable then enable AADKERB),
# 'None' (mid-transition, e.g. a prior run disabled AD DS but the enable failed),
# 'AADKERB' (already done - skip). All are fine to proceed from.
Write-Host "Current storage identity option: $dsOption"

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
Step '2/4 Granting admin consent to the storage account app (Graph)'

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
$clientOut = ($r.Value | Where-Object Code -like '*StdOut*').Message
$clientOut | Write-Host

# Do NOT print a green "COMPLETE" over a failed join. The client output already
# says AzureAdJoined: NO when discovery failed - saying "complete" on top of that
# sends people off to do Cloud Sync on a device that can never get a PRT, and
# they then debug the wrong half of the stack.
if ($clientOut -match 'DNS FAIL' -or $clientOut -match '0x80072ee7') {
    Write-Host @'

==============================================================
 SETUP STOPPED - PUBLIC DNS IS BROKEN
==============================================================
 The client cannot resolve public names, so the device cannot
 reach Entra and hybrid join is impossible. This is NOT an Entra
 or SCP problem.

 The VNet points every VM at the DC for DNS, and the DC has no
 forwarder. Fix it on the DC (elevated), then re-run this script:

   Set-DnsServerForwarder -IPAddress 168.63.129.16
   Resolve-DnsName login.microsoftonline.com -Server 127.0.0.1

 From Cloud Shell, without RDP:
   Invoke-AzVMRunCommand -ResourceGroupName <rg> -VMName <prefix>-dc `
     -CommandId RunPowerShellScript -ScriptString `
     "Set-DnsServerForwarder -IPAddress 168.63.129.16; Resolve-DnsName login.microsoftonline.com -Server 127.0.0.1"
==============================================================
'@ -ForegroundColor Red
    throw 'Client cannot resolve public DNS - fix the DC forwarder and re-run.'
}
if ($clientOut -match 'error_missing_device' -or $clientOut -match '0x801c03f3') {
    Write-Host @'

==============================================================
 AzureAdJoined: NO - and that is EXPECTED right now
==============================================================
 The client asked Entra to complete a registration for a device
 object that does not exist yet, so DRS answered:
     error_missing_device / 0x801c03f3

 In a managed tenant the device object must be put into Entra by
 DIRECTORY SYNC first. That is the manual step below - and its
 device sync is OFF BY DEFAULT, so enabling it is a step people
 miss. Nothing is broken; just do them in order.
==============================================================
'@ -ForegroundColor Yellow
}
elseif ($clientOut -match 'AzureAdJoined\s*:\s*NO') {
    Write-Host @'

==============================================================
 WARNING - HYBRID JOIN DID NOT COMPLETE, AND NOT FOR THE USUAL REASON
==============================================================
 AzureAdJoined: NO, but WITHOUT error_missing_device. Read the
 client output above for the first real error before continuing -
 do not assume Cloud Sync will fix it.
==============================================================
'@ -ForegroundColor Yellow
}

Write-Host @"

==============================================================
 AUTOMATED SETUP COMPLETE
==============================================================
 REMAINING MANUAL STEPS (~15 min, needs Global Admin)
   -> MANUAL-STEP-cloud-sync.md.  ORDER MATTERS:

   1. Install the Entra provisioning agent on the DC
   2. Create a Cloud Sync config scoping OU=AzureFilesLab
   3. Properties > Basics > ENABLE DEVICE SYNC   <- off by default,
      and hybrid join CANNOT work without it
   4. Provision on demand -> Device tab ->
      CN=$Prefix-cli,CN=Computers,DC=contoso,DC=local
   5. Confirm in Entra ID > Devices that $Prefix-cli exists

 Then, on the CLIENT VM (elevated), finish the join:
   dsregcmd /join /debug   # now it should succeed
   # sign out and back in to pick up the PRT, then:
   dsregcmd /status        # AzureAdJoined: YES, AzureAdPrt: YES
   klist cloud_debug       # enabled by policy: true
   klist get krbtgt        # krbtgt/KERBEROS.MICROSOFTONLINE.COM
   net use Z: \\$saName.file.core.windows.net\labshare
==============================================================
"@ -ForegroundColor Green
