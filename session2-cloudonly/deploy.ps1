<#
.SYNOPSIS
  Session 2 (cloud-only) participant environment: Azure Files with Microsoft
  Entra Kerberos, no Active Directory anywhere.

.DESCRIPTION
  STANDALONE. This does not build on, touch, or require the Session 1 (AD DS)
  deployment - the two live side by side. There is no domain controller, no
  domain join, no Entra Connect, no Cloud Sync, and no manual step.

  Builds, in this order (the order matters - see below):
    1. storage account with Entra Kerberos (AADKERB), one file share
    2. admin consent for the auto-created storage app
    3. two CLOUD-ONLY Entra users (labuser1 / labuser2), created via Graph
    4. Windows Server 2025 VM + public IP with a DNS label
    5. system-assigned managed identity
    6. client config: DNS suffix, cloud-Kerberos policy, lab fault script, Fiddler
    7. RESTART (both of those settings need one)
    8. outbound check, then install the Entra join extension (no polling)
    9. RBAC: VM sign-in + share access
    Finally, check AzureAdJoined once before saving/downloading the report.
    A NO/unknown result is reported as incomplete; output files are still saved.

  FIVE THINGS THAT FAIL SILENTLY IF OMITTED - all learned the hard way, all
  handled below. If you adapt this script, keep them:
    - system-assigned managed identity: without it AADLoginForWindows installs,
      reports success, and the Entra join does nothing at all
    - a public IP: Azure retired default outbound access on 30 Sep 2025, so a VM
      without one has no internet - while Run Command still works, because that
      rides the Azure fabric, making the VM look healthy
    - a DNS name label: RDP with an Entra account refuses a bare IP address
    - a primary DNS suffix set BEFORE the join: otherwise the device registers
      only its short name and RDP to the FQDN fails with AADSTS293004
    - CloudKerberosTicketRetrievalEnabled needs a RESTART; check it in the same
      boot and klist cloud_debug says "enabled by policy: 0"

  The one thing that cannot be automated: security defaults force MFA
  registration on first sign-in. That is a prework item, not a bug.

.PARAMETER ResourceGroupName
  Defaults to azfiles-cloudonly. Creates the resource group if absent, or
  reuses it in the selected subscription. Pass a name to use a different lab.

.PARAMETER Prefix
  Optional explicit resource prefix (up to 11 lowercase letters/digits).
  Otherwise derived from the signed-in Azure account, tenant, subscription
  and resource group. Cloud Shell ManagedService contexts use the name after
  /home/ in pwd instead of MSI@50342; no token lookup is needed.
  Use the same context and home name in fault scripts.
  Existing labs made with the old default must pass -Prefix azfcloud.

.PARAMETER LogPath
  Parent directory for private, timestamped run folders containing deploy.log
  and lab-info.txt (resources, credentials, status and lab commands with actual
  deployment values). Defaults to $HOME/azfiles-lab-logs. After finalizing the
  output, requests browser downloads of lab-info.txt and the RDP file in Cloud
  Shell. Keep both files private; do not commit/share credentials.

.EXAMPLE
  # Azure Cloud Shell (PowerShell) - already signed in
  ./deploy.ps1

.EXAMPLE
  # Optional: use a different resource group
  ./deploy.ps1 -ResourceGroupName my-cloudonly-lab
#>
[CmdletBinding()]
param(
    [string]$ResourceGroupName = 'azfiles-cloudonly',
    [string]$Location  = 'koreacentral',
    [ValidatePattern('^[a-z0-9]{1,11}$')]
    [string]$Prefix,
    [string]$ShareName = 'labshare',
    [string]$VmSize    = 'Standard_D2s_v5',
    [ValidateNotNullOrEmpty()]
    [string]$LogPath   = (Join-Path $HOME 'azfiles-lab-logs')
)
$ErrorActionPreference = 'Stop'
$sw = [Diagnostics.Stopwatch]::StartNew()
$startedUtc = [datetime]::UtcNow
function Step([string]$m) {
    $deploymentInfo['Last step'] = $m
    $deploymentInfo['Elapsed'] = Format-CloudDeploymentElapsed $sw.Elapsed
    Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo
    Write-Host "`n[+$($deploymentInfo['Elapsed'])] === $m ===" -ForegroundColor Cyan
}

# Shared with the Session 2 hybrid scripts: Graph from Cloud Shell with no
# device code. Cloud Shell signs you in to Azure but NOT to Graph - separate
# token audiences - and the device-code fallback gives you 120 seconds.
$helper = Join-Path (Split-Path $PSScriptRoot -Parent) 'session2-entra-kerberos/scripts/Connect-LabGraph.ps1'
if (-not (Test-Path $helper)) { throw "Missing $helper - run this from a full clone of the repo." }
. $helper

$azContext = Get-AzContext -ErrorAction Stop
if (-not $azContext) {
    throw 'No Azure context. Run this in Azure Cloud Shell (PowerShell), where you are already signed in.'
}
. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'CloudOnlyLabNaming.ps1')
$namingParameters = @{ ResourceGroupName = $ResourceGroupName; AzureContext = $azContext }
if ($PSBoundParameters.ContainsKey('Prefix')) { $namingParameters.Prefix = $Prefix }
$Prefix = Resolve-CloudOnlyLabPrefix @namingParameters
Write-Host "Cloud-only resource prefix: $Prefix (use this value with -Prefix when accessing this lab from another login context)."
$graph = 'https://graph.microsoft.com/v1.0'
$users = @('labuser1', 'labuser2')

. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'CloudOnlyDeploymentLog.ps1')
. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'CloudOnlyDeploymentOutput.ps1')
$logRun = Start-CloudDeploymentLog -LogPath $LogPath
$deploymentInfo = [ordered]@{
    Status = 'IN PROGRESS'
    'Started UTC' = $startedUtc.ToString('o')
    'Resource group' = $ResourceGroupName
    'Azure tenant ID' = [string]$azContext.Tenant.Id
    'Subscription ID' = [string]$azContext.Subscription.Id
    'Subscription name' = [string]$azContext.Subscription.Name
    'Requested location' = $Location
    'Cloud Shell script directory' = $PSScriptRoot
    Prefix = $Prefix
    'Storage account' = 'not yet recorded'
    'File share' = $ShareName
    'VM name' = "$Prefix-cli"
    'User baseline' = 'NOT VERIFIED'
    Transcript = $logRun.Transcript
}
$deploymentFailure = $null
$deploymentCompleted = $false
$joined = $false
try {
Write-Host "Transcript: $($logRun.Transcript)"
Write-Host "Lab info  : $($logRun.InfoFile)"
Write-Host "Started UTC: $($deploymentInfo['Started UTC']); resource group: $ResourceGroupName; prefix: $Prefix"
Write-Warning 'Logs contain generated lab credentials. Keep them private; do not commit or share them. Cloud Shell retention depends on persistent storage; download the files if needed.'
Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo

# ------------------------------------------------------------------ password
# No % or ! : Run Command parameters pass through a cmd layer that expands them
# and silently mangles the value. That cost a Session 1 deployment.
$U = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'; $L = [char[]]'abcdefghijkmnpqrstuvwxyz'
$D = [char[]]'23456789';                 $S = [char[]]'@#*-+?'
$pick = { param($set, $n) -join (1..$n | ForEach-Object { $set | Get-Random }) }
$plainPw = (& $pick $U 3) + (& $pick $L 6) + (& $pick $D 3) + (& $pick $S 2)
if ($plainPw -match '[\s"''`$%!]') { throw 'Generated password contains a forbidden character - re-run.' }
$secPw = ConvertTo-SecureString $plainPw -AsPlainText -Force
$deploymentInfo['Generated password'] = $plainPw

Step "0/9 Resource group $ResourceGroupName in $Location"
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
}

# ------------------------------------------------- 1. storage + Entra Kerberos
Step '1/9 Storage account with Entra Kerberos'
$accounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop)
if (-not $PSBoundParameters.ContainsKey('Prefix') -and
    @($accounts | Where-Object { $_.StorageAccountName.StartsWith('azfcloud', [StringComparison]::Ordinal) }).Count) {
    throw 'CLOUD_PREFIX_LEGACY_LAB: This resource group contains an account matching the old azfcloud prefix. To reuse that lab, specify its exact previous -Prefix (usually azfcloud); for a new lab, use a separate resource group. No storage account was selected.'
}
$matchingAccounts = @($accounts | Where-Object { $_.StorageAccountName.StartsWith($Prefix, [StringComparison]::Ordinal) })
if ($matchingAccounts.Count -gt 1) {
    throw "CLOUD_STORAGE_AMBIGUOUS: More than one storage account matches '$Prefix' in '$ResourceGroupName'. Use the intended resource group/prefix; no storage account was selected."
}
$sa = $matchingAccounts | Select-Object -First 1
$storageTags = @{ securityControl = 'ignore' }
if ($sa) {
    $saName = $sa.StorageAccountName
    Update-AzTag -ResourceId $sa.Id -Tag $storageTags -Operation Merge -ErrorAction Stop | Out-Null
    Write-Host "  reusing $saName"
} else {
    $saName = "$Prefix" + (-join ((1..8) | ForEach-Object { [char[]]'abcdefghijklmnopqrstuvwxyz' | Get-Random }))
    New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName -Location $Location `
        -SkuName Standard_LRS -Kind StorageV2 -EnableLargeFileShare -MinimumTlsVersion TLS1_2 `
        -Tag $storageTags | Out-Null
    Write-Host "  created $saName"
}
Write-Host '  storage tag: securityControl=ignore'
$deploymentInfo['Storage account'] = $saName
Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo
# Cloud-only: no ActiveDirectoryDomainName / DomainGuid to supply. That is the point.
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
    -EnableAzureActiveDirectoryKerberosForFile $true | Out-Null
$ctx = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).Context
if (-not (Get-AzStorageShare -Name $ShareName -Context $ctx -ErrorAction SilentlyContinue)) {
    New-AzStorageShare -Name $ShareName -Context $ctx | Out-Null
}
Write-Host "  AADKERB enabled, share '$ShareName' ready"

# --------------------------------------------------------- 2. admin consent
Step '2/9 Admin consent for the storage account app'
Connect-LabGraph -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All', 'User.ReadWrite.All'
$spn = $null
for ($i = 0; $i -lt 6 -and -not $spn; $i++) {
    $spn = Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $saName.file.core.windows.net'"
    if (-not $spn) { Write-Host '  waiting for the storage app to appear...'; Start-Sleep 20 }
}
if (-not $spn) { throw "Storage app for $saName never appeared - re-run in a minute." }
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
Get-MgOauth2PermissionGrant -Filter "clientId eq '$($spn.Id)'" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
New-MgOauth2PermissionGrant -BodyParameter @{
    clientId = $spn.Id; consentType = 'AllPrincipals'
    resourceId = $graphSp.Id; scope = 'openid profile User.Read'
} | Out-Null
Write-Host '  consent granted: openid profile User.Read'

# ------------------------------------------------------ 3. cloud-only users
# Two of them: Lab D needs a second identity to contrast against when only one
# of them is granted access.
# Invoke-MgGraphRequest, not Get-MgUser: Cloud Shell ships the Microsoft.Graph
# sub-modules unevenly and Microsoft.Graph.Users is often missing, while
# Invoke-MgGraphRequest lives in the same module as Connect-MgGraph.
Step '3/9 Cloud-only Entra users'
$org = Get-MgOrganization | Select-Object -First 1
$initialDomain = ($org.VerifiedDomains | Where-Object IsInitial).Name
$deploymentInfo['Entra tenant ID'] = [string]$org.Id
$deploymentInfo['Initial domain'] = $initialDomain
$deploymentInfo['Storage app ID'] = [string]$spn.AppId
$deploymentInfo['Storage service principal ID'] = [string]$spn.Id
$deploymentInfo['Lab users'] = ($users | ForEach-Object { "$_@$initialDomain" }) -join ', '
Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo
$userIds = @{}
foreach ($u in $users) {
    $upn = "$u@$initialDomain"
    $flt = [uri]::EscapeDataString("userPrincipalName eq '$upn'")
    $found = (Invoke-MgGraphRequest -Method GET `
        -Uri "$graph/users?`$filter=$flt&`$select=id,userPrincipalName").value | Select-Object -First 1
    # forceChangePasswordNextSignIn = false: a forced change on first sign-in
    # derails an RDP-based lab for reasons unrelated to anything being taught.
    $pwProfile = @{ password = $plainPw; forceChangePasswordNextSignIn = $false }
    if ($found) {
        Invoke-MgGraphRequest -Method PATCH -Uri "$graph/users/$($found.id)" `
            -Body @{ passwordProfile = $pwProfile } | Out-Null
        $userIds[$u] = $found.id
        Write-Host "  $upn exists - password reset"
    } else {
        $new = Invoke-MgGraphRequest -Method POST -Uri "$graph/users" -Body @{
            accountEnabled = $true; displayName = $u; mailNickname = $u
            userPrincipalName = $upn; passwordProfile = $pwProfile
        }
        $userIds[$u] = $new.id
        Write-Host "  created $upn"
    }
}

# --------------------------------------------------------------- 4. VM + IP
Step '4/9 Windows Server 2025 VM'
$vmName = "$Prefix-cli"
$cred   = New-Object System.Management.Automation.PSCredential ('localadmin', $secPw)
if (-not (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -ErrorAction SilentlyContinue)) {
    # WS2025 rather than Windows 11: cloud-only needs Win11 Ent/Pro or WS2025,
    # and Windows *client* images in Azure require an eligible subscription type
    # that participants may not have. WS2025 Desktop Experience is supported by
    # the AADLoginForWindows extension and has no such constraint.
    New-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -Location $Location `
        -Image 'MicrosoftWindowsServer:WindowsServer:2025-datacenter-azure-edition:latest' `
        -Size $VmSize -Credential $cred -OpenPorts 3389 | Out-Null
    Write-Host "  created $vmName"
} else {
    Write-Host "  $vmName exists - reusing"
}

Step '4b/9 Public IP with a DNS label'
$nicId = (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName).NetworkProfile.NetworkInterfaces[0].Id
$nic   = Get-AzNetworkInterface -ResourceId $nicId
if (-not $nic.IpConfigurations[0].PublicIpAddress) {
    $pipName = "$vmName-pip"
    $pip = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $pipName -ErrorAction SilentlyContinue
    if (-not $pip) {
        $pip = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $pipName `
            -Location $Location -AllocationMethod Static -Sku Standard -DomainNameLabel $vmName
    }
    $nic.IpConfigurations[0].PublicIpAddress = $pip
    Set-AzNetworkInterface -NetworkInterface $nic | Out-Null
    $nic = Get-AzNetworkInterface -ResourceId $nicId
}
$pipObj = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName `
    -Name (Split-Path $nic.IpConfigurations[0].PublicIpAddress.Id -Leaf)
if (-not $pipObj.DnsSettings -or -not $pipObj.DnsSettings.Fqdn) {
    $pipObj.DnsSettings = New-Object Microsoft.Azure.Commands.Network.Models.PSPublicIpAddressDnsSettings `
        -Property @{ DomainNameLabel = $vmName }
    Set-AzPublicIpAddress -PublicIpAddress $pipObj | Out-Null
    $pipObj = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $pipObj.Name
}
$fqdn = $pipObj.DnsSettings.Fqdn
$ip   = $pipObj.IpAddress
Write-Host "  $fqdn  ($ip)"
$deploymentInfo['RDP host'] = $fqdn
$deploymentInfo['Public IP'] = $ip
$deploymentInfo['Public IP resource ID'] = $pipObj.Id
$deploymentInfo['NIC resource ID'] = $nic.Id
$deploymentInfo['Subnet resource ID'] = $nic.IpConfigurations[0].Subnet.Id
$deploymentInfo['VNet resource ID'] = $nic.IpConfigurations[0].Subnet.Id -replace '/subnets/[^/]+$', ''
$deploymentInfo['NIC NSG resource ID'] = $nic.NetworkSecurityGroup.Id
Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo

# ------------------------------------------------------- 5. managed identity
# Hard prerequisite for AADLoginForWindows. Without it the extension still
# installs, still reports success, and the join silently does nothing.
Step '5/9 System-assigned managed identity'
$vmObj = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName
$deploymentInfo['VM resource ID'] = $vmObj.Id
$deploymentInfo['VM location'] = $vmObj.Location
$deploymentInfo['VM size'] = $vmObj.HardwareProfile.VmSize
$deploymentInfo['OS disk resource ID'] = $vmObj.StorageProfile.OsDisk.ManagedDisk.Id
if ($vmObj.Identity -and $vmObj.Identity.Type -match 'SystemAssigned') {
    Write-Host '  already enabled'
} else {
    Update-AzVM -ResourceGroupName $ResourceGroupName -VM $vmObj -IdentityType SystemAssigned | Out-Null
    Write-Host '  enabled'
}

# ---------------------------------------------------------- 6. client config
Step '6/9 Client configuration (DNS suffix, Kerberos policy, lab tools)'
. (Join-Path (Join-Path $PSScriptRoot 'scripts') 'CloudOnlyRunCommand.ps1')
$r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -CommandId 'RunPowerShellScript' `
    -ScriptPath (Join-Path (Join-Path $PSScriptRoot 'scripts') 'client-config.ps1') `
    -Parameter @{ DnsSuffix = "$Location.cloudapp.azure.com" }
Assert-CloudOnlyRunCommand -Result $r -CompletionMarker 'CLIENT_CONFIG_DONE'
$deploymentInfo['Capture tools'] = 'Machine installation verified; user Inspector loading/capture NOT VERIFIED'
$deploymentInfo['PowerShell tools'] = 'Az subset and AzFilesHybrid imports verified; Azure diagnostics NOT RUN. VM inventory: C:\LabTools\powershell-modules.json'
$deploymentInfo['Trace helper'] = 'C:\LabTools\Get-KerberosEvidence.ps1: StartTrace, StopTrace (auto-convert), ConvertTrace'
Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo

# --------------------------------------------------------------- 7. restart
Step '7/9 Restart (DNS suffix, Kerberos policy, capture-tool installation)'
Restart-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName | Out-Null
Start-Sleep 45

# ------------------------------------------------- 8. egress check, then join
Step '8/9 Outbound check, then the Entra join'
$probe = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -CommandId 'RunPowerShellScript' -ScriptString @'
foreach ($h in 'login.microsoftonline.com','device.login.microsoftonline.com',
               'enterpriseregistration.windows.net','pas.windows.net') {
    $tcp = Test-NetConnection $h -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Output "$h TCP443=$tcp"
}
'@
$probeTxt = ($probe.Value | Where-Object Code -like '*StdOut*').Message
$probeTxt.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  $_" }
if ($probeTxt -match 'TCP443=False') {
    throw 'The VM cannot reach a device-registration endpoint on 443. Fix egress (public IP or NAT gateway) and re-run.'
}

# Re-installed every run: a failed join is NOT retried by the extension, so a
# stale failed install would keep reporting success while nothing happens.
Remove-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -Name 'AADLoginForWindows' -Force -ErrorAction SilentlyContinue | Out-Null
Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -Name 'AADLoginForWindows' -Publisher 'Microsoft.Azure.ActiveDirectory' `
    -ExtensionType 'AADLoginForWindows' -TypeHandlerVersion '2.0' -Location $Location | Out-Null
Write-Host '  extension installed - continuing with RBAC; Join will be checked once before the final report'
$deploymentInfo['Entra joined'] = 'NOT CHECKED'

# ------------------------------------------------------------------ 9. RBAC
# 'Virtual Machine Administrator Login' is what makes the lab user a local admin
# on the VM, which is what lets Invoke-LabFault.ps1 elevate with consent only.
# Only labuser1 gets share access - Lab D uses labuser2 as the contrast.
Step '9/9 RBAC'
$rgScope = (Get-AzResourceGroup -Name $ResourceGroupName).ResourceId
$saId    = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).Id
foreach ($u in $users) {
    if (-not (Get-AzRoleAssignment -ObjectId $userIds[$u] -Scope $rgScope `
                -RoleDefinitionName 'Virtual Machine Administrator Login' -ErrorAction SilentlyContinue)) {
        New-AzRoleAssignment -ObjectId $userIds[$u] `
            -RoleDefinitionName 'Virtual Machine Administrator Login' -Scope $rgScope | Out-Null
    }
    Write-Host "  $u : VM sign-in"
}
if (-not (Get-AzRoleAssignment -ObjectId $userIds['labuser1'] -Scope $saId `
            -RoleDefinitionName 'Storage File Data SMB Share Contributor' -ErrorAction SilentlyContinue)) {
    New-AzRoleAssignment -ObjectId $userIds['labuser1'] `
        -RoleDefinitionName 'Storage File Data SMB Share Contributor' -Scope $saId | Out-Null
}
Write-Host '  labuser1 : share Contributor  (labuser2 deliberately has none - Lab D)'
Write-Host '  NOTE: role assignments take a few minutes to propagate.'
$deploymentInfo['Resource group ID'] = $rgScope
$deploymentInfo['Storage resource ID'] = $saId
$deploymentInfo['Share UNC'] = "\\$saName.file.core.windows.net\$ShareName"
$deploymentInfo['CIFS SPN'] = "cifs/$saName.file.core.windows.net"
$deploymentInfo['labuser1 object ID'] = $userIds['labuser1']
$deploymentInfo['labuser2 object ID'] = $userIds['labuser2']
$deploymentInfo['VM role assigned'] = 'Both lab users: Virtual Machine Administrator Login at RG scope'
$deploymentInfo['SMB role assigned'] = 'labuser1: Storage File Data SMB Share Contributor at storage-account scope'
$deploymentInfo['labuser2 SMB role'] = 'Not assigned by this deployment; inherited permissions are not ruled out'
$deploymentInfo['Directory scope'] = 'Users, device and storage app are tenant objects, not RG resources'

# Check once after all configuration, without delaying role assignment or polling.
Step 'Final Entra join check (single attempt)'
Write-Host '  One Run Command request; its execution time still applies. No retry/sleep loop.'
$joinResult = Get-CloudOnlyJoinStatus -ResourceGroupName $ResourceGroupName -VMName $vmName
$joined = $joinResult.Joined
$deploymentInfo['Entra joined'] = $joinResult.Status
$deploymentInfo['Entra join checked UTC'] = $joinResult.CheckedUtc
if ($joinResult.Error) { $deploymentInfo['Entra join check error'] = $joinResult.Error }
if (-not $joined) {
    Write-Warning @"
Entra Join is not confirmed ($($joinResult.Status)). RBAC configuration is applied;
output files will still be saved/downloaded, but the lab is NOT ready for Entra
user sign-in or Lab A. Do not assume Join will succeed later without checking.
Review AADLoginForWindows extension status and Microsoft-Windows-User Device
Registration/Admin on the VM. After addressing the cause, check dsregcmd /status
again; a full redeployment is not a Join diagnostic or repair.
"@
}

# ------------------------------------------------------------------- report
$rdp = @"
full address:s:$fqdn
username:s:AzureAD\labuser1@$initialDomain
enablerdsaadauth:i:1
authentication level:i:2
"@
$rdpPath = "$HOME/azfiles-cloudonly.rdp"
$rdp | Set-Content -LiteralPath $rdpPath -Encoding ascii
$deploymentInfo['RDP file'] = $rdpPath
$logRun.Commands = New-CloudDeploymentCommands -Info $deploymentInfo
Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo

Write-Host @"

==============================================================
 $(if ($joined) { 'DEPLOYMENT CONFIGURATION APPLIED' } else { 'DEPLOYMENT INCOMPLETE - ENTRA JOIN NOT CONFIRMED' })
==============================================================
 resource group  : $ResourceGroupName
 storage account : $saName
 resource prefix : $Prefix
 file share      : $ShareName
 lab user        : labuser1@$initialDomain
 RDP host        : $fqdn
 Entra joined    : $($joinResult.Status)$(if (-not $joined) { ' - NOT CONFIRMED; see the warning above' })
 lab output      : $($logRun.InfoFile)
 RDP file        : $rdpPath

 lab-info.txt contains resource IDs, private credentials and commands
 for Lab A/B/C, Consent, trace capture/conversion and Azure diagnostics.
 Open it as a guide; do NOT execute the whole file as a script.
 After saving final status/elapsed time, both files will be submitted
 to Cloud Shell's browser download command if available.
 Check Downloads and allow multiple downloads if your browser asks.
 User login, Kerberos tickets and actual file access remain UNVERIFIED.
 Keep downloaded files private. Do not redeploy a healthy lab to repair faults.
==============================================================
"@ -ForegroundColor Green
$deploymentCompleted = $true
} catch {
    $deploymentFailure = $_
    Write-Host "DEPLOYMENT FAILED: $($_.Exception.Message)" -ForegroundColor Red
    throw
} finally {
    $sw.Stop()
    Complete-CloudDeploymentLog -Run $logRun -Info $deploymentInfo -Elapsed $sw.Elapsed `
        -Completed $deploymentCompleted -Joined $joined -Failure $deploymentFailure
}

# Download only after the final status/elapsed time is persisted and the transcript closes.
if ($deploymentCompleted) {
    Send-CloudDeploymentDownloads -Paths @($logRun.InfoFile, $rdpPath)
}
