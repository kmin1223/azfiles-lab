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
    8. outbound check, then the Entra join
    9. RBAC: VM sign-in + share access

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

.EXAMPLE
  # Azure Cloud Shell (PowerShell) - already signed in
  ./deploy.ps1 -ResourceGroupName azfiles-cloudonly
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Location  = 'koreacentral',
    [string]$Prefix    = 'azfcloud',
    [string]$ShareName = 'labshare',
    [string]$VmSize    = 'Standard_D2s_v5'
)
$ErrorActionPreference = 'Stop'
$sw = [Diagnostics.Stopwatch]::StartNew()
function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# Shared with the Session 2 hybrid scripts: Graph from Cloud Shell with no
# device code. Cloud Shell signs you in to Azure but NOT to Graph - separate
# token audiences - and the device-code fallback gives you 120 seconds.
$helper = Join-Path (Split-Path $PSScriptRoot -Parent) 'session2-entra-kerberos/scripts/Connect-LabGraph.ps1'
if (-not (Test-Path $helper)) { throw "Missing $helper - run this from a full clone of the repo." }
. $helper

if (-not (Get-AzContext)) {
    throw 'No Azure context. Run this in Azure Cloud Shell (PowerShell), where you are already signed in.'
}
$graph = 'https://graph.microsoft.com/v1.0'
$users = @('labuser1', 'labuser2')

# ------------------------------------------------------------------ password
# No % or ! : Run Command parameters pass through a cmd layer that expands them
# and silently mangles the value. That cost a Session 1 deployment.
$U = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'; $L = [char[]]'abcdefghijkmnpqrstuvwxyz'
$D = [char[]]'23456789';                 $S = [char[]]'@#*-+?'
$pick = { param($set, $n) -join (1..$n | ForEach-Object { $set | Get-Random }) }
$plainPw = (& $pick $U 3) + (& $pick $L 6) + (& $pick $D 3) + (& $pick $S 2)
if ($plainPw -match '[\s"''`$%!]') { throw 'Generated password contains a forbidden character - re-run.' }
$secPw = ConvertTo-SecureString $plainPw -AsPlainText -Force

Step "0/9 Resource group $ResourceGroupName in $Location"
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
}

# ------------------------------------------------- 1. storage + Entra Kerberos
Step '1/9 Storage account with Entra Kerberos'
$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue |
    Where-Object StorageAccountName -like "$Prefix*" | Select-Object -First 1
if ($sa) {
    $saName = $sa.StorageAccountName
    Write-Host "  reusing $saName"
} else {
    $saName = "$Prefix" + (-join ((1..8) | ForEach-Object { [char[]]'abcdefghijklmnopqrstuvwxyz' | Get-Random }))
    New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName -Location $Location `
        -SkuName Standard_LRS -Kind StorageV2 -EnableLargeFileShare -MinimumTlsVersion TLS1_2 | Out-Null
    Write-Host "  created $saName"
}
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

# ------------------------------------------------------- 5. managed identity
# Hard prerequisite for AADLoginForWindows. Without it the extension still
# installs, still reports success, and the join silently does nothing.
Step '5/9 System-assigned managed identity'
$vmObj = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName
if ($vmObj.Identity -and $vmObj.Identity.Type -match 'SystemAssigned') {
    Write-Host '  already enabled'
} else {
    Update-AzVM -ResourceGroupName $ResourceGroupName -VM $vmObj -IdentityType SystemAssigned | Out-Null
    Write-Host '  enabled'
}

# ---------------------------------------------------------- 6. client config
Step '6/9 Client configuration (DNS suffix, Kerberos policy, lab tools)'
$r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -CommandId 'RunPowerShellScript' `
    -ScriptPath (Join-Path (Join-Path $PSScriptRoot 'scripts') 'client-config.ps1') `
    -Parameter @{ DnsSuffix = "$Location.cloudapp.azure.com" }
($r.Value | Where-Object Code -like '*StdOut*').Message | Write-Host

# --------------------------------------------------------------- 7. restart
Step '7/9 Restart (the DNS suffix and the Kerberos policy both need one)'
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
Write-Host '  extension installed - waiting for the join (up to 6 min)'

$joined = $false
for ($i = 0; $i -lt 12 -and -not $joined; $i++) {
    Start-Sleep 30
    try {
        $st = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString 'dsregcmd /status | Select-String "AzureAdJoined"'
        $txt  = ($st.Value | Where-Object Code -like '*StdOut*').Message
        $line = @($txt -split "`r?`n" | Where-Object { $_ -match 'AzureAdJoined' })[0]
        if ($line) { Write-Host "  $($line.Trim())" }
        if ($txt -match 'AzureAdJoined\s*:\s*YES') { $joined = $true }
    } catch { Write-Host '  (run command busy, retrying)' }
}
if (-not $joined) {
    Write-Warning @"
The device is not Entra joined after 6 minutes. Read the logs; do not guess:
  Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName ``
    -CommandId RunPowerShellScript -ScriptString 'Get-WinEvent -LogName "Microsoft-Windows-User Device Registration/Admin" -MaxEvents 15 | Format-List TimeCreated,Id,Message'
That channel is the primary evidence for device registration.
"@
}

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

# ------------------------------------------------------------------- report
$rdp = @"
full address:s:$fqdn
username:s:AzureAD\labuser1@$initialDomain
enablerdsaadauth:i:1
authentication level:i:2
"@
$rdpPath = "$HOME/azfiles-cloudonly.rdp"
$rdp | Set-Content -Path $rdpPath -Encoding ascii

Write-Host @"

==============================================================
 DEPLOYMENT COMPLETE  ($([int]$sw.Elapsed.TotalMinutes) min $($sw.Elapsed.Seconds % 60) s)
==============================================================
 storage account : $saName
 file share      : $ShareName
 users           : labuser1@$initialDomain   (has share access)
                   labuser2@$initialDomain   (none - Lab D contrast)
 password        : $plainPw
 RDP host        : $fqdn
 Entra joined    : $(if ($joined) { 'YES' } else { 'NOT YET - see the warning above' })
==============================================================
 CONNECT  (an .rdp file is at $rdpPath)

   full address:s:$fqdn
   username:s:AzureAD\labuser1@$initialDomain
   enablerdsaadauth:i:1
   authentication level:i:2

 Use the FQDN. Entra sign-in rejects a bare IP address, and it must
 match the name the device registered under.

 FIRST SIGN-IN asks you to register MFA (security defaults). Have
 Microsoft Authenticator ready - it takes about two minutes.

 A certificate warning is expected: the VM's RDP certificate is
 issued for its short name, not the Azure FQDN. Continue.
==============================================================
 FIRST THING TO RUN, as labuser1

   dsregcmd /status          AzureAdJoined YES / DomainJoined NO / AzureAdPrt YES
   klist cloud_debug         enabled by policy: 1
   klist get cifs/$saName.file.core.windows.net
   net use Z: \\$saName.file.core.windows.net\$ShareName

 Healthy signature - the cloud TGT says Kdc Called: TicketSuppliedAtLogon
 with etype Unknown (-1), and the service ticket says
 Kdc Called: KdcProxy:login.microsoftonline.com with AES-256 and Renew Time 0.
==============================================================
 LAB FAULTS  (on the VM, elevated - no Azure access needed)

   C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt        # sign out/in after
   C:\LabTools\Invoke-LabFault.ps1 -Fault ProxyMangled
   ... add -Repair to undo
==============================================================
 TEAR DOWN
   Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob
   # then delete the two users and the device object in Entra ID
==============================================================
"@ -ForegroundColor Green
