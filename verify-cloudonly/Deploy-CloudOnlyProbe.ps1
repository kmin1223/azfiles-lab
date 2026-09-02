<#
.SYNOPSIS
  Minimal probe: can a CLOUD-ONLY Entra user, signed in with a PASSWORD, get a
  Kerberos ticket for Azure Files on an Entra-joined VM?

.DESCRIPTION
  This is NOT a lab. It is a single-question experiment, and the answer decides
  whether Session 2's participant track can be cloud-only.

  THE QUESTION
    Microsoft's Entra Kerberos guidance carries a line about signing in with a
    "key-based method (WHfB/FIDO2)". If that is a hard requirement for cloud-only
    identities, then a participant who RDPs in with a password will never get a
    cloud TGT - and an RDP-based lab cannot use Windows Hello. The whole
    cloud-only design dies on that one sentence, so we test it before building
    anything on top of it.

  WHAT THIS BUILDS (~10 minutes, a few cents an hour)
    - a storage account with Microsoft Entra Kerberos (AADKERB) enabled, no AD DS
    - one file share
    - one CLOUD-ONLY Entra user (created via Graph; never synced from anywhere)
    - one Windows Server 2025 VM, Entra JOINED by the AADLoginForWindows
      extension - no domain, no DC, no Cloud Sync, no hybrid join
    - the RBAC needed to sign in to the VM and reach the share
    - CloudKerberosTicketRetrievalEnabled = 1 on the client

  WS2025 rather than Windows 11: cloud-only needs Win11 Ent/Pro or WS2025, and
  Windows *client* images in Azure require an eligible subscription type, which
  participants may not have. If WS2025 works, the lab has no licensing problem.

  WHAT IT DELIBERATELY DOES NOT BUILD
    No faults, no collector, no second user, no lab content. If the probe passes
    we build those; if it fails we have wasted ten minutes instead of a week.

.EXAMPLE
  # Azure Cloud Shell (PowerShell) - already signed in
  ./Deploy-CloudOnlyProbe.ps1 -ResourceGroupName azfiles-cloudonly-probe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Location = 'koreacentral',
    [string]$Prefix   = 'cloudprobe',
    [string]$UserName = 'clouduser1',
    [string]$ShareName = 'labshare'
)
$ErrorActionPreference = 'Stop'
$sw = [Diagnostics.Stopwatch]::StartNew()
function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# Reuse the Session 2 helper: Graph from Cloud Shell with no device code.
$helper = Join-Path (Split-Path $PSScriptRoot -Parent) 'session2-entra-kerberos/scripts/Connect-LabGraph.ps1'
if (-not (Test-Path $helper)) { throw "Missing $helper - run this from a full clone of the repo." }
. $helper

if (-not (Get-AzContext)) {
    throw 'No Azure context. Run this in Azure Cloud Shell (PowerShell), where you are already signed in.'
}

# ---------------------------------------------------------------- password
# Same charset rules the Session 1 deploy learned the hard way: no % or ! (they
# get mangled by the cmd layer Run Command parameters pass through), no quotes,
# backtick, $ or whitespace.
$chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'
$lower = [char[]]'abcdefghijkmnpqrstuvwxyz'
$digit = [char[]]'23456789'
$symb  = [char[]]'@#*-+?'
$rand  = { param($set, $n) -join (1..$n | ForEach-Object { $set | Get-Random }) }
$plainPw = (& $rand $chars 3) + (& $rand $lower 6) + (& $rand $digit 3) + (& $rand $symb 2)
if ($plainPw -match '[\s"''`$%!]') { throw 'Generated password contains a forbidden character - re-run.' }
$secPw = ConvertTo-SecureString $plainPw -AsPlainText -Force

Step "0/6 Resource group $ResourceGroupName in $Location"
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
}

# --------------------------------------------------- 1. storage + AADKERB
Step '1/6 Storage account with Entra Kerberos (no AD DS anywhere)'
# Re-running the probe is normal (it took three attempts to get past Graph the
# first time). Reuse the account instead of littering the RG with new ones.
$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue |
    Where-Object StorageAccountName -like "$Prefix*" | Select-Object -First 1
if ($sa) {
    $saName = $sa.StorageAccountName
    Write-Host "  reusing $saName"
} else {
    $suffix = -join ((1..8) | ForEach-Object { [char[]]'abcdefghijklmnopqrstuvwxyz' | Get-Random })
    $saName = "$Prefix$suffix"
    New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
        -Location $Location -SkuName Standard_LRS -Kind StorageV2 `
        -EnableLargeFileShare -MinimumTlsVersion TLS1_2 | Out-Null
    Write-Host "  created $saName"
}

# For CLOUD-ONLY there is no ActiveDirectoryDomainName / DomainGuid to supply -
# that is the whole point. Just switch the identity source to AADKERB.
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
    -EnableAzureActiveDirectoryKerberosForFile $true | Out-Null
$ctx = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).Context
if (-not (Get-AzStorageShare -Name $ShareName -Context $ctx -ErrorAction SilentlyContinue)) {
    New-AzStorageShare -Name $ShareName -Context $ctx | Out-Null
}
Write-Host "  AADKERB enabled, share '$ShareName' ready"

# --------------------------------------------------- 2. admin consent
Step '2/6 Admin consent for the storage account app'
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
    clientId    = $spn.Id
    consentType = 'AllPrincipals'
    resourceId  = $graphSp.Id
    scope       = 'openid profile User.Read'
} | Out-Null
Write-Host '  consent granted: openid profile User.Read'

# --------------------------------------------------- 3. cloud-only user
Step '3/6 Cloud-only Entra user (created in Entra, synced from nowhere)'
# Cloud Shell ships the Microsoft.Graph sub-modules unevenly: Applications and
# Identity.DirectoryManagement are there, Microsoft.Graph.Users is not, so
# Get-MgUser/New-MgUser blow up. Invoke-MgGraphRequest lives in
# Microsoft.Graph.Authentication - the same module Connect-MgGraph comes from -
# so calling the REST API directly needs nothing extra and cannot drift.
# Note: these return hashtables with camelCase keys, not typed objects.
$graph = 'https://graph.microsoft.com/v1.0'

$org = Get-MgOrganization | Select-Object -First 1
$initialDomain = ($org.VerifiedDomains | Where-Object IsInitial).Name
$upn = "$UserName@$initialDomain"

$flt  = [uri]::EscapeDataString("userPrincipalName eq '$upn'")
$sel  = 'id,userPrincipalName,onPremisesSyncEnabled'
$found = (Invoke-MgGraphRequest -Method GET `
    -Uri "$graph/users?`$filter=$flt&`$select=$sel").value | Select-Object -First 1

# ForceChangePasswordNextSignIn = false matters: a forced change on first
# sign-in derails an RDP-based test for reasons that have nothing to do with
# the question we are asking.
$pwProfile = @{ password = $plainPw; forceChangePasswordNextSignIn = $false }

if ($found) {
    Write-Host "  $upn already exists - resetting its password"
    Invoke-MgGraphRequest -Method PATCH -Uri "$graph/users/$($found.id)" `
        -Body @{ passwordProfile = $pwProfile } | Out-Null
    $userId = $found.id
} else {
    $new = Invoke-MgGraphRequest -Method POST -Uri "$graph/users" -Body @{
        accountEnabled    = $true
        displayName       = $UserName
        mailNickname      = $UserName
        userPrincipalName = $upn
        passwordProfile   = $pwProfile
    }
    $userId = $new.id
    Write-Host "  created $upn"
}

# onPremisesSyncEnabled must be null/false here - if it is True you are looking
# at a hybrid user and this probe is not testing what you think it is.
$check = Invoke-MgGraphRequest -Method GET -Uri "$graph/users/$userId`?`$select=$sel"
Write-Host "  onPremisesSyncEnabled = $($check.onPremisesSyncEnabled)  (must NOT be True)"

# --------------------------------------------------- 4. VM + Entra join
Step '4/6 Windows Server 2025 VM, Entra joined by extension (no domain)'
$vmName  = "$Prefix-cli"
$localAd = 'localadmin'   # break-glass only; the probe signs in as the Entra user
$cred    = New-Object System.Management.Automation.PSCredential ($localAd, $secPw)

$vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -ErrorAction SilentlyContinue
if (-not $vm) {
    New-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -Location $Location `
        -Image 'MicrosoftWindowsServer:WindowsServer:2025-datacenter-azure-edition:latest' `
        -Size 'Standard_D2s_v5' -Credential $cred -OpenPorts 3389 | Out-Null
    Write-Host "  created $vmName"
} else {
    Write-Host "  $vmName already exists - reusing"
}

# A public IP is not optional here, and not only for RDP. Azure retired DEFAULT
# OUTBOUND ACCESS on 30 Sep 2025: a VM with no public IP and no NAT gateway has
# no route to the internet at all. The VM still answers Run Command (that rides
# the Azure fabric, not the internet), so the box looks alive while the Entra
# join quietly fails - which is exactly how this probe failed the first time.
Step '  Public IP (required for outbound - no default outbound access since Sep 2025)'
$nicId = (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName
         ).NetworkProfile.NetworkInterfaces[0].Id
$nic   = Get-AzNetworkInterface -ResourceId $nicId
if (-not $nic.IpConfigurations[0].PublicIpAddress) {
    $pipName = "$vmName-pip"
    $pip = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $pipName -ErrorAction SilentlyContinue
    if (-not $pip) {
        # A DNS name label is NOT cosmetic here. RDP with an Entra ("web")
        # account refuses an IP address outright:
        #   "IP addresses are not supported ... provide the NetBIOS domain name
        #    or FQDN"
        # so without an FQDN nobody can sign in as the cloud user at all.
        $pip = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $pipName `
            -Location $Location -AllocationMethod Static -Sku Standard `
            -DomainNameLabel $vmName
    }
    $nic.IpConfigurations[0].PublicIpAddress = $pip
    Set-AzNetworkInterface -NetworkInterface $nic | Out-Null
    Write-Host "  attached $pipName"
} else {
    Write-Host '  already has one'
}

# Retro-fit a DNS label if the IP was created without one (earlier runs).
$pipObj = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName `
    -Name (Split-Path (Get-AzNetworkInterface -ResourceId $nicId).IpConfigurations[0].PublicIpAddress.Id -Leaf)
if (-not $pipObj.DnsSettings -or -not $pipObj.DnsSettings.Fqdn) {
    $pipObj.DnsSettings = New-Object Microsoft.Azure.Commands.Network.Models.PSPublicIpAddressDnsSettings `
        -Property @{ DomainNameLabel = $saName }
    Set-AzPublicIpAddress -PublicIpAddress $pipObj | Out-Null
    $pipObj = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $pipObj.Name
}
$fqdn = $pipObj.DnsSettings.Fqdn
Write-Host "  FQDN: $fqdn"

# Prove outbound BEFORE installing the extension. Without this check the only
# symptom is "AzureAdJoined : NO", which sends you to debug Entra instead of
# networking. DNS is deliberately part of the test: the platform resolver answers
# even with no internet, so "DNS yes / 443 no" is the signature of no egress.
Step '  Outbound connectivity check'
$probe = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -CommandId 'RunPowerShellScript' -ScriptString @'
# All four are required by device registration, not just login.microsoftonline.com.
foreach ($h in 'login.microsoftonline.com','device.login.microsoftonline.com',
               'enterpriseregistration.windows.net','pas.windows.net') {
    $tcp = Test-NetConnection $h -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Output "$h TCP443=$tcp"
}
'@
$probeTxt = ($probe.Value | Where-Object Code -like '*StdOut*').Message
$probeTxt.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  $_" }
if ($probeTxt -match 'TCP443=False') {
    throw @"
The VM cannot reach one of the device-registration endpoints on 443, so the Entra
join cannot possibly work. Fix egress first - attach a public IP or a NAT gateway
to the subnet - then re-run. (DNS answering while 443 fails is the classic
'no default outbound access' signature; Azure retired default outbound in Sep 2025.)
"@
}

# A SYSTEM-ASSIGNED MANAGED IDENTITY IS A HARD PREREQUISITE for
# AADLoginForWindows. Without it the extension still installs and still reports
# success - and the Entra join SILENTLY FAILS. The only symptom is
# "AzureAdJoined : NO" with nothing wrong anywhere else, which is a superb way to
# lose an afternoon. The portal's "Login with Microsoft Entra ID" checkbox turns
# the identity on for you; adding the extension by hand does not.
Step '  System-assigned managed identity (silent prerequisite)'
$vmObj = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName
if ($vmObj.Identity -and $vmObj.Identity.Type -match 'SystemAssigned') {
    Write-Host "  already enabled ($($vmObj.Identity.PrincipalId))"
} else {
    Update-AzVM -ResourceGroupName $ResourceGroupName -VM $vmObj -IdentityType SystemAssigned | Out-Null
    $vmObj = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName
    Write-Host "  enabled ($($vmObj.Identity.PrincipalId))"
}

# The Entra device registers under the machine's own name(s). RDP with an Entra
# ("web") account then asks Entra to find a device matching the host name you
# typed - and refuses a bare IP address:
#   AADSTS293004: The target-device identifier <fqdn> was not found in the tenant
# So the VM must KNOW its Azure FQDN before it registers. Giving it a primary DNS
# suffix means it registers <vm>.<region>.cloudapp.azure.com, which is exactly
# what participants will type. Without this, every participant would have to edit
# their own hosts file - which needs local admin on a corporate laptop.
# The suffix only takes effect after a restart, so this happens BEFORE the join.
Step '  Primary DNS suffix (so the device registers its Azure FQDN)'
$dnsSuffix = "$Location.cloudapp.azure.com"
$suffixScript = @"
`$p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
Set-ItemProperty -Path `$p -Name 'Domain'    -Value '$dnsSuffix'
Set-ItemProperty -Path `$p -Name 'NV Domain' -Value '$dnsSuffix'
Write-Output "primary DNS suffix = $dnsSuffix"
"@
$tmpS = New-TemporaryFile
Set-Content -Path $tmpS -Value $suffixScript
try {
    $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
        -CommandId 'RunPowerShellScript' -ScriptPath $tmpS
    Write-Host "  $((($r.Value | Where-Object Code -like '*StdOut*').Message).Trim())"
} finally { Remove-Item $tmpS -Force }
Write-Host '  restarting so the suffix applies before registration...'
Restart-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName | Out-Null
Start-Sleep 45

# THE extension under test. It performs a Microsoft Entra JOIN (not hybrid) and
# enables sign-in to the VM with Entra credentials. If this fails on WS2025 the
# whole cloud-only participant track needs a different client OS.
# Re-installed every run on purpose: the extension does NOT retry a failed join,
# so a stale failed install would keep reporting success while nothing happens.
Step '  AADLoginForWindows extension (this is what performs the Entra join)'
Remove-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -Name 'AADLoginForWindows' -Force -ErrorAction SilentlyContinue | Out-Null
Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $vmName `
    -Name 'AADLoginForWindows' -Publisher 'Microsoft.Azure.ActiveDirectory' `
    -ExtensionType 'AADLoginForWindows' -TypeHandlerVersion '2.0' `
    -Location $Location | Out-Null
Write-Host '  extension installed'

# --------------------------------------------------- 5. RBAC
Step '5/6 RBAC: VM sign-in + share access for the cloud user'
$rgScope = (Get-AzResourceGroup -Name $ResourceGroupName).ResourceId
$saId    = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).Id
foreach ($r in @(
    @{ Role = 'Virtual Machine Administrator Login';        Scope = $rgScope },
    @{ Role = 'Storage File Data SMB Share Contributor';    Scope = $saId })) {
    $existing = Get-AzRoleAssignment -ObjectId $userId -Scope $r.Scope `
        -RoleDefinitionName $r.Role -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-AzRoleAssignment -ObjectId $userId -RoleDefinitionName $r.Role -Scope $r.Scope | Out-Null
    }
    Write-Host "  $($r.Role)"
}
Write-Host '  NOTE: role assignments can take a few minutes to propagate.'

# --------------------------------------------------- 6. client policy
Step '6/6 CloudKerberosTicketRetrievalEnabled = 1 on the client'
$clientScript = @'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name CloudKerberosTicketRetrievalEnabled -Value 1 -Type DWord
Write-Output 'CloudKerberosTicketRetrievalEnabled = 1'
dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|TenantName'
'@
$tmp = New-TemporaryFile
Set-Content -Path $tmp -Value $clientScript
try {
    $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
        -CommandId 'RunPowerShellScript' -ScriptPath $tmp
    ($r.Value | Where-Object Code -like '*StdOut*').Message | Write-Host
} finally { Remove-Item $tmp -Force }

# Find the public IP through the VM's own NIC rather than by grabbing the first
# one in the resource group, and give the allocation a moment to appear - a
# dynamic address reads back empty until the VM is running, which produced an
# .rdp file with a blank "full address" on the first run.
Step 'Resolving the public IP'
$ip = $null
for ($i = 0; $i -lt 10 -and -not $ip; $i++) {
    try {
        $nicId = (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName
                 ).NetworkProfile.NetworkInterfaces[0].Id
        $nic   = Get-AzNetworkInterface -ResourceId $nicId
        $pipId = $nic.IpConfigurations[0].PublicIpAddress.Id
        if ($pipId) {
            $cand = (Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName `
                        -Name (Split-Path $pipId -Leaf)).IpAddress
            if ($cand -and $cand -ne 'Not Assigned') { $ip = $cand }
        }
    } catch { }
    if (-not $ip) { Start-Sleep 15 }
}
if ($ip) { Write-Host "  $ip" } else { Write-Host '  still unassigned - see the note in the report below' -ForegroundColor Yellow }

# The Entra join is done by the extension a little after it reports success, so
# the dsregcmd we ran above is too early to mean anything. Poll it here instead
# of printing a premature "AzureAdJoined : NO" and sending someone to debug it.
Step 'Waiting for the Entra join to complete (up to 6 min)'
$joined = $false
for ($i = 0; $i -lt 12 -and -not $joined; $i++) {
    Start-Sleep 30
    try {
        $st = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString 'dsregcmd /status | Select-String "AzureAdJoined|DomainJoined|TenantName"'
        $txt  = ($st.Value | Where-Object Code -like '*StdOut*').Message
        $line = @($txt -split "`r?`n" | Where-Object { $_ -match 'AzureAdJoined' })[0]
        Write-Host "  $($line.Trim())"
        if ($txt -match 'AzureAdJoined\s*:\s*YES') { $joined = $true }
    } catch { Write-Host '  (run command busy, retrying)' }
}
if ($joined) {
    Write-Host '  ENTRA JOIN OK - the AADLoginForWindows extension works on WS2025.' -ForegroundColor Green
} else {
    Write-Host '  STILL NOT JOINED after 6 minutes. Read the logs; do not guess:' -ForegroundColor Yellow
    Write-Host '' -ForegroundColor Yellow
    Write-Host "  Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName ``" -ForegroundColor Yellow
    Write-Host "    -CommandId RunPowerShellScript -ScriptString 'Get-WinEvent -LogName ""Microsoft-Windows-User Device Registration/Admin"" -MaxEvents 15 | Format-List TimeCreated,Id,Message'" -ForegroundColor Yellow
    Write-Host '' -ForegroundColor Yellow
    Write-Host '  That channel is the primary evidence for device registration.' -ForegroundColor Yellow
    Write-Host '  Extension logs on the VM:' -ForegroundColor Yellow
    Write-Host '    C:\WindowsAzure\Logs\Plugins\Microsoft.Azure.ActiveDirectory.AADLoginForWindows' -ForegroundColor Yellow
}

# ------------------------------------------------------------------ report
# FQDN, not $ip: RDP with an Entra account rejects a bare IP address.
$rdp = @"
full address:s:$fqdn
username:s:AzureAD\$upn
enablerdsaadauth:i:1
authentication level:i:2
"@
$rdpPath = "$HOME/cloudonly-probe.rdp"
$rdp | Set-Content -Path $rdpPath -Encoding ascii

Write-Host @"

==============================================================
 PROBE DEPLOYED  ($([int]$sw.Elapsed.TotalMinutes) min $($sw.Elapsed.Seconds % 60) s)
==============================================================
 storage account : $saName
 file share      : $ShareName
 cloud user      : $upn
 password        : $plainPw
 VM              : $vmName
 RDP host (FQDN) : $fqdn
 (IP $ip - for reference only; Entra sign-in will NOT accept an IP)

 The Entra join runs after the extension settles. Give it ~5 minutes.
==============================================================
 STEP 1 - RDP AS THE ENTRA USER (not as localadmin)
==============================================================
 The PRT only exists if you sign in with the Entra account, so
 signing in as localadmin proves nothing.

 Download $rdpPath, or make a .rdp file containing:

$rdp

 enablerdsaadauth:i:1 is required. Your CONNECTING machine should
 be Windows 11 22H2 or later; if the sign-in is refused, that
 compatibility bar is itself a finding - write it down.

 Break-glass if Entra sign-in will not work at all:
   mstsc /v:$ip     user .\$localAd   password as above
   (useful to inspect the box, but it CANNOT answer the question)
==============================================================
 STEP 2 - THE ONE THING WE ARE TESTING
==============================================================
 In the RDP session, as $upn, in a normal (non-elevated) window:

   dsregcmd /status
       AzureAdJoined : YES     <- extension worked
       DomainJoined  : NO      <- confirms this is NOT hybrid
       AzureAdPrt    : YES     <- password sign-in produced a PRT

   klist cloud_debug
       ... enabled by policy: true

   klist get krbtgt
       krbtgt/KERBEROS.MICROSOFTONLINE.COM

   klist get cifs/$saName.file.core.windows.net      <-- THE ANSWER
       a ticket, Kdc Called: KdcProxy:login.microsoftonline.com

   net use Z: \\$saName.file.core.windows.net\$ShareName

 PASS  = the cifs ticket is issued after a PASSWORD sign-in.
         Cloud-only works for the participant track. Build it.
 FAIL  = no PRT, or no cloud TGT, or no cifs ticket.
         Capture the exact error. If it points at credential
         strength (WHfB/FIDO2), the participant track must stay
         hybrid and we fall back to shared-backend + 1 VM each.

 A mount that fails AFTER the cifs ticket is issued is NOT a fail -
 that is just an ACL, and it does not change the decision.
==============================================================
 TEAR DOWN
   Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob
   Invoke-MgGraphRequest -Method DELETE -Uri "$graph/users/$userId"
   # and remove the Entra DEVICE object for $vmName under Entra ID > Devices
==============================================================
"@ -ForegroundColor Green
