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
$suffix = -join ((1..8) | ForEach-Object { [char[]]'abcdefghijklmnopqrstuvwxyz' | Get-Random })
$saName = "$Prefix$suffix"
$sa = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
    -Location $Location -SkuName Standard_LRS -Kind StorageV2 `
    -EnableLargeFileShare -MinimumTlsVersion TLS1_2
Write-Host "  created $saName"

# For CLOUD-ONLY there is no ActiveDirectoryDomainName / DomainGuid to supply -
# that is the whole point. Just switch the identity source to AADKERB.
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
    -EnableAzureActiveDirectoryKerberosForFile $true | Out-Null
$ctx = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).Context
New-AzStorageShare -Name $ShareName -Context $ctx | Out-Null
Write-Host "  AADKERB enabled, share '$ShareName' created"

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
$org = Get-MgOrganization | Select-Object -First 1
$initialDomain = ($org.VerifiedDomains | Where-Object IsInitial).Name
$upn = "$UserName@$initialDomain"

$user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
if ($user) {
    Write-Host "  $upn already exists - resetting its password"
    Update-MgUser -UserId $user.Id -PasswordProfile @{
        Password = $plainPw; ForceChangePasswordNextSignIn = $false }
} else {
    # ForceChangePasswordNextSignIn = false matters: a forced change on first
    # sign-in derails an RDP-based test for reasons that have nothing to do with
    # the question we are asking.
    $user = New-MgUser -DisplayName $UserName -MailNickname $UserName `
        -UserPrincipalName $upn -AccountEnabled `
        -PasswordProfile @{ Password = $plainPw; ForceChangePasswordNextSignIn = $false }
    Write-Host "  created $upn"
}
# onPremisesSyncEnabled must be null/false here - if it is True you are looking
# at a hybrid user and this probe is not testing what you think it is.
$check = Get-MgUser -UserId $user.Id -Property userPrincipalName, onPremisesSyncEnabled
Write-Host "  onPremisesSyncEnabled = $($check.OnPremisesSyncEnabled)  (must NOT be True)"

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

# THE extension under test. It performs a Microsoft Entra JOIN (not hybrid) and
# enables sign-in to the VM with Entra credentials. If this fails on WS2025 the
# whole cloud-only participant track needs a different client OS.
Step '  AADLoginForWindows extension (this is what performs the Entra join)'
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
    $existing = Get-AzRoleAssignment -ObjectId $user.Id -Scope $r.Scope `
        -RoleDefinitionName $r.Role -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-AzRoleAssignment -ObjectId $user.Id -RoleDefinitionName $r.Role -Scope $r.Scope | Out-Null
    }
    Write-Host "  $($r.Role)"
}

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

$ip = (Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName |
    Select-Object -First 1).IpAddress

# ------------------------------------------------------------------ report
$rdp = @"
full address:s:$ip
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
 VM              : $vmName   $ip

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
   Remove-MgUser -UserId $($user.Id)
==============================================================
"@ -ForegroundColor Green
