<#
.SYNOPSIS
  AD DS / Entra Kerberos coexistence - the full 4-row verification matrix.

.DESCRIPTION
  Two storage accounts on ONE client, on two different identity sources:

      saaadkerb   Entra Kerberos (AADKERB)   - SPN lives in Entra
      saadds      on-prem AD DS  (AD)        - SPN lives in your AD

  A client with cloud Kerberos enabled has ".windows.net" in KerbTopLevelNames,
  so EVERY cifs/<sa>.file.core.windows.net SPN is routed to the Entra KDC -
  including the one whose SPN only exists on-prem. The documented fix is a
  host-to-realm mapping that pins that one FQDN back to the on-prem realm.

  The matrix (this is the deliverable):

    #  CloudKerberosTicketRetrievalEnabled  HostToRealm      aadkerb  adds
    1  0                                    none             FAIL     OK
    2  1                                    none             OK       FAIL   <- reproduce
    3  1                                    adds only        OK       OK     <- the fix
    4  1                                    adds + aadkerb   FAIL     OK     <- reverse failure

  Row 4 matters: it proves the mapping is per-HOST and directional. Without it
  people conclude "mappings are good, add them everywhere".

  WHY THE PROBE IS MANUAL
  Azure Run Command executes as SYSTEM, i.e. as the MACHINE account. A machine
  account is not a synced hybrid user, so an AADKERB mount would fail for the
  wrong reason and the matrix would be garbage. The probe therefore runs in your
  RDP session as CONTOSO\labuser1. This script automates everything else -
  account creation, registry state, mappings, reboots and the DC-side check.

  FLOW
    ./Test-Coexistence.ps1 -Setup                 once
    ./Test-Coexistence.ps1 -Row 1                 sets state, reboots the client
      -> RDP in as labuser1, run  C:\LabTools\Probe-Coexistence.ps1 -Row 1
    ./Test-Coexistence.ps1 -Row 2   ... and so on for 3 and 4
    ./Test-Coexistence.ps1 -Collect               prints observed vs expected
    ./Test-Coexistence.ps1 -Cleanup

.NOTES
  Allow ~40 minutes: four reboots and four manual probes.
  Record UTC timestamps - you will want them when reading the DC events.
#>
[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(ParameterSetName = 'Setup')]   [switch]$Setup,
    [Parameter(ParameterSetName = 'Row')]     [ValidateRange(1, 4)] [int]$Row,
    [Parameter(ParameterSetName = 'Collect')] [switch]$Collect,
    [Parameter(ParameterSetName = 'Cleanup')] [switch]$Cleanup,
    [string]$Prefix = 'azflab',
    [string]$Share  = 'labshare'
)
$ErrorActionPreference = 'Stop'

$dcName   = "$Prefix-dc"
$cliName  = "$Prefix-cli"
$adsName  = "${Prefix}ads"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$scripts  = Join-Path (Join-Path $repoRoot 'session1-adds') 'scripts'
$work     = 'C:\LabTools\coexistence'

# The hypothesis, as data. Everything else in this script exists to test it.
$expected = @{
    1 = @{ Reg = 0; Map = 'none';  Aadkerb = 'FAIL'; Adds = 'OK';
           Why = 'no cloud TGT, so AADKERB cannot work; AD DS is untouched' }
    2 = @{ Reg = 1; Map = 'none';  Aadkerb = 'OK';   Adds = 'FAIL';
           Why = 'THE REPRODUCTION - .windows.net routes the AD DS SPN to Entra' }
    3 = @{ Reg = 1; Map = 'adds';  Aadkerb = 'OK';   Adds = 'OK';
           Why = 'THE FIX - the mapping pins only that FQDN back on-prem' }
    4 = @{ Reg = 1; Map = 'both';  Aadkerb = 'FAIL'; Adds = 'OK';
           Why = 'REVERSE FAILURE - mapping the AADKERB host sends it to a KDC that has no SPN for it' }
}

function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

function Invoke-OnVm([string]$Vm, [string]$Script) {
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $Script
    try {
        $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $Vm `
            -CommandId 'RunPowerShellScript' -ScriptPath $tmp -ErrorAction Stop
        ($r.Value | Where-Object Code -like '*StdOut*').Message
    } finally { Remove-Item $tmp -Force }
}

function Wait-VmReady([string]$Vm, [int]$TimeoutMin = 8) {
    $deadline = (Get-Date).AddMinutes($TimeoutMin)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-OnVm $Vm 'Write-Output READY' | Out-Null
            Write-Host '  client is back.' -ForegroundColor Green
            return
        } catch { Start-Sleep -Seconds 20; Write-Host '  waiting...' -ForegroundColor DarkGray }
    }
    throw "$Vm did not come back within $TimeoutMin minutes."
}

function Get-Accounts {
    $aad = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
        Where-Object { $_.AzureFilesIdentityBasedAuth.DirectoryServiceOptions -eq 'AADKERB' } |
        Select-Object -First 1
    $ads = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
        Where-Object StorageAccountName -like "$adsName*" | Select-Object -First 1
    @{ Aad = $aad; Ads = $ads }
}

# ══════════════════════════════════════════════════════════════════ CLEANUP
if ($Cleanup) {
    Step 'Cleanup'
    Invoke-OnVm $cliName @"
ksetup /delhosttorealmmap * * 2>&1 | Out-Null
`$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm'
if (Test-Path `$k) { Remove-Item `$k -Recurse -Force }
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' ``
    -Name CloudKerberosTicketRetrievalEnabled -Value 1 -Type DWord
Remove-Item '$work' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\LabTools\Probe-Coexistence.ps1' -Force -ErrorAction SilentlyContinue
Write-Output 'client reset (cloud Kerberos left ON)'
"@ | Write-Host
    Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
        Where-Object StorageAccountName -like "$adsName*" | ForEach-Object {
            $n = $_.StorageAccountName
            Invoke-OnVm $dcName "Import-Module ActiveDirectory
Get-ADComputer -Filter `"Name -eq '$n'`" | Remove-ADObject -Recursive -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'AD object removed'" | Write-Host
            Remove-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $n -Force
            Write-Host "  removed $n"
        }
    Write-Host "`nDone. Reboot the client once to clear the mappings for good." -ForegroundColor Green
    return
}

# ════════════════════════════════════════════════════════════════════ SETUP
if ($Setup) {
    $acc = Get-Accounts
    if (-not $acc.Aad) {
        Write-Warning 'No AADKERB storage account found. Run the Session 2 setup first -'
        Write-Warning 'the entire point is to have BOTH identity sources present at once.'
        return
    }
    Write-Host "Entra Kerberos account : $($acc.Aad.StorageAccountName)" -ForegroundColor Green

    Step '1/3 Creating the second storage account and joining it to AD DS'
    if ($acc.Ads) {
        $sa = $acc.Ads; Write-Host "  reusing $($sa.StorageAccountName)"
    } else {
        $suffix = -join ((97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
        $sa = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name "$adsName$suffix" `
            -Location $acc.Aad.Location -SkuName Standard_LRS -Kind StorageV2 `
            -MinimumTlsVersion TLS1_2 -AllowSharedKeyAccess $true
        Write-Host "  created $($sa.StorageAccountName)"
    }
    $saName = $sa.StorageAccountName
    $ctx = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).Context
    if (-not (Get-AzStorageShare -Context $ctx -Name $Share -ErrorAction SilentlyContinue)) {
        New-AzStorageShare -Context $ctx -Name $Share | Out-Null
    }
    New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
    Start-Sleep -Seconds 15
    $kerb = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
        Where-Object KeyName -eq 'kerb1').Value

    $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $dcName `
        -CommandId 'RunPowerShellScript' -ScriptPath (Join-Path $scripts '04-domain-join-storage.ps1') `
        -Parameter @{ StorageAccountName = $saName; KerbKey = $kerb; KerberosEncryptionType = 'AES256' }
    $joinOut = ($r.Value | Where-Object Code -like '*StdOut*').Message
    Write-Host $joinOut
    $ad = ($joinOut | Select-String '\{[\s\S]*\}').Matches[0].Value | ConvertFrom-Json

    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
        -EnableActiveDirectoryDomainServicesForFile $true `
        -ActiveDirectoryDomainName $ad.DomainName -ActiveDirectoryNetBiosDomainName $ad.NetBiosDomainName `
        -ActiveDirectoryForestName $ad.ForestName -ActiveDirectoryDomainGuid $ad.DomainGuid `
        -ActiveDirectoryDomainSid $ad.DomainSid -ActiveDirectoryAzureStorageSid $ad.AzureStorageSid `
        -ActiveDirectorySamAccountName $saName -ActiveDirectoryAccountType 'Computer' | Out-Null
    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
        -DefaultSharePermission StorageFileDataSmbShareContributor | Out-Null
    Write-Host "  $saName joined to $($ad.DomainName)" -ForegroundColor Green

    Step '2/3 Dropping the probe script on the client'
    # The probe runs in the RDP session as the lab USER - see .DESCRIPTION.
    $probe = @'
param([Parameter(Mandatory)][ValidateRange(1,4)][int]$Row)
$work = 'C:\LabTools\coexistence'
$cfg  = Get-Content (Join-Path $work 'config.json') -Raw | ConvertFrom-Json
Write-Host "Probing row $Row as $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
$result = @{ Row = $Row; User = "$env:USERDOMAIN\$env:USERNAME"; UtcTime = (Get-Date).ToUniversalTime().ToString('u') }
foreach ($kind in 'Aad', 'Ads') {
    $fqdn = "$($cfg.$kind).file.core.windows.net"
    net use "\\$fqdn\$($cfg.Share)" /delete /y 2>&1 | Out-Null
    klist purge | Out-Null
    $tk = klist get "cifs/$fqdn" 2>&1 | Out-String
    $mt = cmd /c "net use \\$fqdn\$($cfg.Share) /persistent:no 2>&1"
    $ok = $LASTEXITCODE -eq 0
    $realm = if ($tk -match 'Server:\s*cifs/[^@]+@\s*(\S+)') { $Matches[1] } else { '-' }
    $kdc   = if ($tk -match 'Kdc Called:\s*(\S+)')            { $Matches[1] } else { '-' }
    net use "\\$fqdn\$($cfg.Share)" /delete /y 2>&1 | Out-Null
    $result[$kind] = @{ Result = $(if ($ok) { 'OK' } else { 'FAIL' }); Realm = $realm
                        Kdc = $kdc; Detail = ($mt -join ' ').Trim() }
    Write-Host ("  {0,-8} {1,-5} realm={2} kdc={3}" -f $kind, $result[$kind].Result, $realm, $kdc)
}
$result | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $work "row$Row.json") -Encoding utf8
Write-Host "`nSaved. Back in Cloud Shell: ./Test-Coexistence.ps1 -ResourceGroupName <rg> -Row $($Row + 1)" -ForegroundColor Yellow
Write-Host "(after row 4:  -Collect)" -ForegroundColor Yellow
'@
    $cfgJson = @{ Aad = $acc.Aad.StorageAccountName; Ads = $saName; Share = $Share
                  Realm = $ad.DomainName.ToUpper() } | ConvertTo-Json -Compress
    Invoke-OnVm $cliName @"
New-Item -ItemType Directory -Path '$work' -Force | Out-Null
icacls '$work' /grant '*S-1-5-32-545:(OI)(CI)M' 2>&1 | Out-Null
Set-Content -Path (Join-Path '$work' 'config.json') -Value '$cfgJson' -Encoding utf8
Set-Content -Path 'C:\LabTools\Probe-Coexistence.ps1' -Encoding utf8 -Value @'
$probe
'@
Write-Output 'probe script + config written'
"@ | Write-Host

    Step '3/3 Ready'
    Write-Host @"

  Entra Kerberos : $($acc.Aad.StorageAccountName)
  AD DS          : $saName    (realm $($ad.DomainName.ToUpper()))

  Next:  ./Test-Coexistence.ps1 -ResourceGroupName $ResourceGroupName -Row 1
"@ -ForegroundColor Green
    return
}

# ═════════════════════════════════════════════════════════════════════ ROW
if ($PSCmdlet.ParameterSetName -eq 'Row') {
    $acc = Get-Accounts
    if (-not $acc.Ads) { throw 'Run -Setup first.' }
    $e = $expected[$Row]
    $aadFqdn = "$($acc.Aad.StorageAccountName).file.core.windows.net"
    $adsFqdn = "$($acc.Ads.StorageAccountName).file.core.windows.net"
    $realm = (Invoke-OnVm $dcName 'Import-Module ActiveDirectory; (Get-ADDomain).DNSRoot').Trim().ToUpper()

    Step "Row $Row - registry=$($e.Reg), mapping=$($e.Map)"
    Write-Host "  hypothesis: aadkerb=$($e.Aadkerb)  adds=$($e.Adds)"
    Write-Host "  because: $($e.Why)" -ForegroundColor DarkGray

    $maps = switch ($e.Map) {
        'none' { @() }
        'adds' { @($adsFqdn) }
        'both' { @($adsFqdn, $aadFqdn) }
    }
    $addCmds = ($maps | ForEach-Object { "ksetup /addhosttorealmmap $_ $realm 2>&1 | Out-Null" }) -join "`n"

    Invoke-OnVm $cliName @"
# start from a known state every time
`$hk = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm'
if (Test-Path `$hk) { Remove-Item `$hk -Recurse -Force }
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' ``
    -Name CloudKerberosTicketRetrievalEnabled -Value $($e.Reg) -Type DWord
$addCmds
Write-Output "CloudKerberosTicketRetrievalEnabled=$($e.Reg)"
if (Test-Path `$hk) { Get-ChildItem `$hk | ForEach-Object { Write-Output "HostToRealm: `$(`$_.PSChildName)" } }
else { Write-Output 'HostToRealm: (none)' }
"@ | Write-Host

    Step 'Rebooting the client (both settings are read at boot/logon)'
    Restart-AzVM -ResourceGroupName $ResourceGroupName -Name $cliName | Out-Null
    Start-Sleep -Seconds 45
    Wait-VmReady $cliName

    Write-Host ''
    Write-Host ('-' * 64)
    Write-Host " NOW: RDP to the client as CONTOSO\labuser1 and run" -ForegroundColor Yellow
    Write-Host ''
    Write-Host "   C:\LabTools\Probe-Coexistence.ps1 -Row $Row" -ForegroundColor White
    Write-Host ''
    Write-Host " It must run in YOUR session - Run Command would mount as the machine" -ForegroundColor DarkGray
    Write-Host " account, which is not a synced user, and the result would be meaningless." -ForegroundColor DarkGray
    Write-Host ('-' * 64)
    return
}

# ═════════════════════════════════════════════════════════════════ COLLECT
Step 'Collecting results'
$acc = Get-Accounts
$raw = Invoke-OnVm $cliName @"
Get-ChildItem '$work\row*.json' -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output '--8<--'
    Get-Content `$_.FullName -Raw
}
"@
$rows = @{}
foreach ($blk in ($raw -split '--8<--')) {
    if ($blk.Trim()) { $o = $blk | ConvertFrom-Json; $rows[[int]$o.Row] = $o }
}
if (-not $rows.Count) { Write-Warning 'No probe results found. Did you run the probe in the RDP session?'; return }

# Did the on-prem KDC ever see the AD DS SPN? Absence is the signature.
$dc = Invoke-OnVm $dcName @"
`$since = (Get-Date).AddHours(-3)
`$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=`$since} -ErrorAction SilentlyContinue |
      Where-Object { `$_.Message -match '$($acc.Ads.StorageAccountName)' }
Write-Output "4769_FOR_ADS_SPN=`$(@(`$ev).Count)"
"@
Write-Host $dc -ForegroundColor DarkGray

Write-Host ''
Write-Host (' {0,-3} {1,-4} {2,-6} {3,-22} {4,-22}' -f '#', 'reg', 'map', 'aadkerb (exp/obs)', 'adds (exp/obs)')
Write-Host (' ' + ('-' * 74))
$allMatch = $true
foreach ($n in 1..4) {
    $e = $expected[$n]
    if ($rows.ContainsKey($n)) {
        $oA = $rows[$n].Aad.Result; $oD = $rows[$n].Ads.Result
        $mA = $oA -eq $e.Aadkerb;   $mD = $oD -eq $e.Adds
        if (-not ($mA -and $mD)) { $allMatch = $false }
        $col = if ($mA -and $mD) { 'Green' } else { 'Red' }
        Write-Host (' {0,-3} {1,-4} {2,-6} {3,-22} {4,-22}' -f $n, $e.Reg, $e.Map,
            "$($e.Aadkerb) / $oA", "$($e.Adds) / $oD") -ForegroundColor $col
        Write-Host ("       aadkerb realm=$($rows[$n].Aad.Realm) kdc=$($rows[$n].Aad.Kdc)") -ForegroundColor DarkGray
        Write-Host ("       adds    realm=$($rows[$n].Ads.Realm) kdc=$($rows[$n].Ads.Kdc)") -ForegroundColor DarkGray
    } else {
        $allMatch = $false
        Write-Host (' {0,-3} {1,-4} {2,-6} {3,-22} {4,-22}' -f $n, $e.Reg, $e.Map,
            "$($e.Aadkerb) / --", "$($e.Adds) / --") -ForegroundColor DarkGray
    }
}
Write-Host ''
Write-Host ('=' * 74)
if ($allMatch) {
    Write-Host ' VERDICT: HYPOTHESIS CONFIRMED - all four rows behaved as predicted.' -ForegroundColor Green
    Write-Host ' Row 2 is the reproduction, row 3 the fix, row 4 proves the mapping is'
    Write-Host ' per-host and directional. This is a lab.'
} elseif ($rows.ContainsKey(2) -and $rows[2].Ads.Result -eq 'OK') {
    Write-Host ' VERDICT: NOT REPRODUCED - with cloud Kerberos on and no mapping, the' -ForegroundColor Yellow
    Write-Host ' AD DS account still mounted. Coexistence does not break here. Keep it as'
    Write-Host ' a slide, not a lab.'
} else {
    Write-Host ' VERDICT: MIXED - some rows did not match. Read the realm/kdc lines above:' -ForegroundColor Yellow
    Write-Host ' if a FAIL shows a realm of your AD domain, the request DID reach the DC and'
    Write-Host ' the cause is an ordinary AD DS problem, not routing.'
}
Write-Host ('=' * 74)
Write-Host ''
Write-Host "Tear down:  ./Test-Coexistence.ps1 -ResourceGroupName $ResourceGroupName -Cleanup"
