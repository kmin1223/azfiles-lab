<#
.SYNOPSIS
  Session 1 one-shot deployer: simulated on-prem AD DS + Azure Files AD DS auth.

.DESCRIPTION
  Single command, no interaction after the password prompt:
    1. Resource group + ARM template deployment (VNet/DC/client/storage/share)
    2. Promote DC to a new AD forest (contoso.local)
    3. Create lab users (labuser1/labuser2) + Kerberos auditing on the DC
    4. Domain-join the client VM
    5. Domain-join the STORAGE ACCOUNT (computer account + SPN + kerb1 key)
    6. Enable AD DS auth on the storage account (Set-AzStorageAccount)
    7. Final kerb key rotation + AD password sync (1396 guard)
    8. Default share-level permission + NTFS ACLs
    9. Verify the client actually mounts the share

  Three things keep the wall clock down:
    * the client fetches a PREBUILT module bundle (one zip) instead of running
      Install-Module per module - see tools\New-LabToolsBundle.ps1
    * that install runs while the DC is promoting; it needs nothing from AD,
      but it must finish before the client reboots into the domain
    * the client's domain join and reboot happen while the storage account is
      being joined and configured, which only touches the DC and Azure

  Total time: ~12-15 minutes. Run it at the START of the session and present
  slides while it cooks.

.EXAMPLE
  Connect-AzAccount
  .\deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Location = 'koreacentral',
    [string]$Prefix = 'azflab',
    [string]$DomainName = 'contoso.local',
    [string]$AdminUsername = 'labadmin',
    [SecureString]$AdminPassword,
    # Default: build the "2023 vintage" state - RC4 encryption and a storage
    # account whose ActiveDirectoryDomainName holds the NetBIOS name instead of
    # the DNS root. It mounts fine on RC4; the latent salt defect only surfaces
    # when you migrate to AES-256 (Lab: Invoke-Aes256Migration.ps1).
    # Use -Modern to deploy the correct AES-256 configuration instead.
    [switch]$Modern,
    # Override the prebuilt module bundle location (see tools\New-LabToolsBundle.ps1).
    # Leave empty to use the default baked into scripts\07-install-tools.ps1.
    [string]$ModuleBundleUri
)
$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

function Step([string]$msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------- Preflight
foreach ($m in 'Az.Accounts', 'Az.Resources', 'Az.Compute', 'Az.Storage', 'Az.Network') {
    if (-not (Get-Module -ListAvailable $m)) {
        throw "Missing module '$m'. Run: Install-Module Az -Scope CurrentUser"
    }
}
if (-not (Get-AzContext)) { throw 'Not logged in. Run Connect-AzAccount first.' }

if (-not $AdminPassword) {
    $AdminPassword = Read-Host -AsSecureString -Prompt 'Lab admin password (12+ chars, complex)'
}
$plainPw = [System.Net.NetworkCredential]::new('', $AdminPassword).Password
if ($plainPw.Length -lt 12) { throw 'Password must be at least 12 characters.' }
# Run Command passes params as CLI args - avoid characters that break quoting
if ($plainPw -match '[\s"''`$]') {
    throw 'For this lab, avoid spaces, quotes, backticks and $ in the password.'
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()

# ---------------------------------------------------- 1. RG + template deploy
# Plain ARM JSON - no extra tooling required, works in Cloud Shell and locally.
Step '1/9 Deploying infrastructure'
# Nested Join-Path keeps paths correct on both Windows PowerShell 5.1 and
# PowerShell 7 (Cloud Shell / Linux) - avoid literal backslashes.
$templateFile = Join-Path (Join-Path $scriptRoot 'template') 'azuredeploy.json'
if (-not (Test-Path $templateFile)) {
    throw "ARM template not found: $templateFile"
}
Write-Host 'Using ARM template.'

New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force | Out-Null
$dep = New-AzResourceGroupDeployment `
    -ResourceGroupName $ResourceGroupName `
    -TemplateFile $templateFile `
    -adminUsername $AdminUsername `
    -adminPassword $AdminPassword `
    -prefix $Prefix `
    -Name "s1-$(Get-Date -Format yyyyMMddHHmm)"

$saName    = $dep.Outputs.storageAccountName.Value
$dcName    = $dep.Outputs.dcVmName.Value
$cliName   = $dep.Outputs.clientVmName.Value
$dcIpPub   = $dep.Outputs.dcPublicIp.Value
$cliIpPub  = $dep.Outputs.clientPublicIp.Value
Write-Host "Storage account: $saName | DC: $dcIpPub | Client: $cliIpPub"

function Invoke-VmScript {
    param([string]$VmName, [string]$ScriptFile, [hashtable]$Params = @{}, [int]$Retries = 1, [int]$RetryDelaySec = 60)
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            $rc = @{
                ResourceGroupName = $ResourceGroupName; VMName = $VmName
                CommandId = 'RunPowerShellScript'
                ScriptPath = (Join-Path (Join-Path $scriptRoot 'scripts') $ScriptFile)
                ErrorAction = 'Stop'
            }
            # An empty -Parameter hashtable is rejected, so only pass it when used.
            if ($Params -and $Params.Count -gt 0) { $rc['Parameter'] = $Params }
            $r = Invoke-AzVMRunCommand @rc
            $out = ($r.Value | Where-Object Code -like '*StdOut*').Message
            $err = ($r.Value | Where-Object Code -like '*StdErr*').Message
            if ($err) { Write-Warning $err }
            return $out
        } catch {
            if ($i -eq $Retries) { throw }
            Write-Host "  attempt $i failed ($($_.Exception.Message.Split("`n")[0])); retrying in ${RetryDelaySec}s..."
            Start-Sleep -Seconds $RetryDelaySec
        }
    }
}

# Same thing as a background job, for work on one VM that can overlap work on
# the other. Az context autosave means the job picks up the current login.
function Start-VmScriptJob {
    param([string]$VmName, [string]$ScriptFile, [hashtable]$Params = @{}, [int]$Retries = 4)
    Start-Job -Name "job-$VmName-$ScriptFile" -ScriptBlock {
        param($rg, $vmName, $path, $p, $retries)
        Import-Module Az.Compute -ErrorAction SilentlyContinue
        $rc = @{
            ResourceGroupName = $rg; VMName = $vmName
            CommandId = 'RunPowerShellScript'; ScriptPath = $path; ErrorAction = 'Stop'
        }
        # An empty -Parameter hashtable is rejected, so only pass it when used.
        if ($p -and $p.Count -gt 0) { $rc['Parameter'] = $p }
        # Retry inside the job: right after an ARM deployment the guest agent
        # may not be accepting Run Commands yet, and a job has no other way back.
        for ($i = 1; $i -le $retries; $i++) {
            try { return Invoke-AzVMRunCommand @rc }
            catch { if ($i -eq $retries) { throw }; Start-Sleep -Seconds 45 }
        }
    } -ArgumentList $ResourceGroupName, $VmName, (Join-Path (Join-Path $scriptRoot 'scripts') $ScriptFile), $Params, $Retries
}

function Receive-VmScriptJob {
    param($Job, [int]$TimeoutSec = 1200, [string]$Label)
    $Job | Wait-Job -Timeout $TimeoutSec | Out-Null
    if ($Job.State -ne 'Completed') {
        Write-Warning "$Label did not complete cleanly (state: $($Job.State))"
        Remove-Job $Job -Force -ErrorAction SilentlyContinue
        return ''
    }
    $r = Receive-Job $Job
    Remove-Job $Job -Force -ErrorAction SilentlyContinue
    return ($r.Value | Where-Object Code -like '*StdOut*').Message
}

# --------------------------------- PARALLEL: client tooling starts right now
# The client pulls a prebuilt module bundle (Az + AzFilesHybrid + the Graph
# dependency) as a single zip rather than running Install-Module per module -
# roughly a minute instead of nine. It needs nothing from AD, so it also runs
# while the DC promotes. It MUST finish before the client is domain-joined,
# because that reboots the machine and would kill an in-flight Run Command.
Step 'Starting client tooling install in the background (overlaps DC promotion)'
$toolParams = @{}
if ($ModuleBundleUri) { $toolParams['ModuleBundleUri'] = $ModuleBundleUri }
$clientToolsJob = Start-VmScriptJob -VmName $cliName -ScriptFile '07-install-tools.ps1' -Params $toolParams

# ------------------------------------------------------- 2. Promote the DC
Step '2/9 Promoting DC to a new forest (reboots itself)'
$promoteOut = Invoke-VmScript -VmName $dcName -ScriptFile '01-promote-dc.ps1' `
    -Params @{ DomainName = $DomainName; SafeModePassword = $plainPw }
$promoteOut | Write-Host
if ($promoteOut -notmatch 'ALREADY_PROMOTED') {
    # Poll instead of sleeping a flat 4 minutes: the DC is usually back sooner,
    # and when it isn't, a fixed sleep wouldn't have been long enough anyway.
    Write-Host 'Waiting for the DC to come back (polling)...'
    Start-Sleep -Seconds 120   # no point probing before this
    $dcReady = $false
    for ($i = 1; $i -le 16; $i++) {
        try {
            $probe = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $dcName `
                -CommandId 'RunPowerShellScript' -ScriptString `
                "if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2 -and (Get-Service ADWS -ErrorAction SilentlyContinue).Status -eq 'Running') { 'DC_READY' }" `
                -ErrorAction Stop
            if ((($probe.Value | Where-Object Code -like '*StdOut*').Message) -match 'DC_READY') {
                $dcReady = $true
                Write-Host "  DC ready after $([int]$sw.Elapsed.TotalMinutes) min total."
                break
            }
        } catch { }
        Start-Sleep -Seconds 30
    }
    if (-not $dcReady) { Write-Warning 'DC readiness probe timed out - continuing; later steps retry.' }
}

# ----------------------------------------------------------- 3. Lab users
Step '3/9 Creating lab users (retries until AD is up)'
Invoke-VmScript -VmName $dcName -ScriptFile '02-create-lab-users.ps1' `
    -Params @{ Password = $plainPw } -Retries 8 -RetryDelaySec 60 | Write-Host

# DC-side prep is small now (Kerberos auditing + operational logs, no Azure
# tooling by design) and has to run after promotion, so it goes here.
Step 'Enabling Kerberos auditing on the DC (events 4768/4769)'
$dcPrep = Invoke-VmScript -VmName $dcName -ScriptFile '07-install-tools.ps1' -Retries 2 -RetryDelaySec 30
($dcPrep -split "`n" | Where-Object { $_ -match 'TOOLS_|auditing|logs enabled' }) | Write-Host

# ------------------------------- Collect the client tooling job before reboot
Step 'Waiting for the client tooling install to finish'
$toolsOut = Receive-VmScriptJob -Job $clientToolsJob -TimeoutSec 1200 -Label 'client tooling'
if ($toolsOut -match 'TOOLS_READY') {
    Write-Host '  client tooling: OK'
} else {
    $detail = ($toolsOut -split "`n" | Select-String 'TOOLS_PARTIAL|FAILED').Line -join '; '
    Write-Warning "  client tooling incomplete: $detail"
    Write-Warning '  rerun scripts\07-install-tools.ps1 on the client if diagnostics are missing.'
}

# ----------------------------------------------------- 4. Join client VM
# Started as a job: the client reboot (~3 min) overlaps the storage-account
# work below, which only touches the DC and Azure.
Step '4/9 Domain-joining the client VM in the background (reboots itself)'
$clientJoinJob = Start-VmScriptJob -VmName $cliName -ScriptFile '03-join-domain-client.ps1' `
    -Params @{ DomainName = $DomainName; JoinUser = $AdminUsername; JoinPassword = $plainPw }

# --------------------------------------- 5. Domain-join the storage account
Step '5/9 Domain-joining the storage account (kerb key + computer account + SPN)'
New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
$kerbKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
    Where-Object KeyName -eq 'kerb1').Value

$encType = if ($Modern) { 'AES256' } else { 'RC4' }
$joinOut = Invoke-VmScript -VmName $dcName -ScriptFile '04-domain-join-storage.ps1' `
    -Params @{ StorageAccountName = $saName; KerbKey = $kerbKey; KerberosEncryptionType = $encType } `
    -Retries 3 -RetryDelaySec 30
if ($joinOut -notmatch '===JSON_BEGIN===(.+)===JSON_END===') { throw "Unexpected output: $joinOut" }
$ad = $Matches[1] | ConvertFrom-Json

# ------------------------------------------- 6. Enable AD DS auth on the SA
Step '6/9 Enabling AD DS authentication on the storage account'
# LEGACY MODE (default): ActiveDirectoryDomainName gets the NetBIOS name rather
# than the DNS root. Harmless under RC4 (no salt), fatal under AES-256 - the
# exact latent defect behind a real Sev A incident.
$adDomainNameValue = if ($Modern) { $ad.DomainName } else { $ad.NetBiosDomainName }
if (-not $Modern) {
    Write-Host "Legacy mode: ActiveDirectoryDomainName = '$adDomainNameValue' (NetBIOS, not the DNS root)"
}
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
    -EnableActiveDirectoryDomainServicesForFile $true `
    -ActiveDirectoryDomainName $adDomainNameValue `
    -ActiveDirectoryNetBiosDomainName $ad.NetBiosDomainName `
    -ActiveDirectoryForestName $ad.ForestName `
    -ActiveDirectoryDomainGuid $ad.DomainGuid `
    -ActiveDirectoryDomainSid $ad.DomainSid `
    -ActiveDirectoryAzureStorageSid $ad.AzureStorageSid `
    -ActiveDirectorySamAccountName $ad.SamAccountName `
    -ActiveDirectoryAccountType 'Computer' | Out-Null

# Share-level: default permission = no Entra sync needed in this lab
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
    -DefaultSharePermission 'StorageFileDataSmbShareContributor' | Out-Null

# -------------------------------------------- 7. Final kerb key sync
# Rotate kerb1 once more AFTER the SA is fully configured and push it to the
# AD object. Prevents the propagation race that surfaces as error 1396.
Step '7/9 Final kerb key sync (1396/AP_ERR_MODIFIED guard)'
New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
Start-Sleep -Seconds 15  # let the new key value settle before reading it back
$kerbKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
    Where-Object KeyName -eq 'kerb1').Value
Invoke-VmScript -VmName $dcName -ScriptFile '06-sync-kerb-password.ps1' `
    -Params @{ StorageAccountName = $saName; KerbKey = $kerbKey } `
    -Retries 3 -RetryDelaySec 30 | Write-Host

# ------------------------------------------------------------ 8. NTFS ACLs
Step '8/9 Setting NTFS permissions on the share'
$key1 = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName)[0].Value
Invoke-VmScript -VmName $dcName -ScriptFile '05-set-ntfs-perms.ps1' `
    -Params @{ StorageAccountName = $saName; StorageKey = $key1; NetBios = $ad.NetBiosDomainName } `
    -Retries 3 -RetryDelaySec 30 | Write-Host

# ------------------------------- 9. Collect the background client domain join
# Everything above ran on the DC or against Azure, so the client's join and
# reboot happened for free alongside it.
Step '9/9 Confirming the client domain join'
$joinOutput = Receive-VmScriptJob -Job $clientJoinJob -TimeoutSec 900 -Label 'client domain join'
$joinOutput | Write-Host
if (-not $joinOutput) {
    Write-Host '  retrying the domain join in the foreground...'
    Invoke-VmScript -VmName $cliName -ScriptFile '03-join-domain-client.ps1' `
        -Params @{ DomainName = $DomainName; JoinUser = $AdminUsername; JoinPassword = $plainPw } `
        -Retries 3 -RetryDelaySec 60 | Write-Host
}

# ------------------------------------- 10. Verify the mount actually works
# Legacy mode depends on RC4 still being usable in this environment. If it
# isn't, fall back to the correct AES-256 config so the rest of the lab runs.
Step 'Verifying the environment (mount test from the client)'
$labMode = if ($Modern) { 'MODERN (AES-256)' } else { 'LEGACY (RC4)' }
$verify = Invoke-VmScript -VmName $cliName -ScriptFile '08-verify-mount.ps1' `
    -Params @{ StorageAccountName = $saName } -Retries 3 -RetryDelaySec 30
$verify | Write-Host

if ($verify -notmatch 'MOUNT_OK') {
    if (-not $Modern) {
        Write-Warning 'Legacy RC4 mount did not work here - falling back to AES-256 so the lab still runs.'
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
            -EnableActiveDirectoryDomainServicesForFile $true `
            -ActiveDirectoryDomainName $ad.DomainName `
            -ActiveDirectoryNetBiosDomainName $ad.NetBiosDomainName `
            -ActiveDirectoryForestName $ad.ForestName `
            -ActiveDirectoryDomainGuid $ad.DomainGuid `
            -ActiveDirectoryDomainSid $ad.DomainSid `
            -ActiveDirectoryAzureStorageSid $ad.AzureStorageSid `
            -ActiveDirectorySamAccountName $ad.SamAccountName `
            -ActiveDirectoryAccountType 'Computer' | Out-Null
        New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
        Start-Sleep -Seconds 15
        $kerbKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
            Where-Object KeyName -eq 'kerb1').Value
        Invoke-VmScript -VmName $dcName -ScriptFile '04-domain-join-storage.ps1' `
            -Params @{ StorageAccountName = $saName; KerbKey = $kerbKey; KerberosEncryptionType = 'AES256' } `
            -Retries 2 -RetryDelaySec 30 | Out-Null
        $verify = Invoke-VmScript -VmName $cliName -ScriptFile '08-verify-mount.ps1' `
            -Params @{ StorageAccountName = $saName } -Retries 2 -RetryDelaySec 30
        $verify | Write-Host
        $labMode = 'MODERN (AES-256) - RC4 unavailable, AES-256 migration lab not applicable'
    }
    if ($verify -notmatch 'MOUNT_OK') {
        Write-Warning 'Mount still failing - check Test-NetConnection 445 and Debug-AzStorageAccountAuth on the client.'
    }
}

$sw.Stop()
Write-Host @"

==============================================================
 DEPLOYMENT COMPLETE  ($([int]$sw.Elapsed.TotalMinutes) min)
==============================================================
 Lab mode        : $labMode
 Storage account : $saName
 File share      : \\$saName.file.core.windows.net\labshare
 Domain          : $DomainName
 DC (RDP)        : $dcIpPub  ($AdminUsername)
 Client (RDP)    : $cliIpPub ($($ad.NetBiosDomainName)\labuser1)

 Lab quick start (on the CLIENT VM as $($ad.NetBiosDomainName)\labuser1):
   klist purge
   net use Z: \\$saName.file.core.windows.net\labshare
   klist   # look for the cifs/ ticket

 Diagnostics are preinstalled on the CLIENT VM (Az + AzFilesHybrid).
 The DC deliberately has no Azure tooling - only Kerberos auditing (4768/4769):
   Connect-AzAccount
   Debug-AzStorageAccountAuth -StorageAccountName $saName ``
     -ResourceGroupName $ResourceGroupName -Verbose
==============================================================
"@ -ForegroundColor Green
