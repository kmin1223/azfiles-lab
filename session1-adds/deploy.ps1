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
    7. Final kerb key rotation + AD password sync (1396 guard) + NTFS ACLs
       (one Run Command - each round-trip costs ~60s fixed overhead)
    9. Verify the client actually mounts the share

  Timing design:
    * the client's domain join and reboot run in the background while the
      storage account is joined and configured (DC + Azure only)
    * diagnostic tooling (Az + AzFilesHybrid) is NOT part of the critical
      path. It installs LAST, after the mount is verified and the summary is
      written, from a prebuilt bundle (tools\New-LabToolsBundle.ps1). A slow
      or failed tooling install can no longer delay or break the deployment.

  Total time to a verified environment: ~13-16 minutes, plus a few background
  minutes for tooling. Run it at the START of the session and present slides
  while it cooks.

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
    [string]$ModuleBundleUri,
    # Where the transcript and lab-info file land. $HOME survives a Cloud Shell
    # reconnect, so a dropped session doesn't take the results with it.
    [string]$LogPath = (Join-Path $HOME 'azfiles-lab-logs')
)
$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# Stamped so the transcript shows where the time actually went - useful both for
# tuning the deployment and for telling a hung step from a slow one.
function Step([string]$msg) {
    $elapsed = if ($script:sw) { '{0:mm\:ss}' -f $script:sw.Elapsed } else { '00:00' }
    Write-Host "`n[+$elapsed] === $msg ===" -ForegroundColor Cyan
}

# Echo the main command a step runs, so the deployment doubles as a walkthrough
# of how you'd do this by hand. Secret VALUES are never shown - remote-script
# parameters appear as names only.
function Show-Cmd([string]$Command) {
    $Command.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  PS> $_" -ForegroundColor DarkCyan }
}

# What actually runs inside each Run Command payload - the one-line essence.
$scriptCore = @{
    '01-promote-dc.ps1'         = "Install-ADDSForest -DomainName $DomainName (then reboot)"
    '02-create-lab-users.ps1'   = 'New-ADUser labuser1/labuser2; OU AzureFilesLab; auditpol Kerberos 4768/4769'
    '03-join-domain-client.ps1' = "Add-Computer -DomainName $DomainName (then reboot); RDP group for Domain Users"
    '04-domain-join-storage.ps1'= 'New-ADComputer <sa>; setspn cifs/<sa>.file.core.windows.net; Set-ADAccountPassword = kerb1'
    '06-sync-kerb-password.ps1' = 'Set-ADAccountPassword (AD object) = current kerb1; then net use with the storage KEY + icacls'
    '05-set-ntfs-perms.ps1'     = 'net use with the storage KEY, then icacls on the share root'
    '07-install-tools.ps1'      = 'client: module bundle + RSAT | DC: auditpol Kerberos 4768/4769 + operational logs'
    '08-verify-mount.ps1'       = 'net use \\<sa>.file.core.windows.net\labshare as a domain user; report etype'
}

function Show-VmCmd([string]$VmName, [string]$ScriptFile, [hashtable]$Params) {
    $paramNote = if ($Params -and $Params.Count) { " -Parameter @{ $($Params.Keys -join '; ') }" } else { '' }
    Show-Cmd "Invoke-AzVMRunCommand -VMName $VmName -ScriptPath scripts\$ScriptFile$paramNote"
    if ($scriptCore[$ScriptFile]) {
        Write-Host "      inside: $($scriptCore[$ScriptFile])" -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------------ Logging
# Cloud Shell disconnects after ~20 minutes without interaction, which kills
# this script mid-run. Everything therefore goes to disk as it happens, and the
# resource details are written as soon as they exist rather than at the end.
New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
$stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile  = Join-Path $LogPath "deploy-$stamp.log"
$infoFile = Join-Path $LogPath "lab-info-$stamp.txt"
try { Start-Transcript -Path $logFile -Force | Out-Null } catch { }

Write-Host "Transcript : $logFile" -ForegroundColor Yellow
Write-Host "Lab info   : $infoFile" -ForegroundColor Yellow
Write-Host 'Both survive a Cloud Shell disconnect - read them if this window dies.' -ForegroundColor Yellow

function Write-LabInfo([string]$text) {
    $text | Out-File -FilePath $infoFile -Encoding utf8
    Write-Host $text
}

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

Show-Cmd @"
New-AzResourceGroup -Name $ResourceGroupName -Location $Location
New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName ``
    -TemplateFile template\azuredeploy.json -prefix $Prefix
"@
Write-Host '      inside: VNet(DNS->DC) + NSG + 2 VMs (static 10.100.0.4/.5) + storage account + share' -ForegroundColor DarkGray
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

# Record the resource details NOW. If the session drops during the long middle
# stretch, this file is what tells you what was created and how to reach it.
Write-LabInfo @"
==============================================================
 AZURE FILES LAB - SESSION 1  (deployment IN PROGRESS)
==============================================================
 Started         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
 Lab mode        : $(if ($Modern) { 'MODERN (AES-256)' } else { 'LEGACY (RC4)' })
 Subscription    : $((Get-AzContext).Subscription.Name)
 Resource group  : $ResourceGroupName  ($Location)
 Storage account : $saName
 File share      : \\$saName.file.core.windows.net\labshare
 Domain          : $DomainName
 DC (RDP)        : $dcIpPub   ($AdminUsername)
 Client (RDP)    : $cliIpPub  ($AdminUsername, later CONTOSO\labuser1)
 Transcript      : $logFile

 This file is rewritten with the final result when the deployment finishes.
 If it still says IN PROGRESS, the run did not complete - check the transcript
 for the last '=== step ===' line, then re-run deploy.ps1 with the same
 -ResourceGroupName (the steps are re-runnable).
==============================================================
"@

# Azure allows ONE Run Command per VM at a time; a second one is rejected with
# HTTP 409 "Run command extension execution is in progress". That is not a
# failure, it is a queue - so it gets its own generous wait budget and must not
# burn the real retry allowance.
function Test-RunCommandBusy($ErrorRecord) {
    return ($ErrorRecord.Exception.Message -match 'execution is in progress|Conflict')
}

function Wait-VmRunCommandFree {
    param([string]$VmName, [int]$MaxWaitMin = 30)
    $deadline = (Get-Date).AddMinutes($MaxWaitMin)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
                -CommandId 'RunPowerShellScript' -ScriptString "'FREE'" -ErrorAction Stop | Out-Null
            return $true
        } catch {
            if (-not (Test-RunCommandBusy $_)) { return $true }  # busy is the only thing we wait on
            Write-Host '  another Run Command is still executing on this VM; waiting 45s...'
            Start-Sleep -Seconds 45
        }
    }
    Write-Warning "  gave up waiting for $VmName to be free after $MaxWaitMin min"
    return $false
}

function Invoke-VmScript {
    param([string]$VmName, [string]$ScriptFile, [hashtable]$Params = @{}, [int]$Retries = 1, [int]$RetryDelaySec = 60)
    Show-VmCmd -VmName $VmName -ScriptFile $ScriptFile -Params $Params
    $busyWaits = 0
    for ($i = 1; $i -le $Retries; ) {
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
            if (Test-RunCommandBusy $_) {
                $busyWaits++
                if ($busyWaits -gt 40) { throw }   # ~30 min of queueing is enough
                Write-Host "  $VmName is busy with another Run Command; waiting 45s (attempt $busyWaits)..."
                Start-Sleep -Seconds 45
                continue                            # does NOT consume a retry
            }
            $i++
            if ($i -gt $Retries) { throw }
            Write-Host "  attempt $($i - 1) failed ($($_.Exception.Message.Split("`n")[0])); retrying in ${RetryDelaySec}s..."
            Start-Sleep -Seconds $RetryDelaySec
        }
    }
}

# Same thing as a background job, for work on one VM that can overlap work on
# the other. Az context autosave means the job picks up the current login.
function Start-VmScriptJob {
    param([string]$VmName, [string]$ScriptFile, [hashtable]$Params = @{}, [int]$Retries = 4)
    Show-VmCmd -VmName $VmName -ScriptFile $ScriptFile -Params $Params
    Write-Host '      (as a background job)' -ForegroundColor DarkGray
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
        # A 409 means another Run Command owns the VM - wait it out separately,
        # since that can legitimately take much longer than a transient error.
        $busy = 0
        for ($i = 1; $i -le $retries; ) {
            try {
                $res = Invoke-AzVMRunCommand @rc
                # Return the PLAIN STRING, not the result object: job output is
                # serialized on the way back, which mangles the nested Value
                # collection and made successful runs look like empty output.
                return (($res.Value | Where-Object Code -like '*StdOut*').Message)
            }
            catch {
                if ($_.Exception.Message -match 'execution is in progress|Conflict') {
                    $busy++
                    if ($busy -gt 40) { throw }
                    Start-Sleep -Seconds 45
                    continue
                }
                $i++
                if ($i -gt $retries) { throw }
                Start-Sleep -Seconds 45
            }
        }
    } -ArgumentList $ResourceGroupName, $VmName, (Join-Path (Join-Path $scriptRoot 'scripts') $ScriptFile), $Params, $Retries
}

function Receive-VmScriptJob {
    param($Job, [int]$TimeoutSec = 2400, [string]$Label, [string]$VmName)
    $Job | Wait-Job -Timeout $TimeoutSec | Out-Null
    if ($Job.State -ne 'Completed') {
        Write-Warning "$Label did not complete cleanly (state: $($Job.State))"
        # Surface WHY, so a recurring failure is diagnosable from the transcript.
        $reason = $Job.ChildJobs[0].JobStateInfo.Reason.Message
        if (-not $reason) {
            $reason = (Receive-Job $Job -ErrorAction SilentlyContinue 2>&1 |
                Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
                Select-Object -First 1).Exception.Message
        }
        if ($reason) { Write-Warning "  reason: $($reason.Split("`n")[0])" }
        Remove-Job $Job -Force -ErrorAction SilentlyContinue
        # Removing the JOB does not cancel the script running on the VM, and
        # Azure permits only one Run Command per VM. Moving on now would make
        # the next call fail with 409, so block until the VM is actually free.
        if ($VmName) {
            Write-Host "  making sure $VmName is free before continuing..."
            Wait-VmRunCommandFree -VmName $VmName | Out-Null
        }
        return ''
    }
    $r = Receive-Job $Job
    Remove-Job $Job -Force -ErrorAction SilentlyContinue
    # The job already extracted the StdOut message as a plain string.
    return (($r | Where-Object { $_ }) -join "`n")
}

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
# The script also enables Kerberos auditing (4768/4769 incl. failures) and the
# operational logs - folded in rather than a separate call, because each Run
# Command round-trip costs ~60s regardless of what it does.
Step '3/9 Creating lab users + DC Kerberos auditing (retries until AD is up)'
Invoke-VmScript -VmName $dcName -ScriptFile '02-create-lab-users.ps1' `
    -Params @{ Password = $plainPw } -Retries 8 -RetryDelaySec 60 | Write-Host

# ----------------------------------------------------- 4. Join client VM
# Started as a job: the client reboot (~3 min) overlaps the storage-account
# work below, which only touches the DC and Azure.
Step '4/9 Domain-joining the client VM in the background (reboots itself)'
$clientJoinJob = Start-VmScriptJob -VmName $cliName -ScriptFile '03-join-domain-client.ps1' `
    -Params @{ DomainName = $DomainName; JoinUser = $AdminUsername; JoinPassword = $plainPw }

# --------------------------------------- 5. Domain-join the storage account
Step '5/9 Domain-joining the storage account (kerb key + computer account + SPN)'
Show-Cmd @"
New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1
`$kerbKey = (Get-AzStorageAccountKey ... -ListKerbKey | Where-Object KeyName -eq 'kerb1').Value
"@
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
Show-Cmd @"
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName ``
    -EnableActiveDirectoryDomainServicesForFile `$true ``
    -ActiveDirectoryDomainName '$adDomainNameValue' ``
    -ActiveDirectoryNetBiosDomainName '$($ad.NetBiosDomainName)' ``
    -ActiveDirectorySamAccountName '$($ad.SamAccountName)' -ActiveDirectoryAccountType 'Computer' ``
    (+ ForestName / DomainGuid / DomainSid / AzureStorageSid - the FULL set, always)
Set-AzStorageAccount ... -DefaultSharePermission 'StorageFileDataSmbShareContributor'
"@
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
# Steps 7+8 ride the same Run Command: both run on the DC back to back, and
# each separate invocation would cost ~60s of fixed overhead.
Step '7-8/9 Final kerb key sync (1396 guard) + NTFS permissions'
Show-Cmd "New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1   # rotate once more, then push to AD"
New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
Start-Sleep -Seconds 15  # let the new key value settle before reading it back
$kerbKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
    Where-Object KeyName -eq 'kerb1').Value
$key1 = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName)[0].Value
Invoke-VmScript -VmName $dcName -ScriptFile '06-sync-kerb-password.ps1' `
    -Params @{ StorageAccountName = $saName; KerbKey = $kerbKey; StorageKey = $key1; NetBios = $ad.NetBiosDomainName } `
    -Retries 3 -RetryDelaySec 30 | Write-Host

# ------------------------------- 9. Collect the background client domain join
# Everything above ran on the DC or against Azure, so the client's join and
# reboot happened for free alongside it.
Step '9/9 Confirming the client domain join'
$joinOutput = Receive-VmScriptJob -Job $clientJoinJob -TimeoutSec 1200 -Label 'client domain join' -VmName $cliName
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
$summary = @"
==============================================================
 DEPLOYMENT COMPLETE  ($([int]$sw.Elapsed.TotalMinutes) min $($sw.Elapsed.Seconds % 60) s)
==============================================================
 Finished        : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
 Lab mode        : $labMode
 Mount check     : $(if ($verify -match 'MOUNT_OK') { 'PASSED' } else { 'FAILED - see notes below' })
 Subscription    : $((Get-AzContext).Subscription.Name)
 Resource group  : $ResourceGroupName  ($Location)
 Storage account : $saName
 File share      : \\$saName.file.core.windows.net\labshare
 Domain          : $DomainName
 DC (RDP)        : $dcIpPub  ($($ad.NetBiosDomainName)\$AdminUsername ONLY - plain users can't log on to a DC)
 Client (RDP)    : $cliIpPub ($($ad.NetBiosDomainName)\labuser1 - this is where the labs run)
 Transcript      : $logFile

 Lab quick start (on the CLIENT VM as $($ad.NetBiosDomainName)\labuser1):
   klist purge
   net use Z: \\$saName.file.core.windows.net\labshare
   klist   # look for the cifs/ ticket

 Diagnostics are preinstalled on the CLIENT VM (Az + AzFilesHybrid).
 The DC deliberately has no Azure tooling - only Kerberos auditing (4768/4769):
   Connect-AzAccount
   Debug-AzStorageAccountAuth -StorageAccountName $saName ``
     -ResourceGroupName $ResourceGroupName -Verbose

 Teardown when finished:
   Remove-AzResourceGroup -Name $ResourceGroupName -Force
==============================================================
"@
$summary | Out-File -FilePath $infoFile -Encoding utf8
Write-Host "`n$summary" -ForegroundColor Green
Write-Host "Saved to: $infoFile" -ForegroundColor Yellow

# --------------- POST-DEPLOY: diagnostic tooling (off the critical path)
# This step burned two deployments by sitting in the middle of the run: the
# PowerShell Gallery fallback can take 20-30+ minutes on a B-series VM, and a
# Run Command can neither be cancelled nor share the VM with another one.
# So it now runs LAST, after the environment is complete and verified and the
# summary above is already on disk. Nothing later depends on it: the fault labs
# use klist/net use/setspn, and AzFilesHybrid is only needed once attendees
# reach the Debug-AzStorageAccountAuth part - a good half hour into the session.
Step 'Post-deploy: installing diagnostics on the client (bundle path, ~2-4 min)'
Write-Host '  The lab environment is READY - this last step is optional tooling.' -ForegroundColor Yellow
Write-Host '  Safe to Ctrl+C: once issued, the VM finishes the install on its own.' -ForegroundColor Yellow
$toolParams = @{}
if ($ModuleBundleUri) { $toolParams['ModuleBundleUri'] = $ModuleBundleUri }
try {
    $toolsOut = Invoke-VmScript -VmName $cliName -ScriptFile '07-install-tools.ps1' -Params $toolParams
    if ($toolsOut -match 'TOOLS_READY') {
        Write-Host '  client diagnostics: OK' -ForegroundColor Green
    } elseif ($toolsOut -match 'Module bundle unavailable') {
        Write-Warning '  bundle download failed; the VM fell back to the slow gallery path.'
        Write-Warning '  Check the release asset: tools\New-LabToolsBundle.ps1 + gh release create.'
    } else {
        $detail = ($toolsOut -split "`n" | Select-String 'TOOLS_PARTIAL|FAILED').Line -join '; '
        Write-Warning "  diagnostics incomplete: $detail (rerun scripts\07-install-tools.ps1 on the VM)"
    }
} catch {
    Write-Warning "  diagnostics install did not finish: $($_.Exception.Message.Split("`n")[0])"
    Write-Warning '  The lab itself is unaffected. Rerun scripts\07-install-tools.ps1 on the client later.'
}

try { Stop-Transcript | Out-Null } catch { }
