<#
.SYNOPSIS
  Session 1 one-shot deployer: simulated on-prem AD DS + Azure Files AD DS auth.

.DESCRIPTION
  Single command, no interaction after the password prompt:
    1. Resource group + ARM template deployment (VNet/DC/client/storage/share)
    2. Promote DC to a new AD forest (contoso.local)
    3. Create lab users (labuser1/labuser2)
    4. Domain-join the client VM
    5. Domain-join the STORAGE ACCOUNT (computer account + SPN + kerb1 key)
    6. Enable AD DS auth on the storage account (Set-AzStorageAccount)
    7. Final kerb key rotation + AD password sync (1396 guard)
    8. Default share-level permission + NTFS ACLs
    9. Install Az + AzFilesHybrid on both VMs (Debug-AzStorageAccountAuth etc.)

  Total time: ~25-35 minutes. Run it at the START of the session, present
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
    [switch]$Modern
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
            $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
                -CommandId 'RunPowerShellScript' `
                -ScriptPath (Join-Path (Join-Path $scriptRoot 'scripts') $ScriptFile) `
                -Parameter $Params -ErrorAction Stop
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

# ------------------------------------------------------- 2. Promote the DC
Step '2/9 Promoting DC to a new forest (reboots itself, ~10 min)'
$promoteOut = Invoke-VmScript -VmName $dcName -ScriptFile '01-promote-dc.ps1' `
    -Params @{ DomainName = $DomainName; SafeModePassword = $plainPw }
$promoteOut | Write-Host
if ($promoteOut -notmatch 'ALREADY_PROMOTED') {
    Write-Host 'Waiting 4 minutes for DC reboot...'
    Start-Sleep -Seconds 240
}

# ----------------------------------------------------------- 3. Lab users
Step '3/9 Creating lab users (retries until AD is up)'
Invoke-VmScript -VmName $dcName -ScriptFile '02-create-lab-users.ps1' `
    -Params @{ Password = $plainPw } -Retries 8 -RetryDelaySec 60 | Write-Host

# ----------------------------------------------------- 4. Join client VM
Step '4/9 Domain-joining the client VM (reboots itself)'
Invoke-VmScript -VmName $cliName -ScriptFile '03-join-domain-client.ps1' `
    -Params @{ DomainName = $DomainName; JoinUser = $AdminUsername; JoinPassword = $plainPw } `
    -Retries 3 -RetryDelaySec 60 | Write-Host

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

# ------------------------------------------- 9. Diagnostic tooling on the VMs
# Az modules + AzFilesHybrid so attendees can run Debug-AzStorageAccountAuth
# and the kerb-key cmdlets directly on the lab machines.
Step '9/9 Installing diagnostic tools on both VMs (Az + AzFilesHybrid)'
$toolJobs = @($cliName, $dcName) | ForEach-Object {
    $vm = $_
    Start-Job -Name "tools-$vm" -ScriptBlock {
        param($rg, $vmName, $path)
        Import-Module Az.Compute -ErrorAction SilentlyContinue
        Invoke-AzVMRunCommand -ResourceGroupName $rg -VMName $vmName `
            -CommandId 'RunPowerShellScript' -ScriptPath $path -ErrorAction Stop
    } -ArgumentList $ResourceGroupName, $vm, (Join-Path (Join-Path $scriptRoot 'scripts') '07-install-tools.ps1')
}
Write-Host '  installing on both VMs in parallel (a few minutes)...'
$toolJobs | Wait-Job -Timeout 900 | Out-Null
foreach ($j in $toolJobs) {
    if ($j.State -eq 'Completed') {
        $out = (Receive-Job $j).Value | Where-Object Code -like '*StdOut*'
        if ($out.Message -match 'TOOLS_READY') { Write-Host "  $($j.Name): OK" }
        else { Write-Warning "  $($j.Name): finished with warnings - see the lab VM if tools are missing" }
    }
    else {
        Write-Warning "  $($j.Name): $($j.State) - install tools manually if needed (scripts\07-install-tools.ps1)"
    }
    Remove-Job $j -Force -ErrorAction SilentlyContinue
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

 Diagnostics are preinstalled on both VMs (Az + AzFilesHybrid):
   Connect-AzAccount
   Debug-AzStorageAccountAuth -StorageAccountName $saName ``
     -ResourceGroupName $ResourceGroupName -Verbose
==============================================================
"@ -ForegroundColor Green
