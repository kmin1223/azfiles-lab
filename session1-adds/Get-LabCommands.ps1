<#
.SYNOPSIS
  Print every lab command for THIS deployment, with the real storage account
  name, IPs and domain already filled in.

.DESCRIPTION
  The workbook has to say <sa>. This doesn't - it reads your resource group and
  prints commands you can paste as they are.

  deploy.ps1 calls this at the end and saves the result next to the lab-info
  file, so it survives a Cloud Shell disconnect. Run it again any time:

      ./Get-LabCommands.ps1 -ResourceGroupName azfiles-lab

  Windows referenced below:
      [A] Azure Cloud Shell        deploy, faults, the migration lab
      [B] Client VM  (RDP)         klist / net use / evidence   <- most of it
      [C] DC VM      (RDP)         optional manual follow-up / setspn

.EXAMPLE
  ./Get-LabCommands.ps1 -ResourceGroupName azfiles-lab
  ./Get-LabCommands.ps1 -ResourceGroupName azfiles-lab -OutFile ~/lab-commands.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Prefix = 'azflab',
    [string]$Share  = 'labshare',
    [string]$DomainController,
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'

# The lab account, not the extra one Test-Coexistence.ps1 may have created.
$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
    Where-Object { $_.StorageAccountName -like "$Prefix*" -and
                   $_.StorageAccountName -notlike "${Prefix}ads*" } |
    Select-Object -First 1
if (-not $sa) { throw "No $Prefix* storage account in $ResourceGroupName." }

$saName = $sa.StorageAccountName
$fqdn   = "$saName.file.core.windows.net"
$unc    = "\\$fqdn\$Share"
$ad     = $sa.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
$nb     = if ($ad -and $ad.NetBiosDomainName) { $ad.NetBiosDomainName } else { 'CONTOSO' }
$realm  = if ($ad -and $ad.DomainName) { $ad.DomainName.ToUpper() } else { 'CONTOSO.LOCAL' }
$source = $sa.AzureFilesIdentityBasedAuth.DirectoryServiceOptions
# Legacy storage metadata can hold a NetBIOS name instead of a DNS root.
# deploy.ps1 supplies the authoritative forest DNS name; standalone runs only
# Prefer ForestName because Legacy DomainName can be NetBIOS-only.
$forestDns = if ($ad -and $ad.ForestName -match '^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$') {
    $ad.ForestName
} elseif ($ad -and $ad.DomainName -match '^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$') {
    $ad.DomainName
}
if (-not $DomainController -and $forestDns) {
    $DomainController = "$Prefix-dc.$forestDns"
}
$dcArgument = if ($DomainController) { " -DomainController '$($DomainController.Replace("'", "''"))'" } else { '' }

$ips = @{}
foreach ($p in Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue) {
    if ($p.Name -like '*dc*')  { $ips.DC  = $p.IpAddress }
    if ($p.Name -like '*cli*') { $ips.Cli = $p.IpAddress }
}
$dcIp  = if ($ips.DC)  { $ips.DC }  else { '<dc-ip>' }
$cliIp = if ($ips.Cli) { $ips.Cli } else { '<client-ip>' }

$text = @"
================================================================================
 LAB COMMANDS - $saName
 generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  identity source: $source
================================================================================

 [A] Cloud Shell     you are already signed in; no Connect-AzAccount
 [B] Client VM       mstsc /v:$cliIp     sign in as $nb\labuser1
 [C] DC VM           mstsc /v:$dcIp     $nb\labadmin only; optional follow-up

 Share: $unc


--------------------------------------------------------------------------------
 LAB 1 - first mount and tickets
--------------------------------------------------------------------------------
[B]
    klist purge
    klist get cifs/$fqdn
    net use Z: $unc
    klist
    echo hello > "Z:\`$(`$env:USERNAME).txt"

    Expect: Server = cifs/$fqdn, encryption type AES-256.

[B] optional automatic evidence - ONE command in the NORMAL labuser1 window
    # Requires AUTO_EVIDENCE_READY from deployment/upgrade.
    C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
    # SYSTEM captures; a new non-admin labuser1 batch logon connects via UNC.
    # No Z: mapping, logout, password prompt or separate StopTrace is needed.
    # Read the printed run folder: user\ holds mount/tickets/DC evidence;
    # capture\ holds the trace and collector-side events/state.
    # This tests fresh authentication, NOT the existing RDP/app logon session.

[B] manual capture of the EXISTING affected session (real-case alternative)
    # 1. ELEVATED PowerShell (UAC -> Yes)
    C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace -Manual$dcArgument
    # 2. NORMAL PowerShell - the mount must happen in YOUR session
    C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount $saName -Share $Share
    # 3. back in the ELEVATED window
    C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace

[B] the KDC's own record is collected remotely (automatic worker / manual StopTrace)
    Open user\dc-summary.txt (automatic) or dc-summary.txt (manual), then inspect the time-bounded
    DC Security exports (4768/4769/4771, XML/JSON/CSV) for the reproduced request.
    No separate DC sign-in is needed. Without a reliable DNS target above,
    the collector uses its installed DC configuration/domain discovery.
    Missing/denied/empty DC evidence is not proof that the KDC is healthy.
    Sign out/in after new group membership; use -DcCredential if needed
    (manual DC credentials are not stored; automatic tasks use the deployment credential).
    Retry only DC collection for an existing capture:
    C:\LabTools\Get-KerberosEvidence.ps1 -CollectDc -Path '<capture-folder>'$dcArgument

[C] optional administrator follow-up if remote DC collection is unavailable
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 100 |
      Where-Object Message -match '$saName' |
      Select-Object -First 3 | Format-List TimeCreated, Message


--------------------------------------------------------------------------------
 LAB 2 - AES-256 migration  (the centrepiece)
--------------------------------------------------------------------------------
[A] step 0 - plant the 2023 defect (~3 min; start it during the RC4 slides)
    ./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName $ResourceGroupName -Step Legacy

    Review completion and the machine-account probe. The automatic evidence
    command below independently tests a fresh labuser1 logon under Legacy.
[B] C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace

[A] step 1 - comply with the 2026 mandate
    ./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName $ResourceGroupName -Step Enforce

[B] steps 2-3 - fresh-session reproduction AND collection, in the NORMAL window
    C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
    Expected planted-fault symptom: 1396; inspect the actual response/token.
    Read user\reproduction.json and user\klist-after.txt in the printed folder.
    Your original window's klist is NOT the worker's ticket cache.

[B]     Read dc-summary.txt and correlate the DC exports with this request.
        A matching 4769 success proves issuance, not that every KDC/key path is healthy.
[A]     For this planted defect, check the derived-key salt metadata:
    ./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName $ResourceGroupName -Step Status
        -> ActiveDirectoryDomainName reads $nb (NetBIOS), not the DNS root.

[A] step 4 - repair. The ORDER is the lesson
    ./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName $ResourceGroupName -Step Repair

[B]     C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
        Check fresh AES-256 issuance and Session Setup/share-connection success.
        File write/read is a separate verification, not implied by net use.


--------------------------------------------------------------------------------
 LAB 3 - ticket issued, session denied
--------------------------------------------------------------------------------
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault CipherMismatch
[B] C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
    # Read the worker's klist-after.txt, not this window's cache.
    Get-SmbClientConfiguration | Select-Object -ExpandProperty EncryptionCiphers
    # storage side: portal -> storage account -> File shares -> Security
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault CipherMismatch -Repair
[B] C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace


--------------------------------------------------------------------------------
 LABS 4-6 - if time allows
--------------------------------------------------------------------------------
[A] 4  blocked 445 / share permission
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault Block445
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault Block445 -Repair
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault NoShareAccess
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault NoShareAccess -Repair
[B] After EACH fault and EACH repair:
    C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
    Test-NetConnection $fqdn -Port 445

[A] 5  the other 1396 - key drift
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault PasswordMismatch
[B] C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace    # inspect actual 1396 / inner KRB error
[B] Connect-AzAccount                                  # this one runs IN the VM
    Debug-AzStorageAccountAuth -StorageAccountName $saName -ResourceGroupName $ResourceGroupName -Verbose
    #   CheckADObjectPasswordIsCorrect fails
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault PasswordMismatch -Repair
[B] C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace

[A] 6  broken SPN
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault SpnBroken
[B] C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
    # Separate optional klist-get probe in this window (not the captured net use):
    klist purge ; klist get cifs/$fqdn                 # expected klist failure, not net use's code
[C] setspn -L $saName
    setspn -F -Q cifs/$fqdn
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault SpnBroken -Repair
[B] C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace


--------------------------------------------------------------------------------
 HANDY
--------------------------------------------------------------------------------
[B] klist                                   # the ticket cache
    klist purge                             # tickets only - NOT the SMB session
    klist get cifs/$fqdn                     # force one ticket, no mount
    Get-SmbConnection | ? ServerName -like '*file.core.windows.net'   # elevated
    C:\LabTools\Get-KerberosEvidence.ps1 -Analyze -Path '<printed-run-folder>\capture'

    Automatic retest: -StartTrace opens a fresh worker logon; no mapping reset.
    Manual retest: mapping deletion and purge alone do not prove SMB session teardown.
    Preserve manual mode for actual application/RDP-session issues, user GPO,
    and faults affecting Windows logon itself (such as client clock skew).

[A] Existing VM / interrupted deployment: install or update automatic evidence
    ./Update-LabEvidenceAutomation.ps1 -ResourceGroupName $ResourceGroupName -Prefix $Prefix -StorageAccount $saName -Share $Share$dcArgument
    # One-time labuser1 password prompt at setup; no password prompts per capture.

[A] teardown
    Remove-AzResourceGroup -Name $ResourceGroupName -Force
================================================================================
"@

if ($OutFile) {
    $text | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Lab commands written to: $OutFile" -ForegroundColor Yellow
}
$text
