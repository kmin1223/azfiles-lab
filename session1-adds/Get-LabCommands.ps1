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

  Deployment includes the VM password in this private sheet. Do not screen-share
  or commit it. Standalone runs need -AdminPassword to include the password;
  Azure cannot retrieve the existing password.

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
    [string]$AdminUsername = 'labadmin',
    [SecureString]$AdminPassword,
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
# infer a target when the stored domain is a dotted DNS name.
if (-not $DomainController -and $ad -and $ad.DomainName -match '^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$') {
    $DomainController = "$Prefix-dc.$($ad.DomainName)"
}
$dcArgument = if ($DomainController) { " -DomainController '$($DomainController.Replace("'", "''"))'" } else { '' }

$ips = @{}
foreach ($p in Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue) {
    if ($p.Name -like '*dc*')  { $ips.DC  = $p.IpAddress }
    if ($p.Name -like '*cli*') { $ips.Cli = $p.IpAddress }
}
$dcIp  = if ($ips.DC)  { $ips.DC }  else { '<dc-ip>' }
$cliIp = if ($ips.Cli) { $ips.Cli } else { '<client-ip>' }

$passwordText = if ($AdminPassword) {
    [System.Net.NetworkCredential]::new('', $AdminPassword).Password
} else {
    'Not supplied. Rerun with -AdminPassword to include the lab password.'
}
$passwordNotice = if ($AdminPassword) {
    'PRIVATE LAB FILE: contains a plaintext password. Do not screen-share or commit.'
} else {
    'Azure does not return existing VM passwords.'
}

$text = @"
================================================================================
 LAB COMMANDS - $saName
 generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  identity source: $source
================================================================================

 [A] Cloud Shell     you are already signed in; no Connect-AzAccount
 [B] Client VM       mstsc /v:$cliIp     sign in as $nb\labuser1
 [C] DC VM           mstsc /v:$dcIp     $nb\$AdminUsername only; optional follow-up

 VM accounts: $nb\$AdminUsername, $nb\labuser1, $nb\labuser2
 VM password: $passwordText
 $passwordNotice

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

[B] baseline evidence - two windows, three steps in this order
    # 1. ELEVATED PowerShell (UAC -> Yes)
    C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace$dcArgument
    # 2. NORMAL PowerShell - the mount must happen in YOUR session
    C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount $saName -Share $Share
    # 3. back in the ELEVATED window
    C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace

[B] the KDC's own record is collected remotely at StopTrace
    Open dc-summary.txt in the capture folder, then inspect the time-bounded
    DC Security exports (4768/4769/4771, XML/JSON/CSV) for the reproduced request.
    No separate DC sign-in is needed. Without a reliable DNS target above,
    the collector uses its installed DC configuration/domain discovery.
    Missing/denied/empty DC evidence is not proof that the KDC is healthy.
    Sign out/in after new group membership; use -DcCredential if needed
    (the collector does not store credentials).
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

    Read the output: it mounts fine on RC4. That is the point.

[A] step 1 - comply with the 2026 mandate
    ./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName $ResourceGroupName -Step Enforce

[B] step 2 - retest. DROP THE SMB SESSION FIRST, or nothing is proven
    net use * /delete /y
    net use $unc /delete /y
    net use Z: /delete /y
    klist purge
    #   ELEVATED window - Get-SmbConnection needs it:
    Get-SmbConnection | Where-Object ServerName -like '*file.core.windows.net'
    #   back in the normal window:
    net use Z: $unc

    Expect: System error 1396.
    Mount succeeds but klist is empty? You reused the old session - sign out/in.

[B] step 3 - collect evidence, then read it
    C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace$dcArgument          # elevated
    C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount $saName -Share $Share
    C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace           # elevated
    klist

[B]     Read dc-summary.txt and correlate the DC exports with this request.
        A matching 4769 success proves issuance, not that every KDC/key path is healthy.
[A]     For this planted defect, check the derived-key salt metadata:
    ./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName $ResourceGroupName -Step Status
        -> ActiveDirectoryDomainName reads $nb (NetBIOS), not the DNS root.

[A] step 4 - repair. The ORDER is the lesson
    ./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName $ResourceGroupName -Step Repair

[B]     net use * /delete /y ; klist purge ; net use Z: $unc ; klist
        -> AES-256-CTS-HMAC-SHA1-96


--------------------------------------------------------------------------------
 LAB 3 - a perfect ticket, and Access Denied
--------------------------------------------------------------------------------
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault CipherMismatch
[B] net use * /delete /y ; klist purge ; net use Z: $unc
[B] klist                                    # the cifs ticket IS there
    Get-SmbClientConfiguration | Select-Object -ExpandProperty EncryptionCiphers
    # storage side: portal -> storage account -> File shares -> Security
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault CipherMismatch -Repair


--------------------------------------------------------------------------------
 LABS 4-6 - if time allows
--------------------------------------------------------------------------------
[A] 4  blocked 445 / share permission
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault Block445
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault Block445 -Repair
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault NoShareAccess
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault NoShareAccess -Repair
[B] Test-NetConnection $fqdn -Port 445

[A] 5  the other 1396 - key drift
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault PasswordMismatch
[B] klist purge ; net use Z: $unc                      # -> 1396
[B] Connect-AzAccount                                  # this one runs IN the VM
    Debug-AzStorageAccountAuth -StorageAccountName $saName -ResourceGroupName $ResourceGroupName -Verbose
    #   CheckADObjectPasswordIsCorrect fails
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault PasswordMismatch -Repair

[A] 6  broken SPN
    ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault SpnBroken
[B] klist purge ; klist get cifs/$fqdn                 # -> 0xc000018b
[C] setspn -L $saName
    setspn -F -Q cifs/$fqdn
[A] ./faults/Invoke-Fault.ps1 -ResourceGroupName $ResourceGroupName -Fault SpnBroken -Repair


--------------------------------------------------------------------------------
 HANDY
--------------------------------------------------------------------------------
[B] klist                                   # the ticket cache
    klist purge                             # tickets only - NOT the SMB session
    klist get cifs/$fqdn                     # force one ticket, no mount
    Get-SmbConnection | ? ServerName -like '*file.core.windows.net'   # elevated
    C:\LabTools\Get-KerberosEvidence.ps1 -Analyze     # re-read the last capture

    Retest reset, in this order:
    net use $unc /delete /y ; net use Z: /delete /y ; klist purge

[A] teardown
    Remove-AzResourceGroup -Name $ResourceGroupName -Force
================================================================================
"@

if ($OutFile) {
    $text | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Lab commands written to: $OutFile" -ForegroundColor Yellow
}
$text
