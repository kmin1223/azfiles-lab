<#
.SYNOPSIS
  Session 1 fault injection - reproduce (and repair) the classic AD DS
  Kerberos failures against Azure Files.

.DESCRIPTION
  Faults (all reversible with -Repair):

  PasswordMismatch  Rotate the AD computer-account password out from under
                    the storage account.
                    Symptom : mount fails; error 1396 / KRB5KRB_AP_ERR_MODIFIED
                    Teach   : SA kerb key <-> AD account password relationship
                    Repair  : rotate kerb1 and re-sync it to AD

  SpnBroken         Replace the SPN on the storage computer account.
                    Symptom : KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN; klist get fails
                              with 0xc000018b
                    Repair  : restore cifs/<sa>.file.core.windows.net

  EtypeMismatch     Force the CLIENT to offer only DES encryption types.
                    Symptom : "The encryption type requested is not supported
                              by the KDC" / KRB5KDC_ERR_ETYPE_NOSUPP
                    Teach   : same failure class as the 2026 RC4-retirement
                              wave - the lab account is AES-256 for this reason
                    Repair  : reset client policy to defaults

  Block445          NSG outbound Deny TCP/445 on the lab subnet.
                    Symptom : System error 53/67 (often after a timeout);
                              Test-NetConnection -Port 445 fails.
                              (Error 64 is a DIFFERENT signature: TCP connects
                              but a proxy/NAT drops the SMB handshake.)
                    Repair  : delete the rule

  NoShareAccess     Set DefaultSharePermission = None (share-level RBAC gone).
                    Symptom : mount OK-ish but Access Denied at share level
                    Repair  : restore StorageFileDataSmbShareContributor

  --- advanced (evidence required - the error text alone won't tell you) ---

  ClockSkew         Push the CLIENT clock ~10 minutes off the DC.
                    Symptom : mount fails; the error is generic, but the wire
                              shows KRB_AP_ERR_SKEW / KRB_ERR_TIME_SKEW and
                              event 4769 may not even appear
                    Teach   : Kerberos tolerates only ~5 min skew; in the field
                              this looks like "it broke for no reason"
                    Repair  : re-sync time (w32tm /resync)

  DuplicateSpn      Register the storage SPN on a SECOND AD object.
                    Symptom : intermittent/odd failures - the KDC can't decide
                              which account owns the SPN
                    Diagnose: setspn -X (or -Q) shows the duplicate; the trace
                              shows the TGS-REP encrypted for the wrong account
                    Repair  : remove the SPN from the decoy object

.EXAMPLE
  .\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch
  .\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch -Repair
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [ValidateSet('PasswordMismatch', 'SpnBroken', 'EtypeMismatch', 'Block445', 'NoShareAccess',
                 'ClockSkew', 'DuplicateSpn')]
    [string]$Fault,
    [switch]$Repair,
    [string]$Prefix = 'azflab'
)
$ErrorActionPreference = 'Stop'

$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
    Where-Object { $_.StorageAccountName -like "$Prefix*" } | Select-Object -First 1
if (-not $sa) { throw "No $Prefix* storage account in $ResourceGroupName" }
$saName = $sa.StorageAccountName
$dcName = "$Prefix-dc"
$cliName = "$Prefix-cli"
$nsgName = "$Prefix-nsg"

function Invoke-OnVm([string]$Vm, [string]$Script) {
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $Script
    try {
        $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $Vm `
            -CommandId 'RunPowerShellScript' -ScriptPath $tmp
        ($r.Value | Where-Object Code -like '*StdOut*').Message
    } finally { Remove-Item $tmp -Force }
}

$mode = if ($Repair) { 'REPAIR' } else { 'INJECT' }
Write-Host "[$mode] $Fault on $saName" -ForegroundColor Yellow

switch ($Fault) {

    'PasswordMismatch' {
        if (-not $Repair) {
            $rand = -join ((33..126) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
            Invoke-OnVm $dcName @"
Import-Module ActiveDirectory
`$comp = Get-ADComputer -Identity '$saName'
Set-ADAccountPassword -Identity `$comp.DistinguishedName -Reset ``
  -NewPassword (ConvertTo-SecureString '$($rand.Replace("'","''"))' -AsPlainText -Force)
Write-Output 'AD password rotated (out of sync with kerb1)'
"@ | Write-Host
            Write-Host 'Now on the client: klist purge; net use Z: \\...\labshare  -> error 1396 / AP_ERR_MODIFIED'
        } else {
            New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
            $kerb = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
                Where-Object KeyName -eq kerb1).Value
            Invoke-OnVm $dcName @"
Import-Module ActiveDirectory
`$comp = Get-ADComputer -Identity '$saName'
Set-ADAccountPassword -Identity `$comp.DistinguishedName -Reset ``
  -NewPassword (ConvertTo-SecureString '$($kerb.Replace("'","''"))' -AsPlainText -Force)
Write-Output 'kerb1 re-synced to AD password'
"@ | Write-Host
        }
    }

    'SpnBroken' {
        $goodSpn = "cifs/$saName.file.core.windows.net"
        $badSpn = "cifs/borked-$saName.file.core.windows.net"
        $spn = if ($Repair) { $goodSpn } else { $badSpn }
        Invoke-OnVm $dcName @"
Import-Module ActiveDirectory
Set-ADComputer -Identity '$saName' -ServicePrincipalNames @{Replace='$spn'}
Write-Output "SPN now: $spn"
"@ | Write-Host
        if (-not $Repair) {
            Write-Host "Client: klist purge; klist get $goodSpn  -> S_PRINCIPAL_UNKNOWN / 0xc000018b"
        }
    }

    'EtypeMismatch' {
        if (-not $Repair) {
            # 3 = DES only -> KDC refuses (Azure Files supports RC4/AES256 only)
            Invoke-OnVm $cliName @'
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
  -Name SupportedEncryptionTypes -Value 3 -Type DWord
Write-Output 'Client now offers DES only'
'@ | Write-Host
            Write-Host 'Client: klist purge; net use -> "encryption type not supported by the KDC"'
        } else {
            Invoke-OnVm $cliName @'
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
  -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue
Write-Output 'Client encryption types restored to default'
'@ | Write-Host
        }
    }

    'Block445' {
        $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $nsgName
        if (-not $Repair) {
            $nsg | Add-AzNetworkSecurityRuleConfig -Name 'Deny-SMB-445' `
                -Direction Outbound -Access Deny -Protocol Tcp -Priority 100 `
                -SourceAddressPrefix '*' -SourcePortRange '*' `
                -DestinationAddressPrefix 'Storage' -DestinationPortRange 445 |
                Set-AzNetworkSecurityGroup | Out-Null
            Write-Host 'Outbound 445 to Storage blocked. Client: net use -> System error 53/67 (timeout)'
            Write-Host "Diagnose: Test-NetConnection $saName.file.core.windows.net -Port 445"
        } else {
            $nsg | Remove-AzNetworkSecurityRuleConfig -Name 'Deny-SMB-445' |
                Set-AzNetworkSecurityGroup | Out-Null
            Write-Host '445 unblocked.'
        }
    }

    'NoShareAccess' {
        $perm = if ($Repair) { 'StorageFileDataSmbShareContributor' } else { 'None' }
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
            -DefaultSharePermission $perm | Out-Null
        Write-Host "DefaultSharePermission = $perm"
        if (-not $Repair) {
            Write-Host 'Client: mount/access -> Access is denied (share level, NOT NTFS).'
            Write-Host 'Teach: contrast with an NTFS deny - different layer, different error surface.'
        }
    }

    'ClockSkew' {
        if (-not $Repair) {
            # Stop time sync and jump the clock ~10 min (Kerberos tolerance is ~5)
            Invoke-OnVm $cliName @'
Stop-Service w32time -ErrorAction SilentlyContinue
Set-Service w32time -StartupType Disabled -ErrorAction SilentlyContinue
Set-Date (Get-Date).AddMinutes(10)
Write-Output "Client clock is now $(Get-Date) (skewed +10 min)"
'@ | Write-Host
            Write-Host 'Client: klist purge; net use -> fails. The message is vague on purpose.'
            Write-Host 'Evidence: trace shows KRB_AP_ERR_SKEW; compare w32tm /stripchart against the DC.'
        } else {
            Invoke-OnVm $cliName @'
Set-Service w32time -StartupType Automatic
Start-Service w32time
w32tm /resync /force 2>&1 | Out-Null
Start-Sleep -Seconds 5
Write-Output "Client clock re-synced: $(Get-Date)"
'@ | Write-Host
        }
    }

    'DuplicateSpn' {
        $spn = "cifs/$saName.file.core.windows.net"
        $decoy = "$saName-decoy"
        if (-not $Repair) {
            Invoke-OnVm $dcName @"
Import-Module ActiveDirectory
`$ou = (Get-ADOrganizationalUnit -Filter "Name -eq 'AzureFilesLab'").DistinguishedName
if (-not (Get-ADComputer -Filter "Name -eq '$decoy'" -ErrorAction SilentlyContinue)) {
    New-ADComputer -Name '$decoy' -Path `$ou -Enabled `$true ``
        -Description 'decoy holding a duplicate SPN (lab fault)'
}
Set-ADComputer -Identity '$decoy' -ServicePrincipalNames @{Add='$spn'}
Write-Output 'Duplicate SPN registered on $decoy'
setspn -X -P 2>&1 | Select-String -Pattern 'duplicate|$saName' | ForEach-Object { `$_.ToString() }
"@ | Write-Host
            Write-Host "Client: klist purge; net use -> fails or behaves oddly."
            Write-Host "Evidence: on the DC run  setspn -X   (or setspn -Q $spn) to reveal TWO owners."
        } else {
            Invoke-OnVm $dcName @"
Import-Module ActiveDirectory
if (Get-ADComputer -Filter "Name -eq '$decoy'" -ErrorAction SilentlyContinue) {
    Remove-ADComputer -Identity '$decoy' -Confirm:`$false
    Write-Output 'Decoy object removed - SPN is unique again'
}
"@ | Write-Host
        }
    }
}
Write-Host "[$mode] done." -ForegroundColor Green
