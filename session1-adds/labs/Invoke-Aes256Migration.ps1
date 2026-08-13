<#
.SYNOPSIS
  The AES-256 migration lab - modelled on a real Sev A incident.

.DESCRIPTION
  The lab deploys a "2023 vintage" storage account: RC4 Kerberos encryption and
  an ActiveDirectoryDomainName holding the NetBIOS name instead of the DNS root.
  RC4 doesn't salt its keys, so that misconfiguration is invisible - the share
  mounts perfectly. The moment you comply with the 2026 mandate and move to
  AES-256, authentication breaks with error 1396, because the AES key is derived
  from a salt built out of DomainName + SamAccountName + AccountType.

  Steps:
    Status   Show the current state: encryption type, DomainName, kerb key age.
    Enforce  The naive migration - flip the AD object to AES-256 only.
             Expected result: mounts start failing with 1396.
    Repair   The correct fix, in the order that actually matters:
               1. correct ActiveDirectoryDomainName (full parameter set!)
               2. regenerate the kerb key   <- the new salt is baked in HERE
               3. reset the AD object password to that key
    Rollback Return to the legacy RC4 state (to re-run the lab).

.EXAMPLE
  ./Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Status
  ./Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Enforce
  ./Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Repair

.NOTES
  After any change, on the CLIENT VM you must drop existing SMB sessions before
  retesting - an established session keeps working even after the keys change,
  because TreeConnect on a live session performs no new authentication.

  'net use * /delete' removes drive MAPPINGS and 'klist purge' removes TICKETS;
  neither kills the SMB SESSION itself. The tell: the mount "succeeds" while
  klist shows zero tickets - that success came from the old session, not from
  a new Kerberos exchange. Verify and kill it:
      Get-SmbConnection | ? ServerName -like '*file.core.windows.net*'
      net use \\<sa>.file.core.windows.net\labshare /delete /y
      klist purge
  Still listed? Sign out/in, or (elevated) Restart-Service LanmanWorkstation -Force.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [ValidateSet('Status', 'Enforce', 'Repair', 'Rollback')]
    [string]$Step,
    [string]$Prefix = 'azflab'
)
$ErrorActionPreference = 'Stop'

$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
    Where-Object StorageAccountName -like "$Prefix*" | Select-Object -First 1
if (-not $sa) { throw "No $Prefix* storage account in $ResourceGroupName" }
$saName = $sa.StorageAccountName
$dcName = "$Prefix-dc"
$adProps = $sa.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

# Every command this lab runs is echoed BEFORE it runs, so you can follow what
# the script does and reuse the commands yourself. Secrets are masked.
function Show-Cmd([string]$Where, [string]$Command) {
    Write-Host ''
    Write-Host "  .-- commands ($Where) " -ForegroundColor DarkCyan
    $Command.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  | $_" -ForegroundColor Gray }
    Write-Host "  '--" -ForegroundColor DarkCyan
}

function Invoke-OnDc([string]$Script, [string]$Display) {
    # $Display: what to SHOW instead of $Script, when the script embeds a secret.
    Show-Cmd -Where "runs on the DC, $dcName" -Command ($(if ($Display) { $Display } else { $Script }))
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $Script
    try {
        $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $dcName `
            -CommandId 'RunPowerShellScript' -ScriptPath $tmp
        ($r.Value | Where-Object Code -like '*StdOut*').Message
    } finally { Remove-Item $tmp -Force }
}

# Set-AzStorageAccount silently ignores a partial AD property update - you must
# pass the whole set every time, or the value you think you changed won't change.
function Set-AdProperties([string]$DomainNameValue) {
    Show-Cmd -Where 'runs here, against Azure' -Command @"
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName ``
    -EnableActiveDirectoryDomainServicesForFile `$true ``
    -ActiveDirectoryDomainName '$DomainNameValue' ``
    -ActiveDirectoryNetBiosDomainName '$($adProps.NetBiosDomainName)' ``
    -ActiveDirectoryForestName '$($adProps.ForestName)' ``
    -ActiveDirectoryDomainGuid '$($adProps.DomainGuid)' ``
    -ActiveDirectoryDomainSid '$($adProps.DomainSid)' ``
    -ActiveDirectoryAzureStorageSid '$($adProps.AzureStorageSid)' ``
    -ActiveDirectorySamAccountName '$($adProps.SamAccountName)' ``
    -ActiveDirectoryAccountType '$($adProps.AccountType)'
"@
    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
        -EnableActiveDirectoryDomainServicesForFile $true `
        -ActiveDirectoryDomainName $DomainNameValue `
        -ActiveDirectoryNetBiosDomainName $adProps.NetBiosDomainName `
        -ActiveDirectoryForestName $adProps.ForestName `
        -ActiveDirectoryDomainGuid $adProps.DomainGuid `
        -ActiveDirectoryDomainSid $adProps.DomainSid `
        -ActiveDirectoryAzureStorageSid $adProps.AzureStorageSid `
        -ActiveDirectorySamAccountName $adProps.SamAccountName `
        -ActiveDirectoryAccountType $adProps.AccountType | Out-Null
}

function Sync-KerbKeyToAd {
    Show-Cmd -Where 'runs here, against Azure' -Command @"
New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1
`$kerb = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
    Where-Object KeyName -eq 'kerb1').Value
"@
    New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
    Start-Sleep -Seconds 15   # let the new key value settle before reading it
    $kerb = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
        Where-Object KeyName -eq 'kerb1').Value
    $dcScript = @"
Import-Module ActiveDirectory
`$pdc = (Get-ADDomain).PDCEmulator
`$comp = Get-ADComputer -Identity '$saName' -Server `$pdc
Set-ADAccountPassword -Identity `$comp.DistinguishedName -Server `$pdc -Reset ``
  -NewPassword (ConvertTo-SecureString '$($kerb.Replace("'","''"))' -AsPlainText -Force)
repadmin /syncall `$pdc /AdeP 2>&1 | Out-Null
Write-Output "AD password re-synced to the new kerb1 key on `$pdc"
"@
    Invoke-OnDc -Script $dcScript -Display ($dcScript -replace [regex]::Escape($kerb.Replace("'","''")), '<kerb1-key>') |
        Write-Host
}

switch ($Step) {

    'Status' {
        Write-Host "`n=== Storage account: $saName ===" -ForegroundColor Cyan
        Write-Host "ActiveDirectoryDomainName : $($adProps.DomainName)"
        Write-Host "NetBiosDomainName         : $($adProps.NetBiosDomainName)"
        Write-Host "SamAccountName            : $($adProps.SamAccountName)"
        Write-Host "AccountType               : $($adProps.AccountType)"
        if ($adProps.DomainName -eq $adProps.NetBiosDomainName) {
            Write-Warning 'DomainName holds the NetBIOS name, not the DNS root - this is the latent defect.'
        }
        Write-Host "`n=== AD object (read from the PDC) ===" -ForegroundColor Cyan
        Invoke-OnDc @"
Import-Module ActiveDirectory
# Always read from the PDC - another DC can return a stale PasswordLastSet.
`$pdc = (Get-ADDomain).PDCEmulator
Get-ADComputer -Identity '$saName' -Server `$pdc ``
    -Properties KerberosEncryptionType, 'msDS-SupportedEncryptionTypes', PasswordLastSet |
  Select-Object Name, KerberosEncryptionType, 'msDS-SupportedEncryptionTypes', PasswordLastSet |
  Format-List | Out-String | Write-Output
"@ | Write-Host
    }

    'Enforce' {
        Write-Host "Migrating $saName to AES-256 the naive way (AD object only)..." -ForegroundColor Yellow
        Invoke-OnDc @"
Import-Module ActiveDirectory
`$pdc = (Get-ADDomain).PDCEmulator
Set-ADComputer -Identity '$saName' -Server `$pdc -KerberosEncryptionType AES256
repadmin /syncall `$pdc /AdeP 2>&1 | Out-Null
Write-Output 'AD object now advertises AES256 only'
"@ | Write-Host
        Write-Host @"

Now retest on the CLIENT VM. Drop the SMB SESSION first - this matters, and
deleting mappings or purging tickets is NOT enough:
    net use * /delete /y
    net use \\$saName.file.core.windows.net\labshare /delete /y
    klist purge
    Get-SmbConnection    <- must show NO entry for $saName before you retest
    net use Z: \\$saName.file.core.windows.net\labshare

If the mount 'succeeds' but klist shows ZERO tickets, you reused the old
session - no authentication happened at all. Sign out/in (or, elevated,
Restart-Service LanmanWorkstation -Force) and retest.

Expect: System error 1396. Then prove where it broke:
    klist                         <- an AES-256 ticket IS issued
    (on the DC) Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 3
"@ -ForegroundColor Cyan
    }

    'Repair' {
        Write-Host 'Step 1/3 - correcting ActiveDirectoryDomainName to the DNS root...' -ForegroundColor Yellow
        $dnsRoot = (Invoke-OnDc 'Import-Module ActiveDirectory; (Get-ADDomain).DNSRoot').Trim()
        Write-Host "  DNS root: $dnsRoot  (was: $($adProps.DomainName))"
        Set-AdProperties -DomainNameValue $dnsRoot

        $check = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName).AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
        if ($check.DomainName -ne $dnsRoot) {
            throw 'DomainName did not change - Set-AzStorageAccount needs the FULL parameter set.'
        }
        Write-Host "  confirmed: DomainName = $($check.DomainName)" -ForegroundColor Green

        Write-Host 'Step 2/3 + 3/3 - regenerating the kerb key (new salt) and resyncing AD...' -ForegroundColor Yellow
        Sync-KerbKeyToAd

        Write-Host @"

Retest on the CLIENT VM:
    net use * /delete /y
    klist purge
    net use Z: \\$saName.file.core.windows.net\labshare
    klist          <- KerbTicket Encryption Type should now be AES-256

Why this order: the salt is consumed when the key is generated. Fixing the
property alone changes nothing until the key is regenerated and pushed to AD.
"@ -ForegroundColor Cyan
    }

    'Rollback' {
        Write-Host 'Restoring the legacy RC4 + NetBIOS-DomainName state...' -ForegroundColor Yellow
        Set-AdProperties -DomainNameValue $adProps.NetBiosDomainName
        Invoke-OnDc @"
Import-Module ActiveDirectory
`$pdc = (Get-ADDomain).PDCEmulator
Set-ADComputer -Identity '$saName' -Server `$pdc -KerberosEncryptionType RC4
Write-Output 'AD object back to RC4'
"@ | Write-Host
        Sync-KerbKeyToAd
        Write-Host 'Legacy state restored - the lab can be run again.' -ForegroundColor Green
    }
}
