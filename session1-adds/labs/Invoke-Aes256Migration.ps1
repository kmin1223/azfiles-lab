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
  retesting - a mapped share keeps working even after the keys change:
      net use * /delete /y
      klist purge
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

function Invoke-OnDc([string]$Script) {
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
    New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -KeyName kerb1 | Out-Null
    Start-Sleep -Seconds 15   # let the new key value settle before reading it
    $kerb = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName -ListKerbKey |
        Where-Object KeyName -eq 'kerb1').Value
    Invoke-OnDc @"
Import-Module ActiveDirectory
`$pdc = (Get-ADDomain).PDCEmulator
`$comp = Get-ADComputer -Identity '$saName' -Server `$pdc
Set-ADAccountPassword -Identity `$comp.DistinguishedName -Server `$pdc -Reset ``
  -NewPassword (ConvertTo-SecureString '$($kerb.Replace("'","''"))' -AsPlainText -Force)
repadmin /syncall `$pdc /AdeP 2>&1 | Out-Null
Write-Output "AD password re-synced to the new kerb1 key on `$pdc"
"@ | Write-Host
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

Now retest on the CLIENT VM (drop sessions first - this matters):
    net use * /delete /y
    klist purge
    net use Z: \\$saName.file.core.windows.net\labshare

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
