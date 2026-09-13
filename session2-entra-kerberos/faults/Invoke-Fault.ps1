<#
.SYNOPSIS
  Session 2 fault injection - the classic Entra Kerberos failures.

.DESCRIPTION
  Faults (all reversible with -Repair):

  NoCloudTgt        Disables cloud TGT retrieval - via the POLICY registry
                    path, not the LSA path. Windows reads
                    Policies\System\Kerberos\Parameters (Intune CSP) FIRST and
                    only falls back to Lsa\Kerberos\Parameters, so the LSA
                    value still reads 1 and looks perfectly healthy.
                    Symptom : after sign out/in, no cloud TGT; mount fails
                    Diagnose: klist cloud_debug -> "Cloud Kerberos ticket
                              retrieval enabled by policy: false" is the
                              EFFECTIVE value; then reg query BOTH paths to
                              find which one wins. The LSA path alone will
                              mislead you - that is the point of this fault.
                    Teach   : Intune-managed fleets hit exactly this - local
                              reg fixes "don't work" because policy wins
                    Repair  : remove the policy-path value (+ re-logon)

  ConsentRevoked    Remove only the Microsoft Graph AllPrincipals grant with
                    exactly openid/profile/User.Read from the storage app.
                    Refuses ambiguous or non-baseline Graph consent.
                    Scope   : ALL shares/new requests for this storage account,
                              including labshare and rbac-lab; not just one share.
                    Symptom : fresh CIFS service-ticket acquisition may fail.
                              Existing tickets/SMB sessions may survive; this
                              does not clear the PRT or cloud TGT.
                    Diagnose: Entra portal -> App registrations ->
                              [Storage Account] <sa>... -> API permissions
                    Repair  : re-grant only that baseline when Graph consent
                              is absent; verify directory readback, then test
                              a fresh CIFS ticket (not a propagation guarantee).

  NotHybridJoined   dsregcmd /leave on the client (device drops out of Entra).
                    Symptom : dsregcmd /status AzureAdJoined: NO; no PRT ->
                              no cloud TGT -> mount fails
                    Repair  : re-join + reboot (takes a few minutes to register)

  NoShareAccess     DefaultSharePermission = None.
                    Explicit/inherited RBAC remains effective; this fault does
                    not deny a user granted access by setup -ShareUserPrincipalName.
                    Symptom : Kerberos succeeds but share access denied ->
                              proves auth vs authorization are separate layers
                    Repair  : restore StorageFileDataSmbShareContributor

  ProxyMangled      Points WinHTTP at a dead proxy (127.0.0.1:8888) - the
                    classic residue Fiddler leaves behind when it exits
                    uncleanly. Entra Kerberos runs over HTTPS (KDC Proxy), so
                    the machine proxy stack is now part of the auth path.
                    Symptom : klist get cifs/... fails with
                              LsaCallAuthenticationPackage 0x51f /
                              0xc000005e; on-prem AD DS auth (port 88/445)
                              would still work - only the cloud path breaks
                    Diagnose: netsh winhttp show proxy   <- 30-second check
                    Teach   : the diagnostic tool ITSELF caused the outage;
                              always check the proxy stack when only Entra
                              Kerberos fails on one machine
                    Repair  : netsh winhttp reset proxy + reset autoproxy
                              (+ clear iphlpsvc ProxyMgr 8888 entries)

  Discussion-only (cannot be scripted safely, cover on slides):
  - Conditional Access requiring MFA on the storage app -> System error 1327
    (or 86); interactive MFA cannot happen over SMB. Fix: exclude the
    '[Storage Account] <sa>.file.core.windows.net' app from the CA policy.
    Public doc: storage-files-identity-auth-hybrid-identities-enable.

.EXAMPLE
  .\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
  .\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt -Repair
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [ValidateSet('NoCloudTgt', 'ConsentRevoked', 'NotHybridJoined', 'NoShareAccess', 'ProxyMangled')]
    [string]$Fault,
    [switch]$Repair,
    [string]$Prefix = 'azflab'
)
$ErrorActionPreference = 'Stop'

# Shared with setup.ps1: Cloud-Shell-friendly Graph sign-in (no device code) and
# storage-account lookup that ignores Test-Coexistence's second account.
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/Connect-LabGraph.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/LabGraphConsent.ps1')

$sa = Get-LabStorageAccount -ResourceGroupName $ResourceGroupName -Prefix $Prefix
if (-not $sa) { throw "No $Prefix* storage account in $ResourceGroupName" }
$saName = $sa.StorageAccountName
$cliName = "$Prefix-cli"

# Every command is echoed BEFORE it runs, so attendees can see exactly what the
# fault does (and could do it by hand).
function Show-Cmd([string]$Where, [string]$Command) {
    Write-Host ''
    Write-Host "  .-- commands ($Where) " -ForegroundColor DarkCyan
    $Command.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  | $_" -ForegroundColor Gray }
    Write-Host "  '--" -ForegroundColor DarkCyan
}

function Invoke-OnVm([string]$Vm, [string]$Script) {
    Show-Cmd -Where "runs on $Vm" -Command $Script
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $Script
    try {
        $r = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $Vm `
            -CommandId 'RunPowerShellScript' -ScriptPath $tmp
        ($r.Value | Where-Object Code -like '*StdOut*').Message
    } finally { Remove-Item $tmp -Force }
}

function Invoke-LabConsentFault([string]$StorageAccountName, [switch]$Repair) {
    Write-Warning "ConsentRevoked affects ALL shares/new requests for storage account '$StorageAccountName' (including labshare and rbac-lab), not just the RBAC demo share. Use only a disposable lab account. Existing tickets/SMB sessions may survive. This does not clear or revoke the PRT or cloud TGT."
    Write-Host "Fresh-ticket validation (lab user, after closing the lab SMB connections): klist purge; klist get cifs/$StorageAccountName.file.core.windows.net"
    Write-Host 'klist purge affects cached Kerberos tickets in that logon session; consent changes alone do not purge tickets. Directory readback does not prove live CIFS service-ticket acquisition or SMB access, and propagation may lag.'
    Connect-LabGraph -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All'
    $principals = Get-LabConsentPrincipals -StorageAccountName $StorageAccountName
    $clientId = $principals.ClientId
    $graphId = $principals.GraphId
    $baseline = Get-LabGraphConsent -ClientId $clientId -GraphId $graphId
    if (-not $Repair -and -not $baseline) {
        Write-Host 'Graph consent already missing on directory read; nothing removed. This is not evidence of a live ticket or mount failure.'
        return
    }
    if ($Repair -and $baseline) {
        Write-Host 'Exact baseline Graph consent already present on directory read; nothing changed. Validate fresh CIFS service-ticket acquisition separately.'
        return
    }
    if (-not $Repair) {
        Show-Cmd -Where 'runs here, against Microsoft Graph (validated baseline only)' -Command `
            "Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId '$($baseline.Id)' -ErrorAction Stop"
        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $baseline.Id -ErrorAction Stop
    } else {
        Show-Cmd -Where 'runs here, against Microsoft Graph (absent baseline only)' -Command @"
New-MgOauth2PermissionGrant -BodyParameter @{
    clientId    = '$clientId'
    consentType = 'AllPrincipals'
    resourceId  = '$graphId'
    scope       = 'openid profile User.Read'
} -ErrorAction Stop
"@
        New-MgOauth2PermissionGrant -BodyParameter @{
            clientId = $clientId
            consentType = 'AllPrincipals'
            resourceId = $graphId
            scope = 'openid profile User.Read'
        } -ErrorAction Stop | Out-Null
    }
    try {
        $readback = Get-LabGraphConsent -ClientId $clientId -GraphId $graphId
        if (($Repair -and -not $readback) -or (-not $Repair -and $readback)) {
            throw 'The requested consent state is not yet visible.'
        }
    } catch {
        throw "CONSENT_READBACK_UNCONFIRMED: The mutation request completed, but directory readback did not confirm it. Propagation may lag or consent may have changed concurrently. Inspect Permissions and re-read before retrying; no automatic rollback or extra mutation was attempted. $($_.Exception.Message)"
    }
    if ($Repair) {
        Write-Host 'Directory readback confirms the exact baseline Graph consent (openid profile User.Read). Live ticket acquisition/recovery is not yet verified.'
    } else {
        Write-Host 'Directory readback confirms Graph consent is absent. Fresh CIFS service-ticket acquisition may fail; existing tickets/sessions may survive. Live failure is not yet verified.'
    }
    Write-Host 'Diagnose in portal: Entra ID -> Enterprise applications -> [Storage Account]... -> Permissions.'
}

$mode = if ($Repair) { 'REPAIR' } else { 'INJECT' }
Write-Host "[$mode] $Fault" -ForegroundColor Yellow

switch ($Fault) {

    'NoCloudTgt' {
        if (-not $Repair) {
            # Inject at the POLICY path (what an Intune CSP writes). Windows
            # checks this path BEFORE Lsa\Kerberos\Parameters, so the LSA value
            # stays 1 and looks healthy while the effective value is 0.
            Invoke-OnVm $cliName @'
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
  -Name CloudKerberosTicketRetrievalEnabled -Value 0 -Type DWord
# Make sure the LSA path still says 1 - the misleading part is deliberate.
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
  -Name CloudKerberosTicketRetrievalEnabled -Value 1 -Type DWord
Write-Output 'Policy path now DISABLES cloud TGT retrieval; LSA path still says 1.'
'@ | Write-Host
            Write-Host ''
            Write-Host 'Client: sign out/in (applies at logon). Diagnosis path:'
            Write-Host '  1. reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled   <- says 1. Healthy?'
            Write-Host '  2. klist cloud_debug     <- the EFFECTIVE value says disabled. Contradiction!'
            Write-Host '  3. reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled'
            Write-Host '     Policy path wins over the LSA path - this is how Intune-managed devices behave.'
        } else {
            Invoke-OnVm $cliName @'
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
  -Name CloudKerberosTicketRetrievalEnabled -ErrorAction SilentlyContinue
Write-Output 'Policy-path override removed; the LSA value (1) is effective again.'
'@ | Write-Host
            Write-Host 'Client: sign out/in, then klist cloud_debug to confirm.'
        }
    }

    'ProxyMangled' {
        if (-not $Repair) {
            # The exact residue Fiddler leaves when it dies without cleanup:
            # a WinHTTP proxy pointing at 127.0.0.1:8888 that nothing listens on.
            Invoke-OnVm $cliName @'
netsh winhttp set proxy proxy-server="127.0.0.1:8888" bypass-list="" | Out-Null
Write-Output "WinHTTP proxy now points at 127.0.0.1:8888 (nothing is listening there)"
'@ | Write-Host
            Write-Host ''
            Write-Host 'Client (as the lab user): klist purge; klist get cifs/<sa>.file.core.windows.net'
            Write-Host '  -> Error calling API LsaCallAuthenticationPackage ... 0x51f / klist failed with 0xc000005e'
            Write-Host ''
            Write-Host 'Why: Entra Kerberos is KDC Proxy over HTTPS - the machine proxy stack sits in the'
            Write-Host 'auth path. AD DS Kerberos (UDP/TCP 88) would be unaffected; ONLY the cloud path dies.'
            Write-Host 'Diagnose in 30 seconds:  netsh winhttp show proxy'
        } else {
            Invoke-OnVm $cliName @'
netsh winhttp reset proxy | Out-Null
netsh winhttp reset autoproxy 2>$null | Out-Null
# Clear Fiddler leftovers under iphlpsvc ProxyMgr as per the Fiddler TSG
$pm = 'HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ProxyMgr'
if (Test-Path $pm) {
    Get-ChildItem $pm | ForEach-Object {
        if ((Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue) -match '8888') {
            Remove-Item $_.PSPath -Recurse -Force
        }
    }
}
Write-Output 'WinHTTP proxy reset (direct access restored)'
'@ | Write-Host
            Write-Host 'Client: klist purge, then retry klist get / the mount.'
        }
    }

    'ConsentRevoked' {
        Invoke-LabConsentFault -StorageAccountName $saName -Repair:$Repair
    }

    'NotHybridJoined' {
        if (-not $Repair) {
            Invoke-OnVm $cliName @'
dsregcmd /leave 2>&1 | Select-Object -Last 3
Write-Output 'Device left Entra. dsregcmd /status -> AzureAdJoined: NO'
'@ | Write-Host
            Write-Host 'Client: sign out/in, dsregcmd /status, klist cloud_debug -> no PRT, no cloud TGT.'
        } else {
            Invoke-OnVm $cliName @'
Get-ScheduledTask -TaskName 'Automatic-Device-Join' -TaskPath '\Microsoft\Windows\Workplace Join\' |
    Start-ScheduledTask
dsregcmd /join /debug 2>&1 | Select-Object -Last 3
shutdown /r /t 10 /f
Write-Output 'Re-join triggered, rebooting. Registration may take a few minutes.'
'@ | Write-Host
        }
    }

    'NoShareAccess' {
        Write-Warning 'NoShareAccess changes only default share permission, not explicit/inherited RBAC. A user granted share RBAC by setup may retain access. Repair enables a broad default permission; it does not restore user-specific RBAC.'
        $perm = if ($Repair) { 'StorageFileDataSmbShareContributor' } else { 'None' }
        Show-Cmd -Where 'runs here, against Azure' -Command `
            "Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName -DefaultSharePermission '$perm'"
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
            -DefaultSharePermission $perm | Out-Null
        Write-Host "DefaultSharePermission = $perm"
    }
}
Write-Host "[$mode] done." -ForegroundColor Green
