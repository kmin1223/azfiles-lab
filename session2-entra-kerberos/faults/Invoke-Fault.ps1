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

  ConsentRevoked    Remove the OAuth2 permission grants from the storage
                    account's service principal.
                    Symptom : Entra won't issue the TGT for the SA; mount fails
                    Diagnose: Entra portal -> App registrations ->
                              [Storage Account] <sa>... -> API permissions
                    Repair  : re-grant openid/profile/User.Read

  NotHybridJoined   dsregcmd /leave on the client (device drops out of Entra).
                    Symptom : dsregcmd /status AzureAdJoined: NO; no PRT ->
                              no cloud TGT -> mount fails
                    Repair  : re-join + reboot (takes a few minutes to register)

  NoShareAccess     DefaultSharePermission = None.
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

$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
    Where-Object StorageAccountName -like "$Prefix*" | Select-Object -First 1
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
        Connect-MgGraph -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All' -NoWelcome
        $spn = Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $saName.file.core.windows.net'"
        if (-not $spn) { throw 'Storage account service principal not found.' }
        if (-not $Repair) {
            Show-Cmd -Where 'runs here, against Microsoft Graph' -Command @"
Get-MgOauth2PermissionGrant -Filter "clientId eq '$($spn.Id)'" |
    ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId `$_.Id }
"@
            Get-MgOauth2PermissionGrant -Filter "clientId eq '$($spn.Id)'" |
                ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
            Write-Host 'OAuth2 grants removed. New sessions: TGT issuance for the SA fails.'
            Write-Host 'Diagnose in portal: Entra ID -> Enterprise applications -> [Storage Account]... -> Permissions.'
        } else {
            $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
            Show-Cmd -Where 'runs here, against Microsoft Graph' -Command @"
New-MgOauth2PermissionGrant -BodyParameter @{
    clientId    = '$($spn.Id)'          # the storage account's service principal
    consentType = 'AllPrincipals'
    resourceId  = '$($graphSp.Id)'      # Microsoft Graph
    scope       = 'openid profile User.Read'
}
"@
            New-MgOauth2PermissionGrant -BodyParameter @{
                clientId    = $spn.Id
                consentType = 'AllPrincipals'
                resourceId  = $graphSp.Id
                scope       = 'openid profile User.Read'
            } | Out-Null
            Write-Host 'Consent restored (openid profile User.Read).'
        }
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
        $perm = if ($Repair) { 'StorageFileDataSmbShareContributor' } else { 'None' }
        Show-Cmd -Where 'runs here, against Azure' -Command `
            "Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName -DefaultSharePermission '$perm'"
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName `
            -DefaultSharePermission $perm | Out-Null
        Write-Host "DefaultSharePermission = $perm"
    }
}
Write-Host "[$mode] done." -ForegroundColor Green
