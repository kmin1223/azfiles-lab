<#
.SYNOPSIS
  Session 2 fault injection - the classic Entra Kerberos failures.

.DESCRIPTION
  Faults (all reversible with -Repair):

  NoCloudTgt        CloudKerberosTicketRetrievalEnabled = 0 on the client.
                    Symptom : klist cloud_debug shows no cloud TGT; mount
                              fails (often System error 1327)
                    Diagnose: klist cloud_debug ; reg query ...\Kerberos\Parameters
                    Repair  : set back to 1 (+ re-logon)

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

  Discussion-only (cannot be scripted safely, cover on slides):
  - Conditional Access requiring MFA on the storage app -> interactive-MFA
    cannot happen over SMB; exclude the app from the CA policy.

.EXAMPLE
  .\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
  .\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt -Repair
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [ValidateSet('NoCloudTgt', 'ConsentRevoked', 'NotHybridJoined', 'NoShareAccess')]
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
        $val = if ($Repair) { 1 } else { 0 }
        Invoke-OnVm $cliName @"
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' ``
  -Name CloudKerberosTicketRetrievalEnabled -Value $val -Type DWord
Write-Output "CloudKerberosTicketRetrievalEnabled = $val"
"@ | Write-Host
        Write-Host 'Client: sign out/in (policy applies at logon), then klist cloud_debug.'
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
