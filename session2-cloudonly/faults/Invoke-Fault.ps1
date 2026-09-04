<#
.SYNOPSIS
  Session 2 (cloud-only) fault injection - the service-side faults.

.DESCRIPTION
  Most of this session's faults live on the client and are injected there with
  C:\LabTools\Invoke-LabFault.ps1 (no Azure access needed). Only the faults that
  change something in Azure or Entra come through here.

  ConsentRevoked  Removes the OAuth2 permission grants from the storage
                  account's service principal - the app Entra Kerberos issues
                  tickets through.
                  Symptom : the device, the PRT and the cloud TGT are all
                            healthy; only the cifs/<sa> request fails. The
                            evidence chain breaks at step 4 and nowhere else,
                            which is what tells you it is service-side.
                  Diagnose: Fiddler -> the request to login.microsoftonline.com
                            -> Kerberos tab -> response ErrorCode. Confirm in
                            Entra ID > Enterprise applications >
                            [Storage Account] <sa>... > Permissions.
                  This is the capstone fault. Inject it for someone else, or
                  have a partner inject it for you - and do not read the code
                  first if you are the one diagnosing.

  NoShareAccess   Removes labuser1's share-level RBAC assignment.
                  Symptom : Kerberos is perfect, the mount is refused. Proves
                            authentication and authorization are separate.
                  Used by Lab D as the "share RBAC" door.

.EXAMPLE
  # Azure Cloud Shell (PowerShell) - already signed in
  ./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked
  ./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked -Repair
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [ValidateSet('ConsentRevoked', 'NoShareAccess')]
    [string]$Fault,
    [switch]$Repair,
    [string]$Prefix = 'azfcloud',
    [string]$User   = 'labuser1'
)
$ErrorActionPreference = 'Stop'

# Cloud Shell signs you in to Azure but NOT to Graph - separate token audiences -
# and a bare Connect-MgGraph falls back to a device code with a 120-second
# timeout. In the middle of a capstone that is a session-ruining detour.
$helper = Join-Path (Split-Path $PSScriptRoot -Parent) '../session2-entra-kerberos/scripts/Connect-LabGraph.ps1'
if (-not (Test-Path $helper)) {
    $helper = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'session2-entra-kerberos/scripts/Connect-LabGraph.ps1'
}
if (-not (Test-Path $helper)) { throw 'Missing Connect-LabGraph.ps1 - run from a full clone of the repo.' }
. $helper

$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
    Where-Object StorageAccountName -like "$Prefix*" | Select-Object -First 1
if (-not $sa) { throw "No $Prefix* storage account in $ResourceGroupName" }
$saName = $sa.StorageAccountName

$mode = if ($Repair) { 'REPAIR' } else { 'INJECT' }
Write-Host "[$mode] $Fault  (storage: $saName)" -ForegroundColor Yellow

# Every command is echoed before it runs, so attendees can see exactly what the
# fault does - and could do it by hand on a real case.
function Show-Cmd([string]$Command) {
    Write-Host ''
    Write-Host '  .-- commands' -ForegroundColor DarkCyan
    $Command.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  | $_" -ForegroundColor Gray }
    Write-Host "  '--" -ForegroundColor DarkCyan
}

switch ($Fault) {

    'ConsentRevoked' {
        Connect-LabGraph -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All'
        $spn = Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $saName.file.core.windows.net'"
        if (-not $spn) { throw "Storage app for $saName not found." }

        if (-not $Repair) {
            Show-Cmd @"
Get-MgOauth2PermissionGrant -Filter "clientId eq '$($spn.Id)'" |
    ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId `$_.Id }
"@
            Get-MgOauth2PermissionGrant -Filter "clientId eq '$($spn.Id)'" -ErrorAction SilentlyContinue |
                ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
            Write-Host ''
            Write-Host 'Consent removed. On the client:' -ForegroundColor Yellow
            Write-Host '  net use * /delete /y ; klist purge'
            Write-Host '  klist get cifs/<sa>.file.core.windows.net'
            Write-Host ''
            Write-Host 'Steps 1-3 of the chain stay healthy. Only step 4 breaks - that is the tell.'
        } else {
            $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
            Show-Cmd @"
New-MgOauth2PermissionGrant -BodyParameter @{
    clientId = '$($spn.Id)'; consentType = 'AllPrincipals'
    resourceId = '$($graphSp.Id)'; scope = 'openid profile User.Read' }
"@
            Get-MgOauth2PermissionGrant -Filter "clientId eq '$($spn.Id)'" -ErrorAction SilentlyContinue |
                ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
            New-MgOauth2PermissionGrant -BodyParameter @{
                clientId = $spn.Id; consentType = 'AllPrincipals'
                resourceId = $graphSp.Id; scope = 'openid profile User.Read'
            } | Out-Null
            Write-Host 'Consent restored. klist purge on the client, then retry.'
        }
    }

    'NoShareAccess' {
        Connect-LabGraph -Scopes 'User.ReadWrite.All'
        $org = Get-MgOrganization | Select-Object -First 1
        $upn = "$User@$((($org.VerifiedDomains | Where-Object IsInitial).Name))"
        $flt = [uri]::EscapeDataString("userPrincipalName eq '$upn'")
        $u = (Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$flt&`$select=id").value | Select-Object -First 1
        if (-not $u) { throw "User $upn not found." }
        $role = 'Storage File Data SMB Share Contributor'

        if (-not $Repair) {
            Show-Cmd "Remove-AzRoleAssignment -ObjectId $($u.id) -RoleDefinitionName '$role' -Scope $($sa.Id)"
            Remove-AzRoleAssignment -ObjectId $u.id -RoleDefinitionName $role -Scope $sa.Id -ErrorAction SilentlyContinue
            Write-Host ''
            Write-Host "$upn no longer has share-level access." -ForegroundColor Yellow
            Write-Host 'Kerberos stays perfect; the MOUNT is refused. That contrast is the lesson.'
            Write-Host 'RBAC removal can take a few minutes to take effect.'
        } else {
            Show-Cmd "New-AzRoleAssignment -ObjectId $($u.id) -RoleDefinitionName '$role' -Scope $($sa.Id)"
            if (-not (Get-AzRoleAssignment -ObjectId $u.id -Scope $sa.Id -RoleDefinitionName $role -ErrorAction SilentlyContinue)) {
                New-AzRoleAssignment -ObjectId $u.id -RoleDefinitionName $role -Scope $sa.Id | Out-Null
            }
            Write-Host 'Share access restored (allow a few minutes for propagation).'
        }
    }
}
