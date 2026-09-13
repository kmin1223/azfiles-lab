<#
.SYNOPSIS
  Session 2 (cloud-only) fault injection - the service-side faults.

.DESCRIPTION
  Most of this session's faults live on the client and are injected there with
  C:\LabTools\Invoke-LabFault.ps1 (no Azure access needed). Only the faults that
  change something in Azure or Entra come through here.

  ConsentRevoked  Guided participant consent/Fiddler lab on each participant's
                  OWN disposable storage account. Never share credentials or
                  accounts, or inject into another participant's environment.
                  Requires exactly one prefix-matched storage account in the
                  selected resource group/subscription, one storage service
                  principal and one Microsoft Graph service principal.
                  Revokes/restores ONLY the Graph AllPrincipals baseline with
                  exactly openid/profile/User.Read; preserves non-Graph grants.
                  Unexpected/user-specific/ambiguous Graph consent is rejected.
                  Scope   : ALL shares/new requests for that storage account.
                  Symptom : fresh CIFS service-ticket acquisition MAY fail.
                            Existing tickets/SMB sessions may survive; consent
                            changes do not clear the PRT or cloud TGT.
                  Diagnose: Fiddler -> the request to login.microsoftonline.com
                            -> Kerberos tab -> response ErrorCode. Confirm in
                            Entra ID > Enterprise applications >
                            [Storage Account] <sa>... > Permissions.
                  Repair  : -Repair restores only an absent baseline. Directory
                            readback is verified; propagation is not guaranteed
                            and live failure/recovery remains unverified until
                            the actual lab user tests fresh CIFS and SMB access.
                  Prereqs : healthy access first; your own Azure/Graph context
                            in the same lab tenant with consent-write authority.
                            Inspect Get-AzContext and Get-MgContext before use.
                            Stop if ownership, permissions or baseline is unclear.

  NoShareAccess   Removes labuser1's share-level RBAC assignment.
                  Symptom : Kerberos is perfect, the mount is refused. Proves
                            authentication and authorization are separate.
                  Used by Lab D as the "share RBAC" door.

.EXAMPLE
  # Same Azure login, tenant, subscription and resource group as deployment.
  .\session2-cloudonly\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked
  .\session2-cloudonly\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked -Repair

.PARAMETER Prefix
  Optional. Uses the same Azure-context-derived prefix as deploy.ps1 when omitted.
  Cloud Shell ManagedService contexts also require the same /home/<name> in pwd.
  Run from that home directory or any folder beneath it.
  For an existing lab with an explicit or old default prefix, supply that value
  (for example -Prefix azfcloud). Never falls back to another participant's account.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [ValidateSet('ConsentRevoked', 'NoShareAccess')]
    [string]$Fault,
    [switch]$Repair,
    [ValidatePattern('^[a-z0-9]{1,24}$')]
    [string]$Prefix,
    [string]$User   = 'labuser1'
)
$ErrorActionPreference = 'Stop'

# Cloud Shell signs you in to Azure but NOT to Graph - separate token audiences -
# and a bare Connect-MgGraph falls back to a device code with a 120-second
# timeout. Reuse the existing sign-in helper, not its first-match storage lookup.
$helper = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'session2-entra-kerberos\scripts\Connect-LabGraph.ps1'
if (-not (Test-Path $helper)) { throw 'Missing Connect-LabGraph.ps1 - run from a full clone of the repo.' }
. $helper

. (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts') 'CloudOnlyLabNaming.ps1')
$azContext = Get-AzContext -ErrorAction Stop
if (-not $azContext) { throw 'No Azure context. Sign in to the intended lab subscription before running a fault.' }
$namingParameters = @{ ResourceGroupName = $ResourceGroupName; AzureContext = $azContext }
if ($PSBoundParameters.ContainsKey('Prefix')) { $namingParameters.Prefix = $Prefix }
$Prefix = Resolve-CloudOnlyLabPrefix @namingParameters
Write-Host "Cloud-only resource prefix: $Prefix"

function Get-ConsentLabStorageAccount([string]$ResourceGroupName, [string]$Prefix) {
    if ($Prefix -cnotmatch '^[a-z0-9]{1,24}$') {
        throw 'CONSENT_TARGET_INVALID: Use the literal lowercase alphanumeric participant prefix, not a wildcard.'
    }
    $accounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.StorageAccountName.StartsWith($Prefix, [StringComparison]::Ordinal) })
    if ($accounts.Count -ne 1) {
        throw "CONSENT_TARGET_AMBIGUOUS: Expected exactly one '$Prefix*' storage account in '$ResourceGroupName'; found $($accounts.Count). Use the same Azure login/tenant/subscription/resource group as deployment, or pass the recorded -Prefix (azfcloud for the old default). Nothing was changed."
    }
    $accounts[0]
}

$sa = Get-ConsentLabStorageAccount -ResourceGroupName $ResourceGroupName -Prefix $Prefix
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

# Same bounded-baseline checks as the hybrid ConsentRevoked lab. Keep this path
# isolated so participant safety does not depend on executing the hybrid script.
function Assert-ConsentGuid([string]$Value, [string]$Label) {
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Value, [ref]$parsed) -or $parsed -eq [guid]::Empty) {
        throw "CONSENT_ID_INVALID: $Label must be a nonzero GUID. Inspect the storage app and Microsoft Graph service principals before retrying."
    }
}

function Get-LabGraphConsent([string]$ClientId, [string]$GraphId) {
    $grants = @(Get-MgOauth2PermissionGrant -Filter "clientId eq '$ClientId'" -All -ErrorAction Stop)
    foreach ($grant in $grants) {
        Assert-ConsentGuid -Value $grant.ClientId -Label 'Grant clientId'
        Assert-ConsentGuid -Value $grant.ResourceId -Label 'Grant resourceId'
        if ([guid]$grant.ClientId -ne [guid]$ClientId) {
            throw 'CONSENT_STATE_UNEXPECTED: Grant listing returned a different client. Inspect permissions before retrying; no automatic cleanup is safe.'
        }
    }
    $graphGrants = @($grants | Where-Object { [guid]$_.ResourceId -eq [guid]$GraphId })
    if ($graphGrants.Count -eq 0) { return }
    if ($graphGrants.Count -ne 1) {
        throw 'CONSENT_STATE_UNEXPECTED: Expected one Graph AllPrincipals baseline grant or none. Multiple/user-specific Graph grants can mask the fault. Inspect the storage app Permissions; do not delete unrelated consent.'
    }
    $grant = $graphGrants[0]
    $scopes = @(([string]$grant.Scope).Trim() -split '\s+' | Sort-Object -Unique -CaseSensitive)
    if ($grant.ConsentType -cne 'AllPrincipals' -or
        -not [string]::IsNullOrEmpty([string]$grant.PrincipalId) -or
        [string]::IsNullOrWhiteSpace([string]$grant.Id) -or
        $scopes.Count -ne 3 -or
        $scopes -cnotcontains 'openid' -or $scopes -cnotcontains 'profile' -or
        $scopes -cnotcontains 'User.Read') {
        throw 'CONSENT_STATE_UNEXPECTED: Graph consent must be a single AllPrincipals grant with exactly openid/profile/User.Read and no user-specific principal. Inspect Permissions and use a disposable baseline lab account; unexpected consent will not be overwritten.'
    }
    $grant
}

function Invoke-LabConsentFault([string]$StorageAccountName, [switch]$Repair) {
    Write-Warning "ConsentRevoked affects ALL shares/new requests for storage account '$StorageAccountName'. Use only your OWN disposable participant account; never share credentials/accounts or inject for a partner. Existing tickets/SMB sessions may survive. This does not clear or revoke the PRT or cloud TGT."
    Write-Host 'On your Windows client, use the actual cloud-only lab user logon session (whoami /upn), NOT Cloud Shell, SYSTEM, Run Command or a different administrator logon.'
    Write-Host 'Close files/apps using this lab account. Run net use to inspect connections; delete ONLY each lab UNC connection or its mapped drive, never unrelated mappings.'
    Write-Host "For labshare only: net use \\$StorageAccountName.file.core.windows.net\labshare /delete /y"
    Write-Host 'If other shares on this lab account are connected, close those exact connections too; do not use a wildcard delete.'
    Write-Host "Then, in that same lab user session: klist purge; klist get cifs/$StorageAccountName.file.core.windows.net"
    Write-Host 'klist purge clears cached Kerberos tickets in that logon session (including unrelated tickets); use a dedicated lab session. Capture the fresh request with Fiddler, then test the lab share. Do not share credentials or raw authentication captures.'
    Write-Host 'Directory readback does not prove live CIFS service-ticket acquisition or SMB access. Propagation is not guaranteed; live failure/recovery remains unverified until tested by the actual lab user.'
    Connect-LabGraph -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All'
    $escapedName = $StorageAccountName.Replace("'", "''")
    $storageSps = @(Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $escapedName.file.core.windows.net'" -All -ErrorAction Stop)
    $graphSps = @(Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -All -ErrorAction Stop)
    if ($storageSps.Count -ne 1 -or $graphSps.Count -ne 1) {
        throw 'CONSENT_SP_AMBIGUOUS: Expected exactly one storage account service principal and one Microsoft Graph service principal. Inspect Enterprise applications and resolve missing/duplicate identities before retrying.'
    }
    $clientId = [string]$storageSps[0].Id
    $graphId = [string]$graphSps[0].Id
    Assert-ConsentGuid -Value $clientId -Label 'Storage service principal Id'
    Assert-ConsentGuid -Value $graphId -Label 'Microsoft Graph service principal Id'
    if ([guid]$clientId -eq [guid]$graphId) {
        throw 'CONSENT_SP_AMBIGUOUS: Storage and Microsoft Graph service principals must be distinct. Inspect Enterprise applications before retrying.'
    }
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
        Show-Cmd "Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId '$($baseline.Id)' -ErrorAction Stop"
        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $baseline.Id -ErrorAction Stop
    } else {
        Show-Cmd @"
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

switch ($Fault) {

    'ConsentRevoked' {
        Invoke-LabConsentFault -StorageAccountName $saName -Repair:$Repair
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
