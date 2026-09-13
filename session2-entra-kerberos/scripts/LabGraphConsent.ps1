# Shared baseline validation for setup and the consent fault.
. (Join-Path $PSScriptRoot 'LabAppPermissions.ps1')
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
    $scopes = @(([string]$grant.Scope).Trim() -split '\s+' | Sort-Object -Unique)
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

function Get-LabConsentPrincipals {
    param([string]$StorageAccountName, [switch]$RetryMissingStoragePrincipal)
    $escapedName = $StorageAccountName.Replace("'", "''")
    $storageSps = @(Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $escapedName.file.core.windows.net'" -Property @('id', 'appId') -All -ErrorAction Stop)
    if ($RetryMissingStoragePrincipal -and $storageSps.Count -eq 0) {
        Start-Sleep -Seconds 30
        $storageSps = @(Get-MgServicePrincipal -Filter "displayName eq '[Storage Account] $escapedName.file.core.windows.net'" -Property @('id', 'appId') -All -ErrorAction Stop)
    }
    $graphSps = @(Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property @('id', 'appId', 'oauth2PermissionScopes') -All -ErrorAction Stop)
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
    [pscustomobject]@{
        ClientId = $clientId; GraphId = $graphId
        StorageAppId = [string]$storageSps[0].AppId
        GraphServicePrincipal = $graphSps[0]
    }
}

function Initialize-LabGraphConsent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('\A[a-z0-9]{3,24}\z', Options = 'None')]
        [string]$StorageAccountName
    )
    $principals = Get-LabConsentPrincipals -StorageAccountName $StorageAccountName -RetryMissingStoragePrincipal
    $baseline = Get-LabGraphConsent -ClientId $principals.ClientId -GraphId $principals.GraphId
    Initialize-LabAppPermissions -Principals $principals
    if ($baseline) {
        Write-Host 'Admin consent baseline already present on directory read: openid profile User.Read. No grant changed.'
        return
    }
    New-MgOauth2PermissionGrant -BodyParameter @{
        clientId = $principals.ClientId
        consentType = 'AllPrincipals'
        resourceId = $principals.GraphId
        scope = 'openid profile User.Read'
    } -ErrorAction Stop | Out-Null
    try {
        $readback = Get-LabGraphConsent -ClientId $principals.ClientId -GraphId $principals.GraphId
        if (-not $readback) { throw 'The requested baseline is not yet visible.' }
    } catch {
        throw "CONSENT_READBACK_UNCONFIRMED: Grant creation returned, but directory readback did not confirm the baseline. Inspect Permissions before retrying; no rollback or extra mutation was attempted. $($_.Exception.Message)"
    }
    Write-Host 'Admin consent baseline created and confirmed on directory read: openid profile User.Read. Fresh CIFS ticket and SMB access checks are still required.'
}
