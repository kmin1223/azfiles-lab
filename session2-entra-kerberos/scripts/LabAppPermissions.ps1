function Get-LabAppPermissionPlan {
    param($Application, [hashtable]$RequiredScopes)
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $resources = @()
    $keys = @()
    $seenResources = @()
    $graphEntry = $null
    foreach ($resource in $Application.RequiredResourceAccess) {
        Assert-ConsentGuid -Value $resource.ResourceAppId -Label 'Configured resourceAppId'
        $resourceId = ([guid]$resource.ResourceAppId).ToString()
        if ($seenResources -contains $resourceId) {
            throw 'APP_PERMISSIONS_UNEXPECTED: Duplicate configured API entries; no automatic rewrite is safe.'
        }
        $seenResources += $resourceId
        $keys += "resource:$resourceId"
        $permissions = @()
        foreach ($permission in $resource.ResourceAccess) {
            Assert-ConsentGuid -Value $permission.Id -Label 'Configured permission Id'
            if ($permission.Type -cnotin @('Scope', 'Role')) {
                throw 'APP_PERMISSIONS_UNEXPECTED: Unknown configured permission type; no automatic rewrite is safe.'
            }
            $permissionId = ([guid]$permission.Id).ToString()
            $key = "${resourceId}:$($permission.Type):$permissionId"
            if ($keys -ccontains $key) {
                throw 'APP_PERMISSIONS_UNEXPECTED: Duplicate configured permission; no automatic rewrite is safe.'
            }
            $keys += $key
            $permissions += @{ id = $permissionId; type = $permission.Type }
        }
        $entry = @{ resourceAppId = $resourceId; resourceAccess = @($permissions) }
        $resources += $entry
        if ($resourceId -eq $graphAppId) { $graphEntry = $entry }
    }
    if (-not $graphEntry) {
        $graphEntry = @{ resourceAppId = $graphAppId; resourceAccess = @() }
        $resources += $graphEntry
        $keys += "resource:$graphAppId"
    }
    $missing = @()
    foreach ($scope in @('openid', 'profile', 'User.Read')) {
        $permissionId = $RequiredScopes[$scope]
        $key = "${graphAppId}:Scope:$permissionId"
        if ($keys -cnotcontains $key) {
            $missing += $scope
            $graphEntry.resourceAccess += @{ id = $permissionId; type = 'Scope' }
            $keys += $key
        }
    }
    [pscustomobject]@{
        RequiredResourceAccess = @($resources)
        MissingPermissions = @($missing)
        PermissionKeys = @($keys)
    }
}

function Initialize-LabAppPermissions {
    param([Parameter(Mandatory)]$Principals)
    Assert-ConsentGuid -Value $Principals.StorageAppId -Label 'Storage application appId'
    $appId = ([guid]$Principals.StorageAppId).ToString()
    $graph = $Principals.GraphServicePrincipal
    if ($graph.AppId -ne '00000003-0000-0000-c000-000000000000') {
        throw 'APP_PERMISSIONS_UNEXPECTED: Permission definitions must come from Microsoft Graph.'
    }
    $requiredScopes = @{}
    foreach ($name in @('openid', 'profile', 'User.Read')) {
        $definitions = @($graph.Oauth2PermissionScopes | Where-Object {
            $_.Value -ceq $name -and $_.IsEnabled -eq $true
        })
        if ($definitions.Count -ne 1) {
            throw "APP_PERMISSIONS_UNEXPECTED: Microsoft Graph must expose exactly one enabled delegated '$name' scope."
        }
        Assert-ConsentGuid -Value $definitions[0].Id -Label "$name scope Id"
        $id = ([guid]$definitions[0].Id).ToString()
        if ($requiredScopes.Values -contains $id) {
            throw 'APP_PERMISSIONS_UNEXPECTED: Required scope IDs must be distinct.'
        }
        $requiredScopes[$name] = $id
    }
    $properties = @('id', 'appId', 'requiredResourceAccess')
    $apps = @(Get-MgApplication -Filter "appId eq '$appId'" -Property $properties -All -ErrorAction Stop)
    if ($apps.Count -ne 1 -or $apps[0].AppId -ne $appId) {
        throw 'APP_PERMISSIONS_APP_AMBIGUOUS: Expected exactly one app registration matching the storage service principal appId.'
    }
    Assert-ConsentGuid -Value $apps[0].Id -Label 'Storage application object Id'
    $applicationId = [string]$apps[0].Id
    $plan = Get-LabAppPermissionPlan -Application $apps[0] -RequiredScopes $requiredScopes
    if ($plan.MissingPermissions.Count -eq 0) {
        Write-Host 'Configured API permission declarations verified: openid profile User.Read.'
        return
    }
    try {
        Update-MgApplication -ApplicationId $applicationId -BodyParameter @{
            requiredResourceAccess = $plan.RequiredResourceAccess
        } -ErrorAction Stop
    } catch {
        throw "APP_PERMISSIONS_UPDATE_FAILED: Could not restore the required declarations. The Graph session needs Application.ReadWrite.All and the caller must be authorized to edit this app. Reusing an existing Graph connection does not add scopes. No consent change was attempted. $($_.Exception.Message)"
    }
    try {
        $updated = @(Get-MgApplication -ApplicationId $applicationId -Property $properties -ErrorAction Stop)
        if ($updated.Count -ne 1 -or $updated[0].Id -ne $applicationId -or $updated[0].AppId -ne $appId) {
            throw 'The application readback did not match the selected registration.'
        }
        $readback = Get-LabAppPermissionPlan -Application $updated[0] -RequiredScopes $requiredScopes
        if ($readback.MissingPermissions.Count -ne 0 -or
            (($readback.PermissionKeys | Sort-Object) -join '|') -cne
            (($plan.PermissionKeys | Sort-Object) -join '|')) {
            throw 'Configured permissions readback did not match the preserved permissions plus required scopes.'
        }
    } catch {
        throw "APP_PERMISSIONS_READBACK_UNCONFIRMED: App update returned, but its permission declarations were not confirmed. Inspect API permissions before retrying; no consent change or rollback was attempted. $($_.Exception.Message)"
    }
    Write-Host "Configured API permission declarations restored and verified: $($plan.MissingPermissions -join ', '). Other configured permissions were preserved."
}
