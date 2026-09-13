$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\LabGraphConsent.ps1')

function Get-MgServicePrincipal {
    [CmdletBinding()] param($Filter, $Property, [switch]$All)
    throw 'Unmocked service principal read'
}
function Get-MgApplication {
    [CmdletBinding()] param($Filter, $ApplicationId, $Property, [switch]$All)
    throw 'Unmocked application read'
}
function Update-MgApplication {
    [CmdletBinding()] param($ApplicationId, $BodyParameter)
    throw 'Unmocked application write'
}
function Get-MgOauth2PermissionGrant {
    [CmdletBinding()] param($Filter, [switch]$All)
    throw 'Unmocked grant read'
}
function New-MgOauth2PermissionGrant {
    [CmdletBinding()] param($BodyParameter)
    throw 'Unmocked grant creation'
}
function Remove-MgOauth2PermissionGrant {
    [CmdletBinding()] param($OAuth2PermissionGrantId)
    throw 'Grant deletion forbidden'
}

Describe 'Configured permissions and consent are separate baselines (offline)' {
    BeforeEach {
        $script:clientId = '11111111-2222-3333-4444-555555555555'
        $script:graphId = '22222222-2222-3333-4444-555555555555'
        $script:appId = '55555555-2222-3333-4444-555555555555'
        $script:applicationId = '66666666-2222-3333-4444-555555555555'
        $script:otherApiId = '77777777-2222-3333-4444-555555555555'
        $script:graphAppId = '00000003-0000-0000-c000-000000000000'
        $script:openId = 'aaaaaaaa-1111-2222-3333-000000000001'
        $script:profileId = 'aaaaaaaa-1111-2222-3333-000000000002'
        $script:userReadId = 'aaaaaaaa-1111-2222-3333-000000000003'
        $script:otherPermissionId = 'aaaaaaaa-1111-2222-3333-000000000004'
        $script:graph = [pscustomobject]@{
            Id = $graphId; AppId = $graphAppId
            Oauth2PermissionScopes = @(
                [pscustomobject]@{ Id = $openId; Value = 'openid'; IsEnabled = $true }
                [pscustomobject]@{ Id = $profileId; Value = 'profile'; IsEnabled = $true }
                [pscustomobject]@{ Id = $userReadId; Value = 'User.Read'; IsEnabled = $true }
            )
        }
        $script:principals = [pscustomobject]@{
            ClientId = $clientId; GraphId = $graphId; StorageAppId = $appId
            GraphServicePrincipal = $graph
        }
        $script:app = [pscustomobject]@{
            Id = $applicationId; AppId = $appId
            RequiredResourceAccess = @(
                [pscustomobject]@{
                    ResourceAppId = $graphAppId
                    ResourceAccess = @(
                        [pscustomobject]@{ Id = $profileId; Type = 'Scope' }
                        [pscustomobject]@{ Id = $userReadId; Type = 'Scope' }
                        [pscustomobject]@{ Id = $otherPermissionId; Type = 'Role' }
                    )
                }
                [pscustomobject]@{
                    ResourceAppId = $otherApiId
                    ResourceAccess = @([pscustomobject]@{ Id = $otherPermissionId; Type = 'Scope' })
                }
            )
        }
        $script:grants = @([pscustomobject]@{
            Id = 'opaque-grant-id'; ClientId = $clientId; ResourceId = $graphId
            ConsentType = 'AllPrincipals'; PrincipalId = $null; Scope = 'openid profile User.Read'
        })
        $script:appReads = 0
        $script:failRead = 0
        $script:failUpdate = $false
        $script:invisibleUpdate = $false
        $script:dropUnrelated = $false
        $script:duplicateApp = $false
        $script:missingApp = $false
        $script:wrongReadback = $false
        $script:lastPayload = $null
        Mock Get-MgServicePrincipal {
            if (-not $All -or $Property -notcontains 'appId') { throw 'Incomplete principal lookup' }
            if ($Filter -eq "displayName eq '[Storage Account] azflabtest.file.core.windows.net'") {
                return [pscustomobject]@{ Id = $script:clientId; AppId = $script:appId }
            }
            if ($Filter -eq "appId eq '$script:graphAppId'") { return $script:graph }
            throw 'Unexpected principal lookup'
        }
        Mock Get-MgApplication {
            $script:appReads++
            if ($appReads -eq $failRead) { throw 'Application read denied' }
            if ($Property -notcontains 'requiredResourceAccess') { throw 'Required permissions were not selected' }
            if ($ApplicationId) {
                if ($ApplicationId -ne $script:applicationId) { throw 'Wrong application object Id' }
                if ($wrongReadback) { return [pscustomobject]@{ Id = $script:otherApiId; AppId = $script:appId } }
            } elseif ($Filter -ne "appId eq '$script:appId'" -or -not $All) {
                throw 'Application must be resolved by the storage service principal appId'
            }
            if ($missingApp) { return }
            if ($duplicateApp) { $script:app }
            $script:app
        }
        Mock Update-MgApplication {
            if ($ApplicationId -ne $script:applicationId) { throw 'Wrong application update target' }
            if ($failUpdate) { throw 'Application update denied' }
            $script:lastPayload = $BodyParameter
            if (-not $invisibleUpdate) {
                $script:app.RequiredResourceAccess = @(($BodyParameter | ConvertTo-Json -Depth 8 |
                    ConvertFrom-Json).requiredResourceAccess)
                if ($dropUnrelated) {
                    $script:app.RequiredResourceAccess = @($script:app.RequiredResourceAccess |
                        Where-Object ResourceAppId -eq $script:graphAppId)
                }
            }
        }
        Mock Get-MgOauth2PermissionGrant {
            if (-not $All -or $Filter -ne "clientId eq '$script:clientId'") { throw 'Incorrect grant lookup' }
            $script:grants
        }
        Mock New-MgOauth2PermissionGrant {
            $script:grants = @([pscustomobject]@{
                Id = 'new-grant-id'; ClientId = $BodyParameter.clientId; ResourceId = $BodyParameter.resourceId
                ConsentType = $BodyParameter.consentType; PrincipalId = $null; Scope = $BodyParameter.scope
            })
        }
        Mock Remove-MgOauth2PermissionGrant { throw 'Grant deletion forbidden' }
        Mock Write-Host {}
    }

    It 'restores a removed openid declaration even though the consent grant is still complete' {
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        $configured = @($app.RequiredResourceAccess | Where-Object ResourceAppId -eq $graphAppId)
        @($configured[0].ResourceAccess | Where-Object { $_.Id -eq $openId -and $_.Type -ceq 'Scope' }).Count | Should Be 1
        @($configured[0].ResourceAccess | Where-Object Type -ceq 'Role').Count | Should Be 1
        @($app.RequiredResourceAccess | Where-Object ResourceAppId -eq $otherApiId).Count | Should Be 1
        $lastPayload.Keys.Count | Should Be 1
        Assert-MockCalled Update-MgApplication -Times 1 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'does not rewrite configured permissions on a second run' {
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        Assert-MockCalled Update-MgApplication -Times 1 -Exactly -Scope It
        $appReads | Should Be 3
    }

    It 'restores declarations and creates only an absent consent baseline' {
        $script:grants = @()
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        Assert-MockCalled Update-MgApplication -Times 1 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It
        $grants[0].Scope | Should Be 'openid profile User.Read'
    }

    It 'restores all three scopes when the configured Graph entry or whole list is absent' -TestCases @(
        @{ Empty = $true }, @{ Empty = $false }
    ) {
        param($Empty)
        $app.RequiredResourceAccess = if ($Empty) { @() } else { @($app.RequiredResourceAccess[1]) }
        Initialize-LabAppPermissions -Principals $principals
        $entry = @($app.RequiredResourceAccess | Where-Object ResourceAppId -eq $graphAppId)[0]
        $entry.ResourceAccess.Count | Should Be 3
    }

    It 'stops on a denied or unconfirmed update before creating consent' -TestCases @(
        @{ Case = 'denied' }, @{ Case = 'not visible' }, @{ Case = 'lost unrelated' },
        @{ Case = 'readback denied' }, @{ Case = 'wrong readback' }
    ) {
        param($Case)
        $script:grants = @()
        $expected = 'APP_PERMISSIONS_READBACK_UNCONFIRMED'
        switch ($Case) {
            'denied' { $script:failUpdate = $true; $expected = 'APP_PERMISSIONS_UPDATE_FAILED' }
            'not visible' { $script:invisibleUpdate = $true }
            'lost unrelated' { $script:dropUnrelated = $true }
            'readback denied' { $script:failRead = 2 }
            'wrong readback' { $script:wrongReadback = $true }
        }
        { Initialize-LabGraphConsent -StorageAccountName azflabtest } | Should Throw $expected
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'never repairs an app selected ambiguously or from a failed lookup' -TestCases @(
        @{ Case = 'missing' }, @{ Case = 'duplicate' }, @{ Case = 'denied' }
    ) {
        param($Case)
        $expected = 'APP_PERMISSIONS_APP_AMBIGUOUS'
        switch ($Case) {
            'missing' { $script:missingApp = $true }
            'duplicate' { $script:duplicateApp = $true }
            'denied' { $script:failRead = 1; $expected = 'Application read denied' }
        }
        { Initialize-LabAppPermissions -Principals $principals } | Should Throw $expected
        Assert-MockCalled Update-MgApplication -Times 0 -Exactly -Scope It
    }

    It 'rejects missing disabled or ambiguous Graph scope definitions' -TestCases @(
        @{ Case = 'missing' }, @{ Case = 'disabled' }, @{ Case = 'duplicate' }, @{ Case = 'wrong Graph' }
    ) {
        param($Case)
        switch ($Case) {
            'missing' { $graph.Oauth2PermissionScopes = @() }
            'disabled' { $graph.Oauth2PermissionScopes[0].IsEnabled = $false }
            'duplicate' { $graph.Oauth2PermissionScopes += $graph.Oauth2PermissionScopes[0] }
            'wrong Graph' { $graph.AppId = $otherApiId }
        }
        { Initialize-LabAppPermissions -Principals $principals } | Should Throw 'APP_PERMISSIONS_UNEXPECTED'
        Assert-MockCalled Update-MgApplication -Times 0 -Exactly -Scope It
    }

    It 'refuses malformed existing declarations rather than dropping them' -TestCases @(
        @{ Case = 'duplicate resource' }, @{ Case = 'duplicate permission' }, @{ Case = 'unknown type' }
    ) {
        param($Case)
        switch ($Case) {
            'duplicate resource' { $app.RequiredResourceAccess += $app.RequiredResourceAccess[0] }
            'duplicate permission' { $app.RequiredResourceAccess[0].ResourceAccess += $app.RequiredResourceAccess[0].ResourceAccess[0] }
            'unknown type' { $app.RequiredResourceAccess[0].ResourceAccess[0].Type = 'Unknown' }
        }
        { Initialize-LabAppPermissions -Principals $principals } | Should Throw 'APP_PERMISSIONS_UNEXPECTED'
        Assert-MockCalled Update-MgApplication -Times 0 -Exactly -Scope It
    }

    It 'does not alter declarations when consent itself is unexpected' {
        $grants[0].Scope = 'openid'
        { Initialize-LabGraphConsent -StorageAccountName azflabtest } | Should Throw 'CONSENT_STATE_UNEXPECTED'
        Assert-MockCalled Update-MgApplication -Times 0 -Exactly -Scope It
    }
}
