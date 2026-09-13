$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts\LabGraphConsent.ps1')
$script:setupSource = Get-Content (Join-Path $root 'setup.ps1') -Raw
$script:setupTail = [scriptblock]::Create(
    $setupSource.Substring($setupSource.IndexOf("Step '3/4 Granting admin consent")))

function Connect-LabGraph { param($Scopes) throw 'Unmocked Graph connection' }
function Step { param($Message) }
function Invoke-LabClientConfiguration { param($Mode, $TenantId) throw 'Unmocked VM configuration' }
function Get-MgServicePrincipal {
    [CmdletBinding()] param($Filter, [switch]$All)
    throw 'Unmocked service principal read'
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
    throw 'Setup must never delete a grant'
}

Describe 'Setup consent preserves an existing baseline (offline)' {
    BeforeEach {
        $script:clientId = '11111111-2222-3333-4444-555555555555'
        $script:graphId = '22222222-2222-3333-4444-555555555555'
        $script:otherId = '33333333-2222-3333-4444-555555555555'
        $script:tenantId = '44444444-2222-3333-4444-555555555555'
        $script:saName = 'azflabtest'
        $script:storageSps = @([pscustomobject]@{ Id = $clientId })
        $script:graphSps = @([pscustomobject]@{ Id = $graphId })
        $script:baseline = [pscustomobject]@{
            Id = 'opaque-baseline-id'; ClientId = $clientId; ResourceId = $graphId
            ConsentType = 'AllPrincipals'; PrincipalId = $null; Scope = 'openid profile User.Read'
        }
        $script:unrelated = [pscustomobject]@{
            Id = 'opaque-unrelated-id'; ClientId = $clientId; ResourceId = $otherId
            ConsentType = 'Principal'; PrincipalId = $otherId; Scope = 'unrelated.extra'
        }
        $script:grants = @($baseline, $unrelated)
        $script:readCount = 0
        $script:storageReadCount = 0
        $script:failRead = 0
        $script:failSp = $false
        $script:failCreate = $false
        $script:invisibleCreate = $false
        $script:delayedSp = $false
        Mock Connect-LabGraph {}
        Mock Invoke-LabClientConfiguration {}
        Mock Get-MgServicePrincipal {
            if ($failSp) { throw 'SP read denied' }
            if (-not $All) { throw 'SP read must be complete' }
            if ($Filter -eq "displayName eq '[Storage Account] azflabtest.file.core.windows.net'") {
                $script:storageReadCount++
                if ($delayedSp -and $storageReadCount -eq 1) { return }
                return $script:storageSps
            }
            if ($Filter -eq "appId eq '00000003-0000-0000-c000-000000000000'") {
                return $script:graphSps
            }
            throw 'Unexpected SP filter'
        }
        Mock Get-MgOauth2PermissionGrant {
            $script:readCount++
            if ($readCount -eq $failRead) { throw 'Grant read denied' }
            if (-not $All -or $Filter -ne "clientId eq '$script:clientId'") {
                throw 'Grant read must be complete and scoped'
            }
            $script:grants
        }
        Mock New-MgOauth2PermissionGrant {
            if ($failCreate) { throw 'Creation denied' }
            if (-not $invisibleCreate) { $script:grants += $script:baseline }
        }
        Mock Remove-MgOauth2PermissionGrant { throw 'Setup must never delete a grant' }
        Mock Start-Sleep {}
        Mock Write-Host {}
    }

    It 'keeps the existing exact baseline and unrelated grant without mutation' {
        $baseline.Scope = 'User.Read profile openid'
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        $grants.Count | Should Be 2
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
    }

    It 'creates only an absent baseline, preserves other resources, and is idempotent' {
        $script:grants = @($unrelated)
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        $grants.Count | Should Be 2
        $grants[0].Id | Should Be 'opaque-unrelated-id'
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It -ParameterFilter {
            $BodyParameter.clientId -eq $script:clientId -and
            $BodyParameter.resourceId -eq $script:graphId -and
            $BodyParameter.consentType -ceq 'AllPrincipals' -and
            $BodyParameter.scope -ceq 'openid profile User.Read'
        }
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        $readCount | Should Be 3
    }

    It 'retries only an initially absent storage app once' {
        $script:delayedSp = $true
        Initialize-LabGraphConsent -StorageAccountName azflabtest
        $storageReadCount | Should Be 2
        Assert-MockCalled Start-Sleep -Times 1 -Exactly -Scope It -ParameterFilter { $Seconds -eq 30 }
    }

    It 'stops on missing or ambiguous service principals' -TestCases @(
        @{ Case = 'missing storage' }, @{ Case = 'duplicate storage' },
        @{ Case = 'missing Graph' }, @{ Case = 'duplicate Graph' }
    ) {
        param($Case)
        switch ($Case) {
            'missing storage' { $script:storageSps = @() }
            'duplicate storage' { $script:storageSps += $storageSps[0] }
            'missing Graph' { $script:graphSps = @() }
            'duplicate Graph' { $script:graphSps += $graphSps[0] }
        }
        { & $setupTail } | Should Throw 'CONSENT_SP_AMBIGUOUS'
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-LabClientConfiguration -Times 0 -Exactly -Scope It
    }

    It 'does not interpret directory read failures as absent consent' {
        $script:failRead = 1
        { & $setupTail } | Should Throw 'Grant read denied'
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-LabClientConfiguration -Times 0 -Exactly -Scope It
    }

    It 'does not sleep or mutate after a service principal read error' {
        $script:failSp = $true
        { & $setupTail } | Should Throw 'SP read denied'
        Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-LabClientConfiguration -Times 0 -Exactly -Scope It
    }

    It 'refuses unexpected Graph consent instead of deleting or broadening it' -TestCases @(
        @{ Case = 'partial scope' }, @{ Case = 'extra scope' },
        @{ Case = 'user grant' }, @{ Case = 'multiple grants' }
    ) {
        param($Case)
        switch ($Case) {
            'partial scope' { $baseline.Scope = 'openid' }
            'extra scope' { $baseline.Scope = 'openid profile User.Read Mail.Read' }
            'user grant' { $baseline.ConsentType = 'Principal'; $baseline.PrincipalId = $otherId }
            'multiple grants' { $script:grants += $baseline }
        }
        { & $setupTail } | Should Throw 'CONSENT_STATE_UNEXPECTED'
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-LabClientConfiguration -Times 0 -Exactly -Scope It
    }

    It 'stops before the client reboot when creation fails' {
        $script:grants = @($unrelated)
        $script:failCreate = $true
        { & $setupTail } | Should Throw 'Creation denied'
        Assert-MockCalled Invoke-LabClientConfiguration -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'requires successful readback before proceeding to client configuration' -TestCases @(
        @{ Case = 'not visible' }, @{ Case = 'read denied' }
    ) {
        param($Case)
        $script:grants = @($unrelated)
        if ($Case -eq 'not visible') { $script:invisibleCreate = $true } else { $script:failRead = 2 }
        { & $setupTail } | Should Throw 'CONSENT_READBACK_UNCONFIRMED'
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-LabClientConfiguration -Times 0 -Exactly -Scope It
    }

    It 'continues the real setup tail after confirming an existing baseline without deleting its opaque Id' {
        & $setupTail
        Assert-MockCalled Connect-LabGraph -Times 1 -Exactly -Scope It
        Assert-MockCalled Invoke-LabClientConfiguration -Times 1 -Exactly -Scope It -ParameterFilter {
            $Mode -eq 'Configure' -and $TenantId -eq $script:tenantId
        }
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'loads the shared helper and required Graph module before Azure changes' {
        $setupSource | Should Match "'Microsoft.Graph.Identity.SignIns'"
        ($setupSource.IndexOf("'LabGraphConsent.ps1'") -lt
            $setupSource.IndexOf("Step '0/4")) | Should Be $true
        $setupSource | Should Not Match 'Remove-MgOauth2PermissionGrant|existingGrant'
    }
}
