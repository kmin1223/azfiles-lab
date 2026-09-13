$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$faultPath = Join-Path $root 'faults\Invoke-Fault.ps1'
$source = Get-Content $faultPath -Raw
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($faultPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
# Extract only definitions: never run the script's Azure lookup or other faults.
foreach ($name in @('Assert-ConsentGuid', 'Get-LabGraphConsent', 'Invoke-LabConsentFault', 'Show-Cmd')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Connect-LabGraph { param($Scopes) throw 'Unmocked Graph connection' }
function Get-MgServicePrincipal {
    [CmdletBinding()] param($Filter, [switch]$All)
    throw 'Unmocked service principal read'
}
function Get-MgOauth2PermissionGrant {
    [CmdletBinding()] param($Filter, [switch]$All)
    throw 'Unmocked grant read'
}
function Remove-MgOauth2PermissionGrant {
    [CmdletBinding()] param($OAuth2PermissionGrantId)
    throw 'Unmocked grant deletion'
}
function New-MgOauth2PermissionGrant {
    [CmdletBinding()] param($BodyParameter)
    throw 'Unmocked grant creation'
}

Describe 'Presenter ConsentRevoked bounded baseline (offline)' {
    BeforeEach {
        $script:clientId = '11111111-2222-3333-4444-555555555555'
        $script:graphId = '22222222-2222-3333-4444-555555555555'
        $script:otherId = '33333333-2222-3333-4444-555555555555'
        $script:storageSps = @([pscustomobject]@{ Id = $clientId })
        $script:graphSps = @([pscustomobject]@{ Id = $graphId })
        # OAuth2 permission grant IDs are opaque strings, not GUIDs.
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
        $script:failRead = 0
        $script:failSp = $false
        $script:failConnect = $false
        $script:failMutation = $false
        $script:invisibleMutation = $false
        $script:unexpectedReadback = $false
        Mock Connect-LabGraph { if ($failConnect) { throw 'Connection denied' } }
        Mock Get-MgServicePrincipal {
            if ($failSp) { throw 'SP read denied' }
            if (-not $All) { throw 'SP read must be complete' }
            if ($Filter -eq "displayName eq '[Storage Account] azflabtest.file.core.windows.net'") {
                return $storageSps
            }
            if ($Filter -eq "appId eq '00000003-0000-0000-c000-000000000000'") {
                return $graphSps
            }
            throw "Unexpected SP filter: $Filter"
        }
        Mock Get-MgOauth2PermissionGrant {
            $script:readCount++
            if ($readCount -eq $failRead) { throw 'Grant read denied' }
            if (-not $All -or $Filter -ne "clientId eq '$clientId'") {
                throw 'Grant read must be complete and scoped'
            }
            if ($unexpectedReadback -and $readCount -gt 1) {
                $script:baseline.Scope = 'openid profile User.Read Mail.Read'
                return @($script:baseline, $unrelated)
            }
            $grants
        }
        Mock Remove-MgOauth2PermissionGrant {
            if ($failMutation) { throw 'Deletion denied' }
            if (-not $invisibleMutation) {
                $script:grants = @($grants | Where-Object { $_.Id -ne $OAuth2PermissionGrantId })
            }
        }
        Mock New-MgOauth2PermissionGrant {
            if ($failMutation) { throw 'Creation denied' }
            if (-not $invisibleMutation) { $script:grants = @($unrelated, $script:baseline) }
        }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Show-Cmd {}
    }

    It 'deletes only the validated Graph grant and preserves non-Graph user consent' {
        Invoke-LabConsentFault -StorageAccountName azflabtest
        $grants.Count | Should Be 1
        $grants[0].Id | Should Be $unrelated.Id
        $unrelated.Scope | Should Be 'unrelated.extra'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It -ParameterFilter {
            $OAuth2PermissionGrantId -eq 'opaque-baseline-id'
        }
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        $readCount | Should Be 2
    }

    It 'accepts reordered whitespace-separated scope sets for inject and repair' {
        $baseline.Scope = "User.Read`tprofile  openid"
        Invoke-LabConsentFault -StorageAccountName azflabtest -Repair
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Invoke-LabConsentFault -StorageAccountName azflabtest
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It
    }

    It 'makes repeated injection idempotent without claiming a live failure' {
        Invoke-LabConsentFault -StorageAccountName azflabtest
        Invoke-LabConsentFault -StorageAccountName azflabtest
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*already missing*not evidence of a live*'
        }
    }

    It 'does not delete anything when no Graph grant exists' {
        $script:grants = @($unrelated)
        Invoke-LabConsentFault -StorageAccountName azflabtest
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        $grants[0].Id | Should Be $unrelated.Id
    }

    It 'creates only the fixed baseline once and preserves non-Graph consent on repeated repair' {
        $script:grants = @($unrelated)
        Invoke-LabConsentFault -StorageAccountName azflabtest -Repair
        Invoke-LabConsentFault -StorageAccountName azflabtest -Repair
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It -ParameterFilter {
            $BodyParameter.Count -eq 4 -and $BodyParameter.clientId -eq $clientId -and
            $BodyParameter.resourceId -eq $graphId -and $BodyParameter.consentType -ceq 'AllPrincipals' -and
            $BodyParameter.scope -ceq 'openid profile User.Read'
        }
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        @($grants | Where-Object Id -eq $unrelated.Id).Count | Should Be 1
        $readCount | Should Be 3
    }

    It 'leaves an existing exact baseline alone on repair' {
        Invoke-LabConsentFault -StorageAccountName azflabtest -Repair
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*already present*nothing changed*'
        }
    }

    It 'rejects missing or duplicate <Target> principals before mutation (count <Count>)' -TestCases @(
        @{ Target = 'storage'; Count = 0 }, @{ Target = 'storage'; Count = 2 },
        @{ Target = 'graph'; Count = 0 }, @{ Target = 'graph'; Count = 2 }
    ) {
        param($Target, $Count)
        if ($Target -eq 'storage') { $script:storageSps = @($storageSps * $Count) }
        else { $script:graphSps = @($graphSps * $Count) }
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'CONSENT_SP_AMBIGUOUS'
        { Invoke-LabConsentFault -StorageAccountName azflabtest -Repair } | Should Throw 'CONSENT_SP_AMBIGUOUS'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects invalid <Target> GUID <Value> before mutation' -TestCases @(
        @{ Target = 'storage'; Value = '' }, @{ Target = 'storage'; Value = 'not-guid' },
        @{ Target = 'storage'; Value = '00000000-0000-0000-0000-000000000000' },
        @{ Target = 'graph'; Value = '' }, @{ Target = 'graph'; Value = 'not-guid' },
        @{ Target = 'graph'; Value = '00000000-0000-0000-0000-000000000000' }
    ) {
        param($Target, $Value)
        if ($Target -eq 'storage') { $storageSps[0].Id = $Value } else { $graphSps[0].Id = $Value }
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'CONSENT_ID_INVALID'
        { Invoke-LabConsentFault -StorageAccountName azflabtest -Repair } | Should Throw 'CONSENT_ID_INVALID'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects identical storage and Graph identities' {
        $graphSps[0].Id = $clientId
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'CONSENT_SP_AMBIGUOUS'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects unexpected Graph consent: <State>, for injection and repair' -TestCases @(
        @{ State = 'extra scope' }, @{ State = 'missing scope' }, @{ State = 'wrong scope case' },
        @{ State = 'empty scopes' }, @{ State = 'user grant only' }, @{ State = 'user grant alongside' },
        @{ State = 'duplicate baseline' }, @{ State = 'unexpected principal' }, @{ State = 'missing grant id' },
        @{ State = 'wrong client' }
    ) {
        param($State)
        switch ($State) {
            'extra scope' { $baseline.Scope += ' Mail.Read' }
            'missing scope' { $baseline.Scope = 'openid profile' }
            'wrong scope case' { $baseline.Scope = 'openid profile user.read' }
            'empty scopes' { $baseline.Scope = '' }
            'user grant only' { $baseline.ConsentType = 'Principal'; $baseline.PrincipalId = $otherId }
            'user grant alongside' {
                $script:grants += [pscustomobject]@{
                    Id = 'user-grant'; ClientId = $clientId; ResourceId = $graphId
                    ConsentType = 'Principal'; PrincipalId = $otherId; Scope = 'openid profile User.Read'
                }
            }
            'duplicate baseline' { $script:grants += $baseline }
            'unexpected principal' { $baseline.PrincipalId = $otherId }
            'missing grant id' { $baseline.Id = '' }
            'wrong client' { $baseline.ClientId = $otherId }
        }
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'CONSENT_STATE_UNEXPECTED'
        { Invoke-LabConsentFault -StorageAccountName azflabtest -Repair } | Should Throw 'CONSENT_STATE_UNEXPECTED'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects malformed grant identities rather than treating the grant as non-Graph' {
        $baseline.ResourceId = ''
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'CONSENT_ID_INVALID'
        $baseline.ResourceId = $graphId
        $baseline.ClientId = [guid]::Empty
        { Invoke-LabConsentFault -StorageAccountName azflabtest -Repair } | Should Throw 'CONSENT_ID_INVALID'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'propagates connection, SP and initial grant read failures without mutation' {
        $script:failConnect = $true
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'Connection denied'
        $script:failConnect = $false
        $script:failSp = $true
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'SP read denied'
        $script:failSp = $false
        $script:failRead = 1
        { Invoke-LabConsentFault -StorageAccountName azflabtest -Repair } | Should Throw 'Grant read denied'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'does not report success when deletion or creation fails' {
        $script:failMutation = $true
        { Invoke-LabConsentFault -StorageAccountName azflabtest } | Should Throw 'Deletion denied'
        $script:grants = @($unrelated)
        { Invoke-LabConsentFault -StorageAccountName azflabtest -Repair } | Should Throw 'Creation denied'
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter {
            $Object -like 'Directory readback confirms*'
        }
    }

    It 'reports unconfirmed readback without retry or rollback: <State>, repair=<Fix>' -TestCases @(
        @{ State = 'lag'; Fix = $false }, @{ State = 'lag'; Fix = $true },
        @{ State = 'read failure'; Fix = $false }, @{ State = 'read failure'; Fix = $true },
        @{ State = 'concurrent change'; Fix = $false }, @{ State = 'concurrent change'; Fix = $true }
    ) {
        param($State, $Fix)
        if ($Fix) { $script:grants = @($unrelated) }
        switch ($State) {
            'lag' { $script:invisibleMutation = $true }
            'read failure' { $script:failRead = 2 }
            'concurrent change' { $script:unexpectedReadback = $true }
        }
        { Invoke-LabConsentFault -StorageAccountName azflabtest -Repair:$Fix } |
            Should Throw 'CONSENT_READBACK_UNCONFIRMED'
        $readCount | Should Be 2
        $removeCount = 1
        $createCount = 0
        if ($Fix) { $removeCount = 0; $createCount = 1 }
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times $removeCount -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times $createCount -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter {
            $Object -like 'Directory readback confirms*'
        }
    }

    It 'always gives account-wide and fresh-ticket advisories including on an idempotent call' {
        Invoke-LabConsentFault -StorageAccountName azflabtest -Repair
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like '*ALL shares/new requests*labshare*rbac-lab*Existing tickets/SMB sessions may survive*does not clear or revoke the PRT or cloud TGT*'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*after closing the lab SMB connections*klist purge; klist get cifs/azflabtest.file.core.windows.net*'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*Directory readback does not prove live CIFS service-ticket acquisition*propagation may lag*'
        }
    }

    It 'preserves public CLI and dispatch, without a fixed wait or TGT-for-storage claims' {
        ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') |
            Should Be 'ResourceGroupName,Fault,Repair,Prefix'
        ($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Prefix' }).
            DefaultValue.Value | Should Be 'azflab'
        $source | Should Match 'Invoke-LabConsentFault -StorageAccountName \$saName -Repair:\$Repair'
        $source | Should Not Match 'TGT issuance for the SA|issue the TGT for the SA'
        (Get-Command Invoke-LabConsentFault).Definition | Should Not Match 'Start-Sleep'
        $source | Should Match 'NoShareAccess changes only default share permission, not explicit/inherited RBAC'
    }

    It 'uses terminating errors on each Graph SDK operation' {
        $commands = $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -match '^(Get-MgServicePrincipal|Get-MgOauth2PermissionGrant|Remove-MgOauth2PermissionGrant|New-MgOauth2PermissionGrant)$'
        }, $true)
        $commands.Count | Should Be 5
        foreach ($command in $commands) {
            $command.Extent.Text | Should Match '-ErrorAction Stop'
        }
    }
}
