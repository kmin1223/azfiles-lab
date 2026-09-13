$ErrorActionPreference = 'Stop'
$faultPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'faults\Invoke-Fault.ps1'
$source = Get-Content $faultPath -Raw
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($faultPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
# Definitions only: never execute the Azure lookup, Graph helper or live faults.
foreach ($name in @('Get-ConsentLabStorageAccount', 'Assert-ConsentGuid', 'Get-LabGraphConsent', 'Invoke-LabConsentFault', 'Show-Cmd')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Get-AzStorageAccount {
    [CmdletBinding()] param($ResourceGroupName)
    throw 'Unmocked Azure read'
}
function Connect-LabGraph { param($Scopes) throw 'Unmocked Graph connection' }
function Get-MgServicePrincipal {
    [CmdletBinding()] param($Filter, [switch]$All)
    throw 'Unmocked SP read'
}
function Get-MgOauth2PermissionGrant {
    [CmdletBinding()] param($Filter, [switch]$All)
    throw 'Unmocked grant read'
}
function Remove-MgOauth2PermissionGrant {
    [CmdletBinding()] param($OAuth2PermissionGrantId)
    throw 'Unmocked deletion'
}
function New-MgOauth2PermissionGrant {
    [CmdletBinding()] param($BodyParameter)
    throw 'Unmocked creation'
}

Describe 'Cloud-only participant ConsentRevoked (offline)' {
    BeforeEach {
        $script:clientId = '11111111-2222-3333-4444-555555555555'
        $script:graphId = '22222222-2222-3333-4444-555555555555'
        $script:otherId = '33333333-2222-3333-4444-555555555555'
        $script:storageSps = @([pscustomobject]@{ Id = $clientId })
        $script:graphSps = @([pscustomobject]@{ Id = $graphId })
        # OAuth2 grant IDs are opaque strings, not GUIDs.
        $script:baseline = [pscustomobject]@{
            Id = 'opaque-baseline'; ClientId = $clientId; ResourceId = $graphId
            ConsentType = 'AllPrincipals'; PrincipalId = $null; Scope = 'openid profile User.Read'
        }
        $script:unrelated = [pscustomobject]@{
            Id = 'opaque-unrelated'; ClientId = $clientId; ResourceId = $otherId
            ConsentType = 'Principal'; PrincipalId = $otherId; Scope = 'unrelated.extra'
        }
        $script:grants = @($baseline, $unrelated)
        $script:accounts = @([pscustomobject]@{ StorageAccountName = 'azfcloudtest' })
        $script:readCount = 0
        $script:failure = ''
        $script:invisibleMutation = $false
        $script:unexpectedReadback = $false
        Mock Get-AzStorageAccount {
            if ($failure -eq 'Azure') { throw 'Azure read denied' }
            if ($ResourceGroupName -ne 'azfiles-cloudonly') { throw 'Wrong resource group' }
            $accounts
        }
        Mock Connect-LabGraph { if ($failure -eq 'Connect') { throw 'Connection denied' } }
        Mock Get-MgServicePrincipal {
            if ($failure -eq 'SP') { throw 'SP read denied' }
            if (-not $All) { throw 'SP read must be complete' }
            if ($Filter -eq "displayName eq '[Storage Account] azfcloudtest.file.core.windows.net'") {
                return $storageSps
            }
            if ($Filter -eq "appId eq '00000003-0000-0000-c000-000000000000'") { return $graphSps }
            throw "Unexpected SP filter: $Filter"
        }
        Mock Get-MgOauth2PermissionGrant {
            $script:readCount++
            if ($failure -eq 'Read' -or ($failure -eq 'Readback' -and $readCount -eq 2)) {
                throw 'Grant read denied'
            }
            if (-not $All -or $Filter -ne "clientId eq '$clientId'") { throw 'Incomplete/unscoped listing' }
            if ($unexpectedReadback -and $readCount -gt 1) {
                $script:baseline.Scope += ' Mail.Read'
                return @($script:baseline, $unrelated)
            }
            $grants
        }
        Mock Remove-MgOauth2PermissionGrant {
            if ($failure -eq 'Mutation') { throw 'Deletion denied' }
            if (-not $invisibleMutation) {
                $script:grants = @($grants | Where-Object { $_.Id -ne $OAuth2PermissionGrantId })
            }
        }
        Mock New-MgOauth2PermissionGrant {
            if ($failure -eq 'Mutation') { throw 'Creation denied' }
            if (-not $invisibleMutation) { $script:grants = @($unrelated, $script:baseline) }
        }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Show-Cmd {}
    }

    It 'selects exactly one literal prefix match and ignores other participant accounts' {
        $script:accounts += [pscustomobject]@{ StorageAccountName = 'otherparticipant' }
        $sa = Get-ConsentLabStorageAccount -ResourceGroupName azfiles-cloudonly -Prefix azfcloud
        $sa.StorageAccountName | Should Be 'azfcloudtest'
        Assert-MockCalled Get-AzStorageAccount -Times 1 -Exactly -Scope It -ParameterFilter {
            $ResourceGroupName -eq 'azfiles-cloudonly'
        }
    }

    It 'rejects missing, duplicate or overbroad storage matches: <Count>' -TestCases @(
        @{ Count = 0 }, @{ Count = 2 }
    ) {
        param($Count)
        $script:accounts = @($accounts * $Count)
        { Get-ConsentLabStorageAccount -ResourceGroupName azfiles-cloudonly -Prefix azfcloud } |
            Should Throw 'CONSENT_TARGET_AMBIGUOUS'
        Assert-MockCalled Connect-LabGraph -Times 0 -Exactly -Scope It
    }

    It 'rejects unsafe prefix <Prefix>' -TestCases @(
        @{ Prefix = '' }, @{ Prefix = '*' }, @{ Prefix = 'azf?' }, @{ Prefix = 'azf[ab]' },
        @{ Prefix = 'AZFCLOUD' }, @{ Prefix = 'azf-cloud' }
    ) {
        param($Prefix)
        { Get-ConsentLabStorageAccount -ResourceGroupName azfiles-cloudonly -Prefix $Prefix } |
            Should Throw 'CONSENT_TARGET_INVALID'
        Assert-MockCalled Get-AzStorageAccount -Times 0 -Exactly -Scope It
    }

    It 'propagates Azure listing failure without selecting or mutating anything' {
        $script:failure = 'Azure'
        { Get-ConsentLabStorageAccount -ResourceGroupName azfiles-cloudonly -Prefix azfcloud } |
            Should Throw 'Azure read denied'
        Assert-MockCalled Connect-LabGraph -Times 0 -Exactly -Scope It
    }

    It 'deletes only the exact baseline and preserves non-Graph user consent' {
        Invoke-LabConsentFault -StorageAccountName azfcloudtest
        $grants.Count | Should Be 1
        $grants[0].Id | Should Be 'opaque-unrelated'
        $grants[0].Scope | Should Be 'unrelated.extra'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It -ParameterFilter {
            $OAuth2PermissionGrantId -eq 'opaque-baseline'
        }
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        $readCount | Should Be 2
    }

    It 'accepts reordered scope sets and idempotent repair without mutation' {
        $baseline.Scope = "User.Read`tprofile  openid"
        Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*already present*nothing changed*'
        }
    }

    It 'makes repeated injection idempotent without claiming a live failure' {
        Invoke-LabConsentFault -StorageAccountName azfcloudtest
        Invoke-LabConsentFault -StorageAccountName azfcloudtest
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*already missing*not evidence of a live*'
        }
    }

    It 'creates only the absent fixed baseline once and preserves unrelated consent' {
        $script:grants = @($unrelated)
        Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair
        Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 1 -Exactly -Scope It -ParameterFilter {
            $BodyParameter.Count -eq 4 -and $BodyParameter.clientId -eq $clientId -and
            $BodyParameter.resourceId -eq $graphId -and $BodyParameter.consentType -ceq 'AllPrincipals' -and
            $BodyParameter.scope -ceq 'openid profile User.Read'
        }
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        @($grants | Where-Object Id -eq 'opaque-unrelated').Count | Should Be 1
        $readCount | Should Be 3
    }

    It 'rejects <Target> SP count <Count> before injection or repair' -TestCases @(
        @{ Target = 'storage'; Count = 0 }, @{ Target = 'storage'; Count = 2 },
        @{ Target = 'graph'; Count = 0 }, @{ Target = 'graph'; Count = 2 }
    ) {
        param($Target, $Count)
        if ($Target -eq 'storage') { $script:storageSps = @($storageSps * $Count) }
        else { $script:graphSps = @($graphSps * $Count) }
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest } | Should Throw 'CONSENT_SP_AMBIGUOUS'
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair } | Should Throw 'CONSENT_SP_AMBIGUOUS'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects malformed <Target> GUID <Value>' -TestCases @(
        @{ Target = 'storage'; Value = '' }, @{ Target = 'storage'; Value = 'not-guid' },
        @{ Target = 'storage'; Value = '00000000-0000-0000-0000-000000000000' },
        @{ Target = 'graph'; Value = '' }, @{ Target = 'graph'; Value = 'not-guid' },
        @{ Target = 'graph'; Value = '00000000-0000-0000-0000-000000000000' }
    ) {
        param($Target, $Value)
        if ($Target -eq 'storage') { $storageSps[0].Id = $Value } else { $graphSps[0].Id = $Value }
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest } | Should Throw 'CONSENT_ID_INVALID'
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair } | Should Throw 'CONSENT_ID_INVALID'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects identical storage and Graph identities' {
        $graphSps[0].Id = $clientId
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest } | Should Throw 'CONSENT_SP_AMBIGUOUS'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects unexpected Graph consent for injection and repair: <State>' -TestCases @(
        @{ State = 'extra scope' }, @{ State = 'missing scope' }, @{ State = 'wrong case' },
        @{ State = 'extra case variant' },
        @{ State = 'empty scopes' }, @{ State = 'user only' }, @{ State = 'user alongside' },
        @{ State = 'duplicate' }, @{ State = 'principal' }, @{ State = 'missing id' },
        @{ State = 'wrong client' }
    ) {
        param($State)
        switch ($State) {
            'extra scope' { $baseline.Scope += ' Mail.Read' }
            'missing scope' { $baseline.Scope = 'openid profile' }
            'wrong case' { $baseline.Scope = 'openid profile user.read' }
            'extra case variant' { $baseline.Scope += ' user.read' }
            'empty scopes' { $baseline.Scope = '' }
            'user only' { $baseline.ConsentType = 'Principal'; $baseline.PrincipalId = $otherId }
            'user alongside' {
                $script:grants += [pscustomobject]@{
                    Id = 'user-grant'; ClientId = $clientId; ResourceId = $graphId
                    ConsentType = 'Principal'; PrincipalId = $otherId; Scope = 'openid profile User.Read'
                }
            }
            'duplicate' { $script:grants += $baseline }
            'principal' { $baseline.PrincipalId = $otherId }
            'missing id' { $baseline.Id = '' }
            'wrong client' { $baseline.ClientId = $otherId }
        }
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest } | Should Throw 'CONSENT_STATE_UNEXPECTED'
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair } | Should Throw 'CONSENT_STATE_UNEXPECTED'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'rejects malformed grant identities instead of treating them as unrelated' {
        $baseline.ResourceId = ''
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest } | Should Throw 'CONSENT_ID_INVALID'
        $baseline.ResourceId = $graphId
        $baseline.ClientId = [guid]::Empty
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair } | Should Throw 'CONSENT_ID_INVALID'
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'propagates <Stage> failure without mutation' -TestCases @(
        @{ Stage = 'Connect'; Message = 'Connection denied' },
        @{ Stage = 'SP'; Message = 'SP read denied' },
        @{ Stage = 'Read'; Message = 'Grant read denied' }
    ) {
        param($Stage, $Message)
        $script:failure = $Stage
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest } | Should Throw $Message
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair } | Should Throw $Message
        Assert-MockCalled Remove-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
        Assert-MockCalled New-MgOauth2PermissionGrant -Times 0 -Exactly -Scope It
    }

    It 'does not report success on deletion or creation failure' {
        $script:failure = 'Mutation'
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest } | Should Throw 'Deletion denied'
        $script:grants = @($unrelated)
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair } | Should Throw 'Creation denied'
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter {
            $Object -like 'Directory readback confirms*'
        }
    }

    It 'reports unconfirmed readback without retry/rollback: <State>, repair=<Fix>' -TestCases @(
        @{ State = 'lag'; Fix = $false }, @{ State = 'lag'; Fix = $true },
        @{ State = 'read failure'; Fix = $false }, @{ State = 'read failure'; Fix = $true },
        @{ State = 'concurrent'; Fix = $false }, @{ State = 'concurrent'; Fix = $true }
    ) {
        param($State, $Fix)
        if ($Fix) { $script:grants = @($unrelated) }
        switch ($State) {
            'lag' { $script:invisibleMutation = $true }
            'read failure' { $script:failure = 'Readback' }
            'concurrent' { $script:unexpectedReadback = $true }
        }
        { Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair:$Fix } |
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

    It 'gives safe own-user, lab-only cleanup, fresh CIFS and unverified-outcome guidance on no-op too' {
        Invoke-LabConsentFault -StorageAccountName azfcloudtest -Repair
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like '*ALL shares/new requests*OWN disposable*never share*Existing tickets/SMB sessions may survive*PRT or cloud TGT*'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*actual cloud-only lab user logon*whoami /upn*NOT Cloud Shell*'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -eq 'For labshare only: net use \\azfcloudtest.file.core.windows.net\labshare /delete /y'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*same lab user session: klist purge; klist get cifs/azfcloudtest.file.core.windows.net'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like '*Propagation is not guaranteed*live failure/recovery remains unverified*'
        }
    }

    It 'preserves CLI/dispatch and uses target validation before the fault switch' {
        ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') |
            Should Be 'ResourceGroupName,Fault,Repair,Prefix,User'
        $source | Should Match 'Invoke-LabConsentFault -StorageAccountName \$saName -Repair:\$Repair'
        $source.IndexOf('$sa = Get-ConsentLabStorageAccount') | Should BeLessThan $source.IndexOf('switch ($Fault)')
        $source | Should Not Match 'net use \*|capstone|have a partner inject|Only step 4 breaks'
        (Get-Command Invoke-LabConsentFault).Definition | Should Not Match 'Start-Sleep|SilentlyContinue'
    }

    It 'uses terminating errors on every consent SDK operation and complete Graph listings' {
        $commands = $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -match '^(Get-AzStorageAccount|Get-MgServicePrincipal|Get-MgOauth2PermissionGrant|Remove-MgOauth2PermissionGrant|New-MgOauth2PermissionGrant)$'
        }, $true)
        $commands.Count | Should Be 6
        foreach ($command in $commands) {
            $command.Extent.Text | Should Match '-ErrorAction Stop'
            if ($command.GetCommandName() -match '^Get-Mg') { $command.Extent.Text | Should Match '-All' }
        }
    }
}
