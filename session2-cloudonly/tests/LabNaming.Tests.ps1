$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path (Join-Path $root 'scripts') 'CloudOnlyLabNaming.ps1')

function Get-AzContext {
    [CmdletBinding()] param()
    throw 'Unmocked Azure context read'
}
function Get-AzStorageAccount {
    [CmdletBinding()] param($ResourceGroupName)
    throw 'Unmocked storage read'
}

# Execute real entry-point preflights only; exclude all deployment/fault mutations.
$entryPreflights = @{}
foreach ($entry in @('deploy.ps1', 'faults\Invoke-Fault.ps1')) {
    $path = Join-Path $root $entry
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
    $stop = $ast.EndBlock.Statements | Where-Object {
        ($_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$graph') -or
        ($_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Get-ConsentLabStorageAccount')
    } | Select-Object -First 1
    if (-not $stop) { throw "Missing preflight boundary in $entry" }
    $statements = @($ast.EndBlock.Statements | Where-Object { $_.Extent.EndOffset -le $stop.Extent.StartOffset })
    $body = "[CmdletBinding()]`n" + $ast.ParamBlock.Extent.Text + "`n`$PSScriptRoot = '" +
        (Split-Path $path -Parent).Replace("'", "''") + "'`n" +
        (($statements | ForEach-Object { $_.Extent.Text }) -join "`n") + "`nreturn `$Prefix"
    $entryPreflights[$entry] = [scriptblock]::Create($body)

    if ($entry -eq 'deploy.ps1') {
        $deploymentTry = $ast.EndBlock.Statements | Where-Object {
            $_ -is [Management.Automation.Language.TryStatementAst]
        } | Select-Object -First 1
        if (-not $deploymentTry) { throw 'Missing deployment try/finally boundary' }
        $deploymentStatements = $deploymentTry.Body.Statements
        $start = $deploymentStatements | Where-Object {
            $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$accounts'
        } | Select-Object -First 1
        $end = $deploymentStatements | Where-Object {
            $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$sa'
        } | Select-Object -First 1
        if (-not $start -or -not $end) { throw 'Missing storage selection boundaries' }
        $selection = $deploymentStatements | Where-Object {
            $_.Extent.StartOffset -ge $start.Extent.StartOffset -and $_.Extent.EndOffset -le $end.Extent.EndOffset
        }
        $storageSelection = [scriptblock]::Create(
            'param([string]$ResourceGroupName, [string]$Prefix = "azf560970e8")' + "`n" +
            (($selection | ForEach-Object { $_.Extent.Text }) -join "`n") + "`nreturn `$sa"
        )
    }
}

Describe 'Cloud-only automatic naming (offline)' {
    BeforeEach {
        $script:namingContext = [pscustomobject]@{
            Account = [pscustomobject]@{ Id = 'lee@example.com'; Type = 'User' }
            Tenant = [pscustomobject]@{ Id = '11111111-2222-3333-4444-555555555555' }
            Subscription = [pscustomobject]@{ Id = '22222222-2222-3333-4444-555555555555' }
        }
        $script:namingAccounts = @([pscustomobject]@{ StorageAccountName = 'azf560970e8abcdefgh' })
        $script:namingReadFailure = $false
        Mock Get-AzContext { $script:namingContext }
        Mock Get-AzStorageAccount {
            if ($script:namingReadFailure) { throw 'Storage read denied' }
            $script:namingAccounts
        }
        Mock Write-Host {}
    }

    It 'matches the stable SHA-256 vector and all generated name length limits' {
        $prefix = Resolve-CloudOnlyLabPrefix -ResourceGroupName azfiles-cloudonly -AzureContext $namingContext
        $prefix | Should Be 'azf560970e8'
        $prefix | Should Match '^azf[0-9a-f]{8}$'
        ($prefix + '-cli').Length | Should Be 15
        ($prefix + 'abcdefgh').Length | Should BeLessThan 25
        (Resolve-CloudOnlyLabPrefix -ResourceGroupName azfiles-cloudonly -AzureContext $namingContext) |
            Should Be $prefix
    }

    It 'normalizes account and resource group case without using HOME or USERNAME' {
        $namingContext.Account.Id = ' LEE@EXAMPLE.COM '
        Resolve-CloudOnlyLabPrefix -ResourceGroupName ' AZFILES-CLOUDONLY ' -AzureContext $namingContext |
            Should Be 'azf560970e8'
        (Get-Command Resolve-CloudOnlyLabPrefix).Definition | Should Not Match '\$HOME|\$env:'
    }

    It 'separates different <Field> values' -TestCases @(
        @{ Field = 'account' }, @{ Field = 'tenant' }, @{ Field = 'subscription' }, @{ Field = 'resource group' }
    ) {
        param($Field)
        $rg = 'azfiles-cloudonly'
        switch ($Field) {
            'account' { $namingContext.Account.Id = 'other@example.com' }
            'tenant' { $namingContext.Tenant.Id = '33333333-2222-3333-4444-555555555555' }
            'subscription' { $namingContext.Subscription.Id = '33333333-2222-3333-4444-555555555555' }
            'resource group' { $rg = 'another-lab' }
        }
        Resolve-CloudOnlyLabPrefix -ResourceGroupName $rg -AzureContext $namingContext |
            Should Not Be 'azf560970e8'
    }

    It 'rejects incomplete or non-user identity: <State>' -TestCases @(
        @{ State = 'no context' }, @{ State = 'no account' }, @{ State = 'blank account' },
        @{ State = 'service principal' }, @{ State = 'managed identity' }
    ) {
        param($State)
        switch ($State) {
            'no context' { $script:namingContext = $null }
            'no account' { $namingContext.Account = $null }
            'blank account' { $namingContext.Account.Id = ' ' }
            'service principal' { $namingContext.Account.Type = 'ServicePrincipal' }
            'managed identity' { $namingContext.Account.Type = 'ManagedService' }
        }
        { Resolve-CloudOnlyLabPrefix -ResourceGroupName azfiles-cloudonly -AzureContext $namingContext } |
            Should Throw 'CLOUD_PREFIX_IDENTITY_REQUIRED'
    }

    It 'rejects invalid <Field>' -TestCases @(
        @{ Field = 'tenant' }, @{ Field = 'subscription' }, @{ Field = 'empty guid' }, @{ Field = 'resource group' }
    ) {
        param($Field)
        $rg = 'azfiles-cloudonly'
        switch ($Field) {
            'tenant' { $namingContext.Tenant.Id = 'not-a-guid' }
            'subscription' { $namingContext.Subscription.Id = '' }
            'empty guid' { $namingContext.Tenant.Id = [guid]::Empty }
            'resource group' { $rg = ' ' }
        }
        { Resolve-CloudOnlyLabPrefix -ResourceGroupName $rg -AzureContext $namingContext } |
            Should Throw 'CLOUD_PREFIX_CONTEXT_INVALID'
    }

    It 'preserves explicit legacy/custom prefixes without depending on the current user' {
        Resolve-CloudOnlyLabPrefix -ResourceGroupName azfiles-cloudonly -AzureContext $null -Prefix azfcloud |
            Should Be 'azfcloud'
        Resolve-CloudOnlyLabPrefix -ResourceGroupName azfiles-cloudonly -AzureContext $null -Prefix custom01 |
            Should Be 'custom01'
    }

    It 'rejects unsafe explicit prefix <Value>' -TestCases @(
        @{ Value = '' }, @{ Value = ' ' }, @{ Value = '*' }, @{ Value = 'AZFCLOUD' },
        @{ Value = 'azf-cloud' }, @{ Value = 'abcdefghijklmnopqrstuvwxy' }
    ) {
        param($Value)
        { Resolve-CloudOnlyLabPrefix -ResourceGroupName azfiles-cloudonly -AzureContext $namingContext -Prefix $Value } |
            Should Throw 'CLOUD_PREFIX_INVALID'
    }

    It 'resolves the same prefix in real deployment, injection and repair preflights' {
        $deployPrefix = & $entryPreflights['deploy.ps1'] -ResourceGroupName azfiles-cloudonly
        $faultPrefix = & $entryPreflights['faults\Invoke-Fault.ps1'] -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked
        $repairPrefix = & $entryPreflights['faults\Invoke-Fault.ps1'] -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked -Repair
        $deployPrefix | Should Be 'azf560970e8'
        $faultPrefix | Should Be $deployPrefix
        $repairPrefix | Should Be $deployPrefix
        Assert-MockCalled Get-AzStorageAccount -Times 0 -Exactly -Scope It
    }

    It 'preserves an explicit prefix through both real entry points' {
        & $entryPreflights['deploy.ps1'] -ResourceGroupName azfiles-cloudonly -Prefix azfcloud |
            Should Be 'azfcloud'
        & $entryPreflights['faults\Invoke-Fault.ps1'] -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked -Prefix azfcloud |
            Should Be 'azfcloud'
    }

    It 'rejects missing context before either entry point can select a target' {
        $script:namingContext = $null
        { & $entryPreflights['deploy.ps1'] -ResourceGroupName azfiles-cloudonly } | Should Throw 'No Azure context'
        { & $entryPreflights['faults\Invoke-Fault.ps1'] -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked } |
            Should Throw 'No Azure context'
        Assert-MockCalled Get-AzStorageAccount -Times 0 -Exactly -Scope It
    }

    It 'rejects oversized deployment and wildcard fault prefixes at parameter binding' {
        $bindingError = $null
        try {
            & $entryPreflights['deploy.ps1'] -ResourceGroupName azfiles-cloudonly -Prefix abcdefghijkl -ErrorAction Stop | Out-Null
        } catch { $bindingError = $_ }
        $bindingError.FullyQualifiedErrorId | Should Match '^ParameterArgumentValidationError'
        $bindingError = $null
        try {
            & $entryPreflights['faults\Invoke-Fault.ps1'] -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked -Prefix '*' -ErrorAction Stop | Out-Null
        } catch { $bindingError = $_ }
        $bindingError.FullyQualifiedErrorId | Should Match '^ParameterArgumentValidationError'
        Assert-MockCalled Get-AzContext -Times 0 -Exactly -Scope It
    }

    It 'selects only the generated storage prefix and ignores unrelated accounts' {
        $script:namingAccounts += [pscustomobject]@{ StorageAccountName = 'otherparticipant' }
        (& $storageSelection -ResourceGroupName azfiles-cloudonly).StorageAccountName |
            Should Be 'azf560970e8abcdefgh'
    }

    It 'stops rather than silently creating a replacement for the old default lab' {
        $script:namingAccounts = @([pscustomobject]@{ StorageAccountName = 'azfcloudabcdefgh' })
        { & $storageSelection -ResourceGroupName azfiles-cloudonly } | Should Throw 'CLOUD_PREFIX_LEGACY_LAB'
        (& $storageSelection -ResourceGroupName azfiles-cloudonly -Prefix azfcloud).StorageAccountName |
            Should Be 'azfcloudabcdefgh'
    }

    It 'stops on ambiguous storage matches instead of selecting the first' {
        $script:namingAccounts += [pscustomobject]@{ StorageAccountName = 'azf560970e8ijklmnop' }
        { & $storageSelection -ResourceGroupName azfiles-cloudonly } | Should Throw 'CLOUD_STORAGE_AMBIGUOUS'
    }

    It 'propagates a storage listing error rather than treating it as an empty group' {
        $script:namingReadFailure = $true
        { & $storageSelection -ResourceGroupName azfiles-cloudonly } | Should Throw 'Storage read denied'
    }

    It 'allows a genuinely empty resource group to proceed to new storage creation' {
        $script:namingAccounts = @()
        @(& $storageSelection -ResourceGroupName azfiles-cloudonly).Count | Should Be 0
    }
}
