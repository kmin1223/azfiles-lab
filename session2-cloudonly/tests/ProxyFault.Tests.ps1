$ErrorActionPreference = 'Stop'
$clientPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\client-config.ps1'
$tokens = $null
$errors = $null
$clientAst = [Management.Automation.Language.Parser]::ParseFile($clientPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$payloads = @($clientAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $node.Value.StartsWith('<#') -and $node.Value.Contains('ProxyMangled')
}, $true))
if ($payloads.Count -ne 1) { throw 'Expected exactly one embedded local fault script' }
$faultAst = [Management.Automation.Language.Parser]::ParseInput($payloads[0].Value, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($definition in $faultAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst]
}) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$faultSwitch = $faultAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.SwitchStatementAst]
}
$proxyClause = $faultSwitch.Clauses | Where-Object { $_.Item1.Value -eq 'ProxyMangled' }
$proxyBranch = [scriptblock]::Create(($proxyClause.Item2.Statements.Extent.Text -join "`n"))

# Shadow native programs even if a mock is missing; tests must never change host settings.
function netsh { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) throw 'Unmocked netsh' }
function klist { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) throw 'Unmocked klist' }

Describe 'Cloud-only ProxyMangled repair (offline registry and native mocks)' {
    BeforeEach {
        $script:mgr = 'HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ProxyMgr'
        $script:labKey = "$script:mgr\{lab}"
        $script:entries = @{}
        $script:removed = @()
        $script:nativeCalls = @()
        $script:failure = ''
        $script:readFailure = ''
        $script:retainKey = $false
        $script:nestedKey = ''
        $script:rootExists = $true
        Mock Write-Host {}
        Mock Show {}
        Mock Test-Path {
            if ($LiteralPath -eq $script:mgr) { return $script:rootExists }
            $script:entries.ContainsKey([string]$LiteralPath)
        }
        Mock Get-ChildItem {
            if ($script:readFailure -eq 'enumerate') { throw 'registry enumeration denied' }
            if ($LiteralPath -eq $script:mgr) {
                foreach ($path in @($script:entries.Keys)) { [pscustomobject]@{ PSPath = $path } }
            } elseif ($LiteralPath -eq $script:nestedKey) {
                [pscustomobject]@{ PSPath = "$LiteralPath\unexpected" }
            }
        }
        Mock Get-ItemProperty {
            if ($script:readFailure -eq 'values') { throw 'registry read denied' }
            $script:entries[$LiteralPath]
        }
        Mock Remove-Item {
            $path = [string]$LiteralPath
            if (-not $script:entries.ContainsKey($path)) { throw 'Unexpected deletion path' }
            if ($script:failure -eq 'remove') { throw 'registry deletion denied' }
            $script:removed += $path
            if (-not $script:retainKey) { $script:entries.Remove($path) }
        }
        Mock Invoke-LabProxyNative {
            $call = "$Command $($Arguments -join ' ')"
            $script:nativeCalls += $call
            if ($script:failure -eq $call) { throw "PROXY_COMMAND_FAILED: $call" }
        }
    }

    It 'repairs the reported StaticProxy-only key through the deployed fault branch' {
        $script:entries[$script:labKey] = [pscustomobject]@{
            StaticProxy = 'http=127.0.0.1:8888;https=127.0.0.1:8888'
            ProxyBypass = '<-loopback>'
            LastUseTime = [long]123
        }
        $Repair = $true
        & $proxyBranch
        $script:removed.Count | Should Be 1
        $script:removed[0] | Should Be $script:labKey
        $script:entries.Count | Should Be 0
        ($script:nativeCalls -join '|') | Should Be 'netsh winhttp reset proxy|netsh winhttp reset autoproxy|klist purge'
        Assert-MockCalled Show -Times 1 -Exactly -Scope It
        Assert-MockCalled Remove-Item -Times 1 -Exactly -Scope It -ParameterFilter {
            $LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ProxyMgr\{lab}' -and
            $Force -and -not $Recurse
        }
    }

    It 'matches only the exact lab endpoint: <Value>' -TestCases @(
        @{ Field = 'StaticProxy'; Value = '127.0.0.1:8888'; Match = $true },
        @{ Field = 'StaticProxy'; Value = 'http://127.0.0.1:8888'; Match = $true },
        @{ Field = 'StaticProxy'; Value = ' HTTP=127.0.0.1:8888; HTTPS=127.0.0.1:8888 '; Match = $true },
        @{ Field = 'ConfigurationURL'; Value = 'http://127.0.0.1:8888/proxy.pac'; Match = $true },
        @{ Field = 'StaticProxy'; Value = 'http=proxy.corp.example:8888'; Match = $false },
        @{ Field = 'StaticProxy'; Value = '127.0.0.1:88880'; Match = $false },
        @{ Field = 'StaticProxy'; Value = '127.0.0.1:8899'; Match = $false },
        @{ Field = 'StaticProxy'; Value = 'http://127.0.0.1:8888@proxy.corp.example'; Match = $false },
        @{ Field = 'ConfigurationURL'; Value = 'https://corp.example/proxy.pac?port=8888'; Match = $false },
        @{ Field = 'ConfigurationURL'; Value = 'http://127.0.0.1:88880/proxy.pac'; Match = $false }
    ) {
        param($Field, $Value, $Match)
        $properties = @{}
        $properties[$Field] = $Value
        $script:entries[$script:labKey] = [pscustomobject]$properties
        Repair-LabProxy
        ($script:removed.Count -eq 1) | Should Be $Match
        $script:entries.ContainsKey($script:labKey) | Should Be (-not $Match)
    }

    It 'preserves unrelated keys while removing multiple dedicated lab entries' {
        $script:entries[$script:labKey] = [pscustomobject]@{ StaticProxy = '127.0.0.1:8888' }
        $script:entries["$script:mgr\{pac}"] = [pscustomobject]@{ ConfigurationURL = 'http://127.0.0.1:8888/proxy.pac' }
        $script:entries["$script:mgr\{corp}"] = [pscustomobject]@{ StaticProxy = 'http=proxy.corp.example:8888' }
        $script:entries["$script:mgr\{empty}"] = [pscustomobject]@{ LastUseTime = 123 }
        Repair-LabProxy
        $script:removed.Count | Should Be 2
        $script:entries.ContainsKey("$script:mgr\{corp}") | Should Be $true
        $script:entries.ContainsKey("$script:mgr\{empty}") | Should Be $true
    }

    It 'preserves mixed configurations and stops before any changes: <Kind>' -TestCases @(
        @{ Kind = 'mixed static' }, @{ Kind = 'foreign PAC' }, @{ Kind = 'foreign static' }
    ) {
        param($Kind)
        $values = switch ($Kind) {
            'mixed static' { @{ StaticProxy = 'http=127.0.0.1:8888;https=proxy.corp.example:8080' } }
            'foreign PAC' { @{ StaticProxy = '127.0.0.1:8888'; ConfigurationURL = 'https://corp.example/proxy.pac' } }
            'foreign static' { @{ StaticProxy = 'proxy.corp.example:8080'; ConfigurationURL = 'http://127.0.0.1:8888/proxy.pac' } }
        }
        $script:entries[$script:labKey] = [pscustomobject]$values
        { Repair-LabProxy } | Should Throw 'PROXY_REPAIR_MIXED_CONFIGURATION'
        $script:nativeCalls.Count | Should Be 0
        $script:removed.Count | Should Be 0
        Assert-MockCalled Show -Times 0 -Exactly -Scope It
    }

    It 'refuses to delete an unexpected registry subtree' {
        $script:entries[$script:labKey] = [pscustomobject]@{ StaticProxy = '127.0.0.1:8888' }
        $script:nestedKey = $script:labKey
        { Repair-LabProxy } | Should Throw 'PROXY_REPAIR_UNEXPECTED_CHILDREN'
        $script:removed.Count | Should Be 0
        $script:nativeCalls.Count | Should Be 0
    }

    It 'handles an absent ProxyMgr root and repeated repair without deleting anything' {
        $script:rootExists = $false
        Repair-LabProxy
        Repair-LabProxy
        $script:removed.Count | Should Be 0
        Assert-MockCalled Show -Times 2 -Exactly -Scope It
    }

    It 'does not report success on registry access failure: <Kind>' -TestCases @(
        @{ Kind = 'enumerate' }, @{ Kind = 'values' }
    ) {
        param($Kind)
        $script:entries[$script:labKey] = [pscustomobject]@{ StaticProxy = '127.0.0.1:8888' }
        $script:readFailure = $Kind
        { Repair-LabProxy } | Should Throw 'denied'
        Assert-MockCalled Show -Times 0 -Exactly -Scope It
    }

    It 'does not report success on deletion failure or residue: <Kind>' -TestCases @(
        @{ Kind = 'remove'; Expected = 'registry deletion denied' },
        @{ Kind = 'residue'; Expected = 'PROXY_REPAIR_INCOMPLETE' }
    ) {
        param($Kind, $Expected)
        $script:entries[$script:labKey] = [pscustomobject]@{ StaticProxy = '127.0.0.1:8888' }
        $script:failure = $Kind
        $script:retainKey = $Kind -eq 'residue'
        { Repair-LabProxy } | Should Throw $Expected
        Assert-MockCalled Show -Times 0 -Exactly -Scope It
    }

    It 'does not report success when a required command fails: <Call>' -TestCases @(
        @{ Call = 'netsh winhttp reset proxy' },
        @{ Call = 'netsh winhttp reset autoproxy' },
        @{ Call = 'klist purge' }
    ) {
        param($Call)
        $script:failure = $Call
        { Repair-LabProxy } | Should Throw 'PROXY_COMMAND_FAILED'
        Assert-MockCalled Show -Times 0 -Exactly -Scope It
    }

    It 'also checks injection command failure before showing the fault as applied' {
        $Repair = $false
        $script:failure = 'netsh winhttp set proxy 127.0.0.1:8888'
        { & $proxyBranch } | Should Throw 'PROXY_COMMAND_FAILED'
        Assert-MockCalled Show -Times 0 -Exactly -Scope It
    }
}

Describe 'Proxy native exit handling (offline program stubs)' {
    BeforeEach {
        $script:nativeExit = 0
        Mock Write-Host {}
        Mock netsh { $global:LASTEXITCODE = $script:nativeExit; 'netsh fixture' }
        Mock klist { $global:LASTEXITCODE = $script:nativeExit; 'klist fixture' }
    }

    It 'accepts exit zero for <Command> without invoking real programs' -TestCases @(
        @{ Command = 'netsh' }, @{ Command = 'klist' }
    ) {
        param($Command)
        { Invoke-LabProxyNative -Command $Command -Arguments @('fixture') } | Should Not Throw
    }

    It 'throws on nonzero exit for <Command>' -TestCases @(
        @{ Command = 'netsh' }, @{ Command = 'klist' }
    ) {
        param($Command)
        $script:nativeExit = 1
        { Invoke-LabProxyNative -Command $Command -Arguments @('fixture') } | Should Throw 'PROXY_COMMAND_FAILED'
    }
}
