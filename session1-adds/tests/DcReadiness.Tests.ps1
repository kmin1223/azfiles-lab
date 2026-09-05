$ErrorActionPreference = 'Stop'
$setupFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\02-create-lab-users.ps1'
$tokens = $null
$parseErrors = $null
$setupAst = [Management.Automation.Language.Parser]::ParseFile($setupFile, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$begin = $setupAst.Find({
    param($node)
    $node -is [Management.Automation.Language.ForEachStatementAst] -and $node.Variable.VariablePath.UserPath -eq 'rule'
}, $true).Extent.StartOffset
$readinessSetup = [scriptblock]::Create(($setupAst.EndBlock.Statements |
    Where-Object { $_.Extent.StartOffset -ge $begin } |
    ForEach-Object { $_.Extent.Text }) -join "`n")

# All configuration writes are mocked; these stubs prevent accidental native calls.
function Get-NetFirewallRule { param($Name, $PolicyStore) throw 'Unmocked firewall read' }
function New-NetFirewallRule {
    param($Name, $DisplayName, $PolicyStore, $Direction, $Action, $Enabled, $Profile,
        $Protocol, $LocalPort, $RemoteAddress, $Program, $Service)
    throw 'Unmocked firewall write'
}
function Set-NetFirewallRule {
    param($Name, $PolicyStore, $Direction, $Action, $Enabled, $Profile,
        $Protocol, $LocalPort, $RemoteAddress, $Program, $Service)
    throw 'Unmocked firewall write'
}
function Get-ItemProperty { param($Path) throw 'Unmocked registry read' }
function New-ItemProperty { param($Path, $Name, $PropertyType, $Value, [switch]$Force) throw 'Unmocked registry write' }
function Invoke-EventUtility { param($Executable, $Arguments) throw 'Unmocked event utility call' }

Describe 'DC evidence firewall and readiness' {
    BeforeEach {
        $script:EvidenceClientAddress = '10.100.0.5'
        $script:knownRules = @{}
        $script:existingLogLevel = 0x20
        Mock Get-NetFirewallRule {
            if ($knownRules.ContainsKey($Name)) { [pscustomobject]@{ Name = $Name } }
        }
        Mock New-NetFirewallRule {
            if ($LocalPort -notin @('RPC', 'RPCEPMap')) { throw "Invalid firewall port: $LocalPort" }
            if ($knownRules.ContainsKey($Name)) { throw "Rule already exists: $Name" }
            $script:knownRules[$Name] = $true
        }
        Mock Set-NetFirewallRule {
            if ($LocalPort -notin @('RPC', 'RPCEPMap')) { throw "Invalid firewall port: $LocalPort" }
            if (-not $knownRules.ContainsKey($Name)) { throw "Rule does not exist: $Name" }
        }
        Mock Get-ItemProperty { [pscustomobject]@{ KdcExtraLogLevel = $existingLogLevel } }
        Mock New-ItemProperty {}
        Mock Invoke-EventUtility {}
        Mock Write-Warning {}
    }

    It 'creates only client-scoped Domain RPC rules with valid service and port pairs' {
        $result = @(& $readinessSetup)
        $result -contains 'DC_EVIDENCE_READY' | Should Be $true
        Assert-MockCalled New-NetFirewallRule -Times 2 -Exactly -Scope It -ParameterFilter {
            $RemoteAddress -eq '10.100.0.5' -and $Profile -eq 'Domain' -and
            $Protocol -eq 'TCP' -and $Direction -eq 'Inbound' -and
            $Action -eq 'Allow' -and $Enabled -eq 'True' -and
            $PolicyStore -eq 'PersistentStore' -and $Program -eq "$env:SystemRoot\System32\svchost.exe"
        }
        Assert-MockCalled New-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'AzureFilesLab-Evidence-EventLog-RPC' -and $LocalPort -eq 'RPC' -and $Service -eq 'eventlog'
        }
        Assert-MockCalled New-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'AzureFilesLab-Evidence-RPC-EPMap' -and $LocalPort -eq 'RPCEPMap' -and $Service -eq 'RpcSs'
        }
    }

    It 'recovers when the RPC rule exists but the endpoint-mapper rule failed earlier' {
        $script:knownRules['AzureFilesLab-Evidence-EventLog-RPC'] = $true
        $result = @(& $readinessSetup)
        $result -contains 'DC_EVIDENCE_READY' | Should Be $true
        Assert-MockCalled Set-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'AzureFilesLab-Evidence-EventLog-RPC' -and $LocalPort -eq 'RPC' -and
            $RemoteAddress -eq '10.100.0.5' -and $Profile -eq 'Domain'
        }
        Assert-MockCalled New-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'AzureFilesLab-Evidence-RPC-EPMap' -and $LocalPort -eq 'RPCEPMap'
        }
    }

    It 'updates existing rules without creating duplicates or broadening client access' {
        & $readinessSetup | Out-Null
        $script:EvidenceClientAddress = '10.100.0.8'
        & $readinessSetup | Out-Null
        $knownRules.Count | Should Be 2
        Assert-MockCalled New-NetFirewallRule -Times 2 -Exactly -Scope It
        Assert-MockCalled Set-NetFirewallRule -Times 2 -Exactly -Scope It -ParameterFilter {
            $RemoteAddress -eq '10.100.0.8' -and $Profile -eq 'Domain' -and
            $Protocol -eq 'TCP' -and $Action -eq 'Allow' -and $Direction -eq 'Inbound'
        }
    }

    It 'enables both Kerberos audits by stable GUID and preserves existing KDC flags' {
        & $readinessSetup | Out-Null
        foreach ($id in '0CCE9240', '0CCE9242') {
            Assert-MockCalled Invoke-EventUtility -Times 1 -Exactly -Scope It -ParameterFilter {
                $Executable -eq 'auditpol' -and $Arguments[1] -like "/subcategory:{$id-*" -and
                $Arguments -contains '/success:enable' -and $Arguments -contains '/failure:enable'
            }
        }
        Assert-MockCalled New-ItemProperty -Times 1 -Exactly -Scope It -ParameterFilter {
            $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -and
            $Name -eq 'KdcExtraLogLevel' -and $PropertyType -eq 'DWord' -and $Value -eq 0x31
        }
    }

    It 'preserves the default KDC flag when no registry override exists' {
        $script:existingLogLevel = $null
        & $readinessSetup | Out-Null
        Assert-MockCalled New-ItemProperty -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'KdcExtraLogLevel' -and $Value -eq 0x13
        }
    }

    It 'does not emit readiness after a firewall failure' {
        Mock New-NetFirewallRule { throw 'Firewall configuration failed' }
        $script:messages = @()
        { & $readinessSetup | ForEach-Object { $script:messages += $_ } } | Should Throw
        $messages -contains 'DC_EVIDENCE_READY' | Should Be $false
        Assert-MockCalled Invoke-EventUtility -Times 0 -Exactly -Scope It
    }

    It 'does not emit readiness after mandatory audit or registry failures' {
        Mock Invoke-EventUtility { throw 'Audit configuration failed' } -ParameterFilter { $Executable -eq 'auditpol' }
        $script:messages = @()
        { & $readinessSetup | ForEach-Object { $script:messages += $_ } } | Should Throw
        $messages -contains 'DC_EVIDENCE_READY' | Should Be $false
        Mock Invoke-EventUtility {} -ParameterFilter { $Executable -eq 'auditpol' }
        Mock New-ItemProperty { throw 'Registry write denied' }
        { & $readinessSetup | ForEach-Object { $script:messages += $_ } } | Should Throw
        $messages -contains 'DC_EVIDENCE_READY' | Should Be $false
    }

    It 'warns for unavailable optional channels without failing mandatory Security setup' {
        Mock Invoke-EventUtility { throw 'Optional channel unavailable' } -ParameterFilter { $Executable -eq 'wevtutil' }
        $result = @(& $readinessSetup)
        $result -contains 'DC_EVIDENCE_READY' | Should Be $true
        Assert-MockCalled Write-Warning -Times 2 -Exactly -Scope It -ParameterFilter {
            $Message -like 'Optional DC channel*'
        }
    }
}
