$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts\CloudOnlyDeploymentOutput.ps1')
. (Join-Path $root 'scripts\CloudOnlyDeploymentLog.ps1')
$tokens = $null
$errors = $null
$deployAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $root 'deploy.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$deploymentTry = $deployAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst]
} | Select-Object -First 1
$downloadTail = $deployAst.EndBlock.Statements[-1].Extent.Text
function download {
    [CmdletBinding()] param([string]$Path)
    throw 'Unmocked browser download'
}

Describe 'Cloud-only personalized command output (offline)' {
    BeforeEach {
        $script:info = [ordered]@{
            Status = 'IN PROGRESS'
            'Resource group' = 'my-custom-rg'
            Prefix = 'azftest'
            'Storage account' = 'azftestabcdefgh'
            'File share' = 'custom-share'
            'Azure tenant ID' = 'tenant-test'
            'Subscription ID' = 'subscription-test'
            'Cloud Shell script directory' = "/home/user/owner's lab/session2-cloudonly"
            'User baseline' = 'NOT VERIFIED'
            'Generated password' = 'not-a-real-credential'
        }
    }

    It 'substitutes actual deployment values and both sides of the Consent repair' {
        $text = New-CloudDeploymentCommands -Info $info
        $text | Should Match ([regex]::Escape('$cloudRg = ''my-custom-rg'''))
        $text | Should Match ([regex]::Escape('$shareUnc = ''\\azftestabcdefgh.file.core.windows.net\custom-share'''))
        $text | Should Match ([regex]::Escape('$spn = ''cifs/azftestabcdefgh.file.core.windows.net'''))
        $text | Should Match 'Set-AzContext -Tenant ''tenant-test'' -Subscription ''subscription-test'''
        $text | Should Match 'Debug-AzStorageAccountAuth -ResourceGroupName ''my-custom-rg'' -StorageAccountName ''azftestabcdefgh'''
        $text | Should Match ([regex]::Escape('./faults/Invoke-Fault.ps1 -ResourceGroupName $cloudRg -Prefix $prefix -Fault ConsentRevoked -Repair'))
        $text | Should Not Match '\{\{[A-Z]+\}\}'
    }

    It 'preserves quote dollar and template-like characters as literal values in one substitution pass' {
        $info['Resource group'] = 'owner''s $(throw "do not execute") {{SA}}'
        $text = New-CloudDeploymentCommands -Info $info
        $line = @($text -split "`r?`n" | Where-Object { $_.StartsWith('$cloudRg = ') })[0]
        $ast = [Management.Automation.Language.Parser]::ParseInput($line, [ref]$null, [ref]$null)
        $literal = $ast.Find({
            param($n)
            $n -is [Management.Automation.Language.StringConstantExpressionAst]
        }, $true)
        $literal.Value | Should Be $info['Resource group']
        $text | Should Match ([regex]::Escape("Set-Location -LiteralPath '/home/user/owner''s lab/session2-cloudonly'"))
    }

    It 'rejects incomplete metadata instead of generating incorrect target commands' {
        $info.Remove('Subscription ID')
        { New-CloudDeploymentCommands -Info $info } | Should Throw 'DEPLOY_OUTPUT_MISSING'
    }

    It 'separates every command into a labelled parseable block without prose or comment tokens' {
        $text = New-CloudDeploymentCommands -Info $info
        $pattern = '(?ms)^\[COMMANDS \| (A|B|B-admin) \| ([^\r\n]+)\]\r?\n```powershell\r?\n(.*?)^```\r?$'
        $blocks = [regex]::Matches($text, $pattern)
        $blocks.Count | Should Be 21
        ([regex]::Matches($text, '(?m)^```powershell\r?$')).Count | Should Be $blocks.Count
        ([regex]::Matches($text, '(?m)^```\r?$')).Count | Should Be $blocks.Count
        $commandPattern = '^(\$|Get-|Set-|Import-|Connect-|Debug-|whoami |dsregcmd |klist(?: |$)|net use(?: |$)|netsh |C:\\LabTools\\|\.\/faults\/)'
        $commandCount = 0
        foreach ($block in $blocks) {
            $code = $block.Groups[3].Value
            $parseTokens = $null
            $parseErrors = $null
            $null = [Management.Automation.Language.Parser]::ParseInput($code, [ref]$parseTokens, [ref]$parseErrors)
            if ($parseErrors.Count) { throw "Invalid command block: $code`n$parseErrors" }
            @($parseTokens | Where-Object { $_.Kind -eq 'Comment' }).Count | Should Be 0
            foreach ($line in ($code -split "`r?`n" | Where-Object { $_.Trim() })) {
                $line | Should Match $commandPattern
                $commandCount++
            }
            ([regex]::Matches($code, '-Fault ')).Count -le 1 | Should Be $true
            ([regex]::Matches($code, '/delete')).Count -le 1 | Should Be $true
            $code | Should Not Match '(?s)-StartTrace.*-StopTrace'
            if ($code -match 'C:\\LabTools\\(Invoke-LabFault|Get-KerberosEvidence)') {
                $block.Groups[1].Value | Should Be 'B-admin'
            }
            if ($code -match '\./faults/Invoke-Fault') {
                $block.Groups[1].Value | Should Be 'A'
            }
        }
        ($commandCount -gt 35) | Should Be $true
        foreach ($line in ([regex]::Replace($text, $pattern, '') -split "`r?`n")) {
            $line | Should Not Match $commandPattern
        }
        $text | Should Match '\[COMMENTS / MANUAL ACTIONS\]'
        $text | Should Match 'Copy only the lines INSIDE a COMMANDS code block'
    }

    It 'keeps reboot recovery context boundaries and private trace guidance' {
        $text = New-CloudDeploymentCommands -Info $info
        $text | Should Match 'LAB B REPAIR \[B-admin\]'
        $text | Should Match 'Save work, REBOOT, then sign back in'
        $text | Should Match 'LAB C.*only after B is fully recovered'
        $text | Should Match 'Get-KerberosEvidence.ps1 -StartTrace'
        $text | Should Match 'Get-KerberosEvidence.ps1 -StopTrace'
        $text | Should Match 'Get-KerberosEvidence.ps1 -ConvertTrace'
        $text | Should Match 'Do not commit/share captures or credentials'
        $text | Should Not Match 'net use \* /delete'
        $text | Should Not Match 'Remove-AzResourceGroup.*-Force'
        $text | Should Match 'Module import success is not Azure diagnostic or SMB access success'
    }

    It 'saves personalized commands with final status before requesting either download' {
        Mock Start-Transcript {}
        Mock Stop-Transcript {}
        Mock Write-Host {}
        $logRun = Start-CloudDeploymentLog -LogPath (Join-Path $TestDrive 'logs')
        $logRun.Commands = New-CloudDeploymentCommands -Info $info
        $deploymentInfo = $info
        $rdpPath = Join-Path $TestDrive 'azfiles-cloudonly.rdp'
        'offline-rdp' | Set-Content -LiteralPath $rdpPath
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $deploymentCompleted = $true
        $joined = $true
        $deploymentFailure = $null
        $script:requestedPaths = @()
        Mock Send-CloudDeploymentDownloads {
            $script:requestedPaths = $Paths
            $saved = Get-Content -LiteralPath $Paths[0] -Raw
            $saved | Should Match 'Status : CONFIGURATION APPLIED - USER BASELINE REQUIRED'
            $saved | Should Match 'Finished UTC :'
            $saved | Should Match 'Elapsed :'
            $saved | Should Match 'LAB COMMANDS'
            $saved | Should Match 'PASSWORD : not-a-real-credential'
            $saved | Should Match 'User baseline : NOT VERIFIED'
            Assert-MockCalled Stop-Transcript -Times 1 -Exactly -Scope It
        }
        $finish = [scriptblock]::Create('try {} finally ' + $deploymentTry.Finally.Extent.Text + "`n" + $downloadTail)
        & $finish
        $script:requestedPaths.Count | Should Be 2
        $script:requestedPaths[0] | Should Be $logRun.InfoFile
        $script:requestedPaths[1] | Should Be $rdpPath
    }

    It 'does not request downloads for an unfinished deployment' {
        Mock Send-CloudDeploymentDownloads {}
        $deploymentCompleted = $false
        & ([scriptblock]::Create($downloadTail))
        Assert-MockCalled Send-CloudDeploymentDownloads -Times 0 -Exactly -Scope It
    }

    It 'wires resource identities and command generation into the actual deployment report' {
        $source = $deployAst.Extent.Text
        $source | Should Match ([regex]::Escape('$logRun.Commands = New-CloudDeploymentCommands -Info $deploymentInfo'))
        foreach ($field in @('Azure tenant ID','Subscription ID','VM resource ID','NIC resource ID',
            'Subnet resource ID','OS disk resource ID','Storage resource ID','Share UNC','CIFS SPN',
            'labuser1 object ID','labuser2 object ID','Storage service principal ID','RDP sign-in user')) {
            $source | Should Match ([regex]::Escape("'$field'"))
        }
        $source | Should Match ([regex]::Escape('$deploymentInfo[''RDP sign-in user''] = "labuser1@$initialDomain"'))
        $source | Should Not Match 'sign out/in after'
    }
}

Describe 'Cloud Shell download requests (offline)' {
    BeforeEach {
        $script:downloadUnavailable = $false
        $script:paths = @(
            (Join-Path $TestDrive "owner's [private] output.txt")
            (Join-Path $TestDrive 'azfiles-cloudonly.rdp')
        )
        foreach ($path in $script:paths) { 'offline-test-data' | Set-Content -LiteralPath $path }
        $script:requests = @()
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock download { $script:requests += $Path }
    }

    It 'requests both individual files with literal paths and prints manual fallback' {
        Send-CloudDeploymentDownloads -Paths $script:paths
        $script:requests.Count | Should Be 2
        $script:requests[0] | Should Be $script:paths[0]
        $script:requests[1] | Should Be $script:paths[1]
        Assert-MockCalled Write-Host -Times 2 -Exactly -Scope It -ParameterFilter {
            $Object -like 'Manual Cloud Shell download: download *'
        }
        Assert-MockCalled Write-Host -Times 2 -Exactly -Scope It -ParameterFilter {
            $Object -like 'Browser download requested:*check Downloads*'
        }
    }

    It 'warns outside Cloud Shell while preserving saved files' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'download' -and $script:downloadUnavailable }
        $script:downloadUnavailable = $true
        Send-CloudDeploymentDownloads -Paths $script:paths
        Assert-MockCalled download -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-Warning -Times 2 -Exactly -Scope It -ParameterFilter {
            $Message -like 'DEPLOY_DOWNLOAD_UNAVAILABLE:*'
        }
        foreach ($path in $script:paths) { Test-Path -LiteralPath $path | Should Be $true }
    }

    It 'reports a failed first request and still attempts the RDP file' {
        Mock download {
            $script:requests += $Path
            if ($Path -like '*.txt') { throw 'Browser request rejected' }
        }
        Send-CloudDeploymentDownloads -Paths $script:paths
        $script:requests.Count | Should Be 2
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like 'DEPLOY_DOWNLOAD_FAILED:*Browser request rejected*Retry: download *'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -like 'Browser download requested:*'
        }
    }

    It 'treats nonterminating download errors as visible failed requests' {
        Mock download { Write-Error 'Download transport error' }
        Send-CloudDeploymentDownloads -Paths $script:paths
        Assert-MockCalled Write-Warning -Times 2 -Exactly -Scope It -ParameterFilter {
            $Message -like 'DEPLOY_DOWNLOAD_FAILED:*Download transport error*'
        }
    }

    It 'does not claim an unsaved output can be downloaded' {
        { Send-CloudDeploymentDownloads -Paths (Join-Path $TestDrive 'missing.txt') } |
            Should Throw 'DEPLOY_DOWNLOAD_MISSING'
        Assert-MockCalled download -Times 0 -Exactly -Scope It
    }
}
