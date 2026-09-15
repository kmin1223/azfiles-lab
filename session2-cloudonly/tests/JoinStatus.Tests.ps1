$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts\CloudOnlyRunCommand.ps1')
. (Join-Path $root 'scripts\CloudOnlyDeploymentLog.ps1')
. (Join-Path $root 'scripts\CloudOnlyDeploymentOutput.ps1')
function Invoke-AzVMRunCommand {
    [CmdletBinding()] param($ResourceGroupName, $VMName, $CommandId, $ScriptString)
    throw 'Unmocked Azure call'
}
function Step { param($Message) }
$deploy = Get-Content -LiteralPath (Join-Path $root 'deploy.ps1') -Raw
$start = $deploy.IndexOf("Step 'Final Entra join check (single attempt)'")
$end = $deploy.IndexOf('# ------------------------------------------------------------------- report')
if ($start -lt 0 -or $end -le $start) { throw 'Final join check must precede report generation' }
$finalCheck = [scriptblock]::Create($deploy.Substring($start, $end - $start))
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($deploy, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$deploymentTry = $ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst]
} | Select-Object -First 1
$finish = [scriptblock]::Create('try {} finally ' + $deploymentTry.Finally.Extent.Text +
    "`n" + $ast.EndBlock.Statements[-1].Extent.Text)

Describe 'Single final Entra join check (offline)' {
    BeforeEach {
        $script:stdout = 'AzureAdJoined : YES'
        $script:stderr = ''
        $script:componentCode = 'ComponentStatus/StdOut/succeeded'
        $script:requestError = $null
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Start-Sleep { throw 'Join check must never sleep' }
        Mock Invoke-AzVMRunCommand {
            if ($script:requestError) { throw $script:requestError }
            [pscustomobject]@{ Value = @(
                [pscustomobject]@{ Code = $script:componentCode; Message = $script:stdout }
                [pscustomobject]@{ Code = 'ComponentStatus/StdErr/succeeded'; Message = $script:stderr }
            ) }
        }
    }

    It 'checks <State> once and returns the observed state without sleeping' -TestCases @(
        @{ State = 'YES'; Expected = $true },
        @{ State = 'NO'; Expected = $false }
    ) {
        param($State, $Expected)
        $script:stdout = "`r`n    AzureAdJoined : $State`r`n"
        $result = Get-CloudOnlyJoinStatus -ResourceGroupName 'lab-rg' -VMName 'lab-cli'
        $result.Joined | Should Be $Expected
        $result.Status | Should Be $State
        $result.CheckedUtc | Should Match 'Z$'
        $result.Error | Should BeNullOrEmpty
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It -ParameterFilter {
            $ResourceGroupName -eq 'lab-rg' -and $VMName -eq 'lab-cli' -and
            $CommandId -eq 'RunPowerShellScript' -and $ScriptString -like '*dsregcmd /status*' -and
            $ScriptString -like '*LASTEXITCODE*'
        }
        Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
    }

    It 'reports an unknown state for <Kind> without retrying or claiming YES' -TestCases @(
        @{ Kind = 'API error' },
        @{ Kind = 'guest stderr' },
        @{ Kind = 'missing output' },
        @{ Kind = 'unrelated output' },
        @{ Kind = 'conflicting output' },
        @{ Kind = 'failed component' }
    ) {
        param($Kind)
        switch ($Kind) {
            'API error' { $script:requestError = 'Run Command unavailable' }
            'guest stderr' { $script:stderr = 'dsregcmd failed' }
            'missing output' { $script:stdout = '' }
            'unrelated output' { $script:stdout = 'Previously AzureAdJoined : YES' }
            'conflicting output' { $script:stdout = "AzureAdJoined : YES`nAzureAdJoined : NO" }
            'failed component' { $script:componentCode = 'ComponentStatus/StdOut/failed' }
        }
        $result = Get-CloudOnlyJoinStatus -ResourceGroupName 'lab-rg' -VMName 'lab-cli'
        $result.Joined | Should Be $false
        $result.Status | Should Be 'UNKNOWN'
        $result.Error | Should Not BeNullOrEmpty
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It
        Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like 'CLOUD_JOIN_CHECK_FAILED:*No retry*'
        }
    }

    It 'persists <State> before still requesting both deployment files' -TestCases @(
        @{ State = 'YES'; ExpectedStatus = 'CONFIGURATION APPLIED - USER BASELINE REQUIRED' },
        @{ State = 'NO'; ExpectedStatus = 'INCOMPLETE - ENTRA JOIN NOT CONFIRMED' },
        @{ State = 'UNKNOWN'; ExpectedStatus = 'INCOMPLETE - ENTRA JOIN NOT CONFIRMED' }
    ) {
        param($State, $ExpectedStatus)
        if ($State -eq 'UNKNOWN') { $script:requestError = 'Run Command permission denied' }
        else { $script:stdout = "AzureAdJoined : $State" }
        Mock Start-Transcript {}
        Mock Stop-Transcript {}
        Mock Send-CloudDeploymentDownloads {}
        $ResourceGroupName = 'lab-rg'
        $vmName = 'lab-cli'
        $deploymentInfo = [ordered]@{ Status = 'IN PROGRESS'; 'User baseline' = 'NOT VERIFIED' }
        $logRun = Start-CloudDeploymentLog -LogPath (Join-Path $TestDrive 'logs')
        $rdpPath = Join-Path $TestDrive 'azfiles-cloudonly.rdp'
        'offline-rdp' | Set-Content -LiteralPath $rdpPath
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $deploymentFailure = $null
        $deploymentCompleted = $true
        $joined = $true
        . $finalCheck
        & $finish
        $saved = Get-Content -LiteralPath $logRun.InfoFile -Raw
        $saved | Should Match ([regex]::Escape("Status : $ExpectedStatus"))
        $saved | Should Match "Entra joined : $State"
        $saved | Should Match 'Entra join checked UTC :'
        $saved | Should Match 'User baseline : NOT VERIFIED'
        if ($State -eq 'UNKNOWN') {
            $saved | Should Match 'Entra join check error : Run Command permission denied'
        }
        Assert-MockCalled Send-CloudDeploymentDownloads -Times 1 -Exactly -Scope It -ParameterFilter {
            $Paths.Count -eq 2 -and $Paths[0] -eq $logRun.InfoFile -and $Paths[1] -eq $rdpPath
        }
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It
    }

    It 'places the sole join query after RBAC and before the report with no old polling loop' {
        $rbac = $deploy.IndexOf("Step '9/9 RBAC'")
        $lastRole = $deploy.LastIndexOf('New-AzRoleAssignment')
        ($rbac -lt $start -and $lastRole -lt $start -and $start -lt $end) | Should Be $true
        ([regex]::Matches($deploy, 'Get-CloudOnlyJoinStatus -ResourceGroupName')).Count | Should Be 1
        $deploy | Should Not Match 'Start-Sleep 30'
        $deploy | Should Not Match 'up to 6 min|after 6 minutes|run command busy, retrying'
        $deploy | Should Not Match 'for \(\$i = 0; \$i -lt 12'
        $deploy | Should Match 'Start-Sleep 45'
        $deploy | Should Match 'Assert-CloudOnlyRunCommand -Result \$r -CompletionMarker ''CLIENT_CONFIG_DONE'''
    }
}
