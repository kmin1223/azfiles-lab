$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path (Join-Path $root 'scripts') 'CloudOnlyDeploymentLog.ps1')
$tokens = $null
$errors = $null
$deployAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $root 'deploy.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$stepDefinition = $deployAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Step'
}, $true)
. ([scriptblock]::Create($stepDefinition.Extent.Text))
$deploymentTry = $deployAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst]
} | Select-Object -First 1
if (-not $deploymentTry -or -not $deploymentTry.Finally) { throw 'Missing deployment finalizer' }
$failureWrapper = [scriptblock]::Create(
    "try { throw 'Simulated Azure failure' }`n" +
    (($deploymentTry.CatchClauses | ForEach-Object { $_.Extent.Text }) -join "`n") +
    "`nfinally " + $deploymentTry.Finally.Extent.Text
)

Describe 'Cloud-only deployment output (offline)' {
    BeforeEach {
        $script:transcriptStartFailure = $false
        $script:transcriptStopFailure = $false
        Mock Start-Transcript {
            if ($script:transcriptStartFailure) { throw 'Transcript start denied' }
        }
        Mock Stop-Transcript {
            if ($script:transcriptStopFailure) { throw 'Transcript stop failed' }
        }
        Mock Write-Host {}
        Mock Write-Warning {}
        $script:logRun = Start-CloudDeploymentLog -LogPath (Join-Path $TestDrive 'logs')
        $script:deploymentInfo = [ordered]@{
            Status = 'IN PROGRESS'
            Prefix = 'azf560970e8'
            'Generated password' = 'not-a-real-credential'
            'User baseline' = 'NOT VERIFIED'
        }
    }

    It 'formats <Seconds> seconds without rounding minutes or wrapping hours' -TestCases @(
        @{ Seconds = 0; Expected = '00:00:00' },
        @{ Seconds = 59.9; Expected = '00:00:59' },
        @{ Seconds = 90.9; Expected = '00:01:30' },
        @{ Seconds = 3661; Expected = '01:01:01' },
        @{ Seconds = 90061; Expected = '25:01:01' }
    ) {
        param($Seconds, $Expected)
        Format-CloudDeploymentElapsed -Elapsed ([timespan]::FromSeconds($Seconds)) | Should Be $Expected
    }

    It 'creates distinct run folders instead of overwriting a previous output' {
        $second = Start-CloudDeploymentLog -LogPath (Join-Path $TestDrive 'logs')
        $second.Directory | Should Not Be $logRun.Directory
        (Split-Path $logRun.Directory -Leaf) | Should Match '^cloudonly-deploy-\d{8}-\d{6}-[0-9a-f]{8}$'
        Assert-MockCalled Start-Transcript -Times 2 -Exactly -Scope It -ParameterFilter {
            $NoClobber -and $LiteralPath -like '*deploy.log'
        }
    }

    It 'restricts Windows directory access before sensitive output is saved' {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
        $acl = Get-Acl -LiteralPath $logRun.Directory
        $acl.AreAccessRulesProtected | Should Be $true
        $allowed = @(
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            'S-1-5-18'
            'S-1-5-32-544'
        )
        foreach ($rule in $acl.Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            ($allowed -contains $sid) | Should Be $true
        }
    }

    It 'stops when transcript startup fails instead of silently deploying without logs' {
        $script:transcriptStartFailure = $true
        { Start-CloudDeploymentLog -LogPath (Join-Path $TestDrive 'denied') } |
            Should Throw 'Transcript start denied'
    }

    It 'saves a readable in-progress snapshot and replaces it with updated resource details' {
        Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo
        $text = Get-Content -LiteralPath $logRun.InfoFile -Raw
        $text | Should Match 'Status : IN PROGRESS'
        $text | Should Match 'Generated password : not-a-real-credential'
        $text | Should Match 'SENSITIVE'
        $deploymentInfo['Storage account'] = 'azf560970e8abcdefgh'
        Save-CloudDeploymentInfo -Run $logRun -Info $deploymentInfo
        (Get-Content -LiteralPath $logRun.InfoFile -Raw) | Should Match 'Storage account : azf560970e8abcdefgh'
        Test-Path -LiteralPath (Join-Path $logRun.Directory 'lab-info.tmp') | Should Be $false
    }

    It 'records the actual step and prints its elapsed time' {
        $sw = [pscustomobject]@{ Elapsed = [timespan]::FromSeconds(90.9) }
        Step '3/9 Cloud-only Entra users'
        (Get-Content -LiteralPath $logRun.InfoFile -Raw) | Should Match 'Last step : 3/9 Cloud-only Entra users'
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -eq "`n[+00:01:30] === 3/9 Cloud-only Entra users ==="
        }
    }

    It 'records <Expected> with elapsed time and closes the transcript' -TestCases @(
        @{ Completed = $true; Joined = $true; Expected = 'CONFIGURATION APPLIED - USER BASELINE REQUIRED' },
        @{ Completed = $true; Joined = $false; Expected = 'INCOMPLETE - ENTRA JOIN NOT CONFIRMED' },
        @{ Completed = $false; Joined = $false; Expected = 'INTERRUPTED' }
    ) {
        param($Completed, $Joined, $Expected)
        Complete-CloudDeploymentLog -Run $logRun -Info $deploymentInfo -Elapsed ([timespan]::FromSeconds(90.9)) `
            -Completed $Completed -Joined $Joined
        $deploymentInfo['Status'] | Should Be $Expected
        $deploymentInfo['Elapsed'] | Should Be '00:01:30'
        $deploymentInfo['Finished UTC'] | Should Match 'Z$'
        (Get-Content -LiteralPath $logRun.InfoFile -Raw) | Should Match ([regex]::Escape("Status : $Expected"))
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -eq 'Total elapsed : 00:01:30 (hh:mm:ss)'
        }
        Assert-MockCalled Stop-Transcript -Times 1 -Exactly -Scope It
    }

    It 'retains the original deployment failure while saving final status and stopping transcription' {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $deploymentFailure = $null
        $deploymentCompleted = $false
        $joined = $false
        { & $failureWrapper } | Should Throw 'Simulated Azure failure'
        $sw.IsRunning | Should Be $false
        $deploymentInfo['Status'] | Should Be 'FAILED'
        (Get-Content -LiteralPath $logRun.InfoFile -Raw) | Should Match 'Error : Simulated Azure failure'
        Assert-MockCalled Stop-Transcript -Times 1 -Exactly -Scope It
    }

    It 'does not mask the original deployment failure when the info file cannot be saved' {
        $logRun.InfoFile = Join-Path (Join-Path $TestDrive 'missing-parent') 'lab-info.txt'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $deploymentFailure = $null
        $deploymentCompleted = $false
        $joined = $false
        { & $failureWrapper } | Should Throw 'Simulated Azure failure'
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like 'DEPLOY_LOG_FINALIZE_FAILED:*'
        }
        Assert-MockCalled Stop-Transcript -Times 1 -Exactly -Scope It
    }

    It 'fails visibly on a final output write error even after configuration succeeded' {
        $logRun.InfoFile = Join-Path (Join-Path $TestDrive 'missing-parent') 'lab-info.txt'
        $saveError = $null
        try {
            Complete-CloudDeploymentLog -Run $logRun -Info $deploymentInfo -Elapsed ([timespan]::Zero) `
                -Completed $true -Joined $true
        } catch { $saveError = $_ }
        $saveError | Should Not BeNullOrEmpty
        Assert-MockCalled Stop-Transcript -Times 1 -Exactly -Scope It
    }

    It 'reports transcript close errors rather than silently claiming log completion' {
        $script:transcriptStopFailure = $true
        { Complete-CloudDeploymentLog -Run $logRun -Info $deploymentInfo -Elapsed ([timespan]::Zero) `
            -Completed $true -Joined $true } | Should Throw 'Transcript stop failed'
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like 'DEPLOY_LOG_STOP_FAILED:*'
        }
    }

    It 'captures real console output and elapsed time in files in a clean child process' {
        $helperPath = (Join-Path (Join-Path $root 'scripts') 'CloudOnlyDeploymentLog.ps1').Replace("'", "''")
        $parentPath = (Join-Path $TestDrive 'real-transcript').Replace("'", "''")
        $child = @'
param($HelperPath, $LogPath)
$ErrorActionPreference = 'Stop'
. $HelperPath
$run = Start-CloudDeploymentLog -LogPath $LogPath
$info = [ordered]@{ Status = 'IN PROGRESS'; Prefix = 'azftest' }
Write-Host 'OFFLINE SMOKE STEP'
Write-Warning 'OFFLINE SMOKE WARNING'
Complete-CloudDeploymentLog -Run $run -Info $info -Elapsed ([timespan]::FromSeconds(3661)) -Completed $true -Joined $true
'@
        $command = "& { $child } -HelperPath '$helperPath' -LogPath '$parentPath'"
        $executable = (Get-Process -Id $PID).Path
        $output = & $executable -NoProfile -NonInteractive -Command $command 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Offline transcript smoke failed: $output" }
        $folder = @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'real-transcript') -Directory)
        $folder.Count | Should Be 1
        $transcript = Get-Content -LiteralPath (Join-Path $folder[0].FullName 'deploy.log') -Raw
        $transcript | Should Match 'OFFLINE SMOKE STEP'
        $transcript | Should Match 'OFFLINE SMOKE WARNING'
        $transcript | Should Match 'Total elapsed : 01:01:01'
        (Get-Content -LiteralPath (Join-Path $folder[0].FullName 'lab-info.txt') -Raw) |
            Should Match 'Elapsed : 01:01:01'
    }
}
