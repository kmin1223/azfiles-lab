$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$clientPath = Join-Path $root 'scripts\client-config.ps1'
$tokens = $null
$errors = $null
$clientAst = [Management.Automation.Language.Parser]::ParseFile($clientPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($definition in $clientAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst]
}) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
. (Join-Path $root 'scripts\CloudOnlyRunCommand.ps1')
$deploy = Get-Content -LiteralPath (Join-Path $root 'deploy.ps1') -Raw
$configStart = $deploy.IndexOf("Step '6/9 Client configuration")
$configEnd = $deploy.IndexOf('Start-Sleep 45', $configStart)
if ($configStart -lt 0 -or $configEnd -lt 0) { throw 'Deployment configuration/restart section not found' }
$deploymentConfig = [scriptblock]::Create(
    "`$PSScriptRoot = '" + $root.Replace("'", "''") + "'`n" +
    $deploy.Substring($configStart, $configEnd - $configStart))

function Step { param($Message) }
function Save-CloudDeploymentInfo { param($Run, $Info) throw 'Unmocked deployment log' }
function Invoke-AzVMRunCommand {
    [CmdletBinding()] param($ResourceGroupName, $VMName, $CommandId, $ScriptPath, $Parameter)
    throw 'Unmocked Run Command'
}
function Restart-AzVM { [CmdletBinding()] param($ResourceGroupName, $Name) throw 'Unmocked restart' }

Describe 'Capture tool machine installation (offline)' {
    BeforeEach {
        $script:toolExeExists = $false
        $script:inspectorRegistered = $false
        $script:fiddlerRunning = $false
        $script:fiddlerExit = 0
        $script:msiExit = 0
        $script:missingExeAfterInstall = $false
        $script:missingMsiAfterInstall = $false
        $script:shortcutSaved = $false
        $script:toolInstallEvents = @()
        $script:testLink = [pscustomobject]@{ TargetPath = ''; WorkingDirectory = '' }
        $script:testLink | Add-Member -MemberType ScriptMethod -Name Save -Value { $script:shortcutSaved = $true }
        $script:testShell = [pscustomobject]@{}
        $script:testShell | Add-Member -MemberType ScriptMethod -Name CreateShortcut -Value {
            param($path)
            $script:shortcutPath = $path
            $script:testLink
        }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-Process { if ($script:fiddlerRunning) { [pscustomobject]@{ Id = 123 } } }
        Mock Save-LabToolDownload { $script:toolInstallEvents += $Uri }
        Mock Test-Path { $script:toolExeExists } -ParameterFilter { $LiteralPath -like '*\Fiddler.exe' }
        Mock Get-LabInspectorMsi { if ($script:inspectorRegistered) { [pscustomobject]@{ DisplayVersion = '4.5.0.0' } } }
        Mock New-Object { $script:testShell } -ParameterFilter { $ComObject -eq 'WScript.Shell' }
        Mock Start-Process {
            if ($FilePath -like '*msiexec.exe') {
                $script:inspectorRegistered = -not $script:missingMsiAfterInstall
                [pscustomobject]@{ ExitCode = $script:msiExit }
            } else {
                $script:toolExeExists = -not $script:missingExeAfterInstall
                [pscustomobject]@{ ExitCode = $script:fiddlerExit }
            }
        }
    }

    It 'installs to Program Files, publishes a shortcut and uses the real MSI asset without rebooting inside Run Command' {
        Install-LabCaptureTools -ToolsDirectory $TestDrive | Out-Null
        $script:shortcutSaved | Should Be $true
        $script:testLink.TargetPath | Should Be (Join-Path $env:ProgramFiles 'Fiddler\Fiddler.exe')
        $script:shortcutPath | Should Be (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Fiddler Classic (Lab).lnk')
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            $FilePath -like '*FiddlerSetup.exe' -and $Wait -and $PassThru -and
            $ArgumentList -eq "/S /D=$env:ProgramFiles\Fiddler"
        }
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            $FilePath -like '*msiexec.exe' -and $Wait -and $PassThru -and
            $ArgumentList -like '*/qn /norestart /L*v*' -and $ArgumentList -like '*Kerberos.NET-Setup.msi*'
        }
        ($script:toolInstallEvents -join '|') | Should Match 'v4.5.45/Setup.msi'
        ($script:toolInstallEvents -join '|') | Should Not Match 'latest/download/Fiddler.Kerberos.NET.exe'
    }

    It 'reuses verified machine installations but recreates the public shortcut' {
        $script:toolExeExists = $true
        $script:inspectorRegistered = $true
        Install-LabCaptureTools -ToolsDirectory $TestDrive | Out-Null
        $script:shortcutSaved | Should Be $true
        Assert-MockCalled Save-LabToolDownload -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
    }

    It 'stops before downloading or overwriting an active Fiddler installation' {
        $script:fiddlerRunning = $true
        { Install-LabCaptureTools -ToolsDirectory $TestDrive } | Should Throw 'LAB_TOOLS_IN_USE'
        Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
        Assert-MockCalled Save-LabToolDownload -Times 0 -Exactly -Scope It
    }

    It 'reports installer failure rather than printing success: <Kind>' -TestCases @(
        @{ Kind = 'Fiddler'; Expected = 'FIDDLER_INSTALL_FAILED' },
        @{ Kind = 'MSI'; Expected = 'INSPECTOR_INSTALL_FAILED' },
        @{ Kind = 'missing executable'; Expected = 'FIDDLER_INSTALL_MISSING' },
        @{ Kind = 'missing registration'; Expected = 'INSPECTOR_INSTALL_MISSING' }
    ) {
        param($Kind, $Expected)
        switch ($Kind) {
            'Fiddler' { $script:fiddlerExit = 2 }
            'MSI' { $script:msiExit = 1603 }
            'missing executable' { $script:missingExeAfterInstall = $true }
            'missing registration' { $script:missingMsiAfterInstall = $true }
        }
        { Install-LabCaptureTools -ToolsDirectory $TestDrive } | Should Throw $Expected
    }

    It 'accepts MSI reboot-required status while still checking registration' {
        $script:msiExit = 3010
        $output = Install-LabCaptureTools -ToolsDirectory $TestDrive
        ($output -join "`n") | Should Match 'NOT YET VERIFIED'
    }
}

Describe 'Inspector registration and guest output validation (offline)' {
    It 'checks both registry views and rejects unrelated products and versions' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty {
            @(
                [pscustomobject]@{ DisplayName = 'Kerberos.NET Fiddler Extension Machine-Wide Installer'; DisplayVersion = '4.5.0.0' }
                [pscustomobject]@{ DisplayName = 'Kerberos.NET Fiddler Extension Machine-Wide Installer'; DisplayVersion = '4.4.0.0' }
                [pscustomobject]@{ DisplayName = 'Unrelated application'; DisplayVersion = '4.5.0.0' }
            )
        }
        @(Get-LabInspectorMsi).Count | Should Be 2
        Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It -ParameterFilter { $Path -like '*WOW6432Node*' }
        Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It -ParameterFilter { $Path -notlike '*WOW6432Node*' }
    }

    It 'rejects incomplete or failed output: <Kind>' -TestCases @(
        @{ Kind = 'null' }, @{ Kind = 'empty' }, @{ Kind = 'no marker' },
        @{ Kind = 'marker substring' }, @{ Kind = 'stderr with marker' }
    ) {
        param($Kind)
        Mock Write-Host {}
        $guestResult = [pscustomobject]@{ Value = @(
            [pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = 'COMPLETE' }
            [pscustomobject]@{ Code = 'ComponentStatus/StdErr/succeeded'; Message = '' }
        ) }
        switch ($Kind) {
            'null' { $guestResult = $null }
            'empty' { $guestResult.Value = @() }
            'no marker' { $guestResult.Value[0].Message = 'Started' }
            'marker substring' { $guestResult.Value[0].Message = 'NOT_COMPLETE' }
            'stderr with marker' { $guestResult.Value[1].Message = 'Terminating error' }
        }
        { Assert-CloudOnlyRunCommand -Result $guestResult -CompletionMarker COMPLETE } | Should Throw 'CLOUD_CLIENT_CONFIG'
    }
}

Describe 'Capture tool download retries (offline)' {
    BeforeEach {
        $script:downloadCalls = 0
        $script:downloadFailures = 0
        $script:emptyDownload = $false
        Mock Start-Sleep {}
        Mock Write-Warning {}
        Mock Invoke-WebRequest {
            $script:downloadCalls++
            if ($script:downloadCalls -le $script:downloadFailures) {
                Set-Content -LiteralPath $OutFile -Value 'partial'
                throw 'Simulated connection closed'
            }
            if ($script:emptyDownload) { [IO.File]::WriteAllBytes($OutFile, [byte[]]@()) }
            else { Set-Content -LiteralPath $OutFile -Value 'test fixture' }
        }
    }

    It 'retries transient errors and only publishes a completed download' {
        $script:downloadFailures = 2
        $path = Join-Path $TestDrive 'tool.exe'
        Save-LabToolDownload -Uri 'https://example.invalid/tool' -Path $path
        $script:downloadCalls | Should Be 3
        (Get-Content -LiteralPath $path -Raw).Trim() | Should Be 'test fixture'
        Test-Path -LiteralPath "$path.partial" | Should Be $false
    }

    It 'fails after three errors, cleans the partial file and preserves an existing file' {
        $script:downloadFailures = 3
        $path = Join-Path $TestDrive 'previous.exe'
        Set-Content -LiteralPath $path -Value 'previous fixture'
        { Save-LabToolDownload -Uri 'https://example.invalid/tool' -Path $path } | Should Throw 'Simulated connection closed'
        $script:downloadCalls | Should Be 3
        (Get-Content -LiteralPath $path -Raw).Trim() | Should Be 'previous fixture'
        Test-Path -LiteralPath "$path.partial" | Should Be $false
    }

    It 'rejects empty downloads' {
        $script:emptyDownload = $true
        { Save-LabToolDownload -Uri 'https://example.invalid/tool' -Path (Join-Path $TestDrive 'empty.exe') } |
            Should Throw 'Downloaded file is empty'
    }
}

Describe 'Deployment client configuration and restart gate (offline)' {
    BeforeEach {
        $ResourceGroupName = 'test-rg'
        $vmName = 'test-vm'
        $Location = 'koreacentral'
        $deploymentInfo = @{}
        $logRun = $null
        $script:toolCommandResult = [pscustomobject]@{ Value = @(
            [pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = "Details`nCLIENT_CONFIG_DONE`r`n" }
            [pscustomobject]@{ Code = 'ComponentStatus/StdErr/succeeded'; Message = '' }
        ) }
        Mock Save-CloudDeploymentInfo {}
        Mock Invoke-AzVMRunCommand { $script:toolCommandResult }
        Mock Restart-AzVM {}
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'configures the deployment VM and then restarts it exactly once' {
        & $deploymentConfig
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It -ParameterFilter {
            $ResourceGroupName -eq 'test-rg' -and $VMName -eq 'test-vm' -and
            $Parameter.DnsSuffix -eq 'koreacentral.cloudapp.azure.com' -and $ScriptPath -eq $clientPath
        }
        Assert-MockCalled Restart-AzVM -Times 1 -Exactly -Scope It -ParameterFilter {
            $ResourceGroupName -eq 'test-rg' -and $Name -eq 'test-vm'
        }
    }

    It 'does not reboot on missing completion, stderr, or a failed Run Command: <Failure>' -TestCases @(
        @{ Failure = 'marker' }, @{ Failure = 'stderr' }, @{ Failure = 'transport' }
    ) {
        param($Failure)
        switch ($Failure) {
            'marker' { $script:toolCommandResult.Value[0].Message = 'Incomplete installation' }
            'stderr' { $script:toolCommandResult.Value[1].Message = 'Installer failed' }
            'transport' { Mock Invoke-AzVMRunCommand { throw 'Run Command failed' } }
        }
        $failureRecord = $null
        try { & $deploymentConfig }
        catch { $failureRecord = $_ }
        ($null -ne $failureRecord) | Should Be $true
        Assert-MockCalled Restart-AzVM -Times 0 -Exactly -Scope It
    }

    It 'gates full deployment on actual client completion before restart' {
        $deploy = Get-Content -LiteralPath (Join-Path $root 'deploy.ps1') -Raw
        $deploy | Should Match "Assert-CloudOnlyRunCommand -Result .r -CompletionMarker 'CLIENT_CONFIG_DONE'"
        $deploy.IndexOf("Assert-CloudOnlyRunCommand -Result") | Should BeLessThan $deploy.IndexOf('Restart-AzVM')
        $clientAst.Extent.Text | Should Match "IgnoreServerCertErrors' -Value 'False'"
    }

}
