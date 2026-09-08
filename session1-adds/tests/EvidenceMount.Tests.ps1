$installer = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\07-install-tools.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$assignment = $ast.Find({
    param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$helper'
}, $true)
$source = $assignment.Right.Expression.Value
$helperAst = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($definition in $helperAst.FindAll({
    param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst]
}, $true)) {
    if ($definition.Name -in @('Invoke-NonInteractiveUncMount','Invoke-MountAttempt','Write-JsonFile','Test-Admin','Show-Cmd','Save-SmbState')) {
        . ([scriptblock]::Create($definition.Extent.Text))
    }
}

function New-FakeMountProcess {
    $inputStream = [pscustomobject]@{ Closed = $false }
    $inputStream | Add-Member ScriptMethod Close { $this.Closed = $true }
    $reader = [pscustomobject]@{ Text = 'probe output' }
    $reader | Add-Member ScriptMethod ReadToEndAsync {
        $completion = New-Object 'System.Threading.Tasks.TaskCompletionSource[string]'
        $completion.SetResult($this.Text)
        return $completion.Task
    }
    $fake = [pscustomobject]@{
        StartInfo = [pscustomobject]@{
            FileName = ''; Arguments = ''; UseShellExecute = $true; CreateNoWindow = $false
            RedirectStandardInput = $false; RedirectStandardOutput = $false; RedirectStandardError = $false
            StandardOutputEncoding = $null; StandardErrorEncoding = $null
        }
        StandardInput = $inputStream; StandardOutput = $reader; StandardError = $reader
        Started = $false; Disposed = $false; Killed = $false; Finished = $true
        CanStart = $true; ExitCode = 2
    }
    $fake | Add-Member ScriptMethod Start { $this.Started = $true; return $this.CanStart }
    $fake | Add-Member ScriptMethod WaitForExit { param($milliseconds) return $this.Finished }
    $fake | Add-Member ScriptMethod Kill { $this.Killed = $true; $this.Finished = $true }
    $fake | Add-Member ScriptMethod Dispose { $this.Disposed = $true }
    return $fake
}

Describe 'Bounded noninteractive UNC mount' {
    BeforeEach {
        $script:fake = New-FakeMountProcess
        Mock New-Object { $script:fake } -ParameterFilter { $TypeName -eq 'System.Diagnostics.Process' }
    }
    It 'uses an absolute executable, no drive letter, and closes credential-prompt input' {
        $result = Invoke-NonInteractiveUncMount '\\labstorage.file.core.windows.net\labshare'
        $fake.StartInfo.FileName | Should Be "$env:SystemRoot\System32\net.exe"
        $fake.StartInfo.Arguments | Should Be 'use \\labstorage.file.core.windows.net\labshare /persistent:no'
        $fake.StartInfo.UseShellExecute | Should Be $false
        $fake.StandardInput.Closed | Should Be $true
        $fake.Disposed | Should Be $true
        $fake.Killed | Should Be $false
        $result.ExitCode | Should Be 2
        $result.Output | Should Match 'probe output'
        $result.TimedOut | Should Be $false
    }
    It 'terminates its own timed-out process and preserves the timeout distinction' {
        $fake.Finished = $false
        $result = Invoke-NonInteractiveUncMount '\\labstorage.file.core.windows.net\labshare' -TimeoutSeconds 1
        $fake.Killed | Should Be $true
        $fake.Disposed | Should Be $true
        $result.TimedOut | Should Be $true
    }
    It 'surfaces process creation failure' {
        $fake.CanStart = $false
        { Invoke-NonInteractiveUncMount '\\labstorage.file.core.windows.net\labshare' } | Should Throw
        $fake.Disposed | Should Be $true
    }
    It 'rejects shell syntax and arbitrary UNC targets' {
        { Invoke-NonInteractiveUncMount '\\attacker\share & whoami' } | Should Throw
        { Invoke-NonInteractiveUncMount '\\labstorage.file.core.windows.net\..\share' } | Should Throw
        $fake.Started | Should Be $false
    }
}

function klist { $global:LASTEXITCODE = 0; 'Current LogonId is 0:0x123' }
function net { 'No mappings' }
function cmd { throw 'A drive-mapping command must not run in the automatic path.' }

Describe 'Fresh-session UNC evidence semantics' {
    BeforeEach {
        $script:StorageAccount = 'labstorage'
        $script:Share = 'labshare'
        $script:DriveLetter = 'Z'
        $script:out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory $out | Out-Null
        Mock Test-Admin { $false }
        Mock Show-Cmd {}
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Start-Sleep {}
        Mock Save-SmbState {}
        Mock Invoke-NonInteractiveUncMount {
            [pscustomobject]@{ ExitCode = 2; TimedOut = $false; Output = 'System error 1396 has occurred.' }
        }
    }
    It 'records a failed mount as an observed outcome, not a failed collector' {
        Invoke-MountAttempt $out -NoDriveMapping -NonInteractive
        $context = Get-Content "$out\reproduction.json" -Raw | ConvertFrom-Json
        $context.ConnectionMode | Should Be 'UNC'
        $context.NonInteractive | Should Be $true
        $context.Elevated | Should Be $false
        $context.LogonId | Should Be '0:0x123'
        $context.MountExitCode | Should Be 2
        $context.Error | Should Be ''
        [string]::IsNullOrEmpty($context.EndUtc) | Should Be $false
        Test-Path "$out\mapping-reset.txt" | Should Be $false
        Get-Content "$out\mount-result.txt" -Raw | Should Match '1396'
        Assert-MockCalled Invoke-NonInteractiveUncMount -Times 1 -Exactly -Scope It
    }
    It 'keeps timeout output, after-tickets and a complete error interval' {
        Mock Invoke-NonInteractiveUncMount {
            [pscustomobject]@{ ExitCode = -1; TimedOut = $true; Output = 'partial output' }
        }
        { Invoke-MountAttempt $out -NoDriveMapping -NonInteractive } | Should Throw
        $context = Get-Content "$out\reproduction.json" -Raw | ConvertFrom-Json
        $context.MountTimedOut | Should Be $true
        $context.Error | Should Match 'exceeded'
        [string]::IsNullOrEmpty($context.EndUtc) | Should Be $false
        Test-Path "$out\klist-after.txt" | Should Be $true
    }
    It 'never overwrites an existing reproduction' {
        '{}' | Set-Content "$out\reproduction.json"
        { Invoke-MountAttempt $out -NoDriveMapping -NonInteractive } | Should Throw
        Assert-MockCalled Invoke-NonInteractiveUncMount -Times 0 -Exactly -Scope It
    }
}

Describe 'Automatic entry and manual compatibility' {
    It 'offers a side-effect-free library mode for the protected runtime' {
        $source | Should Match 'ParameterSetName = ''Library'''
        $source | Should Match 'if \(\$Library\) \{ return \}'
        $source.IndexOf('if ($Library) { return }') | Should BeLessThan $source.IndexOf('switch ($PSCmdlet.ParameterSetName)')
    }
    It 'routes default Start through a fixed protected runtime but retains Manual' {
        $source | Should Match 'C:\\Program Files\\AzureFilesLabEvidence\\Invoke-LabEvidenceAutomation.ps1'
        $source | Should Match 'if \(-not \$Manual -and'
        $source | Should Match 'deployment-fixed identity'
        $source | Should Match 'Starting a network trace'
    }
    It 'does not restart Workstation or save a password in the helper' {
        $source | Should Not Match 'Restart-Service'
        $source | Should Not Match 'Export-Clixml|/savecred|Register-ScheduledTask'
    }
}
