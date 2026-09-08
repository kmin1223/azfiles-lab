$scripts = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts'
$runtimeFile = Join-Path $scripts 'Invoke-LabEvidenceAutomation.ps1'
$installerFile = Join-Path $scripts 'Install-LabEvidenceAutomation.ps1'
$tokens = $null; $errors = $null
$runtimeAst = [Management.Automation.Language.Parser]::ParseFile($runtimeFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$installerAst = [Management.Automation.Language.Parser]::ParseFile($installerFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($tree in @($runtimeAst,$installerAst)) {
    foreach ($definition in $tree.FindAll({
        param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true)) { . ([scriptblock]::Create($definition.Extent.Text)) }
}
# Collector stand-ins: never load or invoke native capture, Scheduler, identities or services.
function Test-Admin { $false }
function Start-Capture($Out) { throw 'Unmocked capture' }
function Stop-Capture($Out) { throw 'Unmocked stop' }
function Save-EventLogs($Out) { throw 'Unmocked event collection' }
function Save-SmbState($Out,$Suffix) { throw 'Unmocked SMB collection' }
function Write-JsonFile($Value,$Path) { $Value | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path }
function New-TestConfig {
    [pscustomobject]@{ StorageAccount='labstorage'; Share='labshare'; DomainController='dc.contoso.local'
        ExpectedUserSid='S-1-5-21-1-2-3-1100'; Account='CONTOSO\labuser1'
        TaskFolder='\AzureFilesLabEvidence'; BrokerTask='Broker'; WorkerTask='Worker' }
}

Describe 'Automatic evidence validation and boundaries' {
    BeforeEach { $script:config = New-TestConfig }
    It 'accepts the fixed nonsecret configuration' { { Assert-EvidenceConfig $config } | Should Not Throw }
    It 'rejects command injection and arbitrary task names' {
        $config.StorageAccount = 'lab;whoami'
        { Assert-EvidenceConfig $config } | Should Throw
        $config = New-TestConfig; $config.WorkerTask = 'OtherTask'
        { Assert-EvidenceConfig $config } | Should Throw
    }
    It 'rejects SYSTEM and builtin users as the reproduction principal' {
        foreach ($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-21-1-2-3-500')) {
            $config.ExpectedUserSid = $sid
            { Assert-EvidenceConfig $config } | Should Throw
        }
    }
    It 'rejects traversal, alternate streams, UNC and relative paths' {
        foreach ($path in @('..\outside','C:\a\..\outside','C:\a:stream','\\server\share')) {
            { Assert-EvidencePath $path } | Should Throw
        }
    }
    It 'rejects a mocked reparse point before reading its contents' {
        Mock Test-Path { $true }
        Mock Get-Item { [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint } }
        { Assert-EvidencePath 'C:\isolated\link' } | Should Throw
    }
    It 'requires SYSTEM only for the broker' {
        Mock Get-EvidenceIdentity { [pscustomobject]@{ Sid='S-1-5-18'; Admin=$true } }
        { Assert-EvidenceIdentity $config 'Broker' } | Should Not Throw
        { Assert-EvidenceIdentity $config 'Worker' } | Should Throw
    }
    It 'rejects an elevated or wrong-user client and worker' {
        Mock Get-EvidenceIdentity { [pscustomobject]@{ Sid=$config.ExpectedUserSid; Admin=$true } }
        { Assert-EvidenceIdentity $config 'Worker' } | Should Throw
        Mock Get-EvidenceIdentity { [pscustomobject]@{ Sid='S-1-5-21-1-2-3-1101'; Admin=$false } }
        { Assert-EvidenceIdentity $config 'Client' } | Should Throw
    }
    It 'grants write access only on the worker output ACL' {
        $read = New-EvidenceAcl $config.ExpectedUserSid
        $write = New-EvidenceAcl $config.ExpectedUserSid -UserWritable
        ($read.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $config.ExpectedUserSid }).FileSystemRights.ToString() | Should Not Match 'Modify'
        ($write.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $config.ExpectedUserSid }).FileSystemRights.ToString() | Should Match 'Modify'
        $read.AreAccessRulesProtected | Should Be $true
    }
    It 'does not accept unsafe existing task ACLs' {
        $task = [pscustomobject]@{}
        $task | Add-Member ScriptMethod GetSecurityDescriptor { param($Flags) 'O:BAG:BAD:P(A;;GA;;;WD)' }
        { Assert-EvidenceTaskSecurity $task } | Should Throw
    }
}

Describe 'Task definitions without live Scheduler mutations' {
    BeforeEach {
        $script:action = [pscustomobject]@{ Path=''; Arguments=''; WorkingDirectory='' }
        $actions = [pscustomobject]@{}
        $actions | Add-Member ScriptMethod Create { param($Type) $script:action }
        $script:definition = [pscustomobject]@{
            RegistrationInfo=[pscustomobject]@{ Description='' }
            Principal=[pscustomobject]@{ UserId=''; LogonType=0; RunLevel=0 }
            Settings=[pscustomobject]@{ Enabled=$false; AllowDemandStart=$false; AllowHardTerminate=$false; MultipleInstances=0
                ExecutionTimeLimit=''; DisallowStartIfOnBatteries=$true; StopIfGoingOnBatteries=$true
                StartWhenAvailable=$true; RestartCount=9 }
            Actions=$actions
        }
        $script:scheduler = [pscustomobject]@{}
        $scheduler | Add-Member ScriptMethod NewTask { param($Flags) $script:definition }
    }
    It 'uses a password batch worker with least privilege and no retries' {
        $task = New-EvidenceTaskDefinition $scheduler 'Worker' 'CONTOSO\labuser1'
        $task.Principal.LogonType | Should Be 1
        $task.Principal.RunLevel | Should Be 0
        $task.Settings.MultipleInstances | Should Be 2
        $task.Settings.ExecutionTimeLimit | Should Be 'PT3M'
        $task.Settings.RestartCount | Should Be 0
        $task.Settings.AllowHardTerminate | Should Be $true
        $action.Path | Should Be 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $action.Arguments | Should Match '-Mode Worker$'
        $action.Arguments | Should Not Match 'password|credential|StorageAccount|labuser1'
        $action.WorkingDirectory | Should Be 'C:\Program Files\AzureFilesLabEvidence'
    }
    It 'uses a fixed SYSTEM broker action with a bounded lifetime' {
        $task = New-EvidenceTaskDefinition $scheduler 'Broker' 'SYSTEM'
        $task.Principal.LogonType | Should Be 5
        $task.Settings.ExecutionTimeLimit | Should Be 'PT10M'
        $action.Arguments | Should Match '-NoProfile -NonInteractive'
        $action.Arguments | Should Match '-Mode Broker$'
    }
    It 'does not grant worker execute permission or serialize the password' {
        $source = $installerAst.Extent.Text
        $source | Should Match '\$workerSddl = \$baseSddl \+ "\(A;;GR;;;'
        $source | Should Not Match 'Export-Clixml|ConvertFrom-SecureString|Start-Transcript'
        $source | Should Match 'GetNetworkCredential\(\).Password, 1, \$workerSddl'
    }
    It 'leaves the caller-owned credential and SecureString alive' {
        $installerAst.Extent.Text | Should Not Match '\$LabCredential(?:\.Password)?\.Dispose\s*\('
        $installerAst.Extent.Text | Should Not Match '\$LabCredential\s*='
    }
    It 'emits the exact readiness marker only after dispatcher publication' {
        $source = $installerAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Install-EvidenceAutomation'
        },$true).Extent.Text
        $source | Should Match "Write-Output 'AUTO_EVIDENCE_READY'"
        $source | Should Not Match 'AUTO_EVIDENCE_READY:'
        $source.IndexOf('Publish-EvidenceDispatcher') | Should BeLessThan $source.IndexOf("Write-Output 'AUTO_EVIDENCE_READY'")
    }
    It 'owns worker descendants in a non-breakaway kill-on-close job without live job assignment' {
        $runtimeAst.Extent.Text | Should Match 'limits.Basic.Flags=0x2000;'
        $runtimeAst.Extent.Text | Should Match 'AssignProcessToJobObject\(job,GetCurrentProcess\(\)\)'
        $runtimeAst.Extent.Text | Should Match '\$script:WorkerJob = \[LabEvidence.SafeReader\]::OwnWorkerProcessTree\(\)'
        $runtimeAst.Extent.Text | Should Not Match '\$script:WorkerJob.Dispose'
        $workerCode = $runtimeAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-EvidenceWorker'
        },$true).Extent.Text
        $workerCode.IndexOf('OwnWorkerProcessTree') | Should BeLessThan $workerCode.IndexOf('Invoke-MountAttempt')
    }
}

Describe 'Trusted staged collector and dispatcher publication' {
    BeforeEach {
        $fixture = Join-Path $TestDrive ([guid]::NewGuid().ToString('D'))
        $script:stage = Join-Path $fixture 'bootstrap'
        $script:tools = Join-Path $fixture 'LabTools'
        New-Item -ItemType Directory -Path $stage,$tools -Force | Out-Null
        $script:helper = Join-Path $stage 'Get-KerberosEvidence.ps1'
        "'updated dispatcher'" | Set-Content -LiteralPath $helper
        Mock Assert-EvidenceAcl {}
        Mock Assert-EvidenceInstallOwner {}
        Mock Protect-EvidenceToolsRoot {}
        Mock Set-Acl {}
    }
    It 'prefers the staged collector without consulting the mutable legacy helper' {
        (Get-EvidenceCollectorSource $stage) | Should Be $helper
        Remove-Item -LiteralPath $helper
        (Get-EvidenceCollectorSource $stage) | Should Be 'C:\LabTools\Get-KerberosEvidence.ps1'
    }
    It 'publishes only the helper and preserves existing evidence content and ACLs' {
        $evidence = Join-Path $tools 'existing-evidence'
        New-Item -ItemType Directory -Path $evidence | Out-Null
        $artifact = Join-Path $evidence 'trace.txt'
        'preserve me' | Set-Content -LiteralPath $artifact
        $oldAcl = (Get-Acl -LiteralPath $artifact).Sddl
        Publish-EvidenceDispatcher $helper 'S-1-5-21-1-2-3-1100' $tools
        (Get-Content (Join-Path $tools 'Get-KerberosEvidence.ps1') -Raw) | Should Match 'updated dispatcher'
        (Get-Content $artifact -Raw).Trim() | Should Be 'preserve me'
        (Get-Acl -LiteralPath $artifact).Sddl | Should Be $oldAcl
        Assert-MockCalled Protect-EvidenceToolsRoot -Times 1 -Exactly -Scope It -ParameterFilter { $Path -eq $tools }
        Assert-MockCalled Set-Acl -Times 1 -Exactly -Scope It -ParameterFilter {
            $LiteralPath -eq (Join-Path $tools 'Get-KerberosEvidence.ps1') -and $AclObject.AreAccessRulesProtected -and
            @($AclObject.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
                $_.IdentityReference.Value -eq 'S-1-5-32-545' -and
                ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq
                    [Security.AccessControl.FileSystemRights]::ReadAndExecute -and
                ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -eq 0
            }).Count -eq 1
        }
        $runtimeAst.Extent.Text | Should Match 'SetFileSecurity\(path,0x80000004u,descriptor\)'
    }
    It 'normalizes inherited root permissions before requiring a protected root ACL' {
        $script:rootProtected = $false
        $destination = Join-Path $tools 'Get-KerberosEvidence.ps1'
        "'mutable old dispatcher, never executed'" | Set-Content -LiteralPath $destination
        Mock Assert-EvidenceAcl {
            param($Path)
            if ($Path -eq $tools -and -not $script:rootProtected) { throw 'fixture inherited Users Modify' }
        }
        Mock Protect-EvidenceToolsRoot { $script:rootProtected = $true }
        { Publish-EvidenceDispatcher $helper 'S-1-5-21-1-2-3-1100' $tools } | Should Not Throw
        (Get-Content -LiteralPath $destination -Raw) | Should Match 'updated dispatcher'
        Assert-MockCalled Assert-EvidenceInstallOwner -Scope It -ParameterFilter { $Path -eq $tools }
        $publish = $installerAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Publish-EvidenceDispatcher'
        },$true).Extent.Text
        $publish | Should Not Match '::Read\(\$destination'
        $publish.IndexOf('Protect-EvidenceToolsRoot') | Should BeLessThan $publish.IndexOf('Assert-EvidenceAcl $ToolsRoot')
    }
    It 'still refuses untrusted owners before normalizing inherited permissions' {
        Mock Assert-EvidenceInstallOwner { throw 'fixture untrusted owner' }
        { Publish-EvidenceDispatcher $helper 'S-1-5-21-1-2-3-1100' $tools } | Should Throw
        Assert-MockCalled Protect-EvidenceToolsRoot -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-Acl -Times 0 -Exactly -Scope It
    }
    It 'rejects an existing hard-linked dispatcher before changing the root or file' {
        $original = Join-Path $TestDrive 'other-helper.ps1'
        "'old helper'" | Set-Content -LiteralPath $original
        New-Item -ItemType HardLink -Path (Join-Path $tools 'Get-KerberosEvidence.ps1') -Target $original | Out-Null
        { Publish-EvidenceDispatcher $helper 'S-1-5-21-1-2-3-1100' $tools } | Should Throw
        (Get-Content -LiteralPath $original -Raw) | Should Match 'old helper'
        Assert-MockCalled Protect-EvidenceToolsRoot -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-Acl -Times 0 -Exactly -Scope It
    }
    It 'rejects a reparse destination before changing permissions' {
        Mock Assert-EvidencePath { throw 'fixture reparse point' }
        { Publish-EvidenceDispatcher $helper 'S-1-5-21-1-2-3-1100' $tools } | Should Throw
        Assert-MockCalled Protect-EvidenceToolsRoot -Times 0 -Exactly -Scope It
    }
    It 'reports and skips a missing or untrusted optional converter' {
        Mock Write-Warning {}
        $converter = Join-Path $stage 'etl2pcapng.exe'
        @(Get-TrustedEvidenceConverter $converter).Count | Should Be 0
        'fixture, never executable' | Set-Content -LiteralPath $converter
        Mock Assert-EvidenceAcl { throw 'fixture untrusted converter' }
        @(Get-TrustedEvidenceConverter $converter).Count | Should Be 0
        Assert-MockCalled Write-Warning -Times 2 -Exactly -Scope It
    }
    It 'accepts a trusted unlinked converter fixture but skips a hard link' {
        $converter = Join-Path $stage 'etl2pcapng.exe'
        'fixture, never executable' | Set-Content -LiteralPath $converter
        (Get-TrustedEvidenceConverter $converter) | Should Be $converter
        New-Item -ItemType HardLink -Path (Join-Path $stage 'converter-alias.exe') -Target $converter | Out-Null
        @(Get-TrustedEvidenceConverter $converter).Count | Should Be 0
    }
}

Describe 'Bounded installer failure diagnostics' {
    It 'includes stage, numeric source line and error ID without exposing the credential' {
        $secret = 'fixture-password-do-not-print'
        $credential = [pscredential]::new('CONTOSO\labuser1', (ConvertTo-SecureString $secret -AsPlainText -Force))
        try { throw "fixture registration failure: $secret" } catch {
            $record = $_
            $message = Format-EvidenceInstallFailure $record 'register-worker' $credential
        }
        $message | Should Match 'FAILED step=register-worker; line=\d+; id='
        $message | Should Match '\[REDACTED\]'
        $message | Should Not Match $secret
        $credential.GetNetworkCredential().Password | Should Be $secret
        $installerAst.Extent.Text | Should Match 'catch \{ throw \(Format-EvidenceInstallFailure \$_ \$step \$LabCredential\) \}'
    }
    It 'bounds diagnostics and strips control characters without printing invocation source' {
        try { throw ("fixture`r`n" + ('x' * 2000)) } catch {
            $message = Format-EvidenceInstallFailure $_ 'publish-dispatcher' $null
        }
        $message.Length | Should BeLessThan 1020
        $message | Should Not Match '[\r\n]'
        $message | Should Match '\[truncated\]$'
        $formatter = $installerAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Format-EvidenceInstallFailure'
        },$true).Extent.Text
        $formatter | Should Not Match 'PositionMessage|InvocationInfo.Line'
    }
}

Describe 'Isolated inherited root ACL normalization' {
    It 'changes only the fixture root DACL while a real directory guard is held' {
        $root = Join-Path $TestDrive 'native-acl-root'
        New-Item -ItemType Directory -Path $root | Out-Null
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $ownerSid = $identity.User
        $identity.Dispose()
        $fixtureAcl = New-Object Security.AccessControl.DirectorySecurity
        $fixtureAcl.SetAccessRuleProtection($true, $false)
        $fixtureAcl.SetOwner($ownerSid)
        foreach ($entry in @(@($ownerSid.Value,'FullControl'), @('S-1-5-18','FullControl'),
                @('S-1-5-32-544','FullControl'), @('S-1-5-32-545','Modify'))) {
            $fixtureAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                [Security.Principal.SecurityIdentifier]$entry[0], $entry[1],
                'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        $guard = $null
        try {
            Set-Acl -LiteralPath $root -AclObject $fixtureAcl -ErrorAction Stop
            $evidence = Join-Path $root 'existing-evidence'
            New-Item -ItemType Directory -Path $evidence | Out-Null
            $artifact = Join-Path $evidence 'trace.txt'
            'existing evidence' | Set-Content -LiteralPath $artifact
            $evidenceAcl = (Get-Acl -LiteralPath $evidence).Sddl
            $artifactAcl = (Get-Acl -LiteralPath $artifact).Sddl
            Initialize-EvidenceNativeReader
            $guard = Open-EvidenceToolsRoot $root
            Protect-EvidenceToolsRoot $root 'S-1-5-21-1-2-3-1100'
            $normalized = Get-Acl -LiteralPath $root
            $normalized.AreAccessRulesProtected | Should Be $true
            $users = @($normalized.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-545' })
            $users.Count | Should Be 1
            ($users[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) | Should Be 0
            ($users[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) |
                Should Be ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
            (Get-Acl -LiteralPath $evidence).Sddl | Should Be $evidenceAcl
            (Get-Acl -LiteralPath $artifact).Sddl | Should Be $artifactAcl
            (Get-Content -LiteralPath $artifact -Raw).Trim() | Should Be 'existing evidence'
        } finally {
            if ($guard) { $guard.Dispose() }
            # DACL-only restoration needs no SACL/owner privilege under a non-admin test runner.
            [LabEvidence.SafeReader]::ProtectDirectoryOnly($root, $fixtureAcl.GetSecurityDescriptorBinaryForm())
        }
    }
}

Describe 'Run correlation and sanitized worker context' {
    BeforeEach {
        $script:RuntimeRoot = Join-Path $TestDrive 'runtime'
        $script:config = New-TestConfig
        $script:context = [pscustomobject]@{
            UserSid=$config.ExpectedUserSid; Account=$config.Account; Elevated=$false; LogonId='0:0x123'
            StorageAccount=$config.StorageAccount; Share=$config.Share; ConnectionMode='UNC'; NonInteractive=$true
            MountExitCode=5; StartUtc='2026-09-08T00:00:01Z'; EndUtc='2026-09-08T00:00:02Z'
            ArbitraryPath='C:\secret'
        }
        $script:from = [DateTime]::Parse('2026-09-08T00:00:00Z').ToUniversalTime()
        $script:to = $from.AddSeconds(3)
    }
    It 'ignores stale completion and delayed start records' {
        $state = [pscustomobject]@{ BrokerInstanceId='old'; RunId='oldrun'; Complete=$true }
        (Test-EvidenceCompletion $state 'new' 'oldrun') | Should Be $false
        $state.BrokerInstanceId='new'
        (Test-EvidenceCompletion $state 'new' 'oldrun') | Should Be $false
        $state.RunId='newrun'
        (Test-EvidenceCompletion $state 'new' 'oldrun') | Should Be $true
    }
    It 'rejects arbitrary run paths' {
        { Get-EvidenceRunPaths '..\outside' } | Should Throw
        { Get-EvidenceRunPaths ([guid]::NewGuid().ToString('D')) } | Should Not Throw
    }
    It 'preserves mount failure as an observation and drops arbitrary worker fields' {
        $safe = ConvertTo-EvidenceContext $context $config $from $to
        $safe.MountExitCode | Should Be 5
        ($safe.PSObject.Properties.Name -contains 'ArbitraryPath') | Should Be $false
        $safe.ExpectedLogonType | Should Be 'Batch (4)'
    }
    It 'rejects mismatched SID, privileged LUID and stale intervals' {
        $context.LogonId='0:0x3e7'
        { ConvertTo-EvidenceContext $context $config $from $to } | Should Throw
        $context.LogonId='0:0x123'; $context.UserSid='S-1-5-18'
        { ConvertTo-EvidenceContext $context $config $from $to } | Should Throw
        $context.UserSid=$config.ExpectedUserSid; $context.EndUtc='2026-09-07T00:00:00Z'
        { ConvertTo-EvidenceContext $context $config $from $to } | Should Throw
    }
    It 'times out an exact still-running task rather than reading LastTaskResult' {
        $instance = [pscustomobject]@{ State=4 }
        $instance | Add-Member ScriptMethod Refresh {}
        { Wait-EvidenceInstance $instance 0 } | Should Throw
        $runtimeAst.Extent.Text | Should Not Match 'LastTaskResult'
    }
    It 'bounds untrusted reads and pins file and directory handles against link races' {
        $runtimeAst.Extent.Text | Should Match 'stream.Length>maximum'
        $runtimeAst.Extent.Text | Should Match 'i.Links!=1'
        $runtimeAst.Extent.Text | Should Match '0x00200000u'
        $runtimeAst.Extent.Text | Should Match 'CreateFile\(p,0x80000000,directory\?1u:5u'
        $runtimeAst.Extent.Text | Should Match 'session.LogonType!=4'
        $runtimeAst.Extent.Text | Should Match 'session.LogonTime<notBefore'
    }
    It 'reads an isolated JSON fixture and rejects oversized native reads' {
        $path = Join-Path $TestDrive 'bounded.json'
        '{"Value":42}' | Set-Content -LiteralPath $path
        (Read-EvidenceJson $path).Value | Should Be 42
        { Read-EvidenceJson $path 2 } | Should Throw
    }
    It 'rejects a hard-linked user JSON fixture without reading another path' {
        $path = Join-Path $TestDrive 'original.json'
        $link = Join-Path $TestDrive 'linked.json'
        '{"Value":42}' | Set-Content -LiteralPath $path
        New-Item -ItemType HardLink -Path $link -Target $path | Out-Null
        { Read-EvidenceJson $link } | Should Throw
    }
}

Describe 'Owned capture lifecycle with isolated fixture writes' {
    BeforeEach {
        $script:RuntimeRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('D'))
        New-Item -ItemType Directory -Path $RuntimeRoot | Out-Null
        $script:config = New-TestConfig
        $script:worker = [pscustomobject]@{ InstanceGuid=[guid]::NewGuid().ToString('D'); State=0; Stopped=$false }
        $worker | Add-Member ScriptMethod Refresh {}
        $worker | Add-Member ScriptMethod Stop { $this.Stopped=$true; $this.State=0 }
        $script:task = [pscustomobject]@{ State=0 }
        $task | Add-Member ScriptMethod Run { param($Arguments) $script:worker }
        $script:folder = [pscustomobject]@{}
        $folder | Add-Member ScriptMethod GetTask { param($Name) $script:task }
        Mock Assert-EvidenceIdentity {}
        Mock Get-EvidenceFolder { $script:folder }
        Mock Get-EvidenceInstanceId { '00000000-0000-0000-0000-000000000001' }
        Mock New-EvidenceDirectory { param($Path,$Sid,$UserWritable) New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        Mock Read-EvidenceJson { param($Path) Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
        Mock Start-Capture { $true }
        Mock Stop-Capture {}
        Mock Save-EventLogs {}
        Mock Save-SmbState {}
        Mock Wait-EvidenceInstance { param($Instance,$Seconds) if ($Seconds -gt 10) { throw 'fixture worker timeout' } }
    }
    It 'never stops an unowned trace after failed start' {
        Mock Start-Capture { $false }
        { Invoke-EvidenceBroker $config } | Should Throw
        Assert-MockCalled Stop-Capture -Times 0 -Exactly -Scope It
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.CaptureStatus | Should Be 'StartFailed'
        $state.TraceOwned | Should Be $false
    }
    It 'stops its own trace on a worker timeout and preserves failure' {
        $worker.State=4
        { Invoke-EvidenceBroker $config } | Should Throw
        Assert-MockCalled Stop-Capture -Times 1 -Exactly -Scope It
        $worker.Stopped | Should Be $true
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.Status | Should Be 'Failed'
        $state.WorkerStatus | Should Be 'TimedOut'
        $state.Error | Should Match 'timeout'
        $state.TraceOwned | Should Be $false
        Test-Path (Join-Path (Get-EvidenceRunPaths $state.RunId).Capture 'automation-summary.json') | Should Be $true
    }
    It 'retains failed stop ownership and blocks the next run' {
        Mock Stop-Capture { throw 'fixture stop failure' }
        { Invoke-EvidenceBroker $config } | Should Throw
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.TraceOwned | Should Be $true
        $state.CaptureStatus | Should Be 'StopFailed'
        { Invoke-EvidenceBroker $config } | Should Throw
        Assert-MockCalled Start-Capture -Times 1 -Exactly -Scope It
    }
    It 'accepts a correlated worker mount failure while completing the capture' {
        Mock Wait-EvidenceInstance {
            $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
            $paths = Get-EvidenceRunPaths $state.RunId
            Write-JsonFile @{ RunId=$state.RunId; WorkerInstanceId=$state.WorkerInstanceId
                UserSid=$config.ExpectedUserSid; Elevated=$false; LogonType='Batch'; LogonId='0:0x123'
                Status='Completed' } (Join-Path $paths.User 'done.json')
            $now = [DateTime]::UtcNow.ToString('o')
            Write-JsonFile @{ StartUtc=$now; EndUtc=$now; UserSid=$config.ExpectedUserSid
                Account=$config.Account; Elevated=$false; LogonId='0:0x123'; StorageAccount=$config.StorageAccount
                Share=$config.Share; ConnectionMode='UNC'; NonInteractive=$true; MountExitCode=5
            } (Join-Path $paths.User 'reproduction.json')
        }
        { Invoke-EvidenceBroker $config } | Should Not Throw
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.Status | Should Be 'Completed'
        $state.MountExitCode | Should Be 5
        $state.CaptureStatus | Should Be 'Stopped'
        Assert-MockCalled Save-EventLogs -Times 1 -Exactly -Scope It
        Assert-MockCalled Stop-Capture -Times 1 -Exactly -Scope It
    }
    It 'rejects a completion from an earlier worker run and still stops capture' {
        Mock Wait-EvidenceInstance {
            $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
            Write-JsonFile @{ RunId='stale'; Status='Completed' } `
                (Join-Path (Get-EvidenceRunPaths $state.RunId).User 'done.json')
        }
        { Invoke-EvidenceBroker $config } | Should Throw
        Assert-MockCalled Stop-Capture -Times 1 -Exactly -Scope It
        Assert-MockCalled Save-EventLogs -Times 0 -Exactly -Scope It
    }
    It 'never writes privileged JSON into the user-writable folder' {
        $broker = $runtimeAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-EvidenceBroker'
        },$true).Extent.Text
        $broker | Should Not Match 'Write-JsonFile[^\r\n]*\$paths.User'
        $broker | Should Not Match 'Save-DcEvidence|Show-TraceSummary|Invoke-MountAttempt'
        $broker | Should Match 'Write-JsonFile \$context \(Join-Path \$paths.Capture'
    }
}
