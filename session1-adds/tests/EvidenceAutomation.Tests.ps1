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
# Collector stand-ins: never invoke capture, credential logons, UAC or services.
function Test-Admin { $false }
function Start-Capture($Out) { throw 'Unmocked capture' }
function Stop-Capture($Out) { throw 'Unmocked stop' }
function Save-EventLogs($Out) { throw 'Unmocked event collection' }
function Save-SmbState($Out,$Suffix) { throw 'Unmocked SMB collection' }
function Write-JsonFile($Value,$Path) { $Value | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path }
function New-TestConfig {
    [pscustomobject]@{ StorageAccount='labstorage'; Share='labshare'; DomainController='dc.contoso.local'
        ExpectedUserSid='S-1-5-21-1-2-3-1100'; Account='CONTOSO\labuser1'
        Version=2 }
}

Describe 'Automatic evidence validation and boundaries' {
    It 'does not reuse the old Scheduler native helper in an existing PowerShell session' {
        if (-not ('LabEvidence.SafeReader' -as [type])) {
            Add-Type 'namespace LabEvidence { public static class SafeReader { } }'
        }
        Initialize-EvidenceNativeReader
        ([LabEvidence.Direct.SafeReader].GetMethod('Logon') -ne $null) | Should Be $true
    }
    BeforeEach { $script:config = New-TestConfig }
    It 'accepts the fixed nonsecret configuration' { { Assert-EvidenceConfig $config } | Should Not Throw }
    It 'rejects command injection and old configuration versions' {
        $config.StorageAccount = 'lab;whoami'
        { Assert-EvidenceConfig $config } | Should Throw
        $config = New-TestConfig; $config.Version = 1
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
    It 'requires the elevated configured lab account for the coordinator, never SYSTEM' {
        Mock Get-EvidenceIdentity { [pscustomobject]@{ Sid='S-1-5-18'; Admin=$true } }
        { Assert-EvidenceIdentity $config 'Coordinator' } | Should Throw
        { Assert-EvidenceIdentity $config 'Worker' } | Should Throw
        Mock Get-EvidenceIdentity { [pscustomobject]@{ Sid=$config.ExpectedUserSid; Admin=$true } }
        { Assert-EvidenceIdentity $config 'Coordinator' } | Should Not Throw
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
}

Describe 'Local administrator membership versus effective token privileges' {
    BeforeEach {
        $script:config = New-TestConfig
        $script:token = [pscustomobject]@{
            User = [pscustomobject]@{Value=$config.ExpectedUserSid}
            Groups = @(
                [pscustomobject]@{Value='S-1-5-32-544'},
                [pscustomobject]@{Value='S-1-5-21-1-2-3-513'})
        }
    }
    It 'accepts the fixed local administrator with a filtered token in both roles' {
        Mock Get-EvidenceIdentity { ConvertTo-EvidenceIdentity $token $false }
        (Get-EvidenceIdentity).Admin | Should Be $false
        { Assert-EvidenceIdentity $config 'Client' } | Should Not Throw
        { Assert-EvidenceIdentity $config 'Worker' } | Should Not Throw
    }
    It 'rejects an enabled administrator token including when UAC is disabled' {
        Mock Get-EvidenceIdentity { ConvertTo-EvidenceIdentity $token $true }
        (Get-EvidenceIdentity).Admin | Should Be $true
        { Assert-EvidenceIdentity $config 'Client' } | Should Throw
        { Assert-EvidenceIdentity $config 'Worker' } | Should Throw
    }
    It 'still rejects Domain Admins and Enterprise Admins even with filtered tokens' {
        foreach ($rid in @(512,519)) {
            $token.Groups = @([pscustomobject]@{Value="S-1-5-21-1-2-3-$rid"})
            (ConvertTo-EvidenceIdentity $token $false).Admin | Should Be $true
            (Test-EvidenceDomainAdministrator @("S-1-5-21-1-2-3-$rid")) | Should Be $true
        }
    }
    It 'gets the actual token role from Windows without creating or elevating a logon' {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            $expected = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
                (Test-EvidenceDomainAdministrator @($identity.Groups | ForEach-Object Value))
            # Invoke the source body directly; Pester 3 retains this Describe's mocks.
            $definition = $runtimeAst.Find({ param($n)
                $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-EvidenceIdentity'
            },$true)
            $actual = & ($definition.Body.GetScriptBlock())
            $actual.Sid | Should Be $identity.User.Value
            $actual.Admin | Should Be $expected
        } finally { $identity.Dispose() }
    }
    It 'uses the same domain-group rule at installation and keeps the existing UAC convenience' {
        (Test-EvidenceDomainAdministrator @('S-1-5-32-544','S-1-5-21-1-2-3-513')) | Should Be $false
        $resolve = $installerAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-EvidenceAccount'
        },$true).Extent.Text
        $resolve | Should Match 'if \(Test-EvidenceDomainAdministrator \$groups\)'
        $resolve | Should Not Match 'Get-LocalGroupMember|S-1-5-32-544'
        $join = Get-Content (Join-Path $scripts '03-join-domain-client.ps1') -Raw
        $join | Should Match 'Add-LocalGroupMember -Group ''Administrators'''
        $join | Should Not Match 'Remove-LocalGroupMember'
    }
}

Describe 'Direct process launches without credentials, UAC or service changes' {
    BeforeEach {
        $script:InstallRoot = 'C:\Program Files\AzureFilesLabEvidence'
        $script:RuntimeRoot = Join-Path $TestDrive 'runtime'
        $script:run = [guid]::NewGuid().ToString('D')
        $script:secret = 'fixture-$`''"&-' + [char]0x6f22 + [char]0x5b57
        $script:fixtureCredential = [pscredential]::new('CONTOSO\labuser1', (ConvertTo-SecureString $secret -AsPlainText -Force))
        Mock Assert-EvidenceAcl {}
        Mock Start-Process { [pscustomobject]@{Id=123} }
    }
    It 'uses RunAs only for the coordinator, with fixed executable and validated nonsecret arguments' {
        (Start-EvidenceProcess 'Coordinator' $run '0:0x123').Id | Should Be 123
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            $Verb -eq 'RunAs' -and -not $Credential -and
            $FilePath -eq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -and
            $WorkingDirectory -eq $InstallRoot -and $PassThru -and
            $ArgumentList -match '-Mode Coordinator -RunId' -and $ArgumentList -notmatch 'password|labuser1'
        }
    }
    It 'passes special characters only inside PSCredential, never with RunAs or in arguments' {
        Start-EvidenceProcess 'Worker' $run '0:0x123' $fixtureCredential
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            -not $Verb -and $Credential.GetNetworkCredential().Password -ceq $secret -and $LoadUserProfile -and
            $ArgumentList -match '-NoProfile -NonInteractive' -and
            $ArgumentList -match '-Mode Worker -RunId' -and
            $RedirectStandardError -eq (Join-Path (Get-EvidenceRunPaths $run).Capture 'worker-stderr.txt') -and
            -not $ArgumentList.Contains($secret) -and $ArgumentList -notmatch 'password|labuser1'
        }
    }
    It 'rejects argument injection, mixed elevation and credential modes before launch' {
        { Start-EvidenceProcess 'Worker' '..\outside' '0:0x123' $fixtureCredential } | Should Throw
        { Start-EvidenceProcess 'Worker' $run '0:0x123 & whoami' $fixtureCredential } | Should Throw
        { Start-EvidenceProcess 'Coordinator' $run '0:0x123' $fixtureCredential } | Should Throw
        { Start-EvidenceProcess 'Worker' $run '0:0x123' } | Should Throw
        Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
    }
    It 'reports UAC cancellation without requesting capture or a credential logon' {
        Mock Start-Process { throw (New-Object ComponentModel.Win32Exception(1223)) }
        { Start-EvidenceProcess 'Coordinator' $run '0:0x123' } | Should Throw 'UAC consent was cancelled'
    }
    It 'reports credential launch failure without echoing a secret-bearing exception' {
        Mock Start-Process { throw (New-Object ComponentModel.Win32Exception(1326, $script:secret)) }
        try { Start-EvidenceProcess 'Worker' $run '0:0x123' $fixtureCredential; throw 'unexpected success' }
        catch {
            $_.Exception.Message | Should Match 'Worker launch failed'
            $_.Exception.Message.Contains($secret) | Should Be $false
        }
    }
    It 'contains no Scheduler runtime, task registration, password CLI or SendKeys fallback' {
        ($runtimeAst.Extent.Text + $installerAst.Extent.Text) |
            Should Not Match 'Schedule.Service|RegisterTask|NewTask|Get-EvidenceFolder|SendKeys|runas.exe|BatchLogon'
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
        $runtimeAst.Extent.Text | Should Match '\$script:WorkerJob = \[LabEvidence.Direct.SafeReader\]::OwnWorkerProcessTree\(\)'
        $runtimeAst.Extent.Text | Should Not Match '\$script:WorkerJob.Dispose'
        $workerCode = $runtimeAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-EvidenceWorker'
        },$true).Extent.Text
        $workerCode.IndexOf('OwnWorkerProcessTree') | Should BeLessThan $workerCode.IndexOf('Invoke-MountAttempt')
    }
}

Describe 'Explicit legacy migration without touching installed tasks' {
    It 'rejects either exact legacy task before installation' {
        foreach ($name in @('Broker','Worker')) {
            $script:legacy = "C:\Windows\System32\Tasks\AzureFilesLabEvidence\$name"
            Mock Test-Path { param($LiteralPath) $LiteralPath -eq $script:legacy }
            { Assert-NoLegacyEvidenceTasks } | Should Throw 'Legacy evidence tasks exist'
        }
        $installerAst.Extent.Text | Should Not Match 'Unregister-ScheduledTask|Stop-ScheduledTask'
    }
    It 'does not require Scheduler when neither legacy task exists' {
        Mock Test-Path { $false }
        { Assert-NoLegacyEvidenceTasks } | Should Not Throw
    }
    It 'propagates inability to inspect legacy paths' {
        Mock Test-Path { throw 'fixture access denied' }
        { Assert-NoLegacyEvidenceTasks } | Should Throw 'fixture access denied'
    }
}

Describe 'Stored disposable credential round trip using synthetic data only' {
    BeforeEach {
        $script:InstallRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('D'))
        New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'Credentials') -Force | Out-Null
        $script:config = New-TestConfig
        $script:syntheticPassword = 'fixture-$`''"&-' + [char]0x6f22 + [char]0x5b57 + [guid]::NewGuid().ToString('N')
        $script:syntheticCredential = [pscredential]::new($config.Account,
            (ConvertTo-SecureString $syntheticPassword -AsPlainText -Force))
        # Fixture paths only: exercise DPAPI and serialization, not installation/real credential files.
        Mock Assert-EvidencePrivateAcl {}
    }
    It 'round trips Unicode and shell-special characters without writing plaintext or disposing the input' {
        Save-EvidenceCredential $syntheticCredential $config.Account
        $path = Join-Path $InstallRoot 'Credentials\credential.json'
        (Get-Content $path -Raw).Contains($syntheticPassword) | Should Be $false
        $loaded = Read-EvidenceCredential $config
        try {
            $loaded.UserName | Should Be $config.Account
            $loaded.GetNetworkCredential().Password | Should Be $syntheticPassword
            $syntheticCredential.GetNetworkCredential().Password | Should Be $syntheticPassword
        } finally { $loaded.Password.Dispose() }
        @(Get-ChildItem (Split-Path $path -Parent) -Filter '*.new').Count | Should Be 0
    }
    It 'replaces the protected credential for password rotation and verifies the new value' {
        Save-EvidenceCredential $syntheticCredential $config.Account
        $rotated = [pscredential]::new($config.Account, (ConvertTo-SecureString 'rotated-fixture' -AsPlainText -Force))
        Save-EvidenceCredential $rotated $config.Account
        $loaded = Read-EvidenceCredential $config
        try { $loaded.GetNetworkCredential().Password | Should Be 'rotated-fixture' }
        finally { $loaded.Password.Dispose() }
    }
    It 'refuses mismatched account configuration before decrypting' {
        Save-EvidenceCredential $syntheticCredential $config.Account
        $config.Account = 'OTHER\labuser1'
        { Read-EvidenceCredential $config } | Should Throw 'does not match'
    }
    It 'rejects corrupt ciphertext instead of falling back to a password prompt' {
        @{Account=$config.Account; Password='not-base64'} | ConvertTo-Json |
            Set-Content (Join-Path $InstallRoot 'Credentials\credential.json')
        { Read-EvidenceCredential $config } | Should Throw
        $runtimeAst.Extent.Text | Should Not Match 'Get-Credential|Read-Host'
    }
}

Describe 'Credential privacy validation' {
    It 'refuses read access for the non-elevated lab account even when write ACL validation succeeds' {
        Mock Assert-EvidenceAcl {}
        Mock Get-Acl { New-EvidenceAcl 'S-1-5-21-1-2-3-1100' }
        { Assert-EvidencePrivateAcl 'C:\fixture\credential.json' } | Should Throw 'only to Administrators and SYSTEM'
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
            $message = Format-EvidenceInstallFailure $record 'store-lab-credential' $credential
        }
        $message | Should Match 'FAILED step=store-lab-credential; line=\d+; id='
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
            [LabEvidence.Direct.SafeReader]::ProtectDirectoryOnly($root, $fixtureAcl.GetSecurityDescriptorBinaryForm())
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
        $state = [pscustomobject]@{ CoordinatorProcessId=42; CallerLogonId='0:0x123'; RunId='oldrun'; Complete=$true }
        (Test-EvidenceCompletion $state 'newrun' 42 '0:0x123') | Should Be $false
        $state.RunId = 'newrun'
        (Test-EvidenceCompletion $state 'newrun' 43 '0:0x123') | Should Be $false
        (Test-EvidenceCompletion $state 'newrun' 42 '0:0x124') | Should Be $false
        (Test-EvidenceCompletion $state 'newrun' 42 '0:0x123') | Should Be $true
    }
    It 'rejects arbitrary run paths' {
        { Get-EvidenceRunPaths '..\outside' } | Should Throw
        { Get-EvidenceRunPaths ([guid]::NewGuid().ToString('D')) } | Should Not Throw
    }
    It 'preserves mount failure as an observation and drops arbitrary worker fields' {
        $safe = ConvertTo-EvidenceContext $context $config $from $to
        $safe.MountExitCode | Should Be 5
        ($safe.PSObject.Properties.Name -contains 'ArbitraryPath') | Should Be $false
        $safe.ExpectedLogonType | Should Be 'Interactive (2), credential-created'
    }
    It 'rejects mismatched SID, privileged LUID and stale intervals' {
        $context.LogonId='0:0x3e7'
        { ConvertTo-EvidenceContext $context $config $from $to } | Should Throw
        $context.LogonId='0:0x123'; $context.UserSid='S-1-5-18'
        { ConvertTo-EvidenceContext $context $config $from $to } | Should Throw
        $context.UserSid=$config.ExpectedUserSid; $context.EndUtc='2026-09-07T00:00:00Z'
        { ConvertTo-EvidenceContext $context $config $from $to } | Should Throw
    }
    It 'times out the owned process without stopping unrelated processes' {
        $process = [pscustomobject]@{HasExited=$false;Killed=$false}
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $this.Killed }
        $process | Add-Member ScriptMethod Kill { $this.Killed = $true }
        { Wait-EvidenceProcess $process 0 } | Should Throw 'timed out'
        Stop-EvidenceProcess $process
        $process.Killed | Should Be $true
    }
    It 'bounds untrusted reads and pins file and directory handles against link races' {
        $runtimeAst.Extent.Text | Should Match 'stream.Length>maximum'
        $runtimeAst.Extent.Text | Should Match 'i.Links!=1'
        $runtimeAst.Extent.Text | Should Match '0x00200000u'
        $runtimeAst.Extent.Text | Should Match 'CreateFile\(p,0x80000000,directory\?1u:5u'
        $runtimeAst.Extent.Text | Should Match 'session.LogonType!=2'
        $runtimeAst.Extent.Text | Should Match 'session.LogonTime<notBefore'
        $runtimeAst.Extent.Text | Should Match 'String.Equals\(id,caller'
    }
    It 'reads the current native LUID and refuses it as a fresh worker without logging on' {
        $caller = Get-EvidenceLogonId
        $caller | Should Match '^\d+:0x[0-9a-f]+$'
        { [LabEvidence.Direct.SafeReader]::Logon(0, $caller, $true) } | Should Throw
        { [LabEvidence.Direct.SafeReader]::Logon([DateTime]::UtcNow.AddMinutes(1).ToFileTimeUtc(), '', $true) } | Should Throw
    }
    It 'waits for an ordinary short-lived process with no credentials, elevation or capture' {
        $process = [Diagnostics.Process]::new()
        $process.StartInfo.FileName = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $process.StartInfo.Arguments = '-NoProfile -NonInteractive -Command "exit 0"'
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        try {
            $process.Start() | Should Be $true
            Wait-EvidenceProcess $process 15
            $process.ExitCode | Should Be 0
        } finally {
            Stop-EvidenceProcess $process
            $process.Dispose()
        }
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
    It 'bounds retries on a locked state file and preserves the last atomic state' {
        New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
        Write-EvidenceState @{Value='original'}
        $path = Join-Path $RuntimeRoot 'state.json'
        $reader = [IO.File]::Open($path, 'Open', 'Read', 'Read')
        Mock Start-Sleep {}
        try {
            { Write-EvidenceState @{Value='new'} } | Should Throw
            (Read-EvidenceJson $path).Value | Should Be 'original'
            Assert-MockCalled Start-Sleep -Times 5 -Exactly -Scope It
        } finally { $reader.Dispose() }
        Write-EvidenceState @{Value='new'}
        (Read-EvidenceJson $path).Value | Should Be 'new'
    }
}

Describe 'Owned capture lifecycle with isolated fixture writes' {
    BeforeEach {
        $script:RuntimeRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('D'))
        New-Item -ItemType Directory -Path $RuntimeRoot | Out-Null
        $script:config = New-TestConfig
        $script:run = [guid]::NewGuid().ToString('D')
        $script:worker = [pscustomobject]@{Id=123; HasExited=$true; ExitCode=0; Stopped=$false}
        $worker | Add-Member ScriptMethod Kill { $this.Stopped=$true; $this.HasExited=$true }
        $worker | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $this.HasExited }
        $worker | Add-Member ScriptMethod Dispose {}
        Mock Assert-EvidenceIdentity {}
        Mock Read-EvidenceCredential { [pscredential]::new($config.Account, (ConvertTo-SecureString 'fixture' -AsPlainText -Force)) }
        Mock Start-EvidenceProcess { $script:worker }
        Mock New-EvidenceDirectory { param($Path,$Sid,$UserWritable) New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        Mock Read-EvidenceJson { param($Path) Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
        Mock Start-Capture { $true }
        Mock Stop-Capture {}
        Mock Save-EventLogs {}
        Mock Save-SmbState {}
        Mock Wait-EvidenceProcess { throw 'fixture worker timeout' }
    }

    It 'never stops an unowned trace after failed start' {
        Mock Start-Capture { $false }
        { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Throw
        Assert-MockCalled Stop-Capture -Times 0 -Exactly -Scope It
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.CaptureStatus | Should Be 'StartFailed'
        $state.TraceOwned | Should Be $false
    }
    It 'stops its own trace on a worker timeout and preserves failure' {
        $worker.HasExited=$false
        { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Throw
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
        { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Throw
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.TraceOwned | Should Be $true
        $state.CaptureStatus | Should Be 'StopFailed'
        { Invoke-EvidenceCoordinator $config ([guid]::NewGuid().ToString('D')) '0:0x456' } | Should Throw
        Assert-MockCalled Start-Capture -Times 1 -Exactly -Scope It
    }
    It 'accepts a correlated worker mount failure while completing the capture' {
        Mock Wait-EvidenceProcess {
            $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
            $paths = Get-EvidenceRunPaths $state.RunId
            Write-JsonFile @{ RunId=$state.RunId; WorkerProcessId=$state.WorkerProcessId
                UserSid=$config.ExpectedUserSid; Elevated=$false; LogonType=2; LogonId='0:0x123'
                Status='Completed' } (Join-Path $paths.User 'done.json')
            $now = [DateTime]::UtcNow.ToString('o')
            Write-JsonFile @{ StartUtc=$now; EndUtc=$now; UserSid=$config.ExpectedUserSid
                Account=$config.Account; Elevated=$false; LogonId='0:0x123'; StorageAccount=$config.StorageAccount
                Share=$config.Share; ConnectionMode='UNC'; NonInteractive=$true; MountExitCode=5
            } (Join-Path $paths.User 'reproduction.json')
        }
        { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Not Throw
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.Status | Should Be 'Completed'
        $state.MountExitCode | Should Be 5
        $state.CaptureStatus | Should Be 'Stopped'
        Assert-MockCalled Save-EventLogs -Times 1 -Exactly -Scope It
        Assert-MockCalled Stop-Capture -Times 1 -Exactly -Scope It
    }
    It 'rejects a completion from an earlier worker run and still stops capture' {
        Mock Wait-EvidenceProcess {
            $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
            Write-JsonFile @{ RunId='stale'; Status='Completed' } `
                (Join-Path (Get-EvidenceRunPaths $state.RunId).User 'done.json')
        }
        { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Throw
        Assert-MockCalled Stop-Capture -Times 1 -Exactly -Scope It
        Assert-MockCalled Save-EventLogs -Times 0 -Exactly -Scope It
    }
    It 'never writes privileged JSON into the user-writable folder' {
        $coordinator = $runtimeAst.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-EvidenceCoordinator'
        },$true).Extent.Text
        $coordinator | Should Not Match 'Write-JsonFile[^\r\n]*\$paths.User'
        $coordinator | Should Not Match 'Save-DcEvidence|Show-TraceSummary|Invoke-MountAttempt'
        $coordinator | Should Match 'Write-JsonFile \$context \(Join-Path \$paths.Capture'
    }
    It 'does not overlap another coordinator or installer holding the lock' {
        $lock = [IO.File]::Open((Join-Path $RuntimeRoot 'broker.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
        try { { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Throw }
        finally { $lock.Dispose() }
        Assert-MockCalled Start-Capture -Times 0 -Exactly -Scope It
    }
    It 'stops owned capture when credential logon fails' {
        Mock Start-EvidenceProcess { throw 'fixture invalid password' }
        { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Throw
        Assert-MockCalled Stop-Capture -Times 1 -Exactly -Scope It
        (Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json).TraceOwned | Should Be $false
    }
    It 'preserves a cleanup failure and blocks subsequent captures' {
        Mock Stop-EvidenceProcess { throw 'fixture process cleanup failed' }
        { Invoke-EvidenceCoordinator $config $run '0:0x456' } | Should Throw
        $state = Get-Content "$RuntimeRoot\state.json" -Raw | ConvertFrom-Json
        $state.WorkerCleanupFailed | Should Be $true
        { Invoke-EvidenceCoordinator $config ([guid]::NewGuid().ToString('D')) '0:0x456' } | Should Throw
        Assert-MockCalled Start-Capture -Times 1 -Exactly -Scope It
    }
}

Describe 'Original caller results and cancellation with no real process launch' {
    BeforeEach {
        $script:RuntimeRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('D'))
        New-Item -ItemType Directory -Path $RuntimeRoot | Out-Null
        $script:config = New-TestConfig
        $script:fakeCoordinator = [pscustomobject]@{Id=456; ExitCode=0; Finished=$true; Disposed=$false}
        $fakeCoordinator | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $this.Finished }
        $fakeCoordinator | Add-Member ScriptMethod Dispose { $this.Disposed=$true }
        $script:mismatch = $false
        $script:missingResult = $false
        $script:resultStatus = 'Completed'
        Mock Assert-EvidenceIdentity {}
        Mock Get-EvidenceLogonId { '0:0x789' }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Start-EvidenceProcess {
            param($Role,$Id,$Caller)
            $script:lastRunId = $Id
            $paths = Get-EvidenceRunPaths $Id
            New-Item -ItemType Directory -Path $paths.Capture,$paths.User -Force | Out-Null
            'fixture worker result' | Set-Content (Join-Path $paths.User 'worker-output.txt')
            if (-not $script:missingResult) {
                Write-JsonFile @{
                    RunId=$(if ($script:mismatch) { 'stale' } else { $Id })
                    CoordinatorProcessId=456; CallerLogonId=$Caller; Complete=$true
                    Status=$script:resultStatus; CaptureStatus='Stopped'; WorkerStatus='Completed'; MountExitCode=5
                    Error='fixture failure'
                } (Join-Path $paths.Capture 'automation-summary.json')
            }
            $script:fakeCoordinator
        }
    }
    It 'displays the exact completed run and worker output in the original normal caller' {
        { Invoke-EvidenceClient $config } | Should Not Throw
        Assert-MockCalled Write-Host -Scope It -ParameterFilter { "$Object" -match 'fixture worker result' }
        Assert-MockCalled Start-EvidenceProcess -Times 1 -Exactly -Scope It -ParameterFilter { $Role -eq 'Coordinator' }
        $fakeCoordinator.Disposed | Should Be $true
    }
    It 'rejects a stale per-run summary before displaying user-controlled output' {
        $script:mismatch = $true
        { Invoke-EvidenceClient $config } | Should Throw 'does not match'
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter { "$Object" -match 'fixture worker result' }
    }
    It 'fails when the coordinator exits without a result, instead of trusting an older global state' {
        $script:missingResult = $true
        Write-JsonFile @{RunId='old';Complete=$true;Status='Completed';TraceOwned=$false} (Join-Path $RuntimeRoot 'state.json')
        { Invoke-EvidenceClient $config } | Should Throw 'without a result'
    }
    It 'propagates capture failures after displaying the collected partial evidence' {
        $script:resultStatus = 'Failed'
        { Invoke-EvidenceClient $config } | Should Throw 'fixture failure'
        Assert-MockCalled Write-Host -Scope It -ParameterFilter { "$Object" -match 'fixture worker result' }
    }
    It 'bounds caller waiting and leaves coordinator cleanup alone on timeout' {
        $fakeCoordinator.Finished = $false
        { Invoke-EvidenceClient $config } | Should Throw 'Coordinator timed out'
        $fakeCoordinator.Disposed | Should Be $true
        # This process double intentionally has no Kill method.
    }
    It 'propagates cancelled UAC without claiming completion' {
        Mock Start-EvidenceProcess { throw 'UAC consent was cancelled' }
        { Invoke-EvidenceClient $config } | Should Throw 'UAC consent was cancelled'
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter { "$Object" -match 'Capture complete' }
    }
    It 'blocks unresolved ownership before another UAC request' {
        Write-JsonFile @{TraceOwned=$true} (Join-Path $RuntimeRoot 'state.json')
        { Invoke-EvidenceClient $config } | Should Throw 'ownership is unresolved'
        Assert-MockCalled Start-EvidenceProcess -Times 0 -Exactly -Scope It
    }
}
