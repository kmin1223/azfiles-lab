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
$helper = Get-LabTraceHelperContent
$helperAst = [Management.Automation.Language.Parser]::ParseInput($helper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($definition in $helperAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst]
}) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:realTraceNative = (Get-Command Invoke-TraceNative).ScriptBlock

Describe 'Cloud-only trace helper deployment (offline)' {
    BeforeEach {
        $script:installDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:installDirectory | Out-Null
        Mock Write-Output {}
        Mock Save-LabToolDownload { Set-Content -LiteralPath $Path -Value 'offline converter fixture' }
    }

    It 'installs exactly the embedded helper and supported converter through the existing script payload' {
        Install-LabTraceTools -ToolsDirectory $script:installDirectory
        $installed = Join-Path $script:installDirectory 'Get-KerberosEvidence.ps1'
        (Get-Content -LiteralPath $installed -Raw).Trim() | Should Be $helper.Trim()
        (Test-Path -LiteralPath (Join-Path $script:installDirectory 'etl2pcapng.exe')) | Should Be $true
        Assert-MockCalled Save-LabToolDownload -Times 1 -Exactly -Scope It -ParameterFilter {
            $Uri -eq 'https://github.com/microsoft/etl2pcapng/releases/download/v1.11.0/etl2pcapng.exe'
        }
        # deploy.ps1 sends this whole file, not just a path to a VM-side sibling.
        $deploy = Get-Content -LiteralPath (Join-Path $root 'deploy.ps1') -Raw
        $deploy | Should Match "-ScriptPath \(Join-Path \(Join-Path .PSScriptRoot 'scripts'\) 'client-config.ps1'\)"
        $clientAst.Extent.Text.IndexOf('Install-LabTraceTools -ToolsDirectory $tools') |
            Should BeLessThan $clientAst.Extent.Text.LastIndexOf("Write-Output 'CLIENT_CONFIG_DONE'")
    }

    It 'reuses a nonempty converter without downloading' {
        Set-Content -LiteralPath (Join-Path $script:installDirectory 'etl2pcapng.exe') -Value 'existing fixture'
        Install-LabTraceTools -ToolsDirectory $script:installDirectory
        Assert-MockCalled Save-LabToolDownload -Times 0 -Exactly -Scope It
    }

    It 'replaces an empty converter using the retrying downloader' {
        [IO.File]::WriteAllBytes((Join-Path $script:installDirectory 'etl2pcapng.exe'), [byte[]]@())
        Install-LabTraceTools -ToolsDirectory $script:installDirectory
        Assert-MockCalled Save-LabToolDownload -Times 1 -Exactly -Scope It
    }

    It 'fails closed before CLIENT_CONFIG_DONE when provisioning fails: <Kind>' -TestCases @(
        @{ Kind = 'download' }, @{ Kind = 'missing' }, @{ Kind = 'write' }
    ) {
        param($Kind)
        $tools = $script:installDirectory
        $statements = $clientAst.EndBlock.Statements | Where-Object {
            $_.Extent.Text -eq 'Install-LabTraceTools -ToolsDirectory $tools' -or
            $_.Extent.Text -eq "Write-Output 'CLIENT_CONFIG_DONE'"
        }
        @($statements).Count | Should Be 2
        switch ($Kind) {
            'download' { Mock Save-LabToolDownload { throw 'download failed' } }
            'missing' { Mock Save-LabToolDownload {} }
            'write' { Mock Set-Content { throw 'write failed' } -ParameterFilter { $LiteralPath -like '*Get-KerberosEvidence.ps1' } }
        }
        $completionBlock = [scriptblock]::Create(($statements.Extent.Text -join "`n"))
        $failureRecord = $null
        try { & $completionBlock }
        catch { $failureRecord = $_ }
        ($null -ne $failureRecord) | Should Be $true
        Assert-MockCalled Write-Output -Times 0 -Exactly -Scope It -ParameterFilter { $InputObject -eq 'CLIENT_CONFIG_DONE' }
    }

    It 'exposes only StartTrace StopTrace and ConvertTrace with a saved ETL path' {
        ($helperAst.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') |
            Should Be 'StartTrace,StopTrace,ConvertTrace,Path'
        $helper | Should Not Match '(?im)\b(klist|wevtutil|auditpol|Set-ItemProperty|Invoke-WebRequest|Invoke-RestMethod|net use|winhttp)\b'
        $helperAst.EndBlock.Statements[-1].Extent.Text |
            Should Be 'Invoke-LabTraceAction -Action $PSCmdlet.ParameterSetName -Path $Path'
        $helper | Should Match ([regex]::Escape("Get-LocalTracePath -Path 'C:\LabTools\evidence'"))
        $helper | Should Not Match 'AzFilesLab-Traces'
    }
}

Describe 'Trace lifecycle and conversion (offline native mocks)' {
    BeforeEach {
        $script:traceRoot = Join-Path $TestDrive ('Private trace root ' + [guid]::NewGuid().ToString('N'))
        $script:traceFailure = ''
        $script:statusMode = 'owned'
        $script:convertMode = 'good'
        $script:etlMode = 'good'
        $script:traceStopped = $false
        $script:stopIncomplete = $false
        $script:postStopStatus = 'There is no trace session currently in progress.'
        $script:nativeCalls = @()
        $script:lastEtl = $null
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Assert-TraceAdmin {}
        Mock Get-LocalTracePath {
            if ($Path -eq 'C:\LabTools\evidence') { $script:traceRoot } else { $Path }
        }
        Mock Set-PrivateTraceDirectory { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq 'C:\LabTools\etl2pcapng.exe' }
        Mock Get-Item { [pscustomobject]@{ Length = 100 } } -ParameterFilter { $LiteralPath -eq 'C:\LabTools\etl2pcapng.exe' }
        Mock Invoke-TraceNative {
            $script:nativeCalls += ($Arguments -join '|')
            if ($FilePath -like '*netsh.exe') {
                $verb = $Arguments[1]
                if ($script:traceFailure -eq $verb) { throw "mock $verb failed" }
                switch ($verb) {
                    'start' {
                        $script:traceStopped = $false
                        $script:lastEtl = ($Arguments | Where-Object { $_ -like 'tracefile=*' }).Substring(10)
                        if ($script:etlMode -eq 'good') { Set-Content -LiteralPath $script:lastEtl -Value 'etl fixture' }
                        if ($script:etlMode -eq 'empty') { [IO.File]::WriteAllBytes($script:lastEtl, [byte[]]@()) }
                        'started'
                    }
                    'show' {
                        if ($script:traceStopped -and -not $script:stopIncomplete) {
                            return $script:postStopStatus
                        }
                        switch ($script:statusMode) {
                            'owned' { "추적 파일: $script:lastEtl`r`n" }
                            'other' { 'Trace File: C:\Unrelated\trace.etl' }
                            'prefix' { "Trace File: $($script:lastEtl).other" }
                            'idle' { 'There is no trace session currently in progress.' }
                        }
                    }
                    'stop' { $script:traceStopped = $true; 'stopped' }
                }
            } else {
                switch ($script:convertMode) {
                    'good' { Set-Content -LiteralPath $Arguments[1] -Value 'pcap fixture' }
                    'fail' { Set-Content -LiteralPath $Arguments[1] -Value 'partial'; throw 'converter exit 2' }
                    'empty' { [IO.File]::WriteAllBytes($Arguments[1], [byte[]]@()) }
                }
                'converter output'
            }
        }
    }

    It 'starts with no overwrite or implicit stop and stops/converts only its recorded session' {
        $start = Invoke-LabTraceAction -Action Start
        $start | Should Match 'Trace started:'
        $script:nativeCalls[0] | Should Match 'trace\|start\|capture=yes\|report=no\|persistent=no\|overwrite=no\|maxsize=512'
        @($script:nativeCalls | Where-Object { $_ -eq 'trace|stop' }).Count | Should Be 0
        $etl = $script:lastEtl
        $stopped = Invoke-LabTraceAction -Action Stop
        ($stopped -join "`n") | Should Match 'pcapng ready:'
        Test-Path -LiteralPath $etl | Should Be $true
        Test-Path -LiteralPath (Join-Path (Split-Path $etl -Parent) 'trace.pcapng') | Should Be $true
        Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $false
        @($script:nativeCalls | Where-Object { $_ -eq 'trace|stop' }).Count | Should Be 1
        Invoke-LabTraceAction -Action Start | Out-Null
        $script:lastEtl | Should Not Be $etl
    }

    It 'does not silently replace a pending capture' {
        Invoke-LabTraceAction -Action Start | Out-Null
        $etl = $script:lastEtl
        { Invoke-LabTraceAction -Action Start } | Should Throw 'TRACE_PENDING'
        $script:lastEtl | Should Be $etl
        @($script:nativeCalls | Where-Object { $_ -like 'trace|start|*' }).Count | Should Be 1
    }

    It 'requires elevation before doing trace work' {
        Mock Assert-TraceAdmin { throw 'TRACE_ADMIN_REQUIRED' }
        { Invoke-LabTraceAction -Action Start } | Should Throw 'TRACE_ADMIN_REQUIRED'
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_ADMIN_REQUIRED'
        Assert-MockCalled Invoke-TraceNative -Times 0 -Exactly -Scope It
    }

    It 'refuses to stop an unrecorded session' {
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_NO_RUN'
        Assert-MockCalled Invoke-TraceNative -Times 0 -Exactly -Scope It
    }

    It 'refuses unrelated or ambiguous sessions: <Mode>' -TestCases @(
        @{ Mode = 'other' }, @{ Mode = 'prefix' }
    ) {
        param($Mode)
        Invoke-LabTraceAction -Action Start | Out-Null
        $script:statusMode = $Mode
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_SESSION_MISMATCH'
        @($script:nativeCalls | Where-Object { $_ -eq 'trace|stop' }).Count | Should Be 0
        Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $true
    }

    It 'finalizes an already-stopped recorded ETL without issuing another stop' {
        Invoke-LabTraceAction -Action Start | Out-Null
        $script:statusMode = 'idle'
        (Invoke-LabTraceAction -Action Stop) -join "`n" | Should Match 'pcapng ready:'
        @($script:nativeCalls | Where-Object { $_ -eq 'trace|stop' }).Count | Should Be 0
        Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $false
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like 'TRACE_ALREADY_STOPPED:*'
        }
    }

    It 'retains the recorded state if the post-stop result is unrecognized: <Status>' -TestCases @(
        @{ Status = 'Unrecognized status output' },
        @{ Status = 'Trace File: C:\Unrelated\trace.etl' }
    ) {
        param($Status)
        Invoke-LabTraceAction -Action Start | Out-Null
        $script:postStopStatus = $Status
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_STOP_UNCONFIRMED'
        Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $true
        @($script:nativeCalls | Where-Object { $_ -like '*.pcapng' }).Count | Should Be 0
    }

    It 'handles the real native exit-one idle result through the full stop and conversion flow' {
        Mock Invoke-TraceNative {
            & $script:realTraceNative -FilePath $FilePath -Arguments $Arguments `
                -WorkDirectory $WorkDirectory -AllowNoTraceSession:$AllowNoTraceSession
        }
        Mock Start-Process {
            $exitCode = 0
            $stdout = 'native success'
            if ($FilePath -like '*netsh.exe') {
                switch -Regex ($ArgumentList) {
                    '^"trace" "start"' {
                        $script:lastEtl = [regex]::Match($ArgumentList, '"tracefile=([^"]+)"').Groups[1].Value
                        Set-Content -LiteralPath $script:lastEtl -Value 'etl fixture'
                    }
                    '^"trace" "show" "status"$' {
                        if ($script:traceStopped) {
                            $exitCode = 1
                            $stdout = 'There is no trace session currently in progress.'
                        } else {
                            $stdout = "Trace File: $script:lastEtl"
                        }
                    }
                    '^"trace" "stop"$' { $script:traceStopped = $true }
                    default { throw "Unexpected netsh arguments: $ArgumentList" }
                }
            } else {
                $outputPath = [regex]::Matches($ArgumentList, '"([^"]+)"')[1].Groups[1].Value
                Set-Content -LiteralPath $outputPath -Value 'pcap fixture'
            }
            Set-Content -LiteralPath $RedirectStandardOutput -Value $stdout
            Set-Content -LiteralPath $RedirectStandardError -Value ''
            [pscustomobject]@{ ExitCode = $exitCode }
        }
        Invoke-LabTraceAction -Action Start | Out-Null
        (Invoke-LabTraceAction -Action Stop) -join "`n" | Should Match 'pcapng ready:'
        Test-Path -LiteralPath (Join-Path (Split-Path $script:lastEtl -Parent) 'trace.pcapng') | Should Be $true
        Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $false
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            $ArgumentList -eq '"trace" "stop"'
        }
    }

    It 'does not accept a zero start exit without a matching active path' {
        $script:statusMode = 'other'
        { Invoke-LabTraceAction -Action Start } | Should Throw 'TRACE_SESSION_MISMATCH'
        @($script:nativeCalls | Where-Object { $_ -eq 'trace|stop' }).Count | Should Be 0
    }

    It 'retains state and does not convert if a zero stop exit still leaves its trace active' {
        Invoke-LabTraceAction -Action Start | Out-Null
        $script:stopIncomplete = $true
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_STOP_INCOMPLETE'
        Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $true
        @($script:nativeCalls | Where-Object { $_ -like '*.pcapng' }).Count | Should Be 0
    }

    It 'fails on native start or stop errors: <Verb>' -TestCases @(
        @{ Verb = 'start' }, @{ Verb = 'stop' }, @{ Verb = 'show' }
    ) {
        param($Verb)
        if ($Verb -ne 'start') { Invoke-LabTraceAction -Action Start | Out-Null }
        $script:traceFailure = $Verb
        $action = if ($Verb -eq 'start') { 'Start' } else { 'Stop' }
        { Invoke-LabTraceAction -Action $action } | Should Throw "mock $Verb failed"
        if ($Verb -ne 'start') {
            Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $true
        }
        @($script:nativeCalls | Where-Object { $_ -like '*.pcapng' }).Count | Should Be 0
    }

    It 'reports missing or empty ETL after stopping: <Mode>' -TestCases @(
        @{ Mode = 'missing' }, @{ Mode = 'empty' }
    ) {
        param($Mode)
        $script:etlMode = $Mode
        Invoke-LabTraceAction -Action Start | Out-Null
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_ETL_MISSING'
    }

    It 'reports an unavailable converter with the ETL retained: <Kind>' -TestCases @(
        @{ Kind = 'missing' }, @{ Kind = 'empty' }
    ) {
        param($Kind)
        Invoke-LabTraceAction -Action Start | Out-Null
        if ($Kind -eq 'missing') {
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -eq 'C:\LabTools\etl2pcapng.exe' }
        } else {
            Mock Get-Item { [pscustomobject]@{ Length = 0 } } -ParameterFilter { $LiteralPath -eq 'C:\LabTools\etl2pcapng.exe' }
        }
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_CONVERTER_MISSING'
        Test-Path -LiteralPath $script:lastEtl | Should Be $true
    }

    It 'never claims conversion success on a failing empty or absent output: <Mode>' -TestCases @(
        @{ Mode = 'fail' }, @{ Mode = 'empty' }, @{ Mode = 'missing' }
    ) {
        param($Mode)
        Invoke-LabTraceAction -Action Start | Out-Null
        $script:convertMode = $Mode
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_CONVERSION_FAILED'
        Test-Path -LiteralPath $script:lastEtl | Should Be $true
        Test-Path -LiteralPath (Join-Path $script:traceRoot '.active-trace.txt') | Should Be $false
        # A fresh conversion succeeds without touching netsh or overwriting partial data.
        $script:convertMode = 'good'
        $before = $script:nativeCalls.Count
        Invoke-LabTraceAction -Action Convert -Path $script:lastEtl | Out-Null
        $script:nativeCalls.Count | Should Be ($before + 1)
    }

    It 'preserves existing pcapng and retries into a new directory without elevation or netsh' {
        Invoke-LabTraceAction -Action Start | Out-Null
        $pcap = Join-Path (Split-Path $script:lastEtl -Parent) 'trace.pcapng'
        Set-Content -LiteralPath $pcap -Value 'keep original'
        { Invoke-LabTraceAction -Action Stop } | Should Throw 'TRACE_OUTPUT_EXISTS'
        Mock Assert-TraceAdmin { throw 'must not request elevation' }
        Invoke-LabTraceAction -Action Convert -Path $script:lastEtl | Out-Null
        (Get-Content -LiteralPath $pcap -Raw).Trim() | Should Be 'keep original'
        @(Get-ChildItem -LiteralPath $script:traceRoot -Recurse -Filter trace.pcapng).Count | Should Be 2
    }

    It 'refuses to convert its still active capture' {
        Invoke-LabTraceAction -Action Start | Out-Null
        { Invoke-LabTraceAction -Action Convert -Path $script:lastEtl } | Should Throw 'TRACE_STILL_ACTIVE'
    }

    It 'converts a saved legacy ETL into the fixed output root without deleting or moving the source' {
        $legacy = Join-Path $TestDrive 'legacy-profile\AzFilesLab-Traces\old-run'
        New-Item -ItemType Directory -Path $legacy -Force | Out-Null
        $etl = Join-Path $legacy 'trace.etl'
        Set-Content -LiteralPath $etl -Value 'legacy etl fixture'
        Invoke-LabTraceAction -Action Convert -Path $etl | Out-Null
        (Get-Content -LiteralPath $etl -Raw).Trim() | Should Be 'legacy etl fixture'
        @(Get-ChildItem -LiteralPath $script:traceRoot -Recurse -Filter trace.pcapng).Count | Should Be 1
        @($script:nativeCalls | Where-Object { $_ -like 'trace|*' }).Count | Should Be 0
        Assert-MockCalled Get-LocalTracePath -Times 1 -Exactly -Scope It -ParameterFilter {
            $Path -eq 'C:\LabTools\evidence'
        }
    }

    It 'refuses conversion of an ETL opened for writing outside this helper' {
        $etl = Join-Path $TestDrive 'external.etl'
        Set-Content -LiteralPath $etl -Value 'external capture fixture'
        $writer = [IO.File]::Open($etl, 'Open', 'ReadWrite', 'ReadWrite')
        try {
            { Invoke-LabTraceAction -Action Convert -Path $etl } | Should Throw 'TRACE_CONVERSION_FAILED'
            Assert-MockCalled Invoke-TraceNative -Times 0 -Exactly -Scope It
        } finally {
            $writer.Dispose()
        }
    }
}

Describe 'Native quoting exit handling and private storage (offline)' {
    BeforeEach {
        $script:exitCode = 0
        $script:nativeStdout = 'native stdout'
        $script:nativeStderr = 'native stderr'
        Mock Start-Process {
            Set-Content -LiteralPath $RedirectStandardOutput -Value $script:nativeStdout
            Set-Content -LiteralPath $RedirectStandardError -Value $script:nativeStderr
            [pscustomobject]@{ ExitCode = $script:exitCode }
        }
    }

    It 'accepts exit one only for an opted-in recognized netsh idle status' {
        $script:exitCode = 1
        $script:nativeStdout = 'There is no trace session currently in progress.'
        $script:nativeStderr = ''
        (Invoke-TraceNative -FilePath 'C:\Windows\System32\netsh.exe' `
            -Arguments @('trace', 'show', 'status') -WorkDirectory $TestDrive -AllowNoTraceSession).Trim() |
            Should Be $script:nativeStdout
        { Invoke-TraceNative -FilePath 'C:\Windows\System32\netsh.exe' `
            -Arguments @('trace', 'show', 'status') -WorkDirectory $TestDrive } |
            Should Throw 'TRACE_COMMAND_FAILED'
        @(Get-ChildItem -LiteralPath $TestDrive).Count | Should Be 0
    }

    It 'does not suppress unrelated native errors with the idle-status exception: <Kind>' -TestCases @(
        @{ Kind = 'denied' }, @{ Kind = 'empty' }, @{ Kind = 'unexpected-code' },
        @{ Kind = 'stop' }, @{ Kind = 'converter' }, @{ Kind = 'stderr' }
    ) {
        param($Kind)
        $script:exitCode = 1
        $script:nativeStdout = 'There is no trace session currently in progress.'
        $script:nativeStderr = ''
        $file = 'C:\Windows\System32\netsh.exe'
        $arguments = @('trace', 'show', 'status')
        switch ($Kind) {
            'denied' { $script:nativeStdout = 'Access is denied.' }
            'empty' { $script:nativeStdout = '' }
            'unexpected-code' { $script:exitCode = 5 }
            'stop' { $arguments = @('trace', 'stop') }
            'converter' { $file = 'C:\LabTools\etl2pcapng.exe' }
            'stderr' { $script:nativeStderr = 'Unexpected native error' }
        }
        { Invoke-TraceNative -FilePath $file -Arguments $arguments -WorkDirectory $TestDrive -AllowNoTraceSession } |
            Should Throw 'TRACE_COMMAND_FAILED'
    }

    It 'quotes spaced trace and conversion paths as single native arguments' {
        Invoke-TraceNative -FilePath 'C:\Windows\System32\netsh.exe' `
            -Arguments @('trace', 'start', 'tracefile=C:\Private traces\trace.etl') -WorkDirectory $TestDrive | Out-Null
        Invoke-TraceNative -FilePath 'C:\LabTools\etl2pcapng.exe' `
            -Arguments @('C:\Private traces\trace.etl', 'C:\Private traces\trace.pcapng') -WorkDirectory $TestDrive | Out-Null
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            $ArgumentList -eq '"trace" "start" "tracefile=C:\Private traces\trace.etl"' -and $Wait -and $PassThru
        }
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            $ArgumentList -eq '"C:\Private traces\trace.etl" "C:\Private traces\trace.pcapng"'
        }
        @(Get-ChildItem -LiteralPath $TestDrive).Count | Should Be 0
    }

    It 'surfaces nonzero exits and native diagnostic output and cleans transient logs' {
        $script:exitCode = 5
        { Invoke-TraceNative -FilePath 'mock.exe' -Arguments @('trace', 'stop') -WorkDirectory $TestDrive } |
            Should Throw 'native stderr'
        @(Get-ChildItem -LiteralPath $TestDrive).Count | Should Be 0
    }

    It 'rejects shares relative paths and unsafe quoting: <Path>' -TestCases @(
        @{ Path = '\\server\share\trace.etl' }, @{ Path = 'trace.etl' }, @{ Path = 'C:\bad"path.etl' }
    ) {
        param($Path)
        { Get-LocalTracePath -Path $Path } | Should Throw 'TRACE_LOCAL_PATH_REQUIRED'
    }

    It 'accepts a local fixed-drive path containing spaces without requiring the file to exist' {
        $path = Join-Path $TestDrive 'private folder\trace.etl'
        Get-LocalTracePath -Path $path | Should Be $path
    }

    It 'rejects junctions before writing any capture data' {
        Mock Test-Path { $true }
        Mock Get-Item { [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint } }
        { Get-LocalTracePath -Path 'C:\linked\trace.etl' } | Should Throw 'TRACE_REPARSE_PATH'
    }

    It 'protects capture directory inheritance with only owner SYSTEM and Administrators' {
        Mock Set-Acl { $script:capturedAcl = $AclObject }
        Set-PrivateTraceDirectory -Path (Join-Path $TestDrive 'private')
        $script:capturedAcl.AreAccessRulesProtected | Should Be $true
        $rules = $script:capturedAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        $sids = @($rules | ForEach-Object { $_.IdentityReference.Value })
        $sids.Count | Should Be 3
        $sids -contains 'S-1-5-18' | Should Be $true
        $sids -contains 'S-1-5-32-544' | Should Be $true
        $sids -contains ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) | Should Be $true
    }
}
