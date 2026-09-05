$installer = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\07-install-tools.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$assignment = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$helper'
}, $true)
$source = $assignment.Right.Expression.Value
$helperAst = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$functions = @('Write-JsonFile','Get-DcTargets','Initialize-EvidenceRun','Convert-DcEvent',
    'Save-DcEvidence','Save-Log','Save-SmbState','Complete-EvidenceRun','Start-Capture','Stop-Capture')
foreach ($definition in $helperAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
}, $true)) {
    if ($definition.Name -in $functions) { . ([scriptblock]::Create($definition.Extent.Text)) }
}

function New-TestEvent([int]$Id = 4769, [string]$User = 'labuser1', [string]$Status = '0x0') {
    $event = [pscustomobject]@{
        Id = $Id
        RecordId = $Id
        MachineName = 'dc.contoso.local'
        TimeCreated = [DateTime]::Parse('2026-09-06T01:00:02Z').ToUniversalTime()
        XmlData = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData>
<Data Name="TargetUserName">$User</Data><Data Name="ServiceName">labstorage`$</Data>
<Data Name="IpAddress">::ffff:10.100.0.5</Data><Data Name="Status">$Status</Data>
<Data Name="TicketEncryptionType">0x12</Data></EventData></Event>
"@
    }
    $event | Add-Member ScriptMethod ToXml { $this.XmlData }
    $event
}

Describe 'DC evidence collection' {
    BeforeEach {
        $script:out = Join-Path $TestDrive 'run'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $script:DomainController = @('dc.contoso.local')
        $script:DcCredential = $null
        $script:MaxDcEvents = 2000
        $script:DcTimePaddingSeconds = 5
        $script:context = [pscustomobject]@{
            StartUtc = '2026-09-06T01:00:00Z'; EndUtc = '2026-09-06T01:00:04Z'
            UserName = 'labuser1'; Account = 'CONTOSO\labuser1'; UserSid = 'S-1-5-21-1-2-3-1100'
            LogonId = '0:0x123'; Computer = 'client'; ClientAddresses = @('10.100.0.5')
            StorageAccount = 'labstorage'; Spn = 'cifs/labstorage.file.core.windows.net'
            Share = 'labshare'; MountExitCode = 2
        }
        Write-JsonFile $context (Join-Path $out 'reproduction.json')
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'collects the bounded IDs and preserves raw and structured evidence' {
        Mock Get-WinEvent { New-TestEvent }
        Save-DcEvidence $out
        Assert-MockCalled Get-WinEvent -Times 1 -Exactly -Scope It -ParameterFilter {
            $ComputerName -eq 'dc.contoso.local' -and
            ($FilterHashtable.Id -join ',') -eq '4768,4769,4771' -and
            $FilterHashtable.StartTime.ToUniversalTime().ToString('HH:mm:ss') -eq '00:59:55' -and
            $FilterHashtable.EndTime.ToUniversalTime().ToString('HH:mm:ss') -eq '01:00:09'
        }
        $state = Get-Content "$out\dc-collection.json" -Raw | ConvertFrom-Json
        $state.Status | Should Be 'Collected'
        $event = Get-Content "$out\dc-dc.contoso.local\security.json" -Raw | ConvertFrom-Json
        $event.CandidateReasons | Should Be 'User,ClientIP,Service'
        $event.EventData.TicketEncryptionType | Should Be '0x12'
        ([xml](Get-Content "$out\dc-dc.contoso.local\security.xml" -Raw)).Events.ChildNodes.Count | Should Be 1
        Test-Path "$out\dc-dc.contoso.local\security.csv" | Should Be $true
        (Get-Content "$out\azure-files-handoff.txt" -Raw) | Should Match 'Mount exit code: 2'
    }

    It 'does not throw away unrelated events in the bounded window' {
        Mock Get-WinEvent { New-TestEvent -User 'anotheruser' }
        Save-DcEvidence $out
        $event = Get-Content "$out\dc-dc.contoso.local\security.json" -Raw | ConvertFrom-Json
        $event.User | Should Be 'anotheruser'
        $event.CandidateReasons | Should Be 'ClientIP,Service'
    }

    It 'distinguishes a successful empty query from access denied' {
        Mock Get-WinEvent {
            Write-Error -Message 'No events' -ErrorId 'NoMatchingEventsFound' -ErrorAction Stop
        }
        Save-DcEvidence $out
        (Get-Content "$out\dc-collection.json" -Raw | ConvertFrom-Json).Status | Should Be 'NoMatchingEvents'
        Mock Get-WinEvent { throw [UnauthorizedAccessException]::new('Access denied') }
        Save-DcEvidence $out
        $state = Get-Content "$out\dc-collection.json" -Raw | ConvertFrom-Json
        $state.Status | Should Be 'Failed'
        $state.Error | Should Match 'Access denied'
    }

    It 'reports truncation rather than claiming a complete result' {
        $script:MaxDcEvents = 1
        Mock Get-WinEvent { New-TestEvent; New-TestEvent -Id 4771 }
        Save-DcEvidence $out
        $state = Get-Content "$out\dc-collection.json" -Raw | ConvertFrom-Json
        $state.Count | Should Be 1
        $state.Truncated | Should Be $true
    }

    It 'continues after one DC fails and never serializes credentials' {
        $script:DomainController = @('dc.contoso.local','dc2.contoso.local')
        $script:DcCredential = [pscredential]::new('CONTOSO\reader',
            (ConvertTo-SecureString 'test-only-value' -AsPlainText -Force))
        Mock Get-WinEvent {
            if ($ComputerName -eq 'dc.contoso.local') { throw 'RPC unavailable' }
            New-TestEvent
        }
        Save-DcEvidence $out
        $states = Get-Content "$out\dc-collection.json" -Raw | ConvertFrom-Json
        ($states | Where-Object Computer -eq 'dc.contoso.local').Status | Should Be 'Failed'
        ($states | Where-Object Computer -eq 'dc2.contoso.local').Status | Should Be 'Collected'
        Assert-MockCalled Get-WinEvent -ParameterFilter { $Credential.UserName -eq 'CONTOSO\reader' } -Times 2 -Exactly -Scope It
        (Get-Content "$out\dc-collection.json" -Raw) | Should Not Match 'test-only-value'
    }

    It 'skips missing reproductions and rejects unfinished intervals' {
        Remove-Item "$out\reproduction.json"
        Mock Get-WinEvent { throw 'Must not query' }
        Save-DcEvidence $out
        (Get-Content "$out\dc-collection.json" -Raw | ConvertFrom-Json).Status | Should Be 'Skipped'
        $context.EndUtc = $null
        Write-JsonFile $context "$out\reproduction.json"
        { Save-DcEvidence $out } | Should Throw
        Assert-MockCalled Get-WinEvent -Times 0 -Exactly -Scope It
    }

    It 'uses DCs recorded with the run when no override is supplied' {
        $script:DomainController = @()
        Write-JsonFile @{ DomainControllers = @('recorded.contoso.local') } "$out\run.json"
        @(Get-DcTargets $out)[0] | Should Be 'recorded.contoso.local'
    }

    It 'rejects a reversed client clock interval even within the padding' {
        $context.EndUtc = '2026-09-06T00:59:59Z'
        Write-JsonFile $context "$out\reproduction.json"
        Mock Get-WinEvent { throw 'Must not query' }
        { Save-DcEvidence $out } | Should Throw
        Assert-MockCalled Get-WinEvent -Times 0 -Exactly -Scope It
    }

    It 'records failed preflight without preventing a client capture' {
        Mock Get-WinEvent { throw [UnauthorizedAccessException]::new('Access denied') }
        Initialize-EvidenceRun $out
        (Get-Content "$out\dc-preflight.json" -Raw | ConvertFrom-Json).Status | Should Be 'Failed'
        (Get-Content "$out\run.json" -Raw | ConvertFrom-Json).DomainControllers[0] | Should Be 'dc.contoso.local'
        Assert-MockCalled Get-WinEvent -Times 1 -Exactly -Scope It -ParameterFilter { $ListLog -eq 'Security' }
    }

    It 'does not infer the caller or a failure cause from a DC error' {
        Mock Get-WinEvent { New-TestEvent -Id 4771 -Status '0x18' }
        Save-DcEvidence $out
        (Get-Content "$out\dc-summary.txt" -Raw) | Should Match 'not an automatic diagnosis'
        (Get-Content "$out\dc-dc.contoso.local\security.json" -Raw | ConvertFrom-Json).Status | Should Be '0x18'
    }
}

Describe 'Collector lifecycle wiring' {
    It 'publishes split-run state only after a successful trace start' {
        $start = $helperAst.FindAll({ param($n) $n -is [Management.Automation.Language.SwitchStatementAst] }, $true)[0].Clauses |
            Where-Object { $_.Item1.Value -eq 'Start' } | ForEach-Object { $_.Item2.Extent.Text }
        $start.IndexOf('Start-Capture $out') | Should BeLessThan $start.IndexOf('Set-Content -Path $pointer')
    }
    It 'does not stop another trace while starting' {
        $start = $helperAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Start-Capture' }, $true)
        $start.Extent.Text | Should Not Match 'netsh trace stop'
    }
    It 'keeps stop snapshots separate and DC reads before optional trace analysis' {
        $complete = $helperAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Complete-EvidenceRun' }, $true).Extent.Text
        $complete | Should Match "Save-SmbState.*'-collector'"
        $complete.IndexOf('Save-DcEvidence') | Should BeLessThan $complete.IndexOf('Show-TraceSummary')
    }
    It 'merges expected mapping-reset errors outside the PowerShell error stream' {
        $mount = $helperAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-MountAttempt' }, $true).Extent.Text
        $mount | Should Match 'cmd /c "net use \$target /delete /y 2>&1"'
        $mount | Should Match 'mapping-reset.txt'
        $mount | Should Match "throw 'klist purge failed"
    }
}
