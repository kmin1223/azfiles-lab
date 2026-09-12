$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$clientPath = Join-Path $root 'scripts\client-config.ps1'
$setupPath = Join-Path $root 'setup.ps1'
$clientSource = Get-Content $clientPath -Raw
$setupSource = Get-Content $setupPath -Raw
$clientPreflight = [scriptblock]::Create($clientSource.Substring(0, $clientSource.IndexOf('# 3. Fiddler')))
$tokens = $null
$parseErrors = $null
$setupAst = [Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$invokeFunction = $setupAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-LabClientConfiguration'
}, $true)
# Extracted functions have no script-file context; supply the real payload root.
. ([scriptblock]::Create($invokeFunction.Extent.Text.Replace('$PSScriptRoot', '$root')))

# Fail-closed stubs ensure these tests never access a VM, registry or join task.
function dsregcmd { throw 'Unmocked device registration command' }
function Resolve-DnsName { param($Name) throw 'Unmocked DNS query' }
function Get-ScheduledTask { param($TaskName, $TaskPath) throw 'Unmocked task read' }
function Start-ScheduledTask { param([Parameter(ValueFromPipeline)]$InputObject) throw 'Unmocked task start' }
function New-Item { param($Path, [switch]$Force) throw 'Unmocked registry write' }
function Set-ItemProperty { param($Path, $Name, $Value, $Type) throw 'Unmocked registry write' }
function shutdown { throw 'Unmocked reboot request' }
function Get-AzStorageAccount { param($ResourceGroupName) throw 'Unmocked Azure storage read' }
function Remove-AzResourceGroup { param($Name, [switch]$Force, [switch]$AsJob) throw 'Unmocked Azure deletion' }
function Invoke-AzVMRunCommand {
    param($ResourceGroupName, $VMName, $CommandId, $ScriptPath, $Parameter)
    throw 'Unmocked Azure operation'
}

Describe 'Cleanup Connect Sync retirement gate (offline)' {
    BeforeEach {
        Mock Get-AzStorageAccount { throw 'Azure storage read reached before retirement gate' }
        Mock Remove-AzResourceGroup { throw 'Azure deletion reached before retirement gate' }
    }

    It 'rejects IncludeEntra without retirement before any Azure read or deletion' {
        $cleanupPath = Join-Path (Split-Path $root -Parent) 'cleanup.ps1'
        { & $cleanupPath -ResourceGroupName test-rg -Prefix testlab -IncludeEntra } |
            Should Throw 'Retire Connect Sync for this lab'
        Assert-MockCalled Get-AzStorageAccount -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-AzResourceGroup -Times 0 -Exactly -Scope It
    }

    It 'does not treat an explicitly false retirement switch as confirmation' {
        $cleanupPath = Join-Path (Split-Path $root -Parent) 'cleanup.ps1'
        { & $cleanupPath -ResourceGroupName test-rg -Prefix testlab -IncludeEntra -ConnectSyncRetired:$false } |
            Should Throw 'Retire Connect Sync for this lab'
        Assert-MockCalled Get-AzStorageAccount -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-AzResourceGroup -Times 0 -Exactly -Scope It
    }
}

Describe 'Connect Sync client readiness and registration modes (offline)' {
    BeforeEach {
        $script:deviceStatus = @'
DomainJoined : YES
AzureAdJoined : YES
DeviceAuthStatus : SUCCESS
TenantId : test-tenant
'@
        Mock dsregcmd { $global:LASTEXITCODE = 0; $deviceStatus }
        Mock Resolve-DnsName { 'Resolved' }
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'Automatic-Device-Join' } }
        Mock Start-ScheduledTask {}
        Mock New-Item {}
        Mock Set-ItemProperty {}
    }

    It 'checks a healthy device without changing policy or starting registration' {
        $result = @(& $clientPreflight -Mode Check -ExpectedTenantId test-tenant)
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $true
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
        Assert-MockCalled Resolve-DnsName -Times 3 -Exactly -Scope It
    }

    It 'rejects an unjoined pending device instead of reporting success' {
        $script:deviceStatus = $deviceStatus.Replace('AzureAdJoined : YES', 'AzureAdJoined : NO')
        { & $clientPreflight -Mode Check } | Should Throw 'CLIENT_HYBRID_JOIN_NOT_READY'
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'blocks configuration writes until hybrid join is healthy' {
        $script:deviceStatus = $deviceStatus.Replace('AzureAdJoined : YES', 'AzureAdJoined : NO')
        { & $clientPreflight -Mode Configure } | Should Throw 'CLIENT_HYBRID_JOIN_NOT_READY'
        Assert-MockCalled New-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'rejects disabled or deleted cloud devices' {
        $script:deviceStatus = $deviceStatus.Replace('SUCCESS', 'FAILED')
        { & $clientPreflight -Mode Check } | Should Throw 'CLIENT_HYBRID_JOIN_NOT_READY'
        { & $clientPreflight -Mode InitializeRegistration } | Should Throw 'CLIENT_DEVICE_UNHEALTHY'
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'does not accept absent device health as success' {
        $script:deviceStatus = $deviceStatus.Replace('DeviceAuthStatus : SUCCESS', '')
        { & $clientPreflight -Mode Check } | Should Throw 'CLIENT_HYBRID_JOIN_NOT_READY'
    }

    It 'rejects a cloud-only device' {
        $script:deviceStatus = $deviceStatus.Replace('DomainJoined : YES', 'DomainJoined : NO')
        { & $clientPreflight -Mode Configure } | Should Throw 'CLIENT_NOT_DOMAIN_JOINED'
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'rejects a different tenant before any writes' {
        { & $clientPreflight -Mode Configure -ExpectedTenantId another-tenant } |
            Should Throw 'CLIENT_WRONG_TENANT'
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'fails on an unreadable dsregcmd status' {
        Mock dsregcmd { $global:LASTEXITCODE = 1; 'Device query failed' }
        { & $clientPreflight -Mode Check } | Should Throw 'dsregcmd /status failed'
    }

    It 'fails DNS before writing policy or starting a task' {
        Mock Resolve-DnsName { throw 'DNS unavailable' }
        { & $clientPreflight -Mode Configure } | Should Throw 'CLIENT_DNS_FAILED'
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'initializes a pending device only through the SYSTEM scheduled task' {
        $script:deviceStatus = $deviceStatus.Replace('AzureAdJoined : YES', 'AzureAdJoined : NO')
        $result = @(& $clientPreflight -Mode InitializeRegistration -ExpectedTenantId test-tenant)
        $result -contains 'CLIENT_REGISTRATION_STARTED_NOT_READY' | Should Be $true
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $false
        Assert-MockCalled Get-ScheduledTask -Times 1 -Exactly -Scope It -ParameterFilter {
            $TaskName -eq 'Automatic-Device-Join' -and $TaskPath -eq '\Microsoft\Windows\Workplace Join\'
        }
        Assert-MockCalled Start-ScheduledTask -Times 1 -Exactly -Scope It
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled dsregcmd -Times 1 -Exactly -Scope It
    }

    It 'does not reinitialize an already healthy registration' {
        $result = @(& $clientPreflight -Mode InitializeRegistration -ExpectedTenantId test-tenant)
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $true
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'surfaces a missing or failing registration task' {
        $script:deviceStatus = $deviceStatus.Replace('AzureAdJoined : YES', 'AzureAdJoined : NO')
        Mock Get-ScheduledTask { $null }
        { & $clientPreflight -Mode InitializeRegistration } | Should Throw 'task is missing'
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'Automatic-Device-Join' } }
        Mock Start-ScheduledTask { throw 'Task disabled' }
        { & $clientPreflight -Mode InitializeRegistration } | Should Throw 'Task disabled'
    }

    It 'preserves cloud TGT policy configuration for an already healthy client' {
        & $clientPreflight -Mode Configure -ExpectedTenantId test-tenant | Out-Null
        Assert-MockCalled Set-ItemProperty -Times 1 -Exactly -Scope It -ParameterFilter {
            $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -and
            $Name -eq 'CloudKerberosTicketRetrievalEnabled' -and $Value -eq 1 -and $Type -eq 'DWord'
        }
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'reports completion only after scheduling the reboot successfully' {
        $reboot = [scriptblock]::Create($clientSource.Substring($clientSource.LastIndexOf('shutdown /r')))
        Mock shutdown { $global:LASTEXITCODE = 0 }
        @(& $reboot) -contains 'CLIENT_CONFIG_DONE_REBOOTING' | Should Be $true
        Mock shutdown { $global:LASTEXITCODE = 1 }
        { & $reboot } | Should Throw 'Client reboot could not be scheduled'
    }
}

Describe 'Setup prerequisite and completion contract (offline)' {
    BeforeEach {
        $script:ResourceGroupName = 'test-rg'
        $script:Prefix = 'testlab'
        $script:remoteOutput = 'CLIENT_HYBRID_JOIN_READY'
        $script:remoteError = ''
        Mock Invoke-AzVMRunCommand {
            [pscustomobject]@{ Value = @(
                [pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = $remoteOutput }
                [pscustomobject]@{ Code = 'ComponentStatus/StdErr/succeeded'; Message = $remoteError }
            ) }
        }
    }

    It 'passes the expected tenant and read-only mode to the client VM' {
        Invoke-LabClientConfiguration -Mode Check -TenantId test-tenant
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It -ParameterFilter {
            $VMName -eq 'testlab-cli' -and $ResourceGroupName -eq 'test-rg' -and
            $Parameter.Mode -eq 'Check' -and $Parameter.ExpectedTenantId -eq 'test-tenant' -and
            $ScriptPath -like '*client-config.ps1'
        }
    }

    It 'rejects remote success-shaped output without the readiness marker' {
        $script:remoteOutput = 'CLIENT_REGISTRATION_STARTED_NOT_READY'
        { Invoke-LabClientConfiguration -Mode Check -TenantId test-tenant } | Should Throw 'Client Check did not finish'
    }

    It 'surfaces Run Command transport errors without claiming readiness' {
        Mock Invoke-AzVMRunCommand { throw 'VM is unavailable' }
        { Invoke-LabClientConfiguration -Mode Check -TenantId test-tenant } | Should Throw 'VM is unavailable'
    }

    It 'rejects an embedded marker and errors even with an exact marker' {
        $script:remoteOutput = 'Expected marker: CLIENT_HYBRID_JOIN_READY'
        { Invoke-LabClientConfiguration -Mode Check -TenantId test-tenant } | Should Throw 'Client Check did not finish'
        $script:remoteOutput = 'CLIENT_HYBRID_JOIN_READY'
        $script:remoteError = 'Registration check failed'
        { Invoke-LabClientConfiguration -Mode Check -TenantId test-tenant } |
            Should Throw 'Registration check failed'
    }

    It 'requires the configuration and reboot marker for the final step' {
        { Invoke-LabClientConfiguration -Mode Configure -TenantId test-tenant } | Should Throw 'Client Configure did not finish'
        $script:remoteOutput = 'CLIENT_CONFIG_DONE_REBOOTING'
        { Invoke-LabClientConfiguration -Mode Configure -TenantId test-tenant } | Should Not Throw
    }

    It 'checks readiness before storage changes and never invokes an SCP writer' {
        $checkOffset = $setupSource.IndexOf('Invoke-LabClientConfiguration -Mode Check')
        ($checkOffset -gt 0 -and $checkOffset -lt $setupSource.IndexOf('Set-AzStorageAccount')) | Should Be $true
        $setupSource | Should Not Match 'create-scp\.ps1|Cloud Sync|MANUAL-STEP-cloud-sync'
        $clientSource | Should Not Match 'dsregcmd /join /debug|Enable device sync|Provision on demand'
    }

    It 'leaves obsolete SCP commands fail-closed without AD mutations' {
        { & (Join-Path $root 'scripts\create-scp.ps1') -TenantId test-tenant -TenantDomain example.test } |
            Should Throw 'Manual SCP creation is retired'
        (Get-Content (Join-Path $root 'scripts\create-scp.ps1') -Raw) |
            Should Not Match 'New-ADObject|Remove-ADObject|Set-ADObject'
    }

    It 'ships only the renamed guide with both user and computer scopes' {
        Test-Path (Join-Path $root 'MANUAL-STEP-cloud-sync.md') | Should Be $false
        $guide = Get-Content (Join-Path $root 'MANUAL-STEP-connect-sync.md') -Raw
        $guide | Should Match 'OU=AzureFilesLab,DC=contoso,DC=local'
        $guide | Should Match 'CN=Computers,DC=contoso,DC=local'
        $guide | Should Match 'Configure device options'
        $guide | Should Match 'InitializeRegistration'
        $guide | Should Match 'hybrid-labuser1'
    }
}
