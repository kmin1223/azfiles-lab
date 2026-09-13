$ErrorActionPreference = 'Stop'
$script:aclScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\copy-rbac-lab-acl.ps1'
$tokens = $null
$parseErrors = $null
$aclAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $aclScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$writerFunction = $aclAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Set-RbacDirectoryDacl'
}, $true)
. ([scriptblock]::Create($writerFunction.Extent.Text))
$script:nativeDaclWriter = $writerFunction.Body.GetScriptBlock()
# Keep the real entrypoint, but do not redefine the writer over its mock.
$script:aclRunner = [scriptblock]::Create(
    (Get-Content $aclScript -Raw).Remove($writerFunction.Extent.StartOffset, $writerFunction.Extent.Text.Length))

# Stubs prevent Pester 3 dynamic-parameter discovery from invoking real providers.
function New-PSDrive {
    [CmdletBinding()]
    param($Name, $PSProvider, $Root, $Credential, $Scope, [switch]$Persist)
    throw 'Unmocked drive creation'
}
function Get-PSDrive {
    [CmdletBinding()] param($PSProvider, $Scope)
    throw 'Unmocked drive enumeration'
}
function Remove-PSDrive {
    [CmdletBinding()] param($Name, $Scope, [switch]$Force)
    throw 'Unmocked drive removal'
}
function Get-Acl {
    [CmdletBinding()] param($LiteralPath)
    throw 'Unmocked ACL read'
}
function New-TestRootAcl {
    param([string]$Sddl)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    return $acl
}

Describe 'RBAC lab root DACL copy (offline)' {
    BeforeEach {
        $script:testKey = 'OFFLINE-TEST-KEY-NOT-A-SECRET'
        $script:events = New-Object 'System.Collections.Generic.List[string]'
        $script:mounts = @{}
        $script:mountCalls = New-Object 'System.Collections.Generic.List[object]'
        $script:removed = New-Object 'System.Collections.Generic.List[string]'
        $script:reads = @{ source = 0; target = 0 }
        $script:failAt = ''
        $script:partialMount = $false
        $script:sourceChanged = $false
        $script:targetChanged = $false
        $script:writeException = $null
        $script:cleanupStuck = $false
        $script:counters = @{ enumerations = 0 }
        $script:sourceSddl = 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)S:(AU;SA;FA;;;SY)'
        $script:targetSddl = 'O:BAG:BAD:PAI(A;OICI;FA;;;BA)S:(AU;FA;FR;;;BA)'
        $script:sourceAcl = New-TestRootAcl $sourceSddl
        $script:targetAcl = New-TestRootAcl $targetSddl
        $script:accessSection = [System.Security.AccessControl.AccessControlSections]::Access
        $script:identitySections = [System.Security.AccessControl.AccessControlSections]'Owner, Group'
        $script:expectedDacl = $sourceAcl.GetSecurityDescriptorSddlForm($accessSection)
        $script:targetIdentity = $targetAcl.GetSecurityDescriptorSddlForm($identitySections)
        $script:auditSection = [System.Security.AccessControl.AccessControlSections]::Audit
        $script:sourceAudit = $sourceAcl.GetSecurityDescriptorSddlForm($auditSection)
        $script:targetAudit = $targetAcl.GetSecurityDescriptorSddlForm($auditSection)

        Mock ConvertTo-SecureString {
            if ($failAt -eq 'credential') { throw $testKey }
            # A dummy in-memory SecureString; the runtime key is never consumed by a provider.
            New-Object System.Security.SecureString
        }
        Mock Get-PSDrive {
            $counters.enumerations++
            if ($failAt -eq 'enumerate' -and $Scope -eq 'Local') { throw $testKey }
            $events.Add("enumerate:$Scope")
            [pscustomobject]@{ Name = 'Unrelated'; Root = '\\untouched\share' }
            foreach ($name in @($mounts.Keys)) { [pscustomobject]@{ Name = $name } }
        }
        Mock New-PSDrive {
            $kind = if ($Root -like '*\labshare') { 'source' } else { 'target' }
            $events.Add("mount:$kind")
            $mountCalls.Add([pscustomobject]@{
                Name = $Name; Root = $Root; Provider = $PSProvider; Scope = $Scope
                Credential = $Credential; Persist = [bool]$Persist
            })
            if ($failAt -eq "mount:$kind") {
                if ($partialMount) { $mounts[$Name] = $kind }
                throw $testKey
            }
            $mounts[$Name] = $kind
            [pscustomobject]@{ Name = $Name }
        }
        Mock Get-Acl {
            $name = $LiteralPath.Split(':')[0]
            $kind = $mounts[$name]
            if (-not $kind) { throw 'Unmocked ACL path' }
            $reads[$kind]++
            $events.Add("read:${kind}:$($reads[$kind])")
            if ($failAt -eq "read:${kind}:$($reads[$kind])") { throw $testKey }
            if ($kind -eq 'source') {
                if ($sourceChanged -and $reads[$kind] -eq 2) { return (New-TestRootAcl $targetSddl) }
                return $sourceAcl
            }
            if ($targetChanged -and $reads[$kind] -eq 2) { return (New-TestRootAcl $targetSddl) }
            return $targetAcl
        }
        Mock Set-RbacDirectoryDacl {
            if ($LiteralPath -ne '\\azflabtest.file.core.windows.net\rbac-lab') { throw 'Unexpected write path' }
            $events.Add('write:target')
            if ($writeException) { throw $writeException }
            if ($failAt -eq 'write') { throw $testKey }
            if ($AclObject.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All) -cne $expectedDacl) {
                throw 'Write descriptor must contain only the expected DACL'
            }
            $targetAcl.SetSecurityDescriptorSddlForm(
                $AclObject.GetSecurityDescriptorSddlForm($accessSection), $accessSection)
        }
        Mock Remove-PSDrive {
            if (-not $mounts.ContainsKey($Name)) { throw 'Unrelated drive removal forbidden' }
            if ($Scope -ne 'Local') { throw 'Nonlocal removal forbidden' }
            $events.Add("remove:$($mounts[$Name])")
            $removed.Add($Name)
            if ($failAt -eq "remove:$($mounts[$Name])") { throw $testKey }
            if (-not $cleanupStuck) { $mounts.Remove($Name) }
        }
        Mock Remove-Item { throw 'Deletion forbidden' }
        Mock Copy-Item { throw 'Content copying forbidden' }
        Mock Set-Content { throw 'Content writing forbidden' }
    }

    It 'copies only the destination DACL and emits exactly one marker after verified cleanup' {
        $output = @(& $aclRunner -StorageAccountName azflabtest -StorageKey $testKey |
            ForEach-Object { $events.Add("output:$_"); $_ })
        $output.Count | Should Be 1
        $output[0] | Should Be 'RBAC_LAB_ACL_READY'
        $events[$events.Count - 1] | Should Be 'output:RBAC_LAB_ACL_READY'
        $events[$events.Count - 2] | Should Be 'enumerate:Local'
        $mounts.Count | Should Be 0
        $removed.Count | Should Be 2
        $sourceAcl.GetSecurityDescriptorSddlForm($accessSection) | Should Be $expectedDacl
        $targetAcl.GetSecurityDescriptorSddlForm($accessSection) | Should Be $expectedDacl
        $targetAcl.GetSecurityDescriptorSddlForm($identitySections) | Should Be $targetIdentity
        $sourceAcl.GetSecurityDescriptorSddlForm($identitySections) | Should Be 'O:SYG:SY'
        $sourceAcl.GetSecurityDescriptorSddlForm($auditSection) | Should Be $sourceAudit
        $targetAcl.GetSecurityDescriptorSddlForm($auditSection) | Should Be $targetAudit
        $reads.source | Should Be 2
        $reads.target | Should Be 2
        Assert-MockCalled Set-RbacDirectoryDacl -Times 1 -Exactly -Scope It
        Assert-MockCalled Remove-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Copy-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-Content -Times 0 -Exactly -Scope It
    }

    It 'uses distinct random local nonpersistent mounts with one shared administrative credential' {
        & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey | Out-Null
        $mountCalls.Count | Should Be 2
        $mountCalls[0].Name | Should Match '^RbacSrc[0-9a-f]{32}$'
        $mountCalls[1].Name | Should Match '^RbacDst[0-9a-f]{32}$'
        $mountCalls[0].Root | Should Be '\\azflabtest.file.core.windows.net\labshare'
        $mountCalls[1].Root | Should Be '\\azflabtest.file.core.windows.net\rbac-lab'
        foreach ($call in $mountCalls) {
            $call.Provider | Should Be 'FileSystem'
            $call.Scope | Should Be 'Local'
            $call.Persist | Should Be $false
            $call.Credential.UserName | Should Be 'localhost\azflabtest'
        }
        [object]::ReferenceEquals($mountCalls[0].Credential, $mountCalls[1].Credential) | Should Be $true
        $removed -contains 'Unrelated' | Should Be $false
    }

    It 'fails closed without exposing provider errors for every remote operation failure' {
        foreach ($failurePoint in @('mount:source', 'mount:target', 'read:source:1',
                'read:target:1', 'write', 'read:source:2', 'read:target:2')) {
            $script:failAt = $failurePoint
            $script:reads = @{ source = 0; target = 0 }
            $script:mounts = @{}
            $events.Clear()
            $seen = New-Object 'System.Collections.Generic.List[string]'
            $caught = $null
            try {
                & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey |
                    ForEach-Object { $seen.Add([string]$_) }
            }
            catch { $caught = $_ }
            ($null -ne $caught) | Should Be $true
            $caught.Exception.Message | Should Match 'RBAC lab ACL preparation failed during'
            $expectedEvent = if ($failurePoint -eq 'write') { 'write:target' } else { $failurePoint }
            ($events -contains $expectedEvent) | Should Be $true
            $caught.Exception.Message.Contains($testKey) | Should Be $false
            $seen.Count | Should Be 0
            $mounts.Count | Should Be 0
        }
    }

    It 'rejects source DACL changes during the copy' {
        $script:sourceChanged = $true
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'source DACL verification'
        $mounts.Count | Should Be 0
    }

    It 'reports the typed access-denied code without exposing the exception message' {
        $script:writeException = New-Object System.UnauthorizedAccessException("Provider message $testKey")
        $seen = @()
        $caught = $null
        try { $seen = @(& $aclRunner -StorageAccountName azflabtest -StorageKey $testKey) }
        catch { $caught = $_ }
        $caught.Exception.Message | Should Match 'destination DACL write'
        $caught.Exception.Message | Should Match 'ExceptionType=System.UnauthorizedAccessException'
        $caught.Exception.Message | Should Match 'HResult=0x80070005'
        $caught.Exception.Message.Contains($testKey) | Should Be $false
        $seen.Count | Should Be 0
        $mounts.Count | Should Be 0
    }

    It 'includes numeric Win32 diagnostics without the raw provider message' {
        $script:writeException = New-Object System.ComponentModel.Win32Exception(5, $testKey)
        $caught = $null
        try { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey | Out-Null }
        catch { $caught = $_ }
        $caught.Exception.Message | Should Match 'ExceptionType=System.ComponentModel.Win32Exception'
        $caught.Exception.Message | Should Match 'NativeErrorCode=5'
        $caught.Exception.Message.Contains($testKey) | Should Be $false
        $mounts.Count | Should Be 0
    }

    It 'persists an Access-only descriptor through the real runtime API on an isolated local directory' {
        $directory = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'native-dacl-write'))
        $initialAcl = if ($PSVersionTable.PSEdition -eq 'Desktop') {
            $directory.GetAccessControl()
        } else {
            [System.IO.FileSystemAclExtensions]::GetAccessControl($directory)
        }
        $initialIdentity = $initialAcl.GetSecurityDescriptorSddlForm($identitySections)
        $dacl = New-Object System.Security.AccessControl.DirectorySecurity
        $dacl.SetSecurityDescriptorSddlForm($initialAcl.GetSecurityDescriptorSddlForm($accessSection), $accessSection)
        $dacl.SetAccessRuleProtection($true, $true)
        $sourceDirectory = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'native-dacl-source'))
        & $nativeDaclWriter -LiteralPath $sourceDirectory.FullName -AclObject $dacl
        $sourceDescriptor = if ($PSVersionTable.PSEdition -eq 'Desktop') {
            $sourceDirectory.GetAccessControl()
        } else {
            [System.IO.FileSystemAclExtensions]::GetAccessControl($sourceDirectory)
        }
        $persistedSourceDacl = $sourceDescriptor.GetSecurityDescriptorSddlForm($accessSection)
        $dacl = New-Object System.Security.AccessControl.DirectorySecurity
        $dacl.SetSecurityDescriptorSddlForm($persistedSourceDacl, $accessSection)
        & $nativeDaclWriter -LiteralPath $directory.FullName -AclObject $dacl
        $actual = if ($PSVersionTable.PSEdition -eq 'Desktop') {
            $directory.GetAccessControl()
        } else {
            [System.IO.FileSystemAclExtensions]::GetAccessControl($directory)
        }
        $actual.AreAccessRulesProtected | Should Be $true
        $actual.GetSecurityDescriptorSddlForm($accessSection) | Should Be $persistedSourceDacl
        $actual.GetSecurityDescriptorSddlForm($identitySections) | Should Be $initialIdentity
    }

    It 'rejects destination readback differences' {
        $script:targetChanged = $true
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'destination DACL verification'
        $mounts.Count | Should Be 0
    }

    It 'cleans even a mount created by a failing authentication operation' {
        $script:failAt = 'mount:target'
        $script:partialMount = $true
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'destination authentication and mount'
        $removed.Count | Should Be 2
        $mounts.Count | Should Be 0
    }

    It 'attempts both removals when the first removal fails and emits no success marker' {
        $script:failAt = 'remove:source'
        $seen = New-Object 'System.Collections.Generic.List[string]'
        $caught = $null
        try {
            & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey |
                ForEach-Object { $seen.Add([string]$_) }
        }
        catch { $caught = $_ }
        $caught.Exception.Message | Should Match 'Temporary mount removal failed'
        $caught.Exception.Message.Contains($testKey) | Should Be $false
        $removed.Count | Should Be 2
        $seen.Count | Should Be 0
    }

    It 'cleans a partially created first mount without touching unrelated drives' {
        $script:failAt = 'mount:source'
        $script:partialMount = $true
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'source authentication and mount'
        $removed.Count | Should Be 1
        $removed[0] | Should Match '^RbacSrc[0-9a-f]{32}$'
        $mounts.Count | Should Be 0
    }

    It 'reports a second mount cleanup failure after successfully removing the first' {
        $script:failAt = 'remove:target'
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'Temporary mount removal failed'
        $removed.Count | Should Be 2
        $mounts.Count | Should Be 1
        @($mounts.Values)[0] | Should Be 'target'
    }

    It 'reports both the primary verification failure and the cleanup failure' {
        $script:sourceChanged = $true
        $script:failAt = 'remove:target'
        $caught = $null
        try { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey }
        catch { $caught = $_ }
        $caught.Exception.Message | Should Match 'source DACL verification'
        $caught.Exception.Message | Should Match 'Temporary mount removal failed'
        $removed.Count | Should Be 2
    }

    It 'rejects cleanup enumeration failures' {
        $script:failAt = 'enumerate'
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'Temporary mount enumeration failed'
    }

    It 'verifies mounts are actually removed before declaring success' {
        $script:cleanupStuck = $true
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'Temporary mount cleanup verification failed'
    }

    It 'fails explicitly before mounting if credential creation fails' {
        $script:failAt = 'credential'
        { & $aclRunner -StorageAccountName azflabtest -StorageKey $testKey } |
            Should Throw 'credential creation'
        $mountCalls.Count | Should Be 0
    }

    It 'rejects invalid storage account names and empty keys before any provider call' {
        foreach ($invalidName in @('ab', 'Avalidname', 'with-dash', ('a' * 25), 'abc\share', "abc`n")) {
            $bindingFailed = $false
            try { & $aclRunner -StorageAccountName $invalidName -StorageKey $testKey }
            catch [System.Management.Automation.ParameterBindingException] { $bindingFailed = $true }
            $bindingFailed | Should Be $true
        }
        $bindingFailed = $false
        try { & $aclRunner -StorageAccountName azflabtest -StorageKey '' }
        catch [System.Management.Automation.ParameterBindingException] { $bindingFailed = $true }
        $bindingFailed | Should Be $true
        $mountCalls.Count | Should Be 0
        $counters.enumerations | Should Be 0
    }

    It 'has only the fixed-share contract and no shell mappings or content commands' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $aclScript, [ref]$tokens, [ref]$parseErrors)
        $parseErrors.Count | Should Be 0
        ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') |
            Should Be 'StorageAccountName,StorageKey'
        $commands = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($forbidden in @('net', 'net.exe', 'Set-Acl', 'Remove-Item', 'Copy-Item', 'Set-Content',
                'Invoke-Expression', 'Start-Process', 'Write-Host', 'Write-Verbose', 'Write-Debug')) {
            $commands -contains $forbidden | Should Be $false
        }
    }
}
