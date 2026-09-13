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
$grantFunction = $setupAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Grant-LabShareAccess'
}, $true)
. ([scriptblock]::Create($grantFunction.Extent.Text))
# Pester 3 cannot mock Get-Module's PSEdition parameter on newer PowerShell.
$setupPreStorage = [scriptblock]::Create(
    $setupSource.Substring(0, $setupSource.IndexOf('Step "2/4 Enabling Entra Kerberos')).
        Replace('$PSScriptRoot', '$root').
        Replace('Get-Module -ListAvailable', 'Get-TestAvailableModule -ListAvailable'))
$setupPreConsent = [scriptblock]::Create(
    $setupSource.Substring(0, $setupSource.IndexOf("Step '3/4 Granting admin consent")).
        Replace('$PSScriptRoot', '$root').
        Replace('Get-Module -ListAvailable', 'Get-TestAvailableModule -ListAvailable'))

# Fail-closed stubs ensure these tests never access a VM, registry or join task.
function dsregcmd { throw 'Unmocked device registration command' }
function Resolve-DnsName { param($Name) throw 'Unmocked DNS query' }
function Get-ScheduledTask { param($TaskName, $TaskPath) throw 'Unmocked task read' }
function Start-ScheduledTask { param([Parameter(ValueFromPipeline)]$InputObject) throw 'Unmocked task start' }
function New-Item { param($Path, [switch]$Force) throw 'Unmocked registry write' }
function Set-ItemProperty { param($Path, $Name, $Value, $Type) throw 'Unmocked registry write' }
function Get-ItemProperty {
    [CmdletBinding()]
    param($LiteralPath, $Name)
    throw 'Unmocked registry read'
}
function shutdown { throw 'Unmocked reboot request' }
function Get-AzStorageAccount {
    [CmdletBinding()] param($ResourceGroupName, $Name)
    throw 'Unmocked Azure storage read'
}
function Get-AzRmStorageShare {
    [CmdletBinding()] param($ResourceGroupName, $StorageAccountName, $Name)
    throw 'Unmocked share read'
}
function New-AzRmStorageShare {
    [CmdletBinding()] param($ResourceGroupName, $StorageAccountName, $Name, $EnabledProtocol, $QuotaGiB,
        [Alias('Metadata')]$LabMetadata)
    throw 'Unmocked share creation'
}
function Get-AzStorageAccountKey {
    [CmdletBinding()] param($ResourceGroupName, $Name)
    throw 'Unmocked key read'
}
function Get-AzContext { throw 'Unmocked Azure context read' }
function Get-TestAvailableModule { param($Name, [switch]$ListAvailable) throw 'Unmocked module availability check' }
function Get-AzADUser {
    [CmdletBinding()]
    param($UserPrincipalName)
    throw 'Unmocked directory user read'
}
function Get-AzRoleAssignment {
    [CmdletBinding()]
    param($ObjectId, $Scope, $RoleDefinitionName, [switch]$ExpandPrincipalGroups)
    throw 'Unmocked RBAC read'
}
function New-AzRoleAssignment {
    [CmdletBinding()]
    param($ObjectId, $Scope, $RoleDefinitionName)
    throw 'Unmocked RBAC write'
}
function Remove-AzResourceGroup { param($Name, [switch]$Force, [switch]$AsJob) throw 'Unmocked Azure deletion' }
function Invoke-AzVMRunCommand {
    [CmdletBinding()]
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
        Mock Get-ItemProperty { throw 'Unexpected registration metadata read' }
    }

    It 'checks a healthy device without changing policy or starting registration' {
        $result = @(& $clientPreflight -Mode Check -ExpectedTenantId test-tenant)
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $true
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
        Assert-MockCalled Resolve-DnsName -Times 3 -Exactly -Scope It
        Assert-MockCalled Get-ItemProperty -Times 0 -Exactly -Scope It
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

    It 'reads tenant field names case-insensitively like other dsregcmd fields' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId', 'TenantID')
        $result = @(& $clientPreflight -Mode Check -ExpectedTenantId test-tenant)
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $true
    }

    It 'reads indented CRLF tenant output' {
        $script:deviceStatus = ($deviceStatus -split '\r?\n' | ForEach-Object {
            "    $_  "
        }) -join "`r`n"
        $result = @(& $clientPreflight -Mode Check -ExpectedTenantId test-tenant)
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $true
    }

    It 'rejects a missing tenant distinctly before any configuration writes' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant', '')
        { & $clientPreflight -Mode Configure -ExpectedTenantId test-tenant } |
            Should Throw 'CLIENT_TENANT_ID_UNAVAILABLE'
        Assert-MockCalled New-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'does not read the next line as a blank tenant value' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant', "TenantId : `r`nMdmUrl : `r`n")
        { & $clientPreflight -Mode Check -ExpectedTenantId test-tenant } |
            Should Throw 'CLIENT_TENANT_ID_UNAVAILABLE'
    }

    It 'requires a readable tenant for joined devices even without an expected tenant' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant', '')
        { & $clientPreflight -Mode InitializeRegistration } |
            Should Throw 'CLIENT_TENANT_ID_UNAVAILABLE'
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'reads only the current thumbprint registration when Tenant Details are omitted' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant', @'
    Thumbprint : 0123456789abcdef0123456789abcdef01234567
    TenantName :
    AzureAdPrtAuthority : https://login.microsoftonline.com/unrelated-user-tenant
'@)
        Mock Get-ItemProperty { [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555' } }
        $result = @(& $clientPreflight -Mode Check -ExpectedTenantId '11111111-2222-3333-4444-555555555555')
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $true
        ($result -join "`n") | Should Match 'TenantIdSource=HKLM:'
        Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It -ParameterFilter {
            $LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\0123456789abcdef0123456789abcdef01234567' -and
            $Name -eq 'TenantId'
        }
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'still rejects another tenant obtained from the current registration before writes' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant',
            'Thumbprint : 0123456789abcdef0123456789abcdef01234567')
        Mock Get-ItemProperty { [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555' } }
        { & $clientPreflight -Mode Configure -ExpectedTenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } |
            Should Throw 'CLIENT_WRONG_TENANT'
        Assert-MockCalled New-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'resolves a blank tenant without consuming the next field or reinitializing join' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant',
            "TenantID : `r`nMdmUrl : `r`nTHUMBPRINT : 0123456789ABCDEF0123456789ABCDEF01234567")
        Mock Get-ItemProperty { [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555' } }
        $result = @(& $clientPreflight -Mode InitializeRegistration)
        $result -contains 'CLIENT_HYBRID_JOIN_READY' | Should Be $true
        Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'does not use registry metadata to override an explicit dsregcmd tenant' {
        { & $clientPreflight -Mode Check -ExpectedTenantId another-tenant } |
            Should Throw 'CLIENT_WRONG_TENANT'
        Assert-MockCalled Get-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'rejects absent or unreadable registration metadata without choosing another key' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant',
            'Thumbprint : 0123456789abcdef0123456789abcdef01234567')
        Mock Get-ItemProperty { throw 'Registration key not accessible' }
        { & $clientPreflight -Mode Configure -ExpectedTenantId test-tenant } |
            Should Throw 'CLIENT_TENANT_ID_UNAVAILABLE'
        Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It
        Assert-MockCalled New-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'rejects empty malformed and zero registration tenants' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant',
            'Thumbprint : 0123456789abcdef0123456789abcdef01234567')
        foreach ($invalidTenant in @('', 'not-a-guid', '00000000-0000-0000-0000-000000000000')) {
            $script:registrationTenant = $invalidTenant
            Mock Get-ItemProperty { [pscustomobject]@{ TenantId = $registrationTenant } }
            { & $clientPreflight -Mode Configure -ExpectedTenantId test-tenant } |
                Should Throw 'CLIENT_TENANT_ID_UNAVAILABLE'
        }
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'rejects invalid or missing thumbprints rather than constructing an unbound path' {
        foreach ($invalidThumbprint in @('', '*', '..', 'abcd', ('0' * 41))) {
            $script:deviceStatus = "DomainJoined : YES`nAzureAdJoined : YES`nDeviceAuthStatus : SUCCESS`nThumbprint : $invalidThumbprint`nTenantId :"
            { & $clientPreflight -Mode Configure -ExpectedTenantId test-tenant } |
                Should Throw 'CLIENT_TENANT_ID_UNAVAILABLE'
        }
        Assert-MockCalled Get-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-ItemProperty -Times 0 -Exactly -Scope It
    }

    It 'does not use a registration entry to promote an unhealthy device to ready' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant',
            'Thumbprint : 0123456789abcdef0123456789abcdef01234567').Replace('SUCCESS', 'FAILED')
        { & $clientPreflight -Mode Check } | Should Throw 'CLIENT_TENANT_ID_UNAVAILABLE'
        Assert-MockCalled Get-ItemProperty -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Exactly -Scope It
    }

    It 'does not consult registration metadata for a pending device' {
        $script:deviceStatus = $deviceStatus.Replace('TenantId : test-tenant',
            'Thumbprint : 0123456789abcdef0123456789abcdef01234567').Replace('AzureAdJoined : YES', 'AzureAdJoined : NO')
        $result = @(& $clientPreflight -Mode InitializeRegistration -ExpectedTenantId test-tenant)
        $result -contains 'CLIENT_REGISTRATION_STARTED_NOT_READY' | Should Be $true
        Assert-MockCalled Get-ItemProperty -Times 0 -Exactly -Scope It
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

Describe 'Hybrid share RBAC (offline)' {
    BeforeEach {
        $script:shareUpn = 'hybrid-labuser1@example.onmicrosoft.com'
        $script:shareUserId = '11111111-2222-3333-4444-555555555555'
        $script:storageId = '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/azflabtest'
        $script:shareScope = "$storageId/fileServices/default/fileshares/labshare"
        $script:shareRole = 'Storage File Data SMB Share Contributor'
        $script:resolvedUser = [pscustomobject]@{ Id = $shareUserId; UserPrincipalName = $shareUpn }
        $script:expectedAssignment = [pscustomobject]@{
            ObjectId = $shareUserId; Scope = $shareScope; RoleDefinitionName = $shareRole
        }
        $script:existingAssignments = @()
        Mock Get-AzADUser { $resolvedUser }
        Mock Get-AzRoleAssignment { $existingAssignments }
        Mock New-AzRoleAssignment {
            $script:existingAssignments = @($expectedAssignment)
            $expectedAssignment
        }
        Mock Write-Warning {}
    }

    It 'resolves the exact cloud UPN and creates only a labshare-scoped contributor role' {
        Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId
        Assert-MockCalled Get-AzADUser -Times 1 -Exactly -Scope It -ParameterFilter {
            $UserPrincipalName -eq 'hybrid-labuser1@example.onmicrosoft.com'
        }
        Assert-MockCalled New-AzRoleAssignment -Times 1 -Exactly -Scope It -ParameterFilter {
            $ObjectId -eq $shareUserId -and $Scope -eq $shareScope -and
            $RoleDefinitionName -eq 'Storage File Data SMB Share Contributor'
        }
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -match 'not an SMB access check' -and $Message -match '30 minutes'
        }
    }

    It 'does not duplicate the same assignment when rerun' {
        Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId
        Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId
        Assert-MockCalled Get-AzRoleAssignment -Times 2 -Exactly -Scope It
        Assert-MockCalled New-AzRoleAssignment -Times 1 -Exactly -Scope It
    }

    It 'reuses an existing assignment regardless of scope or UPN casing' {
        $script:resolvedUser.UserPrincipalName = $shareUpn.ToUpperInvariant()
        $script:expectedAssignment.Scope = $shareScope.ToUpperInvariant()
        $script:existingAssignments = @($expectedAssignment)
        Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'does not mistake another user role or scope for the requested assignment' {
        $script:existingAssignments = @(
            [pscustomobject]@{ ObjectId = '99999999-2222-3333-4444-555555555555'; Scope = $shareScope; RoleDefinitionName = $shareRole }
            [pscustomobject]@{ ObjectId = $shareUserId; Scope = $shareScope; RoleDefinitionName = 'Owner' }
            [pscustomobject]@{ ObjectId = $shareUserId; Scope = $storageId; RoleDefinitionName = $shareRole }
        )
        Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId
        Assert-MockCalled New-AzRoleAssignment -Times 1 -Exactly -Scope It -ParameterFilter {
            $ObjectId -eq $shareUserId -and $Scope -eq $shareScope -and $RoleDefinitionName -eq $shareRole
        }
    }

    It 'stops on a missing ambiguous or different UPN before reading or writing RBAC' {
        foreach ($users in @(
            @{ Value = @() }
            @{ Value = @($resolvedUser, $resolvedUser) }
            @{ Value = @([pscustomobject]@{ Id = $shareUserId; UserPrincipalName = 'labuser1@example.onmicrosoft.com' }) }
        )) {
            $script:resolvedUser = $users.Value
            { Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId } |
                Should Throw 'SHARE_RBAC_USER_NOT_FOUND'
        }
        Assert-MockCalled Get-AzRoleAssignment -Times 0 -Exactly -Scope It
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'rejects invalid user object IDs without assigning roles' {
        foreach ($invalidId in @('', 'not-a-guid', '00000000-0000-0000-0000-000000000000')) {
            $script:resolvedUser.Id = $invalidId
            { Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId } |
                Should Throw 'SHARE_RBAC_USER_NOT_FOUND'
        }
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'does not accept a display name or domain logon in place of a UPN' {
        foreach ($invalidUpn in @('', 'labuser1', 'CONTOSO\labuser1', ' labuser1@example.com')) {
            $rejected = $false
            try {
                Grant-LabShareAccess -UserPrincipalName $invalidUpn -StorageAccountId $storageId -ErrorAction Stop
            } catch [System.Management.Automation.ParameterBindingException] {
                $rejected = $true
            }
            $rejected | Should Be $true
        }
        Assert-MockCalled Get-AzADUser -Times 0 -Exactly -Scope It
    }

    It 'rejects an empty or non-storage-account scope before any Azure calls' {
        foreach ($invalidScope in @('', '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', "$storageId/fileServices/default")) {
            $rejected = $false
            try {
                Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $invalidScope -ErrorAction Stop
            } catch [System.Management.Automation.ParameterBindingException] {
                $rejected = $true
            }
            $rejected | Should Be $true
        }
        Assert-MockCalled Get-AzADUser -Times 0 -Exactly -Scope It
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'surfaces directory lookup errors rather than substituting another identity' {
        Mock Get-AzADUser { throw 'Directory read denied' }
        { Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId } |
            Should Throw 'Directory read denied'
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'does not mistake a failed RBAC read for an absent assignment' {
        Mock Get-AzRoleAssignment { throw 'RBAC read denied' }
        { Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId } |
            Should Throw 'RBAC read denied'
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'surfaces insufficient role-assignment permission without claiming success' {
        Mock New-AzRoleAssignment { throw 'Microsoft.Authorization/roleAssignments/write denied' }
        { Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId } |
            Should Throw 'roleAssignments/write denied'
        Assert-MockCalled Write-Warning -Times 0 -Exactly -Scope It
    }

    It 'rejects an absent or mismatched create response instead of claiming success' {
        foreach ($response in @(
            @{ Value = $null }
            @{ Value = [pscustomobject]@{ ObjectId = $shareUserId; Scope = $storageId; RoleDefinitionName = $shareRole } }
            @{ Value = [pscustomobject]@{ ObjectId = '99999999-2222-3333-4444-555555555555'; Scope = $shareScope; RoleDefinitionName = $shareRole } }
            @{ Value = [pscustomobject]@{ ObjectId = $shareUserId; Scope = $shareScope; RoleDefinitionName = 'Owner' } }
        )) {
            $script:createdResponse = $response.Value
            Mock New-AzRoleAssignment { $createdResponse }
            { Grant-LabShareAccess -UserPrincipalName $shareUpn -StorageAccountId $storageId } |
                Should Throw 'SHARE_RBAC_NOT_CONFIRMED'
        }
        Assert-MockCalled Write-Warning -Times 0 -Exactly -Scope It
    }
}

Describe 'Opt-in RBAC setup wiring (offline)' {
    BeforeEach {
        $script:setupUpn = 'hybrid-labuser1@example.onmicrosoft.com'
        $script:setupUserId = '11111111-2222-3333-4444-555555555555'
        $script:setupStorageId = '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/azflabtest'
        $script:missingResourcesModule = $false
        Mock Get-TestAvailableModule {
            if ($Name -eq 'Az.Resources' -and $missingResourcesModule) { return }
            [pscustomobject]@{ Name = $Name }
        }
        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'test-tenant' } } }
        Mock Invoke-AzVMRunCommand {
            [pscustomobject]@{ Value = @(
                [pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = 'CLIENT_HYBRID_JOIN_READY' }
                [pscustomobject]@{ Code = 'ComponentStatus/StdErr/succeeded'; Message = '' }
            ) }
        }
        Mock Get-AzStorageAccount {
            [pscustomobject]@{
                Id = $setupStorageId
                StorageAccountName = 'azflabtest'
                AzureFilesIdentityBasedAuth = [pscustomobject]@{ DirectoryServiceOptions = 'AD' }
            }
        }
        Mock Get-AzADUser {
            [pscustomobject]@{ Id = $setupUserId; UserPrincipalName = $setupUpn }
        }
        Mock Get-AzRoleAssignment { @() }
        Mock New-AzRoleAssignment {
            [pscustomobject]@{ ObjectId = $ObjectId; Scope = $Scope; RoleDefinitionName = $RoleDefinitionName }
        }
        Mock Write-Warning {}
    }

    It 'preserves manual setup when the new parameter is omitted' {
        & $setupPreStorage -ResourceGroupName test-rg | Out-Null
        Assert-MockCalled Get-AzADUser -Times 0 -Exactly -Scope It
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-TestAvailableModule -Times 0 -Exactly -Scope It -ParameterFilter { $Name -eq 'Az.Resources' }
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -match 'share RBAC is unchanged'
        }
    }

    It 'requires an explicit user for the two-share lab before Azure calls' {
        { & $setupPreStorage -ResourceGroupName test-rg -PrepareRbacLab } |
            Should Throw 'PrepareRbacLab requires ShareUserPrincipalName'
        Assert-MockCalled Get-AzContext -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'gates both lab planning and initialization behind the explicit opt-in flag' {
        $setupSource | Should Match '(?s)if \(\$PrepareRbacLab\) \{\s+\$rbacLabPlan = Get-RbacFirstLabPlan'
        $setupSource | Should Match '(?s)if \(\$PrepareRbacLab\) \{\s+Step ''2b/4[^'']*''\s+Initialize-RbacFirstLab'
        ($setupSource.IndexOf('Get-RbacFirstLabPlan -ResourceGroupName') -lt
            $setupSource.IndexOf('Step "2/4 Enabling')) | Should Be $true
        ($setupSource.IndexOf('Initialize-RbacFirstLab -Plan') -lt
            $setupSource.IndexOf('Invoke-LabClientConfiguration -Mode Configure')) | Should Be $true
    }

    It 'wires the selected UPN and discovered account to share-scoped RBAC' {
        & $setupPreStorage -ResourceGroupName test-rg -ShareUserPrincipalName $setupUpn | Out-Null
        Assert-MockCalled Get-TestAvailableModule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'Az.Resources' }
        Assert-MockCalled New-AzRoleAssignment -Times 1 -Exactly -Scope It -ParameterFilter {
            $ObjectId -eq $setupUserId -and
            $Scope -eq "$setupStorageId/fileServices/default/fileshares/labshare"
        }
    }

    It 'runs opt-in preparation end to end before consent and only assigns the healthy share role' {
        $script:testShareCreated = $false
        Mock Get-AzStorageAccount {
            [pscustomobject]@{
                Id = $setupStorageId; StorageAccountName = 'azflabtest'; Kind = 'StorageV2'
                AzureFilesIdentityBasedAuth = [pscustomobject]@{
                    DirectoryServiceOptions = 'AADKERB'; DefaultSharePermission = 'None'
                }
            }
        }
        Mock Get-AzRmStorageShare {
            if (-not $Name) {
                [pscustomobject]@{ Name = 'labshare'; EnabledProtocols = 'SMB'; Metadata = $null }
                if ($testShareCreated) {
                    [pscustomobject]@{ Name = 'rbac-lab'; EnabledProtocols = 'SMB'; Metadata = $null }
                }
            } elseif ($Name -eq 'rbac-lab' -and $testShareCreated) {
                [pscustomobject]@{
                    Name = 'rbac-lab'; EnabledProtocols = 'SMB'
                    Metadata = @{ azfiles_lab = 'rbac-first-lab-v1'; user_object_id = $setupUserId }
                }
            }
        }
        Mock New-AzRmStorageShare { $script:testShareCreated = $true }
        Mock Get-AzStorageAccountKey {
            [pscustomobject]@{ KeyName = 'key1'; Value = 'TEST-ONLY-SETUP-KEY' }
        }
        Mock Invoke-AzVMRunCommand {
            if ($VMName -eq 'azflab-dc' -and (
                $Parameter.StorageAccountName -ne 'azflabtest' -or
                $Parameter.StorageKey -ne 'TEST-ONLY-SETUP-KEY')) {
                throw 'DC payload received incorrect parameters'
            }
            $marker = if ($VMName -eq 'azflab-dc') { 'RBAC_LAB_ACL_READY' } else { 'CLIENT_HYBRID_JOIN_READY' }
            [pscustomobject]@{ Value = @(
                [pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = $marker }
                [pscustomobject]@{ Code = 'ComponentStatus/StdErr/succeeded'; Message = '' }
            ) }
        }
        & $setupPreConsent -ResourceGroupName test-rg -ShareUserPrincipalName $setupUpn -PrepareRbacLab | Out-Null
        Assert-MockCalled New-AzRoleAssignment -Times 1 -Exactly -Scope It -ParameterFilter {
            $ObjectId -eq $setupUserId -and
            $Scope -eq "$setupStorageId/fileServices/default/fileshares/labshare"
        }
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It -ParameterFilter {
            $Scope -like '*/rbac-lab'
        }
        Assert-MockCalled New-AzRmStorageShare -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'rbac-lab' }
        Assert-MockCalled Get-AzRmStorageShare -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'rbac-lab' }
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It -ParameterFilter { $VMName -eq 'azflab-dc' }
    }

    It 'stops before lookup or RBAC when the client is not ready' {
        Mock Invoke-AzVMRunCommand { throw 'Client not ready' }
        { & $setupPreStorage -ResourceGroupName test-rg -ShareUserPrincipalName $setupUpn } |
            Should Throw 'Client not ready'
        Assert-MockCalled Get-AzADUser -Times 0 -Exactly -Scope It
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'requires Az.Resources only when opting into RBAC' {
        $script:missingResourcesModule = $true
        { & $setupPreStorage -ResourceGroupName test-rg -ShareUserPrincipalName $setupUpn } |
            Should Throw "Missing module 'Az.Resources'"
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
        Assert-MockCalled New-AzRoleAssignment -Times 0 -Exactly -Scope It
    }

    It 'propagates RBAC failures before the storage transition' {
        Mock New-AzRoleAssignment { throw 'Role assignment denied' }
        { & $setupPreStorage -ResourceGroupName test-rg -ShareUserPrincipalName $setupUpn } |
            Should Throw 'Role assignment denied'
        $grantOffset = $setupSource.IndexOf('Grant-LabShareAccess -UserPrincipalName $ShareUserPrincipalName')
        ($grantOffset -gt 0 -and $grantOffset -lt $setupSource.IndexOf('Set-AzStorageAccount')) | Should Be $true
        ($grantOffset -lt $setupSource.IndexOf('Invoke-LabClientConfiguration -Mode Configure')) | Should Be $true
    }

    It 'does not change default permissions or remove existing RBAC' {
        $setupSource | Should Not Match 'Set-AzStorageAccount[^\r\n]*DefaultSharePermission|Remove-AzRoleAssignment'
        $grantFunction.Extent.Text | Should Not Match 'DefaultSharePermission|Set-Acl|icacls|Remove-Az'
    }

    It 'documents propagation manual mode and the default-only fault limitation' {
        $guide = Get-Content (Join-Path $root 'MANUAL-STEP-connect-sync.md') -Raw
        $guide | Should Match 'ShareUserPrincipalName'
        $guide | Should Match '30 minutes'
        $guide | Should Match 'If you omit the parameter'
        $guide | Should Match 'does \*\*not\*\* revoke this explicit user RBAC'
        $faultSource = Get-Content (Join-Path $root 'faults\Invoke-Fault.ps1') -Raw
        $faultSource | Should Match "Write-Warning 'NoShareAccess changes only default share permission"
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
