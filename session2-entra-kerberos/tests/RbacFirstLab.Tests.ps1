$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts\Initialize-RbacFirstLab.ps1')

function Get-AzRoleAssignment {
    [CmdletBinding()]
    param($ObjectId, $Scope, [switch]$ExpandPrincipalGroups)
    throw 'Unmocked role read'
}
function Get-AzRoleDefinition { [CmdletBinding()] param($Id) throw 'Unmocked role definition read' }
function Get-AzRmStorageShare {
    [CmdletBinding()] param($ResourceGroupName, $StorageAccountName)
    throw 'Unmocked share read'
}
function New-AzRmStorageShare {
    # Pester 3 has an internal typed $Metadata variable; bind the real name as an alias.
    [CmdletBinding()] param($ResourceGroupName, $StorageAccountName, $Name, $EnabledProtocol, $QuotaGiB,
        [Alias('Metadata')]$LabMetadata)
    throw 'Unmocked share creation'
}
function Get-AzStorageAccount {
    [CmdletBinding()] param($ResourceGroupName, $Name)
    throw 'Unmocked account read'
}
function Set-AzStorageAccount {
    [CmdletBinding()] param($ResourceGroupName, $Name, $DefaultSharePermission)
    throw 'Unmocked account write'
}
function Get-AzStorageAccountKey {
    [CmdletBinding()] param($ResourceGroupName, $Name)
    throw 'Unmocked key read'
}
function Invoke-AzVMRunCommand {
    [CmdletBinding()] param($ResourceGroupName, $VMName, $CommandId, $ScriptPath, $Parameter)
    throw 'Unmocked VM command'
}

Describe 'Two-share RBAC first lab (offline)' {
    BeforeEach {
        $script:userId = '11111111-2222-3333-4444-555555555555'
        $script:groupId = '22222222-2222-3333-4444-555555555555'
        $script:roleId = '33333333-2222-3333-4444-555555555555'
        $script:accountId = '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/azflabtest'
        $script:testScope = "$accountId/fileServices/default/fileshares/rbac-lab"
        $script:account = [pscustomobject]@{
            StorageAccountName = 'azflabtest'; Id = $accountId; Kind = 'StorageV2'
            AzureFilesIdentityBasedAuth = [pscustomobject]@{
                DirectoryServiceOptions = 'AADKERB'; DefaultSharePermission = 'None'
            }
        }
        $script:sourceShare = [pscustomobject]@{ Name = 'labshare'; EnabledProtocols = 'SMB'; Metadata = @{} }
        $script:ownedShare = [pscustomobject]@{
            Name = 'rbac-lab'; EnabledProtocols = 'SMB'
            Metadata = @{ azfiles_lab = 'rbac-first-lab-v1'; user_object_id = $userId }
        }
        $script:shares = @($sourceShare)
        $script:effective = @()
        $script:expanded = @()
        $script:definition = [pscustomobject]@{ DataActions = @(); NotDataActions = @() }
        $script:assignment = [pscustomobject]@{
            ObjectId = $userId; RoleDefinitionId = $roleId
            RoleDefinitionName = 'test-role'; Scope = $testScope
        }
        $script:plan = [pscustomobject]@{
            ResourceGroupName = 'test-rg'; StorageAccountName = 'azflabtest'
            StorageAccountId = $accountId; UserObjectId = $userId
            TestShareScope = $testScope; TargetExists = $false
        }
        $script:roleReadFailure = $false
        $script:expansionFailure = $false
        $script:shareReadFailure = $false
        $script:createFailure = $false
        $script:createInvisible = $false
        $script:keyUnavailable = $false
        $script:transportFailure = $false
        $script:defaultUnchanged = $false
        $script:remoteOutput = 'RBAC_LAB_ACL_READY'
        $script:remoteError = ''
        $script:testKey = 'TEST-ONLY-REDACTION-MARKER'
        Mock Get-AzRoleAssignment {
            if ($ExpandPrincipalGroups) {
                if ($Scope) { throw 'Invalid combination: ExpandPrincipalGroups with Scope' }
                if ($expansionFailure) { throw 'Group expansion denied' }
                return $expanded
            }
            if ($roleReadFailure) { throw 'Role read denied' }
            $effective
        }
        Mock Get-AzRoleDefinition { $definition }
        Mock Get-AzRmStorageShare {
            if ($shareReadFailure) { throw 'Share listing denied' }
            $shares
        }
        Mock New-AzRmStorageShare {
            if ($createFailure) { throw 'Share creation denied' }
            if (-not $createInvisible) { $script:shares = @($sourceShare, $ownedShare) }
        }
        Mock Get-AzStorageAccount { $account }
        Mock Set-AzStorageAccount {
            if (-not $defaultUnchanged) { $account.AzureFilesIdentityBasedAuth.DefaultSharePermission = 'None' }
        }
        Mock Get-AzStorageAccountKey {
            if (-not $keyUnavailable) { [pscustomobject]@{ KeyName = 'key1'; Value = $testKey } }
        }
        Mock Invoke-AzVMRunCommand {
            if ($transportFailure) { throw "Transport failure $testKey" }
            [pscustomobject]@{ Value = @(
                [pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = $remoteOutput }
                [pscustomobject]@{ Code = 'ComponentStatus/StdErr/succeeded'; Message = $remoteError }
            ) }
        }
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'plans a separate test share without changing resources' {
        $p = Get-RbacFirstLabPlan -ResourceGroupName test-rg -StorageAccount $account -UserObjectId $userId
        $p.TargetExists | Should Be $false
        $p.TestShareScope | Should Be $testScope
        Assert-MockCalled New-AzRmStorageShare -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-AzStorageAccount -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-AzRoleAssignment -Times 1 -Exactly -Scope It -ParameterFilter {
            $ObjectId -eq $userId -and $ExpandPrincipalGroups -and -not $Scope
        }
    }

    It 'rejects missing source or an NFS source without changing it' {
        $script:shares = @()
        { Get-RbacFirstLabPlan -ResourceGroupName test-rg -StorageAccount $account -UserObjectId $userId } |
            Should Throw 'RBAC_LAB_SOURCE_MISSING'
        $sourceShare.EnabledProtocols = 'NFS'
        $script:shares = @($sourceShare)
        { Get-RbacFirstLabPlan -ResourceGroupName test-rg -StorageAccount $account -UserObjectId $userId } |
            Should Throw 'RBAC_LAB_SOURCE_MISSING'
    }

    It 'rejects provisioned-capacity accounts' {
        $account.Kind = 'FileStorage'
        { Get-RbacFirstLabPlan -ResourceGroupName test-rg -StorageAccount $account -UserObjectId $userId } |
            Should Throw 'RBAC_LAB_ACCOUNT_UNSUPPORTED'
    }

    It 'refuses an existing unowned share or different lab user' {
        $script:shares = @($sourceShare, $ownedShare)
        $ownedShare.Metadata = $null
        { Get-RbacFirstLabPlan -ResourceGroupName test-rg -StorageAccount $account -UserObjectId $userId } |
            Should Throw 'RBAC_LAB_TARGET_NOT_OWNED'
        $ownedShare.Metadata = @{ azfiles_lab = 'rbac-first-lab-v1'; user_object_id = $groupId }
        { Get-RbacFirstLabPlan -ResourceGroupName test-rg -StorageAccount $account -UserObjectId $userId } |
            Should Throw 'RBAC_LAB_TARGET_NOT_OWNED'
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }

    It 'does not treat failed role or group reads as an empty authorization set' {
        $script:roleReadFailure = $true
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Throw 'Role read denied'
        $script:roleReadFailure = $false
        $script:expansionFailure = $true
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Throw 'Group expansion denied'
    }

    It 'rejects unreadable group expansion or role definitions' {
        $script:expanded = @([pscustomobject]@{ ObjectId = '' })
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Throw 'RBAC_LAB_AUDIT_INCOMPLETE'
        $script:expanded = @()
        $script:effective = @($assignment)
        $script:definition = $null
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Throw 'RBAC_LAB_AUDIT_INCOMPLETE'
    }

    It 'allows management-only and blob-only roles without mistaking Owner for SMB access' {
        $script:effective = @($assignment)
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Not Throw
        $definition.DataActions = @('Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read')
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Not Throw
    }

    It 'does not silently discard an unreadable effective principal' {
        $assignment.ObjectId = ''
        $script:effective = @($assignment)
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Throw 'RBAC_LAB_AUDIT_INCOMPLETE'
    }

    It 'stops on direct user data access instead of resetting a repaired lab' {
        $script:effective = @($assignment)
        $definition.DataActions = @('Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read')
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'RBAC_LAB_ALREADY_AUTHORIZED'
        Assert-MockCalled New-AzRmStorageShare -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-AzStorageAccount -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }

    It 'stops on inherited transitive-group roles including a management-group scope' {
        $assignment.ObjectId = $groupId
        $assignment.Scope = '/providers/Microsoft.Management/managementGroups/lab-parent'
        $script:effective = @($assignment)
        $script:expanded = @($assignment)
        $definition.DataActions = @('Microsoft.Storage/*')
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Throw 'RBAC_LAB_ALREADY_AUTHORIZED'
    }

    It 'ignores another principals role rather than falsely claiming it belongs to the selected user' {
        $assignment.ObjectId = $groupId
        $script:effective = @($assignment)
        $definition.DataActions = @('*')
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Not Throw
        Assert-MockCalled Get-AzRoleDefinition -Times 0 -Exactly -Scope It
    }

    It 'conservatively blocks custom wildcard ACL grants even with exclusions' {
        $script:effective = @($assignment)
        $definition.DataActions = @('Microsoft.Storage/storageAccounts/fileServices/*/files/modifypermissions/action')
        $definition.NotDataActions = @('*')
        { Assert-RbacLabNoDataRole -UserObjectId $userId -Scope $testScope } | Should Throw 'RBAC_LAB_ALREADY_AUTHORIZED'
    }

    It 'creates only the tagged 100 GiB SMB test share and uses the DC ACL helper' {
        Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc
        Assert-MockCalled New-AzRmStorageShare -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'rbac-lab' -and $EnabledProtocol -eq 'SMB' -and $QuotaGiB -eq 100 -and
            $LabMetadata.azfiles_lab -eq 'rbac-first-lab-v1' -and $LabMetadata.user_object_id -eq $userId
        }
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It -ParameterFilter {
            $VMName -eq 'test-dc' -and $ScriptPath -like '*scripts\copy-rbac-lab-acl.ps1'
        }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -eq 'RBAC_LAB_PROVISIONED_USER_CHECKS_REQUIRED'
        }
        Assert-MockCalled Set-AzStorageAccount -Times 0 -Exactly -Scope It
    }

    It 'reuses an owned unfinished test share without recreating it' {
        $script:shares = @($sourceShare, $ownedShare)
        Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc
        Assert-MockCalled New-AzRmStorageShare -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It
    }

    It 'stops if shares cannot be read or creation fails' {
        $script:shareReadFailure = $true
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'Share listing denied'
        $script:shareReadFailure = $false
        $script:createFailure = $true
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'Share creation denied'
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }

    It 'does not accept a successful creation response without readback' {
        $script:createInvisible = $true
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'RBAC_LAB_SHARE_NOT_CONFIRMED'
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }

    It 'rejects an incorrect auth mode before creating anything' {
        $account.AzureFilesIdentityBasedAuth.DirectoryServiceOptions = 'AD'
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'RBAC_LAB_STORAGE_NOT_READY'
        Assert-MockCalled New-AzRmStorageShare -Times 0 -Exactly -Scope It
    }

    It 'disables only default permission after copying ACLs and verifies the write' {
        $account.AzureFilesIdentityBasedAuth.DefaultSharePermission = 'StorageFileDataSmbShareContributor'
        Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc
        Assert-MockCalled Set-AzStorageAccount -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'azflabtest' -and $DefaultSharePermission -eq 'None'
        }
    }

    It 'rejects a default-permission update that did not take effect' {
        $account.AzureFilesIdentityBasedAuth.DefaultSharePermission = 'StorageFileDataSmbShareContributor'
        $script:defaultUnchanged = $true
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'RBAC_LAB_DEFAULT_PERMISSION_NOT_CONFIRMED'
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter {
            $Object -eq 'RBAC_LAB_PROVISIONED_USER_CHECKS_REQUIRED'
        }
    }

    It 'does not run remote provisioning without the expected key' {
        $script:keyUnavailable = $true
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'RBAC_LAB_KEY_UNAVAILABLE'
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }

    It 'requires the exact remote marker and empty stderr' {
        $script:remoteOutput = 'Expected RBAC_LAB_ACL_READY'
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'RBAC_LAB_ACL_FAILED'
        $script:remoteOutput = 'RBAC_LAB_ACL_READY'
        $script:remoteError = 'ACL verification failed'
        { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } | Should Throw 'ACL verification failed'
        Assert-MockCalled Set-AzStorageAccount -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter {
            $Object -eq 'RBAC_LAB_PROVISIONED_USER_CHECKS_REQUIRED'
        }
    }

    It 'redacts the runtime key from transport and remote error messages' {
        foreach ($transport in @($true, $false)) {
            $script:transportFailure = $transport
            $script:remoteError = "Remote failed $testKey"
            $message = ''
            try { Initialize-RbacFirstLab -Plan $plan -DcVmName test-dc } catch { $message = $_.Exception.Message }
            $message | Should Match 'RBAC_LAB_ACL_FAILED'
            $message | Should Match '<redacted>'
            $message | Should Not Match $testKey
        }
    }

    It 'never changes RBAC or removes shares and never sleeps for propagation' {
        $source = Get-Content (Join-Path $root 'scripts\Initialize-RbacFirstLab.ps1') -Raw
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
        $commands = $ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() }
        ($commands -contains 'New-AzRoleAssignment') | Should Be $false
        ($commands -contains 'Remove-AzRoleAssignment') | Should Be $false
        ($commands -contains 'Remove-AzRmStorageShare') | Should Be $false
        ($commands -contains 'Start-Sleep') | Should Be $false
    }
}
