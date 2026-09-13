# Dot-sourced by setup.ps1 only for the opt-in, presenter-owned two-share lab.
function Assert-RbacLabNoDataRole {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid]$UserObjectId,
        [Parameter(Mandatory)] [string]$Scope
    )
    $effective = @(Get-AzRoleAssignment -Scope $Scope -ErrorAction Stop)
    # ExpandPrincipalGroups cannot be combined with Scope. Resolve memberships
    # through the subscription query, then intersect with effective scoped roles.
    $expanded = @(Get-AzRoleAssignment -ObjectId $UserObjectId.ToString() -ExpandPrincipalGroups -ErrorAction Stop)
    $principals = @($UserObjectId.ToString())
    foreach ($entry in $expanded) {
        $id = [guid]::Empty
        if (-not [guid]::TryParse([string]$entry.ObjectId, [ref]$id) -or $id -eq [guid]::Empty) {
            throw 'RBAC_LAB_AUDIT_INCOMPLETE: principal expansion returned an unreadable object ID.'
        }
        $principals += $id.ToString()
    }
    foreach ($assignment in $effective) {
        $principalId = [guid]::Empty
        if (-not [guid]::TryParse([string]$assignment.ObjectId, [ref]$principalId) -or $principalId -eq [guid]::Empty) {
            throw 'RBAC_LAB_AUDIT_INCOMPLETE: an effective assignment has no readable principal ID.'
        }
        if ($principalId.ToString() -notin $principals) { continue }
        $roleId = [guid]::Empty
        if (-not [guid]::TryParse(([string]$assignment.RoleDefinitionId).Split('/')[-1], [ref]$roleId)) {
            throw 'RBAC_LAB_AUDIT_INCOMPLETE: an effective assignment has no readable role definition ID.'
        }
        $definitions = @(Get-AzRoleDefinition -Id $roleId.ToString() -ErrorAction Stop)
        if ($definitions.Count -ne 1 -or $null -eq $definitions[0] -or
            -not $definitions[0].PSObject.Properties['DataActions']) {
            throw "RBAC_LAB_AUDIT_INCOMPLETE: could not read role definition $roleId."
        }
        $fileActions = @(
            foreach ($action in $definitions[0].DataActions) {
                if ($action -like 'Microsoft.Storage/storageAccounts/fileServices/fileshares/*') {
                    $action
                    continue
                }
                foreach ($operation in @('read', 'write', 'delete', 'modifypermissions/action',
                    'readFileBackupSemantics/action', 'writeFileBackupSemantics/action',
                    'takeOwnership/action', 'actAsSuperUser/action')) {
                    if ("Microsoft.Storage/storageAccounts/fileServices/fileshares/files/$operation" -like $action) {
                        $action
                        break
                    }
                }
            }
        )
        # Conservatively stop even for conditioned roles / NotDataActions exclusions.
        if ($fileActions.Count -gt 0) {
            throw "RBAC_LAB_ALREADY_AUTHORIZED: role '$($assignment.RoleDefinitionName)' for principal '$($assignment.ObjectId)' at '$($assignment.Scope)' may authorize rbac-lab. No role was removed. Use a clean lab or review this assignment manually; do not reset a repaired lab during class."
        }
    }
}

function Get-RbacFirstLabPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ResourceGroupName,
        [Parameter(Mandatory)] $StorageAccount,
        [Parameter(Mandatory)] [guid]$UserObjectId
    )
    if ($UserObjectId -eq [guid]::Empty) { throw 'RBAC_LAB_USER_REQUIRED: select the exact lab user.' }
    if ($StorageAccount.Kind -ne 'StorageV2') {
        throw 'RBAC_LAB_ACCOUNT_UNSUPPORTED: this optional lab expects the Session 1 StorageV2 account, not a provisioned-capacity account.'
    }
    $shares = @(Get-AzRmStorageShare -ResourceGroupName $ResourceGroupName `
        -StorageAccountName $StorageAccount.StorageAccountName -ErrorAction Stop)
    $source = @($shares | Where-Object Name -eq 'labshare')
    $target = @($shares | Where-Object Name -eq 'rbac-lab')
    if ($source.Count -ne 1 -or $source[0].EnabledProtocols -eq 'NFS') {
        throw 'RBAC_LAB_SOURCE_MISSING: one existing SMB labshare is required.'
    }
    if ($target.Count -gt 1) { throw 'RBAC_LAB_TARGET_AMBIGUOUS: more than one rbac-lab was returned.' }
    if ($target.Count -eq 1 -and (
        $target[0].EnabledProtocols -eq 'NFS' -or
        $null -eq $target[0].Metadata -or
        $target[0].Metadata['azfiles_lab'] -ne 'rbac-first-lab-v1' -or
        $target[0].Metadata['user_object_id'] -ne $UserObjectId.ToString())) {
        throw 'RBAC_LAB_TARGET_NOT_OWNED: rbac-lab already exists without matching lab/user metadata. It was not modified.'
    }
    $scope = "$($StorageAccount.Id)/fileServices/default/fileshares/rbac-lab"
    Assert-RbacLabNoDataRole -UserObjectId $UserObjectId -Scope $scope
    [pscustomobject]@{
        ResourceGroupName = $ResourceGroupName
        StorageAccountName = $StorageAccount.StorageAccountName
        StorageAccountId = $StorageAccount.Id
        UserObjectId = $UserObjectId.ToString()
        TestShareScope = $scope
        TargetExists = ($target.Count -eq 1)
    }
}

function Initialize-RbacFirstLab {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] [string]$DcVmName
    )
    $accountParameters = @{ ResourceGroupName = $Plan.ResourceGroupName; Name = $Plan.StorageAccountName; ErrorAction = 'Stop' }
    $account = Get-AzStorageAccount @accountParameters
    if ($account.Id -ne $Plan.StorageAccountId -or
        $account.AzureFilesIdentityBasedAuth.DirectoryServiceOptions -ne 'AADKERB') {
        throw 'RBAC_LAB_STORAGE_NOT_READY: the selected account must have Entra Kerberos enabled.'
    }
    # Re-read the plan before mutations; never trust an old TargetExists flag.
    $current = Get-RbacFirstLabPlan -ResourceGroupName $Plan.ResourceGroupName `
        -StorageAccount $account -UserObjectId $Plan.UserObjectId
    if (-not $current.TargetExists) {
        New-AzRmStorageShare -ResourceGroupName $Plan.ResourceGroupName `
            -StorageAccountName $Plan.StorageAccountName -Name 'rbac-lab' -EnabledProtocol SMB `
            -QuotaGiB 100 -Metadata @{
                azfiles_lab = 'rbac-first-lab-v1'
                user_object_id = $Plan.UserObjectId
            } -ErrorAction Stop | Out-Null
        $current = Get-RbacFirstLabPlan -ResourceGroupName $Plan.ResourceGroupName `
            -StorageAccount $account -UserObjectId $Plan.UserObjectId
        if (-not $current.TargetExists) { throw 'RBAC_LAB_SHARE_NOT_CONFIRMED: rbac-lab creation was not confirmed.' }
    }

    $storageKey = $null
    $keys = $null
    $payloadParameters = $null
    try {
        $keys = @(Get-AzStorageAccountKey -ResourceGroupName $Plan.ResourceGroupName `
            -Name $Plan.StorageAccountName -ErrorAction Stop -Verbose:$false -Debug:$false |
            Where-Object KeyName -eq 'key1')
        if ($keys.Count -ne 1 -or [string]::IsNullOrWhiteSpace($keys[0].Value)) {
            throw 'RBAC_LAB_KEY_UNAVAILABLE: could not read key1 for the ACL provisioning step.'
        }
        $storageKey = $keys[0].Value
        $payloadParameters = @{ StorageAccountName = $Plan.StorageAccountName; StorageKey = $storageKey }
        try {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $Plan.ResourceGroupName -VMName $DcVmName `
                -CommandId RunPowerShellScript -ScriptPath (Join-Path $PSScriptRoot 'copy-rbac-lab-acl.ps1') `
                -Parameter $payloadParameters -ErrorAction Stop -Verbose:$false -Debug:$false
        } catch {
            $message = $_.Exception.Message.Replace($storageKey, '<redacted>')
            throw "RBAC_LAB_ACL_FAILED: $message"
        }
        $stdout = ((($result.Value | Where-Object Code -like '*StdOut*').Message) -join "`n").Replace($storageKey, '<redacted>')
        $stderr = ((($result.Value | Where-Object Code -like '*StdErr*').Message) -join "`n").Replace($storageKey, '<redacted>')
        if ($stderr.Trim() -or $stdout -notmatch '(?m)^RBAC_LAB_ACL_READY\r?$') {
            throw "RBAC_LAB_ACL_FAILED: DC did not confirm matching root DACLs and cleanup. $stderr $stdout"
        }
    } finally {
        if ($payloadParameters) { $payloadParameters.StorageKey = $null }
        $storageKey = $null
        $keys = $null
    }

    if ($account.AzureFilesIdentityBasedAuth.DefaultSharePermission -ne 'None') {
        Write-Warning 'PrepareRbacLab disables DEFAULT share permission for ALL shares on this dedicated lab account. Existing explicit RBAC and labshare ACLs are not removed.'
        Set-AzStorageAccount @accountParameters -DefaultSharePermission None | Out-Null
    }
    $updated = Get-AzStorageAccount @accountParameters
    if ($updated.AzureFilesIdentityBasedAuth.DefaultSharePermission -ne 'None') {
        throw 'RBAC_LAB_DEFAULT_PERMISSION_NOT_CONFIRMED: default share permission is not None. Do not present the denial lab yet.'
    }
    Assert-RbacLabNoDataRole -UserObjectId $Plan.UserObjectId -Scope $Plan.TestShareScope
    Write-Host 'RBAC_LAB_PROVISIONED_USER_CHECKS_REQUIRED'
    Write-Host 'Root DACLs matched using administrative storage-key access; this does NOT prove the user baseline.'
    Write-Host 'Before class: same user must access labshare, receive Access Denied on rbac-lab, and hold a valid CIFS ticket. Allow prior RBAC/default-permission changes to propagate.'
    Write-Host 'During class: diagnose and assign the role, then continue on labshare. Verify rbac-lab recovery later with all other faults repaired; do not wait in a blocking loop.'
    Write-Host 'Recovery command (Cloud Shell; record the assignment time):'
    Write-Host "New-AzRoleAssignment -ObjectId '$($Plan.UserObjectId)' -RoleDefinitionName 'Storage File Data SMB Share Contributor' -Scope '$($Plan.TestShareScope)' -ErrorAction Stop"
}
