# Copies only the root DACL, using administrative storage-key access on azflab-dc.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('\A[a-z0-9]{3,24}\z', Options = 'None')]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$StorageKey
)

$ErrorActionPreference = 'Stop'
$access = [System.Security.AccessControl.AccessControlSections]::Access
$attemptedMounts = @()
$failure = $null
$cleanupFailures = @()
$secureKey = $null
$credential = $null
$stage = 'credential creation'

try {
    $secureKey = ConvertTo-SecureString -String $StorageKey -AsPlainText -Force -ErrorAction Stop
    $credential = New-Object System.Management.Automation.PSCredential(
        "localhost\$StorageAccountName", $secureKey
    )

    $stage = 'mount preparation'
    $existingNames = @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop |
        Select-Object -ExpandProperty Name)
    do { $sourceName = 'RbacSrc' + [guid]::NewGuid().ToString('N') }
    while ($existingNames -contains $sourceName)
    do { $targetName = 'RbacDst' + [guid]::NewGuid().ToString('N') }
    while ($existingNames -contains $targetName -or $targetName -eq $sourceName)
    $sourceRoot = "${sourceName}:\"
    $targetRoot = "${targetName}:\"

    $stage = 'source authentication and mount'
    $attemptedMounts += $sourceName
    New-PSDrive -Name $sourceName -PSProvider FileSystem `
        -Root "\\$StorageAccountName.file.core.windows.net\labshare" `
        -Credential $credential -Scope Local -ErrorAction Stop | Out-Null

    $stage = 'destination authentication and mount'
    $attemptedMounts += $targetName
    New-PSDrive -Name $targetName -PSProvider FileSystem `
        -Root "\\$StorageAccountName.file.core.windows.net\rbac-lab" `
        -Credential $credential -Scope Local -ErrorAction Stop | Out-Null

    $stage = 'source DACL read'
    $sourceAcl = Get-Acl -LiteralPath $sourceRoot -ErrorAction Stop
    $expectedDacl = $sourceAcl.GetSecurityDescriptorSddlForm($access)
    $stage = 'destination DACL read'
    $targetAcl = Get-Acl -LiteralPath $targetRoot -ErrorAction Stop

    $stage = 'destination DACL write'
    $targetAcl.SetSecurityDescriptorSddlForm($expectedDacl, $access)
    Set-Acl -LiteralPath $targetRoot -AclObject $targetAcl -ErrorAction Stop

    $stage = 'source DACL verification'
    $sourceReadback = Get-Acl -LiteralPath $sourceRoot -ErrorAction Stop
    if ($sourceReadback.GetSecurityDescriptorSddlForm($access) -cne $expectedDacl) {
        throw 'Source root DACL changed during copy.'
    }
    $stage = 'destination DACL verification'
    $targetReadback = Get-Acl -LiteralPath $targetRoot -ErrorAction Stop
    if ($targetReadback.GetSecurityDescriptorSddlForm($access) -cne $expectedDacl) {
        throw 'Destination root DACL does not match.'
    }
}
catch {
    # Provider errors may contain credentials. Report the failed operation, never its raw error.
    $failure = "RBAC lab ACL preparation failed during $stage."
}
finally {
    if ($attemptedMounts.Count -gt 0) {
        try {
            $localMounts = @(Get-PSDrive -PSProvider FileSystem -Scope Local -ErrorAction Stop)
            foreach ($mountName in $attemptedMounts) {
                if ($localMounts.Name -contains $mountName) {
                    try {
                        Remove-PSDrive -Name $mountName -Scope Local -Force -ErrorAction Stop
                    }
                    catch {
                        $cleanupFailures += 'Temporary mount removal failed.'
                    }
                }
            }
            $remainingMounts = @(Get-PSDrive -PSProvider FileSystem -Scope Local -ErrorAction Stop)
            if (@($remainingMounts | Where-Object { $attemptedMounts -contains $_.Name }).Count -gt 0) {
                $cleanupFailures += 'Temporary mount cleanup verification failed.'
            }
        }
        catch {
            $cleanupFailures += 'Temporary mount enumeration failed.'
        }
    }
    $credential = $null
    if ($null -ne $secureKey) {
        $secureKey.Dispose()
    }
}

if ($failure -or $cleanupFailures.Count -gt 0) {
    throw ((@($failure) + $cleanupFailures | Where-Object { $_ }) -join ' ')
}

'RBAC_LAB_ACL_READY'
