<#
.SYNOPSIS
Install or refresh protected evidence tasks on an existing lab client.
.DESCRIPTION
Uses the existing Az login; never connects automatically. An omitted credential
is prompted once. Only an ephemeral RSA public key and OAEP-SHA256 ciphertext
cross Azure Run Command; the password is never an argument or staged file.
Trust depends on the authenticated Azure control plane and the VM administrators.
The VM decrypts in memory and passes a PSCredential to the installer in process.
Managed password strings cannot be guaranteed zeroed; byte buffers are cleared.

Cleanup runs on success and failure. A disconnected client can leave a bootstrap
directory and certificate. The one-hour certificate expiry does NOT delete its
private key. If cleanup cannot complete, an administrator must inspect only the
reported GUID directory under C:\Program Files\AzureFilesLabEvidenceBootstrap
and the LocalMachine\My certificate whose subject and friendly name both equal
AzureFilesLabEvidenceBootstrap-<GUID> (subject prefixed CN=), then remove those
three staged scripts, that directory, and that certificate WITH its private key.
Never broadly purge certificates, directories, Run Commands, or existing tasks.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [string]$Prefix = 'azflab',
    [string]$VMName,
    [string]$StorageAccount,
    [string]$Share = 'labshare',
    [string]$DomainController,
    [PSCredential]$LabCredential
)

function Test-EvidenceDnsName {
    param([string]$Name)
    return ($Name.Length -le 253 -and $Name -cmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$')
}

function Assert-EvidenceBootstrapConfig {
    param([string]$StorageAccount, [string]$Share, [string]$DomainController)
    if ($StorageAccount -cnotmatch '^[a-z0-9]{3,24}$') { throw 'StorageAccount must be 3-24 lowercase letters or digits.' }
    if ($Share -cnotmatch '^(?=.{3,63}$)[a-z0-9]+(?:-[a-z0-9]+)*$') { throw 'Share must be a valid 3-63 character Azure Files share name.' }
    if (-not (Test-EvidenceDnsName $DomainController)) { throw 'DomainController must be a plain fully qualified DNS name.' }
}

function Get-EvidenceHelperSource {
    param([string]$Path)
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'The tools source does not parse.' }
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$helper'
    }, $true))
    if ($assignments.Count -ne 1) { throw 'Expected exactly one literal helper assignment in the tools source.' }
    $expression = $assignments[0].Right
    if ($expression -isnot [Management.Automation.Language.CommandExpressionAst] -or
        $expression.Expression -isnot [Management.Automation.Language.StringConstantExpressionAst]) {
        throw 'The helper must be a literal string, not executable or interpolated code.'
    }
    $source = $expression.Expression.Value
    $null = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'The extracted helper does not parse.' }
    return $source
}

function ConvertTo-EvidenceSourceBase64 {
    param([string]$Source)
    # A BOM is needed for non-ASCII script text read by Windows PowerShell 5.1.
    $encoding = New-Object System.Text.UTF8Encoding($true)
    return [Convert]::ToBase64String([byte[]]($encoding.GetPreamble() + $encoding.GetBytes($Source)))
}

function Read-EvidenceBootstrapMarker {
    param($Result, [string]$Marker, [string]$RunId)
    $messages = @()
    foreach ($entry in @($Result.Value)) {
        if ($entry.Code -match '(?i)failed|error') { throw 'Remote bootstrap reported an unsuccessful status.' }
        if ($entry.Code -match 'StdErr' -and -not [string]::IsNullOrWhiteSpace([string]$entry.Message)) {
            throw 'Remote bootstrap reported an error.'
        }
        if ($entry.Code -match 'StdOut') { $messages += [string]$entry.Message }
    }
    $matches = @([regex]::Matches(($messages -join "`n"), '(?m)^' + [regex]::Escape($Marker) + '([^\r\n]+)\r?$'))
    if ($matches.Count -ne 1) { throw 'Remote bootstrap did not return exactly one expected marker.' }
    try { $payload = $matches[0].Groups[1].Value | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Remote bootstrap marker is invalid.' }
    if ($payload.RunId -cne $RunId) { throw 'Remote bootstrap marker belongs to another run.' }
    return $payload
}

function Protect-EvidenceBootstrapPassword {
    param([PSCredential]$Credential, $PublicKey)
    $rsa = $null; $bytes = $null; $cipher = $null
    try {
        $parameters = New-Object System.Security.Cryptography.RSAParameters
        $parameters.Modulus = [Convert]::FromBase64String($PublicKey.Modulus)
        $parameters.Exponent = [Convert]::FromBase64String($PublicKey.Exponent)
        if ($parameters.Modulus.Length -ne 512 -or
            [Convert]::ToBase64String($parameters.Exponent) -cne 'AQAB' -or
            ($parameters.Modulus[0] -band 128) -eq 0) {
            throw 'Unexpected bootstrap RSA key.'
        }
        # .NET Framework RSA.Create() returns CSP, which cannot do OAEP-SHA256.
        $rsa = if ($PSVersionTable.PSVersion.Major -le 5) {
            New-Object Security.Cryptography.RSACng
        } else { [Security.Cryptography.RSA]::Create() }
        $rsa.ImportParameters($parameters)
        $bytes = [Text.Encoding]::UTF8.GetBytes($Credential.GetNetworkCredential().Password)
        if ($bytes.Length -gt 446) { throw 'Password exceeds the 446-byte RSA bootstrap limit; use a shorter lab password.' }
        $cipher = $rsa.Encrypt($bytes, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        return [Convert]::ToBase64String($cipher)
    } finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
        if ($rsa) { $rsa.Dispose() }
    }
}

function Get-EvidenceBootstrapRemoteCommon {
    # This is source text only. It is never run on the management host.
    return @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Program Files\AzureFilesLabEvidenceBootstrap'
$runId = '__RUN_ID__'
$directory = Join-Path $root $runId
$certificateName = 'AzureFilesLabEvidenceBootstrap-' + $runId
$sourceNames = @('Install-LabEvidenceAutomation.ps1', 'Invoke-LabEvidenceAutomation.ps1', 'Get-KerberosEvidence.ps1')
function Assert-SafeDirectory {
    param([string]$Path, [switch]$Private)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe bootstrap directory.' }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if (-not $Private) { $trusted += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
    if ($owner -notin $trusted) { throw 'Unsafe directory owner.' }
    if ($Private -and -not $acl.AreAccessRulesProtected) { throw 'Bootstrap ACL must be protected.' }
    # Creating sibling folders alone (the normal C:\ ACL) cannot replace these
    # existing, administrator-owned components.
    $writeMask = [Security.AccessControl.FileSystemRights]'WriteData,WriteAttributes,WriteExtendedAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($rule.IdentityReference.Value -in @('S-1-5-18', 'S-1-5-32-544')) { continue }
        if (-not $Private -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($Private -or ($rule.FileSystemRights -band $writeMask)) {
            if (-not $Private -and $rule.IdentityReference.Value -eq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') { continue }
            throw 'Unsafe directory permissions.'
        }
    }
}
function Assert-SafeParents {
    Assert-SafeDirectory 'C:\'
    Assert-SafeDirectory 'C:\Program Files'
    if (Test-Path -LiteralPath $root) { Assert-SafeDirectory $root -Private }
}
function New-PrivateDirectory {
    param([string]$Path)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    # Framework overload applies the protected ACL as the directory is created.
    $null = [IO.Directory]::CreateDirectory($Path, $acl)
    Assert-SafeDirectory $Path -Private
}
function Remove-BootstrapArtifacts {
    param([string]$Thumbprint)
    $failed = $false
    try {
        Assert-SafeParents
        if (Test-Path -LiteralPath $directory) {
            Assert-SafeDirectory $directory -Private
            $entries = @(Get-ChildItem -LiteralPath $directory -Force)
            foreach ($item in $entries) {
                if ($item.Name -notin $sourceNames -or $item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected bootstrap file.' }
            }
            foreach ($name in $sourceNames) {
                $path = Join-Path $directory $name
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
            }
            # Non-recursive: never delete unexpected contents or follow directories.
            [IO.Directory]::Delete($directory, $false)
        }
    } catch { $failed = $true }
    try {
        $certificates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
            $_.Subject -ceq ('CN=' + $certificateName) -and $_.FriendlyName -ceq $certificateName -and
            (-not $Thumbprint -or $_.Thumbprint -ceq $Thumbprint)
        })
        foreach ($certificate in $certificates) {
            Remove-Item -LiteralPath ('Cert:\LocalMachine\My\' + $certificate.Thumbprint) -DeleteKey -Force -ErrorAction Stop
        }
    } catch { $failed = $true }
    if ($failed) { throw 'Bootstrap cleanup incomplete; inspect only this run directory and tagged certificate.' }
}
'@
}

function New-EvidenceBootstrapScript {
    param(
        [ValidateSet('Stage', 'Install', 'Cleanup')] [string]$Phase,
        [string]$RunId, [hashtable]$Sources, $Config,
        [string]$Thumbprint, [string]$Ciphertext
    )
    if ($RunId -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid bootstrap run ID.' }
    if ($Thumbprint -and $Thumbprint -cnotmatch '^[A-F0-9]{40}$') { throw 'Invalid certificate thumbprint.' }
    $common = (Get-EvidenceBootstrapRemoteCommon).Replace('__RUN_ID__', $RunId)
    if ($Phase -eq 'Cleanup') {
        return $common + "`n" + @'
try {
    Remove-BootstrapArtifacts '__THUMBPRINT__'
    Write-Output ('BOOTSTRAP_CLEAN:' + (@{RunId=$runId} | ConvertTo-Json -Compress))
} catch { throw 'Bootstrap cleanup failed.' }
'@.Replace('__THUMBPRINT__', $Thumbprint)
    }
    if ($Phase -eq 'Stage') {
        $expected = @('Install-LabEvidenceAutomation.ps1', 'Invoke-LabEvidenceAutomation.ps1', 'Get-KerberosEvidence.ps1')
        if ($Sources.Count -ne 3 -or @($Sources.Keys | Where-Object { $_ -notin $expected }).Count) { throw 'Unexpected bootstrap sources.' }
        $encodedSources = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Sources | ConvertTo-Json -Compress)))
        return $common + "`n" + @'
$certificate = $null
$ready = $false
try {
    Assert-SafeParents
    if (-not (Test-Path -LiteralPath $root)) { New-PrivateDirectory $root }
    if (Test-Path -LiteralPath $directory) { throw 'Bootstrap run directory already exists.' }
    New-PrivateDirectory $directory
    $sources = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCES__')) | ConvertFrom-Json
    foreach ($name in $sourceNames) {
        $path = Join-Path $directory $name
        $data = [Convert]::FromBase64String($sources.$name)
        $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($data, 0, $data.Length) } finally { $stream.Dispose() }
    }
    $certificate = New-SelfSignedCertificate -Subject ('CN=' + $certificateName) -FriendlyName $certificateName `
        -CertStoreLocation Cert:\LocalMachine\My -Provider 'Microsoft Software Key Storage Provider' `
        -KeyAlgorithm RSA -KeyLength 4096 -KeyExportPolicy NonExportable -KeyUsage KeyEncipherment `
        -Type Custom -TextExtension @('2.5.29.37={text}1.3.6.1.4.1.311.80.1') -NotAfter (Get-Date).AddHours(1)
    $public = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try { $parameters = $public.ExportParameters($false) } finally { $public.Dispose() }
    $marker = @{
        RunId=$runId; Thumbprint=$certificate.Thumbprint
        Modulus=[Convert]::ToBase64String($parameters.Modulus)
        Exponent=[Convert]::ToBase64String($parameters.Exponent)
    } | ConvertTo-Json -Compress
    Write-Output ('BOOTSTRAP_PUBLIC:' + $marker)
    $ready = $true
} catch { throw 'Bootstrap staging failed.' }
finally {
    if ($certificate) { $certificate.Dispose() }
    if (-not $ready) { Remove-BootstrapArtifacts '' }
}
'@.Replace('__SOURCES__', $encodedSources)
    }
    Assert-EvidenceBootstrapConfig $Config.StorageAccount $Config.Share $Config.DomainController
    if (-not $Thumbprint) { throw 'An exact certificate thumbprint is required.' }
    try { $cipherBytes = [Convert]::FromBase64String($Ciphertext) } catch { throw 'Invalid encrypted payload.' }
    if ($cipherBytes.Length -ne 512 -or [Convert]::ToBase64String($cipherBytes) -cne $Ciphertext) { throw 'Invalid encrypted payload length or encoding.' }
    if ([string]::IsNullOrWhiteSpace($Config.UserName)) { throw 'A credential username is required.' }
    $encodedConfig = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Config | ConvertTo-Json -Compress)))
    return $common + "`n" + @'
$certificate = $null; $privateKey = $null; $passwordBytes = $null; $encryptedBytes = $null
$securePassword = $null; $credential = $null; $passwordText = $null; $installed = $false
try {
    Assert-SafeParents
    Assert-SafeDirectory $directory -Private
    $entries = @(Get-ChildItem -LiteralPath $directory -Force)
    if ($entries.Count -ne 3) { throw 'Unexpected bootstrap contents.' }
    foreach ($item in $entries) {
        if ($item.Name -notin $sourceNames -or $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe bootstrap source.' }
    }
    $certificate = Get-Item -LiteralPath 'Cert:\LocalMachine\My\__THUMBPRINT__'
    if ($certificate.Subject -cne ('CN=' + $certificateName) -or
        $certificate.FriendlyName -cne $certificateName -or -not $certificate.HasPrivateKey -or
        $certificate.NotAfter -le (Get-Date)) { throw 'Invalid bootstrap certificate.' }
    $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    $encryptedBytes = [Convert]::FromBase64String('__CIPHERTEXT__')
    $passwordBytes = $privateKey.Decrypt($encryptedBytes, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $passwordText = $utf8.GetString($passwordBytes)
    $securePassword = New-Object Security.SecureString
    foreach ($character in $passwordText.ToCharArray()) { $securePassword.AppendChar($character) }
    $securePassword.MakeReadOnly()
    $passwordText = $null; $character = $null
    $config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__')) | ConvertFrom-Json
    $credential = New-Object Management.Automation.PSCredential($config.UserName, $securePassword)
    # Capture all installer streams locally: never relay credential-bearing errors.
    $output = @(& (Join-Path $directory 'Install-LabEvidenceAutomation.ps1') `
        -StorageAccount $config.StorageAccount -Share $config.Share -DomainController $config.DomainController `
        -LabCredential $credential -SourceDirectory $directory *>&1)
    if (@($output | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count -or
        -not @($output | Where-Object { [string]$_ -match '^AUTO_EVIDENCE_READY(?:\s|$)' }).Count) {
        throw 'Installer did not confirm readiness.'
    }
    $installed = $true
} catch { throw 'Bootstrap installation failed; remote credential details withheld.' }
finally {
    $output = $null; $credential = $null; $passwordText = $null
    if ($passwordBytes) { [Array]::Clear($passwordBytes, 0, $passwordBytes.Length) }
    if ($encryptedBytes) { [Array]::Clear($encryptedBytes, 0, $encryptedBytes.Length) }
    if ($securePassword) { $securePassword.Dispose() }
    if ($privateKey) { $privateKey.Dispose() }
    if ($certificate) { $certificate.Dispose() }
    Remove-BootstrapArtifacts '__THUMBPRINT__'
}
if ($installed) { Write-Output ('AUTO_EVIDENCE_READY:' + (@{RunId=$runId} | ConvertTo-Json -Compress)) }
'@.Replace('__THUMBPRINT__', $Thumbprint).Replace('__CIPHERTEXT__', $Ciphertext).Replace('__CONFIG__', $encodedConfig)
}

function Invoke-EvidenceAutomationBootstrap {
    param(
        [string]$ResourceGroupName, [string]$Prefix = 'azflab', [string]$VMName,
        [string]$StorageAccount, [string]$Share = 'labshare', [string]$DomainController,
        [PSCredential]$LabCredential, [string]$SourceDirectory
    )
    $ErrorActionPreference = 'Stop'
    if (-not (Get-AzContext -ErrorAction Stop)) { throw 'Use an existing authenticated Az context before running this command.' }
    if ($Prefix -cnotmatch '^[a-z][a-z0-9-]{0,39}$') { throw 'Prefix must be a simple lowercase lab prefix.' }
    if (-not $VMName) { $VMName = "$Prefix-cli" }
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
    if (-not $vm) { throw 'The requested lab client VM was not found.' }
    $accounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop | Where-Object {
        if ($StorageAccount) { $_.StorageAccountName -ceq $StorageAccount }
        else { $_.StorageAccountName.StartsWith($Prefix, [StringComparison]::Ordinal) -and -not $_.StorageAccountName.StartsWith("${Prefix}ads", [StringComparison]::Ordinal) }
    })
    if ($accounts.Count -ne 1) { throw 'Specify StorageAccount: exactly one matching non-AD lab storage account is required.' }
    $account = $accounts[0]
    $StorageAccount = $account.StorageAccountName
    $ad = $account.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
    if (-not $DomainController) {
        $forest = if (Test-EvidenceDnsName ([string]$ad.ForestName)) { $ad.ForestName }
                  elseif (Test-EvidenceDnsName ([string]$ad.DomainName)) { $ad.DomainName }
        if (-not $forest) { throw 'Specify DomainController: storage metadata contains no valid forest DNS name.' }
        $DomainController = "$Prefix-dc.$forest"
    }
    Assert-EvidenceBootstrapConfig $StorageAccount $Share $DomainController
    if (-not $LabCredential) {
        if ([string]::IsNullOrWhiteSpace([string]$ad.NetBiosDomainName)) { throw 'Supply LabCredential: the storage account has no NetBIOS domain metadata.' }
        $LabCredential = Get-Credential -UserName ($ad.NetBiosDomainName + '\labuser1') -Message 'Lab evidence task identity (stored by Windows Task Scheduler)'
        if (-not $LabCredential) { throw 'Lab credential entry was cancelled.' }
    }
    $sources = @{}
    foreach ($name in @('Install-LabEvidenceAutomation.ps1', 'Invoke-LabEvidenceAutomation.ps1')) {
        $sources[$name] = ConvertTo-EvidenceSourceBase64 ([IO.File]::ReadAllText((Join-Path $SourceDirectory $name)))
    }
    $sources['Get-KerberosEvidence.ps1'] = ConvertTo-EvidenceSourceBase64 (Get-EvidenceHelperSource (Join-Path $SourceDirectory '07-install-tools.ps1'))
    $config = @{StorageAccount=$StorageAccount; Share=$Share; DomainController=$DomainController; UserName=$LabCredential.UserName}
    $runId = [guid]::NewGuid().ToString('N')
    $thumbprint = ''
    $started = $false
    $complete = $false
    $operation = 'staging'
    try {
        $stage = New-EvidenceBootstrapScript -Phase Stage -RunId $runId -Sources $sources
        $started = $true
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $stage -ErrorAction Stop
        $publicKey = Read-EvidenceBootstrapMarker $result 'BOOTSTRAP_PUBLIC:' $runId
        if ($publicKey.Thumbprint -cnotmatch '^[A-F0-9]{40}$') { throw 'Invalid bootstrap certificate identity.' }
        $thumbprint = $publicKey.Thumbprint
        $operation = 'password encryption (maximum 446 UTF-8 bytes)'
        $ciphertext = Protect-EvidenceBootstrapPassword $LabCredential $publicKey
        $operation = 'installation'
        $install = New-EvidenceBootstrapScript -Phase Install -RunId $runId -Config $config -Thumbprint $thumbprint -Ciphertext $ciphertext
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $install -ErrorAction Stop
        $null = Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' $runId
        $complete = $true
        Write-Output "AUTO_EVIDENCE_READY $VMName (bootstrap $runId)"
    } catch {
        # Do not print Azure/installer ErrorRecords or bound credential arguments.
        throw "Evidence bootstrap $operation failed (run $runId). Credential details withheld."
    } finally {
        $ciphertext = $null; $install = $null; $LabCredential = $null
        if ($started -and -not $complete) {
            try {
                $cleanup = New-EvidenceBootstrapScript -Phase Cleanup -RunId $runId -Thumbprint $thumbprint
                $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $cleanup -ErrorAction Stop
                $null = Read-EvidenceBootstrapMarker $result 'BOOTSTRAP_CLEAN:' $runId
            } catch {
                Write-Warning "Bootstrap cleanup unconfirmed for run $runId. Inspect its exact protected directory and tagged LocalMachine certificate; expiry does not delete the private key. See this script's cleanup guidance."
            }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-EvidenceAutomationBootstrap @PSBoundParameters -SourceDirectory (Join-Path $PSScriptRoot 'scripts')
}
