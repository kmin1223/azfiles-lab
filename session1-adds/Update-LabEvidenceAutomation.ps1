<#
.SYNOPSIS
Install or refresh evidence automation with one Azure VM Run Command.
.DESCRIPTION
For this disposable lab only. Uses the existing Az login and prompts once for
labuser1's credential if none was supplied. The password is an ordinary Run
Command parameter: it can be visible in Azure/VM diagnostics or process arguments.
Use a unique lab password, never a production credential. Do not screen-share setup.
No password is embedded in repository source or intentionally written to the
installer log. Windows Task Scheduler stores the fixed worker credential.

Stages trusted repository scripts in an administrator-only, run-specific folder
at C:\Program Files\AzureFilesLabEvidenceBootstrap-<run-id>. Keeps the scripts and
install.log for troubleshooting. No certificates, encryption handshake, extra
cleanup Run Commands, redeployment, or storage-key rotation are performed.
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
    $encoding = New-Object System.Text.UTF8Encoding($true)
    return [Convert]::ToBase64String([byte[]]($encoding.GetPreamble() + $encoding.GetBytes($Source)))
}

function Remove-EvidencePassword {
    param([string]$Text, [string]$Password)
    if ([string]::IsNullOrEmpty($Password)) { return $Text }
    $escaped = ConvertTo-Json -InputObject $Password -Compress
    $Text.Replace($Password, '[REDACTED]').Replace($escaped.Substring(1, $escaped.Length - 2), '[REDACTED]')
}

function Read-EvidenceBootstrapMarker {
    param($Result, [string]$RunId)
    $messages = @($Result.Value | ForEach-Object { [string]$_.Message }) -join "`n"
    $failures = @([regex]::Matches($messages, '(?m)^AUTO_EVIDENCE_FAILED:([^\r\n]+)\r?$'))
    if ($failures.Count -eq 1) {
        $failure = $failures[0].Groups[1].Value | ConvertFrom-Json -ErrorAction Stop
        if ($failure.RunId -cne $RunId) { throw 'Remote failure record belongs to another run.' }
        $logLocation = if ([string]::IsNullOrWhiteSpace([string]$failure.LogPath)) {
            'VM log not created: staging initialization did not complete.'
        } else { "VM log: $($failure.LogPath)" }
        throw "Stage '$($failure.Stage)': $($failure.Message) [$($failure.Script):$($failure.Line); $($failure.ErrorId)]. $logLocation"
    }
    foreach ($entry in @($Result.Value)) {
        if ($entry.Code -match '(?i)failed|error' -or
            ($entry.Code -match 'StdErr' -and -not [string]::IsNullOrWhiteSpace([string]$entry.Message))) {
            throw "Remote installation failed: $messages"
        }
    }
    $stdout = @($Result.Value | Where-Object Code -match 'StdOut' | ForEach-Object Message) -join "`n"
    $matches = @([regex]::Matches($stdout, '(?m)^AUTO_EVIDENCE_READY:([^\r\n]+)\r?$'))
    if ($failures.Count -or $matches.Count -ne 1) {
        throw "Remote installation did not return one readiness record. Output: $messages"
    }
    $payload = $matches[0].Groups[1].Value | ConvertFrom-Json -ErrorAction Stop
    if ($payload.RunId -cne $RunId) { throw 'Remote readiness record belongs to another run.' }
    return $payload
}

function New-EvidenceBootstrapScript {
    param([string]$RunId, [hashtable]$Sources, $Config)
    if ($RunId -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid bootstrap run ID.' }
    $expected = @('Install-LabEvidenceAutomation.ps1', 'Invoke-LabEvidenceAutomation.ps1', 'Get-KerberosEvidence.ps1')
    if ($Sources.Count -ne 3 -or @($Sources.Keys | Where-Object { $_ -cnotin $expected }).Count) {
        throw 'Unexpected bootstrap sources.'
    }
    Assert-EvidenceBootstrapConfig $Config.StorageAccount $Config.Share $Config.DomainController
    if ([string]::IsNullOrWhiteSpace($Config.UserName)) { throw 'A credential username is required.' }
    $encodedSources = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Sources | ConvertTo-Json -Compress)))
    $encodedConfig = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Config | ConvertTo-Json -Compress)))
    return @'
param([Parameter(Mandatory)][string]$LabPassword)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$runId = '__RUN_ID__'
$directory = $null
$logPath = $null
$stage = 'Preparing staging directory'
$sourceNames = @('Install-LabEvidenceAutomation.ps1', 'Invoke-LabEvidenceAutomation.ps1', 'Get-KerberosEvidence.ps1')

function Remove-InstallPassword([string]$Text) {
    if ([string]::IsNullOrEmpty($LabPassword)) { return $Text }
    $escaped = ConvertTo-Json -InputObject $LabPassword -Compress
    $Text.Replace($LabPassword, '[REDACTED]').Replace($escaped.Substring(1, $escaped.Length - 2), '[REDACTED]')
}
function Write-InstallLog([string]$Text) {
    if ($logPath) { (Remove-InstallPassword $Text) | Out-File -LiteralPath $logPath -Append -Encoding UTF8 }
}
function Assert-SafeDirectory([string]$Path, [switch]$Private) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Unsafe directory: $Path" }
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if (-not $Private) { $trusted += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw "Unsafe directory owner: $Path" }
    if ($Private -and -not $acl.AreAccessRulesProtected) { throw "Staging ACL must be protected: $Path" }
    $writeMask = [Security.AccessControl.FileSystemRights]'WriteData,WriteAttributes,WriteExtendedAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trusted) { continue }
        if (-not $Private -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($Private -or ($rule.FileSystemRights -band $writeMask)) {
            throw "Unsafe directory permissions: $Path; SID=$($rule.IdentityReference.Value); rights=$($rule.FileSystemRights); inherited=$($rule.IsInherited)"
        }
    }
}
function New-PrivateDirectory([string]$Path) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null
    Assert-SafeDirectory $Path -Private
}
function New-InstallDirectory([string]$RunId) {
    if ($RunId -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid installation run ID.' }
    Assert-SafeDirectory 'C:\'
    Assert-SafeDirectory 'C:\Program Files'
    # Do not reuse a mutable shared bootstrap parent from an earlier attempt.
    $path = Join-Path 'C:\Program Files' ('AzureFilesLabEvidenceBootstrap-' + $RunId)
    if (Test-Path -LiteralPath $path) { throw "Run directory already exists: $path" }
    New-PrivateDirectory $path
    return $path
}
function Invoke-StagedEvidenceInstall($Config, [string]$Directory) {
    $securePassword = ConvertTo-SecureString $LabPassword -AsPlainText -Force
    $credential = New-Object Management.Automation.PSCredential($Config.UserName,$securePassword)
    $ready = $false
    try {
        & (Join-Path $Directory 'Install-LabEvidenceAutomation.ps1') `
            -StorageAccount $Config.StorageAccount -Share $Config.Share -DomainController $Config.DomainController `
            -LabCredential $credential -SourceDirectory $Directory *>&1 | ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) { throw $_ }
                Write-InstallLog ([string]$_)
                if ([string]$_ -match '^AUTO_EVIDENCE_READY(?:\s|$)') { $ready = $true }
            }
        if (-not $ready) { throw 'Installer finished without AUTO_EVIDENCE_READY.' }
    } finally {
        $credential = $null
        $securePassword.Dispose()
    }
}
try {
    $directory = New-InstallDirectory $runId
    $logPath = Join-Path $directory 'install.log'
    Write-InstallLog ("Run $runId started at " + [DateTime]::UtcNow.ToString('o'))
    $stage = 'Staging repository scripts'
    Write-InstallLog $stage
    $sources = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCES__')) | ConvertFrom-Json
    foreach ($name in $sourceNames) {
        $data = [Convert]::FromBase64String($sources.$name)
        $stream = [IO.File]::Open((Join-Path $directory $name),'CreateNew','Write','None')
        try { $stream.Write($data,0,$data.Length) } finally { $stream.Dispose() }
    }
    $config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__')) | ConvertFrom-Json
    $stage = 'Installing files and scheduled tasks'
    Write-InstallLog $stage
    Invoke-StagedEvidenceInstall $config $directory
    Write-InstallLog 'Installation completed.'
    Write-Output ('AUTO_EVIDENCE_READY:' + (@{RunId=$runId; LogPath=$logPath} | ConvertTo-Json -Compress))
} catch {
    $failure = $_
    $message = Remove-InstallPassword $failure.Exception.Message
    $record = [ordered]@{
        RunId=$runId; Stage=$stage; Message=$message
        Script=$(if ($failure.InvocationInfo.ScriptName) { Split-Path $failure.InvocationInfo.ScriptName -Leaf } else { '<RunCommand>' })
        Line=$failure.InvocationInfo.ScriptLineNumber; ErrorId=(Remove-InstallPassword $failure.FullyQualifiedErrorId); LogPath=$logPath
    }
    try {
        Write-InstallLog ($record | ConvertTo-Json)
        Write-InstallLog $failure.ScriptStackTrace
    } catch {
        $record.Message += ' [Writing install.log also failed.]'
    }
    # Run Command returns only the output tail. Keep the failure record compact and last.
    if ($record.Message.Length -gt 1200) { $record.Message = $record.Message.Substring(0,1200) + '... (see VM log)' }
    if ($record.ErrorId.Length -gt 160) { $record.ErrorId = $record.ErrorId.Substring(0,160) }
    Write-Output ('AUTO_EVIDENCE_FAILED:' + ($record | ConvertTo-Json -Compress))
    exit 1
} finally { $LabPassword = $null }
'@.Replace('__RUN_ID__',$RunId).Replace('__SOURCES__',$encodedSources).Replace('__CONFIG__',$encodedConfig)
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
        else { $_.StorageAccountName.StartsWith($Prefix,[StringComparison]::Ordinal) -and -not $_.StorageAccountName.StartsWith("${Prefix}ads",[StringComparison]::Ordinal) }
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
        $LabCredential = Get-Credential -UserName ($ad.NetBiosDomainName + '\labuser1') -Message 'Disposable lab password (ordinary Azure Run Command parameter)'
        if (-not $LabCredential) { throw 'Lab credential entry was cancelled.' }
    }
    $sources = @{}
    foreach ($name in @('Install-LabEvidenceAutomation.ps1','Invoke-LabEvidenceAutomation.ps1')) {
        $sources[$name] = ConvertTo-EvidenceSourceBase64 ([IO.File]::ReadAllText((Join-Path $SourceDirectory $name)))
    }
    $sources['Get-KerberosEvidence.ps1'] = ConvertTo-EvidenceSourceBase64 (Get-EvidenceHelperSource (Join-Path $SourceDirectory '07-install-tools.ps1'))
    $config = @{StorageAccount=$StorageAccount; Share=$Share; DomainController=$DomainController; UserName=$LabCredential.UserName}
    $runId = [guid]::NewGuid().ToString('N')
    $script = New-EvidenceBootstrapScript -RunId $runId -Sources $sources -Config $config
    $parameters = @{LabPassword=$LabCredential.GetNetworkCredential().Password}
    Write-Warning 'Lab-only setup: password is an ordinary Run Command parameter and may be visible in Azure/VM diagnostics. Do not share this setup screen.'
    Write-Host "Installing evidence automation on $VMName (one Run Command; run $runId)."
    try {
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName `
            -CommandId 'RunPowerShellScript' -ScriptString $script -Parameter $parameters -ErrorAction Stop
        $ready = Read-EvidenceBootstrapMarker $result $runId
        Write-Output "AUTO_EVIDENCE_READY $VMName; VM log: $($ready.LogPath)"
    } catch {
        $detail = Remove-EvidencePassword $_.Exception.Message $parameters.LabPassword
        throw "Evidence installation failed on $VMName (run $runId). $detail"
    } finally {
        $parameters.Clear()
        $LabCredential = $null
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-EvidenceAutomationBootstrap @PSBoundParameters -SourceDirectory (Join-Path $PSScriptRoot 'scripts')
}
