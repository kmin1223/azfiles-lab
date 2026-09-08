[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Share = 'labshare',
    [Parameter(Mandatory)][string]$DomainController,
    [Parameter(Mandatory)][PSCredential]$LabCredential,
    [string]$SourceDirectory = $PSScriptRoot,
    [switch]$Library
)
$ErrorActionPreference = 'Stop'

function Resolve-EvidenceAccount([PSCredential]$Credential) {
    $sid = (New-Object Security.Principal.NTAccount($Credential.UserName)).Translate(
        [Security.Principal.SecurityIdentifier])
    $account = $sid.Translate([Security.Principal.NTAccount]).Value
    if ($sid.Value -notmatch '^S-1-5-21-\d+-\d+-\d+-\d{4,}$' -or
        $account -notmatch '^[^\\/@\s]+\\labuser1$') { throw 'Supply the fixed domain labuser1 account.' }
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $domain = $account.Split('\')[0]
    $context = New-Object DirectoryServices.AccountManagement.PrincipalContext('Domain', $domain)
    $user = $null
    try {
        $user = [DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(
            $context, [DirectoryServices.AccountManagement.IdentityType]::Sid, $sid.Value)
        if (-not $user) { throw 'Cannot verify the supplied domain user.' }
        $groups = @($user.GetAuthorizationGroups() | ForEach-Object { $_.Sid.Value })
        if (Test-EvidenceDomainAdministrator $groups) {
            throw 'The supplied account belongs to Domain Admins or Enterprise Admins.'
        }
        # Local Administrators membership supports manual UAC consent in this lab.
        # The LUA worker must still pass the runtime's effective-token check.
    } finally { if ($user) { $user.Dispose() }; $context.Dispose() }
    [pscustomobject]@{ Sid = $sid.Value; Account = $account }
}

function New-EvidenceTaskDefinition($Scheduler, [string]$Role, [string]$Account) {
    $definition = $Scheduler.NewTask(0)
    $definition.RegistrationInfo.Description = 'Fixed-target Azure Files evidence automation; fresh batch worker logon.'
    $definition.Principal.UserId = $Account
    $definition.Principal.LogonType = $(if ($Role -eq 'Broker') { 5 } else { 1 })
    $definition.Principal.RunLevel = $(if ($Role -eq 'Broker') { 1 } else { 0 })
    $definition.Settings.Enabled = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.AllowHardTerminate = $true
    $definition.Settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
    $definition.Settings.ExecutionTimeLimit = $(if ($Role -eq 'Broker') { 'PT10M' } else { 'PT3M' })
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.StartWhenAvailable = $false
    $definition.Settings.RestartCount = 0
    $action = $definition.Actions.Create(0)
    $action.Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $action.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Program Files\AzureFilesLabEvidence\Invoke-LabEvidenceAutomation.ps1" -Mode ' + $Role
    $action.WorkingDirectory = 'C:\Program Files\AzureFilesLabEvidence'
    $definition
}

function Get-OptionalEvidenceSchedulerItem($Container, [ValidateSet('Folder','Task')][string]$Kind, [string]$Name) {
    try {
        if ($Kind -eq 'Folder') { return $Container.GetFolder($Name) }
        return $Container.GetTask($Name)
    } catch [Runtime.InteropServices.COMException], [IO.FileNotFoundException] {
        # COM interop can map ERROR_FILE_NOT_FOUND to FileNotFoundException.
        if ((Get-EvidenceHResult $_.Exception) -ne -2147024894) { throw }
        return $null
    }
}

function Assert-EvidenceTaskSecurity($Task) {
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($Task.GetSecurityDescriptor(7))
    if ($descriptor.Owner.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Unsafe existing task owner.' }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace.AceQualifier -eq 'AccessAllowed' -and
            ($ace.AccessMask -band 0x500D0156) -and $ace.SecurityIdentifier.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'Unsafe existing task permissions.'
        }
    }
}

function Get-EvidenceCollectorSource([string]$Directory) {
    $staged = Join-Path $Directory 'Get-KerberosEvidence.ps1'
    if (Get-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue) { return $staged }
    'C:\LabTools\Get-KerberosEvidence.ps1'
}

function Protect-EvidenceToolsRoot([string]$Path, [string]$Sid) {
    $acl = New-EvidenceAcl $Sid
    # Other lab users retain access to the manual collector, not the broker.
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        [Security.Principal.SecurityIdentifier]'S-1-5-32-545', 'ReadAndExecute',
        'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    [LabEvidence.SafeReader]::ProtectDirectoryOnly($Path, $acl.GetSecurityDescriptorBinaryForm())
}

function Assert-EvidenceInstallOwner([string]$Path) {
    Assert-EvidencePath $Path
    $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) {
        throw "Unsafe existing lab-owned path owner: $Path"
    }
}

function Open-EvidenceToolsRoot([string]$Path) {
    if (-not ('LabEvidence.InstallDirectoryGuard' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace LabEvidence {
 public static class InstallDirectoryGuard {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
  public static SafeFileHandle Open(string path) {
   // Refuse existing write/delete handles and prevent new ones during root normalization.
   var handle=CreateFile(path,0x80000000,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(handle.IsInvalid) {
    int error=Marshal.GetLastWin32Error(); handle.Dispose();
    throw new System.ComponentModel.Win32Exception(error);
   }
   return handle;
  }
 }
}
'@
    }
    [LabEvidence.InstallDirectoryGuard]::Open($Path)
}

function Format-EvidenceInstallFailure($Record, [string]$Step, [PSCredential]$Credential) {
    $exception = $Record.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    $text = '[evidence-install] FAILED step={0}; line={1}; id={2}; type={3}; HRESULT={4}: {5}' -f `
        $Step, $Record.InvocationInfo.ScriptLineNumber, $Record.FullyQualifiedErrorId,
        $exception.GetType().Name, $exception.HResult, $exception.Message
    $secret = $null
    try {
        if ($Credential) {
            $secret = $Credential.GetNetworkCredential().Password
            if ($secret) { $text = $text.Replace($secret, '[REDACTED]') }
        }
        $text = $text -replace '[\x00-\x1f\x7f]', ' '
        if ($text.Length -gt 1000) { $text = $text.Substring(0, 1000) + ' [truncated]' }
        $text
    } finally { $secret = $null }
}

function Get-TrustedEvidenceConverter([string]$Path = 'C:\LabTools\etl2pcapng.exe') {
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Write-Warning 'Optional ETL converter is missing; automatic captures will retain ETL without conversion.'
            return
        }
        Assert-EvidenceAcl (Split-Path $Path -Parent)
        Assert-EvidenceAcl $Path
        Initialize-EvidenceNativeReader
        [LabEvidence.SafeReader]::AssertFile($Path)
        $Path
    } catch {
        Write-Warning 'Optional ETL converter failed trust/link validation and will not be installed.'
        return
    }
}

function Publish-EvidenceDispatcher([string]$Source, [string]$Sid, [string]$ToolsRoot = 'C:\LabTools') {
    Assert-EvidenceAcl $Source
    Initialize-EvidenceNativeReader
    # This also rejects existing hard links without opening any file for writing.
    $content = [LabEvidence.SafeReader]::Read($Source, 2097152)
    Assert-EvidencePath $ToolsRoot
    Assert-EvidenceAcl (Split-Path $ToolsRoot -Parent) -ParentDirectory
    if (-not (Test-Path -LiteralPath $ToolsRoot)) { New-EvidenceDirectory $ToolsRoot $Sid }
    Assert-EvidenceInstallOwner $ToolsRoot
    $guard = Open-EvidenceToolsRoot $ToolsRoot
    try {
    Assert-EvidenceInstallOwner $ToolsRoot
    $destination = Join-Path $ToolsRoot 'Get-KerberosEvidence.ps1'
    Assert-EvidencePath $destination
    if (Test-Path -LiteralPath $destination) {
        Assert-EvidenceInstallOwner $destination
        [LabEvidence.SafeReader]::AssertFile($destination)
    }
    Protect-EvidenceToolsRoot $ToolsRoot $Sid
    Assert-EvidenceAcl $ToolsRoot
    Assert-EvidencePath $destination
    if (Test-Path -LiteralPath $destination) {
        Assert-EvidenceInstallOwner $destination
        [LabEvidence.SafeReader]::AssertFile($destination)
    }
    if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Force }
    [IO.File]::WriteAllText($destination, $content, (New-Object Text.UTF8Encoding($true)))
    $fileAcl = New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @($Sid,'ReadAndExecute'),
            @('S-1-5-32-545','ReadAndExecute'))) {
        $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$entry[0], $entry[1], 'Allow')))
    }
    Set-Acl -LiteralPath $destination -AclObject $fileAcl
    Assert-EvidenceAcl $destination
    } finally { $guard.Dispose() }
}

function Install-EvidenceAutomation {
    $step = 'validate-sources'
    try {
    Write-Host "[evidence-install] step=$step"
    $runtimeSource = Join-Path $SourceDirectory 'Invoke-LabEvidenceAutomation.ps1'
    $collectorSource = Get-EvidenceCollectorSource $SourceDirectory
    # Bootstrap validation must precede executing the runtime's validation helpers.
    foreach ($source in @($runtimeSource, $collectorSource)) {
        $path = [IO.Path]::GetFullPath($source)
        if ($path -notmatch '^[A-Za-z]:\\' -or $path.Substring(2).Contains(':')) { throw 'Invalid source path.' }
        $isLeaf = $true
        while ($path) {
            $item = Get-Item -LiteralPath $path -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse source: $path" }
            $acl = Get-Acl -LiteralPath $path
            $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw "Unsafe source owner: $path" }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                $mask = if ($isLeaf) { 0xD0156 } else { 0xD0040 }
                if ($rule.AccessControlType -eq 'Allow' -and
                    -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                    ($rule.FileSystemRights -band $mask) -and $rule.IdentityReference.Value -notin $trusted) {
                    throw "Unsafe source ACL: $path"
                }
            }
            $isLeaf = $false
            $path = Split-Path $path -Parent
        }
    }
    $step = 'load-protected-runtime'; Write-Host "[evidence-install] step=$step"
    . $runtimeSource -Mode Library
    $identity = Get-EvidenceIdentity
    if (-not $identity.Admin) { throw 'Installation requires an administrator.' }
    $step = 'validate-lab-account'; Write-Host "[evidence-install] step=$step"
    $account = Resolve-EvidenceAccount $LabCredential
    $config = [ordered]@{ StorageAccount = $StorageAccount; Share = $Share; DomainController = $DomainController
        ExpectedUserSid = $account.Sid; Account = $account.Account
        TaskFolder = '\AzureFilesLabEvidence'; BrokerTask = 'Broker'; WorkerTask = 'Worker' }
    Assert-EvidenceConfig $config
    $step = 'inspect-scheduled-tasks'; Write-Host "[evidence-install] step=$step"
    $scheduler = New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
    $baseSddl = 'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)'
    $brokerSddl = $baseSddl + "(A;;GRGX;;;$($account.Sid))"
    $workerSddl = $baseSddl + "(A;;GR;;;$($account.Sid))"
    $folder = Get-OptionalEvidenceSchedulerItem $scheduler 'Folder' $config.TaskFolder
    if ($folder) {
        Assert-EvidenceTaskSecurity $folder
        foreach ($name in @('Broker','Worker')) {
            $task = Get-OptionalEvidenceSchedulerItem $folder 'Task' $name
            if ($task) {
                Assert-EvidenceTaskSecurity $task
                if ($task.State -in @(2,4)) { throw 'Cannot update automation while a task is running.' }
            }
        }
    }
    $step = 'secure-install-roots'; Write-Host "[evidence-install] step=$step"
    foreach ($root in @($InstallRoot, $RuntimeRoot)) {
        Assert-EvidencePath $root
        Assert-EvidenceAcl (Split-Path $root -Parent) -ParentDirectory
        if (Test-Path -LiteralPath $root) { Assert-EvidenceAcl $root }
        else { [IO.Directory]::CreateDirectory($root, (New-EvidenceAcl $account.Sid)) | Out-Null }
        Assert-EvidenceAcl $root
        Set-Acl -LiteralPath $root -AclObject (New-EvidenceAcl $account.Sid)
    }
    $statePath = Join-Path $RuntimeRoot 'state.json'
    foreach ($name in @('state.json','state.new','broker.lock')) {
        $existing = Join-Path $RuntimeRoot $name
        if (Test-Path -LiteralPath $existing) { Assert-EvidenceAcl $existing }
    }
    foreach ($existing in @(Get-ChildItem -LiteralPath $InstallRoot -Force)) {
        Assert-EvidenceAcl $existing.FullName
    }
    $installLock = [IO.File]::Open((Join-Path $RuntimeRoot 'broker.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    try {
    $step = 'install-protected-files'; Write-Host "[evidence-install] step=$step"
    if ((Test-Path -LiteralPath $statePath) -and (Read-EvidenceJson $statePath).TraceOwned) {
        throw 'Unresolved capture ownership must be recovered before reinstalling.'
    }
    $runs = Join-Path $RuntimeRoot 'Runs'
    if (Test-Path -LiteralPath $runs) { Assert-EvidenceAcl $runs }
    else { [IO.Directory]::CreateDirectory($runs, (New-EvidenceAcl $account.Sid)) | Out-Null }
    Assert-EvidenceAcl $runs
    $sources = @($collectorSource, $runtimeSource)
    $converterSource = Get-TrustedEvidenceConverter
    if ($converterSource) { $sources += $converterSource }
    foreach ($source in $sources) {
        Assert-EvidenceAcl $source
        $destination = Join-Path $InstallRoot (Split-Path $source -Leaf)
        Assert-EvidencePath $destination
        if (Test-Path -LiteralPath $destination) { Assert-EvidenceAcl $destination }
        # Replace the directory entry, never overwrite an existing hard-linked file.
        if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Force }
        Copy-Item -LiteralPath $source -Destination $destination
        Assert-EvidenceAcl $destination
    }
    $configPath = Join-Path $InstallRoot 'config.json'
    if (Test-Path -LiteralPath $configPath) { Assert-EvidenceAcl $configPath; Remove-Item -LiteralPath $configPath -Force }
    $config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
    $step = 'register-task-folder'; Write-Host "[evidence-install] step=$step"
    if (-not $folder) { $folder = $scheduler.GetFolder('\').CreateFolder($config.TaskFolder, $brokerSddl) }
    $folder.SetSecurityDescriptor($brokerSddl, 0)
    $broker = New-EvidenceTaskDefinition $scheduler 'Broker' 'SYSTEM'
    $worker = New-EvidenceTaskDefinition $scheduler 'Worker' $LabCredential.UserName
    # 0x10 prevents Scheduler from adding an execute ACE for the worker principal.
    $step = 'register-worker'; Write-Host "[evidence-install] step=$step"
    $workerTask = $folder.RegisterTaskDefinition('Worker', $worker, 6 -bor 0x10,
        $LabCredential.UserName, $LabCredential.GetNetworkCredential().Password, 1, $workerSddl)
    $workerTask.SetSecurityDescriptor($workerSddl, 0x10)
    $step = 'register-broker'; Write-Host "[evidence-install] step=$step"
    $brokerTask = $folder.RegisterTaskDefinition('Broker', $broker, 6 -bor 0x10, 'SYSTEM', $null, 5, $brokerSddl)
    $brokerTask.SetSecurityDescriptor($brokerSddl, 0x10)
    $step = 'publish-dispatcher'; Write-Host "[evidence-install] step=$step"
    Publish-EvidenceDispatcher (Join-Path $InstallRoot 'Get-KerberosEvidence.ps1') $account.Sid
    Write-Output 'AUTO_EVIDENCE_READY'
    } finally { $installLock.Dispose() }
    } catch { throw (Format-EvidenceInstallFailure $_ $step $LabCredential) }
}

if (-not $Library) { Install-EvidenceAutomation }
