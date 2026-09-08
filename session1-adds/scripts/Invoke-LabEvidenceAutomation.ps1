[CmdletBinding()]
param(
    [ValidateSet('Client','Coordinator','Worker','Library')][string]$Mode = 'Client',
    [string]$RunId,
    [string]$CallerLogonId
)

$ErrorActionPreference = 'Stop'
if ($Mode -ne 'Library') {
    # Set before any module autoload, including privileged ACL checks.
    $env:SystemRoot = 'C:\Windows'
    $env:windir = 'C:\Windows'
    $env:PATH = 'C:\Windows\System32;C:\Windows'
    $env:PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
}
$script:InstallRoot = 'C:\Program Files\AzureFilesLabEvidence'
$script:RuntimeRoot = 'C:\ProgramData\AzureFilesLabEvidence'

function Assert-EvidenceConfig($Config) {
    if ($Config.StorageAccount -notmatch '^[a-z0-9]{3,24}$' -or
        $Config.Share -notmatch '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$' -or
        $Config.Share -match '--' -or
        $Config.DomainController -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$' -or
        $Config.ExpectedUserSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d{4,}$' -or
        $Config.Account -notmatch '^[^\\/@\s]+\\labuser1$' -or
        $Config.Version -ne 2) {
        throw 'Invalid protected automation configuration.'
    }
}

function Assert-EvidencePath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path -notmatch '^[A-Za-z]:\\' -or
        $Path.Substring(2).Contains(':') -or $Path -match '(^|\\)\.\.?($|\\)') {
        throw "Invalid local evidence path: $Path"
    }
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Reparse points are not allowed: $current"
        }
        $current = Split-Path -Path $current -Parent
    }
}

function New-EvidenceAcl([string]$Sid, [switch]$UserWritable) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'),
            @($Sid, $(if ($UserWritable) { 'Modify' } else { 'ReadAndExecute' })))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$entry[0], $entry[1],
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl
}

function New-EvidenceDirectory([string]$Path, [string]$Sid, [switch]$UserWritable) {
    Assert-EvidencePath $Path
    [IO.Directory]::CreateDirectory($Path, (New-EvidenceAcl $Sid -UserWritable:$UserWritable)) | Out-Null
}

function Assert-EvidenceAcl([string]$Path, [switch]$ParentDirectory) {
    Assert-EvidencePath $Path
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw "Unsafe owner: $Path"
    }
    # Includes write data, append, attributes, delete, ACL/owner changes and directory delete-child.
    $writeMask = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288
    # Standard C:\ and ProgramData ACLs allow creating children, not replacing protected children.
    if ($ParentDirectory) { $writeMask = 64 -bor 65536 -bor 262144 -bor 524288 }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $writeMask) -and $rule.IdentityReference.Value -notin $trusted) {
            throw "Untrusted write permission: $Path"
        }
    }
}

function Initialize-EvidenceNativeReader {
    if ('LabEvidence.Direct.SafeReader' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace LabEvidence.Direct {
 public static class SafeReader {
  [StructLayout(LayoutKind.Sequential)] struct JobLimits {
   public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
   public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority, Scheduling;
  }
  [StructLayout(LayoutKind.Sequential)] struct IoCounters {
   public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
  }
  [StructLayout(LayoutKind.Sequential)] struct ExtendedJobLimits {
   public JobLimits Basic; public IoCounters Io;
   public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateJobObject(IntPtr attributes,string name);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool SetInformationJobObject(SafeFileHandle job,int type,ref ExtendedJobLimits limits,int length);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool AssignProcessToJobObject(SafeFileHandle job,IntPtr process);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  public static SafeFileHandle OwnWorkerProcessTree() {
   var job=CreateJobObject(IntPtr.Zero,null);
   if(job.IsInvalid) { job.Dispose(); throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
   var limits=new ExtendedJobLimits();
   limits.Basic.Flags=0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, without either breakaway permission.
   if(!SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(ExtendedJobLimits)))||
      !AssignProcessToJobObject(job,GetCurrentProcess())) {
    int error=Marshal.GetLastWin32Error(); job.Dispose(); throw new System.ComponentModel.Win32Exception(error);
   }
   return job;
  }
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct Statistics {
   public Luid Token, Authentication; public long Expiration;
   public uint Type, Impersonation, Charged, Available, Groups, Privileges; public Luid Modified;
  }
  [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, Maximum; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct Session {
   public uint Size; public Luid Id; public UnicodeString User, Domain, Authentication; public uint LogonType;
   public uint SessionId; public IntPtr Sid; public long LogonTime;
  }
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool GetTokenInformation(IntPtr token,int type,out Statistics info,int length,out int needed);
  [DllImport("secur32.dll")] static extern uint LsaGetLogonSessionData(ref Luid id,out IntPtr data);
  [DllImport("secur32.dll")] static extern uint LsaFreeReturnBuffer(IntPtr data);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool SetFileSecurity(string path,uint information,byte[] descriptor);
  public static void ProtectDirectoryOnly(string path,byte[] descriptor) {
   // Unlike SetNamedSecurityInfo, this legacy API does not propagate ACLs into existing evidence.
   if(!SetFileSecurity(path,0x80000004u,descriptor))
    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  }
  public static string Logon(long notBefore,string caller,bool requireFresh) {
   using(var identity=System.Security.Principal.WindowsIdentity.GetCurrent()) {
    Statistics s; int needed;
    if(!GetTokenInformation(identity.Token,10,out s,Marshal.SizeOf(typeof(Statistics)),out needed))
     throw new IOException("Cannot inspect worker token.");
    IntPtr data;
    if(LsaGetLogonSessionData(ref s.Authentication,out data)!=0) throw new IOException("Cannot inspect worker logon.");
    try {
     var session=(Session)Marshal.PtrToStructure(data,typeof(Session));
     string id=s.Authentication.High.ToString()+":0x"+s.Authentication.Low.ToString("x");
     if(requireFresh) {
      if(session.LogonType!=2) throw new IOException("Worker requires a credential-created interactive logon (type 2).");
      if(session.LogonTime<notBefore || String.Equals(id,caller,StringComparison.OrdinalIgnoreCase))
       throw new IOException("Worker did not receive a fresh logon/LUID separate from the caller.");
     }
     return id;
    } finally { LsaFreeReturnBuffer(data); }
   }
  }
  [StructLayout(LayoutKind.Sequential)] struct Info {
   public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
   public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
  static SafeFileHandle Open(string p,bool directory) {
   // Pin directories. A final file handle survives atomic status replacement without following it.
   var h=CreateFile(p,0x80000000,directory?1u:5u,IntPtr.Zero,3,0x00200000u|(directory?0x02000000u:0),IntPtr.Zero);
   if(h.IsInvalid) { h.Dispose(); throw new IOException("Cannot safely open evidence component."); }
   Info i;
   if(!GetFileInformationByHandle(h,out i)||(i.Attributes&0x400)!=0||
      ((i.Attributes&0x10)!=0)!=directory||(!directory&&i.Links!=1)) {
    h.Dispose(); throw new IOException("Linked or unexpected evidence component.");
   }
   return h;
  }
  public static void AssertFile(string path) {
   using(var handle=Open(Path.GetFullPath(path),false)) { }
  }
  public static string Read(string path,int maximum) {
   var pins=new List<SafeFileHandle>();
   try {
    string full=Path.GetFullPath(path), parent=Path.GetDirectoryName(full);
    var parents=new Stack<string>();
    while(parent!=null) { parents.Push(parent); parent=Path.GetDirectoryName(parent); }
    while(parents.Count!=0) pins.Add(Open(parents.Pop(),true));
    using(var h=Open(full,false))
    using(var stream=new FileStream(h,FileAccess.Read)) {
     if(stream.Length>maximum) throw new IOException("Evidence exceeds size limit.");
     using(var reader=new StreamReader(stream,Encoding.UTF8,true)) return reader.ReadToEnd();
    }
   } finally { foreach(var h in pins) h.Dispose(); }
  }
 }
}
'@
}

function Read-EvidenceJson([string]$Path, [int]$Maximum = 65536) {
    Assert-EvidencePath $Path
    Initialize-EvidenceNativeReader
    [LabEvidence.Direct.SafeReader]::Read($Path, $Maximum) | ConvertFrom-Json
}

function Write-EvidenceState($State) {
    $path = Join-Path $RuntimeRoot 'state.json'
    $staging = Join-Path $RuntimeRoot 'state.new'
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Force }
    $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $staging -Encoding UTF8
    for ($attempt = 0; ; $attempt++) {
        try {
            if (Test-Path -LiteralPath $path) { [IO.File]::Replace($staging, $path, [NullString]::Value) }
            else { [IO.File]::Move($staging, $path) }
            break
        } catch [IO.IOException] {
            # AV/readers can briefly deny replacement. Preserve atomic publication; never delete state.json.
            $failure = $_.Exception
            while ($failure.InnerException) { $failure = $failure.InnerException }
            if ($attempt -ge 5 -or ($failure.HResult -band 0xffff) -notin @(32,33,1176)) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
}

function Test-EvidenceDomainAdministrator([string[]]$GroupSids) {
    @($GroupSids | Where-Object { $_ -match '^S-1-5-21-\d+-\d+-\d+-(512|519)$' }).Count -gt 0
}

function ConvertTo-EvidenceIdentity($Identity, [bool]$AdministratorEnabled) {
    $groups = @($Identity.Groups | ForEach-Object Value)
    [pscustomobject]@{
        Sid = $Identity.User.Value
        # UAC may retain Administrators as deny-only. Its presence is not elevation.
        Admin = ($AdministratorEnabled -or (Test-EvidenceDomainAdministrator $groups))
    }
}

function Get-EvidenceIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        ConvertTo-EvidenceIdentity $identity ($principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator))
    } finally { $identity.Dispose() }
}

function Assert-EvidenceIdentity($Config, [string]$Role) {
    $identity = Get-EvidenceIdentity
    if ($Role -eq 'Coordinator') {
        if ($identity.Sid -ne $Config.ExpectedUserSid -or -not $identity.Admin) {
            throw 'The coordinator requires the configured labuser1 elevated through UAC consent.'
        }
    } elseif ($identity.Sid -ne $Config.ExpectedUserSid -or $identity.Admin) {
        throw 'Evidence automation requires the configured labuser1 with a non-elevated token, not Domain/Enterprise Admin. Use a normal PowerShell window; local administrators require UAC enabled.'
    }
}

function Assert-EvidencePrivateAcl([string]$Path) {
    Assert-EvidenceAcl $Path
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'Stored credential must be accessible only to Administrators and SYSTEM.'
        }
    }
}

function Read-EvidenceCredential($Config) {
    $directory = Join-Path $InstallRoot 'Credentials'
    $path = Join-Path $directory 'credential.json'
    Assert-EvidencePrivateAcl $directory
    Assert-EvidencePrivateAcl $path
    $stored = Read-EvidenceJson $path
    if ($stored.Account -cne $Config.Account) { throw 'Stored credential account does not match configuration; rerun setup.' }
    Add-Type -AssemblyName System.Security
    $bytes = $null
    $secure = New-Object Security.SecureString
    try {
        $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
            [Convert]::FromBase64String($stored.Password), $null,
            [Security.Cryptography.DataProtectionScope]::LocalMachine)
        if (-not $bytes.Length -or $bytes.Length % 2) { throw 'Invalid stored password encoding.' }
        for ($i = 0; $i -lt $bytes.Length; $i += 2) {
            $secure.AppendChar([char]([int]$bytes[$i] -bor ([int]$bytes[$i + 1] -shl 8)))
        }
        $secure.MakeReadOnly()
        [PSCredential]::new($Config.Account, $secure)
    } catch { $secure.Dispose(); throw }
    finally { if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) } }
}

function Get-EvidenceLogonId {
    Initialize-EvidenceNativeReader
    [LabEvidence.Direct.SafeReader]::Logon(0, '', $false)
}

function Assert-EvidenceRunArguments([string]$Id, [string]$Caller) {
    $null = Get-EvidenceRunPaths $Id
    if ($Caller -notmatch '^\d+:0x[0-9a-fA-F]+$' -or $Caller -match '^0:0x0*(3e7|3e4|3e5)$') {
        throw 'Invalid caller LUID.'
    }
}

function Start-EvidenceProcess([string]$Role, [string]$Id, [string]$Caller, [PSCredential]$Credential) {
    Assert-EvidenceRunArguments $Id $Caller
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        (Join-Path $InstallRoot 'Invoke-LabEvidenceAutomation.ps1') +
        '" -Mode ' + $Role + ' -RunId ' + $Id + ' -CallerLogonId ' + $Caller
    $launch = @{
        FilePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        ArgumentList = $arguments; WorkingDirectory = $InstallRoot
        PassThru = $true; ErrorAction = 'Stop'
    }
    if ($Role -eq 'Coordinator') {
        if ($Credential) { throw 'UAC and credential launch must remain separate.' }
        $launch.Verb = 'RunAs'
    } elseif ($Role -eq 'Worker' -and $Credential) {
        $launch.Credential = $Credential
        $launch.LoadUserProfile = $true
        $launch.WindowStyle = 'Hidden'
        $capture = (Get-EvidenceRunPaths $Id).Capture
        Assert-EvidenceAcl $capture
        $launch.RedirectStandardOutput = Join-Path $capture 'worker-stdout.txt'
        $launch.RedirectStandardError = Join-Path $capture 'worker-stderr.txt'
    } else { throw 'Invalid process launch role or missing credential.' }
    try { Start-Process @launch }
    catch {
        $errorDetail = $_.Exception
        while ($errorDetail.InnerException) { $errorDetail = $errorDetail.InnerException }
        if ($Role -eq 'Coordinator' -and $errorDetail.NativeErrorCode -eq 1223) {
            throw 'UAC consent was cancelled; no capture was requested.'
        }
        # Never include a credential-bearing invocation or a password in diagnostics.
        throw "$Role launch failed (HRESULT $($errorDetail.HResult), Win32 $($errorDetail.NativeErrorCode)). Check UAC, Secondary Logon, the stored lab password and logon policy."
    }
}

function Wait-EvidenceProcess($Process, [int]$Seconds) {
    if (-not $Process.WaitForExit($Seconds * 1000)) { throw 'Evidence worker timed out.' }
}

function Stop-EvidenceProcess($Process) {
    if (-not $Process.HasExited) {
        $Process.Kill()
        if (-not $Process.WaitForExit(10000)) { throw 'Owned worker did not terminate.' }
    }
}

function Get-EvidenceRunPaths([string]$RunId) {
    $parsed = [guid]::Empty
    if (-not [guid]::TryParseExact($RunId, 'D', [ref]$parsed)) { throw 'Invalid run GUID.' }
    $root = Join-Path (Join-Path $RuntimeRoot 'Runs') $RunId
    [pscustomobject]@{ Root = $root; Capture = Join-Path $root 'capture'; User = Join-Path $root 'user' }
}

function ConvertTo-EvidenceContext($Value, $Config, [DateTime]$Start, [DateTime]$End) {
    if ($Value.UserSid -ne $Config.ExpectedUserSid -or $Value.Account -ine $Config.Account -or
        $Value.Elevated -isnot [bool] -or $Value.Elevated -or
        $Value.LogonId -notmatch '^\d+:0x[0-9a-fA-F]+$' -or
        $Value.LogonId -match '^0:0x0*(3e7|3e4|3e5)$' -or
        $Value.StorageAccount -cne $Config.StorageAccount -or $Value.Share -cne $Config.Share -or
        $Value.ConnectionMode -cne 'UNC' -or $Value.NonInteractive -isnot [bool] -or $Value.NonInteractive -ne $true -or
        $Value.MountExitCode -isnot [int]) { throw 'Worker reproduction identity or target validation failed.' }
    $from = [DateTime]::Parse($Value.StartUtc).ToUniversalTime()
    $to = [DateTime]::Parse($Value.EndUtc).ToUniversalTime()
    if ($from -lt $Start -or $to -lt $from -or $to -gt $End) { throw 'Worker reproduction is outside this run window.' }
    [pscustomobject]@{
        StartUtc = $from.ToString('o'); EndUtc = $to.ToString('o'); UserSid = $Config.ExpectedUserSid
        Account = $Config.Account; UserName = 'labuser1'; Elevated = $false; LogonId = $Value.LogonId
        StorageAccount = $Config.StorageAccount; Share = $Config.Share
        Spn = "cifs/$($Config.StorageAccount).file.core.windows.net"; MountExitCode = $Value.MountExitCode
        MountTimedOut = ($Value.MountTimedOut -eq $true)
        ConnectionMode = 'UNC'; NonInteractive = $true; ExpectedLogonType = 'Interactive (2), credential-created'
        Provenance = 'Validated worker report; user-writable evidence is not an attestation'
    }
}

function Invoke-EvidenceWorker($Config, [string]$Id, [string]$Caller) {
    Assert-EvidenceRunArguments $Id $Caller
    Assert-EvidenceIdentity $Config 'Worker'
    if (Test-Admin) { throw 'Worker must not have an administrator token.' }
    Initialize-EvidenceNativeReader
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $state = Read-EvidenceJson (Join-Path $RuntimeRoot 'state.json')
        if ($state.RunId -eq $Id -and $state.CallerLogonId -eq $Caller -and
            $state.WorkerProcessId -eq $PID -and $state.Status -eq 'RunningWorker') { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Worker has no matching coordinator run/PID.' }
        Start-Sleep -Milliseconds 200
    } while ($true)
    $paths = Get-EvidenceRunPaths $state.RunId
    Assert-EvidencePath $paths.User
    $done = @{ RunId = $Id; WorkerProcessId = $PID; UserSid = $Config.ExpectedUserSid
        Elevated = $false; LogonType = 2; LogonId = ''; Status = 'Failed'; Error = '' }
    try {
        # Keep this non-inheritable handle rooted until process exit. Killing this process kills net.exe too.
        # Nested jobs require Windows 8/Server 2012 or newer; failure aborts before reproduction.
        $script:WorkerJob = [LabEvidence.Direct.SafeReader]::OwnWorkerProcessTree()
        $done.LogonId = [LabEvidence.Direct.SafeReader]::Logon(
            [DateTime]::Parse($state.WorkerStartUtc).ToUniversalTime().ToFileTimeUtc(), $Caller, $true)
        & {
            Initialize-EvidenceRun $paths.User
            try { Invoke-MountAttempt $paths.User -NoDriveMapping -NonInteractive }
            finally {
                $reproPath = Join-Path $paths.User 'reproduction.json'
                if ((Test-Path -LiteralPath $reproPath) -and (Read-EvidenceJson $reproPath).EndUtc) {
                    Save-DcEvidence $paths.User
                    $dc = @(Read-EvidenceJson (Join-Path $paths.User 'dc-collection.json'))
                    if (-not $dc.Count -or @($dc | Where-Object {
                        $_.Status -notin @('Collected','NoMatchingEvents') -or $_.Truncated
                    }).Count) { throw 'DC evidence is failed, missing or truncated; inspect dc-collection.json.' }
                }
            }
        } *> (Join-Path $paths.User 'worker-output.txt')
        $done.Status = 'Completed'
    } catch { $done.Error = $_.Exception.Message }
    finally { Write-JsonFile $done (Join-Path $paths.User 'done.json') }
    if ($done.Status -ne 'Completed') { throw "Worker failed: $($done.Error)" }
}

function Invoke-EvidenceCoordinator($Config, [string]$Id, [string]$Caller) {
    Assert-EvidenceRunArguments $Id $Caller
    Assert-EvidenceIdentity $Config 'Coordinator'
    $lock = $null; $worker = $null; $owned = $false; $state = $null; $credential = $null
    try {
        $lock = [IO.File]::Open((Join-Path $RuntimeRoot 'broker.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
        $statePath = Join-Path $RuntimeRoot 'state.json'
        if (Test-Path -LiteralPath $statePath) {
            $previous = Read-EvidenceJson $statePath
            if ($previous.TraceOwned -or $previous.WorkerCleanupFailed) {
                throw 'Previous capture/worker ownership is unresolved. Administrator recovery is required; nothing was stopped.'
            }
        }
        $paths = Get-EvidenceRunPaths $Id
        if (Test-Path -LiteralPath $paths.Root) { throw 'Run ID already exists; evidence cannot be reused.' }
        foreach ($directory in @($paths.Root, $paths.Capture)) {
            New-EvidenceDirectory $directory $Config.ExpectedUserSid
        }
        New-EvidenceDirectory $paths.User $Config.ExpectedUserSid -UserWritable
        $state = [ordered]@{ RunId = $Id; CoordinatorProcessId = $PID; CallerLogonId = $Caller; WorkerProcessId = 0
            Status = 'StartingCapture'; StartUtc = [DateTime]::UtcNow.ToString('o'); EndUtc = $null
            TraceOwned = $true; CaptureStatus = 'Starting'; WorkerStatus = 'NotStarted'
            WorkerStartUtc = $null; WorkerCleanupFailed = $false
            MountExitCode = $null; ExpectedAccount = $Config.Account; ExpectedLogonType = 'Interactive (2), credential-created'
            Error = ''; Complete = $false }
        # A killed coordinator must leave a conservative recovery marker, even during netsh startup.
        Write-EvidenceState $state
        $owned = Start-Capture $paths.Capture
        $state.TraceOwned = [bool]$owned
        if (-not $owned) { $state.CaptureStatus = 'StartFailed'; throw 'Capture failed to start; existing traces were not stopped.' }
        $state.CaptureStatus = 'Capturing'; Write-EvidenceState $state
        $credential = Read-EvidenceCredential $Config
        $state.WorkerStartUtc = [DateTime]::UtcNow.ToString('o')
        $state.Status = 'RunningWorker'; $state.WorkerStatus = 'Running'
        Write-EvidenceState $state
        $worker = Start-EvidenceProcess 'Worker' $Id $Caller $credential
        $state.WorkerProcessId = $worker.Id
        Write-EvidenceState $state
        Wait-EvidenceProcess $worker 180
        $done = Read-EvidenceJson (Join-Path $paths.User 'done.json')
        if ($worker.ExitCode -ne 0 -or $done.RunId -ne $state.RunId -or $done.WorkerProcessId -ne $state.WorkerProcessId -or
            $done.UserSid -ne $Config.ExpectedUserSid -or $done.Elevated -ne $false -or
            $done.LogonType -ne 2 -or $done.LogonId -eq $Caller -or $done.Status -ne 'Completed') {
            throw 'Worker failed or did not provide completion for this exact run/PID. Inspect user\done.json and worker-output.txt.'
        }
        $context = ConvertTo-EvidenceContext (Read-EvidenceJson (Join-Path $paths.User 'reproduction.json')) `
            $Config ([DateTime]::Parse($state.StartUtc).ToUniversalTime()) ([DateTime]::UtcNow)
        if ($context.LogonId -ine $done.LogonId) { throw 'Worker token and reproduction LUID do not match.' }
        Write-JsonFile $context (Join-Path $paths.Capture 'reproduction.json')
        $state.MountExitCode = $context.MountExitCode; $state.WorkerStatus = 'Completed'
        Save-EventLogs $paths.Capture
        Save-SmbState $paths.Capture '-collector'
        $state.Status = 'Completed'
    } catch {
        if ($state) {
            $state.Status = 'Failed'; $state.Error = $_.Exception.Message
            if ($state.WorkerStatus -eq 'Running') {
                $state.WorkerStatus = $(if ($state.Error -match 'timed out|timeout') { 'TimedOut' } else { 'Failed' })
            }
        }
        else { throw }
    } finally {
        try {
        if ($state) {
            if ($worker) {
                try {
                    Stop-EvidenceProcess $worker
                }
                catch {
                    $state.WorkerCleanupFailed = $true
                    $state.Status = 'Failed'; $state.Error += " Worker cleanup: $($_.Exception.Message)"
                }
                finally { $worker.Dispose() }
            }
            if ($owned) {
                try { Stop-Capture $paths.Capture; $state.TraceOwned = $false; $state.CaptureStatus = 'Stopped' }
                catch { $state.Status = 'Failed'; $state.CaptureStatus = 'StopFailed'; $state.Error += " Capture cleanup: $($_.Exception.Message)" }
            }
            $state.Complete = $true; $state.EndUtc = [DateTime]::UtcNow.ToString('o')
            Write-EvidenceState $state
            Write-JsonFile $state (Join-Path $paths.Capture 'automation-summary.json')
        }
        } finally {
            if ($lock) { $lock.Dispose() }
            if ($credential) { $credential.Password.Dispose() }
        }
    }
    if ($state.Status -ne 'Completed') { throw "Automatic evidence failed: $($state.Error)" }
}

function Test-EvidenceCompletion($State, [string]$Id, [int]$CoordinatorId, [string]$Caller) {
    $State -and $State.RunId -eq $Id -and $State.CoordinatorProcessId -eq $CoordinatorId -and
        $State.CallerLogonId -eq $Caller -and $State.Complete -eq $true
}

function Invoke-EvidenceClient($Config) {
    Assert-EvidenceIdentity $Config 'Client'
    $statePath = Join-Path $RuntimeRoot 'state.json'
    $previous = $null
    if (Test-Path -LiteralPath $statePath) {
        $previous = Read-EvidenceJson $statePath
        if ($previous.TraceOwned -or $previous.WorkerCleanupFailed) {
            throw 'A capture is active or ownership is unresolved; inspect protected status before retrying.'
        }
    }
    $id = [guid]::NewGuid().ToString('D')
    $caller = Get-EvidenceLogonId
    $paths = Get-EvidenceRunPaths $id
    Write-Host "Approve one UAC consent. Capture uses a fresh credential-created labuser1 logon, NOT the RDP session."
    Write-Host "Run: $id; evidence: $($paths.Root)"
    $coordinator = Start-EvidenceProcess 'Coordinator' $id $caller
    try {
        if (-not $coordinator.WaitForExit(660000)) {
            throw 'Coordinator timed out; cleanup may still be running. Do not kill it or start another trace; inspect protected state.json.'
        }
        $summary = Join-Path $paths.Capture 'automation-summary.json'
        if (-not (Test-Path -LiteralPath $summary)) {
            throw 'Coordinator exited without a result for this run. Check its window and protected state.json (concurrent capture, UAC/logon or setup failure).'
        }
        $state = Read-EvidenceJson $summary
        if (-not (Test-EvidenceCompletion $state $id $coordinator.Id $caller)) {
            throw 'Coordinator result does not match this run/PID/caller.'
        }
        if ($coordinator.ExitCode -ne 0 -and $state.Status -eq 'Completed') {
            throw 'Coordinator exited unsuccessfully despite its completion record.'
        }
    } finally { $coordinator.Dispose() }
    Write-Host "Capture: $($state.CaptureStatus); worker: $($state.WorkerStatus); mount exit: $($state.MountExitCode)"
    Write-Host "Evidence: $($paths.Root)"
    if (-not (Test-Path -LiteralPath (Join-Path $paths.Capture 'trace.pcapng'))) {
        Write-Warning 'No converted PCAPNG is available. Preserve capture\trace.etl; inspect capture\trace-stop.txt.'
    }
    # User-controlled text is displayed only under the caller's non-elevated identity.
    foreach ($name in @('worker-output.txt','mount-result.txt','reproduction.json','dc-summary.txt','done.json')) {
        $path = Join-Path $paths.User $name
        if (Test-Path -LiteralPath $path) {
            try { Assert-EvidencePath $path; Write-Host ([LabEvidence.Direct.SafeReader]::Read($path, 1048576)) }
            catch { Write-Warning "Cannot display ${name}: $($_.Exception.Message)" }
        }
    }
    foreach ($name in @('worker-stdout.txt','worker-stderr.txt')) {
        $path = Join-Path $paths.Capture $name
        if (Test-Path -LiteralPath $path) {
            try { Write-Host ([LabEvidence.Direct.SafeReader]::Read($path, 1048576)) }
            catch { Write-Warning "Cannot display ${name}: $($_.Exception.Message)" }
        }
    }
    if ($state.Status -ne 'Completed') { throw "Automatic evidence failed: $($state.Error)" }
    Write-Host 'Capture complete. A nonzero mount exit is an observed authentication/SMB result; capture completion does not imply mount success.'
}

if ($Mode -ne 'Library') {
    Assert-EvidenceAcl $InstallRoot
    Assert-EvidenceAcl $RuntimeRoot
    Assert-EvidenceAcl (Join-Path $RuntimeRoot 'Runs')
    foreach ($name in @('config.json','Invoke-LabEvidenceAutomation.ps1','Get-KerberosEvidence.ps1')) {
        Assert-EvidenceAcl (Join-Path $InstallRoot $name)
    }
    $config = Read-EvidenceJson (Join-Path $InstallRoot 'config.json')
    Assert-EvidenceConfig $config
    Assert-EvidenceIdentity $config $Mode
    if ($Mode -eq 'Client') { Invoke-EvidenceClient $config }
    else {
        . (Join-Path $InstallRoot 'Get-KerberosEvidence.ps1') -Library
        $StorageAccount = $config.StorageAccount; $Share = $config.Share
        $DomainController = @($config.DomainController); $DcCredential = $null
        $ConverterPath = Join-Path $InstallRoot 'etl2pcapng.exe'
        if ($Mode -eq 'Coordinator') { Invoke-EvidenceCoordinator $config $RunId $CallerLogonId }
        else { Invoke-EvidenceWorker $config $RunId $CallerLogonId }
    }
}
