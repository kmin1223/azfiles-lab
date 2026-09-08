[CmdletBinding()]
param([ValidateSet('Client','Broker','Worker','Library')][string]$Mode = 'Client')

$ErrorActionPreference = 'Stop'
$script:InstallRoot = 'C:\Program Files\AzureFilesLabEvidence'
$script:RuntimeRoot = 'C:\ProgramData\AzureFilesLabEvidence'

function Assert-EvidenceConfig($Config) {
    if ($Config.StorageAccount -notmatch '^[a-z0-9]{3,24}$' -or
        $Config.Share -notmatch '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$' -or
        $Config.Share -match '--' -or
        $Config.DomainController -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$' -or
        $Config.ExpectedUserSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d{4,}$' -or
        $Config.Account -notmatch '^[^\\/@\s]+\\labuser1$' -or
        $Config.TaskFolder -cne '\AzureFilesLabEvidence' -or
        $Config.BrokerTask -cne 'Broker' -or $Config.WorkerTask -cne 'Worker') {
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
    if ('LabEvidence.SafeReader' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace LabEvidence {
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
  public static string BatchLogon(long notBefore) {
   using(var identity=System.Security.Principal.WindowsIdentity.GetCurrent()) {
    Statistics s; int needed;
    if(!GetTokenInformation(identity.Token,10,out s,Marshal.SizeOf(typeof(Statistics)),out needed))
     throw new IOException("Cannot inspect worker token.");
    IntPtr data;
    if(LsaGetLogonSessionData(ref s.Authentication,out data)!=0) throw new IOException("Cannot inspect worker logon.");
    try {
     var session=(Session)Marshal.PtrToStructure(data,typeof(Session));
     if(session.LogonType!=4) throw new IOException("Worker requires a fresh password batch logon.");
     if(session.LogonTime<notBefore) throw new IOException("Scheduler reused an older logon; fresh evidence requires a new batch session.");
     return s.Authentication.High.ToString()+":0x"+s.Authentication.Low.ToString("x");
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
    [LabEvidence.SafeReader]::Read($Path, $Maximum) | ConvertFrom-Json
}

function Write-EvidenceState($State) {
    $path = Join-Path $RuntimeRoot 'state.json'
    $staging = Join-Path $RuntimeRoot 'state.new'
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Force }
    $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $staging -Encoding UTF8
    if (Test-Path -LiteralPath $path) { [IO.File]::Replace($staging, $path, [NullString]::Value) }
    else { [IO.File]::Move($staging, $path) }
}

function Get-EvidenceIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $groups = @($identity.Groups | ForEach-Object Value)
    [pscustomobject]@{
        Sid = $identity.User.Value
        Admin = ((New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator) -or
            'S-1-5-32-544' -in $groups -or @($groups | Where-Object { $_ -match '^S-1-5-21-.*-(512|519)$' }).Count -gt 0)
    }
}

function Assert-EvidenceIdentity($Config, [string]$Role) {
    $identity = Get-EvidenceIdentity
    if ($Role -eq 'Broker') {
        if ($identity.Sid -ne 'S-1-5-18') { throw 'The evidence broker requires SYSTEM.' }
    } elseif ($identity.Sid -ne $Config.ExpectedUserSid -or $identity.Admin) {
        throw 'Evidence automation requires the configured non-administrator labuser1.'
    }
}

function Get-EvidenceFolder($Config) {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $scheduler.GetFolder($Config.TaskFolder)
}

function Get-EvidenceInstanceId($Task) {
    $instances = @($Task.GetInstances(0))
    if ($instances.Count -ne 1) { throw 'Expected exactly one running scheduled task instance.' }
    ([guid]$instances[0].InstanceGuid).ToString('D')
}

function Get-EvidenceHResult($Exception) {
    while ($Exception.InnerException) { $Exception = $Exception.InnerException }
    $Exception.HResult
}

function Wait-EvidenceInstance($Instance, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try { $Instance.Refresh(); $state = $Instance.State }
        catch [Runtime.InteropServices.COMException] {
            if ((Get-EvidenceHResult $_.Exception) -eq -2147216629) { return } # SCHED_E_TASK_NOT_RUNNING
            throw
        }
        if ($state -notin @(2,4)) { return }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Scheduled worker timed out.' }
        Start-Sleep -Milliseconds 300
    } while ($true)
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
        ConnectionMode = 'UNC'; NonInteractive = $true; ExpectedLogonType = 'Batch (4)'
        Provenance = 'Validated worker report; user-writable evidence is not an attestation'
    }
}

function Invoke-EvidenceWorker($Config) {
    Assert-EvidenceIdentity $Config 'Worker'
    if (Test-Admin) { throw 'Worker must not have an administrator token.' }
    Initialize-EvidenceNativeReader
    $instance = Get-EvidenceInstanceId ((Get-EvidenceFolder $Config).GetTask($Config.WorkerTask))
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $state = Read-EvidenceJson (Join-Path $RuntimeRoot 'state.json')
        if ($state.WorkerInstanceId -eq $instance -and $state.Status -eq 'RunningWorker') { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Worker has no matching broker run.' }
        Start-Sleep -Milliseconds 200
    } while ($true)
    $paths = Get-EvidenceRunPaths $state.RunId
    Assert-EvidencePath $paths.User
    $done = @{ RunId = $state.RunId; WorkerInstanceId = $instance; UserSid = $Config.ExpectedUserSid
        Elevated = $false; LogonType = 'Batch'; LogonId = ''; Status = 'Failed'; Error = '' }
    try {
        # Keep this non-inheritable handle rooted until process exit. Task Stop then kills net.exe too.
        # Nested jobs require Windows 8/Server 2012 or newer; failure aborts before reproduction.
        $script:WorkerJob = [LabEvidence.SafeReader]::OwnWorkerProcessTree()
        $done.LogonId = [LabEvidence.SafeReader]::BatchLogon(
            [DateTime]::Parse($state.StartUtc).ToUniversalTime().ToFileTimeUtc())
        & {
            Initialize-EvidenceRun $paths.User
            try { Invoke-MountAttempt $paths.User -NoDriveMapping -NonInteractive }
            finally {
                $reproPath = Join-Path $paths.User 'reproduction.json'
                if ((Test-Path -LiteralPath $reproPath) -and (Read-EvidenceJson $reproPath).EndUtc) {
                    Save-DcEvidence $paths.User
                }
            }
        } *> (Join-Path $paths.User 'worker-output.txt')
        $done.Status = 'Completed'
    } catch { $done.Error = $_.Exception.Message }
    finally { Write-JsonFile $done (Join-Path $paths.User 'done.json') }
    if ($done.Status -ne 'Completed') { throw "Worker failed: $($done.Error)" }
}

function Invoke-EvidenceBroker($Config) {
    Assert-EvidenceIdentity $Config 'Broker'
    $lock = $null; $worker = $null; $owned = $false; $state = $null
    try {
        $lock = [IO.File]::Open((Join-Path $RuntimeRoot 'broker.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
        $statePath = Join-Path $RuntimeRoot 'state.json'
        if ((Test-Path -LiteralPath $statePath) -and (Read-EvidenceJson $statePath).TraceOwned) {
            throw 'Previous trace ownership is unresolved. Administrator recovery is required; no trace was stopped.'
        }
        $folder = Get-EvidenceFolder $Config
        $id = Get-EvidenceInstanceId ($folder.GetTask($Config.BrokerTask))
        $paths = Get-EvidenceRunPaths ([guid]::NewGuid().ToString('D'))
        foreach ($directory in @($paths.Root, $paths.Capture)) {
            New-EvidenceDirectory $directory $Config.ExpectedUserSid
        }
        New-EvidenceDirectory $paths.User $Config.ExpectedUserSid -UserWritable
        $state = [ordered]@{ RunId = Split-Path $paths.Root -Leaf; BrokerInstanceId = $id; WorkerInstanceId = ''
            Status = 'StartingCapture'; StartUtc = [DateTime]::UtcNow.ToString('o'); EndUtc = $null
            TraceOwned = $true; CaptureStatus = 'Starting'; WorkerStatus = 'NotStarted'
            MountExitCode = $null; ExpectedAccount = $Config.Account; ExpectedLogonType = 'Batch (4)'
            Error = ''; Complete = $false }
        # A killed broker must leave a conservative recovery marker, even during netsh startup.
        Write-EvidenceState $state
        $owned = Start-Capture $paths.Capture
        $state.TraceOwned = [bool]$owned
        if (-not $owned) { $state.CaptureStatus = 'StartFailed'; throw 'Capture failed to start; existing traces were not stopped.' }
        $state.CaptureStatus = 'Capturing'; Write-EvidenceState $state
        $task = $folder.GetTask($Config.WorkerTask)
        if ($task.State -in @(2,4)) { throw 'A worker task is already running.' }
        $worker = $task.Run($null)
        $state.WorkerInstanceId = ([guid]$worker.InstanceGuid).ToString('D')
        $state.Status = 'RunningWorker'; $state.WorkerStatus = 'Running'; Write-EvidenceState $state
        Wait-EvidenceInstance $worker 180
        $done = Read-EvidenceJson (Join-Path $paths.User 'done.json')
        if ($done.RunId -ne $state.RunId -or $done.WorkerInstanceId -ne $state.WorkerInstanceId -or
            $done.UserSid -ne $Config.ExpectedUserSid -or $done.Elevated -ne $false -or
            $done.LogonType -ne 'Batch' -or $done.Status -ne 'Completed') {
            throw 'Worker failed or did not provide completion for this exact run.'
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
        if ($state) {
            if ($worker) {
                try {
                    $worker.Refresh()
                    if ($worker.State -in @(2,4)) { $worker.Stop(); Wait-EvidenceInstance $worker 10 }
                }
                catch {
                    if ((Get-EvidenceHResult $_.Exception) -ne -2147216629) {
                        $state.Status = 'Failed'; $state.Error += " Worker cleanup: $($_.Exception.Message)"
                    }
                }
            }
            if ($owned) {
                try { Stop-Capture $paths.Capture; $state.TraceOwned = $false; $state.CaptureStatus = 'Stopped' }
                catch { $state.Status = 'Failed'; $state.CaptureStatus = 'StopFailed'; $state.Error += " Capture cleanup: $($_.Exception.Message)" }
            }
            $state.Complete = $true; $state.EndUtc = [DateTime]::UtcNow.ToString('o')
            try { Write-EvidenceState $state; Write-JsonFile $state (Join-Path $paths.Capture 'automation-summary.json') }
            finally { if ($lock) { $lock.Dispose(); $lock = $null } }
        }
        if ($lock) { $lock.Dispose() }
    }
    if ($state.Status -ne 'Completed') { throw "Automatic evidence failed: $($state.Error)" }
}

function Test-EvidenceCompletion($State, [string]$InstanceId, [string]$PreviousRun) {
    $State -and $State.BrokerInstanceId -eq $InstanceId -and
        $State.RunId -ne $PreviousRun -and $State.Complete -eq $true
}

function Invoke-EvidenceClient($Config) {
    Assert-EvidenceIdentity $Config 'Client'
    $task = (Get-EvidenceFolder $Config).GetTask($Config.BrokerTask)
    if ($task.State -in @(2,4)) { throw 'An automatic evidence run is already in progress.' }
    $statePath = Join-Path $RuntimeRoot 'state.json'
    $previous = $null
    if (Test-Path -LiteralPath $statePath) {
        $previous = Read-EvidenceJson $statePath
        if ($previous.TraceOwned) { throw 'Unresolved trace ownership requires administrator recovery.' }
    }
    $instance = $task.Run($null)
    $id = ([guid]$instance.InstanceGuid).ToString('D')
    $deadline = [DateTime]::UtcNow.AddMinutes(11); $last = ''; $stoppedAt = $null
    Write-Host "Automatic capture: $($Config.Account), fresh batch logon (not the RDP session)."
    do {
        $state = $null
        if (Test-Path -LiteralPath $statePath) { $state = Read-EvidenceJson $statePath }
        if ($state -and $state.BrokerInstanceId -eq $id -and $state.RunId -ne $previous.RunId) {
            if ($state.Status -ne $last) { Write-Host $state.Status; $last = $state.Status }
            if (Test-EvidenceCompletion $state $id $previous.RunId) { break }
        }
        $running = $false
        try { $instance.Refresh(); $running = $instance.State -in @(2,4) }
        catch [Runtime.InteropServices.COMException] {
            if ((Get-EvidenceHResult $_.Exception) -ne -2147216629) { throw }
        }
        if ($running) { $stoppedAt = $null }
        elseif (-not $stoppedAt) { $stoppedAt = [DateTime]::UtcNow }
        elseif ([DateTime]::UtcNow -ge $stoppedAt.AddSeconds(10)) {
            throw 'Broker exited without a completion record for this task instance. Inspect protected status.'
        }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Automatic evidence timed out. Broker cleanup continues independently; inspect protected status.' }
        Start-Sleep -Milliseconds 500
    } while ($true)
    Write-Host "Capture: $($state.CaptureStatus); worker: $($state.WorkerStatus); mount exit: $($state.MountExitCode)"
    $paths = Get-EvidenceRunPaths $state.RunId
    Write-Host "Evidence: $($paths.Root)"
    if (-not (Test-Path -LiteralPath (Join-Path $paths.Capture 'trace.pcapng'))) {
        Write-Warning 'No converted PCAPNG is available. Preserve capture\trace.etl; inspect capture\trace-stop.txt.'
    }
    # User-controlled text is displayed only under the caller's non-administrator identity.
    foreach ($name in @('worker-output.txt','mount-result.txt','reproduction.json','dc-summary.txt','done.json')) {
        $path = Join-Path $paths.User $name
        if (Test-Path -LiteralPath $path) {
            try { Assert-EvidencePath $path; Write-Host ([LabEvidence.SafeReader]::Read($path, 1048576)) }
            catch { Write-Warning "Cannot display ${name}: $($_.Exception.Message)" }
        }
    }
    if ($state.Status -ne 'Completed') { throw "Automatic evidence failed: $($state.Error)" }
    Write-Host 'Capture complete. A nonzero mount exit is an observed authentication/SMB result; capture completion does not imply mount success.'
}

if ($Mode -ne 'Library') {
    Assert-EvidenceAcl $InstallRoot
    Assert-EvidenceAcl $RuntimeRoot
    $config = Read-EvidenceJson (Join-Path $InstallRoot 'config.json')
    Assert-EvidenceConfig $config
    Assert-EvidenceIdentity $config $Mode
    if ($Mode -eq 'Client') { Invoke-EvidenceClient $config }
    else {
        $env:PATH = 'C:\Windows\System32;C:\Windows'
        $env:PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
        . (Join-Path $InstallRoot 'Get-KerberosEvidence.ps1') -Library
        $StorageAccount = $config.StorageAccount; $Share = $config.Share
        $DomainController = @($config.DomainController); $DcCredential = $null
        $ConverterPath = Join-Path $InstallRoot 'etl2pcapng.exe'
        if ($Mode -eq 'Broker') { Invoke-EvidenceBroker $config }
        else { Invoke-EvidenceWorker $config }
    }
}
