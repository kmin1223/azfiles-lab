# Runs ON the cloud-only client VM, as SYSTEM, via Run Command.
#
# Everything here must happen BEFORE the Entra join, and the VM is restarted
# afterwards, because two of these settings only take effect on restart:
#   - the primary DNS suffix decides the name the device REGISTERS with, and RDP
#     with an Entra account looks the device up by the name you connect to
#     (AADSTS293004 if they disagree)
#   - CloudKerberosTicketRetrievalEnabled is read by the Kerberos SSP at startup;
#     set it and check klist cloud_debug in the same boot and you get
#     "enabled by policy: 0" and go hunting for a policy that does not exist
#
# Args: -DnsSuffix <region>.cloudapp.azure.com
param([Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$DnsSuffix)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ([string]::IsNullOrWhiteSpace($DnsSuffix)) {
    throw 'CLIENT_DNS_SUFFIX_REQUIRED: Supply DnsSuffix for full client configuration.'
}

function Save-LabToolDownload {
    [CmdletBinding()]
    param([string]$Uri, [string]$Path)
    $partial = "$Path.partial"
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $partial -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
            if ((Get-Item -LiteralPath $partial -ErrorAction Stop).Length -eq 0) {
                throw 'Downloaded file is empty.'
            }
            Move-Item -LiteralPath $partial -Destination $Path -Force -ErrorAction Stop
            return
        } catch {
            if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force -ErrorAction Stop }
            if ($attempt -eq 3) { throw }
            Write-Warning "Download attempt $attempt failed for $Uri. Retrying: $($_.Exception.Message)"
            Start-Sleep -Seconds (5 * $attempt)
        }
    }
}

function Get-LabModuleValidationScript {
    @'
param([string]$ModulePath, [string]$ReportPath)
$ErrorActionPreference = 'Stop'
# A clean process and an AllUsers-only search path prevent SYSTEM's profile or
# previously loaded assemblies from making an incomplete installation look good.
$moduleRoot = [IO.Path]::GetFullPath($ModulePath).TrimEnd('\') + '\'
$env:PSModulePath = $ModulePath + ';' + (Join-Path $PSHOME 'Modules')
$names = 'Az.Accounts', 'Az.Storage', 'Az.Resources', 'Az.Network', 'Az.Compute', 'AzFilesHybrid'
foreach ($name in $names) {
    $module = Get-Module -ListAvailable -Name $name |
        Where-Object { $_.Path -and $_.Path.StartsWith($moduleRoot, [StringComparison]::OrdinalIgnoreCase) } |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) { throw "LAB_MODULE_MISSING: $name in $ModulePath" }
    if ($name -eq 'AzFilesHybrid' -and $module.Version -lt [version]'0.3.0') {
        throw "LAB_MODULE_TOO_OLD: AzFilesHybrid $($module.Version); Entra checks require 0.3.0 or later."
    }
    if ($name -eq 'Az.Storage' -and $module.Version -lt [version]'8.1.0') {
        throw "LAB_MODULE_TOO_OLD: Az.Storage $($module.Version); AzFilesHybrid requires 8.1.0 or later."
    }
    # Import also enforces the selected manifest's RequiredModules constraints,
    # which may be stricter than these documented baseline versions.
    Import-Module -Name $module.Path -Global -Force -ErrorAction Stop
}
$expected = [ordered]@{
    'Connect-AzAccount' = 'Az.Accounts'
    'Get-AzStorageAccount' = 'Az.Storage'
    'Debug-AzStorageAccountAuth' = 'AzFilesHybrid'
}
$commands = foreach ($name in $expected.Keys) {
    $command = Get-Command -Name $name -CommandType Cmdlet, Function -ErrorAction Stop
    if ($command.ModuleName -ne $expected[$name] -or
        -not $command.Module.Path.StartsWith($moduleRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LAB_COMMAND_INVALID: $name must be exported by $($expected[$name]) in $ModulePath."
    }
    [pscustomobject]@{ Name = $name; Module = $command.ModuleName; Version = $command.Module.Version.ToString() }
}
$loaded = @(Get-Module | Where-Object {
    $_.Path -and $_.Path.StartsWith($moduleRoot, [StringComparison]::OrdinalIgnoreCase)
} | Sort-Object Name, Version | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Version = $_.Version.ToString(); Path = $_.Path }
})
foreach ($name in $names) {
    if (-not @($loaded | Where-Object Name -eq $name).Count) {
        throw "LAB_MODULE_NOT_IMPORTED: $name"
    }
}
[pscustomobject]@{
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    ModulePath = $ModulePath
    Modules = $loaded
    Commands = @($commands)
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8 -ErrorAction Stop
'@
}

function Get-LabModuleGalleryScript {
    @'
param([string]$ModulePath)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope AllUsers -Force -ErrorAction Stop | Out-Null
if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
    Register-PSRepository -Default -ErrorAction Stop
}
$repository = Get-PSRepository -Name PSGallery -ErrorAction Stop
$source = [uri]$repository.SourceLocation
if ($source.Scheme -ne 'https' -or $source.Host -ne 'www.powershellgallery.com') {
    throw "LAB_GALLERY_SOURCE_INVALID: Expected the official HTTPS PSGallery; found $source"
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
$acceptLicense = (Get-Command Save-Module -ErrorAction Stop).Parameters.ContainsKey('AcceptLicense')
foreach ($name in @('Az.Accounts', 'Az.Storage', 'Az.Resources', 'Az.Network', 'Az.Compute', 'AzFilesHybrid')) {
    $parameters = @{
        Name = $name; Path = $ModulePath; Repository = 'PSGallery'
        Force = $true; ErrorAction = 'Stop'
    }
    if ($acceptLicense) { $parameters.AcceptLicense = $true }
    if ($name -eq 'AzFilesHybrid') { $parameters.MinimumVersion = '0.3.0' }
    if ($name -eq 'Az.Storage') { $parameters.MinimumVersion = '8.1.0' }
    # Save-Module resolves RequiredModules, including version constraints and
    # Graph dependencies. A fresh import will verify the resulting manifests.
    Save-Module @parameters
}
'@
}

function Invoke-LabModuleWorker {
    [CmdletBinding()]
    param([string]$Script, [hashtable]$Parameters, [string]$ToolsDirectory)
    $work = Join-Path $ToolsDirectory ('module-check-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null
    $scriptPath = Join-Path $work 'worker.ps1'
    $stdout = Join-Path $work 'stdout.txt'
    $stderr = Join-Path $work 'stderr.txt'
    Set-Content -LiteralPath $scriptPath -Value $Script -Encoding UTF8 -ErrorAction Stop
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath)
    foreach ($key in $Parameters.Keys) {
        $arguments += "-$key"
        $arguments += [string]$Parameters[$key]
    }
    $quoted = foreach ($argument in $arguments) {
        if ($argument -match '["\r\n]' -or $argument.EndsWith('\')) {
            throw "LAB_MODULE_ARGUMENT_INVALID: Cannot quote $argument"
        }
        '"' + $argument + '"'
    }
    # Run Command and the lab's default interactive shell use Windows PowerShell.
    # PS7 can also discover this standard WindowsPowerShell AllUsers module path.
    $exe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $exe -ArgumentList ($quoted -join ' ') `
        -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -ErrorAction Stop
    $errorText = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw } else { '' }
    if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($errorText)) {
        $detail = if ($errorText.Length -gt 1200) { $errorText.Substring(0, 1200) } else { $errorText }
        throw "LAB_MODULE_WORKER_FAILED: Exit $($process.ExitCode). Logs: $work. $detail"
    }
}

function Test-LabPowerShellModules {
    [CmdletBinding()]
    param([string]$ModulePath, [string]$ToolsDirectory)
    $reportPath = Join-Path $ToolsDirectory ('module-report-' + [guid]::NewGuid().ToString('N') + '.json')
    Invoke-LabModuleWorker -Script (Get-LabModuleValidationScript) `
        -Parameters @{ ModulePath = $ModulePath; ReportPath = $reportPath } -ToolsDirectory $ToolsDirectory
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw "LAB_MODULE_REPORT_MISSING: Import worker did not write $reportPath"
    }
    $report = Get-Content -LiteralPath $reportPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if (@($report.Modules).Count -lt 6 -or @($report.Commands).Count -ne 3) {
        throw "LAB_MODULE_REPORT_INVALID: Incomplete import/command validation: $reportPath"
    }
    $report
}

function Expand-LabModuleBundle {
    [CmdletBinding()]
    param([string]$ZipPath, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $archive.Entries) {
            $relative = $entry.FullName.Replace('/', '\')
            if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':')) {
                throw "LAB_MODULE_BUNDLE_PATH_INVALID: $($entry.FullName)"
            }
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $relative))
            if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                throw "LAB_MODULE_BUNDLE_PATH_INVALID: $($entry.FullName)"
            }
            if (-not $entry.Name) {
                New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop | Out-Null
            } else {
                New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force -ErrorAction Stop | Out-Null
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $false)
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function Publish-LabPowerShellModules {
    [CmdletBinding()]
    param([string]$Source, [string]$ModulePath)
    New-Item -ItemType Directory -Path $ModulePath -Force -ErrorAction Stop | Out-Null
    foreach ($directory in Get-ChildItem -LiteralPath $Source -Directory -ErrorAction Stop) {
        Copy-Item -LiteralPath $directory.FullName -Destination $ModulePath -Recurse -Force -ErrorAction Stop
    }
}

function Write-LabModuleReport {
    param($Report, [string]$ToolsDirectory)
    $path = Join-Path $ToolsDirectory 'powershell-modules.json'
    $Report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    Write-Output "PowerShell modules imported in a fresh Windows PowerShell $($Report.PowerShellVersion) process from $($Report.ModulePath). Report: $path"
    Write-Output 'Installed Az subset: Accounts, Storage, Resources, Network, Compute; NOT the full Az meta-module.'
    foreach ($module in $Report.Modules) { Write-Output "  $($module.Name) $($module.Version)" }
    Write-Output 'Exports verified: Connect-AzAccount, Get-AzStorageAccount, Debug-AzStorageAccountAuth. Azure sign-in, management permissions and diagnostic execution are NOT VERIFIED. VM sign-in/SMB roles alone do not establish management access.'
}

function Install-LabPowerShellModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ToolsDirectory,
        [string]$ModuleBundleUri = 'https://github.com/kmin1223/azfiles-lab/releases/latest/download/labtools-modules.zip'
    )
    $modulePath = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        $report = Test-LabPowerShellModules -ModulePath $modulePath -ToolsDirectory $ToolsDirectory
    } catch {
        Write-Warning "Existing AllUsers module validation failed; installation/repair required. $($_.Exception.Message)"
        $report = $null
    }
    if ($report) {
        Write-LabModuleReport -Report $report -ToolsDirectory $ToolsDirectory
        return
    }
    $failures = @()
    foreach ($source in @('bundle', 'PSGallery')) {
        if ($source -eq 'bundle' -and -not $ModuleBundleUri) {
            Write-Warning 'Module bundle explicitly disabled; using the slower PSGallery fallback.'
            continue
        }
        $stage = Join-Path $ToolsDirectory ('module-stage-' + [guid]::NewGuid().ToString('N'))
        $zip = "$stage.zip"
        New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
        try {
            if ($source -eq 'bundle') {
                Write-Output "Downloading shared lab module bundle: $ModuleBundleUri"
                Save-LabToolDownload -Uri $ModuleBundleUri -Path $zip
                Expand-LabModuleBundle -ZipPath $zip -Destination $stage
            } else {
                Write-Warning 'Using PSGallery fallback for the Az subset (Az.Storage >= 8.1.0) and AzFilesHybrid >= 0.3.0. Dependency downloads can take several minutes; unexpected prompts fail in the noninteractive worker.'
                Invoke-LabModuleWorker -Script (Get-LabModuleGalleryScript) `
                    -Parameters @{ ModulePath = $stage } -ToolsDirectory $ToolsDirectory
            }
            Test-LabPowerShellModules -ModulePath $stage -ToolsDirectory $ToolsDirectory | Out-Null
            Publish-LabPowerShellModules -Source $stage -ModulePath $modulePath
            $report = Test-LabPowerShellModules -ModulePath $modulePath -ToolsDirectory $ToolsDirectory
        } catch {
            $failures += "${source}: $($_.Exception.Message)"
            Write-Warning "Module source failed validation/installation: $($failures[-1])"
            $report = $null
        } finally {
            # Only this invocation's generated staging paths, never installed modules.
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction Stop }
        }
        if ($report) {
            Write-LabModuleReport -Report $report -ToolsDirectory $ToolsDirectory
            return
        }
    }
    throw "LAB_MODULES_UNAVAILABLE: Neither bundle nor PSGallery provided usable AllUsers modules. CLIENT_CONFIG_DONE was not reached. Repair the bundle/feed and rerun deployment. $($failures -join ' | ')"
}

function Get-LabTraceHelperContent {
    # Embedded like Session 1: Run Command transports this with client-config.ps1,
    # without depending on a sibling file or a public source URL inside the VM.
    @'
<#
.SYNOPSIS
  Cloud-only lab: netsh network trace start/stop and local ETL conversion only.
.DESCRIPTION
  Use an elevated PowerShell window as the same lab user for Start and Stop.
  Reproduce the problem yourself in the affected user's normal window.
  StopTrace also converts to pcapng. ConvertTrace retries conversion of a saved
  ETL into a NEW private folder; it never starts or stops a trace.
  Captures contain sensitive network traffic. Keep them local and private;
  do not commit, upload or share them. Conversion does not decrypt TLS.
.EXAMPLE
  C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
.EXAMPLE
  C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace
.EXAMPLE
  C:\LabTools\Get-KerberosEvidence.ps1 -ConvertTrace -Path 'C:\Users\Lab User\AppData\Local\AzFilesLab-Traces\run\trace.etl'
#>
[CmdletBinding(DefaultParameterSetName = 'Start')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Start')][switch]$StartTrace,
    [Parameter(Mandatory, ParameterSetName = 'Stop')][switch]$StopTrace,
    [Parameter(Mandatory, ParameterSetName = 'Convert')][switch]$ConvertTrace,
    [Parameter(Mandatory, ParameterSetName = 'Convert')]
    [ValidateNotNullOrEmpty()][string]$Path
)
$ErrorActionPreference = 'Stop'

function Assert-TraceAdmin {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'TRACE_ADMIN_REQUIRED: Open PowerShell as administrator as the same lab user for StartTrace/StopTrace. Conversion needs no elevation.'
    }
}

function Get-LocalTracePath {
    param([string]$Path)
    if ($Path -notmatch '^[a-zA-Z]:\\' -or $Path -match '["\r\n]') {
        throw "TRACE_LOCAL_PATH_REQUIRED: Use an absolute local drive path, not a share: $Path"
    }
    $full = [IO.Path]::GetFullPath($Path)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw "TRACE_LOCAL_PATH_REQUIRED: Captures must stay on a local fixed drive: $full"
    }
    for ($entry = $full; $entry; $entry = Split-Path -Path $entry -Parent) {
        if ((Test-Path -LiteralPath $entry) -and
            ((Get-Item -LiteralPath $entry -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "TRACE_REPARSE_PATH: Use a local path without links or junctions: $entry"
        }
    }
    $full
}

function Set-PrivateTraceDirectory {
    param([string]$Path)
    New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($owner)
    foreach ($sid in @($owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function New-TraceRunDirectory {
    param([string]$Root)
    $run = Join-Path $Root ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
    Set-PrivateTraceDirectory -Path $run
    $run
}

function Invoke-TraceNative {
    param([string]$FilePath, [string[]]$Arguments, [string]$WorkDirectory)
    # Start-Process joins ArgumentList with spaces, so quote EVERY argument
    # explicitly for both Windows PowerShell 5.1 and PowerShell 7.
    $quoted = foreach ($argument in $Arguments) {
        if ($argument -match '["\r\n]' -or $argument.EndsWith('\')) {
            throw "TRACE_ARGUMENT_INVALID: Cannot safely quote argument: $argument"
        }
        '"' + $argument + '"'
    }
    $id = [guid]::NewGuid().ToString('N')
    $stdout = Join-Path $WorkDirectory "$id.stdout"
    $stderr = Join-Path $WorkDirectory "$id.stderr"
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList ($quoted -join ' ') `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr -ErrorAction Stop
        $output = @(
            if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Raw }
            if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw }
        ) -join "`n"
        if ($process.ExitCode -ne 0) {
            throw "TRACE_COMMAND_FAILED: $FilePath $($quoted -join ' ') exited $($process.ExitCode).`n$output"
        }
        $output
    } finally {
        foreach ($log in @($stdout, $stderr)) {
            if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -ErrorAction Stop }
        }
    }
}

function Assert-TraceSession {
    param([string]$EtlPath, [string]$Root, [switch]$Stopped)
    $status = Invoke-TraceNative -FilePath "$env:WINDIR\System32\netsh.exe" `
        -Arguments @('trace', 'show', 'status') -WorkDirectory $Root
    # Match the complete recorded path, not localized netsh field labels.
    $pattern = '(?im)(?:^|[ \t"=])' + [regex]::Escape($EtlPath) + '[" \t]*\r?$'
    if ($Stopped) {
        if ($status -match $pattern) {
            throw "TRACE_STOP_INCOMPLETE: netsh still reports '$EtlPath' after stop. State retained; inspect 'netsh trace show status' before retrying -StopTrace."
        }
        return
    }
    if ($status -notmatch $pattern) {
        throw "TRACE_SESSION_MISMATCH: netsh did not report the recorded ETL '$EtlPath'. No trace was stopped. Inspect 'netsh trace show status' before taking any manual action.`n$status"
    }
}

function Convert-TraceEtl {
    param([string]$EtlPath, [string]$OutputDirectory)
    if (-not (Test-Path -LiteralPath $EtlPath -PathType Leaf) -or
        (Get-Item -LiteralPath $EtlPath).Length -eq 0) {
        throw "TRACE_ETL_MISSING: ETL is missing or empty: $EtlPath"
    }
    $converter = 'C:\LabTools\etl2pcapng.exe'
    if (-not (Test-Path -LiteralPath $converter -PathType Leaf) -or
        (Get-Item -LiteralPath $converter).Length -eq 0) {
        throw "TRACE_CONVERTER_MISSING: $converter is missing or empty. Ask the lab deployer to repair the Cloud-only client configuration. ETL retained: $EtlPath"
    }
    $pcap = Join-Path $OutputDirectory 'trace.pcapng'
    if (Test-Path -LiteralPath $pcap) {
        throw "TRACE_OUTPUT_EXISTS: Will not overwrite $pcap. Use -ConvertTrace -Path '$EtlPath' for a new private output folder."
    }
    Write-Host "Converting local ETL: $EtlPath -> $pcap"
    $inputLock = $null
    try {
        # Refuse an ETL still open for writing, including a trace started outside
        # this helper. Permit the converter to read but no writer during conversion.
        $inputLock = [IO.File]::Open($EtlPath, 'Open', 'Read', 'Read')
        $result = Invoke-TraceNative -FilePath $converter -Arguments @($EtlPath, $pcap) -WorkDirectory $OutputDirectory
        if (-not (Test-Path -LiteralPath $pcap -PathType Leaf) -or (Get-Item -LiteralPath $pcap).Length -eq 0) {
            throw "Converter returned success without a nonempty pcapng. $result"
        }
    } catch {
        throw "TRACE_CONVERSION_FAILED: $($_.Exception.Message) ETL retained: $EtlPath. Output may be incomplete: $pcap. Retry with -ConvertTrace -Path '$EtlPath' (new output folder)."
    } finally {
        if ($inputLock) { $inputLock.Dispose() }
    }
    Write-Host $result
    Write-Output "pcapng ready: $pcap ($((Get-Item -LiteralPath $pcap).Length) bytes). Keep private; TLS remains encrypted."
}

function Invoke-LabTraceAction {
    param([ValidateSet('Start', 'Stop', 'Convert')][string]$Action, [string]$Path)
    if ($Action -ne 'Convert') { Assert-TraceAdmin }
    $root = Get-LocalTracePath -Path (Join-Path $env:LOCALAPPDATA 'AzFilesLab-Traces')
    Set-PrivateTraceDirectory -Path $root
    $pointer = Join-Path $root '.active-trace.txt'
    $lock = $null
    try {
        # Serialize this user's helper calls; never run an implicit netsh stop.
        $lock = [IO.File]::Open((Join-Path $root '.helper.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
        Write-Warning "Captures are sensitive. Keep local/private; do not upload or commit. Private root: $root"
        switch ($Action) {
            'Start' {
                if (Test-Path -LiteralPath $pointer) {
                    throw "TRACE_PENDING: Use -StopTrace as this user first. State: $pointer. If the trace was stopped externally, inspect 'netsh trace show status' and remove this state file deliberately before starting again."
                }
                $run = New-TraceRunDirectory -Root $root
                $etl = Join-Path $run 'trace.etl'
                if (Test-Path -LiteralPath $etl) { throw "TRACE_OUTPUT_EXISTS: Will not overwrite $etl" }
                Set-Content -LiteralPath $pointer -Value $etl -Encoding UTF8 -ErrorAction Stop
                Write-Host "Starting trace: $etl"
                try {
                    $result = Invoke-TraceNative -FilePath "$env:WINDIR\System32\netsh.exe" `
                        -Arguments @('trace', 'start', 'capture=yes', 'report=no', 'persistent=no',
                            'overwrite=no', 'maxsize=512', "tracefile=$etl") -WorkDirectory $root
                } catch {
                    Remove-Item -LiteralPath $pointer -ErrorAction Stop
                    throw
                }
                # A zero exit alone is insufficient (e.g. an already-running session).
                # Retain state if verification fails so no possibly-active run is lost.
                Assert-TraceSession -EtlPath $etl -Root $root
                Write-Host $result
                Write-Output "Trace started: $etl. Reproduce in your normal window, then run -StopTrace here. Limit: 512 MB."
            }
            'Stop' {
                if (-not (Test-Path -LiteralPath $pointer -PathType Leaf)) {
                    throw "TRACE_NO_RUN: No trace recorded for this user. Use -StartTrace first. No trace was stopped. State: $pointer"
                }
                $etl = Get-LocalTracePath -Path ((Get-Content -LiteralPath $pointer -Raw).Trim())
                if (-not $etl.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
                    throw "TRACE_STATE_INVALID: Recorded ETL is outside the private root: $etl. No trace was stopped."
                }
                Assert-TraceSession -EtlPath $etl -Root $root
                Write-Host "Stopping recorded trace (can take a minute): $etl"
                $result = Invoke-TraceNative -FilePath "$env:WINDIR\System32\netsh.exe" `
                    -Arguments @('trace', 'stop') -WorkDirectory $root
                Assert-TraceSession -EtlPath $etl -Root $root -Stopped
                Remove-Item -LiteralPath $pointer -ErrorAction Stop
                Write-Host $result
                Write-Output "Trace stopped. ETL: $etl"
                Convert-TraceEtl -EtlPath $etl -OutputDirectory (Split-Path $etl -Parent)
            }
            'Convert' {
                $etl = Get-LocalTracePath -Path $Path
                if ([IO.Path]::GetExtension($etl) -ne '.etl') { throw 'TRACE_ETL_REQUIRED: Supply -Path to a saved .etl file.' }
                if (-not (Test-Path -LiteralPath $etl -PathType Leaf)) { throw "TRACE_ETL_MISSING: $etl" }
                if (Test-Path -LiteralPath $pointer) {
                    $active = (Get-Content -LiteralPath $pointer -Raw).Trim()
                    if ($etl -eq $active) { throw 'TRACE_STILL_ACTIVE: Use -StopTrace before converting the recorded capture.' }
                }
                $run = New-TraceRunDirectory -Root $root
                Convert-TraceEtl -EtlPath $etl -OutputDirectory $run
            }
        }
    } finally {
        if ($lock) { $lock.Dispose() }
    }
}

Invoke-LabTraceAction -Action $PSCmdlet.ParameterSetName -Path $Path
'@
}

function Install-LabTraceTools {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ToolsDirectory)
    $helper = Get-LabTraceHelperContent
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseInput($helper, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count) { throw "TRACE_HELPER_INVALID: $($parseErrors -join '; ')" }
    $converter = Join-Path $ToolsDirectory 'etl2pcapng.exe'
    if (-not (Test-Path -LiteralPath $converter -PathType Leaf) -or
        (Get-Item -LiteralPath $converter).Length -eq 0) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Save-LabToolDownload -Uri 'https://github.com/microsoft/etl2pcapng/releases/download/v1.11.0/etl2pcapng.exe' -Path $converter
    }
    if (-not (Test-Path -LiteralPath $converter -PathType Leaf) -or
        (Get-Item -LiteralPath $converter).Length -eq 0) {
        throw "TRACE_CONVERTER_MISSING: Download did not provision $converter"
    }
    $path = Join-Path $ToolsDirectory 'Get-KerberosEvidence.ps1'
    Set-Content -LiteralPath $path -Value $helper -Encoding UTF8 -ErrorAction Stop
    if ((Get-Content -LiteralPath $path -Raw).Trim() -cne $helper.Trim()) {
        throw "TRACE_HELPER_INVALID: Written helper did not match source: $path"
    }
    Write-Output "Cloud-only trace helper installed: $path (-StartTrace, -StopTrace, -ConvertTrace -Path <ETL>). Converter: $converter"
}

function Get-LabInspectorMsi {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root) {
            Get-ItemProperty -Path "$root\*" -ErrorAction Stop |
                Where-Object {
                    $_.DisplayName -eq 'Kerberos.NET Fiddler Extension Machine-Wide Installer' -and
                    $_.DisplayVersion -eq '4.5.0.0'
                }
        }
    }
}

function Install-LabCaptureTools {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ToolsDirectory)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $installRoot = Join-Path $env:ProgramFiles 'Fiddler'
    $exe = Join-Path $installRoot 'Fiddler.exe'
    $installer = Join-Path $ToolsDirectory 'FiddlerSetup.exe'
    $msi = Join-Path $ToolsDirectory 'Kerberos.NET-Setup.msi'
    $msiLog = Join-Path $ToolsDirectory 'kerberos-inspector-msi.log'
    $shortcut = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Fiddler Classic (Lab).lnk'

    # Never replace binaries while another lab user is capturing authentication.
    if (Get-Process -Name Fiddler -ErrorAction SilentlyContinue) {
        throw 'LAB_TOOLS_IN_USE: Close Fiddler normally before installing tools; no process was stopped.'
    }
    Write-Warning 'Install only on a disposable lab VM and ensure the applicable Fiddler license permits your use. User DLL trust approval remains manual.'
    if (-not (Test-Path -LiteralPath $exe)) {
        Save-LabToolDownload -Uri 'https://telerik-fiddler.s3.amazonaws.com/fiddler/FiddlerSetup.exe' -Path $installer
        # NSIS /D must be last and unquoted, including when the path has spaces.
        $process = Start-Process -FilePath $installer -ArgumentList "/S /D=$installRoot" -Wait -PassThru -ErrorAction Stop
        if ($process.ExitCode -ne 0) {
            throw "FIDDLER_INSTALL_FAILED: Exit code $($process.ExitCode). Installer: $installer"
        }
        if (-not (Test-Path -LiteralPath $exe)) {
            throw "FIDDLER_INSTALL_MISSING: Installer returned success but $exe does not exist."
        }
    }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    $link.TargetPath = $exe
    $link.WorkingDirectory = $installRoot
    $link.Save()
    Write-Output "Fiddler executable verified: $exe; public desktop shortcut: $shortcut"

    if (-not @(Get-LabInspectorMsi).Count) {
        Save-LabToolDownload -Uri 'https://github.com/dotnet/Kerberos.NET/releases/download/v4.5.45/Setup.msi' -Path $msi
        $process = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" `
            -ArgumentList "/i `"$msi`" /qn /norestart /L*v `"$msiLog`"" `
            -Wait -PassThru -ErrorAction Stop
        if ($process.ExitCode -notin @(0, 3010)) {
            throw "INSPECTOR_INSTALL_FAILED: Exit code $($process.ExitCode). See $msiLog"
        }
        if (-not @(Get-LabInspectorMsi).Count) {
            throw "INSPECTOR_INSTALL_MISSING: MSI returned success but machine-wide registration is missing. See $msiLog"
        }
    }
    Write-Output 'Inspector machine-wide installer verified. User DLL installation/loading is NOT YET VERIFIED.'
    Write-Output 'After restart, sign in as the lab user, open Fiddler Classic (Lab), and approve only the expected Kerberos.NET DLLs. Verify the Kerberos tab and a real HTTPS KDC Proxy capture.'
}

$tools = 'C:\LabTools'
New-Item -ItemType Directory -Path $tools -Force | Out-Null
# 1. Primary DNS suffix -> the device registers <vm>.<region>.cloudapp.azure.com
$tcpip = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
Set-ItemProperty -Path $tcpip -Name 'Domain'    -Value $DnsSuffix
Set-ItemProperty -Path $tcpip -Name 'NV Domain' -Value $DnsSuffix
Write-Output "primary DNS suffix = $DnsSuffix"

# 2. Cloud Kerberos ticket retrieval. Note WHERE this goes: the LSA path. Lab B
#    later writes the POLICY path, which silently wins over this one.
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
New-Item -Path $lsa -Force | Out-Null
Set-ItemProperty -Path $lsa -Name CloudKerberosTicketRetrievalEnabled -Value 1 -Type DWord
Write-Output 'CloudKerberosTicketRetrievalEnabled = 1 (LSA path)'

# 3. The lab's fault injector, local to the VM.
#    Labs B and C only ever touch the registry and the WinHTTP proxy, so there is
#    no reason to route them through Azure. Keeping them local means a
#    participant needs nothing but RDP - no Azure rights, no Cloud Shell - and it
#    removes the ~60s fixed overhead every Run Command call costs.
$fault = @'
<#
.SYNOPSIS
  Session 2 (cloud-only) fault injection - runs locally on the client VM.

.DESCRIPTION
  NoCloudTgt     Disables cloud TGT retrieval via the POLICY registry path, not
                 the LSA path. Windows reads
                 Policies\System\Kerberos\Parameters (what an Intune CSP writes)
                 FIRST and only falls back to Lsa\Kerberos\Parameters - so the
                 LSA value still reads 1 and looks perfectly healthy while the
                 effective value is 0.
                 REQUIRES SIGN OUT / SIGN IN: the policy is read at logon.
                 Diagnose: klist cloud_debug reports the EFFECTIVE value.

  ProxyMangled   Points WinHTTP at a dead proxy (127.0.0.1:8888) - the residue
                 Fiddler leaves when it exits uncleanly. Entra Kerberos rides
                 HTTPS through the KDC Proxy, so the machine proxy stack is part
                 of the authentication path.
                 Diagnose: netsh winhttp show proxy

.EXAMPLE
  C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt
  C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt -Repair
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('NoCloudTgt', 'ProxyMangled')]
    [string]$Fault,
    [switch]$Repair
)
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an ELEVATED PowerShell. Your lab account is a local admin, so UAC only asks for consent.'
}

$policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
$lsaPath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
$mode = if ($Repair) { 'REPAIR' } else { 'INJECT' }
Write-Host "[$mode] $Fault" -ForegroundColor Yellow

function Show([string[]]$lines) { $lines | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray } }

switch ($Fault) {
    'NoCloudTgt' {
        if (-not $Repair) {
            New-Item -Path $policyPath -Force | Out-Null
            Set-ItemProperty -Path $policyPath -Name CloudKerberosTicketRetrievalEnabled -Value 0 -Type DWord
            Set-ItemProperty -Path $lsaPath    -Name CloudKerberosTicketRetrievalEnabled -Value 1 -Type DWord
            Show @(
                'Policy path now DISABLES cloud TGT retrieval; the LSA path still says 1.'
                ''
                'SIGN OUT AND BACK IN, then walk the chain from step 2:'
                '  reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled'
                '      -> 0x1.  Healthy?'
                '  klist cloud_debug'
                '      -> enabled by policy: 0.  The EFFECTIVE value disagrees.'
                '  reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled'
                '      -> 0x0.  The policy path wins, silently.'
            )
        } else {
            Remove-ItemProperty -Path $policyPath -Name CloudKerberosTicketRetrievalEnabled -ErrorAction SilentlyContinue
            Show @('Policy-path value removed. SIGN OUT AND BACK IN, then re-check klist cloud_debug.')
        }
    }

    'ProxyMangled' {
        if (-not $Repair) {
            netsh winhttp set proxy 127.0.0.1:8888 | Out-Null
            Show @(
                'WinHTTP now points at 127.0.0.1:8888 - nothing is listening there.'
                ''
                'No sign-out needed. Reproduce:'
                '  klist purge'
                '  klist get cifs/<sa>.file.core.windows.net'
                '      -> LsaCallAuthenticationPackage (GetTicket substatus): 0x51f'
                ''
                'Diagnose in 30 seconds:  netsh winhttp show proxy'
            )
        } else {
            netsh winhttp reset proxy      | Out-Null
            netsh winhttp reset autoproxy  | Out-Null
            # Fiddler also leaves :8888 entries behind here; the TSG says clear them.
            $mgr = 'HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ProxyMgr'
            if (Test-Path $mgr) {
                Get-ChildItem $mgr -ErrorAction SilentlyContinue | ForEach-Object {
                    $v = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ConfigurationURL
                    if ($v -match '8888') { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
                }
            }
            klist purge | Out-Null
            Show @('Proxy reset and tickets purged. Retry the mount.')
        }
    }
}
'@
Set-Content -Path (Join-Path $tools 'Invoke-LabFault.ps1') -Value $fault -Encoding UTF8
Write-Output 'C:\LabTools\Invoke-LabFault.ps1 written'

# 4. Install into a shared executable path, not SYSTEM's user profile. The MSI
# stages per-user inspector setup for the next sign-in; the caller reboots.
Install-LabCaptureTools -ToolsDirectory $tools
Install-LabTraceTools -ToolsDirectory $tools
Install-LabPowerShellModules -ToolsDirectory $tools

# 5. Pre-trust a Fiddler root CA so nobody clicks through certificate prompts.
#    Fiddler installs its CA into the CURRENT USER's Root store, and Windows
#    always shows a consent dialog for that - by design, and not suppressible.
#    The LOCAL MACHINE Root store takes an elevated write with no dialog, so we
#    generate the CA in the user's My store and trust it at machine scope; Fiddler
#    then finds a chain that already validates and skips its own prompts.
#    Must run as the LAB USER (the private key lives in that user's store), and
#    this script is SYSTEM - hence the logon task.
$trust = @'
# SECURITY: this creates and machine-trusts a root CA able to intercept ANY TLS
# connection on this computer. Acceptable only on a throwaway lab VM. The key is
# generated locally, never leaves the machine, and differs on every VM.
$ErrorActionPreference = 'Stop'
$cn  = 'DO_NOT_TRUST_FiddlerRoot'
$log = 'C:\LabTools\fiddler-trust.log'
function Say([string]$m) {
    $l = "$(Get-Date -Format s)  $m"
    Write-Output $l
    try { Add-Content -Path $log -Value "$l  [$env:USERNAME]" } catch { }
}
$trusted = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
$mine    = Get-ChildItem Cert:\CurrentUser\My   | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
if ($trusted -and $mine) { Say 'already present and trusted'; return }
if (-not $mine) {
    # Fiddler's own default is SHA-1; current Windows rejects SHA-1 roots. Same
    # subject, stronger hash - Fiddler locates its root by CN and adopts it.
    $mine = New-SelfSignedCertificate `
        -Subject "CN=$cn, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com" `
        -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -KeyLength 2048 `
        -KeyUsage CertSign, CRLSign, DigitalSignature -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2) `
        -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=0',
                         '2.5.29.37={text}1.3.6.1.5.5.7.3.1')
    Say "generated root CA $($mine.Thumbprint)"
}
if (-not $trusted) {
    $pub   = [Security.Cryptography.X509Certificates.X509Certificate2]::new($mine.RawData)
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    $store.Open('ReadWrite'); $store.Add($pub); $store.Close()
    Say 'installed into LocalMachine\Root (no prompt - this is the whole trick)'
}
try {
    $fid = 'HKCU:\Software\Microsoft\Fiddler2'
    if (-not (Test-Path $fid)) { New-Item -Path $fid -Force | Out-Null }
    Set-ItemProperty -Path $fid -Name 'fiddler.network.https.CaptureHTTPS'           -Value 'True'
    Set-ItemProperty -Path $fid -Name 'fiddler.network.https.DecryptHTTPS'           -Value 'True'
    Set-ItemProperty -Path $fid -Name 'fiddler.network.https.IgnoreServerCertErrors' -Value 'False'
    Say 'HTTPS decryption preferences written'
} catch { Say "preference write failed: $($_.Exception.Message)" }
Say 'DONE'
'@
Set-Content -Path (Join-Path $tools 'Setup-FiddlerTrust.ps1') -Value $trust -Encoding UTF8
try {
    $act  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\LabTools\Setup-FiddlerTrust.ps1"'
    $trg  = New-ScheduledTaskTrigger -AtLogOn
    # Group principal so it fires for whichever lab user signs in. RunLevel
    # Highest is what allows the LocalMachine\Root write with no UAC prompt.
    $prin = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Highest
    Register-ScheduledTask -TaskName 'LabSetupFiddlerTrust' -Action $act -Trigger $trg `
        -Principal $prin -Description 'Pre-trusts a Fiddler root CA for the Azure Files lab' -Force | Out-Null
    Write-Output 'Fiddler trust task registered (runs at each logon; idempotent)'
} catch {
    Write-Output "Could not register the Fiddler trust task ($($_.Exception.Message.Split([char]10)[0]))"
}

Write-Output 'CLIENT_CONFIG_DONE'
