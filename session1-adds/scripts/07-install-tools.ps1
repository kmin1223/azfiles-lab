# Runs ON the lab VMs. Installs the PowerShell tooling attendees need for
# diagnostics: Az modules + the AzFilesHybrid module (Debug-AzStorageAccountAuth,
# Test-AzStorageAccountADObjectPasswordIsKerbKey, Update-AzStorageAccountADObjectPassword).
# Safe to re-run - skips whatever is already present.
param(
    # Prebuilt module bundle (see tools\New-LabToolsBundle.ps1). One HTTPS GET
    # beats ~9 minutes of Install-Module round trips. Pass '' to force the
    # gallery path.
    [string]$ModuleBundleUri = 'https://github.com/kmin1223/azfiles-lab/releases/latest/download/labtools-modules.zip'
)
$ErrorActionPreference = 'Continue'   # never fail the deployment over tooling
$ProgressPreference = 'SilentlyContinue'  # much faster downloads

# Role decides what gets installed. ProductType 2 = domain controller.
# The DC only needs Kerberos AUDITING (events 4768/4769) - it is not where the
# Azure-side tooling belongs. AzFilesHybrid and the Az modules go on the CLIENT,
# which is the domain-joined admin workstation the lab (and real guidance) uses
# for Join-/Debug-/Update-AzStorageAccount*. Installing them on a DC would also
# mean signing into Azure on a DC, which is exactly what we don't want to teach.
$isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
$role = if ($isDC) { 'DOMAIN CONTROLLER' } else { 'CLIENT' }

Write-Output "=== Installing lab tooling on $env:COMPUTERNAME ($role) ==="

# TLS 1.2 is required to reach the PowerShell Gallery on Windows Server
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Turn off IE Enhanced Security Configuration -------------------------
# Without this, the interactive sign-in that Connect-AzAccount opens is blocked
# on Windows Server, so Debug-AzStorageAccountAuth can't be used on the VM.
# {..A7..} = Administrators, {..A8..} = Users.
try {
    $escKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}',
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    )
    foreach ($k in $escKeys) {
        if (Test-Path $k) { Set-ItemProperty -Path $k -Name IsInstalled -Value 0 -Force }
    }
    # Applies at next sign-in; restart Explorer so a current session picks it up too.
    Stop-Process -Name Explorer -Force -ErrorAction SilentlyContinue
    Write-Output 'IE Enhanced Security Configuration disabled'
} catch {
    Write-Output "IE ESC change skipped: $($_.Exception.Message)"
}

if (-not $isDC) {

# --- ActiveDirectory PowerShell module (RSAT) ------------------------------
# The AzFilesHybrid cmdlets read and write AD objects, so the client needs the
# AD module. A DC has it already; a member server does not.
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    try {
        Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop | Out-Null
        Write-Output 'RSAT-AD-PowerShell installed'
    } catch {
        Write-Output "RSAT-AD-PowerShell install failed: $($_.Exception.Message)"
    }
} else {
    Write-Output 'ActiveDirectory module already present'
}

# --- FAST PATH: prebuilt module bundle -------------------------------------
# One HTTPS GET + a local extract, instead of ~9 minutes of Install-Module.
# The archive holds module folders at its root, laid out exactly as the module
# path expects, so extraction IS the install. Built by tools\New-LabToolsBundle.ps1.
# If anything about this fails we simply fall through to the gallery below.
$modulePath = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
if ($ModuleBundleUri) {
    try {
        $zip = Join-Path $env:TEMP 'labtools-modules.zip'
        Write-Output 'Downloading prebuilt module bundle...'
        $t0 = Get-Date
        Invoke-WebRequest -Uri $ModuleBundleUri -OutFile $zip -UseBasicParsing -ErrorAction Stop
        $mb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
        Write-Output ("  downloaded ${mb} MB in {0:n0}s" -f ((Get-Date) - $t0).TotalSeconds)

        # Expand-Archive is slow in PS 5.1 and refuses to overwrite; go through
        # the .NET API and overwrite entry by entry so re-runs are safe.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
        try {
            foreach ($entry in $archive.Entries) {
                $target = Join-Path $modulePath $entry.FullName
                if (-not $entry.Name) {
                    New-Item -ItemType Directory -Path $target -Force | Out-Null
                    continue
                }
                New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
            }
        } finally {
            $archive.Dispose()
            Remove-Item $zip -Force -ErrorAction SilentlyContinue
        }
        Write-Output ("Module bundle extracted in {0:n0}s total" -f ((Get-Date) - $t0).TotalSeconds)
    } catch {
        Write-Output "Module bundle unavailable ($($_.Exception.Message)); falling back to PowerShell Gallery"
    }
}

# --- NuGet provider + trust the gallery ------------------------------------
# Only needed for the fallback path, and Install-PackageProvider itself takes
# the better part of a minute - so skip it when the bundle already delivered.
$bundleWorked = (Get-Module -ListAvailable -Name AzFilesHybrid, Az.Accounts, Az.Storage |
    Select-Object -ExpandProperty Name -Unique).Count -ge 3
if (-not $bundleWorked) {
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        Write-Output 'PSGallery ready'
    } catch {
        Write-Output "PSGallery prep warning: $($_.Exception.Message)"
    }
}

# --- Az modules ---
# This list must cover everything in AzFilesHybrid's RequiredModules, or the
# module fails to load with "The required module 'Az.X' is not loaded" and its
# cmdlets look missing. Verify against the shipped manifest after any upgrade:
#   (Import-PowerShellDataFile "$env:ProgramFiles\WindowsPowerShell\Modules\AzFilesHybrid\<ver>\AzFilesHybrid.psd1").RequiredModules
#
# HARD TIME BUDGET on the gallery fallback. PowerShellGet v2 on a B-series VM
# has been observed taking 20-30+ minutes for this set, and a Run Command can't
# be cancelled from outside - a slow install literally holds the VM hostage.
# Better to stop, report TOOLS_PARTIAL honestly, and let the operator rerun
# once the bundle is published.
$galleryBudget = [System.Diagnostics.Stopwatch]::StartNew()
$galleryBudgetMin = 8
$azModules = 'Az.Accounts', 'Az.Storage', 'Az.Resources', 'Az.Network', 'Az.Compute'
foreach ($m in $azModules) {
    if (Get-Module -ListAvailable -Name $m) {
        Write-Output "$m already present"
        continue
    }
    if ($galleryBudget.Elapsed.TotalMinutes -gt $galleryBudgetMin) {
        Write-Output "$m SKIPPED: gallery time budget (${galleryBudgetMin} min) exhausted - publish the module bundle and rerun"
        continue
    }
    try {
        Install-Module -Name $m -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        Write-Output "$m installed"
    } catch {
        Write-Output "$m FAILED: $($_.Exception.Message)"
    }
}

# --- AzFilesHybrid ---
# The gallery package must be "installed" via its own CopyToPSPath.ps1, so we
# save it and run that, which places the module where PowerShell 5.1 finds it.
$azfhInstalled = Get-Module -ListAvailable -Name AzFilesHybrid
if ($azfhInstalled) {
    Write-Output 'AzFilesHybrid already present'
} else {
    try {
        $dest = 'C:\LabTools'
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Save-Module -Name AzFilesHybrid -Path $dest -Force -ErrorAction Stop

        $copyScript = Get-ChildItem -Path $dest -Filter 'CopyToPSPath.ps1' -Recurse |
            Select-Object -First 1
        if ($copyScript) {
            Push-Location $copyScript.DirectoryName
            & $copyScript.FullName -Confirm:$false
            Pop-Location
            Write-Output "AzFilesHybrid installed (source kept in $dest)"
        } else {
            # Fallback: copy the module folder straight into the module path
            $src = Get-ChildItem -Path $dest -Directory -Filter 'AzFilesHybrid' |
                Select-Object -First 1
            if ($src) {
                Copy-Item $src.FullName 'C:\Program Files\WindowsPowerShell\Modules\' -Recurse -Force
                Write-Output 'AzFilesHybrid copied to module path'
            }
        }
    } catch {
        Write-Output "AzFilesHybrid FAILED: $($_.Exception.Message)"
    }
}

# --- Satisfy AzFilesHybrid's declared dependencies -------------------------
# Don't guess this list. 0.3.3.0 needs Microsoft.Graph.Applications on top of
# the Az modules above, and it changes between releases. Read the shipped
# manifest and install whatever is still missing, so a version bump can't
# silently break the module with "command was found ... but could not be loaded".
$psd1 = Get-ChildItem 'C:\Program Files\WindowsPowerShell\Modules\AzFilesHybrid' `
    -Filter 'AzFilesHybrid.psd1' -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($psd1) {
    try {
        $required = (Import-PowerShellDataFile $psd1.FullName).RequiredModules
        foreach ($r in $required) {
            $name = if ($r -is [hashtable]) { $r.ModuleName } else { [string]$r }
            if (-not $name) { continue }
            if (Get-Module -ListAvailable -Name $name) { continue }
            if ($galleryBudget.Elapsed.TotalMinutes -gt $galleryBudgetMin) {
                Write-Output "dependency $name SKIPPED: gallery time budget exhausted"
                continue
            }
            try {
                Install-Module -Name $name -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
                Write-Output "dependency $name installed"
            } catch {
                Write-Output "dependency $name FAILED: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Output "could not read AzFilesHybrid manifest: $($_.Exception.Message)"
    }
}

} else {
    Write-Output 'DC: skipping Az/AzFilesHybrid on purpose - those belong on the client'
}

# --- Evidence tooling: etl2pcapng (converts netsh traces to pcapng) ---
# Kept on both: a DC-side capture of the KDC exchange is a legitimate technique.
$toolDir = 'C:\LabTools'
New-Item -ItemType Directory -Path $toolDir -Force | Out-Null
if (-not (Test-Path "$toolDir\etl2pcapng.exe")) {
    try {
        $url = 'https://github.com/microsoft/etl2pcapng/releases/latest/download/etl2pcapng.exe'
        Invoke-WebRequest -Uri $url -OutFile "$toolDir\etl2pcapng.exe" -UseBasicParsing -ErrorAction Stop
        Write-Output 'etl2pcapng downloaded'
    } catch {
        Write-Output "etl2pcapng download skipped: $($_.Exception.Message)"
    }
}

# --- Turn on the logs a specialist actually reads ---
# Kerberos client operational log is off by default.
try {
    wevtutil sl Microsoft-Windows-Kerberos/Operational /e:true 2>$null
    wevtutil sl Microsoft-Windows-SMBClient/Operational /e:true 2>$null
    Write-Output 'Kerberos + SMBClient operational logs enabled'
} catch { Write-Output 'log enable warning' }

# On a DC: audit Kerberos service-ticket operations (event 4769) incl. failures.
# This is the one thing the DC genuinely has to have for the labs.
if ($isDC) {
    try {
        auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
        Write-Output 'DC: Kerberos auditing enabled (events 4768/4769)'
    } catch { Write-Output 'auditpol warning' }
}

# --- Drop the evidence-collection helper on the box ---
$helper = @'
<#
  Get-KerberosEvidence.ps1 - capture the raw evidence for one mount attempt.

  TWO WAYS TO RUN IT
  ------------------
  1) Split (what you do on a real case). The trace needs admin rights, but the
     MOUNT must happen in the affected user's own, non-elevated session - that
     is the session whose ticket cache and drive mappings you are diagnosing.

        ELEVATED window :  Get-KerberosEvidence.ps1 -StartTrace
        NORMAL window   :  Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <sa>
        ELEVATED window :  Get-KerberosEvidence.ps1 -StopTrace

  2) All-in-one (quick, everything in the elevated window):

        Get-KerberosEvidence.ps1 -StorageAccount <sa>

  3) Re-read a capture you already have (no admin, any machine):

        Get-KerberosEvidence.ps1 -Analyze                 newest run
        Get-KerberosEvidence.ps1 -Analyze -Path <folder>  a specific one

     The identity is still the same domain user, so the Kerberos evidence is
     faithful - but the mount lands in the elevated logon session, which has its
     own ticket cache and drive letters.

  OUTPUT  ->  C:\LabTools\evidence\<timestamp>\
      trace.etl / trace.pcapng    network capture of the whole attempt
      trace-summary.txt           the capture as readable text (needs tshark)
      klist-before/after.txt      ticket cache either side of the mount
      mount-result.txt            the actual net use output/error
      kerberos-log.txt            Microsoft-Windows-Kerberos/Operational
      smbclient-log.txt           SMBClient/Operational
      smbclient-connectivity.txt  SMBClient/Connectivity
      smbclient-security.txt      SMBClient/Security
      smb-connection.txt          negotiated dialect / encryption / signing
      smb-client-config.txt       client SMB settings (cipher order, etc.)

  Do not expect the event logs to explain everything. They record what the
  CLIENT noticed, and a service-side rejection (error 1396) is invisible to it:
  the client's Kerberos stack did nothing wrong. When they are quiet, read
  klist, the DC's 4769 and the trace instead. Each file says so at the top.
#>
[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'All', Mandatory)]
    [Parameter(ParameterSetName = 'Reproduce', Mandatory)]
    [string]$StorageAccount,

    [Parameter(ParameterSetName = 'Start', Mandatory)][switch]$StartTrace,
    [Parameter(ParameterSetName = 'Reproduce', Mandatory)][switch]$Reproduce,
    [Parameter(ParameterSetName = 'Stop', Mandatory)][switch]$StopTrace,
    [Parameter(ParameterSetName = 'Analyze', Mandatory)][switch]$Analyze,
    [Parameter(ParameterSetName = 'Analyze')][string]$Path,

    [string]$Share = 'labshare',
    [string]$DriveLetter = 'Z'
)

$root    = 'C:\LabTools\evidence'
$pointer = Join-Path $root '.current-run.txt'

# Every command this collector runs is echoed BEFORE it runs, so you can see
# exactly what produced each file - and reuse the commands by hand on a case.
function Show-Cmd([string]$Command) {
    Write-Host ''
    Write-Host '  .-- running' -ForegroundColor DarkCyan
    $Command.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  | $_" -ForegroundColor Gray }
    Write-Host "  '--" -ForegroundColor DarkCyan
}

function Test-Admin {
    ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin([string]$Why) {
    if (Test-Admin) { return }
    Write-Host ''
    Write-Warning "$Why needs an ELEVATED window."
    Write-Host 'Right-click PowerShell -> Run as administrator, then answer YES on' -ForegroundColor Yellow
    Write-Host 'the UAC prompt. Do NOT type labadmin credentials: that starts a'    -ForegroundColor Yellow
    Write-Host 'different logon session with a different ticket cache.'             -ForegroundColor Yellow
    exit 1
}

function Get-CurrentRun {
    if (-not (Test-Path $pointer)) {
        Write-Warning 'No capture in progress. Start one first:  Get-KerberosEvidence.ps1 -StartTrace'
        exit 1
    }
    $p = (Get-Content $pointer -Raw).Trim()
    if (-not (Test-Path $p)) {
        Write-Warning "Recorded folder is gone: $p"
        exit 1
    }
    $p
}

function Start-Capture([string]$Out) {
    # Clear a trace left running by an earlier attempt, then start and VERIFY.
    Show-Cmd @"
netsh trace stop                                    # clear anything left running
netsh trace start capture=yes overwrite=yes maxsize=512 ``
      tracefile="$Out\trace.etl"
"@
    netsh trace stop 2>&1 | Out-Null
    $started = netsh trace start capture=yes overwrite=yes maxsize=512 tracefile="$Out\trace.etl" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'netsh trace failed to start:'
        Write-Host ($started -join "`n") -ForegroundColor DarkYellow
        return $false
    }
    $true
}

function Stop-Capture([string]$Out) {
    Write-Host 'Stopping trace (takes ~30s)...'
    Show-Cmd @"
netsh trace stop
etl2pcapng.exe "$Out\trace.etl" "$Out\trace.pcapng"   # for Wireshark
"@
    netsh trace stop | Out-Null
    if ((Test-Path "$Out\trace.etl") -and (Test-Path 'C:\LabTools\etl2pcapng.exe')) {
        & 'C:\LabTools\etl2pcapng.exe' "$Out\trace.etl" "$Out\trace.pcapng" | Out-Null
        $pcap = Get-Item "$Out\trace.pcapng" -ErrorAction SilentlyContinue
        if ($pcap -and $pcap.Length -gt 0) {
            Write-Host ("pcapng ready: {0} ({1:N0} KB)" -f $pcap.FullName, ($pcap.Length / 1KB)) -ForegroundColor Green
        } else {
            Write-Warning "Conversion produced an empty file - check $Out\trace.etl."
        }
    } else {
        Write-Warning "No trace.etl in $Out - the capture did not run."
    }
}

# Events that are routine against Azure Files and say nothing about a failure.
# Without this note a screenful of them looks like a lead.
$benign = @{
    30904 = 'SMB Multichannel not offered by the server - normal for Azure Files'
    30800 = 'share reconnected - routine'
}

function Save-Log([string]$Out, [string]$LogName, [string]$File, [string[]]$Props) {
    $since = (Get-Date).AddMinutes(-15)
    $ev = Get-WinEvent -FilterHashtable @{LogName = $LogName; StartTime = $since} -ErrorAction SilentlyContinue
    $path = Join-Path $Out $File
    if ($ev) {
        $ids = $ev | Group-Object Id | Sort-Object Count -Descending
        $summary = ($ids | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
        $interesting = @($ev | Where-Object { -not $benign.ContainsKey([int]$_.Id) })

        $head = @("$LogName - $(@($ev).Count) event(s) since $since", "Event IDs: $summary", '')
        foreach ($g in $ids) {
            if ($benign.ContainsKey([int]$g.Name)) {
                $head += "  $($g.Name) x$($g.Count)   BENIGN - $($benign[[int]$g.Name])"
            }
        }
        if (-not $interesting.Count) {
            $head += @('', 'NOTHING HERE IS ABOUT YOUR FAILURE - every event above is routine noise.')
        }
        $head += @('', ('-' * 70), '')
        $head | Out-File $path -Encoding utf8
        $ev | Format-List $Props | Out-File $path -Encoding utf8 -Append

        $note = if ($interesting.Count) { "$($interesting.Count) worth reading" } else { 'all routine noise' }
        Write-Host ("  {0,-44} {1,3} event(s)  {2,-16} {3}" -f $LogName, @($ev).Count, $summary, $note)
    } else {
        @(
            "No events in $LogName in the last 15 minutes."
            ''
            'Empty does NOT mean the mount was healthy. These channels record what the'
            'CLIENT stack noticed, and some failures are invisible to it. Error 1396 is'
            'the clearest example: the DC issued a perfectly good ticket and the client'
            'sent a perfectly good AP-REQ, so the client Kerberos stack saw no error at'
            'all. The rejection came back inside the SMB Session Setup, from the service.'
            ''
            'When these logs are quiet, the evidence is elsewhere:'
            '  klist          was a ticket issued, and with which etype?'
            '  DC event 4769  did the KDC succeed?'
            '  trace.pcapng   the Session Setup failure and the real KRB error'
        ) | Out-File $path -Encoding utf8
        Write-Host ("  {0,-44} (no events)" -f $LogName)
    }
}

# Turn the capture into something readable without opening Wireshark. We ask
# tshark for PROTOCOL FIELDS rather than its Info column: the column text drifts
# between versions, the field names do not.
$krbMsg = @{ 10 = 'AS-REQ'; 11 = 'AS-REP'; 12 = 'TGS-REQ'; 13 = 'TGS-REP'
             14 = 'AP-REQ'; 15 = 'AP-REP'; 30 = 'KRB-ERROR' }
$krbErr = @{ 6 = 'C_PRINCIPAL_UNKNOWN'; 7 = 'S_PRINCIPAL_UNKNOWN'; 14 = 'ETYPE_NOSUPP'
             25 = 'PREAUTH_REQUIRED'; 37 = 'AP_ERR_SKEW'; 41 = 'AP_ERR_MODIFIED' }
$smbCmd = @{ 0 = 'Negotiate'; 1 = 'Session Setup'; 2 = 'Logoff'; 3 = 'Tree Connect'
             4 = 'Tree Disconnect'; 5 = 'Create'; 8 = 'Read'; 9 = 'Write'; 14 = 'Query Directory' }

function Get-Tshark {
    $c = Get-Command tshark -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @("$env:ProgramFiles\Wireshark\tshark.exe",
                     "${env:ProgramFiles(x86)}\Wireshark\tshark.exe")) {
        if (Test-Path $p) { return $p }
    }
    $null
}

function Show-TraceSummary([string]$Out) {
    $pcap = Join-Path $Out 'trace.pcapng'
    $path = Join-Path $Out 'trace-summary.txt'
    if (-not (Test-Path $pcap)) { return }

    $tshark = Get-Tshark
    if (-not $tshark) {
        @(
            'tshark was not found, so the capture was not summarised here.'
            ''
            'trace.pcapng is complete - open it on any machine that has Wireshark,'
            'or install Wireshark (tshark ships with it) and run:'
            '    C:\LabTools\Get-KerberosEvidence.ps1 -Analyze'
            ''
            'Wireshark display filter to start with:   kerberos || smb2'
        ) | Out-File $path -Encoding utf8
        Write-Host '  trace summary : skipped (tshark not installed - see trace-summary.txt)' -ForegroundColor DarkYellow
        return
    }

    Show-Cmd @"
tshark -r trace.pcapng -Y "kerberos || smb2" -T fields ``
    -e frame.number -e frame.time_relative -e ip.dst ``
    -e kerberos.msg_type -e kerberos.error_code ``
    -e smb2.cmd -e smb2.flags.response -e smb2.nt_status
"@
    $raw = & $tshark -r $pcap -Y 'kerberos || smb2' -T fields `
        -e frame.number -e frame.time_relative -e ip.dst `
        -e kerberos.msg_type -e kerberos.error_code `
        -e smb2.cmd -e smb2.flags.response -e smb2.nt_status `
        -E 'separator=|' 2>$null

    $lines = @(); $sawTgsRep = $false; $ssFailure = $null; $krbError = $null
    foreach ($r in $raw) {
        $f = $r -split '\|'
        if ($f.Count -lt 8) { continue }
        $num, $t, $dst, $kmsg, $kerr, $scmd, $sresp, $sstat = $f[0..7]
        # a frame can carry several messages; take the first of each field
        $kmsg = ($kmsg -split ',')[0]; $kerr = ($kerr -split ',')[0]
        $scmd = ($scmd -split ',')[0]; $sresp = ($sresp -split ',')[0]; $sstat = ($sstat -split ',')[0]

        if ($kmsg) {
            $name = if ($krbMsg.ContainsKey([int]$kmsg)) { $krbMsg[[int]$kmsg] } else { "krb($kmsg)" }
            $detail = ''
            if ($kerr) {
                $en = if ($krbErr.ContainsKey([int]$kerr)) { $krbErr[[int]$kerr] } else { "code $kerr" }
                $detail = "  <-- $en"; $krbError = $en
            }
            if ($name -eq 'TGS-REP') { $sawTgsRep = $true }
            $lines += ('{0,6}  {1,8:N3}s  {2,-15} KRB   {3}{4}' -f $num, [double]$t, $dst, $name, $detail)
        } elseif ($scmd) {
            $name = if ($smbCmd.ContainsKey([int]$scmd)) { $smbCmd[[int]$scmd] } else { "cmd $scmd" }
            $dir = if ($sresp -eq '1') { 'resp' } else { 'req ' }
            $st = ''
            if ($sresp -eq '1' -and $sstat -and $sstat -ne '0' -and $sstat -ne '0x00000000') {
                $st = "  <-- STATUS $sstat"
                if (-not $ssFailure) { $ssFailure = "$name $sstat" }
            }
            $lines += ('{0,6}  {1,8:N3}s  {2,-15} SMB2  {3} {4}{5}' -f $num, [double]$t, $dst, $name, $dir, $st)
        }
    }

    $verdict = @()
    if ($sawTgsRep -and $ssFailure) {
        $verdict += 'READING: a TGS-REP came back (the KDC issued a ticket) and then SMB2'
        $verdict += "         failed at: $ssFailure"
        $verdict += '         => the KDC did its job; the SERVICE refused the ticket.'
        $verdict += '         That is the error-1396 shape. Look at the salt inputs next.'
    } elseif ($krbError) {
        $verdict += "READING: the KDC itself returned an error ($krbError)."
        $verdict += '         No ticket was ever issued - stop looking at the service.'
    } elseif ($sawTgsRep) {
        $verdict += 'READING: ticket issued and no SMB2 failure in this capture.'
    } else {
        $verdict += 'READING: no TGS-REP in this capture. Either the client never asked'
        $verdict += '         (cached session / wrong SPN / no path to the DC), or the'
        $verdict += '         exchange happened outside the capture window.'
    }

    $out = @("Trace summary - $pcap", ('=' * 78), '',
             ('{0,6}  {1,9}  {2,-15} {3}' -f 'frame', 'time', 'dest', 'message'),
             ('-' * 78)) + $lines + @('', ('=' * 78)) + $verdict
    $out | Out-File $path -Encoding utf8
    Write-Host ''
    $out | ForEach-Object {
        $c = if ($_ -match 'STATUS|<--|READING|=>') { 'Yellow' } else { 'Gray' }
        Write-Host $_ -ForegroundColor $c
    }
}

function Save-EventLogs([string]$Out) {
    Write-Host 'Event logs:'
    Show-Cmd @"
Get-WinEvent -FilterHashtable @{LogName='<channel>'; StartTime=(Get-Date).AddMinutes(-15)}
  Microsoft-Windows-Kerberos/Operational
  Microsoft-Windows-SMBClient/Operational
  Microsoft-Windows-SMBClient/Connectivity
"@
    Save-Log $Out 'Microsoft-Windows-Kerberos/Operational'   'kerberos-log.txt'   @('TimeCreated','Id','LevelDisplayName','Message')
    Save-Log $Out 'Microsoft-Windows-SMBClient/Operational'  'smbclient-log.txt'  @('TimeCreated','Id','Message')
    Save-Log $Out 'Microsoft-Windows-SMBClient/Connectivity' 'smbclient-connectivity.txt' @('TimeCreated','Id','Message')
    Save-Log $Out 'Microsoft-Windows-SMBClient/Security'     'smbclient-security.txt'     @('TimeCreated','Id','Message')
}

# The mount itself, plus the state that only exists in THIS logon session.
function Invoke-MountAttempt([string]$Out) {
    $fqdn = "$StorageAccount.file.core.windows.net"
    # A dead mapping can hold the drive letter while 'net use' lists nothing,
    # which surfaces as "System error 85 - the local device name is already in
    # use". Clear both the letter and the UNC path before trying.
    Show-Cmd @"
net use ${DriveLetter}: /delete /y                  # clear the drive letter
net use \\$fqdn\$Share /delete /y                   # and the UNC connection
Remove-SmbMapping -LocalPath ${DriveLetter}: -Force  # dead mapping -> System error 85
klist purge                                         # tickets only; NOT the SMB session
klist > klist-before.txt
net use ${DriveLetter}: \\$fqdn\$Share /persistent:no
klist > klist-after.txt
"@
    net use "${DriveLetter}:" /delete /y 2>$null | Out-Null
    net use "\\$fqdn\$Share" /delete /y 2>$null | Out-Null
    Remove-SmbMapping -LocalPath "${DriveLetter}:" -Force -ErrorAction SilentlyContinue
    klist purge | Out-Null
    klist > "$Out\klist-before.txt"

    Write-Host 'Attempting the mount...'
    # /persistent:no - a remembered mapping outlives the lab and keeps the
    # drive letter reserved, which later shows up as "System error 85".
    $mount = cmd /c "net use ${DriveLetter}: \\$fqdn\$Share /persistent:no 2>&1"
    $mount | Out-File "$Out\mount-result.txt" -Encoding utf8
    Write-Host ($mount -join "`n")

    Start-Sleep -Seconds 2
    klist > "$Out\klist-after.txt"
    Save-SmbState $Out
}

# Get-SmbConnection needs an ELEVATED token - a standard user (even one who is a
# local admin) gets "Access is denied". Rather than fail the whole reproduce
# step, note it and let -StopTrace pick it up from the elevated window.
function Save-SmbState([string]$Out) {
    Show-Cmd @"
Get-SmbConnection          # needs an ELEVATED window
Get-SmbClientConfiguration # negotiated dialect / encryption / signing
"@
    try {
        Get-SmbConnection -ErrorAction Stop | Format-List * |
            Out-File "$Out\smb-connection.txt" -Encoding utf8
    } catch {
        @(
            'Get-SmbConnection was not available in this session:'
            "  $($_.Exception.Message)"
            ''
            'This cmdlet requires an ELEVATED window. -StopTrace collects it.'
        ) | Out-File "$Out\smb-connection.txt" -Encoding utf8
    }
    try {
        Get-SmbClientConfiguration -ErrorAction Stop | Format-List * |
            Out-File "$Out\smb-client-config.txt" -Encoding utf8
    } catch {
        "Get-SmbClientConfiguration failed: $($_.Exception.Message)" |
            Out-File "$Out\smb-client-config.txt" -Encoding utf8
    }
}

switch ($PSCmdlet.ParameterSetName) {

    'Start' {
        Assert-Admin 'Starting a network trace'
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $out = Join-Path $root $stamp
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        # Let the non-elevated session write its half of the evidence here.
        icacls $out /grant "*S-1-5-32-545:(OI)(CI)M" 2>&1 | Out-Null
        Set-Content -Path $pointer -Value $out -Encoding ascii

        if (-not (Start-Capture $out)) { exit 1 }
        Write-Host ''
        Write-Host "Trace running. Evidence folder: $out" -ForegroundColor Cyan
        Write-Host ''
        Write-Host 'NOW, in your NORMAL (non-elevated) PowerShell window:' -ForegroundColor Yellow
        Write-Host "    C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount $StorageAccount" -ForegroundColor White
        Write-Host ''
        Write-Host 'Then come back here and run:' -ForegroundColor Yellow
        Write-Host '    C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace' -ForegroundColor White
    }

    'Reproduce' {
        if (Test-Admin) {
            Write-Warning 'You are in an ELEVATED window - that is the wrong one for this step.'
            Write-Host 'The point of -Reproduce is to mount in the affected user''s own session,' -ForegroundColor Yellow
            Write-Host 'which has its own ticket cache and drive letters. Use a normal window.'   -ForegroundColor Yellow
            Write-Host ''
        }
        $out = Get-CurrentRun
        Write-Host "Reproducing as $env:USERDOMAIN\$env:USERNAME -> $out" -ForegroundColor Cyan
        Invoke-MountAttempt $out
        Write-Host ''
        Write-Host 'Done. Back in the ELEVATED window run:' -ForegroundColor Yellow
        Write-Host '    C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace' -ForegroundColor White
    }

    'Analyze' {
        # Re-read an existing capture. No admin needed, and it can run on any
        # machine you copied the folder to.
        $out = if ($Path) { $Path } else {
            $d = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
                 Sort-Object Name -Descending | Select-Object -First 1
            if (-not $d) { Write-Warning "No evidence folders under $root."; exit 1 }
            $d.FullName
        }
        Write-Host "Analysing $out" -ForegroundColor Cyan
        Show-TraceSummary $out
    }

    'Stop' {
        Assert-Admin 'Stopping the network trace'
        $out = Get-CurrentRun
        Stop-Capture $out
        Show-TraceSummary $out
        Save-EventLogs $out
        # Elevated here, so this succeeds even if -Reproduce could not run it.
        Save-SmbState $out
        Remove-Item $pointer -ErrorAction SilentlyContinue
        Write-Host ''
        Write-Host "Done. Open $out" -ForegroundColor Green
        Write-Host 'Wireshark filter to start with:  kerberos || smb2'
    }

    'All' {
        Assert-Admin 'Capturing a network trace'
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $out = Join-Path $root $stamp
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        Write-Host "Collecting evidence -> $out" -ForegroundColor Cyan
        Write-Host 'Note: the mount happens in THIS elevated session. To capture the' -ForegroundColor DarkGray
        Write-Host 'user session instead, use -StartTrace / -Reproduce / -StopTrace.'  -ForegroundColor DarkGray

        $ok = Start-Capture $out
        Invoke-MountAttempt $out
        if ($ok) { Stop-Capture $out; Show-TraceSummary $out }
        Save-EventLogs $out
        Write-Host ''
        Write-Host "Done. Open $out" -ForegroundColor Green
        Write-Host 'Wireshark filter to start with:  kerberos || smb2'
    }
}
'@
Set-Content -Path "$toolDir\Get-KerberosEvidence.ps1" -Value $helper -Encoding UTF8
Write-Output 'Get-KerberosEvidence.ps1 placed in C:\LabTools'

# --- Report what's available ---
# Emit the success marker FIRST: Run Command truncates long output, and a
# trailing marker can get cut off, making a successful install look failed.
if ($isDC) {
    # Nothing to install here by design - auditing above is the DC's whole job.
    Write-Output 'TOOLS_READY (DC: Kerberos auditing + logs only, no Azure tooling by design)'
    return
}

$have = Get-Module -ListAvailable -Name Az.Accounts, Az.Storage, Az.Compute, AzFilesHybrid |
    Select-Object -ExpandProperty Name -Unique

# Presence on disk is not enough: AzFilesHybrid can be installed yet unloadable
# because a RequiredModules entry is missing. Prove it actually imports.
$azfhLoads = $false
$azfhError = ''
try {
    Import-Module AzFilesHybrid -Force -ErrorAction Stop
    $azfhLoads = $null -ne (Get-Command Debug-AzStorageAccountAuth -ErrorAction SilentlyContinue)
} catch {
    $azfhError = $_.Exception.Message
}

if ($azfhLoads -and $have -contains 'Az.Accounts') {
    Write-Output 'TOOLS_READY'
} else {
    Write-Output "TOOLS_PARTIAL (present: $($have -join ', ')) AzFilesHybrid import: $azfhError"
}
Write-Output "modules: $($have -join ', ')"
