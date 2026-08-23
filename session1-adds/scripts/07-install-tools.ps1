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
  Usage (elevated, on the CLIENT VM):
      C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>
  Produces C:\LabTools\evidence\<timestamp>\ with:
      trace.etl / trace.pcapng   network capture of the whole attempt
      klist-before/after.txt     ticket cache either side of the mount
      mount-result.txt           the actual net use output/error
      kerberos-log.txt           Microsoft-Windows-Kerberos/Operational
      smbclient-log.txt          SMBClient/Operational
      smbclient-connectivity.txt SMBClient/Connectivity
      smb-connection.txt         negotiated dialect / encryption / signing
      smb-client-config.txt      client SMB settings (cipher order, etc.)

  The two event-log files are EMPTY when the mount succeeds - those channels
  record problems, not successes. Run this again while a fault is injected and
  they fill up. Must be run ELEVATED (netsh trace).
#>
param(
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Share = 'labshare',
    [string]$DriveLetter = 'Z'
)
# netsh trace needs elevation. Without this check the trace silently does
# nothing, the script still prints "pcapng ready", and you find out only when
# Wireshark opens an empty file - during the lab, with no time to redo it.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ''
    Write-Warning 'This must run ELEVATED - netsh trace cannot capture otherwise.'
    Write-Host 'Close this window, right-click PowerShell -> Run as administrator,' -ForegroundColor Yellow
    Write-Host 'and answer YES on the UAC prompt (do NOT enter labadmin credentials:' -ForegroundColor Yellow
    Write-Host ' that starts a different logon session with a different ticket cache).' -ForegroundColor Yellow
    exit 1
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = "C:\LabTools\evidence\$stamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null
$fqdn = "$StorageAccount.file.core.windows.net"

Write-Host "Collecting evidence -> $out" -ForegroundColor Cyan

net use "${DriveLetter}:" /delete /y 2>$null | Out-Null
klist purge | Out-Null
klist > "$out\klist-before.txt"

Write-Host 'Starting network trace...'
# Stop a trace left running by an earlier attempt, then start ours and CHECK it.
netsh trace stop 2>&1 | Out-Null
$startOut = netsh trace start capture=yes overwrite=yes maxsize=512 tracefile="$out\trace.etl" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "netsh trace failed to start - continuing without a capture:"
    Write-Host ($startOut -join "`n") -ForegroundColor DarkYellow
    $traceOk = $false
} else { $traceOk = $true }

Write-Host 'Attempting the mount...'
$mount = cmd /c "net use ${DriveLetter}: \\$fqdn\$Share 2>&1"
$mount | Out-File "$out\mount-result.txt" -Encoding utf8
Write-Host ($mount -join "`n")

Start-Sleep -Seconds 2
if ($traceOk) {
    Write-Host 'Stopping trace (takes ~30s)...'
    netsh trace stop | Out-Null
}

klist > "$out\klist-after.txt"

# Convert for Wireshark - and only claim success if there is really a file.
if ($traceOk -and (Test-Path "$out\trace.etl") -and (Test-Path 'C:\LabTools\etl2pcapng.exe')) {
    & 'C:\LabTools\etl2pcapng.exe' "$out\trace.etl" "$out\trace.pcapng" | Out-Null
    $pcap = Get-Item "$out\trace.pcapng" -ErrorAction SilentlyContinue
    if ($pcap -and $pcap.Length -gt 0) {
        Write-Host ("pcapng ready: {0} ({1:N0} KB)" -f $pcap.FullName, ($pcap.Length / 1KB)) -ForegroundColor Green
    } else {
        Write-Warning "Conversion produced an empty file - check that $out\trace.etl has data."
    }
} elseif ($traceOk) {
    Write-Warning "No trace.etl was written - the capture did not run."
}

# Event logs around the attempt.
# These channels record PROBLEMS, not successes - on a healthy mount they are
# legitimately empty. Say so in the file, so an empty result reads as a finding
# instead of a broken script.
$since = (Get-Date).AddMinutes(-5)
function Save-Log([string]$LogName, [string]$File, [string[]]$Props) {
    $ev = Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=$since} -ErrorAction SilentlyContinue
    $path = Join-Path $out $File
    if ($ev) {
        $ev | Format-List $Props | Out-File $path -Encoding utf8
        Write-Host ("  {0,-46} {1} event(s)" -f $LogName, @($ev).Count)
    } else {
        "No events in $LogName between $since and $(Get-Date)." | Out-File $path -Encoding utf8
        "" | Out-File $path -Encoding utf8 -Append
        "This is EXPECTED for a healthy mount: these channels log failures and" |
            Out-File $path -Encoding utf8 -Append
        "notable conditions, not successful operations. Compare against a run" |
            Out-File $path -Encoding utf8 -Append
        "captured while the mount is FAILING - that is where the entries appear." |
            Out-File $path -Encoding utf8 -Append
        Write-Host ("  {0,-46} (no events - normal when healthy)" -f $LogName)
    }
}
Write-Host 'Event logs:'
Save-Log 'Microsoft-Windows-Kerberos/Operational'   'kerberos-log.txt'   @('TimeCreated','Id','LevelDisplayName','Message')
Save-Log 'Microsoft-Windows-SMBClient/Operational'  'smbclient-log.txt'  @('TimeCreated','Id','Message')
Save-Log 'Microsoft-Windows-SMBClient/Connectivity' 'smbclient-connectivity.txt' @('TimeCreated','Id','Message')

# Always-useful state that does NOT depend on anything having gone wrong:
# negotiated dialect, encryption and signing for the live connection.
Get-SmbConnection | Format-List * | Out-File "$out\smb-connection.txt" -Encoding utf8
Get-SmbClientConfiguration | Format-List * | Out-File "$out\smb-client-config.txt" -Encoding utf8

Write-Host ''
Write-Host "Done. Open $out" -ForegroundColor Green
Write-Host 'Wireshark filter to start with:  kerberos || smb2'
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
