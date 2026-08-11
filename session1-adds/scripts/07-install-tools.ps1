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
      smbclient-log.txt          SMBClient Operational + Connectivity
#>
param(
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Share = 'labshare',
    [string]$DriveLetter = 'Z'
)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = "C:\LabTools\evidence\$stamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null
$fqdn = "$StorageAccount.file.core.windows.net"

Write-Host "Collecting evidence -> $out" -ForegroundColor Cyan

net use "${DriveLetter}:" /delete /y 2>$null | Out-Null
klist purge | Out-Null
klist > "$out\klist-before.txt"

Write-Host 'Starting network trace...'
netsh trace start capture=yes overwrite=yes maxsize=512 tracefile="$out\trace.etl" | Out-Null

Write-Host 'Attempting the mount...'
$mount = cmd /c "net use ${DriveLetter}: \\$fqdn\$Share 2>&1"
$mount | Out-File "$out\mount-result.txt" -Encoding utf8
Write-Host ($mount -join "`n")

Start-Sleep -Seconds 2
Write-Host 'Stopping trace (takes ~30s)...'
netsh trace stop | Out-Null

klist > "$out\klist-after.txt"

# Convert for Wireshark if the tool is present
if (Test-Path 'C:\LabTools\etl2pcapng.exe') {
    & 'C:\LabTools\etl2pcapng.exe' "$out\trace.etl" "$out\trace.pcapng" | Out-Null
    Write-Host "pcapng ready: $out\trace.pcapng"
}

# Event logs around the attempt
$since = (Get-Date).AddMinutes(-5)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kerberos/Operational'; StartTime=$since} -ErrorAction SilentlyContinue |
    Format-List TimeCreated, Id, LevelDisplayName, Message | Out-File "$out\kerberos-log.txt" -Encoding utf8
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SMBClient/Operational'; StartTime=$since} -ErrorAction SilentlyContinue |
    Format-List TimeCreated, Id, Message | Out-File "$out\smbclient-log.txt" -Encoding utf8

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
