# Runs ON the lab VMs. Installs the PowerShell tooling attendees need for
# diagnostics: Az modules + the AzFilesHybrid module (Debug-AzStorageAccountAuth,
# Test-AzStorageAccountADObjectPasswordIsKerbKey, Update-AzStorageAccountADObjectPassword).
# Safe to re-run - skips whatever is already present.
$ErrorActionPreference = 'Continue'   # never fail the deployment over tooling
$ProgressPreference = 'SilentlyContinue'  # much faster downloads

Write-Output "=== Installing lab tooling on $env:COMPUTERNAME ==="

# TLS 1.2 is required to reach the PowerShell Gallery on Windows Server
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- NuGet provider + trust the gallery (needed for unattended installs) ---
try {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    Write-Output 'PSGallery ready'
} catch {
    Write-Output "PSGallery prep warning: $($_.Exception.Message)"
}

# --- Az modules (only what the lab uses, to keep this quick) ---
$azModules = 'Az.Accounts', 'Az.Storage', 'Az.Resources', 'Az.Network'
foreach ($m in $azModules) {
    if (Get-Module -ListAvailable -Name $m) {
        Write-Output "$m already present"
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

# --- Evidence tooling: etl2pcapng (converts netsh traces to pcapng) ---
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
if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2) {
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
Write-Output '--- installed modules ---'
Get-Module -ListAvailable -Name Az.Accounts, Az.Storage, AzFilesHybrid |
    Select-Object Name, Version | Format-Table -AutoSize | Out-String | Write-Output

Write-Output 'TOOLS_READY'
