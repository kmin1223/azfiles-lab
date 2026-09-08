# Runs ON the lab VMs. Installs the PowerShell tooling attendees need for
# diagnostics: Az modules + the AzFilesHybrid module (Debug-AzStorageAccountAuth,
# Test-AzStorageAccountADObjectPasswordIsKerbKey, Update-AzStorageAccountADObjectPassword).
# Safe to re-run - skips whatever is already present.
param(
    # Prebuilt module bundle (see tools\New-LabToolsBundle.ps1). One HTTPS GET
    # beats ~9 minutes of Install-Module round trips. Pass '' to force the
    # gallery path.
    [string]$ModuleBundleUri = 'https://github.com/kmin1223/azfiles-lab/releases/latest/download/labtools-modules.zip',
    [string]$DomainController
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
if ($DomainController) {
    @{ DomainControllers = @($DomainController) } | ConvertTo-Json |
        Set-Content "$toolDir\evidence-config.json" -Encoding UTF8 -ErrorAction Stop
}
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

  AUTOMATIC LAB CAPTURE (after Install-LabEvidenceAutomation)
      NORMAL labuser1 window: Get-KerberosEvidence.ps1 -StartTrace
      Captures once, reproduces in a fresh non-admin batch logon using UNC
      (no drive letter), stops, and returns results to this window.
      Task Scheduler holds the lab credential; this helper never reads it.

  MANUAL CAPTURE / EXISTING USER SESSION
  ------------------
  1) Split (what you do on a real case). The trace needs admin rights, but the
     MOUNT must happen in the affected user's own, non-elevated session - that
     is the session whose ticket cache and drive mappings you are diagnosing.

        ELEVATED window :  Get-KerberosEvidence.ps1 -StartTrace -Manual [-DomainController <dc-fqdn>]
        NORMAL window   :  Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <sa>
        ELEVATED window :  Get-KerberosEvidence.ps1 -StopTrace

  2) All-in-one (quick, everything in the elevated window):

        Get-KerberosEvidence.ps1 -StorageAccount <sa>

  3) Re-read a capture you already have (no admin, any machine):

        Get-KerberosEvidence.ps1 -Analyze                 newest run
        Get-KerberosEvidence.ps1 -Analyze -Path <folder>  a specific one

  4) Retry DC collection without another mount:
        Get-KerberosEvidence.ps1 -CollectDc -Path <folder> [-DcCredential <PSCredential>]

     All-in-one captures its caller's context, not necessarily the affected
     application's context. Prefer split capture for user-specific failures.

  DC SECURITY LOGS
      Stop queries 4768/4769/4771 for the recorded reproduction interval.
      DC selection: explicit -DomainController, run config, installed config,
      then computer-domain discovery (a candidate, not proof of the issuing DC).
      -DcCredential on Stop/All optionally supplies read credentials in memory.
      Manual capture saves no credentials. No backend collection is required.
      Reproduce resets mappings and purges this logon session's tickets.
      Use one reproduction per capture; original state is saved before reset.

  AUTOMATIC OUTPUT -> C:\ProgramData\AzureFilesLabEvidence\<printed run path>\
      user\                      fresh labuser1 mount, tickets and DC reads
      capture\                   protected trace and collector-side events
      Use the returned run path; the manual .current-run.txt is not updated.
      The original window's ticket cache is not the worker's cache.

  MANUAL OUTPUT -> C:\LabTools\evidence\<timestamp>\
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
      reproduction.json          UTC interval, identity/context, mount exit code
      dc-summary.txt             collection status + candidate event table
      dc-<name>\security.*       bounded DC events: original XML, JSON and CSV
      dc-collection.json         per-DC status, count, truncation and errors
      azure-files-handoff.txt    target, context and UTC interval for case handoff
      *-collector.txt            elevated Stop snapshots (separate from reproduce)

  No events is not proof of no KDC request; check cache, actual KDC, clocks,
  auditing and retention. Event candidates are not automatic root-cause verdicts.
#>
[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'All', Mandatory)]
    [Parameter(ParameterSetName = 'Reproduce', Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccount,

    [Parameter(ParameterSetName = 'Start', Mandatory)][switch]$StartTrace,
    [Parameter(ParameterSetName = 'Start')][switch]$Manual,
    [Parameter(ParameterSetName = 'Library', Mandatory)][switch]$Library,
    [Parameter(ParameterSetName = 'Reproduce', Mandatory)][switch]$Reproduce,
    [Parameter(ParameterSetName = 'Stop', Mandatory)][switch]$StopTrace,
    [Parameter(ParameterSetName = 'Analyze', Mandatory)][switch]$Analyze,
    [Parameter(ParameterSetName = 'Dc', Mandatory)][switch]$CollectDc,
    [Parameter(ParameterSetName = 'Dc', Mandatory)]
    [Parameter(ParameterSetName = 'Analyze')][string]$Path,

    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$Share = 'labshare',
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter = 'Z',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')][string[]]$DomainController,
    [PSCredential]$DcCredential,
    [ValidateRange(1,100000)][int]$MaxDcEvents = 2000,
    [ValidateRange(0,300)][int]$DcTimePaddingSeconds = 5
)

$root    = 'C:\LabTools\evidence'
$pointer = Join-Path $root '.current-run.txt'
$ConverterPath = 'C:\LabTools\etl2pcapng.exe'
$ErrorActionPreference = 'Stop'

function Write-JsonFile($Value, [string]$File) {
    ConvertTo-Json -InputObject $Value -Depth 10 |
        Set-Content -LiteralPath $File -Encoding UTF8
}

function Get-DcTargets([string]$Out) {
    if ($DomainController) { return @($DomainController | Sort-Object -Unique) }
    foreach ($file in @((Join-Path $Out 'run.json'), 'C:\LabTools\evidence-config.json')) {
        if (Test-Path -LiteralPath $file) {
            $config = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            if ($config.DomainControllers) { return @($config.DomainControllers | Sort-Object -Unique) }
        }
    }
    $domain = [DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
    try {
        $dc = $domain.FindDomainController()
        try {
            Write-Warning 'Using a discovered DC candidate. In a multi-DC domain specify the actual responding DC(s).'
            return $dc.Name
        } finally { $dc.Dispose() }
    } finally { $domain.Dispose() }
}

function Initialize-EvidenceRun([string]$Out) {
    $targets = @()
    $preflight = @()
    try { $targets = @(Get-DcTargets $Out) } catch {
        $preflight += [pscustomobject]@{ Computer = ''; Status = 'Failed'; Error = $_.Exception.Message }
        Write-Warning "DC discovery/configuration failed: $($_.Exception.Message). Specify -DomainController on Stop."
    }
    foreach ($dc in $targets) {
        $query = @{ ComputerName = $dc; ListLog = 'Security'; ErrorAction = 'Stop' }
        if ($DcCredential) { $query.Credential = $DcCredential }
        try {
            $null = Get-WinEvent @query
            $preflight += [pscustomobject]@{ Computer = $dc; Status = 'Accessible'; Error = '' }
        } catch {
            $preflight += [pscustomobject]@{ Computer = $dc; Status = 'Failed'; Error = $_.Exception.Message }
            Write-Warning "DC Security preflight failed on ${dc}: $($_.Exception.Message). Client capture can still proceed."
        }
    }
    Write-JsonFile $preflight (Join-Path $Out 'dc-preflight.json')
    Write-JsonFile ([ordered]@{
        RunId = Split-Path $Out -Leaf
        DomainControllers = $targets
        CaptureStartUtc = [DateTime]::UtcNow.ToString('o')
    }) (Join-Path $Out 'run.json')
}

function Convert-DcEvent($Event, $Context) {
    [xml]$xml = $Event.ToXml()
    $fields = [ordered]@{}
    foreach ($node in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")) {
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }
    $reasons = @()
    $user = [string]$fields['TargetUserName']
    if ($user -and ($user -split '@')[0] -ieq $Context.UserName) { $reasons += 'User' }
    $ip = ([string]$fields['IpAddress']) -replace '^::ffff:', ''
    if ($ip -and @($Context.ClientAddresses) -contains $ip) { $reasons += 'ClientIP' }
    $service = [string]$fields['ServiceName']
    if ($service -and ($service.TrimEnd('$') -ieq $Context.StorageAccount -or
                      $service -ieq $Context.Spn)) { $reasons += 'Service' }
    [pscustomobject][ordered]@{
        TimeUtc = $Event.TimeCreated.ToUniversalTime().ToString('o')
        DC = $Event.MachineName
        RecordId = $Event.RecordId
        EventId = $Event.Id
        User = $user
        Service = $service
        ClientIP = [string]$fields['IpAddress']
        Status = [string]$fields['Status']
        TicketEncryptionType = [string]$fields['TicketEncryptionType']
        CandidateReasons = $reasons -join ','
        EventData = $fields
    }
}

function Save-DcEvidence([string]$Out) {
    $file = Join-Path $Out 'reproduction.json'
    if (-not (Test-Path -LiteralPath $file)) {
        $status = @([pscustomobject]@{ Computer = ''; Status = 'Skipped'; Error = 'No recorded reproduction interval.' })
        Write-JsonFile $status (Join-Path $Out 'dc-collection.json')
        'DC collection skipped: no reproduction.json. No statement about KDC activity is possible.' |
            Set-Content (Join-Path $Out 'dc-summary.txt')
        Write-Warning 'No reproduction recorded; DC Security collection skipped.'
        return
    }
    $context = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    if (-not $context.EndUtc) { throw 'Reproduction is still running or was interrupted. No complete DC query interval is available.' }
    $start = [DateTimeOffset]::Parse($context.StartUtc).UtcDateTime
    $end = [DateTimeOffset]::Parse($context.EndUtc).UtcDateTime
    if ($end -lt $start) { throw 'Invalid reproduction interval: end precedes start. Check client clock changes.' }
    $start = $start.AddSeconds(-$DcTimePaddingSeconds)
    $end = $end.AddSeconds($DcTimePaddingSeconds)
    $states = @()
    $all = @()
    $targets = @()
    try { $targets = @(Get-DcTargets $Out) } catch {
        $states += [pscustomobject]@{ Computer = ''; Status = 'Failed'; Count = 0; Truncated = $false; Error = $_.Exception.Message }
        Write-Warning "DC selection failed: $($_.Exception.Message)"
    }
    foreach ($dc in $targets) {
        if ($dc -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw "Invalid DC name in configuration: $dc" }
        $folder = Join-Path $Out "dc-$dc"
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $query = @{
            ComputerName = $dc
            FilterHashtable = @{ LogName = 'Security'; Id = @(4768,4769,4771); StartTime = $start; EndTime = $end }
            MaxEvents = $MaxDcEvents + 1
            ErrorAction = 'Stop'
        }
        if ($DcCredential) { $query.Credential = $DcCredential }
        $events = @()
        $queryError = $null
        try { $events = @(Get-WinEvent @query) } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $queryError = $_ }
        }
        if ($queryError) {
            $states += [pscustomobject]@{ Computer = $dc; Status = 'Failed'; Count = 0; Truncated = $false; Error = $queryError.Exception.Message }
            Write-Warning "DC Security collection failed on ${dc}: $($queryError.Exception.Message)"
            continue
        }
        $truncated = $events.Count -gt $MaxDcEvents
        $events = @($events | Select-Object -First $MaxDcEvents | Sort-Object TimeCreated,RecordId)
        $rows = @($events | ForEach-Object { Convert-DcEvent $_ $context })
        Write-JsonFile $rows (Join-Path $folder 'security.json')
        @('<Events>') + @($events | ForEach-Object { $_.ToXml() }) + @('</Events>') |
            Set-Content (Join-Path $folder 'security.xml') -Encoding UTF8
        if ($rows.Count) {
            $rows | Select-Object TimeUtc,DC,RecordId,EventId,User,Service,ClientIP,Status,TicketEncryptionType,CandidateReasons |
                Export-Csv (Join-Path $folder 'security.csv') -NoTypeInformation -Encoding UTF8
        } else {
            '"TimeUtc","DC","RecordId","EventId","User","Service","ClientIP","Status","TicketEncryptionType","CandidateReasons"' |
                Set-Content (Join-Path $folder 'security.csv') -Encoding UTF8
        }
        $states += [pscustomobject]@{
            Computer = $dc
            Status = $(if ($rows.Count) { 'Collected' } else { 'NoMatchingEvents' })
            Count = $rows.Count
            Truncated = $truncated
            Error = ''
        }
        if ($truncated) { Write-Warning "DC query on $dc exceeded $MaxDcEvents events. Increase -MaxDcEvents or narrow the reproduction." }
        $all += $rows
    }
    Write-JsonFile $states (Join-Path $Out 'dc-collection.json')
    $candidates = @($all | Where-Object CandidateReasons | Sort-Object TimeUtc)
    $display = @($candidates | Select-Object -First 40)
    $summary = @(
        'DC Security evidence - observations, not an automatic diagnosis'
        "Requested UTC interval: $($start.ToString('o')) through $($end.ToString('o')) (padding: ${DcTimePaddingSeconds}s)"
        "Reproduce account: $($context.Account); LUID: $($context.LogonId)"
        "Target: $($context.Spn); share: $($context.Share)"
        ''
        ($states | Format-Table Computer,Status,Count,Truncated,Error -Wrap -AutoSize | Out-String -Width 200)
        "Candidate events matching user, client IP or service: $($candidates.Count); showing $($display.Count)."
        'A candidate match is not proof of causation. All queried events are retained per DC.'
        ($display | Format-Table TimeUtc,EventId,User,Service,ClientIP,Status,CandidateReasons -AutoSize | Out-String -Width 220)
        '4769 success = ticket issuance, not Azure Files acceptance.'
        'No matching events: check cached tickets, responding DC, clock offsets, time window, auditing/KdcExtraLogLevel and retention.'
        'Collection Failed is different from a successful query with no events.'
        'Client/DC evidence only. See azure-files-handoff.txt for the case context.'
    )
    $summary | Set-Content (Join-Path $Out 'dc-summary.txt') -Encoding UTF8
    $summary | ForEach-Object { Write-Host $_ }
    @(
        "Storage account: $($context.StorageAccount)"
        "Share: $($context.Share)"
        "SPN: $($context.Spn)"
        "Client: $($context.Computer); addresses: $($context.ClientAddresses -join ', ')"
        "User: $($context.Account); SID: $($context.UserSid); LUID: $($context.LogonId)"
        "Reproduction UTC: $($context.StartUtc) through $($context.EndUtc)"
        "Mount exit code: $($context.MountExitCode); output: mount-result.txt"
        'Read the failing SMB operation, outer status and inner authentication token where visible.'
        'Encrypted commands may be unreadable. Correlate client events and non-secret configuration; do not infer a unique cause from one code.'
    ) | Set-Content (Join-Path $Out 'azure-files-handoff.txt') -Encoding UTF8
}

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
    Show-Cmd @"
netsh trace start capture=yes overwrite=yes maxsize=512 ``
      tracefile="$Out\trace.etl"
"@
    $started = & "$env:SystemRoot\System32\netsh.exe" trace start capture=yes overwrite=yes maxsize=512 tracefile="$Out\trace.etl" 2>&1
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
    $stopOutput = & "$env:SystemRoot\System32\netsh.exe" trace stop 2>&1
    $stopOutput | Out-File "$Out\trace-stop.txt" -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "Trace stop failed. Run pointer retained for recovery; see $Out\trace-stop.txt." }
    if ((Test-Path "$Out\trace.etl") -and (Test-Path -LiteralPath $ConverterPath)) {
        & $ConverterPath "$Out\trace.etl" "$Out\trace.pcapng" | Out-Null
        $conversionExit = $LASTEXITCODE
        $pcap = Get-Item "$Out\trace.pcapng" -ErrorAction SilentlyContinue
        if ($conversionExit -eq 0 -and $pcap -and $pcap.Length -gt 0) {
            Write-Host ("pcapng ready: {0} ({1:N0} KB)" -f $pcap.FullName, ($pcap.Length / 1KB)) -ForegroundColor Green
        } else {
            Write-Warning "Conversion failed or produced an empty file (exit $conversionExit). Original ETL retained."
        }
    } else {
        Write-Warning "ETL or etl2pcapng converter unavailable; keep $Out\trace.etl for analysis. DC collection is independent."
    }
}

# Events that are routine against Azure Files and say nothing about a failure.
# Without this note a screenful of them looks like a lead.
$benign = @{
    30904 = 'SMB Multichannel not offered in this connection - verify server tier/capabilities if relevant'
    30800 = 'share reconnected - routine'
}
# The opposite list: events that ARE about your failure, and what to read in them.
$meaningful = @{
    31001 = 'SSPI failed while building the Session Setup token - read Security status'
    31010 = 'Share access failed - correlate the target share and Session Setup result'
}
# Status codes that Windows fails to name in the event text. 0x80090322 is
# logged as "Unknown NTSTATUS Error code" because it is a SECURITY_STATUS, not
# an NTSTATUS - so the event tells you nothing unless you know this table.
$statusNotes = @{
    '0x80090322' = 'SEC_E_WRONG_PRINCIPAL - investigate target/SPN and ticket validation; not proof of a particular key/salt defect.'
    '0xc000006d' = 'STATUS_LOGON_FAILURE - inspect operation, credentials and effective identity; the code does not identify the caller.'
    '0xc0000022' = 'STATUS_ACCESS_DENIED - identify the failed SMB operation and inspect auth, policy or authorization evidence. Blob length does not classify the cause.'
}

function Save-Log([string]$Out, [string]$LogName, [string]$File, [string[]]$Props) {
    $intervalFile = Join-Path $Out 'reproduction.json'
    if (-not (Test-Path $intervalFile)) {
        "Skipped $LogName`: no recorded reproduction interval." | Out-File (Join-Path $Out $File) -Encoding utf8
        return
    }
    $interval = Get-Content $intervalFile -Raw | ConvertFrom-Json
    $since = [DateTimeOffset]::Parse($interval.StartUtc).UtcDateTime.AddSeconds(-$DcTimePaddingSeconds)
    $until = [DateTimeOffset]::Parse($interval.EndUtc).UtcDateTime.AddSeconds($DcTimePaddingSeconds)
    $ev = @()
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{LogName = $LogName; StartTime = $since; EndTime = $until} -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            "Collection failed for $LogName`: $($_.Exception.Message)" | Out-File (Join-Path $Out $File) -Encoding utf8
            Write-Warning "Collection failed for $LogName`: $($_.Exception.Message)"
            return
        }
    }
    $path = Join-Path $Out $File
    if ($ev) {
        $ids = $ev | Group-Object Id | Sort-Object Count -Descending
        $summary = ($ids | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
        $interesting = @($ev)

        $head = @("$LogName - $(@($ev).Count) event(s) since $since", "Event IDs: $summary", '')
        foreach ($g in $ids) {
            if ($benign.ContainsKey([int]$g.Name)) {
                $head += "  $($g.Name) x$($g.Count)   CONTEXT - $($benign[[int]$g.Name])"
            } elseif ($meaningful.ContainsKey([int]$g.Name)) {
                $head += "  $($g.Name) x$($g.Count)   READ THIS - $($meaningful[[int]$g.Name])"
            }
        }
        # Decode the status codes Windows leaves as 'Unknown'.
        foreach ($code in $statusNotes.Keys) {
            if ($ev | Where-Object { $_.Message -like "*$code*" }) {
                $head += @('', "  $code = $($statusNotes[$code])")
            }
        }
        # A wall of identical events is one fact, not N facts - say the cadence
        # instead. For 1396 that cadence IS information: the client retrying.
        foreach ($g in $ids) {
            if ([int]$g.Count -gt 2 -and -not $benign.ContainsKey([int]$g.Name)) {
                $texts = @($g.Group | ForEach-Object { $_.Message })
                if (($texts | Select-Object -Unique).Count -eq 1) {
                    $ts = @($g.Group | Sort-Object TimeCreated | Select-Object -ExpandProperty TimeCreated)
                    $gap = [math]::Round((($ts[-1] - $ts[0]).TotalSeconds / [math]::Max(1, $ts.Count - 1)), 1)
                    $head += "  $($g.Name): all $($g.Count) messages identical, about every ${gap}s - a retry loop, not $($g.Count) problems."
                }
            }
        }

        $dropped = @($ev.Count - $interesting.Count)[0]
        if ($interesting.Count) {
            if ($dropped -gt 0) {
                $full = $path -replace '\.txt$', '-full.txt'
                $head += @('', "$dropped routine event(s) are NOT listed below. Full set: $(Split-Path $full -Leaf)")
                $ev | Format-List $Props | Out-File $full -Encoding utf8
            }
            $head += @('', ('-' * 70), '')
            $head | Out-File $path -Encoding utf8
            $interesting | Format-List $Props | Out-File $path -Encoding utf8 -Append
        } else {
            $head += @('', 'NOTHING HERE IS ABOUT YOUR FAILURE - every event above is routine noise.',
                       'The events themselves are not repeated here; nothing in them varies.',
                       '', ('-' * 70), '')
            $head | Out-File $path -Encoding utf8
            $ev | Select-Object -First 1 | Format-List $Props | Out-File $path -Encoding utf8 -Append
            "... and $($ev.Count - 1) more, identical." | Out-File $path -Encoding utf8 -Append
        }

        $note = if ($interesting.Count) { "$($interesting.Count) worth reading" } else { 'all routine noise' }
        Write-Host ("  {0,-44} {1,3} event(s)  {2,-16} {3}" -f $LogName, @($ev).Count, $summary, $note)
    } else {
        @(
            "No events in $LogName between $($since.ToString('o')) and $($until.ToString('o'))."
            ''
            'Empty does NOT mean the mount was healthy - it means THIS channel had'
            'nothing to say. Different failures land in different channels:'
            ''
            '  Kerberos/Operational    client-side Kerberos events when recorded'
            '  SMBClient/Operational   SMB operational context'
            '  SMBClient/Security      authentication/security events'
            ''
            'And regardless of the channels:'
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
# SMB2 statuses that are NOT failures. STATUS_MORE_PROCESSING_REQUIRED is the
# normal status for an intermediate Session Setup response - and it is what the
# service returns while REJECTING a ticket, because the rejection lives inside
# the GSS blob, not in the SMB header. Filter on SMB status alone and you miss it.
$smbOk = @('0x00000000', '0xc0000016', '0')

# SMB 3.1.1 encryption negotiate context - MS-SMB2 2.2.3.1.2.
$cipherName = @{ 1 = 'AES-128-CCM'; 2 = 'AES-128-GCM'; 3 = 'AES-256-CCM'; 4 = 'AES-256-GCM' }

function ConvertTo-CipherNames([string]$Raw) {
    $out = @()
    foreach ($v in ($Raw -split ',')) {
        $s = $v.Trim()
        if (-not $s) { continue }
        $n = if ($s -match '^0x') { [Convert]::ToInt32($s, 16) } else { [int]$s }
        if ($cipherName.ContainsKey($n)) { $out += $cipherName[$n] } else { $out += "cipher($s)" }
    }
    $out
}

# These first observed fields are navigation aids, not a correlated negotiation.
function Get-CipherStory([string]$Tshark, [string]$Pcap) {
    $rows = & $Tshark -r $Pcap -Y 'smb2.cmd == 0' -T fields `
        -e smb2.flags.response -e smb2.cipher_id -E 'separator=|' 2>$null
    $offered = $null; $chosen = $null
    foreach ($r in $rows) {
        $f = $r -split '\|'
        if ($f.Count -lt 2 -or -not $f[1]) { continue }
        $names = @(ConvertTo-CipherNames $f[1])
        if (-not $names.Count) { continue }
        if ($f[0] -eq '1') { if (-not $chosen)  { $chosen  = $names } }
        else               { if (-not $offered) { $offered = $names } }
    }
    if (-not $chosen -and -not $offered) {
        return @(
            'CIPHER: no encryption negotiate context found in this capture.'
            '        Either the dialect is below 3.1.1, or this tshark build does'
            '        not carry the smb2.cipher_id field. In Wireshark, open the'
            '        Negotiate Protocol Response and read:'
            '        SMB2 > Negotiate Context: SMB2_ENCRYPTION_CAPABILITIES > CipherId'
        )
    }
    $lines = @('CIPHER (SMB3 channel encryption, settled at Negotiate):')
    if ($offered) { $lines += "  client offered : $($offered -join ', ')" }
    if ($chosen)  { $lines += "  server chose   : $($chosen -join ', ')" }
    $lines += ''
    $lines += '  First observed request/response fields only; they are not correlated'
    $lines += '  by connection. Verify the target stream before interpreting them.'
    $lines += '  Compare account policy and the actual failure operation/status.'
    $lines += '  Neither cipher order nor security-buffer length proves root cause.'
    $lines
}

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

tshark -r trace.pcapng -Y "smb2.cmd == 0" -T fields ``
    -e smb2.flags.response -e smb2.cipher_id     # which cipher was agreed
"@
    # tcp ports matter: a Kerberos error on 88 is the KDC refusing, the SAME
    # error inside SMB (445) is the SERVICE refusing. Opposite conclusions.
    $raw = & $tshark -r $pcap -Y 'kerberos || smb2' -T fields `
        -e frame.number -e frame.time_relative -e ip.dst `
        -e tcp.srcport -e tcp.dstport `
        -e kerberos.msg_type -e kerberos.error_code `
        -e smb2.cmd -e smb2.flags.response -e smb2.nt_status `
        -E 'separator=|' 2>$null

    $lines = @(); $sawTgsRep = $false; $ssFailure = $null
    $krbErrKdc = $null; $krbErrSvc = $null; $attempts = 0
    foreach ($r in $raw) {
        $f = $r -split '\|'
        if ($f.Count -lt 10) { continue }
        $num, $t, $dst, $sport, $dport, $kmsg, $kerr, $scmd, $sresp, $sstat = $f[0..9]
        $onSmb = ($sport -eq '445' -or $dport -eq '445')
        # a frame can carry several messages; take the first of each field
        $kmsg = ($kmsg -split ',')[0]; $kerr = ($kerr -split ',')[0]
        $scmd = ($scmd -split ',')[0]; $sresp = ($sresp -split ',')[0]; $sstat = ($sstat -split ',')[0]

        if ($kmsg) {
            $name = if ($krbMsg.ContainsKey([int]$kmsg)) { $krbMsg[[int]$kmsg] } else { "krb($kmsg)" }
            $detail = ''
            if ($kerr) {
                $en = if ($krbErr.ContainsKey([int]$kerr)) { $krbErr[[int]$kerr] } else { "code $kerr" }
                if ($onSmb) {
                    # Carried in the SMB Session Setup response - the SERVICE said no.
                    $detail = "  <-- $en   (from the SERVICE, inside SMB)"
                    $krbErrSvc = $en; $attempts++
                } else {
                    $detail = "  <-- $en   (from the KDC)"
                    if ($en -ne 'PREAUTH_REQUIRED') { $krbErrKdc = $en }
                }
            }
            if ($name -eq 'TGS-REP') { $sawTgsRep = $true }
            $where = if ($onSmb) { 'KRB/SMB' } else { 'KRB    ' }
            $lines += ('{0,6}  {1,8:N3}s  {2,-15} {3} {4}{5}' -f $num, [double]$t, $dst, $where, $name, $detail)
        }
        if ($scmd) {
            $name = if ($smbCmd.ContainsKey([int]$scmd)) { $smbCmd[[int]$scmd] } else { "cmd $scmd" }
            $dir = if ($sresp -eq '1') { 'resp' } else { 'req ' }
            $st = ''
            if ($sresp -eq '1' -and $sstat -and $smbOk -notcontains $sstat) {
                $st = "  <-- STATUS $sstat"
                if (-not $ssFailure) { $ssFailure = "$name $sstat" }
            } elseif ($sresp -eq '1' -and $sstat -eq '0xc0000016') {
                $st = '  (MORE_PROCESSING_REQUIRED - normal mid-handshake)'
            }
            $lines += ('{0,6}  {1,8:N3}s  {2,-15} SMB2  {3} {4}{5}' -f $num, [double]$t, $dst, $name, $dir, $st)
        }
    }

    $verdict = @(
        'OBSERVATIONS across the capture (not correlated by target/connection):'
        "  Any TGS-REP observed: $sawTgsRep"
        "  Last Kerberos error outside SMB: $krbErrKdc"
        "  Last Kerberos error inside SMB: $krbErrSvc"
        "  First observed SMB failure: $ssFailure"
        'Read the actual operation/status/token, and corroborate with dc-summary.txt.'
        'TGS issuance does not prove service acceptance. Missing packets/events and'
        'security-buffer length do not establish root cause. Later retries can differ.'
    )

    $cipher = Get-CipherStory $tshark $pcap

    $out = @("Trace summary - $pcap", ('=' * 78), '',
             ('{0,6}  {1,9}  {2,-15} {3}' -f 'frame', 'time', 'dest', 'where / message'),
             ('-' * 78)) + $lines + @('', ('=' * 78)) + $verdict +
           @('', ('-' * 78)) + $cipher
    $out | Out-File $path -Encoding utf8
    Write-Host ''
    $out | ForEach-Object {
        $c = if ($_ -match 'STATUS|<--|READING|=>|CIPHER|server chose|client offered') { 'Yellow' } else { 'Gray' }
        Write-Host $_ -ForegroundColor $c
    }
}

function Save-EventLogs([string]$Out) {
    Write-Host 'Event logs:'
    Show-Cmd @"
Get-WinEvent -FilterHashtable @{LogName='<channel>'; StartTime=<repro-start>; EndTime=<repro-end>}
  Microsoft-Windows-Kerberos/Operational
  Microsoft-Windows-SMBClient/Operational
  Microsoft-Windows-SMBClient/Connectivity
"@
    Save-Log $Out 'Microsoft-Windows-Kerberos/Operational'   'kerberos-log.txt'   @('TimeCreated','Id','LevelDisplayName','Message')
    Save-Log $Out 'Microsoft-Windows-SMBClient/Operational'  'smbclient-log.txt'  @('TimeCreated','Id','Message')
    Save-Log $Out 'Microsoft-Windows-SMBClient/Connectivity' 'smbclient-connectivity.txt' @('TimeCreated','Id','Message')
    Save-Log $Out 'Microsoft-Windows-SMBClient/Security'     'smbclient-security.txt'     @('TimeCreated','Id','Message')
}

function Invoke-NonInteractiveUncMount {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^\\\\[a-z0-9]{3,24}\.file\.core\.windows\.net\\[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')]
        [string]$Unc,
        [ValidateRange(1,120)][int]$TimeoutSeconds = 120
    )
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = "$env:SystemRoot\System32\net.exe"
    $process.StartInfo.Arguments = "use $Unc /persistent:no"
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.StandardOutputEncoding = [Console]::OutputEncoding
    $process.StartInfo.StandardErrorEncoding = [Console]::OutputEncoding
    try {
        if (-not $process.Start()) { throw 'Could not start the UNC connection probe.' }
        # EOF prevents a credential prompt from hanging an unattended worker.
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw 'The timed-out UNC probe did not terminate.' }
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) {
            throw 'UNC probe output streams did not close after process exit.'
        }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            TimedOut = $timedOut
            Output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        }
    } finally {
        $process.Dispose()
    }
}

# The mount itself, plus the state that only exists in THIS logon session.
function Invoke-MountAttempt([string]$Out, [switch]$NoDriveMapping, [switch]$NonInteractive) {
    if ($NonInteractive -and -not $NoDriveMapping) {
        throw 'NonInteractive reproduction requires NoDriveMapping.'
    }
    if (Test-Path (Join-Path $Out 'reproduction.json')) {
        throw 'This capture already has a reproduction. Stop it and start a new capture; evidence will not be overwritten.'
    }
    $fqdn = "$StorageAccount.file.core.windows.net"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $original = klist 2>&1 | Out-String
    $original | Out-File "$Out\klist-original.txt" -Encoding utf8
    $luid = if ($original -match '(?m)^[^\r\n]*?(\d+:0x[0-9a-fA-F]+)') { $Matches[1] } else { 'unparsed - see klist-original.txt' }
    $addresses = @()
    try {
        $addresses = @([Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
            ForEach-Object IPAddressToString | ForEach-Object { $_ -replace '^::ffff:', '' })
    } catch { Write-Warning "Client address discovery failed: $($_.Exception.Message)" }
    $context = [ordered]@{
        StartUtc = [DateTime]::UtcNow.ToString('o')
        EndUtc = $null
        Account = $identity.Name
        UserName = ($identity.Name -split '\\')[-1]
        UserSid = $identity.User.Value
        LogonId = $luid
        Elevated = Test-Admin
        Computer = $env:COMPUTERNAME
        ClientAddresses = $addresses
        StorageAccount = $StorageAccount
        Spn = "cifs/$fqdn"
        Share = $Share
        MountExitCode = $null
        MountTimedOut = $false
        ConnectionMode = $(if ($NoDriveMapping) { 'UNC' } else { 'DriveMapping' })
        NonInteractive = [bool]$NonInteractive
        Error = ''
    }
    Write-JsonFile $context (Join-Path $Out 'reproduction.json')
    net use 2>&1 | Out-File "$Out\mappings-original.txt" -Encoding utf8
    Write-Warning 'Reproduce purges tickets in THIS logon session. Original state has been saved.'
    try {
    if (-not $NoDriveMapping) {
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
    foreach ($target in @("${DriveLetter}:", "\\$fqdn\$Share")) {
        # Merge stderr in cmd so an absent mapping does not terminate PowerShell 5.1.
        $resetOutput = cmd /c "net use $target /delete /y 2>&1"
        $resetExit = $LASTEXITCODE
        @("Reset ${target}: exit $resetExit") + @($resetOutput) |
            Out-File "$Out\mapping-reset.txt" -Encoding utf8 -Append
        if ($resetExit -ne 0) {
            Write-Host "Mapping reset for $target returned $resetExit (possibly absent); see mapping-reset.txt."
        }
    }
    Remove-SmbMapping -LocalPath "${DriveLetter}:" -Force -ErrorAction SilentlyContinue
    } else {
        Show-Cmd "klist purge`nklist`nnet use \\$fqdn\$Share /persistent:no`nklist"
        Write-Host 'UNC-only probe: no drive letter or existing-session reset. Automatic runs use a fresh batch logon.' -ForegroundColor Cyan
    }
    klist purge | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'klist purge failed; the intended fresh-ticket reproduction could not be prepared.' }
    klist > "$Out\klist-before.txt"

    Write-Host 'Attempting the mount...'
    # /persistent:no - a remembered mapping outlives the lab and keeps the
    # drive letter reserved, which later shows up as "System error 85".
    if ($NonInteractive) {
        $result = Invoke-NonInteractiveUncMount -Unc "\\$fqdn\$Share"
        $mount = $result.Output
        $context.MountExitCode = $result.ExitCode
        $context.MountTimedOut = $result.TimedOut
    } elseif ($NoDriveMapping) {
        $mount = cmd /c "net use \\$fqdn\$Share /persistent:no 2>&1"
        $context.MountExitCode = $LASTEXITCODE
    } else {
        $mount = cmd /c "net use ${DriveLetter}: \\$fqdn\$Share /persistent:no 2>&1"
        $context.MountExitCode = $LASTEXITCODE
    }
    $mount | Out-File "$Out\mount-result.txt" -Encoding utf8
    Write-Host ($mount -join "`n")

    Start-Sleep -Seconds 2
    klist > "$Out\klist-after.txt"
    Save-SmbState $Out
    if ($context.MountTimedOut) { throw 'UNC connection probe exceeded 120 seconds; partial output and tickets were retained.' }
    } catch {
        $context.Error = $_.Exception.Message
        throw
    } finally {
        $context.EndUtc = [DateTime]::UtcNow.ToString('o')
        Write-JsonFile $context (Join-Path $Out 'reproduction.json')
        $identity.Dispose()
    }
}

# Get-SmbConnection needs an ELEVATED token - a standard user (even one who is a
# local admin) gets "Access is denied". Rather than fail the whole reproduce
# step, note it and let -StopTrace pick it up from the elevated window.
function Save-SmbState([string]$Out, [string]$Suffix = '') {
    Show-Cmd @"
Get-SmbConnection          # needs an ELEVATED window
Get-SmbClientConfiguration # configured client policy, not the negotiated cipher
"@
    try {
        Get-SmbConnection -ErrorAction Stop | Format-List * |
            Out-File "$Out\smb-connection$Suffix.txt" -Encoding utf8
    } catch {
        @(
            'Get-SmbConnection was not available in this session:'
            "  $($_.Exception.Message)"
            ''
            'This cmdlet requires an ELEVATED window. -StopTrace collects it.'
        ) | Out-File "$Out\smb-connection$Suffix.txt" -Encoding utf8
    }
    try {
        Get-SmbClientConfiguration -ErrorAction Stop | Format-List * |
            Out-File "$Out\smb-client-config$Suffix.txt" -Encoding utf8
    } catch {
        "Get-SmbClientConfiguration failed: $($_.Exception.Message)" |
            Out-File "$Out\smb-client-config$Suffix.txt" -Encoding utf8
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $logonInfo = klist 2>&1 | Out-String
        $logonId = if ($logonInfo -match '(?m)^[^\r\n]*?(\d+:0x[0-9a-fA-F]+)') { $Matches[1] } else { 'unparsed - see klist-context file' }
        $logonInfo | Out-File "$Out\klist-context$Suffix.txt" -Encoding utf8
        Write-JsonFile @{ Account = $identity.Name; UserSid = $identity.User.Value; LogonId = $logonId; Elevated = Test-Admin; TimeUtc = [DateTime]::UtcNow.ToString('o') } `
            (Join-Path $Out "smb-context$Suffix.json")
    } finally { $identity.Dispose() }
}

function Complete-EvidenceRun([string]$Out) {
    $reproFile = Join-Path $Out 'reproduction.json'
    if ((Test-Path $reproFile) -and -not (Get-Content $reproFile -Raw | ConvertFrom-Json).EndUtc) {
        throw 'Reproduction has no end time. Wait for it to finish before stopping; for an interrupted process stop netsh manually and preserve the run.'
    }
    $run = Get-Content (Join-Path $Out 'run.json') -Raw | ConvertFrom-Json
    if (-not $run.TraceStopped) {
        Stop-Capture $Out
        $run | Add-Member NoteProperty TraceStopped $true -Force
        $run | Add-Member NoteProperty CaptureEndUtc ([DateTime]::UtcNow.ToString('o')) -Force
        Write-JsonFile $run (Join-Path $Out 'run.json')
    }
    Save-DcEvidence $Out
    Save-EventLogs $Out
    Save-SmbState $Out '-collector'
    Show-TraceSummary $Out
    Remove-Item -LiteralPath $pointer
    Write-Host "Done. Read $Out\dc-summary.txt; raw data and collection errors are retained." -ForegroundColor Green
}

if ($Library) { return }

switch ($PSCmdlet.ParameterSetName) {

    'Start' {
        $automation = 'C:\Program Files\AzureFilesLabEvidence\Invoke-LabEvidenceAutomation.ps1'
        if (-not $Manual -and (Test-Path -LiteralPath $automation)) {
            if ($PSBoundParameters.Keys | Where-Object { $_ -notin @('StartTrace','Verbose','Debug','ErrorAction','WarningAction','InformationAction') }) {
                throw 'Automatic capture uses the deployment-fixed identity, target and DC. Use -StartTrace -Manual for custom parameters.'
            }
            & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -File $automation -Mode Client
            if ($LASTEXITCODE -ne 0) { throw "Automatic evidence collection failed (exit $LASTEXITCODE)." }
            return
        }
        if (-not $Manual -and -not (Test-Admin)) {
            throw 'Automatic evidence is not installed. Run Update-LabEvidenceAutomation.ps1 from the lab repository in Cloud Shell once, or use -StartTrace -Manual in an elevated window.'
        }
        Assert-Admin 'Starting a network trace'
        if (Test-Path $pointer) { throw 'A collector run is already recorded. Finish it with -StopTrace before starting another.' }
        $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
        $out = Join-Path $root $stamp
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        # Let the non-elevated session write its half of the evidence here.
        icacls $out /grant "*S-1-5-32-545:(OI)(CI)M" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant the normal session write access to the evidence folder.' }
        Initialize-EvidenceRun $out
        if (-not (Start-Capture $out)) { exit 1 }
        Set-Content -Path $pointer -Value $out -Encoding ascii
        Write-Host ''
        Write-Host "Trace running. Evidence folder: $out" -ForegroundColor Cyan
        Write-Host ''
        Write-Host 'NOW, in your NORMAL (non-elevated) PowerShell window:' -ForegroundColor Yellow
        Write-Host '    C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <sa> -Share labshare' -ForegroundColor White
        Write-Host ''
        Write-Host 'Then come back here and run:' -ForegroundColor Yellow
        Write-Host '    C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace' -ForegroundColor White
    }

    'Reproduce' {
        if (Test-Admin) {
            Write-Warning 'You are in an ELEVATED window. Confirm this is the actual affected logon context.'
            Write-Host 'The point of -Reproduce is to mount in the affected user''s own session,' -ForegroundColor Yellow
            Write-Host 'which has its own ticket cache and drive letters. Use a normal window.'   -ForegroundColor Yellow
            Write-Host ''
        }
        $out = Get-CurrentRun
        $run = Get-Content (Join-Path $out 'run.json') -Raw | ConvertFrom-Json
        if ($run.TraceStopped) { throw 'Trace is already stopped. Finish -StopTrace and start a new capture.' }
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

    'Dc' {
        Save-DcEvidence (Resolve-Path -LiteralPath $Path).Path
    }

    'Stop' {
        Assert-Admin 'Stopping the network trace'
        $out = Get-CurrentRun
        Complete-EvidenceRun $out
        Write-Host 'Wireshark filter to start with:  kerberos || smb2'
    }

    'All' {
        Assert-Admin 'Capturing a network trace'
        if (Test-Path $pointer) { throw 'A collector run is already recorded. Finish it with -StopTrace first.' }
        $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
        $out = Join-Path $root $stamp
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        Write-Host "Collecting evidence -> $out" -ForegroundColor Cyan
        Write-Host 'Note: the mount happens in THIS elevated session. To capture the' -ForegroundColor DarkGray
        Write-Host 'user session instead, use -StartTrace / -Reproduce / -StopTrace.'  -ForegroundColor DarkGray

        Initialize-EvidenceRun $out
        if (-not (Start-Capture $out)) { exit 1 }
        Set-Content -Path $pointer -Value $out -Encoding ascii
        try { Invoke-MountAttempt $out } finally { Complete-EvidenceRun $out }
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
