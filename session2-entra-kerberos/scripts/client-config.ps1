# Runs ON the client VM. Enables cloud Kerberos ticket retrieval, kicks
# hybrid-join registration, installs Fiddler for KDC Proxy inspection, then
# reboots so the changes fully apply.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# 1. Allow retrieving the Entra Kerberos TGT during logon
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name CloudKerberosTicketRetrievalEnabled -Value 1 -Type DWord
Write-Output 'CloudKerberosTicketRetrievalEnabled = 1'

# 1b. DNS preflight. Hybrid join talks to enterpriseregistration.windows.net and
# login.microsoftonline.com over HTTPS. The VNet points every VM at the DC for
# DNS, so if the DC has no forwarder NOTHING public resolves - and dsregcmd
# reports it as 0x80072ee7 -> 0x801c003d, which reads like a tenant/SCP problem
# rather than what it is. Name it here so nobody debugs Entra for an hour.
$dnsOk = $true
foreach ($n in 'login.microsoftonline.com', 'enterpriseregistration.windows.net') {
    try {
        Resolve-DnsName $n -ErrorAction Stop | Out-Null
        Write-Output "DNS OK: $n"
    } catch {
        $dnsOk = $false
        Write-Output "DNS FAIL: $n could not be resolved"
    }
}
if (-not $dnsOk) {
    Write-Output ''
    Write-Output '*** PUBLIC DNS IS BROKEN ON THIS CLIENT - hybrid join will fail. ***'
    Write-Output 'Cause: the VNet points this VM at the DC, and the DC has no DNS forwarder.'
    Write-Output 'Fix (on the DC, elevated), then re-run session2 setup.ps1:'
    Write-Output '    Set-DnsServerForwarder -IPAddress 168.63.129.16'
    Write-Output '    Resolve-DnsName login.microsoftonline.com -Server 127.0.0.1'
    Write-Output ''
}

# 2. Prime hybrid join. THIS ATTEMPT IS EXPECTED TO FAIL on a first run, and that
# is not a bug in this script - it is the order the lab is built in.
#
# In a MANAGED (non-federated) tenant the device object must already exist in
# Entra before the client can complete registration: the client asks DRS to
# renew a device whose id is its own AD computer objectGUID, and directory sync
# is what puts that object in Entra (Cloud Sync maps DeviceId <- objectGUID).
# Cloud Sync runs AFTER this script, and its device sync is off by default - so
# on the first pass DRS answers:
#     error_missing_device / "The device object by the given id ... is not found"
#     DsrDeviceAutoJoin failed 0x801c03f3
# We still run it here to create the local device keys and surface the SCP
# discovery result early. The join that actually succeeds happens after Cloud
# Sync device sync has provisioned the computer object.
$task = Get-ScheduledTask -TaskName 'Automatic-Device-Join' `
    -TaskPath '\Microsoft\Windows\Workplace Join\' -ErrorAction SilentlyContinue
if ($task) { $task | Start-ScheduledTask }
$joinOut = dsregcmd /join /debug 2>&1
$joinOut | Select-Object -Last 8 | Write-Output
if ($joinOut -match 'error_missing_device' -or $joinOut -match '0x801c03f3') {
    Write-Output ''
    Write-Output 'EXPECTED at this stage: the Entra device object does not exist yet.'
    Write-Output 'Next: Cloud Sync -> Properties -> Basics -> Enable device sync (preview),'
    Write-Output 'then Provision on demand for CN=azflab-cli,CN=Computers,DC=contoso,DC=local,'
    Write-Output 'then re-run  dsregcmd /join /debug  on the client. See MANUAL-STEP-cloud-sync.md.'
}

# 3. Fiddler Classic + Kerberos.NET extension - the ONLY way to see the KDC
# Proxy (HTTPS) exchange that Entra Kerberos uses. Wireshark/netsh only show
# encrypted TCP here. Best-effort: never fail setup over a diagnostic tool.
try {
    $tool = 'C:\LabTools'
    New-Item -ItemType Directory -Path $tool -Force | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Fiddler Classic (Telerik) - silent install
    $fidExe = Join-Path $tool 'FiddlerSetup.exe'
    if (-not (Test-Path 'C:\Program Files*\Fiddler*\Fiddler.exe')) {
        Invoke-WebRequest -Uri 'https://telerik-fiddler.s3.amazonaws.com/fiddler/FiddlerSetup.exe' `
            -OutFile $fidExe -UseBasicParsing -ErrorAction Stop
        Start-Process -FilePath $fidExe -ArgumentList '/S' -Wait
        Write-Output 'Fiddler Classic installed'
    } else {
        Write-Output 'Fiddler already present'
    }

    # Kerberos.NET Fiddler extension (dotnet/Kerberos.NET releases). The URL
    # moves between releases, so leave the installer on the box for the lab to
    # run manually if the download 404s.
    $krbExt = Join-Path $tool 'Fiddler.Kerberos.NET.exe'
    Invoke-WebRequest -Uri 'https://github.com/dotnet/Kerberos.NET/releases/latest/download/Fiddler.Kerberos.NET.exe' `
        -OutFile $krbExt -UseBasicParsing -ErrorAction Stop
    Start-Process -FilePath $krbExt -ArgumentList '/S' -Wait -ErrorAction SilentlyContinue
    Write-Output 'Kerberos.NET Fiddler extension staged/installed'
} catch {
    Write-Output "Fiddler tooling not fully installed ($($_.Exception.Message.Split([char]10)[0])) - install from C:\LabTools during the lab if needed"
}

# 4. Pre-trust the Fiddler root CA so nobody has to click through the certificate
# prompts during the lab.
#
# Fiddler generates its root CA on first run and installs it into the CURRENT
# USER's Root store. Windows ALWAYS shows a "Security Warning" consent dialog for
# a user-store root, and that dialog cannot be suppressed - by design, it is the
# only thing standing between a user and a silent TLS-interception CA.
#
# The LOCAL MACHINE Root store behaves differently: an elevated process may write
# to it without any dialog. So we generate the CA ourselves, trust it at machine
# scope, and leave it in the user's My store where Fiddler looks for it. Fiddler
# finds a chain that already validates and skips its own prompts.
#
# This must run as the LAB USER (the private key has to live in that user's My
# store), but Run Command here executes as SYSTEM - so we drop the script and let
# a logon task run it in the right context. It is idempotent, so labuser2 gets it
# too, and re-running costs nothing.
$fidTrust = 'C:\LabTools\Setup-FiddlerTrust.ps1'
$fidTrustBody = @'
<#
  Setup-FiddlerTrust.ps1 - make Fiddler HTTPS decryption work without the
  interactive certificate prompts. Idempotent; safe to run at every logon.

  SECURITY - READ BEFORE REUSING THIS ANYWHERE ELSE
  This creates and machine-trusts a root CA that can intercept ANY TLS
  connection on this computer. That is acceptable only on a throwaway lab VM.
  The private key is generated locally and never leaves the machine - nothing
  is shipped in the repo, and every lab VM gets a different key. Do NOT run
  this on a real workstation, and delete the VM when the lab is over.
#>
$ErrorActionPreference = 'Stop'
$cn      = 'DO_NOT_TRUST_FiddlerRoot'
$subject = "CN=$cn, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com"
$log     = 'C:\LabTools\fiddler-trust.log'
function Say([string]$m) {
    $line = "$(Get-Date -Format s)  $m"
    Write-Output $line
    try { Add-Content -Path $log -Value "$line  [$env:USERNAME]" } catch { }
}

# Already trusted for this user? Then there is nothing to do.
$trusted = Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
$mine = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1

if ($trusted -and $mine) { Say 'Fiddler root CA already present and trusted - nothing to do.'; return }

if (-not $mine) {
    # Fiddler's own default is SHA-1 (MakeCertParamsRoot); we use SHA-256 because
    # SHA-1 roots are rejected on current Windows. Fiddler locates the root by CN,
    # so a stronger cert with the same subject is adopted normally.
    $mine = New-SelfSignedCertificate `
        -Subject $subject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy Exportable `
        -KeyLength 2048 `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2) `
        -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=0',
                         '2.5.29.37={text}1.3.6.1.5.5.7.3.1')
    Say "Generated root CA  $($mine.Thumbprint)"
} else {
    Say "Reusing existing root CA  $($mine.Thumbprint)"
}

if (-not $trusted) {
    # Public part only - the private key stays in the user's My store.
    $pub   = [Security.Cryptography.X509Certificates.X509Certificate2]::new($mine.RawData)
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    $store.Open('ReadWrite')      # needs elevation; the logon task supplies it
    $store.Add($pub)
    $store.Close()
    Say 'Installed into LocalMachine\Root (no prompt - this is the whole trick).'
}

# Turn HTTPS decryption on ahead of time. Fiddler keeps about:config prefs here.
# Best effort only: the pref names are not a documented contract, so if Telerik
# renames one the participant just ticks the box by hand - a 5-second click, not
# the 10-minute certificate dance this script exists to remove.
try {
    $fid = 'HKCU:\Software\Microsoft\Fiddler2'
    if (-not (Test-Path $fid)) { New-Item -Path $fid -Force | Out-Null }
    Set-ItemProperty -Path $fid -Name 'fiddler.network.https.CaptureHTTPS'          -Value 'True'
    Set-ItemProperty -Path $fid -Name 'fiddler.network.https.DecryptHTTPS'          -Value 'True'
    Set-ItemProperty -Path $fid -Name 'fiddler.network.https.IgnoreServerCertErrors' -Value 'True'
    Say 'HTTPS decryption preferences written (verify in Tools > Options > HTTPS).'
} catch {
    Say "Could not write Fiddler preferences: $($_.Exception.Message)"
}

Say 'DONE. Start Fiddler as administrator - there should be no certificate prompt.'
'@
try {
    Set-Content -Path $fidTrust -Value $fidTrustBody -Encoding UTF8
    $act  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$fidTrust`""
    $trg  = New-ScheduledTaskTrigger -AtLogOn
    # A group principal so the task fires for whichever lab user signs in.
    # RunLevel Highest is what lets it write LocalMachine\Root with no UAC prompt.
    $prin = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Highest
    Register-ScheduledTask -TaskName 'LabSetupFiddlerTrust' -Action $act -Trigger $trg `
        -Principal $prin -Description 'Pre-trusts the Fiddler root CA for the Azure Files lab' -Force | Out-Null
    Write-Output 'Fiddler trust task registered (runs at each logon; idempotent)'
} catch {
    Write-Output "Could not register the Fiddler trust task ($($_.Exception.Message.Split([char]10)[0])) - run $fidTrust by hand"
}

Write-Output 'CLIENT_CONFIG_DONE_REBOOTING'
shutdown /r /t 10 /f
