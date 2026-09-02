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
param([Parameter(Mandatory)] [string]$DnsSuffix)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
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

# 4. Fiddler + the Kerberos.NET inspector. This is the ONLY way to read the KDC
#    Proxy exchange - it is HTTPS, so a packet capture shows encrypted TCP and
#    nothing else. The capstone turns on reading the response ErrorCode.
#    Best effort: never fail a deployment over a diagnostic tool.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not (Test-Path 'C:\Program Files*\Fiddler*\Fiddler.exe')) {
        $f = Join-Path $tools 'FiddlerSetup.exe'
        Invoke-WebRequest -Uri 'https://telerik-fiddler.s3.amazonaws.com/fiddler/FiddlerSetup.exe' `
            -OutFile $f -UseBasicParsing -ErrorAction Stop
        Start-Process -FilePath $f -ArgumentList '/S' -Wait
        Write-Output 'Fiddler Classic installed'
    }
    $k = Join-Path $tools 'Fiddler.Kerberos.NET.exe'
    Invoke-WebRequest -Uri 'https://github.com/dotnet/Kerberos.NET/releases/latest/download/Fiddler.Kerberos.NET.exe' `
        -OutFile $k -UseBasicParsing -ErrorAction Stop
    Start-Process -FilePath $k -ArgumentList '/S' -Wait -ErrorAction SilentlyContinue
    Write-Output 'Kerberos.NET inspector staged'
} catch {
    Write-Output "Fiddler tooling not fully installed ($($_.Exception.Message.Split([char]10)[0])) - install from C:\LabTools if needed"
}

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
    Set-ItemProperty -Path $fid -Name 'fiddler.network.https.IgnoreServerCertErrors' -Value 'True'
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
