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

# 2. Trigger hybrid join (device reads the SCP from AD and registers with Entra)
$task = Get-ScheduledTask -TaskName 'Automatic-Device-Join' `
    -TaskPath '\Microsoft\Windows\Workplace Join\' -ErrorAction SilentlyContinue
if ($task) { $task | Start-ScheduledTask }
dsregcmd /join /debug 2>&1 | Select-Object -Last 5 | Write-Output

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

Write-Output 'CLIENT_CONFIG_DONE_REBOOTING'
shutdown /r /t 10 /f
