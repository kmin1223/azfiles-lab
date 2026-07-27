# Runs ON the client VM. Enables cloud Kerberos ticket retrieval and kicks
# hybrid-join registration, then reboots so the changes fully apply.
$ErrorActionPreference = 'Stop'

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

Write-Output 'CLIENT_CONFIG_DONE_REBOOTING'
shutdown /r /t 10 /f
