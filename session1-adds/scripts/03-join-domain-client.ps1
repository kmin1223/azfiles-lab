# Runs ON the client VM via Run Command. Joins the AD domain and reboots.
# Args: -DomainName contoso.local -JoinUser labadmin -JoinPassword <pw>
param(
    [string]$DomainName = 'contoso.local',
    [string]$JoinUser,
    [string]$JoinPassword
)
$ErrorActionPreference = 'Stop'

$netbios = $DomainName.Split('.')[0].ToUpper()

function Grant-RdpToDomainUsers {
    # Plain domain users can't RDP by default - add them to the local group.
    try {
        Add-LocalGroupMember -Group 'Remote Desktop Users' `
            -Member "$netbios\Domain Users" -ErrorAction Stop
        Write-Output 'RDP_GROUP_UPDATED'
    } catch [Microsoft.PowerShell.Commands.MemberExistsException] {
        Write-Output 'RDP_GROUP_ALREADY_SET'
    }
}

if ((Get-CimInstance Win32_ComputerSystem).Domain -eq $DomainName) {
    Grant-RdpToDomainUsers
    Write-Output 'ALREADY_JOINED'
    exit 0
}

$sec = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$netbios\$JoinUser", $sec)

Add-Computer -DomainName $DomainName -Credential $cred -Force
Grant-RdpToDomainUsers
Write-Output 'JOINED_REBOOTING'
# 60s, not 10: the Run Command extension needs time to report this script's
# output back to Azure. Rebooting too soon leaves the operation looking failed
# even though the join succeeded, which forces a pointless retry. The reboot
# overlaps other deployment work anyway, so the extra 50s costs nothing.
shutdown /r /t 60 /f
