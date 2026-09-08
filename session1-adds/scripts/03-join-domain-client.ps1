# Runs ON the client VM via Run Command. Joins the AD domain and reboots.
# Args: -DomainName contoso.local -JoinUser labadmin -JoinPassword <pw>
param(
    [string]$DomainName = 'contoso.local',
    [string]$JoinUser,
    [string]$JoinPassword,
    # Lab users that need to elevate ON THIS CLIENT (see Grant-LocalAdmin).
    [string[]]$LabUsers = @('labuser1', 'labuser2')
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

function Grant-LocalAdmin {
    # Keep local admin membership for manual lab commands: with the default
    # UAC policy, elevation needs consent rather than another password.
    # This does NOT guarantee the same LUID, ticket cache or SMB connections
    # between normal and elevated windows. Manual reproduction stays in the
    # affected user's normal window; the automatic worker uses a fresh,
    # non-elevated batch token and SYSTEM performs the capture.
    #
    # This grants nothing on the file share: Azure Files authorises from the
    # Kerberos PAC (domain groups), which local group membership never enters.
    foreach ($u in $LabUsers) {
        try {
            Add-LocalGroupMember -Group 'Administrators' -Member "$netbios\$u" -ErrorAction Stop
            Write-Output "LOCAL_ADMIN_ADDED $u"
        } catch [Microsoft.PowerShell.Commands.MemberExistsException] {
            Write-Output "LOCAL_ADMIN_ALREADY_SET $u"
        } catch {
            # Non-fatal: a missing user must not fail the domain join.
            Write-Output "LOCAL_ADMIN_SKIPPED $u ($($_.Exception.Message))"
        }
    }
}

if ((Get-CimInstance Win32_ComputerSystem).Domain -eq $DomainName) {
    Grant-RdpToDomainUsers
    Grant-LocalAdmin
    Write-Output 'ALREADY_JOINED'
    exit 0
}

$sec = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$netbios\$JoinUser", $sec)

Add-Computer -DomainName $DomainName -Credential $cred -Force
Grant-RdpToDomainUsers
Grant-LocalAdmin
Write-Output 'JOINED_REBOOTING'
# 60s, not 10: the Run Command extension needs time to report this script's
# output back to Azure. Rebooting too soon leaves the operation looking failed
# even though the join succeeded, which forces a pointless retry. The reboot
# overlaps other deployment work anyway, so the extra 50s costs nothing.
shutdown /r /t 60 /f
