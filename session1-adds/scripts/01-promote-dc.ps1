# Runs ON the DC VM via Run Command. Installs AD DS and promotes a new forest.
# Args: -DomainName contoso.local -SafeModePassword <pw>
param(
    [string]$DomainName = 'contoso.local',
    [string]$SafeModePassword
)
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'   # see the note above Install-ADDSForest

if (Get-Service NTDS -ErrorAction SilentlyContinue) {
    Write-Output 'ALREADY_PROMOTED'
    exit 0
}

Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null

$sec = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force
Import-Module ADDSDeployment

# NoRebootOnCompletion so Run Command returns cleanly; reboot is scheduled below.
#
# WarningAction SilentlyContinue: Install-ADDSForest emits the same three
# warnings twice (precheck + install), and all are expected in this lab:
#   - "no static IP": Azure guests use DHCP by design; the address IS static,
#     assigned in the ARM template at the fabric level (10.100.0.4)
#   - "DNS delegation cannot be created": isolated lab forest, no parent zone
#   - "NT4 crypto algorithms": informational default on WS2022
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName ($DomainName.Split('.')[0].ToUpper()) `
    -SafeModeAdministratorPassword $sec `
    -InstallDns `
    -NoRebootOnCompletion `
    -WarningAction SilentlyContinue `
    -Force | Out-Null

Write-Output 'PROMOTED_REBOOTING (expected AD DS warnings suppressed: fabric-static IP / no parent DNS zone / NT4 crypto notice)'
shutdown /r /t 10 /f
