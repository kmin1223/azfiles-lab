# Runs ON the DC VM via Run Command. Installs AD DS and promotes a new forest.
# Args: -DomainName contoso.local -SafeModePassword <pw>
param(
    [string]$DomainName = 'contoso.local',
    [string]$SafeModePassword
)
$ErrorActionPreference = 'Stop'

if (Get-Service NTDS -ErrorAction SilentlyContinue) {
    Write-Output 'ALREADY_PROMOTED'
    exit 0
}

Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null

$sec = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force
Import-Module ADDSDeployment

# NoRebootOnCompletion so Run Command returns cleanly; reboot is scheduled below.
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName ($DomainName.Split('.')[0].ToUpper()) `
    -SafeModeAdministratorPassword $sec `
    -InstallDns `
    -NoRebootOnCompletion `
    -Force | Out-Null

Write-Output 'PROMOTED_REBOOTING'
shutdown /r /t 10 /f
