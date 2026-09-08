$sessionRoot = Split-Path $PSScriptRoot -Parent
$commandSheet = Join-Path $sessionRoot 'Get-LabCommands.ps1'
$deploySource = Get-Content (Join-Path $sessionRoot 'deploy.ps1') -Raw

function Get-AzStorageAccount {}
function Get-AzPublicIpAddress {}

Describe 'Automatic evidence deployment wiring' {
    It 'passes the actual deployment login and password to the private command sheet' {
        $deploySource | Should Match '-AdminUsername \$AdminUsername -AdminPassword \$AdminPassword -OutFile \$cmdFile'
        $deploySource | Should Match 'PRIVATE: includes the VM password in plaintext'
    }
    It 'passes the existing secure credential to the update wrapper, not VM parameters' {
        $deploySource | Should Match '\[PSCredential\]::new\("\$\(\$ad.NetBiosDomainName\)\\labuser1", \$AdminPassword\)'
        $deploySource | Should Match '-LabCredential \$evidenceCredential'
        $deploySource | Should Match 'one-command collector is NOT ready'
        $deploySource.LastIndexOf('Update-LabEvidenceAutomation.ps1') | Should BeGreaterThan $deploySource.IndexOf("ScriptFile '07-install-tools.ps1'")
    }
}

Describe 'Generated command sheet uses automatic and explicit manual flows' {
    BeforeEach {
        Mock Get-AzStorageAccount {
            [pscustomobject]@{
                StorageAccountName = 'customlabstorage'
                AzureFilesIdentityBasedAuth = [pscustomobject]@{
                    DirectoryServiceOptions = 'AD'
                    ActiveDirectoryProperties = [pscustomobject]@{
                        NetBiosDomainName = 'CONTOSO'; DomainName = 'CONTOSO'; ForestName = 'contoso.local'
                    }
                }
            }
        }
        Mock Get-AzPublicIpAddress { @() }
        Mock Write-Host {}
    }
    It 'uses ForestName when Legacy metadata has a NetBIOS-only DomainName' {
        $destination = Join-Path $TestDrive 'commands.txt'
        & $commandSheet -ResourceGroupName lab-rg -Prefix custom -Share evidence -OutFile $destination
        $text = Get-Content $destination -Raw
        $text | Should Match 'Get-KerberosEvidence.ps1 -StartTrace -Manual -DomainController ''custom-dc.contoso.local'''
        $text | Should Match 'Update-LabEvidenceAutomation.ps1 -ResourceGroupName lab-rg -Prefix custom -StorageAccount customlabstorage -Share evidence'
        $text | Should Match 'original window''s klist is NOT'
        $text | Should Match 'user\\dc-summary.txt'
        $text | Should Not Match 'step 2 - retest. DROP THE SMB SESSION'
        $text | Should Match 'VM password: Not supplied'
    }
    It 'preserves an explicit authoritative DC target' {
        $destination = Join-Path $TestDrive 'explicit.txt'
        & $commandSheet -ResourceGroupName lab-rg -Prefix custom -DomainController dc.training.local -OutFile $destination
        $text = Get-Content $destination -Raw
        $text | Should Match 'DomainController ''dc.training.local'''
        $text | Should Not Match 'DomainController ''custom-dc.contoso.local'''
    }
    It 'includes the supplied password literally in the saved and returned sheet' {
        $destination = Join-Path $TestDrive 'private-commands.txt'
        $password = 'fixture-$`''"&-' + [guid]::NewGuid().ToString('N')
        $secure = ConvertTo-SecureString $password -AsPlainText -Force
        $output = & $commandSheet -ResourceGroupName lab-rg -Prefix custom `
            -AdminUsername trainingadmin -AdminPassword $secure -OutFile $destination
        $text = Get-Content $destination -Raw
        $text.Contains("VM password: $password") | Should Be $true
        $output.Contains("VM password: $password") | Should Be $true
        $text | Should Match 'VM accounts: CONTOSO\\trainingadmin, CONTOSO\\labuser1, CONTOSO\\labuser2'
        $text | Should Match 'DC VM\s+mstsc /v:<dc-ip>\s+CONTOSO\\trainingadmin only'
        $text | Should Match 'PRIVATE LAB FILE: contains a plaintext password'
        $text | Should Not Match 'VM password: Not supplied'
        ([System.Net.NetworkCredential]::new('', $secure).Password) | Should Be $password
    }
}
