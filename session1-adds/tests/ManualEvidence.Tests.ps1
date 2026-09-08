$sessionRoot = Split-Path $PSScriptRoot -Parent
$commands = Join-Path $sessionRoot 'Get-LabCommands.ps1'
$deployment = Get-Content (Join-Path $sessionRoot 'deploy.ps1') -Raw
$tools = Get-Content (Join-Path $sessionRoot 'scripts\07-install-tools.ps1') -Raw
function Get-AzStorageAccount {}
function Get-AzPublicIpAddress {}

Describe 'Manual evidence rollback for fresh deployments' {
    It 'does not provision or dispatch to automatic evidence' {
        ($deployment + $tools) | Should Not Match 'Update-LabEvidenceAutomation|Invoke-LabEvidenceAutomation|AUTO_EVIDENCE_READY|StartTrace -Manual'
        $tools | Should Match ([regex]::Escape("C:\LabTools\evidence"))
        foreach ($name in @('Update-LabEvidenceAutomation.ps1',
                'scripts\Invoke-LabEvidenceAutomation.ps1',
                'scripts\Install-LabEvidenceAutomation.ps1')) {
            Test-Path (Join-Path $sessionRoot $name) | Should Be $false
        }
    }
    It 'keeps the requested password forwarding separate from removed automation' {
        $deployment | Should Match '-AdminUsername \$AdminUsername -AdminPassword \$AdminPassword -OutFile \$cmdFile'
        $deployment | Should Match 'PRIVATE: includes the VM password in plaintext'
    }
    It 'parses restored deployment scripts without executing deployment' {
        foreach ($path in @('deploy.ps1','Get-LabCommands.ps1','scripts\07-install-tools.ps1',
                'scripts\03-join-domain-client.ps1')) {
            $tokens=$null; $errors=$null
            [void][Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $sessionRoot $path), [ref]$tokens, [ref]$errors)
            $errors.Count | Should Be 0
        }
    }
}

Describe 'Private manual command sheets' {
    BeforeEach {
        Mock Get-AzStorageAccount {
            [pscustomobject]@{
                StorageAccountName='azflabfixture'
                AzureFilesIdentityBasedAuth=[pscustomobject]@{
                    DirectoryServiceOptions='AD'
                    ActiveDirectoryProperties=[pscustomobject]@{
                        NetBiosDomainName='CONTOSO'; DomainName='contoso.local'
                    }
                }
            }
        }
        Mock Get-AzPublicIpAddress { @() }
        Mock Write-Host {}
    }
    It 'prints the manual three-step flow with the supplied private password' {
        $file = Join-Path $TestDrive 'private.txt'
        $password = 'fixture-' + [guid]::NewGuid().ToString('N')
        & $commands -ResourceGroupName fixture -AdminUsername trainingadmin `
            -AdminPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
            -OutFile $file | Out-Null
        $text = Get-Content $file -Raw
        $text.Contains("VM password: $password") | Should Be $true
        $text | Should Match 'CONTOSO\\trainingadmin'
        $text | Should Match 'Get-KerberosEvidence.ps1 -StartTrace'
        $text | Should Match 'Get-KerberosEvidence.ps1 -Reproduce'
        $text | Should Match 'Get-KerberosEvidence.ps1 -StopTrace'
        $text | Should Not Match 'AUTO_EVIDENCE_READY|StartTrace -Manual|Update-LabEvidenceAutomation'
        $text | Should Match 'Do not screen-share or commit'
    }
    It 'does not claim to retrieve a password for standalone runs' {
        $file = Join-Path $TestDrive 'no-password.txt'
        & $commands -ResourceGroupName fixture -OutFile $file | Out-Null
        (Get-Content $file -Raw) | Should Match 'VM password: Not supplied'
    }
}
