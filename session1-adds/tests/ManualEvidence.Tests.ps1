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
    It 'prints the command-sheet notice last and only after successful generation' {
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseInput(
            $deployment, [ref]$tokens, [ref]$errors)
        $statements = $ast.EndBlock.Statements
        $notice = $statements[-2].Extent.Text
        $notice | Should Match '^if \(\$commandSheetReady\)'
        $statements[-1].Extent.Text | Should Match 'Stop-Transcript \| Out-Null'
        $deployment | Should Not Match 'again:'
        $deployment | Should Match '\$commandSheetReady = \$false'
        $deployment | Should Match '-OutFile \$cmdFile \| Out-Null\s+\$commandSheetReady = \$true'
        Mock Write-Host {}
        $cmdFile = 'fixture-commands.txt'
        $commandSheetReady = $false
        & ([scriptblock]::Create($notice))
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It
        $commandSheetReady = $true
        & ([scriptblock]::Create($notice))
        Assert-MockCalled Write-Host -Times 4 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -eq '   view:  Get-Content fixture-commands.txt'
        }
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
    It 'uses only the all-connections reset and ticket purge without redundant target deletions' {
        $file = Join-Path $TestDrive 'reset-commands.txt'
        & $commands -ResourceGroupName fixture -OutFile $file | Out-Null
        $text = Get-Content $file -Raw
        $text | Should Not Match 'net use (?:Z:|\\\\\S+) /delete /y'
        $reset = 'net use \* /delete /y\r?\n\s+klist purge'
        ([regex]::Matches($text, $reset)).Count | Should Be 2
        $text | Should Match 'net use \* /delete /y ; klist purge ; net use Z:'
        $text | Should Match 'Open handles can keep an SMB session alive'
    }
    It 'fills salt comparison commands with deployment values and preserves runtime variables' {
        $file = Join-Path $TestDrive 'salt-commands.txt'
        & $commands -ResourceGroupName 'training-rg' -OutFile $file | Out-Null
        $text = Get-Content $file -Raw
        $text.Contains('$rg = ''training-rg''') | Should Be $true
        ([regex]::Matches($text, [regex]::Escape('$sa = ''azflabfixture'''))).Count | Should Be 2
        $text.Contains('$ad = (Get-AzStorageAccount -ResourceGroupName $rg -Name $sa).AzureFilesIdentityBasedAuth.ActiveDirectoryProperties') | Should Be $true
        $text.Contains('$ad | Format-List DomainName, NetBiosDomainName, SamAccountName, AccountType') | Should Be $true
        $text.Contains('$pdc = $domain.PDCEmulator') | Should Be $true
        $text.Contains('Get-ADDomain -Server $pdc | Format-List DNSRoot, NetBIOSName') | Should Be $true
        $text.Contains('Get-ADComputer -Identity $sa -Server $pdc -Properties ServicePrincipalName | Format-List SamAccountName, ObjectClass, ServicePrincipalName') | Should Be $true
        $blocks = [regex]::Matches($text, '(?m)^\[[AB]\] (?:Cloud Shell - read|Client VM - read)[^\r\n]*\r?\n((?:    [^\r\n]+\r?\n)+)')
        $blocks.Count | Should Be 2
        foreach ($block in $blocks) {
            $tokens = $null; $errors = $null
            [void][Management.Automation.Language.Parser]::ParseInput(
                $block.Groups[1].Value, [ref]$tokens, [ref]$errors)
            $errors.Count | Should Be 0
        }
    }
}
