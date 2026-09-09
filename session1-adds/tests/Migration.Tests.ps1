$migrationFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'labs\Invoke-Aes256Migration.ps1'

# Execute the orchestrator and generated DC payloads with all remote mutations mocked.
function Get-AzStorageAccount { param($ResourceGroupName, $Name) throw 'Unmocked Azure read' }
function Set-AzStorageAccount {
    param($ResourceGroupName, $Name, $EnableActiveDirectoryDomainServicesForFile,
        $ActiveDirectoryDomainName, $ActiveDirectoryNetBiosDomainName,
        $ActiveDirectoryForestName, $ActiveDirectoryDomainGuid, $ActiveDirectoryDomainSid,
        $ActiveDirectoryAzureStorageSid, $ActiveDirectorySamAccountName, $ActiveDirectoryAccountType)
    throw 'Unmocked Azure write'
}
function New-AzStorageAccountKey { param($ResourceGroupName, $Name, $KeyName) throw 'Unmocked key rotation' }
function Get-AzStorageAccountKey { param($ResourceGroupName, $Name, [switch]$ListKerbKey) throw 'Unmocked key read' }
function Invoke-AzVMRunCommand { param($ResourceGroupName, $VMName, $CommandId, $ScriptPath) throw 'Unmocked remote call' }
function Get-ADDomain { throw 'Unmocked AD read' }
function Get-ADComputer { param($Identity, $Server) throw 'Unmocked AD read' }
function Set-ADComputer { param($Identity, $Server, $KerberosEncryptionType) throw 'Unmocked AD write' }
function Set-ADAccountPassword { param($Identity, $Server, [switch]$Reset, $NewPassword) throw 'Unmocked password write' }
function Get-ADDomainController { param($Filter, $Server) throw 'Unmocked topology read' }
function repadmin { throw 'Unmocked replication' }

Describe 'Migration remote-call batching' {
    BeforeEach {
        $script:operations = New-Object 'System.Collections.Generic.List[string]'
        $script:controllerCount = 1
        $script:replicationExit = 0
        $script:properties = [pscustomobject]@{
            DomainName = 'contoso.local'; NetBiosDomainName = 'CONTOSO'
            ForestName = 'contoso.local'; DomainGuid = 'test-guid'; DomainSid = 'test-sid'
            AzureStorageSid = 'test-storage-sid'; SamAccountName = 'azflabtest'; AccountType = 'Computer'
        }
        Mock Get-AzStorageAccount {
            [pscustomobject]@{
                StorageAccountName = 'azflabtest'
                AzureFilesIdentityBasedAuth = [pscustomobject]@{ ActiveDirectoryProperties = $properties }
            }
        }
        Mock Set-AzStorageAccount { $operations.Add('metadata'); $properties.DomainName = $ActiveDirectoryDomainName }
        Mock New-AzStorageAccountKey { $operations.Add('rotate') }
        Mock Start-Sleep { $operations.Add("wait:$Seconds") }
        Mock Get-AzStorageAccountKey {
            $operations.Add('key-read')
            [pscustomobject]@{ KeyName = 'kerb1'; Value = "mock_key_with'quote" }
        }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADDomain { [pscustomobject]@{ PDCEmulator = 'azflab-dc.contoso.local'; DNSRoot = 'contoso.local' } }
        Mock Get-ADComputer { [pscustomobject]@{ DistinguishedName = 'CN=azflabtest,DC=contoso,DC=local' } }
        Mock Set-ADComputer { $operations.Add("encryption:$KerberosEncryptionType") }
        Mock Set-ADAccountPassword { $operations.Add('password') }
        Mock Get-ADDomainController {
            1..$controllerCount | ForEach-Object { [pscustomobject]@{ Name = "dc$_" } }
        }
        Mock repadmin { $operations.Add('replication'); $global:LASTEXITCODE = $replicationExit }
        Mock Write-Host {}
        Mock Invoke-AzVMRunCommand {
            if ($VMName -eq 'azflab-dc') {
                $operations.Add('dc-call')
                $payload = Get-Content -LiteralPath $ScriptPath -Raw
                $output = @(& ([scriptblock]::Create($payload))) -join "`n"
            } else { throw 'Unexpected VM' }
            [pscustomobject]@{ Value = @([pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = $output }) }
        }
    }

    It 'applies Legacy in one DC call without client verification and reports configuration success only' {
        & $migrationFile -ResourceGroupName azfiles-lab -Step Legacy
        ($operations -join ',') | Should Be 'metadata,rotate,wait:15,key-read,dc-call,encryption:RC4,password'
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It -ParameterFilter { $VMName -eq 'azflab-dc' }
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It -ParameterFilter { $VMName -eq 'azflab-cli' }
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter {
            $Object -eq 'Legacy configuration applied successfully. Mount verification was not run.'
        }
        Assert-MockCalled repadmin -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-ADComputer -Times 1 -Exactly -Scope It -ParameterFilter {
            $Server -eq 'azflab-dc.contoso.local' -and $KerberosEncryptionType -eq 'RC4'
        }
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It -ParameterFilter {
            ($Object -join ' ') -like '*mock_key*'
        }
    }

    It 'retains replication for multiple DCs in Legacy and Enforce' {
        $script:controllerCount = 2
        & $migrationFile -ResourceGroupName azfiles-lab -Step Legacy
        & $migrationFile -ResourceGroupName azfiles-lab -Step Enforce
        Assert-MockCalled repadmin -Times 2 -Exactly -Scope It
    }

    It 'keeps Enforce to one DC call and skips single-DC replication without rotating keys' {
        & $migrationFile -ResourceGroupName azfiles-lab -Step Enforce
        ($operations -join ',') | Should Be 'dc-call,encryption:AES256'
        Assert-MockCalled repadmin -Times 0 -Exactly -Scope It
        Assert-MockCalled New-AzStorageAccountKey -Times 0 -Exactly -Scope It
    }

    It 'preserves Repair encryption policy while using the shared password-sync path' {
        & $migrationFile -ResourceGroupName azfiles-lab -Step Repair
        Assert-MockCalled Set-ADComputer -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-ADAccountPassword -Times 1 -Exactly -Scope It
        Assert-MockCalled repadmin -Times 0 -Exactly -Scope It
        $properties.DomainName | Should Be 'contoso.local'
    }

    It 'does not report success after a failed DC update' {
        Mock Set-ADComputer { throw 'Mock AD update failure' }
        { & $migrationFile -ResourceGroupName azfiles-lab -Step Legacy } | Should Throw
        Assert-MockCalled Set-ADAccountPassword -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It -ParameterFilter { $VMName -eq 'azflab-cli' }
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It
    }

    It 'stops on an Azure settings failure without rotating keys or reporting success' {
        Mock Set-AzStorageAccount { throw 'Mock Azure update failure' }
        { & $migrationFile -ResourceGroupName azfiles-lab -Step Legacy } | Should Throw
        Assert-MockCalled New-AzStorageAccountKey -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It
    }

    It 'does not report success when the DC completion marker is missing' {
        Mock Invoke-AzVMRunCommand {
            [pscustomobject]@{ Value = @([pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = 'partial output' }) }
        }
        { & $migrationFile -ResourceGroupName azfiles-lab -Step Legacy } | Should Throw
        Assert-MockCalled Write-Host -Times 0 -Exactly -Scope It
    }

    It 'keeps detailed Legacy commands available through verbose output without exposing keys' {
        Mock Write-Verbose {}
        & $migrationFile -ResourceGroupName azfiles-lab -Step Legacy -Verbose
        Assert-MockCalled Write-Verbose -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like '*Set-ADAccountPassword*' -and $Message -like '*<kerb1-key>*'
        }
        Assert-MockCalled Write-Verbose -Times 0 -Exactly -Scope It -ParameterFilter {
            $Message -like '*mock_key*'
        }
    }

    It 'surfaces replication failures instead of reporting completion' {
        $script:controllerCount = 2
        $script:replicationExit = 1
        { & $migrationFile -ResourceGroupName azfiles-lab -Step Enforce } | Should Throw
    }

    It 'rejects incomplete Run Command output' {
        Mock Invoke-AzVMRunCommand {
            [pscustomobject]@{ Value = @([pscustomobject]@{ Code = 'ComponentStatus/StdOut/succeeded'; Message = 'partial output' }) }
        }
        { & $migrationFile -ResourceGroupName azfiles-lab -Step Enforce } | Should Throw
    }

    It 'keeps Rollback as the Legacy alias' {
        & $migrationFile -ResourceGroupName azfiles-lab -Step Rollback
        ($operations -join ',') | Should Be 'metadata,rotate,wait:15,key-read,dc-call,encryption:RC4,password'
    }
}
