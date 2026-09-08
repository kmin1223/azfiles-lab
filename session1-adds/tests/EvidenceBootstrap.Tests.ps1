$wrapper = Join-Path (Split-Path $PSScriptRoot -Parent) 'Update-LabEvidenceAutomation.ps1'
$tokens = $null; $parseErrors = $null
$wrapperAst = [Management.Automation.Language.Parser]::ParseFile($wrapper, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Bootstrap wrapper must parse before tests can load its functions.' }
foreach ($definition in $wrapperAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
}, $true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}

function New-TestEvidenceRsa {
    $rsa = if ($PSVersionTable.PSVersion.Major -le 5) { New-Object Security.Cryptography.RSACng }
           else { [Security.Cryptography.RSA]::Create() }
    $rsa.KeySize = 4096
    return $rsa
}
function New-TestEvidencePublicKey {
    param($Rsa, [string]$RunId)
    $parameters = $Rsa.ExportParameters($false)
    [pscustomobject]@{
        RunId = $RunId; Thumbprint = ('A' * 40)
        Modulus = [Convert]::ToBase64String($parameters.Modulus)
        Exponent = [Convert]::ToBase64String($parameters.Exponent)
    }
}
function New-TestEvidenceResult {
    param([string]$Marker, $Payload, [string]$StdErr = '')
    [pscustomobject]@{ Value = @(
        [pscustomobject]@{Code='ComponentStatus/StdOut/succeeded'; Message=($Marker + ($Payload | ConvertTo-Json -Compress))},
        [pscustomobject]@{Code='ComponentStatus/StdErr/succeeded'; Message=$StdErr}
    ) }
}

Describe 'Evidence bootstrap syntax and literal sources' {
    It 'parses as Windows PowerShell source' {
        $errors = $null; $lex = $null
        $null = [Management.Automation.Language.Parser]::ParseFile($wrapper, [ref]$lex, [ref]$errors)
        $errors.Count | Should Be 0
    }
    It 'extracts the real embedded helper without running the tools installer' {
        $path = Join-Path (Split-Path $wrapper -Parent) 'scripts\07-install-tools.ps1'
        $source = Get-EvidenceHelperSource $path
        $source | Should Match 'function'
        $errors = $null; $lex = $null
        $null = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$lex, [ref]$errors)
        $errors.Count | Should Be 0
    }
    It 'never evaluates unrelated tools code' {
        $path = Join-Path $TestDrive 'literal.ps1'
        @'
throw 'MUST NEVER EXECUTE'
$helper = 'param(); Write-Output "helper"'
'@ | Set-Content $path
        (Get-EvidenceHelperSource $path) | Should Be 'param(); Write-Output "helper"'
    }
    It 'rejects dynamic and ambiguous helper assignments' {
        $path = Join-Path $TestDrive 'dynamic.ps1'
        '$helper = "$(throw ''executed'')"' | Set-Content $path
        { Get-EvidenceHelperSource $path } | Should Throw
        '$helper = ''one''; $helper = ''two''' | Set-Content $path
        { Get-EvidenceHelperSource $path } | Should Throw
    }
    It 'stages non-ASCII helper source with a UTF-8 BOM' {
        $source = 'param(); # ' + [char]0xD55C
        $bytes = [Convert]::FromBase64String((ConvertTo-EvidenceSourceBase64 $source))
        [BitConverter]::ToString($bytes[0..2]) | Should Be 'EF-BB-BF'
        [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) | Should Be $source
    }
}

Describe 'Evidence bootstrap target validation' {
    It 'accepts lab DNS and share targets' {
        { Assert-EvidenceBootstrapConfig 'azflab123' 'labshare' 'azflab-dc.contoso.local' } | Should Not Throw
        { Assert-EvidenceBootstrapConfig 'azflab123' 'lab-share' 'dc.child.contoso.local' } | Should Not Throw
    }
    It 'rejects malformed or injectable targets' {
        foreach ($account in @('ABC', 'ab', ('a' * 25), 'abc;whoami')) {
            { Assert-EvidenceBootstrapConfig $account 'labshare' 'dc.contoso.local' } | Should Throw
        }
        foreach ($share in @('ab', '-abc', 'abc-', 'abc--def', 'ABC', 'abc/def', ('a' * 64))) {
            { Assert-EvidenceBootstrapConfig 'azflab123' $share 'dc.contoso.local' } | Should Throw
        }
        foreach ($dc in @('CONTOSO', '\\dc.contoso.local', 'dc.contoso.local;whoami', '-dc.contoso.local', 'dc..local', 'dc.local/path')) {
            { Assert-EvidenceBootstrapConfig 'azflab123' 'labshare' $dc } | Should Throw
        }
    }
}

Describe 'Evidence bootstrap RSA envelope' {
    BeforeAll {
        $script:cryptoRsa = New-TestEvidenceRsa
        $script:cryptoPublic = New-TestEvidencePublicKey $cryptoRsa ('1' * 32)
    }
    AfterAll { $script:cryptoRsa.Dispose() }
    It 'round-trips the password with OAEP SHA256 and RSA4096 only in memory' {
        $password = 'fixture-only-' + [char]0xD55C + '-not-a-real-password'
        $credential = New-Object Management.Automation.PSCredential('CONTOSO\labuser1', (ConvertTo-SecureString $password -AsPlainText -Force))
        $encrypted = Protect-EvidenceBootstrapPassword $credential $cryptoPublic
        $encrypted | Should Not Match ([regex]::Escape($password))
        $cipher = [Convert]::FromBase64String($encrypted)
        $cipher.Length | Should Be 512
        $plain = $cryptoRsa.Decrypt($cipher, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        try { [Text.Encoding]::UTF8.GetString($plain) | Should Be $password }
        finally { [Array]::Clear($plain, 0, $plain.Length); $credential.Password.Dispose() }
    }
    It 'rejects a tampered ciphertext instead of recovering a credential' {
        $credential = New-Object Management.Automation.PSCredential('CONTOSO\labuser1', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        $cipher = [Convert]::FromBase64String((Protect-EvidenceBootstrapPassword $credential $cryptoPublic))
        $cipher[31] = $cipher[31] -bxor 1
        { $cryptoRsa.Decrypt($cipher, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256) } | Should Throw
    }
    It 'accepts the exact OAEP boundary and rejects oversized UTF-8 with an actionable error' {
        $credential = New-Object Management.Automation.PSCredential('CONTOSO\labuser1', (ConvertTo-SecureString ('x' * 446) -AsPlainText -Force))
        { Protect-EvidenceBootstrapPassword $credential $cryptoPublic } | Should Not Throw
        $credential = New-Object Management.Automation.PSCredential('CONTOSO\labuser1', (ConvertTo-SecureString ([string][char]0xD55C * 149) -AsPlainText -Force))
        { Protect-EvidenceBootstrapPassword $credential $cryptoPublic } | Should Throw '446-byte'
    }
    It 'rejects malformed or downgraded public keys' {
        { Protect-EvidenceBootstrapPassword $null ([pscustomobject]@{Modulus='not base64'; Exponent='AQAB'}) } | Should Throw
        { Protect-EvidenceBootstrapPassword $null ([pscustomobject]@{Modulus=[Convert]::ToBase64String((New-Object byte[] 256)); Exponent='AQAB'}) } | Should Throw
    }
}

Describe 'Evidence bootstrap GUID-bound results' {
    It 'requires a unique matching marker in stdout' {
        $id = '1' * 32
        $result = New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$id}
        (Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' $id).RunId | Should Be $id
        { Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' ('2' * 32) } | Should Throw
        { Read-EvidenceBootstrapMarker $result 'BOOTSTRAP_PUBLIC:' $id } | Should Throw
        $result.Value[0].Message += "`n" + $result.Value[0].Message
        { Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' $id } | Should Throw
    }
    It 'rejects stderr even when the transport and marker succeed' {
        $id = '1' * 32
        $result = New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$id} 'remote failure'
        { Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' $id } | Should Throw
    }
    It 'rejects failed component status and malformed marker JSON' {
        $id = '1' * 32
        $result = New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$id}
        $result.Value += [pscustomobject]@{Code='ProvisioningState/failed';Message='failed'}
        { Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' $id } | Should Throw
        $result = New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$id}
        $result.Value[0].Message = 'AUTO_EVIDENCE_READY:not-json'
        { Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' $id } | Should Throw
    }
    It 'rejects a failed stdout status even if it contains the expected marker' {
        $id = '1' * 32
        $result = New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$id}
        $result.Value[0].Code = 'ComponentStatus/StdOut/failed'
        { Read-EvidenceBootstrapMarker $result 'AUTO_EVIDENCE_READY:' $id } | Should Throw
    }
}

Describe 'Evidence bootstrap remote script construction' {
    BeforeEach {
        $script:id = '1' * 32
        $script:sources = @{
            'Install-LabEvidenceAutomation.ps1' = ConvertTo-EvidenceSourceBase64 'param(); "AUTO_EVIDENCE_READY"'
            'Invoke-LabEvidenceAutomation.ps1' = ConvertTo-EvidenceSourceBase64 '# runtime'
            'Get-KerberosEvidence.ps1' = ConvertTo-EvidenceSourceBase64 '# helper'
        }
        $script:config = @{StorageAccount='azflab123';Share='labshare';DomainController='dc.contoso.local';UserName="CONTOSO\lab'user1"}
        $script:ciphertext = [Convert]::ToBase64String((New-Object byte[] 512))
    }
    It 'produces parseable PS5 scripts for all phases without evaluating them' {
        foreach ($phase in @('Stage', 'Install', 'Cleanup')) {
            $source = New-EvidenceBootstrapScript -Phase $phase -RunId $id -Sources $sources -Config $config -Thumbprint ('A' * 40) -Ciphertext $ciphertext
            $errors = $null; $lex = $null
            $null = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$lex, [ref]$errors)
            $errors.Count | Should Be 0
            $source | Should Not Match '__[A-Z_]+__'
        }
    }
    It 'allows only the three fixed staged source names and validated identities' {
        $sources['other.ps1'] = ''
        { New-EvidenceBootstrapScript -Phase Stage -RunId $id -Sources $sources } | Should Throw
        { New-EvidenceBootstrapScript -Phase Cleanup -RunId "..\bad" } | Should Throw
        { New-EvidenceBootstrapScript -Phase Cleanup -RunId $id -Thumbprint "';whoami" } | Should Throw
        { New-EvidenceBootstrapScript -Phase Install -RunId $id -Config $config -Thumbprint ('A' * 40) -Ciphertext 'AA==' } | Should Throw
    }
    It 'uses protected no-follow staging and nonexportable ephemeral private keys' {
        $source = New-EvidenceBootstrapScript -Phase Stage -RunId $id -Sources $sources
        $source | Should Match 'ReparsePoint'
        $source | Should Match 'AreAccessRulesProtected'
        $source | Should Match 'GetOwner'
        $source | Should Match 'CreateNew'
        $source | Should Match '-KeyLength 4096 -KeyExportPolicy NonExportable'
        $source | Should Match 'AddHours\(1\)'
        $source | Should Match 'ExportParameters\(\$false\)'
        $source | Should Not Match 'Export-Pfx|ExportParameters\(\$true\)'
    }
    It 'keeps settings out of PowerShell syntax and decrypts only in-process' {
        $source = New-EvidenceBootstrapScript -Phase Install -RunId $id -Config $config -Thumbprint ('A' * 40) -Ciphertext $ciphertext
        $source | Should Not Match ([regex]::Escape($config.UserName))
        $source | Should Not Match 'Start-Process|Start-Transcript|ConvertFrom-SecureString|Export-Clixml'
        $source | Should Match 'GetRSAPrivateKey'
        $source | Should Match 'OaepSHA256'
        $source | Should Match '\-LabCredential \$credential'
        $source | Should Match '\[Array\]::Clear'
        $source | Should Match 'Remove-BootstrapArtifacts'
        $source | Should Match 'ErrorRecord'
    }
    It 'cleans only run-bound files and tagged certificates, including private keys' {
        $source = New-EvidenceBootstrapScript -Phase Cleanup -RunId $id
        $source | Should Match ([regex]::Escape($id))
        $source | Should Match '\.Subject -ceq'
        $source | Should Match '\.FriendlyName -ceq'
        $source | Should Match '\-DeleteKey'
        $source | Should Match 'Delete\(\$directory, \$false\)'
        $source | Should Not Match '\-Recurse|Remove-AzVMRunCommand|Unregister-ScheduledTask'
    }
}

# Local stubs let Pester mock Az on machines with no Azure module installed.
function Get-AzContext { [CmdletBinding()] param() throw 'Unmocked Azure call.' }
function Get-AzVM { [CmdletBinding()] param($ResourceGroupName, $Name) throw 'Unmocked Azure call.' }
function Get-AzStorageAccount { [CmdletBinding()] param($ResourceGroupName) throw 'Unmocked Azure call.' }
function Invoke-AzVMRunCommand {
    [CmdletBinding()] param($ResourceGroupName, $VMName, $CommandId, $ScriptString, $Parameter)
    throw 'Unmocked Azure call.'
}

Describe 'Evidence bootstrap orchestration without Azure access' {
    BeforeAll { $script:orchestrationRsa = New-TestEvidenceRsa }
    AfterAll { $script:orchestrationRsa.Dispose() }
    BeforeEach {
        $script:sourceDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory $sourceDirectory
        'param(); "AUTO_EVIDENCE_READY"' | Set-Content (Join-Path $sourceDirectory 'Install-LabEvidenceAutomation.ps1')
        '# runtime' | Set-Content (Join-Path $sourceDirectory 'Invoke-LabEvidenceAutomation.ps1')
        '$helper = ''param(); # literal helper''' | Set-Content (Join-Path $sourceDirectory '07-install-tools.ps1')
        $script:password = 'fixture-secret-' + [guid]::NewGuid().ToString('N')
        $script:credential = New-Object Management.Automation.PSCredential('CONTOSO\labuser1', (ConvertTo-SecureString $password -AsPlainText -Force))
        $script:account = [pscustomobject]@{
            StorageAccountName='azflab123'
            AzureFilesIdentityBasedAuth=[pscustomobject]@{ActiveDirectoryProperties=[pscustomobject]@{
                ForestName='contoso.local';DomainName='CONTOSO';NetBiosDomainName='CONTOSO'
            }}
        }
        $script:remoteCalls = @()
        $script:failureMode = ''
        Mock Get-AzContext { [pscustomobject]@{Account='existing-context'} }
        Mock Get-AzVM { [pscustomobject]@{Name=$Name} }
        Mock Get-AzStorageAccount { $script:account }
        Mock Get-Credential { $script:credential }
        Mock Write-Warning {}
        Mock Invoke-AzVMRunCommand {
            if ($Parameter) { throw 'Password must never be propagated via Run Command parameters.' }
            $script:remoteCalls += $ScriptString
            $run = [regex]::Match($ScriptString, '\$runId = ''([a-f0-9]{32})''').Groups[1].Value
            if ($ScriptString -match 'BOOTSTRAP_PUBLIC:') {
                if ($script:failureMode -eq 'stage-transport') { throw $script:password }
                New-TestEvidenceResult 'BOOTSTRAP_PUBLIC:' (New-TestEvidencePublicKey $script:orchestrationRsa $run)
            } elseif ($ScriptString -match 'BOOTSTRAP_CLEAN:') {
                if ($script:failureMode -eq 'cleanup') { throw $script:password }
                New-TestEvidenceResult 'BOOTSTRAP_CLEAN:' @{RunId=$run}
            } else {
                if ($script:failureMode -in @('install', 'cleanup')) { throw $script:password }
                if ($script:failureMode -eq 'stale') { $run = '0' * 32 }
                $errorText = if ($script:failureMode -eq 'stderr') { 'installer error' } else { '' }
                New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$run} $errorText
            }
        }
    }
    It 'uses supplied credentials without prompting and sends no plaintext or credential parameters' {
        $result = Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory
        $result | Should Match '^AUTO_EVIDENCE_READY azflab-cli'
        $remoteCalls.Count | Should Be 2
        ($remoteCalls -join "`n") | Should Not Match ([regex]::Escape($password))
        ($remoteCalls -join "`n") | Should Not Match ([regex]::Escape([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($password))))
        Assert-MockCalled Get-Credential -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-AzVMRunCommand -Times 2 -Exactly -Scope It -ParameterFilter { $CommandId -eq 'RunPowerShellScript' -and -not $Parameter }
        $install = $remoteCalls[1]
        $encoded = [regex]::Match($install, "FromBase64String\('([A-Za-z0-9+/=]+)'\)\) \| ConvertFrom-Json").Groups[1].Value
        $settings = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json
        $settings.DomainController | Should Be 'azflab-dc.contoso.local'
        $settings.UserName | Should Be 'CONTOSO\labuser1'
    }
    It 'prompts only once for NetBIOS labuser1 when no credential was supplied' {
        $null = Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -SourceDirectory $sourceDirectory
        Assert-MockCalled Get-Credential -Times 1 -Exactly -Scope It -ParameterFilter { $UserName -eq 'CONTOSO\labuser1' }
    }
    It 'preserves the caller-owned SecureString after success and failure' {
        $callerPassword = $credential.Password
        $null = Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory
        [object]::ReferenceEquals($callerPassword, $credential.Password) | Should Be $true
        $credential.GetNetworkCredential().Password | Should Be $password
        $callerPassword.Length | Should Be $password.Length
        $script:failureMode = 'install'
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        $credential.GetNetworkCredential().Password | Should Be $password
        $callerPassword.Length | Should Be $password.Length
    }
    It 'requires existing Azure context without attempting login or remote work' {
        Mock Get-AzContext { $null }
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }
    It 'rejects ambiguous storage discovery before any remote change' {
        Mock Get-AzStorageAccount { $script:account; $script:account }
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }
    It 'excludes the separate prefix-ads account from automatic discovery' {
        Mock Get-AzStorageAccount {
            $script:account
            [pscustomobject]@{StorageAccountName='azflabads123'}
            [pscustomobject]@{StorageAccountName='unrelated123'}
        }
        $result = Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory
        $result | Should Match '^AUTO_EVIDENCE_READY'
        $remoteCalls.Count | Should Be 2
    }
    It 'fails before staging when the requested VM is absent' {
        Mock Get-AzVM { $null }
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }
    It 'fails before staging if repository sources are not yet available' {
        Remove-Item -LiteralPath (Join-Path $sourceDirectory 'Invoke-LabEvidenceAutomation.ps1')
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }
    It 'does not construct a DNS controller from legacy NetBIOS DomainName' {
        $account.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.ForestName = ''
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }
    It 'uses explicit storage and controller targets and ignores unrelated accounts' {
        $account.StorageAccountName = 'another123'
        $null = Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -StorageAccount 'another123' -DomainController 'dc.other.local' -VMName 'lab-client' -LabCredential $credential -SourceDirectory $sourceDirectory
        Assert-MockCalled Get-AzVM -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'lab-client' }
        $remoteCalls.Count | Should Be 2
    }
    It 'cleans the staged key when encryption rejects an oversized credential' {
        $large = New-Object Management.Automation.PSCredential('CONTOSO\labuser1', (ConvertTo-SecureString ('q' * 447) -AsPlainText -Force))
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $large -SourceDirectory $sourceDirectory } | Should Throw '446 UTF-8 bytes'
        $remoteCalls.Count | Should Be 2
        $remoteCalls[1] | Should Match 'BOOTSTRAP_CLEAN:'
        ($remoteCalls -join "`n") | Should Not Match ('q' * 447)
    }
    It 'cleans the GUID after a stage transport failure even without a returned thumbprint' {
        $script:failureMode = 'stage-transport'
        try { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory; throw 'Expected failure' }
        catch { $_.Exception.Message | Should Not Match ([regex]::Escape($password)) }
        $remoteCalls.Count | Should Be 2
        $remoteCalls[1] | Should Match 'BOOTSTRAP_CLEAN:'
    }
    It 'cleans after installation failure and never echoes the caught error' {
        $script:failureMode = 'install'
        try { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory; throw 'Expected failure' }
        catch { $_.Exception.Message | Should Match 'installation failed'; $_.Exception.Message | Should Not Match ([regex]::Escape($password)) }
        $remoteCalls.Count | Should Be 3
        $remoteCalls[2] | Should Match "Remove-BootstrapArtifacts 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"
    }
    It 'does not accept stale success or success accompanied by stderr' {
        foreach ($mode in @('stale', 'stderr')) {
            $script:failureMode = $mode
            { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        }
        $remoteCalls.Count | Should Be 6
    }
    It 'makes cleanup failure visible without exposing the remote exception' {
        $script:failureMode = 'cleanup'
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName 'lab-rg' -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter { $Message -match 'cleanup unconfirmed' -and $Message -notmatch [regex]::Escape($script:password) }
    }
}
