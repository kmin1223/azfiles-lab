$wrapper = Join-Path (Split-Path $PSScriptRoot -Parent) 'Update-LabEvidenceAutomation.ps1'
$tokens = $null; $errors = $null
$wrapperAst = [Management.Automation.Language.Parser]::ParseFile($wrapper,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($definition in $wrapperAst.FindAll({
    param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
},$true)) { . ([scriptblock]::Create($definition.Extent.Text)) }

function New-TestEvidenceResult([string]$Marker, $Payload, [string]$StdErr = '') {
    [pscustomobject]@{Value=@(
        [pscustomobject]@{Code='ComponentStatus/StdOut/succeeded'; Message=$Marker + ($Payload | ConvertTo-Json -Compress)},
        [pscustomobject]@{Code='ComponentStatus/StdErr/succeeded'; Message=$StdErr}
    )}
}
function New-TestEvidenceConfig {
    @{StorageAccount='azflab123'; Share='labshare'; DomainController='dc.contoso.local'; UserName='CONTOSO\labuser1'}
}
function New-TestEvidenceSources {
    @{
        'Install-LabEvidenceAutomation.ps1'=ConvertTo-EvidenceSourceBase64 'param(); "AUTO_EVIDENCE_READY"'
        'Invoke-LabEvidenceAutomation.ps1'=ConvertTo-EvidenceSourceBase64 '# runtime'
        'Get-KerberosEvidence.ps1'=ConvertTo-EvidenceSourceBase64 '# helper'
    }
}

Describe 'Literal collector extraction and target validation' {
    It 'parses and extracts the real helper without executing its installer' {
        $source = Get-EvidenceHelperSource (Join-Path (Split-Path $wrapper -Parent) 'scripts\07-install-tools.ps1')
        $source | Should Match 'function Invoke-MountAttempt'
        $lex=$null; $err=$null
        [void][Management.Automation.Language.Parser]::ParseInput($source,[ref]$lex,[ref]$err)
        $err.Count | Should Be 0
    }
    It 'never evaluates unrelated code or an interpolated helper' {
        $path=Join-Path $TestDrive 'literal.ps1'
        'throw ''MUST NOT EXECUTE''; $helper = ''param(); "helper"''' | Set-Content $path
        (Get-EvidenceHelperSource $path) | Should Be 'param(); "helper"'
        '$helper = "$(throw ''executed'')"' | Set-Content $path
        { Get-EvidenceHelperSource $path } | Should Throw
        '$helper = ''one''; $helper = ''two''' | Set-Content $path
        { Get-EvidenceHelperSource $path } | Should Throw
    }
    It 'preserves UTF8 with a BOM for Windows PowerShell 5.1' {
        $source='param(); # ' + [char]0xD55C
        $bytes=[Convert]::FromBase64String((ConvertTo-EvidenceSourceBase64 $source))
        [BitConverter]::ToString($bytes[0..2]) | Should Be 'EF-BB-BF'
        [Text.Encoding]::UTF8.GetString($bytes,3,$bytes.Length-3) | Should Be $source
    }
    It 'accepts plain target names but rejects malformed and injectable settings' {
        { Assert-EvidenceBootstrapConfig 'azflab123' 'lab-share' 'dc.contoso.local' } | Should Not Throw
        { Assert-EvidenceBootstrapConfig 'ab;cmd' 'labshare' 'dc.contoso.local' } | Should Throw
        { Assert-EvidenceBootstrapConfig 'azflab123' '..\share' 'dc.contoso.local' } | Should Throw
        { Assert-EvidenceBootstrapConfig 'azflab123' 'labshare' 'CONTOSO' } | Should Throw
        { Assert-EvidenceBootstrapConfig 'azflab123' 'labshare' 'dc.local;cmd' } | Should Throw
    }
}

Describe 'One-call remote installer construction' {
    BeforeEach {
        $script:config=New-TestEvidenceConfig
        $script:sources=New-TestEvidenceSources
        $script:remote=New-EvidenceBootstrapScript ('1'*32) $sources $config
    }
    It 'parses the complete Windows script and uses a password parameter, not interpolation' {
        $lex=$null; $err=$null
        [void][Management.Automation.Language.Parser]::ParseInput($remote,[ref]$lex,[ref]$err)
        $err.Count | Should Be 0
        $remote | Should Match 'param\(\[Parameter\(Mandatory\)\]\[string\]\$LabPassword\)'
        $remote | Should Not Match '__[A-Z_]+__|New-SelfSignedCertificate|GetRSAPrivateKey|Cert:\\|OaepSHA256'
        $remote | Should Not Match 'Start-Process|Start-Transcript|Export-Clixml'
    }
    It 'keeps username data outside executable syntax and permits only fixed source names' {
        $config.UserName="CONTOSO\lab'user1"
        $built=New-EvidenceBootstrapScript ('1'*32) $sources $config
        $built | Should Not Match ([regex]::Escape($config.UserName))
        $sources['unexpected.ps1']=''
        { New-EvidenceBootstrapScript ('1'*32) $sources $config } | Should Throw
        { New-EvidenceBootstrapScript '..\other' (New-TestEvidenceSources) $config } | Should Throw
    }
    It 'protects staged scripts and keeps a per-run diagnostic log without broad cleanup' {
        $remote | Should Match 'ReparsePoint'
        $remote | Should Match 'GetOwner'
        $remote | Should Match 'AreAccessRulesProtected'
        $remote | Should Match "'CreateNew'"
        $remote | Should Match "'install.log'"
        $remote | Should Match 'ScriptLineNumber'
        $remote | Should Match 'FullyQualifiedErrorId'
        $remote | Should Match 'ScriptStackTrace'
        $remote | Should Match 'AUTO_EVIDENCE_FAILED:'
        $remote | Should Match '\$directory = New-InstallDirectory \$runId'
        $remote | Should Not Match '\-Recurse|Remove-AzVMRunCommand|Remove-Item|Unregister-ScheduledTask'
    }
}

Describe 'Independent staging initialization without VM filesystem changes' {
    BeforeAll {
        $source=New-EvidenceBootstrapScript ('1'*32) (New-TestEvidenceSources) (New-TestEvidenceConfig)
        $lex=$null; $err=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$lex,[ref]$err)
        foreach($definition in $ast.FindAll({
            param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in @('Assert-SafeDirectory','New-PrivateDirectory','New-InstallDirectory')
        },$true)) { . ([scriptblock]::Create($definition.Extent.Text)) }
    }
    BeforeEach {
        $script:legacy='C:\Program Files\AzureFilesLabEvidenceBootstrap'
        Mock Test-Path { param($LiteralPath) $LiteralPath -eq $script:legacy }
        Mock Assert-SafeDirectory {
            param($Path)
            if ($Path -eq $script:legacy) { throw 'Unsafe legacy directory permissions' }
        }
        Mock New-PrivateDirectory {}
    }
    It 'creates independent private siblings without checking or using the unsafe legacy folder' {
        $first=New-InstallDirectory ('1'*32)
        $second=New-InstallDirectory ('2'*32)
        $first | Should Be ('C:\Program Files\AzureFilesLabEvidenceBootstrap-' + ('1'*32))
        $second | Should Be ('C:\Program Files\AzureFilesLabEvidenceBootstrap-' + ('2'*32))
        Assert-MockCalled New-PrivateDirectory -Times 2 -Exactly -Scope It
        Assert-MockCalled Assert-SafeDirectory -Times 2 -Exactly -Scope It -ParameterFilter { $Path -eq 'C:\Program Files' }
        Assert-MockCalled Assert-SafeDirectory -Times 0 -Exactly -Scope It -ParameterFilter { $Path -eq $script:legacy }
        Assert-MockCalled Test-Path -Times 0 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $script:legacy }
    }
    It 'refuses an existing run path instead of repairing or reusing it' {
        Mock Test-Path { $true }
        { New-InstallDirectory ('1'*32) } | Should Throw 'Run directory already exists'
        Assert-MockCalled New-PrivateDirectory -Times 0 -Exactly -Scope It
    }
    It 'still rejects unsafe Program Files permissions before creating anything' {
        Mock Assert-SafeDirectory {
            param($Path)
            if ($Path -eq 'C:\Program Files') { throw 'Unsafe parent ACL' }
        }
        { New-InstallDirectory ('1'*32) } | Should Throw 'Unsafe parent ACL'
        Assert-MockCalled New-PrivateDirectory -Times 0 -Exactly -Scope It
    }
    It 'does not hide failure to establish the new private directory' {
        Mock New-PrivateDirectory { throw 'Private ACL validation failed' }
        { New-InstallDirectory ('1'*32) } | Should Throw 'Private ACL validation failed'
    }
    It 'rejects malformed run identifiers before touching any path' {
        { New-InstallDirectory '..\other' } | Should Throw 'Invalid installation run ID'
        Assert-MockCalled Assert-SafeDirectory -Times 0 -Exactly -Scope It
        Assert-MockCalled New-PrivateDirectory -Times 0 -Exactly -Scope It
    }
}

Describe 'Private staging ACL validation with in-memory security descriptors' {
    BeforeEach {
        $script:acl=New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
        foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                [Security.Principal.SecurityIdentifier]$sid,'FullControl','Allow')))
        }
        Mock Get-Item { [pscustomobject]@{PSIsContainer=$true;Attributes=[IO.FileAttributes]::Directory} }
        Mock Get-Acl { $script:acl }
    }
    It 'accepts protected administrator and SYSTEM permissions' {
        { Assert-SafeDirectory 'C:\fixture' -Private } | Should Not Throw
    }
    It 'keeps extra read permissions forbidden on the new private folder and names the ACE' {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]'S-1-5-32-545','ReadAndExecute','Allow')))
        { Assert-SafeDirectory 'C:\fixture' -Private } | Should Throw 'SID=S-1-5-32-545; rights=ReadAndExecute'
    }
    It 'rejects untrusted write permissions' {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]'S-1-5-32-545','Modify','Allow')))
        { Assert-SafeDirectory 'C:\fixture' -Private } | Should Throw 'Unsafe directory permissions'
    }
    It 'rejects untrusted owners and linked directories' {
        $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-1100')
        { Assert-SafeDirectory 'C:\fixture' -Private } | Should Throw 'Unsafe directory owner'
        Mock Get-Item { [pscustomobject]@{PSIsContainer=$true;Attributes=[IO.FileAttributes]::ReparsePoint} }
        { Assert-SafeDirectory 'C:\fixture' -Private } | Should Throw 'Unsafe directory:'
    }
}

Describe 'Remote in-process installation using an isolated fake installer' {
    BeforeAll {
        $source=New-EvidenceBootstrapScript ('1'*32) (New-TestEvidenceSources) (New-TestEvidenceConfig)
        $lex=$null; $err=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$lex,[ref]$err)
        foreach($definition in $ast.FindAll({
            param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in @('Remove-InstallPassword','Write-InstallLog','Invoke-StagedEvidenceInstall')
        },$true)) { . ([scriptblock]::Create($definition.Extent.Text)) }
    }
    BeforeEach {
        $script:stage=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory $stage | Out-Null
        $script:logPath=Join-Path $stage 'install.log'
        $script:LabPassword='fixture-only-"$`;' + [char]0xD55C
        $script:installer=Join-Path $stage 'Install-LabEvidenceAutomation.ps1'
    }
    It 'constructs a credential, accepts readiness, and logs progress without a password' {
        @'
param($StorageAccount,$Share,$DomainController,[PSCredential]$LabCredential,$SourceDirectory)
if ($LabCredential.UserName -ne 'CONTOSO\labuser1') { throw 'Wrong identity' }
Write-Host 'Registering fixed tasks'
Write-Warning ('Example password-bearing diagnostic: ' + $LabCredential.GetNetworkCredential().Password)
Write-Output 'AUTO_EVIDENCE_READY'
'@ | Set-Content $installer
        { Invoke-StagedEvidenceInstall (New-TestEvidenceConfig) $stage } | Should Not Throw
        $log=Get-Content $logPath -Raw
        $log | Should Match 'Registering fixed tasks|AUTO_EVIDENCE_READY'
        $log | Should Match '\[REDACTED\]'
        $log | Should Not Match ([regex]::Escape($LabPassword))
    }
    It 'preserves the installer exception and its original source line' {
        @'
param($StorageAccount,$Share,$DomainController,$LabCredential,$SourceDirectory)
Write-Output 'Before registration'
throw 'Scheduler registration failed: access denied'
'@ | Set-Content $installer
        try { Invoke-StagedEvidenceInstall (New-TestEvidenceConfig) $stage; throw 'Expected a failure' }
        catch {
            $_.Exception.Message | Should Match 'Scheduler registration failed'
            $_.InvocationInfo.ScriptName | Should Be $installer
            $_.InvocationInfo.ScriptLineNumber | Should Be 3
        }
        Get-Content $logPath -Raw | Should Match 'Before registration'
    }
    It 'does not accept a successful-looking marker followed by a nonterminating error' {
        @'
param($StorageAccount,$Share,$DomainController,$LabCredential,$SourceDirectory)
'AUTO_EVIDENCE_READY'
Write-Error 'Failed after marker' -ErrorAction Continue
'@ | Set-Content $installer
        { Invoke-StagedEvidenceInstall (New-TestEvidenceConfig) $stage } | Should Throw
    }
    It 'fails when the installer returns without a readiness marker' {
        'param($StorageAccount,$Share,$DomainController,$LabCredential,$SourceDirectory); "not ready"' | Set-Content $installer
        { Invoke-StagedEvidenceInstall (New-TestEvidenceConfig) $stage } | Should Throw 'without AUTO_EVIDENCE_READY'
    }
}

Describe 'Actionable, correlated remote results' {
    It 'explains why there is no log when staging initialization fails' {
        $id='1'*32
        $r=New-TestEvidenceResult 'AUTO_EVIDENCE_FAILED:' @{
            RunId=$id;Stage='Preparing staging directory';Message='Unsafe parent ACL'
            Script='script.ps1';Line=31;ErrorId='UnsafeAcl';LogPath=$null
        }
        { Read-EvidenceBootstrapMarker $r $id } | Should Throw 'VM log not created: staging initialization did not complete'
    }
    It 'requires exactly one matching readiness record' {
        $id='1'*32
        $r=New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$id;LogPath='C:\private\install.log'}
        (Read-EvidenceBootstrapMarker $r $id).LogPath | Should Be 'C:\private\install.log'
        { Read-EvidenceBootstrapMarker $r ('2'*32) } | Should Throw
        $r.Value[0].Message+="`n"+$r.Value[0].Message
        { Read-EvidenceBootstrapMarker $r $id } | Should Throw
    }
    It 'surfaces failure stage, message, file, line, ID and log path even with a successful ARM transport' {
        $id='1'*32
        $r=New-TestEvidenceResult 'AUTO_EVIDENCE_FAILED:' @{
            RunId=$id;Stage='Register worker';Message='Access denied';Script='Install.ps1';Line=123
            ErrorId='UnauthorizedAccess';LogPath='C:\private\install.log'
        }
        try { Read-EvidenceBootstrapMarker $r $id; throw 'Expected failure' }
        catch {
            $_.Exception.Message | Should Match "Stage 'Register worker': Access denied"
            $_.Exception.Message | Should Match 'Install.ps1:123'
            $_.Exception.Message | Should Match 'UnauthorizedAccess'
            $_.Exception.Message | Should Match 'C:\\private\\install.log'
        }
    }
    It 'keeps unstructured stderr visible rather than replacing it with a generic error' {
        $r=New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=('1'*32)} 'Parameter binding failed'
        { Read-EvidenceBootstrapMarker $r ('1'*32) } | Should Throw 'Parameter binding failed'
        $r.Value[1].Message=''
        $r.Value[0].Code='ComponentStatus/StdOut/failed'
        { Read-EvidenceBootstrapMarker $r ('1'*32) } | Should Throw
    }
    It 'rejects malformed JSON and stale failure records' {
        $r=New-TestEvidenceResult 'AUTO_EVIDENCE_FAILED:' @{RunId=('2'*32)}
        { Read-EvidenceBootstrapMarker $r ('1'*32) } | Should Throw
        $r.Value[0].Message='AUTO_EVIDENCE_READY:not-json'
        { Read-EvidenceBootstrapMarker $r ('1'*32) } | Should Throw
    }
    It 'redacts both literal and JSON-escaped passwords without hiding other details' {
        $password='fixture"password'
        (Remove-EvidencePassword ('Access denied: '+$password) $password) | Should Be 'Access denied: [REDACTED]'
        (Remove-EvidencePassword 'Access denied: fixture\"password' $password) | Should Be 'Access denied: [REDACTED]'
    }
}

function Get-AzContext { [CmdletBinding()] param() throw 'Unmocked Azure call.' }
function Get-AzVM { [CmdletBinding()] param($ResourceGroupName,$Name) throw 'Unmocked Azure call.' }
function Get-AzStorageAccount { [CmdletBinding()] param($ResourceGroupName) throw 'Unmocked Azure call.' }
function Invoke-AzVMRunCommand {
    [CmdletBinding()] param($ResourceGroupName,$VMName,$CommandId,$ScriptString,$Parameter)
    throw 'Unmocked Azure call.'
}

Describe 'Single Run Command orchestration without Azure access' {
    BeforeEach {
        $script:sourceDirectory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory $sourceDirectory | Out-Null
        'param(); "AUTO_EVIDENCE_READY"' | Set-Content (Join-Path $sourceDirectory 'Install-LabEvidenceAutomation.ps1')
        '# runtime' | Set-Content (Join-Path $sourceDirectory 'Invoke-LabEvidenceAutomation.ps1')
        '$helper = ''param(); # literal helper''' | Set-Content (Join-Path $sourceDirectory '07-install-tools.ps1')
        $script:password='fixture-"$`;' + [guid]::NewGuid().ToString('N') + [char]0xD55C
        $script:credential=New-Object Management.Automation.PSCredential('CONTOSO\labuser1',(ConvertTo-SecureString $password -AsPlainText -Force))
        $script:account=[pscustomobject]@{
            StorageAccountName='azflab123'
            AzureFilesIdentityBasedAuth=[pscustomobject]@{ActiveDirectoryProperties=[pscustomobject]@{
                ForestName='contoso.local';DomainName='CONTOSO';NetBiosDomainName='CONTOSO'
            }}
        }
        $script:remoteCalls=@()
        $script:fail=$false
        Mock Get-AzContext { [pscustomobject]@{Account='existing-context'} }
        Mock Get-AzVM { [pscustomobject]@{Name=$Name} }
        Mock Get-AzStorageAccount { $script:account }
        Mock Get-Credential { $script:credential }
        Mock Write-Warning {}
        Mock Write-Host {}
        Mock Invoke-AzVMRunCommand {
            $script:remoteCalls += [pscustomobject]@{Source=$ScriptString; Parameters=$Parameter.Clone()}
            if($script:fail) { throw ('Transport detail: '+$script:password) }
            $run=[regex]::Match($ScriptString,'\$runId = ''([a-f0-9]{32})''').Groups[1].Value
            New-TestEvidenceResult 'AUTO_EVIDENCE_READY:' @{RunId=$run;LogPath='C:\private\install.log'}
        }
    }
    It 'uses exactly one call with the unchanged password parameter and no embedded password' {
        $r=Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory
        $r | Should Match '^AUTO_EVIDENCE_READY azflab-cli'
        $remoteCalls.Count | Should Be 1
        $remoteCalls[0].Parameters.LabPassword | Should Be $password
        $remoteCalls[0].Source | Should Not Match ([regex]::Escape($password))
        $encoded = [regex]::Matches($remoteCalls[0].Source,"FromBase64String\('([A-Za-z0-9+/=]+)'\)\) \| ConvertFrom-Json")
        $settings = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded[$encoded.Count-1].Groups[1].Value)) | ConvertFrom-Json
        $settings.DomainController | Should Be 'azflab-dc.contoso.local'
        $settings.UserName | Should Be 'CONTOSO\labuser1'
        Assert-MockCalled Get-Credential -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-AzVMRunCommand -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter { $Message -match 'ordinary Run Command parameter' }
    }
    It 'prompts once for the domain labuser1 when a credential is omitted' {
        $null=Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -SourceDirectory $sourceDirectory
        Assert-MockCalled Get-Credential -Times 1 -Exactly -Scope It -ParameterFilter { $UserName -eq 'CONTOSO\labuser1' }
    }
    It 'preserves caller-owned credentials and error details with no cleanup RPC after failure' {
        $original=$credential.Password
        $null=Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory
        $script:fail=$true
        try { Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory; throw 'Expected failure' }
        catch {
            $_.Exception.Message | Should Match 'Transport detail:'
            $_.Exception.Message | Should Not Match ([regex]::Escape($password))
        }
        $remoteCalls.Count | Should Be 2
        [object]::ReferenceEquals($original,$credential.Password) | Should Be $true
        $credential.GetNetworkCredential().Password | Should Be $password
    }
    It 'requires an existing Azure context before remote work' {
        Mock Get-AzContext { $null }
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }
    It 'rejects ambiguous accounts and a missing VM before remote work' {
        Mock Get-AzStorageAccount { $script:account; $script:account }
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Mock Get-AzVM { $null }
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        Assert-MockCalled Invoke-AzVMRunCommand -Times 0 -Exactly -Scope It
    }
    It 'excludes the coexistence account and uses forest DNS with Legacy metadata' {
        Mock Get-AzStorageAccount { $script:account; [pscustomobject]@{StorageAccountName='azflabads123'} }
        $null=Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory
        $remoteCalls.Count | Should Be 1
        $account.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.ForestName=''
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw 'forest DNS'
    }
    It 'accepts explicit targets and refuses missing source files before remote work' {
        $null=Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -StorageAccount azflab123 -VMName custom-cli -DomainController dc.other.local -LabCredential $credential -SourceDirectory $sourceDirectory
        Assert-MockCalled Get-AzVM -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'custom-cli' }
        Remove-Item -LiteralPath (Join-Path $sourceDirectory 'Invoke-LabEvidenceAutomation.ps1')
        { Invoke-EvidenceAutomationBootstrap -ResourceGroupName lab-rg -LabCredential $credential -SourceDirectory $sourceDirectory } | Should Throw
        $remoteCalls.Count | Should Be 1
    }
}
