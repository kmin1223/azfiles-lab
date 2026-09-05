$ErrorActionPreference = 'Stop'
$setupFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\02-create-lab-users.ps1'
$tokens = $null
$parseErrors = $null
$setupAst = [Management.Automation.Language.Parser]::ParseFile($setupFile, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$begin = $setupAst.Find({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$channelXml'
}, $true).Extent.StartOffset
$end = $setupAst.Find({
    param($node)
    $node -is [Management.Automation.Language.ForEachStatementAst] -and $node.Variable.VariablePath.UserPath -eq 'rule'
}, $true).Extent.StartOffset
$aclSetup = [scriptblock]::Create(($setupAst.EndBlock.Statements |
    Where-Object { $_.Extent.StartOffset -ge $begin -and $_.Extent.EndOffset -le $end } |
    ForEach-Object { $_.Extent.Text }) -join "`n")

function Invoke-EventUtility { param($Executable, $Arguments) throw 'Unmocked event utility call' }
function Get-AceBytes($Ace) {
    $bytes = New-Object byte[] $Ace.BinaryLength
    $Ace.GetBinaryForm($bytes, 0)
    [Convert]::ToBase64String($bytes)
}

Describe 'DC Security channel read access' {
    BeforeEach {
        $script:readers = [pscustomobject]@{
            SID = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-101-202-303-1100')
        }
        $script:initialSddl = 'O:BAG:SYD:P(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)S:(AU;SA;0x1;;;WD)'
        # Same namespace and attribute layout emitted by wevtutil gl Security /f:xml.
        $script:channelContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<channel name="Security" enabled="true" type="Admin" isolation="Custom"
 channelAccess="$initialSddl" xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <logging><logFileName>%SystemRoot%\System32\Winevt\Logs\Security.evtx</logFileName></logging>
</channel>
"@
        $script:writes = @()
        Mock Invoke-EventUtility {
            if ($Executable -ne 'wevtutil') { throw 'Unexpected executable' }
            if (($Arguments -join ' ') -eq 'gl Security /f:xml') { return $channelContent }
            if ($Arguments[0] -eq 'sl' -and $Arguments[1] -eq 'Security' -and $Arguments[2].StartsWith('/ca:')) {
                $sddl = $Arguments[2].Substring(4)
                $script:writes += $sddl
                $xml = [xml]$channelContent
                $xml.DocumentElement.SetAttribute('channelAccess', $sddl)
                $script:channelContent = $xml.OuterXml
                return
            }
            throw "Unexpected utility arguments: $Arguments"
        }
    }

    It 'reads the actual XML attribute and adds only a read ACE while preserving the descriptor' {
        & $aclSetup
        $writes.Count | Should Be 1
        $old = [Security.AccessControl.RawSecurityDescriptor]::new($initialSddl)
        $new = [Security.AccessControl.RawSecurityDescriptor]::new($writes[0])
        $new.Owner.Value | Should Be $old.Owner.Value
        $new.Group.Value | Should Be $old.Group.Value
        $new.ControlFlags | Should Be $old.ControlFlags
        $new.DiscretionaryAcl.Count | Should Be ($old.DiscretionaryAcl.Count + 1)
        for ($i = 0; $i -lt $old.DiscretionaryAcl.Count; $i++) {
            (Get-AceBytes $new.DiscretionaryAcl[$i]) | Should Be (Get-AceBytes $old.DiscretionaryAcl[$i])
        }
        $new.SystemAcl.Count | Should Be $old.SystemAcl.Count
        (Get-AceBytes $new.SystemAcl[0]) | Should Be (Get-AceBytes $old.SystemAcl[0])
        $added = $new.DiscretionaryAcl[$old.DiscretionaryAcl.Count]
        $added.SecurityIdentifier.Value | Should Be $readers.SID.Value
        $added.AccessMask | Should Be 1
        $added.AceQualifier.ToString() | Should Be 'AccessAllowed'
        $added.AceFlags.ToString() | Should Be 'None'
    }

    It 'accepts live read-only Windows configuration without writing to the real channel' {
        $xml = & "$env:SystemRoot\System32\wevtutil.exe" gl Security /f:xml
        $LASTEXITCODE | Should Be 0
        $script:channelContent = $xml -join "`n"
        & $aclSetup
        $writes.Count | Should Be 1
        ([xml]$channelContent).DocumentElement.GetAttribute('channelAccess') | Should Match $readers.SID.Value
    }

    It 'does not append another ACE or write configuration on a second run' {
        & $aclSetup
        & $aclSetup
        $writes.Count | Should Be 1
        Assert-MockCalled Invoke-EventUtility -Times 1 -Exactly -Scope It -ParameterFilter {
            $Arguments[0] -eq 'sl'
        }
    }

    It 'rejects missing and empty access attributes without replacing permissions' {
        foreach ($xml in @(
            '<channel name="Security"/>',
            '<channel name="Security" channelAccess=" "/>',
            '<channel name="Other" channelAccess="O:BAG:SYD:(A;;0x1;;;BA)"/>'
        )) {
            $script:channelContent = $xml
            { & $aclSetup } | Should Throw
        }
        Assert-MockCalled Invoke-EventUtility -Times 0 -Exactly -Scope It -ParameterFilter {
            $Arguments[0] -eq 'sl'
        }
    }

    It 'rejects malformed XML and invalid SDDL without replacing permissions' {
        foreach ($xml in @('<channel', '<channel name="Security" channelAccess="invalid-sddl"/>')) {
            $script:channelContent = $xml
            { & $aclSetup } | Should Throw
        }
        $writes.Count | Should Be 0
    }

    It 'does not invent a DACL when the existing descriptor has none' {
        $script:channelContent = '<channel name="Security" channelAccess="O:BAG:SY"/>'
        { & $aclSetup } | Should Throw
        $writes.Count | Should Be 0
    }

    It 'propagates query and write failures instead of claiming readiness' {
        Mock Invoke-EventUtility { throw 'Query denied' }
        { & $aclSetup } | Should Throw
        Mock Invoke-EventUtility {
            if ($Arguments[0] -eq 'gl') { return $channelContent }
            throw 'Write denied'
        }
        { & $aclSetup } | Should Throw
        $writes.Count | Should Be 0
    }
}
