$setupFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\02-create-lab-users.ps1'
$tokens = $null
$parseErrors = $null
$setupAst = [Management.Automation.Language.Parser]::ParseFile($setupFile, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$begin = $setupAst.Find({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$readerName'
}, $true).Extent.StartOffset
$end = $setupAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-EventUtility'
}, $true).Extent.StartOffset
$membershipSetup = [scriptblock]::Create(($setupAst.EndBlock.Statements |
    Where-Object { $_.Extent.StartOffset -ge $begin -and $_.Extent.EndOffset -le $end } |
    ForEach-Object { $_.Extent.Text }) -join "`n")

# Only the membership block runs; AD calls are mocked even on hosts without RSAT.
function Get-ADGroup { param($Identity, $Filter) throw 'Unmocked AD call' }
function New-ADGroup { param($Name, $SamAccountName, $GroupScope, $GroupCategory, $Path, [switch]$PassThru) throw 'Unmocked AD call' }
function Get-ADGroupMember { param($Identity) throw 'Unmocked AD call' }
function Get-ADUser { param($Identity) throw 'Unmocked AD call' }
function Add-ADGroupMember { param($Identity, $Members) throw 'Unmocked AD call' }

Describe 'DC evidence reader membership' {
    BeforeEach {
        $script:ouDn = 'OU=AzureFilesLab,DC=contoso,DC=local'
        $script:readerGroup = [pscustomobject]@{
            DistinguishedName = "CN=AzureFilesLabEvidenceReaders,$ouDn"
            GroupScope = 'DomainLocal'; GroupCategory = 'Security'; ObjectClass = 'group'
        }
        $script:builtinGroup = [pscustomobject]@{
            DistinguishedName = 'CN=Event Log Readers,CN=Builtin,DC=contoso,DC=local'
            ObjectClass = 'group'
        }
        $script:groupExists = $true
        $script:readerMemberDns = @()
        $script:builtinMemberDns = @()
        Mock Get-ADGroup {
            if ($Identity -eq 'S-1-5-32-573') { return $builtinGroup }
            if ($Filter -and $groupExists) { return $readerGroup }
        }
        Mock New-ADGroup {
            $script:groupExists = $true
            $readerGroup
        }
        Mock Get-ADUser {
            [pscustomobject]@{ DistinguishedName = "CN=$Identity,$ouDn"; ObjectClass = 'user' }
        }
        Mock Get-ADGroupMember {
            $dns = if ($Identity.DistinguishedName -eq $builtinGroup.DistinguishedName) {
                $builtinMemberDns
            } else { $readerMemberDns }
            foreach ($dn in $dns) { [pscustomobject]@{ DistinguishedName = $dn } }
        }
        Mock Add-ADGroupMember {
            if ($Identity.DistinguishedName -eq $builtinGroup.DistinguishedName) {
                if ($Members.ObjectClass -ne 'user') {
                    throw 'AD error 8520: cross domain local group nesting is not allowed'
                }
                $script:builtinMemberDns += $Members.DistinguishedName
            } else {
                $script:readerMemberDns += $Members.DistinguishedName
            }
        }
    }

    It 'adds users directly to BUILTIN without nesting the DomainLocal group' {
        & $membershipSetup
        $builtinMemberDns.Count | Should Be 2
        $readerMemberDns.Count | Should Be 2
        Assert-MockCalled Add-ADGroupMember -Times 0 -Exactly -Scope It -ParameterFilter {
            $Members.ObjectClass -eq 'group'
        }
        Assert-MockCalled Get-ADGroup -Times 1 -Exactly -Scope It -ParameterFilter {
            $Identity -eq 'S-1-5-32-573'
        }
    }

    It 'recovers the partially configured group without recreating it or its users' {
        $script:readerMemberDns = @("CN=labuser1,$ouDn", "CN=labuser2,$ouDn")
        & $membershipSetup
        $builtinMemberDns.Count | Should Be 2
        Assert-MockCalled New-ADGroup -Times 0 -Exactly -Scope It
        Assert-MockCalled Add-ADGroupMember -Times 2 -Exactly -Scope It -ParameterFilter {
            $Identity.DistinguishedName -eq $builtinGroup.DistinguishedName -and $Members.ObjectClass -eq 'user'
        }
    }

    It 'does not add duplicate members on a second run' {
        & $membershipSetup
        & $membershipSetup
        $builtinMemberDns.Count | Should Be 2
        $readerMemberDns.Count | Should Be 2
        Assert-MockCalled Add-ADGroupMember -Times 4 -Exactly -Scope It
    }

    It 'creates the DomainLocal security group on a fresh deployment' {
        $script:groupExists = $false
        & $membershipSetup
        Assert-MockCalled New-ADGroup -Times 1 -Exactly -Scope It -ParameterFilter {
            $GroupScope -eq 'DomainLocal' -and $GroupCategory -eq 'Security' -and $PassThru
        }
        $builtinMemberDns.Count | Should Be 2
    }

    It 'propagates membership failures instead of allowing a readiness claim' {
        Mock Add-ADGroupMember { throw 'Access denied' }
        { & $membershipSetup } | Should Throw
    }
}
