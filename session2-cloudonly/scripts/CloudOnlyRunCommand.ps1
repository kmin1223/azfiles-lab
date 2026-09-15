function Assert-CloudOnlyRunCommand {
    [CmdletBinding()]
    param(
        [AllowNull()] [object]$Result,
        [Parameter(Mandatory)] [string]$CompletionMarker
    )
    $stdout = (@($Result.Value | Where-Object Code -like '*StdOut*' | ForEach-Object Message) -join "`n")
    $stderr = (@($Result.Value | Where-Object Code -like '*StdErr*' | ForEach-Object Message) -join "`n")
    if ($stdout) { Write-Host $stdout }
    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        throw "CLOUD_CLIENT_CONFIG_FAILED: $stderr"
    }
    $pattern = '(?m)^' + [regex]::Escape($CompletionMarker) + '\r?$'
    if ($stdout -notmatch $pattern) {
        throw "CLOUD_CLIENT_CONFIG_INCOMPLETE: Run Command did not return $CompletionMarker. Inspect the VM Run Command output before retrying; no restart was requested."
    }
}

function Get-CloudOnlyJoinStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ResourceGroupName,
        [Parameter(Mandatory)] [string]$VMName
    )

    $status = 'UNKNOWN'
    $failure = $null
    try {
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName `
            -CommandId 'RunPowerShellScript' -ErrorAction Stop -ScriptString @'
$ErrorActionPreference = 'Stop'
$status = dsregcmd /status
if ($LASTEXITCODE -ne 0) { throw "dsregcmd failed with exit code $LASTEXITCODE" }
$status | Select-String '^\s*AzureAdJoined\s*:'
'@
        $stdout = (@($result.Value | Where-Object Code -like '*StdOut*' | ForEach-Object Message) -join "`n")
        $stderr = (@($result.Value | Where-Object Code -like '*StdErr*' | ForEach-Object Message) -join "`n")
        if (-not [string]::IsNullOrWhiteSpace($stderr)) { throw "Guest query failed: $stderr" }
        $failed = @($result.Value | Where-Object Code -match '/(failed|error)$')
        if ($failed.Count) { throw 'Run Command returned a failed component status.' }
        $matches = [regex]::Matches($stdout, '(?im)^[ \t]*AzureAdJoined[ \t]*:[ \t]*(YES|NO)[ \t]*\r?$')
        if ($matches.Count -ne 1) {
            throw 'Run Command did not return exactly one AzureAdJoined YES/NO result.'
        }
        $status = $matches[0].Groups[1].Value.ToUpperInvariant()
        Write-Host "  AzureAdJoined : $status"
    } catch {
        $status = 'UNKNOWN'
        $failure = $_.Exception.Message
        Write-Warning "CLOUD_JOIN_CHECK_FAILED: $failure No retry; Join remains unverified."
    }

    [pscustomobject]@{
        Joined = ($status -eq 'YES')
        Status = $status
        CheckedUtc = [datetime]::UtcNow.ToString('o')
        Error = $failure
    }
}
