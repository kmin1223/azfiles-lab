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
