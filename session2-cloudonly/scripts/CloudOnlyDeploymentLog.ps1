function Format-CloudDeploymentElapsed {
    param([Parameter(Mandatory)] [timespan]$Elapsed)
    '{0:00}:{1:00}:{2:00}' -f [math]::Floor($Elapsed.TotalHours), $Elapsed.Minutes, $Elapsed.Seconds
}

function Start-CloudDeploymentLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$LogPath)

    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $name = "cloudonly-deploy-$stamp-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction Stop | Out-Null
    $directory = New-Item -ItemType Directory -Path (Join-Path $LogPath $name) -ErrorAction Stop
    # Restrict the directory before creating files containing generated passwords.
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $sids = @(
            [Security.Principal.WindowsIdentity]::GetCurrent().User
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        )
        foreach ($sid in $sids) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($rule)
        }
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            [IO.Directory]::SetAccessControl($directory.FullName, $acl)
        } else {
            [IO.FileSystemAclExtensions]::SetAccessControl($directory, $acl)
        }
    } else {
        & chmod 700 -- $directory.FullName
        if ($LASTEXITCODE -ne 0) {
            throw 'DEPLOY_LOG_PERMISSIONS_FAILED: Could not restrict the log directory. No deployment started.'
        }
    }

    $run = [pscustomobject]@{
        Directory = $directory.FullName
        Transcript = Join-Path $directory.FullName 'deploy.log'
        InfoFile = Join-Path $directory.FullName 'lab-info.txt'
    }
    Start-Transcript -LiteralPath $run.Transcript -NoClobber -ErrorAction Stop | Out-Null
    $run
}

function Save-CloudDeploymentInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Run,
        [Parameter(Mandatory)] [System.Collections.IDictionary]$Info
    )
    $lines = @(
        'Azure Files Cloud-only deployment'
        'SENSITIVE: contains generated lab credentials. Do not commit or share.'
        'IN PROGRESS means no final outcome was recorded; inspect deploy.log.'
        ''
    )
    foreach ($key in $Info.Keys) { $lines += '{0} : {1}' -f $key, $Info[$key] }
    $temporary = Join-Path $Run.Directory 'lab-info.tmp'
    $lines | Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
    Move-Item -LiteralPath $temporary -Destination $Run.InfoFile -Force -ErrorAction Stop
}

function Complete-CloudDeploymentLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Run,
        [Parameter(Mandatory)] [System.Collections.IDictionary]$Info,
        [Parameter(Mandatory)] [timespan]$Elapsed,
        [bool]$Completed,
        [bool]$Joined,
        [AllowNull()] [object]$Failure
    )
    $loggingFailure = $null
    try {
        $Info['Finished UTC'] = [datetime]::UtcNow.ToString('o')
        $Info['Elapsed'] = Format-CloudDeploymentElapsed $Elapsed
        $Info['Status'] = if ($Failure) { 'FAILED' } elseif (-not $Completed) { 'INTERRUPTED' } elseif ($Joined) {
            'CONFIGURATION APPLIED - USER BASELINE REQUIRED'
        } else { 'INCOMPLETE - ENTRA JOIN NOT CONFIRMED' }
        if ($Failure) { $Info['Error'] = $Failure.Exception.Message }
        Write-Host "`nStatus        : $($Info['Status'])"
        Write-Host "Total elapsed : $($Info['Elapsed']) (hh:mm:ss)"
        Write-Host "Transcript    : $($Run.Transcript)"
        Write-Host "Lab info      : $($Run.InfoFile)"
        Save-CloudDeploymentInfo -Run $Run -Info $Info
    } catch {
        $loggingFailure = $_
        Write-Warning "DEPLOY_LOG_FINALIZE_FAILED: $($_.Exception.Message)"
    } finally {
        try {
            Stop-Transcript -ErrorAction Stop | Out-Null
        } catch {
            if (-not $loggingFailure) { $loggingFailure = $_ }
            Write-Warning "DEPLOY_LOG_STOP_FAILED: $($_.Exception.Message)"
        }
    }
    # Preserve the deployment's original exception if logging also fails.
    if ($loggingFailure -and -not $Failure) { throw $loggingFailure }
}
