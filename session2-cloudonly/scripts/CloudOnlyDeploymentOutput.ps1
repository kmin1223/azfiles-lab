function New-CloudDeploymentCommands {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Collections.IDictionary]$Info)

    $fields = @{
        RG = 'Resource group'; PREFIX = 'Prefix'; SA = 'Storage account'
        SHARE = 'File share'; TENANT = 'Azure tenant ID'; SUB = 'Subscription ID'
        SOURCE = 'Cloud Shell script directory'
    }
    $values = @{}
    foreach ($key in $fields.Keys) {
        $value = [string]$Info[$fields[$key]]
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "DEPLOY_OUTPUT_MISSING: $($fields[$key])"
        }
        $values[$key] = "'" + $value.Replace("'", "''") + "'"
    }
    $values['SPN'] = "'" + ("cifs/$($Info['Storage account']).file.core.windows.net").Replace("'", "''") + "'"
    $values['UNC'] = "'" + ("\\$($Info['Storage account']).file.core.windows.net\$($Info['File share'])").Replace("'", "''") + "'"
    $template = @'

==============================================================
LAB COMMANDS - run one section at a time, NOT this entire file
==============================================================
This file contains private credentials above. Keep it private.
Run labs only after Entra join and the Lab A user baseline succeed.
Configuration applied does NOT mean user access has been verified.
Use the resource names in this file, not another participant's examples.

[A] Azure Cloud Shell / PowerShell - management and Consent fault
[B] Windows VM / labuser1 NORMAL PowerShell - tickets and SMB access
[B-admin] SAME labuser1 / elevated PowerShell - local faults and trace
An Azure management login does not replace the Windows logon identity.

CONNECT
Open the downloaded azfiles-cloudonly.rdp on your local Windows computer.
It includes the actual FQDN, labuser1 UPN and enablerdsaadauth:i:1.
Supported mstsc: Advanced > Use a web account to sign in to the remote computer.
Use the registered, resolvable hostname, not the IP address.
Check unexpected certificate warnings; do not blindly accept them.
First sign-in/MFA registration follows your tenant's policy.
Use the labuser1 password recorded above; localadmin is bootstrap only.

LAB A - normal baseline [B]
Run these assignments again after reboot or opening a new PowerShell:
$storageAccount = {{SA}}
$shareName = {{SHARE}}
$spn = {{SPN}}
$shareUnc = {{UNC}}
whoami /upn
dsregcmd /status
klist cloud_debug
klist get $spn
klist
Get-ChildItem -LiteralPath $shareUnc -ErrorAction Stop

Expected: AzureAdJoined YES, DomainJoined NO, AzureAdPrt YES;
effective Cloud Kerberos policy 1, Cloud TGT, a fresh CIFS ticket,
and actual file listing. A cached ticket alone is not a fresh test.
Optional drive mapping (only if Z: is unused):
net use Z: $shareUnc /persistent:no

FRESH REQUEST - before comparisons and after repairs [B]
First inspect connections:
net use
Close files and remove ONLY this labshare connection if it is listed:
net use $shareUnc /delete
If it is mapped as Z:, remove that exact lab mapping instead:
net use Z: /delete
Do not run both delete commands blindly; never remove all connections.
In this dedicated lab logon only (purges its other Kerberos tickets too):
klist purge
klist get $spn
klist
Get-ChildItem -LiteralPath $shareUnc -ErrorAction Stop

LAB B / B+ - NoCloudTgt [B-admin]
C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt
Save work, then REBOOT THE VM. Sign back in as the same labuser1.
Use reboot even if an older fault script prints "SIGN OUT".
[B] Re-run the Lab A variable assignments, then:
dsregcmd /status
klist cloud_debug
klist
klist get $spn
Observe effective policy 0, Cloud Referral TGT 0 and no usable Cloud TGT.
Observed after reboot: 0x520 / 0x8009030e; exact codes can vary.
Record dsregcmd flags as observed; do not assume they stay YES.

LAB B REPAIR [B-admin]
C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt -Repair
Save work, REBOOT, then sign back in as the same labuser1.
[B] Re-run variables and the fresh-request checks above.
Require policy 1, Cloud TGT, new CIFS ticket and file access before Lab C.

LAB C - ProxyMangled [B-admin], only after B is fully recovered
Close Fiddler first; record the original proxy configuration:
netsh winhttp show proxy
C:\LabTools\Invoke-LabFault.ps1 -Fault ProxyMangled
[B] Make a fresh request and record the result.
[B-admin] Observe and repair:
netsh winhttp show proxy
C:\LabTools\Invoke-LabFault.ps1 -Fault ProxyMangled -Repair
[B] Repeat fresh-request checks. Verify original proxy and file access.

FIDDLER / KERBEROS.NET - before Consent injection
Open the public desktop shortcut "Fiddler Classic (Lab)".
The Inspector MSI is machine-staged; user loading is a separate check.
Approve only expected Kerberos.NET DLLs and verify the Kerberos tab.
Configure HTTPS capture/trust for this dedicated lab, not blanket TLS bypass.
Prove a normal Kerberos response and file access before injecting Consent.
HTTP 200 alone is not proof of Kerberos success; inspect the response body.
Capture actual Request/Trace/Correlation IDs when present, plus UTC time.

CONSENT - [A] your own Cloud Shell, full repository clone
Set-Location -LiteralPath {{SOURCE}}
$cloudRg = {{RG}}
$prefix = {{PREFIX}}
Set-AzContext -Tenant {{TENANT}} -Subscription {{SUB}}
Get-AzContext
Get-MgContext
Verify Azure/Graph tenant, permissions and target before proceeding.
Run only after B/C repair and the normal Fiddler baseline:
./faults/Invoke-Fault.ps1 -ResourceGroupName $cloudRg -Prefix $prefix -Fault ConsentRevoked
[B] Capture a FRESH CIFS request; existing tickets/connections may still work.
[A] Restore the same baseline (do not redeploy to repair):
./faults/Invoke-Fault.ps1 -ResourceGroupName $cloudRg -Prefix $prefix -Fault ConsentRevoked -Repair
[B] Repeat fresh-request and file-access checks, then close Fiddler normally.
Verify access also succeeds without Fiddler. Grant readback alone is not recovery.

OPTIONAL NETSH TRACE [B-admin]
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
[B] Reproduce the request in the normal labuser1 window.
[B-admin] Same elevated user that started the trace:
C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace
StopTrace converts ETL to pcapng automatically.
Convert an existing ETL only (replace this example with its actual path):
C:\LabTools\Get-KerberosEvidence.ps1 -ConvertTrace -Path 'C:\Private capture\trace.etl'
Output: private, unique folders under %LOCALAPPDATA%\AzFilesLab-Traces.
This helper only starts/stops netsh and converts ETL; it does not decrypt HTTPS.
Do not commit/share captures or credentials.

OPTIONAL AZURE POWERSHELL DIAGNOSTICS [B]
Get-Content -LiteralPath C:\LabTools\powershell-modules.json
Get-Module -ListAvailable Az.Accounts, Az.Storage, AzFilesHybrid
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Storage -MinimumVersion 8.1.0 -ErrorAction Stop
Import-Module AzFilesHybrid -MinimumVersion 0.3.0 -ErrorAction Stop
Get-Command Connect-AzAccount, Get-AzStorageAccount, Debug-AzStorageAccountAuth -ErrorAction Stop
Installed Az subset: Accounts, Storage, Resources, Network, Compute + dependencies.
AzFilesHybrid provides Debug-AzStorageAccountAuth; this is not the full Az meta-module.
Actual Azure diagnostics require a separate authorized management login:
Connect-AzAccount -Tenant {{TENANT}} -Subscription {{SUB}}
Get-AzContext
Debug-AzStorageAccountAuth -ResourceGroupName {{RG}} -StorageAccountName {{SA}} -Verbose
Use an account with the required storage management permissions (Owner per the guide).
The lab VM-login and SMB roles do not grant that management access.
Module import success is not Azure diagnostic or SMB access success.

END OF LAB
Repair faults, close traces/Fiddler and confirm the normal access baseline.
No resource deletion is automatic. Review the exact RG before any cleanup.
Directory users, device and storage app are tenant objects, not RG resources.
'@
    # A single substitution pass preserves literal quotes, dollars and token-like names.
    [regex]::Replace($template, '\{\{([A-Z]+)\}\}', {
        param($match)
        $values[$match.Groups[1].Value]
    })
}

function Send-CloudDeploymentDownloads {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]]$Paths)

    $ErrorActionPreference = 'Stop'
    $downloadCommand = Get-Command download -ErrorAction SilentlyContinue
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "DEPLOY_DOWNLOAD_MISSING: $path"
        }
        $manual = "download '" + $path.Replace("'", "''") + "'"
        Write-Host "Saved file: $path"
        Write-Host "Manual Cloud Shell download: $manual"
        if (-not $downloadCommand) {
            Write-Warning 'DEPLOY_DOWNLOAD_UNAVAILABLE: No Cloud Shell download command; files remain saved locally.'
            continue
        }
        try {
            $output = & $downloadCommand $path
            $succeeded = $?
            $output | Out-Host
            $resolved = if ($downloadCommand.CommandType -eq 'Alias') {
                $downloadCommand.ResolvedCommand
            } else { $downloadCommand }
            if (-not $succeeded -or ($resolved.CommandType -eq 'Application' -and $LASTEXITCODE -ne 0)) {
                throw 'The download command reported failure.'
            }
            Write-Host "Browser download requested: $path (check Downloads; allow multiple downloads if prompted)."
        } catch {
            Write-Warning "DEPLOY_DOWNLOAD_FAILED: $path - $($_.Exception.Message). Retry: $manual"
        }
    }
}
