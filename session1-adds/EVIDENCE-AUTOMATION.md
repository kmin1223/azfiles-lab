# One-command Session 1 evidence

After deployment prints `AUTO_EVIDENCE_READY`, run this in the **normal
`labuser1` PowerShell window on the client VM** after each fault and repair:

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
```

The command waits for capture, reproduction, and collection to finish and
prints the result and run-folder path in the original window. It does not
require another password prompt, RDP sign-out, drive-letter reset, or separate
`-StopTrace`.

## Existing deployed VMs

Update the local/cloud copy of this repository first. In Azure Cloud Shell,
from `session1-adds`, run:

```powershell
./Update-LabEvidenceAutomation.ps1 -ResourceGroupName azfiles-lab
```

Supply the deployed **domain `labuser1` password once** when prompted. For a
custom deployment, specify `-Prefix`, `-VMName`, `-StorageAccount`,
`-DomainController`, and/or `-Share` as needed. This installs/updates only the
evidence automation on the client: it does not redeploy the lab, rotate the
storage identity key, or repair an active fault.

New `deploy.ps1` runs pass the existing deployment credential in memory, so no
second setup prompt is needed. If the password changes later, rerun this
update command with the new credential.

### Installation failures

The update uses **one VM Run Command**. It does not need an RSA certificate or
a separate password-encryption exchange. Do not redeploy the resource group
just because this post-deployment step failed.

Failures report the stage, actual error message, script/line, error ID, and a
VM-local log path. Staged scripts and `install.log` remain in the run-specific
administrator-only folder:

```text
C:\Program Files\AzureFilesLabEvidenceBootstrap\<run-id>\install.log
```

An error before that directory is created is returned directly without a log
path. An Azure transport interruption might also prevent a structured response.
Only a matching readiness record counts as completed installation; ARM request
success alone does not.

The older `Credential details withheld` message did not identify the actual
failure. After updating the repository, rerun only the update command above.
The installer repairs inherited write permissions on its known LabTools root
when safe to do so, publishes the trusted helper, and preserves existing
evidence subfolders. It still refuses unsafe ownership and linked paths.

If an older installer reports `The supplied account is an administrator`,
update the scripts and rerun the update command. The lab deliberately adds
`labuser1` to the client's local Administrators group for manual UAC consent.
The installer now allows that membership; it does not remove it, change UAC,
or require signing out. Domain Admins and Enterprise Admins remain rejected.
The client and worker must still pass the effective-token check at run time.

## What is isolated

A protected SYSTEM task starts the machine-wide network trace. A separate
fixed task logs on as **`labuser1` with a non-elevated, password-based batch
logon**, giving the attempt a new logon session/LUID. That worker purges only
its own Kerberos cache and runs:

```powershell
net use \\<storage-account>.file.core.windows.net\<share> /persistent:no
```

The probe uses UNC only, not `Z:`. Standard input is closed so failed
authentication cannot wait indefinitely for a credential prompt. The probe
has a timeout, and the broker stops its owned capture even if reproduction
fails. Concurrent automated runs are rejected rather than sharing evidence.

The worker uses Task Scheduler `TASK_RUNLEVEL_LUA` (least privilege), not
`TASK_RUNLEVEL_HIGHEST`. With UAC enabled, a local administrator can run with a
filtered token. The Administrators SID can remain in that token as deny-only;
its presence alone does not mean the process is elevated.
The runtime uses `WindowsPrincipal.IsInRole(Administrator)` to check the
effective token. If the worker has administrator rights, it stops before
mounting. UAC must remain enabled for this local-administrator lab setup.
See [Task Scheduler security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
and [WindowsPrincipal.IsInRole](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsprincipal.isinrole).

Existing SMB connections and drive mappings in the original RDP logon are not
the reproduction context and are not disconnected. Read the **worker's**
ticket files and `reproduction.json`, not `klist` in the original window.

## Reading the result

The returned folder under `C:\ProgramData\AzureFilesLabEvidence` separates
worker-writable `user` evidence from protected `capture` output:

| Location | Meaning |
| --- | --- |
| `user\mount-result.txt` | Actual UNC connection output; a nonzero mount result can be the expected fault observation |
| `user\reproduction.json` | Worker identity, LUID, elevation, UNC mode, interval, exit code, timeout/error |
| `user\klist-original.txt`, `klist-before.txt`, `klist-after.txt` | Worker ticket cache around purge and mount |
| `user\dc-summary.txt`, `dc-collection.json`, `dc-*` | DC Security reads as the domain worker; inspect access failures, truncation, and candidate matching |
| `capture\trace.etl` | Machine-wide network trace, which can include unrelated traffic |
| `capture\trace.pcapng` | Conversion output when the optional protected converter is available |
| `capture\*-collector.*` | Privileged snapshots, not evidence of the worker's own ticket cache |

A successful UNC connection proves neither file write/read permission nor the
cause of a previous failure. Inspect packet operation/status/security tokens
and DC records together. A ticket being issued is not proof the server accepted
it. A noninteractive failure may return a different `net use` message/code from
the old interactive credential-prompt/cancel flow.

Task launch, timeout, trace-stop, or validation failures are collection
failures, distinct from a normally completed probe that observes an SMB error.
Keep partial output. If trace cleanup is reported as failed, do not repeatedly
launch new runs or blindly stop another person's trace; an administrator must
inspect the reported state and resolve capture ownership first.

## When to keep manual capture

A batch logon is **not equivalent to the existing interactive RDP/application
session**. Use manual capture for user-session-specific failures, interactive
GPO/profile behavior, and faults that prevent the worker from logging on
(for example, some clock-skew scenarios).

```powershell
# Elevated window: explicit Manual bypasses the automatic default.
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace -Manual

# Actual affected user's normal window:
C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <name> -Share labshare

# Original elevated window:
C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace
```

Manual capture retains its existing behavior. Deleting mappings and running
`klist purge` alone still do not prove the old SMB session was destroyed.
Do not overlap manual and automatic captures.

## Credential and privilege boundary

Windows Task Scheduler stores the worker credential for the fixed lab task.
The non-elevated user can invoke the fixed broker but cannot edit the task
definition or protected code/configuration from that token. The lab retains
local administrator membership for manual UAC consent; this is not an account
that can never elevate, and UAC is not a security boundary against that user.
The worker runs without enabled administrator rights. Administrators/SYSTEM
still control this machine and its stored task
credentials; this is a dedicated lab convenience, not a production credential
vault or an arbitrary-user impersonation service.

**Disposable lab only:** the setup wrapper passes the password as an ordinary
Azure VM Run Command parameter, like the lab's other deployment steps. Azure
control-plane transport uses HTTPS, but the parameter is **not a secret
parameter**: it may appear in Azure/VM diagnostics or process arguments.
Use a unique lab password, never a production credential, and do not share the
setup screen.

The VM builds a PSCredential and registers the task in-process. The wrapper does
not embed the password in repository scripts or intentionally save it in
`install.log`; matching password text is redacted from its diagnostic output.
This is not a guarantee that Azure or the VM agent will redact the parameter.
There is no new certificate or credential file to manage.

Existing deployment logs and `lab-info` files retain their previous password
handling. Treat them and all evidence as sensitive. Old RSA-bootstrap artifacts
are not broadly deleted by this update; only inspect/remove a confirmed old
run's artifacts if cleanup was previously interrupted.
