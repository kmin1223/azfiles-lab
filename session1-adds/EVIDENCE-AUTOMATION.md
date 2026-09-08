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

## What is isolated

A protected SYSTEM task starts the machine-wide network trace. A separate
fixed task logs on as **non-admin `labuser1` with a password-based batch
logon**, giving the attempt a new logon session/LUID. That worker purges only
its own Kerberos cache and runs:

```powershell
net use \\<storage-account>.file.core.windows.net\<share> /persistent:no
```

The probe uses UNC only, not `Z:`. Standard input is closed so failed
authentication cannot wait indefinitely for a credential prompt. The probe
has a timeout, and the broker stops its owned capture even if reproduction
fails. Concurrent automated runs are rejected rather than sharing evidence.

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
The user can invoke the fixed broker but cannot edit the task definition or
protected code/configuration. The worker is not granted local administrator
rights. Administrators/SYSTEM still control this machine and its stored task
credentials; this is a dedicated lab convenience, not a production credential
vault or an arbitrary-user impersonation service.

The setup wrapper stages trusted repository sources using Azure VM Run Command
and encrypts the password with a temporary VM-local RSA public key before
transport. Only ciphertext crosses the new Run Command script/parameter
boundary; the VM decrypts it in memory and registers the task in-process.
No new plaintext password file or process-command-line argument is created.
The temporary certificate and staging directory are removed during cleanup;
an interrupted transport can require the explicitly reported cleanup.

This does not change the lab deployment's existing password/report handling.
Treat deployment logs, existing `lab-info` files, and all evidence as sensitive.
