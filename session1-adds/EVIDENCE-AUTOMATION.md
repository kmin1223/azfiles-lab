# One-command Session 1 evidence

After deployment prints `AUTO_EVIDENCE_READY`, run this in the **normal,
non-elevated `labuser1` PowerShell window on the client VM**:

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
```

**Approve one UAC consent per capture.** No password is entered per capture,
no RDP logout is required, and no separate `-StopTrace` is needed. The command
waits and displays results and the run directory in the original window.

## How it works

1. The normal client generates a run GUID and records its actual logon LUID.
   `Start-Process -Verb RunAs` opens an elevated capture coordinator as the
   same configured `labuser1`. This is the single UAC consent.
2. The coordinator holds the exclusive capture/install lock, creates a new
   protected run directory, and starts the machine-wide network trace.
3. The coordinator reads the stored deployment credential and uses
   **`Start-Process -Credential`**, separately from `-Verb RunAs`, to launch
   the fixed protected worker script. The password is a `PSCredential`/
   `SecureString`, not interpolated into any worker process arguments.
4. Before reproduction, the worker verifies the configured SID, a
   **non-elevated effective token**, and an actual **interactive logon,
   type 2**, created after this launch request with a different LUID from
   the caller. Unexpected elevation, reused LUIDs, and other logon types fail
   closed. `-Credential` is not an elevation request and is never combined
   with `-Verb RunAs`. This is not a batch logon or the existing RDP context.
5. The worker purges only its own ticket cache and attempts
   `net use \\<account>.file.core.windows.net\<share> /persistent:no`.
   `net.exe` uses its absolute System32 path, closed stdin and a 120-second
   limit. There is **no drive mapping or existing-session reset**.
   The worker then collects time-correlated DC Security evidence.
6. The coordinator waits at most 180 seconds for the launched worker,
   validates run GUID/PID/SID/LUID/target/interval correlation, collects
   privileged snapshots, and stops **only the capture it started**, in
   `finally`. The original caller reads that run's protected summary and
   displays the worker's output under its own non-elevated identity.

No custom service, Scheduler registration, RSA bootstrap, `runas.exe`
password arguments or keyboard automation is used. The worker owns a
kill-on-close job for its descendants; timeout cleanup kills only the
process returned by this launch and its job's descendants.

The lab's existing local Administrators membership for `labuser1` is retained
so UAC can be **consent**, rather than an administrator password prompt.
UAC must be enabled with consent policy and the Windows Secondary Logon
service/logon policy must permit credential-based interactive process creation.
Domain Admins and Enterprise Admins are rejected. A deny-only Administrators
SID does not mean elevation; the worker checks the enabled token role using
`WindowsPrincipal.IsInRole(Administrator)`.

This implementation has local Windows PowerShell 5.1/Pester coverage, including
synthetic DPAPI round trips and read-only native token inspection. **It has not
yet been validated on the deployed VM.** The first VM check must confirm the
actual UAC policy, Secondary Logon, type-2 fresh LUID, non-elevated token, UNC
attempt, DC access and successful capture cleanup. A policy/token mismatch is
a failure, not a reason to weaken the guards.

## Setup and existing VMs

From an updated repository in Azure Cloud Shell, run:

```powershell
./Update-LabEvidenceAutomation.ps1 -ResourceGroupName azfiles-lab
```

Supply the deployed **domain `labuser1` password once** if prompted. For custom
deployments use `-Prefix`, `-VMName`, `-StorageAccount`, `-DomainController`
and/or `-Share`. New `deploy.ps1` runs pass the existing deployment credential
in memory, without a second setup prompt. Rerun the update with the new
credential after a password change.

The API and **one VM Run Command** are unchanged: exactly three trusted source
files are staged (installer, runtime, extracted collector). The update installs
only evidence automation, not Azure resources, users, UAC policy, storage keys
or fault repairs.

### One-time migration from the removed Scheduler version

For safety, setup **aborts before changing installed files** if either exact
legacy task file is present:

* `\AzureFilesLabEvidence\Broker`
* `\AzureFilesLabEvidence\Worker`

It does not run, stop, disable or delete tasks automatically, does not change
other task folders, and does not revoke logon rights. New installations need
no Scheduler service or objects; the migration guard only checks those two
fixed files under `C:\Windows\System32\Tasks`.

On a legacy VM, an administrator must retire those two tasks once:

1. Stop requesting old captures. Inspect both task definitions and confirm
   their actions are the old **fixed AzureFilesLabEvidence runtime**, not
   unrelated work. Inspect protected `state.json` and any existing evidence.
2. Disable only these two known tasks to prevent new starts, and wait for
   active/queued runs and their owned capture cleanup to finish. **Do not
   forcibly stop active tasks or blindly run `netsh trace stop`.** If cleanup
   failed or ownership is unresolved, investigate and resolve that first.
3. After confirming both are idle and owned by this lab installation, remove
   only those two tasks through Task Scheduler. Do not delete the task files
   by hand. Other tasks, evidence and permissions remain untouched.
4. Rerun the update command. The empty legacy folder may remain; normal setup
   and capture never use it.

This deliberate one-time administrative migration avoids silently replacing
scripts that an older SYSTEM task could still execute. It is not a recurring
capture step and does not require logging out of RDP.

### Installation diagnostics

Failures retain the installation stage, error ID, actual redacted error, source
line and log location in a run-specific administrator-only directory:

```text
C:\Program Files\AzureFilesLabEvidenceBootstrap-<run-id>\install.log
```

`AUTO_EVIDENCE_READY`/`AUTO_EVIDENCE_FAILED` records are correlated to the
bootstrap run. ARM transport success alone is not setup success. Errors before
staging explicitly report that no VM log was created. Transport interruptions
can prevent any structured result; inspect the VM rather than redeploying.
Readiness confirms installation, not a successful credential logon or capture;
those are checked when the normal command runs.
Staged scripts/logs and old unrelated bootstrap artifacts are not broadly
deleted. Unsafe owners, reparse paths and untrusted write ACLs still fail.

## Credential storage and trust

**Dedicated disposable lab only. Use a unique password, never a production
credential.** Setup persists it in:

```text
C:\Program Files\AzureFilesLabEvidence\Credentials\credential.json
```

The directory and file are accessible only to Administrators/SYSTEM. The
password is machine-scope Windows DPAPI ciphertext, allowing installation by
SYSTEM and subsequent reading by the UAC-elevated lab account. It is not
user-scope `Export-Clixml`, which would bind decryption to the installing user.
Configuration and trusted scripts are user-readable but only administrator/
SYSTEM-writable; worker evidence is kept in a separate user-writable folder.

**This is not a credential vault or a security boundary against labuser1.**
That account can consent to elevation; administrators/SYSTEM can recover or
replace this credential. Machine DPAPI alone is not access control: anyone
on this machine who obtains the encrypted blob may be able to decrypt it.
Protect the ACLs, VM disks/backups and logs. Plaintext necessarily exists
briefly in privileged memory and the Windows logon API; no guarantee is made
against a compromised administrator, memory inspection or crash dumps.

The setup wrapper still sends the password as an **ordinary Azure VM Run
Command parameter**. HTTPS protects transport, but this is **not a secret
parameter**: Azure/VM diagnostics or setup process arguments may expose it.
The scripts redact matching password text in their installation diagnostics
and do not intentionally write plaintext to `install.log` or worker arguments.
Do not screen-share setup. Existing `lab-info` and private command-sheet files
retain their established password handling (including plaintext passwords);
do not share or commit them. Updating the protected local credential does not
erase previous diagnostic copies.

## Results, failures and recovery

Each GUID run under `C:\ProgramData\AzureFilesLabEvidence\Runs` has:

| Location | Meaning |
| --- | --- |
| `user\mount-result.txt` | UNC result; a nonzero SMB/authentication exit can be the expected fault |
| `user\reproduction.json` | Actual identity, LUID, elevation, target, interval, exit and timeout |
| `user\klist-original.txt`, `klist-before.txt`, `klist-after.txt` | Fresh worker's ticket cache, not the original caller's |
| `user\dc-summary.txt`, `dc-collection.json`, `dc-*` | DC Security results and access/truncation details |
| `user\done.json`, `worker-output.txt` | Worker completion/failure diagnostics |
| `capture\trace.etl`, optional `trace.pcapng` | Machine-wide trace; may include unrelated traffic |
| `capture\reproduction.json`, `automation-summary.json` | Validated context and final coordinator outcome |
| `capture\worker-stdout.txt`, `worker-stderr.txt` | Process startup/token-guard errors, even before user evidence exists |
| `capture\*-collector.*` | Privileged snapshots, not the worker's own ticket cache |

User-writable reports are validated for consistency, **not cryptographic
attestations**. A completed probe with nonzero SMB exit is valid evidence;
launch/logon, token, timeout, DC collection/truncation, correlation and
capture-cleanup errors are collection failures. Preserve partial output.
A successful UNC connection proves neither file read/write authorization nor
the cause of an earlier failure. Ticket issuance is not server acceptance.

Cancelling UAC reports cancellation without requesting capture. Worker launch
errors identify the launch stage and Windows error code without echoing the
password. Credential/UAC launch itself uses synchronous Windows APIs; consent
and OS logon latency are not worker execution time. After coordinator launch,
the original caller waits at most 11 minutes. A caller timeout does **not**
kill the elevated coordinator: cleanup may continue independently.

If capture stop or worker cleanup fails, protected `state.json` retains
unresolved ownership and subsequent runs/setup refuse to proceed. An
administrator must inspect the exact recorded run/PIDs and machine trace,
resolve only the owned resources, and reconcile the recovery marker after
verified cleanup. Never clear the marker just to bypass the guard or blindly
stop another person's trace. Concurrent automatic runs are excluded by the
same lock as installation; never overlap manual and automatic captures.

## Explicit manual path

A new credential-created type-2 logon is **not equivalent to the existing
interactive RDP/application session**. Keep manual capture for session-specific
faults, application state, interactive GPO/profile behavior, or faults that
prevent a new Windows logon (for example, some clock-skew cases).

```powershell
# Elevated window:
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace -Manual

# Actual affected user's normal window:
C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <name> -Share labshare

# Original elevated window:
C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace
```

The legacy manual flow is unchanged. Mapping deletion and `klist purge` alone
do not prove an existing SMB session was destroyed.
