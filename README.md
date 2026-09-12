# Azure Files Identity-Based Auth — Hands-On Lab Kit

> **Publishing this repo?** It's safe to make public — no secrets, keys,
> subscription/tenant IDs, or real IPs are stored here (a lab password is
> auto-generated at runtime; kerb keys are fetched at runtime). The repo
> deliberately carries **only the deploy/lab automation**: decks (`*.pptx`) and
> all documents (`docs/`) are distributed separately and may reference
> Microsoft-internal tooling — the `.gitignore` keeps them out. Never add the
> source Microsoft support-wiki PDFs (Microsoft Confidential / NDA).

Two 60-minute sessions. In Session 1, attendees deploy at minute 0 and follow
guided break/fix labs. Session 2 has two separate tracks: **participants do
cloud-only hands-on labs; only the presenter builds and demonstrates hybrid
labs**. Both Session 2 environments must be prepared before the session.

Session 2 runs **shared concepts → one prebuilt hybrid demo (healthy access,
one fault, recovery) → continuous participant cloud-only labs A, B/B+, C and
capstone → wrap-up**. Additional hybrid demos are optional follow-up, not
interruptions to participant hands-on.

| Session | Topic | Deploy time | Automation |
|---|---|---|---|
| 1 | On-prem AD DS auth (simulated with an Azure DC) | ~15 min | `session1-adds/deploy.ps1` — fully unattended |
| 2 — Hands-on — Cloud-only | Microsoft Entra Kerberos, cloud-only identities | Prework; allow time for deployment, join, RBAC and first sign-in | `session2-cloudonly/deploy.ps1` |
| 2 — Presenter demo — Hybrid | Microsoft Entra Kerberos, synced AD identities | Presenter-only prework and rehearsal | Connect Sync + hybrid join, then `session2-entra-kerberos/setup.ps1` |

Participants do **not** need to retain or redeploy Session 1 for Session 2.
Their cloud-only environment uses a separate resource group, `azfiles-cloudonly`,
with no DC, AD join or directory synchronization. Only the presenter may reuse a dedicated
Session 1 deployment for the hybrid demo. Enabling AADKERB on that storage
account replaces its AD DS authentication; do not convert an account still
needed for a Session 1 demo.

## Contents

```
azfiles-lab/
├── README.md                        <- you are here
├── cleanup.ps1                      <- Session 1 / presenter hybrid teardown
├── session1-adds/
│   ├── deploy.ps1                   <- attendees run THIS at session start
│   ├── template/azuredeploy.json     <- ARM template (no Bicep needed)
│   ├── scripts/                     <- run-command payloads (DC/client, incl. tool install)
│   └── faults/Invoke-Fault.ps1      <- break/fix scenarios (5 faults)
├── session2-cloudonly/              <- PARTICIPANTS: standalone prework
│   ├── deploy.ps1
│   ├── scripts/client-config.ps1    <- installs VM-local faults for Labs B/C
│   └── faults/Invoke-Fault.ps1      <- cloud-only service-side faults
├── session2-entra-kerberos/          <- PRESENTER ONLY: hybrid demos
│   ├── setup.ps1
│   ├── MANUAL-STEP-connect-sync.md  <- presenter-only Connect Sync / hybrid join setup
│   ├── scripts/
│   └── faults/Invoke-Fault.ps1      <- presenter hybrid break/fix scenarios
└── tools/
    └── New-LabToolsBundle.ps1       <- PRESENTER ONLY: build the module bundle
```

> Decks, workbooks, the cue sheet, the facilitator guide and the diagnostic
> flowchart are **not in this repo** — the presenter distributes them directly
> (mail/Teams) before the session.

## Presenter prerequisite: publish the module bundle (one time)

The client VM needs Az + AzFilesHybrid. Installing those from the PowerShell
Gallery takes about nine minutes per attendee and sits on the critical path of
the deployment, so the VM downloads a prebuilt bundle instead — one zip, about
a minute.

Build and publish it once (Cloud Shell is fine):

```powershell
./tools/New-LabToolsBundle.ps1 -Trim
gh release create tools-v1 labtools-modules.zip --repo kmin1223/azfiles-lab \
  --title 'Lab tooling module bundle' --notes 'Prebuilt Az + AzFilesHybrid modules.'
```

`scripts/07-install-tools.ps1` points at `/releases/latest/download/labtools-modules.zip`,
so refreshing later is just `gh release upload tools-v1 labtools-modules.zip --clobber`.

> If the bundle is missing or unreachable, the deployment still works — the
> script falls back to `Install-Module` and simply takes longer. Point somewhere
> else with `deploy.ps1 -ModuleBundleUri <url>`.

## Attendee prerequisites (send before Session 1)

- An Azure subscription with **Owner** (RBAC + storage changes needed) and
  quota for 2× `Standard_B2ms` VMs.
- For Session 2: **Global Administrator** on a disposable dev/trial Entra tenant —
  needed by the lab automation for cloud-user creation and app consent.
  Participants do not configure directory synchronization. A personal dev tenant
  (e.g., via the M365 developer program or a new trial) is strongly
  recommended over a corporate tenant.
- **Azure Cloud Shell** — the one supported place to run the deploy and fault
  commands. Nothing to install (Az + Microsoft.Graph preinstalled), already
  signed in, no execution-policy or unblock friction.
- RDP client — the in-VM klist/mount steps aren't a shell task.
- **Plain ARM template** — nothing extra to install.

> Run deployment and cloud-side faults from Cloud Shell. Session 2 participant
> Labs B/C run inside the Windows VM instead. Cloud Shell examples use
> forward-slash paths (`./deploy.ps1`) and need no `Connect-AzAccount`
> when the correct subscription context is already active.

## Session 1 quick start (attendees)

Open Cloud Shell (PowerShell) at <https://portal.azure.com> → the `>_` icon.
You're already signed in, and Az/Microsoft.Graph are preinstalled — no setup,
no `Connect-AzAccount`.

```powershell
git clone https://github.com/kmin1223/azfiles-lab.git
cd azfiles-lab/session1-adds
./deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

*(Multiple subscriptions? Run `Set-AzContext -Subscription "<name-or-id>"`
before deploy.)*

The deploy is fully automated from here: forest promotion, lab users
(`labuser1`/`labuser2`), client domain join, storage account domain join
(computer account + SPN + kerb1 key), AD DS auth enablement, default share
permission, and NTFS ACLs. It lands in the **supported configuration** —
AES-256 with the DNS root in `ActiveDirectoryDomainName`. The AES-256 migration
lab regresses it to the legacy RC4 state on demand (`-Step Legacy`), so the
deployment itself is never left in a broken shape. A verified environment takes about 13–16 minutes;
the diagnostic tooling (Az + AzFilesHybrid) installs on the client **after**
that, off the critical path, so a slow download can't hold up the lab.

`Invoke-Aes256Migration.ps1 -Step Legacy` combines the RC4 setting and AD
password synchronization in one DC Run Command. It retains the 15-second
key-refresh wait and the subsequent client mount probe. Legacy, Enforce, and
Repair skip `repadmin /syncall` when the domain has only one DC; domains with
multiple DCs retain the replication step. No extra Run Command is needed to
check the topology.

### Collect Client and DC evidence for a mount attempt

The client installer generates `C:\LabTools\Get-KerberosEvidence.ps1`. Wait for
the **post-deployment client tools installation** before using it; the
`DEPLOYMENT COMPLETE` banner alone does not mean the collector is installed.
The DC setup grants the lab evidence-reader group read access and enables
remote event-log access from the lab client's private address only. It does
not make the lab users domain administrators.
The two dedicated RPC firewall rules apply on all network profiles, but remain
restricted to the client's single private IP, the service, and its RPC ports.
A newly promoted DC can retain the Public network profile; Domain-only rules
then do not apply, even though the DC and client belong to the domain.
TCP 135 connectivity alone is not sufficient: the Event Log service's dynamic
RPC port must also be reachable. Do not disable the firewall or open the entire
dynamic port range to work around this.
The two lab users are added directly to the built-in Event Log Readers group;
the DomainLocal evidence-reader group is used separately for the Security
channel read ACE. Nesting that DomainLocal group into the built-in group fails
with AD error 8520.
Source updates do not update existing VMs automatically. Existing lab users
must sign out and sign in again after the DC reader-group membership is applied.

If deployment stopped during DC evidence setup (group membership or Security
configuration parsing), stop the retrying deploy, update the source, and rerun
with the same resource group and the original
password supplied through `-AdminPassword` (a SecureString). Existing lab users
are retained, so omitting that parameter and generating a new password would
not synchronize their passwords. The partially created reader group is reused.

Use **two PowerShell windows, three steps** on the client:

```powershell
# Elevated window: uses the DC recorded by deployment.
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace

# Normal window: reproduce as the affected user.
C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <sa> -Share labshare

# Return to the elevated window.
C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace
```

Reproduce saves the original ticket/mapping state, then **resets the selected
mappings and purges this logon session's tickets** before mounting. Use one
reproduction per capture. The elevated Stop snapshots have a `-collector`
suffix and do not replace the reproducing user's snapshots.

Stop retrieves **DC Security events 4768, 4769 and 4771** for the recorded
reproduction interval, with five seconds of padding on each side, independently
of whether Wireshark/tshark is installed. Results appear in the console and in
the same `C:\LabTools\evidence\<run>\` directory:

| File | Purpose |
|---|---|
| `reproduction.json` | UTC interval, user/SID/LUID, target and mount exit code |
| `dc-summary.txt` | Per-DC collection status and candidate event table |
| `dc-<name>\security.xml`, `.json`, `.csv` | Original event XML and structured fields for the queried interval |
| `dc-collection.json` | Counts, errors and explicit truncation status |
| `azure-files-handoff.txt` | Target/context and UTC interval for manual service-side investigation |

The default per-DC limit is 2,000 events; a limit hit is explicitly reported.
Candidate matches use user, client IP or service fields, but all returned events
are retained. A successful empty query is **not** the same as an access/RPC
failure, and neither proves that the KDC was never contacted. Check the actual
KDC, cached tickets, clock offsets, audit settings and log retention.

Override DC selection with `-DomainController <dc-fqdn>` on Start/Stop. Multiple
DC names are supported; automatic discovery chooses a candidate, not necessarily
the KDC that handled a request in a multi-DC environment. Retry just the DC read
without resetting mappings or tickets:

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -CollectDc -Path C:\LabTools\evidence\<run> `
    -DomainController <dc-fqdn> -MaxDcEvents 5000
```

If another read identity is needed, supply `-DcCredential (Get-Credential)` on
Stop or CollectDc. Credentials are used in memory and are never written to the
run/config files. A credential supplied during Start preflight must be supplied
again for Stop; it is deliberately not persisted.

Trace summaries show **observations, not root-cause verdicts**. Ticket issuance
does not prove Azure Files accepted the ticket, and security-buffer length does
not separate authentication from cipher/authorization failures. Azure Files
backend logs remain a separate, authorized manual collection step; the handoff
file helps correlate the attempt but does not contain a backend Activity ID.

### If your shell disconnects mid-deploy

Cloud Shell drops the session after roughly 20 minutes without interaction, and
that kills the running script. Nothing is lost, because the deploy writes to
`~/azfiles-lab-logs/` as it goes:

| File | What it holds |
|---|---|
| `lab-info-<timestamp>.txt` | resource group, storage account, RDP addresses, credentials to use — written **as soon as the ARM deployment finishes**, then rewritten with the final result and total run time |
| `deploy-<timestamp>.log` | full transcript, each step stamped with elapsed time |

```powershell
Get-Content ~/azfiles-lab-logs/lab-info-*.txt | Select-Object -Last 30
```

If `lab-info` still says **IN PROGRESS**, the run didn't finish. Find the last
`[+mm:ss] === step ===` line in the transcript, then re-run `deploy.ps1` with the
same `-ResourceGroupName` — the steps are re-runnable and skip completed work.

## Session 2 quick start (attendees)

**Hands-on — Cloud-only.** Complete this before the session. Session 1 is not
a prerequisite. Use Cloud Shell PowerShell, an Owner subscription, a dev/trial
tenant, and quota for one `Standard_D2s_v5` VM. Use a short, lowercase,
participant-unique prefix so the public DNS label does not collide in the region.

```powershell
# From the repository root
./session2-cloudonly/deploy.ps1 -ResourceGroupName azfiles-cloudonly -Prefix <your-prefix>
```

Download the generated RDP file, sign in as the generated Entra lab user, and
complete any required MFA registration. Before attending, confirm
`AzureAdJoined: YES`, `DomainJoined: NO`, `AzureAdPrt: YES`, a CIFS service ticket,
and a successful mount. A deployment completion message alone is not this gate.
Use the same prefix in later cloud-side fault commands.

### Session 2 presenter setup (hybrid)

**Presenter demo — Hybrid.** Use Microsoft Entra Connect Sync, not the Cloud Sync
device-sync preview. Complete all setup before presenting:

1. Prepare a separate Session 1 AD DS lab; do not convert the storage account
   still needed for Session 1 demonstrations.
2. Follow `session2-entra-kerberos/MANUAL-STEP-connect-sync.md` to install
   Connect Sync on a supported host, configure password hash synchronization,
   include both lab users and the client computer in scope, and configure
   hybrid join/SCP with the Connect wizard. Verify the synchronized identities,
   device registration and user PRT.
3. Run the storage/client setup below, then verify the effective cloud Kerberos
   policy, new CIFS ticket and successful mount.

```powershell
# From the repository root, against the presenter's dedicated hybrid lab only
./session2-entra-kerberos/setup.ps1 -ResourceGroupName azfiles-lab
```

The manual guide is the source of truth for host prerequisites, UPN matching
and safe retirement of any previous Cloud Sync enrollment. Never synchronize
the same objects concurrently with both engines. Rehearse healthy access plus each planned fault
and repair. Participants watch these demonstrations; they do not run this setup
or its fault commands. Keep a known-good recording as a fallback for live demos.

## Break/fix (run only the commands for your track)

```powershell
# Session 1  (from the session1-adds folder)
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch -Repair
# Faults: PasswordMismatch | SpnBroken | EtypeMismatch | Block445 | NoShareAccess
#         CipherMismatch | ClockSkew | DuplicateSpn

# The AES-256 migration lab is a separate, staged script (the centerpiece):
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Legacy   # plant the 2023 defect (~3 min)
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Enforce  # comply -> error 1396
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Repair   # fix, in the order that matters

# Session 2 — PARTICIPANTS, on the cloud-only VM in elevated PowerShell
C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt
# Do not repair until Lab B+ finishes; then repeat with -Repair.
# Other local fault: ProxyMangled

# Session 2 — PARTICIPANTS, Cloud Shell from session2-cloudonly
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-cloudonly -Prefix <your-prefix> -Fault NoShareAccess
# Other service-side fault: ConsentRevoked (capstone)

# Session 2 — PRESENTER ONLY, Cloud Shell from session2-entra-kerberos
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
# Faults: NoCloudTgt | ConsentRevoked | NotHybridJoined | NoShareAccess | ProxyMangled
```

Every fault maps to a real-world support issue (error 1396, 1327, 64/67,
KRB5KRB_AP_ERR_MODIFIED, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, ETYPE_NOSUPP, missing
cloud TGT, revoked consent…). The facilitator guide has the full
symptom → diagnosis → fix catalog.

## Cleanup (after Session 2)

**Participants — cloud-only:** delete only your cloud-only resource group.

```powershell
Remove-AzResourceGroup -Name azfiles-cloudonly -Force -AsJob
```

After Azure deletion completes, remove any remaining lab-owned Entra users,
device, storage application and service principal. Do not delete similarly
named objects belonging to another lab. There is no directory synchronization to remove.

**Presenter — hybrid:** BEFORE deleting the DC or sync host, follow the retirement
checklist in `session2-entra-kerberos/MANUAL-STEP-connect-sync.md`.
Remove only lab-owned objects from the synchronization scope/source and verify
the deletion exports while Connect Sync and AD are still running, then retire
the dedicated lab sync host. Do not stop a shared sync service or disable
directory synchronization tenant-wide. After completing the checklist:

```powershell
./cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra -ConnectSyncRetired
```

`-ConnectSyncRetired` acknowledges the prerequisite; the script does not retire
Connect Sync itself or delete synchronized users. A separate sync host outside
the lab RG also needs its own retirement. Never give this hybrid cleanup command to cloud-only
participants as their teardown procedure.

## Cost note

Session 1 uses two VMs; each Session 2 participant uses one cloud-only VM and
storage. The presenter's hybrid environment is additional. Clean up each
environment after use, or deallocate VMs between sessions to reduce idle costs.
