# Azure Files Identity-Based Auth — Hands-On Lab Kit

> **Publishing this repo?** It's safe to make public — no secrets, keys,
> subscription/tenant IDs, or real IPs are stored here (a lab password is
> auto-generated at runtime; kerb keys are fetched at runtime). The repo
> deliberately carries **only the deploy/lab automation**: decks (`*.pptx`) and
> all documents (`docs/`) are distributed separately and may reference
> Microsoft-internal tooling — the `.gitignore` keeps them out. Never add the
> source Microsoft support-wiki PDFs (Microsoft Confidential / NDA).

Two 60-minute sessions. Each session: attendees kick off an automation script
in **their own subscription** at minute 0, the presenter covers concepts on
slides while it deploys, then everyone does guided break/fix labs together.

| Session | Topic | Deploy time | Automation |
|---|---|---|---|
| 1 | On-prem AD DS auth (simulated with an Azure DC) | ~15 min | `session1-adds/deploy.ps1` — fully unattended |
| 2 | Microsoft Entra Kerberos (hybrid identities) | ~10 min + 10 min manual | `session2-entra-kerberos/setup.ps1` + one interactive Cloud Sync step |

Session 2 builds on the Session 1 environment. If the two sessions are days
apart, have attendees **tear down after Session 1** (avoid idle VM costs) and
**redeploy Session 1 shortly before Session 2** — send the reminder from the
pre-session announcement doc (distributed with the other session materials).
If the sessions are back-to-back, they can
instead leave the environment running.

## Contents

```
azfiles-lab/
├── README.md                        <- you are here
├── cleanup.ps1                      <- full teardown (both sessions)
├── session1-adds/
│   ├── deploy.ps1                   <- attendees run THIS at session start
│   ├── template/azuredeploy.json     <- ARM template (no Bicep needed)
│   ├── scripts/                     <- run-command payloads (DC/client, incl. tool install)
│   └── faults/Invoke-Fault.ps1      <- break/fix scenarios (5 faults)
├── session2-entra-kerberos/
│   ├── setup.ps1                    <- attendees run THIS at session start
│   ├── MANUAL-STEP-cloud-sync.md    <- the one interactive step
│   ├── scripts/
│   └── faults/Invoke-Fault.ps1      <- break/fix scenarios (4 faults)
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
- For Session 2: **Global Administrator** on a (trial/dev) Entra tenant —
  needed for admin consent and Cloud Sync. A personal dev tenant
  (e.g., via the M365 developer program or a new trial) is strongly
  recommended over a corporate tenant.
- **Azure Cloud Shell** — the one supported place to run the deploy and fault
  commands. Nothing to install (Az + Microsoft.Graph preinstalled), already
  signed in, no execution-policy or unblock friction.
- RDP client — the in-VM klist/mount steps aren't a shell task.
- **Plain ARM template** — nothing extra to install.

> Run everything from Cloud Shell. The scripts are cross-platform, but the docs
> assume Cloud Shell throughout: forward-slash paths (`./deploy.ps1`) and no
> `Connect-AzAccount` (you are already signed in).

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

### Collect Client and DC evidence for a mount attempt

The client installer generates `C:\LabTools\Get-KerberosEvidence.ps1`. Wait for
the **post-deployment client tools installation** before using it; the
`DEPLOYMENT COMPLETE` banner alone does not mean the collector is installed.
The DC setup grants the lab evidence-reader group read access and enables
remote event-log access from the lab client's private address only. It does
not make the lab users domain administrators.
The two lab users are added directly to the built-in Event Log Readers group;
the DomainLocal evidence-reader group is used separately for the Security
channel read ACE. Nesting that DomainLocal group into the built-in group fails
with AD error 8520.
Source updates do not update existing VMs automatically. Existing lab users
must sign out and sign in again after the DC reader-group membership is applied.

If deployment stopped at this group-membership error, stop the retrying deploy,
update the source, and rerun with the same resource group and the original
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

Session 2 reuses the Session 1 environment, so **redeploy Session 1 first** if
you tore it down (see the pre-session announcement you received).

```powershell
cd azfiles-lab/session2-entra-kerberos
./setup.ps1 -ResourceGroupName azfiles-lab
# then follow MANUAL-STEP-cloud-sync.md (~10 min, Global Admin in browser)
```

## Break/fix (presenter-driven, everyone follows along)

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

# Session 2  (from the session2-entra-kerberos folder)
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
# Faults: NoCloudTgt | ConsentRevoked | NotHybridJoined | NoShareAccess
```

Every fault maps to a real-world support issue (error 1396, 1327, 64/67,
KRB5KRB_AP_ERR_MODIFIED, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, ETYPE_NOSUPP, missing
cloud TGT, revoked consent…). The facilitator guide has the full
symptom → diagnosis → fix catalog.

## Cleanup (after Session 2)

```powershell
./cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra
```

Then delete the Cloud Sync configuration + provisioning agent in the Entra
portal (noted by the script).

## Cost note

2× B2ms + Standard LRS storage ≈ a few USD for the two sessions if you clean
up the same day. Deallocate VMs between sessions if they're days apart.
