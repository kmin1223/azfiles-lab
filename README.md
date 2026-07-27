# Azure Files Identity-Based Auth — Hands-On Lab Kit

> **Publishing this repo?** It's safe to make public — no secrets, keys,
> subscription/tenant IDs, or real IPs are stored here (passwords are prompted
> at runtime; kerb keys are fetched at runtime). Two rules: **do not add the
> source Microsoft support-wiki PDFs** (they're Microsoft Confidential / NDA and
> live outside this folder), and don't commit `docs/_archive-old/`. A
> `.gitignore` already covers both.

Two 60-minute sessions. Each session: attendees kick off an automation script
in **their own subscription** at minute 0, the presenter covers concepts on
slides while it deploys, then everyone does guided break/fix labs together.

| Session | Topic | Deploy time | Automation |
|---|---|---|---|
| 1 | On-prem AD DS auth (simulated with an Azure DC) | ~25–35 min | `session1-adds/deploy.ps1` — fully unattended |
| 2 | Microsoft Entra Kerberos (hybrid identities) | ~10 min + 10 min manual | `session2-entra-kerberos/setup.ps1` + one interactive Cloud Sync step |

Session 2 builds on the Session 1 environment. If the two sessions are days
apart, have attendees **tear down after Session 1** (avoid idle VM costs) and
**redeploy Session 1 shortly before Session 2** — send the reminder in
`docs/pre-session-announcements.md`. If the sessions are back-to-back, they can
instead leave the environment running.

## Contents

```
azfiles-lab/
├── README.md                        <- you are here
├── cleanup.ps1                      <- full teardown (both sessions)
├── session1-adds-deck.pptx          <- Session 1 slides
├── session2-entra-kerberos-deck.pptx<- Session 2 slides
├── docs/
│   ├── facilitator-guide.docx              <- presenter: run-of-show, timings, issue catalog
│   ├── cuesheet-session1.docx              <- presenter: slide-by-slide Korean cue sheet (Session 1)
│   ├── participant-workbook-session1.docx  <- attendees: Session 1 learn-by-diagnosing labs
│   ├── participant-workbook-session2.docx  <- attendees: Session 2 incl. redeploy step
│   ├── diagnostic-flowchart.pdf            <- printable one-page triage tree (both sessions)
│   └── pre-session-announcements.docx      <- copy/paste reminders (esp. "redeploy before Session 2")
├── session1-adds/
│   ├── deploy.ps1                   <- attendees run THIS at session start
│   ├── bicep/main.bicep
│   ├── scripts/                     <- run-command payloads (DC/client)
│   └── faults/Invoke-Fault.ps1      <- break/fix scenarios (5 faults)
└── session2-entra-kerberos/
    ├── setup.ps1                    <- attendees run THIS at session start
    ├── MANUAL-STEP-cloud-sync.md    <- the one interactive step
    ├── scripts/
    └── faults/Invoke-Fault.ps1      <- break/fix scenarios (4 faults)
```

## Attendee prerequisites (send before Session 1)

- An Azure subscription with **Owner** (RBAC + storage changes needed) and
  quota for 2× `Standard_B2ms` VMs.
- For Session 2: **Global Administrator** on a (trial/dev) Entra tenant —
  needed for admin consent and Cloud Sync. A personal dev tenant
  (e.g., via the M365 developer program or a new trial) is strongly
  recommended over a corporate tenant.
- Where to run the deploy/fault commands — either works:
  - **Azure Cloud Shell (recommended):** Az + Microsoft.Graph are preinstalled,
    and there's no execution-policy / unblock friction. Get the kit with
    `git clone https://github.com/kmin1223/azfiles-lab.git`. Use forward-slash
    paths (`./deploy.ps1`).
  - **Local PowerShell 7+:** `Install-Module Az, Microsoft.Graph -Scope CurrentUser`.
- RDP client (required either way — the in-VM klist/mount steps aren't a shell
  task).
- **No Bicep CLI needed** — the deployment uses a precompiled ARM JSON template.

> Scripts use nested `Join-Path`, so they run unchanged on both Windows
> PowerShell 5.1 and PowerShell 7 (Cloud Shell / Linux).

## Session 1 quick start (attendees)

```powershell
# Get the kit (Cloud Shell or local):
#   git clone https://github.com/kmin1223/azfiles-lab.git ; cd azfiles-lab/session1-adds

# 0. Downloaded/extracted files carry a "block" flag - clear it once for the whole kit (local Windows only)
Get-ChildItem -Path .\ -Recurse | Unblock-File

# 1. Allow the unsigned lab scripts to run in THIS window only (resets when you close it)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 2. Deploy
Connect-AzAccount
cd session1-adds
.\deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

> Two things that trip up files copied from the internet:
> - **"file cannot be copied / opened" or a SmartScreen block** → run the
>   `Unblock-File` line above from the kit's root folder (clears Mark-of-the-Web).
> - **"running scripts is disabled"** → the `Set-ExecutionPolicy` line fixes it.
>
> The fault scripts are unsigned too, so keep the same window open for the labs.

Everything else is automated: forest promotion, lab users
(`labuser1`/`labuser2`), client domain join, storage account domain join
(computer account + SPN + kerb1 key), AD DS auth enablement, default share
permission, NTFS ACLs.

## Session 2 quick start (attendees)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Connect-AzAccount
cd session2-entra-kerberos
.\setup.ps1 -ResourceGroupName azfiles-lab
# then follow MANUAL-STEP-cloud-sync.md (~10 min, Global Admin in browser)
```

## Break/fix (presenter-driven, everyone follows along)

```powershell
# Session 1
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch -Repair
# Faults: PasswordMismatch | SpnBroken | EtypeMismatch | Block445 | NoShareAccess

# Session 2
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
# Faults: NoCloudTgt | ConsentRevoked | NotHybridJoined | NoShareAccess
```

Every fault maps to a real-world support issue (error 1396, 1327, 64/67,
KRB5KRB_AP_ERR_MODIFIED, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, ETYPE_NOSUPP, missing
cloud TGT, revoked consent…). The facilitator guide has the full
symptom → diagnosis → fix catalog.

## Cleanup (after Session 2)

```powershell
.\cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra
```

Then delete the Cloud Sync configuration + provisioning agent in the Entra
portal (noted by the script).

## Cost note

2× B2ms + Standard LRS storage ≈ a few USD for the two sessions if you clean
up the same day. Deallocate VMs between sessions if they're days apart.
