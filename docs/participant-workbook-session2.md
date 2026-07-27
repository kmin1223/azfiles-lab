---
title: "Participant Workbook — Session 2"
subtitle: "Azure Files with Microsoft Entra Kerberos for Hybrid Identities (hands-on)"
---

# About this lab

This session builds on the Session 1 environment, switching it to **Microsoft
Entra Kerberos** — where Entra ID issues the Kerberos tickets and clients need
no line of sight to a domain controller. You'll enable it, confirm a healthy
mount, then break and fix the common Entra Kerberos issues.

This is **Session 2 of 2**. Since you tore down Session 1, you must **redeploy it
first** (Lab 0) — do this *before* the session starts.

**Machines** (same as Session 1): **DC VM** `azflab-dc` (`labadmin`),
**Client VM** `azflab-cli` (`CONTOSO\labuser1`). Replace `<sa>` with your storage
account name from the redeploy output.

**Handy to keep open:** `diagnostic-flowchart.pdf` — its right-hand lane is this
session's diagnosis path.

---

# Quick background

Entra Kerberos adds a cloud ticket path on top of Session 1's setup. The chain:
an **SCP** in AD tells the device which tenant to join → the device becomes
**Entra hybrid joined** → at logon it gets a **PRT** → Windows uses it to fetch a
**cloud TGT** from Entra → that gets a **service ticket** for the share. The user
must be a **hybrid identity** (an AD user synced to Entra). Break any link and
the mount fails.

---

# Prerequisites

Beyond your Session 1 subscription:

- **Global Administrator** on a dev/trial Entra tenant (not corporate prod).
  Least-privilege alternative: **Hybrid Identity Administrator** (Cloud Sync) +
  **Cloud Application Administrator** (admin consent).
- `Install-Module Microsoft.Graph -Scope CurrentUser`

---

# Lab 0 · Redeploy Session 1 (do this BEFORE the session)

```powershell
Get-ChildItem -Path .\ -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Connect-AzAccount
cd session1-adds
.\deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

**Expected:** the green **DEPLOYMENT COMPLETE** box. Note the new storage account
name and IPs (they differ from last time). Optionally re-run Session 1's healthy
mount to confirm AD DS still works.

---

# Lab 1 · Enable Entra Kerberos

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Connect-AzAccount
cd session2-entra-kerberos
.\setup.ps1 -ResourceGroupName azfiles-lab
```

**Expected:** the script flips the storage account to Entra Kerberos (AADKERB),
grants admin consent to its app, writes the hybrid-join SCP, configures the
client for cloud tickets, and reboots the client. It ends by printing the
remaining manual step.

---

# Lab 2 · Sync a hybrid identity (Entra Cloud Sync)

Entra Kerberos needs hybrid identities. This is the one interactive step
(~10 min, Global Admin). Follow **MANUAL-STEP-cloud-sync.md**:

1. On the DC, install the Entra provisioning agent from the Entra portal (Cloud
   sync blade), signing in as Global Admin.
2. Create a Cloud Sync configuration for `contoso.local`, scoped to
   `OU=AzureFilesLab`, with password hash sync enabled.
3. Wait until `labuser1` shows **On-premises sync enabled = Yes** in the Entra
   portal (use *Provision on demand* to speed it up).

**Expected:** `labuser1` appears as a synced user in Entra ID.

**Why:** a cloud-only user can't get a cloud Kerberos ticket on this WS2022
client — the identity has to exist in both AD and Entra.

---

# Lab 3 · Confirm a healthy cloud mount

On the Client VM, sign in fresh as `CONTOSO\labuser1`:

```
dsregcmd /status
klist cloud_debug
net use Y: \\<sa>.file.core.windows.net\labshare
klist
```

**Expected:** `dsregcmd /status` shows **AzureAdJoined : YES**. `klist` shows
tickets in **two realms** — `CONTOSO.LOCAL` and `KERBEROS.MICROSOFTONLINE.COM`.
The share mounts with no DC line of sight.

**Why:** the second realm is the cloud TGT from Entra — that's the whole
difference from Session 1. Screenshot this as your "known good."

---

# Lab 4 · Fix a missing cloud TGT (error 1327)

**Break it:**

```powershell
cd session2-entra-kerberos
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
```

**Reproduce** (Client VM) — sign out and back in first (the policy applies at
logon), then:

```
klist cloud_debug
net use Y: \\<sa>.file.core.windows.net\labshare
```

**Expected:** no cloud TGT present; mount fails (often `System error 1327`).

**Diagnose:**

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled
dsregcmd /status
```

The device is still joined, but the registry value is off, so Windows never
requests a cloud TGT.

**Fix:** `-Fault NoCloudTgt -Repair`, then sign out and back in.

**Why:** this registry/GPO value is required and is off by default — a classic
"works on the pilot VM, fails at scale" cause when a policy misses some devices.

---

# Lab 5 · Fix revoked admin consent

**Break it:**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault ConsentRevoked
```

**Reproduce** (Client VM): `klist purge`, then mount — it fails.

**Diagnose:** in the portal, **Entra ID → Enterprise applications → [Storage
Account] `<sa>`.file.core.windows.net → Permissions** — the grant is gone.

**Fix:** `-Fault ConsentRevoked -Repair`, then remount.

**Why:** enabling Entra Kerberos creates an app for the storage account that
needs consented `openid` / `profile` / `User.Read`. Removing it (e.g. a security
"unused app" cleanup) stops ticket issuance.

---

# Lab 6 · Fix a device that left Entra

**Break it:**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NotHybridJoined
```

**Reproduce** (Client VM):

```
dsregcmd /status
klist cloud_debug
```

**Expected:** `AzureAdJoined : NO` → no PRT → no cloud TGT → mount fails.

**Fix:** `-Fault NotHybridJoined -Repair` (re-joins and reboots; registration
takes a few minutes — confirm in **Entra → Devices**), then remount.

**Why:** every downstream step depends on the device being joined, so this one
break takes out the whole chain.

> **Note (discussion, not a lab):** if a Conditional Access policy requires MFA
> on the storage app, SMB can't satisfy it and mounts fail with a generic access
> denial. The fix is to exclude the `[Storage Account]` app from that policy —
> never disable MFA tenant-wide. You'd spot it in the Entra sign-in logs.

---

# Tracing tip

For AD DS you'd use netsh/Wireshark, but Entra Kerberos rides over HTTPS ("KDC
Proxy"), so those only show encrypted TCP. To read the ticket exchange, use
**Fiddler + the Kerberos.NET extension** (enable Decrypt HTTPS, reboot, run
`klist get cifs/<sa>…`).

---

# Clean up

```powershell
.\cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra
```

Then delete the Cloud Sync configuration and provisioning agent in the Entra
portal (the script reminds you).

---

# Command reference

```
dsregcmd /status                    device & PRT / join state
dsregcmd /refreshprt                refresh the Primary Refresh Token
klist cloud_debug                   cloud TGT diagnostics
klist                               cached tickets (note the two realms)
```

# Error → cause quick map

| You see | Likely cause |
|---|---|
| System error 1327 / no cloud TGT | CloudKerberosTicketRetrievalEnabled not set |
| AzureAdJoined: NO | device not hybrid joined / registration |
| Generic access denied | admin consent missing, or CA/MFA on the app |
| Works for some users only | user is cloud-only (not a hybrid identity) |
| System error 53 / 67 / timeout | port 445 blocked or DNS |
