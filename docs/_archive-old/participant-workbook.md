---
title: "Azure Files Identity-Based Authentication — Participant Workbook"
subtitle: "Two hands-on sessions: On-prem AD DS & Microsoft Entra Kerberos"
---

# How to use this workbook

Follow along at your own pace in **your own Azure subscription**. Each session
has one deployment you kick off at the start, then a series of short labs you
run with the group. Every lab lists the exact commands, what you should see,
and a checkpoint to confirm you're on track before moving on.

Two machines you'll work with (IP addresses are printed when your deployment
finishes):

- **DC VM** (`azflab-dc`) — your simulated on-premises domain controller. Sign
  in as `labadmin`.
- **Client VM** (`azflab-cli`) — a domain-joined workstation. Sign in as
  `CONTOSO\labuser1` for the labs.

Throughout, replace `<sa>` with your own storage account name (e.g.
`azflabphp4x4o7s4pa6`) shown in the deployment output.

---

# Before you start (prerequisites)

You need:

- An Azure subscription where you have the **Owner** role, with quota for two
  `Standard_B2ms` VMs.
- For Session 2: **Global Administrator** on a dev/trial Microsoft Entra
  tenant. Please don't use a corporate production tenant.
- PowerShell 7+ with the Azure modules:

```powershell
Install-Module Az, Microsoft.Graph -Scope CurrentUser
```

- An RDP client, and connectivity to your VMs (this lab's network security
  group allows RDP from the **AzureCloud** service tag — connect over your
  Azure VPN).

No Bicep CLI is required — the deployment uses a precompiled ARM template.

---

# Session 1 — On-Premises AD DS Authentication

## Step 1 · Start your deployment

Open PowerShell in the `session1-adds` folder and run:

```powershell
# Clear the "downloaded from the internet" block on the kit files (run once)
Get-ChildItem -Path .\ -Recurse | Unblock-File

# Allow the unsigned lab scripts in THIS window only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

Connect-AzAccount
.\deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

You'll be prompted for a lab admin password (12+ characters; avoid spaces,
quotes, backticks, and `$`). The script then runs unattended for ~15–30
minutes: it deploys the network and VMs, promotes the domain controller,
creates lab users, domain-joins the client and the storage account, enables
AD DS authentication, and sets permissions.

**Checkpoint:** the script ends with a green **DEPLOYMENT COMPLETE** box that
lists your storage account name and the DC/Client public IPs. Note these down.
Keep this PowerShell window open — you'll use it for the break/fix labs.

While it deploys, the presenter walks through the concepts. Don't move on until
you see the completion box.

## Step 2 · Lab 1 — the healthy state

Connect to the **Client VM** by RDP as `CONTOSO\labuser1`, open a Command
Prompt, and run:

```
klist purge
klist get cifs/<sa>.file.core.windows.net
net use Z: \\<sa>.file.core.windows.net\labshare
klist
```

**What you should see:** the share maps with no password prompt, and `klist`
lists a ticket whose **Server** is `cifs/<sa>.file.core.windows.net` with
**KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96**. Open `Z:\` — the file
`hello-from-setup.txt` is there.

**Checkpoint:** you can read the file, and you can create one:

```
echo hello > Z:\%username%.txt
```

### Verify the healthy baseline

Before we start breaking things, record what "healthy" looks like at every
layer. Each check below is the exact thing a later lab will break — seeing the
good value now is what lets you recognize the failure later. Take a screenshot
of each so you can compare.

**A. Network reachability** (Client VM) — the layer *Block445* attacks:

```powershell
Test-NetConnection <sa>.file.core.windows.net -Port 445
nslookup <sa>.file.core.windows.net
```

Healthy: `TcpTestSucceeded : True`, and the name resolves to a
`file.*.store.core.windows.net` address.

**B. The Kerberos ticket** (Client VM, after the mount above) — what
*PasswordMismatch* attacks:

```
klist
```

Healthy: a ticket with **Server: cifs/<sa>.file.core.windows.net** and
**KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96**.

**C. Storage account identity config** (PowerShell on your machine):

```powershell
$sa = Get-AzStorageAccount -ResourceGroupName azfiles-lab -Name <sa>
$sa.AzureFilesIdentityBasedAuth.DirectoryServiceOptions        # AD
$sa.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties      # domain / SIDs / SamAccountName
$sa.AzureFilesIdentityBasedAuth.DefaultSharePermission         # StorageFileDataSmbShareContributor
```

Healthy: `DirectoryServiceOptions = AD`; the AD properties are fully populated
(note **SamAccountName** is present — that's what allows AES-256); and the
default share permission is `StorageFileDataSmbShareContributor` — the value
*NoShareAccess* will set to `None`.

**D. The AD computer account** (DC VM) — what *SpnBroken* and *EtypeMismatch*
attack:

```powershell
Get-ADComputer <sa> -Properties ServicePrincipalNames, KerberosEncryptionType, msDS-SupportedEncryptionTypes |
  Select-Object Name, ServicePrincipalNames, KerberosEncryptionType, msDS-SupportedEncryptionTypes
```

Healthy: SPN = `cifs/<sa>.file.core.windows.net`, and
`KerberosEncryptionType = {AES256}` (`msDS-SupportedEncryptionTypes = 16`).

**E. NTFS permissions** (Client VM, on the mounted drive) — layer 3:

```
icacls Z:\
```

Healthy: `CONTOSO\Domain Users` has Modify `(M)`, `CONTOSO\Domain Admins` has
Full `(F)`.

**F. One command that checks everything** *(optional — the presenter will demo
this; do it yourself only if you have time)* (DC VM). It needs the
AzFilesHybrid module, so it takes a minute to set up the first time:

```powershell
Install-Module AzFilesHybrid -Scope CurrentUser   # first time only
Connect-AzAccount
Debug-AzStorageAccountAuth -StorageAccountName <sa> -ResourceGroupName azfiles-lab -Verbose
```

Healthy: every check passes (CheckADObject, CheckADObjectPasswordIsCorrect,
CheckStorageAccountDomainJoined, CheckUserFileAccess, and so on). Keep this
output — after each fault, rerun it and watch exactly which check flips to a
failure. This is the single most useful tool in real cases, which is why it's
worth seeing at least once.

**Baseline map — what each check anticipates:**

| Baseline check | Healthy value | Lab that breaks it |
|---|---|---|
| Test-NetConnection -Port 445 | TcpTestSucceeded: True | Lab 4 · Block445 |
| Default share permission | StorageFileDataSmbShareContributor | Lab 4 · NoShareAccess |
| SPN on the AD object | cifs/<sa>.file.core.windows.net | Lab 3 · SpnBroken |
| Kerb key ↔ AD password | mount works, valid cifs ticket | Lab 2 · PasswordMismatch |
| KerberosEncryptionType | AES256 | (etype mismatch class) |
| Debug-AzStorageAccountAuth | all checks pass | any of the above |

## Step 3 · Lab 2 — password / kerb-key mismatch (error 1396)

This is the single most common issue in the field.

**Inject** (presenter, or you, in the PowerShell window on your machine):

```powershell
cd session1-adds
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch
```

**Reproduce** (Client VM):

```
klist purge
net use Z: \\<sa>.file.core.windows.net\labshare
```

**What you should see:**

```
System error 1396 has occurred.
The target account name is incorrect.
```

**Diagnose:** first prove the KDC side is fine — request a ticket and inspect
it:

```
klist get cifs/<sa>.file.core.windows.net
klist
```

The `cifs/...` ticket is issued (AES-256). So authentication works; the file
service simply can't decrypt the ticket because its kerb key no longer matches
the AD computer-account password. That's an **AP** stage failure —
KRB5KRB_AP_ERR_MODIFIED.

**Fix** (PowerShell on your machine):

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch -Repair
```

Then on the Client VM:

```
klist purge
net use Z: \\<sa>.file.core.windows.net\labshare
```

**Checkpoint:** the mount succeeds. In production the same fix is
`Update-AzStorageAccountADObjectPassword`.

## Step 4 · Lab 3 — broken SPN (KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)

**Inject:**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault SpnBroken
```

**Reproduce** (Client VM):

```
klist purge
klist get cifs/<sa>.file.core.windows.net
```

**What you should see:** `klist` fails with `0xc000018b` / "the SAM database …
does not have a computer account" — the KDC has no object owning that SPN.

**Diagnose** (DC VM):

```
setspn -Q cifs/<sa>.file.core.windows.net
```

Nothing is returned — the SPN is missing/wrong.

**Fix:**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault SpnBroken -Repair
```

**Checkpoint:** `klist get cifs/<sa>...` issues a ticket again and the share
mounts.

## Step 5 · Lab 4 — blocked port 445, and lost share access

Two quick ones.

**Blocked 445:**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault Block445
```

Client VM:

```
net use Z: \\<sa>.file.core.windows.net\labshare
Test-NetConnection <sa>.file.core.windows.net -Port 445
```

You'll see **System error 64** and `TcpTestSucceeded : False`. Repair with
`-Fault Block445 -Repair`.

**Lost share-level access (authorization, not authentication):**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoShareAccess
```

Client VM — the Kerberos ticket looks perfect, but:

```
net use Z: \\<sa>.file.core.windows.net\labshare
```

fails with **Access is denied**. This is layer 2 (share-level RBAC), not
Kerberos. Repair with `-Fault NoShareAccess -Repair`.

**Checkpoint:** you can articulate the difference between an *authentication*
failure (1396, PRINCIPAL_UNKNOWN) and an *authorization* failure (access
denied with a valid ticket).

## Session 1 command reference

```
klist                                   list cached tickets
klist purge                             clear tickets
klist get cifs/<sa>.file.core.windows.net   request a service ticket
Test-NetConnection <sa>.file.core.windows.net -Port 445   check SMB reachability
setspn -Q cifs/<sa>.file.core.windows.net   look up the SPN (DC VM)
Debug-AzStorageAccountAuth -StorageAccountName <sa> -ResourceGroupName azfiles-lab -Verbose
```

---

# Session 2 — Microsoft Entra Kerberos (Hybrid Identities)

This session **reuses your Session 1 environment** — same resource group.

## Step 1 · Run the setup

```powershell
Get-ChildItem -Path .\ -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Connect-AzAccount
cd session2-entra-kerberos
.\setup.ps1 -ResourceGroupName azfiles-lab
```

This switches the storage account to Entra Kerberos (AADKERB), grants admin
consent to its auto-created app, writes the hybrid-join SCP in AD, and
configures the client for cloud-ticket retrieval (then reboots it).

## Step 2 · The one manual step — Entra Cloud Sync

Entra Kerberos needs **hybrid identities** (AD users synced to Entra). This is
the only interactive part; it needs a Global Admin sign-in in a browser and
takes ~10 minutes. Follow **MANUAL-STEP-cloud-sync.md**:

1. On the DC VM, download and install the Entra provisioning agent from the
   Entra portal (Cloud sync blade), signing in as Global Admin.
2. Create a Cloud Sync configuration for `contoso.local`, scoped to
   `OU=AzureFilesLab`, with password hash sync enabled.
3. Wait until `labuser1` shows **On-premises sync enabled = Yes** in the Entra
   portal (use *Provision on demand* to speed this up).

**Checkpoint:** `labuser1` appears as a synced user in Entra ID.

## Step 3 · Lab 1 — mount with a cloud TGT

On the Client VM, sign in fresh as `CONTOSO\labuser1`:

```
dsregcmd /status
klist cloud_debug
net use Y: \\<sa>.file.core.windows.net\labshare
klist
```

**What you should see:** `dsregcmd /status` shows **AzureAdJoined : YES**;
`klist` shows tickets in two realms — `CONTOSO.LOCAL` and
`KERBEROS.MICROSOFTONLINE.COM`. The share mounts with no line of sight to the
DC required.

**Checkpoint:** same UNC path as Session 1, but now the ticket comes from
Entra ID.

## Step 4 · Lab 2 — the missing registry key (no cloud TGT)

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
```

Sign out and back in on the Client VM, then:

```
klist cloud_debug
net use Y: \\<sa>.file.core.windows.net\labshare
```

Cloud TGT is absent; the mount fails (often System error 1327). Verify the
policy:

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled
```

**Fix:** `-Fault NoCloudTgt -Repair`, then **sign out and in** (the policy
applies at logon).

## Step 5 · Lab 3 — consent revoked

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault ConsentRevoked
```

Ticket issuance for the share now fails. Check it in the portal: **Entra ID →
Enterprise applications → [Storage Account] `<sa>`.file.core.windows.net →
Permissions** (empty). **Fix:** `-Fault ConsentRevoked -Repair`.

## Step 6 · Lab 4 — device not hybrid joined

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NotHybridJoined
```

On the Client VM, `dsregcmd /status` now shows **AzureAdJoined : NO** → no PRT
→ no cloud TGT → mount fails. **Fix:** `-Fault NotHybridJoined -Repair`
(re-join + reboot; registration takes a few minutes — confirm in Entra →
Devices).

> **Discussion (not scripted):** if a Conditional Access policy requires MFA on
> the storage account's app, SMB can't satisfy it and mounts fail with a
> generic access denial. The fix is to exclude the `[Storage Account]` app from
> that policy — never disable MFA tenant-wide.

## Session 2 command reference

```
dsregcmd /status                    device & PRT state
dsregcmd /refreshprt                refresh the Primary Refresh Token
klist cloud_debug                   cloud TGT diagnostics
klist                               list cached tickets (note the two realms)
```

---

# Cleanup

When you're finished with both sessions:

```powershell
.\cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra
```

Then, in the Entra portal, delete the Cloud Sync configuration and the
provisioning agent (the script reminds you). Deleting the resource group
removes all the Azure resources (VMs, network, storage) in one shot.

> **Tip:** if you plan to redeploy right away with the same resource group
> name, wait a few minutes first — the storage account name is derived from the
> resource group and may still be reserved.

---

# Quick error → cause map

| You see | Likely cause | Where to look |
|---|---|---|
| System error 64 / 53 | Port 445 blocked / DNS | `Test-NetConnection -Port 445` |
| System error 1396 (AP_ERR_MODIFIED) | Kerb key ≠ AD password | `Debug-AzStorageAccountAuth` |
| 0xc000018b / PRINCIPAL_UNKNOWN | SPN missing or wrong | `setspn -Q cifs/<sa>…` (DC) |
| "encryption type not supported" | etype mismatch (use AES-256) | `klist` etype, gpedit |
| Access denied, ticket valid | Authorization (share RBAC or NTFS) | role assignments / `icacls` |
| System error 1327 / no cloud TGT | CloudKerberos key not set | `klist cloud_debug` |
| AzureAdJoined: NO | Device not hybrid joined | `dsregcmd /status` |
| Works for some users only | Unsynced (non-hybrid) user | Entra → Users → sync state |
