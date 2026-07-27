---
title: "Participant Workbook — Session 1"
subtitle: "Azure Files On-Premises AD DS Authentication (hands-on)"
---

# About this lab

You'll deploy a small AD DS + Azure Files environment in your own subscription,
confirm it works, then break and fix the most common authentication issues.
Each lab lists the commands to run, what you should see, and a short note on
why. Work at your own pace; the presenter keeps the room roughly in sync.

This is **Session 1 of 2**. Session 2 runs a few days later, so you'll delete
everything at the end and redeploy before Session 2 (you'll get a reminder).

**Machines** (IPs are printed when your deployment finishes):

- **DC VM** (`azflab-dc`) — the simulated on-prem domain controller. Sign in as
  `labadmin`.
- **Client VM** (`azflab-cli`) — a domain-joined workstation. Sign in as
  `CONTOSO\labuser1`.

Replace `<sa>` everywhere with your storage account name from the deploy output
(it looks like `azflab` + a random suffix, e.g. `azflababcd1234efgh`).

**Handy to keep open:** `diagnostic-flowchart.pdf` — a one-page "symptom → cause"
tree for both sessions.

---

# Quick background

"Domain-joining a storage account" means AD holds a **computer account** for it
whose **SPN** is `cifs/<sa>.file.core.windows.net` and whose **password is the
storage kerb key**. A client gets a Kerberos ticket for that SPN from the DC and
presents it to the file service over SMB (port 445). Access then passes through
three layers: network (445) → share-level RBAC → NTFS permissions. Each fault in
this lab breaks one of those pieces.

---

# Prerequisites

- Azure subscription with the **Owner** role and quota for two `Standard_B2ms`
  VMs.
- Where you'll run the deploy/fault commands — pick one:
  - **Azure Cloud Shell (easiest):** nothing to install — Az and Microsoft.Graph
    are already there, and there's no execution-policy / "unblock" friction.
  - **Local PowerShell 7+:** `Install-Module Az -Scope CurrentUser`.
- An **RDP client**, connected to your Azure VPN (RDP is allowed from the
  AzureCloud service tag). *Required either way* — the klist / net use / mount
  steps happen inside the VMs, which Cloud Shell can't do.

No Bicep CLI required.

> **Running in Cloud Shell?** Get the kit with
> `git clone https://github.com/kmin1223/azfiles-lab.git`, `cd` into it, and
> skip the `Unblock-File` /
> `Set-ExecutionPolicy` lines below — they're Windows-only. Type paths with
> forward slashes (`./deploy.ps1`, `./faults/Invoke-Fault.ps1`). One caveat:
> Cloud Shell disconnects after ~20 min idle; the deploy prints output the
> whole time so it stays alive, and if it ever drops just re-run the same
> command (it resumes safely).

---

# Lab 1 · Deploy the environment

In PowerShell, from the `session1-adds` folder:

```powershell
Get-ChildItem -Path .\ -Recurse | Unblock-File            # local Windows only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force   # local Windows only
Connect-AzAccount
.\deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

*(In Cloud Shell, skip the first two lines and run `./deploy.ps1 …`.)*

Enter a lab admin password when prompted (12+ chars; avoid spaces, quotes,
backticks, `$`). The script runs unattended for ~15–30 minutes.

**Expected:** a green **DEPLOYMENT COMPLETE** box listing your storage account
name and the DC/Client public IPs. Note them down; keep this PowerShell window
open for later labs.

The presenter covers concepts on the slides while this runs.

---

# Lab 2 · Confirm a healthy mount

RDP to the **Client VM** as `CONTOSO\labuser1`, open Command Prompt, and run:

```
klist purge
net use Z: \\<sa>.file.core.windows.net\labshare
klist
```

**Expected:** the share maps with no password prompt. `klist` shows a ticket
with **Server = cifs/<sa>.file.core.windows.net** and **encryption type
AES-256**. Open `Z:\` — you'll see `hello-from-setup.txt`, and you can create a
file:

```
echo hello > Z:\%username%.txt
```

**Why:** your logon already got you a Kerberos TGT; mounting the share just adds
a service ticket for the `cifs` SPN — no extra credentials needed. Take a quick
screenshot of this `klist` output; it's your "known good" reference for the
fault labs.

---

# Lab 3 · Fix a mount failure (error 1396)

The most common issue in the field: the AD account password and the storage
kerb key fall out of sync.

**Break it** (in your PowerShell window):

```powershell
cd session1-adds
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch
```

**Reproduce** (Client VM):

```
klist purge
net use Z: \\<sa>.file.core.windows.net\labshare
```

**Expected:** `System error 1396 — The target account name is incorrect.`

**Diagnose** (Client VM):

```
klist get cifs/<sa>.file.core.windows.net
```

The ticket *is* issued — so the DC and SPN are fine. The failure is that the
file service can't decrypt the ticket because its kerb key no longer matches the
AD account password.

**Fix** (PowerShell window):

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch -Repair
```

Then on the Client VM: `klist purge` and mount again — it succeeds.

**Why:** in production the same fix is
`Update-AzStorageAccountADObjectPassword` (a storage account keeps two kerb
keys, kerb1/kerb2, and you rotate between them).

---

# Lab 4 · Fix a broken SPN (error 0xc000018b)

**Break it:**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault SpnBroken
```

**Reproduce** (Client VM):

```
klist purge
klist get cifs/<sa>.file.core.windows.net
```

**Expected:** the request fails with `0xc000018b` / "the SAM database does not
have a computer account…". Unlike Lab 3, no ticket is issued at all.

**Diagnose** (DC VM):

```
setspn -Q cifs/<sa>.file.core.windows.net
```

Nothing is returned — no AD object owns that SPN, so the DC can't issue a
ticket.

**Fix:**

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault SpnBroken -Repair
```

Confirm with `klist get cifs/<sa>…` (ticket issued) and remount.

**Why:** the SPN is how the DC finds the storage service. Missing or duplicate
SPNs commonly come from manual joins or multi-forest setups.

---

# Lab 5 · Two quick ones

## 5a · Blocked port 445

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault Block445
```

Client VM:

```
net use Z: \\<sa>.file.core.windows.net\labshare
Test-NetConnection <sa>.file.core.windows.net -Port 445
```

**Expected:** `System error 53` (or a timeout), and `TcpTestSucceeded : False`.
Fix: `-Fault Block445 -Repair`.

**Why:** SMB needs outbound TCP 445. ISPs, firewalls, and NSGs often block it;
the fix is to open it or use a private endpoint / VPN. (A related but different
error, 64, means 445 connects but a proxy/NAT drops the SMB handshake.)

## 5b · Lost share-level access

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoShareAccess
```

Client VM: the `klist` ticket still looks perfect, but:

```
net use Z: \\<sa>.file.core.windows.net\labshare
```

**Expected:** `System error 5 — Access is denied.` Fix:
`-Fault NoShareAccess -Repair`.

**Why:** authentication succeeded (valid ticket) but authorization failed — this
is the share-level RBAC layer, not Kerberos. Effective access is always the more
restrictive of the share-level role and the NTFS permission.

---

# Optional · More faults to try

If you have time (or want to practice after redeploying):

- `-Fault EtypeMismatch` — forces an unsupported encryption type on the client;
  mount fails with "the encryption type requested is not supported by the KDC."
  This is the same failure class as the 2026 RC4 retirement. Repair resets the
  client policy.
- Have a partner inject a fault of their choice without telling you, and see how
  quickly you can identify and fix it using the flowchart.

---

# Clean up

Session 2 is a few days away — delete everything now to avoid idle VM costs:

```powershell
Remove-AzResourceGroup -Name azfiles-lab -Force
```

Nothing was created in Entra during Session 1, so that's all. Keep this workbook
and your kit folder — you'll redeploy this same environment before Session 2.

---

# Command reference

```
klist                                        list cached Kerberos tickets
klist purge                                  clear tickets
klist get cifs/<sa>.file.core.windows.net    request a service ticket
net use Z: \\<sa>.file.core.windows.net\labshare   mount the share
Test-NetConnection <sa>.file.core.windows.net -Port 445   check SMB reachability
setspn -Q cifs/<sa>.file.core.windows.net    look up the SPN (on the DC)
Debug-AzStorageAccountAuth -StorageAccountName <sa> -ResourceGroupName azfiles-lab -Verbose
```

# Error → cause quick map

| You see | Likely cause |
|---|---|
| System error 53 / 67 / timeout | Port 445 blocked or DNS |
| System error 64 | 445 connects, proxy/NAT drops the SMB handshake |
| System error 1396 (AP_ERR_MODIFIED) | Kerb key ≠ AD account password |
| 0xc000018b / PRINCIPAL_UNKNOWN | SPN missing or wrong |
| "encryption type not supported" | Encryption mismatch (use AES-256) |
| System error 5, ticket valid | Authorization — share RBAC or NTFS |
