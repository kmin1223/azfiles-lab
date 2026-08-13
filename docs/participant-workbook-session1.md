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

> **Your lab starts as a "2023 vintage" environment**, on purpose: RC4 Kerberos
> encryption, and a storage account whose `ActiveDirectoryDomainName` holds the
> **NetBIOS** name instead of the DNS root. It mounts perfectly — RC4 keys aren't
> salted, so that wrong value is never used. Lab 3 is the AES-256 migration,
> where the salt suddenly matters. This mirrors a real Sev A incident.

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

The deployment uses a plain ARM template — nothing extra to install.

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

**Azure Cloud Shell (recommended)** — open Cloud Shell (PowerShell) from the
Azure portal (`>_` icon):

```powershell
git clone https://github.com/kmin1223/azfiles-lab.git
cd azfiles-lab/session1-adds
./deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

**Local Windows PowerShell** — from the `session1-adds` folder:

```powershell
Get-ChildItem -Path .\ -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Connect-AzAccount
.\deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

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
with **Server = cifs/<sa>.file.core.windows.net** and encryption type
**RSADSI RC4-HMAC(NT)** — this is the legacy environment you inherited. Open
`Z:\` — you'll see `hello-from-setup.txt`, and you can create a file:

```
echo hello > Z:\%username%.txt
```

**Why:** your logon already got you a Kerberos TGT; mounting the share just adds
a service ticket for the `cifs` SPN — no extra credentials needed. Take a quick
screenshot of this `klist` output; it's your "known good" reference for the
fault labs.

**The one-command health check.** The **Client VM** has the Az and
**AzFilesHybrid** modules installed, so you can run the official diagnostic
right there. Run it on the **client, not the DC** — that is where these cmdlets
belong in a real environment too, and the DC in this lab has no Azure tooling on
purpose:

```powershell
Connect-AzAccount
Debug-AzStorageAccountAuth -StorageAccountName <sa> -ResourceGroupName azfiles-lab -Verbose
```

Every check should pass. Re-run it after each fault below and watch which check
flips to a failure.

> **If the cmdlet is "found in the module AzFilesHybrid, but the module could
> not be loaded"**, don't trust that error — it describes the symptom, not the
> cause. Force the import to get the real one:
>
> ```powershell
> Import-Module AzFilesHybrid -Force -Verbose
> ```
>
> It names an unmet `RequiredModules` entry — e.g. *"The required module
> 'Az.Compute' is not loaded."* Fixing them one at a time is slow (0.3.3.0 also
> needs `Microsoft.Graph.Applications`), so read the manifest and install
> everything missing at once, from a **fresh** elevated window — a session that
> already loaded `Az.Accounts` will refuse the install with *"currently in use"*:
>
> ```powershell
> $psd1 = 'C:\Program Files\WindowsPowerShell\Modules\AzFilesHybrid\0.3.3.0\AzFilesHybrid.psd1'
> foreach ($m in (Import-PowerShellDataFile $psd1).RequiredModules) {
>     $n = if ($m -is [hashtable]) { $m.ModuleName } else { $m }
>     if (-not (Get-Module -ListAvailable -Name $n)) {
>         Install-Module $n -Scope AllUsers -Force -AllowClobber
>     }
> }
> ```
>
> Then `Import-Module AzFilesHybrid -Force` in another new window.
>
> This is worth internalizing: *"command not found"* on a module that is plainly
> installed is a **dependency** failure, not a missing-install failure. The same
> reasoning applies to customer environments where a partial Az install breaks
> AzFilesHybrid.

> **If `Connect-AzAccount` fails on the VM** with "user interaction is required"
> or a token error, the interactive sign-in window is being blocked. Use device
> code instead — it prints a code you enter at
> <https://microsoft.com/devicelogin> from your own browser:
>
> ```powershell
> Connect-AzAccount -UseDeviceAuthentication
> ```
>
> Everything else in these labs (`klist`, `net use`, the evidence collector,
> `setspn`, event 4769) needs **no** Azure sign-in on the VM.

> **Reading the output critically:** this cmdlet flags RBAC/Entra checks as
> failures whenever your design simply doesn't use them — our lab relies on
> `DefaultSharePermission` with no Entra sync, so `CheckSidHasAadUser` and
> `CheckUserRbacAssignment` are *expected* to fail. Map each reported failure to
> your design before chasing it.

## Capture your known-good reference

Before you break anything, capture what a **working** mount looks like on the
wire. Every later capture is a diff against this one. In an **elevated**
PowerShell on the Client VM:

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>
```

It purges tickets, starts a network trace, performs the mount, stops the trace,
converts it to `.pcapng`, and collects the Kerberos/SMBClient logs into
`C:\LabTools\evidence\<timestamp>\`.

Open `trace.pcapng` in Wireshark (or copy it off the VM) and filter:

```
kerberos || smb2
```

**What a healthy attempt looks like:** `TGS-REQ` naming `cifs/<sa>…`, a `TGS-REP`
back, then SMB2 `Negotiate` → `Session Setup` (success) → `Tree Connect`
(success).

And on the **DC**, the KDC's own record of that ticket:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 5 |
  Format-List TimeCreated, Message
```

Note three fields in event 4769: the **Service Name** (the SPN as the client
asked for it), the **Ticket Encryption Type** (`0x17` = RC4 in this legacy
baseline; `0x12` = AES-256 after the migration), and the **Failure Code**
(`0x0` on success).

---

# Lab 3 · The AES-256 migration ★

You're the admin who has to comply with the 2026 mandate: move this share off
RC4. Do it, and deal with what happens.

## Step 1 — look before you leap

```powershell
cd session1-adds
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Status
```

Note what it reports — especially `ActiveDirectoryDomainName`. Keep it in mind;
don't act on it yet.

## Step 2 — perform the migration

```powershell
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Enforce
```

This flips the AD object to AES-256 only — the change most people would make.

## Step 3 — retest (drop the SMB *session* first!)

On the **Client VM**:

```
net use * /delete /y
net use \\<sa>.file.core.windows.net\labshare /delete /y
klist purge
Get-SmbConnection
net use Z: \\<sa>.file.core.windows.net\labshare
```

**Expected:** `System error 1396`.

> Deleting mappings and purging tickets is **not enough** — neither kills the
> SMB *session*, and a TreeConnect on a live session performs no new
> authentication, so the old session keeps working after any key change.
> `Get-SmbConnection` must show **no entry** for the storage account before you
> retest.
>
> **How to spot it when it bites you:** the mount "succeeds" but `klist` shows
> **zero tickets**. Success without tickets means no Kerberos exchange happened
> — you tested the old session, not the new configuration. Sign out/in (or,
> elevated, `Restart-Service LanmanWorkstation -Force`) and retest. The same
> trap shows up in real support cases as *"we changed the auth config and
> nothing happened"*.

## Step 4 — diagnose from evidence

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>
klist
```

The ticket **is** issued, and it's **AES-256**. On the **DC**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 3 |
  Format-List TimeCreated, Message
```

Event 4769 says **success**. So the KDC, the SPN, and the encryption type are
all fine — the only thing left is the key the **service** uses to decrypt. Why
would that be wrong when nothing about the password changed?

Because the AES key is derived with a **salt** built from
`DomainName + SamAccountName + AccountType`. Run `-Step Status` again and look
at `ActiveDirectoryDomainName`: it holds the **NetBIOS** name, not the DNS root.
Under RC4 (unsalted) that never mattered. Under AES-256 it's fatal.

## Step 5 — repair, in the right order

```powershell
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Repair
```

It does three things, and the order is the lesson:

1. correct `ActiveDirectoryDomainName` to the DNS root — passing the **full**
   parameter set (a partial `Set-AzStorageAccount` is silently ignored)
2. **regenerate the kerb key** — this is when the new salt is baked in
3. reset the AD object's password to that key, and force replication

Retest on the Client VM (`net use * /delete /y`, `klist purge`, mount). `klist`
should now show **AES-256-CTS-HMAC-SHA1-96**.

**Why fixing the property alone isn't enough:** the salt is consumed at key
generation time. Change the property and stop there, and nothing happens — the
existing key still carries the old salt.

*Want to run it again?* `-Step Rollback` restores the legacy state.

---

# Lab 4 · Access denied — with a perfect Kerberos ticket ★

A real support case: a share stopped being reachable and the error said
*"the user name or password is incorrect."* Kerberos was healthy the whole time.

## Break it

```powershell
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault CipherMismatch
```

The storage account is set to allow **AES-256-GCM only**; the client is set to
offer **AES-128-GCM**.

## Reproduce (Client VM)

```
net use * /delete /y
klist purge
net use Z: \\<sa>.file.core.windows.net\labshare
```

**Expected:** `Access is denied` (or "The user name or password is incorrect").

## Diagnose

First confirm Kerberos is *not* the problem:

```
klist
```

The `cifs/<sa>…` ticket is there. On the DC, event 4769 shows success. So
authentication worked — the failure is after it.

Now compare the two sides of the cipher negotiation:

```powershell
# client
Get-SmbClientConfiguration | Select-Object -ExpandProperty EncryptionCiphers
# storage: Azure portal -> storage account -> File shares -> Security
```

They have no cipher in common. SMB negotiates the cipher **before** the client
even names the storage account, so the service can't pick one per account — if
there's no overlap, the session is refused and the error surfaces as an access
denial.

## Fix

```powershell
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault CipherMismatch -Repair
```

**Why this matters:** the error text points straight at credentials, so the
natural reaction is to audit RBAC, then NTFS, then the domain join — and find
nothing wrong, because nothing is. In the real case that cost several days.

---

# Lab 5 · Fix a mount failure (error 1396) — different root cause

Same symptom as Lab 3, different cause: here the AD account password and the
storage kerb key simply fall out of sync (rotation policy, a manual reset).

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

**Diagnose — from evidence, not the error text** (Client VM):

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>
```

Open the new `trace.pcapng` with filter `kerberos || smb2` and compare it to
your known-good capture:

| Stage | Healthy capture | This capture |
|---|---|---|
| TGS-REQ / REP | ticket issued | **still issued** — the KDC is fine |
| SMB2 Session Setup | success | **fails** — `KRB_AP_ERR_MODIFIED` |

Then confirm from the KDC's side, on the **DC**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 3 |
  Format-List TimeCreated, Message
```

Event 4769 shows a **successful** ticket issue for the SPN. That single fact
eliminates the DC, the SPN, and the encryption type in one step — the only thing
left is the key the *service* uses to decrypt. This is the difference between
guessing from an error string and proving it.

Cross-check with the module:

```powershell
Debug-AzStorageAccountAuth -StorageAccountName <sa> -ResourceGroupName azfiles-lab -Verbose
# CheckADObjectPasswordIsCorrect fails
```

**Fix** (PowerShell window):

```powershell
.\faults\Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault PasswordMismatch -Repair
```

Then on the Client VM: `klist purge` and mount again — it succeeds.

**Why:** in production the same fix is
`Update-AzStorageAccountADObjectPassword` (a storage account keeps two kerb
keys, kerb1/kerb2, and you rotate between them).

---

# Lab 6 · Fix a broken SPN (error 0xc000018b)

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
have a computer account…". Unlike the earlier labs, no ticket is issued at all.

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

# Lab 7 · Two quick ones

## 7a · Blocked port 445

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

## 7b · Lost share-level access

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

# Optional · Advanced faults (evidence required)

These three can't be identified from the error message alone — you need the
trace or event 4769. That's the point.

- **`-Fault EtypeMismatch`** — forces an unsupported encryption type on the
  client. In 4769 you'll see the request fail with an etype mismatch; on the
  wire, `KDC_ERR_ETYPE_NOSUPP` in the TGS-REP. Same failure class as the 2026
  RC4 retirement.
- **`-Fault ClockSkew`** — pushes the client clock ~10 minutes off. The mount
  error is vague; the trace shows `KRB_AP_ERR_SKEW`. Confirm with
  `w32tm /stripchart /computer:azflab-dc /samples:3`. (Kerberos tolerates about
  5 minutes.)
- **`-Fault DuplicateSpn`** — registers the storage SPN on a second AD object.
  On the DC, `setspn -X` reveals the duplicate; the KDC can end up encrypting the
  ticket for the wrong account. A classic, hard-to-spot production issue.

Repair each with `-Repair`, as usual.

**Pair exercise:** have a partner inject any fault without telling you. Diagnose
it using only `Get-KerberosEvidence.ps1`, event 4769, and the flowchart — then
name the fault before you repair it.

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
setspn -X                                    find DUPLICATE SPNs (on the DC)
Debug-AzStorageAccountAuth -StorageAccountName <sa> -ResourceGroupName azfiles-lab -Verbose

--- migration lab ---
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Status|Enforce|Repair|Rollback

--- evidence ---
C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>    trace + logs for one attempt
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 5    KDC record (DC)
w32tm /stripchart /computer:azflab-dc /samples:3             clock skew vs the DC
Wireshark filter:  kerberos || smb2
```

# Error → cause quick map

| You see (error, or on the wire) | Likely cause |
|---|---|
| `KRB_AP_ERR_SKEW` | Clock skew > ~5 min between client and DC |
| duplicate SPN in `setspn -X` | Two AD objects claim the same SPN |
| System error 53 / 67 / timeout | Port 445 blocked or DNS |
| System error 64 | 445 connects, proxy/NAT drops the SMB handshake |
| System error 1396 (AP_ERR_MODIFIED) | Kerb key ≠ AD account password — **or** an AES salt mismatch (wrong DomainName) |
| 0xc000018b / PRINCIPAL_UNKNOWN | SPN missing or wrong |
| "encryption type not supported" | Encryption mismatch (use AES-256) |
| System error 5, ticket valid | Authorization (share RBAC / NTFS) — **or an SMB cipher mismatch** |
