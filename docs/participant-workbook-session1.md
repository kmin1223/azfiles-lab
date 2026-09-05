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

> **Your lab deploys in the supported configuration** — AES-256 Kerberos
> encryption and an `ActiveDirectoryDomainName` holding the DNS root. In the
> AES-256 migration lab you will **regress it yourself** to a "2023 vintage"
> state (RC4 + the **NetBIOS** name in that field), watch it mount perfectly
> anyway — RC4 keys aren't salted, so the wrong value is never used — and then
> migrate forward and find out why it breaks. This mirrors a real Sev A incident.

---

# Prerequisites

- Azure subscription with the **Owner** role and quota for two `Standard_B2ms`
  VMs.
- **Azure Cloud Shell** — where every deploy and fault command runs. Nothing to
  install (Az and Microsoft.Graph are already there), you are already signed in,
  and there is no execution-policy or "unblock" friction.
- An **RDP client**, connected to your Azure VPN (RDP is allowed from the
  AzureCloud service tag). *Also required* — the klist / net use / mount steps
  happen inside the VMs, which Cloud Shell can't do.

The deployment uses a plain ARM template — nothing extra to install.

> **Everything outside the VMs runs in Azure Cloud Shell.** Open it from the
> portal (`>_` icon), pick PowerShell, and `git clone` the kit there. You are
> already signed in, so there is no `Connect-AzAccount` step, and paths use
> forward slashes (`./deploy.ps1`, `./faults/Invoke-Fault.ps1`). One caveat:
> Cloud Shell disconnects after ~20 min idle; the deploy prints output the
> whole time so it stays alive, and if it ever drops just re-run the same
> command (it resumes safely).

---

# Lab 1 · Deploy the environment

In **Azure Cloud Shell** (PowerShell) — the `>_` icon in the Azure portal:

```powershell
git clone https://github.com/kmin1223/azfiles-lab.git
cd azfiles-lab/session1-adds
./deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

No password prompt: the script **auto-generates the lab password** and prints
it in the summary and the `~/azfiles-lab-logs/lab-info-*.txt` file — you'll
need it for RDP (labadmin and labuser1 share it). To choose your own instead,
pass `-AdminPassword` (12+ chars; avoid spaces, quotes,
backticks, `$`). The script runs unattended for ~15 minutes.

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
**AES-256-CTS-HMAC-SHA1-96** — the supported configuration. Remember this line:
in the AES-256 migration lab you will regress it to RC4 and back. Open
`Z:\` — you'll see `hello-from-setup.txt`, and you can create a file:

```
echo hello > "Z:\$($env:USERNAME).txt"
```

**Why:** your logon already got you a Kerberos TGT; mounting the share just adds
a service ticket for the `cifs` SPN — no extra credentials needed. Take a quick
screenshot of this `klist` output; it's your "known good" reference for the
fault labs.

**The one-command health check.** The **Client VM** has the Az and
**AzFilesHybrid** modules installed, so you can run the official diagnostic
right there. Run it on the **client, not the DC** — that is where these cmdlets
belong in a real environment too, and the DC in this lab has no Azure tooling on
purpose.

This is **the one place you sign in to Azure by hand**: it runs inside the VM,
not in Cloud Shell, so the VM has no session of its own.

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
> Connect-AzAccount -DeviceCode
> ```
>
> **If that "succeeds" but lists no subscriptions** (per-tenant MFA warnings,
> empty table at the end): your account spans several tenants and each one
> demands its own MFA pass. Target the right tenant from the start — look up
> the GUID where you deployed (`Get-AzSubscription | Select Name, TenantId`
> in Cloud Shell), then:
>
> ```powershell
> Connect-AzAccount -DeviceCode -TenantId <tenant-guid>
> ```
>
> If it is still blocked (e.g. conditional access requires a compliant device),
> skip the VM sign-in entirely — only `Debug-AzStorageAccountAuth` needs it.
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
wire. Every later capture is a diff against this one.

Do it the way you would on a real case: **the trace needs admin rights, but the
mount must happen in the affected user's own, non-elevated session** — that is
the session whose ticket cache and drive letters you are diagnosing. So you use
two windows.

```powershell
# 1) ELEVATED PowerShell  (labuser1 is a local admin here: just click Yes on UAC)
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace

# 2) NORMAL PowerShell - reproduce as the user
C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <sa>

# 3) back in the ELEVATED window
C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace
```

> **If UAC asks for a password, close it and start again.** Elevating with
> `labadmin` would run the trace as a different user entirely. Elevation must
> stay `labuser1`.
>
> In a hurry? `Get-KerberosEvidence.ps1 -StorageAccount <sa>` in the elevated
> window does all three in one go. The identity is still `labuser1`, so the
> Kerberos evidence is faithful — but the mount lands in the elevated logon
> session, with its own ticket cache and drive letters. This is exactly the
> split you ask customers to respect when you request a trace: *you* start the
> capture, *the affected user* reproduces.

It purges tickets, starts a network trace, performs the mount, stops the trace,
converts it to `.pcapng`, and collects the Kerberos/SMBClient logs into
`C:\LabTools\evidence\<timestamp>\`.

> **Which channel sees what.** The three event logs behave very differently, and
> knowing which one to open is half the skill:
>
> | Channel | On a healthy mount | On the 1396 failure |
> |---|---|---|
> | `Kerberos/Operational` | empty | **still empty** — the client's Kerberos stack did nothing wrong |
> | `SMBClient/Operational` | routine 30904 noise | the same routine noise |
> | `SMBClient/Security` | empty | **event 31001, the real record** |
>
> `Kerberos/Operational` stays quiet because the client behaved perfectly: it got
> a good ticket from the DC and sent a good AP-REQ. The refusal came from the
> **service**, inside the SMB Session Setup — so it lands in `SMBClient/Security`.
>
> The 30904 events ("server does not support multichannel") are routine **in this
> lab's configuration** — our standard share's Negotiate response doesn't
> advertise multichannel. Don't generalise it: **Azure Files does support SMB
> Multichannel on premium (SSD) file shares**, where it is off by default and
> enabled per storage account. So a customer seeing these events may simply not
> have turned it on. The
> collector labels them benign and tells you how many events are actually worth
> reading, so a full-looking log doesn't send you chasing it.
>
> `smb-connection.txt` and `smb-client-config.txt` are always populated —
> dialect, cipher, signing — and the latter is what you compare in Lab 3.

Open `trace.pcapng` in Wireshark (or copy it off the VM) and filter:

```
kerberos || smb2
```

**What a healthy attempt looks like** — the whole thing takes about 13 ms:

```
  SMB2  Negotiate Protocol Request / Response      <- BEFORE any Kerberos
  KRB5  AS-REQ
  KRB5  KRB Error: KRB5KDC_ERR_PREAUTH_REQUIRED    <- normal, see below
  KRB5  AS-REQ        (retried, now with pre-auth)
  KRB5  AS-REP                                     <- TGT issued
  KRB5  TGS-REQ
  KRB5  TGS-REP                                    <- service ticket issued
  SMB2  Session Setup Request   (large - it carries the ticket)
  SMB2  Session Setup Response  (success)
  SMB2  Encrypted SMB3 ...
```

Three things in that list surprise people:

- **`KRB5KDC_ERR_PREAUTH_REQUIRED` is not a problem.** The first AS-REQ carries no
  pre-authentication data, so the KDC asks for it and the client immediately
  retries. Wireshark paints it red; it is the most misread frame in any Kerberos
  capture. A healthy exchange contains it.
- **`Negotiate` happens before Kerberos.** The dialect and the SMB cipher are
  settled before a single Kerberos frame goes out, and the storage account's
  `channelEncryption` setting is **not** consulted at this point — that check
  happens one step later, at Session Setup, which is what Lab 3 lives on. (The
  account name *is* on the wire here, in `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID` —
  the server just doesn't use it to choose the cipher.)

  > **How the cipher gets chosen — observed, not specified.** In every capture we
  > took against Azure Files, the server returned the client's **first** offered
  > cipher. MS-SMB2 leaves the selection algorithm to the implementation (Windows
  > Server, for instance, picks by *server* preference), so treat "first offer
  > wins" as **the behaviour of Azure Files as we measured it**, not as a
  > protocol rule. The repair it implies is unaffected either way: put an
  > account-allowed cipher at the **head** of the client's list.
- **You never see `Tree Connect`.** Once Session Setup succeeds, SMB3 encryption
  is on and everything after it shows as `Encrypted SMB3`. **The wire shows you
  authentication, not authorization** — which is why the "Access denied" labs
  need different evidence.

> **Why your capture has more in it than a customer's.** The collector runs
> `klist purge` first, so even the TGT has to be re-acquired and you get the AS
> exchange too. On a real case the user already holds a TGT and you will usually
> see only `TGS-REQ` / `TGS-REP`. Don't treat a missing AS exchange as a finding.
>
> **And note what did NOT happen: you were not asked to log on again.** The TGT
> is not stored somewhere separate — the *credential that can fetch a TGT* is.
> A logon session holds two things: the ticket cache, and the session's own
> credential material. `klist purge` empties only the first, so the next Kerberos
> request silently re-authenticates with the second. That AS exchange in your
> capture **is** that silent re-authentication.
>
> Two consequences worth carrying to a real case. First, purge is a safe reset
> **only while the DC is reachable** — purge with the DC down and you cannot get
> a new TGT until you sign out and back in. Second, purge does **not** re-validate
> the password: it reuses whatever credential material the logon session already
> holds. So a purge tells you nothing about whether the password is still current
> — and if that material has gone stale (the password was changed elsewhere), the
> silent AS-REQ **fails** rather than succeeding quietly. Don't read "the mount
> still works after purge" as "the password is fine".

And on the **DC**, the KDC's own record of that ticket:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 5 |
  Format-List TimeCreated, Message
```

Note three fields in event 4769:

- **Service Name** — the **account or computer object** the ticket was requested
  *for*, so it looks like `<sa>$`, not like the SPN string the client typed.
  (Microsoft's own field definition: *"the name of the account or computer for
  which the service ticket was requested."*) This matters more than it sounds:
  when you are hunting a duplicate SPN, this field tells you **which object the
  KDC actually matched**. To see the SPN the client asked for, read the client
  side — `klist get <spn>` or the TGS-REQ in the trace.
- **Ticket Encryption Type** — `0x12` = AES-256, what you have now; `0x17` = RC4,
  which is what you'll see after regressing to the legacy state in the migration lab.
- **Failure Code** — `0x0` on success.

---

# Lab 3 · The AES-256 migration ★

Your account is currently configured correctly. To play out the real incident,
you first have to become the customer who inherited a 2023-era environment —
then comply with the 2026 mandate and deal with what happens.

## Step 1 — build the "2023 vintage" state

```powershell
cd session1-adds
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Legacy
```

This does what an admin did three years ago: drops the AD object to **RC4** and
writes the **NetBIOS** name into `ActiveDirectoryDomainName` instead of the DNS
root. It then mounts the share to prove the state is healthy.

Takes about 3 minutes. **Read the output**: the mount succeeds and the ticket is
RC4. That is the whole point — the wrong `ActiveDirectoryDomainName` is sitting
right there and nothing complains, because RC4 keys are unsalted and never
consume that value. A defect like this survives for years precisely because it
has no symptom.

> If the script warns that RC4 **did not** mount, this environment has RC4
> disabled at the OS level. Skip to Step 2 (`-Step Enforce`) — you'll still see
> the AES-256 failure and the repair, just without the "invisible for years"
> setup.

## Step 2 — perform the migration

```powershell
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Enforce
```

This flips the AD object to AES-256 only — the change most people would make.

## Step 3 — retest (drop the SMB *session* first!)

On the **Client VM**:

```powershell
# in your NORMAL window
net use * /delete /y
net use \\<sa>.file.core.windows.net\labshare /delete /y
net use Z: /delete /y
klist purge

# in the ELEVATED window - Get-SmbConnection requires it.
# Filter: an unfiltered list also shows the machine's own IPC$ connection to
# the DC, which is normal and has nothing to do with the share.
Get-SmbConnection | Where-Object ServerName -like '*file.core.windows.net'

# back in the normal window
net use Z: \\<sa>.file.core.windows.net\labshare
```

**Expected:** `System error 1396`.

> Two things that will bite you here. **`Get-SmbConnection` needs an elevated
> window** — a standard token gets *"Access is denied"*, even for a local admin.
> And **`System error 85` ("the local device name is already in use")** while
> `net use` lists nothing means a dead mapping still owns the letter: clear it
> with `net use Z: /delete /y` or `Remove-SmbMapping -LocalPath Z: -Force`.

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

Before answering, notice that **the same failure has three different names**
depending on which layer you look at — and all three point at the *name*, which
is the misleading part:

| Layer | What it says |
|---|---|
| Kerberos, on the wire | `KRB_AP_ERR_MODIFIED` (error 41) |
| SSPI, in `SMBClient/Security` event 31001 | `0x80090322` = `SEC_E_WRONG_PRINCIPAL` |
| Win32, from `net use` | `1396` "The target account name is incorrect" |

All three say *wrong principal / wrong target name*. **The name is fine.** The
key derived from it is wrong. (The event log shows `0x80090322` as "Unknown
NTSTATUS Error code" because it is a SECURITY_STATUS, not an NTSTATUS — don't
let that stop you.)

Because the AES key is derived with a **salt** built from
`DomainName + SamAccountName + AccountType`. Now run `-Step Status` and look
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

*Want to run it again?* `-Step Legacy` puts the defect back. (`-Step Rollback`
still works as its old name.) Leave the account **repaired** at the end of the
session so it's in the supported state for Session 2.

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
# client - the list is tried IN THIS ORDER, top first
Get-SmbClientConfiguration | Select-Object -ExpandProperty EncryptionCiphers
# storage: Azure portal -> storage account -> File shares -> Security
#          ("SMB channel encryption" - anything unchecked is refused)
```

## On the wire — where the decision was actually made

Open `trace-summary.txt` and read the **CIPHER** block at the bottom, or open the
capture in Wireshark with filter `smb2 || kerberos` and look at two frames:

| Frame | What to read | This lab |
|---|---|---|
| Negotiate Protocol **Request** | `SMB2_ENCRYPTION_CAPABILITIES` → CipherId list | what the client offered, in order |
| Negotiate Protocol **Response** | `SMB2_ENCRYPTION_CAPABILITIES` → CipherId | the one the server picked |
| Session Setup **Response** | NT Status, **Blob Length** | `0xc0000022`, blob length **0** |

Three things that capture proves, and they are not what most people assume:

1. **The server takes the client's first offer, full stop.** Two runs prove it:

   | Client offers (in order) | Account allows | Server chose | Result |
   |---|---|---|---|
   | 128-GCM, 128-CCM, 256-GCM, 256-CCM | 256-GCM only | **128-GCM** | denied |
   | **256-CCM**, 128-GCM, 128-CCM, 256-GCM | 128-CCM, 128-GCM | **256-CCM** | denied |

   Look hard at the second row. The client's list contained **two** ciphers the
   account allows — and the server still picked the disallowed one, because it
   was first. If the server filtered by account policy it would have chosen
   128-GCM and the mount would have worked.

   **The rule: the HEAD of the client's list must be a cipher the account allows.**
   Anything further down is decoration. This is why the repair reorders rather
   than appends.

   Row 2 has a sharper edge too: **AES-256-CCM isn't even an option on the
   account.** Azure Files exposes only AES-128-CCM, AES-128-GCM and AES-256-GCM.
   So the server negotiated a cipher the account could never allow, no matter how
   it is configured — proof that the two layers don't talk to each other.
2. **Negotiate does not consult the account policy.** It returns
   `STATUS_SUCCESS`. The account's `channelEncryption` is enforced one step later,
   at Session Setup. (The client *does* name the account at Negotiate — it is
   right there in `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID` — the server just doesn't
   use it to filter the cipher list.)
3. **This particular rejection carries no Kerberos error at all.** `Blob Length: 0`,
   no GSS token, response in ~3 ms. Compare with Lab 5, where the same-looking
   denial *does* carry a Kerberos error (`AP_ERR_MODIFIED`) inside the blob.

   The useful triage rule is a **conjunction**, not a single field:

   | You see | Read it as |
   |---|---|
   | `0xc0000022` + blob length **0** + Kerberos logs/trace **clean** | the service refused before identity — look at channel/config, e.g. the cipher |
   | denial + blob **populated** with a KRB error | identity — read that error |

   A populated blob proves a Kerberos error was returned; **an empty blob on its
   own proves only that no GSS token came back.** Confirm with the SMB status
   code and the client-side Kerberos logs before you rule identity out. Used with
   that qualifier, it is still the fastest triage in this session.

This also matches the documented requirement: if you set an account to
AES-256-GCM only, Microsoft's own guidance is to run
`Set-SmbClientConfiguration -EncryptionCiphers "AES_256_GCM"` on every connecting
client. The capture shows *why* that instruction exists.

## Fix — on the client, not the account

```powershell
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault CipherMismatch -Repair
```

The repair changes the **client's** cipher order so an account-allowed cipher
leads:

```powershell
Set-SmbClientConfiguration -EncryptionCiphers "AES_256_GCM,AES_128_GCM,AES_128_CCM,AES_256_CCM"
```

Two deliberate choices in that line, both straight from real support practice:

- **The account keeps its hardened setting.** "Maximum security" on the storage
  account is usually a decision someone made on purpose; the first move is to
  bring the client up to it, not to weaken the account. (Re-allowing the cipher
  on the account is the fallback when a fleet of unmanageable clients is
  involved.)
- **The weaker ciphers stay in the client list, just lower.** Removing them
  entirely breaks compatibility elsewhere — notably, mounting with the
  **storage account key** needs AES-128-CCM. Order, not removal, is the tool.
- **`AES_256_CCM` goes last on purpose.** Azure Files doesn't expose it on the
  account at all, so a client that leads with it can never connect — whatever the
  account is set to. It is kept in the list only for non-Azure SMB servers.

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
your known-good capture. **Everything is identical until one frame:**

```
 healthy   ... TGS-REP -> Session Setup Request -> Session Setup Response (ok) -> Encrypted SMB3
 this one  ... TGS-REP -> Session Setup Request -> KRB Error: KRB5KRB_AP_ERR_MODIFIED
```

Two details in that error frame are worth more than the rest of the capture:

- **Its Protocol column says `SMB2`, and it comes from the storage account, not
  the DC.** The Kerberos error is carried *inside* the Session Setup response,
  on port 445. That is the service saying "I could not decrypt your ticket" —
  and it is exactly why `Kerberos/Operational` on the client stays empty.
- **Right after it, the client asks the DC for the ticket again** (TGS-REQ /
  TGS-REP), tries once more, and fails the same way. The whole cycle repeats
  every 5–6 seconds.

That second point produces the most counter-intuitive fact in this lab: **during
a total outage, the DC's 4769 log fills up with SUCCESS.** The client keeps
asking, and the KDC keeps correctly issuing. If you were looking only at the DC
you would conclude everything is fine.

## Open that error frame — the failure is three layers down

Click the `KRB Error` frame and expand it. Every layer above the Kerberos
payload reports something that looks *fine*:

```
SMB2 header    NT Status: STATUS_MORE_PROCESSING_REQUIRED (0xc0000016)   normal
 └ SPNEGO      negResult: accept-incomplete                              normal
    └ Kerberos krb5_tok_id: KRB5_ERROR
                error-code: eRR-MODIFIED (41)                            ← the failure
                sname:      <sa>
```

`STATUS_MORE_PROCESSING_REQUIRED` is the ordinary status for an intermediate
Session Setup response, and `accept-incomplete` just means the handshake has more
legs to go. The service even allocated a Session Id and set `Encrypt: True`.

**So a filter on SMB2 status codes finds nothing here.** The rejection only
exists inside the security blob. Wireshark digs it out for you and puts it in the
Info column — that convenience is the only reason it looked obvious. On a case
where someone hands you "no SMB errors in the trace", this is the frame they
missed.

The `sname` field is worth a look too: it is the principal the **service** tried
to be — your storage account name. The service is telling you *"I am who you
asked for, and I still could not decrypt this."*

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
error, 64, means 445 connects but the session gets torn down — usually a
proxy/NAT/firewall, though not only.)

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
- **`-Fault DuplicateSpn`** — the "ghost object": tries to register the storage
  SPN on a second AD object.

  > **Read this before you run it.** AD enforces SPN uniqueness forest-wide at
  > write time, so on a healthy modern domain this write is usually **refused**
  > (*"SPN value provided for addition/modification is not unique forest-wide"*).
  > That refusal is itself the lesson — it is why real duplicate-SPN incidents
  > come from odd states (lingering objects, restored-from-backup DCs, writes
  > that bypassed the check) rather than from someone simply typing `setspn -a`
  > twice. And **when duplicates do exist, the usual KDC answer is
  > `KDC_ERR_PRINCIPAL_NOT_UNIQUE`**, not a silent match on the wrong object.
  > Treat "the KDC matched the ghost and used the wrong key" as one possible
  > outcome, not the expected one.

  Diagnosis order:
  1. `setspn -X` (or `-F -Q cifs/<sa>...`) to look for duplicates — but know its
     limit: `-F` is a **forest** search against the GC, so another *domain* in the
     forest does **not** hide a duplicate. What can hide is an object that never
     replicated properly — a **lingering object** sitting in one DC's local
     partition.
  2. The decisive evidence is **event 4769 on the DC that failed the request**:
     its Service Name / Service ID show *which account the KDC actually
     matched*. One 4769 line beats hours of theorising. (Straight from a real
     Sev A: `setspn -F` swore the SPN was unique while one DC kept answering
     error 14 — the winning move was pulling 4769 from that specific DC.)

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
./labs/Invoke-Aes256Migration.ps1 -ResourceGroupName azfiles-lab -Step Status|Legacy|Enforce|Repair

--- evidence ---
C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>    trace + logs for one attempt
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 5    KDC record (DC)
w32tm /stripchart /computer:azflab-dc /samples:3             clock skew vs the DC
Wireshark filter:  kerberos || smb2
```

# Error → cause quick map

| You see (error, or in the trace) | Likely cause |
|---|---|
| `KRB_AP_ERR_SKEW` | Clock skew > ~5 min between client and DC |
| duplicate SPN in `setspn -X` | Two AD objects claim the same SPN |
| System error 53 / 67 / timeout | Port 445 blocked or DNS |
| System error 64 | 445 connects but the session is torn down. Most often a proxy/NAT/firewall middlebox — **but not only**: `ERROR_NETNAME_DELETED` also covers server-side teardown, so Kerberos/account config stays on the list. Trace it and see where it stops. |
| System error 1396 (AP_ERR_MODIFIED) | Kerb key ≠ AD account password — **or** an AES salt mismatch (wrong DomainName) |
| 0xc000018b / PRINCIPAL_UNKNOWN | SPN missing or wrong |
| "encryption type not supported" | Encryption mismatch (use AES-256) |
| System error 5, ticket valid | Authorization (share RBAC / NTFS) — **or an SMB cipher mismatch** |
