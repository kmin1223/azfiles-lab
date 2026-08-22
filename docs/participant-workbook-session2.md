---
title: "Participant Workbook — Session 2"
subtitle: "Azure Files with Microsoft Entra Kerberos — evidence-based diagnosis (hands-on)"
---

# About this lab

Session 1 authenticated against an on-prem AD DS domain controller. Session 2
switches the same storage account to **Microsoft Entra Kerberos**: Entra ID
becomes the KDC, tickets are fetched over an **HTTPS KDC Proxy**, and the client
needs no line of sight to a domain controller at all.

The goal this time is not "click through the setup." It is to **build the
evidence chain a support engineer actually walks** — from device state, to the
cloud TGT, to the service ticket, to the KDC Proxy exchange in the network trace — and
then to break individual links and read which piece of evidence moved. By the
end you should be able to take a raw `klist` / `dsregcmd` / Fiddler capture and
say where the failure is, not just that there is one.

This is **Session 2 of 2**. Because you tore Session 1 down, **redeploy it first**
(Lab 0), before the session.

**Machines** (same as Session 1): **DC VM** `azflab-dc` (`labadmin`),
**Client VM** `azflab-cli` (`CONTOSO\labuser1`). Replace `<sa>` with your storage
account name from the redeploy output.

---

# The access flow (memorise this — every lab maps to one arrow)

```
 SCP in AD ──▶ device Entra hybrid-joined ──▶ PRT at logon ──▶ cloud TGT
   (setup)        (dsregcmd: AzureAdJoined)      (SSO State)    (krbtgt @
                                                                 MICROSOFTONLINE)
        │                                                              │
        │                                                              ▼
        │                                             service ticket (cifs/<sa>)
        │                                             fetched via KDC Proxy over
        │                                             HTTPS: login.microsoftonline.com
        ▼                                                              │
 hybrid identity                                                       ▼
 (AD user synced to Entra) ─────────────────────────────────▶  SMB mount
                                                          then: share RBAC → NTFS ACL
```

Each fault in this workbook cuts exactly one arrow. Your job is to find which.

---

# The evidence chain (your standard sweep)

Run these on the Client VM, signed in as the lab user, top to bottom. In a
healthy state every line has a known-good signature — learn those first (Lab A),
because diagnosis is just spotting which one changed.

| # | Command | What it proves | Healthy signature |
|---|---|---|---|
| 1 | `dsregcmd /status` | device is Entra joined + has a PRT | `AzureAdJoined : YES`, `AzureAdPrt : YES` |
| 2 | `klist cloud_debug` | cloud TGT retrieval is **effectively** on | `Cloud Kerberos ... enabled by policy: true` |
| 3 | `klist get krbtgt` | a cloud TGT was issued | `krbtgt/KERBEROS.MICROSOFTONLINE.COM`, `Kdc Called: TicketSuppliedAtLogon` |
| 4 | `klist get cifs/<sa>.file.core.windows.net` | a service ticket was issued | `cifs/<sa>...`, AES-256, `Kdc Called: KdcProxy:login.microsoftonline.com` |
| 5 | Fiddler + Kerberos.NET | the KDC Proxy request/response itself | request to `login.microsoftonline.com`, response `ErrorCode` = 0 |
| 6 | `net use Z: \\<sa>...\labshare` | authorization (share RBAC → NTFS) | `command completed successfully` |

The single most useful habit: **where does the chain first break?** A missing
step 4 with a healthy step 3 is a different problem from a missing step 3.

---

# Prerequisites

Beyond your Session 1 subscription:

- **Global Administrator** on a dev/trial Entra tenant (not corporate prod).
  Least-privilege alternative: **Hybrid Identity Administrator** (Cloud Sync) +
  **Cloud Application Administrator** (admin consent).
- Where you run the Azure/Graph commands:
  - **Azure Cloud Shell (easiest):** Az and Microsoft.Graph preinstalled.
  - **Local PowerShell 7+:** `Install-Module Az, Microsoft.Graph -Scope CurrentUser`.
- An **RDP client** on your Azure VPN for the in-VM steps.
- **No restrictive App Management Policy in the tenant.** Enabling Entra Kerberos
  adds a symmetric key to an auto-created app; a tenant policy blocking
  password-credential addition fails it with
  `AadCredentialDisallowedByAppManagementPolicy`. This is the main reason the lab
  wants a **dev/trial tenant**. A Global Admin can grant an exception for the
  **Storage Resource Provider** (app ID `a6aa9161-5291-40bb-8c5c-923b567bee3b`)
  at <https://aka.ms/app-mgmt-policy-ux>.

> **Scope note — cloud-only identities.** This lab uses **hybrid** identities
> (AD users synced to Entra), the GA path. Entra Kerberos *also* supports
> **cloud-only (Entra-only)** identities in **preview** — a separate enablement
> path with no AD DS at all. Out of scope here, but know it exists: a customer
> with no on-prem AD is not automatically unsupported. (Azure blog: "Azure Files
> Entra-Only identities.")

---

# Lab 0 · Redeploy Session 1 (do this BEFORE the session)

```powershell
git clone https://github.com/kmin1223/azfiles-lab.git   # if you don't have it
cd azfiles-lab/session1-adds
Connect-AzAccount
./deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
```

**Expected:** the green **DEPLOYMENT COMPLETE** box. Note the new storage account
name and IPs.

---

# Lab 1 · Enable Entra Kerberos + sync a hybrid identity

```powershell
cd ../session2-entra-kerberos
./setup.ps1 -ResourceGroupName azfiles-lab
```

`setup.ps1` disables the Session 1 AD DS auth (a storage account has **one**
identity source at a time), enables Entra Kerberos (AADKERB), grants admin
consent to the storage account's app, writes the hybrid-join SCP, installs
Fiddler + the Kerberos.NET extension on the client, and reboots it.

Then the **one interactive step** (~10 min, Global Admin) — follow
**MANUAL-STEP-cloud-sync.md**: install the Entra provisioning agent on the DC,
create a Cloud Sync config scoped to `OU=AzureFilesLab`, and wait until
`labuser1` shows **On-premises sync enabled = Yes**.

**Why the sync matters:** Entra Kerberos issues a ticket only to an identity that
exists in Entra. `labuser1` lives in AD; Cloud Sync gives it an Entra twin. This
is the arrow labelled *hybrid identity* in the flow.

---

# Lab A · Build the known-good evidence chain (the baseline)

Sign in fresh on the Client VM as `CONTOSO\labuser1`, then walk the whole chain
and **record each healthy signature** — this is your reference for every fault
that follows. Spend real time here; the diagnosis labs are just deltas from it.

```
dsregcmd /status
klist purge
klist cloud_debug
klist get krbtgt
klist get cifs/<sa>.file.core.windows.net
net use Z: \\<sa>.file.core.windows.net\labshare
klist
```

Confirm each against the table above. Two details worth pointing out on screen:

- the cloud TGT (`krbtgt/KERBEROS.MICROSOFTONLINE.COM`) shows
  `Kdc Called: TicketSuppliedAtLogon` and etype `Unknown (-1)` — it was handed to
  you at logon via the PRT, not fetched on demand.
- the service ticket shows `Kdc Called: KdcProxy:login.microsoftonline.com` —
  proof the KDC was reached over HTTPS, not port 88.

**Now see the KDC Proxy exchange itself.** Wireshark/netsh only show encrypted
TCP here — the whole point of KDC Proxy. Use Fiddler:

1. Run **Fiddler** (elevated). Tools → Options → **Decrypt HTTPS traffic** and
   **Ignore server certificate errors**; accept the cert prompts; restart if this
   is the first run.
2. `klist purge`, then `klist get cifs/<sa>.file.core.windows.net`.
3. Find the request to **login.microsoftonline.com**; open the **Kerberos** tab
   to read the request/response. In a healthy run the response `ErrorCode` is 0.

Screenshot the healthy Fiddler response — you'll compare the capstone's failing
one against it.

---

# Lab B · A registry value that reads healthy but isn't (policy precedence)

The most instructive Entra Kerberos trap: the setting *looks* correct in the
obvious place, yet the effective value is off.

**Break it:**

```powershell
cd session2-entra-kerberos
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
```

**Reproduce** — sign out and back in (the policy applies at logon), then run the
chain from step 2.

**Diagnose — and notice the contradiction:**

```
# 1) The "obvious" location looks fine:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled
    ...CloudKerberosTicketRetrievalEnabled    REG_DWORD    0x1     <- says enabled!

# 2) But the EFFECTIVE value disagrees:
klist cloud_debug
    Cloud Kerberos ticket retrieval enabled by policy: false        <- reality

# 3) Find who wins:
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled
    ...CloudKerberosTicketRetrievalEnabled    REG_DWORD    0x0     <- the policy path
```

**The rule:** Windows reads the **Policies** path (what an **Intune CSP** writes)
**first**, and only falls back to the **LSA** path if it's unset. So on an
Intune-managed device a local `reg add` to the LSA path "does nothing" — the
policy silently wins. `klist cloud_debug` is the arbiter: it reports the
*effective* value, so trust it over any single registry read.

**Fix:** `-Fault NoCloudTgt -Repair`, then sign out/in and re-walk the chain.

**Field takeaway:** "the registry is set correctly but it still fails" almost
always means a higher-precedence policy source. Check `klist cloud_debug` and
both paths before touching anything.

---

# Concept · Cloud or on-prem? — flags vs ground truth

This is the trap that costs the most hours on a real Sev A. A hybrid-joined
machine is covered in **cloud-looking flags** — and none of them tell you
whether a given SPN request actually went to Entra. Here is a real impacted
machine whose `cifs/…file.core.windows.net` mount failed:

**Flags that look "cloud" but do NOT decide routing:**

| Signal | Impacted machine | What it actually means |
|---|---|---|
| `AzureAdPrt : YES` | YES | the device holds an Entra PRT — for web/app SSO. Normal on any hybrid-joined box. |
| `CloudTgt : YES` (SSO State) | YES | a cloud-assisted **on-prem** TGT at logon (Windows Hello / cloud trust). It's about *getting an on-prem TGT*, not routing SPNs to Entra. |
| `KerbTopLevelNames` has `.windows.net` | YES | the suffix list the client *would* use **if** cloud Kerberos were enabled. Necessary, not sufficient. |

**The two signals that actually decide it — both point on-prem here:**

| Signal | Impacted machine | Meaning |
|---|---|---|
| `klist cloud_debug` → `enabled by policy` | **0** | the master switch (`CloudKerberosTicketRetrievalEnabled`) is off — confirmed by the registry having no such value |
| ticket cache realms | **all on-prem** | 12 tickets, every `Kdc Called` is an on-prem DC; **not one** `krbtgt @ KERBEROS.MICROSOFTONLINE.COM`, no `KdcProxy`, `Cloud Referral TGT present: 0` |

So despite `.windows.net` being in the list, the switch is `0` → the SPN was
**never routed to Entra**. The failure (`0xc00002fd` / KDC_ERR_ETYPE_NOSUPP) came
from an **on-prem DC**. Chasing Entra here is hours down the drain.

> **Two different "cloud TGTs" — do not conflate them.** `CloudTgt : YES` in SSO
> State is the Windows-Hello / cloud-trust TGT for **on-prem** realms. The Azure
> Files "cloud TGT" is a ticket in the **`KERBEROS.MICROSOFTONLINE.COM`** realm,
> which only appears when the master switch is on. Same words, different realms.

**The rule of thumb:**

> Flags describe **capability**; the ticket cache describes **what happened**.
> PRT + CloudTgt + KerbTopLevelNames = "the car has cloud features installed."
> `CloudKerberosTicketRetrievalEnabled` = "is the ignition on." The ticket
> cache = "where it actually drove." **Trust the cache.**

---

# Lab B+ · Prove the flags don't move (routing vs flags)

You already toggled the master switch in Lab B. Now watch what the *cloud flags*
do while you do it — the answer is **nothing**, and that's the whole lesson.

**With the switch ON** (healthy state), record:

```
klist cloud_debug        | note "enabled by policy: true"
klist get cifs/<sa>.file.core.windows.net
klist                    | a KERBEROS.MICROSOFTONLINE.COM ticket via KdcProxy
dsregcmd /status         | AzureAdPrt: YES · CloudTgt: YES · KerbTopLevelNames has .windows.net
```

**Now break it** (Lab B's fault), sign out/in, and re-run the SAME four:

```
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault NoCloudTgt
```

**What changed vs what didn't:**

| Command | After the fault |
|---|---|
| `klist cloud_debug` | `enabled by policy: false` — **changed** |
| `klist get cifs/<sa>` + `klist` | no cloud-realm ticket; the request no longer goes to Entra — **changed** |
| `dsregcmd /status` | `AzureAdPrt`, `CloudTgt`, `KerbTopLevelNames` — **all identical** |

That is the trap in one screen: **the routing changed, the flags did not.** If
you had diagnosed from `dsregcmd` alone you'd have concluded "still cloud" and
looked in the wrong place. Only `cloud_debug` and the cache told the truth.

**Fix:** `-Fault NoCloudTgt -Repair`, sign out/in, confirm the cloud-realm ticket
returns.

> **Real-case corollary (AD DS side).** On an AD DS-joined storage account, the
> opposite bug also exists: with the switch **ON**, `.windows.net` matches
> `KerbTopLevelNames` and the client wrongly routes `cifs/<sa>` to the **cloud**
> realm — which can't issue for an AD DS account → `0xc000018b`. The fix there is
> a `HostToRealm`/`SpnMappings` entry (LSA path) that pins the suffix back to the
> on-prem realm. Same root skill: confirm the realm from the cache before
> theorising.

---

# Lab C · When the diagnostic tool causes the outage (KDC Proxy path)

Entra Kerberos rides over HTTPS, which means the machine's **proxy stack is now
part of the authentication path** — something that never mattered with AD DS
Kerberos on port 88. Fiddler is notorious for leaving a proxy pointed at
`127.0.0.1:8888` when it exits uncleanly. This lab reproduces that residue.

**Break it:**

```powershell
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault ProxyMangled
```

**Reproduce** (Client VM, as the lab user):

```
klist purge
klist get cifs/<sa>.file.core.windows.net
    Error calling API LsaCallAuthenticationPackage (GetTicket substatus): 0x51f
    klist failed with 0xc000005e/-1073741730
```

**Diagnose — 30 seconds:**

```
netsh winhttp show proxy
    Proxy Server(s) :  127.0.0.1:8888        <- nothing is listening there
```

**The tell that isolates it:** *only the cloud path breaks.* An AD DS mount (port
88/445) from the same machine would still work — because it doesn't traverse the
HTTP proxy. So "Windows auth to on-prem works, Entra Kerberos to Azure Files
fails, on one machine" points straight at the proxy stack.

**Fix:** `-Fault ProxyMangled -Repair` (runs `netsh winhttp reset proxy`, resets
autoproxy, and clears the `iphlpsvc\ProxyMgr` `:8888` leftovers per the Fiddler
TSG), then `klist purge` and retry.

---

# Lab D · Three doors that all say "Access denied" (explicit authorization)

Session 1 used `DefaultSharePermission` so *everyone* who authenticated got
Contributor. Now that `labuser1` is a real synced Entra identity, we can do
authorization properly — and see how three different layers produce the *same*
error text.

**Set the baseline — remove the blanket permission, grant the user explicitly:**

```powershell
# Remove the "everyone" default so the layers below actually gate access
Set-AzStorageAccount -ResourceGroupName azfiles-lab -Name <sa> -DefaultSharePermission None

# Grant labuser1 (its Entra object) the share-level RBAC role
$uid = (Get-MgUser -Filter "startsWith(userPrincipalName,'labuser1')").Id
New-AzRoleAssignment -ObjectId $uid `
  -RoleDefinitionName "Storage File Data SMB Share Contributor" `
  -Scope (Get-AzStorageAccount -ResourceGroupName azfiles-lab -Name <sa>).Id
```

Remount as `labuser1`. It should now work **through an explicit assignment**, not
the default — and this is the moment `Debug-AzStorageAccountAuth`'s
`CheckSidHasAadUser` / `CheckUserRbacAssignment` finally **pass** (they were
*expected* failures in Session 1 by design). Run Debug now and see them flip to
Passed — that contrast is the point.

**Now walk the three doors.** Each of these produces "Access is denied," and only
evidence tells them apart:

| Break | How | Distinguishing evidence |
|---|---|---|
| **Storage firewall / network** | portal: Networking → *Enabled from selected networks*, don't add the client | `net use` times out or `System error 53/67`; `Test-NetConnection <sa>.file.core.windows.net -Port 445` fails |
| **Share-level RBAC** | remove the role assignment above | mount fails immediately; `Debug-AzStorageAccountAuth` → `CheckUserRbacAssignment` FAILED; Kerberos tickets are all healthy |
| **NTFS ACL** | (on a mounted share) `icacls` deny for the user on a subfolder | mount and share access **succeed**; only the file/folder open is denied — deepest layer |

**Diagnostic order that saves time:** network (can I even reach 445?) → share
RBAC (am I allowed onto the share?) → NTFS (am I allowed this file?). The error
text is identical; the layer that's actually blocking is not. Effective access is
always the **most restrictive** of the three.

Restore afterwards: re-add the RBAC role (or set `DefaultSharePermission` back),
re-open the firewall, clear the NTFS deny.

---

# Capstone · Root-cause a failure from evidence only

Minimal information, TSG method. Have a partner (or the facilitator) inject
**one** fault without telling you which:

```powershell
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-lab -Fault ConsentRevoked
```

You get only: *"labuser1 can't mount the share; it worked an hour ago."* Find the
cause using the evidence chain, ending in a **Fiddler capture**:

1. Walk steps 1–4. Where does the chain first break? (Here: step 4 fails while
   1–3 are healthy — the device, PRT and cloud TGT are all fine, so it's **not**
   a client/device problem.)
2. Capture step 4 in **Fiddler**. Open the failing request to
   `login.microsoftonline.com` → **Kerberos** tab → **response**. Read the
   **ErrorCode**, and note the **Entra Request ID + timestamp** in the response —
   that's what you'd hand to the Entra ID team to pull the server-side trace.
3. Confirm your hypothesis in the portal: **Entra ID → Enterprise applications →
   [Storage Account] `<sa>`… → Permissions** — the grant is gone.

**Fix:** `-Fault ConsentRevoked -Repair`, remount, re-capture — ErrorCode back to
0.

**Why this is the capstone:** it forces the full method — chain first to localise
(client vs service), Fiddler to read the actual KDC Proxy error, portal to
confirm, and the Request ID to hand off. That's the Entra Kerberos support loop
end to end.

> **Discussion (not scripted): MFA Conditional Access → error 1327/86.** If a CA
> policy requires MFA on the storage account's app, SMB can't perform an
> interactive MFA, and `net use` returns **System error 1327** ("Account
> restrictions are preventing this user from signing in") — or 86. The fix is to
> **exclude the `[Storage Account] <sa>.file.core.windows.net` app** from that CA
> policy, never to weaken MFA tenant-wide. You'd confirm it in the Entra sign-in
> logs (look for the storage app + a blocked MFA requirement). This is documented
> publicly in *storage-files-identity-auth-hybrid-identities-enable*.

---

# Deeper faults kept for reference

Still available via `Invoke-Fault.ps1`, for self-study or a longer session:

- **NotHybridJoined** — `dsregcmd /leave`; `AzureAdJoined : NO` → no PRT → no
  cloud TGT. Cuts the earliest arrow in the flow, so the whole chain drops.
- **NoShareAccess** — `DefaultSharePermission None` with no explicit grant; the
  simplest of the three "Access denied" doors.

---

# Advanced tracing reference

For the rare escalation, the hybrid-flow TSG's Kerberos ETW capture (survives a
disconnect; run for a few minutes around ticket expiry, ~1 hour after issue):

```
logman start auth_kerberos -ow -o kerberos.etl -nb 16 16 -bs 1024 -max 8192 -ets
logman update trace auth_kerberos -p "{6B510852-3583-4e2d-AFFE-A67F9F223438}" 0x7ffffff 0xff -ets
# ... (see the TSG for the full provider list) ...
# reproduce the issue
logman stop auth_kerberos -ets
```

Always record a **UTC timestamp** with any capture — Fiddler, Wireshark, or ETW —
so it can be correlated with Entra server-side logs by Request ID.

---

# Clean up

```powershell
./cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra
```

Then delete the Cloud Sync configuration and provisioning agent in the Entra
portal (the script reminds you).

---

# Command reference

```
dsregcmd /status                    device & PRT / join state
dsregcmd /refreshprt                refresh the Primary Refresh Token
klist cloud_debug                   EFFECTIVE cloud-TGT policy value (trust this)
klist get krbtgt                    force a cloud TGT
klist get cifs/<sa>...              force a service ticket (shows KdcProxy)
klist                               cached tickets (note the two realms)
netsh winhttp show proxy            proxy stack (part of the Entra path)
```

# Error → first move quick map

| You see | First move |
|---|---|
| No cloud TGT, but reg looks set | `klist cloud_debug` + check the **Policies** path (Lab B) |
| PRT/CloudTgt YES → "must be cloud" | don't infer routing from flags — `cloud_debug enabled by policy` + cache realm decide it (Lab B+) |
| `LsaCallAuthenticationPackage 0x51f` / `0xc000005e` | `netsh winhttp show proxy` (Lab C) |
| `System error 1327` / 86 | CA/MFA on the storage app — check sign-in logs (capstone note) |
| `AzureAdJoined : NO` | device registration (NotHybridJoined) |
| Access denied, tickets all healthy | authorization layers: network → RBAC → NTFS (Lab D) |
| Works for some users only | those users are cloud-only, not synced hybrid |
| Chain breaks at step 4 only | service-side: admin consent / app — capture in Fiddler |
