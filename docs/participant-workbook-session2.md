---
title: "Participant Workbook — Session 2"
subtitle: "Azure Files with Microsoft Entra Kerberos — evidence-based diagnosis (hands-on)"
---

# About this lab

Session 1 authenticated against an on-premises AD DS domain controller. Session 2
switches the KDC: **Microsoft Entra ID issues the Kerberos tickets**, they are
fetched over an **HTTPS KDC Proxy**, and the client needs no line of sight to a
domain controller — because there is no domain controller.

Your environment is **cloud-only**: Entra-only identities, an Entra-joined
Windows Server 2025 VM, and no Active Directory anywhere. That path went **GA in
May 2026**; it is not a preview and not a workaround.

**This session is standalone.** It does not build on, need, or touch your Session
1 deployment. If you still have Session 1 running, leave it — the two live side
by side, and you can compare `klist` output between them if you want to.

## What you will and will not build

Hybrid identities — AD users synced to Entra — are what most customers run, and
they carry complications that are worth *seeing* but not worth *building*: an
Entra provisioning agent, Cloud Sync, a device-sync toggle that is off by default
and still in preview, and a hybrid join that fails in ways that look like
anything but what they are. **The facilitator demonstrates that path on their own
environment.** Everything marked below as hands-on, you do yourself.

The goal is not "click through the setup." It is to **build the evidence chain a
support engineer actually walks** — device state, PRT, cloud TGT, service ticket,
KDC Proxy exchange — and then break individual links and read which piece of
evidence moved.

---

# The access flow (memorise this — every lab cuts one arrow)

```
 sign in as an Entra user ──▶ PRT issued at logon ──▶ cloud TGT
   (password + MFA)              (dsregcmd: AzureAdPrt)   (krbtgt @
                                                           MICROSOFTONLINE)
        │                                                       │
        │                                                       ▼
        │                                      service ticket (cifs/<sa>)
        │                                      fetched via KDC Proxy over
        │                                      HTTPS: login.microsoftonline.com
        ▼                                                       │
 device Entra joined                                            ▼
 (AzureAdJoined: YES) ────────────────────────────────▶   SMB mount
                                                     then: share RBAC → NTFS ACL
```

Notice what is **not** in that picture: no SCP, no directory sync, no domain
join, no on-premises realm. Compare it with the facilitator's hybrid diagram —
every extra box there is a place a real customer's deployment can break.

---

# The evidence chain (your standard sweep)

Run these on the client VM, signed in as your lab user, top to bottom. Learn the
healthy signature first (Lab A) — diagnosis is just spotting which line changed.

| # | Command | What it proves | Healthy signature |
|---|---|---|---|
| 1 | `dsregcmd /status` | device is Entra joined and holds a PRT | `AzureAdJoined : YES`, `DomainJoined : NO`, `AzureAdPrt : YES` |
| 2 | `klist cloud_debug` | cloud TGT retrieval is **effectively** on | `Cloud Kerberos enabled by policy: 1` |
| 3 | `klist get krbtgt` | a cloud TGT was issued | `krbtgt/KERBEROS.MICROSOFTONLINE.COM`, `Kdc Called: TicketSuppliedAtLogon`, etype `Unknown (-1)` |
| 4 | `klist get cifs/<sa>.file.core.windows.net` | a service ticket was issued | AES-256, `Kdc Called: KdcProxy:login.microsoftonline.com`, `Renew Time: 0` |
| 5 | Fiddler + Kerberos.NET | the KDC Proxy request/response itself | request to `login.microsoftonline.com`, response `ErrorCode` = 0 |
| 6 | `net use Z: \\<sa>...\labshare` | authorization (share RBAC → NTFS) | `command completed successfully` |

The single most useful habit: **where does the chain first break?** A failure at
step 4 with 1–3 healthy is a completely different problem from a failure at 3.

> These signatures are **identical to the hybrid ones**. Same realm, same
> `TicketSuppliedAtLogon`, same `KdcProxy`, same `Renew Time: 0`. What changes
> between hybrid and cloud-only is how the identity got into Entra — not what a
> healthy ticket looks like. That is why what you learn here transfers.

---

# Prerequisites

- **Your own Azure subscription**, and **Global Administrator on a dev/trial
  Entra tenant** — not your corporate production tenant.
- **Azure Cloud Shell** for every Azure/Graph command. You are already signed in
  there; there is no `Connect-AzAccount` step.
- **An RDP client on Windows 11 22H2 or later.** Sign-in uses an Entra account,
  which needs the `enablerdsaadauth` option, and older clients do not support it.
- **Microsoft Authenticator on your phone.** New tenants have security defaults
  on, so your lab account is asked to register MFA at first sign-in. Do this
  **before the session** (see Lab 0) — it takes two minutes, and two minutes
  times everyone in the room is the whole first lab.
- **No restrictive App Management Policy in the tenant.** Enabling Entra Kerberos
  adds a symmetric key to an auto-created app; a tenant policy blocking
  password-credential addition fails it with
  `AadCredentialDisallowedByAppManagementPolicy`. This is the main reason the lab
  wants a **dev/trial tenant**. A Global Admin can grant an exception for the
  **Storage Resource Provider** (app ID `a6aa9161-5291-40bb-8c5c-923b567bee3b`)
  at <https://aka.ms/app-mgmt-policy-ux>.

---

# Lab 0 · Deploy (do this BEFORE the session)

```powershell
git clone https://github.com/kmin1223/azfiles-lab.git   # if you don't have it
cd azfiles-lab/session2-cloudonly
./deploy.ps1 -ResourceGroupName azfiles-cloudonly
```

About five minutes. It builds a storage account with Entra Kerberos, two
cloud-only users, an Entra-joined Windows Server 2025 VM, and the lab tooling.
There is **no manual step**.

At the end it downloads an `.rdp` file to your browser. If it does not, run
`download ~/azfiles-cloudonly.rdp` in Cloud Shell.

**Then sign in once, before the session**, to get MFA registration out of the
way:

- open the `.rdp`, sign in as `labuser1@<tenant>.onmicrosoft.com`
- complete the Authenticator enrolment
- a certificate warning is expected — the VM's RDP certificate is issued for its
  short name, not the Azure FQDN. Continue past it.
- run `dsregcmd /status` and confirm `AzureAdJoined : YES`

> **Why the .rdp file?** `enablerdsaadauth` is a file property; `mstsc` has no
> switch or GUI field for it, so `mstsc /v:<host>` will not use Entra sign-in.
> And the address must be the **FQDN** — Entra rejects a bare IP, and the name
> has to match the one the device registered under.

---

# Lab A · Build the known-good evidence chain (hands-on)

Sign in fresh as `labuser1`, walk the whole chain, and **record each healthy
signature**. This is your reference for every fault that follows. Spend real time
here; the diagnosis labs are just deltas from it.

```
dsregcmd /status
klist purge
klist cloud_debug
klist get krbtgt
klist get cifs/<sa>.file.core.windows.net
net use Z: \\<sa>.file.core.windows.net\labshare
klist
```

Two details worth stopping on:

- the cloud TGT shows `Kdc Called: TicketSuppliedAtLogon` and etype
  `Unknown (-1)` — it was **handed to you at logon with the PRT**, not fetched on
  demand.
- the service ticket shows `Kdc Called: KdcProxy:login.microsoftonline.com` —
  proof the KDC was reached over HTTPS, not port 88.

Also note `NgcSet : NO` in `dsregcmd`. You signed in with a **password**, no
Windows Hello, and it still produced a PRT and a Kerberos ticket. Some guidance
implies key-based sign-in is required here; it is not.

## Now see the KDC Proxy exchange itself

Wireshark shows only encrypted TCP — that is the whole point of KDC Proxy. Use
Fiddler:

1. Run **Fiddler** as administrator. The lab pre-trusts its root CA at machine
   scope, so **you should get no certificate prompts.** If Fiddler asks anyway,
   run `C:\LabTools\Setup-FiddlerTrust.ps1` elevated and restart it.
2. `klist purge`, then `klist get cifs/<sa>.file.core.windows.net`.
3. Find the request to **login.microsoftonline.com**; open the **Kerberos** tab.
   In a healthy run the response `ErrorCode` is 0.

**Screenshot the healthy response** — you will compare the capstone's failing one
against it.

> Close Fiddler cleanly with the X button. Killing it leaves a proxy pointed at
> `127.0.0.1:8888` — which is exactly Lab C.

---

# Lab B · A registry value that reads healthy but isn't (hands-on)

The most instructive Entra Kerberos trap: the setting *looks* correct where you
would look for it, and the effective value is the opposite.

**Break it** — on the VM, in an **elevated** PowerShell (your lab account is a
local admin, so UAC only asks for consent):

```powershell
C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt
```

**Reproduce** — sign out and back in (the policy is read at logon), then run the
chain from step 2.

**Diagnose — and notice the contradiction:**

```
# 1) The "obvious" location looks fine:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled
    ...CloudKerberosTicketRetrievalEnabled    REG_DWORD    0x1     <- says enabled!

# 2) But the EFFECTIVE value disagrees:
klist cloud_debug
    Cloud Kerberos enabled by policy: 0                            <- reality

# 3) Find who wins:
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v CloudKerberosTicketRetrievalEnabled
    ...CloudKerberosTicketRetrievalEnabled    REG_DWORD    0x0     <- the policy path
```

**The rule:** Windows reads the **Policies** path (what an **Intune CSP** writes)
**first**, and only falls back to the **LSA** path if it is unset. So on an
Intune-managed device a local `reg add` to the LSA path "does nothing" — the
policy silently wins. `klist cloud_debug` is the arbiter: it reports the
*effective* value, so trust it over any single registry read.

> **A second way to get `enabled by policy: 0` with nothing wrong.** This setting
> is read by the Kerberos SSP at **startup**. Set it and check in the same boot
> and you will see 0 with no policy anywhere. If the values look right and the
> effective one is still 0, reboot before you theorise. (This happened to us
> while building the lab.)

**Do not repair yet.** Lab B+ reads this same broken state — repairing now costs
you a second sign-out cycle for nothing.

**Field takeaway:** "the registry is set correctly but it still fails" almost
always means a higher-precedence policy source, or a service that has not re-read
it. Check `klist cloud_debug` and both paths before touching anything.

---

# Lab B+ · Prove the flags don't move (hands-on)

You just changed the routing. Now look at what the *cloud flags* did — the answer
is **nothing**, and that is the whole lesson.

**Still in the broken state**, run:

```
klist cloud_debug
klist get cifs/<sa>.file.core.windows.net
klist
dsregcmd /status
```

| Command | After the fault |
|---|---|
| `klist cloud_debug` | `enabled by policy: 0` — **changed** |
| `klist get cifs/<sa>` + `klist` | no cloud-realm service ticket — **changed** |
| `dsregcmd /status` | `AzureAdPrt`, `CloudTgt`, `KerbTopLevelNames` — **all identical** |

Look closely at `dsregcmd` in the broken state:

```
AzureAdPrt        : YES
CloudTgt          : YES
KerbTopLevelNames : .windows.net, .windows.net:1433, .azure.net, ...
```

Every cloud-looking signal says yes. The routing is dead anyway.

> **The rule of thumb**
>
> Flags describe **capability**; the ticket cache describes **what happened**.
> PRT + CloudTgt + KerbTopLevelNames = "the car has cloud features installed."
> `CloudKerberosTicketRetrievalEnabled` = "is the ignition on."
> The ticket cache = "where it actually drove." **Trust the cache.**

**Fix:**

```powershell
C:\LabTools\Invoke-LabFault.ps1 -Fault NoCloudTgt -Repair
```

then sign out and back in, and confirm the cloud-realm ticket returns.

> **[Facilitator demo] The hybrid version of this trap.** On a hybrid-joined
> machine the same flags are present *and* there is an on-premises realm to be
> wrongly routed to — so the request silently goes to a DC that cannot serve it.
> That variant cost days on a real Sev A. Your facilitator will walk the actual
> `dsregcmd` and `klist` capture from the impacted machine. The reading skill is
> the same one you just used.

---

# Lab C · When the diagnostic tool causes the outage (hands-on)

Entra Kerberos rides over HTTPS, which means the machine's **proxy stack is now
part of the authentication path** — something that never mattered with AD DS
Kerberos on port 88. Fiddler is notorious for leaving a proxy pointed at
`127.0.0.1:8888` when it exits uncleanly. You ran Fiddler in Lab A. That is not a
coincidence.

**Break it** (elevated, on the VM — no sign-out needed):

```powershell
C:\LabTools\Invoke-LabFault.ps1 -Fault ProxyMangled
```

**Reproduce:**

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

**The tell that isolates it:** *only the cloud path breaks.* Anything that does
not traverse the HTTP proxy still works. So "this one machine can authenticate
everywhere except Azure Files over Entra Kerberos" points straight at the proxy
stack.

**Fix:** `-Fault ProxyMangled -Repair`, then `klist purge` and retry.

---

# Lab D · Three doors that all say "Access denied" (hands-on)

Your deployment granted **labuser1** share access and deliberately gave
**labuser2** none. Now see how three different layers produce the *same* error
text.

| Break | How | Distinguishing evidence |
|---|---|---|
| **Storage firewall / network** | portal: Networking → *Enabled from selected networks*, don't add the VM | `net use` times out or `System error 53/67`; `Test-NetConnection <sa>.file.core.windows.net -Port 445` fails |
| **Share-level RBAC** | `./faults/Invoke-Fault.ps1 -Fault NoShareAccess` (Cloud Shell) | mount fails immediately; **Kerberos tickets are all healthy** |
| **NTFS ACL** | see below | mount and share access **succeed**; only the file or folder open is denied — the deepest layer |

**The identity contrast, for free:** sign in as **labuser2** and try to mount. The
Kerberos chain is perfect — PRT, cloud TGT, `cifs/<sa>` ticket, all issued — and
the mount is refused. Authentication and authorization are different questions,
and the ticket cache proves which one you are looking at.

## The NTFS door on a cloud-only share

There is no domain-joined client here, so the familiar `icacls` with a `DOMAIN\user`
does not apply. Cloud-only shares are ACL'd with **Entra SIDs**, which look like
`S-1-12-1-…`:

```powershell
# Cloud Shell - find the Entra SID for a user
$ctx = (Get-AzStorageAccount -ResourceGroupName azfiles-cloudonly -Name <sa>).Context
Get-AzStorageFileAcl -ShareName labshare -Path '/' -Context $ctx
```

Set a deny with `Set-AzStorageFileAcl` (SDDL), and use
`Invoke-AzStorageFileAclInheritance` to push it down a tree.

**Diagnostic order that saves time:** network (can I even reach 445?) → share
RBAC (am I allowed onto the share?) → NTFS (am I allowed this file?). The error
text is identical; the layer that is actually blocking is not. Effective access
is always the **most restrictive** of the three.

Restore afterwards: `-Fault NoShareAccess -Repair`, re-open the firewall, clear
the NTFS deny. **The capstone needs a clean environment.**

---

# Capstone · Root-cause a failure from evidence only (hands-on)

Minimal information, TSG method. Have a partner — or the facilitator — inject
**one** fault without telling you which:

```powershell
./faults/Invoke-Fault.ps1 -ResourceGroupName azfiles-cloudonly -Fault ConsentRevoked
```

You get only: *"labuser1 can't mount the share; it worked an hour ago."*

1. Walk steps 1–4. **Where does the chain first break?** Here: step 4 fails while
   1–3 are healthy — the device, the PRT and the cloud TGT are all fine, so it is
   **not** a client problem.
2. Capture step 4 in **Fiddler**. Open the failing request to
   `login.microsoftonline.com` → **Kerberos** tab → **response**. Read the
   **ErrorCode**, and note the **Entra Request ID + timestamp** in the response —
   that is what you would hand to the Entra ID team to pull the server-side trace.
3. Confirm your hypothesis in the portal: **Entra ID → Enterprise applications →
   [Storage Account] `<sa>`… → Permissions** — the grant is gone.

**Fix:** `-Fault ConsentRevoked -Repair`, `klist purge`, remount, re-capture —
`ErrorCode` back to 0.

**Why this is the capstone:** it forces the full method — chain first to localise
(client vs service), Fiddler to read the actual KDC Proxy error, portal to
confirm, and the Request ID to hand off. That is the Entra Kerberos support loop
end to end.

> **Discussion (not scripted): MFA Conditional Access → error 1327/86.** If a CA
> policy requires MFA on the storage account's app, SMB cannot perform an
> interactive MFA, and `net use` returns **System error 1327** ("Account
> restrictions are preventing this user from signing in") — or 86. The fix is to
> **exclude the `[Storage Account] <sa>.file.core.windows.net` app** from that CA
> policy, never to weaken MFA tenant-wide. Confirm it in the Entra sign-in logs.

---

# [Facilitator demo] The hybrid path — what you did not have to build

Your environment had no directory sync because it needed none. Most customers do,
and this is what it costs them. Watch for the failure modes, not the clicks.

| Piece | Why it exists | How it fails |
|---|---|---|
| **SCP in AD** | tells domain-joined devices which tenant to register with | missing or wrong tenant → the device never even tries |
| **Entra provisioning agent** | puts AD objects into Entra | needs outbound 443 from a DC; registration uses username/password auth, which breaks under MFA |
| **Cloud Sync users** | Entra Kerberos only issues to identities that exist in Entra | scoping filter misses the OU → "works for some users only" |
| **Cloud Sync DEVICE sync** | a managed tenant needs the device object in Entra *before* the client can complete its join | **off by default, and in preview.** Without it: `error_missing_device` / `0x801c03f3`, and the client's device id is the AD computer object's `objectGUID` |
| **Hybrid join** | the device half of the trust | fails long after everything "succeeded" |

**Two things to take to a real case:**

- A customer on Cloud Sync whose hybrid join fails with `error_missing_device` is
  almost certainly missing **device sync** — or needs Entra Connect Sync, which is
  the GA path for hybrid join.
- The GUID in that error is the **AD computer object's objectGUID**. Cloud Sync
  maps `DeviceId ← objectGUID` directly, so you can match them in one command:
  `Get-ADComputer <name> -Properties ObjectGUID`.

---

# Clean up

```powershell
cd ~/azfiles-lab/session2-cloudonly
Remove-AzResourceGroup -Name azfiles-cloudonly -Force -AsJob
```

Then in Entra ID, delete the two lab users and the device object for the VM.

---

# Command reference

```
dsregcmd /status                    device, PRT and join state
dsregcmd /refreshprt                refresh the Primary Refresh Token
klist cloud_debug                   EFFECTIVE cloud-TGT policy value (trust this)
klist get krbtgt                    force a cloud TGT
klist get cifs/<sa>...              force a service ticket (shows KdcProxy)
klist                               cached tickets
klist purge                         tickets only - does NOT drop the SMB session
netsh winhttp show proxy            proxy stack (now part of the auth path)
net use * /delete /y                drop every mount (do this before klist purge)
C:\LabTools\Invoke-LabFault.ps1     local faults (elevated)
```

# Error → first move quick map

| You see | First move |
|---|---|
| No cloud TGT, but the registry looks set | `klist cloud_debug` + check the **Policies** path (Lab B); if both look right, reboot |
| PRT/CloudTgt YES → "must be cloud" | don't infer routing from flags — `cloud_debug` and the cache realm decide it (Lab B+) |
| `LsaCallAuthenticationPackage 0x51f` / `0xc000005e` | `netsh winhttp show proxy` (Lab C) |
| `System error 1327` / 86 | CA/MFA on the storage app — check the sign-in logs |
| `AzureAdJoined : NO` | device registration: managed identity, egress on 443, then the `Microsoft-Windows-User Device Registration/Admin` log |
| Access denied, tickets all healthy | authorization layers: network → share RBAC → NTFS (Lab D) |
| Chain breaks at step 4 only | service-side: admin consent / the storage app — capture it in Fiddler |
| `AADSTS293004` when connecting by RDP | the name you connected to does not match the device's registered name |
