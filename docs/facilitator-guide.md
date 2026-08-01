---
title: "Azure Files Identity-Based Authentication — Facilitator Guide"
subtitle: "Two 60-minute hands-on lab sessions"
---

# Format

Each session follows the same rhythm: attendees start the automation in their
own subscription at minute 0, you present concepts while it deploys, then the
group does guided break/fix labs. The fault scripts reproduce the issues most
frequently seen in real support cases (sourced from four prior troubleshooting
decks on this topic).

**Golden rule:** never present a fault without first showing the *healthy*
state (successful mount + `klist` output). The contrast is the lesson.

# Attendee prerequisites (announce a week ahead)

Azure subscription with Owner role and quota for two Standard_B2ms VMs; for
Session 2, Global Administrator on a disposable/dev Entra tenant (least-priv
alternative: Hybrid Identity Administrator for Cloud Sync + Cloud Application
Administrator for admin consent); PowerShell 7 with the Az and Microsoft.Graph
modules; an RDP client. Strongly discourage corporate production tenants for
Session 2.

# Session 1 — On-Premises AD DS Authentication

## Run of show

| Time | Activity |
|---|---|
| 0:00–0:05 | Welcome. Everyone starts `deploy.ps1` in Cloud Shell (verify step 1/9 is running before moving on). |
| 0:05–0:28 | **Foundations** while it deploys: the four-stage exchange → the mechanism trio (join / tickets / encryption) → where the evidence lives → reading a failed exchange → identity sources, line of sight, what the automation built, the collector. |
| 0:30–0:38 | **Lab 1** — the legacy environment. It mounts fine on RC4. Capture a known-good trace. |
| 0:38–0:40 | *Concept:* RC4 retirement + the three-year-old defect (real Sev A). |
| 0:40–0:50 | **Lab 2 ★** — the AES-256 migration: enforce → 1396 → diagnose from evidence → repair in the right order. |
| 0:50–0:52 | *Concept:* SMB cipher negotiation. |
| 0:52–0:56 | **Lab 3 ★** — access denied with a perfect ticket (cipher mismatch). |
| 0:56–1:00 | Wrap-up: triage table, tear-down, Session 2 prereqs. |

Labs 4–7 in the workbook (blocked 445, share-level denial, plain 1396 key drift,
broken SPN) plus the advanced faults are **self-service** — cover them only if
you are ahead of schedule.

## Structure note — concepts sit next to their lab

Foundations go up front because the deployment needs ~25 minutes of airtime.
Everything after that is paired: the concept slide immediately precedes the lab
that exercises it (RC4 → migration lab; cipher negotiation → cipher lab; three
doors + matrix → the authorization labs). Say this out loud at the agenda slide
so nobody wonders why RC4 shows up late.

## Lab flow details

Lab 1 (healthy): on the client VM as `CONTOSO\labuser1`, mount and inspect —
then insist everyone runs the collector once on the **working** mount:

    C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>

That capture is the reference every later diagnosis diffs against. Without it
the evidence labs lose their punch.

Labs 2–4: inject → reproduce → **capture** → compare against known-good →
repair. In Lab 2, put the trace or the 4769 entry on screen: a successful ticket
issue alongside a failed SessionSetup is the single most convincing artifact in
the session. If time remains, `ClockSkew` and `DuplicateSpn` are the best
advanced faults — neither is identifiable without the evidence.

# Session 2 — Microsoft Entra Kerberos (Hybrid Identities)

> **Prerequisite — sent as a reminder 2–3 days before:** attendees **redeploy
> the Session 1 lab beforehand** (they tore it down after Session 1). Confirm in
> your reminder that everyone has a running environment *and* Global Admin on a
> dev Entra tenant. Anyone who couldn't redeploy should pair up. See
> `pre-session-announcements.md`.

## Run of show

| Time | Activity |
|---|---|
| 0:00–0:05 | Quick check that everyone's Session 1 lab is redeployed and reachable, then run `setup.ps1` (fast, ~10 min total including client reboot). |
| 0:05–0:15 | Attendees do the manual Cloud Sync step (MANUAL-STEP-cloud-sync.md) while you narrate it on screen. This doubles as content: what a hybrid identity actually is. |
| 0:15–0:30 | Slides: Entra Kerberos model (cloud TGT, no DC line of sight), requirements checklist, what the automation did (AADKERB, consent, SCP, registry). |
| 0:30–0:40 | Lab 1 (healthy): `dsregcmd /status`, `klist cloud_debug`, mount, compare the ticket realm (KERBEROS.MICROSOFTONLINE.COM) with Session 1. |
| 0:40–0:55 | Labs 2–4: NoCloudTgt → ConsentRevoked → NotHybridJoined. NoShareAccess as backup. Cover the MFA/Conditional Access pitfall verbally (not scripted). |
| 0:55–1:00 | Wrap-up: decision tree across both auth methods, cleanup instructions. |

## Key messages

On WS2022 clients (this lab), Entra Kerberos needs **hybrid identities** —
unsynced users fail, still a top field misconfiguration. Mention the 2026
update: Entra-only (cloud-only) identities are GA on Win11 25H2+/WS2025;
macOS is now supported via Platform SSO (preview). No line of sight to
a DC is needed *for data access*, but configuring per-directory/file NTFS
permissions still requires it (use default share permission to sidestep in
labs/AVD). MFA cannot be satisfied over SMB: any Conditional Access policy
demanding MFA must exclude the storage account app. The device must be Entra
joined or hybrid joined and the OS must be Win 10 (KB5007253+), Win 11, or
WS2022 (KB5007254+).

## Timing risks

Hybrid join registration and Cloud Sync provisioning each have a few minutes
of nondeterministic lag. If a participant's device isn't registered by 0:30,
pair them with a neighbor and circle back — do not stall the room. The
"Provision on demand" button in Cloud Sync is your fastest unblocker for user
sync issues and makes a good live demo by itself.

# Issue Catalog (symptom → cause → diagnosis → fix)

## Session 1 faults

**Error 1396 / KRB5KRB_AP_ERR_MODIFIED — "Logon Failure: The target account name is incorrect"**
Cause: the AD computer-account password no longer matches the storage
account's kerb key. Worth knowing: a storage account has **two** kerb keys
(kerb1 and kerb2); on receiving a ticket Azure Files tries kerb1 first, then
kerb2 — so both can be out of sync. Diagnose: mount fails after `klist purge`;
`Test-AzStorageAccountADObjectPasswordIsKerbKey` reports whether the AD password
matches either key; `Debug-AzStorageAccountAuth` flags
CheckADObjectPasswordIsCorrect. Fix: rotate and re-sync
(`Invoke-Fault.ps1 -Fault PasswordMismatch -Repair` in the lab). Production best
practice is the **two-stage rotation** with
`Update-AzStorageAccountADObjectPassword -RotateToKerbKey kerb2` → wait a few
hours → rotate back to kerb1, so an in-flight ticket signed with the old key
still validates during the change. Note there are ~9 documented root causes for
1396 (out-of-sync key, RC4 disabled on DC/client, AES-256 not actually enabled
on the SA, missing SamAccountName, AAD DS accounts wrongly AD-joined, etc.) —
the key-mismatch case is just the most common.

**KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN / klist error 0xc000018b**
Cause: the SPN `cifs/<sa>.file.core.windows.net` is missing or wrong on the AD
object. Diagnose: `klist get cifs/<sa>.file.core.windows.net` fails;
`setspn -Q cifs/<sa>.file.core.windows.net` finds nothing;
`Get-ADComputer <sa> -Properties ServicePrincipalNames`. Fix: restore the SPN.

**"The encryption type requested is not supported by the KDC" (KRB5KDC_ERR_ETYPE_NOSUPP)**
Cause: client and KDC/service share no common etype. Timely context: the 2026
Windows hardening has retired RC4-HMAC (rollout since April; the July wave
flipped AD DS defaults to AES-256 — enforcement is live), so storage accounts
domain-joined before 2023 (or manually with RC4) are failing in the field
right now — expect audience questions. The lab
deploys AES-256 from the start. Diagnose: gpedit/registry
`SupportedEncryptionTypes`; `Get-ADComputer <sa> -Properties
msDS-SupportedEncryptionTypes`; network trace shows ETYPE_NOSUPP in TGS-REP.
Fix: restore allowed etypes; to migrate an account to AES-256, ensure
SamAccountName is registered on the SA, set the encryption type, then rotate
the kerb key/password (order matters — AES keys derive from the password at
set time; `Update-AzStorageAccountAuthForAES256` in AzFilesHybrid automates it).

**System error 53 / 67 (often after a timeout) on `net use`**
Cause: outbound TCP/445 blocked (ISP, firewall, NSG) or DNS failure. This is
what the Block445 lab produces. Diagnose:
`Test-NetConnection <sa>.file.core.windows.net -Port 445`. Fix: unblock 445, or
use private endpoint/VPN.

**System error 64 — "network name no longer available"**
A *different* signature: TCP 445 connects, but a proxy/NAT middlebox drops the
SMB handshake. `Test-NetConnection` may even succeed. Diagnose with a network
trace (handshake starts, no response). Teach the contrast with 53/67 — it's a
frequent mis-triage in the field.

**System error 67 — network name cannot be found**
Cause (classic): single slash in the UNC path typo, or DNS failure; also seen
with blocked 445. Diagnose: check the exact command, `nslookup` the FQDN.

**System error 1327**
Cause: account restriction (commonly blank/expired password or, in Entra
Kerberos, no cloud TGT). Check identity state before network state.

**Access denied although `klist` shows a valid cifs ticket (System error 5)**
Cause: authorization, not authentication — share-level RBAC
(DefaultSharePermission/role assignment) or NTFS ACL missing. Read the two
layers together with the effective-access matrix (see slide): the user gets the
**more restrictive** of RBAC and NTFS. Diagnose: which layer? Try with the
storage key (bypasses share-level RBAC), check role assignments, `icacls`. Fix:
assign share-level permission and/or NTFS rights.

**System error 5 / "the user name or password is incorrect" — SMB cipher mismatch**
*(Lab 3, from a real support case that took days to resolve.)*
Cause: cipher is negotiated in the SMB Negotiate, before the client names the
storage account, so Azure Files can't choose a per-account cipher. If the
account's SMB security allows only AES-256-GCM and the client offers only
AES-128-GCM, there is no overlap and the session is refused — surfacing as an
access denial that **accuses the identity**. In the real case, Kerberos was
verified healthy (tickets issued, both SPNs present) and the investigation still
went RBAC → NTFS → NTLMv2 before the traces pointed at cipher negotiation.
Diagnose: Portal → Storage account → File shares → Security (allowed ciphers) vs
`Get-SmbClientConfiguration | select EncryptionCiphers` on the client. Fix:
allow AES-128-GCM on the account, or set the client to offer AES-256-GCM first.
AES-256-GCM requires Win 11 / WS2022+.

**Reading `Debug-AzStorageAccountAuth` output critically**
The cmdlet reports RBAC/Entra checks as failures whenever the environment simply
doesn't use them — e.g. a share relying on **DefaultSharePermission** with no
Entra sync will fail `CheckSidHasAadUser` / `CheckUserRbacAssignment`, and that
is *expected*, not a defect. Teach attendees to map each reported failure to
their design before acting on it; chasing an expected failure is a common way to
lose a day.

**Custom domain names — three facts worth stating**
Domain-joining a storage account does **not** create any DNS record in on-prem
DNS; a CNAME (`<sa>.contoso.com → <sa>.file.core.windows.net`) must be created
manually. Using that custom FQDN also requires a **second SPN** on the AD object
(`cifs/<sa>.contoso.com`). And cached credentials for either name will mask your
test results — `cmdkey /list` then `cmdkey /delete:<name>` before retesting.

**System error 5 when EDITING NTFS ACLs (not just reading)**
Cause: to change NTFS permissions you must mount with the **storage account
key**, hold **Storage File Data SMB Share Elevated Contributor** (over SMB), or
**Storage File Data Privileged Contributor** (over REST; bypasses NTFS) — a
plain Contributor can't. A very common trap is stale cached credentials.
Diagnose: `cmdkey /list` to see cached creds; check for the default ACL set
(`BUILTIN\Administrators:(OI)(CI)(F)`, `NT AUTHORITY\Authenticated Users:(OI)(CI)(M)`,
`CREATOR OWNER`, etc.). Fix: drop the mount, clear cached creds in Credential
Manager, `klist purge`, **reboot** (required), then remount with the storage key.

**System error 1326 — process running as the computer account**
Cause: a service running as `NT AUTHORITY\SYSTEM` (Defender, backup agents,
etc.) accesses the share as the *machine* account, which has no RBAC role, so
TreeConnect returns logon failure. Diagnose: Process Monitor → the failing
process's token SID → `Get-ADObject -Filter "objectSid -eq '<sid>'"` shows a
computer object. Fix: computer accounts aren't supported for AD auth unless the
share uses a **default share-level permission** (which covers all authenticated
identities, including machine accounts).

## Session 2 faults

**No cloud TGT (`klist cloud_debug` empty), mount fails ~1327**
Cause: `CloudKerberosTicketRetrievalEnabled` not set to 1 (policy applies at
logon). Diagnose: `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters /v CloudKerberosTicketRetrievalEnabled`;
`klist cloud_debug`. Fix: set to 1, sign out/in.

**Ticket issuance fails after consent removed**
Cause: admin consent (openid/profile/User.Read) missing on the
`[Storage Account] <sa>.file.core.windows.net` app. Diagnose: Entra portal →
Enterprise applications → the SA app → Permissions. Fix: re-grant consent.

**Device not hybrid/Entra joined**
Cause: `dsregcmd /status` shows AzureAdJoined: NO → no PRT → no cloud TGT.
Diagnose: `dsregcmd /status`, `dsregcmd /refreshprt`. Fix: re-register
(SCP present? `Automatic-Device-Join` task? reboot), verify in Entra Devices.

**User is cloud-only (Entra-only)**
Cause: on WS2022/older clients, Entra Kerberos requires hybrid identities.
Entra-only (cloud-only) identity support is now GA but needs Win11 25H2/26H1
or WS2025 clients — worth stating precisely, since "cloud-only never works"
is no longer true. Diagnose: user's "On-premises sync enabled" attribute +
client OS version. Fix: sync from AD (Cloud Sync / Connect Sync), or move to
a supported OS for Entra-only.

**AadCredentialDisallowedByAppManagementPolicy — enabling Entra Kerberos fails**
Cause: enabling AADKERB adds a symmetric (password) key to the auto-created
storage app, but a tenant App Management Policy forbids password-credential
addition (or caps key lifetime < 366 days). Very common in corporate/hardened
tenants — it's why the lab asks for a dev tenant. Fix (Global Admin): grant an
exception for the **Storage Resource Provider** (app ID
`a6aa9161-5291-40bb-8c5c-923b567bee3b`) on the "Block password addition" and
"Restrict max password lifetime" settings at <https://aka.ms/app-mgmt-policy-ux>,
then re-run `setup.ps1`. If policy can't change, use a subscription whose tenant
has no such policy. Note the storage account is left in `None` state after a
failed attempt (AD DS already disabled) — `setup.ps1` is idempotent and resumes.

**MFA / Conditional Access (discussion only)**
CA policy requiring MFA on the storage app breaks SMB silently-ish.
Fix: exclude the `[Storage Account]` app from MFA policies.

**Network tracing here is different — Wireshark/netsh won't work**
Entra Kerberos uses KDC Proxy over HTTPS, so a network trace only shows
encrypted TCP to login.microsoftonline.com. Use **Fiddler + the Kerberos.NET
extension** instead: enable Decrypt HTTPS traffic, reboot, run
`klist get cifs/<sa>…`, and read the AS-REQ/REP and any KRB_ERROR on the
Kerberos tab. For a PG escalation, capture the **Request ID** from the response
(`x-ms-request-id` header, or the Trace ID in the KRB_ERROR EText) plus the
timestamp — and remember a KRB_ERROR still returns HTTP 200.

**KRB_AP_ERR_SKEW — vague mount failure, everything looks configured**
Cause: client/DC clock difference beyond Kerberos' ~5 minute tolerance. The
mount error text is unhelpful; only the trace (or the Kerberos operational log)
names the skew. Diagnose: `w32tm /stripchart /computer:<dc> /samples:3`. Fix:
re-enable/restart w32time and `w32tm /resync /force`. Lab: `-Fault ClockSkew`.

**Duplicate SPN — intermittent or nonsensical failures**
Cause: the same `cifs/<sa>…` SPN registered on two AD objects; the KDC may
encrypt the ticket for the wrong account. Diagnose: `setspn -X` on the DC (or
`setspn -Q` and count the owners). Fix: remove the SPN from the wrong object.
Lab: `-Fault DuplicateSpn`. This one is genuinely hard to spot from symptoms —
use it to make the evidence-first point.

# Evidence-first diagnosis (the specialist habit)

Both lab VMs ship with `C:\LabTools\Get-KerberosEvidence.ps1`, which captures a
whole mount attempt: network trace (converted to `.pcapng` via etl2pcapng),
klist before/after, and the Kerberos + SMBClient operational logs. Kerberos
auditing (4768/4769) is enabled on the DC by the deployment.

Teach the loop: **capture a working mount first**, then every failure is a diff
against known-good. The three questions the evidence answers that an error
string can't:

1. **Did the KDC issue a ticket?** — event 4769 on the DC (and the TGS-REP in
   the trace). Success here eliminates SPN, etype and DC problems in one step.
2. **What did the client actually ask for?** — 4769's Service Name shows the SPN
   string as requested, which exposes CNAME/suffix and typo problems.
3. **Where did it stop?** — TGS vs SessionSetup vs TreeConnect in the trace maps
   directly to authentication vs service-key vs authorization.

The flagship demo is Lab 2: 4769 shows a **successful** ticket issue while SMB
SessionSetup fails with KRB_AP_ERR_MODIFIED — proof that only the service's key
is wrong. Show this on screen; it's the moment the session earns its level.

# Troubleshooting toolkit (both sessions)

    C:\LabTools\Get-KerberosEvidence.ps1 -StorageAccount <sa>   # one-shot evidence capture
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 5   # KDC record (DC)
    setspn -X                             # duplicate SPNs (DC)
    w32tm /stripchart /computer:<dc>      # clock skew
    Wireshark filter:  kerberos || smb2
    klist / klist purge / klist get cifs/<sa>.file.core.windows.net
    klist -li 0x3e7                       # the SYSTEM session's tickets
    klist cloud_debug                     # Entra Kerberos: cloud TGT state
    Get-AzStorageKerberosTicketStatus     # ticket etype + "Azure Files Health Status"
    dsregcmd /status ; dsregcmd /refreshprt
    Test-NetConnection <sa>.file.core.windows.net -Port 445
    Get-SmbClientConfiguration | select EncryptionCiphers   # SMB cipher order
    Test-AzStorageAccountADObjectPasswordIsKerbKey ...       # is the AD pw = a kerb key?
    Debug-AzStorageAccountAuth -StorageAccountName <sa> -ResourceGroupName <rg> -Verbose   # AzFilesHybrid
      # sub-checks: -Filter CheckSidHasAadUser,CheckUserRbacAssignment  (or CheckUserFileAccess -FilePath X:\f)
    AzFileDiagnostics.ps1                 # guided checks incl. mount attempt
    netsh trace start capture=yes tracefile=c:\trace.etl  →  repro  →  netsh trace stop   # AD DS only; + etl2pcapng
    Fiddler + Kerberos.NET extension      # Entra Kerberos (KDC Proxy over HTTPS)

Event logs worth showing once: Microsoft-Windows-SMBClient/Operational &
Connectivity, Microsoft-Windows-Kerberos/Operational.

# References

Overview — Azure Files identity-based authentication (Microsoft Learn);
On-premises AD DS authentication to Azure file shares; Access Azure file
shares using Microsoft Entra ID with Kerberos for hybrid identities;
Troubleshoot Azure Files identity-based authentication (SMB); Configure
Microsoft Entra hybrid join; klist / dsregcmd documentation; etl2pcapng
(GitHub, microsoft/etl2pcapng).
