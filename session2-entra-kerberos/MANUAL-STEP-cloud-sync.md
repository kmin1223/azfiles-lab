# Manual Step: Entra Cloud Sync (hybrid identities)

This is the **only interactive step** in the whole lab. It requires a Global
Administrator sign-in in a browser, which cannot (and should not) be scripted.
Budget **~10 minutes**; run it right after `setup.ps1` while the presenter is
on slides.

Why it's needed: **this lab uses the hybrid identity scenario** — AD users
synced to Entra ID, which is the GA path for Entra Kerberos. `labuser1` and
`labuser2` exist only in the on-prem AD until you sync them.

> Cloud-only (Entra-only) identities are **also supported, GA since May 2026** — a
> separate enablement path (feature flag + admin consent) that needs no AD DS
> at all. It's out of scope for this lab but worth knowing when a customer has
> no on-prem footprint. See the Azure blog post "Azure Files Entra-Only
> identities" and the internal Entra-Only Kerberos TSG.

## 1. Install the provisioning agent on the DC

RDP to the DC VM (`azflab-dc`, IP printed by deploy.ps1) as `labadmin`, then:

1. Open a browser → https://entra.microsoft.com → sign in as a **Global Admin**
   of your lab tenant.
2. Go to **Identity → Hybrid management → Microsoft Entra Connect → Cloud sync**.
3. Click **Download agent**, run the installer on the DC.
4. In the installer, sign in with the Global Admin account, use the default
   (gMSA) service account option, confirm the `contoso.local` domain.

## 2. Create the sync configuration

Back in the Entra portal (Cloud sync blade):

1. **New configuration** → select `contoso.local`.
2. **Scoping filters** → *Selected organizational units* →
   `OU=AzureFilesLab,DC=contoso,DC=local`.
3. Leave **Password hash sync** enabled (required for this lab).
4. **Enable** the configuration and save.

## 2b. Enable DEVICE sync — do not skip this

> **Without this step hybrid join can never succeed**, and the failure looks like
> something else entirely. `dsregcmd /join` returns:
>
> ```
> Join error subcode: error_missing_device
> Join message: The device object by the given id (<guid>) is not found.
> DsrDeviceAutoJoin failed 0x801c03f3.
> ```
>
> That `<guid>` is the **objectGUID of the AD computer object** — Cloud Sync maps
> `DeviceId` ← `objectGUID` directly. The client is asking Entra to complete a
> registration against a device object that sync was supposed to create, and
> device sync is **disabled by default**.

1. Cloud sync blade → select your **AD to Microsoft Entra ID** configuration.
2. **Properties** → **Basics** → edit icon.
3. Tick **Enable device sync** → **Apply**.
4. **Provision on demand** → **Device** tab → enter the computer's distinguished
   name (`CN=azflab-cli,CN=Computers,DC=contoso,DC=local`) → **Provision**.
   This avoids waiting for the next cycle.

Requires provisioning agent **1.1.1107 or later** — if the Device tab or the
Enable device sync toggle is missing, your agent is too old. Download the current
one from the portal.

> **Preview.** Device sync with Cloud Sync is a **preview** capability. The GA
> path for Microsoft Entra hybrid join is **Entra Connect Sync**, which does sync
> computer objects. This lab uses Cloud Sync because it is far lighter to stand
> up and because the subject of the session is Azure Files, not directory sync.
> Say this out loud to the audience — and remember it on cases: a customer whose
> hybrid join fails with `error_missing_device` while running Cloud Sync is
> almost certainly missing device sync, or needs Entra Connect Sync instead.

## 3. Verify

Provisioning usually starts within 2–3 minutes:

- Portal: **Entra ID → Users** → `labuser1` appears with
  **On-premises sync enabled = Yes**.
- Portal: **Entra ID → Devices** → `azflab-cli` appears, Join type
  **Microsoft Entra hybrid joined** (it may say Registered until the client
  completes its side). The **Device ID must equal the AD computer object's
  objectGUID** — check with `Get-ADComputer azflab-cli -Properties ObjectGUID`
  on the DC.
- Only then, on the CLIENT (elevated): `dsregcmd /join /debug` →
  `AzureAdJoined : YES`. Sign out and back in to get the PRT.
- PowerShell:

```powershell
# In Cloud Shell. Use the shared helper - a bare Connect-MgGraph here falls back
# to the device code flow and times out after 120 seconds.
. ./scripts/Connect-LabGraph.ps1
Connect-LabGraph -Scopes User.Read.All

Get-MgUser -Filter "startsWith(userPrincipalName,'labuser1')" `
  -Property userPrincipalName,onPremisesSyncEnabled |
  Select-Object userPrincipalName,onPremisesSyncEnabled
```

> **Tenant note:** `labuser1@contoso.local` is not a verified domain, so the
> synced UPN becomes `labuser1@<tenant>.onmicrosoft.com`. That's fine for this
> lab; mention it to the audience — it's a common source of confusion.

## Troubleshooting the sync itself

- Agent shows unhealthy → check outbound 443 from the DC; restart the
  **Microsoft Entra provisioning agent** service.
- User not appearing → confirm the OU scoping filter matches
  `OU=AzureFilesLab`, then use **Provision on demand** in the config blade for
  an immediate, verbose test of a single user (great live demo).
