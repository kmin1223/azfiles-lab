# Manual Step: Entra Cloud Sync (hybrid identities)

This is the **only interactive step** in the whole lab. It requires a Global
Administrator sign-in in a browser, which cannot (and should not) be scripted.
Budget **~10 minutes**; run it right after `setup.ps1` while the presenter is
on slides.

Why it's needed: Entra Kerberos only works for **hybrid identities** — AD
users synced to Entra ID. Cloud-only users are not supported. `labuser1` and
`labuser2` exist only in the on-prem AD until you sync them.

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

## 3. Verify

Provisioning usually starts within 2–3 minutes:

- Portal: **Entra ID → Users** → `labuser1` appears with
  **On-premises sync enabled = Yes**.
- PowerShell:

```powershell
Connect-MgGraph -Scopes User.Read.All
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
