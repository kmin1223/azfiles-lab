---
title: "Pre-Session Announcements (copy/paste)"
subtitle: "Azure Files Identity-Based Auth — hands-on lab series"
---

Ready-to-send messages for email, Teams, or Slack. Fill in the bracketed
details before sending.

---

# 1 · Before Session 1 (send ~1 week ahead)

**Subject: Action needed before our Azure Files lab — Session 1 on [DATE]**

Hi all,

Next [DATE] we're running the first of two hands-on Azure Files identity
sessions. You'll deploy a small lab into **your own Azure subscription** and
break/fix real Kerberos issues with us. Please have this ready beforehand:

- An **Azure subscription where you are Owner**, with quota for two
  `Standard_B2ms` VMs (a personal/dev subscription is fine).
- **PowerShell 7+** with the Az module:
  `Install-Module Az -Scope CurrentUser`
- An **RDP client**, connected to our **Azure VPN** (the lab only allows RDP
  from Azure — [VPN setup link/notes]).
- The lab kit: [download link]. Unzip it somewhere simple like `C:\temp`.

The deployment uses a plain ARM template and is self-contained.

We'll kick off the deployment together at the start, so nothing to run in
advance. See you there!

[Your name]

---

# 2 · Before Session 2 (send 2–3 days ahead) — IMPORTANT

**Subject: Please redeploy the lab BEFORE Session 2 on [DATE]**

Hi all,

Session 2 (Microsoft Entra Kerberos) builds directly on the Session 1
environment. Since we deleted those resources after Session 1 to avoid idle VM
costs, **please redeploy the Session 1 lab before we meet** — it takes ~15–30
minutes and we won't have time to wait for it during the session.

**Do this the day before (or morning of) Session 2:**

1. Open PowerShell in your lab kit's `session1-adds` folder.
2. Run:

   ```powershell
   Get-ChildItem -Path .\ -Recurse | Unblock-File
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   Connect-AzAccount
   .\deploy.ps1 -ResourceGroupName azfiles-lab -Location koreacentral
   ```

3. Wait for the green **DEPLOYMENT COMPLETE** box. Note the new storage account
   name and the DC/Client IPs (they'll be different from last time).

**Also make sure you have (new for Session 2):**

- **Global Administrator** on a **dev/trial Entra tenant** (not a corporate
  production tenant). A free M365 developer tenant works well.
- The Microsoft Graph module:
  `Install-Module Microsoft.Graph -Scope CurrentUser`

If your redeploy fails or you can't get Global Admin, message me **before** the
session so we can sort it out. Come with the lab already running — we'll go
straight into Entra Kerberos.

[Your name]

---

# 3 · After Session 2 (optional cleanup reminder)

**Subject: Don't forget to tear down your Azure Files lab**

Thanks for joining! To avoid ongoing charges, please delete your lab:

```powershell
.\cleanup.ps1 -ResourceGroupName azfiles-lab -IncludeEntra
```

Then, in the Entra portal, remove the Cloud Sync configuration and the
provisioning agent (the script reminds you). That's everything.

[Your name]
