# Manual Step: Microsoft Entra Connect Sync (hybrid identities)

**Presenter demo - Hybrid: presenter-only prework.** Participants use
`session2-cloudonly/deploy.ps1`; they do not need AD DS or directory sync.
Keep that cloud-only environment and its identities separate.

Complete this guide **before** `setup.ps1`, not while participants wait:

**Session 1 base -> Connect Sync users/password hash synchronization (PHS) and
computer scope -> Connect wizard device options/SCP -> healthy hybrid join and
user PRT -> storage/client setup -> fresh user logon and working SMB baseline.**

Use a disposable presenter tenant and a dedicated Session 1 deployment. Switching
its storage account to AADKERB replaces AD DS authentication. This is the
Connect Sync hybrid path; no Cloud Sync device preview, device writeback,
federation, Intune enrollment, or Windows Hello cloud-trust deployment is needed.

## 1. Choose and verify the Connect host

The checked-in `session1-adds/template/azuredeploy.json` specifies
`MicrosoftWindowsServer/WindowsServer/2022-datacenter-azure-edition` for the DC,
not Server 2016/2019. Do not infer the actual VM's OS from an old lab screenshot.
On the proposed host, in elevated Windows PowerShell:

```powershell
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
    Select-Object ProductName, InstallationType
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, PartOfDomain
```

[Current Learn prerequisites](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)
recommend **Windows Server 2022 or 2025**, domain joined, Standard or better,
with **full GUI/Desktop Experience**; Server Core is not supported. The template's
Server 2022 edition is not an OS-version blocker, but check actual installation,
updates, resources, TLS 1.2 and .NET prerequisites before installing. Prefer .NET
Framework 4.8 on a fully patched host. Use the latest supported Connect release
from the Entra admin center, not an old cached MSI. Learn currently warns that
versions below **2.5.79.0 stop synchronizing September 30, 2026**; that is a floor,
not a recommendation to install an old version.

**Recommended:** a dedicated, domain-joined Server 2022/2025 member server with
Desktop Experience, on the lab network using the DC for DNS, with at least
4 GB RAM and 70 GB disk for this small lab. Connect holds privileged identity
data: treat it as Tier 0 and restrict access. Reusing this disposable Server 2022
DC is a lab consolidation choice only, subject to the same prerequisite checks
and installer requirements; it is not the recommended production topology.
If the existing host is unsupported, Core, undersized or otherwise unsuitable,
prepare a supported dedicated member server before continuing. **No script here
deploys a new VM.** Record any separately provisioned host for cleanup.

Allow Connect-to-DC traffic and outbound HTTPS required by the prerequisites.
Clients must resolve/reach `login.microsoftonline.com`,
`enterpriseregistration.windows.net` and `device.login.microsoftonline.com`
in **SYSTEM/machine context**. Do not TLS-intercept device registration endpoints.
If public DNS fails, check the lab DC forwarder (`168.63.129.16`); DNS success
alone does not prove HTTPS/proxy connectivity.

### Required rights

| Task | Rights |
| --- | --- |
| Install/configure Connect | Local administrator on Connect host; directly assigned Entra **Hybrid Identity Administrator** in the intended tenant |
| Create AD connector account/PHS permissions | AD **Enterprise Admin** supplied interactively to the wizard to create its least-privilege connector account; do not use an Enterprise/Domain Admin as the ongoing connector account |
| Configure forest SCP | AD **Enterprise Admin** for `contoso.local`, supplied to the device-options wizard |
| Set lab UPN suffix/users | AD rights to update forest UPN suffixes and the two users (the isolated lab forest administrator suffices) |
| Run `setup.ps1` later | Azure rights to update storage and execute client VM Run Command; Entra admin consent rights for delegated Microsoft Graph permissions (use the disposable tenant's Global Administrator for this lab step) |

The lab does not require Connect Health: do not add Global Administrator just
to install that optional agent. Use separate cloud administrator and synchronized
lab-user accounts; never assign directory administrator roles to the lab users.

## 2. Resolve old sync configurations and identity collisions FIRST

For a fresh deployment, verify there is no existing active Connect exporter or
Cloud Sync configuration targeting these objects. There must be **one writer**
for the lab users and computer. A second active Connect server for the same
tenant is not this lab's topology.

If reusing the previous Cloud Sync lab, **do not install an exporting Connect
configuration over the same objects**:

1. Inventory the old configuration's scopes, tenant, synchronized user object IDs,
   UPNs, `onPremisesImmutableId`, AD source anchors and the existing device ID.
   Preserve this record and the old config for rollback. Use a clean, separate
   presenter tenant instead if you cannot establish ownership/matching safely.
2. Stop/disable the old **lab** Cloud Sync provisioning configuration in Entra
   and wait until no cycle is running, **before** enabling any Connect export.
   Do not merely stop one agent when another agent can continue provisioning.
   Do not change scope or delete source users to stop sync: that can export
   deletions. Do not disable tenant-wide synchronization in a shared tenant.
3. Configure Connect initially in **staging mode** for a takeover. Check the
   existing source anchor and imported cloud identity mapping in Synchronization
   Service Manager; preview the pending exports. The same users must retain the
   same cloud object IDs. Stop on duplicate/add/delete surprises or anchor
   conflicts; do not clear ImmutableId, force soft/hard matching, disable tenant
   takeover protections, or delete cloud identities to get a green run.
4. Only after verifying matching and the old writer is stopped, use Connect
   **Configure -> Configure staging mode** to leave staging mode and enable
   export/PHS. Recheck object IDs, sync errors and PHS. Keep the old writer
   disabled. If rolling back, stop Connect exports first; never enable both.
   Uninstall the old provisioning agent only after verifying it serves no other
   configuration. Existing device registration also needs the checks below.

This is a guarded lab transition, not a general-purpose identity migration
procedure. Prefer a clean presenter tenant over repairing unknown identity
history. [Supported topologies](https://learn.microsoft.com/entra/identity/hybrid/cloud-sync/plan-cloud-sync-topologies)
and [Connect staging/preview guidance](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-staging-server)
describe the boundaries.

### Use verified, distinct UPNs

The AD domain remains `contoso.local`; **do not rename the forest**. Its suffix
cannot be verified in Entra. Before first export, add a suffix that is verified
in the intended tenant (a verified custom domain or its initial
`<tenant>.onmicrosoft.com` domain). Use `userPrincipalName`, not an alternate
sign-in attribute or implicit `.local` rewriting.

The participant deployment creates `labuser1@<tenant>.onmicrosoft.com` and
`labuser2@<tenant>.onmicrosoft.com`. Do not let Connect take these cloud-only
accounts over. The examples below use **hybrid-labuser1** and
**hybrid-labuser2** as UPN local parts while preserving AD sAMAccountNames
`labuser1`/`labuser2` and SIDs/ACLs. First verify these proposed UPNs, mail and
proxy addresses do not match any existing cloud-only or deleted user; also
check the two AD users' current mail/proxy addresses. Use another unused UPN
pair or a separate tenant if needed. Do not silently reuse a match.

In Entra admin center, check **Domain names**, **Users** and **Deleted users**.
For a previous synchronized lab, keep the established verified UPNs/anchors
unless an explicit migration plan calls for changing them; do not blindly run
the fresh-lab update below.

```powershell
# DC, elevated, NEW lab only; replace with a domain VERIFIED in your tenant.
Import-Module ActiveDirectory
$suffix = '<tenant>.onmicrosoft.com'
if ($suffix -match '[<>]') { throw 'Set the verified tenant suffix first.' }
Get-ADUser labuser1 -Properties userPrincipalName,mail,proxyAddresses
Get-ADUser labuser2 -Properties userPrincipalName,mail,proxyAddresses
$forest = Get-ADForest
if ($forest.UPNSuffixes -notcontains $suffix) {
    Set-ADForest -Identity $forest.Name -UPNSuffixes @{ Add = $suffix }
}
Set-ADUser labuser1 -UserPrincipalName "hybrid-labuser1@$suffix"
Set-ADUser labuser2 -UserPrincipalName "hybrid-labuser2@$suffix"
Get-ADUser -SearchBase 'OU=AzureFilesLab,DC=contoso,DC=local' -Filter * `
    -Properties userPrincipalName | Select-Object SamAccountName,UserPrincipalName
Get-ADComputer azflab-cli -Properties DistinguishedName,ObjectGUID
```

For a nondefault prefix, replace `azflab-cli` with `<prefix>-cli` throughout.
If the computer has moved, use its actual distinguished name in sync scope.

## 3. Install and scope Connect Sync (not Express settings)

On the selected host, launch the current **Microsoft Entra Connect** installer
downloaded from **Entra ID -> Entra Connect -> Connect Sync**, as administrator.
Use [custom installation](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-custom):

1. Choose **Customize** (not Express, which would synchronize the entire forest).
   Default local SQL Express is sufficient for this small lab.
2. **User sign-in:** select **Password Hash Synchronization**. Leave Seamless SSO
   unchecked; PHS is sufficient here. No AD FS/PTA infrastructure is needed.
3. **Connect to Microsoft Entra ID:** sign in interactively as the intended
   tenant's Hybrid Identity Administrator. **Connect your directories:** add
   `contoso.local`; let the wizard create its connector account using the
   temporary Enterprise Admin credentials.
4. **Microsoft Entra sign-in configuration:** keep `userPrincipalName`; ensure
   the lab users' actual suffix is **Verified**. The forest's unused `.local`
   suffix can remain unverified, but neither lab user should still use it.
5. **Domain and OU filtering:** choose selected domains/OUs/containers, not
   the whole domain. Include **both** rows below. Exclude Domain Controllers
   and unrelated OUs/containers. Inspect the contents before enabling export.
6. Keep normal single-forest identity/source-anchor defaults for a **new** lab.
   For a takeover, retain and verify the existing source anchor as described
   above. Do not add group-based pilot filtering on top of this OU scope.
7. **Optional features:** PHS enabled; no device/password/group writeback,
   Exchange hybrid deployment or directory extension filtering needed. Keep
   default device attribute flows, including `userCertificate`.
8. Review the configuration. For a clean new lab, start synchronization when
   configuration completes. For a takeover, stay in staging mode until step 2's
   review is complete. Staging mode does **not** export or synchronize passwords.

| Include | Exact distinguished name with default lab settings |
| --- | --- |
| Lab users OU | `OU=AzureFilesLab,DC=contoso,DC=local` |
| Client computer container | `CN=Computers,DC=contoso,DC=local` |
| Client object within that container | `CN=azflab-cli,CN=Computers,DC=contoso,DC=local` |

**Computers is a container (`CN`), not `OU=Computers`.** Selecting only
AzureFilesLab omits the client. Selecting Computers includes its contents;
it is safe only for this isolated lab. If it holds unrelated devices, use an
approved dedicated OU and update the scope deliberately rather than syncing
them all. The storage AD computer in AzureFilesLab is not the hybrid client.

Use **Configure -> Customize synchronization options** to correct OU scope.
In Synchronization Service Manager, review imports/synchronization/exports for
errors; do not assume a running service means the users were exported.

## 4. Let the Connect wizard configure hybrid join and SCP

On the Connect server, follow the
[managed-domain wizard](https://learn.microsoft.com/entra/identity/devices/how-to-hybrid-join):

1. Open **Microsoft Entra Connect -> Configure -> Configure device options**.
2. Continue through Overview and sign in as Hybrid Identity Administrator.
3. Choose **Configure Microsoft Entra hybrid join** (not device writeback).
4. Select the Windows 10 or later domain-joined device option for the lab client.
5. In **SCP configuration**, select forest `contoso.local`, select
   **Microsoft Entra ID** as Authentication Service, and **Add** the forest
   Enterprise Admin credentials.
6. Select **Configure**, then **Exit** when configuration finishes.

The SCP belongs to the wizard. `setup.ps1` never creates, deletes or replaces
it; `scripts/create-scp.ps1` now refuses to mutate AD. SCP is forest-wide, so
use an isolated lab forest, not a production forest. Read-only verification on DC:

```powershell
$config = (Get-ADRootDSE).configurationNamingContext
Get-ADObject `
  -Identity "CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,$config" `
  -Properties keywords | Select-Object -ExpandProperty keywords
```

Expect `azureADId:<intended-tenant-guid>` and `azureADName:<verified-domain>`.
The tenant must match the subscription used by `setup.ps1`. If wrong, correct
the wizard configuration, not the SCP with a hand-written overwrite.

## 5. Complete the registration cycle BEFORE storage setup

In a managed domain, the first client registration attempt discovers SCP and
writes a self-signed certificate to its AD computer's **userCertificate**.
Connect then syncs the computer GUID/SID/certificate, and the client retries
registration. **An initial join attempt can precede successful device export.**
Do not wait forever for a device object before ever starting the client task.

From an elevated client PowerShell, with the script copied to the client:

```powershell
.\client-config.ps1 -Mode InitializeRegistration -ExpectedTenantId '<tenant-guid>'
```

This starts the built-in **Automatic-Device-Join** scheduled task in SYSTEM
context; it makes no Kerberos policy/tool changes and does not reboot. It reports
`CLIENT_REGISTRATION_STARTED_NOT_READY`, not success. Alternatively start the
same task in Task Scheduler under Microsoft -> Windows -> Workplace Join.
Do not run a second simultaneous `dsregcmd /join` alongside it.

On the DC, confirm the task wrote the certificate:

```powershell
Get-ADComputer azflab-cli -Properties userCertificate |
    Select-Object Name,@{n='CertificateCount';e={@($_.userCertificate).Count}}
```

Then on the **Connect server**, elevated Windows PowerShell (not Cloud Shell/DC
unless that is your Connect host):

```powershell
Import-Module ADSync
Get-ADSyncScheduler | Select-Object SyncCycleEnabled,StagingModeEnabled,NextSyncCycleStartTimeInUTC
Start-ADSyncSyncCycle -PolicyType Delta
```

Wait for the run and export to finish in Synchronization Service Manager.
The usual scheduler interval is 30 minutes; a delta request is asynchronous,
not proof of export, and PHS has its own processing. After changing OU filters,
allow the wizard's full synchronization (or an **Initial** cycle), not just Delta.

Retry the client InitializeRegistration task after export (or wait for its
scheduled retry), then use:

```powershell
.\client-config.ps1 -Mode Check -ExpectedTenantId '<tenant-guid>'
dsregcmd /status
```

Require **DomainJoined: YES**, **AzureAdJoined: YES**, **DeviceAuthStatus:
SUCCESS**, and the expected **TenantId**. Check mode is read-only and fails
until those device checks pass. In Entra **Devices**, require the matching
device to be Microsoft Entra hybrid joined with registration completed.
Match the local `dsregcmd` DeviceId, not only display name.

**Pending is not Microsoft Entra registered and not healthy hybrid join.**
It means a device was synced but has not finished registration; it cannot yet
obtain a PRT. An initial `error_missing_device` / `0x801c03f3` can be the
pre-export window, but a persistent error is not expected success.

Verify both users in Entra **Users** by their exact chosen UPNs:
**On-premises sync enabled = Yes**, correct on-premises SID and no unexpected
duplicate or takeover. Test cloud sign-in with each AD password to establish
PHS, then sign out of the client and back in with the synchronized domain user.
In **that user's normal non-elevated shell**, require `AzureAdPrt: YES` from
`dsregcmd /status`. Run Command/SYSTEM cannot prove the user's PRT. If RDP
authentication mode prevents token issuance, diagnose that sign-in path before
the demo; do not count an admin/SYSTEM session as the lab user's baseline.

## 6. Configure storage/client, then rehearse fresh-logon access

Only after the device, synchronized users/PHS and user PRT gates above, run
from the repo root in **Cloud Shell PowerShell**, in the intended subscription:

```powershell
./session2-entra-kerberos/setup.ps1 -ResourceGroupName azfiles-lab -Prefix azflab
```

It checks client hybrid join/tenant **before** changing storage, enables AADKERB,
grants storage-app consent, applies the client cloud Kerberos policy and reboots.
It does not configure Connect or repair SCP. No fault injection is part of setup.

After reboot, sign in afresh as `CONTOSO\labuser1` (its configured, synced UPN
is the cloud identity). In the **same non-elevated user session**:

```powershell
dsregcmd /status
klist cloud_debug
klist
# Substitute the actual storage account name.
klist get cifs/<storage>.file.core.windows.net
net use Z: \\<storage>.file.core.windows.net\labshare
Get-ChildItem Z:\
```

Require device health, PRT, effective cloud Kerberos retrieval policy, a cloud
TGT, a newly retrieved CIFS ticket and successful share access. Remove only
known lab SMB connections if old Session 1 connections obscure the result.
Do not call `setup.ps1`'s configuration message the completed baseline.
Rehearse healthy access and recovery before presenting any hybrid fault.

## Troubleshooting and cleanup

| Symptom | Check before retrying |
| --- | --- |
| Users missing/wrong sign-in | Exact verified UPN; OU scope; duplicate/matching errors in Synchronization Service Manager; active exporter, PHS and AD connector replication permissions |
| No computer export | Include `CN=Computers`; verify `userCertificate` after the client task; retain default device attribute flows; examine sync/export errors |
| Pending / `0x801c03f3` persists | Confirm certificate export completed and retry task; inspect **User Device Registration/Admin** events, intended SCP tenant, SYSTEM DNS/HTTPS/proxy access; do not report setup complete |
| DeviceAuthStatus not SUCCESS | Check that the correct cloud device exists and is enabled; investigate deleted/recreated device history, not automatic SCP replacement |
| Device joined but no PRT | Fresh password logon as the exact synced user, PHS, verified UPN, authentication/Conditional Access failures and RDP sign-in context |
| PRT present but SMB fails | Effective Kerberos policy, new cloud/CIFS tickets, storage-app consent, share-level access and NTFS ACLs; do not change sync architecture to fix an ACL |

For devices deleted/recreated by scope changes, follow
[Microsoft's pending-device recovery](https://learn.microsoft.com/troubleshoot/azure/active-directory/pending-devices);
`dsregcmd /leave` is a targeted recovery action, **not** routine setup.

### Retire synchronization BEFORE resource deletion

Resource-group deletion alone does **not** remove tenant synchronization
configuration or synchronized objects. Complete this checklist while the DC
and Connect server are still running and reachable:

1. Inventory the exact lab user and device object IDs, AD objects, sync scopes,
   connector/service accounts, consent grants and Connect host. Confirm which
   resources are exclusively lab-owned. Keep any retired Cloud Sync job disabled.
   Review and stop automatic scheduling on a **dedicated lab** Connect server
   while making the controlled cleanup changes; do not stop a shared sync service.
2. Remove **only the lab users and computers** from the AD synchronization
   scope or delete their lab-only AD source objects. Do not exclude a container
   containing unrelated objects. Review the resulting pending deletion exports
   in Synchronization Service Manager before exporting. Keep Connect and the DC
   available: run the required controlled synchronization/export after the
   change (full/Initial synchronization for a scope change; Delta for source
   deletions). Stopping the scheduler does not replace these deletion exports.
3. Wait for the deletion exports to finish and verify the intended cloud user
   and device deletions by the recorded IDs. Resolve export errors or deletion
   threshold alerts through ownership review; do not bypass safeguards to
   proceed. Only then retire the lab-only Connect configuration/server and
   ensure it cannot resume provisioning. If a host serves other workloads,
   retire only this lab's approved scope with its owner, not the shared service.
4. Confirm the checklist before passing `-ConnectSyncRetired` below. The switch
   is an operator attestation, not an instruction to stop sync or a replacement
   for checking deletion exports. Do **not** disable tenant-wide DirSync or
   delete shared users/SCP as generic cleanup. Remove a forest-wide SCP only
   when retiring the isolated lab forest, with no remaining dependent devices.

After the checklist, from the repository root in PowerShell, replacing the
resource-group and prefix placeholders with the actual lab values:

```powershell
.\cleanup.ps1 -ResourceGroupName '<rg>' -Prefix '<prefix>' -IncludeEntra -ConnectSyncRetired
```

For Cloud Shell PowerShell, use `./cleanup.ps1` with the same arguments.
The `-IncludeEntra` path requires `-ConnectSyncRetired` **before any resource-group
or resource deletion**. Do not pass it merely to bypass the gate. A separately
provisioned Connect host **outside the lab resource group must be retired and
removed manually**; the resource-group cleanup cannot remove it. See root
`cleanup.ps1` and the presenter cleanup instructions for the remaining teardown.

## Official references

- [Connect prerequisites](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)
- [Custom installation and exact wizard pages](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-custom)
- [Accounts and permissions](https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions)
- [Configure Microsoft Entra hybrid join](https://learn.microsoft.com/entra/identity/devices/how-to-hybrid-join)
- [Managed-domain registration sequence](https://learn.microsoft.com/entra/identity/devices/device-registration-how-it-works#hybrid-azure-ad-joined-in-managed-environments)
- [Pending devices](https://learn.microsoft.com/troubleshoot/azure/active-directory/pending-devices)
- [Connect scheduler](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler)
