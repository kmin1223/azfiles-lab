---
title: "Cloud-only probe — findings"
subtitle: "2026-09-02 · decides the Session 2 participant track"
---

# Verdict: PASS

**A cloud-only Entra user, signed in with a PASSWORD over RDP, obtained a
Kerberos service ticket for Azure Files.** No Windows Hello, no FIDO2, no AD DS,
no Cloud Sync, no hybrid join.

```
Client: clouduser1@<tenant>.onmicrosoft.com @ AzureAD
Server: krbtgt/KERBEROS.MICROSOFTONLINE.COM
        etype Unknown (-1)   Kdc Called: TicketSuppliedAtLogon

Client: clouduser1@<tenant>.onmicrosoft.com @ AzureAD
Server: cifs/<sa>.file.core.windows.net @ KERBEROS.MICROSOFTONLINE.COM
        etype AES-256-CTS-HMAC-SHA1-96   Renew Time: 0
        Kdc Called: KdcProxy:login.microsoftonline.com
```

Corroborating state at that moment:

| Signal | Value |
|---|---|
| `NgcSet` (Windows Hello) | **NO** — no key-based credential existed |
| `AzureAdPrt` | **YES** — a password sign-in produced the PRT |
| `KeySignTest` | PASSED |
| `DeviceAuthStatus` | SUCCESS |
| `DomainJoined` | NO |

The "must sign in with a key-based method (WHfB/FIDO2)" line that blocked this
design does **not** apply to Azure Files Entra Kerberos with a cloud-only user on
an Entra-joined device.

## Why this matters

The ticket signature is **identical to the hybrid one** the workbook already
documents — same realms, same `TicketSuppliedAtLogon`, same `KdcProxy`, same
`Renew Time: 0`. So Lab A's healthy-signature table, the klist concept slide and
the evidence chain all transfer to cloud-only **unchanged**.

---

# Five requirements the probe uncovered

Every one of these fails *silently* or *misleadingly*. All five must be baked
into the participant deployment; four are automatable, one is prework.

| # | Requirement | Symptom when missing |
|---|---|---|
| 1 | **System-assigned managed identity** on the VM | `AADLoginForWindows` installs, reports success, and the Entra join **silently does nothing**. Only symptom: `AzureAdJoined : NO` |
| 2 | **Public IP** (or NAT gateway) | Azure retired default outbound access on 30 Sep 2025. No egress → join impossible. Run Command still works (Azure fabric), so the VM looks healthy |
| 3 | **DNS name label** on the public IP | RDP with an Entra account refuses a bare IP: *"IP addresses are not supported"* |
| 4 | **Primary DNS suffix** on the VM, set *before* the join | The device registers only its short name, so RDP to the Azure FQDN fails with `AADSTS293004: target-device identifier ... not found in the tenant`. Workaround is a hosts-file entry — which needs local admin on the participant's own laptop, so this must be fixed server-side |
| 5 | **MFA registration on the lab account** | Security defaults are on in a new tenant; first sign-in forces Authenticator enrolment. Not automatable → **prework item** |

Also confirmed: **Windows Server 2025 Datacenter (Desktop Experience) works** with
the extension, which avoids the Windows-client licensing constraint on Azure.

## And one that is not a requirement but bit us anyway

`CloudKerberosTicketRetrievalEnabled` needs a **restart** to take effect. Setting
it and then checking `klist cloud_debug` in the same boot reports
`enabled by policy: 0` and sends you hunting for a policy that isn't there.

---

# Lab B+ survives cloud-only after all

The plan assumed Lab B+ ("flags vs ground truth") could only exist on a hybrid
machine. The probe shows otherwise. On the pure Entra-joined VM, before the
restart:

```
dsregcmd:            CloudTgt : YES
                     KerbTopLevelNames : .windows.net, .azure.net, ...
klist cloud_debug:   Cloud Kerberos enabled by policy: 0
                     Cloud Referral TGT present in cache: 0
```

Every cloud-looking flag says yes; the thing that decides routing says no. That
is exactly the lesson, reproducible without any on-prem realm. What is lost is
only the *misrouting to on-prem* half — the reading skill, which is the point,
is intact.

Keep the real Sev A `dsregcmd` / `klist` capture as the paper exercise for the
hybrid variant, and run the live version here.

---

# The mount works too

```
net use Z: \\<sa>.file.core.windows.net\labshare
The command completed successfully.
```

So the chain is complete end to end: password sign-in → PRT → cloud TGT →
service ticket over KDC Proxy → SMB mount. Share-level RBAC
(`Storage File Data SMB Share Contributor`) plus the share's default root ACL is
enough; no ACL surgery was needed to get on the share.

That shrinks the Lab D rework: the **network** door and the **share RBAC** door
behave exactly as they do in the hybrid lab. Only the **NTFS** door changes -
setting a deny for a specific cloud user means `Set-AzStorageFileAcl` with an
Entra SID (`S-1-12-1-…`) instead of `icacls` from a domain-joined client.

---

# Still open

- **RDP client bar.** The connection needs `enablerdsaadauth:i:1` and a recent
  Windows 11 client. Confirm what participants actually have before committing.
- **Entra SID ACLs.** Verify `Get-/Set-AzStorageFileAcl` round-trips a
  `S-1-12-1-…` deny, since that is the only part of Lab D that has to change.
