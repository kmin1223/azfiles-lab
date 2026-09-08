# Manual evidence collection restored

The experimental automatic collector has been rolled back. The collector in
`scripts/07-install-tools.ps1` is restored to pre-automation commit `7c2a8d5`.
New deployments do not install scheduled tasks, credential-created workers or
stored evidence credentials.

## Fresh deployment

Use the updated repository's normal `deploy.ps1` flow. Its client tooling step
installs the manual collector. No existing-VM replacement or migration tool is
provided. Do not run the removed `Update-LabEvidenceAutomation.ps1`.

The source rollback does not modify any existing VM or delete evidence.
Before deleting an old resource group, copy any evidence you need from
`C:\ProgramData\AzureFilesLabEvidence\Runs` and `C:\LabTools\evidence`.

## Two windows, three steps

Start in an elevated PowerShell window on the client:

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -StartTrace
```

Reproduce in the affected user's **normal** PowerShell window. Replace
`<storage-account>` with the actual name:

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -Reproduce -StorageAccount <storage-account> -Share labshare
```

Return to the **original elevated window**:

```powershell
C:\LabTools\Get-KerberosEvidence.ps1 -StopTrace
```

The baseline has no `-Manual` parameter and does not create a new user logon.
Results are saved in `C:\LabTools\evidence\<timestamp>`. The original collector's
mapping-reset behavior is restored: use the disposable lab context, not a
production session with unrelated mappings. Purging tickets does not by itself
prove that an established SMB session was closed. Label cached-session evidence
honestly. DC events demonstrate issuance, not Azure Files acceptance.

The normal tooling step downloads `etl2pcapng.exe` to `C:\LabTools` when
available; otherwise retain the ETL.

## Presentation materials

Slides, presenter cards and cue sheets have been preserved, not rewritten.
Their recently added one-command/UAC-worker instructions describe the removed
experimental workflow. For live collection use the three commands above until
those materials are revised. Generated `Get-LabCommands.ps1` sheets use the
restored manual workflow and retain the requested private VM-password section.
