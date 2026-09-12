# Retained to fail safely for old command sheets. The Connect wizard owns SCP.
param(
    [string]$TenantId,
    [string]$TenantDomain
)
$ErrorActionPreference = 'Stop'
throw 'Manual SCP creation is retired. In Microsoft Entra Connect: Configure -> Configure device options -> Configure Microsoft Entra hybrid join -> SCP configuration. See MANUAL-STEP-connect-sync.md. No AD objects were changed.'
