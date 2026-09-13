function Resolve-CloudOnlyLabPrefix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$ResourceGroupName,
        [AllowNull()] [object]$AzureContext,
        [string]$Prefix
    )

    if ($PSBoundParameters.ContainsKey('Prefix')) {
        if ($Prefix -cnotmatch '^[a-z0-9]{1,24}$') {
            throw 'CLOUD_PREFIX_INVALID: Use 1-24 lowercase letters/digits for an explicit prefix.'
        }
        return $Prefix
    }

    if (-not $AzureContext -or
        [string]::IsNullOrWhiteSpace([string]$AzureContext.Account.Id) -or
        [string]$AzureContext.Account.Type -notin @('User', 'ManagedService')) {
        throw 'CLOUD_PREFIX_IDENTITY_REQUIRED: Automatic naming needs an Azure User context or a Cloud Shell ManagedService context. Check Get-AzContext, or supply the recorded -Prefix for an existing lab.'
    }

    $tenantId = [guid]::Empty
    $subscriptionId = [guid]::Empty
    if (-not [guid]::TryParse([string]$AzureContext.Tenant.Id, [ref]$tenantId) -or
        $tenantId -eq [guid]::Empty -or
        -not [guid]::TryParse([string]$AzureContext.Subscription.Id, [ref]$subscriptionId) -or
        $subscriptionId -eq [guid]::Empty -or
        [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        throw 'CLOUD_PREFIX_CONTEXT_INVALID: Automatic naming needs a valid tenant, subscription and resource group. Check Get-AzContext before continuing.'
    }

    $accountName = ([string]$AzureContext.Account.Id).Trim().ToLowerInvariant()
    if ([string]$AzureContext.Account.Type -ieq 'ManagedService') {
        # Cloud Shell reports MSI@50342, not a participant ID. Use a naming label,
        # not an authentication identity, from pwd; nested folders do not matter.
        if ((Get-Location).Path -cnotmatch '^/home/([^/]+)(?:/|$)') {
            throw 'CLOUD_PREFIX_HOME_REQUIRED: Run from /home/<name> or a folder beneath it in Cloud Shell, or supply the recorded -Prefix for an existing lab.'
        }
        $accountName = $Matches[1].ToLowerInvariant()
    }

    $identity = @(
        $tenantId.ToString('D')
        $accountName
        $subscriptionId.ToString('D')
        $ResourceGroupName.Trim().ToLowerInvariant()
    ) -join '|'
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity)))
    } finally {
        $sha.Dispose()
    }
    # Eleven characters leave room for "-cli" in the Windows computer name.
    'azf' + $hash.Replace('-', '').Substring(0, 8).ToLowerInvariant()
}
