<#
.SYNOPSIS
  Connect to Microsoft Graph from Azure Cloud Shell without a device code.

.DESCRIPTION
  Cloud Shell signs you in to Azure, but NOT to Microsoft Graph - they are
  separate token audiences. Left alone, Connect-MgGraph falls back to the device
  code flow (Cloud Shell has no browser) and gives you 120 seconds to open
  microsoft.com/devicelogin before it aborts with:

      Authentication timed out after 120 seconds due to inactivity.

  In a timed lab that is a reliable way to lose people - and the worst place for
  it to happen is the capstone, where the fault script needs Graph in front of
  the whole room.

  So: mint a Graph token from the Azure context you ALREADY have. No browser, no
  code, no timeout. Device code remains the fallback for tenants where the Azure
  PowerShell client app has not been consented the directory scopes we need.

  Dot-source this file, then call Connect-LabGraph.

.EXAMPLE
  . (Join-Path $PSScriptRoot 'scripts/Connect-LabGraph.ps1')
  Connect-LabGraph -Scopes 'Application.Read.All','DelegatedPermissionGrant.ReadWrite.All'
#>

function Connect-LabGraph {
    [CmdletBinding()]
    param(
        # Only used by the device-code fallback; the token path carries whatever
        # the Azure PowerShell client app was already consented.
        [string[]]$Scopes = @('Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All')
    )

    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Write-Host '  Graph: already connected.' -ForegroundColor DarkGray
        return
    }

    $reused = $false
    try {
        $p = @{ ResourceUrl = 'https://graph.microsoft.com'; ErrorAction = 'Stop' }
        # Az 14+ returns a SecureString and warns unless you ask for it explicitly.
        if ((Get-Command Get-AzAccessToken).Parameters.ContainsKey('AsSecureString')) {
            $p['AsSecureString'] = $true
        }
        $tok = Get-AzAccessToken @p
        $secure = if ($tok.Token -is [System.Security.SecureString]) {
            $tok.Token
        } else {
            ConvertTo-SecureString $tok.Token -AsPlainText -Force
        }
        # Graph SDK v2 wants a SecureString; v1 wants a plain string.
        if ((Get-Command Connect-MgGraph).Parameters['AccessToken'].ParameterType -eq [System.Security.SecureString]) {
            Connect-MgGraph -AccessToken $secure -NoWelcome -ErrorAction Stop
        } else {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
            Connect-MgGraph -AccessToken $plain -NoWelcome -ErrorAction Stop
        }
        # Prove the token actually carries directory read, rather than
        # discovering it three cmdlets later as a confusing 403.
        Get-MgOrganization -ErrorAction Stop | Out-Null
        $reused = $true
        Write-Host '  Graph: reused your Cloud Shell sign-in (no device code needed).' -ForegroundColor DarkGray
    } catch {
        Write-Host "  Graph: could not reuse the Azure token ($($_.Exception.Message.Split("`n")[0]))." -ForegroundColor DarkYellow
    }

    if (-not $reused) {
        Write-Host ''
        Write-Host '  Falling back to device code sign-in.' -ForegroundColor Yellow
        Write-Host '  Open https://microsoft.com/devicelogin in a browser NOW and enter the code below.' -ForegroundColor Yellow
        Write-Host '  You get about 2 minutes. If it times out, just run this script again -' -ForegroundColor Yellow
        Write-Host '  everything already done is detected and skipped.' -ForegroundColor Yellow
        Write-Host ''
        Connect-MgGraph -Scopes $Scopes -NoWelcome
    }
}

# The lab storage account, excluding the SECOND account that Test-Coexistence
# creates ("<prefix>ads..."). Both match "<prefix>*", and the order Azure
# returns them in is not guaranteed - so a plain -First 1 can silently point the
# whole script at the wrong account. Get-LabCommands.ps1 already learned this.
function Get-LabStorageAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ResourceGroupName,
        [string]$Prefix = 'azflab'
    )
    Get-AzStorageAccount -ResourceGroupName $ResourceGroupName |
        Where-Object { $_.StorageAccountName -like "$Prefix*" -and
                       $_.StorageAccountName -notlike "${Prefix}ads*" } |
        Select-Object -First 1
}
