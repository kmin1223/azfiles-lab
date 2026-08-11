<#
.SYNOPSIS
  Build labtools-modules.zip - the prebuilt PowerShell module bundle the lab
  VMs download instead of talking to the PowerShell Gallery.

.DESCRIPTION
  Install-Module is slow: PowerShellGet v2 resolves, downloads and expands each
  module one at a time through the NuGet provider. On a lab VM that is ~9
  minutes for the Az subset plus AzFilesHybrid and its Microsoft.Graph
  dependency, and it sits on the critical path of the deployment.

  This packages the exact same modules once, into one zip. The VM then does a
  single HTTPS GET and a local extract - about a minute.

  Run this ONCE (or after a module version bump), then attach the resulting zip
  to a GitHub release so the VMs can fetch it anonymously:

      gh release create tools-v1 labtools-modules.zip `
          --repo kmin1223/azfiles-lab `
          --title "Lab tooling module bundle" `
          --notes "Prebuilt Az + AzFilesHybrid modules for the Session 1 client VM."

  scripts\07-install-tools.ps1 defaults to the '/releases/latest/download/'
  URL, so re-releasing with the same asset name is all that's needed later.

.NOTES
  Runs anywhere PowerShell can reach the gallery - Cloud Shell is fine. The
  files are plain module folders, so building on Linux and consuming on Windows
  works.

.EXAMPLE
  ./tools/New-LabToolsBundle.ps1
  ./tools/New-LabToolsBundle.ps1 -OutFile ~/labtools-modules.zip -Trim
#>
[CmdletBinding()]
param(
    [string]$OutFile = (Join-Path (Get-Location) 'labtools-modules.zip'),
    [string]$StagingPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'labtools-bundle'),
    # Drop help XML and symbols. Roughly halves the download; Get-Help still
    # works online, and nobody reads local help mid-lab.
    [switch]$Trim
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Keep this list in sync with scripts\07-install-tools.ps1
$seedModules = 'Az.Accounts', 'Az.Storage', 'Az.Resources', 'Az.Network', 'Az.Compute', 'AzFilesHybrid'

if (Test-Path $StagingPath) { Remove-Item $StagingPath -Recurse -Force }
New-Item -ItemType Directory -Path $StagingPath -Force | Out-Null

Write-Host "Staging into $StagingPath" -ForegroundColor Cyan
foreach ($m in $seedModules) {
    Write-Host "  saving $m..."
    Save-Module -Name $m -Path $StagingPath -Force
}

# AzFilesHybrid declares RequiredModules (0.3.3.0 wants Microsoft.Graph.
# Applications on top of the Az modules). If any of them are missing the module
# refuses to load and its cmdlets look like they were never installed - so
# resolve the list from the shipped manifest rather than guessing it.
$psd1 = Get-ChildItem (Join-Path $StagingPath 'AzFilesHybrid') -Filter 'AzFilesHybrid.psd1' -Recurse |
    Select-Object -First 1
if ($psd1) {
    foreach ($r in (Import-PowerShellDataFile $psd1.FullName).RequiredModules) {
        $name = if ($r -is [hashtable]) { $r.ModuleName } else { [string]$r }
        if (-not $name) { continue }
        if (Test-Path (Join-Path $StagingPath $name)) { continue }
        Write-Host "  saving dependency $name..."
        Save-Module -Name $name -Path $StagingPath -Force
    }
} else {
    Write-Warning 'AzFilesHybrid manifest not found - dependency list not verified.'
}

if ($Trim) {
    Write-Host 'Trimming help and symbols...' -ForegroundColor Cyan
    Get-ChildItem $StagingPath -Recurse -Include '*.pdb' -File | Remove-Item -Force
    Get-ChildItem $StagingPath -Recurse -Directory |
        Where-Object { $_.Name -match '^(en-US|en)$' } | Remove-Item -Recurse -Force
}

$modules = Get-ChildItem $StagingPath -Directory
$sizeMb = [math]::Round(((Get-ChildItem $StagingPath -Recurse -File |
    Measure-Object Length -Sum).Sum / 1MB), 1)
Write-Host "Bundling $($modules.Count) modules ($sizeMb MB uncompressed)" -ForegroundColor Cyan
$modules | ForEach-Object { Write-Host "  - $($_.Name)" }

if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
# Zip the module folders at the archive root, so the VM can extract straight
# into $env:ProgramFiles\WindowsPowerShell\Modules.
Compress-Archive -Path (Join-Path $StagingPath '*') -DestinationPath $OutFile -CompressionLevel Optimal

$zipMb = [math]::Round((Get-Item $OutFile).Length / 1MB, 1)
Write-Host ''
Write-Host "Bundle ready: $OutFile ($zipMb MB)" -ForegroundColor Green
Write-Host 'Publish it with:' -ForegroundColor Green
Write-Host "  gh release create tools-v1 '$OutFile' --repo kmin1223/azfiles-lab --title 'Lab tooling module bundle' --notes 'Prebuilt Az + AzFilesHybrid modules.'"
Write-Host ''
Write-Host 'Already released once? Replace the asset instead:' -ForegroundColor Green
Write-Host "  gh release upload tools-v1 '$OutFile' --repo kmin1223/azfiles-lab --clobber"
