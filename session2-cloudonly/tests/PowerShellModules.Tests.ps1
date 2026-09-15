$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$clientPath = Join-Path $root 'scripts\client-config.ps1'
$tokens = $null
$errors = $null
$clientAst = [Management.Automation.Language.Parser]::ParseFile($clientPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($definition in $clientAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst]
}) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$validationScript = [scriptblock]::Create((Get-LabModuleValidationScript))
$galleryScript = [scriptblock]::Create((Get-LabModuleGalleryScript))

# Never bootstrap a provider, change repositories, download a module or import
# real Az/Graph modules on the test host, even if a mock is accidentally omitted.
function Install-PackageProvider {
    [CmdletBinding()] param($Name, $MinimumVersion, $Scope, [switch]$Force)
    throw 'Unmocked provider installation'
}
function Get-PSRepository { [CmdletBinding()] param($Name) throw 'Unmocked repository lookup' }
function Register-PSRepository { [CmdletBinding()] param([switch]$Default) throw 'Unmocked repository registration' }
function Set-PSRepository { [CmdletBinding()] param($Name, $InstallationPolicy) throw 'Unmocked repository change' }
function Save-Module {
    [CmdletBinding()] param($Name, $Path, $Repository, $MinimumVersion, [switch]$Force, [switch]$AcceptLicense)
    throw 'Unmocked module download'
}

function New-ModuleTestReport {
    param([string]$ModulePath)
    $versions = [ordered]@{
        'Az.Accounts' = '4.0.1'; 'Az.Storage' = '8.1.0'; 'Az.Resources' = '7.8.0'
        'Az.Network' = '7.12.0'; 'Az.Compute' = '9.0.1'; 'AzFilesHybrid' = '0.3.3.0'
    }
    [pscustomobject]@{
        PowerShellVersion = '5.1'
        ModulePath = $ModulePath
        Modules = @(
            foreach ($name in $versions.Keys) {
                [pscustomobject]@{ Name = $name; Version = $versions[$name]; Path = "$ModulePath\$name\$($versions[$name])\$name.psd1" }
            }
        )
        Commands = @('Connect-AzAccount', 'Get-AzStorageAccount', 'Debug-AzStorageAccountAuth')
    }
}

Describe 'AllUsers module provisioning and fallback orchestration (offline)' {
    BeforeEach {
        $script:moduleTools = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:moduleTools | Out-Null
        $script:allUsersPath = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
        $script:installedValid = $false
        $script:existingFailure = 'LAB_MODULE_MISSING'
        $script:moduleSource = ''
        $script:bundleFailure = ''
        $script:galleryFailure = ''
        $script:postCopyFailure = $false
        $script:moduleEvents = @()
        $script:publishedReport = $null
        Mock Write-Output {}
        Mock Write-Warning {}
        Mock Save-LabToolDownload {
            $script:moduleEvents += 'download'
            if ($script:bundleFailure -eq 'download') { throw 'bundle network failure' }
            Set-Content -LiteralPath $Path -Value 'offline zip fixture'
        }
        Mock Expand-LabModuleBundle {
            $script:moduleEvents += 'extract'
            if ($script:bundleFailure -eq 'corrupt') { throw 'corrupt archive' }
            $script:moduleSource = 'bundle'
        }
        Mock Invoke-LabModuleWorker {
            $script:moduleEvents += 'gallery'
            $script:moduleSource = 'gallery'
            if ($script:galleryFailure -eq 'download') { throw 'gallery download failure' }
        }
        Mock Test-LabPowerShellModules {
            if ($ModulePath -eq $script:allUsersPath) {
                $script:moduleEvents += 'verify-installed'
                if (-not $script:installedValid) { throw $script:existingFailure }
                if ($script:postCopyFailure) { throw 'post-copy import failed' }
            } else {
                $script:moduleEvents += 'verify-stage'
                if ($script:moduleSource -eq 'bundle' -and $script:bundleFailure -in @('old', 'import')) {
                    throw "bundle $script:bundleFailure"
                }
                if ($script:moduleSource -eq 'gallery' -and $script:galleryFailure -eq 'import') {
                    throw 'gallery import failed'
                }
            }
            New-ModuleTestReport -ModulePath $ModulePath
        }
        Mock Publish-LabPowerShellModules {
            $script:moduleEvents += 'publish'
            $script:installedValid = $true
        }
        Mock Write-LabModuleReport {
            $script:moduleEvents += 'report'
            $script:publishedReport = $Report
        }
    }

    It 'reuses already importable AllUsers modules without downloads or provider changes' {
        $script:installedValid = $true
        Install-LabPowerShellModules -ToolsDirectory $script:moduleTools
        ($script:moduleEvents -join ',') | Should Be 'verify-installed,report'
        $script:publishedReport.ModulePath | Should Be $script:allUsersPath
        Assert-MockCalled Save-LabToolDownload -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-LabModuleWorker -Times 0 -Exactly -Scope It
    }

    It 'validates bundle staging then AllUsers imports before reporting success' {
        Install-LabPowerShellModules -ToolsDirectory $script:moduleTools
        ($script:moduleEvents -join ',') |
            Should Be 'verify-installed,download,extract,verify-stage,publish,verify-installed,report'
        Assert-MockCalled Save-LabToolDownload -Times 1 -Exactly -Scope It -ParameterFilter {
            $Uri -eq 'https://github.com/kmin1223/azfiles-lab/releases/latest/download/labtools-modules.zip'
        }
        Assert-MockCalled Publish-LabPowerShellModules -Times 1 -Exactly -Scope It -ParameterFilter {
            $ModulePath -eq (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') -and
            $Source -like "$script:moduleTools\module-stage-*"
        }
        @(Get-ChildItem -LiteralPath $script:moduleTools -Filter 'module-stage-*').Count | Should Be 0
    }

    It 'repairs an old or broken installed module set instead of treating presence as success: <Failure>' -TestCases @(
        @{ Failure = 'LAB_MODULE_TOO_OLD' }, @{ Failure = 'dependency import failed' }
    ) {
        param($Failure)
        $script:existingFailure = $Failure
        Install-LabPowerShellModules -ToolsDirectory $script:moduleTools
        Assert-MockCalled Publish-LabPowerShellModules -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like 'Existing AllUsers module validation failed*'
        }
    }

    It 'uses an explicit Gallery fallback for a rejected bundle: <Failure>' -TestCases @(
        @{ Failure = 'download' }, @{ Failure = 'corrupt' }, @{ Failure = 'old' }, @{ Failure = 'import' }
    ) {
        param($Failure)
        $script:bundleFailure = $Failure
        Install-LabPowerShellModules -ToolsDirectory $script:moduleTools
        Assert-MockCalled Invoke-LabModuleWorker -Times 1 -Exactly -Scope It -ParameterFilter {
            $Script -eq (Get-LabModuleGalleryScript) -and $Parameters.ModulePath -like "$script:moduleTools\module-stage-*"
        }
        Assert-MockCalled Publish-LabPowerShellModules -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter { $Message -like 'Using PSGallery fallback*' }
        $script:publishedReport.ModulePath | Should Be $script:allUsersPath
    }

    It 'does not report success if fallback download or import fails: <Failure>' -TestCases @(
        @{ Failure = 'download' }, @{ Failure = 'import' }
    ) {
        param($Failure)
        $script:bundleFailure = 'corrupt'
        $script:galleryFailure = $Failure
        { Install-LabPowerShellModules -ToolsDirectory $script:moduleTools } | Should Throw 'LAB_MODULES_UNAVAILABLE'
        Assert-MockCalled Write-LabModuleReport -Times 0 -Exactly -Scope It
        Assert-MockCalled Publish-LabPowerShellModules -Times 0 -Exactly -Scope It
        @(Get-ChildItem -LiteralPath $script:moduleTools -Filter 'module-stage-*').Count | Should Be 0
    }

    It 'fails if staged modules work but installed imports still fail' {
        $script:postCopyFailure = $true
        { Install-LabPowerShellModules -ToolsDirectory $script:moduleTools } | Should Throw 'post-copy import failed'
        Assert-MockCalled Write-LabModuleReport -Times 0 -Exactly -Scope It
    }

    It 'supports deliberately disabling the bundle without pretending it worked' {
        Install-LabPowerShellModules -ToolsDirectory $script:moduleTools -ModuleBundleUri ''
        Assert-MockCalled Save-LabToolDownload -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-LabModuleWorker -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter { $Message -like 'Module bundle explicitly disabled*' }
    }
}

Describe 'Module import and exported-command validation script (offline)' {
    # Pester 3's proxy for the native Get-Module exposes a PSEdition parameter,
    # which collides with the read-only automatic variable on modern shells.
    function Get-Module {
        [CmdletBinding()] param($Name, [switch]$ListAvailable)
        Microsoft.PowerShell.Core\Get-Module @PSBoundParameters
    }
    BeforeEach {
        $script:fixtureRoot = Join-Path $TestDrive 'AllUsers modules'
        $script:fixtureReportPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.json')
        $script:fixtureModules = @{}
        $script:loadedModules = @{}
        $script:commandOwnerOverride = ''
        $script:importFailure = $false
        $script:exportMissing = $false
        foreach ($module in (New-ModuleTestReport -ModulePath $script:fixtureRoot).Modules) {
            $script:fixtureModules[$module.Name] = [pscustomobject]@{
                Name = $module.Name; Version = [version]$module.Version; Path = $module.Path
            }
        }
        Mock Get-Module { $script:fixtureModules[$Name] } -ParameterFilter {
            $ListAvailable -and $Name -in @('Az.Accounts', 'Az.Storage', 'Az.Resources', 'Az.Network', 'Az.Compute', 'AzFilesHybrid')
        }
        Mock Get-Module { $script:loadedModules.Values } -ParameterFilter { -not $Name -and -not $ListAvailable }
        Mock Import-Module {
            if ($script:importFailure -and $Name -like '*\AzFilesHybrid.psd1') { throw 'required Graph dependency missing' }
            $module = $script:fixtureModules.Values | Where-Object Path -eq $Name | Select-Object -First 1
            $script:loadedModules[$module.Name] = $module
        } -ParameterFilter { $Name -like "$script:fixtureRoot\*" }
        Mock Get-Command {
            if ($script:exportMissing -and $Name -eq 'Debug-AzStorageAccountAuth') { throw 'Debug export missing' }
            $owner = switch ($Name) {
                'Connect-AzAccount' { 'Az.Accounts' }
                'Get-AzStorageAccount' { 'Az.Storage' }
                'Debug-AzStorageAccountAuth' { 'AzFilesHybrid' }
            }
            if ($script:commandOwnerOverride) { $owner = $script:commandOwnerOverride }
            [pscustomobject]@{ Name = $Name; ModuleName = $owner; Module = $script:fixtureModules[$owner] }
        } -ParameterFilter { $Name -in @('Connect-AzAccount', 'Get-AzStorageAccount', 'Debug-AzStorageAccountAuth') }
    }

    It 'imports every seed manifest and records exact versions and the three exported commands' {
        $oldPath = $env:PSModulePath
        try { & $validationScript -ModulePath $script:fixtureRoot -ReportPath $script:fixtureReportPath }
        finally { $env:PSModulePath = $oldPath }
        $result = Get-Content -LiteralPath $script:fixtureReportPath -Raw | ConvertFrom-Json
        @($result.Modules).Count | Should Be 6
        @($result.Commands).Count | Should Be 3
        ($result.Modules | Where-Object Name -eq AzFilesHybrid).Version | Should Be '0.3.3.0'
        Assert-MockCalled Import-Module -Times 6 -Exactly -Scope It -ParameterFilter {
            $Name -like "$script:fixtureRoot\*" -and $Global -and $Force
        }
    }

    It 'rejects missing old or profile-only modules before writing a success report: <Kind>' -TestCases @(
        @{ Kind = 'missing'; Expected = 'LAB_MODULE_MISSING' },
        @{ Kind = 'old'; Expected = 'LAB_MODULE_TOO_OLD' },
        @{ Kind = 'old storage'; Expected = 'LAB_MODULE_TOO_OLD: Az.Storage' },
        @{ Kind = 'profile-only'; Expected = 'LAB_MODULE_MISSING' }
    ) {
        param($Kind, $Expected)
        switch ($Kind) {
            'missing' { $script:fixtureModules.Remove('AzFilesHybrid') }
            'old' { $script:fixtureModules['AzFilesHybrid'].Version = [version]'0.2.9' }
            'old storage' { $script:fixtureModules['Az.Storage'].Version = [version]'8.0.9' }
            'profile-only' { $script:fixtureModules['AzFilesHybrid'].Path = 'C:\Users\SYSTEM\Documents\WindowsPowerShell\Modules\AzFilesHybrid.psd1' }
        }
        $oldPath = $env:PSModulePath
        $failureRecord = $null
        try { & $validationScript -ModulePath $script:fixtureRoot -ReportPath $script:fixtureReportPath }
        catch { $failureRecord = $_ }
        finally { $env:PSModulePath = $oldPath }
        $failureRecord.Exception.Message | Should Match $Expected
        Test-Path -LiteralPath $script:fixtureReportPath | Should Be $false
    }

    It 'accepts AzFilesHybrid 0.3.0 and Az.Storage 8.1.0 baseline versions' {
        $script:fixtureModules['AzFilesHybrid'].Version = [version]'0.3.0'
        $oldPath = $env:PSModulePath
        try { & $validationScript -ModulePath $script:fixtureRoot -ReportPath $script:fixtureReportPath }
        finally { $env:PSModulePath = $oldPath }
        Test-Path -LiteralPath $script:fixtureReportPath | Should Be $true
    }

    It 'does not hide failed manifest dependencies or missing exports: <Kind>' -TestCases @(
        @{ Kind = 'dependency'; Expected = 'required Graph dependency missing' },
        @{ Kind = 'export'; Expected = 'Debug export missing' },
        @{ Kind = 'wrong owner'; Expected = 'LAB_COMMAND_INVALID' }
    ) {
        param($Kind, $Expected)
        switch ($Kind) {
            'dependency' { $script:importFailure = $true }
            'export' { $script:exportMissing = $true }
            'wrong owner' { $script:commandOwnerOverride = 'Az.Storage' }
        }
        $oldPath = $env:PSModulePath
        $failureRecord = $null
        try { & $validationScript -ModulePath $script:fixtureRoot -ReportPath $script:fixtureReportPath }
        catch { $failureRecord = $_ }
        finally { $env:PSModulePath = $oldPath }
        $failureRecord.Exception.Message | Should Match $Expected
        Test-Path -LiteralPath $script:fixtureReportPath | Should Be $false
    }
}

Describe 'Gallery fallback script (offline)' {
    BeforeEach {
        $script:repositoryRegistered = $true
        $script:sourceLocation = 'https://www.powershellgallery.com/api/v2'
        $script:acceptLicense = $true
        Mock Install-PackageProvider {}
        Mock Get-PSRepository {
            if ($script:repositoryRegistered) { [pscustomobject]@{ SourceLocation = $script:sourceLocation } }
        }
        Mock Register-PSRepository { $script:repositoryRegistered = $true }
        Mock Set-PSRepository {}
        Mock Save-Module {}
        Mock Get-Command {
            $parameters = @{}
            if ($script:acceptLicense) { $parameters.AcceptLicense = $true }
            [pscustomobject]@{ Parameters = $parameters }
        } -ParameterFilter { $Name -eq 'Save-Module' }
    }

    It 'bootstraps AllUsers NuGet and saves the intended subset and constrained AzFilesHybrid, not the Az meta-module' {
        & $galleryScript -ModulePath $TestDrive
        Assert-MockCalled Install-PackageProvider -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'NuGet' -and $MinimumVersion -eq '2.8.5.201' -and $Scope -eq 'AllUsers' -and $Force
        }
        Assert-MockCalled Set-PSRepository -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'PSGallery' -and $InstallationPolicy -eq 'Trusted'
        }
        Assert-MockCalled Save-Module -Times 6 -Exactly -Scope It -ParameterFilter {
            $Repository -eq 'PSGallery' -and $Path -eq $TestDrive -and $Force -and $AcceptLicense
        }
        Assert-MockCalled Save-Module -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'AzFilesHybrid' -and $MinimumVersion -eq '0.3.0'
        }
        Assert-MockCalled Save-Module -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'Az.Storage' -and $MinimumVersion -eq '8.1.0'
        }
        Assert-MockCalled Save-Module -Times 0 -Exactly -Scope It -ParameterFilter { $Name -eq 'Az' }
        [Net.ServicePointManager]::SecurityProtocol | Should Be ([Net.SecurityProtocolType]::Tls12)
    }

    It 'registers a missing default Gallery and accommodates older Save-Module parameter sets' {
        $script:repositoryRegistered = $false
        $script:acceptLicense = $false
        & $galleryScript -ModulePath $TestDrive
        Assert-MockCalled Register-PSRepository -Times 1 -Exactly -Scope It -ParameterFilter { $Default }
        Assert-MockCalled Save-Module -Times 6 -Exactly -Scope It -ParameterFilter { -not $AcceptLicense }
    }

    It 'propagates provider or module download failures: <Kind>' -TestCases @(
        @{ Kind = 'provider' }, @{ Kind = 'module' }
    ) {
        param($Kind)
        if ($Kind -eq 'provider') { Mock Install-PackageProvider { throw 'provider failed' } }
        else { Mock Save-Module { throw 'module failed' } }
        $failureRecord = $null
        try { & $galleryScript -ModulePath $TestDrive }
        catch { $failureRecord = $_ }
        $failureRecord.Exception.Message | Should Match "$Kind failed"
    }

    It 'refuses a nonofficial Gallery source before trusting or downloading' {
        $script:sourceLocation = 'https://example.invalid/feed'
        $failureRecord = $null
        try { & $galleryScript -ModulePath $TestDrive }
        catch { $failureRecord = $_ }
        $failureRecord.Exception.Message | Should Match 'LAB_GALLERY_SOURCE_INVALID'
        Assert-MockCalled Set-PSRepository -Times 0 -Exactly -Scope It
        Assert-MockCalled Save-Module -Times 0 -Exactly -Scope It
    }
}

Describe 'Module worker process and report contracts (offline)' {
    BeforeEach {
        $script:workerTools = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:workerTools | Out-Null
        $script:workerExit = 0
        $script:workerError = ''
        Mock Start-Process {
            Set-Content -LiteralPath $RedirectStandardOutput -Value 'worker fixture'
            Set-Content -LiteralPath $RedirectStandardError -Value $script:workerError
            [pscustomobject]@{ ExitCode = $script:workerExit }
        }
    }

    It 'uses a fresh noninteractive Windows PowerShell process with quoted paths' {
        Invoke-LabModuleWorker -Script 'throw "must never execute on host"' `
            -Parameters @{ ModulePath = 'C:\Program Files\WindowsPowerShell\Modules' } -ToolsDirectory $script:workerTools
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
            $FilePath -like '*\WindowsPowerShell\v1.0\powershell.exe' -and
            $ArgumentList -like '*"-NoProfile" "-NonInteractive"*' -and
            $ArgumentList -like '*"-ModulePath" "C:\Program Files\WindowsPowerShell\Modules"*' -and $Wait -and $PassThru
        }
    }

    It 'rejects nonzero exit codes and stderr even with a zero exit: <Kind>' -TestCases @(
        @{ Kind = 'exit' }, @{ Kind = 'stderr' }
    ) {
        param($Kind)
        if ($Kind -eq 'exit') { $script:workerExit = 1 }
        else { $script:workerError = 'Import failed' }
        { Invoke-LabModuleWorker -Script 'fixture' -Parameters @{} -ToolsDirectory $script:workerTools } |
            Should Throw 'LAB_MODULE_WORKER_FAILED'
    }

    It 'rejects missing or incomplete validation reports: <Kind>' -TestCases @(
        @{ Kind = 'missing' }, @{ Kind = 'incomplete' }
    ) {
        param($Kind)
        $script:reportKind = $Kind
        Mock Invoke-LabModuleWorker {
            if ($script:reportKind -eq 'incomplete') {
                Set-Content -LiteralPath $Parameters.ReportPath -Value '{"Modules":[],"Commands":[]}'
            }
        }
        { Test-LabPowerShellModules -ModulePath 'C:\AllUsers' -ToolsDirectory $script:workerTools } | Should Throw 'LAB_MODULE_REPORT'
    }

    It 'persists exact resolved versions without claiming the full Az meta-module' {
        $report = New-ModuleTestReport -ModulePath 'C:\Program Files\WindowsPowerShell\Modules'
        $output = Write-LabModuleReport -Report $report -ToolsDirectory $script:workerTools
        ($output -join "`n") | Should Match 'NOT the full Az meta-module'
        ($output -join "`n") | Should Match 'management permissions and diagnostic execution are NOT VERIFIED'
        $saved = Get-Content -LiteralPath (Join-Path $script:workerTools 'powershell-modules.json') -Raw | ConvertFrom-Json
        ($saved.Modules | Where-Object Name -eq AzFilesHybrid).Version | Should Be '0.3.3.0'
        $saved.ModulePath | Should Be 'C:\Program Files\WindowsPowerShell\Modules'
    }

    It 'does not execute sign-in diagnostics role grants or AD DS prerequisites during module setup' {
        foreach ($text in @((Get-LabModuleValidationScript), (Get-LabModuleGalleryScript))) {
            $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$null)
            $commands = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)
            @($commands | Where-Object {
                $_.GetCommandName() -in @('Connect-AzAccount', 'Debug-AzStorageAccountAuth',
                    'Install-WindowsFeature', 'Add-Computer', 'New-AzRoleAssignment', 'Install-Module')
            }).Count | Should Be 0
        }
    }
}

Describe 'Module bundle layout and publication (offline fixture files only)' {
    BeforeEach {
        $script:bundleRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:bundleRoot | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
    }

    It 'extracts the existing module-name/version layout and copies it to a simulated AllUsers path' {
        $source = Join-Path $script:bundleRoot 'source'
        $version = Join-Path $source 'AzFilesHybrid\0.3.3.0'
        New-Item -ItemType Directory -Path $version -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $version 'AzFilesHybrid.psd1') -Value 'offline fixture, not an importable module'
        $zip = Join-Path $script:bundleRoot 'bundle.zip'
        [IO.Compression.ZipFile]::CreateFromDirectory($source, $zip)
        $stage = Join-Path $script:bundleRoot 'stage'
        New-Item -ItemType Directory -Path $stage | Out-Null
        Expand-LabModuleBundle -ZipPath $zip -Destination $stage
        $destination = Join-Path $script:bundleRoot 'simulated AllUsers'
        Publish-LabPowerShellModules -Source $stage -ModulePath $destination
        Publish-LabPowerShellModules -Source $stage -ModulePath $destination
        (Get-Content -LiteralPath (Join-Path $destination 'AzFilesHybrid\0.3.3.0\AzFilesHybrid.psd1') -Raw).Trim() |
            Should Be 'offline fixture, not an importable module'
    }

    It 'rejects archive entries that escape staging: <Entry>' -TestCases @(
        @{ Entry = '../escape.txt' }, @{ Entry = 'C:/escape.txt' }, @{ Entry = '/escape.txt' },
        @{ Entry = 'AzFilesHybrid/file:stream' }
    ) {
        param($Entry)
        $zip = Join-Path $script:bundleRoot 'bad.zip'
        $archive = [IO.Compression.ZipFile]::Open($zip, 'Create')
        try { $archive.CreateEntry($Entry) | Out-Null }
        finally { $archive.Dispose() }
        $stage = Join-Path $script:bundleRoot 'stage'
        New-Item -ItemType Directory -Path $stage | Out-Null
        { Expand-LabModuleBundle -ZipPath $zip -Destination $stage } | Should Throw 'LAB_MODULE_BUNDLE_PATH_INVALID'
        Test-Path -LiteralPath (Join-Path $script:bundleRoot 'escape.txt') | Should Be $false
    }
}

Describe 'Client completion marker ordering with modules (offline)' {
    BeforeEach {
        $script:markerEvents = @()
        Mock Install-LabCaptureTools { $script:markerEvents += 'capture' }
        Mock Install-LabTraceTools { $script:markerEvents += 'trace' }
        Mock Install-LabPowerShellModules { $script:markerEvents += 'modules' }
        Mock Write-Output { $script:markerEvents += $InputObject }
        $statements = $clientAst.EndBlock.Statements | Where-Object {
            $_.Extent.Text -in @('Install-LabCaptureTools -ToolsDirectory $tools',
                'Install-LabTraceTools -ToolsDirectory $tools',
                'Install-LabPowerShellModules -ToolsDirectory $tools',
                "Write-Output 'CLIENT_CONFIG_DONE'")
        }
        @($statements).Count | Should Be 4
        $script:completionBlock = [scriptblock]::Create(($statements.Extent.Text -join "`n"))
        $tools = $TestDrive
    }

    It 'keeps capture and trace provisioning and only emits completion after module verification' {
        & $script:completionBlock
        ($script:markerEvents -join ',') | Should Be 'capture,trace,modules,CLIENT_CONFIG_DONE'
    }

    It 'does not emit completion when module provisioning throws' {
        Mock Install-LabPowerShellModules { throw 'LAB_MODULES_UNAVAILABLE' }
        $failureRecord = $null
        try { & $script:completionBlock }
        catch { $failureRecord = $_ }
        $failureRecord.Exception.Message | Should Match 'LAB_MODULES_UNAVAILABLE'
        Assert-MockCalled Write-Output -Times 0 -Exactly -Scope It -ParameterFilter { $InputObject -eq 'CLIENT_CONFIG_DONE' }
    }
}
