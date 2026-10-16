<# 
Dev Supply Chain IOC Checker
Dependency-free, offline-only, read-only static scanner for Windows developer environments.
#>

[CmdletBinding()]
param(
    [string]$Path,
    [switch]$UserProfile,
    [switch]$Deep,
    [switch]$MajorLocations,
    [switch]$EndpointTelemetry,
    [string]$ReportDir,
    [string]$TextOut,
    [string]$JsonOut,
    [int]$MaxFileSizeMB = 10,
    [int]$MaxFiles = 200000,
    [int]$EndpointDays = 30,
    [string]$LauncherPath,
    [string[]]$Checks,
    [switch]$NoColor,
    [switch]$Quiet,
    [switch]$VerboseProgress,
    [switch]$SyntheticValidation
)

$script:ScannerName = 'Dev Supply Chain IOC Checker'
$script:ScannerVersion = '0.1.27'
$script:KeyvChainDropApprovedPackageHash = '7da86fddcb4bc5c4352d3f2120903a07314ae2ce3071d980061862bcbc8aa497'
$script:Context = $null
$script:WarnedMaxFiles = $false
$script:SkipOwnSyntheticSamples = $false
$script:SkipOwnReportArtifacts = $true
$script:WarnedOwnSyntheticSamplesSkipped = $false
$script:CurrentPhase = 'startup'
$script:CurrentScanRoot = ''
$script:EncodingProbeMaxBytes = 65536
$script:VariationSelectorDecodeMaxBytes = 8192
$script:VariationSelectorMatchLimit = 8192
$script:RegexMatchTimeoutSeconds = 2
[AppDomain]::CurrentDomain.SetData('REGEX_DEFAULT_MATCH_TIMEOUT', [TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
$script:RunStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:BoundedRegexCache = @{}
$script:CurrentFileStatPath = ''
$script:LastProgressElapsedMs = 0
$script:VerboseProgressEnabled = [bool]$VerboseProgress
$script:ProgressIntervalMs = if ($script:VerboseProgressEnabled) { 5000 } else { 30000 }
$script:DetailedProgressFileMinBytes = 1048576
$script:SlowScannerStepThresholdMs = 2000
$script:TargetedPerProjectFileLimit = 2000
$script:NodeRuntimeInventoryLimit = 100
$script:SeverityOrder = @('DANGER', 'WARN', 'CAUTION', 'INFO', 'OK')
$script:SeverityRank = @{
    'DANGER' = 4
    'WARN' = 3
    'CAUTION' = 2
    'INFO' = 1
    'OK' = 0
}
$script:LikelyBinaryExtensions = @{
    '.7z'=$true; '.a'=$true; '.avi'=$true; '.bin'=$true; '.bmp'=$true; '.bz2'=$true
    '.cab'=$true; '.class'=$true; '.db'=$true; '.dll'=$true; '.dmg'=$true; '.dylib'=$true
    '.eot'=$true; '.exe'=$true; '.flac'=$true; '.gif'=$true; '.gz'=$true; '.ico'=$true
    '.iso'=$true; '.jar'=$true; '.jpeg'=$true; '.jpg'=$true; '.lib'=$true; '.mov'=$true
    '.mp3'=$true; '.mp4'=$true; '.msi'=$true; '.node'=$true; '.ogg'=$true; '.otf'=$true
    '.p7s'=$true; '.pdb'=$true; '.pdf'=$true; '.png'=$true; '.pyc'=$true; '.pyo'=$true; '.so'=$true
    '.sqlite'=$true; '.sqlite3'=$true; '.tar'=$true; '.tgz'=$true; '.traineddata'=$true; '.ttf'=$true
    '.vsix'=$true; '.wasm'=$true; '.wav'=$true; '.webm'=$true; '.webp'=$true
    '.woff'=$true; '.woff2'=$true; '.xz'=$true; '.zip'=$true
}
$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($script:BaseDir)) {
    $script:BaseDir = (Get-Location).Path
}

function New-ArrayList {
    $list = New-Object System.Collections.ArrayList
    return ,$list
}

function Add-ListItem {
    param(
        $List,
        $Item
    )
    [void]$List.Add($Item)
}

$script:LeafCheckOrder = @(
    'Packages',
    'LifecycleScripts',
    'NodeRuntime',
    'InvisibleUnicode',
    'CiCd',
    'AiMcp',
    'IdeExtensions',
    'HooksAndTasks',
    'SecretsInventory',
    'NpmGlobal',
    'NpmCache',
    'ScannerSelf'
)

$script:CheckNameMap = @{}
foreach ($checkName in @($script:LeafCheckOrder + @('Recommended','MajorRecommended','AllSafe'))) {
    $script:CheckNameMap[$checkName.ToLowerInvariant()] = $checkName
}

$script:NpmIncidentWatchlistNames = @(
    '@tanstack/react-router',
    '@tanstack/history',
    '@tanstack/router-core',
    '@mistralai/mistralai',
    '@mistralai/mistralai-azure',
    '@mistralai/mistralai-gcp'
)

$script:NpmIncidentWatchlistPrefixes = @(
    '@redhat-cloud-services/'
)

function Normalize-CheckToken {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }
    $key = $Value.Trim().ToLowerInvariant()
    if ($script:CheckNameMap.ContainsKey($key)) {
        return [string]$script:CheckNameMap[$key]
    }
    return ''
}

function Expand-CheckMacro {
    param([string]$CheckName)
    switch ($CheckName) {
        'Recommended' {
            return @('Packages','LifecycleScripts','NodeRuntime','InvisibleUnicode','CiCd','AiMcp','IdeExtensions','HooksAndTasks','SecretsInventory','ScannerSelf')
        }
        'MajorRecommended' {
            return @('Packages','LifecycleScripts','NodeRuntime','InvisibleUnicode','CiCd','AiMcp','IdeExtensions','HooksAndTasks','SecretsInventory','NpmGlobal','ScannerSelf')
        }
        'AllSafe' {
            return @($script:LeafCheckOrder)
        }
        default {
            return @($CheckName)
        }
    }
}

function Resolve-CheckSelection {
    $rawTokens = New-ArrayList
    foreach ($item in @($Checks)) {
        if ([string]::IsNullOrWhiteSpace([string]$item)) {
            continue
        }
        foreach ($part in ([string]$item -split ',')) {
            if (-not [string]::IsNullOrWhiteSpace($part)) {
                Add-ListItem $rawTokens $part.Trim()
            }
        }
    }

    if ($rawTokens.Count -eq 0) {
        Add-ListItem $rawTokens 'Recommended'
    }

    $selected = New-ArrayList
    $expandedSet = @{}
    foreach ($token in @($rawTokens)) {
        $normalized = Normalize-CheckToken $token
        if ([string]::IsNullOrEmpty($normalized)) {
            throw ("Unsupported check name: {0}. Valid values: {1}" -f $token, ([string]::Join(', ', [string[]]@($script:CheckNameMap.Values | Sort-Object -Unique))))
        }
        Add-ListItem $selected $normalized
        foreach ($expanded in @(Expand-CheckMacro $normalized)) {
            $expandedSet[$expanded] = $true
        }
    }

    $expanded = New-ArrayList
    $skipped = New-ArrayList
    foreach ($leaf in @($script:LeafCheckOrder)) {
        if ($expandedSet.ContainsKey($leaf)) {
            Add-ListItem $expanded $leaf
        }
        else {
            Add-ListItem $skipped $leaf
        }
    }

    return [ordered]@{
        selected = @($selected.ToArray())
        expanded = @($expanded.ToArray())
        skipped = @($skipped.ToArray())
        enabled = $expandedSet
    }
}

function Test-CheckEnabled {
    param([string]$CheckName)
    if ($null -eq $script:Context -or $null -eq $script:Context.checks -or $null -eq $script:Context.checks.enabled) {
        return $true
    }
    return [bool]$script:Context.checks.enabled.ContainsKey($CheckName)
}

function Test-EnabledChecksRequireProjectPath {
    if ($null -eq $script:Context -or $null -eq $script:Context.checks) {
        return $true
    }
    foreach ($checkName in @('Packages','LifecycleScripts','NodeRuntime','InvisibleUnicode','CiCd','AiMcp','IdeExtensions','HooksAndTasks','SecretsInventory')) {
        if (Test-CheckEnabled $checkName) {
            return $true
        }
    }
    return $false
}

function ConvertTo-RedactedPath {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    $result = $Value
    if (-not [string]::IsNullOrEmpty($env:USERPROFILE)) {
        $escapedProfile = [regex]::Escape($env:USERPROFILE)
        $result = [regex]::Replace($result, $escapedProfile, '~', 'IgnoreCase')
    }
    if (-not [string]::IsNullOrEmpty($env:COMPUTERNAME)) {
        $result = [regex]::Replace($result, [regex]::Escape($env:COMPUTERNAME), '<COMPUTER>', 'IgnoreCase')
    }
    return $result
}

function Write-ScanHeartbeat {
    param(
        [string]$Stage,
        [string]$Path,
        [switch]$Force
    )
    if ($Quiet -or $null -eq $script:Context -or $null -eq $script:Context.scanStats) {
        return
    }
    $elapsedMs = [int64]$script:RunStopwatch.ElapsedMilliseconds
    if (-not $Force -and ($elapsedMs - $script:LastProgressElapsedMs) -lt $script:ProgressIntervalMs) {
        return
    }
    $script:LastProgressElapsedMs = $elapsedMs
    $root = if ([string]::IsNullOrWhiteSpace($script:CurrentScanRoot)) { $Path } else { $script:CurrentScanRoot }
    $redactedRoot = ConvertTo-RedactedPath $root
    $current = if ([string]::IsNullOrWhiteSpace($Path)) { $root } else { $Path }
    $redactedCurrent = ConvertTo-RedactedPath $current
    $elapsed = [TimeSpan]::FromMilliseconds($elapsedMs)
    $elapsedText = ('{0:00}:{1:00}:{2:00}' -f [Math]::Floor($elapsed.TotalHours), $elapsed.Minutes, $elapsed.Seconds)
    if ($script:VerboseProgressEnabled) {
        Write-Host ("      progress: stage={0}; root={1}; current={2}; discoveryDirs={3}; enumerated={4}; queued={5}; scanned={6}; elapsed={7}" -f $Stage, $redactedRoot, $redactedCurrent, $script:Context.scanStats.projectDiscoveryDirectoriesVisited, $script:Context.scanStats.filesEnumerated, $script:Context.scanStats.uniqueFilesQueued, $script:Context.scanStats.filesScanned, $elapsedText)
    }
    else {
        Write-Host ("      progress: stage={0}; root={1}; queued={2}; scanned={3}; elapsed={4}" -f $Stage, $redactedRoot, $script:Context.scanStats.uniqueFilesQueued, $script:Context.scanStats.filesScanned, $elapsedText)
    }
}

function Redact-SecretLikeText {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    $text = ConvertTo-RedactedPath $Value
    $text = $text -replace "(`r|`n)+", ' '
    $text = [regex]::Replace($text, '(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]+', '$1 <REDACTED>')
    $text = [regex]::Replace($text, '(?i)(token|secret|password|passwd|api[_-]?key|auth|credential|private[_-]?key)\s*[:=]\s*["'']?[^"'',\s}\]]+', '$1=<REDACTED>')
    $text = [regex]::Replace($text, '(?i)AKIA[0-9A-Z]{16}', '<AWS_ACCESS_KEY_REDACTED>')
    $text = [regex]::Replace($text, '(?i)github_pat_[A-Za-z0-9_]+', '<GITHUB_TOKEN_REDACTED>')
    $text = [regex]::Replace($text, '(?i)gh[pousr]_[A-Za-z0-9_]+', '<GITHUB_TOKEN_REDACTED>')
    $text = [regex]::Replace($text, '(?i)sk-[A-Za-z0-9_-]{16,}', '<API_TOKEN_REDACTED>')
    $text = [regex]::Replace($text, '-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '<PRIVATE_KEY_REDACTED>')
    if ($text.Length -gt 240) {
        $text = $text.Substring(0, 240) + '...'
    }
    return $text
}

function Get-FullPathSafe {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $null
    }
    try {
        $fullPath = [System.IO.Path]::GetFullPath($CandidatePath)
        $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
        if (-not [string]::IsNullOrEmpty($pathRoot) -and
            $fullPath.TrimEnd('\', '/').Equals($pathRoot.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
            return $pathRoot
        }
        return $fullPath.TrimEnd('\', '/')
    }
    catch {
        return $null
    }
}

function Test-IsPathUnderRoot {
    param([string]$CandidatePath, [string]$RootPath)
    $candidate = Get-FullPathSafe $CandidatePath
    $root = Get-FullPathSafe $RootPath
    if ([string]::IsNullOrEmpty($candidate) -or [string]::IsNullOrEmpty($root)) {
        return $false
    }
    $rootWithSeparator = $root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $candidate.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-SafeAutomaticProfileRoot {
    param(
        [string]$CandidatePath,
        [string]$EnvironmentName
    )
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
        return $null
    }

    $reason = $null
    $candidate = $null
    $profile = $null
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE) -or
        -not [System.IO.Path]::IsPathRooted($env:USERPROFILE)) {
        $reason = 'user-profile-unavailable'
    }
    else {
        $profile = Get-FullPathSafe $env:USERPROFILE
        if ([string]::IsNullOrEmpty($profile)) {
            $reason = 'user-profile-unavailable'
        }
    }
    if ([string]::IsNullOrEmpty($reason) -and -not [System.IO.Path]::IsPathRooted($CandidatePath)) {
        $reason = 'relative-path'
    }
    elseif ([string]::IsNullOrEmpty($reason)) {
        $candidate = Get-FullPathSafe $CandidatePath
        if ([string]::IsNullOrEmpty($candidate)) {
            $reason = 'invalid-path'
        }
        else {
            try {
                $candidateRoot = Get-FullPathSafe ([System.IO.Path]::GetPathRoot($candidate))
                $profileRoot = Get-FullPathSafe ([System.IO.Path]::GetPathRoot($profile))
                if ([string]::IsNullOrEmpty($candidateRoot) -or
                    $candidate.Equals($candidateRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $reason = 'filesystem-root'
                }
                elseif (-not [string]::IsNullOrEmpty($profileRoot) -and
                    $profile.Equals($profileRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $reason = 'unsafe-user-profile-root'
                }
                elseif (-not (Test-Path -LiteralPath $profile -PathType Container) -or
                    (Test-IsReparsePoint (Get-Item -LiteralPath $profile -Force -ErrorAction Stop))) {
                    $reason = 'unsafe-user-profile-root'
                }
                elseif ($candidate.Equals($profile, [System.StringComparison]::OrdinalIgnoreCase) -or
                    -not (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $profile)) {
                    $reason = 'outside-user-profile'
                }
                elseif ((Test-Path -LiteralPath $candidate) -and
                    (-not (Test-Path -LiteralPath $candidate -PathType Container) -or
                     (Test-PathHasReparsePointBelowRoot -RootPath $profile -CandidatePath $candidate))) {
                    $reason = 'non-directory-or-reparse-path'
                }
            }
            catch {
                $reason = 'path-validation-failed'
            }
        }
    }

    if (-not [string]::IsNullOrEmpty($reason)) {
        Add-Finding -Severity 'WARN' -Category 'AUTOMATIC_ENVIRONMENT_ROOT_REJECTED' -Title 'Environment-defined automatic scan root was rejected' -Path $CandidatePath -Evidence ("environment={0}; reason={1}; path value redacted" -f $EnvironmentName,$reason) -Recommendation 'Keep automatic tool roots under USERPROFILE, or scan an intentional external directory explicitly with -Path.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
        return $null
    }
    return $candidate
}

function Get-ScannerDistributionInfo {
    $base = $script:BaseDir
    $scriptPath = Join-Path $base 'Scan-DevSupplyChain.ps1'
    $launcher = Join-Path $base 'run-checker.bat'
    $readme = Join-Path $base 'README.md'
    $iocDir = Join-Path $base 'iocs'
    $campaignIoc = Join-Path $iocDir 'campaign-keyv-chaindrop-20260806.json'
    $manifest = Join-Path $base 'tests\samples\manifest.json'

    $missing = New-ArrayList
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { Add-ListItem $missing 'Scan-DevSupplyChain.ps1' }
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { Add-ListItem $missing 'run-checker.bat' }
    if (-not (Test-Path -LiteralPath $readme -PathType Leaf)) { Add-ListItem $missing 'README.md' }
    if (-not (Test-Path -LiteralPath $iocDir -PathType Container)) { Add-ListItem $missing 'iocs' }
    if ((Test-Path -LiteralPath $iocDir -PathType Container) -and -not (Test-Path -LiteralPath $campaignIoc -PathType Leaf)) { Add-ListItem $missing 'iocs/campaign-keyv-chaindrop-20260806.json' }
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { Add-ListItem $missing 'tests/samples/manifest.json' }

    $status = 'complete'
    if ($missing.Count -gt 0) {
        $hasOnlyScript = (Test-Path -LiteralPath $scriptPath -PathType Leaf) -and
            -not (Test-Path -LiteralPath $launcher -PathType Leaf) -and
            -not (Test-Path -LiteralPath $readme -PathType Leaf) -and
            -not (Test-Path -LiteralPath $iocDir -PathType Container) -and
            -not (Test-Path -LiteralPath $manifest -PathType Leaf)
        if ($hasOnlyScript) {
            $status = 'script-only'
        }
        elseif ($missing -contains 'tests/samples/manifest.json' -and $missing.Count -eq 1) {
            $status = 'missing-samples-manifest'
        }
        elseif ($missing -contains 'iocs' -and $missing.Count -eq 1) {
            $status = 'missing-iocs'
        }
        else {
            $status = 'incomplete'
        }
    }

    $warnings = New-ArrayList
    foreach ($item in @($missing)) {
        Add-ListItem $warnings ("Missing distribution item: {0}" -f $item)
    }
    if ($status -eq 'script-only') {
        Add-ListItem $warnings 'Scanner is running from a script-only copy; external scanner fixture skipping is disabled.'
    }
    elseif ($status -ne 'complete') {
        Add-ListItem $warnings 'Scanner distribution is incomplete; use the extracted release folder and run-checker.bat for repeatable results.'
    }

    return [ordered]@{
        status = $status
        warnings = @($warnings.ToArray())
        manifestPath = $manifest
        iocDir = $iocDir
        launcherPath = $launcher
    }
}

function Get-OwnSyntheticSampleRoot {
    try {
        $root = [System.IO.Path]::GetFullPath((Join-Path $script:BaseDir 'tests\samples'))
        return $root.TrimEnd('\', '/')
    }
    catch {
        return $null
    }
}

function Test-IsPathUnderOwnSyntheticSamples {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }

    try {
        $sampleRoot = Get-OwnSyntheticSampleRoot
        if ([string]::IsNullOrEmpty($sampleRoot)) {
            return $false
        }
        $candidate = [System.IO.Path]::GetFullPath($CandidatePath)
        $sampleRootWithSeparator = $sampleRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        if ($candidate.Equals($sampleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
        return $candidate.StartsWith($sampleRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Test-IsOwnIocDataPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    try {
        $iocRoot = [System.IO.Path]::GetFullPath((Join-Path $script:BaseDir 'iocs')).TrimEnd('\', '/')
        $candidate = [System.IO.Path]::GetFullPath($CandidatePath)
        $iocRootWithSeparator = $iocRoot + [System.IO.Path]::DirectorySeparatorChar
        if ($candidate.Equals($iocRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
        return $candidate.StartsWith($iocRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Test-IsScannerSelfIocReferencePath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    $candidate = Get-FullPathSafe $CandidatePath
    $scriptPath = Get-FullPathSafe $script:ScriptPath
    if ([string]::IsNullOrEmpty($candidate)) {
        return $false
    }
    if (-not [string]::IsNullOrEmpty($scriptPath) -and $candidate.Equals($scriptPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return (Test-IsOwnIocDataPath $CandidatePath)
}

function Test-IsPathUnderOwnReportArtifacts {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    $candidate = Get-FullPathSafe $CandidatePath
    if ([string]::IsNullOrEmpty($candidate)) {
        return $false
    }

    $reportDirectory = Get-FullPathSafe (Join-Path $script:BaseDir 'reports')
    if ($null -ne $script:Context -and $null -ne $script:Context.reportPaths -and
        -not [string]::IsNullOrWhiteSpace([string]$script:Context.reportPaths.directory)) {
        $reportDirectory = Get-FullPathSafe ([string]$script:Context.reportPaths.directory)
    }
    if (-not [string]::IsNullOrEmpty($reportDirectory) -and
        (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $reportDirectory)) {
        return $true
    }

    if ($null -ne $script:Context -and $null -ne $script:Context.reportPaths) {
        foreach ($reportPath in @($script:Context.reportPaths.text, $script:Context.reportPaths.json)) {
            $resolvedReportPath = Get-FullPathSafe ([string]$reportPath)
            if (-not [string]::IsNullOrEmpty($resolvedReportPath) -and
                $candidate.Equals($resolvedReportPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }
    return $false
}

function Test-IsExplicitOwnReportArtifactRoot {
    param([string]$CandidatePath)
    return (Test-IsPathUnderOwnReportArtifacts $CandidatePath)
}

function Get-ScannerArtifactInfo {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $null
    }
    $candidate = Get-FullPathSafe $CandidatePath
    if ([string]::IsNullOrEmpty($candidate)) {
        return $null
    }

    $current = $candidate
    try {
        if (Test-Path -LiteralPath $current -PathType Leaf) {
            $current = Split-Path -Parent $current
        }
    }
    catch {
        $current = Split-Path -Parent $current
    }

    while (-not [string]::IsNullOrEmpty($current)) {
        $scanner = Join-Path $current 'Scan-DevSupplyChain.ps1'
        $launcher = Join-Path $current 'run-checker.bat'
        $readme = Join-Path $current 'README.md'
        $sampleRoot = Join-Path $current 'tests\samples'
        if ((Test-Path -LiteralPath $scanner -PathType Leaf) -and
            (Test-Path -LiteralPath $launcher -PathType Leaf) -and
            (Test-Path -LiteralPath $readme -PathType Leaf)) {
            $rootFull = Get-FullPathSafe $current
            $baseFull = Get-FullPathSafe $script:BaseDir
            if (-not [string]::IsNullOrEmpty($rootFull) -and -not [string]::IsNullOrEmpty($baseFull) -and $rootFull.Equals($baseFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $null
            }
            $relative = ''
            $isSample = Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $sampleRoot
            if ($isSample) {
                $sampleFull = Get-FullPathSafe $sampleRoot
                if (-not [string]::IsNullOrEmpty($sampleFull) -and $candidate.Length -gt $sampleFull.Length) {
                    $relative = $candidate.Substring($sampleFull.Length).TrimStart('\', '/') -replace '/', '\'
                }
            }
            return [ordered]@{
                root = (Get-FullPathSafe $current)
                isSample = [bool]$isSample
                sampleRoot = (Get-FullPathSafe $sampleRoot)
                relativePath = $relative
            }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrEmpty($parent) -or $parent.Equals($current, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }
    return $null
}

function Register-ScannerArtifactRoot {
    param([string]$RootPath)
    if ($null -eq $script:Context -or $null -eq $script:Context.scannerArtifactRootsSeen -or [string]::IsNullOrEmpty($RootPath)) {
        return
    }
    $root = Get-FullPathSafe $RootPath
    if ([string]::IsNullOrEmpty($root)) {
        return
    }
    $key = $root.ToLowerInvariant()
    if (-not $script:Context.scannerArtifactRootsSeen.ContainsKey($key)) {
        $script:Context.scannerArtifactRootsSeen[$key] = $true
        Add-ScanStat -Name 'scannerArtifactRootsFound'
    }
}

function Register-ScannerArtifactUntrustedPath {
    param([string]$CandidatePath)
    if ($null -eq $script:Context -or $null -eq $script:Context.scannerArtifactUntrustedPaths -or [string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    $candidate = Get-FullPathSafe $CandidatePath
    if ([string]::IsNullOrEmpty($candidate)) {
        return $false
    }
    $key = $candidate.ToLowerInvariant()
    if ($script:Context.scannerArtifactUntrustedPaths.ContainsKey($key)) {
        return $false
    }
    $script:Context.scannerArtifactUntrustedPaths[$key] = $true
    if ($null -ne $script:Context.sourceContextCache) {
        [void]$script:Context.sourceContextCache.Remove($key)
    }
    return $true
}

function Test-IsScannerArtifactUntrustedPath {
    param([string]$CandidatePath)
    if ($null -eq $script:Context -or $null -eq $script:Context.scannerArtifactUntrustedPaths -or [string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    $candidate = Get-FullPathSafe $CandidatePath
    if ([string]::IsNullOrEmpty($candidate)) {
        return $false
    }
    return $script:Context.scannerArtifactUntrustedPaths.ContainsKey($candidate.ToLowerInvariant())
}

function Get-OwnSyntheticSampleRelativePath {
    param([string]$CandidatePath)
    if (-not (Test-IsPathUnderOwnSyntheticSamples $CandidatePath)) {
        return $null
    }
    try {
        $sampleRoot = Get-OwnSyntheticSampleRoot
        $candidate = [System.IO.Path]::GetFullPath($CandidatePath)
        if ($candidate.Equals($sampleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ''
        }
        return $candidate.Substring($sampleRoot.Length).TrimStart('\', '/') -replace '/', '\'
    }
    catch {
        return $null
    }
}

function Test-IsSafeManifestRelativePath {
    param([string]$RelativePath)
    if ([string]::IsNullOrEmpty($RelativePath)) { return $false }
    if ([System.IO.Path]::IsPathRooted($RelativePath)) { return $false }
    if ($RelativePath -match ':') { return $false }
    $normalized = $RelativePath -replace '/', '\'
    foreach ($segment in ($normalized -split '\\')) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -eq '..') {
            return $false
        }
    }
    return $true
}

function Normalize-SampleManifestKey {
    param([string]$RelativePath)
    if ([string]::IsNullOrEmpty($RelativePath)) { return '' }
    return (($RelativePath -replace '/', '\').TrimStart('\')).ToLowerInvariant()
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes) { return '' }
    $builder = New-Object System.Text.StringBuilder
    foreach ($b in $Bytes) {
        [void]$builder.AppendFormat('{0:x2}', $b)
    }
    return $builder.ToString()
}

function Get-Sha256HexFromBytes {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ConvertTo-HexString ($sha.ComputeHash($Bytes))
    }
    finally {
        $sha.Dispose()
    }
}

function Get-TextLfSha256ForFile {
    param([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
        $utf8BomStrict = New-Object System.Text.UTF8Encoding($true, $true)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $text = $utf8BomStrict.GetString($bytes, 3, $bytes.Length - 3)
        }
        elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
        }
        elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            $text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
        }
        else {
            $text = $utf8Strict.GetString($bytes)
        }
        $normalized = $text -replace "`r`n", "`n"
        $normalized = $normalized -replace "`r", "`n"
        $normalizedBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($normalized)
        return Get-Sha256HexFromBytes $normalizedBytes
    }
    catch {
        return $null
    }
}

function Get-BytesSha256ForFile {
    param([string]$FilePath)
    $stream = $null
    $sha = $null
    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $sha) { $sha.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-IsNpmCacheBlobPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    $normalized = $CandidatePath.ToLowerInvariant() -replace '/', '\'
    return ($normalized -match '\\_cacache\\content-v2(?:\\|$)')
}

function Test-IsDependencyMetadataPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    $normalized = $CandidatePath.ToLowerInvariant() -replace '/', '\'
    if ($normalized -match '\\[^\\]+\.dist-info\\metadata$') { return $true }
    if ($normalized -match '\\[^\\]+\.egg-info\\pkg-info$') { return $true }
    if ($normalized -match '\\node_modules\\[^\\]+\\package\.json$') { return $true }
    if ($normalized -match '\\node_modules\\@[^\\]+\\[^\\]+\\package\.json$') { return $true }
    return $false
}

function Test-IsDependencyOrGeneratedArtifactPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrWhiteSpace($CandidatePath) -or [string]::IsNullOrWhiteSpace($script:CurrentScanRoot)) {
        return $false
    }
    $candidate = Get-FullPathSafe $CandidatePath
    $root = Get-FullPathSafe $script:CurrentScanRoot
    if ([string]::IsNullOrEmpty($candidate) -or [string]::IsNullOrEmpty($root) -or
        -not (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $root) -or
        $candidate.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    $relative = $candidate.Substring($root.Length).TrimStart('\', '/')
    $normalized = ('\' + $relative.ToLowerInvariant()) -replace '/', '\'
    if ($normalized -match '\\(?:node_modules|vendor|site-packages|\.venv|venv|env|__pycache__|\.tox|\.mypy_cache|\.pytest_cache|\.next|\.nuxt|\.svelte-kit|dist|build|out|target|obj|\.cache|\.tmp|tmp)\\') { return $true }
    return $false
}

function Test-IsTargetedScanPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrWhiteSpace($CandidatePath) -or $null -eq $script:Context -or $null -eq $script:Context.targetedFilePaths) {
        return $false
    }
    try { $key = [System.IO.Path]::GetFullPath($CandidatePath).ToLowerInvariant() }
    catch { return $false }
    if ($null -ne $script:Context.securityCandidateMetadata -and $script:Context.securityCandidateMetadata.ContainsKey($key)) {
        return [bool]$script:Context.securityCandidateMetadata[$key].selected
    }
    return $script:Context.targetedFilePaths.ContainsKey($key)
}

function Load-OwnSyntheticSampleManifest {
    $entries = @{}
    $manifestPath = $null
    $root = Get-OwnSyntheticSampleRoot
    if (-not [string]::IsNullOrEmpty($root)) {
        $manifestPath = Join-Path $root 'manifest.json'
    }
    $result = [ordered]@{
        status = 'missing'
        path = $manifestPath
        entries = $entries
        error = ''
    }
    if ([string]::IsNullOrEmpty($manifestPath) -or -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return $result
    }

    try {
        $raw = [System.IO.File]::ReadAllText($manifestPath)
        $json = $raw | ConvertFrom-Json -ErrorAction Stop
        $samplesProperty = $json.PSObject.Properties['samples']
        if ($null -eq $samplesProperty -or $null -eq $samplesProperty.Value) {
            throw 'manifest missing samples array'
        }
        foreach ($sample in @($samplesProperty.Value)) {
            if ($null -eq $sample) { throw 'manifest contains null sample entry' }
            $relativePath = [string]$sample.relativePath
            $hashMode = [string]$sample.hashMode
            $sha256 = [string]$sample.sha256
            if (-not (Test-IsSafeManifestRelativePath $relativePath)) {
                throw ("unsafe sample path: {0}" -f $relativePath)
            }
            if ($hashMode -notin @('text-lf-sha256','bytes-sha256','presence-only')) {
                throw ("unsupported hashMode for {0}" -f $relativePath)
            }
            if ($hashMode -ne 'presence-only' -and ($sha256 -notmatch '^[0-9a-fA-F]{64}$')) {
                throw ("invalid sha256 for {0}" -f $relativePath)
            }
            $skip = $true
            if ($null -ne $sample.PSObject.Properties['skipInParentScan']) {
                $skip = [bool]$sample.skipInParentScan
            }
            $categories = @()
            if ($null -ne $sample.PSObject.Properties['expectedCategories']) {
                $categories = @($sample.expectedCategories)
            }
            $key = Normalize-SampleManifestKey $relativePath
            $entries[$key] = [ordered]@{
                relativePath = ($relativePath -replace '/', '\')
                hashMode = $hashMode
                sha256 = $sha256.ToLowerInvariant()
                expectedCategories = $categories
                skipInParentScan = $skip
            }
        }
        $result.status = 'valid'
        $result.entries = $entries
    }
    catch {
        $result.status = 'invalid'
        $result.entries = @{}
        if ($null -ne $_.Exception) {
            $result.error = $_.Exception.Message
        }
        else {
            $result.error = [string]$_
        }
    }
    return $result
}

function Mark-SyntheticSampleUntrusted {
    param([string]$CandidatePath)
    [void](Register-SyntheticSampleUntrusted $CandidatePath)
}

function Register-SyntheticSampleUntrusted {
    param([string]$CandidatePath)
    if ($null -eq $script:Context -or [string]::IsNullOrEmpty($CandidatePath)) { return }
    if ($null -eq $script:Context.syntheticSampleUntrustedPaths) { return $false }
    try {
        $key = [System.IO.Path]::GetFullPath($CandidatePath).ToLowerInvariant()
        if ($script:Context.syntheticSampleUntrustedPaths.ContainsKey($key)) {
            return $false
        }
        $script:Context.syntheticSampleUntrustedPaths[$key] = $true
        return $true
    }
    catch {
        return $false
    }
}

function Test-IsSyntheticSampleUntrustedPath {
    param([string]$CandidatePath)
    if ($null -eq $script:Context -or $null -eq $script:Context.syntheticSampleUntrustedPaths -or [string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    try {
        $key = [System.IO.Path]::GetFullPath($CandidatePath).ToLowerInvariant()
        return $script:Context.syntheticSampleUntrustedPaths.ContainsKey($key)
    }
    catch {
        return $false
    }
}

function Get-AiPathRole {
    param([string]$CandidatePath)
    if ($null -ne $script:Context -and $null -ne $script:Context.aiPathRoleCache -and -not [string]::IsNullOrEmpty($CandidatePath)) {
        $cache=$script:Context.aiPathRoleCache
        if ($cache.ContainsKey($CandidatePath)) { return [string]$cache[$CandidatePath] }
        $role=Get-AiPathRoleUncached $CandidatePath
        if ($cache.Count -ge 4096) { $cache.Clear() }
        $cache[$CandidatePath]=$role
        return $role
    }
    return (Get-AiPathRoleUncached $CandidatePath)
}

function Get-AiPathRoleUncached {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return 'normal'
    }

    $normalized = $CandidatePath.ToLowerInvariant() -replace '/', '\'
    $name = ''
    $ext = ''
    try {
        $name = [System.IO.Path]::GetFileName($normalized)
        $ext = [System.IO.Path]::GetExtension($normalized)
    }
    catch {
        $name = ''
        $ext = ''
    }

    if ($name -in @('mcp.json','.mcp.json','claude_desktop_config.json') -and $normalized -match '\\\.codex\\plugins\\cache\\') {
        return 'cached-ai-config'
    }
    if ($name -in @('mcp.json','.mcp.json','claude_desktop_config.json')) {
        return 'active-ai-config'
    }
    if ($name -eq 'settings.json' -and $normalized -match '\\(\.cursor|\.claude|\.windsurf|\.continue|\.gemini|\.opencode|cursor\\user|windsurf\\user|code(?: - insiders)?\\user|vscodium\\user|positron\\user)\\') {
        return 'active-ai-config'
    }
    if ($normalized -match '\\(\.continue|\.gemini|\.opencode)\\' -and $ext -in @('.json','.jsonc','.toml','.yaml','.yml')) {
        return 'active-ai-config'
    }
    if ($name -in @('agents.md','agents.override.md','claude.md','gemini.md','copilot-instructions.md','.cursorrules') -or
        $normalized -match '\\.cursor\\rules\\.*\.mdc?$' -or
        $normalized -match '\\.github\\instructions\\.*\.instructions\.md$') {
        return 'active-ai-instruction'
    }

    $isCodexPath = ($normalized -match '\\\.codex(\\|$)')
    if (-not $isCodexPath) {
        if ($normalized -match '\\(\.cursor|\.claude|\.windsurf|\.continue|\.gemini|\.opencode)\\') {
            if ($ext -in @('.json','.toml','.yaml','.yml')) {
                return 'active-ai-config'
            }
            if ($ext -in @('.md','.markdown','.rst','.txt','.adoc')) {
                return 'reference-text'
            }
        }
        return 'normal'
    }

    if ($normalized -match '\\\.codex\\config\.toml$') { return 'active-ai-config' }
    if ($normalized -match '\\\.codex\\agents\\[^\\]+\.toml$') { return 'active-ai-config' }
    if ($normalized -match '\\\.codex\\plugins\\cache\\.*\\\.codex-plugin\\plugin\.json$') { return 'plugin-metadata' }
    if ($normalized -match '\\\.codex\\(skills|vendor_imports\\skills)\\.*\\scripts\\' -and $ext -in @('.ps1','.py','.js','.mjs','.cjs','.sh','.bash','.zsh','.cmd','.bat')) {
        return 'executable-tooling'
    }
    if ($normalized -match '\\\.codex\\plugins\\cache\\' -and $ext -in @('.ps1','.py','.js','.mjs','.cjs','.sh','.bash','.zsh','.cmd','.bat')) {
        return 'executable-tooling'
    }
    if ($normalized -match '\\\.codex\\sessions\\.*\.jsonl$') { return 'session-log' }
    if ($normalized -match '\\\.codex\\cache\\') { return 'cache-data' }
    if ($normalized -match '\\\.codex\\models_cache\.json$') { return 'cache-data' }
    if ($normalized -match '\\\.codex\\plugins\\cache\\') { return 'cache-data' }
    if ($normalized -match '\\\.codex\\(skills|vendor_imports\\skills|references|docs)\\') { return 'reference-text' }
    if ($name -match '^(readme|license|licence|changelog|changes|notice|skill)(\..*)?$') { return 'reference-text' }
    if ($ext -in @('.md','.markdown','.rst','.txt','.adoc')) { return 'reference-text' }
    return 'normal'
}

function Get-FindingPathType {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return 'virtual'
    }
    try {
        if (Test-Path -LiteralPath $CandidatePath -PathType Leaf) { return 'file' }
        if (Test-Path -LiteralPath $CandidatePath -PathType Container) { return 'directory' }
    }
    catch {
    }
    if ($CandidatePath -match '^[A-Za-z]:\\|^\\\\|[\\/]') {
        return 'unknown'
    }
    return 'virtual'
}

function Test-IsJetBrainsPluginPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return $false }
    $normalized = $CandidatePath.ToLowerInvariant() -replace '/', '\'
    if ($normalized -match '\\jetbrains\\(?:[^\\]+\\)*plugins(?:\\|$)') { return $true }
    return ($normalized -match '\\\.(idea|intellijidea|pycharm|webstorm|phpstorm|rubymine|clion|datagrip|goland|rider|androidstudio)[^\\]*\\config\\plugins(?:\\|$)')
}

function Test-IsVsCodeStyleExtensionPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return $false }
    $normalized = $CandidatePath.ToLowerInvariant() -replace '/', '\'
    return ($normalized -match '\\(\.vscode|\.vscode-insiders|\.vscode-server|\.cursor)\\extensions(?:\\|$)')
}

function Test-IsNodeModulesPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return $false }
    $normalized = $CandidatePath.ToLowerInvariant() -replace '/', '\'
    return ($normalized -match '\\node_modules(?:\\|$)')
}

function Test-IsKnownSetuptoolsDistutilsPrecedenceHook {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or $File.Name.ToLowerInvariant() -ne 'distutils-precedence.pth' -or [string]::IsNullOrWhiteSpace($Text)) { return $false }
    $normalized = (($Text.Trim()) -replace '\s+', ' ')
    return ($normalized -eq "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim();")
}

function Get-JetBrainsPluginAggregateRoot {
    param([string]$CandidatePath)
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return 'JetBrains plugins' }
    $normalized = $CandidatePath -replace '/', '\'
    $match = [regex]::Match($normalized, '^(.*?\\plugins)(?:\\([^\\]+))?', 'IgnoreCase')
    if ($match.Success) {
        if (-not [string]::IsNullOrEmpty($match.Groups[2].Value)) {
            return ($match.Groups[1].Value + '\' + $match.Groups[2].Value)
        }
        return $match.Groups[1].Value
    }
    return $normalized
}

function Register-JetBrainsRoot {
    param([string]$RootPath)
    if ([string]::IsNullOrWhiteSpace($RootPath) -or $null -eq $script:Context) { return }
    try { $key = [System.IO.Path]::GetFullPath($RootPath).ToLowerInvariant() }
    catch { $key = $RootPath.ToLowerInvariant() }
    if (-not $script:Context.jetBrainsRootsSeen.ContainsKey($key)) {
        $script:Context.jetBrainsRootsSeen[$key] = $true
        Add-ScanStat -Name 'jetBrainsRootsFound'
    }
}

function Get-SourceContextUncached {
    param([string]$CandidatePath)
    if (Test-IsJetBrainsPluginPath $CandidatePath) { return 'jetbrains-plugin' }
    if (Test-IsScannerSelfIocReferencePath $CandidatePath) { return 'scanner-self' }
    if (Test-IsScannerArtifactUntrustedPath $CandidatePath) { return 'scanner-artifact-untrusted' }
    $artifactInfo = Get-ScannerArtifactInfo $CandidatePath
    if ($null -ne $artifactInfo) {
        Register-ScannerArtifactRoot -RootPath ([string]$artifactInfo.root)
        if ([bool]$artifactInfo.isSample) { return 'scanner-artifact-sample' }
        return 'scanner-artifact'
    }
    if (Test-IsSyntheticSampleUntrustedPath $CandidatePath) { return 'synthetic-sample-untrusted' }
    if (Test-IsPathUnderOwnSyntheticSamples $CandidatePath) { return 'synthetic-sample' }
    if (Test-IsNpmCacheBlobPath $CandidatePath) { return 'cache' }
    if (Test-IsDependencyMetadataPath $CandidatePath) { return 'dependency-metadata' }
    $aiRole = Get-AiPathRole $CandidatePath
    if ($aiRole -ne 'normal') { return $aiRole }
    return 'normal'
}

function Get-SourceContext {
    param([string]$CandidatePath)
    if ($null -eq $script:Context -or $null -eq $script:Context.sourceContextCache -or [string]::IsNullOrWhiteSpace($CandidatePath)) {
        return (Get-SourceContextUncached $CandidatePath)
    }
    $fullPath = Get-FullPathSafe $CandidatePath
    $cacheKey = if ([string]::IsNullOrEmpty($fullPath)) { $CandidatePath.ToLowerInvariant() } else { $fullPath.ToLowerInvariant() }
    if ($script:Context.sourceContextCache.ContainsKey($cacheKey)) {
        return [string]$script:Context.sourceContextCache[$cacheKey]
    }
    $sourceContext = Get-SourceContextUncached $CandidatePath
    $script:Context.sourceContextCache[$cacheKey] = [string]$sourceContext
    return $sourceContext
}

function Add-ScanStat {
    param([string]$Name, [int]$Amount = 1, [string]$FilePath)
    if ($null -eq $script:Context -or $null -eq $script:Context.scanStats) {
        return
    }
    if ($null -eq $script:AllowedScanStatNames) {
    $allowedStats = @(
        'filesEnumerated',
        'filesScanned',
        'filesSkipped',
        'likelyBinaryFilesSkipped',
        'compressedFilesSkipped',
        'syntheticSamplesSkipped',
        'cacheFilesSkipped',
        'cacheBlobDirectoriesSkipped',
        'encodingFallbackAggregated',
        'unicodeVariationSelectorsAggregated',
        'scannerFileErrors',
        'regexMatchTimeouts',
        'codexReferenceRiskAggregated',
        'codexSessionRiskAggregated',
        'codexCacheRiskAggregated',
        'codexPluginMetadataRiskAggregated',
        'aiTokenReferenceAggregated',
        'aiReferenceExecutableSampleAggregated',
        'capabilityFindingsAggregated',
        'scannerArtifactRootsFound',
        'scannerArtifactSamplesSkipped',
        'scannerArtifactIocReferencesAggregated',
        'scannerReportArtifactsSkipped',
        'syntheticSampleKnownSkipped',
        'syntheticSampleUnexpectedFiles',
        'syntheticSampleHashMismatches',
        'npmGlobalRootsFound',
        'npmGlobalPackagesChecked',
        'npmCacheRootsFound',
        'npmCacheMetadataFilesScanned',
        'npmCacheMetadataFilesSkipped',
        'npmCacheMetadataLimitReached',
        'npmCacheAccessDenied',
        'npmTargetedPackagesInspected',
        'npmTargetedEntrypointsQueued',
        'npmTargetedEntrypointResolutionFailures',
        'githubActionMutableRefs',
        'githubActionOfficialMutableRefs',
        'wasmArtifactsFound',
        'uniqueFilesQueued',
        'projectRootsDiscovered',
        'projectDiscoveryDirectoriesVisited',
        'projectDiscoveryLimitReached',
        'targetedDependencyFilesQueued',
        'targetedDependencyFilesSkippedByBudget',
        'deepDirectoriesEntered',
        'deepFilesQueued',
        'jetBrainsRootsFound',
        'jetBrainsPluginsInspected',
        'jetBrainsArchivesInspected',
        'jetBrainsArchiveEntriesInspected',
        'jetBrainsArchivesSkipped',
        'jetBrainsNativeArtifacts',
        'nodeRuntimeCandidatesFound',
        'nodeRuntimePriorityFilesQueued',
        'nodeRuntimeFilesSkippedByBudget',
        'nodeRuntimeBinariesInspected',
        'nodeRuntimeVersionReferencesInspected',
        'nodeRuntimeUnresolvedReferences',
        'nodeRuntimeCriticalMatches',
        'nodeRuntimeHighMatches',
        'nodeRuntimeVersionReadFailures',
        'nodeRuntimeInstalledVersionsEvaluated',
        'nodeRuntimeInstalledVulnerableVersions',
        'nodeRuntimeInstalledNotAffectedVersions',
        'nodeRuntimeProjectVersionsEvaluated',
        'nodeRuntimeProjectVulnerableReferences',
        'nodeRuntimeProjectNotAffectedReferences',
        'nodeRuntimeInventoryEntriesOmitted',
        'campaignPackagesLoaded',
        'campaignPackageVersionPairsLoaded',
        'packageIocIndexEntries',
        'packageIocDuplicatesMerged',
        'packageLockStructuralScans',
        'packageLockEntriesEvaluated',
        'packageLockFallbacks',
        'incidentHashCandidates',
        'securityUpdateCandidatesQueued',
        'securityUpdateCandidatesAnalyzed',
        'securityUpdateAnalysisLimits',
        'fileHashComputations',
        'pythonDistributionHeadersRead',
        'incidentScriptReferencesResolved',
        'criticalCandidateFailures',
        'nonCriticalCandidateFailures',
        'criticalDirectoryFailures',
        'nonCriticalDirectoryFailures',
        'coverageRetryAttempts',
        'coverageRetryResolved'
    )
    $script:AllowedScanStatNames=@{}
    foreach ($statName in $allowedStats) { $script:AllowedScanStatNames[$statName]=$true }
    }
    if (-not $script:AllowedScanStatNames.ContainsKey($Name)) {
        return
    }
    if ($Name -in @('filesEnumerated','filesSkipped')) {
        $eventName=if ($Name -eq 'filesEnumerated') { 'fileEnumerationEvents' } else { 'fileSkipEvents' }
        $script:Context.scanStats[$eventName]=[int]$script:Context.scanStats[$eventName]+$Amount
    }
    if ($Name -in @('filesEnumerated','filesScanned','filesSkipped','syntheticSamplesSkipped','syntheticSampleKnownSkipped','likelyBinaryFilesSkipped','compressedFilesSkipped','cacheFilesSkipped')) {
        if ([string]::IsNullOrEmpty($FilePath)) { $FilePath=$script:CurrentFileStatPath }
        if (-not [string]::IsNullOrEmpty($FilePath)) {
            if ($null -eq $script:StatPathSets) { $script:StatPathSets=@{} }
            if (-not $script:StatPathSets.ContainsKey($Name)) { $script:StatPathSets[$Name]=@{} }
            $statKey=[IO.Path]::GetFullPath($FilePath).ToLowerInvariant()
            if ($script:StatPathSets[$Name].ContainsKey($statKey)) { return }
            $script:StatPathSets[$Name][$statKey]=$true
        }
    }
    $script:Context.scanStats[$Name] = [int]$script:Context.scanStats[$Name] + $Amount
}

function Get-DefaultRiskType {
    param([string]$Category, [string]$Severity)
    if ([string]::IsNullOrEmpty($Category)) { return 'posture' }
    if ($Category -match '^NODE_RUNTIME_VULNERABILITY') { return 'vulnerability' }
    if ($Category -match '(_LIMIT_REACHED$|^MAX_FILES_REACHED$|^NPM_GLOBAL_STATIC_READ_LIMITATION$)') { return 'limitation' }
    if ($Category -match '^(KNOWN_|DNS_CACHE_IOC|EVENT_LOG_IOC)') { return 'known-ioc' }
    if ($Category -match '(SECRET_EXFIL|SECRET_HARVEST|TOKEN_PATH_EXFIL|AI_TOKEN_PATH_EXFIL)') { return 'active-exfil' }
    if ($Category -match '(EXTERNAL_EXECUTION|FETCH_EXECUTE|PTH_EXECUTION|CUSTOMIZE_SUSPICIOUS|COMPOSER_SUSPICIOUS_EXECUTION)') { return 'fetch-execute' }
    if ($Category -match '(CAPABILITY|AUTHORIZED_API_CLIENT|REMOTE_INSTALL_OR_WRITE)') { return 'capability' }
    if ($Category -match '(UNPINNED|PERMISSION|PULL_REQUEST_TARGET|CONTENTS_WRITE|ID_TOKEN_WRITE|MANUAL_TRIGGER|SCHEDULED_TRIGGER|LIFECYCLE_SCRIPT|NATIVE_ARTIFACT|ACTIVATION_EVENTS|INVISIBLE_UNICODE)') { return 'posture' }
    if ($Category -match '(ACCESS_DENIED|SKIPPED|FAILED|UNAVAILABLE|PATH_TOO_LONG|SCANNER_FILE_ERROR|SCANNER_ERROR|AGGREGATED)') { return 'limitation' }
    if ($Category -match '(SECRET_FILE_PRESENT|ENV_SECRET_NAME|STARTUP_FILE_PRESENT|REPARSE_POINT)') { return 'inventory' }
    if ($Severity -eq 'DANGER') { return 'posture' }
    if ($Severity -eq 'INFO' -or $Severity -eq 'OK') { return 'limitation' }
    return 'posture'
}

function Get-DefaultConfidence {
    param([string]$Category, [string]$Severity, [string]$RiskType)
    if ($RiskType -in @('known-ioc','active-exfil')) { return 'high' }
    if ($Category -match '^(MCP_AGENT_EXTERNAL_EXECUTION|GITHUB_ACTIONS_EXTERNAL_EXECUTION|PACKAGE_LIFECYCLE_EXTERNAL_EXECUTION|PYTHON_PTH_EXECUTION_HOOK|INVISIBLE_UNICODE_EXECUTION_COMPOUND)$') { return 'high' }
    if ($Severity -eq 'DANGER') { return 'high' }
    if ($RiskType -eq 'capability') {
        if ($Severity -eq 'WARN') { return 'medium' }
        return 'low'
    }
    if ($Severity -eq 'WARN') { return 'medium' }
    return 'low'
}

function Get-DefaultCheckForFinding {
    param([string]$Category, [string]$SourceContext)
    if ([string]::IsNullOrEmpty($Category)) { return 'ScannerSelf' }
    if ($Category -match '^NODE_RUNTIME') { return 'NodeRuntime' }
    if ($Category -match '^NPM_GLOBAL') { return 'NpmGlobal' }
    if ($Category -match '^NPM_CACHE') { return 'NpmCache' }
    if ($Category -match '^(KNOWN_COMPROMISED_PACKAGE|PACKAGE_|PYTHON_|COMPOSER_|NPM_INCIDENT_WATCHLIST|NPM_INCIDENT_MARKER|KNOWN_IOC_TEXT_PATTERN|KNOWN_IOC_REFERENCE_TEXT|LOCAL_)') {
        if ($Category -match '(LIFECYCLE|PTH|CUSTOMIZE|AUTOLOAD|SETUP|CODE_|DEV_TOOL_PERSISTENCE)') { return 'LifecycleScripts' }
        return 'Packages'
    }
    if ($Category -match '^(INVISIBLE_UNICODE|UNICODE_|GLASSWORM_)') { return 'InvisibleUnicode' }
    if ($Category -match '^GITHUB_ACTIONS') { return 'CiCd' }
    if ($Category -match '^(WORKSPACE_HOOK|HOOK_|TASK_)') { return 'HooksAndTasks' }
    if ($Category -match '^(MCP_|AI_)') { return 'AiMcp' }
    if ($Category -match '^(IDE_EXTENSION|KNOWN_SUSPICIOUS_IDE_EXTENSION)') { return 'IdeExtensions' }
    if ($Category -match '^(SECRET_FILE_PRESENT)') { return 'SecretsInventory' }
    if ($Category -match '^(SCANNER_|OWN_SYNTHETIC|SYNTHETIC_|DEFAULT_PATH_USED|SCAN_COMPLETED|MAJOR_LOCATION|USERPROFILE_NOT_AVAILABLE|PATH_NOT_FOUND|ACCESS_DENIED|REPARSE_POINT|MAX_FILES|FILE_INFO|TEXT_|IOC_|KNOWN_FILE_IOC|KNOWN_SUSPICIOUS_FILE)') { return 'ScannerSelf' }
    if ($SourceContext -in @('active-ai-config','cached-ai-config','executable-tooling','reference-text','session-log','cache-data','plugin-metadata')) { return 'AiMcp' }
    return 'ScannerSelf'
}

function Get-DefaultDetectionMethod {
    param([string]$Category, [string]$SourceContext)
    if ($Category -match '^NPM_GLOBAL') { return 'static-path' }
    if ($Category -match '^NPM_CACHE') { return 'metadata' }
    if ($Category -match '^(SECRET_FILE_PRESENT|MCP_AGENT_ENV_SECRET_NAME|STARTUP_FILE_PRESENT)') { return 'inventory' }
    if ($Category -match '^(DNS_CACHE|EVENT_LOG|RUN_KEY|SCHEDULED_TASK|POWERSHELL_HISTORY|ENDPOINT_)') { return 'telemetry-opt-in' }
    if ($Category -match '(AGGREGATED|SKIPPED|LIMIT|UNAVAILABLE|ACCESS_DENIED|FAILED)') { return 'metadata' }
    if ($SourceContext -eq 'cache' -or $SourceContext -eq 'dependency-metadata') { return 'metadata' }
    return 'static-file'
}

function ConvertTo-SafeVulnerabilityDetails {
    param($Value)
    if ($null -eq $Value) { return $null }

    $ids = New-ArrayList
    foreach ($idValue in @((Get-PropertyValue $Value 'advisoryIds'))) {
        $id = ([string]$idValue).ToUpperInvariant()
        if ($id -match '^CVE-[0-9]{4}-[0-9]{4,7}$' -and $ids.Count -lt 20) {
            Add-ListItem $ids $id
        }
    }
    $upstreamSeverity = ([string](Get-PropertyValue $Value 'upstreamSeverity')).ToUpperInvariant()
    if ($upstreamSeverity -notin @('CRITICAL','HIGH')) { $upstreamSeverity = '' }
    $detectedVersion = [string](Get-PropertyValue $Value 'detectedVersion')
    if ($detectedVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') { $detectedVersion = '' }
    $fixedVersion = [string](Get-PropertyValue $Value 'fixedVersionForMajor')
    if ($fixedVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') { $fixedVersion = '' }
    $evidenceKind = [string](Get-PropertyValue $Value 'evidenceKind')
    if ($evidenceKind -notin @('installed-binary-metadata','version-manager-pin','container-image-pin','ci-runtime-pin','manifest-constraint')) {
        $evidenceKind = ''
    }
    $conditionStatus = [string](Get-PropertyValue $Value 'conditionStatus')
    if ($conditionStatus -notin @('not-required','matched','partial','unknown')) { $conditionStatus = 'unknown' }

    return [ordered]@{
        advisoryIds = @($ids.ToArray())
        upstreamSeverity = $upstreamSeverity
        detectedVersion = $detectedVersion
        evidenceKind = $evidenceKind
        fixedVersionForMajor = $fixedVersion
        conditionStatus = $conditionStatus
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory=$true)][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Title,
        [string]$Path,
        $Line,
        [string]$Evidence,
        [string]$Recommendation,
        [string]$PathType,
        [string]$SourceContext,
        [string]$RiskType,
        [string]$Confidence,
        [string]$Check,
        [string]$DetectionMethod,
        $Vulnerability,
        [string]$RuleId,
        [string]$SourceId,
        [string]$UpstreamSeverity
    )

    if ($null -eq $script:Context) {
        return
    }

    $allowed = $script:SeverityOrder
    if ($allowed -notcontains $Severity) {
        $Severity = 'INFO'
    }

    $redactedPath = ConvertTo-RedactedPath $Path
    $redactedEvidence = Redact-SecretLikeText $Evidence
    $redactedRecommendation = Redact-SecretLikeText $Recommendation
    if ([string]::IsNullOrEmpty($PathType)) {
        $PathType = Get-FindingPathType $Path
    }
    if ([string]::IsNullOrEmpty($SourceContext)) {
        $SourceContext = Get-SourceContext $Path
    }
    if ([string]::IsNullOrEmpty($RiskType)) {
        $RiskType = Get-DefaultRiskType -Category $Category -Severity $Severity
    }
    if ($RiskType -notin @('known-ioc','active-exfil','fetch-execute','capability','posture','limitation','inventory','vulnerability')) {
        $RiskType = Get-DefaultRiskType -Category $Category -Severity $Severity
    }
    if ([string]::IsNullOrEmpty($Confidence)) {
        $Confidence = Get-DefaultConfidence -Category $Category -Severity $Severity -RiskType $RiskType
    }
    if ($Confidence -notin @('high','medium','low')) {
        $Confidence = Get-DefaultConfidence -Category $Category -Severity $Severity -RiskType $RiskType
    }
    if ([string]::IsNullOrEmpty($Check)) {
        $Check = Get-DefaultCheckForFinding -Category $Category -SourceContext $SourceContext
    }
    if ($Check -notin $script:LeafCheckOrder) {
        $Check = Get-DefaultCheckForFinding -Category $Category -SourceContext $SourceContext
    }
    if ([string]::IsNullOrEmpty($DetectionMethod)) {
        $DetectionMethod = Get-DefaultDetectionMethod -Category $Category -SourceContext $SourceContext
    }
    if ($DetectionMethod -notin @('static-file','static-path','metadata','inventory','telemetry-opt-in')) {
        $DetectionMethod = Get-DefaultDetectionMethod -Category $Category -SourceContext $SourceContext
    }
    $safeVulnerability = ConvertTo-SafeVulnerabilityDetails $Vulnerability
    $vulnerabilityKey = ''
    if ($null -ne $safeVulnerability) {
        $vulnerabilityKey = [string]::Join(',', [string[]]@($safeVulnerability.advisoryIds)) + '|' +
            [string]$safeVulnerability.upstreamSeverity + '|' + [string]$safeVulnerability.detectedVersion + '|' +
            [string]$safeVulnerability.evidenceKind + '|' + [string]$safeVulnerability.fixedVersionForMajor + '|' +
            [string]$safeVulnerability.conditionStatus
    }
    if ($RiskType -eq 'capability' -and $Severity -in @('WARN','CAUTION') -and $SourceContext -ne 'active-ai-config' -and $null -ne $script:Context.capabilityFindingCountsByRoot) {
        $capabilityRoot = Get-CapabilityRoot -Path $redactedPath
        if ([string]::IsNullOrEmpty($capabilityRoot)) {
            $capabilityRoot = 'unknown'
        }
        if (-not $script:Context.capabilityFindingCountsByRoot.ContainsKey($capabilityRoot)) {
            $script:Context.capabilityFindingCountsByRoot[$capabilityRoot] = 0
        }
        $countForRoot = [int]$script:Context.capabilityFindingCountsByRoot[$capabilityRoot]
        if ($countForRoot -ge 3) {
            Add-ScanStat -Name 'capabilityFindingsAggregated'
            return
        }
        $script:Context.capabilityFindingCountsByRoot[$capabilityRoot] = $countForRoot + 1
    }
    $dedupeKey = [string]::Join('|', @(
        $Severity,
        $Category,
        $Title,
        $redactedPath,
        $redactedEvidence,
        $SourceContext,
        $RiskType,
        $Confidence,
        $Check,
        $DetectionMethod,
        $vulnerabilityKey
    ))
    if ($null -ne $script:Context.findingKeys -and $script:Context.findingKeys.ContainsKey($dedupeKey)) {
        return
    }
    if ($null -ne $script:Context.findingKeys) {
        $script:Context.findingKeys[$dedupeKey] = $true
    }

    $finding = [ordered]@{
        severity = $Severity
        category = $Category
        title = $Title
        path = $redactedPath
        pathType = $PathType
        line = $null
        sourceContext = $SourceContext
        check = $Check
        detectionMethod = $DetectionMethod
        riskType = $RiskType
        confidence = $Confidence
        vulnerability = $safeVulnerability
        evidence = $redactedEvidence
        recommendation = $redactedRecommendation
    }
    if ($RuleId -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') { $finding['ruleId'] = $RuleId }
    if ($SourceId -cmatch '^S[0-9]{2}$') { $finding['sourceId'] = $SourceId }
    if ($UpstreamSeverity -in @('CRITICAL','HIGH','MODERATE','MEDIUM','LOW')) { $finding['upstreamSeverity'] = $UpstreamSeverity.ToUpperInvariant() }
    if ($null -ne $Line) {
        try {
            $lineValue = [int]$Line
            if ($lineValue -gt 0) {
                $finding.line = $lineValue
            }
        }
        catch {
        }
    }
    Add-ListItem $script:Context.findings $finding
}

function Add-Limitation {
    param([string]$Text)
    if ($null -ne $script:Context -and -not [string]::IsNullOrEmpty($Text)) {
        Add-ListItem $script:Context.limitations $Text
    }
}

function Test-IsOwnSyntheticSamplePath {
    param([string]$CandidatePath)
    if (-not $script:SkipOwnSyntheticSamples -or [string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    if (-not (Test-IsPathUnderOwnSyntheticSamples $CandidatePath)) {
        return $false
    }
    try {
        if (Test-Path -LiteralPath $CandidatePath -PathType Container) {
            return $false
        }
    }
    catch {
        return $false
    }

    $relativePath = Get-OwnSyntheticSampleRelativePath $CandidatePath
    if ([string]::IsNullOrEmpty($relativePath)) {
        return $false
    }

    $manifest = $script:Context.ownSyntheticSampleManifest
    $manifestStatus = [string]$script:Context.syntheticSampleManifestStatus
    if ($relativePath -ieq 'manifest.json') {
        if ($manifestStatus -eq 'valid') {
            return $true
        }
        Mark-SyntheticSampleUntrusted $CandidatePath
        return $false
    }

    if ($manifestStatus -eq 'missing') {
        [void](Register-SyntheticSampleUntrusted $CandidatePath)
        Add-Finding -Severity 'WARN' -Category 'OWN_SYNTHETIC_SAMPLE_MANIFEST_MISSING' -Title 'Scanner synthetic sample manifest is missing' -Path $CandidatePath -SourceContext 'synthetic-sample-untrusted' -Evidence 'Known fixture skip was disabled because tests/samples/manifest.json was not found.' -Recommendation 'Scan proceeded normally to avoid hiding unexpected files.'
        return $false
    }
    if ($manifestStatus -ne 'valid') {
        [void](Register-SyntheticSampleUntrusted $CandidatePath)
        Add-Finding -Severity 'WARN' -Category 'OWN_SYNTHETIC_SAMPLE_MANIFEST_INVALID' -Title 'Scanner synthetic sample manifest is invalid' -Path $CandidatePath -SourceContext 'synthetic-sample-untrusted' -Evidence 'Known fixture skip was disabled because tests/samples/manifest.json could not be trusted.' -Recommendation 'Fix the manifest or scan tests/samples explicitly for validation.'
        return $false
    }

    $key = Normalize-SampleManifestKey $relativePath
    $entry = $null
    if ($null -ne $manifest -and $null -ne $manifest.entries -and $manifest.entries.ContainsKey($key)) {
        $entry = $manifest.entries[$key]
    }
    if ($null -eq $entry) {
        $firstUntrusted = Register-SyntheticSampleUntrusted $CandidatePath
        if ($firstUntrusted) {
            Add-ScanStat -Name 'syntheticSampleUnexpectedFiles'
        }
        Add-Finding -Severity 'WARN' -Category 'OWN_SYNTHETIC_SAMPLE_UNEXPECTED_FILE' -Title 'Unexpected file found under scanner synthetic samples' -Path $CandidatePath -SourceContext 'synthetic-sample-untrusted' -Evidence ("Unexpected own synthetic sample file: {0}" -f $relativePath) -Recommendation 'The file was scanned normally because it is not listed in the trusted synthetic sample manifest.'
        return $false
    }
    if (-not [bool]$entry.skipInParentScan) {
        return $false
    }

    $hashMode = [string]$entry.hashMode
    if ($hashMode -eq 'presence-only') {
        return $true
    }

    $actualHash = $null
    if ($hashMode -eq 'text-lf-sha256') {
        $actualHash = Get-TextLfSha256ForFile $CandidatePath
    }
    elseif ($hashMode -eq 'bytes-sha256') {
        $actualHash = Get-BytesSha256ForFile $CandidatePath
    }
    if ([string]::IsNullOrEmpty($actualHash) -or $actualHash.ToLowerInvariant() -ne ([string]$entry.sha256).ToLowerInvariant()) {
        $firstUntrusted = Register-SyntheticSampleUntrusted $CandidatePath
        if ($firstUntrusted) {
            Add-ScanStat -Name 'syntheticSampleHashMismatches'
        }
        Add-Finding -Severity 'WARN' -Category 'OWN_SYNTHETIC_SAMPLE_HASH_MISMATCH' -Title 'Scanner synthetic sample file differs from manifest' -Path $CandidatePath -SourceContext 'synthetic-sample-untrusted' -Evidence ("Synthetic fixture hash mismatch: {0}; mode={1}" -f $relativePath, $hashMode) -Recommendation 'The file was scanned normally because it no longer matches the trusted synthetic fixture manifest.'
        return $false
    }

    return $true
}

function Test-IsVerifiedScannerArtifactSamplePath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    if ($script:Context.syntheticSamplesExplicit) {
        return $false
    }
    if ([string]$script:Context.distributionStatus -eq 'script-only') {
        return $false
    }

    $artifact = Get-ScannerArtifactInfo $CandidatePath
    if ($null -eq $artifact -or -not [bool]$artifact.isSample) {
        return $false
    }
    Register-ScannerArtifactRoot -RootPath ([string]$artifact.root)

    $relativePath = [string]$artifact.relativePath
    if ([string]::IsNullOrEmpty($relativePath)) {
        return $false
    }
    if (-not (Test-IsSafeManifestRelativePath $relativePath)) {
        [void](Register-ScannerArtifactUntrustedPath $CandidatePath)
        Add-Finding -Severity 'WARN' -Category 'SCANNER_ARTIFACT_SAMPLE_UNSAFE_PATH' -Title 'External scanner artifact sample path is unsafe' -Path $CandidatePath -SourceContext 'scanner-artifact-untrusted' -Evidence 'External scanner sample path could not be mapped to a safe manifest relative path.' -Recommendation 'The file was scanned normally because it is not trusted fixture content.'
        return $false
    }

    $manifest = $script:Context.ownSyntheticSampleManifest
    $manifestStatus = [string]$script:Context.syntheticSampleManifestStatus
    if ($manifestStatus -ne 'valid' -or $null -eq $manifest -or $null -eq $manifest.entries) {
        [void](Register-ScannerArtifactUntrustedPath $CandidatePath)
        Add-Finding -Severity 'WARN' -Category 'SCANNER_ARTIFACT_SAMPLE_SKIP_DISABLED' -Title 'External scanner artifact sample skip is disabled' -Path $CandidatePath -SourceContext 'scanner-artifact-untrusted' -Evidence ("Current scanner manifest status is {0}; external artifact manifests are not trusted." -f $manifestStatus) -Recommendation 'The file was scanned normally to avoid hiding untrusted content.'
        return $false
    }

    $key = Normalize-SampleManifestKey $relativePath
    $entry = $null
    if ($manifest.entries.ContainsKey($key)) {
        $entry = $manifest.entries[$key]
    }
    if ($null -eq $entry -or -not [bool]$entry.skipInParentScan) {
        $first = Register-ScannerArtifactUntrustedPath $CandidatePath
        if ($first) {
            Add-ScanStat -Name 'syntheticSampleUnexpectedFiles'
        }
        Add-Finding -Severity 'WARN' -Category 'SCANNER_ARTIFACT_SAMPLE_UNEXPECTED_FILE' -Title 'Unexpected file found under external scanner artifact samples' -Path $CandidatePath -SourceContext 'scanner-artifact-untrusted' -Evidence ("External scanner sample file is not in the current trusted fixture manifest: {0}" -f $relativePath) -Recommendation 'The file was scanned normally because external scanner artifact manifests are not trusted.'
        return $false
    }

    $hashMode = [string]$entry.hashMode
    if ($hashMode -eq 'presence-only') {
        Add-ScanStat -Name 'scannerArtifactSamplesSkipped'
        return $true
    }

    $actualHash = $null
    if ($hashMode -eq 'text-lf-sha256') {
        $actualHash = Get-TextLfSha256ForFile $CandidatePath
    }
    elseif ($hashMode -eq 'bytes-sha256') {
        $actualHash = Get-BytesSha256ForFile $CandidatePath
    }
    if ([string]::IsNullOrEmpty($actualHash) -or $actualHash.ToLowerInvariant() -ne ([string]$entry.sha256).ToLowerInvariant()) {
        $firstMismatch = Register-ScannerArtifactUntrustedPath $CandidatePath
        if ($firstMismatch) {
            Add-ScanStat -Name 'syntheticSampleHashMismatches'
        }
        Add-Finding -Severity 'WARN' -Category 'SCANNER_ARTIFACT_SAMPLE_HASH_MISMATCH' -Title 'External scanner artifact sample differs from current manifest' -Path $CandidatePath -SourceContext 'scanner-artifact-untrusted' -Evidence ("External scanner sample hash mismatch: {0}; mode={1}" -f $relativePath, $hashMode) -Recommendation 'The file was scanned normally because it does not match the current trusted fixture hash.'
        return $false
    }

    Add-ScanStat -Name 'scannerArtifactSamplesSkipped'
    return $true
}

function Test-IsExplicitOwnSyntheticSampleRoot {
    param([string]$RootPath)
    return (Test-IsPathUnderOwnSyntheticSamples $RootPath)
}

function Resolve-ReportOutputPath {
    param([string]$CandidatePath, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
        throw ("{0} report output path is empty." -f $Label)
    }
    try {
        return [System.IO.Path]::GetFullPath($CandidatePath)
    }
    catch {
        throw ("{0} report output path is invalid." -f $Label)
    }
}

function Get-AvailableDefaultReportPath {
    param(
        [string]$OutputDirectory,
        [string]$Stamp,
        [string]$Extension,
        [string]$OccupiedPath
    )
    foreach ($attempt in 0..9999) {
        $suffix = if ($attempt -eq 0) { '' } else { "-$attempt" }
        $candidate = Resolve-ReportOutputPath -CandidatePath (Join-Path $OutputDirectory ("dev-supplychain-report-{0}{1}.{2}" -f $Stamp,$suffix,$Extension)) -Label $Extension.ToUpperInvariant()
        if (-not [string]::IsNullOrEmpty($OccupiedPath) -and $candidate.Equals($OccupiedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        if (-not (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    throw ("No unused default {0} report output path was available." -f $Extension.ToUpperInvariant())
}

function New-ReportPaths {
    $outputDir = $ReportDir
    if ([string]::IsNullOrEmpty($outputDir)) {
        $outputDir = Join-Path $script:BaseDir 'reports'
    }
    try {
        $outputDir = [System.IO.Path]::GetFullPath($outputDir)
    }
    catch {
        throw 'Report directory path is invalid.'
    }
    if ((Test-Path -LiteralPath $outputDir) -and -not (Test-Path -LiteralPath $outputDir -PathType Container)) {
        throw 'Report directory path points to an existing non-directory item.'
    }
    if (-not (Test-Path -LiteralPath $outputDir -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($outputDir)
    }

    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $textPath = $null
    $jsonPath = $null
    if (-not [string]::IsNullOrWhiteSpace($TextOut)) {
        $textPath = Resolve-ReportOutputPath -CandidatePath $TextOut -Label 'TXT'
    }
    if (-not [string]::IsNullOrWhiteSpace($JsonOut)) {
        $jsonPath = Resolve-ReportOutputPath -CandidatePath $JsonOut -Label 'JSON'
    }
    if (-not [string]::IsNullOrEmpty($textPath) -and -not [string]::IsNullOrEmpty($jsonPath) -and $textPath.Equals($jsonPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'TXT and JSON report output paths must be different.'
    }
    if (-not [string]::IsNullOrEmpty($textPath) -and (Test-Path -LiteralPath $textPath)) {
        throw 'TXT report output path already exists. Existing files are never overwritten.'
    }
    if (-not [string]::IsNullOrEmpty($jsonPath) -and (Test-Path -LiteralPath $jsonPath)) {
        throw 'JSON report output path already exists. Existing files are never overwritten.'
    }
    if ([string]::IsNullOrEmpty($textPath)) {
        $textPath = Get-AvailableDefaultReportPath -OutputDirectory $outputDir -Stamp $stamp -Extension 'txt' -OccupiedPath $jsonPath
    }
    if ([string]::IsNullOrEmpty($jsonPath)) {
        $jsonPath = Get-AvailableDefaultReportPath -OutputDirectory $outputDir -Stamp $stamp -Extension 'json' -OccupiedPath $textPath
    }

    return [ordered]@{
        directory = $outputDir
        text = $textPath
        json = $jsonPath
    }
}

function Set-IocDataSetStatus {
    param(
        [string]$Name,
        [string]$FilePath,
        [string]$Status,
        [string]$LastUpdated,
        [int]$ExpiresAfterDays = 0
    )
    if ($null -eq $script:Context -or [string]::IsNullOrWhiteSpace($Name)) { return }
    $parsedUpdated = $null
    $expiresOn = ''
    $ageDays = $null
    $daysPastDue = 0
    if (-not [string]::IsNullOrWhiteSpace($LastUpdated)) {
        try {
            $parsedUpdated = [DateTime]::ParseExact($LastUpdated, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            if ($parsedUpdated.Date -gt (Get-Date).Date -and $Status -in @('current','stale')) { $Status = 'invalid' }
            $ageDays = [Math]::Max(0, [int][Math]::Floor(((Get-Date) - $parsedUpdated).TotalDays))
            if ($ExpiresAfterDays -gt 0) {
                $expiry = $parsedUpdated.AddDays($ExpiresAfterDays)
                $expiresOn = $expiry.ToString('yyyy-MM-dd')
                if ($expiry -lt (Get-Date)) {
                    $daysPastDue = [Math]::Max(0, [int][Math]::Floor(((Get-Date) - $expiry).TotalDays))
                }
            }
        }
        catch {
            if ($Status -in @('current','stale')) { $Status = 'invalid' }
        }
    }
    $key = $Name.ToLowerInvariant()
    $script:Context.iocDataSets[$key] = [ordered]@{
        name = $Name
        path = (ConvertTo-RedactedPath $FilePath)
        status = $Status
        lastUpdated = $LastUpdated
        expiresAfterDays = $ExpiresAfterDays
        expiresOn = $expiresOn
        ageDays = $ageDays
        daysPastDue = $daysPastDue
    }
}

function Get-IocDataSummary {
    $datasets = @($script:Context.iocDataSets.Values | Sort-Object name)
    $stale = @($datasets | Where-Object { $_.status -eq 'stale' }).Count
    $missing = @($datasets | Where-Object { $_.status -eq 'missing' }).Count
    $invalid = @($datasets | Where-Object { $_.status -eq 'invalid' }).Count
    $current = @($datasets | Where-Object { $_.status -eq 'current' }).Count
    return [ordered]@{
        status = $(if (($stale + $missing + $invalid) -eq 0) { 'current' } else { 'review-required' })
        releaseReady = (($stale + $missing + $invalid) -eq 0)
        currentCount = $current
        staleCount = $stale
        missingCount = $missing
        invalidCount = $invalid
        datasets = $datasets
    }
}

function Get-ScanScopeSummary {
    $included = New-ArrayList
    $excluded = New-ArrayList
    if ([bool]$script:Context.mode.path) { Add-ListItem $included 'explicit-target-path' }
    if ([bool]$script:Context.mode.majorLocations) {
        Add-ListItem $included 'bounded-major-developer-locations'
        Add-ListItem $included 'selected-user-profile-ai-configs-extensions-and-tooling'
    }
    if ([bool]$script:Context.mode.userProfile) { Add-ListItem $included 'bounded-user-profile-configs-and-extensions' }
    if ([bool]$script:Context.mode.endpointTelemetry) { Add-ListItem $included 'bounded-endpoint-telemetry' }
    if ([bool]$script:Context.mode.syntheticValidation) { Add-ListItem $included 'explicit-synthetic-validation-roots' }
    if (Test-CheckEnabled 'NpmGlobal') { Add-ListItem $included 'static-npm-global-metadata' }
    if (Test-CheckEnabled 'NpmCache') { Add-ListItem $included 'bounded-npm-cache-metadata' }
    if (Test-NodeRuntimeHostScopeRequested) { Add-ListItem $included 'known-path-and-PATH-node-runtime-metadata' }
    Add-ListItem $excluded 'full-disk-recursion'
    Add-ListItem $excluded 'reparse-point-targets'
    Add-ListItem $excluded 'known-credential-file-contents'
    Add-ListItem $excluded 'npm-cache-content-v2-blobs'
    if (-not [bool]$script:Context.mode.deep) { Add-ListItem $excluded 'recursive-dependency-build-and-cache-content' }
    if (-not [bool]$script:Context.mode.majorLocations) { Add-ListItem $excluded 'major-developer-location-discovery' }
    if (-not [bool]$script:Context.mode.userProfile) {
        if ([bool]$script:Context.mode.majorLocations) {
            Add-ListItem $excluded 'codex-session-history-and-runtime-cache'
            Add-ListItem $excluded 'broad-user-profile-config-discovery'
        }
        else {
            Add-ListItem $excluded 'user-profile-config-discovery'
        }
    }
    if (-not [bool]$script:Context.mode.endpointTelemetry) { Add-ListItem $excluded 'endpoint-telemetry' }
    $profile = 'custom-bounded'
    if ([bool]$script:Context.mode.path -and [bool]$script:Context.mode.majorLocations -and [bool]$script:Context.mode.userProfile -and [bool]$script:Context.mode.endpointTelemetry) {
        $profile = 'comprehensive-bounded-host-triage'
    }
    elseif ([bool]$script:Context.mode.majorLocations) { $profile = 'major-locations-bounded' }
    elseif ([bool]$script:Context.mode.path) { $profile = 'project-path-bounded' }
    return [ordered]@{
        profile = $profile
        bounded = $true
        fullDisk = $false
        deepTraversal = [bool]$script:Context.mode.deep
        dependencyCoverage = $(if ([bool]$script:Context.mode.deep) { 'bounded-recursive' } else { 'targeted-metadata-and-entrypoints' })
        included = @($included.ToArray())
        excluded = @($excluded.ToArray())
    }
}

function Initialize-ScannerContext {
    $script:StatPathSets=@{}
    $paths = New-ReportPaths
    $distribution = Get-ScannerDistributionInfo
    $checkSelection = Resolve-CheckSelection
    $script:Context = [ordered]@{
        generatedAt = (Get-Date).ToString('o')
        scannerError = $false
        reportPaths = $paths
        launcherPath = $LauncherPath
        distributionStatus = [string]$distribution.status
        distributionWarnings = @($distribution.warnings)
        checks = $checkSelection
        scanRoots = New-ArrayList
        findings = New-ArrayList
        findingKeys = @{}
        limitations = New-ArrayList
        syntheticSamplesExplicit = $false
        syntheticSampleManifestStatus = 'not-loaded'
        ownSyntheticSampleManifest = $null
        syntheticSampleUntrustedPaths = @{}
        scannerArtifactRootsSeen = @{}
        scannerArtifactUntrustedPaths = @{}
        sourceContextCache = @{}
        aiPathRoleCache = @{}
        capabilityFindingCountsByRoot = @{}
        iocDataSets = @{}
        queuedFilePaths = @{}
        processedFilePaths = @{}
        scannerStepPerformance = @{}
        scannerActivityPerformance = @{}
        slowScannerSteps = New-ArrayList
        slowScannerActivities = New-ArrayList
        targetedFilePaths = @{}
        securityCandidateMetadata = @{}
        pythonDistributionHeaders = @{}
        targetedDependencyLimitWarned = $false
        jetBrainsRootsSeen = @{}
        jetBrainsNativeRoots = @{}
        jetBrainsArchiveSkippedRoots = @{}
        nodeRuntimeProjectScanPerformed = $false
        nodeRuntimeHostScanPerformed = $false
        nodeRuntimeBudgetWarned = $false
        nodeRuntimeUnresolvedPaths = New-ArrayList
        nodeRuntimeInventory = New-ArrayList
        nodeRuntimeInventoryKeys = @{}
        nodeRuntimeDataLastUpdated = '2026-10-06'
        nodeRuntimeLocalDataStatus = 'builtin-only'
        campaignIocData = [ordered]@{
            campaignId = 'keyv-chaindrop-2026-08'
            status = 'builtin-only-script-copy'
            lastReviewed = $null
            packageCount = 0
            packageVersionPairCount = 0
            builtinFallbackActive = $true
        }
        iocIndexes = [ordered]@{
            packages = @{}
            fileHashes = @{}
        }
        coverage = [ordered]@{
            traversalComplete = $true
            directoryCoverageComplete = $true
            candidateCoverageComplete = $true
            scanComplete = $false
            finalized = $false
            candidateFailures = New-ArrayList
            directoryFailures = New-ArrayList
            candidateFailureKeys = @{}
            directoryFailureKeys = @{}
            candidateFailureGroups = @{}
            directoryFailureGroups = @{}
            directoryRetryCandidates = New-ArrayList
            retry = [ordered]@{ samePrivilegeAttempts=0; samePrivilegeResolved=0; remaining=0 }
        }
        scanStats = [ordered]@{
            filesEnumerated = 0
            filesScanned = 0
            filesSkipped = 0
            fileEnumerationEvents = 0
            fileSkipEvents = 0
            likelyBinaryFilesSkipped = 0
            compressedFilesSkipped = 0
            maxEncodingProbeBytesObserved = 0
            syntheticSamplesSkipped = 0
            syntheticSampleKnownSkipped = 0
            syntheticSampleUnexpectedFiles = 0
            syntheticSampleHashMismatches = 0
            cacheFilesSkipped = 0
            cacheBlobDirectoriesSkipped = 0
            encodingFallbackAggregated = 0
            unicodeVariationSelectorsAggregated = 0
            scannerFileErrors = 0
            regexMatchTimeouts = 0
            codexReferenceRiskAggregated = 0
            codexSessionRiskAggregated = 0
            codexCacheRiskAggregated = 0
            codexPluginMetadataRiskAggregated = 0
            aiTokenReferenceAggregated = 0
            aiReferenceExecutableSampleAggregated = 0
            capabilityFindingsAggregated = 0
            scannerArtifactRootsFound = 0
            scannerArtifactSamplesSkipped = 0
            scannerArtifactIocReferencesAggregated = 0
            scannerReportArtifactsSkipped = 0
            npmGlobalRootsFound = 0
            npmGlobalPackagesChecked = 0
            npmCacheRootsFound = 0
            npmCacheMetadataFilesScanned = 0
            npmCacheMetadataFilesSkipped = 0
            npmCacheMetadataLimitReached = 0
            npmCacheAccessDenied = 0
            npmTargetedPackagesInspected = 0
            npmTargetedEntrypointsQueued = 0
            npmTargetedEntrypointResolutionFailures = 0
            githubActionMutableRefs = 0
            githubActionOfficialMutableRefs = 0
            wasmArtifactsFound = 0
            uniqueFilesQueued = 0
            projectRootsDiscovered = 0
            projectDiscoveryDirectoriesVisited = 0
            projectDiscoveryLimitReached = 0
            targetedDependencyFilesQueued = 0
            targetedDependencyFilesSkippedByBudget = 0
            deepDirectoriesEntered = 0
            deepFilesQueued = 0
            jetBrainsRootsFound = 0
            jetBrainsPluginsInspected = 0
            jetBrainsArchivesInspected = 0
            jetBrainsArchiveEntriesInspected = 0
            jetBrainsArchivesSkipped = 0
            jetBrainsNativeArtifacts = 0
            nodeRuntimeCandidatesFound = 0
            nodeRuntimePriorityFilesQueued = 0
            nodeRuntimeFilesSkippedByBudget = 0
            nodeRuntimeBinariesInspected = 0
            nodeRuntimeVersionReferencesInspected = 0
            nodeRuntimeUnresolvedReferences = 0
            nodeRuntimeCriticalMatches = 0
            nodeRuntimeHighMatches = 0
            nodeRuntimeVersionReadFailures = 0
            nodeRuntimeInstalledVersionsEvaluated = 0
            nodeRuntimeInstalledVulnerableVersions = 0
            nodeRuntimeInstalledNotAffectedVersions = 0
            nodeRuntimeProjectVersionsEvaluated = 0
            nodeRuntimeProjectVulnerableReferences = 0
            nodeRuntimeProjectNotAffectedReferences = 0
            nodeRuntimeInventoryEntriesOmitted = 0
            campaignPackagesLoaded = 0
            campaignPackageVersionPairsLoaded = 0
            packageIocIndexEntries = 0
            packageIocDuplicatesMerged = 0
            packageLockStructuralScans = 0
            packageLockEntriesEvaluated = 0
            packageLockFallbacks = 0
            incidentHashCandidates = 0
            securityUpdateCandidatesQueued = 0
            securityUpdateCandidatesAnalyzed = 0
            securityUpdateAnalysisLimits = 0
            fileHashComputations = 0
            pythonDistributionHeadersRead = 0
            incidentScriptReferencesResolved = 0
            criticalCandidateFailures = 0
            nonCriticalCandidateFailures = 0
            criticalDirectoryFailures = 0
            nonCriticalDirectoryFailures = 0
            coverageRetryAttempts = 0
            coverageRetryResolved = 0
        }
        aggregatesFlushed = $false
        iocs = $null
        mode = [ordered]@{
            path = -not [string]::IsNullOrEmpty($Path)
            userProfile = [bool]$UserProfile
            deep = [bool]$Deep
            majorLocations = [bool]$MajorLocations
            endpointTelemetry = [bool]$EndpointTelemetry
            syntheticValidation = [bool]$SyntheticValidation
        }
    }

    Initialize-ScanExecution
    Add-Limitation 'No network lookup was performed.'
    Add-Limitation 'No external package manager, git, node, python, curl, or wget command was executed.'
    Add-Limitation 'YAML, TOML, and lockfiles are scanned by static pattern matching, not full semantic parsing.'
    Add-Limitation 'GitHub workflow files nested under dependency or generated-artifact directories are not active in the consuming repository and are not evaluated as repository CI; other static code checks still apply.'
    Add-Limitation ("Full-text regular-expression checks use an explicit {0}-second timeout, with a process-wide default as defense in depth. A timeout is reported and marks scan coverage incomplete while remaining checks continue." -f $script:RegexMatchTimeoutSeconds)
    Add-Limitation ("Variation Selector analysis and per-cluster static decode buffers are limited to {0} matched selectors/bytes. Over-limit files are reported as incomplete coverage after a bounded tail-cluster check." -f $script:VariationSelectorMatchLimit)
    Add-Limitation ("Targeted dependency files are limited to {0} run-wide and fairly divided across discovered projects with a per-project cap of 2,000. Deep traversal is separate." -f (Get-TargetedDependencyFileBudget))
    Add-Limitation 'Node.js runtime checks use static version metadata and explicit version declarations; binaries are not executed and metadata does not prove publisher authenticity.'
    Add-Limitation 'Node.js EOL status, complete semver range evaluation, and registry-backed CVE auditing are outside scope.'
    Add-Limitation 'Absence of findings does not prove the host is clean.'
    if ($SyntheticValidation) {
        Add-Limitation 'SyntheticValidation is active. Host-root checks accept only explicit test roots under this checker distribution tests/samples or reports directory.'
    }
    $script:Context.ownSyntheticSampleManifest = Load-OwnSyntheticSampleManifest
    $script:Context.syntheticSampleManifestStatus = [string]$script:Context.ownSyntheticSampleManifest.status
    if ([string]$script:Context.distributionStatus -ne 'complete') {
        Add-Finding -Severity 'WARN' -Category 'SCANNER_DISTRIBUTION_INCOMPLETE' -Title 'Scanner distribution appears incomplete' -Path $script:BaseDir -PathType 'directory' -SourceContext 'scanner-self' -Evidence ("distributionStatus={0}; warnings={1}" -f $script:Context.distributionStatus, ([string]::Join('; ', [string[]]$script:Context.distributionWarnings))) -Recommendation 'For distributed use, extract the full tool folder and start from run-checker.bat.'
    }
}

function Initialize-ScanExecution {
    $names = New-ArrayList
    Add-ListItem $names 'LoadIocs'
    if (Test-CheckEnabled 'NodeRuntime') { Add-ListItem $names 'NodeRuntimeMetadata' }
    $defaultProject = ([string]::IsNullOrEmpty($Path) -and -not $UserProfile -and -not $MajorLocations -and -not $EndpointTelemetry -and (Test-EnabledChecksRequireProjectPath))
    if (-not [string]::IsNullOrEmpty($Path) -or $defaultProject) { Add-ListItem $names 'Project' }
    if ($UserProfile) { Add-ListItem $names 'UserProfile' }
    if ($MajorLocations) { Add-ListItem $names 'MajorLocations' }
    if ($EndpointTelemetry) { Add-ListItem $names 'EndpointTelemetry' }
    if (Test-CheckEnabled 'NpmGlobal') { Add-ListItem $names 'NpmGlobal' }
    if (Test-CheckEnabled 'NpmCache') { Add-ListItem $names 'NpmCache' }
    $phases = [ordered]@{}
    foreach ($name in $names) {
        $phases[$name] = [ordered]@{ name=$name; status='not-started'; startedAt=$null; finishedAt=$null; elapsedMs=0; startElapsedMs=0 }
    }
    $script:Context.execution = [ordered]@{
        status='running'; startedAt=([DateTimeOffset]::Now.AddMilliseconds(-$script:RunStopwatch.Elapsed.TotalMilliseconds).ToString('o')); finishedAt=$null
        elapsedMs=0; lastPhase=$null; lastStep=$null; interruptionReason=$null; phases=$phases
    }
}

function Invoke-ScanPhase {
    param([string]$Name, [scriptblock]$ScriptBlock)
    $phase = $script:Context.execution.phases[$Name]
    if ($null -eq $phase -or $phase.status -ne 'not-started') { throw 'Invalid scanner phase transition.' }
    $phase.status = 'running'
    $phase.startedAt = (Get-Date).ToString('o')
    $phase.startElapsedMs = $script:RunStopwatch.ElapsedMilliseconds
    $script:Context.execution.lastPhase = $Name
    if (-not $Quiet) {
        $labels=@{
            LoadIocs='Offline IOC data'; NodeRuntimeMetadata='Node.js version metadata'
            Project='Selected project folder'; UserProfile='User profile configurations'
            MajorLocations='Major developer locations'; EndpointTelemetry='Endpoint logs and startup metadata'
            NpmGlobal='npm global metadata'; NpmCache='npm cache metadata'
        }
        $number=[Array]::IndexOf([string[]]@($script:Context.execution.phases.Keys),$Name)+1
        Write-Host ("Phase {0}/{1}: {2}" -f $number,$script:Context.execution.phases.Count,$labels[$Name])
    }
    try {
        & $ScriptBlock
        $phase.status = 'completed'
    }
    catch [System.Management.Automation.PipelineStoppedException] {
        $phase.status = 'interrupted'
        throw
    }
    catch {
        $phase.status = 'failed'
        throw
    }
    finally {
        # Ctrl+C may bypass catch. A phase is complete only after its body returns.
        if ($phase.status -eq 'running') { $phase.status = 'interrupted' }
        $phase.finishedAt = (Get-Date).ToString('o')
        $phase.elapsedMs = [int64]($script:RunStopwatch.ElapsedMilliseconds - $phase.startElapsedMs)
    }
}

function Get-ScanExecutionSummary {
    if ($null -eq $script:Context.execution) { return $null }
    $execution = $script:Context.execution
    $phases = @($execution.phases.Values | ForEach-Object {
        [ordered]@{ name=$_.name; status=$_.status; startedAt=$_.startedAt; finishedAt=$_.finishedAt; elapsedMs=[int64]$_.elapsedMs }
    })
    $pending = 0
    foreach ($key in $script:Context.queuedFilePaths.Keys) {
        if (-not $script:Context.processedFilePaths.ContainsKey($key)) { $pending++ }
    }
    return [ordered]@{
        status=$execution.status; startedAt=$execution.startedAt; finishedAt=$execution.finishedAt
        timestampSource='start-wall-clock-plus-monotonic-elapsed'
        elapsedMs=[int64]$execution.elapsedMs; lastPhase=$execution.lastPhase; lastStep=$execution.lastStep
        interruptionReason=$execution.interruptionReason
        unfinishedPhases=@($phases | Where-Object { $_.status -ne 'completed' } | ForEach-Object { $_.name })
        queuedFilesUnprocessed=[int]$pending; phases=$phases
    }
}

function Complete-ScanExecution {
    param([ValidateSet('completed','interrupted','error')][string]$Status)
    if ($null -eq $script:Context -or $null -eq $script:Context.execution) { return }
    if ($script:Context.execution.status -ne 'running' -and -not ($Status -eq 'error' -and $script:Context.execution.status -eq 'completed')) { return }
    $execution = $script:Context.execution
    if ($Status -eq 'completed' -and @($execution.phases.Values | Where-Object { $_.status -ne 'completed' }).Count -gt 0) { $Status = 'interrupted' }
    $execution.status = $Status
    $execution.elapsedMs = [int64]$script:RunStopwatch.ElapsedMilliseconds
    $execution.finishedAt = ([DateTimeOffset]::Parse($execution.startedAt).AddMilliseconds($execution.elapsedMs)).ToString('o')
    if ($Status -ne 'completed') {
        $script:Context.coverage.finalized = $false
        $script:Context.coverage.traversalComplete = $false
        $script:Context.coverage.candidateCoverageComplete = $false
        $script:Context.coverage.scanComplete = $false
    }
    if ($Status -eq 'interrupted') {
        $execution.interruptionReason = 'pipeline-stopped-or-plan-unfinished'
        foreach ($phase in $execution.phases.Values) {
            if ($phase.status -eq 'running') {
                $phase.status = 'interrupted'; $phase.finishedAt = $execution.finishedAt
                $phase.elapsedMs = [int64]($script:RunStopwatch.ElapsedMilliseconds - $phase.startElapsedMs)
            }
        }
        $summary = Get-ScanExecutionSummary
        Add-Finding -Severity 'WARN' -Category 'SCAN_INTERRUPTED' -Title 'Scan interrupted before all planned checks finished' -Path 'scan execution' -PathType 'virtual' -Evidence ("lastPhase={0}; lastStep={1}; unfinishedPhases={2}; queuedFilesUnprocessed={3}; cause may be Ctrl+C or another pipeline stop." -f $summary.lastPhase,$summary.lastStep,([string]::Join(',', [string[]]$summary.unfinishedPhases)),$summary.queuedFilesUnprocessed) -Recommendation 'Use this as an interrupted report. Rerun the unfinished scope when needed; zero counters do not mean an unstarted check found no targets.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
    }
}

function Get-CheckExecutionStatus {
    param([string]$CheckName)
    if (-not (Test-CheckEnabled $CheckName)) { return 'not-selected' }
    if ($null -eq $script:Context.execution) { return 'unknown' }
    $names = if ($CheckName -in @('NpmGlobal','NpmCache','EndpointTelemetry')) { @($CheckName) }
        elseif ($CheckName -eq 'ScannerSelf') { @('LoadIocs','Project','UserProfile','MajorLocations') }
        elseif ($CheckName -eq 'NodeRuntime') { @('NodeRuntimeMetadata','Project','UserProfile','MajorLocations') }
        else { @('Project','UserProfile','MajorLocations') }
    $states = @($names | Where-Object { $script:Context.execution.phases.Contains($_) } | ForEach-Object { $script:Context.execution.phases[$_].status })
    if ($states.Count -eq 0) { return 'not-applicable' }
    if ($states -contains 'failed') { return 'failed' }
    if ($states -contains 'interrupted') { return 'interrupted' }
    if ($states -contains 'running') { return 'running' }
    if (@($states | Where-Object { $_ -eq 'completed' }).Count -eq $states.Count) { return 'completed' }
    if ($states -contains 'completed') { return 'partial' }
    return 'not-started'
}

function Get-ScanStatsForReport {
    $stats = [ordered]@{
        scanRoots = @($script:Context.scanRoots)
        filesEnumerated = [int]$script:Context.scanStats.filesEnumerated
        filesScanned = [int]$script:Context.scanStats.filesScanned
        filesSkipped = [int]$script:Context.scanStats.filesSkipped
        fileEnumerationEvents = [int]$script:Context.scanStats.fileEnumerationEvents
        fileSkipEvents = [int]$script:Context.scanStats.fileSkipEvents
        likelyBinaryFilesSkipped = [int]$script:Context.scanStats.likelyBinaryFilesSkipped
        compressedFilesSkipped = [int]$script:Context.scanStats.compressedFilesSkipped
        maxEncodingProbeBytesObserved = [int]$script:Context.scanStats.maxEncodingProbeBytesObserved
        syntheticSamplesSkipped = [int]$script:Context.scanStats.syntheticSamplesSkipped
        syntheticSampleKnownSkipped = [int]$script:Context.scanStats.syntheticSampleKnownSkipped
        syntheticSampleUnexpectedFiles = [int]$script:Context.scanStats.syntheticSampleUnexpectedFiles
        syntheticSampleHashMismatches = [int]$script:Context.scanStats.syntheticSampleHashMismatches
        cacheFilesSkipped = [int]$script:Context.scanStats.cacheFilesSkipped
        cacheBlobDirectoriesSkipped = [int]$script:Context.scanStats.cacheBlobDirectoriesSkipped
        encodingFallbackAggregated = [int]$script:Context.scanStats.encodingFallbackAggregated
        unicodeVariationSelectorsAggregated = [int]$script:Context.scanStats.unicodeVariationSelectorsAggregated
        scannerFileErrors = [int]$script:Context.scanStats.scannerFileErrors
        regexMatchTimeouts = [int]$script:Context.scanStats.regexMatchTimeouts
        codexReferenceRiskAggregated = [int]$script:Context.scanStats.codexReferenceRiskAggregated
        codexSessionRiskAggregated = [int]$script:Context.scanStats.codexSessionRiskAggregated
        codexCacheRiskAggregated = [int]$script:Context.scanStats.codexCacheRiskAggregated
        codexPluginMetadataRiskAggregated = [int]$script:Context.scanStats.codexPluginMetadataRiskAggregated
        aiTokenReferenceAggregated = [int]$script:Context.scanStats.aiTokenReferenceAggregated
        aiReferenceExecutableSampleAggregated = [int]$script:Context.scanStats.aiReferenceExecutableSampleAggregated
        capabilityFindingsAggregated = [int]$script:Context.scanStats.capabilityFindingsAggregated
        scannerArtifactRootsFound = [int]$script:Context.scanStats.scannerArtifactRootsFound
        scannerArtifactSamplesSkipped = [int]$script:Context.scanStats.scannerArtifactSamplesSkipped
        scannerArtifactIocReferencesAggregated = [int]$script:Context.scanStats.scannerArtifactIocReferencesAggregated
        scannerReportArtifactsSkipped = [int]$script:Context.scanStats.scannerReportArtifactsSkipped
        npmGlobalRootsFound = [int]$script:Context.scanStats.npmGlobalRootsFound
        npmGlobalPackagesChecked = [int]$script:Context.scanStats.npmGlobalPackagesChecked
        npmCacheRootsFound = [int]$script:Context.scanStats.npmCacheRootsFound
        npmCacheMetadataFilesScanned = [int]$script:Context.scanStats.npmCacheMetadataFilesScanned
        npmCacheMetadataFilesSkipped = [int]$script:Context.scanStats.npmCacheMetadataFilesSkipped
        npmCacheMetadataLimitReached = [int]$script:Context.scanStats.npmCacheMetadataLimitReached
        npmCacheAccessDenied = [int]$script:Context.scanStats.npmCacheAccessDenied
        npmTargetedPackagesInspected = [int]$script:Context.scanStats.npmTargetedPackagesInspected
        npmTargetedEntrypointsQueued = [int]$script:Context.scanStats.npmTargetedEntrypointsQueued
        npmTargetedEntrypointResolutionFailures = [int]$script:Context.scanStats.npmTargetedEntrypointResolutionFailures
        githubActionMutableRefs = [int]$script:Context.scanStats.githubActionMutableRefs
        githubActionOfficialMutableRefs = [int]$script:Context.scanStats.githubActionOfficialMutableRefs
        wasmArtifactsFound = [int]$script:Context.scanStats.wasmArtifactsFound
        uniqueFilesQueued = [int]$script:Context.scanStats.uniqueFilesQueued
        projectRootsDiscovered = [int]$script:Context.scanStats.projectRootsDiscovered
        projectDiscoveryDirectoriesVisited = [int]$script:Context.scanStats.projectDiscoveryDirectoriesVisited
        projectDiscoveryLimitReached = [int]$script:Context.scanStats.projectDiscoveryLimitReached
        targetedDependencyFilesQueued = [int]$script:Context.scanStats.targetedDependencyFilesQueued
        targetedDependencyFilesSkippedByBudget = [int]$script:Context.scanStats.targetedDependencyFilesSkippedByBudget
        deepDirectoriesEntered = [int]$script:Context.scanStats.deepDirectoriesEntered
        deepFilesQueued = [int]$script:Context.scanStats.deepFilesQueued
        jetBrainsRootsFound = [int]$script:Context.scanStats.jetBrainsRootsFound
        jetBrainsPluginsInspected = [int]$script:Context.scanStats.jetBrainsPluginsInspected
        jetBrainsArchivesInspected = [int]$script:Context.scanStats.jetBrainsArchivesInspected
        jetBrainsArchiveEntriesInspected = [int]$script:Context.scanStats.jetBrainsArchiveEntriesInspected
        jetBrainsArchivesSkipped = [int]$script:Context.scanStats.jetBrainsArchivesSkipped
        jetBrainsNativeArtifacts = [int]$script:Context.scanStats.jetBrainsNativeArtifacts
        nodeRuntimeCandidatesFound = [int]$script:Context.scanStats.nodeRuntimeCandidatesFound
        nodeRuntimePriorityFilesQueued = [int]$script:Context.scanStats.nodeRuntimePriorityFilesQueued
        nodeRuntimeFilesSkippedByBudget = [int]$script:Context.scanStats.nodeRuntimeFilesSkippedByBudget
        nodeRuntimeBinariesInspected = [int]$script:Context.scanStats.nodeRuntimeBinariesInspected
        nodeRuntimeVersionReferencesInspected = [int]$script:Context.scanStats.nodeRuntimeVersionReferencesInspected
        nodeRuntimeUnresolvedReferences = [int]$script:Context.scanStats.nodeRuntimeUnresolvedReferences
        nodeRuntimeCriticalMatches = [int]$script:Context.scanStats.nodeRuntimeCriticalMatches
        nodeRuntimeHighMatches = [int]$script:Context.scanStats.nodeRuntimeHighMatches
        nodeRuntimeVersionReadFailures = [int]$script:Context.scanStats.nodeRuntimeVersionReadFailures
        nodeRuntimeInstalledVersionsEvaluated = [int]$script:Context.scanStats.nodeRuntimeInstalledVersionsEvaluated
        nodeRuntimeInstalledVulnerableVersions = [int]$script:Context.scanStats.nodeRuntimeInstalledVulnerableVersions
        nodeRuntimeInstalledNotAffectedVersions = [int]$script:Context.scanStats.nodeRuntimeInstalledNotAffectedVersions
        nodeRuntimeProjectVersionsEvaluated = [int]$script:Context.scanStats.nodeRuntimeProjectVersionsEvaluated
        nodeRuntimeProjectVulnerableReferences = [int]$script:Context.scanStats.nodeRuntimeProjectVulnerableReferences
        nodeRuntimeProjectNotAffectedReferences = [int]$script:Context.scanStats.nodeRuntimeProjectNotAffectedReferences
        nodeRuntimeInventoryEntriesOmitted = [int]$script:Context.scanStats.nodeRuntimeInventoryEntriesOmitted
        campaignPackagesLoaded = [int]$script:Context.scanStats.campaignPackagesLoaded
        campaignPackageVersionPairsLoaded = [int]$script:Context.scanStats.campaignPackageVersionPairsLoaded
        packageIocIndexEntries = [int]$script:Context.scanStats.packageIocIndexEntries
        packageIocDuplicatesMerged = [int]$script:Context.scanStats.packageIocDuplicatesMerged
        packageLockStructuralScans = [int]$script:Context.scanStats.packageLockStructuralScans
        packageLockEntriesEvaluated = [int]$script:Context.scanStats.packageLockEntriesEvaluated
        packageLockFallbacks = [int]$script:Context.scanStats.packageLockFallbacks
        incidentHashCandidates = [int]$script:Context.scanStats.incidentHashCandidates
        securityUpdateCandidatesQueued = [int]$script:Context.scanStats.securityUpdateCandidatesQueued
        securityUpdateCandidatesAnalyzed = [int]$script:Context.scanStats.securityUpdateCandidatesAnalyzed
        securityUpdateAnalysisLimits = [int]$script:Context.scanStats.securityUpdateAnalysisLimits
        fileHashComputations = [int]$script:Context.scanStats.fileHashComputations
        pythonDistributionHeadersRead = [int]$script:Context.scanStats.pythonDistributionHeadersRead
        incidentScriptReferencesResolved = [int]$script:Context.scanStats.incidentScriptReferencesResolved
        criticalCandidateFailures = [int]$script:Context.scanStats.criticalCandidateFailures
        nonCriticalCandidateFailures = [int]$script:Context.scanStats.nonCriticalCandidateFailures
        criticalDirectoryFailures = [int]$script:Context.scanStats.criticalDirectoryFailures
        nonCriticalDirectoryFailures = [int]$script:Context.scanStats.nonCriticalDirectoryFailures
        coverageRetryAttempts = [int]$script:Context.scanStats.coverageRetryAttempts
        coverageRetryResolved = [int]$script:Context.scanStats.coverageRetryResolved
    }
    return $stats
}

function Get-CapabilityRoot {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return 'unknown' }
    $p = $Path -replace '/', '\'
    $m = [regex]::Match($p, '^(.+?\\\.codex\\plugins\\cache\\[^\\]+\\[^\\]+\\[^\\]+)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($p, '^(.+?\\\.codex\\skills\\\.system\\[^\\]+)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($p, '^(.+?\\\.codex\\vendor_imports\\skills\\skills\\\.curated\\[^\\]+)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($p, '^(.+?\\\.codex\\skills\\[^\\]+)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return $p
}

function Get-AiToolingProvenance {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'unknown' }
    $normalized = $Path.ToLowerInvariant() -replace '/', '\'
    if ($normalized -match '\\.codex\\plugins\\cache\\openai-bundled\\') { return 'bundled-cache' }
    if ($normalized -match '\\.codex\\plugins\\cache\\openai-curated-remote\\') { return 'curated-cache' }
    if ($normalized -match '\\.codex\\plugins\\cache\\') { return 'plugin-cache' }
    if ($normalized -match '\\.codex\\skills\\\.system\\') { return 'system-skill' }
    if ($normalized -match '\\.codex\\(skills|vendor_imports\\skills)\\') { return 'local-or-vendored-skill' }
    return 'unknown'
}

function Get-CapabilitySummary {
    $groups = @{}
    foreach ($finding in @($script:Context.findings)) {
        if ([string]$finding.riskType -ne 'capability') { continue }
        $root = Get-CapabilityRoot -Path ([string]$finding.path)
        if (-not $groups.ContainsKey($root)) {
            $groups[$root] = [ordered]@{
                root = $root
                count = 0
                maxSeverity = 'INFO'
                provenance = (Get-AiToolingProvenance -Path $root)
                representativePaths = New-ArrayList
                categories = @{}
            }
        }
        $entry = $groups[$root]
        $entry.count = [int]$entry.count + 1
        $findingSeverity = [string]$finding.severity
        if ($script:SeverityRank.ContainsKey($findingSeverity) -and
            [int]$script:SeverityRank[$findingSeverity] -gt [int]$script:SeverityRank[[string]$entry.maxSeverity]) {
            $entry.maxSeverity = $findingSeverity
        }
        if ($entry.representativePaths.Count -lt 3 -and -not [string]::IsNullOrEmpty([string]$finding.path)) {
            Add-ListItem $entry.representativePaths ([string]$finding.path)
        }
        $category = [string]$finding.category
        if (-not [string]::IsNullOrEmpty($category)) {
            if (-not $entry.categories.ContainsKey($category)) { $entry.categories[$category] = 0 }
            $entry.categories[$category] = [int]$entry.categories[$category] + 1
        }
    }

    $items = New-ArrayList
    foreach ($key in $groups.Keys) {
        $entry = $groups[$key]
        Add-ListItem $items ([ordered]@{
            root = $entry.root
            count = [int]$entry.count
            maxSeverity = [string]$entry.maxSeverity
            provenance = [string]$entry.provenance
            representativePaths = @($entry.representativePaths.ToArray())
            categories = $entry.categories
        })
    }
    return @($items | Sort-Object @{ Expression = { -1 * [int]$_.count } }, @{ Expression = { [string]$_.root } })
}

function Get-PriorityFindings {
    $excludedContexts = @('synthetic-sample','scanner-self','scanner-artifact-sample','cache','dependency-metadata','reference-text','session-log','cache-data')
    $items = New-ArrayList
    foreach ($finding in @($script:Context.findings)) {
        if ($finding.severity -notin @('DANGER','WARN')) { continue }
        $context = [string]$finding.sourceContext
        if ($context -in @('synthetic-sample','scanner-self','scanner-artifact-sample')) { continue }
        $riskType = [string]$finding.riskType
        if ($riskType -eq 'capability') { continue }
        $isPriorityRisk = ($riskType -in @('known-ioc','active-exfil') -or ($riskType -eq 'fetch-execute' -and $context -eq 'active-ai-config'))
        if (($excludedContexts -contains $context) -and -not $isPriorityRisk) { continue }
        $isNodeRuntimeVulnerability = ($riskType -eq 'vulnerability' -and [string]$finding.check -eq 'NodeRuntime')
        if ($isNodeRuntimeVulnerability) {
            $details = $finding.vulnerability
            $kind = if ($null -eq $details) { '' } else { [string]$details.evidenceKind }
            $upstream = if ($null -eq $details) { '' } else { [string]$details.upstreamSeverity }
            if ($kind -ne 'installed-binary-metadata' -and $upstream -notin @('CRITICAL','HIGH')) { continue }
        }
        Add-ListItem $items $finding
    }

    $ordered = @($items) | Sort-Object `
        @{ Expression = {
            $riskType = [string]$_.riskType
            if ($riskType -eq 'known-ioc') { 0 }
            elseif ($riskType -eq 'active-exfil') { 1 }
            elseif ($riskType -eq 'fetch-execute' -and [string]$_.sourceContext -eq 'active-ai-config') { 2 }
            elseif ($_.severity -eq 'DANGER') { 3 }
            elseif ($riskType -eq 'vulnerability' -and $null -ne $_.vulnerability -and [string]$_.vulnerability.evidenceKind -eq 'installed-binary-metadata' -and [string]$_.vulnerability.upstreamSeverity -eq 'CRITICAL') { 4 }
            elseif ($riskType -eq 'vulnerability' -and $null -ne $_.vulnerability -and [string]$_.vulnerability.evidenceKind -eq 'installed-binary-metadata') { 5 }
            elseif ($riskType -eq 'vulnerability' -and $null -ne $_.vulnerability -and [string]$_.vulnerability.upstreamSeverity -eq 'CRITICAL') { 6 }
            elseif ($riskType -eq 'vulnerability' -and $null -ne $_.vulnerability -and [string]$_.vulnerability.upstreamSeverity -eq 'HIGH') { 7 }
            else { 8 }
        } }, `
        @{ Expression = { if ($_.severity -eq 'DANGER') { 0 } else { 1 } } }, `
        @{ Expression = { if ([string]$_.confidence -eq 'high') { 0 } elseif ([string]$_.confidence -eq 'medium') { 1 } else { 2 } } }, `
        @{ Expression = { [string]$_.category } }
    $result = New-ArrayList
    $nodeRuntimeCount = 0
    foreach ($finding in @($ordered)) {
        if ([string]$finding.riskType -eq 'vulnerability' -and [string]$finding.check -eq 'NodeRuntime') {
            if ($nodeRuntimeCount -ge 3) { continue }
            $nodeRuntimeCount++
        }
        Add-ListItem $result $finding
        if ($result.Count -ge 10) { break }
    }
    return @($result.ToArray())
}

function Get-SummaryBySourceContext {
    $result = [ordered]@{}
    foreach ($finding in @($script:Context.findings)) {
        $context = [string]$finding.sourceContext
        if ([string]::IsNullOrEmpty($context)) {
            $context = 'normal'
        }
        if ($result.Keys -notcontains $context) {
            $result[$context] = [ordered]@{
                danger = 0
                warn = 0
                caution = 0
                info = 0
                ok = 0
            }
        }
        switch ($finding.severity) {
            'DANGER' { $result[$context]['danger'] = [int]$result[$context]['danger'] + 1 }
            'WARN' { $result[$context]['warn'] = [int]$result[$context]['warn'] + 1 }
            'CAUTION' { $result[$context]['caution'] = [int]$result[$context]['caution'] + 1 }
            'INFO' { $result[$context]['info'] = [int]$result[$context]['info'] + 1 }
            'OK' { $result[$context]['ok'] = [int]$result[$context]['ok'] + 1 }
        }
    }
    return $result
}

function Get-SummaryByCheck {
    $result = [ordered]@{}
    foreach ($checkName in @($script:LeafCheckOrder)) {
        $result[$checkName] = [ordered]@{
            danger = 0
            warn = 0
            caution = 0
            info = 0
            ok = 0
        }
    }
    foreach ($finding in @($script:Context.findings)) {
        $checkName = [string]$finding.check
        if ([string]::IsNullOrEmpty($checkName) -or -not $result.Contains($checkName)) {
            $checkName = 'ScannerSelf'
        }
        switch ($finding.severity) {
            'DANGER' { $result[$checkName]['danger'] = [int]$result[$checkName]['danger'] + 1 }
            'WARN' { $result[$checkName]['warn'] = [int]$result[$checkName]['warn'] + 1 }
            'CAUTION' { $result[$checkName]['caution'] = [int]$result[$checkName]['caution'] + 1 }
            'INFO' { $result[$checkName]['info'] = [int]$result[$checkName]['info'] + 1 }
            'OK' { $result[$checkName]['ok'] = [int]$result[$checkName]['ok'] + 1 }
        }
    }
    return $result
}

function Get-FindingClassSummary {
    $counts=[ordered]@{ securityEvidence=0; versionMatches=0; configurationReview=0; capabilities=0; coverageLimitations=0; context=0 }
    foreach ($finding in $script:Context.findings) {
        if ($finding.riskType -eq 'vulnerability') { $counts.versionMatches++; continue }
        if ($finding.riskType -eq 'capability') { $counts.capabilities++; continue }
        if ($finding.riskType -eq 'limitation' -and
            ($finding.severity -notin @('INFO','OK') -or $finding.category -match '(READ_LIMITATION|LIMIT_REACHED|MAX_FILES|READ_FAILED|ACCESS_DENIED|PATH_TOO_LONG|PATH_NOT_FOUND|DECODE_FAILED|TOO_LARGE|SCANNER_ERROR|UNAVAILABLE|COVERAGE_PARTIAL|COVERAGE_INCOMPLETE)')) {
            $counts.coverageLimitations++; continue
        }
        # Inventory/reference and expected binary skips stay context, even when
        # their historical category defaults to an IOC or limitation risk type.
        if ($finding.severity -in @('INFO','OK')) { $counts.context++; continue }
        switch ([string]$finding.riskType) {
            { $_ -in @('known-ioc','active-exfil','fetch-execute') } { $counts.securityEvidence++; break }
            'vulnerability' { $counts.versionMatches++; break }
            'capability' { $counts.capabilities++; break }
            'limitation' { $counts.coverageLimitations++; break }
            default { $counts.configurationReview++; break }
        }
    }
    return $counts
}

function Get-CheckStats {
    $stats = [ordered]@{}
    foreach ($checkName in @($script:LeafCheckOrder)) {
        $stats[$checkName] = [ordered]@{
            enabled = [bool](Test-CheckEnabled $checkName)
            executionStatus = Get-CheckExecutionStatus $checkName
        }
    }
    $stats.NpmGlobal.rootsFound = [int]$script:Context.scanStats.npmGlobalRootsFound
    $stats.NpmGlobal.packagesChecked = [int]$script:Context.scanStats.npmGlobalPackagesChecked
    $stats.NpmCache.rootsFound = [int]$script:Context.scanStats.npmCacheRootsFound
    $stats.NpmCache.metadataFilesScanned = [int]$script:Context.scanStats.npmCacheMetadataFilesScanned
    $stats.NpmCache.metadataFilesSkipped = [int]$script:Context.scanStats.npmCacheMetadataFilesSkipped
    $stats.NpmCache.metadataLimitReached = [int]$script:Context.scanStats.npmCacheMetadataLimitReached
    $stats.NpmCache.accessDenied = [int]$script:Context.scanStats.npmCacheAccessDenied
    $stats.Packages.projectRootsDiscovered = [int]$script:Context.scanStats.projectRootsDiscovered
    $stats.Packages.targetedDependencyFilesQueued = [int]$script:Context.scanStats.targetedDependencyFilesQueued
    $stats.IdeExtensions.jetBrainsRootsFound = [int]$script:Context.scanStats.jetBrainsRootsFound
    $stats.IdeExtensions.jetBrainsPluginsInspected = [int]$script:Context.scanStats.jetBrainsPluginsInspected
    $stats.IdeExtensions.jetBrainsArchivesInspected = [int]$script:Context.scanStats.jetBrainsArchivesInspected
    $stats.NodeRuntime.scope = Get-NodeRuntimeScopeForReport
    $stats.NodeRuntime.candidatesFound = [int]$script:Context.scanStats.nodeRuntimeCandidatesFound
    $stats.NodeRuntime.binariesInspected = [int]$script:Context.scanStats.nodeRuntimeBinariesInspected
    $stats.NodeRuntime.versionReferencesInspected = [int]$script:Context.scanStats.nodeRuntimeVersionReferencesInspected
    $stats.NodeRuntime.criticalMatches = [int]$script:Context.scanStats.nodeRuntimeCriticalMatches
    $stats.NodeRuntime.highMatches = [int]$script:Context.scanStats.nodeRuntimeHighMatches
    $stats.NodeRuntime.installedVersionsEvaluated = [int]$script:Context.scanStats.nodeRuntimeInstalledVersionsEvaluated
    $stats.NodeRuntime.installedVulnerableVersions = [int]$script:Context.scanStats.nodeRuntimeInstalledVulnerableVersions
    $stats.NodeRuntime.installedNotAffectedVersions = [int]$script:Context.scanStats.nodeRuntimeInstalledNotAffectedVersions
    $stats.NodeRuntime.projectVersionsEvaluated = [int]$script:Context.scanStats.nodeRuntimeProjectVersionsEvaluated
    $stats.NodeRuntime.projectVulnerableReferences = [int]$script:Context.scanStats.nodeRuntimeProjectVulnerableReferences
    $stats.NodeRuntime.projectNotAffectedReferences = [int]$script:Context.scanStats.nodeRuntimeProjectNotAffectedReferences
    $stats.NodeRuntime.unresolvedProjectReferences = [int]$script:Context.scanStats.nodeRuntimeUnresolvedReferences
    return $stats
}

function Get-NodeRuntimeScopeForReport {
    if (-not (Test-CheckEnabled 'NodeRuntime')) { return 'disabled' }
    if ([bool]$script:Context.nodeRuntimeProjectScanPerformed -and [bool]$script:Context.nodeRuntimeHostScanPerformed) { return 'combined' }
    if ([bool]$script:Context.nodeRuntimeHostScanPerformed) { return 'host-known-paths' }
    return 'project-static'
}

function Get-NodeRuntimeSummary {
    $groups = @{}
    foreach ($finding in @($script:Context.findings)) {
        if ([string]$finding.riskType -ne 'vulnerability' -or [string]$finding.check -ne 'NodeRuntime' -or $null -eq $finding.vulnerability) { continue }
        $details = $finding.vulnerability
        $key = ([string]$details.detectedVersion) + '|' + ([string]$details.upstreamSeverity) + '|' + ([string]$details.evidenceKind) + '|' + ([string]$finding.severity)
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [ordered]@{
                detectedVersion = [string]$details.detectedVersion
                upstreamSeverity = [string]$details.upstreamSeverity
                scannerSeverity = [string]$finding.severity
                evidenceKind = [string]$details.evidenceKind
                count = 0
                advisoryIds = @{}
                fixedVersions = @{}
                representativePaths = New-ArrayList
            }
        }
        $entry = $groups[$key]
        $entry.count = [int]$entry.count + 1
        foreach ($id in @($details.advisoryIds)) { $entry.advisoryIds[[string]$id] = $true }
        if (-not [string]::IsNullOrWhiteSpace([string]$details.fixedVersionForMajor)) { $entry.fixedVersions[[string]$details.fixedVersionForMajor] = $true }
        if ($entry.representativePaths.Count -lt 3 -and -not [string]::IsNullOrEmpty([string]$finding.path)) { Add-ListItem $entry.representativePaths ([string]$finding.path) }
    }
    $result = New-ArrayList
    foreach ($key in $groups.Keys) {
        $entry = $groups[$key]
        Add-ListItem $result ([ordered]@{
            detectedVersion = $entry.detectedVersion
            upstreamSeverity = $entry.upstreamSeverity
            scannerSeverity = $entry.scannerSeverity
            evidenceKind = $entry.evidenceKind
            count = [int]$entry.count
            advisoryIds = @($entry.advisoryIds.Keys | Sort-Object)
            fixedVersions = @($entry.fixedVersions.Keys | Sort-Object)
            representativePaths = @($entry.representativePaths.ToArray())
        })
    }
    return @($result | Sort-Object @{Expression={ if ($_.upstreamSeverity -eq 'CRITICAL') { 0 } else { 1 } }},detectedVersion,evidenceKind | Select-Object -First 20)
}

function Get-NodeRuntimeAssessment {
    $installedEvaluated = [int]$script:Context.scanStats.nodeRuntimeInstalledVersionsEvaluated
    $projectEvaluated = [int]$script:Context.scanStats.nodeRuntimeProjectVersionsEvaluated
    $unresolved = [int]$script:Context.scanStats.nodeRuntimeUnresolvedReferences
    return [ordered]@{
        scope = Get-NodeRuntimeScopeForReport
        installedBinaries = [ordered]@{
            inspected = [int]$script:Context.scanStats.nodeRuntimeBinariesInspected
            versionsEvaluated = $installedEvaluated
            vulnerable = [int]$script:Context.scanStats.nodeRuntimeInstalledVulnerableVersions
            notAffected = [int]$script:Context.scanStats.nodeRuntimeInstalledNotAffectedVersions
            versionReadFailures = [int]$script:Context.scanStats.nodeRuntimeVersionReadFailures
        }
        projectReferences = [ordered]@{
            observed = [int]($projectEvaluated + $unresolved)
            versionsEvaluated = $projectEvaluated
            vulnerable = [int]$script:Context.scanStats.nodeRuntimeProjectVulnerableReferences
            notAffected = [int]$script:Context.scanStats.nodeRuntimeProjectNotAffectedReferences
            unresolved = $unresolved
        }
        inventory = [ordered]@{
            limit = [int]$script:NodeRuntimeInventoryLimit
            entriesReported = @($script:Context.nodeRuntimeInventory).Count
            entriesOmitted = [int]$script:Context.scanStats.nodeRuntimeInventoryEntriesOmitted
            entries = @($script:Context.nodeRuntimeInventory.ToArray())
        }
    }
}

function Get-SyntheticSampleStatus {
    if ($script:Context.syntheticSamplesExplicit) {
        return 'explicitly-scanned'
    }
    $syntheticFindings = @($script:Context.findings | Where-Object { $_.sourceContext -eq 'synthetic-sample' -and $_.category -ne 'OWN_SYNTHETIC_SAMPLES_SKIPPED' }).Count
    if ($syntheticFindings -gt 0) {
        return 'explicitly-scanned'
    }
    if ([int]$script:Context.scanStats.syntheticSamplesSkipped -gt 0 -or [int]$script:Context.scanStats.scannerArtifactSamplesSkipped -gt 0) {
        return 'excluded'
    }
    return 'none-found'
}

function Get-SyntheticSampleManifestStatusForReport {
    if ($script:Context.syntheticSamplesExplicit) {
        return 'explicitly-scanned'
    }
    return [string]$script:Context.syntheticSampleManifestStatus
}

function Flush-AggregatedFindings {
    if ($null -eq $script:Context -or $script:Context.aggregatesFlushed) {
        return
    }
    $script:Context.aggregatesFlushed = $true
    if ([int]$script:Context.scanStats.syntheticSampleKnownSkipped -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'OWN_SYNTHETIC_SAMPLES_SKIPPED' -Title 'Known scanner synthetic sample files skipped' -Path (Join-Path (Get-OwnSyntheticSampleRoot) 'manifest.json') -PathType 'file' -SourceContext 'synthetic-sample' -Evidence ("Skipped {0} manifest-verified synthetic fixture file(s)." -f $script:Context.scanStats.syntheticSampleKnownSkipped) -Recommendation 'Scan tests/samples explicitly when validating the scanner.'
    }
    if ([int]$script:Context.scanStats.scannerArtifactSamplesSkipped -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'SCANNER_ARTIFACT_SAMPLES_SKIPPED' -Title 'Known external scanner artifact sample files skipped' -Path 'external scanner artifacts' -PathType 'virtual' -SourceContext 'scanner-artifact-sample' -Evidence ("Skipped {0} external scanner artifact fixture file(s) that matched the current manifest hash allowlist." -f $script:Context.scanStats.scannerArtifactSamplesSkipped) -Recommendation 'Unknown or modified external scanner sample files are scanned normally.'
    }
    if ([int]$script:Context.scanStats.scannerArtifactIocReferencesAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'SCANNER_SELF_IOC_REFERENCE_AGGREGATED' -Title 'Scanner self IOC references aggregated' -Path $script:BaseDir -PathType 'directory' -SourceContext 'scanner-self' -Evidence ("Aggregated {0} scanner self-reference IOC occurrence(s) from the running scanner or local IOC data." -f $script:Context.scanStats.scannerArtifactIocReferencesAggregated) -Recommendation 'This indicates scanner rules or IOC data references, not target-project compromise by itself.'
    }
    if ([int]$script:Context.scanStats.scannerReportArtifactsSkipped -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'SCANNER_REPORT_ARTIFACTS_SKIPPED' -Title 'Scanner report artifact directories skipped' -Path $script:BaseDir -PathType 'directory' -SourceContext 'scanner-self' -Evidence ("Skipped {0} own scanner report artifact directorie(s) under the running scanner folder." -f $script:Context.scanStats.scannerReportArtifactsSkipped) -Recommendation 'Scan reports explicitly with -Path if historical report contents must be reviewed.'
    }
    if ([int]$script:Context.scanStats.githubActionOfficialMutableRefs -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'GITHUB_ACTIONS_OFFICIAL_VERSION_REFS_AGGREGATED' -Title 'Official GitHub Actions use mutable version refs' -Path 'GitHub Actions workflows' -PathType 'virtual' -SourceContext 'normal' -Evidence ("Aggregated {0} actions/* or github/* version reference(s)." -f $script:Context.scanStats.githubActionOfficialMutableRefs) -Recommendation 'Full commit SHA pinning provides stronger immutability when required by the project threat model.' -RiskType 'posture' -Confidence 'low' -Check 'CiCd' -DetectionMethod 'metadata'
    }
    if ([int]$script:Context.scanStats.aiReferenceExecutableSampleAggregated -gt 0) {
        Add-Finding -Severity 'CAUTION' -Category 'AI_REFERENCE_TEXT_EXECUTABLE_SAMPLE_RISK_AGGREGATED' -Title 'AI reference text contains executable-looking risky samples' -Path '.codex reference text' -PathType 'virtual' -SourceContext 'reference-text' -Evidence ("Aggregated {0} reference text file(s) with executable-looking fetch-execute or secret-send samples. Reference text is not active configuration by itself." -f $script:Context.scanStats.aiReferenceExecutableSampleAggregated) -Recommendation 'Review examples before copying them into active configs or scripts; prioritize a linked active config or executable finding if present.' -RiskType 'posture' -Confidence 'medium'
    }
    if ([int]$script:Context.scanStats.capabilityFindingsAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'AI_TOOLING_CAPABILITY_FINDINGS_AGGREGATED' -Title 'Additional AI tooling capability findings aggregated' -Path 'AI tooling capability summary' -PathType 'virtual' -SourceContext 'executable-tooling' -Evidence ("Aggregated {0} additional capability-only finding(s) after per-root representative limits." -f $script:Context.scanStats.capabilityFindingsAggregated) -Recommendation 'Use capabilitySummary and representative findings for review; capability is not evidence of infection by itself.' -RiskType 'capability' -Confidence 'low'
    }
    if ([int]$script:Context.scanStats.cacheFilesSkipped -gt 0 -or [int]$script:Context.scanStats.cacheBlobDirectoriesSkipped -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_BLOB_SKIPPED' -Title 'npm cache content blobs skipped' -Path 'npm cache content-v2' -PathType 'virtual' -SourceContext 'cache' -Evidence ("Skipped {0} individually encountered blob file(s) and {1} content-v2 directorie(s) without enumerating their contents. Directory contents are outside coverage; no file count is inferred." -f $script:Context.scanStats.cacheFilesSkipped,$script:Context.scanStats.cacheBlobDirectoriesSkipped) -Recommendation 'Review package manifests and lockfiles; NpmCache checks inspect only explicitly selected bounded cache index metadata.'
    }
    if ([int]$script:Context.scanStats.encodingFallbackAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'TEXT_DEFAULT_ENCODING_AGGREGATED' -Title 'Default encoding fallback findings aggregated' -Path 'dependency metadata' -PathType 'virtual' -SourceContext 'dependency-metadata' -Evidence ("Aggregated {0} dependency metadata file(s) decoded with default encoding." -f $script:Context.scanStats.encodingFallbackAggregated) -Recommendation 'Inspect manually only if invisible Unicode findings point to the same dependency metadata.'
    }
    if ([int]$script:Context.scanStats.compressedFilesSkipped -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'COMPRESSED_DATA_SKIPPED' -Title 'Compressed or binary container text analysis skipped' -Path 'bounded compressed file probes' -PathType 'virtual' -Evidence ("Skipped {0} Zstd-signature, ZIP-container or binary-probed .br file(s) after applicable filename/hash checks. Probes are at most 4,096 bytes; no decompression was performed." -f $script:Context.scanStats.compressedFilesSkipped) -Recommendation 'Compressed interiors are outside text coverage. Text disguised with these extensions remains eligible for text analysis.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
    }
    if ([int]$script:Context.scanStats.unicodeVariationSelectorsAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'UNICODE_VARIATION_SELECTOR_AGGREGATED' -Title 'Low-risk emoji variation selectors aggregated' -Path 'unicode variation selector data' -PathType 'virtual' -SourceContext 'dependency-metadata' -Evidence ("Aggregated {0} low-risk U+FE0E/U+FE0F occurrence(s) without nearby execution pattern." -f $script:Context.scanStats.unicodeVariationSelectorsAggregated) -Recommendation 'Review only if another finding points to the same file or dependency.'
    }
    if ([int]$script:Context.scanStats.codexReferenceRiskAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'AI_REFERENCE_TEXT_RISK_AGGREGATED' -Title 'AI reference text contains security example patterns' -Path '.codex reference text' -PathType 'virtual' -SourceContext 'reference-text' -Evidence ("Aggregated {0} reference text file(s) with URL, fetch-execute, IOC, or token-path examples." -f $script:Context.scanStats.codexReferenceRiskAggregated) -Recommendation 'Treat as documentation context unless another active config or executable finding points to the same content.'
    }
    if ([int]$script:Context.scanStats.codexSessionRiskAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'AI_SESSION_LOG_RISK_AGGREGATED' -Title 'AI session logs contain security pattern text' -Path '.codex session logs' -PathType 'virtual' -SourceContext 'session-log' -Evidence ("Aggregated {0} session log file(s) with URL, fetch-execute, IOC, or token-path text." -f $script:Context.scanStats.codexSessionRiskAggregated) -Recommendation 'Session logs are not executable configuration. Review only if active config or tooling findings also appear.'
    }
    if ([int]$script:Context.scanStats.codexCacheRiskAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'AI_CACHE_RISK_AGGREGATED' -Title 'AI cache data contains security pattern text' -Path '.codex cache data' -PathType 'virtual' -SourceContext 'cache-data' -Evidence ("Aggregated {0} cache data file(s) with URL, fetch-execute, IOC, or token-path text." -f $script:Context.scanStats.codexCacheRiskAggregated) -Recommendation 'Cache text is not treated as executable configuration by itself.'
    }
    if ([int]$script:Context.scanStats.codexPluginMetadataRiskAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'AI_PLUGIN_METADATA_RISK_AGGREGATED' -Title 'AI plugin metadata contains security pattern text without command field' -Path '.codex plugin metadata' -PathType 'virtual' -SourceContext 'plugin-metadata' -Evidence ("Aggregated {0} plugin metadata file(s) with URL, fetch-execute, IOC, or token-path text outside command fields." -f $script:Context.scanStats.codexPluginMetadataRiskAggregated) -Recommendation 'Plugin metadata without command-like fields is lower priority, but inspect related active commands if present.'
    }
    if ([int]$script:Context.scanStats.aiTokenReferenceAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'AI_TOKEN_REFERENCE_IN_TEXT' -Title 'AI token path references were aggregated outside executable context' -Path 'AI reference/session/cache text' -PathType 'virtual' -SourceContext 'reference-text' -Evidence ("Aggregated {0} low-risk token-path reference(s) outside active execution context. Values redacted." -f $script:Context.scanStats.aiTokenReferenceAggregated) -Recommendation 'Token path examples are not evidence of exfiltration unless paired with executable context.'
    }
    if ([int]$script:Context.scanStats.nodeRuntimeUnresolvedReferences -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'NODE_RUNTIME_REFERENCES_UNRESOLVED' -Title 'Some Node.js version references could not be evaluated exactly' -Path 'Node.js runtime references' -PathType 'virtual' -SourceContext 'node-runtime' -Evidence ("Unresolved reference count={0}; representative paths={1}" -f $script:Context.scanStats.nodeRuntimeUnresolvedReferences, ([string]::Join('; ', [string[]]@($script:Context.nodeRuntimeUnresolvedPaths)))) -Recommendation 'Use an exact MAJOR.MINOR.PATCH pin or inspect the effective runtime version manually.' -RiskType 'limitation' -Confidence 'low' -Check 'NodeRuntime' -DetectionMethod 'metadata'
    }
    if ([int]$script:Context.scanStats.nodeRuntimeVersionReadFailures -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'NODE_RUNTIME_VERSION_READ_FAILURES' -Title 'Some Node.js runtime candidates could not be identified or versioned' -Path 'Node.js runtime candidates' -PathType 'virtual' -SourceContext 'node-runtime' -Evidence ("Candidate identity, metadata, or bounded host traversal failure count={0}. No executable was launched." -f $script:Context.scanStats.nodeRuntimeVersionReadFailures) -Recommendation 'Inspect the candidate path manually if an expected Node.js installation is missing from the runtime summary.' -RiskType 'limitation' -Confidence 'low' -Check 'NodeRuntime' -DetectionMethod 'metadata'
    }
    foreach ($entry in @($script:Context.jetBrainsNativeRoots.Values)) {
        Add-Finding -Severity 'INFO' -Category 'JETBRAINS_PLUGIN_NATIVE_ARTIFACTS_AGGREGATED' -Title 'JetBrains plugin contains native artifacts' -Path ([string]$entry.root) -SourceContext 'jetbrains-plugin' -Evidence ("Native artifact count={0}; representative paths={1}" -f $entry.count, ([string]::Join('; ', [string[]]@($entry.representatives)))) -Recommendation 'Native artifacts are capability context, not evidence of compromise by themselves. Verify unexpected plugin provenance.' -RiskType 'capability' -Confidence 'low' -Check 'IdeExtensions' -DetectionMethod 'metadata'
    }
    foreach ($entry in @($script:Context.jetBrainsArchiveSkippedRoots.Values)) {
        Add-Finding -Severity 'INFO' -Category 'JETBRAINS_ARCHIVES_SKIPPED_AGGREGATED' -Title 'Some JetBrains plugin artifacts could not be safely inspected' -Path ([string]$entry.root) -SourceContext 'jetbrains-plugin' -Evidence ("Skipped artifact count={0}; representative paths={1}" -f $entry.count, ([string]::Join('; ', [string[]]@($entry.representatives)))) -Recommendation 'Inspect these archives manually if the plugin is unexpected; the scanner did not extract or execute them.' -RiskType 'limitation' -Confidence 'low' -Check 'IdeExtensions' -DetectionMethod 'metadata'
    }
}

function Get-OverallResult {
    $danger = 0
    $warn = 0
    $caution = 0
    foreach ($finding in $script:Context.findings) {
        if ($finding.severity -eq 'DANGER') { $danger++ }
        if ($finding.severity -eq 'WARN') { $warn++ }
        if ($finding.severity -eq 'CAUTION') { $caution++ }
    }
    if ($danger -gt 0) { return 'DANGER' }
    if ($warn -gt 0) { return 'WARN' }
    if ($caution -gt 0) { return 'CAUTION' }
    return 'OK'
}

function Get-Summary {
    $summary = [ordered]@{
        danger = 0
        warn = 0
        caution = 0
        info = 0
        ok = 0
    }
    foreach ($finding in $script:Context.findings) {
        switch ($finding.severity) {
            'DANGER' { $summary.danger++ }
            'WARN' { $summary.warn++ }
            'CAUTION' { $summary.caution++ }
            'INFO' { $summary.info++ }
            'OK' { $summary.ok++ }
        }
    }
    return $summary
}

function Write-Utf8BomFile {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$Content
    )
    $parent = Split-Path -Parent $FilePath
    if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }
    $encoding = New-Object System.Text.UTF8Encoding($true)
    $stream = $null
    $writer = $null
    try {
        $stream = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $writer = New-Object System.IO.StreamWriter($stream, $encoding)
        $writer.Write($Content)
        $writer.Flush()
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }
        elseif ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Write-Reports {
    if ($null -eq $script:Context) {
        return
    }

    Complete-ScanExecution -Status 'interrupted'
    Finalize-ScanCoverage
    Flush-AggregatedFindings
    $summary = Get-Summary
    $overall = Get-OverallResult
    $priorityFindings = Get-PriorityFindings
    $capabilitySummary = Get-CapabilitySummary
    $nodeRuntimeSummary = Get-NodeRuntimeSummary
    $nodeRuntimeAssessment = Get-NodeRuntimeAssessment
    $scanScopeSummary = Get-ScanScopeSummary
    $iocDataSummary = Get-IocDataSummary
    $coverageStatusSummary = Get-CoverageStatusSummary
    $executionSummary = Get-ScanExecutionSummary
    $findingClasses = Get-FindingClassSummary
    $report = [ordered]@{
        schemaVersion = $script:ScannerVersion
        generatedAt = $script:Context.generatedAt
        scanner = [ordered]@{
            name = $script:ScannerName
            version = $script:ScannerVersion
            dependencyMode = 'none'
            networkAccess = $false
            readOnly = $true
            severityOrder = @($script:SeverityOrder)
            cautionExitCode = 1
            regexMatchTimeoutSeconds = [int]$script:RegexMatchTimeoutSeconds
            variationSelectorMatchLimit = [int]$script:VariationSelectorMatchLimit
            variationSelectorDecodeMaxBytes = [int]$script:VariationSelectorDecodeMaxBytes
            scriptPathRedacted = (ConvertTo-RedactedPath $script:ScriptPath)
            scriptDirectoryRedacted = (ConvertTo-RedactedPath $script:BaseDir)
            launcherPathRedacted = (ConvertTo-RedactedPath $script:Context.launcherPath)
            distributionStatus = [string]$script:Context.distributionStatus
            distributionWarnings = @($script:Context.distributionWarnings)
        }
        host = [ordered]@{
            userProfileRedacted = '~'
            computerNameRedacted = '<COMPUTER>'
            powershellVersion = $PSVersionTable.PSVersion.ToString()
        }
        mode = $script:Context.mode
        scanScope = $scanScopeSummary
        executionSafety = [ordered]@{
            networkAccess = 'none'
            externalCommands = 'none'
            targetCodeExecution = 'none'
        }
        selectedChecks = @($script:Context.checks.selected)
        expandedChecks = @($script:Context.checks.expanded)
        skippedChecks = @($script:Context.checks.skipped)
        nodeRuntimeScope = Get-NodeRuntimeScopeForReport
        nodeRuntimeData = [ordered]@{
            status = [string]$script:Context.nodeRuntimeLocalDataStatus
            effectiveLastUpdated = [string]$script:Context.nodeRuntimeDataLastUpdated
        }
        iocData = $iocDataSummary
        campaignIocData = $script:Context.campaignIocData
        traversalComplete = [bool]$script:Context.coverage.traversalComplete
        directoryCoverageComplete = [bool]$script:Context.coverage.directoryCoverageComplete
        candidateCoverageComplete = [bool]$script:Context.coverage.candidateCoverageComplete
        scanComplete = [bool]$script:Context.coverage.scanComplete
        completionStatus = [string]$coverageStatusSummary.completionStatus
        executionStatus = [string]$executionSummary.status
        execution = $executionSummary
        performance = Get-ScannerPerformanceSummary
        coverage = [ordered]@{
            summary = $coverageStatusSummary
            candidateFailures = @($script:Context.coverage.candidateFailures)
            directoryFailures = @($script:Context.coverage.directoryFailures)
            retry = $script:Context.coverage.retry
        }
        scanRoots = @($script:Context.scanRoots)
        scanStats = Get-ScanStatsForReport
        checkStats = Get-CheckStats
        overallResult = $overall
        summary = $summary
        findingClassSummary = $findingClasses
        summaryBySourceContext = Get-SummaryBySourceContext
        summaryByCheck = Get-SummaryByCheck
        priorityFindings = @($priorityFindings)
        capabilitySummary = @($capabilitySummary)
        nodeRuntimeSummary = @($nodeRuntimeSummary)
        nodeRuntimeAssessment = $nodeRuntimeAssessment
        syntheticSamples = [ordered]@{
            status = Get-SyntheticSampleStatus
            manifestStatus = Get-SyntheticSampleManifestStatusForReport
            explicitlyScanned = [bool]$script:Context.syntheticSamplesExplicit
            skipped = [int]$script:Context.scanStats.syntheticSamplesSkipped
            ownKnownSkipped = [int]$script:Context.scanStats.syntheticSampleKnownSkipped
            scannerArtifactKnownSkipped = [int]$script:Context.scanStats.scannerArtifactSamplesSkipped
            findings = @($script:Context.findings | Where-Object { $_.sourceContext -eq 'synthetic-sample' -and $_.category -ne 'OWN_SYNTHETIC_SAMPLES_SKIPPED' }).Count
        }
        findings = @($script:Context.findings)
        limitations = @($script:Context.limitations)
    }

    $json = $report | ConvertTo-Json -Depth 12
    Write-Utf8BomFile -FilePath $script:Context.reportPaths.json -Content $json

    $lines = New-ArrayList
    Add-ListItem $lines "$script:ScannerName Report"
    Add-ListItem $lines "Version: $script:ScannerVersion"
    Add-ListItem $lines ("GeneratedAt: " + $script:Context.generatedAt)
    Add-ListItem $lines ("ExecutionStatus: {0}; StartedAt={1}; FinishedAt={2}; ElapsedMs={3}" -f $executionSummary.status,$executionSummary.startedAt,$executionSummary.finishedAt,$executionSummary.elapsedMs)
    Add-ListItem $lines ("UnfinishedPhases: {0}; QueuedFilesUnprocessed={1}" -f ([string]::Join(', ',[string[]]$executionSummary.unfinishedPhases)),$executionSummary.queuedFilesUnprocessed)
    foreach ($phase in $executionSummary.phases) { Add-ListItem $lines ("ExecutionPhase: {0}; Status={1}; ElapsedMs={2}" -f $phase.name,$phase.status,$phase.elapsedMs) }
    Add-ListItem $lines ("Performance: ExecutionElapsedMs={0}; PartitionElapsedMs={1}; OtherElapsedMs={2}; SlowStepsLimit={3}" -f $report.performance.executionElapsedMs,$report.performance.partitionElapsedMs,$report.performance.otherElapsedMs,$report.performance.slowStepsLimit)
    Add-ListItem $lines ("TimingScope: {0}" -f $report.performance.timingScope)
    foreach ($activity in $report.performance.activities) { Add-ListItem $lines ("PerformanceActivity: {0}; Attempts={1}; ElapsedMs={2}; MaxElapsedMs={3}; Partition={4}" -f $activity.activity,$activity.attempts,$activity.elapsedMs,$activity.maxElapsedMs,$activity.partition) }
    foreach ($slow in $report.performance.slowSteps) { Add-ListItem $lines ("SlowStep: {0}; Path={1}; ElapsedMs={2}; TimedOut={3}" -f $slow.step,$slow.path,$slow.elapsedMs,$slow.timedOut) }
    foreach ($slow in $report.performance.slowActivities) { Add-ListItem $lines ("SlowActivity: {0}; Path={1}; ElapsedMs={2}; Partition={3}" -f $slow.activity,$slow.path,$slow.elapsedMs,$slow.partition) }
    Add-ListItem $lines ("FileCountSemantics: distinct paths per counter; enumeration/skip events may repeat; queued is not the sum of scanned and excluded. EnumerationEvents={0}; SkipEvents={1}" -f $script:Context.scanStats.fileEnumerationEvents,$script:Context.scanStats.fileSkipEvents)
    Add-ListItem $lines ("ScannerPath: {0}" -f (ConvertTo-RedactedPath $script:ScriptPath))
    Add-ListItem $lines ("LauncherPath: {0}" -f (ConvertTo-RedactedPath $script:Context.launcherPath))
    Add-ListItem $lines ("DistributionStatus: {0}" -f $script:Context.distributionStatus)
    if (@($script:Context.distributionWarnings).Count -gt 0) {
        Add-ListItem $lines ("DistributionWarnings: {0}" -f ([string]::Join('; ', [string[]]$script:Context.distributionWarnings)))
    }
    Add-ListItem $lines ("Mode: Path={0}, UserProfile={1}, Deep={2}, MajorLocations={3}, EndpointTelemetry={4}, SyntheticValidation={5}" -f $script:Context.mode.path, $script:Context.mode.userProfile, $script:Context.mode.deep, $script:Context.mode.majorLocations, $script:Context.mode.endpointTelemetry, $script:Context.mode.syntheticValidation)
    Add-ListItem $lines ("ScopeProfile: {0}; Bounded=true; FullDisk=false; DependencyCoverage={1}" -f $scanScopeSummary.profile,$scanScopeSummary.dependencyCoverage)
    Add-ListItem $lines 'ReadOnly: true'
    Add-ListItem $lines 'NetworkAccess: false'
    Add-ListItem $lines 'ExternalCommands: none'
    Add-ListItem $lines 'TargetCodeExecution: none'
    Add-ListItem $lines ("OverallResult: $overall")
    Add-ListItem $lines ("FindingClasses: SecurityEvidence={0}; VersionMatches={1}; ConfigurationReview={2}; Capabilities={3}; CoverageLimitations={4}; Context={5}" -f $findingClasses.securityEvidence,$findingClasses.versionMatches,$findingClasses.configurationReview,$findingClasses.capabilities,$findingClasses.coverageLimitations,$findingClasses.context)
    Add-ListItem $lines 'Severity and execution completion are separate. Counts are findings, not infection counts.'
    Add-ListItem $lines ("CampaignIocStatus: {0}" -f $script:Context.campaignIocData.status)
    Add-ListItem $lines ("TraversalComplete: {0}" -f $script:Context.coverage.traversalComplete)
    Add-ListItem $lines ("DirectoryCoverageComplete: {0}" -f $script:Context.coverage.directoryCoverageComplete)
    Add-ListItem $lines ("CandidateCoverageComplete: {0}" -f $script:Context.coverage.candidateCoverageComplete)
    Add-ListItem $lines ("CompletionStatus: {0}" -f $coverageStatusSummary.completionStatus)
    Add-ListItem $lines ("CompletionLabel: {0}" -f $coverageStatusSummary.completionLabel)
    Add-ListItem $lines ("ScanComplete: {0}" -f $script:Context.coverage.scanComplete)
    Add-ListItem $lines ("CoverageFailures: Critical={0}; NonCritical={1}; Total={2}" -f $coverageStatusSummary.criticalFailures,$coverageStatusSummary.nonCriticalFailures,$coverageStatusSummary.totalFailures)
    Add-ListItem $lines ("DependencyCoverageStatus: {0}; TargetedFilesSkippedByBudget={1}" -f $coverageStatusSummary.dependencyCoverageStatus,$coverageStatusSummary.targetedDependencyFilesSkippedByBudget)
    Add-ListItem $lines ("NpmCacheCoverageStatus: {0}; MetadataScanned={1}; MetadataSkipped={2}; LimitReached={3}" -f $coverageStatusSummary.npmCacheCoverageStatus,$coverageStatusSummary.npmCacheMetadataFilesScanned,$coverageStatusSummary.npmCacheMetadataFilesSkipped,$coverageStatusSummary.npmCacheMetadataLimitReached)
    Add-ListItem $lines ("CoverageNextAction: {0}" -f $coverageStatusSummary.nextAction)
    foreach ($action in $coverageStatusSummary.nextActions) { Add-ListItem $lines ("CoverageAction: {0}; Count={1}; Paths={2}; Action={3}" -f $action.reason,$action.count,([string]::Join('; ',[string[]]$action.paths)),$action.action) }
    foreach ($reason in @($coverageStatusSummary.incompleteReasons)) { Add-ListItem $lines ("CoverageReason: {0}" -f $reason) }
    Add-ListItem $lines ''
    Add-ListItem $lines '[SCAN CONFIG]'
    Add-ListItem $lines ("SelectedChecks: {0}" -f ([string]::Join(', ', [string[]]$script:Context.checks.selected)))
    Add-ListItem $lines ("ExpandedChecks: {0}" -f ([string]::Join(', ', [string[]]$script:Context.checks.expanded)))
    Add-ListItem $lines ("SkippedChecks: {0}" -f ([string]::Join(', ', [string[]]$script:Context.checks.skipped)))
    Add-ListItem $lines ("DeepTraversal: {0}" -f $(if ($Deep) { 'enabled' } else { 'disabled' }))
    Add-ListItem $lines ("RunFileBudget: {0}/{1}" -f $script:Context.scanStats.uniqueFilesQueued, $MaxFiles)
    Add-ListItem $lines ("TargetedDependencyBudget: {0}/{1}" -f $script:Context.scanStats.targetedDependencyFilesQueued, (Get-TargetedDependencyFileBudget))
    Add-ListItem $lines ("NodeRuntimeScope: {0}" -f (Get-NodeRuntimeScopeForReport))
    Add-ListItem $lines ("NodeRuntimePriorityBudget: {0}/{1}" -f $script:Context.scanStats.nodeRuntimePriorityFilesQueued, (Get-NodeRuntimePriorityBudget))
    Add-ListItem $lines ("NodeRuntimeData: {0}; LastUpdated={1}" -f $script:Context.nodeRuntimeLocalDataStatus, $script:Context.nodeRuntimeDataLastUpdated)
    Add-ListItem $lines ("NodeRuntimeInstalled: Inspected={0}; VersionsEvaluated={1}; Vulnerable={2}; NotAffected={3}; VersionReadFailures={4}" -f $nodeRuntimeAssessment.installedBinaries.inspected,$nodeRuntimeAssessment.installedBinaries.versionsEvaluated,$nodeRuntimeAssessment.installedBinaries.vulnerable,$nodeRuntimeAssessment.installedBinaries.notAffected,$nodeRuntimeAssessment.installedBinaries.versionReadFailures)
    Add-ListItem $lines ("NodeRuntimeProjectReferences: Observed={0}; VersionsEvaluated={1}; Vulnerable={2}; NotAffected={3}; Unresolved={4}" -f $nodeRuntimeAssessment.projectReferences.observed,$nodeRuntimeAssessment.projectReferences.versionsEvaluated,$nodeRuntimeAssessment.projectReferences.vulnerable,$nodeRuntimeAssessment.projectReferences.notAffected,$nodeRuntimeAssessment.projectReferences.unresolved)
    Add-ListItem $lines ("CampaignIocData: {0}; Packages={1}; Pairs={2}" -f $script:Context.campaignIocData.status,$script:Context.campaignIocData.packageCount,$script:Context.campaignIocData.packageVersionPairCount)
    Add-ListItem $lines ("IocData: {0}; ReleaseReady={1}; Current={2}; Stale={3}; Missing={4}; Invalid={5}" -f $iocDataSummary.status,$iocDataSummary.releaseReady,$iocDataSummary.currentCount,$iocDataSummary.staleCount,$iocDataSummary.missingCount,$iocDataSummary.invalidCount)
    Add-ListItem $lines 'NetworkAccess: none'
    Add-ListItem $lines 'ExternalCommands: none'
    Add-ListItem $lines 'TargetCodeExecution: none'
    Add-ListItem $lines ''
    Add-ListItem $lines '[SCAN SCOPE]'
    Add-ListItem $lines ("Profile: {0}" -f $scanScopeSummary.profile)
    Add-ListItem $lines ("Included: {0}" -f ([string]::Join(', ', [string[]]$scanScopeSummary.included)))
    Add-ListItem $lines ("Excluded: {0}" -f ([string]::Join(', ', [string[]]$scanScopeSummary.excluded)))
    Add-ListItem $lines ''
    Add-ListItem $lines '[IOC DATA FRESHNESS]'
    Add-ListItem $lines ("Status: {0}; ReleaseReady={1}" -f $iocDataSummary.status,$iocDataSummary.releaseReady)
    foreach ($dataset in @($iocDataSummary.datasets)) {
        Add-ListItem $lines ("{0}: Status={1}; LastUpdated={2}; ExpiresOn={3}; AgeDays={4}; DaysPastDue={5}" -f $dataset.name,$dataset.status,$dataset.lastUpdated,$dataset.expiresOn,$dataset.ageDays,$dataset.daysPastDue)
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[SUMMARY]'
    Add-ListItem $lines ("DANGER: {0}" -f $summary.danger)
    Add-ListItem $lines ("WARN:   {0}" -f $summary.warn)
    Add-ListItem $lines ("CAUTION: {0}" -f $summary.caution)
    Add-ListItem $lines ("INFO:   {0}" -f $summary.info)
    Add-ListItem $lines ("OK:     {0}" -f $summary.ok)
    Add-ListItem $lines ''
    Add-ListItem $lines '[SYNTHETIC SAMPLES]'
    Add-ListItem $lines ("Status: {0}" -f (Get-SyntheticSampleStatus))
    Add-ListItem $lines ("ManifestStatus: {0}" -f (Get-SyntheticSampleManifestStatusForReport))
    Add-ListItem $lines ("ExplicitlyScanned: {0}" -f $script:Context.syntheticSamplesExplicit)
    Add-ListItem $lines ("Skipped: {0}" -f $script:Context.scanStats.syntheticSamplesSkipped)
    Add-ListItem $lines ("OwnKnownSkipped: {0}" -f $script:Context.scanStats.syntheticSampleKnownSkipped)
    Add-ListItem $lines ("ScannerArtifactKnownSkipped: {0}" -f $script:Context.scanStats.scannerArtifactSamplesSkipped)
    Add-ListItem $lines ''
    Add-ListItem $lines '[SUMMARY BY SOURCE CONTEXT]'
    $bySource = Get-SummaryBySourceContext
    foreach ($context in $bySource.Keys) {
        Add-ListItem $lines ("{0}: DANGER={1}, WARN={2}, CAUTION={3}, INFO={4}, OK={5}" -f $context, $bySource[$context].danger, $bySource[$context].warn, $bySource[$context].caution, $bySource[$context].info, $bySource[$context].ok)
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[CHECK SUMMARY]'
    $byCheck = Get-SummaryByCheck
    foreach ($checkName in @($script:LeafCheckOrder)) {
        $item = $byCheck[$checkName]
        $enabled = Test-CheckEnabled $checkName
        Add-ListItem $lines ("{0}: Enabled={1}, DANGER={2}, WARN={3}, CAUTION={4}, INFO={5}, OK={6}" -f $checkName, $enabled, $item.danger, $item.warn, $item.caution, $item.info, $item.ok)
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[SCAN STATS]'
    $scanStats = Get-ScanStatsForReport
    Add-ListItem $lines ("ScanRoots: {0}" -f (@($scanStats.scanRoots).Count))
    Add-ListItem $lines ("FilesEnumerated: {0}" -f $scanStats.filesEnumerated)
    Add-ListItem $lines ("UniqueFilesQueued: {0}" -f $scanStats.uniqueFilesQueued)
    Add-ListItem $lines ("FilesScanned: {0}" -f $scanStats.filesScanned)
    Add-ListItem $lines ("FilesSkipped: {0}" -f $scanStats.filesSkipped)
    Add-ListItem $lines ("LikelyBinaryFilesSkipped: {0}" -f $scanStats.likelyBinaryFilesSkipped)
    Add-ListItem $lines ("MaxEncodingProbeBytesObserved: {0}" -f $scanStats.maxEncodingProbeBytesObserved)
    Add-ListItem $lines ("SyntheticSamplesSkipped: {0}" -f $scanStats.syntheticSamplesSkipped)
    Add-ListItem $lines ("SyntheticSampleKnownSkipped: {0}" -f $scanStats.syntheticSampleKnownSkipped)
    Add-ListItem $lines ("SyntheticSampleUnexpectedFiles: {0}" -f $scanStats.syntheticSampleUnexpectedFiles)
    Add-ListItem $lines ("SyntheticSampleHashMismatches: {0}" -f $scanStats.syntheticSampleHashMismatches)
    Add-ListItem $lines ("CacheFilesSkipped: {0}" -f $scanStats.cacheFilesSkipped)
    Add-ListItem $lines ("CacheBlobDirectoriesSkipped: {0}" -f $scanStats.cacheBlobDirectoriesSkipped)
    Add-ListItem $lines ("UnicodeVariationSelectorsAggregated: {0}" -f $scanStats.unicodeVariationSelectorsAggregated)
    Add-ListItem $lines ("ScannerFileErrors: {0}" -f $scanStats.scannerFileErrors)
    Add-ListItem $lines ("RegexMatchTimeouts: {0}" -f $scanStats.regexMatchTimeouts)
    Add-ListItem $lines ("CodexReferenceRiskAggregated: {0}" -f $scanStats.codexReferenceRiskAggregated)
    Add-ListItem $lines ("CodexSessionRiskAggregated: {0}" -f $scanStats.codexSessionRiskAggregated)
    Add-ListItem $lines ("CodexCacheRiskAggregated: {0}" -f $scanStats.codexCacheRiskAggregated)
    Add-ListItem $lines ("CodexPluginMetadataRiskAggregated: {0}" -f $scanStats.codexPluginMetadataRiskAggregated)
    Add-ListItem $lines ("AiTokenReferenceAggregated: {0}" -f $scanStats.aiTokenReferenceAggregated)
    Add-ListItem $lines ("AiReferenceExecutableSampleAggregated: {0}" -f $scanStats.aiReferenceExecutableSampleAggregated)
    Add-ListItem $lines ("CapabilityFindingsAggregated: {0}" -f $scanStats.capabilityFindingsAggregated)
    Add-ListItem $lines ("NpmCacheMetadataLimitReached: {0}" -f $scanStats.npmCacheMetadataLimitReached)
    Add-ListItem $lines ("ScannerArtifactRootsFound: {0}" -f $scanStats.scannerArtifactRootsFound)
    Add-ListItem $lines ("ScannerArtifactSamplesSkipped: {0}" -f $scanStats.scannerArtifactSamplesSkipped)
    Add-ListItem $lines ("ScannerArtifactIocReferencesAggregated: {0}" -f $scanStats.scannerArtifactIocReferencesAggregated)
    Add-ListItem $lines ("ScannerReportArtifactsSkipped: {0}" -f $scanStats.scannerReportArtifactsSkipped)
    Add-ListItem $lines ("NpmTargetedPackagesInspected: {0}" -f $scanStats.npmTargetedPackagesInspected)
    Add-ListItem $lines ("NpmTargetedEntrypointsQueued: {0}" -f $scanStats.npmTargetedEntrypointsQueued)
    Add-ListItem $lines ("NpmTargetedEntrypointResolutionFailures: {0}" -f $scanStats.npmTargetedEntrypointResolutionFailures)
    Add-ListItem $lines ("GithubActionMutableRefs: {0}" -f $scanStats.githubActionMutableRefs)
    Add-ListItem $lines ("GithubActionOfficialMutableRefs: {0}" -f $scanStats.githubActionOfficialMutableRefs)
    Add-ListItem $lines ("WasmArtifactsFound: {0}" -f $scanStats.wasmArtifactsFound)
    Add-ListItem $lines ("ProjectRootsDiscovered: {0}" -f $scanStats.projectRootsDiscovered)
    Add-ListItem $lines ("ProjectDiscoveryDirectoriesVisited: {0}" -f $scanStats.projectDiscoveryDirectoriesVisited)
    Add-ListItem $lines ("ProjectDiscoveryLimitReached: {0}" -f $scanStats.projectDiscoveryLimitReached)
    Add-ListItem $lines ("TargetedDependencyFilesQueued: {0}" -f $scanStats.targetedDependencyFilesQueued)
    Add-ListItem $lines ("TargetedDependencyFilesSkippedByBudget: {0}" -f $scanStats.targetedDependencyFilesSkippedByBudget)
    Add-ListItem $lines ("DeepDirectoriesEntered: {0}" -f $scanStats.deepDirectoriesEntered)
    Add-ListItem $lines ("DeepFilesQueued: {0}" -f $scanStats.deepFilesQueued)
    Add-ListItem $lines ("JetBrainsRootsFound: {0}" -f $scanStats.jetBrainsRootsFound)
    Add-ListItem $lines ("JetBrainsPluginsInspected: {0}" -f $scanStats.jetBrainsPluginsInspected)
    Add-ListItem $lines ("JetBrainsArchivesInspected: {0}" -f $scanStats.jetBrainsArchivesInspected)
    Add-ListItem $lines ("JetBrainsArchiveEntriesInspected: {0}" -f $scanStats.jetBrainsArchiveEntriesInspected)
    Add-ListItem $lines ("JetBrainsArchivesSkipped: {0}" -f $scanStats.jetBrainsArchivesSkipped)
    Add-ListItem $lines ("JetBrainsNativeArtifacts: {0}" -f $scanStats.jetBrainsNativeArtifacts)
    Add-ListItem $lines ("NodeRuntimeCandidatesFound: {0}" -f $scanStats.nodeRuntimeCandidatesFound)
    Add-ListItem $lines ("NodeRuntimePriorityFilesQueued: {0}" -f $scanStats.nodeRuntimePriorityFilesQueued)
    Add-ListItem $lines ("NodeRuntimeFilesSkippedByBudget: {0}" -f $scanStats.nodeRuntimeFilesSkippedByBudget)
    Add-ListItem $lines ("NodeRuntimeBinariesInspected: {0}" -f $scanStats.nodeRuntimeBinariesInspected)
    Add-ListItem $lines ("NodeRuntimeVersionReferencesInspected: {0}" -f $scanStats.nodeRuntimeVersionReferencesInspected)
    Add-ListItem $lines ("NodeRuntimeUnresolvedReferences: {0}" -f $scanStats.nodeRuntimeUnresolvedReferences)
    Add-ListItem $lines ("NodeRuntimeCriticalMatches: {0}" -f $scanStats.nodeRuntimeCriticalMatches)
    Add-ListItem $lines ("NodeRuntimeHighMatches: {0}" -f $scanStats.nodeRuntimeHighMatches)
    Add-ListItem $lines ("NodeRuntimeVersionReadFailures: {0}" -f $scanStats.nodeRuntimeVersionReadFailures)
    Add-ListItem $lines ("NodeRuntimeInstalledVersionsEvaluated: {0}" -f $scanStats.nodeRuntimeInstalledVersionsEvaluated)
    Add-ListItem $lines ("NodeRuntimeInstalledVulnerableVersions: {0}" -f $scanStats.nodeRuntimeInstalledVulnerableVersions)
    Add-ListItem $lines ("NodeRuntimeInstalledNotAffectedVersions: {0}" -f $scanStats.nodeRuntimeInstalledNotAffectedVersions)
    Add-ListItem $lines ("NodeRuntimeProjectVersionsEvaluated: {0}" -f $scanStats.nodeRuntimeProjectVersionsEvaluated)
    Add-ListItem $lines ("NodeRuntimeProjectVulnerableReferences: {0}" -f $scanStats.nodeRuntimeProjectVulnerableReferences)
    Add-ListItem $lines ("NodeRuntimeProjectNotAffectedReferences: {0}" -f $scanStats.nodeRuntimeProjectNotAffectedReferences)
    Add-ListItem $lines ("NodeRuntimeInventoryEntriesOmitted: {0}" -f $scanStats.nodeRuntimeInventoryEntriesOmitted)
    Add-ListItem $lines ("CampaignPackagesLoaded: {0}" -f $scanStats.campaignPackagesLoaded)
    Add-ListItem $lines ("CampaignPackageVersionPairsLoaded: {0}" -f $scanStats.campaignPackageVersionPairsLoaded)
    Add-ListItem $lines ("PackageIocIndexEntries: {0}" -f $scanStats.packageIocIndexEntries)
    Add-ListItem $lines ("PackageIocDuplicatesMerged: {0}" -f $scanStats.packageIocDuplicatesMerged)
    Add-ListItem $lines ("PackageLockStructuralScans: {0}" -f $scanStats.packageLockStructuralScans)
    Add-ListItem $lines ("PackageLockEntriesEvaluated: {0}" -f $scanStats.packageLockEntriesEvaluated)
    Add-ListItem $lines ("PackageLockFallbacks: {0}" -f $scanStats.packageLockFallbacks)
    Add-ListItem $lines ("IncidentHashCandidates: {0}" -f $scanStats.incidentHashCandidates)
    Add-ListItem $lines ("SecurityUpdateCandidatesQueued: {0}" -f $scanStats.securityUpdateCandidatesQueued)
    Add-ListItem $lines ("SecurityUpdateCandidatesAnalyzed: {0}" -f $scanStats.securityUpdateCandidatesAnalyzed)
    Add-ListItem $lines ("SecurityUpdateAnalysisLimits: {0}" -f $scanStats.securityUpdateAnalysisLimits)
    Add-ListItem $lines ("FileHashComputations: {0}" -f $scanStats.fileHashComputations)
    Add-ListItem $lines ("PythonDistributionHeadersRead: {0}" -f $scanStats.pythonDistributionHeadersRead)
    Add-ListItem $lines ("IncidentScriptReferencesResolved: {0}" -f $scanStats.incidentScriptReferencesResolved)
    Add-ListItem $lines ("CriticalCandidateFailures: {0}" -f $scanStats.criticalCandidateFailures)
    Add-ListItem $lines ("NonCriticalCandidateFailures: {0}" -f $scanStats.nonCriticalCandidateFailures)
    Add-ListItem $lines ("CriticalDirectoryFailures: {0}" -f $scanStats.criticalDirectoryFailures)
    Add-ListItem $lines ("NonCriticalDirectoryFailures: {0}" -f $scanStats.nonCriticalDirectoryFailures)
    Add-ListItem $lines ("CoverageRetryAttempts: {0}" -f $scanStats.coverageRetryAttempts)
    Add-ListItem $lines ("CoverageRetryResolved: {0}" -f $scanStats.coverageRetryResolved)
    Add-ListItem $lines ''
    Add-ListItem $lines '[NODE RUNTIME SUMMARY]'
    Add-ListItem $lines ("InstalledBinaries: Inspected={0}; VersionsEvaluated={1}; Vulnerable={2}; NotAffected={3}; VersionReadFailures={4}" -f $nodeRuntimeAssessment.installedBinaries.inspected,$nodeRuntimeAssessment.installedBinaries.versionsEvaluated,$nodeRuntimeAssessment.installedBinaries.vulnerable,$nodeRuntimeAssessment.installedBinaries.notAffected,$nodeRuntimeAssessment.installedBinaries.versionReadFailures)
    Add-ListItem $lines ("ProjectReferences: Observed={0}; VersionsEvaluated={1}; Vulnerable={2}; NotAffected={3}; Unresolved={4}" -f $nodeRuntimeAssessment.projectReferences.observed,$nodeRuntimeAssessment.projectReferences.versionsEvaluated,$nodeRuntimeAssessment.projectReferences.vulnerable,$nodeRuntimeAssessment.projectReferences.notAffected,$nodeRuntimeAssessment.projectReferences.unresolved)
    foreach ($entry in @($nodeRuntimeAssessment.inventory.entries)) {
        Add-ListItem $lines ("Inventory: Source={0}; Version={1}; Status={2}; Evidence={3}; Path={4}" -f $entry.sourceType,$entry.detectedVersion,$entry.advisoryStatus,$entry.evidenceKind,$entry.path)
    }
    if ([int]$nodeRuntimeAssessment.inventory.entriesOmitted -gt 0) {
        Add-ListItem $lines ("InventoryEntriesOmitted: {0}" -f $nodeRuntimeAssessment.inventory.entriesOmitted)
    }
    if (@($nodeRuntimeSummary).Count -eq 0) {
        Add-ListItem $lines 'None'
    }
    else {
        foreach ($entry in @($nodeRuntimeSummary)) {
            Add-ListItem $lines ("Node.js {0}; ScannerSeverity={1}; UpstreamSeverity={2}; Evidence={3}; Findings={4}; Advisories={5}; FixedForMajor={6}" -f $entry.detectedVersion,$entry.scannerSeverity,$entry.upstreamSeverity,$entry.evidenceKind,$entry.count,([string]::Join(', ', [string[]]$entry.advisoryIds)),([string]::Join(', ', [string[]]$entry.fixedVersions)))
            foreach ($representativePath in @($entry.representativePaths)) { Add-ListItem $lines ("RepresentativePath: {0}" -f $representativePath) }
        }
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[CAPABILITY SUMMARY]'
    if (@($capabilitySummary).Count -eq 0) {
        Add-ListItem $lines 'None'
    }
    else {
        foreach ($entry in @($capabilitySummary)) {
            Add-ListItem $lines ("[{0}] {1} finding(s) under {2}; Provenance={3}" -f $entry.maxSeverity, $entry.count, $entry.root, $entry.provenance)
            foreach ($representativePath in @($entry.representativePaths)) {
                Add-ListItem $lines ("RepresentativePath: {0}" -f $representativePath)
            }
        }
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[PRIORITY FINDINGS]'
    if (@($priorityFindings).Count -eq 0) {
        Add-ListItem $lines 'None'
    }
    else {
        foreach ($finding in @($priorityFindings)) {
            Add-ListItem $lines ("[{0}] {1} - {2}" -f $finding.severity, $finding.category, $finding.path)
            Add-ListItem $lines ("SourceContext: {0}" -f $finding.sourceContext)
            Add-ListItem $lines ("RiskType: {0}" -f $finding.riskType)
            Add-ListItem $lines ("Confidence: {0}" -f $finding.confidence)
            if ($null -ne $finding.vulnerability) {
                Add-ListItem $lines ("UpstreamSeverity: {0}" -f $finding.vulnerability.upstreamSeverity)
                Add-ListItem $lines ("DetectedVersion: {0}" -f $finding.vulnerability.detectedVersion)
            }
        }
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[FINDINGS]'
    foreach ($finding in $script:Context.findings) {
        Add-ListItem $lines ("[{0}] {1}" -f $finding.severity, $finding.category)
        Add-ListItem $lines ("Title: {0}" -f $finding.title)
        if (-not [string]::IsNullOrEmpty($finding.path)) {
            Add-ListItem $lines ("Path: {0}" -f $finding.path)
        }
        if (-not [string]::IsNullOrEmpty($finding.pathType)) {
            Add-ListItem $lines ("PathType: {0}" -f $finding.pathType)
        }
        if ($null -ne $finding.line) {
            Add-ListItem $lines ("Line: {0}" -f $finding.line)
        }
        if (-not [string]::IsNullOrEmpty($finding.sourceContext)) {
            Add-ListItem $lines ("SourceContext: {0}" -f $finding.sourceContext)
        }
        if (-not [string]::IsNullOrEmpty($finding.check)) {
            Add-ListItem $lines ("Check: {0}" -f $finding.check)
        }
        if (-not [string]::IsNullOrEmpty($finding.detectionMethod)) {
            Add-ListItem $lines ("DetectionMethod: {0}" -f $finding.detectionMethod)
        }
        if (-not [string]::IsNullOrEmpty($finding.riskType)) {
            Add-ListItem $lines ("RiskType: {0}" -f $finding.riskType)
        }
        if (-not [string]::IsNullOrEmpty($finding.confidence)) {
            Add-ListItem $lines ("Confidence: {0}" -f $finding.confidence)
        }
        foreach ($field in @('ruleId','sourceId','upstreamSeverity')) {
            $value = [string](Get-PropertyValue $finding $field)
            if (-not [string]::IsNullOrEmpty($value)) { Add-ListItem $lines ("{0}: {1}" -f $field,$value) }
        }
        if ($null -ne $finding.vulnerability) {
            Add-ListItem $lines ("UpstreamSeverity: {0}" -f $finding.vulnerability.upstreamSeverity)
            Add-ListItem $lines ("Advisories: {0}" -f ([string]::Join(', ', [string[]]$finding.vulnerability.advisoryIds)))
            Add-ListItem $lines ("DetectedVersion: {0}" -f $finding.vulnerability.detectedVersion)
            Add-ListItem $lines ("VersionEvidence: {0}" -f $finding.vulnerability.evidenceKind)
            Add-ListItem $lines ("FixedVersionForMajor: {0}" -f $finding.vulnerability.fixedVersionForMajor)
            Add-ListItem $lines ("ConditionStatus: {0}" -f $finding.vulnerability.conditionStatus)
        }
        Add-ListItem $lines ("Evidence: {0}" -f $finding.evidence)
        Add-ListItem $lines ("Recommendation: {0}" -f $finding.recommendation)
        Add-ListItem $lines ''
    }
    Add-ListItem $lines '[LIMITATIONS]'
    foreach ($limitation in $script:Context.limitations) {
        Add-ListItem $lines ("- {0}" -f $limitation)
    }

    Write-Utf8BomFile -FilePath $script:Context.reportPaths.text -Content ([string]::Join("`r`n", [string[]]$lines.ToArray()))

    if (-not $Quiet) {
        Write-Host ("OverallResult: {0}" -f $overall)
        Write-Host ("Findings by severity: DANGER={0}; WARN={1}; CAUTION={2}; INFO={3}; OK={4}" -f $summary.danger,$summary.warn,$summary.caution,$summary.info,$summary.ok)
        Write-Host ("Finding types: Evidence={0}; VersionMatches={1}; ConfigReview={2}; Capabilities={3}; CoverageLimits={4}; Context={5}" -f $findingClasses.securityEvidence,$findingClasses.versionMatches,$findingClasses.configurationReview,$findingClasses.capabilities,$findingClasses.coverageLimitations,$findingClasses.context)
        Write-Host ("Scope (planned): {0}; FullDisk=false; Deep={1}; Included={2}" -f $scanScopeSummary.profile,$scanScopeSummary.deepTraversal,([string]::Join(', ', [string[]]$scanScopeSummary.included)))
        Write-Host ("Execution: {0}; ElapsedMs={1}; UnfinishedPhases={2}; QueuedFilesUnprocessed={3}" -f $executionSummary.status,$executionSummary.elapsedMs,([string]::Join(',',[string[]]$executionSummary.unfinishedPhases)),$executionSummary.queuedFilesUnprocessed)
        Write-Host ("IOC data: {0}; ReleaseReady={1}; Stale={2}; Missing={3}; Invalid={4}" -f $iocDataSummary.status,$iocDataSummary.releaseReady,$iocDataSummary.staleCount,$iocDataSummary.missingCount,$iocDataSummary.invalidCount)
        Write-Host ("Completion: {0}; ScanComplete={1}; FilesScanned={2}; FilesSkipped={3}; CoverageFailures=Critical:{4},NonCritical:{5}" -f $coverageStatusSummary.completionLabel,$script:Context.coverage.scanComplete,$script:Context.scanStats.filesScanned,$script:Context.scanStats.filesSkipped,$coverageStatusSummary.criticalFailures,$coverageStatusSummary.nonCriticalFailures)
        if (Test-CheckEnabled 'NodeRuntime') {
            Write-Host ("Node.js installed: inspected={0}; evaluated={1}; vulnerable={2}; notAffected={3}; readFailures={4}" -f $nodeRuntimeAssessment.installedBinaries.inspected,$nodeRuntimeAssessment.installedBinaries.versionsEvaluated,$nodeRuntimeAssessment.installedBinaries.vulnerable,$nodeRuntimeAssessment.installedBinaries.notAffected,$nodeRuntimeAssessment.installedBinaries.versionReadFailures)
            Write-Host ("Node.js project refs: observed={0}; evaluated={1}; vulnerable={2}; notAffected={3}; unresolved={4}" -f $nodeRuntimeAssessment.projectReferences.observed,$nodeRuntimeAssessment.projectReferences.versionsEvaluated,$nodeRuntimeAssessment.projectReferences.vulnerable,$nodeRuntimeAssessment.projectReferences.notAffected,$nodeRuntimeAssessment.projectReferences.unresolved)
        }
        if (-not [bool]$script:Context.coverage.scanComplete -or $coverageStatusSummary.dependencyCoverageStatus -match 'partial|sampled' -or $coverageStatusSummary.npmCacheCoverageStatus -match 'partial|limit') {
            Write-Host ("Coverage: Dependencies={0}; NpmGlobal={1}; NpmCache={2}; NextAction={3}" -f $coverageStatusSummary.dependencyCoverageStatus,$coverageStatusSummary.npmGlobalCoverageStatus,$coverageStatusSummary.npmCacheCoverageStatus,$coverageStatusSummary.nextAction)
        }
        Write-Host ("TXT:  {0}" -f $script:Context.reportPaths.text)
        Write-Host ("JSON: {0}" -f $script:Context.reportPaths.json)
    }
}

function Add-BuiltinPackageIoc {
    param($List, [string]$Ecosystem, [string]$Name, [string[]]$Versions, [string]$Notes)
    Add-ListItem $List ([ordered]@{ ecosystem=$Ecosystem; name=$Name; versions=@($Versions); severity='DANGER'; notes=$Notes })
}

function Add-BuiltinFileHashIoc {
    param($List, [string]$PathPattern, [string]$Sha256, [string]$Notes)
    Add-ListItem $List ([ordered]@{ pathPattern=$PathPattern; sha256=$Sha256; severity='DANGER'; notes=$Notes })
}

function New-NodeRuntimeRange {
    param([string]$MinInclusive, [string]$MaxExclusive)
    return [ordered]@{ minInclusive=$MinInclusive; maxExclusive=$MaxExclusive }
}

function New-NodeRuntimeFixedVersion {
    param([int]$Major, [string]$Version)
    return [ordered]@{ major=$Major; version=$Version }
}

function New-NodeRuntimeAdvisory {
    param(
        [string]$Id,
        [string]$UpstreamSeverity,
        [string]$Published,
        [string]$Source,
        [object[]]$AffectedRanges,
        [object[]]$FixedVersions,
        [string[]]$Conditions
    )
    return [ordered]@{
        id = $Id
        upstreamSeverity = $UpstreamSeverity
        published = $Published
        source = $Source
        affectedRanges = @($AffectedRanges)
        fixedVersions = @($FixedVersions)
        conditions = @($Conditions)
    }
}

function Load-BuiltinNodeRuntimeIocs {
    $items = New-ArrayList
    $feb2020 = 'https://nodejs.org/en/blog/vulnerability/february-2020-security-releases'
    $sep2020 = 'https://nodejs.org/en/blog/vulnerability/september-2020-security-releases'
    $feb2021 = 'https://nodejs.org/en/blog/vulnerability/february-2021-security-releases'
    $jan2026 = 'https://nodejs.org/en/blog/vulnerability/december-2025-security-releases'
    $mar2026 = 'https://nodejs.org/en/blog/vulnerability/march-2026-security-releases'
    $jun2026 = 'https://nodejs.org/en/blog/vulnerability/june-2026-security-releases'
    $jul2026 = 'https://nodejs.org/en/blog/vulnerability/july-2026-security-releases'

    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2019-15605' 'CRITICAL' '2020-02-06' $feb2020 @(
        (New-NodeRuntimeRange '10.0.0' '10.19.0'), (New-NodeRuntimeRange '12.0.0' '12.15.0'), (New-NodeRuntimeRange '13.0.0' '13.8.0')
    ) @((New-NodeRuntimeFixedVersion 10 '10.19.0'),(New-NodeRuntimeFixedVersion 12 '12.15.0'),(New-NodeRuntimeFixedVersion 13 '13.8.0')) @('http-server'))
    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2020-8251' 'CRITICAL' '2020-09-15' $sep2020 @(
        (New-NodeRuntimeRange '14.0.0' '14.11.0')
    ) @((New-NodeRuntimeFixedVersion 14 '14.11.0')) @('http-server'))
    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2021-22883' 'CRITICAL' '2021-02-23' $feb2021 @(
        (New-NodeRuntimeRange '10.0.0' '10.24.0'), (New-NodeRuntimeRange '12.0.0' '12.21.0'),
        (New-NodeRuntimeRange '14.0.0' '14.16.0'), (New-NodeRuntimeRange '15.0.0' '15.10.0')
    ) @((New-NodeRuntimeFixedVersion 10 '10.24.0'),(New-NodeRuntimeFixedVersion 12 '12.21.0'),(New-NodeRuntimeFixedVersion 14 '14.16.0'),(New-NodeRuntimeFixedVersion 15 '15.10.0')) @('http2-server','unknownProtocol'))

    foreach ($id in @('CVE-2025-55131','CVE-2025-55130','CVE-2025-59465')) {
        $conditions = switch ($id) {
            'CVE-2025-55131' { @('vm-timeout','buffer-allocation') }
            'CVE-2025-55130' { @('permission-model','symlink') }
            default { @('http2-server') }
        }
        Add-ListItem $items (New-NodeRuntimeAdvisory $id 'HIGH' '2026-01-13' $jan2026 @(
            (New-NodeRuntimeRange '20.0.0' '20.20.0'), (New-NodeRuntimeRange '22.0.0' '22.22.0'),
            (New-NodeRuntimeRange '24.0.0' '24.13.0'), (New-NodeRuntimeRange '25.0.0' '25.3.0')
        ) @((New-NodeRuntimeFixedVersion 20 '20.20.0'),(New-NodeRuntimeFixedVersion 22 '22.22.0'),(New-NodeRuntimeFixedVersion 24 '24.13.0'),(New-NodeRuntimeFixedVersion 25 '25.3.0')) $conditions)
    }
    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2026-21637' 'HIGH' '2026-03-24' $mar2026 @(
        (New-NodeRuntimeRange '20.20.0' '20.20.2'), (New-NodeRuntimeRange '22.22.0' '22.22.2'),
        (New-NodeRuntimeRange '24.13.0' '24.14.1'), (New-NodeRuntimeRange '25.3.0' '25.8.2')
    ) @((New-NodeRuntimeFixedVersion 20 '20.20.2'),(New-NodeRuntimeFixedVersion 22 '22.22.2'),(New-NodeRuntimeFixedVersion 24 '24.14.1'),(New-NodeRuntimeFixedVersion 25 '25.8.2')) @('tls-server','SNICallback'))
    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2026-21710' 'HIGH' '2026-03-24' $mar2026 @(
        (New-NodeRuntimeRange '20.0.0' '20.20.2'), (New-NodeRuntimeRange '22.0.0' '22.22.2'),
        (New-NodeRuntimeRange '24.0.0' '24.14.1'), (New-NodeRuntimeRange '25.0.0' '25.8.2')
    ) @((New-NodeRuntimeFixedVersion 20 '20.20.2'),(New-NodeRuntimeFixedVersion 22 '22.22.2'),(New-NodeRuntimeFixedVersion 24 '24.14.1'),(New-NodeRuntimeFixedVersion 25 '25.8.2')) @('http-server','headersDistinct'))

    foreach ($id in @('CVE-2026-48933','CVE-2026-48618')) {
        $conditions = if ($id -eq 'CVE-2026-48933') { @('webcrypto','large-input') } else { @('tls-client','unicode-hostname') }
        Add-ListItem $items (New-NodeRuntimeAdvisory $id 'HIGH' '2026-06-18' $jun2026 @(
            (New-NodeRuntimeRange '22.0.0' '22.23.0'), (New-NodeRuntimeRange '24.0.0' '24.17.0'), (New-NodeRuntimeRange '26.0.0' '26.3.1')
        ) @((New-NodeRuntimeFixedVersion 22 '22.23.0'),(New-NodeRuntimeFixedVersion 24 '24.17.0'),(New-NodeRuntimeFixedVersion 26 '26.3.1')) $conditions)
    }
    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2026-56846' 'HIGH' '2026-07-29' $jul2026 @(
        (New-NodeRuntimeRange '22.0.0' '22.23.2'), (New-NodeRuntimeRange '24.0.0' '24.18.1')
    ) @((New-NodeRuntimeFixedVersion 22 '22.23.2'),(New-NodeRuntimeFixedVersion 24 '24.18.1')) @('http2-server','memory-exhaustion'))
    foreach ($id in @('CVE-2026-56848','CVE-2026-58043')) {
        $conditions = if ($id -eq 'CVE-2026-56848') { @('http2-server','use-after-free') } else { @('permission-model','path-prefix') }
        Add-ListItem $items (New-NodeRuntimeAdvisory $id 'HIGH' '2026-07-29' $jul2026 @(
            (New-NodeRuntimeRange '22.0.0' '22.23.2'), (New-NodeRuntimeRange '24.0.0' '24.18.1'), (New-NodeRuntimeRange '26.0.0' '26.5.1')
        ) @((New-NodeRuntimeFixedVersion 22 '22.23.2'),(New-NodeRuntimeFixedVersion 24 '24.18.1'),(New-NodeRuntimeFixedVersion 26 '26.5.1')) $conditions)
    }

    return [ordered]@{
        schemaVersion = '0.1.14'
        lastUpdated = '2026-10-06'
        expiresAfterDays = 30
        highRetentionDays = 365
        advisories = $items
    }
}

function Get-SecurityUpdate20261006Iocs {
    # Curated public-report supplement. Loading it does not renew older dataset freshness.
    return [ordered]@{
        packages = @(
            [ordered]@{ ecosystem='npm'; name='@7nohe/openapi-react-query-codegen'; versions=@('0.5.4','0.5.5','1.6.3','1.6.4','2.2.1','2.2.2','3.0.3','3.0.4','0.0.0-365d4eb738d3146583431948d3ba6e27a32556be','0.0.0-ec7876d6c917dad516ba69bbfafc948b834bf0ab'); sourceId='S01'; notes='Trinitite exact affected versions; no broader version range is asserted.'; severity='DANGER' },
            [ordered]@{ ecosystem='npm'; name='@memtensor/memos-cloud-openclaw-plugin'; versions=@('0.1.21','0.1.23','0.1.25'); sourceId='S04'; notes='supplychain.local runtime worm; intervening 0.1.22 and 0.1.24 were reported clean.'; severity='DANGER' },
            [ordered]@{ ecosystem='python'; name='memoryos'; versions=@('2.0.34'); sourceId='S05'; notes='supplychain.local Python distribution; import package is memos.'; severity='DANGER' },
            [ordered]@{ ecosystem='npm'; name='feishu-docx-mcp'; versions=@('0.3.2'); sourceId='S06'; notes='September 2026 Shai-Hulud recurrence; exact reported version.'; severity='DANGER' },
            [ordered]@{ ecosystem='npm'; name='bmc-i18n-extract-cli'; versions=@('1.1.1'); sourceId='S06'; notes='September 2026 Shai-Hulud recurrence; exact reported version.'; severity='DANGER' },
            [ordered]@{ ecosystem='npm'; name='blueai-cli'; versions=@('0.7.0'); sourceId='S06'; notes='September 2026 Shai-Hulud recurrence; exact reported version.'; severity='DANGER' },
            [ordered]@{ ecosystem='npm'; name='bmc-translate-utils'; versions=@('1.1.1'); sourceId='S06'; notes='September 2026 Shai-Hulud recurrence; exact reported version.'; severity='DANGER' },
            [ordered]@{ ecosystem='python'; name='anthropic-sdk'; versions=@('0.1.0'); sourceId='S07'; notes='Malicious impersonation package; distinct from the legitimate anthropic distribution.'; severity='DANGER' },
            [ordered]@{ ecosystem='npm'; name='virgil-cli'; versions=@('0.1.4'); sourceId='S08'; notes='Reported undisclosed conversation and tool-result forwarding; credential theft is not asserted.'; severity='DANGER' }
        )
        files = @(
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='8e5d1af68ca340ae0c6e8132cb00c686ec2d60502c1994d94ce353d1472ad5a3'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h01'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='b49afb7dba04cd99b357ce7c652c823a3707f28e130bd5c6645851a7adc030d6'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h02'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='59370c67b54a0ccaedd265e2356f04540b2fba1e1845300ef6de4d5437d99380'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h03'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='778d6f0058045d6a2ab9a7e1d3e3be8e7e6b4d9cc217d13949bf1dfbab759a7c'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h04'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='b24d121667f21f492cb9db34fbfd515d5922a8dd30b9c45215c7220abbb10ca8'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h05'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='e1f1162ece9a6e6ea21a20399cbf31c563a8149d433a68711f4223870c203d5a'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h06'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='b6012b2ff87f08f93ee53921c48db907ddbcf5461b03bb988083b01a36886237'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h07'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])(?:3FWCvzduYZg|nu|is_it_this_simple|index)\.js$'; sha256='709af2fdeb50324229e94c44c679a0fab18bd8e17d3864405989c526cbb63ad8'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S02'; ruleId='security-20261006-h08'; notes='Trinitite reported payload hash; individual version-to-hash correspondence is not asserted.' },
            [ordered]@{ pathPattern='(?i)[\\/]\.sckit[\\/]windows-(?:amd64|arm64)[\\/]sckit\.exe$'; sha256='56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be'; severity='DANGER'; ownerCheck='Packages'; artifactRole='package-runtime-binary'; sourceId='S03'; ruleId='security-20261006-h09'; notes='supplychain.local Windows sckit implant hash.' },
            [ordered]@{ pathPattern='(?i)[\\/]\.sckit[\\/]windows-(?:amd64|arm64)[\\/]sckit\.exe$'; sha256='d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26'; severity='DANGER'; ownerCheck='Packages'; artifactRole='package-runtime-binary'; sourceId='S03'; ruleId='security-20261006-h10'; notes='supplychain.local Windows sckit implant hash.' },
            [ordered]@{ pathPattern='(?i)[\\/]\.sckit[\\/]windows-(?:amd64|arm64)[\\/]sckit\.exe$'; sha256='16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047'; severity='DANGER'; ownerCheck='Packages'; artifactRole='package-runtime-binary'; sourceId='S03'; ruleId='security-20261006-h11'; notes='supplychain.local Windows sckit implant hash.' },
            [ordered]@{ pathPattern='(?i)[\\/]\.sckit[\\/]windows-(?:amd64|arm64)[\\/]sckit\.exe$'; sha256='f7c4014e284f3d56c452b8b222a287c54f73dc4a40a7e022e765ac8376362947'; severity='DANGER'; ownerCheck='Packages'; artifactRole='package-runtime-binary'; sourceId='S03'; ruleId='security-20261006-h12'; notes='supplychain.local Windows sckit implant hash.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])index\.js$'; sha256='e37e3ddeeaaa9e0c4fdbcb829b4895a6521031c80053fc436625b61e6ee5b1a6'; severity='DANGER'; ownerCheck='Packages'; artifactRole='npm-runtime'; sourceId='S06'; ruleId='security-20261006-h13'; notes='September Shai-Hulud root index.js payload hash.' },
            [ordered]@{ pathPattern='(?i)\.(?:vsix|zip)$'; sha256='a276b76d3b00f302bb4dfb3690125c85ff472b16049c3c37476ac5e51096df07'; severity='DANGER'; ownerCheck='IdeExtensions'; artifactRole='ide-archive'; sourceId='S11'; ruleId='security-20261006-h14'; notes='Confirmed malicious Marketplace artifact hash; extension identity alone is not sufficient.' },
            [ordered]@{ pathPattern='(?i)[\\/]out[\\/]extension\.js$'; sha256='5e68ca8c2097caccdb74d2752b85b85595a4bf646b442b8431a2416e87dbf268'; severity='DANGER'; ownerCheck='IdeExtensions'; artifactRole='ide-payload'; sourceId='S11'; ruleId='security-20261006-h15'; notes='Confirmed malicious Marketplace artifact hash; extension identity alone is not sufficient.' },
            [ordered]@{ pathPattern='(?i)(?:^|[\\/])app\.js$'; sha256='684c877a52d226d50584cb886ca8ec5bec6355d4de853f406734c79d5b387804'; severity='DANGER'; ownerCheck='IdeExtensions'; artifactRole='ide-payload'; sourceId='S11'; ruleId='security-20261006-h16'; notes='Confirmed malicious Marketplace artifact hash; extension identity alone is not sufficient.' }
        )
        actions = @(
            [ordered]@{ repository='actions-cool/issues-helper'; compromisedCommits=@('a0c53dd42fc842d2f9276c5a1d4f9a26abe8713d'); compromisedRefs=@('v2.2.1'); sourceId='S09'; notes='Mini Shai-Hulud: reported malicious immutable commit and historical ref. Re-enabled September 16 and disabled again September 25; current availability is not asserted.' }
        )
        advisories = @(
            [ordered]@{ id='CVE-2026-55158'; repository='wktk/conflibot'; upstreamSeverity='CRITICAL'; published='2026-08-17'; sourceUrl='https://github.com/advisories/GHSA-2qvg-qr73-mqxp'; sourceId='S10'; affectedRanges=@([ordered]@{ maxExclusive='1.2.1' }); fixedVersions=@('1.2.1','2.0.0'); conditions=@('pull_request_target','attacker-controlled-head-ref') }
        )
        extensions = @(
            [ordered]@{ id='microsoftvs.microsoftvs'; platform='vscode'; versions=@('*'); severity='INFO'; confidence='low'; matchType='id-watchlist'; sourceId='S11'; notes='Identity appears in the reported Marketplace campaign; version and cross-registry identity alone do not establish that this local artifact is malicious.'; allowNameFallback=$false },
            [ordered]@{ id='cosmic-themes.theme-cosmic-nebula'; platform='vscode'; versions=@('*'); severity='INFO'; confidence='low'; matchType='id-watchlist'; sourceId='S11'; notes='Identity appears in the reported Marketplace campaign; version and cross-registry identity alone do not establish that this local artifact is malicious.'; allowNameFallback=$false }
        )
        patterns = @(
            [ordered]@{ id='supplychain_local_campaign_host_marker'; regex='(?i)(?<![a-z0-9._-])(?:[a-z0-9-]+\.)*skyleen\.fr(?![a-z0-9._-])'; sourceId='S03'; severity='WARN'; title='Reported supplychain.local infrastructure marker'; notes='A bounded reported endpoint marker appears in executable context. The marker alone does not establish execution or compromise. Values redacted.'; contexts=@('code','execution-config','active-ai-config','executable-tooling') },
            [ordered]@{ id='shai_hulud_september_host_marker'; regex='(?i)(?<![a-z0-9._-])t\.m-kosche\.com(?![a-z0-9._-])'; sourceId='S06'; severity='WARN'; title='Reported Shai-Hulud infrastructure marker'; notes='A bounded reported endpoint marker appears in executable context. The marker alone does not establish execution or compromise. Values redacted.'; contexts=@('code','execution-config','active-ai-config','executable-tooling') },
            [ordered]@{ id='glassworm_theme_host_marker'; regex='(?i)(?<![a-z0-9._-])fingercakes4sale\.store(?![a-z0-9._-])'; sourceId='S11'; severity='WARN'; title='Reported GlassWorm theme infrastructure marker'; notes='A bounded reported endpoint marker appears in executable context. The marker alone does not establish execution or compromise. Values redacted.'; contexts=@('code','execution-config','active-ai-config','executable-tooling') },
            [ordered]@{ id='virgil_secondary_transfer_endpoint_marker'; regex='(?i)(?<![a-z0-9._-])api\.nm-streetwear\.space/vx/learn(?![a-z0-9_/-])'; sourceId='S08'; severity='WARN'; title='Reported conversation-forwarding endpoint marker'; notes='A bounded reported endpoint marker appears in executable context. The marker alone does not establish execution or compromise. Values redacted.'; contexts=@('code','execution-config','active-ai-config','executable-tooling') }
        )
    }
}

function Load-BuiltinIocs {
    $packages = New-ArrayList
    Add-BuiltinPackageIoc $packages 'npm' 'axios' @('1.14.1','0.30.4') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' 'plain-crypto-js' @('4.2.1') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' '@aifabrix/miso-client' @('4.7.2') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' '@iflow-mcp/watercrawl-watercrawl-mcp' @('1.3.0','1.3.1','1.3.2','1.3.3','1.3.4') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'python' 'litellm' @('1.82.7','1.82.8') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' 'keyv' @('6.0.0') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'flat-cache' @('6.1.24') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'file-entry-cache' @('11.1.6') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'cacheable' @('2.5.1') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@cacheable/memory' @('2.2.1') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@cacheable/net' @('2.1.1') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@cacheable/node-cache' @('3.1.2') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@cacheable/utils' @('2.5.1') 'Keyv/ChainDrop core fallback exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/generator-helpers' @('1.1.1') 'AsyncAPI compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/generator-components' @('0.7.1') 'AsyncAPI compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/generator' @('3.3.1') 'AsyncAPI compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/specs' @('6.11.2','6.11.2-alpha.1') 'AsyncAPI compromise exact versions'
    Add-BuiltinPackageIoc $packages 'npm' 'jscrambler' @('8.14.0','8.16.0','8.17.0','8.18.0','8.20.0') 'Jscrambler compromise exact versions'
    Add-BuiltinPackageIoc $packages 'npm' 'gulp-jscrambler' @('8.6.2') 'Jscrambler related compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'jscrambler-metro-plugin' @('9.0.2') 'Jscrambler related compromise exact version'
    foreach ($injectiveName in @(
        '@injectivelabs/sdk-ts','@injectivelabs/utils','@injectivelabs/networks','@injectivelabs/ts-types',
        '@injectivelabs/exceptions','@injectivelabs/wallet-base','@injectivelabs/wallet-core',
        '@injectivelabs/wallet-cosmos','@injectivelabs/wallet-private-key','@injectivelabs/wallet-evm',
        '@injectivelabs/wallet-trezor','@injectivelabs/wallet-cosmostation','@injectivelabs/wallet-ledger',
        '@injectivelabs/wallet-wallet-connect','@injectivelabs/wallet-magic','@injectivelabs/wallet-strategy',
        '@injectivelabs/wallet-turnkey','@injectivelabs/wallet-cosmos-strategy'
    )) {
        Add-BuiltinPackageIoc $packages 'npm' $injectiveName @('1.20.21') 'Injective compromise exact version'
    }
    Add-BuiltinPackageIoc $packages 'npm' '@bitwarden/cli' @('2026.4.0') 'Bitwarden CLI npm compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'react-native-country-select' @('0.3.91') 'React Native GlassWorm exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'react-native-international-phone-number' @('0.11.8') 'React Native GlassWorm exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'mbt' @('1.2.48') 'SAP CAP ecosystem compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@cap-js/db-service' @('2.10.1') 'SAP CAP ecosystem compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@cap-js/postgres' @('2.2.2') 'SAP CAP ecosystem compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@cap-js/sqlite' @('2.2.2') 'SAP CAP ecosystem compromise exact version'
    $paymentVersions = @('1.0.0','1.0.1','1.0.2','1.0.3')
    foreach ($paymentName in @('paysafe-checkout','paysafe-vault','neteller','skrill-payments','paysafe-js','paysafe-api','paysafe-node','paysafe-cards','paysafe-fraud','paysafe-kyc','skrill','skrill-sdk','paysafe-payments')) {
        Add-BuiltinPackageIoc $packages 'npm' $paymentName $paymentVersions 'Payment brand typosquat campaign exact versions'
    }
    foreach ($pythonPaymentName in @('paysafe-kyc','paysafe-payments','paysafe-sdk','paysafe-api')) {
        Add-BuiltinPackageIoc $packages 'python' $pythonPaymentName @('1.0.0') 'Python payment brand typosquat exact version'
    }

    $extensions = New-ArrayList
    Add-ListItem $extensions ([ordered]@{ id='nrwl.angular-console'; versions=@('18.95.0'); severity='DANGER'; notes='Known compromised Nx Console exposure version' })
    Add-ListItem $extensions ([ordered]@{ id='specstudio.code-wakatime-activity-tracker'; versions=@('*'); severity='DANGER'; notes='Known suspicious extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='floktokbok.autoimport'; versions=@('*'); severity='DANGER'; notes='Known suspicious extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='quartz.quartz-markdown-editor'; versions=@('0.3.0'); severity='DANGER'; notes='Known suspicious extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.ssh-tools'; versions=@('0.5.1'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.i18n-tools-plus'; versions=@('1.6.8'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.mind-map'; versions=@('1.0.61'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.scss-to-css-compile'; versions=@('1.3.4'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })
    foreach ($watchId in @('outsidestormcommand.monochromator-theme','keyacrosslaud.auto-loop-for-antigravity','krundoven.ironplc-fast-hub','boulderzitunnel.vscode-buddies','cubedivervolt.html-code-validate','winnerdomain17.version-lens-tool')) {
        Add-ListItem $extensions ([ordered]@{ id=$watchId; versions=@('*'); severity='WARN'; confidence='medium'; matchType='id-watchlist'; notes='Confirmed malicious extension ID; exact affected version was not independently established' })
    }
    foreach ($extensionIoc in @($extensions)) {
        $extensionIoc['platform'] = 'vscode'
        $extensionIoc['allowNameFallback'] = $false
    }

    $files = New-ArrayList
    Add-ListItem $files ([ordered]@{ path='%PROGRAMDATA%\wt.exe'; pathPattern='\\programdata\\wt\.exe$'; severity='DANGER'; notes='Axios/plain-crypto-js campaign persistence filename baseline' })
    Add-BuiltinFileHashIoc $files '\\extensions\\.*\.wasm$' '558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f' 'GlassWASM malicious module hash'
    Add-BuiltinFileHashIoc $files '\\extensions\\.*\.vsix$' '3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58' 'GlassWASM flint-debug VSIX hash'
    Add-BuiltinFileHashIoc $files '\\extensions\\.*\.vsix$' '97c275e3406ad6576529f41604ad138c5bdc4297d195bf61b049e14f6b30adfd' 'GlassWorm downloaded VSIX hash'
    Add-BuiltinFileHashIoc $files '\\extensions\\.*\.(exe|dll|node|so|dylib)$' '1b62b7c2ed7cc296ce821f977ef7b22bae59ef1dcdb9a34ae19467ee39bcf168' 'GlassWorm native installer hash'
    Add-BuiltinFileHashIoc $files '\\extensions\\.*\.(exe|dll|node|so|dylib)$' '4ebfe8f66ca7e9751060b3301b5e8838d6017593cdae748541de83bfa28183bd' 'GlassWorm native installer hash'
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\(?:dist\\)?setup\.js$' 'a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60' 'Jscrambler malicious setup.js hash'
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\(?:dist\\)?intro\.js$' 'a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86' 'Jscrambler malicious intro.js hash'
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\package\.json$' 'bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0' 'Jscrambler malicious package.json hash'
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\.*\.(exe|dll|node)$' 'b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903' 'Jscrambler malicious Windows payload hash'
    Add-BuiltinFileHashIoc $files '\\\.github\\actions\\.*\.(js|cjs|mjs)$' '9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015' 'Vendored codfish semantic-release action payload hash'

    Add-BuiltinFileHashIoc $files '(?i)(?:^|[\\/])setup\.mjs$' '54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668' 'Keyv/ChainDrop core fallback setup.mjs hash'
    Add-BuiltinFileHashIoc $files '(?i)(?:^|[\\/])setup\.mjs$' 'fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb' 'Keyv/ChainDrop core fallback repository loader hash'
    Add-BuiltinFileHashIoc $files '(?i)(?:^|[\\/])(?:Math_Symbol\.js|math_init\.js)$' '9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc' 'Keyv/ChainDrop core fallback payload hash'

    $actions = New-ArrayList
    Add-ListItem $actions ([ordered]@{
        repository='codfish/semantic-release-action'
        compromisedCommits=@('5792aba0e2180b9b80b77644370a6889d5817456','bcb6b1d409144318e8fad2171d6fe06d02299d1a')
        compromisedRefs=@('v2','v2.2.1','v3','v3.0.0','v3.1.0','v3.2.0','v3.3.0','v3.4.0','v3.5.0','v4','v4.0.0','v4.0.1','v5','v5.0.0')
        notes='Known compromised GitHub Action commits and historically affected mutable refs'
    })

    $patterns = New-ArrayList
    $domains = New-ArrayList
    Add-ListItem $domains 'flipboxstudio.info'
    Add-ListItem $domains 'sentry.anyclaw.store'
    Add-ListItem $domains 'sfrclak.com'
    Add-ListItem $domains 'dodod.lat'
    Add-ListItem $domains 'npm-cache.com'
    $ips = New-ArrayList
    Add-ListItem $ips '164.92.88.210'

    $securityUpdate = Get-SecurityUpdate20261006Iocs
    foreach ($entry in @($securityUpdate.packages)) { Add-ListItem $packages $entry }
    foreach ($entry in @($securityUpdate.files)) { Add-ListItem $files $entry }
    foreach ($entry in @($securityUpdate.actions)) { Add-ListItem $actions $entry }
    foreach ($entry in @($securityUpdate.extensions)) { Add-ListItem $extensions $entry }
    foreach ($entry in @($securityUpdate.patterns)) { Add-ListItem $patterns $entry }

    return [ordered]@{
        packages = $packages
        extensions = $extensions
        files = $files
        actions = $actions
        actionAdvisories = @($securityUpdate.advisories)
        patterns = $patterns
        domains = $domains
        ips = $ips
        nodeRuntimes = Load-BuiltinNodeRuntimeIocs
    }
}

function Get-PropertyValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-ExtensionIocPlatform {
    param($Ioc)
    $platform = [string](Get-PropertyValue $Ioc 'platform')
    if ([string]::IsNullOrWhiteSpace($platform)) { return 'vscode' }
    return $platform.ToLowerInvariant()
}

function Test-ActionAdvisoryData {
    param($Advisory)
    if ($null -eq $Advisory) { return $false }
    $id = [string](Get-PropertyValue $Advisory 'id')
    $repository = [string](Get-PropertyValue $Advisory 'repository')
    $source = [string](Get-PropertyValue $Advisory 'sourceUrl')
    if ($id -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,8}$' -or $repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { return $false }
    if ($source -cnotmatch '^https://github\.com/advisories/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$') { return $false }
    if ([string](Get-PropertyValue $Advisory 'upstreamSeverity') -notin @('CRITICAL','HIGH','MODERATE','MEDIUM','LOW')) { return $false }
    try { $published=[DateTime]::ParseExact([string](Get-PropertyValue $Advisory 'published'), 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture); if ($published.Date -gt [DateTime]::UtcNow.Date) { return $false } }
    catch { return $false }
    $ranges = @((Get-PropertyValue $Advisory 'affectedRanges'))
    $fixed = @((Get-PropertyValue $Advisory 'fixedVersions'))
    if ($ranges.Count -lt 1 -or $ranges.Count -gt 4 -or $fixed.Count -lt 1 -or $fixed.Count -gt 8) { return $false }
    foreach ($range in $ranges) {
        $maximum = [string](Get-PropertyValue $range 'maxExclusive')
        if ($maximum -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or $null -eq (ConvertTo-NodeRuntimeVersion $maximum)) { return $false }
        $minimum = [string](Get-PropertyValue $range 'minInclusive')
        if (-not [string]::IsNullOrEmpty($minimum) -and ($minimum -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or $null -eq (ConvertTo-NodeRuntimeVersion $minimum))) { return $false }
        if (-not [string]::IsNullOrEmpty($minimum) -and (Compare-NodeRuntimeVersion -Left (ConvertTo-NodeRuntimeVersion $minimum) -Right (ConvertTo-NodeRuntimeVersion $maximum)) -ge 0) { return $false }
    }
    foreach ($version in $fixed) {
        if ([string]$version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or $null -eq (ConvertTo-NodeRuntimeVersion ([string]$version))) { return $false }
    }
    if ([string](Get-PropertyValue $Advisory 'sourceId') -cnotmatch '^S[0-9]{2}$') { return $false }
    $conditions=@((Get-PropertyValue $Advisory 'conditions'))
    if ($conditions.Count -lt 1 -or $conditions.Count -gt 8) { return $false }
    foreach ($condition in $conditions) { if ([string]$condition -notmatch '^[a-z][a-z0-9_-]{0,79}$') { return $false } }
    return $true
}

function Test-LocalIocEntry {
    param($Entry, [string]$Section)
    if ($null -eq $Entry -or $Entry -is [string]) { return $false }
    if ($Section -in @('packages','extensions')) {
        $versions = @((Get-PropertyValue $Entry 'versions'))
        if ($versions.Count -eq 0) { return $false }
        foreach ($version in $versions) {
            if ($Section -eq 'extensions' -and [string]$version -eq '*') { continue }
            $ecosystem = if ($Section -eq 'packages') { [string](Get-PropertyValue $Entry 'ecosystem') } else { 'npm' }
            if (-not (Test-IsExactPackageVersionText -Version ([string]$version) -Ecosystem $ecosystem)) { return $false }
        }
        if ($Section -eq 'packages') {
            $packageName = [string](Get-PropertyValue $Entry 'name')
            if ([string](Get-PropertyValue $Entry 'ecosystem') -ieq 'python') {
                return ($packageName.Length -le 128 -and $packageName -match '\A[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\z')
            }
            return ([string](Get-PropertyValue $Entry 'ecosystem') -in @('npm','python') -and
                [string](Get-PropertyValue $Entry 'name') -match '^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$')
        }
        return (-not [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $Entry 'id')))
    }
    if ($Section -eq 'actions') {
        if ([string](Get-PropertyValue $Entry 'repository') -notmatch '^[a-z0-9_.-]+/[a-z0-9_.-]+$') { return $false }
        $commits = @((Get-PropertyValue $Entry 'compromisedCommits') | Where-Object {$null -ne $_})
        $refs = @((Get-PropertyValue $Entry 'compromisedRefs') | Where-Object {-not [string]::IsNullOrWhiteSpace([string]$_)})
        foreach ($commit in $commits) { if ([string]$commit -notmatch '^[0-9a-f]{40}$') { return $false } }
        return (($commits.Count + $refs.Count) -gt 0)
    }
    if ($Section -eq 'files') {
        $hash = [string](Get-PropertyValue $Entry 'sha256')
        if (-not [string]::IsNullOrEmpty($hash) -and $hash -notmatch '^[0-9a-f]{64}$') { return $false }
        $hasSelector = (-not [string]::IsNullOrEmpty($hash))
        foreach ($field in @('path','pathPattern','fileName','pathContains')) {
            if (-not [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $Entry $field))) { $hasSelector = $true }
        }
        if (-not $hasSelector) { return $false }
    }
    $pattern = [string](Get-PropertyValue $Entry $(if ($Section -eq 'patterns') { 'regex' } else { 'pathPattern' }))
    if ($Section -eq 'patterns' -and ([string]::IsNullOrWhiteSpace($pattern) -or [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $Entry 'id')))) { return $false }
    if (-not [string]::IsNullOrEmpty($pattern)) {
        try { $null = New-Object Text.RegularExpressions.Regex($pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2)) }
        catch { return $false }
    }
    return $true
}

function Load-LocalIocs {
    if ($null -eq $script:Context.iocs) {
        $script:Context.iocs = Load-BuiltinIocs
    }

    $files = @(
        'known-packages.json',
        'known-extensions.json',
        'known-files.json',
        'known-actions.json',
        'suspicious-patterns.json'
    )
    $iocDir = Join-Path $script:BaseDir 'iocs'
    if (-not (Test-Path -LiteralPath $iocDir -PathType Container)) {
        foreach ($name in $files) {
            Set-IocDataSetStatus -Name $name -FilePath (Join-Path $iocDir $name) -Status 'missing'
        }
        Add-Finding -Severity 'WARN' -Category 'IOC_DATA_DIRECTORY_MISSING' -Title 'Local IOC data directory is missing' -Path $iocDir -Evidence 'The scanner is using only its smaller built-in baseline.' -Recommendation 'Restore the shipped iocs directory before relying on negative results or publishing a release.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
        return
    }

    foreach ($name in $files) {
        $file = Join-Path $iocDir $name
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            Set-IocDataSetStatus -Name $name -FilePath $file -Status 'missing'
            Add-Finding -Severity 'WARN' -Category 'IOC_DATA_FILE_MISSING' -Title 'A shipped local IOC file is missing' -Path $file -Evidence 'The corresponding local IOC additions were not loaded; the smaller built-in baseline remains active.' -Recommendation 'Restore the missing IOC JSON before relying on negative results or publishing a release.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
            continue
        }
        try {
            $text = [System.IO.File]::ReadAllText($file)
            if ([string]::IsNullOrWhiteSpace($text)) {
                Set-IocDataSetStatus -Name $name -FilePath $file -Status 'invalid'
                Add-Finding -Severity 'WARN' -Category 'IOC_DATA_FILE_EMPTY' -Title 'A shipped local IOC file is empty' -Path $file -Evidence 'The empty IOC file was not loaded.' -Recommendation 'Restore a reviewed IOC JSON before publishing a release.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
                continue
            }
            $json = $text | ConvertFrom-Json -ErrorAction Stop
            $lastUpdated = [string](Get-PropertyValue $json 'lastUpdated')
            $sourceSet = [string](Get-PropertyValue $json 'sourceSet')
            $expires = 0
            $updatedDate = $null
            $datasetStatus = 'invalid'
            try {
                $expires = [int](Get-PropertyValue $json 'expiresAfterDays')
                $updatedDate = [DateTime]::ParseExact($lastUpdated, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            }
            catch { }
            if ($null -eq $updatedDate -or $updatedDate.Date -gt (Get-Date).Date -or $expires -lt 1 -or $expires -gt 365 -or [string]::IsNullOrWhiteSpace($sourceSet)) {
                $datasetStatus = 'invalid'
                Add-Finding -Severity 'WARN' -Category 'IOC_DATA_HEADER_INVALID' -Title 'Local IOC file freshness metadata is invalid' -Path $file -Evidence 'lastUpdated, sourceSet, or expiresAfterDays failed validation; IOC entries are still loaded as historical indicators.' -Recommendation 'Repair the metadata from a documented manual review before publishing a release.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
            }
            elseif ($updatedDate.AddDays($expires) -lt (Get-Date)) {
                $datasetStatus = 'stale'
                Add-Finding -Severity 'WARN' -Category 'IOC_DATA_STALE' -Title 'Local IOC file is stale' -Path $file -Evidence ("lastUpdated={0}; expiresAfterDays={1}; historical exact indicators remain enabled." -f $lastUpdated,$expires) -Recommendation 'Manually review and update local IOC JSON from trusted sources before publishing a release.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
            }
            else {
                $datasetStatus = 'current'
            }

            $requiredSection = @{
                'known-packages.json'='packages'; 'known-files.json'='files'; 'known-extensions.json'='extensions'
                'known-actions.json'='actions'; 'suspicious-patterns.json'='patterns'
            }[$name]
            $sectionProperty = $json.PSObject.Properties[$requiredSection]
            $sectionValid = ($null -ne $sectionProperty -and $sectionProperty.Value -is [Array] -and @($sectionProperty.Value).Count -gt 0)
            if ($sectionValid) {
                foreach ($entry in $sectionProperty.Value) {
                    if (-not (Test-LocalIocEntry $entry $requiredSection)) { $sectionValid = $false; break }
                }
            }
            if (-not $sectionValid) {
                $datasetStatus = 'invalid'
                Add-Finding -Severity 'WARN' -Category 'IOC_DATA_SECTION_INVALID' -Title 'A required local IOC section is missing or invalid' -Path $file -Evidence ("Required nonempty array with valid entries: {0}; historical built-in indicators remain enabled." -f $requiredSection) -Recommendation 'Restore the complete reviewed IOC dataset before publication.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
            }

            if ($name -eq 'known-actions.json') {
                $advisories = @((Get-PropertyValue $json 'advisories'))
                $advisoriesValid = ([string](Get-PropertyValue $json 'schemaVersion') -eq '0.1.23' -and $advisories.Count -ge 1 -and $advisories.Count -le 128)
                foreach ($advisory in @($advisories | Select-Object -First 128)) {
                    if (-not (Test-ActionAdvisoryData $advisory)) { $advisoriesValid = $false }
                }
                if ($advisoriesValid) {
                    foreach ($advisory in $advisories) {
                        $exists = $false
                        foreach ($existingAdvisory in @($script:Context.iocs.actionAdvisories)) {
                            if ([string](Get-PropertyValue $existingAdvisory 'id') -eq [string](Get-PropertyValue $advisory 'id') -and [string](Get-PropertyValue $existingAdvisory 'repository') -ieq [string](Get-PropertyValue $advisory 'repository')) { $exists = $true; break }
                        }
                        if (-not $exists) { $script:Context.iocs.actionAdvisories += $advisory }
                    }
                }
                if (-not $advisoriesValid) {
                    $datasetStatus = 'invalid'
                    Add-Finding -Severity 'WARN' -Category 'ACTION_ADVISORY_DATA_INVALID' -Title 'Action advisory section is missing or invalid' -Path $file -Evidence 'Historical action indicators and the limited built-in advisory remain available; this dataset is not release-ready.' -Recommendation 'Restore the reviewed 0.1.23 advisory section without renewing unreviewed historical data.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
                }
            }

            $packages = Get-PropertyValue $json 'packages'
            foreach ($package in @($packages)) {
                if ($null -ne $package) {
                    Add-ListItem $script:Context.iocs.packages ([ordered]@{
                        ecosystem = [string](Get-PropertyValue $package 'ecosystem')
                        name = [string](Get-PropertyValue $package 'name')
                        versions = @((Get-PropertyValue $package 'versions'))
                        severity = [string](Get-PropertyValue $package 'severity')
                        notes = [string](Get-PropertyValue $package 'notes')
                        sourceId = [string](Get-PropertyValue $package 'sourceId')
                    })
                }
            }

            $extensions = Get-PropertyValue $json 'extensions'
            foreach ($extension in @($extensions)) {
                if ($null -ne $extension) {
                    Add-ListItem $script:Context.iocs.extensions ([ordered]@{
                        id = ([string](Get-PropertyValue $extension 'id')).ToLowerInvariant()
                        versions = @((Get-PropertyValue $extension 'versions'))
                        severity = [string](Get-PropertyValue $extension 'severity')
                        confidence = [string](Get-PropertyValue $extension 'confidence')
                        matchType = [string](Get-PropertyValue $extension 'matchType')
                        platform = $(
                            $platform = [string](Get-PropertyValue $extension 'platform')
                            if ([string]::IsNullOrWhiteSpace($platform)) { 'vscode' } else { $platform.ToLowerInvariant() }
                        )
                        name = [string](Get-PropertyValue $extension 'name')
                        allowNameFallback = [bool](Get-PropertyValue $extension 'allowNameFallback')
                        notes = [string](Get-PropertyValue $extension 'notes')
                        sourceId = [string](Get-PropertyValue $extension 'sourceId')
                    })
                }
            }

            $actions = Get-PropertyValue $json 'actions'
            foreach ($action in @($actions)) {
                if ($null -ne $action) {
                    Add-ListItem $script:Context.iocs.actions ([ordered]@{
                        repository = ([string](Get-PropertyValue $action 'repository')).ToLowerInvariant()
                        compromisedCommits = @((Get-PropertyValue $action 'compromisedCommits'))
                        compromisedRefs = @((Get-PropertyValue $action 'compromisedRefs'))
                        notes = [string](Get-PropertyValue $action 'notes')
                        sourceId = [string](Get-PropertyValue $action 'sourceId')
                    })
                }
            }

            $knownFiles = Get-PropertyValue $json 'files'
            foreach ($knownFile in @($knownFiles)) {
                if ($null -ne $knownFile) {
                    Add-ListItem $script:Context.iocs.files ([ordered]@{
                        path = [string](Get-PropertyValue $knownFile 'path')
                        pathPattern = [string](Get-PropertyValue $knownFile 'pathPattern')
                        fileName = [string](Get-PropertyValue $knownFile 'fileName')
                        pathContains = [string](Get-PropertyValue $knownFile 'pathContains')
                        sha256 = ([string](Get-PropertyValue $knownFile 'sha256')).ToLowerInvariant()
                        severity = [string](Get-PropertyValue $knownFile 'severity')
                        notes = [string](Get-PropertyValue $knownFile 'notes')
                        ownerCheck = [string](Get-PropertyValue $knownFile 'ownerCheck')
                        artifactRole = [string](Get-PropertyValue $knownFile 'artifactRole')
                        sourceId = [string](Get-PropertyValue $knownFile 'sourceId')
                        ruleId = [string](Get-PropertyValue $knownFile 'ruleId')
                    })
                }
            }

            $domains = Get-PropertyValue $json 'domains'
            foreach ($domainEntry in @($domains)) {
                if ($null -eq $domainEntry) { continue }
                $domain = [string]$domainEntry
                $domainValue = Get-PropertyValue $domainEntry 'domain'
                if (-not [string]::IsNullOrEmpty($domainValue)) {
                    $domain = [string]$domainValue
                }
                if (-not [string]::IsNullOrWhiteSpace($domain)) {
                    Add-ListItem $script:Context.iocs.domains $domain.ToLowerInvariant()
                }
            }

            $ips = Get-PropertyValue $json 'ips'
            foreach ($ipEntry in @($ips)) {
                if ($null -eq $ipEntry) { continue }
                $ip = [string]$ipEntry
                $ipValue = Get-PropertyValue $ipEntry 'ip'
                if (-not [string]::IsNullOrEmpty($ipValue)) {
                    $ip = [string]$ipValue
                }
                if (-not [string]::IsNullOrWhiteSpace($ip)) {
                    Add-ListItem $script:Context.iocs.ips $ip
                }
            }

            $patterns = Get-PropertyValue $json 'patterns'
            foreach ($pattern in @($patterns)) {
                if ($null -ne $pattern) {
                    Add-ListItem $script:Context.iocs.patterns ([ordered]@{
                        id = [string](Get-PropertyValue $pattern 'id')
                        regex = [string](Get-PropertyValue $pattern 'regex')
                        severity = [string](Get-PropertyValue $pattern 'severity')
                        title = [string](Get-PropertyValue $pattern 'title')
                        notes = [string](Get-PropertyValue $pattern 'notes')
                        contexts = @((Get-PropertyValue $pattern 'contexts'))
                        sourceId = [string](Get-PropertyValue $pattern 'sourceId')
                    })
                }
            }
            Set-IocDataSetStatus -Name $name -FilePath $file -Status $datasetStatus -LastUpdated $lastUpdated -ExpiresAfterDays $expires
        }
        catch {
            Set-IocDataSetStatus -Name $name -FilePath $file -Status 'invalid'
            Add-Finding -Severity 'WARN' -Category 'IOC_JSON_INVALID' -Title 'Local IOC JSON could not be parsed' -Path $file -Evidence 'The IOC file was ignored because JSON parsing failed.' -Recommendation 'Fix or remove the malformed local IOC file.'
        }
    }
}

function Get-CampaignIocCanonicalHash {
    param($Packages)
    $lines = New-ArrayList
    foreach ($package in @($Packages)) {
        $name = ([string](Get-PropertyValue $package 'name')).Trim().ToLowerInvariant()
        $versions = @((Get-PropertyValue $package 'versions') | ForEach-Object { ([string]$_).Trim() })
        Add-ListItem $lines ($name + '|' + [string]::Join(',', [string[]]$versions))
    }
    $projection = [string]::Join("`n", [string[]]$lines.ToArray()) + "`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($projection)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Load-KeyvChainDropCampaignIocs {
    $file = Join-Path $script:BaseDir 'iocs\campaign-keyv-chaindrop-20260806.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Set-IocDataSetStatus -Name 'campaign-keyv-chaindrop-20260806.json' -FilePath $file -Status 'missing'
        $script:Context.campaignIocData.status = 'builtin-fallback-missing'
        Add-Finding -Severity 'WARN' -Category 'CAMPAIGN_IOC_DATA_MISSING' -Title 'Keyv/ChainDrop campaign IOC snapshot is missing' -Path $file -Evidence 'The full campaign snapshot was not found; built-in core fallback indicators remain active.' -Recommendation 'Restore the complete scanner distribution before relying on full campaign coverage.' -RiskType 'limitation' -Confidence 'high' -Check 'Packages' -DetectionMethod 'metadata'
        return
    }

    try {
        $info = Get-Item -LiteralPath $file -Force -ErrorAction Stop
        if ($info.Length -gt 4194304) { throw 'campaign IOC file exceeds size limit' }
        $json = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json -ErrorAction Stop
        if ([string](Get-PropertyValue $json 'schemaVersion') -ne '1') { throw 'schema mismatch' }
        if ([string](Get-PropertyValue $json 'campaignId') -ne 'keyv-chaindrop-2026-08') { throw 'campaign mismatch' }
        $integrity = Get-PropertyValue $json 'integrity'
        $packages = @((Get-PropertyValue $json 'packages'))
        $expectedPackages = [int](Get-PropertyValue $integrity 'packageCount')
        $expectedPairs = [int](Get-PropertyValue $integrity 'packageVersionPairCount')
        if ($expectedPackages -ne 443 -or $expectedPairs -ne 2235 -or $packages.Count -ne $expectedPackages) { throw 'count header mismatch' }

        $seenPairs = @{}
        $pairCount = 0
        foreach ($package in $packages) {
            $name = ([string](Get-PropertyValue $package 'name')).Trim()
            if ([string]::IsNullOrWhiteSpace($name) -or $name -cne $name.ToLowerInvariant() -or $name -notmatch '^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$') { throw 'invalid package name' }
            $versions = @((Get-PropertyValue $package 'versions'))
            if ($versions.Count -eq 0) { throw 'empty version set' }
            foreach ($versionEntry in $versions) {
                $version = ([string]$versionEntry).Trim()
                if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') { throw 'non-exact campaign version' }
                $pairKey = ($name + '|' + $version).ToLowerInvariant()
                if ($seenPairs.ContainsKey($pairKey)) { throw 'duplicate package/version pair' }
                $seenPairs[$pairKey] = $true
                $pairCount++
            }
        }
        if ($pairCount -ne $expectedPairs) { throw 'pair count mismatch' }
        $actualCanonicalHash = Get-CampaignIocCanonicalHash -Packages $packages
        $expectedCanonicalHash = ([string](Get-PropertyValue $integrity 'sha256')).ToLowerInvariant()
        if ($expectedCanonicalHash -notmatch '^[0-9a-f]{64}$' -or $actualCanonicalHash -ne $expectedCanonicalHash -or $expectedCanonicalHash -ne $script:KeyvChainDropApprovedPackageHash) { throw 'canonical hash mismatch' }

        $validatedFiles = New-ArrayList
        foreach ($knownFile in @((Get-PropertyValue $json 'files'))) {
            $hash = ([string](Get-PropertyValue $knownFile 'sha256')).ToLowerInvariant()
            $pathPattern = [string](Get-PropertyValue $knownFile 'pathPattern')
            if ($hash -notmatch '^[0-9a-f]{64}$' -or [string]::IsNullOrWhiteSpace($pathPattern)) { throw 'invalid campaign file IOC' }
            $null = New-Object System.Text.RegularExpressions.Regex($pathPattern)
            Add-ListItem $validatedFiles ([ordered]@{
                pathPattern = $pathPattern
                sha256 = $hash
                severity = 'DANGER'
                notes = [string](Get-PropertyValue $knownFile 'notes')
                campaignId = 'keyv-chaindrop-2026-08'
            })
        }
        $approvedFileIndicators = @(
            '54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668|(?i)(?:^|[\\/])setup\.mjs$',
            'fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb|(?i)(?:^|[\\/])setup\.mjs$',
            '9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc|(?i)(?:^|[\\/])(?:Math_Symbol\.js|math_init\.js)$'
        )
        if ($validatedFiles.Count -ne $approvedFileIndicators.Count) { throw 'campaign file IOC count mismatch' }
        for ($i = 0; $i -lt $approvedFileIndicators.Count; $i++) {
            $actualIndicator = ([string](Get-PropertyValue $validatedFiles[$i] 'sha256')) + '|' + ([string](Get-PropertyValue $validatedFiles[$i] 'pathPattern'))
            if ($actualIndicator -cne $approvedFileIndicators[$i]) { throw 'campaign file IOC approval mismatch' }
        }

        $validatedPatterns = New-ArrayList
        foreach ($pattern in @((Get-PropertyValue $json 'patterns'))) {
            $value = ([string]$pattern).Trim()
            if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 128 -or $value -match '[\\/:]') { throw 'invalid campaign marker pattern' }
            Add-ListItem $validatedPatterns $value
        }
        $approvedPatterns = @('setup.mjs','Math_Symbol.js','math_init.js','format-results.txt')
        if ($validatedPatterns.Count -ne $approvedPatterns.Count) { throw 'campaign marker count mismatch' }
        for ($i = 0; $i -lt $approvedPatterns.Count; $i++) {
            if ([string]$validatedPatterns[$i] -cne $approvedPatterns[$i]) { throw 'campaign marker approval mismatch' }
        }

        $validatedGitRefs = New-ArrayList
        foreach ($gitRef in @((Get-PropertyValue $json 'gitRefs'))) {
            $value = ([string]$gitRef).Trim()
            if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256 -or $value -match '(?:^/|/$|\.\.|\\|[~^:?*\[])') { throw 'invalid campaign Git ref' }
            Add-ListItem $validatedGitRefs $value
        }
        if ($validatedGitRefs.Count -ne 1 -or [string]$validatedGitRefs[0] -cne 'dependabot/github_actions/format/setup-formatter') { throw 'campaign Git ref approval mismatch' }

        $lastReviewed = [string](Get-PropertyValue $json 'lastReviewed')
        $reviewDate = [DateTime]::ParseExact($lastReviewed, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        if ($reviewDate.Date -gt (Get-Date).Date) { throw 'campaign review date is in the future' }
        $reviewAfterDays = [int](Get-PropertyValue $json 'reviewAfterDays')
        if ($reviewAfterDays -lt 1 -or $reviewAfterDays -gt 3650) { throw 'invalid review period' }
        $isStale = $reviewDate.AddDays($reviewAfterDays) -lt (Get-Date)

        foreach ($package in $packages) {
            Add-ListItem $script:Context.iocs.packages ([ordered]@{
                ecosystem = 'npm'
                name = [string](Get-PropertyValue $package 'name')
                versions = @((Get-PropertyValue $package 'versions'))
                severity = 'DANGER'
                notes = 'Keyv/ChainDrop reviewed campaign snapshot exact version'
                campaignId = 'keyv-chaindrop-2026-08'
            })
        }
        foreach ($knownFile in @($validatedFiles)) { Add-ListItem $script:Context.iocs.files $knownFile }

        $script:Context.campaignIocData.lastReviewed = $lastReviewed
        $script:Context.campaignIocData.packageCount = $expectedPackages
        $script:Context.campaignIocData.packageVersionPairCount = $expectedPairs
        $script:Context.campaignIocData.gitRefs = @($validatedGitRefs)
        $script:Context.campaignIocData.patterns = @($validatedPatterns)
        $script:Context.campaignIocData.status = 'full'
        $script:Context.campaignIocData.builtinFallbackActive = $false
        Add-ScanStat -Name 'campaignPackagesLoaded' -Amount $expectedPackages
        Add-ScanStat -Name 'campaignPackageVersionPairsLoaded' -Amount $expectedPairs
        Set-IocDataSetStatus -Name 'campaign-keyv-chaindrop-20260806.json' -FilePath $file -Status $(if ($isStale) { 'stale' } else { 'current' }) -LastUpdated $lastReviewed -ExpiresAfterDays $reviewAfterDays

        if ($isStale) {
            $script:Context.campaignIocData.status = 'stale-full'
            Add-Finding -Severity 'WARN' -Category 'CAMPAIGN_IOC_DATA_STALE' -Title 'Keyv/ChainDrop campaign IOC snapshot is due for review' -Path $file -Evidence 'Historical exact indicators remain enabled, but the snapshot review date has expired.' -Recommendation 'Review the campaign snapshot against trusted source material without removing historical exact indicators.' -RiskType 'limitation' -Confidence 'high' -Check 'Packages' -DetectionMethod 'metadata'
        }
    }
    catch {
        Set-IocDataSetStatus -Name 'campaign-keyv-chaindrop-20260806.json' -FilePath $file -Status 'invalid'
        $script:Context.campaignIocData.status = 'builtin-fallback-invalid'
        $script:Context.campaignIocData.lastReviewed = $null
        $script:Context.campaignIocData.packageCount = 0
        $script:Context.campaignIocData.packageVersionPairCount = 0
        Add-Finding -Severity 'WARN' -Category 'CAMPAIGN_IOC_DATA_INVALID' -Title 'Keyv/ChainDrop campaign IOC snapshot is invalid' -Path $file -Evidence 'The campaign file failed schema, exact-version, count, regex, or canonical-hash validation and was ignored as a unit.' -Recommendation 'Restore a validated campaign snapshot; built-in core fallback indicators remain active.' -RiskType 'limitation' -Confidence 'high' -Check 'Packages' -DetectionMethod 'metadata'
    }
}

function Get-IocSeverityRank {
    param([string]$Severity)
    $normalized = if ($null -eq $Severity) { '' } else { $Severity.Trim().ToUpperInvariant() }
    if ($script:SeverityRank.ContainsKey($normalized)) {
        return [int]$script:SeverityRank[$normalized]
    }
    return -1
}

function Finalize-IocIndexes {
    $script:Context.knownFileIocCandidates = $null
    $packageIndex = @{}
    $fileHashIndex = @{}
    $conflicts = 0
    foreach ($ioc in @($script:Context.iocs.packages)) {
        $ecosystem = ([string](Get-PropertyValue $ioc 'ecosystem')).Trim().ToLowerInvariant()
        $name = ConvertTo-PackageIocName -Ecosystem $ecosystem -Name ([string](Get-PropertyValue $ioc 'name'))
        if ([string]::IsNullOrWhiteSpace($ecosystem) -or [string]::IsNullOrWhiteSpace($name)) { continue }
        foreach ($versionEntry in @((Get-PropertyValue $ioc 'versions'))) {
            $version = ConvertTo-PackageIocVersion -Ecosystem $ecosystem -Version ([string]$versionEntry)
            if ([string]::IsNullOrWhiteSpace($version)) { continue }
            $key = $ecosystem + '|' + $name + '|' + $version.ToLowerInvariant()
            if ($packageIndex.ContainsKey($key)) {
                $existing = $packageIndex[$key]
                if ((Get-IocSeverityRank ([string](Get-PropertyValue $ioc 'severity'))) -gt (Get-IocSeverityRank ([string](Get-PropertyValue $existing 'severity')))) {
                    $packageIndex[$key] = $ioc
                }
                $conflicts++
            }
            else {
                $packageIndex[$key] = $ioc
            }
        }
    }
    foreach ($ioc in @($script:Context.iocs.files)) {
        $hash = ([string](Get-PropertyValue $ioc 'sha256')).ToLowerInvariant()
        if ($hash -match '^[0-9a-f]{64}$' -and -not $fileHashIndex.ContainsKey($hash)) { $fileHashIndex[$hash] = $ioc }
    }
    $script:Context.iocIndexes.packages = $packageIndex
    $script:Context.iocIndexes.fileHashes = $fileHashIndex
    $script:Context.scanStats.packageIocIndexEntries = $packageIndex.Count
    $script:Context.scanStats.packageIocDuplicatesMerged = $conflicts
}

function ConvertTo-PackageIocName {
    param([string]$Ecosystem, [string]$Name)
    $normalized = $Name.Trim().ToLowerInvariant()
    if ($Ecosystem -ieq 'python') { $normalized = [regex]::Replace($normalized, '[-_.]+', '-') }
    return $normalized
}

function Get-ExactPackageIocMatch {
    param([string]$Ecosystem, [string]$Name, [string]$Version)
    if ($null -eq $script:Context -or $null -eq $script:Context.iocIndexes) { return $null }
    $normalizedName = ConvertTo-PackageIocName -Ecosystem $Ecosystem -Name $Name
    $normalizedVersion = ConvertTo-PackageIocVersion -Ecosystem $Ecosystem -Version $Version
    if ([string]::IsNullOrWhiteSpace($normalizedName) -or [string]::IsNullOrWhiteSpace($normalizedVersion)) { return $null }
    $key = $Ecosystem.Trim().ToLowerInvariant() + '|' + $normalizedName + '|' + $normalizedVersion.ToLowerInvariant()
    if ($script:Context.iocIndexes.packages.ContainsKey($key)) { return $script:Context.iocIndexes.packages[$key] }
    $wildcardKey = $Ecosystem.Trim().ToLowerInvariant() + '|' + $normalizedName + '|*'
    if ($script:Context.iocIndexes.packages.ContainsKey($wildcardKey)) { return $script:Context.iocIndexes.packages[$wildcardKey] }
    return $null
}

function ConvertTo-NodeRuntimeVersion {
    param([string]$Value, [switch]$AllowFourth)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $match = [regex]::Match($Value.Trim(), '^[vV]?(?<major>[0-9]+)\.(?<minor>[0-9]+)\.(?<patch>[0-9]+)(?:\.(?<fourth>[0-9]+))?(?<pre>-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
    if (-not $match.Success) { return $null }
    if ($match.Groups['fourth'].Success -and -not $AllowFourth) { return $null }
    try {
        $major = [int]$match.Groups['major'].Value
        $minor = [int]$match.Groups['minor'].Value
        $patch = [int]$match.Groups['patch'].Value
        $pre = [string]$match.Groups['pre'].Value
        if ($pre.StartsWith('-')) { $pre = $pre.Substring(1) }
        $normalized = ('{0}.{1}.{2}' -f $major,$minor,$patch)
        if (-not [string]::IsNullOrEmpty($pre)) { $normalized += '-' + $pre }
        return [ordered]@{ major=$major; minor=$minor; patch=$patch; prerelease=$pre; normalized=$normalized }
    }
    catch { return $null }
}

function Compare-NodeRuntimePrerelease {
    param([string]$Left, [string]$Right)
    if ([string]::IsNullOrEmpty($Left) -and [string]::IsNullOrEmpty($Right)) { return 0 }
    if ([string]::IsNullOrEmpty($Left)) { return 1 }
    if ([string]::IsNullOrEmpty($Right)) { return -1 }
    $leftParts = $Left -split '\.'
    $rightParts = $Right -split '\.'
    $count = [Math]::Max($leftParts.Count, $rightParts.Count)
    for ($i = 0; $i -lt $count; $i++) {
        if ($i -ge $leftParts.Count) { return -1 }
        if ($i -ge $rightParts.Count) { return 1 }
        $leftNumeric = $leftParts[$i] -match '^[0-9]+$'
        $rightNumeric = $rightParts[$i] -match '^[0-9]+$'
        if ($leftNumeric -and $rightNumeric) {
            $leftNumberText = $leftParts[$i].TrimStart('0')
            $rightNumberText = $rightParts[$i].TrimStart('0')
            if ([string]::IsNullOrEmpty($leftNumberText)) { $leftNumberText = '0' }
            if ([string]::IsNullOrEmpty($rightNumberText)) { $rightNumberText = '0' }
            if ($leftNumberText.Length -lt $rightNumberText.Length) { return -1 }
            if ($leftNumberText.Length -gt $rightNumberText.Length) { return 1 }
            $numericComparison = [string]::CompareOrdinal($leftNumberText, $rightNumberText)
            if ($numericComparison -lt 0) { return -1 }
            if ($numericComparison -gt 0) { return 1 }
        }
        elseif ($leftNumeric) { return -1 }
        elseif ($rightNumeric) { return 1 }
        else {
            $comparison = [string]::CompareOrdinal($leftParts[$i], $rightParts[$i])
            if ($comparison -lt 0) { return -1 }
            if ($comparison -gt 0) { return 1 }
        }
    }
    return 0
}

function Compare-NodeRuntimeVersion {
    param($Left, $Right)
    foreach ($property in @('major','minor','patch')) {
        $leftValue = [int]$Left[$property]
        $rightValue = [int]$Right[$property]
        if ($leftValue -lt $rightValue) { return -1 }
        if ($leftValue -gt $rightValue) { return 1 }
    }
    return (Compare-NodeRuntimePrerelease -Left ([string]$Left.prerelease) -Right ([string]$Right.prerelease))
}

function Test-NodeRuntimeVersionInRange {
    param($Version, $Range)
    $min = ConvertTo-NodeRuntimeVersion ([string](Get-PropertyValue $Range 'minInclusive'))
    $max = ConvertTo-NodeRuntimeVersion ([string](Get-PropertyValue $Range 'maxExclusive'))
    if ($null -eq $Version -or $null -eq $min -or $null -eq $max) { return $false }
    return ((Compare-NodeRuntimeVersion $Version $min) -ge 0 -and (Compare-NodeRuntimeVersion $Version $max) -lt 0)
}

function Normalize-NodeRuntimeAdvisory {
    param($Advisory)
    if ($null -eq $Advisory) { return $null }
    $id = ([string](Get-PropertyValue $Advisory 'id')).ToUpperInvariant()
    $severity = ([string](Get-PropertyValue $Advisory 'upstreamSeverity')).ToUpperInvariant()
    $published = [string](Get-PropertyValue $Advisory 'published')
    $source = [string](Get-PropertyValue $Advisory 'source')
    if ($id -notmatch '^CVE-[0-9]{4}-[0-9]{4,7}$' -or $severity -notin @('CRITICAL','HIGH') -or $source -notmatch '^https://nodejs\.org/') { return $null }
    try {
        $publishedDate = [DateTime]::ParseExact($published, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        if ($publishedDate.Date -gt (Get-Date).Date) { return $null }
    }
    catch { return $null }

    $ranges = New-ArrayList
    foreach ($range in @((Get-PropertyValue $Advisory 'affectedRanges'))) {
        $minText = [string](Get-PropertyValue $range 'minInclusive')
        $maxText = [string](Get-PropertyValue $range 'maxExclusive')
        $min = ConvertTo-NodeRuntimeVersion $minText
        $max = ConvertTo-NodeRuntimeVersion $maxText
        if ($null -eq $min -or $null -eq $max -or (Compare-NodeRuntimeVersion $min $max) -ge 0) { return $null }
        Add-ListItem $ranges ([ordered]@{ minInclusive=$min.normalized; maxExclusive=$max.normalized })
    }
    if ($ranges.Count -eq 0) { return $null }

    $fixed = New-ArrayList
    foreach ($entry in @((Get-PropertyValue $Advisory 'fixedVersions'))) {
        $version = ConvertTo-NodeRuntimeVersion ([string](Get-PropertyValue $entry 'version'))
        $major = 0
        try { $major = [int](Get-PropertyValue $entry 'major') } catch { return $null }
        if ($null -eq $version -or $version.major -ne $major) { return $null }
        Add-ListItem $fixed ([ordered]@{ major=$major; version=$version.normalized })
    }
    if ($fixed.Count -eq 0) { return $null }

    $conditions = New-ArrayList
    foreach ($conditionValue in @((Get-PropertyValue $Advisory 'conditions'))) {
        $condition = ([string]$conditionValue).Trim()
        if ($condition -match '^[A-Za-z0-9._-]{1,64}$') { Add-ListItem $conditions $condition }
    }
    return [ordered]@{
        id=$id
        upstreamSeverity=$severity
        published=$published
        source=$source
        affectedRanges=@($ranges.ToArray() | Sort-Object minInclusive,maxExclusive)
        fixedVersions=@($fixed.ToArray() | Sort-Object major,version)
        conditions=@($conditions.ToArray() | Sort-Object -Unique)
    }
}

function Get-NodeRuntimeAdvisoryFingerprint {
    param($Advisory)
    $ranges = @($Advisory.affectedRanges | ForEach-Object { ([string]$_.minInclusive) + '..' + ([string]$_.maxExclusive) })
    $fixed = @($Advisory.fixedVersions | ForEach-Object { ([string]$_.major) + '=' + ([string]$_.version) })
    return [string]::Join('|', @(
        [string]$Advisory.id,
        [string]$Advisory.upstreamSeverity,
        [string]$Advisory.published,
        [string]$Advisory.source,
        [string]::Join(',', [string[]]$ranges),
        [string]::Join(',', [string[]]$fixed),
        [string]::Join(',', [string[]]@($Advisory.conditions))
    ))
}

function Load-LocalNodeRuntimeIocs {
    if ($null -eq $script:Context.iocs.nodeRuntimes) { $script:Context.iocs.nodeRuntimes = Load-BuiltinNodeRuntimeIocs }
    $file = Join-Path $script:BaseDir 'iocs\known-node-runtimes.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Set-IocDataSetStatus -Name 'known-node-runtimes.json' -FilePath $file -Status 'missing' -LastUpdated $script:Context.nodeRuntimeDataLastUpdated -ExpiresAfterDays 30
        return
    }
    try {
        $json = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json -ErrorAction Stop
        $schemaVersion = [string](Get-PropertyValue $json 'schemaVersion')
        $lastUpdated = [string](Get-PropertyValue $json 'lastUpdated')
        $expiresAfterDays = 0
        $highRetentionDays = 0
        $parsedUpdated = $null
        try {
            $expiresAfterDays = [int](Get-PropertyValue $json 'expiresAfterDays')
            $highRetentionDays = [int](Get-PropertyValue $json 'highRetentionDays')
            $parsedUpdated = [DateTime]::ParseExact($lastUpdated, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        }
        catch { }
        if ($schemaVersion -ne '0.1.14' -or $expiresAfterDays -ne 30 -or $highRetentionDays -ne 365 -or
            $null -eq $parsedUpdated -or $parsedUpdated.Date -gt (Get-Date).Date) {
            Set-IocDataSetStatus -Name 'known-node-runtimes.json' -FilePath $file -Status 'invalid' -LastUpdated $lastUpdated -ExpiresAfterDays $expiresAfterDays
            Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_IOC_HEADER_INVALID' -Title 'Local Node.js runtime IOC header is invalid' -Path $file -Evidence 'The local Node.js IOC header failed schema, retention, date, or expiry validation; the built-in baseline remains active.' -Recommendation 'Restore a schemaVersion 0.1.14 file with expiresAfterDays=30, highRetentionDays=365, and a valid review date.' -RiskType 'limitation' -Confidence 'high' -Check 'NodeRuntime' -DetectionMethod 'metadata'
            $script:Context.nodeRuntimeLocalDataStatus = 'invalid-builtin-active'
            return
        }
        $localAdvisories = @((Get-PropertyValue $json 'advisories'))
        $existingById = @{}
        foreach ($existing in @($script:Context.iocs.nodeRuntimes.advisories)) {
            $normalizedExisting = Normalize-NodeRuntimeAdvisory $existing
            if ($null -ne $normalizedExisting) { $existingById[[string]$normalizedExisting.id] = $normalizedExisting }
        }
        $seenBaseline = @{}
        $seenLocalIds = @{}
        $accepted = 0
        $conflicts = 0
        $invalidEntries = 0
        foreach ($entry in $localAdvisories) {
            $normalized = Normalize-NodeRuntimeAdvisory $entry
            if ($null -eq $normalized) {
                $invalidEntries++
                Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_IOC_ENTRY_INVALID' -Title 'Node.js runtime advisory entry is invalid' -Path $file -Evidence 'An advisory entry failed schema or trusted-source validation and was ignored.' -Recommendation 'Use an official nodejs.org security release and exact affected/fixed version boundaries.' -Check 'NodeRuntime' -DetectionMethod 'metadata'
                continue
            }
            $id = [string]$normalized.id
            if ($seenLocalIds.ContainsKey($id)) {
                $invalidEntries++
                Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_IOC_ENTRY_INVALID' -Title 'Duplicate Node.js runtime advisory ID' -Path $file -Evidence ("Duplicate advisory ID: {0}; the built-in baseline remains active." -f $id) -Recommendation 'Keep each advisory ID unique before publication.' -Check 'NodeRuntime' -DetectionMethod 'metadata'
                continue
            }
            $seenLocalIds[$id] = $true
            if ($existingById.ContainsKey($id)) {
                $seenBaseline[$id] = $true
                if ((Get-NodeRuntimeAdvisoryFingerprint $existingById[$id]) -ne (Get-NodeRuntimeAdvisoryFingerprint $normalized)) {
                    $conflicts++
                    Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_IOC_CONFLICT' -Title 'Local Node.js advisory conflicts with the built-in baseline' -Path $file -Evidence ("Conflicting advisory ID: {0}. Built-in data was retained." -f $id) -Recommendation 'Restore the shipped entry or add a separately identified supplemental advisory.' -Check 'NodeRuntime' -DetectionMethod 'metadata'
                }
                continue
            }
            Add-ListItem $script:Context.iocs.nodeRuntimes.advisories $normalized
            $existingById[$id] = $normalized
            $accepted++
        }
        $builtinIds = @((Load-BuiltinNodeRuntimeIocs).advisories | ForEach-Object { [string]$_.id })
        $missingBuiltin = @($builtinIds | Where-Object { -not $seenBaseline.ContainsKey($_) })
        if ($missingBuiltin.Count -gt 0) {
            Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_IOC_PARITY_MISMATCH' -Title 'Shipped Node.js IOC file does not mirror the built-in baseline' -Path $file -Evidence ("Missing or unmatched built-in advisory count: {0}. Built-in data remains active." -f $missingBuiltin.Count) -Recommendation 'Restore the shipped known-node-runtimes.json before distribution.' -Check 'NodeRuntime' -DetectionMethod 'metadata'
        }
        if ($conflicts -eq 0 -and $invalidEntries -eq 0 -and $missingBuiltin.Count -eq 0) {
            $script:Context.nodeRuntimeDataLastUpdated = $parsedUpdated.ToString('yyyy-MM-dd')
            $script:Context.nodeRuntimeLocalDataStatus = if ($accepted -gt 0) { 'baseline-plus-local' } else { 'baseline-parity' }
            $nodeStatus = if ($parsedUpdated.AddDays($expiresAfterDays) -lt (Get-Date)) { 'stale' } else { 'current' }
            Set-IocDataSetStatus -Name 'known-node-runtimes.json' -FilePath $file -Status $nodeStatus -LastUpdated $lastUpdated -ExpiresAfterDays $expiresAfterDays
        }
        else {
            Set-IocDataSetStatus -Name 'known-node-runtimes.json' -FilePath $file -Status 'invalid' -LastUpdated $lastUpdated -ExpiresAfterDays $expiresAfterDays
            $script:Context.nodeRuntimeLocalDataStatus = 'invalid-builtin-active'
        }
    }
    catch {
        Set-IocDataSetStatus -Name 'known-node-runtimes.json' -FilePath $file -Status 'invalid'
        Add-Finding -Severity 'WARN' -Category 'IOC_JSON_INVALID' -Title 'Local Node.js runtime IOC JSON could not be parsed' -Path $file -Evidence 'The Node.js IOC file was ignored because JSON parsing failed; the built-in baseline remains active.' -Recommendation 'Restore or repair known-node-runtimes.json.' -Check 'NodeRuntime' -DetectionMethod 'metadata'
        $script:Context.nodeRuntimeLocalDataStatus = 'invalid-builtin-active'
    }
}

function Test-NodeRuntimeDataStaleness {
    if (-not (Test-CheckEnabled 'NodeRuntime')) { return }
    try {
        $updated = [DateTime]::ParseExact([string]$script:Context.nodeRuntimeDataLastUpdated, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        if ($updated.AddDays(30) -lt (Get-Date)) {
            $file = Join-Path $script:BaseDir 'iocs\known-node-runtimes.json'
            $existingStatus = Get-PropertyValue $script:Context.iocDataSets['known-node-runtimes.json'] 'status'
            if ($existingStatus -notin @('missing','invalid')) {
                Set-IocDataSetStatus -Name 'known-node-runtimes.json' -FilePath $file -Status 'stale' -LastUpdated $updated.ToString('yyyy-MM-dd') -ExpiresAfterDays 30
            }
            Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_DATA_STALE' -Title 'Node.js vulnerability data is older than 30 days' -Path $file -Evidence ("lastUpdated={0}; expiresAfterDays=30; the offline baseline may not include recent security releases." -f $updated.ToString('yyyy-MM-dd')) -Recommendation 'Manually review official Node.js security releases and update the offline baseline before publishing a release.' -RiskType 'limitation' -Confidence 'high' -Check 'NodeRuntime' -DetectionMethod 'metadata'
        }
    }
    catch { }
}

function Get-NodeRuntimeFixedVersionForMajor {
    param($Advisory, [int]$Major)
    foreach ($entry in @($Advisory.fixedVersions)) {
        if ([int](Get-PropertyValue $entry 'major') -eq $Major) { return [string](Get-PropertyValue $entry 'version') }
    }
    return ''
}

function Get-NodeRuntimeConditionStatus {
    param($Advisory)
    $conditions = @($Advisory.conditions)
    if ($conditions.Count -eq 0) { return 'not-required' }
    $knownMatched = 0
    $unknown = 0
    foreach ($condition in $conditions) {
        if ([string]$condition -eq 'windows') { $knownMatched++ } else { $unknown++ }
    }
    if ($knownMatched -gt 0 -and $unknown -eq 0) { return 'matched' }
    if ($knownMatched -gt 0 -and $unknown -gt 0) { return 'partial' }
    return 'unknown'
}

function Get-NodeRuntimeAdvisoryMatches {
    param($Version)
    $result = New-ArrayList
    if ($null -eq $Version -or $null -eq $script:Context.iocs.nodeRuntimes) { return @() }
    foreach ($advisory in @($script:Context.iocs.nodeRuntimes.advisories)) {
        foreach ($range in @($advisory.affectedRanges)) {
            if (Test-NodeRuntimeVersionInRange -Version $Version -Range $range) {
                Add-ListItem $result ([ordered]@{
                    advisory = $advisory
                    fixedVersion = Get-NodeRuntimeFixedVersionForMajor -Advisory $advisory -Major ([int]$Version.major)
                    conditionStatus = Get-NodeRuntimeConditionStatus $advisory
                })
                break
            }
        }
    }
    return @($result.ToArray())
}

function Get-HighestNodeRuntimeFixedVersion {
    param([object[]]$Matches)
    $highest = $null
    foreach ($match in @($Matches)) {
        $candidate = ConvertTo-NodeRuntimeVersion ([string]$match.fixedVersion)
        if ($null -ne $candidate -and ($null -eq $highest -or (Compare-NodeRuntimeVersion $candidate $highest) -gt 0)) { $highest = $candidate }
    }
    if ($null -eq $highest) { return '' }
    return [string]$highest.normalized
}

function Get-AggregatedNodeRuntimeConditionStatus {
    param([object[]]$Matches)
    $statuses = @($Matches | ForEach-Object { [string]$_.conditionStatus } | Sort-Object -Unique)
    if ($statuses -contains 'partial') { return 'partial' }
    if ($statuses -contains 'unknown') { return 'unknown' }
    if ($statuses -contains 'matched') { return 'matched' }
    return 'not-required'
}

function Add-NodeRuntimeInventoryEntry {
    param(
        $Version,
        [string]$Path,
        [string]$EvidenceKind,
        $Line,
        [object[]]$Matches
    )
    if ($null -eq $Version -or $null -eq $script:Context.nodeRuntimeInventory -or $null -eq $script:Context.nodeRuntimeInventoryKeys) { return }
    $sourceType = if ($EvidenceKind -eq 'installed-binary-metadata') { 'installed-binary' } else { 'project-reference' }
    $redactedPath = ConvertTo-RedactedPath $Path
    $key = ([string]$sourceType) + '|' + ([string]$redactedPath) + '|' + ([string]$Line) + '|' + ([string]$Version.normalized) + '|' + ([string]$EvidenceKind)
    if ($script:Context.nodeRuntimeInventoryKeys.ContainsKey($key)) { return }
    $script:Context.nodeRuntimeInventoryKeys[$key] = $true
    if ($script:Context.nodeRuntimeInventory.Count -ge [int]$script:NodeRuntimeInventoryLimit) {
        Add-ScanStat -Name 'nodeRuntimeInventoryEntriesOmitted'
        return
    }

    $advisoryIds = @($Matches | ForEach-Object { [string]$_.advisory.id } | Sort-Object -Unique)
    $upstreamSeverity = 'NONE'
    if (@($Matches | Where-Object { [string]$_.advisory.upstreamSeverity -eq 'CRITICAL' }).Count -gt 0) {
        $upstreamSeverity = 'CRITICAL'
    }
    elseif (@($Matches | Where-Object { [string]$_.advisory.upstreamSeverity -eq 'HIGH' }).Count -gt 0) {
        $upstreamSeverity = 'HIGH'
    }
    $conditionStatus = if (@($Matches).Count -gt 0) { Get-AggregatedNodeRuntimeConditionStatus $Matches } else { 'not-applicable' }
    Add-ListItem $script:Context.nodeRuntimeInventory ([ordered]@{
        sourceType = $sourceType
        evidenceKind = $EvidenceKind
        detectedVersion = [string]$Version.normalized
        advisoryStatus = $(if (@($Matches).Count -gt 0) { 'affected' } else { 'not-affected-in-offline-baseline' })
        upstreamSeverity = $upstreamSeverity
        advisoryCount = @($advisoryIds).Count
        advisoryIds = @($advisoryIds)
        conditionStatus = $conditionStatus
        path = $redactedPath
        line = $Line
    })
}

function Add-NodeRuntimeVersionFinding {
    param(
        [string]$VersionText,
        [string]$Path,
        [string]$EvidenceKind,
        [string]$DetectionMethod,
        $Line,
        [switch]$AllowFourth
    )
    Add-ScanStat -Name 'nodeRuntimeVersionReferencesInspected'
    $isInstalledBinary = ($EvidenceKind -eq 'installed-binary-metadata')
    $version = ConvertTo-NodeRuntimeVersion $VersionText -AllowFourth:$AllowFourth
    if ($null -eq $version) {
        Register-NodeRuntimeUnresolvedReference -Path $Path
        return
    }
    if ($isInstalledBinary) {
        Add-ScanStat -Name 'nodeRuntimeInstalledVersionsEvaluated'
    }
    else {
        Add-ScanStat -Name 'nodeRuntimeProjectVersionsEvaluated'
    }
    $matches = @(Get-NodeRuntimeAdvisoryMatches $version)
    if ($matches.Count -eq 0) {
        if ($isInstalledBinary) {
            Add-ScanStat -Name 'nodeRuntimeInstalledNotAffectedVersions'
        }
        else {
            Add-ScanStat -Name 'nodeRuntimeProjectNotAffectedReferences'
        }
        Add-NodeRuntimeInventoryEntry -Version $version -Path $Path -EvidenceKind $EvidenceKind -Line $Line -Matches @()
        return
    }
    if ($isInstalledBinary) {
        Add-ScanStat -Name 'nodeRuntimeInstalledVulnerableVersions'
    }
    else {
        Add-ScanStat -Name 'nodeRuntimeProjectVulnerableReferences'
    }
    Add-NodeRuntimeInventoryEntry -Version $version -Path $Path -EvidenceKind $EvidenceKind -Line $Line -Matches $matches

    foreach ($upstreamSeverity in @('CRITICAL','HIGH')) {
        $severityMatches = @($matches | Where-Object { [string]$_.advisory.upstreamSeverity -eq $upstreamSeverity })
        if ($severityMatches.Count -eq 0) { continue }
        $scannerSeverity = if ($EvidenceKind -eq 'manifest-constraint') { 'INFO' } else { 'WARN' }
        $confidence = if ($EvidenceKind -eq 'installed-binary-metadata') { 'high' } elseif ($EvidenceKind -eq 'manifest-constraint') { 'low' } else { 'medium' }
        $ids = @($severityMatches | ForEach-Object { [string]$_.advisory.id } | Sort-Object -Unique)
        $fixedVersion = Get-HighestNodeRuntimeFixedVersion $severityMatches
        $conditionStatus = Get-AggregatedNodeRuntimeConditionStatus $severityMatches
        if ($upstreamSeverity -eq 'CRITICAL') { Add-ScanStat -Name 'nodeRuntimeCriticalMatches' } else { Add-ScanStat -Name 'nodeRuntimeHighMatches' }
        $category = if ($EvidenceKind -eq 'manifest-constraint') { 'NODE_RUNTIME_VULNERABILITY_CONSTRAINT' } else { 'NODE_RUNTIME_VULNERABILITY_VERSION' }
        $title = if ($EvidenceKind -eq 'installed-binary-metadata') { 'Installed Node.js version matches an offline vulnerability advisory' } else { 'Project Node.js version reference matches an offline vulnerability advisory' }
        $recommendation = if ([string]::IsNullOrEmpty($fixedVersion)) {
            'Review the official Node.js security release and select a supported patched runtime.'
        }
        else {
            "Review the project or installation and update this major line to Node.js $fixedVersion or later."
        }
        Add-Finding -Severity $scannerSeverity -Category $category -Title $title -Path $Path -Line $Line -SourceContext 'node-runtime' `
            -Evidence ("Static version match only; upstreamSeverity={0}; detectedVersion={1}; advisoryCount={2}; conditionStatus={3}. No binary or project code was executed." -f $upstreamSeverity,$version.normalized,$ids.Count,$conditionStatus) `
            -Recommendation $recommendation -RiskType 'vulnerability' -Confidence $confidence -Check 'NodeRuntime' -DetectionMethod $DetectionMethod `
            -Vulnerability ([ordered]@{ advisoryIds=$ids; upstreamSeverity=$upstreamSeverity; detectedVersion=$version.normalized; evidenceKind=$EvidenceKind; fixedVersionForMajor=$fixedVersion; conditionStatus=$conditionStatus })
    }
}

function Register-NodeRuntimeUnresolvedReference {
    param([string]$Path)
    Add-ScanStat -Name 'nodeRuntimeUnresolvedReferences'
    if ($null -ne $script:Context.nodeRuntimeUnresolvedPaths -and $script:Context.nodeRuntimeUnresolvedPaths.Count -lt 3) {
        $redacted = ConvertTo-RedactedPath $Path
        if (-not [string]::IsNullOrWhiteSpace($redacted) -and -not @($script:Context.nodeRuntimeUnresolvedPaths).Contains($redacted)) {
            Add-ListItem $script:Context.nodeRuntimeUnresolvedPaths $redacted
        }
    }
}

function Get-FirstNonCommentNodeRuntimeValue {
    param([string]$Text)
    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimmed) -and -not $trimmed.StartsWith('#')) { return ($trimmed -split '\s+')[0] }
    }
    return ''
}

function Add-NodeRuntimeTextReference {
    param([string]$Value, [System.IO.FileInfo]$File, [string]$EvidenceKind, $Line)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    Add-NodeRuntimeVersionFinding -VersionText $Value.Trim().Trim('"').Trim("'") -Path $File.FullName -EvidenceKind $EvidenceKind -DetectionMethod 'static-file' -Line $Line
}

function Scan-NodeRuntimeReference {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text) -or -not (Test-CheckEnabled 'NodeRuntime')) { return }
    $name = $File.Name.ToLowerInvariant()
    $path = $File.FullName.ToLowerInvariant() -replace '/', '\'
    if ($name -in @('.nvmrc','.node-version')) {
        Add-NodeRuntimeTextReference -Value (Get-FirstNonCommentNodeRuntimeValue $Text) -File $File -EvidenceKind 'version-manager-pin' -Line 1
        return
    }
    if ($name -eq '.tool-versions') {
        $lineNumber = 0
        foreach ($lineText in ($Text -split "`r?`n")) {
            $lineNumber++
            $match = [regex]::Match($lineText, '^\s*nodejs\s+(.+?)\s*$')
            if (-not $match.Success) { continue }
            foreach ($value in ($match.Groups[1].Value -split '\s+')) {
                Add-NodeRuntimeTextReference -Value $value -File $File -EvidenceKind 'version-manager-pin' -Line $lineNumber
            }
        }
        return
    }
    if ($name -in @('.mise.toml','mise.toml')) {
        $lineNumber = 0
        foreach ($lineText in ($Text -split "`r?`n")) {
            $lineNumber++
            $match = [regex]::Match($lineText, '^\s*(?:node|nodejs)\s*=\s*["'']([^"'']+)["'']')
            if ($match.Success) { Add-NodeRuntimeTextReference -Value $match.Groups[1].Value -File $File -EvidenceKind 'version-manager-pin' -Line $lineNumber }
        }
        return
    }
    if ($name -eq 'package.json') {
        if (Test-IsNodeModulesPath $File.FullName) { return }
        try {
            $json = $Text | ConvertFrom-Json -ErrorAction Stop
            $volta = Get-PropertyValue (Get-PropertyValue $json 'volta') 'node'
            if (-not [string]::IsNullOrWhiteSpace([string]$volta)) { Add-NodeRuntimeTextReference -Value ([string]$volta) -File $File -EvidenceKind 'version-manager-pin' }
            $engine = Get-PropertyValue (Get-PropertyValue $json 'engines') 'node'
            if (-not [string]::IsNullOrWhiteSpace([string]$engine)) { Add-NodeRuntimeTextReference -Value ([string]$engine) -File $File -EvidenceKind 'manifest-constraint' }
        }
        catch { Register-NodeRuntimeUnresolvedReference -Path $File.FullName }
        return
    }
    if ($name -like 'dockerfile*') {
        $lineNumber = 0
        foreach ($lineText in ($Text -split "`r?`n")) {
            $lineNumber++
            $match = [regex]::Match($lineText, '(?i)^\s*FROM\s+node:[vV]?([0-9]+\.[0-9]+\.[0-9]+)')
            if ($match.Success) { Add-NodeRuntimeTextReference -Value $match.Groups[1].Value -File $File -EvidenceKind 'container-image-pin' -Line $lineNumber }
            elseif ($lineText -match '(?i)^\s*FROM\s+node:') { Register-NodeRuntimeUnresolvedReference -Path $File.FullName }
        }
        return
    }
    if ($path -match '\\.devcontainer\\devcontainer\.json$') {
        try {
            $json = $Text | ConvertFrom-Json -ErrorAction Stop
            $imageValue = [string](Get-PropertyValue $json 'image')
            $match = [regex]::Match($imageValue, '(?i)(?:^|/)node:[vV]?([0-9]+\.[0-9]+\.[0-9]+)')
            if ($match.Success) { Add-NodeRuntimeTextReference -Value $match.Groups[1].Value -File $File -EvidenceKind 'container-image-pin' }
            elseif ($imageValue -match '(?i)(?:^|/)node:') { Register-NodeRuntimeUnresolvedReference -Path $File.FullName }
        }
        catch { Register-NodeRuntimeUnresolvedReference -Path $File.FullName }
        return
    }
    if ($path -match '\\.github\\workflows\\[^\\]+\.ya?ml$') {
        $lines = @($Text -split "`r?`n")
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch '(?i)uses\s*:\s*actions/setup-node@') { continue }
            $limit = [Math]::Min($lines.Count - 1, $i + 12)
            $found = $false
            for ($j = $i + 1; $j -le $limit; $j++) {
                if ($lines[$j] -match '^\s*-\s*uses\s*:' -or $lines[$j] -match '^\s*uses\s*:') { break }
                $match = [regex]::Match($lines[$j], '(?i)^\s*node-version\s*:\s*["'']?([^\s"''#]+)')
                if ($match.Success) {
                    Add-NodeRuntimeTextReference -Value $match.Groups[1].Value -File $File -EvidenceKind 'ci-runtime-pin' -Line ($j + 1)
                    $found = $true
                    break
                }
            }
            if (-not $found) { Register-NodeRuntimeUnresolvedReference -Path $File.FullName }
        }
    }
}

function Scan-NodeRuntimeBinary {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File -or $File.Name.ToLowerInvariant() -ne 'node.exe' -or -not (Test-CheckEnabled 'NodeRuntime')) { return $false }
    Add-ScanStat -Name 'nodeRuntimeBinariesInspected'
    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
        $identity = ([string]$info.ProductName) + '|' + ([string]$info.FileDescription) + '|' + ([string]$info.OriginalFilename)
        if ($identity -notmatch '(?i)(node\.js|node\.exe|nodejs)') {
            Add-ScanStat -Name 'nodeRuntimeVersionReadFailures'
            return $false
        }
        $versionText = [string]$info.ProductVersion
        if ($null -eq (ConvertTo-NodeRuntimeVersion $versionText -AllowFourth)) { $versionText = [string]$info.FileVersion }
        if ($null -eq (ConvertTo-NodeRuntimeVersion $versionText -AllowFourth)) {
            Add-ScanStat -Name 'nodeRuntimeVersionReadFailures'
            return $true
        }
        Add-NodeRuntimeVersionFinding -VersionText $versionText -Path $File.FullName -EvidenceKind 'installed-binary-metadata' -DetectionMethod 'metadata' -AllowFourth
    }
    catch { Add-ScanStat -Name 'nodeRuntimeVersionReadFailures' }
    return $true
}

function Test-IsReparsePoint {
    param($FileSystemInfo)
    if ($null -eq $FileSystemInfo) { return $false }
    return (($FileSystemInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Test-IsAlwaysSkipDirectory {
    param([System.IO.DirectoryInfo]$Directory)
    if ($null -eq $Directory) { return $true }
    return (@('.git', '.hg', '.svn') -contains $Directory.Name.ToLowerInvariant())
}

function Test-IsNormallySkippedDirectory {
    param([System.IO.DirectoryInfo]$Directory)
    if ($null -eq $Directory) { return $true }
    $name = $Directory.Name.ToLowerInvariant()
    $fullName = $Directory.FullName.ToLowerInvariant() -replace '/', '\'
    $skip = @(
        'node_modules','.venv','venv','env','__pycache__','.tox','.mypy_cache',
        '.pytest_cache','vendor','.next','.nuxt','.svelte-kit','dist','build',
        'out','target','bin','obj','.cache','.tmp','tmp','reports'
    )
    if (($skip -contains $name) -and ($name -in @('vendor','dist','build','out','bin')) -and $fullName -match '\\\.codex\\plugins\\cache\\') {
        return $false
    }
    return ($skip -contains $name)
}

function Test-IsDefaultSkipDirectory {
    param([System.IO.DirectoryInfo]$Directory)
    if (Test-IsAlwaysSkipDirectory $Directory) { return $true }
    if ($Deep) { return $false }
    return (Test-IsNormallySkippedDirectory $Directory)
}

function Test-IsSecretInventoryFile {
    param([string]$FilePath)
    if ([string]::IsNullOrEmpty($FilePath)) {
        return $false
    }
    $p = $FilePath.ToLowerInvariant()
    if ($p -match '\\\.codex\\auth\.json$') { return $true }
    if ($p -match '\\\.claude\\auth\.json$') { return $true }
    if ($p -match '\\\.cursor\\auth\.json$') { return $true }
    if ($p -match '\\\.windsurf\\auth\.json$') { return $true }
    if ($p -match '\\(\.gemini|\.continue|\.opencode)\\(?:auth|credentials|oauth_creds|tokens)\.json$') { return $true }
    if ($p -match '\\\.git-credentials$') { return $true }
    $leaf = [System.IO.Path]::GetFileName($p)
    if ($leaf -match '^\.env(?:\..+)?$' -and $leaf -notmatch '^\.env\.(example|sample|template)$') { return $true }
    if ($p -match '\\\.npmrc$') { return $true }
    if ($p -match '\\\.pypirc$') { return $true }
    if ($p -match '\\\.netrc$') { return $true }
    if ($p -match '\\\.ssh\\id_(rsa|ed25519|ecdsa|dsa)$') { return $true }
    if ($p -match '\\\.aws\\credentials$') { return $true }
    if ($p -match '\\\.kube\\config$') { return $true }
    return $false
}

function Get-SecurityCandidateMetadata {
    param([string]$Path)
    if ($null -eq $script:Context -or $null -eq $script:Context.securityCandidateMetadata -or [string]::IsNullOrWhiteSpace($Path)) { return $null }
    try { $key = [System.IO.Path]::GetFullPath($Path).ToLowerInvariant() } catch { return $null }
    if ($script:Context.securityCandidateMetadata.ContainsKey($key)) { return $script:Context.securityCandidateMetadata[$key] }
    return $null
}

function Register-SecurityCandidateMetadata {
    param([string]$Path, [string]$Kind, [string]$OwnerCheck, [string]$SelectionReason, [string]$BoundaryRoot, [Nullable[bool]]$Critical, [switch]$Selected)
    if ($null -eq $script:Context -or [string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Kind)) { return }
    try { $key = [System.IO.Path]::GetFullPath($Path).ToLowerInvariant() } catch { return }
    if ($null -eq $script:Context.securityCandidateMetadata) { $script:Context.securityCandidateMetadata = @{} }
    if (-not $script:Context.securityCandidateMetadata.ContainsKey($key)) {
        $script:Context.securityCandidateMetadata[$key] = [ordered]@{
            kind=$Kind; ownerChecks=@(); selectionReasons=@(); boundaryRoot=$BoundaryRoot
            critical=($null -ne $Critical -and [bool]$Critical); selected=[bool]$Selected; ciBridgeProof=$false
        }
    }
    $metadata = $script:Context.securityCandidateMetadata[$key]
    if ($OwnerCheck -in $script:LeafCheckOrder -and $metadata.ownerChecks -notcontains $OwnerCheck) { $metadata.ownerChecks += $OwnerCheck }
    if (-not [string]::IsNullOrWhiteSpace($SelectionReason) -and $metadata.selectionReasons -notcontains $SelectionReason) { $metadata.selectionReasons += $SelectionReason }
    if ($null -ne $Critical -and [bool]$Critical) { $metadata.critical = $true }
    if ($Selected) { $metadata.selected = $true }
    if ([string]::IsNullOrWhiteSpace([string]$metadata.boundaryRoot)) { $metadata.boundaryRoot = $BoundaryRoot }
    if ($Kind -eq 'incident-hash' -or ($metadata.kind -eq 'file')) { $metadata.kind = $Kind }
}

function Test-SecurityCandidateBoundary {
    param([string]$Path, [string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $metadata = Get-SecurityCandidateMetadata $Path
        if ($null -ne $metadata) { $Root = [string]$metadata.boundaryRoot }
    }
    if ([string]::IsNullOrWhiteSpace($Root)) { return $true }
    if (-not (Test-IsPathUnderRoot -CandidatePath $Path -RootPath $Root)) { return $false }
    return (-not (Test-PathHasReparsePointBelowRoot -CandidatePath $Path -RootPath $Root))
}

function Register-SecurityAnalysisLimit {
    param([System.IO.FileInfo]$File, [string]$FailureType)
    Add-ScanStat -Name 'securityUpdateAnalysisLimits'
    $kind = Get-CoverageCandidateKindForFile -File $File
    Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind $kind -FailureType $FailureType -Critical (Test-IsCriticalCandidate -Path $File.FullName -Kind $kind)
}

function Test-IsCriticalCandidate {
    param([string]$Path, [string]$Kind)
    if ($Kind -eq 'incident-hash') { return $true }
    $candidateMetadata = Get-SecurityCandidateMetadata $Path
    if ($null -ne $candidateMetadata) { return [bool]$candidateMetadata.critical }
    if ($Kind -eq 'python-distribution-metadata') { return $true }
    if ($Kind -eq 'native-build-config') { return (-not (Test-IsDependencyOrGeneratedArtifactPath $Path) -or (Test-IsTargetedScanPath $Path)) }
    if ($Kind -in @('lockfile','installed-package','incident-hash','startup-script','vscode-task','claude-settings','ai-config','workflow','git-ref','npm-global','npm-cache')) { return $true }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $normalized = $Path.ToLowerInvariant() -replace '/', '\'
    $leaf = [System.IO.Path]::GetFileName($normalized)
    if ($leaf -in @('package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb','pipfile.lock','poetry.lock','uv.lock','composer.lock','tasks.json','settings.json','mcp.json','.mcp.json','claude_desktop_config.json','setup.mjs','math_symbol.js','math_init.js','packed-refs')) { return $true }
    if ($normalized -match '\\node_modules\\.*\\package\.json$') { return $true }
    if ($normalized -match '\\.github\\workflows\\[^\\]+\.ya?ml$') { return $true }
    return $false
}

function Get-FileSystemFailureDetails {
    param([System.Exception]$Exception, [string]$DefaultFailureType = 'read-error')
    # PowerShell wraps .NET calls. Inspect the cause, never its message (which may
    # contain target data), and do not infer long paths from a broad catch clause.
    $cause = $Exception
    for ($depth = 0; $null -ne $cause -and $null -ne $cause.InnerException -and $depth -lt 16; $depth++) {
        $cause = $cause.InnerException
    }
    $kind = $DefaultFailureType
    $type = ''; $hresult = ''
    if ($null -ne $cause) {
        $type = $cause.GetType().FullName
        $hresult = ('0x{0:X8}' -f $cause.HResult)
        $win32 = $cause.HResult -band 0xFFFF
        if ($cause -is [System.UnauthorizedAccessException] -or $cause -is [System.Security.SecurityException]) { $kind = 'access-denied' }
        elseif ($cause -is [System.IO.PathTooLongException]) { $kind = 'path-too-long' }
        elseif ($cause -is [System.IO.FileNotFoundException] -or $cause -is [System.IO.DirectoryNotFoundException]) { $kind = 'path-not-found' }
        elseif ($cause -is [System.IO.IOException]) {
            switch ($win32) {
                5 { $kind = 'access-denied' }
                32 { $kind = 'file-in-use' }
                33 { $kind = 'file-in-use' }
                206 { $kind = 'path-too-long' }
                default { $kind = 'io-error' }
            }
        }
        elseif ($cause -is [System.Text.DecoderFallbackException]) { $kind = 'decode-error' }
        elseif ($cause -is [System.ArgumentException] -or $cause -is [System.NotSupportedException]) { $kind = 'invalid-path' }
    }
    return [ordered]@{ failureType=$kind; exceptionType=$type; hresult=$hresult }
}

function Register-CoverageFailure {
    param(
        [ValidateSet('candidate','directory')][string]$Scope,
        [string]$Path,
        [string]$Kind,
        [string]$FailureType,
        [Nullable[bool]]$Critical,
        [System.Exception]$Exception
    )
    if ($null -eq $script:Context -or [string]::IsNullOrWhiteSpace($Path)) { return }
    if ([string]::IsNullOrWhiteSpace($Kind)) { $Kind = $Scope }
    if ([string]::IsNullOrWhiteSpace($FailureType)) { $FailureType = 'enumeration-error' }
    $isCritical = if ($null -ne $Critical) { [bool]$Critical } else { Test-IsCriticalCandidate -Path $Path -Kind $Kind }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { $full = $Path }
    $dedupe = ($Scope + '|' + $Kind + '|' + $FailureType + '|' + $full).ToLowerInvariant()
    $keys = if ($Scope -eq 'candidate') { $script:Context.coverage.candidateFailureKeys } else { $script:Context.coverage.directoryFailureKeys }
    if ($keys.ContainsKey($dedupe)) { return }
    $keys[$dedupe] = $true

    $groups = if ($Scope -eq 'candidate') { $script:Context.coverage.candidateFailureGroups } else { $script:Context.coverage.directoryFailureGroups }
    $groupKey = ($Kind + '|' + $FailureType + '|' + $isCritical).ToLowerInvariant()
    if (-not $groups.ContainsKey($groupKey)) {
        $groups[$groupKey] = [ordered]@{ kind=$Kind; failureType=$FailureType; critical=$isCritical; count=0; representativePaths=New-ArrayList; exceptionTypes=New-ArrayList; hresults=New-ArrayList }
    }
    $group = $groups[$groupKey]
    $group.count = [int]$group.count + 1
    if ($group.representativePaths.Count -lt 3) { Add-ListItem $group.representativePaths (ConvertTo-RedactedPath $full) }
    if ($null -ne $Exception) {
        $details = Get-FileSystemFailureDetails -Exception $Exception -DefaultFailureType $FailureType
        if ($group.exceptionTypes.Count -lt 3 -and $group.exceptionTypes -notcontains $details.exceptionType) { Add-ListItem $group.exceptionTypes $details.exceptionType }
        if ($group.hresults.Count -lt 3 -and $group.hresults -notcontains $details.hresult) { Add-ListItem $group.hresults $details.hresult }
    }

    if ($Scope -eq 'candidate') {
        if ($isCritical) { Add-ScanStat -Name 'criticalCandidateFailures' } else { Add-ScanStat -Name 'nonCriticalCandidateFailures' }
    }
    else {
        $script:Context.coverage.directoryCoverageComplete = $false
        if ($isCritical -and $FailureType -eq 'access-denied' -and $script:Context.coverage.directoryRetryCandidates.Count -lt 3) {
            Add-ListItem $script:Context.coverage.directoryRetryCandidates $full
        }
        if ($isCritical) { Add-ScanStat -Name 'criticalDirectoryFailures' } else { Add-ScanStat -Name 'nonCriticalDirectoryFailures' }
    }
}

function Get-CoverageFailureSummary {
    param([ValidateSet('candidate','directory')][string]$Scope)
    $groups = if ($Scope -eq 'candidate') { $script:Context.coverage.candidateFailureGroups } else { $script:Context.coverage.directoryFailureGroups }
    $result = New-ArrayList
    foreach ($group in @($groups.Values)) {
        Add-ListItem $result ([ordered]@{
            kind = [string]$group.kind
            failureType = [string]$group.failureType
            critical = [bool]$group.critical
            count = [int]$group.count
            representativePaths = @($group.representativePaths.ToArray())
            exceptionTypes = @($group.exceptionTypes.ToArray())
            hresults = @($group.hresults.ToArray())
        })
    }
    return @($result | Sort-Object @{Expression={ if ($_.critical) { 0 } else { 1 } }},kind,failureType)
}

function Get-CoverageStatusSummary {
    $criticalCandidate = [int]$script:Context.scanStats.criticalCandidateFailures
    $nonCriticalCandidate = [int]$script:Context.scanStats.nonCriticalCandidateFailures
    $criticalDirectory = [int]$script:Context.scanStats.criticalDirectoryFailures
    $nonCriticalDirectory = [int]$script:Context.scanStats.nonCriticalDirectoryFailures
    $criticalTotal = $criticalCandidate + $criticalDirectory
    $nonCriticalTotal = $nonCriticalCandidate + $nonCriticalDirectory
    $reasons = New-ArrayList
    foreach ($failure in @($script:Context.coverage.candidateFailures)) {
        Add-ListItem $reasons ("candidate:{0}/{1}={2};critical={3}" -f $failure.kind,$failure.failureType,$failure.count,$failure.critical)
    }
    foreach ($failure in @($script:Context.coverage.directoryFailures)) {
        Add-ListItem $reasons ("directory:{0}/{1}={2};critical={3}" -f $failure.kind,$failure.failureType,$failure.count,$failure.critical)
    }

    $dependencyChecksEnabled = ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts'))
    $dependencyPartial = ([int]$script:Context.scanStats.targetedDependencyFilesSkippedByBudget -gt 0 -or [int]$script:Context.scanStats.projectDiscoveryLimitReached -gt 0)
    $dependencyCoverageStatus = 'not-selected'
    if ($dependencyChecksEnabled) {
        $dependencyExecution = if (Test-CheckEnabled 'Packages') { Get-CheckExecutionStatus 'Packages' } else { Get-CheckExecutionStatus 'LifecycleScripts' }
        if ($dependencyExecution -ne 'completed') {
            $dependencyCoverageStatus = $dependencyExecution
        }
        elseif ([bool]$script:Context.mode.deep) {
            $dependencyCoverageStatus = if ($dependencyPartial) { 'bounded-recursive-partial' } else { 'bounded-recursive-within-limits' }
        }
        elseif ([int]$script:Context.scanStats.projectRootsDiscovered -gt 1) {
            $dependencyCoverageStatus = if ($dependencyPartial) { 'targeted-multi-project-sampled' } else { 'targeted-multi-project-within-limits' }
        }
        else {
            $dependencyCoverageStatus = if ($dependencyPartial) { 'targeted-direct-partial' } else { 'targeted-direct-within-limits' }
        }
    }

    $npmCacheCoverageStatus = 'not-selected'
    if (Test-CheckEnabled 'NpmCache') {
        $cacheExecution = Get-CheckExecutionStatus 'NpmCache'
        if ($cacheExecution -ne 'completed') {
            $npmCacheCoverageStatus = $cacheExecution
        }
        elseif ([int]$script:Context.scanStats.npmCacheAccessDenied -gt 0) {
            $npmCacheCoverageStatus = 'bounded-metadata-partial'
        }
        elseif ([int]$script:Context.scanStats.npmCacheRootsFound -eq 0) {
            $npmCacheCoverageStatus = 'not-found'
        }
        elseif ([int]$script:Context.scanStats.npmCacheMetadataLimitReached -gt 0) {
            $npmCacheCoverageStatus = 'bounded-metadata-limit-reached'
        }
        elseif ([int]$script:Context.scanStats.npmCacheMetadataFilesSkipped -gt 0 -or [int]$script:Context.scanStats.npmCacheAccessDenied -gt 0) {
            $npmCacheCoverageStatus = 'bounded-metadata-partial'
        }
        else {
            $npmCacheCoverageStatus = 'bounded-metadata-within-limits'
        }
    }

    $npmGlobalCoverageStatus = Get-CheckExecutionStatus 'NpmGlobal'
    if ($npmGlobalCoverageStatus -eq 'completed') {
        $npmGlobalCoverageStatus = if ([int]$script:Context.scanStats.npmGlobalRootsFound -eq 0) { 'not-found' } else { 'bounded-metadata-inspected' }
    }
    $execution = Get-ScanExecutionSummary
    if ($null -ne $execution -and $execution.status -ne 'completed') {
        Add-ListItem $reasons ("execution:{0};unfinishedPhases={1};queuedFilesUnprocessed={2}" -f $execution.status,([string]::Join(',',[string[]]$execution.unfinishedPhases)),$execution.queuedFilesUnprocessed)
    }
    $nextActions=New-ArrayList
    if ([bool]$script:Context.scannerError) {
        Add-ListItem $nextActions ([ordered]@{ reason='scanner-error'; count=1; paths=@(); action='Review SCANNER_ERROR before relying on this report.' })
    }
    if ($null -ne $execution -and $execution.status -eq 'interrupted') {
        Add-ListItem $nextActions ([ordered]@{ reason='interrupted'; count=@($execution.unfinishedPhases).Count; paths=@(); action='Scan was interrupted. Review execution.unfinishedPhases and rerun only the unfinished scope when needed; not-started checks have no negative result.' })
    }
    foreach ($scope in @('candidate','directory')) {
        foreach ($failure in @($script:Context.coverage[($scope+'Failures')])) {
            $action=switch ([string]$failure.failureType) {
                'regex-timeout' { 'Review the affected file and regex ruleId; the named rule or step is incomplete. Narrowing the folder alone may not resolve it.' }
                'too-large' { 'Review oversized files separately; keep size limits bounded and inspect only the required file if a higher limit is needed.' }
                'file-in-use' { 'Close the conflicting writer when appropriate and rerun the affected path.' }
                'access-denied' { 'Review read access for the affected path; rerun only when the required access is available.' }
                'decode-error' { 'Review the encoding or file type of the affected file without executing it.' }
                'budget-exhausted' { 'Rerun the affected bounded project scope when complete candidate targeting is required.' }
                'analysis-limit' { 'Review the affected configuration within its documented analysis bounds; remaining data was not fully inspected.' }
                'parse-error' { 'Review the syntax of the affected configuration; partial extraction does not establish complete command coverage.' }
                default { 'Review the grouped failure reason and affected paths before treating this scope as complete.' }
            }
            Add-ListItem $nextActions ([ordered]@{
                reason=($scope+':'+[string]$failure.kind+'/'+[string]$failure.failureType)
                count=[int]$failure.count; critical=[bool]$failure.critical
                paths=@($failure.representativePaths); action=$action
            })
        }
    }
    if ([int]$script:Context.scanStats.targetedDependencyFilesSkippedByBudget -gt 0) {
        Add-ListItem $nextActions ([ordered]@{ reason='dependency-sampling'; count=[int]$script:Context.scanStats.targetedDependencyFilesSkippedByBudget; paths=@(); action='Scan affected child projects directly when complete dependency targeting is required.' })
    }
    if ([int]$script:Context.scanStats.projectDiscoveryLimitReached -gt 0) {
        Add-ListItem $nextActions ([ordered]@{ reason='project-discovery-limit'; count=[int]$script:Context.scanStats.projectDiscoveryLimitReached; paths=@(); action='Review project-discovery limits and select the required child project directly; undiscovered projects have no negative result.' })
    }
    if ([int]$script:Context.scanStats.npmCacheMetadataLimitReached -gt 0) {
        Add-ListItem $nextActions ([ordered]@{ reason='npm-cache-sampling'; count=[int]$script:Context.scanStats.npmCacheMetadataLimitReached; paths=@(); action='Treat npm cache coverage as bounded metadata sampling; review the affected index scope only when deeper review is required.' })
    }
    if ($nextActions.Count -eq 0 -and -not [bool]$script:Context.coverage.scanComplete) {
        Add-ListItem $nextActions ([ordered]@{ reason='coverage-incomplete'; count=0; paths=@(); action='Review traversal and scanner limitation findings before treating the result as complete.' })
    }
    $nextAction=if ($nextActions.Count -eq 0) { 'No coverage-specific action is required.' } else { [string]::Join(' ',[string[]]@($nextActions | ForEach-Object { $_.action } | Select-Object -Unique)) }

    $completionStatus = 'complete'
    $completionLabel = 'COMPLETE'
    $hasNonCriticalPartial = ($nonCriticalTotal -gt 0 -or $dependencyPartial -or $npmCacheCoverageStatus -match 'partial|limit' -or -not [bool]$script:Context.coverage.directoryCoverageComplete)
    if ([bool]$script:Context.scannerError) {
        $completionStatus = 'error'
        $completionLabel = 'ERROR'
    }
    elseif ($null -ne $execution -and $execution.status -eq 'interrupted') {
        $completionStatus = 'incomplete-critical'
        $completionLabel = 'INTERRUPTED (planned checks unfinished)'
    }
    elseif ($criticalTotal -gt 0 -or -not [bool]$script:Context.coverage.candidateCoverageComplete) {
        $completionStatus = 'incomplete-critical'
        $completionLabel = 'INCOMPLETE (critical coverage)'
    }
    elseif (-not [bool]$script:Context.coverage.scanComplete -or $hasNonCriticalPartial) {
        $completionStatus = 'partial-non-critical'
        $completionLabel = 'PARTIAL (non-critical)'
    }

    $unfinishedPhases=@()
    if ($null -ne $execution) { $unfinishedPhases=@($execution.unfinishedPhases) }
    return [ordered]@{
        scanComplete = [bool]$script:Context.coverage.scanComplete
        completionStatus = $completionStatus
        completionLabel = $completionLabel
        executionStatus = if ($null -eq $execution) { 'unknown' } else { $execution.status }
        unfinishedPhases = @($unfinishedPhases)
        criticalFailures = [int]$criticalTotal
        nonCriticalFailures = [int]$nonCriticalTotal
        totalFailures = [int]($criticalTotal + $nonCriticalTotal)
        incompleteReasons = @($reasons.ToArray())
        dependencyCoverageStatus = $dependencyCoverageStatus
        targetedDependencyFilesSkippedByBudget = [int]$script:Context.scanStats.targetedDependencyFilesSkippedByBudget
        nodeRuntimeFilesSkippedByBudget = [int]$script:Context.scanStats.nodeRuntimeFilesSkippedByBudget
        npmCacheCoverageStatus = $npmCacheCoverageStatus
        npmGlobalCoverageStatus = $npmGlobalCoverageStatus
        npmCacheMetadataFilesScanned = [int]$script:Context.scanStats.npmCacheMetadataFilesScanned
        npmCacheMetadataFilesSkipped = [int]$script:Context.scanStats.npmCacheMetadataFilesSkipped
        npmCacheMetadataLimitReached = [int]$script:Context.scanStats.npmCacheMetadataLimitReached
        nextAction = $nextAction
        nextActions = @($nextActions.ToArray())
    }
}

function Retry-CriticalDirectoryFailures {
    $candidates = @($script:Context.coverage.directoryRetryCandidates)
    if ($candidates.Count -eq 0) { return }
    foreach ($candidate in $candidates) {
        if ([int]$script:Context.coverage.retry.samePrivilegeAttempts -ge 1) { break }
        $script:Context.coverage.retry.samePrivilegeAttempts++
        Add-ScanStat -Name 'coverageRetryAttempts'
        # The retry is an existence/enumeration probe only. A successful probe does not
        # claim scan coverage for files missed during the original traversal.
        try { $null = [System.IO.Directory]::GetFileSystemEntries([string]$candidate) } catch { }
    }
}

function Finalize-ScanCoverage {
    if ($null -eq $script:Context -or [bool]$script:Context.coverage.finalized) { return }
    $executionFinished = ($null -eq $script:Context.execution -or $script:Context.execution.status -eq 'completed')
    if ($executionFinished) { Retry-CriticalDirectoryFailures }
    $candidateFailures = @(Get-CoverageFailureSummary -Scope 'candidate')
    $directoryFailures = @(Get-CoverageFailureSummary -Scope 'directory')
    $script:Context.coverage.candidateFailures = $candidateFailures
    $script:Context.coverage.directoryFailures = $directoryFailures
    $criticalCandidateCount = @($candidateFailures | Where-Object { $_.critical } | ForEach-Object { $_.count } | Measure-Object -Sum).Sum
    $criticalDirectoryCount = @($directoryFailures | Where-Object { $_.critical } | ForEach-Object { $_.count } | Measure-Object -Sum).Sum
    if ($null -eq $criticalCandidateCount) { $criticalCandidateCount = 0 }
    if ($null -eq $criticalDirectoryCount) { $criticalDirectoryCount = 0 }
    $script:Context.coverage.candidateCoverageComplete = ($executionFinished -and $criticalCandidateCount -eq 0 -and $criticalDirectoryCount -eq 0)
    $script:Context.coverage.retry.remaining = [int]$criticalDirectoryCount
    $candidateFailureCount = @($candidateFailures | ForEach-Object { $_.count } | Measure-Object -Sum).Sum
    $boundedPartial = ([int]$script:Context.scanStats.targetedDependencyFilesSkippedByBudget -gt 0 -or
        [int]$script:Context.scanStats.projectDiscoveryLimitReached -gt 0 -or
        [int]$script:Context.scanStats.npmCacheMetadataLimitReached -gt 0 -or
        [int]$script:Context.scanStats.npmCacheMetadataFilesSkipped -gt 0 -or
        [int]$script:Context.scanStats.npmCacheAccessDenied -gt 0)
    $script:Context.coverage.scanComplete = (-not $script:Context.scannerError -and [bool]$script:Context.coverage.traversalComplete -and [bool]$script:Context.coverage.directoryCoverageComplete -and [bool]$script:Context.coverage.candidateCoverageComplete -and [int]$candidateFailureCount -eq 0 -and -not $boundedPartial)
    $script:Context.coverage.finalized = $true

    if ($executionFinished -and -not [bool]$script:Context.coverage.candidateCoverageComplete) {
        Add-Finding -Severity 'WARN' -Category 'SCAN_CANDIDATE_COVERAGE_INCOMPLETE' -Title 'Security-critical candidate coverage is incomplete' -Path 'scan coverage' -PathType 'virtual' -Evidence ("criticalCandidateFailures={0}; criticalDirectoryFailures={1}" -f $criticalCandidateCount,$criticalDirectoryCount) -Recommendation 'Review representative paths and rerun a narrower scan with sufficient read access before treating the result as clean.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
    }
    if (-not [bool]$script:Context.coverage.directoryCoverageComplete) {
        Add-Finding -Severity 'INFO' -Category 'SCAN_DIRECTORY_COVERAGE_PARTIAL' -Title 'Some directory enumeration was incomplete' -Path 'scan coverage' -PathType 'virtual' -Evidence ("directoryFailureGroups={0}" -f $directoryFailures.Count) -Recommendation 'Review representative directory paths when complete traversal is required.' -RiskType 'limitation' -Confidence 'medium' -Check 'ScannerSelf' -DetectionMethod 'metadata'
    }
}

function Get-TargetedDependencyFileBudget {
    $half = [int][Math]::Floor([double]$MaxFiles * 0.5)
    return [Math]::Min(10000, [Math]::Max(0, $half))
}

function Get-TargetedDependencyPerProjectFileLimit {
    param([int]$ProjectCount)
    if ($ProjectCount -lt 1) { return 0 }
    $fairShare = [int][Math]::Ceiling([double](Get-TargetedDependencyFileBudget) / [double]$ProjectCount)
    return [Math]::Min(2000, [Math]::Max(1, $fairShare))
}

function Test-RunFileBudgetExhausted {
    return ($null -ne $script:Context -and [int]$script:Context.scanStats.uniqueFilesQueued -ge $MaxFiles)
}

function Test-TargetedDependencyBudgetExhausted {
    return ($null -ne $script:Context -and [int]$script:Context.scanStats.targetedDependencyFilesQueued -ge (Get-TargetedDependencyFileBudget))
}

function Register-TargetedDependencyBudgetReached {
    param([string]$CandidatePath)
    if ($null -eq $script:Context) { return }
    $pathForFinding = if ([string]::IsNullOrWhiteSpace($CandidatePath)) { 'targeted dependency coverage' } else { $CandidatePath }
    $script:Context.coverage.traversalComplete = $false
    Register-CoverageFailure -Scope 'candidate' -Path $pathForFinding -Kind 'targeted-dependency' -FailureType 'budget-exhausted' -Critical (Test-IsCriticalCandidate -Path $pathForFinding -Kind 'targeted-dependency')
    if (-not [bool]$script:Context.targetedDependencyLimitWarned) {
        $script:Context.targetedDependencyLimitWarned = $true
        Add-Finding -Severity 'WARN' -Category 'TARGETED_DEPENDENCY_LIMIT_REACHED' -Title 'Targeted dependency scan budget reached' -Path $pathForFinding -Evidence ("Targeted dependency files are limited to {0} run-wide, reserving at least half of MaxFiles and capping default broad scans at 10,000 dependency files." -f (Get-TargetedDependencyFileBudget)) -Recommendation 'Scan the affected child project directly or use Deep on one trusted project if broader dependency content is required.' -Check 'Packages' -DetectionMethod 'metadata'
    }
}

function Register-RunFileBudgetReached {
    param([string]$CandidatePath)
    if ($null -eq $script:Context) { return }
    $pathForFinding = if ([string]::IsNullOrWhiteSpace($CandidatePath)) { 'scan coverage' } else { $CandidatePath }
    $script:Context.coverage.traversalComplete = $false
    Register-CoverageFailure -Scope 'candidate' -Path $pathForFinding -Kind 'run-wide' -FailureType 'budget-exhausted' -Critical $true
    if (-not $script:WarnedMaxFiles) {
        Add-Finding -Severity 'WARN' -Category 'MAX_FILES_REACHED' -Title 'Maximum unique file count reached' -Path $pathForFinding -Evidence "Run-wide MaxFiles limit reached: $MaxFiles. Remaining directories were not enumerated." -Recommendation 'Increase MaxFiles or narrow the scan path.'
        $script:WarnedMaxFiles = $true
    }
}

function Reserve-ScanFile {
    param(
        [string]$FilePath,
        [switch]$Targeted,
        [switch]$DeepOnly,
        [string]$Kind,
        [string]$OwnerCheck,
        [string]$SelectionReason,
        [string]$BoundaryRoot,
        [Nullable[bool]]$Critical,
        [switch]$Selected
    )
    if ([string]::IsNullOrWhiteSpace($FilePath) -or $null -eq $script:Context) { return $false }
    try {
        $fullPath = [System.IO.Path]::GetFullPath($FilePath)
    }
    catch {
        return $false
    }
    $key = $fullPath.ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($Kind)) {
        Register-SecurityCandidateMetadata -Path $fullPath -Kind $Kind -OwnerCheck $OwnerCheck -SelectionReason $SelectionReason -BoundaryRoot $BoundaryRoot -Critical $Critical -Selected:$Selected
    }
    if ($script:Context.queuedFilePaths.ContainsKey($key)) { return $false }

    if ($Targeted) {
        $targetedBudget = Get-TargetedDependencyFileBudget
        if ([int]$script:Context.scanStats.targetedDependencyFilesQueued -ge $targetedBudget) {
            Add-ScanStat -Name 'targetedDependencyFilesSkippedByBudget'
            Register-TargetedDependencyBudgetReached -CandidatePath $fullPath
            return $false
        }
    }

    if ([int]$script:Context.scanStats.uniqueFilesQueued -ge $MaxFiles) {
        Register-RunFileBudgetReached -CandidatePath $fullPath
        return $false
    }

    $script:Context.queuedFilePaths[$key] = $true
    Add-ScanStat -Name 'uniqueFilesQueued'
    if (-not [string]::IsNullOrWhiteSpace($Kind)) { Add-ScanStat -Name 'securityUpdateCandidatesQueued' }
    if ($Targeted) {
        $script:Context.targetedFilePaths[$key] = $true
        Add-ScanStat -Name 'targetedDependencyFilesQueued'
    }
    if ($DeepOnly) { Add-ScanStat -Name 'deepFilesQueued' }
    return $true
}

function Get-NodeRuntimePriorityBudget {
    if (-not (Test-CheckEnabled 'NodeRuntime')) { return 0 }
    $enabledChecks = @($script:Context.checks.expanded)
    if ($enabledChecks.Count -eq 1 -and $enabledChecks[0] -eq 'NodeRuntime') {
        return [Math]::Min($MaxFiles, 5000)
    }
    return [Math]::Min(1000, [Math]::Max(1, [int][Math]::Floor([double]$MaxFiles * 0.05)))
}

function Add-NodeRuntimePriorityCandidate {
    param($List, [string]$FilePath)
    if ([string]::IsNullOrWhiteSpace($FilePath) -or -not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return }
    Add-ScanStat -Name 'nodeRuntimeCandidatesFound'
    $budget = Get-NodeRuntimePriorityBudget
    if ([int]$script:Context.scanStats.nodeRuntimePriorityFilesQueued -ge $budget) {
        Add-ScanStat -Name 'nodeRuntimeFilesSkippedByBudget'
        if (-not [bool]$script:Context.nodeRuntimeBudgetWarned) {
            $script:Context.nodeRuntimeBudgetWarned = $true
            Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_BUDGET_REACHED' -Title 'Node.js runtime priority scan budget reached' -Path $FilePath -Evidence ("NodeRuntime priority files are limited to {0}; normal traversal continues within MaxFiles." -f $budget) -Recommendation 'Increase MaxFiles or scan a narrower project directly if Node.js declarations may be beyond the limit.' -RiskType 'limitation' -Confidence 'medium' -Check 'NodeRuntime' -DetectionMethod 'metadata'
        }
        return
    }
    try {
        $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (Test-IsReparsePoint $item)) { return }
        if (Test-IsVerifiedScannerArtifactSamplePath $item.FullName) { return }
        if (Test-IsOwnSyntheticSamplePath $item.FullName) {
            Add-ScanStat -Name 'filesSkipped' -FilePath $item.FullName
            Add-ScanStat -Name 'syntheticSamplesSkipped' -FilePath $item.FullName
            Add-ScanStat -Name 'syntheticSampleKnownSkipped' -FilePath $item.FullName
            return
        }
        if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $item.FullName)) { return }
        if (Reserve-ScanFile -FilePath $item.FullName) {
            Add-ScanStat -Name 'filesEnumerated' -FilePath $item.FullName
            Add-ScanStat -Name 'nodeRuntimePriorityFilesQueued'
            Add-ListItem $List ([System.IO.FileInfo]$item.FullName)
        }
    }
    catch {
        Add-ScanStat -Name 'nodeRuntimeVersionReadFailures'
    }
}

function Get-NodeRuntimeProjectCandidatePaths {
    param([string]$ProjectRoot)
    $result = New-ArrayList
    $seen = @{}
    if ([string]::IsNullOrWhiteSpace($ProjectRoot) -or -not (Test-Path -LiteralPath $ProjectRoot -PathType Container)) { return @() }

    foreach ($relative in @('package.json','.nvmrc','.node-version','.tool-versions','.mise.toml','mise.toml','.devcontainer\devcontainer.json')) {
        $candidate = Join-Path $ProjectRoot $relative
        if ((Test-Path -LiteralPath $candidate -PathType Leaf) -and
            (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $ProjectRoot) -and
            -not (Test-PathHasReparsePointBelowRoot -RootPath $ProjectRoot -CandidatePath $candidate)) {
            $key = ([System.IO.Path]::GetFullPath($candidate)).ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) { $seen[$key]=$true; Add-ListItem $result $candidate }
        }
    }
    try {
        foreach ($candidate in @([System.IO.Directory]::GetFiles($ProjectRoot, 'Dockerfile*', [System.IO.SearchOption]::TopDirectoryOnly) | Sort-Object)) {
            if (-not (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $ProjectRoot) -or (Test-PathHasReparsePointBelowRoot -RootPath $ProjectRoot -CandidatePath $candidate)) { continue }
            $key = ([System.IO.Path]::GetFullPath($candidate)).ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) { $seen[$key]=$true; Add-ListItem $result $candidate }
            if ($result.Count -ge 20) { break }
        }
    }
    catch { }
    $workflowRoot = Join-Path $ProjectRoot '.github\workflows'
    if ($result.Count -lt 20 -and (Test-Path -LiteralPath $workflowRoot -PathType Container) -and
        -not (Test-PathHasReparsePointBelowRoot -RootPath $ProjectRoot -CandidatePath $workflowRoot)) {
        try {
            foreach ($candidate in @([System.IO.Directory]::GetFiles($workflowRoot) | Sort-Object)) {
                if ([System.IO.Path]::GetExtension($candidate).ToLowerInvariant() -notin @('.yml','.yaml')) { continue }
                if (-not (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $ProjectRoot) -or (Test-PathHasReparsePointBelowRoot -RootPath $ProjectRoot -CandidatePath $candidate)) { continue }
                $key = ([System.IO.Path]::GetFullPath($candidate)).ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) { $seen[$key]=$true; Add-ListItem $result $candidate }
                if ($result.Count -ge 20) { break }
            }
        }
        catch { }
    }
    return @($result.ToArray() | Select-Object -First 20)
}

function Test-NodeRuntimeHostScopeRequested {
    if (-not (Test-CheckEnabled 'NodeRuntime')) { return $false }
    $validation = Get-ValidationOnlyStaticRoots -EnvName 'DEV_SUPPLYCHAIN_CHECKER_TEST_NODE_RUNTIME_ROOTS'
    if ($validation.active) { return $true }
    if ($MajorLocations -or $UserProfile) { return $true }
    return (@($script:Context.checks.selected) -contains 'MajorRecommended' -or @($script:Context.checks.selected) -contains 'AllSafe')
}

function Add-NodeRuntimeSearchRoot {
    param($List, [hashtable]$Seen, [string]$RootPath, [int]$MaxDepth)
    if ([string]::IsNullOrWhiteSpace($RootPath) -or $RootPath -match '^[A-Za-z][A-Za-z0-9+.-]*://' -or $RootPath.StartsWith('\\')) { return }
    try {
        $full = [System.IO.Path]::GetFullPath($RootPath)
        if (-not [System.IO.Path]::IsPathRooted($full) -or -not (Test-Path -LiteralPath $full -PathType Container)) { return }
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if (Test-IsReparsePoint $item) { return }
        $key = $item.FullName.ToLowerInvariant()
        if (-not $Seen.ContainsKey($key)) {
            $Seen[$key] = $true
            Add-ListItem $List ([ordered]@{ path=$item.FullName; maxDepth=$MaxDepth })
        }
    }
    catch { }
}

function Get-NodeRuntimeHostSearchRoots {
    $validation = Get-ValidationOnlyStaticRoots -EnvName 'DEV_SUPPLYCHAIN_CHECKER_TEST_NODE_RUNTIME_ROOTS'
    $roots = New-ArrayList
    $seen = @{}
    if ($validation.active) {
        foreach ($root in @($validation.roots)) { Add-NodeRuntimeSearchRoot -List $roots -Seen $seen -RootPath $root -MaxDepth 8 }
        return @($roots.ToArray())
    }

    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles', 'Process')
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($programFiles)) { Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $programFiles 'nodejs') 2 }
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) { Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $programFilesX86 'nodejs') 2 }

    $processPath = [Environment]::GetEnvironmentVariable('Path', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($processPath)) {
        foreach ($pathEntry in @($processPath -split ';')) {
            $candidate = ([string]$pathEntry).Trim().Trim('"')
            if (-not [string]::IsNullOrWhiteSpace($candidate)) { Add-NodeRuntimeSearchRoot $roots $seen $candidate 0 }
        }
    }

    foreach ($entry in @(
        @{ env='NVM_HOME'; suffix=''; depth=2 }, @{ env='NVM_SYMLINK'; suffix=''; depth=1 },
        @{ env='VOLTA_HOME'; suffix='tools\image\node'; depth=4 }, @{ env='FNM_DIR'; suffix='node-versions'; depth=5 },
        @{ env='NVS_HOME'; suffix='node'; depth=5 }
    )) {
        $base = [Environment]::GetEnvironmentVariable([string]$entry.env, 'Process')
        if ([string]::IsNullOrWhiteSpace($base)) { continue }
        $candidate = if ([string]::IsNullOrEmpty([string]$entry.suffix)) { $base } else { Join-Path $base ([string]$entry.suffix) }
        Add-NodeRuntimeSearchRoot $roots $seen $candidate ([int]$entry.depth)
    }

    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:LOCALAPPDATA 'Volta\tools\image\node') 4
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:LOCALAPPDATA 'nvs\node') 5
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:LOCALAPPDATA 'fnm\node-versions') 5
    }
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:APPDATA 'fnm\node-versions') 5
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:APPDATA 'nvm') 3
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:USERPROFILE '.fnm\node-versions') 5
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:USERPROFILE '.nvs\node') 5
        Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:USERPROFILE '.volta\tools\image\node') 4
    }
    $scoopRoot = [Environment]::GetEnvironmentVariable('SCOOP', 'Process')
    if ([string]::IsNullOrWhiteSpace($scoopRoot) -and -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { $scoopRoot = Join-Path $env:USERPROFILE 'scoop' }
    if (-not [string]::IsNullOrWhiteSpace($scoopRoot)) {
        foreach ($app in @('nodejs','nodejs-lts','nodejs-current')) { Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $scoopRoot ('apps\' + $app)) 3 }
    }
    return @($roots.ToArray())
}

function Get-NodeRuntimeHostCandidatePaths {
    $result = New-ArrayList
    $seenFiles = @{}
    $directoriesVisited = 0
    foreach ($root in @(Get-NodeRuntimeHostSearchRoots)) {
        $queue = New-Object System.Collections.Queue
        $queue.Enqueue([ordered]@{ path=[string]$root.path; depth=0 })
        while ($queue.Count -gt 0 -and $directoriesVisited -lt 2000 -and $result.Count -lt 200) {
            $item = $queue.Dequeue()
            $directoriesVisited++
            try {
                $dir = Get-Item -LiteralPath ([string]$item.path) -Force -ErrorAction Stop
                if (-not $dir.PSIsContainer -or (Test-IsReparsePoint $dir)) { continue }
                foreach ($filePath in @([System.IO.Directory]::GetFiles($dir.FullName, 'node.exe', [System.IO.SearchOption]::TopDirectoryOnly) | Sort-Object)) {
                    $file = Get-Item -LiteralPath $filePath -Force -ErrorAction Stop
                    if (Test-IsReparsePoint $file) { continue }
                    $key = $file.FullName.ToLowerInvariant()
                    if (-not $seenFiles.ContainsKey($key)) { $seenFiles[$key]=$true; Add-ListItem $result $file.FullName }
                    if ($result.Count -ge 200) { break }
                }
                if ([int]$item.depth -ge [int]$root.maxDepth) { continue }
                foreach ($subdirPath in @([System.IO.Directory]::GetDirectories($dir.FullName) | Sort-Object)) {
                    $subdir = Get-Item -LiteralPath $subdirPath -Force -ErrorAction Stop
                    if (-not (Test-IsReparsePoint $subdir)) { $queue.Enqueue([ordered]@{ path=$subdir.FullName; depth=([int]$item.depth + 1) }) }
                }
            }
            catch { Add-ScanStat -Name 'nodeRuntimeVersionReadFailures' }
        }
        if ($directoriesVisited -ge 2000 -or $result.Count -ge 200) { break }
    }
    return @($result.ToArray())
}

function Scan-HostNodeRuntimes {
    if (-not (Test-NodeRuntimeHostScopeRequested)) { return }
    $script:Context.nodeRuntimeHostScanPerformed = $true
    $files = New-ArrayList
    foreach ($candidate in @(Get-NodeRuntimeHostCandidatePaths)) { Add-NodeRuntimePriorityCandidate -List $files -FilePath $candidate }
    foreach ($file in @($files)) { Scan-File -File $file }
}

function Add-FileIfExists {
    param($List, [string]$FilePath, [string]$Kind, [string]$OwnerCheck, [string]$SelectionReason, [string]$BoundaryRoot, [Nullable[bool]]$Critical, [switch]$Selected)
    if ([string]::IsNullOrEmpty($FilePath)) {
        return
    }
    if (-not [string]::IsNullOrWhiteSpace($Kind)) {
        Register-SecurityCandidateMetadata -Path $FilePath -Kind $Kind -OwnerCheck $OwnerCheck -SelectionReason $SelectionReason -BoundaryRoot $BoundaryRoot -Critical $Critical -Selected:$Selected
        if (-not (Test-SecurityCandidateBoundary -Path $FilePath -Root $BoundaryRoot)) {
            Register-CoverageFailure -Scope 'candidate' -Path $FilePath -Kind $Kind -FailureType 'path-boundary-rejected' -Critical $Critical
            return
        }
    }
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return }
    if ($List.Count -ge $script:TargetedPerProjectFileLimit) {
        Add-ScanStat -Name 'targetedDependencyFilesSkippedByBudget'
        if (-not [bool]$script:Context.targetedDependencyLimitWarned) {
            $script:Context.targetedDependencyLimitWarned = $true
            Add-Finding -Severity 'WARN' -Category 'TARGETED_DEPENDENCY_LIMIT_REACHED' -Title 'Per-project targeted dependency limit reached' -Path $FilePath -Evidence ("A child project reached its fair-share targeted-file limit of {0}; normal source and configuration scanning continues." -f $script:TargetedPerProjectFileLimit) -Recommendation 'Scan this child project directly or use Deep on one trusted project if broader dependency content is required.' -Check 'Packages' -DetectionMethod 'metadata'
        }
        return
    }
    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
        try {
            Add-ScanStat -Name 'filesEnumerated' -FilePath $FilePath
            if (Test-IsVerifiedScannerArtifactSamplePath $FilePath) {
                Add-ScanStat -Name 'filesSkipped' -FilePath $FilePath
                return
            }
            if (Test-IsOwnSyntheticSamplePath $FilePath) {
                Add-ScanStat -Name 'filesSkipped' -FilePath $FilePath
                Add-ScanStat -Name 'syntheticSamplesSkipped' -FilePath $FilePath
                Add-ScanStat -Name 'syntheticSampleKnownSkipped' -FilePath $FilePath
                return
            }
            if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $FilePath)) {
                Add-ScanStat -Name 'filesSkipped' -FilePath $FilePath
                Add-ScanStat -Name 'scannerReportArtifactsSkipped'
                return
            }
            if (Reserve-ScanFile -FilePath $FilePath -Targeted -Kind $Kind -OwnerCheck $OwnerCheck -SelectionReason $SelectionReason -BoundaryRoot $BoundaryRoot -Critical $Critical -Selected:$Selected) {
                Add-ListItem $List ([System.IO.FileInfo]$FilePath)
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'FILE_INFO_FAILED' -Title 'File metadata could not be read' -Path $FilePath -Evidence 'FileInfo failed while collecting targeted scan file.' -Recommendation 'Inspect manually if this path is important.'
        }
    }
}

function Add-PriorityFileIfExists {
    param($List, [string]$FilePath)
    if ([string]::IsNullOrWhiteSpace($FilePath)) { return }
    try {
        $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (Test-IsReparsePoint $item)) { return }
        Add-ScanStat -Name 'filesEnumerated' -FilePath $FilePath
        if (Reserve-ScanFile -FilePath $item.FullName) { Add-ListItem $List $item }
    }
    catch [System.Management.Automation.ItemNotFoundException] { return }
    catch {
        Register-CoverageFailure -Scope 'candidate' -Path $FilePath -Kind (Get-CoverageCandidateKindForFile -File (New-Object System.IO.FileInfo($FilePath))) -FailureType 'access-denied'
    }
}

function Get-PrioritySecurityFileList {
    param([string]$RootPath)
    $result = New-ArrayList
    if ([string]::IsNullOrWhiteSpace($RootPath) -or -not (Test-Path -LiteralPath $RootPath -PathType Container)) { return $result }
    foreach ($relative in @(
        '.vscode\tasks.json','.vscode\mcp.json','.claude\settings.json','.claude\settings.local.json',
        '.cursor\mcp.json','.windsurf\mcp.json','.gemini\settings.json',
        '.continue\config.json','.continue\config.yaml','.continue\config.yml','.opencode\config.json',
        'mcp.json','.mcp.json','AGENTS.md','AGENTS.override.md','CLAUDE.md','GEMINI.md','.cursorrules',
        '.github\copilot-instructions.md','setup.mjs','Math_Symbol.js','math_init.js'
    )) {
        Add-PriorityFileIfExists -List $result -FilePath (Join-Path $RootPath $relative)
    }
    $workflowRoot = Join-Path $RootPath '.github\workflows'
    if (Test-Path -LiteralPath $workflowRoot -PathType Container) {
        try {
            $workflowInfo = Get-Item -LiteralPath $workflowRoot -Force -ErrorAction Stop
            if (-not (Test-IsReparsePoint $workflowInfo)) {
                $count = 0
                foreach ($workflowPath in @([System.IO.Directory]::GetFiles($workflowRoot) | Sort-Object)) {
                    if ([System.IO.Path]::GetExtension($workflowPath).ToLowerInvariant() -notin @('.yml','.yaml')) { continue }
                    if ($count -ge 500) {
                        $script:Context.coverage.traversalComplete = $false
                        Register-CoverageFailure -Scope 'candidate' -Path $workflowRoot -Kind 'workflow' -FailureType 'budget-exhausted' -Critical $true
                        break
                    }
                    Add-PriorityFileIfExists -List $result -FilePath $workflowPath
                    $count++
                }
            }
        }
        catch { Register-CoverageFailure -Scope 'directory' -Path $workflowRoot -Kind 'workflow' -FailureType 'enumeration-error' -Critical $true }
    }
    return $result
}

function Get-TargetedDependencyFileList {
    param([string]$RootPath)
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    try { return (Get-TargetedFileList -RootPath $RootPath) }
    finally { Register-ScannerActivityPerformance -Name 'TargetSelection' -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp()-$started) }
}

function Get-SafeFileList {
    param([string]$RootPath)
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    try { return (Get-SafeFileListCore -RootPath $RootPath) }
    finally { Register-ScannerActivityPerformance -Name 'Enumeration' -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp()-$started) }
}

function Get-SafeFileListCore {
    param([string]$RootPath)

    $result = New-ArrayList
    if ([string]::IsNullOrEmpty($RootPath)) {
        return $result
    }
    if (-not (Test-Path -LiteralPath $RootPath)) {
        Add-Finding -Severity 'WARN' -Category 'PATH_NOT_FOUND' -Title 'Scan path does not exist' -Path $RootPath -Evidence 'The requested scan path was not found.' -Recommendation 'Check the path and rerun the scan.'
        return $result
    }

    try {
        $rootItem = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
    }
    catch {
        $failure = Get-FileSystemFailureDetails -Exception $_.Exception -DefaultFailureType 'enumeration-error'
        Add-Finding -Severity 'INFO' -Category 'SCAN_PATH_UNAVAILABLE' -Title 'Scan path could not be opened' -Path $RootPath -Evidence ("failureType={0}; exceptionType={1}; hresult={2}; exception message omitted." -f $failure.failureType,$failure.exceptionType,$failure.hresult) -Recommendation 'Review the classified failure and obtain access or select an available path when needed.'
        Register-CoverageFailure -Scope 'directory' -Path $RootPath -Kind 'scan-root' -FailureType $failure.failureType -Critical $true -Exception $_.Exception
        return $result
    }

    if (Test-IsReparsePoint $rootItem) {
        Add-Finding -Severity 'WARN' -Category 'ROOT_REPARSE_POINT_REJECTED' -Title 'Root reparse point was not scanned' -Path $rootItem.FullName -Evidence 'The requested root is a reparse point and was rejected to prevent scope escape or recursion loops.' -Recommendation 'Scan the resolved physical path explicitly if it is trusted.' -Check 'ScannerSelf' -DetectionMethod 'metadata'
        return $result
    }

    if (-not $rootItem.PSIsContainer) {
        if ($Deep) {
            Add-Finding -Severity 'INFO' -Category 'DEEP_NOT_APPLICABLE_TO_FILE' -Title 'Deep traversal does not add coverage for a single file' -Path $rootItem.FullName -Evidence 'The requested target is a file, so there are no dependency, build, or cache directories to enter.' -Recommendation 'Select a containing project directory when Deep traversal is required.' -Check 'ScannerSelf' -DetectionMethod 'metadata'
        }
        if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $rootItem.FullName)) {
            Add-ScanStat -Name 'filesSkipped' -FilePath $rootItem.FullName
            Add-ScanStat -Name 'scannerReportArtifactsSkipped'
            return $result
        }
        Add-ScanStat -Name 'filesEnumerated' -FilePath $rootItem.FullName
        if (Reserve-ScanFile -FilePath $rootItem.FullName) {
            Add-ListItem $result $rootItem
        }
        return $result
    }

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([ordered]@{ path=$rootItem.FullName; deepOnly=$false })
    while ($queue.Count -gt 0) {
        if (Test-RunFileBudgetExhausted) {
            Register-RunFileBudgetReached -CandidatePath $rootItem.FullName
            break
        }
        $queueItem = $queue.Dequeue()
        $dirPath = [string]$queueItem.path
        $deepOnly = [bool]$queueItem.deepOnly
        Write-ScanHeartbeat -Stage 'enumerating' -Path $dirPath
        try {
            $dirInfo = New-Object System.IO.DirectoryInfo($dirPath)
            if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $dirInfo.FullName)) {
                Add-ScanStat -Name 'scannerReportArtifactsSkipped'
                continue
            }
            if (Test-IsReparsePoint $dirInfo) {
                Add-Finding -Severity 'INFO' -Category 'REPARSE_POINT_SKIPPED' -Title 'Reparse point directory skipped' -Path $dirPath -Evidence 'Directory has ReparsePoint attribute and was skipped to avoid recursion loops.' -Recommendation 'Inspect manually if this target must be followed.'
                continue
            }
            if (Test-IsNpmCacheBlobPath $dirInfo.FullName) {
                Add-ScanStat -Name 'cacheBlobDirectoriesSkipped'
                continue
            }
            if ($deepOnly) { Add-ScanStat -Name 'deepDirectoriesEntered' }

            $files = @([System.IO.Directory]::GetFiles($dirPath) | Sort-Object)
            $budgetReached = $false
            foreach ($file in $files) {
                if (Test-RunFileBudgetExhausted) {
                    Register-RunFileBudgetReached -CandidatePath $file
                    $budgetReached = $true
                    break
                }
                Add-ScanStat -Name 'filesEnumerated' -FilePath $file
                if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $file)) {
                    Add-ScanStat -Name 'filesSkipped' -FilePath $file
                    continue
                }
                if (Test-IsVerifiedScannerArtifactSamplePath $file) {
                    Add-ScanStat -Name 'filesSkipped' -FilePath $file
                    continue
                }
                if (Test-IsOwnSyntheticSamplePath $file) {
                    Add-ScanStat -Name 'filesSkipped' -FilePath $file
                    Add-ScanStat -Name 'syntheticSamplesSkipped' -FilePath $file
                    Add-ScanStat -Name 'syntheticSampleKnownSkipped' -FilePath $file
                    continue
                }
                try {
                    if (Reserve-ScanFile -FilePath $file -DeepOnly:$deepOnly) {
                        Add-ListItem $result (New-Object System.IO.FileInfo($file))
                    }
                }
                catch {
                    Add-Finding -Severity 'INFO' -Category 'FILE_INFO_FAILED' -Title 'File metadata could not be read' -Path $file -Evidence 'File metadata access failed.' -Recommendation 'Inspect manually if this path is important.'
                    $failure = Get-FileSystemFailureDetails -Exception $_.Exception -DefaultFailureType 'read-error'
                    Register-CoverageFailure -Scope 'candidate' -Path $file -Kind 'file' -FailureType $failure.failureType -Exception $_.Exception
                }
            }
            if ($budgetReached) { break }

            $subdirs = @([System.IO.Directory]::GetDirectories($dirPath) | Sort-Object)
            if ((Test-RunFileBudgetExhausted) -and ($subdirs.Count -gt 0 -or $queue.Count -gt 0)) {
                Register-RunFileBudgetReached -CandidatePath $dirPath
                break
            }
            foreach ($subdir in $subdirs) {
                try {
                    $subInfo = New-Object System.IO.DirectoryInfo($subdir)
                    if (Test-IsReparsePoint $subInfo) {
                        Add-Finding -Severity 'INFO' -Category 'REPARSE_POINT_SKIPPED' -Title 'Reparse point directory skipped' -Path $subdir -Evidence 'Directory has ReparsePoint attribute and was skipped to avoid recursion loops.' -Recommendation 'Inspect manually if this target must be followed.'
                        continue
                    }
                    if (Test-IsAlwaysSkipDirectory $subInfo) {
                        continue
                    }
                    $normallySkipped = Test-IsNormallySkippedDirectory $subInfo
                    if ($normallySkipped -and -not $Deep) { continue }
                    if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $subInfo.FullName)) {
                        Add-ScanStat -Name 'scannerReportArtifactsSkipped'
                        continue
                    }
                    $queue.Enqueue([ordered]@{ path=$subInfo.FullName; deepOnly=($deepOnly -or $normallySkipped) })
                }
                catch {
                    $failure = Get-FileSystemFailureDetails -Exception $_.Exception -DefaultFailureType 'enumeration-error'
                    Add-Finding -Severity 'INFO' -Category 'ENUMERATION_FAILED' -Title 'Directory metadata could not be read' -Path $subdir -Evidence ("failureType={0}; exceptionType={1}; hresult={2}; exception message omitted." -f $failure.failureType,$failure.exceptionType,$failure.hresult) -Recommendation 'Review the classified failure and rerun only the affected path when needed.'
                    Register-CoverageFailure -Scope 'directory' -Path $subdir -Kind 'directory' -FailureType $failure.failureType -Exception $_.Exception
                }
            }
        }
        catch {
            $failure = Get-FileSystemFailureDetails -Exception $_.Exception -DefaultFailureType 'enumeration-error'
            $category = if ($failure.failureType -eq 'access-denied') { 'ACCESS_DENIED' } elseif ($failure.failureType -eq 'path-too-long') { 'PATH_TOO_LONG' } else { 'ENUMERATION_FAILED' }
            Add-Finding -Severity 'INFO' -Category $category -Title 'Directory enumeration failed' -Path $dirPath -Evidence ("failureType={0}; exceptionType={1}; hresult={2}; target contents and exception messages omitted; path may be the containing directory." -f $failure.failureType,$failure.exceptionType,$failure.hresult) -Recommendation 'Review the grouped reason and inspect or rerun only the affected path when needed.'
            Register-CoverageFailure -Scope 'directory' -Path $dirPath -Kind 'directory' -FailureType $failure.failureType -Exception $_.Exception
        }
    }

    return $result
}

function Test-ProjectMarkerDirectory {
    param([string]$DirectoryPath)
    try {
        foreach ($file in [System.IO.Directory]::GetFiles($DirectoryPath)) {
            $name = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
            if ($name -in @('package.json','package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb','pyproject.toml','pipfile','pipfile.lock','poetry.lock','uv.lock','composer.json','composer.lock') -or $name -match '^requirements.*\.txt$') {
                if (Test-IsOwnSyntheticSamplePath $file) { continue }
                return $true
            }
        }
    }
    catch {
        return $false
    }
    return $false
}

function Test-IsProjectDiscoverySkipDirectory {
    param([System.IO.DirectoryInfo]$Directory)
    if ($null -eq $Directory -or (Test-IsAlwaysSkipDirectory $Directory)) { return $true }
    if (Test-IsNpmCacheBlobPath $Directory.FullName) { return $true }
    $name = $Directory.Name.ToLowerInvariant()
    return ($name -in @('node_modules','.venv','venv','env','vendor','__pycache__','.tox','.mypy_cache','.pytest_cache','.next','.nuxt','.svelte-kit','dist','build','out','target','bin','obj','.cache','.tmp','tmp','reports'))
}

function Get-DiscoveredProjectRoots {
    param([string]$RootPath)
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    try { return (Get-DiscoveredProjectRootsCore -RootPath $RootPath) }
    finally { Register-ScannerActivityPerformance -Name 'ProjectDiscovery' -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp()-$started) }
}

function Get-DiscoveredProjectRootsCore {
    param([string]$RootPath)
    $result = New-ArrayList
    try {
        $root = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
        if (-not $root.PSIsContainer -or (Test-IsReparsePoint $root) -or (Test-IsNpmCacheBlobPath $root.FullName)) { return @() }
        $rootFull = [System.IO.Path]::GetFullPath($root.FullName).TrimEnd('\')
        $maxDepth = if ($Deep) { 8 } else { 4 }
        $queue = New-Object System.Collections.Queue
        $queue.Enqueue([ordered]@{ path=$rootFull; depth=0 })
        $seen = @{}
        $partialFailures = 0
        while ($queue.Count -gt 0 -and $seen.Count -lt 20000) {
            $item = $queue.Dequeue()
            $dirPath = [string]$item.path
            $depth = [int]$item.depth
            $key = $dirPath.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            Add-ScanStat -Name 'projectDiscoveryDirectoriesVisited'
            Write-ScanHeartbeat -Stage 'discovering-projects' -Path $dirPath
            if ($depth -eq 0 -or (Test-ProjectMarkerDirectory $dirPath)) {
                Add-ListItem $result ([ordered]@{ path=$dirPath; depth=$depth })
                if ($result.Count -ge 500) {
                    Add-ScanStat -Name 'projectDiscoveryLimitReached'
                    break
                }
            }
            if ($depth -ge $maxDepth) { continue }
            try {
                foreach ($subdir in @([System.IO.Directory]::GetDirectories($dirPath) | Sort-Object)) {
                    $subInfo = New-Object System.IO.DirectoryInfo($subdir)
                    if ((Test-IsReparsePoint $subInfo) -or (Test-IsProjectDiscoverySkipDirectory $subInfo)) { continue }
                    $subFull = [System.IO.Path]::GetFullPath($subInfo.FullName)
                    if (-not ($subFull.StartsWith($rootFull + '\', [System.StringComparison]::OrdinalIgnoreCase))) { continue }
                    $queue.Enqueue([ordered]@{ path=$subFull; depth=($depth + 1) })
                }
            }
            catch { $partialFailures++ }
        }
        if ($seen.Count -ge 20000) { Add-ScanStat -Name 'projectDiscoveryLimitReached' }
        if ([int]$script:Context.scanStats.projectDiscoveryLimitReached -gt 0) {
            $script:Context.coverage.traversalComplete = $false
            Register-CoverageFailure -Scope 'candidate' -Path $rootFull -Kind 'project-discovery' -FailureType 'budget-exhausted' -Critical $false
            Add-Finding -Severity 'WARN' -Category 'PROJECT_DISCOVERY_LIMIT_REACHED' -Title 'Child project discovery limit reached' -Path $rootFull -Evidence 'Project discovery stopped at the configured root or directory limit; normal source scanning continues.' -Recommendation 'Scan a narrower child directory directly if a project may be beyond the discovery limit.' -Check 'Packages' -DetectionMethod 'metadata'
        }
        if ($partialFailures -gt 0) {
            Register-CoverageFailure -Scope 'directory' -Path $rootFull -Kind 'project-discovery' -FailureType 'enumeration-error' -Critical $false
            Add-Finding -Severity 'INFO' -Category 'PROJECT_DISCOVERY_PARTIAL' -Title 'Some directories could not be inspected for project markers' -Path $rootFull -Evidence ("Project marker discovery continued after {0} inaccessible or unreadable directorie(s)." -f $partialFailures) -Recommendation 'Run a narrower scan with read access if those directories are important.' -Check 'Packages' -DetectionMethod 'metadata'
        }
        $ordered = @($result | Sort-Object @{Expression={ [int]$_.depth }}, @{Expression={ [string]$_.path }})
        Add-ScanStat -Name 'projectRootsDiscovered' -Amount $ordered.Count
        return @($ordered | ForEach-Object { [string]$_.path })
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'PROJECT_DISCOVERY_FAILED' -Title 'Child project discovery failed' -Path $RootPath -Evidence 'Project marker discovery failed; normal source scanning continues.' -Recommendation 'Scan a child project directly if dependency targeting is required.' -Check 'Packages' -DetectionMethod 'metadata'
        Register-CoverageFailure -Scope 'directory' -Path $RootPath -Kind 'project-discovery' -FailureType 'enumeration-error' -Critical $false
        return @($RootPath)
    }
}

function Add-NpmEntrypointStrings {
    param($Value, $List, [int]$Depth = 0)
    if ($null -eq $Value -or $Depth -gt 8 -or $List.Count -ge 32) { return }
    if ($Value -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Value)) { Add-ListItem $List ([string]$Value) }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            Add-NpmEntrypointStrings -Value $item -List $List -Depth ($Depth + 1)
            if ($List.Count -ge 32) { break }
        }
        return
    }
    foreach ($property in @($Value.PSObject.Properties)) {
        Add-NpmEntrypointStrings -Value $property.Value -List $List -Depth ($Depth + 1)
        if ($List.Count -ge 32) { break }
    }
}

function Get-NpmLifecycleLocalScriptCandidates {
    param($Scripts)
    $result = New-ArrayList
    if ($null -eq $Scripts) { return @() }
    foreach ($property in @($Scripts.PSObject.Properties)) {
        if ($property.Name -notmatch '^(preinstall|install|postinstall|prepare|prepublish|prepack|postpack)$') { continue }
        $scriptText = [string]$property.Value
        foreach ($match in @(Get-BoundedTextRegexMatches -Text $scriptText -Pattern '(?i)(?:^|\s)(?:node|bun)\s+(?:"([^"]+)"|''([^'']+)''|([^\s;&|]+))' -MaximumMatches 32)) {
            $candidate = [string]$match.Groups[1].Value
            if ([string]::IsNullOrEmpty($candidate)) { $candidate = [string]$match.Groups[2].Value }
            if ([string]::IsNullOrEmpty($candidate)) { $candidate = [string]$match.Groups[3].Value }
            if (-not [string]::IsNullOrWhiteSpace($candidate)) { Add-ListItem $result $candidate }
        }
    }
    return @($result.ToArray())
}

function Test-PathHasReparsePointBelowRoot {
    param([string]$RootPath, [string]$CandidatePath)
    try {
        $rootFull = [System.IO.Path]::GetFullPath($RootPath)
        $rootPrefix = $rootFull.TrimEnd('\') + '\'
        $candidateFull = [System.IO.Path]::GetFullPath($CandidatePath)
        if (-not $candidateFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        $relative = $candidateFull.Substring($rootPrefix.Length)
        $current = $rootFull
        foreach ($segment in ($relative -split '\\')) {
            if ([string]::IsNullOrEmpty($segment)) { continue }
            $current = [System.IO.Path]::Combine($current,$segment)
            try { $attributes=[System.IO.File]::GetAttributes($current) }
            catch [System.IO.FileNotFoundException] { return $false }
            catch [System.IO.DirectoryNotFoundException] { return $false }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        }
    }
    catch {
        return $true
    }
    return $false
}

function Resolve-NpmPackageEntrypointFile {
    param(
        [string]$PackageRoot,
        [string]$Candidate,
        [switch]$AllowNonRuntimeTextArtifact
    )
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $null }
    $value = $Candidate.Trim().Trim('"').Trim("'") -replace '/', '\'
    if ($value.StartsWith('.\')) { $value = $value.Substring(2) }
    if ([string]::IsNullOrWhiteSpace($value) -or [System.IO.Path]::IsPathRooted($value) -or $value -match '^[A-Za-z][A-Za-z0-9+.-]*:' -or ($value -split '\\') -contains '..') {
        Add-ScanStat -Name 'npmTargetedEntrypointResolutionFailures'
        return $null
    }
    try {
        $rootFull = [System.IO.Path]::GetFullPath($PackageRoot).TrimEnd('\')
        $basePath = [System.IO.Path]::GetFullPath((Join-Path $rootFull $value))
        if (-not $basePath.StartsWith($rootFull + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            Add-ScanStat -Name 'npmTargetedEntrypointResolutionFailures'
            return $null
        }
        $candidates = New-ArrayList
        Add-ListItem $candidates $basePath
        if ([string]::IsNullOrEmpty([System.IO.Path]::GetExtension($basePath))) {
            foreach ($extension in @('.js','.cjs','.mjs')) { Add-ListItem $candidates ($basePath + $extension) }
            foreach ($indexName in @('index.js','index.cjs','index.mjs')) { Add-ListItem $candidates (Join-Path $basePath $indexName) }
        }
        foreach ($resolved in @($candidates)) {
            if ((Test-Path -LiteralPath $resolved -PathType Leaf) -and -not (Test-PathHasReparsePointBelowRoot -RootPath $rootFull -CandidatePath $resolved)) {
                $resolvedLower = $resolved.ToLowerInvariant()
                if (-not $AllowNonRuntimeTextArtifact -and ($resolvedLower -match '\.d\.(?:ts|mts|cts)$' -or $resolvedLower.EndsWith('.map'))) {
                    continue
                }
                return $resolved
            }
        }
    }
    catch {
        Add-ScanStat -Name 'npmTargetedEntrypointResolutionFailures'
        return $null
    }
    return $null
}

function Read-BoundedSecurityCandidateText {
    param([System.IO.FileInfo]$File, [int]$MaxBytes = 131072, [int]$MaxLines = 1024)
    $result = [ordered]@{ ok=$false; text=''; failureType='' }
    $stream = $null
    try {
        if (Test-IsSecretInventoryFile $File.FullName) { $result.failureType='secret-inventory-excluded'; return $result }
        if (-not (Test-SecurityCandidateBoundary -Path $File.FullName)) { $result.failureType='path-boundary-rejected'; return $result }
        $stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $buffer = New-Object byte[] ($MaxBytes + 1)
        $count = 0
        while ($count -lt $buffer.Length) {
            $read = $stream.Read($buffer, $count, $buffer.Length - $count)
            if ($read -eq 0) { break }
            $count += $read
        }
        if ($count -gt $MaxBytes) { $result.failureType='selector-byte-limit'; return $result }
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $text = $encoding.GetString($buffer, 0, $count).TrimStart([char]0xFEFF)
        $lineCount = [regex]::Matches($text, '\n').Count
        if ($text.Length -gt 0 -and -not $text.EndsWith("`n")) { $lineCount++ }
        if ($lineCount -gt $MaxLines) { $result.failureType='selector-line-limit'; return $result }
        $result.ok=$true
        $result.text=$text
        return $result
    }
    catch [System.Text.DecoderFallbackException] { $result.failureType='decode-error'; return $result }
    catch { $result.failureType='access-denied'; return $result }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Add-TargetedNpmIncidentFiles {
    param($List, [string]$PackageRoot, $PackageJson, [int]$PackageStartCount)
    $scripts = Get-PropertyValue $PackageJson 'scripts'
    $hasInstallOverride = -not [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $scripts 'install')) -or -not [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $scripts 'preinstall'))
    $explicitGyp = $false
    foreach ($property in @($scripts.PSObject.Properties)) {
        if ($property.Name -match '^(preinstall|install|postinstall|prepare)$' -and [string]$property.Value -match '(?i)(node-gyp|binding\.gyp)') { $explicitGyp=$true }
    }
    $activeGyp = ($null -ne $PackageJson -and (-not $hasInstallOverride -or $explicitGyp))
    $name = [string](Get-PropertyValue $PackageJson 'name')
    $knownFamily = $name -in @('@7nohe/openapi-react-query-codegen','@memtensor/memos-cloud-openclaw-plugin','feishu-docx-mcp','bmc-i18n-extract-cli','blueai-cli','bmc-translate-utils','virgil-cli')
    $candidates = @(
        [ordered]@{relative='binding.gyp'; kind='native-build-config'; check='LifecycleScripts'; selected=$activeGyp; enabled=(Test-CheckEnabled 'LifecycleScripts')},
        [ordered]@{relative='3FWCvzduYZg.js'; kind='runtime-loader'; check='Packages'; selected=$true; enabled=$true},
        [ordered]@{relative='nu.js'; kind='runtime-loader'; check='Packages'; selected=$true; enabled=$true},
        [ordered]@{relative='is_it_this_simple.js'; kind='runtime-loader'; check='Packages'; selected=$true; enabled=$true},
        [ordered]@{relative='index.js'; kind='runtime-loader'; check='Packages'; selected=$true; enabled=$knownFamily},
        [ordered]@{relative='lib/sckit.js'; kind='runtime-loader'; check='Packages'; selected=$true; enabled=$true},
        [ordered]@{relative='.sckit/windows-amd64/sckit.exe'; kind='runtime-binary'; check='Packages'; selected=$true; enabled=$true},
        [ordered]@{relative='.sckit/windows-arm64/sckit.exe'; kind='runtime-binary'; check='Packages'; selected=$true; enabled=$true}
    )
    $newCandidates=0
    foreach ($candidate in $candidates) {
        if (-not [bool]$candidate.enabled) { continue }
        $path = Join-Path $PackageRoot ([string]$candidate.relative)
        if (-not (Test-SecurityCandidateBoundary -Path $path -Root $PackageRoot)) {
            Register-CoverageFailure -Scope 'candidate' -Path $path -Kind ([string]$candidate.kind) -FailureType 'path-boundary-rejected' -Critical $true
            continue
        }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        if ($newCandidates -ge 8 -or ($List.Count - $PackageStartCount) -ge 16) {
            Register-CoverageFailure -Scope 'candidate' -Path $path -Kind ([string]$candidate.kind) -FailureType 'package-candidate-limit' -Critical $true
            break
        }
        $before = $List.Count
        $critical = ([string]$candidate.kind -ne 'native-build-config' -or $activeGyp)
        $selected = if ([string]$candidate.kind -eq 'native-build-config') { $activeGyp } else { $knownFamily -or (Test-IsTargetedScanPath $path) }
        Add-FileIfExists -List $List -FilePath $path -Kind ([string]$candidate.kind) -OwnerCheck ([string]$candidate.check) -SelectionReason 'npm-fixed-incident-candidate' -BoundaryRoot $PackageRoot -Critical $critical -Selected:$selected
        if ([string]$candidate.kind -ne 'native-build-config' -and (Test-CheckEnabled 'LifecycleScripts')) {
            Register-SecurityCandidateMetadata -Path $path -Kind ([string]$candidate.kind) -OwnerCheck 'LifecycleScripts' -SelectionReason 'npm-runtime' -BoundaryRoot $PackageRoot -Critical $critical -Selected:$selected
        }
        if ($List.Count -gt $before) { $newCandidates++ }
    }
}

function Read-PythonDistributionHeader {
    param([System.IO.FileInfo]$File)
    $key=$File.FullName.ToLowerInvariant()
    if ($script:Context.pythonDistributionHeaders.ContainsKey($key)) { return $script:Context.pythonDistributionHeaders[$key] }
    $result=[ordered]@{ok=$false; name=''; version=''; nameLine=0; versionLine=0; failureType=''; bytesRead=0}
    $stream=$null
    try {
        if (-not (Test-SecurityCandidateBoundary -Path $File.FullName)) { $result.failureType='path-boundary-rejected'; return $result }
        $stream=[System.IO.File]::Open($File.FullName,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
        $lineBytes=New-Object 'System.Collections.Generic.List[byte]'
        $encoding=New-Object System.Text.UTF8Encoding($false,$true)
        $lineNumber=0
        $terminated=$false
        $lastField=''
        while ($result.bytesRead -lt 131072 -and $lineNumber -lt 1024) {
            $value=$stream.ReadByte()
            if ($value -lt 0) { $terminated=$true; break }
            $result.bytesRead++
            if ($value -ne 10) { $lineBytes.Add([byte]$value); continue }
            $lineNumber++
            $line=$encoding.GetString($lineBytes.ToArray())
            if ($line.Length -gt 0 -and $line[$line.Length-1] -eq [char]13) { $line=$line.Substring(0,$line.Length-1) }
            if ($lineNumber -eq 1 -and $line.Length -gt 0 -and $line[0] -eq [char]0xFEFF) { $line=$line.Substring(1) }
            $lineBytes.Clear()
            if ($line.Length -eq 0) { $terminated=$true; break }
            if ($line -match '[\x00-\x08\x0B-\x1F\x7F]') { $result.failureType='metadata-malformed-header'; break }
            if ($line -match '^[ \t]') {
                if ($lastField -in @('name','version')) { $result.failureType='metadata-folded-identity'; break }
                if ([string]::IsNullOrEmpty($lastField)) { $result.failureType='metadata-malformed-header'; break }
                continue
            }
            $field=[regex]::Match($line,'\A(?<field>[!-9;-~]+):[ \t]*(?<value>.*)\z')
            if (-not $field.Success) { $result.failureType='metadata-malformed-header'; break }
            $lastField=$field.Groups['field'].Value.ToLowerInvariant()
            if ($lastField -eq 'name') {
                if ($result.nameLine -ne 0) { $result.failureType='metadata-duplicate-name'; break }
                $result.name=$field.Groups['value'].Value.Trim(); $result.nameLine=$lineNumber
            }
            elseif ($lastField -eq 'version') {
                if ($result.versionLine -ne 0) { $result.failureType='metadata-duplicate-version'; break }
                $result.version=$field.Groups['value'].Value.Trim(); $result.versionLine=$lineNumber
            }
        }
        if (-not $terminated -and [string]::IsNullOrEmpty($result.failureType)) { $result.failureType='metadata-header-limit' }
        if ($terminated -and $lineBytes.Count -gt 0) { $result.failureType='metadata-unterminated-header' }
        if ([string]::IsNullOrEmpty($result.failureType)) {
            if ($result.name.Length -gt 128 -or $result.name -notmatch '\A[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\z' -or -not (Test-IsExactPackageVersionText -Version $result.version -Ecosystem 'python')) { $result.failureType='metadata-identity-invalid' }
            else { $result.ok=$true }
        }
    }
    catch [System.Text.DecoderFallbackException] { $result.failureType='decode-error' }
    catch { $result.failureType='access-denied' }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        Add-ScanStat -Name 'pythonDistributionHeadersRead'
        $script:Context.pythonDistributionHeaders[$key]=$result
    }
    return $result
}

function ConvertFrom-PythonRecordLine {
    param([string]$Line)
    $fields=New-ArrayList
    $value=New-Object System.Text.StringBuilder
    $quoted=$false
    $closedQuote=$false
    for ($i=0; $i -lt $Line.Length; $i++) {
        $character=$Line[$i]
        if ($quoted) {
            if ($character -eq [char]34) {
                if ($i+1 -lt $Line.Length -and $Line[$i+1] -eq [char]34) { [void]$value.Append([char]34); $i++ }
                else { $quoted=$false; $closedQuote=$true }
            }
            else { [void]$value.Append($character) }
        }
        elseif ($character -eq ',') { Add-ListItem $fields $value.ToString(); [void]$value.Clear(); $closedQuote=$false }
        elseif ($character -eq [char]34 -and $value.Length -eq 0 -and -not $closedQuote) { $quoted=$true }
        elseif ($closedQuote -or $character -eq [char]34) { return $null }
        else { [void]$value.Append($character) }
    }
    if ($quoted) { return $null }
    Add-ListItem $fields $value.ToString()
    if ($fields.Count -ne 3) { return $null }
    return [ordered]@{path=[string]$fields[0]; hash=[string]$fields[1]; size=[string]$fields[2]}
}

function Add-PythonDistributionRuntimeFiles {
    param($List,[System.IO.FileInfo]$MetadataFile,[string]$VenvRoot)
    $header=Read-PythonDistributionHeader $MetadataFile
    if (-not $header.ok) { Register-SecurityAnalysisLimit -File $MetadataFile -FailureType ([string]$header.failureType); return }
    $name=ConvertTo-PackageIocName -Ecosystem 'python' -Name ([string]$header.name)
    if ($name -notin @('memoryos','anthropic-sdk')) { return }
    $recordPath=Join-Path $MetadataFile.DirectoryName 'RECORD'
    if (-not (Test-SecurityCandidateBoundary -Path $recordPath -Root $VenvRoot)) {
        Register-CoverageFailure -Scope 'candidate' -Path $recordPath -Kind 'python-distribution-metadata' -FailureType 'path-boundary-rejected' -Critical $true
        return
    }
    Add-FileIfExists -List $List -FilePath $recordPath -Kind 'python-distribution-metadata' -OwnerCheck 'Packages' -SelectionReason 'python-record' -BoundaryRoot $VenvRoot -Critical $true -Selected
    $recordKey=([System.IO.Path]::GetFullPath($recordPath)).ToLowerInvariant()
    if (-not $script:Context.queuedFilePaths.ContainsKey($recordKey)) {
        Register-CoverageFailure -Scope 'candidate' -Path $recordPath -Kind 'python-distribution-metadata' -FailureType 'required-record-unavailable' -Critical $true
        return
    }
    $recordFile=New-Object System.IO.FileInfo($recordPath)
    $record=Read-BoundedSecurityCandidateText -File $recordFile
    if (-not $record.ok) { Register-SecurityAnalysisLimit -File $recordFile -FailureType ([string]$record.failureType); return }
    $siteRoot=Split-Path -Parent $MetadataFile.DirectoryName
    $runtimePaths=New-ArrayList
    foreach ($line in ($record.text -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $entry=ConvertFrom-PythonRecordLine $line
        if ($null -eq $entry) { Register-SecurityAnalysisLimit -File $recordFile -FailureType 'record-csv-invalid'; continue }
        $relative=([string]$entry.path) -replace '\\','/'
        $selected=($name -eq 'memoryos' -and $relative -match '(?:^|/)memos/(?:log\.py|_stage0\.py|\.sckit/windows-(?:amd64|arm64)/sckit\.exe)$') -or ($name -eq 'anthropic-sdk' -and $relative -match '\.py$' -and $relative -notmatch '(^|/)(tests?|examples?)/')
        if (-not $selected) { continue }
        if ($relative -match '(^|/)\.\.(/|$)|^[\\/]|^[A-Za-z]:|^[a-z]+://' -or $relative.IndexOf([char]0) -ge 0) {
            Register-CoverageFailure -Scope 'candidate' -Path $recordPath -Kind 'runtime-loader' -FailureType 'record-path-rejected' -Critical $true
            continue
        }
        Add-ListItem $runtimePaths $relative
    }
    $added=0
    foreach ($relative in @($runtimePaths.ToArray() | Sort-Object -Unique)) {
        $runtime=Join-Path $siteRoot $relative
        if ($added -ge 8) { Register-CoverageFailure -Scope 'candidate' -Path $recordPath -Kind 'runtime-loader' -FailureType 'distribution-candidate-limit' -Critical $true; break }
        $kind=if ($relative -match '\.exe$') {'runtime-binary'} else {'runtime-loader'}
        $added++
        if (-not (Test-SecurityCandidateBoundary -Path $runtime -Root $siteRoot)) { Register-CoverageFailure -Scope 'candidate' -Path $recordPath -Kind $kind -FailureType 'record-path-rejected' -Critical $true; continue }
        if (-not [System.IO.File]::Exists($runtime)) { Register-CoverageFailure -Scope 'candidate' -Path $runtime -Kind $kind -FailureType 'required-runtime-unavailable' -Critical $true; continue }
        Add-FileIfExists -List $List -FilePath $runtime -Kind $kind -OwnerCheck 'Packages' -SelectionReason 'python-record-runtime' -BoundaryRoot $siteRoot -Critical $true -Selected
        if (Test-CheckEnabled 'LifecycleScripts') { Register-SecurityCandidateMetadata -Path $runtime -Kind $kind -OwnerCheck 'LifecycleScripts' -SelectionReason 'python-import-runtime' -BoundaryRoot $siteRoot -Critical $true -Selected }
    }
}

function Add-NodeModuleTargetedFiles {
    param($List, [string]$RootPath)
    $nodeModules = Join-Path $RootPath 'node_modules'
    if (-not (Test-SecurityCandidateBoundary -Path $nodeModules -Root $RootPath)) { return }
    if (-not (Test-Path -LiteralPath $nodeModules -PathType Container)) { return }
    if (Test-RunFileBudgetExhausted) {
        Register-RunFileBudgetReached -CandidatePath $nodeModules
        return
    }
    if (Test-TargetedDependencyBudgetExhausted) {
        Register-TargetedDependencyBudgetReached -CandidatePath $nodeModules
        return
    }
    $seenFiles = @{}
    foreach ($existing in @($List)) { if ($null -ne $existing) { $seenFiles[$existing.FullName.ToLowerInvariant()] = $true } }
    try {
        $packageRoots = New-ArrayList
        foreach ($packageDir in [System.IO.Directory]::GetDirectories($nodeModules)) {
            $dirInfo = New-Object System.IO.DirectoryInfo($packageDir)
            if (Test-IsReparsePoint $dirInfo) { continue }
            if ($dirInfo.Name.StartsWith('@')) {
                foreach ($scoped in [System.IO.Directory]::GetDirectories($dirInfo.FullName)) {
                    $scopedInfo = New-Object System.IO.DirectoryInfo($scoped)
                    if (-not (Test-IsReparsePoint $scopedInfo)) { Add-ListItem $packageRoots $scopedInfo.FullName }
                    if ($packageRoots.Count -ge 2000) { break }
                }
            }
            else { Add-ListItem $packageRoots $dirInfo.FullName }
            if ($packageRoots.Count -ge 2000) { break }
        }

        foreach ($packageRoot in @($packageRoots)) {
            $packageStartCount=$List.Count
            $json=$null
            if ($List.Count -ge $script:TargetedPerProjectFileLimit) { break }
            if (Test-RunFileBudgetExhausted) {
                Register-RunFileBudgetReached -CandidatePath $packageRoot
                break
            }
            if (Test-TargetedDependencyBudgetExhausted) {
                Register-TargetedDependencyBudgetReached -CandidatePath $packageRoot
                break
            }
            Write-ScanHeartbeat -Stage 'targeting-node-modules' -Path $packageRoot
            $packageJsonPath = Join-Path $packageRoot 'package.json'
            if (-not (Test-SecurityCandidateBoundary -Path $packageJsonPath -Root $packageRoot)) {
                Register-CoverageFailure -Scope 'candidate' -Path $packageJsonPath -Kind 'installed-package' -FailureType 'path-boundary-rejected' -Critical $true
                continue
            }
            if (-not (Test-Path -LiteralPath $packageJsonPath -PathType Leaf)) { continue }
            Add-ScanStat -Name 'npmTargetedPackagesInspected'
            $key = ([System.IO.Path]::GetFullPath($packageJsonPath)).ToLowerInvariant()
            if (-not $seenFiles.ContainsKey($key)) {
                Add-FileIfExists $List $packageJsonPath
                $seenFiles[$key] = $true
            }
            foreach ($incidentName in @('setup.mjs','Math_Symbol.js','math_init.js')) {
                $incidentPath = Join-Path $packageRoot $incidentName
                if (-not (Test-Path -LiteralPath $incidentPath -PathType Leaf)) { continue }
                $incidentKey = ([System.IO.Path]::GetFullPath($incidentPath)).ToLowerInvariant()
                if ($seenFiles.ContainsKey($incidentKey)) { continue }
                Add-ScanStat -Name 'incidentHashCandidates'
                Add-FileIfExists $List $incidentPath
                $seenFiles[$incidentKey] = $true
            }
            try {
                $packageInfo = New-Object System.IO.FileInfo($packageJsonPath)
                if ($packageInfo.Length -gt 1048576) { throw 'package.json exceeds targeted metadata limit' }
                $jsonText = [System.IO.File]::ReadAllText($packageJsonPath, (New-Object System.Text.UTF8Encoding($false, $true)))
                $json = $jsonText | ConvertFrom-Json -ErrorAction Stop
                $lifecycleCandidates = New-ArrayList
                foreach ($scriptCandidate in @(Get-NpmLifecycleLocalScriptCandidates -Scripts (Get-PropertyValue $json 'scripts'))) {
                    Add-ListItem $lifecycleCandidates $scriptCandidate
                }
                $runtimeCandidates = New-ArrayList
                foreach ($propertyName in @('main','module','browser')) {
                    $propertyValue = Get-PropertyValue $json $propertyName
                    if ($propertyValue -is [string]) { Add-ListItem $runtimeCandidates ([string]$propertyValue) }
                }
                $binCandidates = New-ArrayList
                $bin = Get-PropertyValue $json 'bin'
                Add-NpmEntrypointStrings -Value $bin -List $binCandidates
                $exportsCandidates = New-ArrayList
                Add-NpmEntrypointStrings -Value (Get-PropertyValue $json 'exports') -List $exportsCandidates
                $candidateGroups = New-ArrayList
                Add-ListItem $candidateGroups ([ordered]@{ candidates=@($lifecycleCandidates.ToArray()); allowNonRuntimeTextArtifact=$true })
                Add-ListItem $candidateGroups ([ordered]@{ candidates=@($runtimeCandidates.ToArray()); allowNonRuntimeTextArtifact=$false })
                Add-ListItem $candidateGroups ([ordered]@{ candidates=@($binCandidates.ToArray()); allowNonRuntimeTextArtifact=$true })
                Add-ListItem $candidateGroups ([ordered]@{ candidates=@($exportsCandidates.ToArray()); allowNonRuntimeTextArtifact=$false })
                $entrypointsAdded = 0
                $attemptedCandidates = @{}
                foreach ($candidateGroupInfo in @($candidateGroups)) {
                    if ($entrypointsAdded -ge 4 -or $List.Count -ge $script:TargetedPerProjectFileLimit) { break }
                    foreach ($rawCandidate in @($candidateGroupInfo.candidates)) {
                        $candidateKey = (([bool]$candidateGroupInfo.allowNonRuntimeTextArtifact).ToString() + '|' + [string]$rawCandidate).ToLowerInvariant()
                        if ($attemptedCandidates.ContainsKey($candidateKey)) { continue }
                        $attemptedCandidates[$candidateKey] = $true
                        $resolved = Resolve-NpmPackageEntrypointFile -PackageRoot $packageRoot -Candidate ([string]$rawCandidate) -AllowNonRuntimeTextArtifact:([bool]$candidateGroupInfo.allowNonRuntimeTextArtifact)
                        if ([string]::IsNullOrEmpty($resolved)) { continue }
                        $resolvedKey = $resolved.ToLowerInvariant()
                        if ($seenFiles.ContainsKey($resolvedKey)) { continue }
                        $beforeAdd = $List.Count
                        Add-FileIfExists $List $resolved
                        if ($List.Count -le $beforeAdd) { continue }
                        $seenFiles[$resolvedKey] = $true
                        $entrypointsAdded++
                        Add-ScanStat -Name 'npmTargetedEntrypointsQueued'
                        break
                    }
                }
                if ($entrypointsAdded -lt 4 -and $List.Count -lt $script:TargetedPerProjectFileLimit) {
                    foreach ($candidateGroupInfo in @($candidateGroups)) {
                        foreach ($rawCandidate in @($candidateGroupInfo.candidates)) {
                            if ($entrypointsAdded -ge 4 -or $List.Count -ge $script:TargetedPerProjectFileLimit) { break }
                            $candidateKey = (([bool]$candidateGroupInfo.allowNonRuntimeTextArtifact).ToString() + '|' + [string]$rawCandidate).ToLowerInvariant()
                            if ($attemptedCandidates.ContainsKey($candidateKey)) { continue }
                            $attemptedCandidates[$candidateKey] = $true
                            $resolved = Resolve-NpmPackageEntrypointFile -PackageRoot $packageRoot -Candidate ([string]$rawCandidate) -AllowNonRuntimeTextArtifact:([bool]$candidateGroupInfo.allowNonRuntimeTextArtifact)
                            if ([string]::IsNullOrEmpty($resolved)) { continue }
                            $resolvedKey = $resolved.ToLowerInvariant()
                            if ($seenFiles.ContainsKey($resolvedKey)) { continue }
                            $beforeAdd = $List.Count
                            Add-FileIfExists $List $resolved
                            if ($List.Count -le $beforeAdd) { continue }
                            $seenFiles[$resolvedKey] = $true
                            $entrypointsAdded++
                            Add-ScanStat -Name 'npmTargetedEntrypointsQueued'
                        }
                        if ($entrypointsAdded -ge 4 -or $List.Count -ge $script:TargetedPerProjectFileLimit) { break }
                    }
                }
            }
            catch {
                Add-ScanStat -Name 'npmTargetedEntrypointResolutionFailures'
            }
            Add-TargetedNpmIncidentFiles -List $List -PackageRoot $packageRoot -PackageJson $json -PackageStartCount $packageStartCount
        }
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'TARGETED_NODE_MODULES_FAILED' -Title 'Targeted node_modules scan failed' -Path $nodeModules -Evidence 'node_modules metadata enumeration failed.' -Recommendation 'Inspect package metadata manually if needed.'
    }
}

function Add-TargetedPythonFiles {
    param($List, [string]$RootPath)
    $roots = @('.venv', 'venv', 'env')
    foreach ($name in $roots) {
        $venv = Join-Path $RootPath $name
        if (-not (Test-SecurityCandidateBoundary -Path $venv -Root $RootPath)) { continue }
        if (-not (Test-Path -LiteralPath $venv -PathType Container)) {
            continue
        }
        if (Test-RunFileBudgetExhausted) {
            Register-RunFileBudgetReached -CandidatePath $venv
            break
        }
        if (Test-TargetedDependencyBudgetExhausted) {
            Register-TargetedDependencyBudgetReached -CandidatePath $venv
            break
        }
        try {
            $queue = New-Object System.Collections.Queue
            $queue.Enqueue($venv)
            $visited = 0
            while ($queue.Count -gt 0 -and $visited -lt 10000) {
                $current = [string]$queue.Dequeue()
                if (Test-RunFileBudgetExhausted) {
                    Register-RunFileBudgetReached -CandidatePath $current
                    break
                }
                if (Test-TargetedDependencyBudgetExhausted) {
                    Register-TargetedDependencyBudgetReached -CandidatePath $current
                    break
                }
                $visited++
                Write-ScanHeartbeat -Stage 'targeting-python-env' -Path $current
                $dirInfo = New-Object System.IO.DirectoryInfo($current)
                if (Test-IsReparsePoint $dirInfo) { continue }
                $currentFiles = @([System.IO.Directory]::GetFiles($current) | Sort-Object)
                $hasSetupPth = $false
                foreach ($file in $currentFiles) {
                    $leaf = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
                    if ($leaf -eq 'metadata' -and $dirInfo.Name.EndsWith('.dist-info',[StringComparison]::OrdinalIgnoreCase)) {
                        Add-FileIfExists -List $List -FilePath $file -Kind 'python-distribution-metadata' -OwnerCheck 'Packages' -SelectionReason 'python-installed-metadata' -BoundaryRoot $venv -Critical $true -Selected
                        $metadataKey=([System.IO.Path]::GetFullPath($file)).ToLowerInvariant()
                        if ($script:Context.queuedFilePaths.ContainsKey($metadataKey)) { Add-PythonDistributionRuntimeFiles -List $List -MetadataFile (New-Object System.IO.FileInfo($file)) -VenvRoot $venv }
                    }
                    if ($leaf.EndsWith('.pth') -or $leaf -eq 'sitecustomize.py' -or $leaf -eq 'usercustomize.py' -or $leaf -eq 'direct_url.json' -or $leaf -eq 'record') {
                        Add-FileIfExists $List $file
                    }
                    if ($leaf -match '-setup\.pth$') { $hasSetupPth = $true }
                }
                if ($hasSetupPth) {
                    Add-FileIfExists $List (Join-Path $current '_index.js')
                    Add-FileIfExists $List (Join-Path $current '.bun_ran')
                }
                foreach ($subdir in @([System.IO.Directory]::GetDirectories($current) | Sort-Object)) {
                    $queue.Enqueue($subdir)
                }
            }
            if ($queue.Count -gt 0 -and $visited -ge 10000) { Register-CoverageFailure -Scope 'directory' -Path $venv -Kind 'python-distribution-metadata' -FailureType 'python-directory-limit' -Critical $true }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'TARGETED_PYTHON_ENV_FAILED' -Title 'Targeted Python environment scan failed' -Path $venv -Evidence 'Python environment metadata enumeration failed.' -Recommendation 'Inspect Python environment hooks manually if needed.'
        }
    }
}

function Add-TargetedIdeIocFiles {
    param($List,[string]$RootPath)
    $metadataPaths=New-ArrayList
    Add-ListItem $metadataPaths (Join-Path $RootPath 'package.json')
    foreach ($relativeRoot in @('.vscode/extensions','.vscode-insiders/extensions','.vscode-server/extensions','.cursor/extensions')) {
        $extensionsRoot=Join-Path $RootPath $relativeRoot
        if (-not (Test-SecurityCandidateBoundary -Path $extensionsRoot -Root $RootPath) -or -not (Test-Path -LiteralPath $extensionsRoot -PathType Container)) { continue }
        $inspected=0
        foreach ($directory in @([System.IO.Directory]::GetDirectories($extensionsRoot) | Sort-Object)) {
            if ($inspected -ge 128) { Register-CoverageFailure -Scope 'directory' -Path $extensionsRoot -Kind 'installed-package' -FailureType 'ide-root-limit' -Critical $true; break }
            $inspected++
            if (-not (Test-SecurityCandidateBoundary -Path $directory -Root $RootPath)) { continue }
            Add-ListItem $metadataPaths (Join-Path $directory 'package.json')
        }
    }
    foreach ($metadataPath in @($metadataPaths.ToArray() | Sort-Object -Unique)) {
        if (Test-RunFileBudgetExhausted) { Register-RunFileBudgetReached -CandidatePath $metadataPath; break }
        if (-not (Test-SecurityCandidateBoundary -Path $metadataPath -Root $RootPath) -or -not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { continue }
        $isExtensionPath=Test-IsVsCodeStyleExtensionPath $metadataPath
        # Reserve before selector reads; a normal project package is not promoted to IDE scope by its leaf name.
        $metadataFile=New-Object System.IO.FileInfo($metadataPath)
        if (-not $isExtensionPath -and $metadataFile.Length -gt 131072) { continue }
        if ($isExtensionPath) {
            Add-FileIfExists -List $List -FilePath $metadataPath -Kind 'installed-package' -OwnerCheck 'IdeExtensions' -SelectionReason 'ide-metadata' -BoundaryRoot $RootPath -Critical $true -Selected
        }
        else {
            if (-not (Reserve-ScanFile -FilePath $metadataPath -Targeted)) {
                if (-not $script:Context.queuedFilePaths.ContainsKey($metadataPath.ToLowerInvariant())) { continue }
            }
            else { Add-ListItem $List $metadataFile }
        }
        $read=Read-BoundedSecurityCandidateText -File $metadataFile
        if (-not $read.ok) { if ($isExtensionPath) { Register-SecurityAnalysisLimit -File $metadataFile -FailureType ([string]$read.failureType) }; continue }
        try { $json=$read.text | ConvertFrom-Json -ErrorAction Stop }
        catch { if ($isExtensionPath) { Register-SecurityAnalysisLimit -File $metadataFile -FailureType 'ide-metadata-invalid' }; continue }
        $id=([string](Get-PropertyValue $json 'publisher')+'.'+[string](Get-PropertyValue $json 'name')).ToLowerInvariant()
        if (-not $isExtensionPath -and $id -notin @('microsoftvs.microsoftvs','cosmic-themes.theme-cosmic-nebula')) { continue }
        Register-SecurityCandidateMetadata -Path $metadataPath -Kind 'installed-package' -OwnerCheck 'IdeExtensions' -SelectionReason 'ide-metadata' -BoundaryRoot $RootPath -Critical $true -Selected
        $extensionRoot=Split-Path -Parent $metadataPath
        $relativePaths=New-ArrayList
        if ($id -eq 'microsoftvs.microsoftvs') { Add-ListItem $relativePaths 'out/extension.js' }
        if ($id -eq 'cosmic-themes.theme-cosmic-nebula') { Add-ListItem $relativePaths 'app.js' }
        foreach ($propertyName in @('main','browser')) {
            $value=Get-PropertyValue $json $propertyName
            if ($value -is [string]) { Add-ListItem $relativePaths ([string]$value) }
        }
        $candidateCount=0
        foreach ($relative in @($relativePaths.ToArray() | Select-Object -Unique)) {
            if ($candidateCount -ge 3) { Register-CoverageFailure -Scope 'candidate' -Path $metadataPath -Kind 'runtime-loader' -FailureType 'ide-candidate-limit' -Critical $true; break }
            $resolved=Resolve-NpmPackageEntrypointFile -PackageRoot $extensionRoot -Candidate ([string]$relative)
            if ([string]::IsNullOrWhiteSpace($resolved)) {
                $unsafe=([string]$relative -match '(^|[\\/])\.\.([\\/]|$)|^[\\/]{2}|^[A-Za-z]:|^[a-z]+://')
                $requiredFixed=($id -eq 'microsoftvs.microsoftvs' -and $relative -eq 'out/extension.js') -or ($id -eq 'cosmic-themes.theme-cosmic-nebula' -and $relative -eq 'app.js')
                if ($unsafe -or $requiredFixed) {
                    $failure=if ($unsafe) {'ide-payload-path-rejected'} else {'ide-payload-unavailable'}
                    Register-CoverageFailure -Scope 'candidate' -Path $metadataPath -Kind 'runtime-loader' -FailureType $failure -Critical $true
                }
                continue
            }
            $candidateCount++
            Add-FileIfExists -List $List -FilePath $resolved -Kind 'runtime-loader' -OwnerCheck 'IdeExtensions' -SelectionReason 'ide-payload' -BoundaryRoot $extensionRoot -Critical $true -Selected
        }
    }
}

function Get-CiLocalScriptReferences {
    param([string]$Text,[switch]$Workflow)
    $pattern=if ($Workflow) { '(?m)^\s*(?:-\s*)?(?:run\s*:\s*)?(?:(?:bash|sh|node|python|pwsh|powershell)\s+)?(?<path>\./[A-Za-z0-9._/-]+\.(?:sh|bash|js|mjs|cjs|py|ps1))(?=\s|$)' }
        else { '(?i)\bBASH_ENV\s*=\s*["'']?(?<path>(?:\./)?[A-Za-z0-9._/-]+\.(?:sh|bash|js|mjs|cjs|py|ps1))' }
    return @(Get-BoundedTextRegexMatches -Text $Text -Pattern $pattern -MaximumMatches 65 | ForEach-Object { $_.Groups['path'].Value } | Select-Object -Unique)
}

function Add-TargetedCiBridgeFiles {
    param($List,[string]$RootPath)
    $workflowRoot=Join-Path $RootPath '.github/workflows'
    if (-not (Test-SecurityCandidateBoundary -Path $workflowRoot -Root $RootPath) -or -not (Test-Path -LiteralPath $workflowRoot -PathType Container)) { return }
    $workflows=@([System.IO.Directory]::GetFiles($workflowRoot) | Where-Object {$_ -match '\.ya?ml$'} | Sort-Object)
    $scriptsAdded=0
    $workflowCount=0
    foreach ($workflowPath in $workflows) {
        if ($workflowCount -ge 64) { Register-CoverageFailure -Scope 'directory' -Path $workflowRoot -Kind 'workflow' -FailureType 'ci-workflow-selector-limit' -Critical $true; break }
        $workflowCount++
        Add-FileIfExists -List $List -FilePath $workflowPath -Kind 'workflow' -OwnerCheck 'CiCd' -SelectionReason 'active-workflow' -BoundaryRoot $RootPath -Critical $true -Selected
        if (-not $script:Context.queuedFilePaths.ContainsKey($workflowPath.ToLowerInvariant())) { continue }
        $workflowFile=New-Object System.IO.FileInfo($workflowPath)
        $read=Read-BoundedSecurityCandidateText -File $workflowFile -MaxLines 2048
        if (-not $read.ok) { Register-SecurityAnalysisLimit -File $workflowFile -FailureType ([string]$read.failureType); continue }
        foreach ($relative in @(Get-CiLocalScriptReferences -Text $read.text -Workflow)) {
            if ($scriptsAdded -ge 8) { Register-CoverageFailure -Scope 'candidate' -Path $workflowPath -Kind 'runtime-loader' -FailureType 'ci-script-candidate-limit' -Critical $true; break }
            if ($relative -match '(^|/)\.\.(/|$)|^[A-Za-z]:|^[\\/]|^[a-z]+://') { Register-CoverageFailure -Scope 'candidate' -Path $workflowPath -Kind 'runtime-loader' -FailureType 'ci-script-path-rejected' -Critical $true; continue }
            $scriptPath=Join-Path $RootPath $relative
            Add-FileIfExists -List $List -FilePath $scriptPath -Kind 'runtime-loader' -OwnerCheck 'CiCd' -SelectionReason 'workflow-local-script' -BoundaryRoot $RootPath -Critical $true -Selected
            if (-not $script:Context.queuedFilePaths.ContainsKey(([System.IO.Path]::GetFullPath($scriptPath)).ToLowerInvariant())) { Register-CoverageFailure -Scope 'candidate' -Path $scriptPath -Kind 'runtime-loader' -FailureType 'ci-script-unavailable' -Critical $true; continue }
            $scriptsAdded++
            $scriptFile=New-Object System.IO.FileInfo($scriptPath)
            $scriptRead=Read-BoundedSecurityCandidateText -File $scriptFile
            if (-not $scriptRead.ok) { Register-SecurityAnalysisLimit -File $scriptFile -FailureType ([string]$scriptRead.failureType); continue }
            $writesBashEnv=Test-BoundedTextRegex -Text $scriptRead.text -Pattern '(?im)^\s*(?:echo|printf)\b[^\r\n]*\bBASH_ENV\s*=[^\r\n]*>>?\s*["'']?\$\{?GITHUB_ENV\b'
            if (-not $writesBashEnv) { continue }
            foreach ($bridgeRelative in @(Get-CiLocalScriptReferences -Text $scriptRead.text)) {
                if ($scriptsAdded -ge 8) { Register-SecurityAnalysisLimit -File $scriptFile -FailureType 'ci-script-candidate-limit'; break }
                if ($bridgeRelative -match '(^|/)\.\.(/|$)|^[A-Za-z]:|^[\\/]|^[a-z]+://') { Register-SecurityAnalysisLimit -File $scriptFile -FailureType 'ci-bridge-path-rejected'; continue }
                $bridgePath=Join-Path $RootPath $bridgeRelative
                if (-not (Test-SecurityCandidateBoundary -Path $bridgePath -Root $RootPath)) { Register-SecurityAnalysisLimit -File $scriptFile -FailureType 'ci-bridge-path-rejected'; continue }
                Add-FileIfExists -List $List -FilePath $bridgePath -Kind 'runtime-loader' -OwnerCheck 'CiCd' -SelectionReason 'ci-publish-bridge' -BoundaryRoot $RootPath -Critical $true -Selected
                $bridgeMetadata=Get-SecurityCandidateMetadata $bridgePath
                if (-not [System.IO.File]::Exists($bridgePath)) { Register-SecurityAnalysisLimit -File $scriptFile -FailureType 'ci-bridge-unavailable'; continue }
                if ($null -ne $bridgeMetadata) { $bridgeMetadata.ciBridgeProof=$true }
                $scriptsAdded++
            }
        }
    }
}

function Get-TargetedFileList {
    param([string]$RootPath)
    $result = New-ArrayList
    if ([string]::IsNullOrEmpty($RootPath) -or -not (Test-Path -LiteralPath $RootPath -PathType Container)) {
        return $result
    }

    if (((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts')) -and -not (Test-RunFileBudgetExhausted)) {
        Add-NodeModuleTargetedFiles $result $RootPath
        Add-TargetedPythonFiles $result $RootPath
        Add-FileIfExists $result (Join-Path $RootPath 'vendor\composer\autoload_files.php')
        Add-FileIfExists $result (Join-Path $RootPath 'vendor\composer\installed.json')
    }
    if (Test-CheckEnabled 'HooksAndTasks') {
        Add-FileIfExists $result (Join-Path $RootPath '.git\config')
        $hooksDir = Join-Path $RootPath '.git\hooks'
        if (Test-Path -LiteralPath $hooksDir -PathType Container) {
            try {
                foreach ($hook in [System.IO.Directory]::GetFiles($hooksDir)) {
                    Add-FileIfExists $result $hook
                }
            }
            catch {
                Add-Finding -Severity 'INFO' -Category 'GIT_HOOK_ENUMERATION_FAILED' -Title 'Git hook metadata scan failed' -Path $hooksDir -Evidence 'Git hooks could not be enumerated.' -Recommendation 'Inspect hooks manually if needed.'
            }
        }
    }
    if (Test-CheckEnabled 'IdeExtensions') { Add-TargetedIdeIocFiles -List $result -RootPath $RootPath }
    if (Test-CheckEnabled 'CiCd') { Add-TargetedCiBridgeFiles -List $result -RootPath $RootPath }
    return $result
}

function Test-IsProbablyBinary {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return $false
    }
    $limit = [Math]::Min($Bytes.Length, 4096)
    $nul = 0
    $controls = 0
    for ($i = 0; $i -lt $limit; $i++) {
        $b = $Bytes[$i]
        if ($b -eq 0) { $nul++ }
        if ($b -lt 9 -or ($b -gt 13 -and $b -lt 32)) { $controls++ }
    }
    if (($nul / [double]$limit) -gt 0.01) { return $true }
    if (($controls / [double]$limit) -gt 0.25) { return $true }
    return $false
}

function Test-IsLikelyBinaryFile {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File -or [string]::IsNullOrWhiteSpace($File.Extension)) {
        return $false
    }
    return [bool]$script:LikelyBinaryExtensions.ContainsKey($File.Extension.ToLowerInvariant())
}

function Get-CompressedProbeKind {
    param([byte[]]$Bytes, [string]$Extension)
    if ($null -eq $Bytes -or $Bytes.Length -lt 4) { return '' }
    if (($Bytes[0] -eq 0x28 -and $Bytes[1] -eq 0xB5 -and $Bytes[2] -eq 0x2F -and $Bytes[3] -eq 0xFD) -or
        ($Bytes[0] -ge 0x50 -and $Bytes[0] -le 0x5F -and $Bytes[1] -eq 0x2A -and $Bytes[2] -eq 0x4D -and $Bytes[3] -eq 0x18)) { return 'zstd-signature' }
    if ($Extension -ieq '.nupkg' -and $Bytes[0] -eq 0x50 -and $Bytes[1] -eq 0x4B -and
        (($Bytes[2] -eq 3 -and $Bytes[3] -eq 4) -or ($Bytes[2] -eq 5 -and $Bytes[3] -eq 6))) { return 'zip-container-signature' }
    if ($Extension -ine '.br') { return '' }
    # Brotli has no universal magic. An extension alone never exempts text.
    if (($Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) -or ($Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF)) { return '' }
    $evenZeros=0; $oddZeros=0
    for ($i=0; $i -lt $Bytes.Length; $i++) { if ($Bytes[$i] -eq 0) { if (($i % 2) -eq 0) { $evenZeros++ } else { $oddZeros++ } } }
    if (($oddZeros -gt ($Bytes.Length / 8) -and $evenZeros -lt ($oddZeros / 4)) -or
        ($evenZeros -gt ($Bytes.Length / 8) -and $oddZeros -lt ($evenZeros / 4))) { return '' }
    if (Test-IsProbablyBinary $Bytes) { return 'brotli-extension-binary-probe' }
    try {
        $strict=New-Object System.Text.UTF8Encoding($false,$true)
        # A probe may end in a partial UTF-8 sequence; do not flush that suffix.
        $decoder=$strict.GetDecoder(); $chars=New-Object char[] ($Bytes.Length+1)
        $null=$decoder.GetChars($Bytes,0,$Bytes.Length,$chars,0,$false)
    }
    catch [System.Text.DecoderFallbackException] {
        $asciiCount=0
        foreach ($byte in $Bytes) { if ($byte -in @(9,10,13) -or ($byte -ge 32 -and $byte -le 126)) { $asciiCount++ } }
        $ascii=[Text.Encoding]::ASCII.GetString($Bytes)
        $sourceStart='(?im)^\s*(?:#!|[{\[]|(?:const|let|var|function|import|export|class|param|using|namespace|def|from)\b|\$[A-Za-z_])'
        if (($asciiCount / [double]$Bytes.Length) -lt 0.65 -and -not [regex]::IsMatch($ascii,$sourceStart)) { return 'brotli-extension-binary-probe' }
    }
    return ''
}

function Get-CompressedFileKind {
    param([System.IO.FileInfo]$File)
    if ($File.Extension.ToLowerInvariant() -notin @('.zst','.zstd','.br','.nupkg')) { return '' }
    if (-not (Test-SecurityCandidateBoundary -Path $File.FullName)) { return '' }
    $stream=$null
    try {
        $stream=[IO.File]::Open($File.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $buffer=New-Object byte[] 4096
        $count=$stream.Read($buffer,0,$buffer.Length)
        if ($count -eq 0) { return '' }
        return Get-CompressedProbeKind -Bytes ([byte[]]$buffer[0..($count-1)]) -Extension $File.Extension
    }
    catch { return '' } # The normal bounded reader reports a read failure.
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Get-CoverageCandidateKindForFile {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) { return 'file' }
    $candidateMetadata = Get-SecurityCandidateMetadata $File.FullName
    if ($null -ne $candidateMetadata) { return [string]$candidateMetadata.kind }
    $name = $File.Name.ToLowerInvariant()
    $path = $File.FullName.ToLowerInvariant() -replace '/', '\'
    if ($File.Extension -ieq '.gyp') { return 'native-build-config' }
    if ($name -eq 'metadata' -and $path -match '\\.dist-info\\metadata$|\\[^\\]+\.dist-info\\metadata$') { return 'python-distribution-metadata' }
    if ($name -in @('package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb','pipfile.lock','poetry.lock','uv.lock','composer.lock')) { return 'lockfile' }
    if ($name -eq 'package.json' -and $path -match '\\node_modules\\') { return 'installed-package' }
    if ($name -in @('setup.mjs','math_symbol.js','math_init.js')) { return 'incident-hash' }
    if ($path -match '\\.vscode\\tasks\.json$') { return 'vscode-task' }
    if ($path -match '\\.claude\\settings\.json$') { return 'claude-settings' }
    if ($name -in @('mcp.json','.mcp.json','claude_desktop_config.json') -or (Get-AiPathRole $File.FullName) -in @('active-ai-config','active-ai-instruction')) { return 'ai-config' }
    if ($path -match '\\.github\\workflows\\[^\\]+\.ya?ml$') { return 'workflow' }
    if ($name -eq 'packed-refs' -or $path -match '\\.git\\refs\\') { return 'git-ref' }
    return 'file'
}

function Read-TextFileSafe {
    param([System.IO.FileInfo]$File)
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    try { return (Read-TextFileSafeCore -File $File) }
    finally { Register-ScannerActivityPerformance -Name 'Reading' -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp()-$started) -File $File }
}

function Read-TextFileSafeCore {
    param([System.IO.FileInfo]$File)

    $maxBytes = [int64]$MaxFileSizeMB * 1024 * 1024
    $result = [ordered]@{
        ok = $false
        skipped = $false
        isBinary = $false
        text = ''
        encoding = ''
    }

    try {
        if (-not (Test-SecurityCandidateBoundary -Path $File.FullName)) {
            Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind (Get-CoverageCandidateKindForFile $File) -FailureType 'path-boundary-rejected'
            return $result
        }
        if ($File.Length -gt $maxBytes) {
            Add-Finding -Severity 'INFO' -Category 'FILE_TOO_LARGE_SKIPPED' -Title 'File skipped because it exceeds size limit' -Path $File.FullName -Evidence ("Length exceeds MaxFileSizeMB={0}." -f $MaxFileSizeMB) -Recommendation 'Increase MaxFileSizeMB or inspect manually if this file is important.'
            Add-ScanStat -Name 'filesSkipped' -FilePath $File.FullName
            $result.skipped = $true
            Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind (Get-CoverageCandidateKindForFile -File $File) -FailureType 'too-large'
            return $result
        }

        $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
        $encodingProbeLength = [Math]::Min($bytes.Length, $script:EncodingProbeMaxBytes)
        if ($encodingProbeLength -gt [int]$script:Context.scanStats.maxEncodingProbeBytesObserved) {
            $script:Context.scanStats.maxEncodingProbeBytesObserved = [int]$encodingProbeLength
        }
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $enc = New-Object System.Text.UTF8Encoding($true, $true)
            $result.text = $enc.GetString($bytes, 3, $bytes.Length - 3)
            $result.encoding = 'utf-8-bom'
            $result.ok = $true
            return $result
        }
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $result.text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
            $result.encoding = 'utf-16le-bom'
            $result.ok = $true
            return $result
        }
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            $result.text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
            $result.encoding = 'utf-16be-bom'
            $result.ok = $true
            return $result
        }

        $evenZeros = 0
        $oddZeros = 0
        for ($i = 0; $i -lt $encodingProbeLength; $i++) {
            if ($bytes[$i] -eq 0) {
                if (($i % 2) -eq 0) { $evenZeros++ } else { $oddZeros++ }
            }
        }
        if ($encodingProbeLength -gt 4 -and $oddZeros -gt ($encodingProbeLength / 8) -and $evenZeros -lt ($oddZeros / 4)) {
            $result.text = [System.Text.Encoding]::Unicode.GetString($bytes)
            $result.encoding = 'utf-16le-heuristic'
            $result.ok = $true
            return $result
        }
        if ($encodingProbeLength -gt 4 -and $evenZeros -gt ($encodingProbeLength / 8) -and $oddZeros -lt ($evenZeros / 4)) {
            $result.text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes)
            $result.encoding = 'utf-16be-heuristic'
            $result.ok = $true
            return $result
        }
        if (Test-IsProbablyBinary $bytes) {
            Add-ScanStat -Name 'filesSkipped' -FilePath $File.FullName
            $result.skipped = $true
            $result.isBinary = $true
            if ($File.Name.ToLowerInvariant() -eq 'bun.lockb') {
                Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'unsupported-binary-lockfile' -Critical $true
            }
            return $result
        }

        try {
            $strict = New-Object System.Text.UTF8Encoding($false, $true)
            $result.text = $strict.GetString($bytes)
            $result.encoding = 'utf-8-strict'
            $result.ok = $true
            return $result
        }
        catch {
            $result.text = [System.Text.Encoding]::Default.GetString($bytes)
            $result.encoding = 'default-fallback'
            $result.ok = $true
            if (Test-IsNpmCacheBlobPath $File.FullName -or (Test-IsDependencyMetadataPath $File.FullName)) {
                Add-ScanStat -Name 'encodingFallbackAggregated'
            }
            else {
                Add-Finding -Severity 'INFO' -Category 'TEXT_DEFAULT_ENCODING_USED' -Title 'File decoded with system default encoding' -Path $File.FullName -Evidence 'Strict UTF-8 and UTF-16 heuristics did not match.' -Recommendation 'Inspect manually if invisible Unicode detection is important for this file.'
            }
            return $result
        }
    }
    catch {
        $failure = Get-FileSystemFailureDetails -Exception $_.Exception
        $category = switch ($failure.failureType) { 'access-denied' { 'ACCESS_DENIED' }; 'path-too-long' { 'PATH_TOO_LONG' }; 'decode-error' { 'TEXT_DECODE_FAILED' }; default { 'FILE_READ_FAILED' } }
        Add-Finding -Severity 'INFO' -Category $category -Title 'File text could not be read' -Path $File.FullName -Evidence ("failureType={0}; exceptionType={1}; hresult={2}; target contents and exception messages omitted." -f $failure.failureType,$failure.exceptionType,$failure.hresult) -Recommendation 'Review the grouped reason; close a conflicting writer or obtain read access and rerun the affected path when appropriate.'
        Add-ScanStat -Name 'filesSkipped' -FilePath $File.FullName
        $result.skipped = $true
        Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind (Get-CoverageCandidateKindForFile -File $File) -FailureType $failure.failureType -Exception $_.Exception
        return $result
    }
}

function Get-LineNumberForIndex {
    param([string]$Text, [int]$Index)
    if ([string]::IsNullOrEmpty($Text) -or $Index -le 0) {
        return 1
    }
    $line = 1
    $max = [Math]::Min($Index, $Text.Length)
    $chunkSize = 65536
    for ($offset = 0; $offset -lt $max; $offset += $chunkSize) {
        $length = [Math]::Min($chunkSize, $max - $offset)
        $chunk = $Text.Substring($offset, $length)
        $line += $chunk.Length - $chunk.Replace("`n", [string]::Empty).Length
    }
    return $line
}

function Test-BoundedTextRegex {
    param([string]$Text, [string]$Pattern)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Pattern)) {
        return $false
    }
    return (Get-CachedBoundedRegex $Pattern).IsMatch($Text)
}

function Get-CachedBoundedRegex {
    param([string]$Pattern)
    if ($null -eq $script:BoundedRegexCache) { $script:BoundedRegexCache=@{} }
    $key=([string]$script:RegexMatchTimeoutSeconds)+'|'+[Globalization.CultureInfo]::CurrentCulture.Name+'|'+$Pattern
    if (-not $script:BoundedRegexCache.ContainsKey($key)) {
        if ($script:BoundedRegexCache.Count -ge 256) { $script:BoundedRegexCache.Clear() }
        $script:BoundedRegexCache[$key]=New-Object Text.RegularExpressions.Regex(
            $Pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
    }
    return $script:BoundedRegexCache[$key]
}

function Get-BoundedTextRegexMatch {
    param([string]$Text, [string]$Pattern)
    return (Get-CachedBoundedRegex $Pattern).Match($Text)
}

function Get-BoundedTextRegexMatches {
    param([string]$Text, [string]$Pattern, [int]$MaximumMatches = [int]::MaxValue)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Pattern)) {
        return @()
    }
    if ($MaximumMatches -lt 1) { return @() }
    $boundedRegex = Get-CachedBoundedRegex $Pattern
    $matches = New-ArrayList
    $match = $boundedRegex.Match($Text)
    while ($match.Success -and $matches.Count -lt $MaximumMatches) {
        Add-ListItem $matches $match
        $match = $match.NextMatch()
    }
    return @($matches.ToArray())
}

function Get-FirstMatchLine {
    param([string]$Text, [string]$Pattern)
    $match = Get-BoundedTextRegexMatch -Text $Text -Pattern $Pattern
    if ($match.Success) {
        return (Get-LineNumberForIndex -Text $Text -Index $match.Index)
    }
    return $null
}

function Get-ExternalExecutionPatternDefinitions {
    return @(
        [pscustomobject]@{
            Id = 'fetch-command'
            Pattern = '(?is)(?<![\w.-])(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b.{0,120}(\||;|&&).{0,120}\b(bash|sh|powershell|pwsh|iex|Invoke-Expression|cmd\.exe)\b'
            SourceGroup = 1
            SinkGroup = 3
        },
        [pscustomobject]@{
            Id = 'remote-url'
            Pattern = '(?is)(https?://|raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com).{0,160}(\biex\b|Invoke-Expression|(?<![.\w])eval\s*\(|(?<![.\w])exec\s*\(|\b(?:bash|sh|powershell|pwsh)\b\s+(?:-[^\r\n]*\s)?(?:-c|-Command)\b)'
            SourceGroup = 1
            SinkGroup = 2
        },
        [pscustomobject]@{
            Id = 'decode-execute'
            Pattern = '(?is)(FromBase64String|base64\s+-d|certutil\s+-decode).{0,120}(iex|Invoke-Expression|bash|sh|powershell|pwsh|eval|exec)'
            SourceGroup = 1
            SinkGroup = 2
        }
    )
}

function Get-ExternalExecutionPatternMatches {
    param([string]$Text, [int]$MaximumMatchesPerPattern = 64)
    if ([string]::IsNullOrEmpty($Text)) { return @() }

    $results = New-ArrayList
    $definitionOrder = 0
    foreach ($definition in @(Get-ExternalExecutionPatternDefinitions)) {
        $sentinelLimit = if ($MaximumMatchesPerPattern -lt [int]::MaxValue) { $MaximumMatchesPerPattern + 1 } else { [int]::MaxValue }
        $definitionMatches = @(Get-BoundedTextRegexMatches -Text $Text -Pattern ([string]$definition.Pattern) -MaximumMatches $sentinelLimit)
        $limitExceeded = $definitionMatches.Count -gt $MaximumMatchesPerPattern
        foreach ($match in @($definitionMatches | Select-Object -First $MaximumMatchesPerPattern)) {
            Add-ListItem $results ([pscustomobject]@{
                Definition = $definition
                DefinitionOrder = $definitionOrder
                LimitExceeded = $limitExceeded
                Match = $match
            })
        }
        $definitionOrder++
    }
    return @($results.ToArray() | Sort-Object @{ Expression = { [int]$_.Match.Index } }, @{ Expression = { [int]$_.DefinitionOrder } })
}

function Get-ExternalExecutionPatternMatch {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    foreach ($definition in @(Get-ExternalExecutionPatternDefinitions)) {
        $match = Get-BoundedTextRegexMatch -Text $Text -Pattern ([string]$definition.Pattern)
        if ($match.Success) {
            return $match
        }
    }
    return $null
}

function Test-ExternalExecutionPattern {
    param([string]$Text)
    return ($null -ne (Get-ExternalExecutionPatternMatch -Text $Text))
}

function Get-ExternalExecutionPatternLine {
    param([string]$Text)
    $match = Get-ExternalExecutionPatternMatch -Text $Text
    if ($null -eq $match) { return $null }
    return (Get-LineNumberForIndex -Text $Text -Index $match.Index)
}

function Get-PowerShellLexicalScopeAst {
    param($Node, $RootAst)
    $current = $Node
    while ($null -ne $current) {
        if ($current -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            return $current
        }
        $current = $current.Parent
    }
    return $RootAst
}

function Test-PowerShellAstNodeInScope {
    param($Node, $ScopeAst, $RootAst)
    if ($null -eq $Node -or $null -eq $ScopeAst -or $null -eq $RootAst) { return $false }
    $nodeScope = Get-PowerShellLexicalScopeAst -Node $Node -RootAst $RootAst
    return [object]::ReferenceEquals($nodeScope, $ScopeAst)
}

function Test-PowerShellPassiveRegexReachability {
    param(
        $RootAst,
        $InitialScope,
        [string]$ContainerName,
        [object[]]$AllVariables,
        [object[]]$AllCommands,
        [object[]]$AllFunctionDefinitions,
        [object[]]$AllMemberExpressions,
        [object[]]$AllInvokeMemberExpressions
    )

    # These commands have known non-dynamic-scope semantics. Their own raw fetch/execute
    # matches are still classified independently; allowing them here only prevents an
    # unrelated command from invalidating a proven passive Pattern table in the same scope.
    $safeBuiltinCommands = @(
        'Compare-Object','ConvertFrom-Csv','ConvertFrom-Json','ConvertTo-Csv','ConvertTo-Json',
        'Join-Path','New-Object','Out-Null','Split-Path','Write-Debug','Write-Error',
        'Write-Host','Write-Information','Write-Output','Write-Verbose','Write-Warning',
        'Invoke-WebRequest','iwr','Invoke-RestMethod','irm','Invoke-Expression','iex','Start-Job',
        'curl','curl.exe','wget','wget.exe','bash','sh','powershell','powershell.exe','pwsh','pwsh.exe','cmd','cmd.exe'
    )
    $reflectionCommands = @('Get-Variable','gv','New-Variable','nv','Set-Variable','sv','Remove-Variable','rv')
    $unsafeMemberNames = @(
        'GetVariable','GetVariableValue','SetVariable','SetVariableValue','Invoke','InvokeReturnAsIs',
        'InvokeScript','InvokeWithContext','PSVariable'
    )
    $executionSinkCommands = @(
        'Invoke-Expression','iex','Invoke-Command','icm','Start-Job','Start-Process','saps',
        'bash','sh','powershell','powershell.exe','pwsh','pwsh.exe','cmd','cmd.exe'
    )
    $scopeQueue = New-ArrayList
    $visitedScopes = New-ArrayList
    $reachableReadsOwnSource = $false
    $reachableHasExecutionSink = $false
    Add-ListItem $scopeQueue $InitialScope

    while ($scopeQueue.Count -gt 0) {
        $scopeAst = $scopeQueue[0]
        $scopeQueue.RemoveAt(0)
        $alreadyVisited = $false
        foreach ($visitedScope in @($visitedScopes.ToArray())) {
            if ([object]::ReferenceEquals($visitedScope, $scopeAst)) {
                $alreadyVisited = $true
                break
            }
        }
        if ($alreadyVisited) { continue }
        Add-ListItem $visitedScopes $scopeAst

        $scopeVariables = @($AllVariables | Where-Object {
            Test-PowerShellAstNodeInScope -Node $_ -ScopeAst $scopeAst -RootAst $RootAst
        })
        if (-not [object]::ReferenceEquals($scopeAst, $InitialScope) -and
            @($scopeVariables | Where-Object { [string]$_.VariablePath.UserPath -ieq $ContainerName }).Count -gt 0) {
            return $false
        }
        if (@($scopeVariables | Where-Object { [string]$_.VariablePath.UserPath -ieq 'ExecutionContext' }).Count -gt 0) {
            return $false
        }
        if (@($scopeVariables | Where-Object {
            [string]$_.VariablePath.UserPath -match '^(?i:variable|function|alias):'
        }).Count -gt 0) {
            return $false
        }

        $scopeCommands = @($AllCommands | Where-Object {
            Test-PowerShellAstNodeInScope -Node $_ -ScopeAst $scopeAst -RootAst $RootAst
        })
        $readsOwnSource = @($scopeVariables | Where-Object {
            [string]$_.VariablePath.UserPath -in @('PSCommandPath','PSScriptRoot','MyInvocation')
        }).Count -gt 0
        $hasExecutionSink = @($scopeCommands | Where-Object {
            [string]$_.GetCommandName() -in $executionSinkCommands
        }).Count -gt 0
        if ($readsOwnSource) { $reachableReadsOwnSource = $true }
        if ($hasExecutionSink) { $reachableHasExecutionSink = $true }
        if ($reachableReadsOwnSource -and $reachableHasExecutionSink) {
            return $false
        }

        foreach ($memberAst in @($AllMemberExpressions | Where-Object {
            Test-PowerShellAstNodeInScope -Node $_ -ScopeAst $scopeAst -RootAst $RootAst
        })) {
            if ([string]$memberAst.Member.Value -in $unsafeMemberNames) {
                return $false
            }
        }
        foreach ($invokeMemberAst in @($AllInvokeMemberExpressions | Where-Object {
            Test-PowerShellAstNodeInScope -Node $_ -ScopeAst $scopeAst -RootAst $RootAst
        })) {
            $memberName = [string]$invokeMemberAst.Member.Value
            if ($memberName -in $unsafeMemberNames) {
                return $false
            }
            if ($memberName -ieq 'Create' -and [string]$invokeMemberAst.Expression.Extent.Text -match '(?i)scriptblock') {
                return $false
            }
        }

        foreach ($commandAst in $scopeCommands) {
            if ([string]$commandAst.Extent.Text -match '(?i)(?:^|[\s''"])(?:variable|function|alias):') {
                return $false
            }
            if ([string]$commandAst.InvocationOperator -notin @('','Unknown')) {
                return $false
            }
            $commandName = [string]$commandAst.GetCommandName()
            if ([string]::IsNullOrWhiteSpace($commandName)) {
                return $false
            }
            if ($commandName -in $reflectionCommands -or $commandName -in @('Set-Alias','sal','New-Alias','nal','Import-Module','ipmo')) {
                return $false
            }

            $localTargets = @($AllFunctionDefinitions | Where-Object { [string]$_.Name -ieq $commandName })
            if ($localTargets.Count -gt 0) {
                if ($localTargets.Count -ne 1) {
                    return $false
                }
                Add-ListItem $scopeQueue $localTargets[0]
                continue
            }
            if ($commandName -notin $safeBuiltinCommands) {
                return $false
            }
        }
    }
    return $true
}

function Test-RegexGroupInsideAnySpan {
    param($Group, [object[]]$Spans)
    if ($null -eq $Group -or -not $Group.Success -or $Group.Length -lt 1) { return $false }
    foreach ($span in @($Spans)) {
        if ([int]$Group.Index -ge [int]$span.Start -and
            ([int]$Group.Index + [int]$Group.Length) -le [int]$span.End) {
            return $true
        }
    }
    return $false
}

function Get-PowerShellExternalExecutionAssessment {
    param([string]$Text, [object[]]$PassiveSpans = @())
    $rawMatches = @(Get-ExternalExecutionPatternMatches -Text $Text)
    if ($rawMatches.Count -eq 0) {
        return [pscustomobject]@{ Disposition = 'None'; Match = $null; Line = $null; Reason = 'no-pattern' }
    }

    $fallbackMatch = $rawMatches[0].Match
    if (@($rawMatches | Where-Object { [bool]$_.LimitExceeded }).Count -gt 0) {
        return [pscustomobject]@{
            Disposition = 'Ambiguous'
            Match = $fallbackMatch
            Line = Get-LineNumberForIndex -Text $Text -Index $fallbackMatch.Index
            Reason = 'external-pattern-match-limit'
        }
    }
    $tokens = $null
    $parseErrors = $null
    try {
        if ([object]::ReferenceEquals($script:RegexDataOriginalText,$Text) -and $null -ne $script:RegexDataAst) {
            $ast=$script:RegexDataAst
            $parseErrors=@()
        }
        else {
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$parseErrors)
        }
    }
    catch {
        return [pscustomobject]@{
            Disposition = 'Ambiguous'
            Match = $fallbackMatch
            Line = Get-LineNumberForIndex -Text $Text -Index $fallbackMatch.Index
            Reason = 'powershell-parser-exception'
        }
    }
    if ($null -eq $ast -or @($parseErrors).Count -gt 0) {
        return [pscustomobject]@{
            Disposition = 'Ambiguous'
            Match = $fallbackMatch
            Line = Get-LineNumberForIndex -Text $Text -Index $fallbackMatch.Index
            Reason = 'powershell-parse-error'
        }
    }

    $allVariables = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))
    $allAssignments = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
    $allForEachStatements = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ForEachStatementAst] }, $true))
    $allCommands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    $allFunctionDefinitions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    $allMemberExpressions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.MemberExpressionAst] }, $true))
    $allInvokeMemberExpressions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true))
    $candidates = New-ArrayList

    foreach ($hashtableAst in @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true))) {
        foreach ($pair in @($hashtableAst.KeyValuePairs)) {
            $keyAst = $pair.Item1
            $valueAst = $pair.Item2
            if ($keyAst -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or [string]$keyAst.Value -ine 'Pattern') {
                continue
            }

            $literalNodes = @($valueAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
            }, $true))
            if ($literalNodes.Count -ne 1) { continue }
            $literalAst = $literalNodes[0]
            if ($literalAst.StringConstantType -notin @(
                [System.Management.Automation.Language.StringConstantType]::SingleQuoted,
                [System.Management.Automation.Language.StringConstantType]::DoubleQuoted
            )) { continue }
            if ($literalAst.Extent.StartOffset -ne $valueAst.Extent.StartOffset -or $literalAst.Extent.EndOffset -ne $valueAst.Extent.EndOffset) {
                continue
            }

            $assignmentAst = $hashtableAst.Parent
            while ($null -ne $assignmentAst -and $assignmentAst -isnot [System.Management.Automation.Language.AssignmentStatementAst]) {
                $assignmentAst = $assignmentAst.Parent
            }
            if ($null -eq $assignmentAst -or $assignmentAst.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) {
                continue
            }
            $containerName = [string]$assignmentAst.Left.VariablePath.UserPath
            if ([string]::IsNullOrWhiteSpace($containerName) -or $containerName.Contains(':')) {
                continue
            }
            $unsafeAssignmentExpression = @($assignmentAst.Right.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -or
                $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
                $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
                $node -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
                $node -is [System.Management.Automation.Language.VariableExpressionAst]
            }, $true)).Count -gt 0
            if ($unsafeAssignmentExpression) { continue }

            $allowedItemMembers = New-ArrayList
            foreach ($tablePair in @($hashtableAst.KeyValuePairs)) {
                if ($tablePair.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $tableKey = [string]$tablePair.Item1.Value
                    if ($tableKey -ine 'Pattern' -and $tableKey -notin @('Values','Keys','Item','Count','Length','PSObject')) {
                        Add-ListItem $allowedItemMembers $tableKey
                    }
                }
            }
            Add-ListItem $candidates ([pscustomobject]@{
                ContainerName = $containerName
                Assignment = $assignmentAst
                Scope = Get-PowerShellLexicalScopeAst -Node $assignmentAst -RootAst $ast
                Literal = $literalAst
                AllowedItemMembers = @($allowedItemMembers.ToArray())
            })
        }
    }

    $safeSpans = New-ArrayList
    # Only caller-proven spans are added; syntax is always parsed from the
    # original source, never from the blanked text used by lexical checks.
    foreach ($span in $PassiveSpans) { Add-ListItem $safeSpans $span }
    $processedAssignments = New-ArrayList
    foreach ($candidateSeed in @($candidates.ToArray())) {
        $alreadyProcessed = $false
        foreach ($processedAssignment in @($processedAssignments.ToArray())) {
            if ([object]::ReferenceEquals($processedAssignment, $candidateSeed.Assignment)) {
                $alreadyProcessed = $true
                break
            }
        }
        if ($alreadyProcessed) { continue }
        Add-ListItem $processedAssignments $candidateSeed.Assignment

        $candidateAssignment = $candidateSeed.Assignment
        $candidateScope = $candidateSeed.Scope
        $containerName = [string]$candidateSeed.ContainerName
        $containerCandidates = @($candidates | Where-Object { [object]::ReferenceEquals($_.Assignment, $candidateAssignment) })
        $scopeVariables = @($allVariables | Where-Object {
            Test-PowerShellAstNodeInScope -Node $_ -ScopeAst $candidateScope -RootAst $ast
        })
        $scopeAssignments = @($allAssignments | Where-Object {
            Test-PowerShellAstNodeInScope -Node $_ -ScopeAst $candidateScope -RootAst $ast
        })
        $containerAssignments = @($scopeAssignments | Where-Object {
            $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            [string]$_.Left.VariablePath.UserPath -ieq $containerName
        })
        if ($containerAssignments.Count -ne 1 -or -not [object]::ReferenceEquals($containerAssignments[0], $candidateAssignment)) {
            continue
        }
        if (-not (Test-PowerShellPassiveRegexReachability -RootAst $ast -InitialScope $candidateScope -ContainerName $containerName -AllVariables $allVariables -AllCommands $allCommands -AllFunctionDefinitions $allFunctionDefinitions -AllMemberExpressions $allMemberExpressions -AllInvokeMemberExpressions $allInvokeMemberExpressions)) {
            continue
        }

        $consumerLoops = New-ArrayList
        foreach ($forEachAst in @($allForEachStatements | Where-Object {
            Test-PowerShellAstNodeInScope -Node $_ -ScopeAst $candidateScope -RootAst $ast
        })) {
            $conditionContainerUses = @($scopeVariables | Where-Object {
                [string]$_.VariablePath.UserPath -ieq $containerName -and
                $_.Extent.StartOffset -ge $forEachAst.Condition.Extent.StartOffset -and
                $_.Extent.EndOffset -le $forEachAst.Condition.Extent.EndOffset
            })
            if ($conditionContainerUses.Count -eq 1 -and
                $forEachAst.Condition.Extent.Text.Trim() -eq $conditionContainerUses[0].Extent.Text) {
                Add-ListItem $consumerLoops $forEachAst
            }
        }

        $containerSafe = $true
        $patternConsumerCount = 0
        foreach ($variableAst in @($scopeVariables | Where-Object { [string]$_.VariablePath.UserPath -ieq $containerName })) {
            if ([object]::ReferenceEquals($variableAst, $candidateAssignment.Left)) { continue }

            $usedByConsumerLoop = $false
            foreach ($consumerLoop in @($consumerLoops.ToArray())) {
                if ($variableAst.Extent.StartOffset -ge $consumerLoop.Condition.Extent.StartOffset -and
                    $variableAst.Extent.EndOffset -le $consumerLoop.Condition.Extent.EndOffset) {
                    $usedByConsumerLoop = $true
                    break
                }
            }
            if ($usedByConsumerLoop) { continue }

            if ($variableAst.Parent -is [System.Management.Automation.Language.MemberExpressionAst] -and
                [object]::ReferenceEquals($variableAst.Parent.Expression, $variableAst)) {
                $memberName = [string]$variableAst.Parent.Member.Value
                if ($memberName -in @('Count','Length')) { continue }
                if ($memberName -ieq 'Pattern' -and $variableAst.Parent.Parent -is [System.Management.Automation.Language.BinaryExpressionAst]) {
                    $binaryAst = $variableAst.Parent.Parent
                    if ([object]::ReferenceEquals($binaryAst.Right, $variableAst.Parent) -and
                        [string]$binaryAst.Operator -in @('Imatch','Cmatch','Inotmatch','Cnotmatch')) {
                        $patternConsumerCount++
                        continue
                    }
                }
            }
            $containerSafe = $false
            break
        }
        if (-not $containerSafe) { continue }

        $allowedItemMembers = @($containerCandidates | ForEach-Object { @($_.AllowedItemMembers) } | Sort-Object -Unique)
        foreach ($itemName in @($consumerLoops.ToArray() | ForEach-Object { [string]$_.Variable.VariablePath.UserPath } | Sort-Object -Unique)) {
            foreach ($variableAst in @($scopeVariables | Where-Object { [string]$_.VariablePath.UserPath -ieq $itemName })) {
                $isLoopVariable = @($consumerLoops.ToArray() | Where-Object {
                    [object]::ReferenceEquals($variableAst, $_.Variable)
                }).Count -gt 0
                if ($isLoopVariable) { continue }

                $containingLoops = @($consumerLoops.ToArray() | Where-Object {
                    [string]$_.Variable.VariablePath.UserPath -ieq $itemName -and
                    $variableAst.Extent.StartOffset -ge $_.Body.Extent.StartOffset -and
                    $variableAst.Extent.EndOffset -le $_.Body.Extent.EndOffset
                })
                if ($containingLoops.Count -ne 1) {
                    $containerSafe = $false
                    break
                }
                if ($variableAst.Parent -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
                    $containerSafe = $false
                    break
                }
                if ($variableAst.Parent -isnot [System.Management.Automation.Language.MemberExpressionAst] -or
                    -not [object]::ReferenceEquals($variableAst.Parent.Expression, $variableAst)) {
                    $containerSafe = $false
                    break
                }

                $memberName = [string]$variableAst.Parent.Member.Value
                if ($memberName -ine 'Pattern') {
                    if ($memberName -in $allowedItemMembers) { continue }
                    $containerSafe = $false
                    break
                }
                if ($variableAst.Parent.Parent -isnot [System.Management.Automation.Language.BinaryExpressionAst]) {
                    $containerSafe = $false
                    break
                }
                $binaryAst = $variableAst.Parent.Parent
                if (-not [object]::ReferenceEquals($binaryAst.Right, $variableAst.Parent) -or
                    [string]$binaryAst.Operator -notin @('Imatch','Cmatch','Inotmatch','Cnotmatch')) {
                    $containerSafe = $false
                    break
                }
                $patternConsumerCount++
            }
            if (-not $containerSafe) { break }
        }

        if ($containerSafe -and $patternConsumerCount -gt 0) {
            foreach ($candidate in $containerCandidates) {
                Add-ListItem $safeSpans ([pscustomobject]@{
                    Start = [int]$candidate.Literal.Extent.StartOffset
                    End = [int]$candidate.Literal.Extent.EndOffset
                })
            }
        }
    }

    $firstActive = $null
    $firstAmbiguous = $null
    foreach ($rawMatchEntry in $rawMatches) {
        $sourceGroup = $rawMatchEntry.Match.Groups[[int]$rawMatchEntry.Definition.SourceGroup]
        $sinkGroup = $rawMatchEntry.Match.Groups[[int]$rawMatchEntry.Definition.SinkGroup]
        $sourceIsPassive = Test-RegexGroupInsideAnySpan -Group $sourceGroup -Spans @($safeSpans.ToArray())
        $sinkIsPassive = Test-RegexGroupInsideAnySpan -Group $sinkGroup -Spans @($safeSpans.ToArray())
        if ($sourceIsPassive -and $sinkIsPassive) { continue }
        if ($sourceIsPassive -xor $sinkIsPassive) {
            if ($null -eq $firstAmbiguous) { $firstAmbiguous = $rawMatchEntry }
            continue
        }
        if ($null -eq $firstActive) { $firstActive = $rawMatchEntry }
    }

    if ($null -ne $firstActive) {
        return [pscustomobject]@{
            Disposition = 'Active'
            Match = $firstActive.Match
            Line = Get-LineNumberForIndex -Text $Text -Index $firstActive.Match.Index
            Reason = 'executable-or-unproven-data-flow'
        }
    }
    if ($null -ne $firstAmbiguous) {
        return [pscustomobject]@{
            Disposition = 'Ambiguous'
            Match = $firstAmbiguous.Match
            Line = Get-LineNumberForIndex -Text $Text -Index $firstAmbiguous.Match.Index
            Reason = 'mixed-passive-and-unproven-anchors'
        }
    }
    return [pscustomobject]@{
        Disposition = 'PassiveRegex'
        Match = $fallbackMatch
        Line = Get-LineNumberForIndex -Text $Text -Index $fallbackMatch.Index
        Reason = 'static-pattern-values-used-only-by-regex-match'
    }
}

function Test-PowerShellRegexDataUse {
    param($Variable, $RootAst, [object[]]$Functions, [string[]]$Visited = @())
    $parent=$Variable.Parent
    if ($parent -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        [string]$parent.Operator -in @('Imatch','Cmatch','Inotmatch','Cnotmatch')) { return $true }
    if ($parent -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $parent.Static -and $parent.Expression.Extent.Text -ieq '[string]' -and
        [string]$parent.Member.Value -in @('IsNullOrEmpty','IsNullOrWhiteSpace') -and $parent.Arguments.Count -eq 1) { return $true }
    if ($parent -isnot [System.Management.Automation.Language.CommandAst] -or
        [string]$parent.InvocationOperator -notin @('','Unknown')) { return $false }
    $elements=@($parent.CommandElements)
    $position=-1
    for ($i=1;$i -lt $elements.Count;$i++) { if ([object]::ReferenceEquals($elements[$i],$Variable)) { $position=$i; break } }
    if ($position -lt 2 -or $elements[$position-1] -isnot [System.Management.Automation.Language.CommandParameterAst]) { return $false }
    $parameter=[string]$elements[$position-1].ParameterName
    $name=[string]$parent.GetCommandName()
    $targets=@($Functions | Where-Object { $_.Name -ieq $name })
    if ($targets.Count -ne 1 -or $Visited.Count -ge 8 -or $Visited -contains $name) { return $false }
    $target=$targets[0]
    $parameters=@($target.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ieq $parameter })
    if ($parameters.Count -ne 1 -or $null -ne $parameters[0].DefaultValue) { return $false }
    if (@($parameters[0].Attributes | Where-Object { $_.TypeName.FullName -notin @('string','System.String') }).Count -gt 0) { return $false }
    $uses=@($target.FindAll({param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst]},$true))
    if (@($uses | Where-Object { $_.VariablePath.UserPath -in @('Matches','PSBoundParameters','MyInvocation','args','input','PSCommandPath','PSScriptRoot') }).Count -gt 0) { return $false }
    $count=0
    foreach ($use in @($uses | Where-Object { $_.VariablePath.UserPath -ieq $parameter })) {
        if ([object]::ReferenceEquals($use,$parameters[0].Name)) { continue }
        if (-not (Test-PowerShellAstNodeInScope -Node $use -ScopeAst $target -RootAst $RootAst)) { return $false }
        if (-not (Test-PowerShellRegexDataUse -Variable $use -RootAst $RootAst -Functions $Functions -Visited @($Visited+$name))) { return $false }
        $count++
    }
    return ($count -gt 0)
}

function Test-PowerShellRegexClassifierScope {
    param($ScopeAst, $RootAst, [object[]]$Commands, [object[]]$InvokeMembers, [object[]]$Variables)
    # Ordinary patterns can also select real credentials for later transfer.
    # Mask them only in a classifier scope with no I/O, execution, unknown calls,
    # reflective access or capture consumers. Here-string proof stays separate.
    foreach ($variable in $Variables) {
        if ((Test-PowerShellAstNodeInScope -Node $variable -ScopeAst $ScopeAst -RootAst $RootAst) -and
            $variable.VariablePath.UserPath -in @('Matches','PSBoundParameters','MyInvocation','args','input','PSCommandPath','PSScriptRoot','ExecutionContext')) { return $false }
    }
    foreach ($command in $Commands) {
        if ((Test-PowerShellAstNodeInScope -Node $command -ScopeAst $ScopeAst -RootAst $RootAst) -and
            ($command.GetCommandName() -notin @('Out-Null','Write-Verbose','Write-Debug') -or [string]$command.InvocationOperator -notin @('','Unknown'))) { return $false }
    }
    foreach ($member in $InvokeMembers) {
        if (-not (Test-PowerShellAstNodeInScope -Node $member -ScopeAst $ScopeAst -RootAst $RootAst)) { continue }
        if ($member.Static -and $member.Expression.Extent.Text -in @('[string]','[System.String]') -and [string]$member.Member.Value -in @('IsNullOrEmpty','IsNullOrWhiteSpace')) { continue }
        if ($member.Static -and $member.Expression.Extent.Text -in @('[regex]','[System.Text.RegularExpressions.Regex]') -and [string]$member.Member.Value -in @('IsMatch','Match','Matches')) { continue }
        return $false
    }
    return $true
}

function Get-PowerShellRegexDataProjection {
    param([string]$Text)
    $unchanged=[ordered]@{text=$Text; spans=@()}
    if ([string]::IsNullOrEmpty($Text) -or $Text.Length -gt 262144 -or -not $Text.Contains("'")) { return $unchanged }
    if ([object]::ReferenceEquals($script:RegexDataOriginalText,$Text)) { return $script:RegexDataProjection }
    $tokens=$null; $errors=$null; $offset=0
    $ast=[System.Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -gt 0) {
        # Hybrid BAT files can contain a standalone marker followed by a valid
        # PowerShell payload. Parse that syntax, while leaving all prefix bytes
        # and all unproven payload bytes in normal detection.
        $markers=@(Get-BoundedTextRegexMatches -Text $Text -Pattern '(?m)^__[A-Za-z0-9_]+__[ \t]*\r?\n(?=(?:\[CmdletBinding\(\)\]\s*)?param\s*\()' -MaximumMatches 2)
        if ($markers.Count -ne 1) { return $unchanged }
        $offset=$markers[0].Index+$markers[0].Length
        $ast=[System.Management.Automation.Language.Parser]::ParseInput($Text.Substring($offset),[ref]$tokens,[ref]$errors)
    }
    if ($null -eq $ast -or @($errors).Count -gt 0) { return $unchanged }
    $variables=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst]},$true))
    $assignments=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]},$true))
    $functions=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true))
    $commands=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true))
    $members=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst]},$true))
    $invokeMembers=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]},$true))
    $loops=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst]},$true))
    if ($variables.Count -gt 6000 -or $assignments.Count -gt 2000) { return $unchanged }
    if (@($commands | Where-Object {
        $_.GetCommandName() -in @('Set-Alias','New-Alias','Import-Module','Set-Variable','New-Variable','Get-Variable') -or
        ($_.GetCommandName() -in @('Set-Item','New-Item') -and $_.Extent.Text -match '(?i)function:|alias:|variable:')
    }).Count -gt 0) { return $unchanged }
    $spans=New-ArrayList
    $classifierScopes=@{}
    $scopeVariableCache=@{}
    $scopeCommandCache=@{}
    $scopeInvokeCache=@{}
    $assignmentsByName=@{}
    $qualifiedNames=@{}
    foreach ($variable in $variables) {
        $variableName=[string]$variable.VariablePath.UserPath
        if ($variableName.Contains(':')) { $qualifiedNames[($variableName -split ':')[-1]]=$true }
        $nodeScope=Get-PowerShellLexicalScopeAst -Node $variable -RootAst $ast
        $nodeKey=$nodeScope.GetType().Name+':'+$nodeScope.Extent.StartOffset+':'+$nodeScope.Extent.EndOffset
        if (-not $scopeVariableCache.ContainsKey($nodeKey)) { $scopeVariableCache[$nodeKey]=New-ArrayList }
        Add-ListItem $scopeVariableCache[$nodeKey] $variable
    }
    foreach ($node in @($commands)+@($invokeMembers)) {
        $nodeScope=Get-PowerShellLexicalScopeAst -Node $node -RootAst $ast
        $nodeKey=$nodeScope.GetType().Name+':'+$nodeScope.Extent.StartOffset+':'+$nodeScope.Extent.EndOffset
        $cache=if ($node -is [System.Management.Automation.Language.CommandAst]) { $scopeCommandCache } else { $scopeInvokeCache }
        if (-not $cache.ContainsKey($nodeKey)) { $cache[$nodeKey]=New-ArrayList }
        Add-ListItem $cache[$nodeKey] $node
    }
    foreach ($binding in $assignments) {
        if ($binding.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $nodeScope=Get-PowerShellLexicalScopeAst -Node $binding -RootAst $ast
        $bindingName=$nodeScope.GetType().Name+':'+$nodeScope.Extent.StartOffset+':'+$nodeScope.Extent.EndOffset+'|'+[string]$binding.Left.VariablePath.UserPath
        if (-not $assignmentsByName.ContainsKey($bindingName)) { $assignmentsByName[$bindingName]=New-ArrayList }
        Add-ListItem $assignmentsByName[$bindingName] $binding
    }
    foreach ($assignment in $assignments) {
        if ($assignment.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $literals=@($assignment.Right.FindAll({param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]},$true))
        if ($literals.Count -ne 1 -or $literals[0].StringConstantType -notin @([System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString,[System.Management.Automation.Language.StringConstantType]::SingleQuoted) -or
            $assignment.Right.Extent.Text.Trim() -cne $literals[0].Extent.Text) { continue }
        $name=[string]$assignment.Left.VariablePath.UserPath
        if ($name.Contains(':')) { continue }
        if ($qualifiedNames.ContainsKey($name)) { continue }
        $scope=Get-PowerShellLexicalScopeAst -Node $assignment -RootAst $ast
        $scopeKey=$scope.GetType().Name+':'+$scope.Extent.StartOffset+':'+$scope.Extent.EndOffset
        if ($literals[0].StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuoted) {
            if (-not $classifierScopes.ContainsKey($scopeKey)) { $classifierScopes[$scopeKey]=Test-PowerShellRegexClassifierScope -ScopeAst $scope -RootAst $ast -Commands @($scopeCommandCache[$scopeKey]) -InvokeMembers @($scopeInvokeCache[$scopeKey]) -Variables @($scopeVariableCache[$scopeKey]) }
            if (-not $classifierScopes[$scopeKey]) { continue }
        }
        $scopeVariables=$scopeVariableCache[$scopeKey]
        if (@($scopeVariables | Where-Object { $_.VariablePath.UserPath -in @('Matches','PSBoundParameters','MyInvocation','args','input','PSCommandPath','PSScriptRoot') }).Count -gt 0) { continue }
        $bindings=@($assignmentsByName[($scopeKey+'|'+$name)])
        if ($bindings.Count -ne 1 -or @($scopeVariables | Where-Object { $_.VariablePath.UserPath -ieq 'Matches' }).Count -gt 0) { continue }
        if (-not (Test-PowerShellPassiveRegexReachability -RootAst $ast -InitialScope $scope -ContainerName $name -AllVariables $variables -AllCommands $commands -AllFunctionDefinitions $functions -AllMemberExpressions $members -AllInvokeMemberExpressions $invokeMembers)) { continue }
        $safe=$true; $consumers=0
        foreach ($use in @($scopeVariables | Where-Object { $_.VariablePath.UserPath -ieq $name })) {
            if ([object]::ReferenceEquals($use,$assignment.Left)) { continue }
            $consumerLoops=@($loops | Where-Object { $use.Extent.StartOffset -ge $_.Condition.Extent.StartOffset -and $use.Extent.EndOffset -le $_.Condition.Extent.EndOffset })
            if ($consumerLoops.Count -eq 1) {
                $loop=$consumerLoops[0]
                $condition=$loop.Condition.Extent.Text -replace '\$[A-Za-z_][A-Za-z0-9_]*',''
                if ($condition -match '[^@(),\s]') { $safe=$false; break }
                $itemName=[string]$loop.Variable.VariablePath.UserPath
                if ($qualifiedNames.ContainsKey($itemName)) { $safe=$false; break }
                $itemUses=@($scopeVariables | Where-Object { $_.VariablePath.UserPath -ieq $itemName })
                foreach ($itemUse in $itemUses) {
                    if ([object]::ReferenceEquals($itemUse,$loop.Variable)) { continue }
                    if ($itemUse.Extent.StartOffset -lt $loop.Body.Extent.StartOffset -or $itemUse.Extent.EndOffset -gt $loop.Body.Extent.EndOffset -or
                        -not (Test-PowerShellRegexDataUse -Variable $itemUse -RootAst $ast -Functions $functions)) { $safe=$false; break }
                    $consumers++
                }
                if (-not (Test-PowerShellPassiveRegexReachability -RootAst $ast -InitialScope $scope -ContainerName $itemName -AllVariables $variables -AllCommands $commands -AllFunctionDefinitions $functions -AllMemberExpressions $members -AllInvokeMemberExpressions $invokeMembers)) { $safe=$false }
            }
            elseif (Test-PowerShellRegexDataUse -Variable $use -RootAst $ast -Functions $functions) { $consumers++ }
            else { $safe=$false }
            if (-not $safe) { break }
        }
        if ($safe -and $consumers -gt 0) { Add-ListItem $spans ([ordered]@{start=$offset+$literals[0].Extent.StartOffset; end=$offset+$literals[0].Extent.EndOffset}) }
    }
    $inlinePatterns=@($ast.FindAll({param($n)
        $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $n.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuoted -and
        $n.Value.Length -ge 32 -and
        $n.Parent -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        [string]$n.Parent.Operator -in @('Imatch','Cmatch','Inotmatch','Cnotmatch') -and
        [object]::ReferenceEquals($n.Parent.Right,$n)
    },$true))
    foreach ($literal in $inlinePatterns) {
        $scope=Get-PowerShellLexicalScopeAst -Node $literal -RootAst $ast
        $scopeKey=$scope.GetType().Name+':'+$scope.Extent.StartOffset+':'+$scope.Extent.EndOffset
        if (-not $classifierScopes.ContainsKey($scopeKey)) { $classifierScopes[$scopeKey]=Test-PowerShellRegexClassifierScope -ScopeAst $scope -RootAst $ast -Commands @($scopeCommandCache[$scopeKey]) -InvokeMembers @($scopeInvokeCache[$scopeKey]) -Variables @($scopeVariableCache[$scopeKey]) }
        if (-not $classifierScopes[$scopeKey]) { continue }
        if (-not (Test-PowerShellPassiveRegexReachability -RootAst $ast -InitialScope $scope -ContainerName '' -AllVariables $variables -AllCommands $commands -AllFunctionDefinitions $functions -AllMemberExpressions $members -AllInvokeMemberExpressions $invokeMembers)) { continue }
        Add-ListItem $spans ([ordered]@{start=$offset+$literal.Extent.StartOffset; end=$offset+$literal.Extent.EndOffset})
    }
    $chars=$Text.ToCharArray()
    foreach ($span in $spans) { for ($i=$span.start;$i -lt $span.end;$i++) { if ($chars[$i] -ne [char]10 -and $chars[$i] -ne [char]13) { $chars[$i]=[char]32 } } }
    $result=[ordered]@{text=(-join $chars); spans=@($spans.ToArray())}
    $script:RegexDataOriginalText=$Text; $script:RegexDataProjection=$result
    $script:RegexDataAst=if ($offset -eq 0) { $ast } else { $null }
    return $result
}

function Get-GitHubActionsExternalExecutionLine {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $lines = $Text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = [string]$lines[$i]
        $trimmed = $line.Trim()
        if ([string]::IsNullOrEmpty($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }
        if (Test-ExternalExecutionPattern $line) {
            return ($i + 1)
        }

        if ($trimmed -match '^(run|script)\s*:\s*(\||>|.+)$' -or $trimmed -match '^[-]?\s*(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b') {
            $block = New-Object System.Text.StringBuilder
            [void]$block.AppendLine($line)
            $max = [Math]::Min($i + 5, $lines.Count - 1)
            for ($j = $i + 1; $j -le $max; $j++) {
                $nextLine = [string]$lines[$j]
                [void]$block.AppendLine($nextLine)
            }
            if (Test-ExternalExecutionPattern ($block.ToString())) {
                return ($i + 1)
            }
        }
    }
    return $null
}

function Test-SecretExfilPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $secretPattern = '(secrets\.[A-Za-z0-9_]+|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_RUNTIME_TOKEN|GITHUB_TOKEN|process\.env\.[A-Za-z0-9_]*(TOKEN|SECRET|KEY)|env:[A-Za-z0-9_]*(TOKEN|SECRET|KEY))'
    $aiTokenPathPattern = '(\.codex\\+auth\.json|CODEX_HOME|\.claude|\.cursor|\.windsurf)'
    $egressPattern = '(https?://|curl|wget|Invoke-WebRequest|Invoke-RestMethod|fetch\s*\(|request\s*\(|axios|WebClient|HttpClient)'
    if (Test-BoundedTextRegex -Text $Text -Pattern ('(?is)' + $secretPattern + '.{0,300}' + $egressPattern)) { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern ('(?is)' + $egressPattern + '.{0,300}' + $secretPattern)) { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern ('(?is)' + $aiTokenPathPattern + '.{0,300}' + $egressPattern)) { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern ('(?is)' + $egressPattern + '.{0,300}' + $aiTokenPathPattern)) { return $true }
    return $false
}

function Get-UrlHostsFromText {
    param([string]$Text)
    $hosts = New-ArrayList
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    foreach ($m in @(Get-BoundedTextRegexMatches -Text $Text -Pattern '(?i)https?://([A-Za-z0-9._:-]+)')) {
        $urlHost = [string]$m.Groups[1].Value
        if ($urlHost.Contains(':')) {
            $urlHost = $urlHost.Split(':')[0]
        }
        if (-not [string]::IsNullOrEmpty($urlHost)) {
            Add-ListItem $hosts $urlHost.ToLowerInvariant()
        }
    }
    return @($hosts.ToArray())
}

function Test-IsAllowedGithubHost {
    param([string]$HostName)
    if ([string]::IsNullOrEmpty($HostName)) { return $false }
    $h = $HostName.ToLowerInvariant()
    return ($h -in @('api.github.com','github.com','codeload.github.com'))
}

function Test-AiTextHasUntrustedEgress {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|discord(app)?\.com/api/webhooks|webhook)') { return $true }
    $hosts = @(Get-UrlHostsFromText -Text $Text)
    foreach ($urlHost in $hosts) {
        if (-not (Test-IsAllowedGithubHost -HostName $urlHost)) {
            return $true
        }
    }
    if ($hosts.Count -eq 0 -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(curl|wget|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|fetch\s*\(|request\s*\(|requests\.|urllib\.request|axios|WebClient|HttpClient).{0,160}(\$url|args\.url|param\s*\(|Read-Host|\$\{?uri\}?)')) {
        return $true
    }
    return $false
}

function Test-AiTextHasOnlyAllowedGithubEgress {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|discord(app)?\.com/api/webhooks|webhook)') { return $false }
    $hosts = @(Get-UrlHostsFromText -Text $Text)
    if ($hosts.Count -eq 0) { return $false }
    foreach ($urlHost in $hosts) {
        if (-not (Test-IsAllowedGithubHost -HostName $urlHost)) {
            return $false
        }
    }
    return $true
}

function Test-AiTextHasWriteOrUpload {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(\bPOST\b|\bPUT\b|\bPATCH\b|\bDELETE\b|upload|UploadString|UploadData|requests\.post|requests\.put|axios\.post|axios\.put|fetch\s*\(.{0,200}method\s*:\s*[''"]?(POST|PUT|PATCH|DELETE)|curl.{0,160}(-X\s*(POST|PUT|PATCH|DELETE)|--data|-d\s|--form|-F\s)|Invoke-RestMethod.{0,160}(-Method\s+(Post|Put|Patch|Delete)|-Body)|Invoke-WebRequest.{0,160}(-Method\s+(Post|Put|Patch|Delete)|-Body))')
}

function Test-AiTextHasTokenReference {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(GITHUB_TOKEN|GH_TOKEN|process\.env\.[A-Za-z0-9_]*(TOKEN|SECRET|KEY)|os\.environ(\.get)?\s*\(\s*[''"][A-Za-z0-9_]*(TOKEN|SECRET|KEY)|env:[A-Za-z0-9_]*(TOKEN|SECRET|KEY)|\$env:[A-Za-z0-9_]*(TOKEN|SECRET|KEY))')
}

function Test-AiAuthorizedGithubReadClient {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $hasGithubClient = Test-BoundedTextRegex -Text $Text -Pattern '(?is)(GITHUB_TOKEN|GH_TOKEN|Authorization|github_request|github_api_contents_url|api\.github\.com|codeload\.github\.com)'
    if (-not $hasGithubClient) { return $false }
    if (Test-AiTextHasUntrustedEgress -Text $Text) { return $false }
    if (Test-AiTextHasWriteOrUpload -Text $Text) { return $false }
    return $true
}

function Test-AiRemoteInstallOrWriteCapability {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ((Test-AiTextHasWriteOrUpload -Text $Text) -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(https?://|api\.github\.com|github\.com|codeload\.github\.com|fetch\s*\(|request\s*\(|requests\.|curl|Invoke-RestMethod|Invoke-WebRequest)')) {
        return $true
    }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(codeload\.github\.com|https://github\.com/[^''"\s]+\.git|git@github\.com:[^''"\s]+\.git|argparse\.|--url|args\.url).{0,500}(subprocess\.run|git\s+clone|download|zip|extract|install)') {
        return $true
    }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(subprocess\.run|git\s+clone|download|zip|extract|install).{0,500}(codeload\.github\.com|https://github\.com/[^''"\s]+\.git|git@github\.com:[^''"\s]+\.git|argparse\.|--url|args\.url)') {
        return $true
    }
    return $false
}

function Test-LocalCredentialTransferUse {
    param([string]$Code,[int]$SourceIndex,[string]$SendPattern)
    $prefix=$Code.Substring([Math]::Max(0,$SourceIndex-240),[Math]::Min(240,$SourceIndex))
    # Anchor to the end of the prefix, not each earlier line. Otherwise a
    # preceding PowerShell/Python assignment without a semicolon can capture
    # an unrelated variable instead of the actual credential-read recipient.
    $binding=Get-BoundedTextRegexMatch -Text $prefix -Pattern '(?:\b(?:const|let|var)\s+|\$)?(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:await\s+)?[^;\r\n]*$'
    $name=if ($binding.Success) { $binding.Groups['name'].Value } else { '' }
    foreach ($send in @(Get-BoundedTextRegexMatches -Text $Code -Pattern $SendPattern)) {
        $end=[Math]::Min($Code.Length,$send.Index+1536)
        $open=$Code.IndexOf('(',$send.Index)
        if ($open -ge $send.Index -and $open -lt $send.Index+$send.Length+2) {
            $depth=0
            for ($i=$open;$i -lt $end;$i++) {
                if ($Code[$i] -eq '(') { $depth++ }
                elseif ($Code[$i] -eq ')') { $depth--; if ($depth -eq 0) { $end=$i+1; break } }
            }
        }
        else {
            $boundary=Get-BoundedTextRegexMatch -Text $Code.Substring($send.Index,$end-$send.Index) -Pattern '[;\r\n]'
            if ($boundary.Success) { $end=$send.Index+$boundary.Index }
        }
        if ($SourceIndex -ge $send.Index -and $SourceIndex -lt $end) { return $true }
        if ([string]::IsNullOrEmpty($name) -or $send.Index -lt $SourceIndex) { continue }
        $between=$Code.Substring($SourceIndex,$send.Index-$SourceIndex)
        $symbol='(?<![\w$])\$?'+[regex]::Escape($name.TrimStart('$'))+'(?![\w$]|\s*:)'
        if (Test-BoundedTextRegex -Text $between -Pattern ($symbol+'\s*=(?!=)')) { continue }
        $call=$Code.Substring($send.Index,$end-$send.Index)
        if (Test-BoundedTextRegex -Text $call -Pattern $symbol) { return $true }
        foreach ($derived in @(Get-BoundedTextRegexMatches -Text $between -Pattern '(?m)(?:\b(?:const|let|var)\s+|\$)(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<rhs>[^;\r\n]{1,300})')) {
            if (-not (Test-BoundedTextRegex -Text $derived.Groups['rhs'].Value -Pattern $symbol)) { continue }
            $derivedSymbol='(?<![\w$])\$?'+[regex]::Escape($derived.Groups['name'].Value)+'(?![\w$]|\s*:)'
            $after=$between.Substring($derived.Index+$derived.Length)
            if (-not (Test-BoundedTextRegex -Text $after -Pattern ($derivedSymbol+'\s*=(?!=)')) -and (Test-BoundedTextRegex -Text $call -Pattern $derivedSymbol)) { return $true }
        }
    }
    return $false
}

function Get-AiSecretExfilAssessment {
    param([string]$Text, [ValidateSet('plain','javascript','python')][string]$Language = 'plain')
    $result = [ordered]@{ detected=$false; index=0 }
    if ([string]::IsNullOrEmpty($Text)) { return $result }
    # Masking an entire bundle is unnecessary when none of the source tokens
    # can occur. These broad tokens also admit whitespace/comment-separated
    # accesses recognized after masking; this is only a negative prefilter.
    if (-not (Test-BoundedTextRegex -Text $Text -Pattern '(?i)process|environ|env:|Get-Content|ReadAllText|read_text|readFile|open|cat|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN')) { return $result }
    $code = if ($Language -eq 'plain') { $Text } else { Get-StaticCodeMask -Text $Text -Language $Language }
    # A variable-name inventory, URL in a comment, or pagination .cursor is not
    # credential access. Keep real read/send compounds and their source offset.
    $sourcePattern = '(?i)(process\s*\.\s*env\s*(?:\.\s*[A-Za-z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)|\[)|os\s*\.\s*environ|\$env:[A-Za-z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)|Get-Content|ReadAllText\s*\(|read_text\s*\(|readFile(?:Sync)?\s*\(|open\s*\(|\bcat\s+)'
    if ($Language -eq 'plain') { $sourcePattern+='|(?i)\b(?:GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN)\b' }
    $readPath = '(?i)(\.codex[\\/]+auth\.json|CODEX_HOME.{0,120}auth\.json|\.(?:claude|cursor|windsurf)[\\/]+[^''"\s]{0,120}(?:auth|token|credential)|\.ssh[\\/]+id_(?:rsa|ed25519)|\.aws[\\/]+credentials|\.config[\\/]+gcloud|\.kube[\\/]+config|\.npmrc|\.pypirc)'
    $sendPattern = '(?is)(fetch\s*\(|requests\.(?:post|put|get)|axios\.(?:post|put|get)|https?\.request\s*\(|\brequest\s*\(|curl\b|wget\b|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|UploadString|UploadData)'
    foreach ($source in @(Get-BoundedTextRegexMatches -Text $code -Pattern $sourcePattern)) {
        $start = [Math]::Max(0,$source.Index-500)
        $length = [Math]::Min($Text.Length-$start,$source.Index-$start+750)
        $local = $Text.Substring($start,$length)
        $active = $code.Substring($start,$length)
        $fileRead = $source.Value -match '(?i)Get-Content|ReadAllText|read_text|readFile|open\s*\(|\bcat\s+'
        if ($fileRead) {
            $argument = $Text.Substring($source.Index,[Math]::Min(240,$Text.Length-$source.Index)) -split '[;\r\n]',2
            if ($argument[0] -notmatch $readPath) {
                $parameter=Get-BoundedTextRegexMatch -Text $argument[0] -Pattern '(?:\(|Get-Content\s+(?:(?:-LiteralPath|-Path)\s+)?)(?<name>\$?[A-Za-z_][A-Za-z0-9_]*)\b'
                if (-not $parameter.Success) { continue }
                $name=[regex]::Escape($parameter.Groups['name'].Value.TrimStart('$'))
                $before=$Text.Substring([Math]::Max(0,$source.Index-500),[Math]::Min(500,$source.Index))
                $bindings=@(Get-BoundedTextRegexMatches -Text $before -Pattern ('(?m)(?:\b(?:const|let|var)\s+|\$)'+$name+'\s*=\s*(?<value>[^;\r\n]{1,240})'))
                if ($bindings.Count -eq 0 -or $bindings[-1].Groups['value'].Value -notmatch $readPath) { continue }
            }
        }
        elseif ($source.Value -match 'env\s*\[|environ') {
            $argument = $Text.Substring($source.Index,[Math]::Min(160,$Text.Length-$source.Index)) -split '[;\r\n]',2
            if ($argument[0] -notmatch '(?i)TOKEN|SECRET|KEY|PASSWORD') { continue }
        }
        if (-not (Test-BoundedTextRegex -Text $active -Pattern $sendPattern)) { continue }
        if (-not (Test-LocalCredentialTransferUse -Code $active -SourceIndex ($source.Index-$start) -SendPattern $sendPattern)) { continue }
        if (-not $fileRead -and (Test-AiTextHasOnlyAllowedGithubEgress -Text $local)) { continue }
        $result.detected=$true; $result.index=$source.Index
        return $result
    }
    return $result
}

function Test-AiSecretExfilPattern {
    param([string]$Text)
    return [bool](Get-AiSecretExfilAssessment -Text $Text).detected
}

function Test-AiFetchExecutePattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $patterns = @(
        '(?is)(curl|wget|\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod).{0,160}(\||;|&&).{0,160}(bash|sh|powershell|pwsh|\biex\b|Invoke-Expression|cmd\.exe)',
        '(?is)(DownloadString|fetch\s*\(|urlopen\s*\(|requests\.get|urllib\.request|https?://|raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com).{0,180}(\biex\b|Invoke-Expression|eval\s*\(|exec\s*\(|bash\s+-c|sh\s+-c|powershell\s+-|pwsh\s+-)',
        '(?is)(FromBase64String|base64\s+-d|certutil\s+-decode).{0,160}(\biex\b|Invoke-Expression|eval\s*\(|exec\s*\(|bash|sh|powershell|pwsh)'
    )
    $lines = $Text -split "`r?`n"
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrEmpty($trimmed)) { continue }
        foreach ($pattern in $patterns) {
            if ($trimmed -match $pattern) { return $true }
        }
    }

    $blocks = [regex]::Split($Text, "(`r?`n){2,}")
    foreach ($block in $blocks) {
        if ([string]::IsNullOrEmpty($block)) { continue }
        if ($block.Length -gt 900) { continue }
        foreach ($pattern in $patterns) {
            if ($block -match $pattern) { return $true }
        }
    }
    return $false
}

function Test-KnownIocTextPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text) -or $null -eq $script:Context -or $null -eq $script:Context.iocs) {
        return $false
    }
    foreach ($domain in @($script:Context.iocs.domains)) {
        if (-not [string]::IsNullOrEmpty($domain) -and (Test-BoundedTextRegex -Text $Text -Pattern ([regex]::Escape($domain)))) {
            return $true
        }
    }
    foreach ($ip in @($script:Context.iocs.ips)) {
        if (-not [string]::IsNullOrEmpty($ip) -and (Test-BoundedTextRegex -Text $Text -Pattern ([regex]::Escape($ip)))) {
            return $true
        }
    }
    return $false
}

function Get-KnownIocTextMatch {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text) -or $null -eq $script:Context -or $null -eq $script:Context.iocs) {
        return $null
    }
    foreach ($domain in @($script:Context.iocs.domains)) {
        if (-not [string]::IsNullOrEmpty($domain) -and (Test-BoundedTextRegex -Text $Text -Pattern ([regex]::Escape($domain)))) {
            return [ordered]@{ type='domain'; value=$domain; pattern=[regex]::Escape($domain) }
        }
    }
    foreach ($ip in @($script:Context.iocs.ips)) {
        if (-not [string]::IsNullOrEmpty($ip) -and (Test-BoundedTextRegex -Text $Text -Pattern ([regex]::Escape($ip)))) {
            return [ordered]@{ type='ip'; value=$ip; pattern=[regex]::Escape($ip) }
        }
    }
    return $null
}

function Test-IocContextsAllow {
    param($PatternIoc, [string]$TextContext, [string]$SourceContext)
    $contexts = @($PatternIoc.contexts)
    if ($contexts.Count -eq 0 -or ([string]::IsNullOrEmpty([string]$contexts[0]))) {
        return $true
    }
    foreach ($context in $contexts) {
        $c = [string]$context
        if ([string]::IsNullOrEmpty($c)) { continue }
        if ($c -ieq $TextContext -or $c -ieq $SourceContext) {
            return $true
        }
    }
    return $false
}

function Test-SecretHarvestingExternalSendPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    # Separate keyword recognition from consumption. The previous adjacent
    # unbounded classes retried every TOKEN/KEY occurrence in an unterminated
    # quoted property. Lookaheads plus atomic consumption keep that path linear.
    $secretHarvestPattern = '(?is)(\.npmrc|\.pypirc|\.netrc|\.ssh\\+id_rsa|\.ssh\\+id_ed25519|\.aws\\+credentials|\.kube\\+config|\.codex\\+auth\.json|CODEX_HOME|secrets\.[A-Za-z0-9_]+|\$\{\{\s*secrets\.|process\.env(\.(?=[A-Za-z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD))(?>[A-Za-z0-9_]+)|\s*\[\s*["''](?=[^"'']*(?:TOKEN|SECRET|KEY|PASSWORD))(?>[^"'']*)["'']\s*\])|os\.environ(?:\.get)?\s*\(\s*["''](?=[^"'']*(?:TOKEN|SECRET|KEY|PASSWORD))(?>[^"'']*)["'']|Get-ChildItem\s+Env:|\$env:(?=[A-Za-z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD))(?>[A-Za-z0-9_]+)|env:(?=[A-Za-z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD))(?>[A-Za-z0-9_]+)|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN)'
    $sendPattern = '(?is)(curl|wget|Invoke-RestMethod|Invoke-WebRequest|\biwr\b|\birm\b|fetch\s*\(|request\s*\(|requests\.post|requests\.put|axios\.post|axios\.put|WebClient|HttpClient|UploadString|UploadData).{0,220}(https?://|raw\.githubusercontent|gist\.github|pastebin|webhook|--data|-d\s|--form|-F\s|-Body|method\s*:\s*[''"]?(POST|PUT|PATCH)|POST|PUT|PATCH|upload)'
    # Preserve arbitrarily long whitespace accepted by the original expression.
    # Those rare shapes use its bounded-time full-text fallback. Otherwise each
    # send consumes <=350 chars and the 850-char windows retain the 500-char gap.
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(?:fetch|request|method)\s{33,}|method\s*:\s{33,}') {
        return ((Test-BoundedTextRegex -Text $Text -Pattern ($secretHarvestPattern+'.{0,500}'+$sendPattern)) -or
            (Test-BoundedTextRegex -Text $Text -Pattern ($sendPattern+'.{0,500}'+$secretHarvestPattern)))
    }
    $secretAnchorPattern = '(?is)(\.npmrc|\.pypirc|\.netrc|\.ssh|\.aws|\.kube|\.codex|CODEX_HOME|secrets\.|\$\{\{\s*secrets\.|process\.env|os\.environ|Get-ChildItem\s+Env:|\$env:|env:|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN)'
    $sendAnchorPattern = '(?is)(curl|wget|Invoke-RestMethod|Invoke-WebRequest|\biwr\b|\birm\b|fetch\s*\(|request\s*\(|requests\.(post|put)|axios\.(post|put)|WebClient|HttpClient|UploadString|UploadData)'
    if (-not (Test-BoundedTextRegex -Text $Text -Pattern $sendAnchorPattern)) { return $false }
    # Validate one anchored credential candidate at a time without restarting
    # the credential regexp at unrelated positions across a compiler bundle.
    $anchors=Get-CachedBoundedRegex $secretAnchorPattern
    $credential=Get-CachedBoundedRegex ('\G(?:'+$secretHarvestPattern+')')
    $after=Get-CachedBoundedRegex ('\A(?s:.{0,500})(?:'+$sendPattern+')')
    $before=Get-CachedBoundedRegex ('(?:'+$sendPattern+')(?s:.{0,500})\z')
    $anchor=$anchors.Match($Text)
    while ($anchor.Success) {
        $match=$credential.Match($Text,$anchor.Index)
        if ($match.Success) {
            $end=$match.Index+$match.Length
            if ($after.IsMatch($Text.Substring($end,[Math]::Min(850,$Text.Length-$end)))) { return $true }
            $start=[Math]::Max(0,$match.Index-850)
            if ($before.IsMatch($Text.Substring($start,$match.Index-$start))) { return $true }
        }
        $anchor=$anchor.NextMatch()
    }
    return $false
}

function Get-DeveloperToolWriteAssessment {
    param([string]$Text)
    $result=[ordered]@{detected=$false; index=0}
    if ([string]::IsNullOrEmpty($Text)) { return $result }
    $toolPath='(?i)(\.(?:vscode|cursor|claude|codex|windsurf)[\\/]|["'']\.(?:vscode|cursor|claude|codex|windsurf)["'']|claude_desktop_config\.json|mcp\.json|settings\.json)'
    $writes='(?i)(?:writeFile(?:Sync)?|WriteAllText|copyFile(?:Sync)?)\s*\(|(?:Set-Content|Add-Content|Out-File|Copy-Item|New-Item)\b'
    foreach ($write in @(Get-BoundedTextRegexMatches -Text $Text -Pattern $writes)) {
        $tail=$Text.Substring($write.Index+$write.Length,[Math]::Min(2048,$Text.Length-$write.Index-$write.Length))
        $destination=''; $depth=0; $quote=[char]0
        $argumentNumber=1; $wantedArgument=if ($write.Value -match '(?i)^copyFile') {2} else {1}
        for ($i=0;$i -lt $tail.Length;$i++) {
            $c=$tail[$i]
            if ($quote -ne [char]0) {
                if ($c -eq '\' -or $c -eq [char]96) { $destination+=$c; if ($i+1 -lt $tail.Length) { $i++; $destination+=$tail[$i] }; continue }
                if ($c -eq $quote) { $quote=[char]0 }
            }
            elseif ($c -eq [char]34 -or $c -eq [char]39) { $quote=$c }
            elseif ($c -eq '(') { $depth++ }
            elseif ($c -eq ')') { if ($depth -eq 0) { break }; $depth-- }
            elseif ($c -eq ',' -and $depth -eq 0) {
                if ($argumentNumber -eq $wantedArgument) { break }
                $argumentNumber++; $destination=''; continue
            }
            elseif ($c -eq ';' -or $c -eq [char]10 -or $c -eq [char]13) { break }
            $destination+=$c
        }
        if ($write.Value -notmatch '\(') {
            $argumentPattern='(?<argument>"[^"\r\n]*"|''[^''\r\n]*''|[^\s;]+)'
            $option=if ($write.Value -match '(?i)^Copy-Item') { 'Destination' } else { 'LiteralPath|Path|FilePath' }
            $named=Get-BoundedTextRegexMatch -Text $destination -Pattern ('(?i)-(?:'+$option+')\s+'+$argumentPattern)
            if ($named.Success) { $destination=$named.Groups['argument'].Value }
            else {
                $positional=@(Get-BoundedTextRegexMatches -Text $destination -Pattern $argumentPattern -MaximumMatches 8)
                $position=if ($write.Value -match '(?i)^Copy-Item') {1} else {0}
                if ($positional.Count -le $position) { continue }
                $destination=$positional[$position].Groups['argument'].Value
            }
        }
        # Resolve a simple local destination binding, not a nearby manifest's
        # target field or the data/content argument of an unrelated write.
        $boundDestination=$destination
        if ($destination.Trim() -match '^\$?(?<name>[A-Za-z_][A-Za-z0-9_]*)$') {
            $name=[regex]::Escape($Matches.name)
            $before=$Text.Substring([Math]::Max(0,$write.Index-1000),[Math]::Min(1000,$write.Index))
            $bindings=@(Get-BoundedTextRegexMatches -Text $before -Pattern ('(?m)(?:\b(?:const|let|var)\s+|\$)'+$name+'\s*=\s*(?<value>[^;\r\n]{1,400})'))
            if ($bindings.Count -gt 0) { $boundDestination=$bindings[-1].Groups['value'].Value }
        }
        if (-not (Test-BoundedTextRegex -Text $boundDestination -Pattern $toolPath)) { continue }
        $start=[Math]::Max(0,$write.Index-500)
        $window=$Text.Substring($start,[Math]::Min(1000,$Text.Length-$start))
        if (Test-BoundedTextRegex -Text $window -Pattern '(?i)https?://|curl|wget|fetch\s*\(|request\s*\(|process\.env|TOKEN|SECRET') {
            $result.detected=$true; $result.index=$write.Index; return $result
        }
    }
    return $result
}

function Test-DeveloperToolPersistenceRiskPattern {
    param([string]$Text)
    return [bool](Get-DeveloperToolWriteAssessment $Text).detected
}

function Test-ImportOrRuntimeExecutionPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-SecretHarvestingExternalSendPattern $Text) { return $true }
    if (Test-ExternalExecutionPattern $Text) { return $true }
    if (Test-DeveloperToolPersistenceRiskPattern $Text) {
        return $true
    }
    return $false
}

function Get-NpmIncidentContextMarker {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    if ($null -eq $script:IncidentContextMarkers) { $script:IncidentContextMarkers = @(
        @{ label='83.142.209.194'; pattern='83\.142\.209\.194' },
        @{ label='/tmp/transformers.pyz'; pattern='/tmp/transformers\.pyz|\\tmp\\transformers\.pyz' },
        @{ label='pgmonitor.py'; pattern='\bpgmonitor\.py\b' },
        @{ label='pgsql-monitor.service'; pattern='pgsql-monitor\.service' },
        @{ label='setup_bun.js'; pattern='\bsetup_bun\.js\b' },
        @{ label='bun_environment.js'; pattern='\bbun_environment\.js\b' },
        @{ label='actionsSecrets.json'; pattern='\bactionsSecrets\.json\b' },
        @{ label='truffleSecrets.json'; pattern='\btruffleSecrets\.json\b' }
    ) }
    $hasLiteral=$false
    $foldedText=$Text.ToLowerInvariant()
    foreach ($marker in $script:IncidentContextMarkers) {
        $literal=if ($marker.label -eq '/tmp/transformers.pyz') { 'transformers.pyz' } else { [string]$marker.label }
        if ($foldedText.IndexOf($literal.ToLowerInvariant(),[StringComparison]::Ordinal) -ge 0) { $hasLiteral=$true; break }
    }
    # For ASCII, ordinal preflight cannot discard a culture-sensitive regex
    # match. Non-ASCII input retains the complete original case semantics.
    if (-not $hasLiteral -and [Text.Encoding]::UTF8.GetByteCount($Text) -eq $Text.Length) { return $null }
    foreach ($marker in $script:IncidentContextMarkers) {
        if (Test-BoundedTextRegex -Text $Text -Pattern ([string]$marker.pattern)) {
            return $marker
        }
    }
    return $null
}

function Get-NpmIncidentFileNameMarker {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) { return $null }
    $name = $File.Name.ToLowerInvariant()
    switch ($name) {
        'setup_bun.js' { return @{ label='setup_bun.js'; pattern='\bsetup_bun\.js\b' } }
        'bun_environment.js' { return @{ label='bun_environment.js'; pattern='\bbun_environment\.js\b' } }
        'actionssecrets.json' { return @{ label='actionsSecrets.json'; pattern='\bactionsSecrets\.json\b' } }
        'trufflesecrets.json' { return @{ label='truffleSecrets.json'; pattern='\btruffleSecrets\.json\b' } }
        default { return $null }
    }
}

function Test-GlassWormC2ChannelMarker {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(@solana/web3\.js|mainnet-beta|api\.mainnet-beta\.solana\.com|solana).{0,350}(getAccountInfo|getParsedAccountInfo|getSignaturesForAddress|getTransaction|PublicKey\s*\(|Connection\s*\()') { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(getAccountInfo|getParsedAccountInfo|getSignaturesForAddress|getTransaction|PublicKey\s*\(|Connection\s*\().{0,350}(@solana/web3\.js|mainnet-beta|api\.mainnet-beta\.solana\.com|solana)') { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(bittorrent-dht|dht-rpc|k-rpc|announce_peer|get_peers|bootstrap\.addrs)') { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(googleapis\.com/calendar|calendar/v3|calendar\.events\.list|events\.list\s*\().{0,350}(summary|title|description)') { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(summary|title|description).{0,350}(googleapis\.com/calendar|calendar/v3|calendar\.events\.list|events\.list\s*\()') { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)') { return $true }
    return $false
}

function Test-GlassWormExecutionOrExfilCompound {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-ExternalExecutionPattern $Text) { return $true }
    if (Test-SecretHarvestingExternalSendPattern $Text) { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|Buffer\.from|atob\s*\(|FromBase64String|decodeURIComponent|String\.fromCharCode).{0,400}(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)') { return $true }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz).{0,400}(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|Buffer\.from|atob\s*\(|FromBase64String|decodeURIComponent|String\.fromCharCode)') { return $true }
    return $false
}

function Test-ReferenceTextExecutableSamplePattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)```[^`]{0,1800}(curl|wget|\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod).{0,220}(\|\s*(iex|bash|sh|powershell|pwsh)|Invoke-Expression|bash\s+-c|sh\s+-c|powershell\s+-|pwsh\s+-)[^`]{0,1800}```') {
        return $true
    }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)```[^`]{0,1800}(\.npmrc|\.pypirc|\.netrc|\.codex\\+auth\.json|process\.env|os\.environ|GITHUB_TOKEN|GH_TOKEN|TOKEN|SECRET).{0,500}(requests\.post|axios\.post|fetch\s*\(|Invoke-RestMethod|curl).{0,220}(https?://|--data|-d\s|-Body|method\s*:\s*[''"]?POST)[^`]{0,1800}```') {
        return $true
    }
    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^(PS>|>|\$|curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|powershell|pwsh)\b' -and (Test-ExternalExecutionPattern $trimmed)) {
            return $true
        }
    }
    return $false
}

function Get-KnownFileIocCandidates {
    if ($null -ne $script:Context.knownFileIocCandidates) { return @($script:Context.knownFileIocCandidates) }
    $entries=New-ArrayList
    $compiled=@{}
    foreach ($ioc in @($script:Context.iocs.files)) {
        $pattern=[string](Get-PropertyValue $ioc 'pathPattern')
        $patternOnly=-not [string]::IsNullOrEmpty($pattern) -and [string]::IsNullOrEmpty([string](Get-PropertyValue $ioc 'fileName')) -and [string]::IsNullOrEmpty([string](Get-PropertyValue $ioc 'path'))
        $regex=$null
        if ($patternOnly) {
            if (-not $compiled.ContainsKey($pattern)) {
                try { $compiled[$pattern]=New-Object System.Text.RegularExpressions.Regex($pattern,[System.Text.RegularExpressions.RegexOptions]::IgnoreCase,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds)) }
                catch { $compiled[$pattern]=$null }
            }
            $regex=$compiled[$pattern]
        }
        Add-ListItem $entries ([ordered]@{ioc=$ioc; pathRegex=$regex; ownerCheck=[string](Get-PropertyValue $ioc 'ownerCheck')})
    }
    $script:Context.knownFileIocCandidates=@($entries.ToArray())
    return @($script:Context.knownFileIocCandidates)
}

function Test-KnownFileIocMatch {
    param([System.IO.FileInfo]$File, $Ioc)
    if ($null -eq $File -or $null -eq $Ioc) { return $false }
    $artifactRole = [string](Get-PropertyValue $Ioc 'artifactRole')
    if ($artifactRole -in @('ide-archive','ide-payload')) {
        $candidateMetadata = Get-SecurityCandidateMetadata $File.FullName
        $isIdeCandidate = (Test-IsVsCodeStyleExtensionPath $File.FullName) -or ($null -ne $candidateMetadata -and $candidateMetadata.ownerChecks -contains 'IdeExtensions')
        if (-not $isIdeCandidate) { return $false }
        if ($artifactRole -eq 'ide-archive' -and $null -ne $candidateMetadata -and $candidateMetadata.selectionReasons -notcontains 'explicit-ide-archive' -and -not (Test-IsVsCodeStyleExtensionPath $File.FullName)) { return $false }
    }
    $path = $File.FullName -replace '/', '\'
    $pathLower = $path.ToLowerInvariant()

    $pathPattern = [string](Get-PropertyValue $Ioc 'pathPattern')
    if (-not [string]::IsNullOrEmpty($pathPattern) -and $path -match $pathPattern) {
        return $true
    }

    $fileName = [string](Get-PropertyValue $Ioc 'fileName')
    if (-not [string]::IsNullOrEmpty($fileName) -and $File.Name -ieq $fileName) {
        $pathContains = [string](Get-PropertyValue $Ioc 'pathContains')
        if ([string]::IsNullOrEmpty($pathContains) -or $pathLower.Contains($pathContains.ToLowerInvariant())) {
            return $true
        }
    }

    $configuredPath = [string](Get-PropertyValue $Ioc 'path')
    if (-not [string]::IsNullOrEmpty($configuredPath)) {
        $expanded = [Environment]::ExpandEnvironmentVariables($configuredPath)
        try {
            $expandedFull = [System.IO.Path]::GetFullPath($expanded)
            if ($expandedFull.Equals($File.FullName, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        catch {
        }
    }
    return $false
}

function Add-KnownFileIocFinding {
    param([System.IO.FileInfo]$File, $Ioc)
    if ($null -eq $File -or $null -eq $Ioc) { return }
    $severity = [string](Get-PropertyValue $Ioc 'severity')
    if ([string]::IsNullOrEmpty($severity)) { $severity = 'DANGER' }
    $notes = [string](Get-PropertyValue $Ioc 'notes')
    if ([string]::IsNullOrEmpty($notes)) { $notes = 'Known suspicious file IOC matched.' }
    $checkName = 'ScannerSelf'
    $category = 'KNOWN_SUSPICIOUS_FILE_IOC'
    $title = 'Known suspicious file IOC detected'
    $evidence = ("Known file IOC matched. Notes: {0}" -f $notes)
    $pathLower = $File.FullName.ToLowerInvariant() -replace '/', '\'
    if (Test-IsJetBrainsPluginPath $File.FullName) {
        $checkName = 'IdeExtensions'
        $category = 'JETBRAINS_PLUGIN_KNOWN_IOC'
        $title = 'Known suspicious JetBrains plugin artifact detected'
    }
    elseif (Test-IsVsCodeStyleExtensionPath $File.FullName) { $checkName = 'IdeExtensions' }
    elseif ($pathLower -match '\\node_modules\\') { $checkName = 'Packages' }
    elseif ($pathLower -match '\\\.github\\actions\\') { $checkName = 'CiCd' }
    $declaredOwner = [string](Get-PropertyValue $Ioc 'ownerCheck')
    if ($declaredOwner -in $script:LeafCheckOrder) { $checkName = $declaredOwner }
    if ([string](Get-PropertyValue $Ioc 'campaignId') -eq 'keyv-chaindrop-2026-08') {
        $checkName = 'LifecycleScripts'
        $category = 'KNOWN_MALICIOUS_FILE_HASH'
        $title = 'Known Keyv/ChainDrop file hash detected'
        $evidence = ("Exact SHA-256 campaign IOC matched. Notes: {0}" -f $notes)
    }
    Add-Finding -Severity $severity -Category $category -Title $title -Path $File.FullName -Evidence $evidence -Recommendation 'Preserve evidence and verify endpoint context before deleting or modifying the file.' -RiskType 'known-ioc' -Confidence 'high' -Check $checkName -DetectionMethod 'metadata' -SourceId ([string](Get-PropertyValue $Ioc 'sourceId')) -RuleId ([string](Get-PropertyValue $Ioc 'ruleId'))
}

function Scan-KnownFileIocs {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File -or $null -eq $script:Context -or $null -eq $script:Context.iocs) { return }
    $seenHashes = @{}
    $actualHash = ''
    $hashAttempted = $false
    $normalizedPath=$File.FullName -replace '/', '\'
    foreach ($candidate in @(Get-KnownFileIocCandidates)) {
        if ($null -ne $candidate.pathRegex -and -not $candidate.pathRegex.IsMatch($normalizedPath)) { continue }
        $ioc=$candidate.ioc
        $ownerCheck = [string]$candidate.ownerCheck
        if (-not [string]::IsNullOrWhiteSpace($ownerCheck) -and -not (Test-CheckEnabled $ownerCheck)) { continue }
        if (-not (Test-KnownFileIocMatch -File $File -Ioc $ioc)) { continue }
        $expectedHash = [string](Get-PropertyValue $ioc 'sha256')
        if (-not [string]::IsNullOrEmpty($expectedHash)) {
            $hashKey = $expectedHash.ToLowerInvariant()
            if ($seenHashes.ContainsKey($hashKey)) { continue }
            $seenHashes[$hashKey] = $true
            if ($File.Name -match '^(?i:setup\.mjs|Math_Symbol\.js|math_init\.js)$') { Add-ScanStat -Name 'incidentHashCandidates' }
            if (-not $hashAttempted) {
                $hashAttempted = $true
                if (-not (Test-SecurityCandidateBoundary -Path $File.FullName)) {
                    Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'incident-hash' -FailureType 'path-boundary-rejected' -Critical $true
                }
                elseif ($File.Length -gt ([int64]$MaxFileSizeMB * 1024 * 1024)) {
                    Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'incident-hash' -FailureType 'too-large' -Critical $true
                }
                else {
                    Add-ScanStat -Name 'fileHashComputations'
                    $actualHash = Get-BytesSha256ForFile $File.FullName
                    if ([string]::IsNullOrEmpty($actualHash)) {
                        Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'incident-hash' -FailureType 'access-denied' -Critical $true
                    }
                }
            }
            if ([string]::IsNullOrEmpty($actualHash)) { continue }
            if ($actualHash.ToLowerInvariant() -ne $expectedHash.ToLowerInvariant()) {
                continue
            }
        }
        Add-KnownFileIocFinding -File $File -Ioc $ioc
    }
}

function Scan-FixedKnownFileIocs {
    if ($null -eq $script:Context -or $null -eq $script:Context.iocs) { return }
    foreach ($ioc in @($script:Context.iocs.files)) {
        $configuredPath = [string](Get-PropertyValue $ioc 'path')
        if ([string]::IsNullOrEmpty($configuredPath)) { continue }
        $expanded = [Environment]::ExpandEnvironmentVariables($configuredPath)
        try {
            if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) { continue }
            $file = New-Object System.IO.FileInfo($expanded)
            Add-KnownFileIocFinding -File $file -Ioc $ioc
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'KNOWN_FILE_IOC_PATH_UNAVAILABLE' -Title 'Known file IOC path could not be checked' -Path $expanded -Evidence 'The configured IOC path was unavailable or inaccessible.' -Recommendation 'Check manually if endpoint compromise is suspected.'
        }
    }
}

function Scan-KnownTextIocs {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    if (Test-IsScannerSelfIocReferencePath $File.FullName) {
        if (Test-KnownIocTextPattern $Text) {
            Add-ScanStat -Name 'scannerArtifactIocReferencesAggregated'
        }
        return
    }
    $match = Get-KnownIocTextMatch -Text $Text
    if ($null -eq $match) { return }
    $role = Get-AiPathRole $File.FullName
    $textContext = Get-TextContext -File $File
    if ($role -in @('reference-text','session-log','cache-data')) {
        Add-AiContextAggregate -Role $role
        return
    }
    if ($textContext -eq 'documentation') {
        Add-Finding -Severity 'INFO' -Category 'KNOWN_IOC_REFERENCE_TEXT' -Title 'Known IOC appears in documentation text' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern ([string]$match.pattern)) -Evidence ("Known IOC {0} referenced in documentation: {1}" -f $match.type, $match.value) -Recommendation 'Treat as documentation context unless an executable finding points to the same IOC.' -RiskType 'known-ioc' -Confidence 'low'
        return
    }
    if ($File.Extension.ToLowerInvariant() -in @('.ps1','.bat','.cmd')) {
        $projection=Get-PowerShellRegexDataProjection $Text
        $activeMatch=Get-KnownIocTextMatch -Text $projection.text
        if ($null -eq $activeMatch) {
            Add-Finding -Severity 'INFO' -Category 'KNOWN_IOC_REFERENCE_TEXT' -Title 'Known IOC appears only in proven passive regex test data' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern ([string]$match.pattern)) -Evidence ("Known IOC {0} occurs in literal data whose consumers are statically proven regex-only: {1}. No filename exemption was used." -f $match.type,$match.value) -Recommendation 'Retain as test-data context; unknown consumers and active IOC occurrences remain in normal analysis.' -RiskType 'posture' -Confidence 'high'
            return
        }
        $Text=$projection.text; $match=$activeMatch
    }
    Add-Finding -Severity 'DANGER' -Category 'KNOWN_IOC_TEXT_PATTERN' -Title 'Known IOC text pattern detected' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern ([string]$match.pattern)) -Evidence ("Known IOC {0} matched: {1}" -f $match.type, $match.value) -Recommendation 'Preserve evidence and inspect surrounding file context without executing it.' -RiskType 'known-ioc' -Confidence 'high'
}

function Test-VerifiedSelfTestMarkerReference {
    param([System.IO.FileInfo]$File,[string]$Text,[string]$RuleId)
    if ($null -eq $File -or $Text.Length -gt 1048576) { return $false }
    # Versioned, manually reviewed source identities. Only these four posture
    # markers are refined; executable behavior, hashes and other IOCs still run.
    $references=@{
        '.github/workflows/validate.yml'=@{hash='2033beff1bd937ffc0980d55c55ace0900994ab62fd76a0f849fc0f87429a2d6';rules=@('glassworm-c2-marker')}
        'tests/Test-IocMaintenance.ps1'=@{hash='608e130535a759fdf9b97074e57eda6c72efd95761f8425f5870279f43997ef2';rules=@('keyv_chaindrop_nodereal_contract_marker')}
        'tests/Test-SecurityUpdate20261006.ps1'=@{hash='2fd05cf2f9e7a0c81f51bb165ead1d965b086c1ddbd490a1e6e682f78a0c395a';rules=@('supplychain_local_campaign_host_marker','virgil_secondary_transfer_endpoint_marker')}
    }
    $root=[IO.Path]::GetFullPath($script:BaseDir).TrimEnd('\')+'\'
    if (-not $File.FullName.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { return $false }
    $relative=$File.FullName.Substring($root.Length).Replace('\','/')
    if (-not $references.ContainsKey($relative) -or $RuleId -notin $references[$relative].rules) { return $false }
    $normalized=$Text.Replace([string][char]13+[char]10,[string][char]10).Replace([string][char]13,[string][char]10).TrimStart([char]0xFEFF)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    return ($hash -ceq $references[$relative].hash)
}

function Scan-LocalSuspiciousTextPatterns {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    if (Test-IsScannerSelfIocReferencePath $File.FullName) {
        return
    }
    if ($null -eq $script:Context -or $null -eq $script:Context.iocs) { return }
    $textContext = Get-TextContext -File $File
    $sourceContext = Get-SourceContext $File.FullName
    foreach ($patternIoc in @($script:Context.iocs.patterns)) {
        $regex = [string](Get-PropertyValue $patternIoc 'regex')
        if ([string]::IsNullOrEmpty($regex)) { continue }
        if (-not (Test-IocContextsAllow -PatternIoc $patternIoc -TextContext $textContext -SourceContext $sourceContext)) { continue }
        $patternStarted=[Diagnostics.Stopwatch]::GetTimestamp()
        try {
            # Only this exact shipped expression has this necessary literal.
            # A locally edited expression with the same id is still evaluated.
            if ($regex -ceq '(?i)(?<![a-z0-9._-])(?:[a-z0-9-]+\.)*skyleen\.fr(?![a-z0-9._-])' -and
                -not (Test-BoundedTextRegex -Text $Text -Pattern 'skyleen\.fr')) { continue }
            $match = Get-BoundedTextRegexMatch -Text $Text -Pattern $regex
            if (-not $match.Success) { continue }
            $severity = [string](Get-PropertyValue $patternIoc 'severity')
            if ([string]::IsNullOrEmpty($severity)) { $severity = 'WARN' }
            $id = [string](Get-PropertyValue $patternIoc 'id')
            if ([string]::IsNullOrEmpty($id)) { $id = 'LOCAL_SUSPICIOUS_TEXT_PATTERN' }
            $title = [string](Get-PropertyValue $patternIoc 'title')
            if ([string]::IsNullOrEmpty($title)) { $title = 'Local suspicious text pattern matched' }
            $notes = [string](Get-PropertyValue $patternIoc 'notes')
            if ([string]::IsNullOrEmpty($notes)) { $notes = 'Local suspicious pattern matched. Line content redacted.' }
            if ($severity -eq 'WARN' -and (Test-VerifiedSelfTestMarkerReference -File $File -Text $Text -RuleId $id)) {
                Add-Finding -Severity INFO -Category 'SCANNER_TEST_MARKER_REFERENCE' -Title 'Reviewed scanner test data references a reported marker' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $match.Index) -SourceContext 'scanner-test-reference' -Evidence ("ruleId={0}; the exact distribution-relative path and normalized source SHA-256 match the reviewed regression source. Other checks remain active." -f $id) -Recommendation 'Retain as test context; changed source and external copies are evaluated normally.' -RiskType inventory -Confidence high -Check ScannerSelf -RuleId $id
            }
            else {
                Add-Finding -Severity $severity -Category $id.ToUpperInvariant() -Title $title -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $match.Index) -Evidence $notes -Recommendation 'Review the file context manually and update local IOC data if this is no longer relevant.' -SourceId ([string](Get-PropertyValue $patternIoc 'sourceId')) -RuleId $id
            }
        }
        catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
            $elapsed=[int64](1000.0*([Diagnostics.Stopwatch]::GetTimestamp()-$patternStarted)/[Diagnostics.Stopwatch]::Frequency)
            $stepName='Scan-LocalSuspiciousTextPatterns.'+[string](Get-PropertyValue $patternIoc 'id')
            Register-ScannerRegexTimeout -StepName $stepName -File $File -Exception $_.Exception -ElapsedMs $elapsed
            Register-ScannerStepPerformance -Name $stepName -ElapsedMs $elapsed -TimedOut $true -File $File -Nested
            continue
        }
        catch {
            $iocPatternPath = Join-Path $script:BaseDir 'iocs\suspicious-patterns.json'
            $patternId = [string](Get-PropertyValue $patternIoc 'id')
            if ([string]::IsNullOrEmpty($patternId)) { $patternId = 'unknown' }
            Add-Finding -Severity 'WARN' -Category 'LOCAL_IOC_PATTERN_INVALID' -Title 'Local suspicious regex could not be evaluated' -Path $iocPatternPath -Evidence ("Local suspicious pattern id ignored: {0}" -f $patternId) -Recommendation 'Fix the regex in iocs/suspicious-patterns.json.'
        }
    }
}

function Scan-GlassWormBehavior {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    if (Test-IsScannerSelfIocReferencePath $File.FullName) {
        if (Test-GlassWormC2ChannelMarker $Text) {
            Add-ScanStat -Name 'scannerArtifactIocReferencesAggregated'
        }
        return
    }
    if (-not (Test-GlassWormC2ChannelMarker $Text)) { return }

    $textContext = Get-TextContext -File $File
    $sourceContext = Get-SourceContext $File.FullName
    $aiRole = Get-AiPathRole $File.FullName
    if ($sourceContext -in @('reference-text','session-log','cache-data') -or $aiRole -in @('reference-text','session-log','cache-data')) {
        $aggregateRole = $sourceContext
        if ($aggregateRole -notin @('reference-text','session-log','cache-data')) {
            $aggregateRole = $aiRole
        }
        Add-AiContextAggregate -Role $aggregateRole
        return
    }

    $compound = Test-GlassWormExecutionOrExfilCompound $Text
    if ($compound) {
        Add-Finding -Severity 'DANGER' -Category 'GLASSWORM_C2_EXECUTION_OR_EXFIL_PATTERN' -Title 'GlassWorm-style C2 marker appears with execution or exfil pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|sfrclak\.com|dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)') -Evidence ("context={0}; sourceContext={1}; compoundPattern=c2-marker-with-execution-or-exfil" -f $textContext, $sourceContext) -Recommendation 'Preserve evidence and inspect this file from a trusted editor before running related tooling.' -RiskType 'fetch-execute' -Confidence 'high'
        return
    }

    if ($textContext -in @('code','execution-config')) {
        if (Test-VerifiedSelfTestMarkerReference -File $File -Text $Text -RuleId 'glassworm-c2-marker') {
            Add-Finding -Severity INFO -Category 'SCANNER_TEST_MARKER_REFERENCE' -Title 'Reviewed scanner workflow generates a marker fixture' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'mainnet-beta') -SourceContext 'scanner-test-reference' -Evidence 'The shipped validation workflow matches its reviewed source SHA-256. This marker is fixture data; execution/exfiltration compound checks still ran.' -Recommendation 'Retain as test context; edited workflows are evaluated normally.' -RiskType inventory -Confidence high -Check InvisibleUnicode -RuleId 'glassworm-c2-marker'
        }
        else {
            Add-Finding -Severity 'WARN' -Category 'GLASSWORM_C2_MARKER_IN_EXECUTABLE_CONTEXT' -Title 'GlassWorm-style C2 marker appears in executable context' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)') -Evidence ("context={0}; sourceContext={1}; no nearby execution or exfil pattern found" -f $textContext, $sourceContext) -Recommendation 'Verify whether this C2-like channel usage is expected.' -RiskType 'posture' -Confidence 'medium'
        }
    }
    else {
        Add-Finding -Severity 'INFO' -Category 'GLASSWORM_C2_MARKER_TEXT' -Title 'GlassWorm-style C2 marker appears in non-executable text' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3)') -Evidence ("context={0}; no nearby execution or exfil pattern found" -f $textContext) -Recommendation 'Treat as low priority unless another finding points to the same file.' -RiskType 'posture' -Confidence 'low'
    }
}

function Scan-ReferenceTextSecuritySamples {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    if ((Get-AiPathRole $File.FullName) -ne 'reference-text') { return }
    if (Test-ReferenceTextExecutableSamplePattern $Text) {
        Add-ScanStat -Name 'aiReferenceExecutableSampleAggregated'
    }
}

function Test-AiTokenPathReference {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(\.codex\\+auth\.json|CODEX_HOME|\.claude|\.cursor|\.windsurf)')
}

function Get-ScannerExceptionEvidence {
    param($ErrorRecord, [string]$Phase)
    $errorType = 'unknown'
    $message = ''
    $scriptLine = ''
    if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.Exception) {
        $errorType = $ErrorRecord.Exception.GetType().FullName
        $message = $ErrorRecord.Exception.Message
    }
    if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.InvocationInfo) {
        $scriptLine = [string]$ErrorRecord.InvocationInfo.ScriptLineNumber
    }
    return ("ExceptionType={0}; Phase={1}; ScriptLine={2}; Message={3}" -f $errorType, $Phase, $scriptLine, $message)
}

function Get-RegexTimeoutDetails {
    param([System.Exception]$Exception)
    $cause=$Exception
    for ($i=0; $i -lt 16 -and $null -ne $cause; $i++) {
        if ($cause -is [System.Text.RegularExpressions.RegexMatchTimeoutException]) {
            $sha=[Security.Cryptography.SHA256]::Create()
            try { $digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$cause.Pattern)) }
            finally { $sha.Dispose() }
            return [ordered]@{
                ruleId=('regex-sha256-'+([BitConverter]::ToString($digest).Replace('-','').Substring(0,16).ToLowerInvariant()))
                timeoutMs=[int64]$cause.MatchTimeout.TotalMilliseconds
            }
        }
        $cause=$cause.InnerException
    }
    return [ordered]@{ ruleId='regex-unknown'; timeoutMs=[int64]($script:RegexMatchTimeoutSeconds*1000) }
}

function Register-ScannerActivityPerformance {
    param([string]$Name, [int64]$ElapsedTicks, [System.IO.FileInfo]$File)
    if ($null -eq $script:Context -or $null -eq $script:Context.scannerActivityPerformance) { return }
    $stats=$script:Context.scannerActivityPerformance
    if (-not $stats.ContainsKey($Name)) {
        if ($stats.Count -ge 32) { return }
        $stats[$Name]=[ordered]@{ activity=$Name; attempts=0; elapsedTicks=0L; maxElapsedTicks=0L }
    }
    $entry=$stats[$Name]; $entry.attempts++
    $entry.elapsedTicks += $ElapsedTicks
    if ($ElapsedTicks -gt $entry.maxElapsedTicks) { $entry.maxElapsedTicks=$ElapsedTicks }
    $elapsedMs=1000.0*$ElapsedTicks/[Diagnostics.Stopwatch]::Frequency
    if ($elapsedMs -ge $script:SlowScannerStepThresholdMs -and $null -ne $File -and $null -ne $script:Context.slowScannerActivities) {
        $slow=$script:Context.slowScannerActivities
        $candidate=[ordered]@{activity=$Name;path=(ConvertTo-RedactedPath $File.FullName);elapsedMs=[Math]::Round($elapsedMs,3);partition=($Name -in @('Enumeration','ProjectDiscovery','TargetSelection','FileProcessing'))}
        if ($slow.Count -lt 20) { Add-ListItem $slow $candidate }
        else {
            $minimum=0
            for($i=1;$i -lt $slow.Count;$i++){if($slow[$i].elapsedMs -lt $slow[$minimum].elapsedMs){$minimum=$i}}
            if($elapsedMs -gt $slow[$minimum].elapsedMs){$slow[$minimum]=$candidate}
        }
    }
}

function Get-ScannerPerformanceSummary {
    $execution=Get-ScanExecutionSummary
    $activities=New-ArrayList
    $partitionTicks=0L
    foreach ($entry in @($script:Context.scannerActivityPerformance.Values | Sort-Object { [string]$_.activity })) {
        $partition=([string]$entry.activity -in @('Enumeration','ProjectDiscovery','TargetSelection','FileProcessing'))
        if ($partition) { $partitionTicks += [int64]$entry.elapsedTicks }
        Add-ListItem $activities ([ordered]@{
            activity=[string]$entry.activity; attempts=[int]$entry.attempts
            elapsedMs=[Math]::Round(1000.0*$entry.elapsedTicks/[Diagnostics.Stopwatch]::Frequency,3)
            maxElapsedMs=[Math]::Round(1000.0*$entry.maxElapsedTicks/[Diagnostics.Stopwatch]::Frequency,3)
            partition=$partition
        })
    }
    $steps=@($script:Context.scannerStepPerformance.Values | Sort-Object { [string]$_.step })
    $partitionMs=1000.0*$partitionTicks/[Diagnostics.Stopwatch]::Frequency
    return [ordered]@{
        slowStepThresholdMs=[int]$script:SlowScannerStepThresholdMs
        steps=@($steps)
        activities=@($activities.ToArray())
        executionElapsedMs=[int64]$execution.elapsedMs
        partitionElapsedMs=[Math]::Round($partitionMs,3)
        otherElapsedMs=[Math]::Round([Math]::Max(0.0,([double]$execution.elapsedMs-$partitionMs)),3)
        timingScope='Scan execution; report formatting/writes excluded. Partition activities do not overlap. Reading and step timings are nested in their containing activities; do not add them to the partition total.'
        slowStepsLimit=20
        slowSteps=@($script:Context.slowScannerSteps.ToArray() | Sort-Object { [int64]$_.elapsedMs } -Descending)
        slowActivitiesLimit=20
        slowActivities=@($script:Context.slowScannerActivities.ToArray() | Sort-Object { [double]$_.elapsedMs } -Descending)
    }
}

function Register-ScannerStepPerformance {
    param([string]$Name, [int64]$ElapsedMs, [bool]$TimedOut, [System.IO.FileInfo]$File, [switch]$Nested)
    if ($null -eq $script:Context.scannerStepPerformance) { return }
    $stats=$script:Context.scannerStepPerformance
    if (-not $stats.ContainsKey($Name)) {
        if ($stats.Count -ge 128) { return }
        $stats[$Name]=[ordered]@{ step=$Name; attempts=0; elapsedMs=0L; maxElapsedMs=0L; slowCount=0; timeoutCount=0; nested=[bool]$Nested }
    }
    $entry=$stats[$Name]
    $entry.attempts++
    $entry.elapsedMs += $ElapsedMs
    if ($ElapsedMs -gt $entry.maxElapsedMs) { $entry.maxElapsedMs=$ElapsedMs }
    if ($ElapsedMs -ge $script:SlowScannerStepThresholdMs) { $entry.slowCount++ }
    if ($TimedOut) { $entry.timeoutCount++ }
    if ($ElapsedMs -ge $script:SlowScannerStepThresholdMs -and $null -ne $File -and $null -ne $script:Context.slowScannerSteps) {
        $slow=$script:Context.slowScannerSteps
        $candidate=[ordered]@{ step=$Name; path=(ConvertTo-RedactedPath $File.FullName); elapsedMs=$ElapsedMs; timedOut=$TimedOut }
        if ($slow.Count -lt 20) { Add-ListItem $slow $candidate }
        else {
            $minimum=0
            for ($i=1;$i -lt $slow.Count;$i++) { if ($slow[$i].elapsedMs -lt $slow[$minimum].elapsedMs) { $minimum=$i } }
            if ($ElapsedMs -gt $slow[$minimum].elapsedMs) { $slow[$minimum]=$candidate }
        }
    }
}

function Register-ScannerRegexTimeout {
    param([string]$StepName, [System.IO.FileInfo]$File, [System.Exception]$Exception, [int64]$ElapsedMs)
    $path=if ($null -ne $File) { $File.FullName } else { $null }
    $timeout=Get-RegexTimeoutDetails -Exception $Exception
    Add-ScanStat -Name 'regexMatchTimeouts'
    $script:Context.coverage.traversalComplete=$false
    if (-not [string]::IsNullOrWhiteSpace($path)) {
        $kind=Get-CoverageCandidateKindForFile -File $File
        Register-CoverageFailure -Scope 'candidate' -Path $path -Kind $kind -FailureType 'regex-timeout' -Critical (Test-IsCriticalCandidate -Path $path -Kind $kind)
    }
    Add-Finding -Severity 'WARN' -Category 'REGEX_SCAN_TIMEOUT' -Title 'A bounded regular-expression check timed out for one file' -Path $path -Evidence ("step={0}; ruleId={1}; timeoutMs={2}; elapsedMs={3}; pattern and target text are not included." -f $StepName,$timeout.ruleId,$timeout.timeoutMs,$ElapsedMs) -Recommendation 'Review this file and ruleId. The named rule or containing step did not finish; other checks continued. Narrowing a folder alone may not fix the same file/rule timeout.' -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
    if (-not $Quiet) { Write-Host ("      regex timeout: step={0}; ruleId={1}; current={2}; continued with remaining checks" -f $StepName,$timeout.ruleId,(ConvertTo-RedactedPath $path)) }
}

function Invoke-ScannerStep {
    param(
        [Parameter(Mandatory=$true)][string]$StepName,
        [System.IO.FileInfo]$File,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    $oldPhase = $script:CurrentPhase
    $script:CurrentPhase = $StepName
    if ($null -ne $script:Context.execution) { $script:Context.execution.lastStep=$StepName }
    $path = $null
    if ($null -ne $File) {
        $path = $File.FullName
    }
    $showDetailedProgress = $false
    if ($null -ne $File) {
        try { $showDetailedProgress = ($script:VerboseProgressEnabled -and [int64]$File.Length -ge $script:DetailedProgressFileMinBytes) } catch { }
    }
    Write-ScanHeartbeat -Stage $StepName -Path $path -Force:$showDetailedProgress
    $stepStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut=$false
    try {
        & $ScriptBlock
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        $timedOut=$true
        Register-ScannerRegexTimeout -StepName $StepName -File $File -Exception $_.Exception -ElapsedMs $stepStopwatch.ElapsedMilliseconds
    }
    catch {
        Add-ScanStat -Name 'scannerFileErrors'
        Add-Finding -Severity 'WARN' -Category 'SCANNER_FILE_ERROR' -Title 'Scanner step failed for one file' -Path $path -Evidence (Get-ScannerExceptionEvidence -ErrorRecord $_ -Phase $StepName) -Recommendation 'Review scanner logs and rerun parser validation. The scanner continued with remaining checks.'
    }
    finally {
        $stepStopwatch.Stop()
        Register-ScannerStepPerformance -Name $StepName -ElapsedMs $stepStopwatch.ElapsedMilliseconds -TimedOut $timedOut -File $File
        if (-not $Quiet -and $script:VerboseProgressEnabled -and $stepStopwatch.ElapsedMilliseconds -ge $script:SlowScannerStepThresholdMs) {
            Write-Host ("      slow step completed: stage={0}; current={1}; stepElapsedMs={2}" -f $StepName, (ConvertTo-RedactedPath $path), $stepStopwatch.ElapsedMilliseconds)
        }
        $script:CurrentPhase = $oldPhase
    }
}

function Get-TextContext {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) { return 'text' }
    $path = $File.FullName.ToLowerInvariant()
    $name = $File.Name.ToLowerInvariant()
    $ext = $File.Extension.ToLowerInvariant()

    $aiRole = Get-AiPathRole $File.FullName
    if ($aiRole -eq 'active-ai-config') { return 'execution-config' }
    if ($aiRole -eq 'executable-tooling') { return 'code' }
    if ($aiRole -in @('reference-text','session-log')) { return 'documentation' }
    if ($aiRole -in @('cache-data','plugin-metadata')) { return 'text' }
    if (Test-IsDependencyMetadataPath $File.FullName) { return 'dependency-metadata' }
    if ($name -match '^(readme|license|licence|changelog|changes|notice)(\..*)?$') { return 'documentation' }
    if ($ext -in @('.md','.markdown','.rst','.txt','.adoc')) { return 'documentation' }
    if ($path -match '\\(\.github\\workflows|\.git\\hooks|\.husky|\.vscode|\.cursor\\rules|\.github\\instructions)\\') { return 'execution-config' }
    if ($name -in @('mcp.json','.mcp.json','claude_desktop_config.json','settings.json','agents.md','agents.override.md','claude.md','gemini.md','copilot-instructions.md','.cursorrules')) { return 'execution-config' }
    if ($ext -in @('.js','.mjs','.cjs','.jsx','.ts','.tsx','.ps1','.psm1','.psd1','.bat','.cmd','.sh','.bash','.zsh','.py','.rb','.php','.pl','.psql')) { return 'code' }
    if ($name -in @('package.json','pyproject.toml','composer.json')) { return 'execution-config' }
    return 'text'
}

function Get-CodePointLabel {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return 'unknown' }
    try {
        if ($Value.Length -ge 2 -and [System.Char]::IsHighSurrogate($Value[0]) -and [System.Char]::IsLowSurrogate($Value[1])) {
            return ('U+{0:X5}' -f [System.Char]::ConvertToUtf32($Value[0], $Value[1]))
        }
        return ('U+{0:X4}' -f [int][char]$Value[0])
    }
    catch {
        return 'unknown'
    }
}

function Test-IsDocEmojiVariationSelector {
    param([string]$CodePoint, [string]$TextContext)
    if ($TextContext -notin @('documentation','dependency-metadata')) {
        return $false
    }
    return ($CodePoint -eq 'U+FE0E' -or $CodePoint -eq 'U+FE0F')
}

function Test-InvisibleUnicodeExecutionNear {
    param([string]$Text, [int]$Index)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $start = [Math]::Max(0, $Index - 240)
    $length = [Math]::Min($Text.Length - $start, 480)
    if ($length -le 0) { return $false }
    $window = $Text.Substring($start, $length)
    return ($window -match '(?is)(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|FromBase64String|Buffer\.from|atob\s*\(|base64|String\.fromCharCode|decodeURIComponent)')
}

function Get-GlassWormVariationSelectorDecoderSignatureMatch {
    param([string]$Text)
    $notFound = [ordered]@{ success = $false; index = -1 }
    if ([string]::IsNullOrEmpty($Text)) { return $notFound }

    foreach ($literal in @('.codePointAt','FE00','FE0F','E0100','E01EF')) {
        if ($Text.IndexOf($literal, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return $notFound
        }
    }

    $assignmentPattern = '(?is)(?<codePointVariable>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;{}\r\n]{0,256}?(?<codePointCall>\.codePointAt\s*\([^)}\r\n]{0,64}\))'
    $searchIndex = 0
    $candidateCount = 0
    while ($searchIndex -lt $Text.Length -and $candidateCount -lt 256) {
        $callIndex = $Text.IndexOf('.codePointAt', $searchIndex, [System.StringComparison]::OrdinalIgnoreCase)
        if ($callIndex -lt 0) { break }
        $candidateCount++
        $searchIndex = $callIndex + 12

        $assignmentWindowStart = [Math]::Max(0, $callIndex - 384)
        $assignmentWindowLength = [Math]::Min(512, $Text.Length - $assignmentWindowStart)
        if ($assignmentWindowLength -le 0) { continue }
        $assignmentWindow = $Text.Substring($assignmentWindowStart, $assignmentWindowLength)
        foreach ($assignment in @(Get-BoundedTextRegexMatches -Text $assignmentWindow -Pattern $assignmentPattern -MaximumMatches 8)) {
            $absoluteCallIndex = $assignmentWindowStart + [int]$assignment.Groups['codePointCall'].Index
            if ($absoluteCallIndex -ne $callIndex) { continue }
            $variableName = [string]$assignment.Groups['codePointVariable'].Value
            if ([string]::IsNullOrEmpty($variableName)) { continue }

            $windowStart = $assignmentWindowStart + [int]$assignment.Index
            $windowLength = [Math]::Min(8192, $Text.Length - $windowStart)
            if ($windowLength -le 0) { continue }
            $window = $Text.Substring($windowStart, $windowLength)
            $variableToken = '(?<![A-Za-z0-9_$])' + [regex]::Escape($variableName) + '(?![A-Za-z0-9_$])'
            $requiredPatterns = @(
                ('(?is)(?:{0}\s*>=\s*0x0*FE00\b|0x0*FE00\b\s*<=\s*{0})' -f $variableToken),
                ('(?is)(?:{0}\s*<=\s*0x0*FE0F\b|0x0*FE0F\b\s*>=\s*{0})' -f $variableToken),
                ('(?is){0}\s*-\s*0x0*FE00\b' -f $variableToken),
                ('(?is)(?:{0}\s*>=\s*0x0*E0100\b|0x0*E0100\b\s*<=\s*{0})' -f $variableToken),
                ('(?is)(?:{0}\s*<=\s*0x0*E01EF\b|0x0*E01EF\b\s*>=\s*{0})' -f $variableToken),
                ('(?is){0}\s*-\s*0x0*E0100\b' -f $variableToken)
            )
            $isDecoder = $true
            foreach ($requiredPattern in $requiredPatterns) {
                if (-not (Test-BoundedTextRegex -Text $window -Pattern $requiredPattern)) {
                    $isDecoder = $false
                    break
                }
            }
            if ($isDecoder) {
                return [ordered]@{
                    success = $true
                    index = $callIndex
                }
            }
        }
    }
    return $notFound
}

function Test-GlassWormDecoderExecutionOrExfilPattern {
    param([string]$Text, [int]$Index)
    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0 -or $Index -ge $Text.Length) { return $false }
    $windowStart = [Math]::Max(0, $Index - 4096)
    $windowLength = [Math]::Min(8192, $Text.Length - $windowStart)
    if ($windowLength -le 0) { return $false }
    $window = $Text.Substring($windowStart, $windowLength)
    if (Test-ExternalExecutionPattern $window) { return $true }
    if (Test-SecretHarvestingExternalSendPattern $window) { return $true }
    return (Test-BoundedTextRegex -Text $window -Pattern '(?is)(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|FromBase64String|Buffer\.from|atob\s*\(|fetch\s*\(|child_process|process\.env|GITHUB_TOKEN|NPM_TOKEN|\.npmrc|\.git-credentials)')
}

function Test-DecodedVariationSelectorPayloadMarker {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(eval\s*\(|Function\s*\(|Buffer\.from|atob\s*\(|FromBase64String|fetch\s*\(|child_process|process\.env|GITHUB_TOKEN|NPM_TOKEN|\.npmrc|\.git-credentials|Invoke-Expression)')
}

function New-VariationSelectorClusterResult {
    param(
        [int]$Index,
        [int]$Count,
        [bool]$ContainsSupplementary,
        $ByteValues
    )
    if ($Count -lt 3 -or $null -eq $ByteValues) { return $null }

    $decodeCount = [int]$ByteValues.Count
    $decodeBytes = New-Object byte[] $decodeCount
    if ($decodeCount -gt 0) {
        $ByteValues.CopyTo(0, $decodeBytes, 0, $decodeCount)
    }
    $decodedText = ''
    $decodeSucceeded = $false
    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $decodedText = $strictUtf8.GetString($decodeBytes)
        $decodeSucceeded = $true
    }
    catch {
        $decodedText = ''
    }

    return [ordered]@{
        index = $Index
        count = $Count
        containsSupplementary = $ContainsSupplementary
        decodeSucceeded = $decodeSucceeded
        decodeTruncated = ($Count -gt $decodeCount)
        decodedMarker = ($decodeSucceeded -and (Test-DecodedVariationSelectorPayloadMarker $decodedText))
    }
}

function Get-VariationSelectorAnalysis {
    param([string]$Text)

    $clusters = New-ArrayList
    $total = 0
    $maxConsecutive = 0
    $containsSupplementary = $false
    $clusterStart = -1
    $clusterCount = 0
    $clusterContainsSupplementary = $false
    $clusterBytes = New-Object 'System.Collections.Generic.List[byte]'
    $clusterEnd = -1
    $selectorPattern = '[\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]'
    $selectorRegex = New-Object System.Text.RegularExpressions.Regex($selectorPattern, [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
    $selectorMatch = $selectorRegex.Match($Text)
    $selectorAnalysisTruncated = $false

    while ($selectorMatch.Success -and $total -lt $script:VariationSelectorMatchLimit) {
        $matchIndex = [int]$selectorMatch.Index
        $codeUnitLength = [int]$selectorMatch.Length
        if ($clusterCount -gt 0 -and $matchIndex -ne $clusterEnd) {
            if ($clusterCount -gt $maxConsecutive) { $maxConsecutive = $clusterCount }
            $cluster = New-VariationSelectorClusterResult -Index $clusterStart -Count $clusterCount -ContainsSupplementary $clusterContainsSupplementary -ByteValues $clusterBytes
            if ($null -ne $cluster) { Add-ListItem $clusters $cluster }
            $clusterStart = -1
            $clusterCount = 0
            $clusterContainsSupplementary = $false
            $clusterBytes = New-Object 'System.Collections.Generic.List[byte]'
        }

        $byteValue = -1
        $isSupplementary = ($codeUnitLength -eq 2)
        if ($isSupplementary) {
            $byteValue = ([int][char]$selectorMatch.Value[1] - 0xDD00) + 16
        }
        else {
            $byteValue = [int][char]$selectorMatch.Value[0] - 0xFE00
        }
        if ($clusterStart -lt 0) { $clusterStart = $matchIndex }
        $clusterCount++
        $total++
        if ($clusterBytes.Count -lt $script:VariationSelectorDecodeMaxBytes) {
            $clusterBytes.Add([byte]$byteValue)
        }
        if ($isSupplementary) {
            $containsSupplementary = $true
            $clusterContainsSupplementary = $true
        }
        $clusterEnd = $matchIndex + $codeUnitLength
        $selectorMatch = $selectorMatch.NextMatch()
    }

    if ($selectorMatch.Success) {
        $selectorAnalysisTruncated = $true
        $tailStart = [int]$selectorMatch.Index
        $longClusterRegex = New-Object System.Text.RegularExpressions.Regex(('(?:{0}){{10}}' -f $selectorPattern), [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
        $tailCluster = $longClusterRegex.Match($Text, $tailStart)
        if (-not $tailCluster.Success) {
            $clusterRegex = New-Object System.Text.RegularExpressions.Regex(('(?:{0}){{3}}' -f $selectorPattern), [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
            $tailCluster = $clusterRegex.Match($Text, $tailStart)
        }
        if ($tailCluster.Success) {
            $tailClusterCount = if ($tailCluster.Length -ge 10) { 10 } else { 3 }
            if ($tailClusterCount -gt $maxConsecutive) { $maxConsecutive = $tailClusterCount }
            Add-ListItem $clusters ([ordered]@{
                index = [int]$tailCluster.Index
                count = $tailClusterCount
                containsSupplementary = ($tailCluster.Value -match '\uDB40[\uDD00-\uDDEF]')
                decodeSucceeded = $false
                decodeTruncated = $true
                decodedMarker = $false
            })
        }
    }

    if ($clusterCount -gt 0) {
        if ($clusterCount -gt $maxConsecutive) { $maxConsecutive = $clusterCount }
        $cluster = New-VariationSelectorClusterResult -Index $clusterStart -Count $clusterCount -ContainsSupplementary $clusterContainsSupplementary -ByteValues $clusterBytes
        if ($null -ne $cluster) { Add-ListItem $clusters $cluster }
    }

    $decodedClusterCount = 0
    $decodeFailures = 0
    $decodeTruncatedClusters = 0
    $decodedMarker = $false
    foreach ($cluster in @($clusters)) {
        if ([bool]$cluster.decodeSucceeded) { $decodedClusterCount++ } else { $decodeFailures++ }
        if ([bool]$cluster.decodeTruncated) { $decodeTruncatedClusters++ }
        if ([bool]$cluster.decodedMarker) { $decodedMarker = $true }
    }

    return [ordered]@{
        totalVariationSelectors = $total
        maxConsecutiveVariationSelectors = $maxConsecutive
        containsSupplementaryVariationSelector = $containsSupplementary
        clusters = @($clusters.ToArray())
        decodedClusterCount = $decodedClusterCount
        decodeFailures = $decodeFailures
        decodeTruncatedClusters = $decodeTruncatedClusters
        selectorAnalysisTruncated = $selectorAnalysisTruncated
        decodedMarker = $decodedMarker
    }
}

function Scan-InvisibleUnicode {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ([string]::IsNullOrEmpty($Text)) {
        return
    }
    $bmpPattern = '[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F]'
    $supplementPattern = '\uDB40[\uDD00-\uDDEF]'
    $bmp = Get-BoundedTextRegexMatch -Text $Text -Pattern $bmpPattern
    $supplement = Get-BoundedTextRegexMatch -Text $Text -Pattern $supplementPattern
    $decoderMatch = Get-GlassWormVariationSelectorDecoderSignatureMatch $Text
    $decoderSignature = [bool]$decoderMatch.success
    if (-not $bmp.Success -and -not $supplement.Success -and -not $decoderSignature) {
        return
    }

    $sourceContext = Get-SourceContext $File.FullName
    $dependencyOrGenerated = Test-IsDependencyOrGeneratedArtifactPath $File.FullName
    $targetedDependencyPath = ($dependencyOrGenerated -and (Test-IsTargetedScanPath $File.FullName))
    if ($sourceContext -in @('session-log','cache-data')) {
        Add-AiContextAggregate -Role $sourceContext
        return
    }
    if ($sourceContext -eq 'reference-text' -and $decoderSignature -and -not $bmp.Success -and -not $supplement.Success) {
        Add-AiContextAggregate -Role $sourceContext
        return
    }

    $textContext = Get-TextContext -File $File
    $analysis = Get-VariationSelectorAnalysis $Text
    if (Test-IsScannerSelfIocReferencePath $File.FullName) {
        if ($decoderSignature -or [int]$analysis.totalVariationSelectors -gt 0) {
            Add-ScanStat -Name 'scannerArtifactIocReferencesAggregated'
        }
        return
    }

    $isExecutableContext = ($textContext -in @('code','execution-config'))
    $hasCluster = ([int]$analysis.maxConsecutiveVariationSelectors -ge 3)
    $decodedMarkerCluster = $null
    $longCluster = $null
    foreach ($candidateCluster in @($analysis.clusters)) {
        if ($null -eq $decodedMarkerCluster -and [bool]$candidateCluster.decodedMarker) {
            $decodedMarkerCluster = $candidateCluster
        }
        if ($null -eq $longCluster -and [int]$candidateCluster.count -ge 10) {
            $longCluster = $candidateCluster
        }
    }
    $hasLongExecutableCluster = ($isExecutableContext -and $null -ne $longCluster)
    $decoderExecutionOrExfilNear = ($decoderSignature -and (Test-GlassWormDecoderExecutionOrExfilPattern -Text $Text -Index ([int]$decoderMatch.index)))
    $decoderCompound = ($decoderSignature -and $isExecutableContext -and $hasCluster)
    $decodedPayloadCompound = ($null -ne $decodedMarkerCluster)
    $analysisEvidence = (
        'variationSelectorCount={0}; decoderExecutionOrExfilNear={1}; maxConsecutiveVariationSelectors={2}; containsSupplementary={3}; decodedClusters={4}; decodeFailures={5}; decodeTruncatedClusters={6}; selectorAnalysisTruncated={7}; decodedMarker={8}; context={9}' -f
        [int]$analysis.totalVariationSelectors,
        ([bool]$decoderExecutionOrExfilNear).ToString().ToLowerInvariant(),
        [int]$analysis.maxConsecutiveVariationSelectors,
        ([bool]$analysis.containsSupplementaryVariationSelector).ToString().ToLowerInvariant(),
        [int]$analysis.decodedClusterCount,
        [int]$analysis.decodeFailures,
        [int]$analysis.decodeTruncatedClusters,
        ([bool]$analysis.selectorAnalysisTruncated).ToString().ToLowerInvariant(),
        ([bool]$analysis.decodedMarker).ToString().ToLowerInvariant(),
        $textContext
    )

    if ($decoderCompound) {
        Add-Finding -Severity 'DANGER' -Category 'GLASSWORM_VARIATION_SELECTOR_DECODER_COMPOUND' -Title 'GlassWorm-style Variation Selector decoder appears with a payload cluster' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index ([int]$decoderMatch.index)) -Evidence ("decoderSignature=true; {0}" -f $analysisEvidence) -Recommendation 'Preserve the file and inspect it from a trusted editor without executing the decoder or decoded content.' -RiskType 'posture' -Confidence 'high' -Check 'InvisibleUnicode' -DetectionMethod 'static-file'
        return
    }
    if ($decodedPayloadCompound) {
        Add-Finding -Severity 'DANGER' -Category 'GLASSWORM_VARIATION_SELECTOR_DECODED_PAYLOAD' -Title 'Variation Selector cluster statically decodes to execution or secret-access markers' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index ([int]$decodedMarkerCluster.index)) -Evidence $analysisEvidence -Recommendation 'Preserve the file and review provenance. The scanner decoded text in memory for static matching only and did not execute or report the payload.' -RiskType 'posture' -Confidence 'high' -Check 'InvisibleUnicode' -DetectionMethod 'static-file'
        return
    }
    if ($hasLongExecutableCluster) {
        Add-Finding -Severity 'DANGER' -Category 'GLASSWORM_VARIATION_SELECTOR_CLUSTER' -Title 'Long consecutive Variation Selector cluster appears in executable context' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index ([int]$longCluster.index)) -Evidence $analysisEvidence -Recommendation 'Preserve the file and inspect the hidden cluster from a trusted editor without executing it.' -RiskType 'posture' -Confidence 'high' -Check 'InvisibleUnicode' -DetectionMethod 'static-file'
        return
    }
    if ($decoderSignature) {
        Add-Finding -Severity 'WARN' -Category 'GLASSWORM_VARIATION_SELECTOR_DECODER' -Title 'GlassWorm-style Variation Selector decoder signature detected' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index ([int]$decoderMatch.index)) -Evidence ("decoderSignature=true; {0}" -f $analysisEvidence) -Recommendation 'Review whether this decoder is expected and compare it with trusted source.' -RiskType 'posture' -Confidence 'medium' -Check 'InvisibleUnicode' -DetectionMethod 'static-file'
        return
    }
    if ([bool]$analysis.selectorAnalysisTruncated) {
        $script:Context.coverage.traversalComplete = $false
        Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind (Get-CoverageCandidateKindForFile -File $File) -FailureType 'variation-selector-limit'
        Add-Finding -Severity 'WARN' -Category 'INVISIBLE_UNICODE_ANALYSIS_LIMIT_REACHED' -Title 'Variation Selector analysis reached its bounded match limit' -Path $File.FullName -Line 1 -Evidence ("{0}; matchLimit={1}" -f $analysisEvidence, $script:VariationSelectorMatchLimit) -Recommendation 'Review this unusually selector-dense file offline. Other files and checks continued.' -RiskType 'limitation' -Confidence 'high' -Check 'InvisibleUnicode' -DetectionMethod 'static-file'
        return
    }
    if ($hasCluster) {
        Add-Finding -Severity 'WARN' -Category 'GLASSWORM_VARIATION_SELECTOR_CLUSTER' -Title 'Consecutive Variation Selector cluster detected' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index ([int]$analysis.clusters[0].index)) -Evidence $analysisEvidence -Recommendation 'Review whether the cluster is intentional. The decoded text was not included in the report.' -RiskType 'posture' -Confidence 'medium' -Check 'InvisibleUnicode' -DetectionMethod 'static-file'
        return
    }

    $matches = New-ArrayList
    foreach ($m in @(Get-BoundedTextRegexMatches -Text $Text -Pattern $bmpPattern)) {
        Add-ListItem $matches $m
    }
    foreach ($m in @(Get-BoundedTextRegexMatches -Text $Text -Pattern $supplementPattern)) {
        Add-ListItem $matches $m
    }

    $selected = $null
    $selectedCodePoint = $null
    foreach ($m in @($matches)) {
        $codePoint = Get-CodePointLabel $m.Value
        if ($codePoint -eq 'U+FE0E' -or $codePoint -eq 'U+FE0F') {
            if (($textContext -in @('code','execution-config')) -and (Test-InvisibleUnicodeExecutionNear -Text $Text -Index $m.Index)) {
                $selected = $m
                $selectedCodePoint = $codePoint
                break
            }
            Add-ScanStat -Name 'unicodeVariationSelectorsAggregated'
            continue
        }
        $selected = $m
        $selectedCodePoint = $codePoint
        break
    }
    if ($null -eq $selected) {
        return
    }

    $line = Get-LineNumberForIndex -Text $Text -Index $selected.Index
    if ($isExecutableContext -and (Test-InvisibleUnicodeExecutionNear -Text $Text -Index $selected.Index)) {
        if ($dependencyOrGenerated -and -not $targetedDependencyPath) {
            Add-Finding -Severity 'WARN' -Category 'INVISIBLE_UNICODE_EXECUTION_COMPOUND' -Title 'Dependency or generated code contains invisible Unicode near an execution pattern' -Path $File.FullName -Line $line -Evidence ("codePoint={0}; context={1}; compoundPattern=execution-or-decoder-nearby; dependencyOrGenerated=true" -f $selectedCodePoint, $textContext) -Recommendation 'Verify package or generated-artifact provenance; a single local compound without a selector cluster or decoded payload is not treated as confirmed malicious behavior.' -RiskType 'posture' -Confidence 'medium' -Check 'InvisibleUnicode' -DetectionMethod 'static-file'
        }
        else {
            Add-Finding -Severity 'DANGER' -Category 'INVISIBLE_UNICODE_EXECUTION_COMPOUND' -Title 'Invisible Unicode appears near decoder or execution pattern' -Path $File.FullName -Line $line -Evidence ("codePoint={0}; context={1}; compoundPattern=execution-or-decoder-nearby" -f $selectedCodePoint, $textContext) -Recommendation 'Inspect the file from a trusted editor and compare with known-good source.'
        }
    }
    else {
        Add-Finding -Severity 'CAUTION' -Category 'INVISIBLE_UNICODE_PRESENT' -Title 'Invisible Unicode character detected' -Path $File.FullName -Line $line -Evidence ("codePoint={0}; context={1}" -f $selectedCodePoint, $textContext) -Recommendation 'Inspect whether the character is intentional.'
    }
}

function Normalize-Version {
    param([string]$Version)
    if ([string]::IsNullOrEmpty($Version)) { return '' }
    $v = $Version.Trim()
    $m = [regex]::Match($v, '([0-9]+(\.[0-9A-Za-z-]+)+)')
    if ($m.Success) {
        return $m.Groups[1].Value
    }
    return $v.TrimStart('v','^','~','=','>','<',' ')
}

function ConvertTo-PythonPackageVersion {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version) -or $Version.Length -gt 128) { return '' }
    # PEP 440 public/local identity only; constraints and partial matches are never accepted.
    $pattern='\Av?(?:(?<epoch>[0-9]+)!)?(?<release>[0-9]+(?:\.[0-9]+)*)(?:[-_.]?(?<pre>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?<preNumber>[0-9]+)?)?(?:-(?<postNumber1>[0-9]+)|[-_.]?(?<post>post|rev|r)[-_.]?(?<postNumber2>[0-9]+)?)?(?:[-_.]?(?<dev>dev)[-_.]?(?<devNumber>[0-9]+)?)?(?:\+(?<local>[0-9a-z]+(?:[-_.][0-9a-z]+)*))?\z'
    $match=[regex]::Match($Version.Trim(),$pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant,[TimeSpan]::FromSeconds(2))
    if (-not $match.Success) { return '' }
    $normalized=''
    if ($match.Groups['epoch'].Success) {
        $epoch=[regex]::Replace($match.Groups['epoch'].Value,'\A0+(?=[0-9])','')
        if ($epoch -ne '0') { $normalized=$epoch+'!' }
    }
    $release=@($match.Groups['release'].Value.Split('.') | ForEach-Object {[regex]::Replace($_,'\A0+(?=[0-9])','')})
    $normalized+=[string]::Join('.',[string[]]$release)
    if ($match.Groups['pre'].Success) {
        $label=switch ($match.Groups['pre'].Value.ToLowerInvariant()) { 'alpha' {'a'}; 'beta' {'b'}; 'preview' {'rc'}; 'pre' {'rc'}; 'c' {'rc'}; default {$match.Groups['pre'].Value.ToLowerInvariant()} }
        $number=$match.Groups['preNumber'].Value
        if ([string]::IsNullOrEmpty($number)) { $number='0' }
        $normalized+=$label+[regex]::Replace($number,'\A0+(?=[0-9])','')
    }
    if ($match.Groups['post'].Success -or $match.Groups['postNumber1'].Success) {
        $number=if ($match.Groups['postNumber1'].Success) {$match.Groups['postNumber1'].Value} else {$match.Groups['postNumber2'].Value}
        if ([string]::IsNullOrEmpty($number)) { $number='0' }
        $normalized+='.post'+[regex]::Replace($number,'\A0+(?=[0-9])','')
    }
    if ($match.Groups['dev'].Success) {
        $number=$match.Groups['devNumber'].Value
        if ([string]::IsNullOrEmpty($number)) { $number='0' }
        $normalized+='.dev'+[regex]::Replace($number,'\A0+(?=[0-9])','')
    }
    if ($match.Groups['local'].Success) {
        $segments=@($match.Groups['local'].Value.ToLowerInvariant() -split '[-_.]' | ForEach-Object {if ($_ -match '\A[0-9]+\z') {[regex]::Replace($_,'\A0+(?=[0-9])','')} else {$_}})
        $normalized+='+'+[string]::Join('.',[string[]]$segments)
    }
    return $normalized
}

function ConvertTo-PackageIocVersion {
    param([string]$Ecosystem,[string]$Version)
    if ($Ecosystem -ine 'python') { return (Normalize-Version $Version) }
    $normalized=ConvertTo-PythonPackageVersion $Version
    if ([string]::IsNullOrEmpty($normalized)) { return '' }
    $match=[regex]::Match($normalized,'\A(?<epoch>[0-9]+!)?(?<release>[0-9]+(?:\.[0-9]+)*)(?<suffix>.*)\z')
    # Zero padding in the release tuple is equivalent; epoch, pre/post/dev and local parts remain distinct.
    $release=[regex]::Replace($match.Groups['release'].Value,'(?:\.0)+\z','')
    return ($match.Groups['epoch'].Value+$release+$match.Groups['suffix'].Value)
}

function Test-IsExactPackageVersionText {
    param([string]$Version,[string]$Ecosystem='npm')
    if ([string]::IsNullOrWhiteSpace($Version)) { return $false }
    if ($Ecosystem -ieq 'python') { return (-not [string]::IsNullOrEmpty((ConvertTo-PythonPackageVersion $Version))) }
    return ($Version.Trim() -match '^(v|=)?[0-9]+\.[0-9]+\.[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*$')
}

function Add-KnownPackageFinding {
    param(
        [string]$Ecosystem,
        [string]$Name,
        [string]$Version,
        [string]$Path,
        $Line,
        [string]$EvidenceKind = 'text-fallback'
    )
    if ($null -eq $script:Context.iocs) { return }
    $normalizedVersion = if ($Ecosystem -ieq 'python') { ConvertTo-PythonPackageVersion $Version } else { Normalize-Version $Version }
    $ioc = Get-ExactPackageIocMatch -Ecosystem $Ecosystem -Name $Name -Version $normalizedVersion
    if ($null -eq $ioc) { return }
    $sev = [string](Get-PropertyValue $ioc 'severity')
    if ([string]::IsNullOrEmpty($sev)) { $sev = 'DANGER' }
    $category = 'KNOWN_COMPROMISED_PACKAGE'
    $title = 'Known compromised package version detected'
    $confidence = 'high'
    if ($EvidenceKind -notin @('installed-exact','lockfile-exact')) {
        if ($sev -eq 'DANGER') { $sev = 'WARN' }
        $category = 'KNOWN_COMPROMISED_PACKAGE_REFERENCE'
        $title = 'Manifest, cache, constraint, or fallback text references a known compromised version'
        $confidence = 'medium'
    }
    Add-Finding -Severity $sev -Category $category -Title $title -Path $Path -Line $Line -Evidence ("ecosystem={0}; package={1}; version={2}; evidenceKind={3}" -f $Ecosystem, $Name, $normalizedVersion, $EvidenceKind) -Recommendation 'Confirm the resolved version in a lockfile or installed package metadata before concluding that the affected version is present.' -RiskType 'known-ioc' -Confidence $confidence -Check 'Packages' -DetectionMethod 'metadata' -SourceId ([string](Get-PropertyValue $ioc 'sourceId'))
}

function Test-NpmIncidentWatchlistPackageName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    $normalized = $Name.Trim().ToLowerInvariant()
    foreach ($watchName in @($script:NpmIncidentWatchlistNames)) {
        if ($normalized -eq $watchName.ToLowerInvariant()) {
            return $true
        }
    }
    foreach ($prefix in @($script:NpmIncidentWatchlistPrefixes)) {
        if ($normalized.StartsWith($prefix.ToLowerInvariant())) {
            return $true
        }
    }
    return $false
}

function Add-NpmIncidentWatchlistFinding {
    param([string]$Name, [string]$Version, [string]$Path, $Line)
    if (-not (Test-CheckEnabled 'Packages')) { return }
    if (-not (Test-NpmIncidentWatchlistPackageName $Name)) { return }
    $versionText = $Version
    if ([string]::IsNullOrEmpty($versionText)) {
        $versionText = 'unknown'
    }
    Add-Finding -Severity 'INFO' -Category 'NPM_INCIDENT_WATCHLIST_PACKAGE_NAME' -Title 'npm package name appears in recent supply-chain incident watchlist' -Path $Path -Line $Line -Evidence ("Package name={0}; version={1}; exact affected version not asserted." -f $Name, $versionText) -Recommendation 'Treat as context only unless exact IOC or behavior findings also appear. Verify package provenance manually.' -RiskType 'posture' -Confidence 'low' -Check 'Packages' -DetectionMethod 'metadata'
}

function Add-UniquePackageEntry {
    param($List, [hashtable]$Seen, [string]$Name, [string]$Version, [int]$Line = 1)
    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($Version)) { return }
    $normalizedName = $Name.Trim().Trim('"').Trim("'").ToLowerInvariant()
    $normalizedVersion = $Version.Trim().Trim('"').Trim("'")
    if ($normalizedName -notmatch '^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$') { return }
    if (-not (Test-IsExactPackageVersionText $normalizedVersion)) { return }
    $normalizedVersion = Normalize-Version $normalizedVersion
    $key = $normalizedName + '|' + $normalizedVersion
    if ($Seen.ContainsKey($key)) { return }
    $Seen[$key] = $true
    Add-ListItem $List ([ordered]@{ name=$normalizedName; version=$normalizedVersion; line=$Line })
}

function Get-PnpmLockEntries {
    param([string]$Text)
    $result = New-ArrayList
    $seen = @{}
    $lines = $Text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $trimmed = $lines[$i].Trim()
        if ($trimmed -notmatch '^["'']?(?<key>[^"'']+)["'']?:\s*$') { continue }
        $keyText = [string]$Matches['key']
        $keyText = $keyText -replace '\([^\)]*\)$',''
        $match = [regex]::Match($keyText, '^(?:/)?(?<name>@[^/\s]+/[^@/\s]+|[^@/\s]+)@(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$')
        if (-not $match.Success) {
            $match = [regex]::Match($keyText, '^/(?<name>@[^/\s]+/[^/\s]+|[^/\s]+)/(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$')
        }
        if ($match.Success) { Add-UniquePackageEntry -List $result -Seen $seen -Name $match.Groups['name'].Value -Version $match.Groups['version'].Value -Line ($i + 1) }
    }
    return $result
}

function Get-YarnLockEntries {
    param([string]$Text)
    $result = New-ArrayList
    $seen = @{}
    $lines = $Text -split "`r?`n"
    $currentName = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $trimmed = $line.Trim()
        $resolution = [regex]::Match($trimmed, '^resolution\s*:\s*["'']?(?<name>@[^@\s"'']+/[^@\s"'']+|[^@\s"'']+)@npm:(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)')
        if ($resolution.Success) {
            Add-UniquePackageEntry -List $result -Seen $seen -Name $resolution.Groups['name'].Value -Version $resolution.Groups['version'].Value -Line ($i + 1)
            continue
        }
        if ($line -notmatch '^\s' -and $trimmed.EndsWith(':') -and $trimmed.Contains('@')) {
            $selector = ($trimmed.TrimEnd(':').Trim('"').Split(',')[0]).Trim().Trim('"')
            $at = $selector.LastIndexOf('@')
            if ($at -gt 0) { $currentName = $selector.Substring(0,$at) } else { $currentName = '' }
            continue
        }
        if (-not [string]::IsNullOrEmpty($currentName)) {
            $versionMatch = [regex]::Match($trimmed, '^version\s+["'']?(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)["'']?')
            if ($versionMatch.Success) {
                Add-UniquePackageEntry -List $result -Seen $seen -Name $currentName -Version $versionMatch.Groups['version'].Value -Line ($i + 1)
                $currentName = ''
            }
        }
    }
    return $result
}

function Get-BunTextLockEntries {
    param([string]$Text)
    $result = New-ArrayList
    $seen = @{}
    $lines = $Text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($match in [regex]::Matches($lines[$i], '(?<name>@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9._-]+)@(?:npm:)?(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)', 'IgnoreCase')) {
            Add-UniquePackageEntry -List $result -Seen $seen -Name $match.Groups['name'].Value -Version $match.Groups['version'].Value -Line ($i + 1)
        }
    }
    return $result
}

function Get-BoundedNpmTextFallbackEntries {
    param([string]$Text)
    $result = New-ArrayList
    $seen = @{}
    $lines = $Text -split "`r?`n"
    $limit = [Math]::Min($lines.Count, 200000)
    for ($i = 0; $i -lt $limit; $i++) {
        $line = $lines[$i]
        foreach ($match in [regex]::Matches($line, '["'']name["'']\s*:\s*["''](?<name>(?:@[a-z0-9._-]+/)?[a-z0-9._-]+)["''].{0,400}?["'']version["'']\s*:\s*["''](?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)["'']', 'IgnoreCase')) {
            Add-UniquePackageEntry -List $result -Seen $seen -Name $match.Groups['name'].Value -Version $match.Groups['version'].Value -Line ($i + 1)
        }
    }
    return $result
}

function Scan-KnownPackageText {
    param([System.IO.FileInfo]$File, [string]$Text, [string]$Ecosystem, [string]$EvidenceKindOverride)
    $fileName = $File.Name.ToLowerInvariant()
    $evidenceKind = 'text-fallback'
    if ($fileName -in @('package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock')) {
        $evidenceKind = 'lockfile-exact'
    }
    if (-not [string]::IsNullOrEmpty($EvidenceKindOverride)) { $evidenceKind = $EvidenceKindOverride }
    if ($Ecosystem -eq 'npm') {
        $entries = @()
        switch ($fileName) {
            'pnpm-lock.yaml' { $entries = @(Get-PnpmLockEntries -Text $Text) }
            'yarn.lock' { $entries = @(Get-YarnLockEntries -Text $Text) }
            'bun.lock' { $entries = @(Get-BunTextLockEntries -Text $Text) }
            default { $entries = @(Get-BoundedNpmTextFallbackEntries -Text $Text) }
        }
        foreach ($entry in $entries) {
            Add-ScanStat -Name 'packageLockEntriesEvaluated'
            Add-KnownPackageFinding -Ecosystem 'npm' -Name ([string]$entry.name) -Version ([string]$entry.version) -Path $File.FullName -Line $entry.line -EvidenceKind $evidenceKind
        }
        return
    }

    foreach ($ioc in @($script:Context.iocs.packages)) {
        if ($ioc.ecosystem -ne $Ecosystem) { continue }
        $normalizedName = ConvertTo-PackageIocName -Ecosystem $Ecosystem -Name ([string]$ioc.name)
        $namePattern = '(?<![A-Za-z0-9._-])' + ([string]::Join('[-_.]+',[string[]]@($normalizedName.Split('-') | ForEach-Object {[regex]::Escape($_)}))) + '(?![A-Za-z0-9._-])'
        foreach ($badVersion in @($ioc.versions)) {
            if ($badVersion -eq '*') { continue }
            $versionPattern = '(?<![0-9A-Za-z.!+_-])' + [regex]::Escape($badVersion) + '(?![0-9A-Za-z.!+_-])'
            $pattern = '(?is)' + $namePattern + '.{0,120}' + $versionPattern
            $match = Get-BoundedTextRegexMatch -Text $Text -Pattern $pattern
            if (-not $match.Success) { continue }
            $matchEvidenceKind = $evidenceKind
            if ($fileName -match '^requirements' -and -not (Test-BoundedTextRegex -Text $Text -Pattern ('(?im)^\s*' + $namePattern + '(?:\[[^\]]+\])?\s*==\s*' + $versionPattern + '(?:\s|;|$)'))) { $matchEvidenceKind = 'constraint-reference' }
            Add-KnownPackageFinding -Ecosystem $Ecosystem -Name $ioc.name -Version $badVersion -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $match.Index) -EvidenceKind $matchEvidenceKind
        }
    }
}

function Scan-NpmPackageLockDependencyObject {
    param($Dependencies, [System.IO.FileInfo]$File, [int]$Depth = 0)
    if ($null -eq $Dependencies) { return }
    if ($Depth -gt 64) {
        Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'depth-limit' -Critical $true
        return
    }
    foreach ($property in @($Dependencies.PSObject.Properties)) {
        $name = [string]$property.Name
        $entry = $property.Value
        $version = [string](Get-PropertyValue $entry 'version')
        if (-not [string]::IsNullOrEmpty($name) -and -not [string]::IsNullOrEmpty($version)) {
            Add-ScanStat -Name 'packageLockEntriesEvaluated'
            Add-KnownPackageFinding -Ecosystem 'npm' -Name $name -Version $version -Path $File.FullName -Line 1 -EvidenceKind 'lockfile-exact'
            Add-NpmIncidentWatchlistFinding -Name $name -Version $version -Path $File.FullName -Line 1
        }
        Scan-NpmPackageLockDependencyObject -Dependencies (Get-PropertyValue $entry 'dependencies') -File $File -Depth ($Depth + 1)
    }
}

function Scan-NpmPackageLockJson {
    param([System.IO.FileInfo]$File, [string]$Text)
    Add-ScanStat -Name 'packageLockStructuralScans'
    try {
        # Windows PowerShell 5.1 rejects the valid package-lock packages[""] root key.
        # Rename only that structural key in-memory; package object boundaries and values stay intact.
        $rootKeyPattern = New-Object System.Text.RegularExpressions.Regex('(?s)("packages"\s*:\s*\{\s*)""\s*:')
        $jsonText = $rootKeyPattern.Replace($Text, '$1"__dev_supplychain_root__":', 1)
        $json = $jsonText | ConvertFrom-Json -ErrorAction Stop
        $packages = Get-PropertyValue $json 'packages'
        if ($null -ne $packages) {
            foreach ($property in @($packages.PSObject.Properties)) {
                $packagePath = ([string]$property.Name) -replace '\\', '/'
                if ([string]::IsNullOrEmpty($packagePath) -or $packagePath -eq '__dev_supplychain_root__') { continue }
                $parts = @((('/' + $packagePath) -split '/node_modules/'))
                $name = [string]$parts[$parts.Count - 1]
                $version = [string](Get-PropertyValue $property.Value 'version')
                if (-not [string]::IsNullOrEmpty($name) -and -not [string]::IsNullOrEmpty($version)) {
                    Add-ScanStat -Name 'packageLockEntriesEvaluated'
                    Add-KnownPackageFinding -Ecosystem 'npm' -Name $name -Version $version -Path $File.FullName -Line 1 -EvidenceKind 'lockfile-exact'
                    Add-NpmIncidentWatchlistFinding -Name $name -Version $version -Path $File.FullName -Line 1
                }
            }
        }
        Scan-NpmPackageLockDependencyObject -Dependencies (Get-PropertyValue $json 'dependencies') -File $File
        return $true
    }
    catch {
        Add-ScanStat -Name 'packageLockFallbacks'
        Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true
        Add-Finding -Severity 'INFO' -Category 'PACKAGE_LOCK_JSON_PARSE_FAILED' -Title 'npm JSON lockfile could not be parsed' -Path $File.FullName -Evidence 'The malformed package-lock.json or npm-shrinkwrap.json was not used to infer exact package/version matches.' -Recommendation 'Check lockfile syntax if this is unexpected.' -Check 'Packages' -DetectionMethod 'metadata'
        return $false
    }
}

function Scan-NpmFiles {
    param([System.IO.FileInfo]$File, [string]$Text)
    $name = $File.Name.ToLowerInvariant()
    if ($name -notin @('package.json','package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb')) {
        return
    }

    if ((Test-CheckEnabled 'Packages') -and $name -ne 'package.json') {
        if ($name -in @('package-lock.json','npm-shrinkwrap.json')) {
            if (-not (Scan-NpmPackageLockJson -File $File -Text $Text)) {
                # Malformed JSON must not be proximity-matched into an exact compromised version.
            }
        }
        else {
            Scan-KnownPackageText -File $File -Text $Text -Ecosystem 'npm'
        }
    }

    if ($name -eq 'package.json') {
        try {
            $json = $Text | ConvertFrom-Json -ErrorAction Stop
            $ownName = [string](Get-PropertyValue $json 'name')
            $ownVersion = [string](Get-PropertyValue $json 'version')
            if ((Test-CheckEnabled 'Packages') -and -not [string]::IsNullOrEmpty($ownName) -and -not [string]::IsNullOrEmpty($ownVersion)) {
                $ownEvidenceKind = 'manifest-exact'
                if ($File.FullName -match '(?i)\\node_modules\\') { $ownEvidenceKind = 'installed-exact' }
                Add-KnownPackageFinding -Ecosystem 'npm' -Name $ownName -Version $ownVersion -Path $File.FullName -Line 1 -EvidenceKind $ownEvidenceKind
                Add-NpmIncidentWatchlistFinding -Name $ownName -Version $ownVersion -Path $File.FullName -Line 1
            }

            $scriptBlock = Get-PropertyValue $json 'scripts'
            if ((Test-CheckEnabled 'LifecycleScripts') -and $null -ne $scriptBlock) {
                foreach ($prop in $scriptBlock.PSObject.Properties) {
                    if ($prop.Name -match '^(preinstall|install|postinstall|prepare|prepublish|prepack|postpack)$') {
                        $severity = 'CAUTION'
                        $category = 'PACKAGE_LIFECYCLE_SCRIPT'
                        $title = 'Package lifecycle script is present'
                        if (Test-SecretHarvestingExternalSendPattern ([string]$prop.Value)) {
                            $severity = 'DANGER'
                            $category = 'PACKAGE_LIFECYCLE_SECRET_EXFIL_PATTERN'
                            $title = 'Package lifecycle script contains secret harvesting and external send pattern'
                        }
                        elseif (Test-ExternalExecutionPattern ([string]$prop.Value)) {
                            $severity = 'DANGER'
                            $category = 'PACKAGE_LIFECYCLE_EXTERNAL_EXECUTION'
                            $title = 'Package lifecycle script contains external execution pattern'
                        }
                        elseif (Test-DeveloperToolPersistenceRiskPattern ([string]$prop.Value)) {
                            $severity = 'DANGER'
                            $category = 'PACKAGE_LIFECYCLE_DEV_TOOL_PERSISTENCE_PATTERN'
                            $title = 'Package lifecycle script can modify developer tool configuration'
                        }
                        Add-Finding -Severity $severity -Category $category -Title $title -Path $File.FullName -Evidence ("Lifecycle script name: {0}. Script value redacted." -f $prop.Name) -Recommendation 'Review lifecycle scripts without executing package manager commands.' -Check 'LifecycleScripts'
                    }
                }
            }

            if (Test-CheckEnabled 'Packages') {
                $depSections = @('dependencies','devDependencies','optionalDependencies','peerDependencies')
                foreach ($section in $depSections) {
                    $deps = Get-PropertyValue $json $section
                    if ($null -eq $deps) { continue }
                    foreach ($dep in $deps.PSObject.Properties) {
                        $dependencyVersion = [string]$dep.Value
                        $dependencyEvidenceKind = 'constraint-reference'
                        if (Test-IsExactPackageVersionText $dependencyVersion) { $dependencyEvidenceKind = 'manifest-exact' }
                        Add-KnownPackageFinding -Ecosystem 'npm' -Name $dep.Name -Version $dependencyVersion -Path $File.FullName -Line 1 -EvidenceKind $dependencyEvidenceKind
                        Add-NpmIncidentWatchlistFinding -Name $dep.Name -Version ([string]$dep.Value) -Path $File.FullName -Line 1
                    }
                }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'PACKAGE_JSON_PARSE_FAILED' -Title 'package.json could not be parsed as JSON' -Path $File.FullName -Evidence 'Falling back to text-based package scanning.' -Recommendation 'Check package.json syntax if this is unexpected.'
        }
    }
}

function Get-ChainDropBehaviorSignals {
    param([string]$Text)
    $signals = [ordered]@{
        credentialTarget = $false
        credentialRead = $false
        broadEnvironmentHarvest = $false
        explicitCredentialVariable = $false
        externalWrite = $false
        exactCampaignMarker = $false
        npmAuth = $false
        npmPublishCommand = $false
        npmRegistryPublishApi = $false
        packageMutation = $false
        ownershipEnumeration = $false
        multiPackageReplicationLoop = $false
        vscodeFolderOpenWrite = $false
        claudeSessionStartWrite = $false
        incidentPayloadReference = $false
    }
    if ([string]::IsNullOrEmpty($Text)) { return $signals }
    $signals.credentialTarget = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(\.npmrc\b|\.ssh[\\/](?:id_rsa|id_ed25519|config)\b|\.aws[\\/]credentials\b|\.kube[\\/]config\b|\.codex[\\/]auth\.json\b|\.env(?:\.[A-Za-z0-9._-]+)?\b)')
    $signals.credentialRead = ([bool]$signals.credentialTarget -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(readFileSync\s*\(|readFile\s*\(|readdirSync\s*\(|Bun\.file\s*\(|Get-Content\b|ReadAllText\s*\(|fs\.promises\.readFile\s*\()'))
    $signals.broadEnvironmentHarvest = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\s*\(\s*process\.env\s*\)|\bin\s+process\.env\b)')
    $signals.explicitCredentialVariable = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|ACTIONS_RUNTIME_TOKEN|_authToken)')
    $writeCandidate=Test-BoundedTextRegex -Text $Text -Pattern '(?is)(axios\.(?:post|put|patch)|method\s*:|--data\b|-d\s|--form\b|-F\s|-Method\s+(?:Post|Put|Patch)|-X\s*(?:POST|PUT|PATCH))'
    $signals.externalWrite = ($writeCandidate -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(axios\.(?:post|put|patch)\s*\(|fetch\s*\([^\)]{0,900}method\s*:\s*["'']?(?:POST|PUT|PATCH)|https?\.request\s*\([^\)]{0,900}method\s*:\s*["'']?(?:POST|PUT|PATCH)|curl\b.{0,500}(?:-X\s*(?:POST|PUT|PATCH)|--data\b|-d\s|--form\b|-F\s)|Invoke-RestMethod\b.{0,500}-Method\s+(?:Post|Put|Patch))'))
    $signals.exactCampaignMarker = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(npm-cache\.com(?:/router)?|Shai-Hulud:\s*Here\s*We\s*Go\s*Again|dependabot/github_actions/format/setup-formatter)')
    $signals.npmAuth = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(NPM_TOKEN|NODE_AUTH_TOKEN|_authToken|\.npmrc\b|Authorization.{0,220}registry\.npmjs\.org|registry\.npmjs\.org.{0,220}Authorization)')
    $signals.npmPublishCommand = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(\bnpm(?:\.cmd|\.exe)?\s+publish\b|(?:execFile|exec|spawn|spawnSync|execFileSync)\s*\([^\)]{0,700}["'']npm(?:\.cmd|\.exe)?["''][^\)]{0,700}["'']publish["''])')
    $signals.npmRegistryPublishApi = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(registry\.npmjs\.org.{0,1200}method\s*:\s*["'']PUT|method\s*:\s*["'']PUT.{0,1200}registry\.npmjs\.org)')
    $signals.packageMutation = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)(package\.json|\.tgz\b|tarball)') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(writeFileSync\s*\(|writeFile\s*\(|WriteAllText\s*\(|Set-Content\b|JSON\.stringify\s*\()') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(preinstall|scripts|setup\.mjs|Math_Symbol\.js|math_init\.js|tarball|\.tgz\b|version)'))
    $signals.ownershipEnumeration = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(npm\s+(?:access\s+(?:list|ls)|owner\s+ls|whoami)\b|/-/whoami\b|access\s+ls-packages|list-packages)')
    $signals.multiPackageReplicationLoop = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)(for\s*\(|for\s+await|\.map\s*\(|\.forEach\s*\()') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(packages|ownedPackages|packageNames|npm\s+publish|registry\.npmjs\.org)'))
    $writePattern = '(?is)(writeFileSync\s*\(|writeFile\s*\(|WriteAllText\s*\(|Set-Content\b|Add-Content\b|Out-File\b)'
    $signals.vscodeFolderOpenWrite = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)\.vscode[\\/]tasks\.json') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)folderOpen') -and (Test-BoundedTextRegex -Text $Text -Pattern $writePattern))
    $signals.claudeSessionStartWrite = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)\.claude[\\/]settings\.json') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)SessionStart') -and (Test-BoundedTextRegex -Text $Text -Pattern $writePattern))
    $signals.incidentPayloadReference = (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(setup\.mjs|Math_Symbol\.js|math_init\.js|format-results\.txt)')
    return $signals
}

function Get-ChainDropBehaviorDecision {
    param([string]$Text, [bool]$IncidentName = $false, [bool]$KnownCompromisedPackageContext = $false, [System.IO.FileInfo]$File)
    $signals = Get-ChainDropBehaviorSignals -Text $Text
    $credentialAccess = ([bool]$signals.credentialRead -or [bool]$signals.broadEnvironmentHarvest -or [bool]$signals.explicitCredentialVariable)
    # Whole-file co-presence is useful context but is not a source-to-sink path in a
    # large bundle. DANGER requires the bounded harvesting/send compound.
    $credentialExfil=$false; $credentialExfilComplete=$true
    $harvestClock=[Diagnostics.Stopwatch]::StartNew()
    try { $credentialExfil = (Test-SecretHarvestingExternalSendPattern $Text) }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        if ($null -eq $File) { throw }
        $credentialExfilComplete=$false
        Register-ScannerRegexTimeout -StepName 'Scan-NpmRuntimeCode.SecretHarvesting' -File $File -Exception $_.Exception -ElapsedMs $harvestClock.ElapsedMilliseconds
        Register-ScannerStepPerformance -Name 'Scan-NpmRuntimeCode.SecretHarvesting' -ElapsedMs $harvestClock.ElapsedMilliseconds -TimedOut $true -File $File -Nested
    }
    finally { $harvestClock.Stop() }
    $publish = ([bool]$signals.npmPublishCommand -or [bool]$signals.npmRegistryPublishApi)
    $corroboration = ([bool]$signals.ownershipEnumeration -or [bool]$signals.multiPackageReplicationLoop -or [bool]$signals.exactCampaignMarker -or $KnownCompromisedPackageContext)
    $propagation = ([bool]$signals.npmAuth -and $publish -and [bool]$signals.packageMutation -and $corroboration)
    $persistenceWrite = ([bool]$signals.vscodeFolderOpenWrite -or [bool]$signals.claudeSessionStartWrite)
    $severity = 'NONE'
    $reason = ''
    if ($credentialExfil) { $severity='DANGER'; $reason='credential read or harvest plus external POST/PUT/PATCH' }
    elseif ($propagation) { $severity='DANGER'; $reason='npm auth plus publish plus mutation plus replication corroboration' }
    elseif ($persistenceWrite -and ([bool]$signals.incidentPayloadReference -or [bool]$signals.exactCampaignMarker)) { $severity='DANGER'; $reason='developer-tool auto-execution write plus campaign payload reference' }
    elseif ($IncidentName -and ([bool]$signals.incidentPayloadReference -or [bool]$signals.npmAuth -or $credentialAccess)) { $severity='WARN'; $reason='incident filename plus supporting campaign behavior' }
    return [ordered]@{ severity=$severity; reason=$reason; signals=$signals; credentialExfil=$credentialExfil; credentialExfilComplete=$credentialExfilComplete; propagation=$propagation; persistenceWrite=$persistenceWrite }
}

function Get-TrueChainDropSignalNames {
    param($Signals)
    $result = New-ArrayList
    if ($Signals -is [System.Collections.IDictionary]) {
        foreach ($key in @($Signals.Keys)) {
            if ([bool]$Signals[$key]) { Add-ListItem $result ([string]$key) }
        }
    }
    else {
        foreach ($property in @($Signals.PSObject.Properties)) {
            if ([bool]$property.Value) { Add-ListItem $result ([string]$property.Name) }
        }
    }
    return @($result.ToArray())
}

function Resolve-SafeLocalScriptReference {
    param([string]$BaseRoot, [string]$RawPath)
    if ([string]::IsNullOrWhiteSpace($BaseRoot) -or [string]::IsNullOrWhiteSpace($RawPath)) { return $null }
    $match = [regex]::Match($RawPath.Trim(), '(?i)^\s*(?:(?:node|bun|powershell|pwsh|cmd)(?:\.exe)?\s+(?:(?:-File|/c)\s+)?)?["'']?(?<path>(?:\.?[\\/])?[A-Za-z0-9_.@-]+(?:[\\/][A-Za-z0-9_.@-]+)*\.(?:js|mjs|cjs|ps1|cmd|bat|sh))["'']?(?:\s|$)')
    if (-not $match.Success) { return $null }
    $relative = $match.Groups['path'].Value -replace '/', '\'
    if ($relative.StartsWith('.\')) { $relative = $relative.Substring(2) }
    if ([System.IO.Path]::IsPathRooted($relative) -or ($relative -split '\\') -contains '..' -or $relative -match '^[A-Za-z][A-Za-z0-9+.-]*:') { return $null }
    try {
        $rootFull = [System.IO.Path]::GetFullPath($BaseRoot).TrimEnd('\')
        $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $relative))
        if (-not $candidate.StartsWith($rootFull + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
        if (Test-IsSecretInventoryFile $candidate) { return $null }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
        if (Test-PathHasReparsePointBelowRoot -RootPath $rootFull -CandidatePath $candidate) { return $null }
        $info = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        if ($info.Length -gt 2097152) { Register-CoverageFailure -Scope 'candidate' -Path $candidate -Kind 'startup-script' -FailureType 'too-large' -Critical $true; return $null }
        Add-ScanStat -Name 'incidentScriptReferencesResolved'
        return $candidate
    }
    catch { return $null }
}

function Test-ChainDropReferencedScript {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $leaf = [System.IO.Path]::GetFileName($Path)
    if ($leaf -match '^(?i:setup\.mjs|Math_Symbol\.js|math_init\.js)$') { return $true }
    try {
        $hash = Get-BytesSha256ForFile $Path
        if (-not [string]::IsNullOrEmpty($hash) -and $script:Context.iocIndexes.fileHashes.ContainsKey($hash.ToLowerInvariant())) { return $true }
        $file = New-Object System.IO.FileInfo($Path)
        $read = Read-TextFileSafe -File $file
        if (-not $read.ok) { return $false }
        $decision = Get-ChainDropBehaviorDecision -Text ([string]$read.text)
        return ([string]$decision.severity -eq 'DANGER')
    }
    catch { return $false }
}

function Scan-VscodeFolderOpenPersistence {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($File.FullName -notmatch '(?i)\\\.vscode\\tasks\.json$') { return }
    try {
        $json = $Text | ConvertFrom-Json -ErrorAction Stop
        $projectRoot = Split-Path -Parent (Split-Path -Parent $File.FullName)
        foreach ($task in @((Get-PropertyValue $json 'tasks'))) {
            $runOptions = Get-PropertyValue $task 'runOptions'
            if ([string](Get-PropertyValue $runOptions 'runOn') -ne 'folderOpen') { continue }
            $commandText = [string](Get-PropertyValue $task 'command')
            foreach ($arg in @((Get-PropertyValue $task 'args'))) { $commandText += ' ' + [string]$arg }
            $resolved = Resolve-SafeLocalScriptReference -BaseRoot $projectRoot -RawPath $commandText
            if (-not [string]::IsNullOrEmpty($resolved) -and (Test-ChainDropReferencedScript -Path $resolved)) {
                Add-Finding -Severity 'DANGER' -Category 'NPM_CHAINDROP_VSCODE_FOLDEROPEN_PERSISTENCE' -Title 'VS Code folderOpen task references a ChainDrop-shaped local script' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'folderOpen') -Evidence ("runOn=folderOpen; localScript={0}; script content redacted" -f (ConvertTo-RedactedPath $resolved)) -Recommendation 'Do not trust or open the workspace until the task and referenced script are reviewed.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'HooksAndTasks' -DetectionMethod 'static-file'
            }
        }
    }
    catch { Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'vscode-task' -FailureType 'parse-error' -Critical $true }
}

function Add-ClaudeHookCommandStrings {
    param($Value, $List, [int]$Depth = 0)
    if ($null -eq $Value -or $null -eq $List -or $Depth -gt 8 -or $List.Count -ge 32) { return }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            Add-ClaudeHookCommandStrings -Value $item -List $List -Depth ($Depth + 1)
            if ($List.Count -ge 32) { break }
        }
        return
    }
    foreach ($property in @($Value.PSObject.Properties)) {
        if ($property.Name -ieq 'command' -and $property.Value -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace([string]$property.Value)) { Add-ListItem $List ([string]$property.Value) }
            continue
        }
        if (-not ($property.Value -is [string])) {
            Add-ClaudeHookCommandStrings -Value $property.Value -List $List -Depth ($Depth + 1)
        }
        if ($List.Count -ge 32) { break }
    }
}

function Scan-ClaudeSessionStartPersistence {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($File.FullName -notmatch '(?i)\\\.claude\\settings\.json$') { return }
    try { $json = $Text | ConvertFrom-Json -ErrorAction Stop } catch { Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'claude-settings' -FailureType 'parse-error' -Critical $true; return }
    $hooks = Get-PropertyValue $json 'hooks'
    $sessionStart = Get-PropertyValue $hooks 'SessionStart'
    if ($null -eq $sessionStart) { return }
    $projectRoot = Split-Path -Parent (Split-Path -Parent $File.FullName)
    $commands = New-ArrayList
    Add-ClaudeHookCommandStrings -Value $sessionStart -List $commands
    $seen = @{}
    foreach ($command in @($commands)) {
        $resolved = Resolve-SafeLocalScriptReference -BaseRoot $projectRoot -RawPath ([string]$command)
        if ([string]::IsNullOrEmpty($resolved) -or $seen.ContainsKey($resolved.ToLowerInvariant())) { continue }
        $seen[$resolved.ToLowerInvariant()] = $true
        if (Test-ChainDropReferencedScript -Path $resolved) {
            Add-Finding -Severity 'DANGER' -Category 'NPM_CHAINDROP_CLAUDE_SESSIONSTART_PERSISTENCE' -Title 'Claude SessionStart hook references a ChainDrop-shaped local script' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'SessionStart') -Evidence ("hook=SessionStart; localScript={0}; script content redacted" -f (ConvertTo-RedactedPath $resolved)) -Recommendation 'Do not start Claude Code in this workspace until the hook and referenced script are reviewed.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'AiMcp' -DetectionMethod 'static-file'
        }
    }
}

function Scan-BoundedGitRefIocs {
    param([string]$ProjectRoot)
    if ($null -eq $script:Context.campaignIocData.gitRefs) { return }
    $gitDir = Join-Path $ProjectRoot '.git'
    if (-not (Test-Path -LiteralPath $gitDir -PathType Container)) { return }
    try { if (Test-IsReparsePoint (Get-Item -LiteralPath $gitDir -Force -ErrorAction Stop)) { return } } catch { return }
    foreach ($ref in @($script:Context.campaignIocData.gitRefs)) {
        if ([string]::IsNullOrWhiteSpace([string]$ref) -or [string]$ref -match '\.\.' -or [System.IO.Path]::IsPathRooted([string]$ref)) { continue }
        $head = Join-Path $gitDir ('refs\heads\' + ([string]$ref -replace '/', '\'))
        if (Test-Path -LiteralPath $head -PathType Leaf) {
            Add-Finding -Severity 'DANGER' -Category 'NPM_CHAINDROP_GIT_REF_IOC' -Title 'Known incident-associated Git ref exists locally' -Path $head -Evidence ("gitRef={0}" -f $ref) -Recommendation 'Inspect repository and workflow history from a trusted environment without executing this ref.' -RiskType 'known-ioc' -Confidence 'high' -Check 'HooksAndTasks' -DetectionMethod 'metadata'
        }
        $remoteRoot = Join-Path $gitDir 'refs\remotes'
        if (Test-Path -LiteralPath $remoteRoot -PathType Container) {
            try {
                foreach ($remote in @([System.IO.Directory]::GetDirectories($remoteRoot) | Select-Object -First 100)) {
                    if (Test-IsReparsePoint (Get-Item -LiteralPath $remote -Force)) { continue }
                    $remoteRef = Join-Path $remote ([string]$ref -replace '/', '\')
                    if (Test-Path -LiteralPath $remoteRef -PathType Leaf) { Add-Finding -Severity 'DANGER' -Category 'NPM_CHAINDROP_GIT_REF_IOC' -Title 'Known incident-associated remote Git ref exists locally' -Path $remoteRef -Evidence ("gitRef={0}" -f $ref) -Recommendation 'Inspect repository and workflow history from a trusted environment without executing this ref.' -RiskType 'known-ioc' -Confidence 'high' -Check 'HooksAndTasks' -DetectionMethod 'metadata' }
                }
            }
            catch { Register-CoverageFailure -Scope 'directory' -Path $remoteRoot -Kind 'git-ref' -FailureType 'enumeration-error' -Critical $true }
        }
        $packed = Join-Path $gitDir 'packed-refs'
        if (Test-Path -LiteralPath $packed -PathType Leaf) {
            try {
                $packedInfo = Get-Item -LiteralPath $packed -Force -ErrorAction Stop
                if ($packedInfo.Length -gt 4194304) { Register-CoverageFailure -Scope 'candidate' -Path $packed -Kind 'git-ref' -FailureType 'too-large' -Critical $true; continue }
                $packedText = [System.IO.File]::ReadAllText($packed)
                if (Test-BoundedTextRegex -Text $packedText -Pattern ('(?m)refs/(?:heads|remotes/[^/]+)/' + [regex]::Escape([string]$ref) + '\s*$')) { Add-Finding -Severity 'DANGER' -Category 'NPM_CHAINDROP_GIT_REF_IOC' -Title 'Known incident-associated Git ref exists in packed refs' -Path $packed -Evidence ("gitRef={0}" -f $ref) -Recommendation 'Inspect repository and workflow history from a trusted environment without executing this ref.' -RiskType 'known-ioc' -Confidence 'high' -Check 'HooksAndTasks' -DetectionMethod 'metadata' }
            }
            catch { Register-CoverageFailure -Scope 'candidate' -Path $packed -Kind 'git-ref' -FailureType 'access-denied' -Critical $true }
        }
    }
}

function Get-StaticCodeMask {
    param([string]$Text,[ValidateSet('javascript','python','gyp')][string]$Language='javascript')
    if ([object]::ReferenceEquals($script:StaticMaskOriginalText,$Text) -and $script:StaticMaskLanguage -eq $Language) { return $script:StaticMaskValue }
    $strings='(?s)""".*?"""|''''''.*?''''''|"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''|`(?:\\.|[^`\\])*`'
    $comments=if ($Language -in @('python','gyp')) { '#[^\r\n]*' } else { '(?s)/\*.*?\*/|//[^\r\n]*' }
    $pattern='(?:'+$strings+'|'+$comments+')'
    $result=[regex]::Replace($Text,$pattern,[System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        if (-not $match.Value.Contains("`n") -and -not $match.Value.Contains("`r")) { return ''.PadRight($match.Length) }
        return [regex]::Replace($match.Value,'[^\r\n]',' ',[System.Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
    },[System.Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
    $script:StaticMaskOriginalText=$Text; $script:StaticMaskLanguage=$Language; $script:StaticMaskValue=$result
    return $result
}

function ConvertFrom-GypStaticEscapes {
    param([string]$Text)
    if ($Text.Length -gt 65536) { throw 'gyp-scalar-limit' }
    $value=$Text
    for ($pass=0; $pass -lt 2; $pass++) {
        $decoded=[regex]::Replace($value,'\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2})',[System.Text.RegularExpressions.MatchEvaluator]{
            param($match)
            $code=[Convert]::ToInt32($match.Value.Substring(2),16)
            if ($code -gt 0x10FFFF -or ($code -ge 0xD800 -and $code -le 0xDFFF)) { throw 'gyp-invalid-unicode-scalar' }
            return [char]::ConvertFromUtf32($code)
        },[System.Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
        $decoded=[regex]::Replace($decoded,'\\(?<escape>[\\"''nrt])',[System.Text.RegularExpressions.MatchEvaluator]{
            param($match)
            switch ($match.Groups['escape'].Value) { 'n' {return "`n"}; 'r' {return "`r"}; 't' {return "`t"}; default {return $match.Groups['escape'].Value} }
        },[System.Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
        if ($decoded.Length -gt 65536) { throw 'gyp-scalar-limit' }
        if ($decoded -ceq $value) { return $decoded }
        $value=$decoded
    }
    return $value
}

function Get-GypStaticExecutionAssessment {
    param([string]$Text)
    $result=[ordered]@{matches=New-ArrayList; failureType=''; scalarCount=0}
    $stack=New-ArrayList
    $pendingConditions=$false
    $index=0
    while ($index -lt $Text.Length) {
        $character=$Text[$index]
        if ([char]::IsWhiteSpace($character)) { $index++; continue }
        if ($character -eq '#') { $end=$Text.IndexOf("`n",$index); if ($end -lt 0) { break }; $index=$end+1; continue }
        if ($pendingConditions -and $character -notin @(':','[')) { $result.failureType='gyp-condition-list-invalid'; return $result }
        if ($character -eq [char]34 -or $character -eq [char]39) {
            $start=$index
            $quote=$character
            $index++
            $builder=New-Object System.Text.StringBuilder
            $closed=$false
            while ($index -lt $Text.Length) {
                $current=$Text[$index]
                if ($current -eq $quote) { $closed=$true; $index++; break }
                if ($current -eq '\' -and $index+1 -lt $Text.Length) { [void]$builder.Append($current); $index++; [void]$builder.Append($Text[$index]); $index++ }
                else { [void]$builder.Append($current); $index++ }
                if ($builder.Length -gt 65536) { $result.failureType='gyp-scalar-limit'; return $result }
            }
            if (-not $closed) { $result.failureType='gyp-string-unclosed'; return $result }
            try { $value=ConvertFrom-GypStaticEscapes $builder.ToString() }
            catch { $result.failureType='gyp-invalid-escape'; return $result }
            $top=if ($stack.Count -gt 0) { $stack[$stack.Count-1] } else { $null }
            if ($null -ne $top -and $top.conditionRow -and $top.first) {
                $top.first=$false
                $result.scalarCount++
                if ($result.scalarCount -gt 64) { $result.failureType='gyp-condition-limit'; return $result }
                $code=Get-StaticCodeMask -Text $value -Language gyp
                $traversal=(Test-BoundedTextRegex -Text $code -Pattern '__class__\s*\.\s*__(?:base|bases|mro)__') -and (Test-BoundedTextRegex -Text $code -Pattern '__subclasses__\s*\(')
                $recovery=Test-BoundedTextRegex -Text $value -Pattern '__builtins__|__globals__|catch_warnings'
                $import=Test-BoundedTextRegex -Text $value -Pattern '__import__|import_module'
                $execution=Test-BoundedTextRegex -Text $code -Pattern '\.\s*(?:system|popen|Popen|run|call|exec[a-z]*)\s*\('
                if ($traversal -and $recovery -and $import -and $execution) { Add-ListItem $result.matches ([ordered]@{index=$start; length=$index-$start}) }
            }
            $lookahead=$index
            while ($lookahead -lt $Text.Length) {
                if ([char]::IsWhiteSpace($Text[$lookahead])) { $lookahead++; continue }
                if ($Text[$lookahead] -eq '#') { $end=$Text.IndexOf("`n",$lookahead); if ($end -lt 0) { $lookahead=$Text.Length; break }; $lookahead=$end+1; continue }
                break
            }
            if ($lookahead -lt $Text.Length -and $Text[$lookahead] -eq ':' -and $value -ceq 'conditions') { $pendingConditions=$true }
            continue
        }
        if ($character -eq '[' -or $character -eq '{') {
            if ($stack.Count -ge 32) { $result.failureType='gyp-depth-limit'; return $result }
            $parent=if ($stack.Count -gt 0) { $stack[$stack.Count-1] } else { $null }
            $row=($character -eq '[' -and $null -ne $parent -and $parent.conditionsRoot)
            if ($null -ne $parent -and $parent.conditionRow -and $parent.first) { $result.failureType='gyp-condition-nonscalar'; return $result }
            Add-ListItem $stack ([ordered]@{open=$character; conditionsRoot=($character -eq '[' -and $pendingConditions); conditionRow=$row; first=$true})
            $pendingConditions=$false
            $index++; continue
        }
        if ($character -eq ']' -or $character -eq '}') {
            if ($stack.Count -eq 0) { $result.failureType='gyp-unbalanced'; return $result }
            $top=$stack[$stack.Count-1]
            if (($character -eq ']' -and $top.open -ne '[') -or ($character -eq '}' -and $top.open -ne '{')) { $result.failureType='gyp-unbalanced'; return $result }
            $stack.RemoveAt($stack.Count-1)
            $index++; continue
        }
        if ($stack.Count -gt 0) {
            $top=$stack[$stack.Count-1]
            if ($top.conditionRow -and $top.first -and $character -notin @(':',',')) { $result.failureType='gyp-condition-nonscalar'; return $result }
        }
        $index++
    }
    if ($stack.Count -gt 0) { $result.failureType='gyp-unbalanced' }
    return $result
}

function Scan-GypBuildFile {
    param([System.IO.FileInfo]$File,[string]$Text)
    if ($File.Extension -ine '.gyp' -or -not (Test-CheckEnabled 'LifecycleScripts')) { return }
    Add-ScanStat -Name 'securityUpdateCandidatesAnalyzed'
    if ($Text.Length -gt 131072) { Register-SecurityAnalysisLimit -File $File -FailureType 'gyp-file-limit'; return }
    $assessment=Get-GypStaticExecutionAssessment $Text
    if (-not [string]::IsNullOrWhiteSpace([string]$assessment.failureType)) { Register-SecurityAnalysisLimit -File $File -FailureType ([string]$assessment.failureType) }
    $metadata=Get-SecurityCandidateMetadata $File.FullName
    $selected=if ($null -ne $metadata) { [bool]$metadata.selected } else { -not (Test-IsDependencyOrGeneratedArtifactPath $File.FullName) }
    foreach ($match in @($assessment.matches)) {
        $severity=if ($selected) {'DANGER'} else {'WARN'}
        Add-Finding -Severity $severity -Category 'GYP_PYTHON_EXECUTION_COMPOUND' -Title 'GYP condition combines object traversal, import recovery and process execution' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index ([int]$match.index)) -Evidence 'A bounded condition scalar contains a Python sandbox-escape/process compound. Source text and command values are redacted; the condition was not evaluated.' -Recommendation 'Review the native build entrypoint and package provenance without invoking node-gyp or importing the expression.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'LifecycleScripts' -DetectionMethod 'static-file' -RuleId 'gyp-python-execution-compound' -SourceId 'S02'
    }
}

function Get-RuntimeTransferAssessment {
    param([string]$Text,[string]$Language='javascript',[bool]$CiBridge=$false)
    $result=[ordered]@{dns=$false; sckit=$false; secondary=''; ciTransfer=''; index=0; dnsIndex=0; sckitIndex=0; secondaryIndex=0; ciIndex=0; failureType=''}
    if ([string]::IsNullOrEmpty($Text)) { return $result }
    if ($Language -eq 'shell') {
        if (-not $CiBridge -or $Text -notmatch '(?i)NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|\.npmrc|\.pypirc') { return $result }
    }
    elseif ($Text -notmatch '(?i)\bdns\b|\bsocket\b|sckit|\bmessages\b|\bconversation\w*\b|tool_?results?') { return $result }
    if ($Language -eq 'shell') {
        # Preserve expansion positions, while excluding literal strings and comments from call/flow proofs.
        $mask=[regex]::Replace($Text,'''[^'']*''|"(?:\\.|[^"\\])*"|#[^\r\n]*',[System.Text.RegularExpressions.MatchEvaluator]{
            param($token)
            if ($token.Value.StartsWith('"')) {
                return [regex]::Replace($token.Value,'(?<var>\$(?:\{[^}\r\n]{1,128}\}|[A-Za-z_][A-Za-z0-9_]{0,63}))|[^\r\n$]+|\$',{param($part) if ($part.Groups['var'].Success) { return $part.Value }; return (' '*$part.Length)},[System.Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds(2))
            }
            return [regex]::Replace($token.Value,'[^\r\n]',' ',[System.Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds(2))
        },[System.Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds(2))
    }
    else { $mask=Get-StaticCodeMask -Text $Text -Language $Language }
    $anchorPattern=if ($Language -eq 'shell') { '(?m)(?:^|;)[ \t]*(?<shellCall>curl|wget)\b' }
        else { '\b(?:dns\s*\.\s*(?:resolve\w*|lookup)|socket\s*\.\s*getaddrinfo|fetch|requests\s*\.\s*post|axios\s*\.\s*post|https?\s*\.\s*request|spawn|execFile|subprocess\s*\.\s*(?:Popen|run))\s*\(' }
    $anchors=@(Get-BoundedTextRegexMatches -Text $mask -Pattern $anchorPattern -MaximumMatches 65)
    if ($anchors.Count -gt 64) { $result.failureType='transfer-anchor-limit'; $anchors=@($anchors | Select-Object -First 64) }
    foreach ($anchor in $anchors) {
        $start=[Math]::Max(0,$anchor.Index-1536)
        $before=$mask.Substring($start,$anchor.Index-$start)
        $functionBoundary=if ($Language -eq 'shell') { '(?m)(?:\bfunction\s+[A-Za-z_]\w*\s*(?:\(\))?\s*\{|\b[A-Za-z_]\w*\s*\(\)\s*\{)' }
            elseif ($Language -eq 'python') { '(?m)^\s*(?:async\s+)?def\s+[A-Za-z_]\w*[^\r\n]*:' }
            else { '\bfunction(?:\s+[A-Za-z_$][\w$]*)?\s*\([^()]*\)\s*\{|=>\s*\{' }
        $boundaries=@(Get-BoundedTextRegexMatches -Text $before -Pattern $functionBoundary -MaximumMatches 64)
        if ($boundaries.Count -gt 0) { $start+=$boundaries[-1].Index }
        $length=[Math]::Min(2048,$Text.Length-$start)
        $local=$Text.Substring($start,$length)
        $code=$mask.Substring($start,$length)
        $relativeIndex=$anchor.Index-$start
        $after=$code.Substring($relativeIndex,[Math]::Min(512,$code.Length-$relativeIndex))
        if ($anchor.Value -match '(spawn|execFile|subprocess)' -and $local -match '(?i)\.sckit[\\/]|["'']\.sckit["'']' -and $local -match '_stage0|stage0' -and $local -match '(?i)config|base64') {
            $result.sckit=$true; $result.index=$anchor.Index; $result.sckitIndex=$anchor.Index
        }
        if ($Language -eq 'shell') {
            if (-not $CiBridge -or -not $anchor.Groups['shellCall'].Success) { continue }
            $activeSendLine=($code.Substring($relativeIndex) -split "\r?\n",2)[0]
            $sendLine=($local.Substring($relativeIndex) -split "`r?`n",2)[0]
            $reads=@(Get-BoundedTextRegexMatches -Text $code -Pattern '(?m)\b(?<var>[A-Za-z_][A-Za-z0-9_]{0,63})\s*=\s*(?<rhs>[^;\r\n]{1,512})' -MaximumMatches 65)
            if ($reads.Count -gt 64) { $result.failureType='transfer-assignment-limit'; continue }
            $hasFlow=$false
            foreach ($read in $reads) {
                if ($read.Index -ge $relativeIndex) { continue }
                $sourceLine=($local.Substring($read.Index) -split "`r?`n",2)[0]
                if ($sourceLine -notmatch '(?i)\.npmrc|\.pypirc|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY') { continue }
                if ($read.Groups['rhs'].Value -notmatch '\bcat\b|\$(?:\{)?(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY)\b') { continue }
                $overwritten=@($reads | Where-Object {$_.Index -gt $read.Index -and $_.Index -lt $relativeIndex -and $_.Groups['var'].Value -ceq $read.Groups['var'].Value})
                if ($overwritten.Count -gt 0) { continue }
                $sources=@(Get-BoundedTextRegexMatches -Text $read.Groups['rhs'].Value -Pattern '\$(?:\{)?(?<var>NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY)\b' -MaximumMatches 8)
                $sourceOverwritten=$false
                foreach ($sourceVariable in $sources) {
                    $binding=@($reads | Where-Object {$_.Index -lt $read.Index -and $_.Groups['var'].Value -ceq $sourceVariable.Groups['var'].Value} | Select-Object -Last 1)
                    if ($binding.Count -gt 0 -and $binding[0].Groups['rhs'].Value -notmatch '\bcat\b|\$(?:\{)?(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY)\b') { $sourceOverwritten=$true }
                }
                if ($sourceOverwritten) { continue }
                $variable=[regex]::Escape($read.Groups['var'].Value)
                if ($activeSendLine -match ('\$(?:\{)?'+$variable+'\b')) { $hasFlow=$true; break }
            }
            foreach ($environmentRead in @(Get-BoundedTextRegexMatches -Text $activeSendLine -Pattern '\$(?:\{)?(?<var>NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY)\b' -MaximumMatches 8)) {
                $binding=@($reads | Where-Object {$_.Index -lt $relativeIndex -and $_.Groups['var'].Value -ceq $environmentRead.Groups['var'].Value} | Select-Object -Last 1)
                if ($binding.Count -eq 0) { $hasFlow=$true }
            }
            if ($hasFlow -and $sendLine -match '(?i)(--data(?:-binary|-raw)?|-d|--post-data|--upload-file|-T)\b') {
                $urls=@(Get-BoundedTextRegexMatches -Text $sendLine -Pattern 'https?://(?<host>[A-Za-z0-9.-]+)(?=[:/\s"'']|$)' -MaximumMatches 64)
                foreach ($url in $urls) {
                    $hostName=$url.Groups['host'].Value.ToLowerInvariant()
                    if ($hostName -match '^(?:[a-z0-9-]+\.)*skyleen\.fr$') { $result.ciTransfer='known-c2'; $result.index=$anchor.Index; $result.ciIndex=$anchor.Index; break }
                    if ($hostName -notin @('registry.npmjs.org','upload.pypi.org','test.pypi.org') -and $result.ciTransfer -ne 'known-c2') { $result.ciTransfer='additional-destination'; $result.index=$anchor.Index; $result.ciIndex=$anchor.Index }
                }
            }
            continue
        }
        if ($anchor.Value -match 'dns|socket') {
            $reads=@(Get-BoundedTextRegexMatches -Text $code -Pattern '(?<![\w$.])(?<var>[A-Za-z_$][A-Za-z0-9_$]{0,63})\s*=\s*(?<rhs>[^;\r\n]{1,512})' -MaximumMatches 65)
            if ($reads.Count -gt 64) { $result.failureType='transfer-assignment-limit'; continue }
            foreach ($read in $reads) {
                $rhs=$read.Groups['rhs'].Value
                $source=$local.Substring($read.Index,[Math]::Min($read.Length,$local.Length-$read.Index))
                if ($rhs -notmatch '(?i)process\s*\.\s*env|os\s*\.\s*environ|readFile(?:Sync)?\s*\(|open\s*\(' -or $source -notmatch '(?i)TOKEN|API[_-]?KEY|SECRET|PASSWORD|CREDENTIAL|\.npmrc|\.pypirc|\.ssh|\.aws') { continue }
                $secretVar=[regex]::Escape($read.Groups['var'].Value)
                foreach ($encoded in $reads) {
                    if ($encoded.Index -lt $read.Index -or $encoded.Index -gt $relativeIndex) { continue }
                    $encodedSource=$local.Substring($encoded.Index,[Math]::Min($encoded.Length,$local.Length-$encoded.Index))
                    if ($encoded.Groups['rhs'].Value -notmatch ('\b'+$secretVar+'\b') -or $encodedSource -notmatch '(?i)base64|b64encode|toString\s*\(\s*["'']hex["'']|hexlify') { continue }
                    $overwritten=@($reads | Where-Object {$_.Index -gt $read.Index -and $_.Index -lt $encoded.Index -and $_.Groups['var'].Value -ceq $read.Groups['var'].Value})
                    if ($overwritten.Count -gt 0) { continue }
                    $encodedVar=[regex]::Escape($encoded.Groups['var'].Value)
                    $overwritten=@($reads | Where-Object {$_.Index -gt $encoded.Index -and $_.Index -lt $relativeIndex -and $_.Groups['var'].Value -ceq $encoded.Groups['var'].Value})
                    if ($overwritten.Count -gt 0) { continue }
                    $queryVars=@($encodedVar)
                    foreach ($derived in $reads) {
                        if ($derived.Index -gt $encoded.Index -and $derived.Index -lt $relativeIndex -and $derived.Groups['rhs'].Value -match ('\b'+$encodedVar+'\b')) {
                            $overwritten=@($reads | Where-Object {$_.Index -gt $derived.Index -and $_.Index -lt $relativeIndex -and $_.Groups['var'].Value -ceq $derived.Groups['var'].Value})
                            if ($overwritten.Count -eq 0) { $queryVars+=([regex]::Escape($derived.Groups['var'].Value)) }
                        }
                    }
                    foreach ($queryVar in $queryVars) {
                        if ($after -match ('^[^(]*\([^;\r\n]{0,400}\b'+$queryVar+'\b')) { $result.dns=$true; $result.index=$anchor.Index; $result.dnsIndex=$anchor.Index; break }
                    }
                }
            }
        }
    }
    if ($Language -ne 'shell') {
        $calls=New-ArrayList
        foreach ($anchor in $anchors) {
            if ($anchor.Value -notmatch 'fetch|requests|axios|request') { continue }
            $length=[Math]::Min(1024,$Text.Length-$anchor.Index)
            $segment=$Text.Substring($anchor.Index,$length)
            $activeSegment=$mask.Substring($anchor.Index,$length)
            # Stop at the end of this statement. The same payload identifier must appear in both calls.
            $end=$segment.IndexOf(';'); if ($end -ge 0) { $segment=$segment.Substring(0,$end); $activeSegment=$activeSegment.Substring(0,$end) }
            $payload=Get-BoundedTextRegexMatch -Text $activeSegment -Pattern '\b(?<var>messages|conversation|conversations|tool_results|toolResults|toolResult)\b'
            if (-not $payload.Success) { continue }
            $destination=Get-BoundedTextRegexMatch -Text $segment -Pattern 'https?://(?<host>[A-Za-z0-9.-]+)(?<path>/[^\s"''`)]*)?'
            $scopeStart=[Math]::Max(0,$anchor.Index-1536)
            $scopeMatches=@(Get-BoundedTextRegexMatches -Text ($mask.Substring($scopeStart,$anchor.Index-$scopeStart)) -Pattern $functionBoundary -MaximumMatches 64)
            $scope=if ($scopeMatches.Count -gt 0) {$scopeStart+$scopeMatches[-1].Index} else {0}
            Add-ListItem $calls ([ordered]@{payload=$payload.Groups['var'].Value; destination=$destination.Value; known=($destination.Value -match '^https?://api\.nm-streetwear\.space/vx/learn(?:[/?#]|$)'); index=$anchor.Index; scope=$scope})
        }
        foreach ($call in $calls) {
            foreach ($other in $calls) {
                if ($call.index -eq $other.index -or $call.payload -cne $other.payload -or [string]::IsNullOrEmpty($call.destination) -or $call.destination -ceq $other.destination) { continue }
                if ($call.scope -ne $other.scope -or [Math]::Abs($call.index-$other.index) -gt 2048) { continue }
                if ($call.known) { $result.secondary='reported-destination'; $result.index=$call.index; $result.secondaryIndex=$call.index; break }
                if (-not [string]::IsNullOrEmpty($other.destination) -and $result.secondary -ne 'reported-destination') { $result.secondary='additional-destination'; $result.index=$call.index; $result.secondaryIndex=$call.index }
            }
        }
    }
    return $result
}

function Scan-RuntimeTransferBehavior {
    param([System.IO.FileInfo]$File,[string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text) -or $File.Extension -notin @('.js','.mjs','.cjs','.ts','.py','.sh','.bash')) { return }
    $sourceContext=Get-SourceContext $File.FullName
    if ($sourceContext -in @('scanner-self','reference-text','session-log','cache-data','plugin-metadata') -or (Get-TextContext -File $File) -eq 'documentation') { return }
    $metadata=Get-SecurityCandidateMetadata $File.FullName
    $dependency=Test-IsDependencyOrGeneratedArtifactPath $File.FullName
    $selected=Test-IsTargetedScanPath $File.FullName
    $ideOwner=($null -ne $metadata -and 'IdeExtensions' -in @($metadata.ownerChecks)) -or (Test-IsVsCodeStyleExtensionPath $File.FullName)
    $ciOwner=$null -ne $metadata -and 'CiCd' -in @($metadata.ownerChecks)
    $check=if ($ideOwner -and (Test-CheckEnabled 'IdeExtensions')) {'IdeExtensions'} elseif ($ciOwner -and (Test-CheckEnabled 'CiCd')) {'CiCd'} elseif (Test-CheckEnabled 'LifecycleScripts') {'LifecycleScripts'} else {''}
    if ([string]::IsNullOrEmpty($check)) { return }
    $bridge=$ciOwner -and [bool]$metadata.ciBridgeProof
    $language=if ($File.Extension -eq '.py') {'python'} elseif ($File.Extension -in @('.sh','.bash')) {'shell'} else {'javascript'}
    $assessment=Get-RuntimeTransferAssessment -Text $Text -Language $language -CiBridge $bridge
    Add-ScanStat -Name 'securityUpdateCandidatesAnalyzed'
    if (-not [string]::IsNullOrEmpty($assessment.failureType)) { Register-SecurityAnalysisLimit -File $File -FailureType $assessment.failureType }
    if ($assessment.sckit) {
        $line=Get-LineNumberForIndex -Text $Text -Index ([int]$assessment.sckitIndex)
        Add-Finding -Severity 'WARN' -Category 'SCKIT_STAGE0_LOADER_COMPOUND' -Title 'Runtime loader combines a hidden sckit process, stage0 and configuration markers' -Path $File.FullName -Line $line -Evidence 'A local process-call window contains the sckit/stage0/configuration compound. Code and configuration values are redacted; this heuristic does not establish a malicious binary hash.' -Recommendation 'Verify the selected entrypoint and the reported implant hashes without executing the loader.' -RiskType 'posture' -Confidence 'medium' -Check $check -DetectionMethod 'static-file' -RuleId 'sckit-stage0-loader' -SourceId 'S03'
    }
    if ($assessment.dns) {
        $line=Get-LineNumberForIndex -Text $Text -Index ([int]$assessment.dnsIndex)
        $severity=if ($dependency -and -not $selected) {'WARN'} else {'DANGER'}
        $confidence=if ($severity -eq 'DANGER') {'high'} else {'medium'}
        Add-Finding -Severity $severity -Category 'CREDENTIAL_DNS_EXFIL_PATTERN' -Title 'Credential-derived encoded data flows into a DNS query' -Path $File.FullName -Line $line -Evidence 'A bounded static assignment flow links credential access, encoding and a DNS query argument. Credential values and query labels are redacted; no query was made.' -Recommendation 'Trace the selected entrypoint and destination without executing the code or resolving the domain.' -RiskType 'active-exfil' -Confidence $confidence -Check $check -DetectionMethod 'static-file' -RuleId 'dns-credential-flow' -SourceId 'S02'
    }
    if (-not [string]::IsNullOrEmpty($assessment.secondary)) {
        $line=Get-LineNumberForIndex -Text $Text -Index ([int]$assessment.secondaryIndex)
        $severity=if ($assessment.secondary -eq 'reported-destination') {'WARN'} else {'CAUTION'}
        Add-Finding -Severity $severity -Category 'CONVERSATION_SECONDARY_TRANSFER' -Title 'Conversation or tool-result data is sent to an additional destination' -Path $File.FullName -Line $line -Evidence ("Two active transfer statements share a conversation/tool-result identifier; assessment={0}. Payload and endpoint values are redacted. Credential theft is not asserted." -f $assessment.secondary) -Recommendation 'Verify user consent and the purpose of the additional transfer before using the tool.' -RiskType 'posture' -Confidence 'medium' -Check $check -DetectionMethod 'static-file' -RuleId 'conversation-secondary-transfer' -SourceId 'S08'
    }
    if (-not [string]::IsNullOrEmpty($assessment.ciTransfer)) {
        $line=Get-LineNumberForIndex -Text $Text -Index ([int]$assessment.ciIndex)
        $severity=if ($assessment.ciTransfer -eq 'known-c2') {'DANGER'} else {'WARN'}
        Add-Finding -Severity $severity -Category 'CI_PUBLISH_BRIDGE_EXFIL_PATTERN' -Title 'A workflow-selected BASH_ENV bridge transfers credential-derived data' -Path $File.FullName -Line $line -Evidence ("The selected bridge has a credential-read/transfer flow; destinationAssessment={0}. Credential values and shell contents are redacted." -f $assessment.ciTransfer) -Recommendation 'Review the workflow, local publish script and bridge without running them or contacting the endpoint.' -RiskType 'active-exfil' -Confidence 'high' -Check 'CiCd' -DetectionMethod 'static-file' -RuleId 'ci-publish-bridge-flow' -SourceId 'S03'
    }
}

function Scan-NpmRuntimeCode {
    param([System.IO.FileInfo]$File, [string]$Text)
    if (-not (Test-CheckEnabled 'LifecycleScripts')) { return }
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    $sourceContext = Get-SourceContext $File.FullName
    $aiRole = Get-AiPathRole $File.FullName
    if ($sourceContext -eq 'scanner-self' -or $aiRole -in @('executable-tooling','reference-text','session-log','cache-data','plugin-metadata') -or $sourceContext -in @('executable-tooling','reference-text','session-log','cache-data','plugin-metadata')) {
        return
    }
    $ext = $File.Extension.ToLowerInvariant()
    if ($ext -notin @('.js','.mjs','.cjs','.jsx','.ts','.tsx','.ps1','.cmd','.bat','.sh','.bash')) {
        return
    }
    $path = $File.FullName.ToLowerInvariant() -replace '/', '\'
    if ($path -match '\\(readme|docs|documentation)\\') {
        return
    }

    $dependencyOrGenerated = Test-IsDependencyOrGeneratedArtifactPath $File.FullName
    $targetedDependencyPath = ($dependencyOrGenerated -and (Test-IsTargetedScanPath $File.FullName))
    $incidentName = ($File.Name -match '^(?i:setup\.mjs|Math_Symbol\.js|math_init\.js)$')
    $originalText=$Text
    $passiveSpans=@()
    if ($ext -in @('.ps1','.bat','.cmd')) {
        $proofStart=[Diagnostics.Stopwatch]::GetTimestamp()
        try { $projection=Get-PowerShellRegexDataProjection $Text }
        finally { Register-ScannerActivityPerformance -Name 'PowerShellContextProof' -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp()-$proofStart) -File $File }
        $passiveSpans=@($projection.spans)
        if ($projection.spans.Count -gt 0) {
            Add-Finding -Severity 'INFO' -Category 'PACKAGE_CODE_PASSIVE_REGEX_DATA' -Title 'Literal examples have proven regex-only consumers' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $projection.spans[0].start) -Evidence ("Statically proven passive literal count={0}; unknown consumers and other original-source bytes remain analyzed." -f $projection.spans.Count) -Recommendation 'Treat these literals as test data; this does not establish the safety of the rest of the script.' -RiskType 'posture' -Confidence 'high'
            $Text=$projection.text
        }
    }
    $decision = Get-ChainDropBehaviorDecision -Text $Text -IncidentName $incidentName -File $File
    $signalNames = @(Get-TrueChainDropSignalNames -Signals $decision.signals)
    if ([bool]$decision.propagation) {
        Add-Finding -Severity 'DANGER' -Category 'NPM_CHAINDROP_PROPAGATION_CHAIN' -Title 'Code matches a strong npm self-propagation chain' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(npm\s+publish|registry\.npmjs\.org|access\s+ls-packages|owner\s+ls)') -Evidence ("reason={0}; signals={1}; raw code and credential values redacted" -f $decision.reason,([string]::Join(',', [string[]]$signalNames))) -Recommendation 'Do not execute the script or publish packages; preserve evidence and review package ownership activity.' -RiskType 'active-exfil' -Confidence 'high' -Check 'LifecycleScripts' -DetectionMethod 'static-file'
        return
    }
    if ([bool]$decision.credentialExfil) {
        if ($dependencyOrGenerated -and -not $targetedDependencyPath) {
            Add-Finding -Severity 'WARN' -Category 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -Title 'Dependency or generated code contains a credential-access and external-write compound' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.npmrc|\.ssh|\.aws|\.kube|process\.env|NPM_TOKEN|GITHUB_TOKEN)') -Evidence ("reason={0}; signals={1}; dependencyOrGenerated=true; targeted=false; values redacted" -f $decision.reason,([string]::Join(',', [string[]]$signalNames))) -Recommendation 'Verify package or generated-artifact provenance and determine whether this code is reachable from an active entrypoint.' -RiskType 'posture' -Confidence 'medium' -Check 'LifecycleScripts' -DetectionMethod 'static-file'
        }
        else {
            Add-Finding -Severity 'DANGER' -Category 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -Title 'Package or project code contains credential harvesting and external write pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.npmrc|\.ssh|\.aws|\.kube|process\.env|NPM_TOKEN|GITHUB_TOKEN)') -Evidence ("reason={0}; signals={1}; values redacted" -f $decision.reason,([string]::Join(',', [string[]]$signalNames))) -Recommendation 'Inspect without executing package code or lifecycle scripts.' -RiskType 'active-exfil' -Confidence 'high' -Check 'LifecycleScripts' -DetectionMethod 'static-file'
        }
        return
    }
    if ([string]$decision.severity -eq 'WARN') {
        Add-Finding -Severity 'WARN' -Category 'NPM_CHAINDROP_PARTIAL_CONTEXT' -Title 'Incident-named script has supporting ChainDrop behavior' -Path $File.FullName -Line 1 -Evidence ("reason={0}; signals={1}; raw code redacted" -f $decision.reason,([string]::Join(',', [string[]]$signalNames))) -Recommendation 'Review offline and correlate with exact package/version or hash findings.' -RiskType 'posture' -Confidence 'medium' -Check 'LifecycleScripts' -DetectionMethod 'static-file'
    }

    $developerWrite=Get-DeveloperToolWriteAssessment $Text
    if ($developerWrite.detected) {
        $persistenceSeverity = if ($dependencyOrGenerated -and -not $targetedDependencyPath) { 'WARN' } else { 'DANGER' }
        $persistenceRiskType = if ($persistenceSeverity -eq 'DANGER') { 'active-exfil' } else { 'posture' }
        $persistenceConfidence = if ($persistenceSeverity -eq 'DANGER') { 'high' } else { 'medium' }
        Add-Finding -Severity $persistenceSeverity -Category 'PACKAGE_CODE_DEV_TOOL_PERSISTENCE_PATTERN' -Title 'Package or project code can modify developer tool configuration' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $developerWrite.index) -Evidence ("A write destination references developer tool configuration near network or token access. Values redacted. dependencyOrGenerated={0}; targeted={1}" -f ([bool]$dependencyOrGenerated).ToString().ToLowerInvariant(),([bool]$targetedDependencyPath).ToString().ToLowerInvariant()) -Recommendation 'Inspect before running package install, build, or helper scripts.' -RiskType $persistenceRiskType -Confidence $persistenceConfidence -Check 'LifecycleScripts'
        return
    }
    $externalExecutionAssessment = $null
    if ($ext -eq '.ps1') {
        $externalExecutionAssessment = Get-PowerShellExternalExecutionAssessment -Text $originalText -PassiveSpans $passiveSpans
    }
    else {
        $externalExecutionMatch = Get-ExternalExecutionPatternMatch -Text $Text
        if ($null -eq $externalExecutionMatch) {
            $externalExecutionAssessment = [pscustomobject]@{ Disposition = 'None'; Match = $null; Line = $null; Reason = 'no-pattern' }
        }
        else {
            $externalExecutionAssessment = [pscustomobject]@{
                Disposition = 'Active'
                Match = $externalExecutionMatch
                Line = Get-LineNumberForIndex -Text $Text -Index $externalExecutionMatch.Index
                Reason = 'non-powershell-text-pattern'
            }
        }
    }
    if ([string]$externalExecutionAssessment.Disposition -in @('Active','Ambiguous')) {
        $externalExecutionClassification = ([string]$externalExecutionAssessment.Disposition).ToLowerInvariant()
        if ($dependencyOrGenerated -and -not $targetedDependencyPath) {
            Add-Finding -Severity 'CAUTION' -Category 'PACKAGE_CODE_EXTERNAL_EXECUTION' -Title 'Dependency or generated code contains external fetch and execution capability' -Path $File.FullName -Line $externalExecutionAssessment.Line -Evidence ("classification={0}; reason={1}; an unselected dependency or generated artifact contains fetch-and-execute capability without an exact IOC or active entrypoint relationship. Line content redacted." -f $externalExecutionClassification,[string]$externalExecutionAssessment.Reason) -Recommendation 'Verify package or build-artifact provenance before invoking this helper.' -RiskType 'capability' -Confidence 'medium' -Check 'LifecycleScripts'
        }
        else {
            $externalExecutionConfidence = if ([string]$externalExecutionAssessment.Disposition -eq 'Ambiguous') { 'medium' } else { 'high' }
            Add-Finding -Severity 'DANGER' -Category 'PACKAGE_CODE_EXTERNAL_EXECUTION' -Title 'Package or project code contains external fetch and execution pattern' -Path $File.FullName -Line $externalExecutionAssessment.Line -Evidence ("classification={0}; reason={1}; code contains external fetch plus execution pattern. Line content redacted." -f $externalExecutionClassification,[string]$externalExecutionAssessment.Reason) -Recommendation 'Do not execute related package code until reviewed.' -RiskType 'fetch-execute' -Confidence $externalExecutionConfidence -Check 'LifecycleScripts'
        }
    }
}

function Scan-NpmIncidentContextMarkers {
    param([System.IO.FileInfo]$File, [string]$Text)
    if (-not ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts'))) { return }
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    $sourceContext = Get-SourceContext $File.FullName
    $marker = Get-NpmIncidentContextMarker -Text $Text
    $fileNameMarker = Get-NpmIncidentFileNameMarker -File $File
    if ($null -eq $marker -and $null -ne $fileNameMarker) {
        $marker = $fileNameMarker
    }
    if ($null -eq $marker) { return }
    if ($sourceContext -eq 'scanner-self') {
        Add-ScanStat -Name 'scannerArtifactIocReferencesAggregated'
        return
    }
    $textContext = Get-TextContext -File $File
    $line = Get-FirstMatchLine -Text $Text -Pattern ([string]$marker.pattern)
    if ($null -eq $line -and $null -ne $fileNameMarker) {
        $line = 1
    }
    if ($textContext -in @('code','execution-config') -and (Test-ImportOrRuntimeExecutionPattern $Text)) {
        Add-Finding -Severity 'DANGER' -Category 'NPM_INCIDENT_MARKER_EXECUTABLE_CONTEXT' -Title 'Recent npm incident marker appears with execution or credential behavior' -Path $File.FullName -Line $line -Evidence ("marker={0}; context={1}; compoundPattern=marker-with-execution-or-secret-behavior" -f $marker.label, $textContext) -Recommendation 'Preserve evidence and inspect without executing package code.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'LifecycleScripts'
    }
    elseif ($textContext -in @('code','execution-config')) {
        Add-Finding -Severity 'WARN' -Category 'NPM_INCIDENT_MARKER_EXECUTABLE_TEXT' -Title 'Recent npm incident marker appears in executable context' -Path $File.FullName -Line $line -Evidence ("marker={0}; context={1}" -f $marker.label, $textContext) -Recommendation 'Verify whether this marker is expected in the package or script.' -RiskType 'posture' -Confidence 'medium' -Check 'Packages'
    }
    else {
        Add-Finding -Severity 'INFO' -Category 'NPM_INCIDENT_MARKER_REFERENCE_TEXT' -Title 'Recent npm incident marker appears in non-executable text' -Path $File.FullName -Line $line -Evidence ("marker={0}; context={1}" -f $marker.label, $textContext) -Recommendation 'Treat as context unless another executable finding points to the same file.' -RiskType 'posture' -Confidence 'low' -Check 'Packages'
    }
}

function Scan-PythonTextLock {
    param([System.IO.FileInfo]$File,[string]$Text)
    # Match literal name/version fields within one TOML [[package]] block, never across blocks.
    # Mask strings/comments before identifying tables or keys so multiline examples are not dependencies.
    $quote=[string][char]39
    $triple=$quote*3
    $pattern='(?<string>"""(?:\\[\s\S]|"{1,2}(?!")|[^"\\])*(?<end>"{3,5}|\z)|'+$triple+'(?:(?!'+$triple+')[\s\S])*(?<end>'+$quote+'{3,5}|\z)|"(?:\\[^\r\n]|[^"\\\r\n])*(?<end>"|(?=\r?$))|'+$quote+'[^'+$quote+'\r\n]*(?<end>'+$quote+'|(?=\r?$)))|#[^\r\n]*'
    $maskState=@{invalid=$false}
    $mask=[regex]::Replace($Text,$pattern,[Text.RegularExpressions.MatchEvaluator]{
        param($match)
        if ($match.Groups['string'].Success -and $match.Groups['end'].Value.Length -eq 0) { $maskState.invalid=$true }
        return [regex]::Replace($match.Value,'[^\r\n]',' ',[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
    },[Text.RegularExpressions.RegexOptions]::Multiline -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant,[TimeSpan]::FromSeconds($script:RegexMatchTimeoutSeconds))
    if ($maskState.invalid) { Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true; return }
    $lines=$Text -split "`r?`n"
    $maskLines=$mask -split "`r?`n"
    $entry=$null
    $invalid=$false
    for ($i=0; $i -le $lines.Count; $i++) {
        $line=if ($i -eq $lines.Count) {'[__scanner_end__]'} else {$lines[$i]}
        $maskLine=if ($i -eq $lines.Count) {'[__scanner_end__]'} else {$maskLines[$i]}
        if ($maskLine -match '^\s*\[') {
            if ($null -ne $entry) {
                if ($entry.invalid -or ($entry.versionLine -gt 0 -and ($entry.nameLine -eq 0 -or $entry.name -notmatch '\A[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\z' -or $entry.name.Length -gt 128 -or -not (Test-IsExactPackageVersionText -Version $entry.version -Ecosystem 'python')))) { $invalid=$true }
                elseif ($entry.nameLine -gt 0 -and $entry.versionLine -gt 0) {
                    Add-ScanStat -Name 'packageLockEntriesEvaluated'
                    Add-KnownPackageFinding -Ecosystem 'python' -Name $entry.name -Version $entry.version -Path $File.FullName -Line $entry.versionLine -EvidenceKind 'lockfile-exact'
                }
            }
            $entry=$null
            if ($maskLine -cmatch '^\s*\[\[package\]\]\s*$') { $entry=@{name='';version='';nameLine=0;versionLine=0;invalid=$false} }
            continue
        }
        if ($null -eq $entry -or $maskLine -cnotmatch '^\s*(?:name|version)\s*=') { continue }
        $field=[regex]::Match($line,'\A\s*(?<field>name|version)\s*=\s*(?<quote>["''])(?<value>[^"'']*)\k<quote>\s*(?:#.*)?\z')
        if ($field.Success) {
            $key=$field.Groups['field'].Value
            if ($entry[$key+'Line'] -ne 0) { $entry.invalid=$true }
            $entry[$key]=$field.Groups['value'].Value
            $entry[$key+'Line']=$i+1
        }
        elseif ($line -cmatch '^\s*(?:name|version)\s*=') { $entry.invalid=$true }
    }
    if ($invalid) { Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true }
}

function Scan-PipfileLockJson {
    param([System.IO.FileInfo]$File, [string]$Text)
    Add-ScanStat -Name 'packageLockStructuralScans'
    try {
        if (-not $Text.TrimStart().StartsWith('{',[StringComparison]::Ordinal)) { throw 'pipfile-root-not-object' }
        $json = $Text | ConvertFrom-Json -ErrorAction Stop
        foreach ($sectionName in @('default','develop')) {
            $sectionProperty = $json.PSObject.Properties[$sectionName]
            if ($null -eq $sectionProperty) { continue }
            $section = $sectionProperty.Value
            if ($section -isnot [System.Management.Automation.PSCustomObject] -and $section -isnot [System.Collections.IDictionary]) {
                Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true
                continue
            }
            foreach ($property in @($section.PSObject.Properties)) {
                if ($property.Value -isnot [System.Management.Automation.PSCustomObject] -and $property.Value -isnot [System.Collections.IDictionary]) {
                    Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true
                    continue
                }
                $versionProperty = $property.Value.PSObject.Properties['version']
                if ($null -eq $versionProperty) { continue }
                $declaredVersion = $versionProperty.Value
                if ($declaredVersion -isnot [string]) {
                    Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true
                    continue
                }
                $rawVersion = [string]$declaredVersion
                $match = [regex]::Match($rawVersion, '\A==\s*(?<version>[^\r\n]+)\z')
                if (-not $match.Success) {
                    Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true
                    continue
                }
                if (-not (Test-IsExactPackageVersionText -Version $match.Groups['version'].Value -Ecosystem 'python')) {
                    Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true
                    continue
                }
                Add-ScanStat -Name 'packageLockEntriesEvaluated'
                Add-KnownPackageFinding -Ecosystem 'python' -Name ([string]$property.Name) -Version $match.Groups['version'].Value -Path $File.FullName -Line 1 -EvidenceKind 'lockfile-exact'
            }
        }
        return $true
    }
    catch {
        Add-ScanStat -Name 'packageLockFallbacks'
        Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'parse-error' -Critical $true
        Add-Finding -Severity 'INFO' -Category 'PIPFILE_LOCK_JSON_PARSE_FAILED' -Title 'Pipfile.lock could not be parsed as JSON' -Path $File.FullName -Evidence 'The malformed lockfile was not used to infer exact package/version matches.' -Recommendation 'Check Pipfile.lock syntax before treating Python dependency coverage as complete.' -Check 'Packages' -DetectionMethod 'metadata'
        return $false
    }
}

function Scan-PythonDistributionMetadata {
    param([System.IO.FileInfo]$File)
    $header = Read-PythonDistributionHeader -File $File
    if (-not $header.ok) {
        Register-SecurityAnalysisLimit -File $File -FailureType ([string]$header.failureType)
        return
    }
    Add-ScanStat -Name 'filesScanned' -FilePath $File.FullName
    if (Test-CheckEnabled 'Packages') {
        Add-KnownPackageFinding -Ecosystem 'python' -Name ([string]$header.name) -Version ([string]$header.version) -Path $File.FullName -Line ([int]$header.versionLine) -EvidenceKind 'installed-exact'
    }
}

function Scan-PythonFiles {
    param([System.IO.FileInfo]$File, [string]$Text)
    $name = $File.Name.ToLowerInvariant()
    $path = $File.FullName.ToLowerInvariant()
    if ($name -notmatch '^(requirements.*\.txt|requirements\.ioc-sample|pyproject\.toml|pipfile|pipfile\.lock|poetry\.lock|uv\.lock|setup\.py|setup\.cfg|sitecustomize\.py|usercustomize\.py|direct_url\.json|record|_index\.js|\.bun_ran)$' -and -not $name.EndsWith('.pth')) {
        return
    }

    if (Test-CheckEnabled 'Packages') {
        if ($name -eq 'pipfile.lock') {
            [void](Scan-PipfileLockJson -File $File -Text $Text)
            return
        }
        if ($name -in @('poetry.lock','uv.lock')) {
            Scan-PythonTextLock -File $File -Text $Text
            return
        }
        Scan-KnownPackageText -File $File -Text $Text -Ecosystem 'python'
    }

    if ((Test-CheckEnabled 'LifecycleScripts') -and $name.EndsWith('.pth')) {
        if (Test-IsKnownSetuptoolsDistutilsPrecedenceHook -File $File -Text $Text) {
            Add-Finding -Severity 'INFO' -Category 'PYTHON_PTH_KNOWN_SETUPTOOLS_SHIM' -Title 'Known setuptools distutils compatibility hook detected' -Path $File.FullName -Line 1 -Evidence 'Exact canonical setuptools distutils-precedence.pth content matched.' -Recommendation 'No action is needed unless this environment or setuptools installation is untrusted.' -RiskType 'inventory' -Confidence 'high' -Check 'LifecycleScripts' -DetectionMethod 'static-file'
        }
        elseif ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)\bimport\b') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(exec|eval|subprocess|base64|requests|urllib|os\.environ|socket)')) {
            Add-Finding -Severity 'DANGER' -Category 'PYTHON_PTH_EXECUTION_HOOK' -Title 'Python .pth file contains execution hook pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\bimport\b') -Evidence '.pth file contains import plus execution/network/credential pattern. Line content redacted.' -Recommendation 'Inspect this environment hook without importing the package.'
        }
        elseif (Test-BoundedTextRegex -Text $Text -Pattern '(?is)\bimport\b') {
            Add-Finding -Severity 'CAUTION' -Category 'PYTHON_PTH_IMPORT_HOOK' -Title 'Python .pth file contains import hook' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\bimport\b') -Evidence '.pth file contains an import statement.' -Recommendation 'Verify that the import hook is expected.'
        }
    }

    if ((Test-CheckEnabled 'LifecycleScripts') -and $name -eq '_index.js') {
        $referencingPth = $null
        try {
            foreach ($pthPath in [System.IO.Directory]::GetFiles($File.DirectoryName, '*-setup.pth')) {
                $pthInfo = New-Object System.IO.FileInfo($pthPath)
                if ($pthInfo.Length -gt 65536) { continue }
                $pthText = [System.IO.File]::ReadAllText($pthPath)
                if ($pthText -match '(?i)_index\.js') { $referencingPth = $pthPath; break }
            }
        }
        catch {
        }
        if ($null -ne $referencingPth -and ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)(bun|bun\.sh|https?://|fetch\s*\(|request\s*\().{0,500}(subprocess|child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe)') -or (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(subprocess|child_process|spawn\s*\(|exec\s*\().{0,500}(bun|bun\.sh|https?://|fetch\s*\(|request\s*\()'))) {
            Add-Finding -Severity 'DANGER' -Category 'PYTHON_PTH_BUN_BOOTSTRAP_EXECUTION' -Title 'Python .pth hook references a Bun bootstrap with download and process execution' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(bun|https?://|subprocess|child_process|spawn|exec)') -Evidence 'Adjacent *-setup.pth references _index.js, which combines Bun/network and process execution patterns. Content redacted.' -Recommendation 'Do not import packages from this environment until the hook and adjacent files are reviewed.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'LifecycleScripts' -DetectionMethod 'static-file'
        }
    }

    if ((Test-CheckEnabled 'LifecycleScripts') -and $name -eq '.bun_ran') {
        $hasSetupPth = $false
        $hasIndex = $false
        try {
            $hasSetupPth = ([System.IO.Directory]::GetFiles($File.DirectoryName, '*-setup.pth').Count -gt 0)
            $hasIndex = Test-Path -LiteralPath (Join-Path $File.DirectoryName '_index.js') -PathType Leaf
        }
        catch {
        }
        if ($hasSetupPth -and $hasIndex) {
            Add-Finding -Severity 'WARN' -Category 'PYTHON_BUN_BOOTSTRAP_MARKER' -Title 'Python environment contains a Bun bootstrap marker beside a .pth hook' -Path $File.FullName -Evidence 'A .bun_ran marker, *-setup.pth, and _index.js coexist. Marker content was not reported.' -Recommendation 'Review the adjacent hook and script before importing packages.' -RiskType 'posture' -Confidence 'medium' -Check 'LifecycleScripts' -DetectionMethod 'metadata'
        }
    }

    if ((Test-CheckEnabled 'LifecycleScripts') -and ($name -eq 'sitecustomize.py' -or $name -eq 'usercustomize.py')) {
        if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(exec|eval|subprocess|base64|requests|urllib|os\.environ|socket|https?://)') {
            Add-Finding -Severity 'DANGER' -Category 'PYTHON_CUSTOMIZE_SUSPICIOUS' -Title 'Python startup customization contains suspicious pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(exec|eval|subprocess|base64|requests|urllib|os\.environ|socket|https?://)') -Evidence 'Python startup customization file contains execution/network/credential pattern. Line content redacted.' -Recommendation 'Inspect manually before running Python in this environment.'
        }
        else {
            Add-Finding -Severity 'CAUTION' -Category 'PYTHON_CUSTOMIZE_PRESENT' -Title 'Python startup customization file exists' -Path $File.FullName -Evidence 'sitecustomize.py or usercustomize.py is loaded automatically by Python.' -Recommendation 'Verify that this startup customization is expected.'
        }
    }

    if ((Test-CheckEnabled 'LifecycleScripts') -and $path.EndsWith('setup.py') -and (Test-ExternalExecutionPattern $Text)) {
        Add-Finding -Severity 'DANGER' -Category 'PYTHON_SETUP_EXTERNAL_EXECUTION' -Title 'setup.py contains external execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|https?://)') -Evidence 'setup.py contains external fetch/execution pattern. Line content redacted.' -Recommendation 'Do not execute package build/install until reviewed.'
    }
}

function Scan-ComposerFiles {
    param([System.IO.FileInfo]$File, [string]$Text)
    $name = $File.Name.ToLowerInvariant()
    $path = $File.FullName.ToLowerInvariant()
    if ($name -notin @('composer.json','composer.lock','autoload_files.php','installed.json')) {
        return
    }
    if (-not (Test-CheckEnabled 'LifecycleScripts')) {
        return
    }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)autoload\s*"?\s*:\s*.*files|autoload\.files') {
        Add-Finding -Severity 'CAUTION' -Category 'COMPOSER_AUTOLOAD_FILES' -Title 'Composer autoload.files entry detected' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'autoload') -Evidence 'Composer autoload.files can execute PHP files automatically.' -Recommendation 'Verify that every autoloaded file is expected.'
    }
    if ($path -match '\\vendor\\composer\\autoload_files\.php$') {
        Add-Finding -Severity 'CAUTION' -Category 'COMPOSER_AUTOLOAD_FILES_PRESENT' -Title 'Composer autoload_files.php exists' -Path $File.FullName -Evidence 'Composer autoload_files.php is a targeted execution surface.' -Recommendation 'Review referenced files if Composer dependencies are suspect.'
    }
    if (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(flipboxstudio\.info|shell_exec|proc_open|curl_exec|base64_decode\s*\(|eval\s*\(|assert\s*\(|file_get_contents\s*\(\s*["'']https?://)') {
        Add-Finding -Severity 'DANGER' -Category 'COMPOSER_SUSPICIOUS_EXECUTION' -Title 'Composer/PHP file contains suspicious execution or IOC pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(flipboxstudio\.info|shell_exec|proc_open|curl_exec|base64_decode|eval|assert|file_get_contents)') -Evidence 'Suspicious PHP execution or known IOC pattern. Line content redacted.' -Recommendation 'Preserve evidence and inspect dependency provenance.'
    }
}

function Get-GitHubActionUsesEntries {
    param([string]$Text)
    $entries = New-ArrayList
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $lineNumber = 0
    foreach ($line in ($Text -split "`r?`n")) {
        $lineNumber++
        $match = [regex]::Match($line, '^\s*(?:-\s*)?uses\s*:\s*["'']?([^"''\s#]+)', 'IgnoreCase')
        if (-not $match.Success) { continue }
        $value = [string]$match.Groups[1].Value
        if ($value.StartsWith('./') -or $value.StartsWith('.\') -or $value.StartsWith('docker://')) { continue }
        $atIndex = $value.LastIndexOf('@')
        if ($atIndex -le 0 -or $atIndex -ge ($value.Length - 1)) { continue }
        $target = $value.Substring(0, $atIndex)
        $reference = $value.Substring($atIndex + 1)
        $segments = $target -split '/'
        if ($segments.Count -lt 2) { continue }
        Add-ListItem $entries ([ordered]@{
            repository = (($segments[0] + '/' + $segments[1]).ToLowerInvariant())
            reference = $reference
            display = ($segments[0] + '/' + $segments[1] + '@' + $reference)
            line = $lineNumber
        })
    }
    return @($entries.ToArray())
}

function Get-ActionAdvisoryAssessment {
    param($Entry,$Advisory)
    if ([string]$Entry.repository -ine [string](Get-PropertyValue $Advisory 'repository')) { return $null }
    $reference=[string]$Entry.reference
    if ($reference -notmatch '^[vV]?[0-9]+\.[0-9]+\.[0-9]+$') { return [ordered]@{status='unresolved'; advisory=$Advisory; version=''} }
    $version=ConvertTo-NodeRuntimeVersion $reference
    if ($null -eq $version) { return [ordered]@{status='unresolved'; advisory=$Advisory; version=''} }
    $affected=$false
    foreach ($range in @((Get-PropertyValue $Advisory 'affectedRanges'))) {
        $max=ConvertTo-NodeRuntimeVersion ([string](Get-PropertyValue $range 'maxExclusive'))
        $minText=[string](Get-PropertyValue $range 'minInclusive')
        $min=if ([string]::IsNullOrWhiteSpace($minText)) { $null } else { ConvertTo-NodeRuntimeVersion $minText }
        if ($null -ne $max -and (Compare-NodeRuntimeVersion $version $max) -lt 0 -and ($null -eq $min -or (Compare-NodeRuntimeVersion $version $min) -ge 0)) { $affected=$true }
    }
    return [ordered]@{status=$(if ($affected) {'affected-reference'} else {'outside-declared-range'}); advisory=$Advisory; version=[string]$version.normalized}
}

function Scan-GitHubActionReferences {
    param([System.IO.FileInfo]$File, [string]$Text)
    $thirdPartyMutable = New-ArrayList
    foreach ($entry in @(Get-GitHubActionUsesEntries -Text $Text)) {
        foreach ($advisory in @($script:Context.iocs.actionAdvisories)) {
            $assessment=Get-ActionAdvisoryAssessment -Entry $entry -Advisory $advisory
            if ($null -eq $assessment -or $assessment.status -eq 'outside-declared-range') { continue }
            $unresolved=($assessment.status -eq 'unresolved')
            $category=if ($unresolved) {'GITHUB_ACTION_ADVISORY_REF_UNRESOLVED'} else {'GITHUB_ACTION_REFERENCE_VULNERABILITY'}
            $severity=if ($unresolved) {'INFO'} else {'WARN'}
            $confidence=if ($unresolved) {'low'} else {'medium'}
            Add-Finding -Severity $severity -Category $category -Title 'GitHub Action reference requires advisory review' -Path $File.FullName -Line $entry.line -Evidence ("advisory={0}; repository={1}; declaredVersion={2}; assessment={3}; mutable ref contents and exploit preconditions were not verified offline." -f [string](Get-PropertyValue $advisory 'id'),[string]$entry.repository,[string]$assessment.version,[string]$assessment.status) -Recommendation 'Review the published advisory, pull-request trust boundary, and a verified immutable Action commit. A numeric tag alone does not authenticate the runtime artifact.' -RiskType 'posture' -Confidence $confidence -Check 'CiCd' -DetectionMethod 'metadata' -RuleId 'action-reference-advisory' -SourceId ([string](Get-PropertyValue $advisory 'sourceId')) -UpstreamSeverity ([string](Get-PropertyValue $advisory 'upstreamSeverity'))
        }
        $matchedKnown = $false
        foreach ($ioc in @($script:Context.iocs.actions)) {
            if ([string]$ioc.repository -ne [string]$entry.repository) { continue }
            foreach ($commit in @($ioc.compromisedCommits)) {
                if ([string]$entry.reference -ieq [string]$commit) {
                    Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_KNOWN_COMPROMISED_COMMIT' -Title 'GitHub Action references a known compromised commit' -Path $File.FullName -Line $entry.line -Evidence ("action={0}; match=compromised-commit" -f $entry.display) -Recommendation 'Disable the workflow and review runs, artifacts, and exposed credentials associated with this Action reference.' -RiskType 'known-ioc' -Confidence 'high' -Check 'CiCd' -DetectionMethod 'metadata' -SourceId ([string](Get-PropertyValue $ioc 'sourceId'))
                    $matchedKnown = $true
                }
            }
            foreach ($knownRef in @($ioc.compromisedRefs)) {
                if ([string]$entry.reference -ceq [string]$knownRef) {
                    Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_HISTORICALLY_COMPROMISED_REF' -Title 'GitHub Action uses a historically affected mutable ref' -Path $File.FullName -Line $entry.line -Evidence ("action={0}; match=historically-affected-ref" -f $entry.display) -Recommendation 'Pin to a reviewed full commit SHA and verify the current ref target from a trusted source.' -RiskType 'known-ioc' -Confidence 'medium' -Check 'CiCd' -DetectionMethod 'metadata' -SourceId ([string](Get-PropertyValue $ioc 'sourceId'))
                    $matchedKnown = $true
                }
            }
        }
        if ($matchedKnown) { continue }
        if ([string]$entry.reference -match '^[0-9a-fA-F]{40}$') { continue }
        Add-ScanStat -Name 'githubActionMutableRefs'
        if ([string]$entry.reference -match '^(?i:main|master)$') {
            Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_BRANCH_REF' -Title 'GitHub Action uses a mutable branch reference' -Path $File.FullName -Line $entry.line -Evidence ("action={0}; referenceType=branch" -f $entry.display) -Recommendation 'Pin the Action to a reviewed full commit SHA.' -RiskType 'posture' -Confidence 'medium' -Check 'CiCd' -DetectionMethod 'metadata'
            continue
        }
        $owner = ([string]$entry.repository -split '/')[0]
        if ($owner -in @('actions','github')) {
            Add-ScanStat -Name 'githubActionOfficialMutableRefs'
            continue
        }
        Add-ListItem $thirdPartyMutable $entry
    }
    if ($thirdPartyMutable.Count -gt 0) {
        $first = $thirdPartyMutable[0]
        Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_MUTABLE_THIRD_PARTY_REFS' -Title 'Workflow uses third-party Actions without full commit SHA pinning' -Path $File.FullName -Line $first.line -Evidence ("count={0}; firstAction={1}; references are mutable" -f $thirdPartyMutable.Count, $first.display) -Recommendation 'Review each third-party Action and pin it to a full commit SHA.' -RiskType 'posture' -Confidence 'medium' -Check 'CiCd' -DetectionMethod 'metadata'
    }
}

function Scan-GitHubActions {
    param([System.IO.FileInfo]$File, [string]$Text)
    $path = $File.FullName.ToLowerInvariant()
    $isWorkflowFile = ($path -match '\\\.github\\workflows\\.*\.ya?ml$')
    if (-not $isWorkflowFile -and $path -notmatch '\\\.github\\actions\\') {
        return
    }
    if ($isWorkflowFile -and (Test-IsDependencyOrGeneratedArtifactPath $File.FullName)) {
        return
    }
    if ((Get-AiPathRole $File.FullName) -eq 'cache-data') {
        # A plugin's cached workflow is not installed as the consuming project's
        # CI. Keep its presence visible without claiming that its permissions
        # or triggers are active on this host. Other file checks still apply.
        $manual=Test-BoundedTextRegex -Text $Text -Pattern '(?im)^\s*workflow_dispatch\s*:'
        $oidc=Test-BoundedTextRegex -Text $Text -Pattern '(?im)^\s*id-token\s*:\s*write\s*$'
        Add-Finding -Severity 'INFO' -Category 'GITHUB_ACTIONS_CACHED_WORKFLOW_REFERENCE' -Title 'Cached GitHub Actions workflow retained as reference' -Path $File.FullName -SourceContext 'cache-data' -Line 1 -Evidence ("activation=unknown; cachedWorkflow=true; manualTrigger={0}; idTokenWrite={1}; owning repository and deployment were not queried." -f $manual.ToString().ToLowerInvariant(),$oidc.ToString().ToLowerInvariant()) -Recommendation 'Review the owning repository workflow only when assessing that repository; the cache copy does not establish active CI on this PC.' -RiskType 'inventory' -Confidence 'high' -Check 'CiCd' -DetectionMethod 'metadata'
        return
    }
    $scannerSelfReference = Test-IsScannerSelfIocReferencePath $File.FullName
    Scan-GitHubActionReferences -File $File -Text $Text
    $hasPullRequestTarget = Test-BoundedTextRegex -Text $Text -Pattern '(?im)^\s*pull_request_target\s*:|^\s*on\s*:\s*\[?[^\r\n]*pull_request_target'
    $allowsUnsafeCheckout = Test-BoundedTextRegex -Text $Text -Pattern '(?im)^\s*allow-unsafe-pr-checkout\s*:\s*true\s*$'
    $hasPrivilegedContext = Test-BoundedTextRegex -Text $Text -Pattern '(?is)(secrets\.|GITHUB_TOKEN|permissions\s*:.{0,400}(contents|packages|id-token|pull-requests)\s*:\s*write)'
    $checkoutAnchor = Get-BoundedTextRegexMatch -Text $Text -Pattern '(?is)uses\s*:\s*actions/checkout@[^\r\n]+.{0,900}(ref|repository)\s*:\s*[^\r\n]*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|head\.repo\.(full_name|clone_url))'
    if (-not $checkoutAnchor.Success -and $allowsUnsafeCheckout) {
        $checkoutAnchor = Get-BoundedTextRegexMatch -Text $Text -Pattern '(?im)^\s*allow-unsafe-pr-checkout\s*:\s*true\s*$'
    }
    $hasFollowOnExecution = $false
    if ($checkoutAnchor.Success) {
        $afterStart = $checkoutAnchor.Index + $checkoutAnchor.Length
        $afterLength = [Math]::Min(3000, $Text.Length - $afterStart)
        if ($afterLength -gt 0) {
            $afterCheckout = $Text.Substring($afterStart, $afterLength)
            $hasFollowOnExecution = ($afterCheckout -match '(?is)(\brun\s*:|npm\s+(install|ci|run)|pnpm\s+|yarn\s+|bun\s+|python\s+|node\s+|make\s+|gradle|mvn\s+)')
        }
    }
    if ($hasPullRequestTarget -and $checkoutAnchor.Success -and $hasPrivilegedContext -and $hasFollowOnExecution) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_PRIVILEGED_PR_HEAD_EXECUTION' -Title 'Privileged pull_request_target workflow checks out and executes untrusted PR code' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'pull_request_target|github\.event\.pull_request\.head') -Evidence 'Workflow combines pull_request_target, PR head checkout, privileged token/permissions, and follow-on execution. Values redacted.' -Recommendation 'Do not execute PR head code in a privileged workflow; split untrusted build and privileged follow-up jobs.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'CiCd' -DetectionMethod 'static-file'
    }
    elseif ($hasPullRequestTarget -and ($checkoutAnchor.Success -or $allowsUnsafeCheckout)) {
        Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_UNSAFE_PR_CHECKOUT_POSTURE' -Title 'pull_request_target workflow permits or requests untrusted PR checkout' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'pull_request_target|allow-unsafe-pr-checkout|github\.event\.pull_request\.head') -Evidence 'Untrusted PR checkout posture detected without the complete privileged execution compound.' -Recommendation 'Verify that no secrets, write token, or executable step can consume the checked-out PR content.' -RiskType 'posture' -Confidence 'medium' -Check 'CiCd' -DetectionMethod 'static-file'
    }
    $discussionSelfHosted = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)on\s*:\s*(\r?\n\s*)?discussion\b') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)runs-on\s*:\s*(\[.*self-hosted.*\]|self-hosted)') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)github\.event\.discussion\.body|github\.event\.comment\.body'))
    $discussionBodyInRun = Test-BoundedTextRegex -Text $Text -Pattern '(?is)run\s*:\s*(\||>)?.{0,600}github\.event\.(discussion|comment)\.body'
    if ($discussionSelfHosted -and $discussionBodyInRun) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_DISCUSSION_SELF_HOSTED_EXECUTION' -Title 'GitHub Actions workflow can execute discussion text on a self-hosted runner' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'github\.event\.(discussion|comment)\.body|self-hosted|discussion') -Evidence 'Workflow combines discussion/comment body input with self-hosted runner execution context. Line content redacted.' -Recommendation 'Disable or remove this workflow unless it is a deliberately reviewed internal automation.' -RiskType 'fetch-execute' -Confidence 'high'
    }
    elseif ($discussionSelfHosted) {
        Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_DISCUSSION_SELF_HOSTED_INPUT' -Title 'GitHub Actions workflow exposes discussion text to a self-hosted runner' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'github\.event\.(discussion|comment)\.body|self-hosted|discussion') -Evidence 'Workflow references discussion/comment body on a self-hosted runner, but direct run execution was not detected.' -Recommendation 'Review whether untrusted discussion text can influence commands, scripts, or action inputs.' -RiskType 'posture' -Confidence 'medium'
    }
    if ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)toJSON\s*\(\s*secrets\s*\)|secrets\.\*|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_RUNTIME_TOKEN') -and (Test-BoundedTextRegex -Text $Text -Pattern '(?is)actions/upload-artifact|upload-artifact|artifact_path|actionsSecrets\.json|truffleSecrets\.json')) {
        $campaignCorroboration = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)format-results\.txt|dependabot/github_actions/format/setup-formatter') -or $File.Name -ieq 'codeql_analysis.yml')
        $artifactEvidence = if ($campaignCorroboration) { 'Workflow references broad secret material near artifact upload behavior; Keyv/ChainDrop campaign marker also present. Secret values are not printed.' } else { 'Workflow references broad secret material near artifact upload behavior. Secret values are not printed.' }
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_SECRETS_ARTIFACT_EXFIL_PATTERN' -Title 'GitHub Actions workflow can package secrets into artifacts' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'toJSON\s*\(\s*secrets\s*\)|upload-artifact|actionsSecrets\.json|truffleSecrets\.json') -Evidence $artifactEvidence -Recommendation 'Inspect workflow history and rotate exposed credentials if this workflow ran.' -RiskType 'active-exfil' -Confidence 'high'
    }
    $externalExecutionLine = if ($scannerSelfReference) { $null } else { Get-GitHubActionsExternalExecutionLine -Text $Text }
    if ($null -ne $externalExecutionLine) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_EXTERNAL_EXECUTION' -Title 'GitHub Actions workflow contains fetch-and-execute pattern' -Path $File.FullName -Line $externalExecutionLine -Evidence 'Workflow contains external fetch plus shell/execution pattern. Line content redacted.' -Recommendation 'Review workflow provenance and disable unsafe execution paths before running CI.'
    }
    if (-not $scannerSelfReference -and (Test-SecretExfilPattern $Text)) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_SECRET_EXFIL_PATTERN' -Title 'GitHub Actions workflow references secrets with external transmission pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(secrets\.|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_RUNTIME_TOKEN|GITHUB_TOKEN)') -Evidence 'Secret/token reference appears near external transmission pattern. Secret values are not printed.' -Recommendation 'Inspect workflow changes and rotate affected credentials if compromise is plausible.'
    }
    if (-not $scannerSelfReference -and (Test-SecretHarvestingExternalSendPattern $Text)) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_SECRET_HARVEST_EXFIL_PATTERN' -Title 'GitHub Actions workflow contains secret harvesting and external send pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.npmrc|\.pypirc|\.netrc|\.ssh|\.aws|\.kube|process\.env|os\.environ|GITHUB_TOKEN|GH_TOKEN|TOKEN|SECRET)') -Evidence 'Workflow appears to collect credential material near an external send pattern. Values redacted.' -Recommendation 'Inspect workflow changes and rotate affected credentials if compromise is plausible.' -RiskType 'active-exfil' -Confidence 'high'
    }
    $manualTriggerLine = Get-FirstMatchLine -Text $Text -Pattern 'workflow_dispatch'
    if ($null -ne $manualTriggerLine) {
        $manualTriggerHasElevatedContext = Test-BoundedTextRegex -Text $Text -Pattern '(?is)(secrets\.|contents\s*:\s*write|packages\s*:\s*write|id-token\s*:\s*write|pull-requests\s*:\s*write|run\s*:\s*(\||>)?.{0,800}(github\.event\.inputs|inputs\.))'
        if ($manualTriggerHasElevatedContext) {
            Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_MANUAL_TRIGGER' -Title 'Manual GitHub Actions trigger has elevated execution context' -Path $File.FullName -Line $manualTriggerLine -Evidence 'workflow_dispatch is combined with secrets, write permission, or manual input used by a run step. Values redacted.' -Recommendation 'Restrict permissions and validate manual inputs before commands consume them.' -RiskType 'posture' -Confidence 'medium' -Check 'CiCd' -DetectionMethod 'static-file'
        }
        else {
            Add-Finding -Severity 'CAUTION' -Category 'GITHUB_ACTIONS_MANUAL_TRIGGER' -Title 'GitHub Actions workflow allows manual execution' -Path $File.FullName -Line $manualTriggerLine -Evidence 'workflow_dispatch is present without a detected secret, write-permission, or command-input compound.' -Recommendation 'Confirm that manual execution is intentional; no elevated compound was detected.' -RiskType 'posture' -Confidence 'low' -Check 'CiCd' -DetectionMethod 'static-file'
        }
    }
    $warnPatterns = [ordered]@{
        'pull_request_target' = 'GITHUB_ACTIONS_PULL_REQUEST_TARGET'
        'schedule\s*:' = 'GITHUB_ACTIONS_SCHEDULED_TRIGGER'
        'contents\s*:\s*write' = 'GITHUB_ACTIONS_CONTENTS_WRITE'
        'packages\s*:\s*write' = 'GITHUB_ACTIONS_PACKAGES_WRITE'
        'id-token\s*:\s*write' = 'GITHUB_ACTIONS_ID_TOKEN_WRITE'
        'npm\s+publish' = 'GITHUB_ACTIONS_NPM_PUBLISH'
        'twine\s+upload' = 'GITHUB_ACTIONS_TWINE_UPLOAD'
        'docker\s+push' = 'GITHUB_ACTIONS_DOCKER_PUSH'
    }
    foreach ($pattern in $warnPatterns.Keys) {
        $line = Get-FirstMatchLine -Text $Text -Pattern $pattern
        if ($null -ne $line) {
            Add-Finding -Severity 'WARN' -Category $warnPatterns[$pattern] -Title 'GitHub Actions workflow has risky CI posture' -Path $File.FullName -Line $line -Evidence ("Static workflow pattern matched: {0}" -f $warnPatterns[$pattern]) -Recommendation 'Review whether this permission or trigger is necessary and pinned.'
        }
    }
}

function Scan-HooksAndWorkspaceTasks {
    param([System.IO.FileInfo]$File, [string]$Text)
    $path = $File.FullName.ToLowerInvariant()
    $isTarget = $false
    if ($path -match '\\\.git\\hooks\\') { $isTarget = $true }
    if ($path -match '\\\.husky\\') { $isTarget = $true }
    if ($path -match '\\\.vscode\\(tasks|settings)\.json$') { $isTarget = $true }
    if (-not $isTarget) { return }

    if (Test-ExternalExecutionPattern $Text) {
        Add-Finding -Severity 'DANGER' -Category 'WORKSPACE_HOOK_EXTERNAL_EXECUTION' -Title 'Hook or workspace task contains external execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|https?://)') -Evidence 'Hook/task contains external fetch plus execution pattern. Line content redacted.' -Recommendation 'Do not execute hooks or tasks until reviewed.'
    }
    elseif (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(EncodedCommand|FromBase64String|Invoke-Expression|\biex\b)') {
        Add-Finding -Severity 'WARN' -Category 'WORKSPACE_HOOK_OBFUSCATION' -Title 'Hook or workspace task contains obfuscation pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(EncodedCommand|FromBase64String|Invoke-Expression|\biex\b)') -Evidence 'Hook/task contains encoded command or expression execution pattern.' -Recommendation 'Review before running project hooks or tasks.'
    }
}

function Add-McpCommandFragmentsFromObject {
    param($Object, $List, [string]$PropertyName, $State=$null, [int]$Depth=0)
    if ($null -eq $State) { $State=@{nodes=0;characters=0;limited=$false} }
    $State.nodes++
    if ($State.nodes -gt 8192 -or $Depth -gt 32 -or $List.Count -ge 256 -or $State.characters -ge 65536) { $State.limited=$true; return }
    if ($null -eq $Object) {
        return
    }

    $collect = ($PropertyName -match '^(command|cmd|args|executable)$')
    if ($Object -is [string]) {
        if ($collect) {
            if ($Object.Length+$State.characters -gt 65536) { $State.limited=$true; return }
            Add-ListItem $List ([string]$Object)
            $State.characters+=$Object.Length
        }
        return
    }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        foreach ($item in $Object) {
            Add-McpCommandFragmentsFromObject -Object $item -List $List -PropertyName $PropertyName -State $State -Depth ($Depth+1)
            if ($State.limited) { break }
        }
        return
    }

    foreach ($property in @($Object.PSObject.Properties)) {
        $name = $property.Name
        if ($name -match '^(command|cmd|args|executable)$') {
            Add-McpCommandFragmentsFromObject -Object $property.Value -List $List -PropertyName $name -State $State -Depth ($Depth+1)
        }
        elseif ($property.Value -is [System.Collections.IEnumerable] -or $property.Value -is [psobject]) {
            Add-McpCommandFragmentsFromObject -Object $property.Value -List $List -PropertyName '' -State $State -Depth ($Depth+1)
        }
        if ($State.limited) { break }
    }
}

function Get-McpCommandText {
    param([string]$Text, [System.IO.FileInfo]$File)
    # Escaped JSON property names can spell command keys, so they require parsing.
    if (-not (Test-BoundedTextRegex -Text $Text -Pattern '(?m)(["''](?:command|cmd|args|executable)["'']\s*:|^\s*(?:command|cmd|args|executable)\s*[:=]|\\u[0-9a-f]{4})')) { return '' }
    $fragments = New-ArrayList
    $state=@{nodes=0;characters=0;limited=$false}
    $jsonInvalid=$false
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $json = $Text | ConvertFrom-Json -ErrorAction Stop
        Add-McpCommandFragmentsFromObject -Object $json -List $fragments -PropertyName '' -State $state
    }
    catch {
        $jsonInvalid=($null -ne $File -and $File.Extension -ieq '.json')
    }
    finally {
        Register-ScannerActivityPerformance -Name 'McpCommandExtraction' -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp()-$started) -File $File
    }
    if ($fragments.Count -eq 0 -and -not $state.limited) {
        $lines = $Text -split "`r?`n"
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrEmpty($trimmed)) { continue }
            if ($trimmed.StartsWith('#') -or $trimmed.StartsWith('//')) { continue }
            $match = [regex]::Match($trimmed, '^(command|cmd|args|executable)\s*[:=]\s*(.+)$', 'IgnoreCase')
            if ($match.Success) {
                if ($fragments.Count -ge 256 -or $state.characters+$match.Groups[2].Value.Length -gt 65536) { $state.limited=$true; break }
                Add-ListItem $fragments $match.Groups[2].Value
                $state.characters+=$match.Groups[2].Value.Length
            }
        }
    }

    if (($state.limited -or $jsonInvalid) -and $null -ne $File) {
        $failureType=if ($state.limited) { 'analysis-limit' } else { 'parse-error' }
        $category=if ($state.limited) { 'MCP_COMMAND_ANALYSIS_LIMIT_REACHED' } else { 'MCP_COMMAND_CONFIG_PARSE_FAILED' }
        Register-CoverageFailure -Scope candidate -Path $File.FullName -Kind 'ai-command-config' -FailureType $failureType -Critical $false
        $script:Context.coverage.traversalComplete=$false
        Add-Finding -Severity WARN -Category $category -Title 'MCP command extraction did not cover the complete configuration' -Path $File.FullName -Evidence ("failureType={0}; limits: 8,192 nodes, depth 32, 256 fragments, 65,536 characters. Configuration values omitted." -f $failureType) -Recommendation 'Inspect the affected command configuration in a smaller valid file; partial extraction is not a completed negative result.' -RiskType limitation -Check AiMcp -DetectionMethod metadata
    }
    if ($fragments.Count -eq 0) {
        return ''
    }
    return [string]::Join("`n", [string[]]$fragments.ToArray())
}

function Test-HasUnpinnedNpx {
    param([string]$CommandText)
    if ([string]::IsNullOrEmpty($CommandText)) { return $false }
    if ($CommandText -notmatch '(?i)\bnpx(\.cmd|\.exe)?\b') { return $false }
    return ($CommandText -notmatch '(?i)(^|[\s"''=])((@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)|([A-Za-z0-9._-]+))@[0-9]+(\.[0-9A-Za-z-]+)+')
}

function Test-HasUnpinnedUvx {
    param([string]$CommandText)
    if ([string]::IsNullOrEmpty($CommandText)) { return $false }
    if ($CommandText -notmatch '(?i)\buvx(\.exe)?\b') { return $false }
    return ($CommandText -notmatch '(?i)==[0-9]+(\.[0-9A-Za-z-]+)+')
}

function Add-AiContextAggregate {
    param([string]$Role, [switch]$TokenReference)
    if ($TokenReference) {
        Add-ScanStat -Name 'aiTokenReferenceAggregated'
    }
    switch ($Role) {
        'reference-text' { Add-ScanStat -Name 'codexReferenceRiskAggregated' }
        'session-log' { Add-ScanStat -Name 'codexSessionRiskAggregated' }
        'cache-data' { Add-ScanStat -Name 'codexCacheRiskAggregated' }
        'plugin-metadata' { Add-ScanStat -Name 'codexPluginMetadataRiskAggregated' }
    }
}

function Scan-McpAndAgentConfigs {
    param([System.IO.FileInfo]$File, [string]$Text)
    $path = $File.FullName.ToLowerInvariant()
    $name = $File.Name.ToLowerInvariant()
    $role = Get-AiPathRole $File.FullName
    $isTarget = $false
    if ($name -in @('mcp.json','.mcp.json','claude_desktop_config.json','settings.json')) { $isTarget = $true }
    if ($role -ne 'normal') { $isTarget = $true }
    if ($path -match '\\(\.cursor|\.claude|\.windsurf|\.continue|\.gemini|\.opencode)\\') { $isTarget = $true }
    if (-not $isTarget) { return }

    $commandText = Get-McpCommandText -Text $Text -File $File
    $hasCommandText = -not [string]::IsNullOrEmpty($commandText)
    $isCommandConfig = ($role -in @('active-ai-config','cached-ai-config','plugin-metadata') -or ($role -eq 'normal' -and $name -in @('mcp.json','.mcp.json','claude_desktop_config.json','settings.json')))
    $isReferenceContext = ($role -in @('reference-text','session-log','cache-data'))
    $commandExfil=Get-AiSecretExfilAssessment -Text $commandText
    $toolLanguage=if ($File.Extension.ToLowerInvariant() -eq '.py') { 'python' } elseif ($File.Extension.ToLowerInvariant() -in @('.js','.mjs','.cjs','.ts','.tsx')) { 'javascript' } else { 'plain' }
    $toolExfil=if ($role -eq 'executable-tooling') { Get-AiSecretExfilAssessment -Text $Text -Language $toolLanguage } else { [ordered]@{detected=$false;index=0} }

    if ($isCommandConfig -and (Test-HasUnpinnedNpx -CommandText $commandText)) {
        $cached=($role -eq 'cached-ai-config')
        $severity=if ($cached) { 'CAUTION' } else { 'WARN' }
        $category=if ($cached) { 'MCP_CACHED_UNPINNED_NPX' } else { 'MCP_UNPINNED_NPX' }
        $risk=if ($cached) { 'capability' } else { 'posture' }
        Add-Finding -Severity $severity -Category $category -Title 'MCP command configuration selects an unpinned npx package' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\bnpx\b') -Evidence ("A declared command selects npx without a fixed package version; cachedConfig={0}; activation=unknown; command execution was not observed. Values redacted." -f $cached.ToString().ToLowerInvariant()) -Recommendation 'Verify whether this entry is enabled, then pin a vetted MCP server version before invoking it.' -RiskType $risk -Confidence 'medium' -Check 'AiMcp' -DetectionMethod 'static-file'
    }
    elseif ($role -eq 'executable-tooling' -and (Test-HasUnpinnedNpx -CommandText $commandText)) {
        $toolingProvenance = Get-AiToolingProvenance -Path $File.FullName
        Add-Finding -Severity 'CAUTION' -Category 'AI_TOOLING_UNPINNED_NPX' -Title 'AI tooling helper can invoke an unpinned npx package' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\bnpx\b') -Evidence ("A passive tooling helper contains unpinned npx capability; provenance={0}; provenance label is path-derived and not independently verified." -f $toolingProvenance) -Recommendation 'Pin the package before invoking this helper.' -RiskType 'capability' -Confidence 'medium' -Check 'AiMcp' -DetectionMethod 'static-file'
    }
    if ($isCommandConfig -and (Test-HasUnpinnedUvx -CommandText $commandText)) {
        $cached=($role -eq 'cached-ai-config')
        $severity=if ($cached) { 'CAUTION' } else { 'WARN' }
        $category=if ($cached) { 'MCP_CACHED_UNPINNED_UVX' } else { 'MCP_UNPINNED_UVX' }
        $risk=if ($cached) { 'capability' } else { 'posture' }
        Add-Finding -Severity $severity -Category $category -Title 'MCP command configuration selects an unpinned uvx package' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\buvx\b') -Evidence ("A declared command selects uvx without a fixed package version; cachedConfig={0}; activation=unknown; command execution was not observed. Values redacted." -f $cached.ToString().ToLowerInvariant()) -Recommendation 'Verify whether this entry is enabled, then pin a vetted MCP server version before invoking it.' -RiskType $risk -Confidence 'medium' -Check 'AiMcp' -DetectionMethod 'static-file'
    }
    elseif ($role -eq 'executable-tooling' -and (Test-HasUnpinnedUvx -CommandText $commandText)) {
        $toolingProvenance = Get-AiToolingProvenance -Path $File.FullName
        Add-Finding -Severity 'CAUTION' -Category 'AI_TOOLING_UNPINNED_UVX' -Title 'AI tooling helper can invoke an unpinned uvx package' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\buvx\b') -Evidence ("A passive tooling helper contains unpinned uvx capability; provenance={0}; provenance label is path-derived and not independently verified." -f $toolingProvenance) -Recommendation 'Pin the package before invoking this helper.' -RiskType 'capability' -Confidence 'medium' -Check 'AiMcp' -DetectionMethod 'static-file'
    }

    if ($isCommandConfig -and $hasCommandText -and (Test-AiFetchExecutePattern $commandText)) {
        Add-Finding -Severity 'DANGER' -Category 'MCP_AGENT_EXTERNAL_EXECUTION' -Title 'MCP or agent config contains external execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|raw\.githubusercontent|gist\.github|pastebin|https?://)') -Evidence 'Config command contains external fetch plus execution pattern. Values redacted.' -Recommendation 'Disable this config entry until manually reviewed.' -RiskType 'fetch-execute' -Confidence 'high'
    }
    elseif ($role -eq 'executable-tooling' -and (Test-AiFetchExecutePattern $Text)) {
        $toolingProvenance = Get-AiToolingProvenance -Path $File.FullName
        Add-Finding -Severity 'CAUTION' -Category 'AI_TOOLING_EXTERNAL_EXECUTION_CAPABILITY' -Title 'AI tooling script contains external execution capability' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|raw\.githubusercontent|gist\.github|pastebin|https?://)') -Evidence ("Passive executable tooling contains tightly coupled external fetch plus execution capability; provenance={0}; provenance label is path-derived and not independently verified. Values redacted." -f $toolingProvenance) -Recommendation 'Review the script before invoking this skill, plugin, or helper; active command configurations remain higher priority.' -RiskType 'capability' -Confidence 'medium' -Check 'AiMcp' -DetectionMethod 'static-file'
    }
    elseif ($role -eq 'active-ai-instruction' -and ((Test-AiFetchExecutePattern $Text) -or (Test-AiSecretExfilPattern $Text))) {
        Add-Finding -Severity 'WARN' -Category 'AI_INSTRUCTION_EXECUTION_OR_SECRET_SEND_PATTERN' -Title 'Active AI instruction file contains execution or secret-send guidance' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|https?://|GITHUB_TOKEN|NPM_TOKEN|\.npmrc|auth\.json)') -Evidence 'An instruction file consumed by an AI coding tool contains a fetch-execute or credential-send pattern. Text and values redacted.' -Recommendation 'Verify the instruction provenance and remove untrusted operational guidance before allowing an agent to act on it.' -RiskType 'posture' -Confidence 'medium'
    }
    elseif ($isReferenceContext -and ((Test-ExternalExecutionPattern $Text) -or (Test-KnownIocTextPattern $Text))) {
        Add-AiContextAggregate -Role $role
    }
    elseif ($role -eq 'plugin-metadata' -and -not $hasCommandText -and ((Test-ExternalExecutionPattern $Text) -or (Test-KnownIocTextPattern $Text))) {
        Add-AiContextAggregate -Role $role
    }

    if ($isCommandConfig -and $hasCommandText -and $commandExfil.detected) {
        Add-Finding -Severity 'DANGER' -Category 'AI_TOKEN_PATH_EXFIL_PATTERN' -Title 'AI token path appears with external transmission pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(Get-Content|ReadAllText|readFile|process\s*\.\s*env|\$env:|GITHUB_TOKEN|GH_TOKEN|auth\.json)') -Evidence 'AI command contains a bounded credential-access and external-transmission compound. Values redacted; this is a static heuristic, not proof of an actual transfer.' -Recommendation 'Preserve evidence and rotate affected credentials if compromise is plausible.' -RiskType 'active-exfil' -Confidence 'high'
    }
    elseif ($role -eq 'executable-tooling' -and $toolExfil.detected) {
        Add-Finding -Severity 'DANGER' -Category 'AI_TOKEN_PATH_EXFIL_PATTERN' -Title 'AI tooling script references token path with external transmission pattern' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $toolExfil.index) -Evidence 'Executable AI tooling contains a bounded credential-access and external-transmission compound outside literal inventory/comment data. Values redacted; this is a static heuristic, not proof of an actual transfer.' -Recommendation 'Preserve evidence and rotate affected credentials if compromise is plausible.' -RiskType 'active-exfil' -Confidence 'high'
    }
    elseif ($isReferenceContext -and (Test-AiTokenPathReference $Text)) {
        Add-AiContextAggregate -Role $role -TokenReference
    }
    elseif ($role -eq 'plugin-metadata' -and -not $hasCommandText -and (Test-AiTokenPathReference $Text)) {
        Add-AiContextAggregate -Role $role -TokenReference
    }

    if ($role -eq 'executable-tooling' -and (Test-AiRemoteInstallOrWriteCapability $Text) -and -not $toolExfil.detected) {
        Add-Finding -Severity 'CAUTION' -Category 'AI_TOOLING_REMOTE_INSTALL_OR_WRITE_CAPABILITY' -Title 'AI tooling can download, install, or write to a remote service' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(codeload\.github\.com|github\.com|api\.github\.com|--url|args\.url|POST|PUT|PATCH|DELETE|upload)') -Evidence 'Executable AI tooling has remote install/write capability. Values redacted.' -Recommendation 'Use only when the tool source and destination are trusted.' -RiskType 'capability' -Confidence 'medium'
    }
    elseif ($role -eq 'executable-tooling' -and (Test-AiAuthorizedGithubReadClient $Text)) {
        Add-Finding -Severity 'INFO' -Category 'AI_TOOLING_AUTHORIZED_API_CLIENT' -Title 'AI tooling uses an authorized GitHub API client' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(GITHUB_TOKEN|GH_TOKEN|Authorization|github_request|api\.github\.com)') -Evidence 'Tooling appears to use GitHub authorization for allowed GitHub read endpoints. Values redacted.' -Recommendation 'This is a capability note, not evidence of credential exfiltration by itself.' -RiskType 'capability' -Confidence 'low'
    }

    if ($isCommandConfig) {
        $envKeyMatches = @(Get-BoundedTextRegexMatches -Text $Text -Pattern '(?i)"([A-Za-z_][A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|KEY))"\s*:')
        foreach ($m in $envKeyMatches) {
            Add-Finding -Severity 'INFO' -Category 'MCP_AGENT_ENV_SECRET_NAME' -Title 'MCP or agent config references a secret-like environment variable name' -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $m.Index) -Evidence ("Environment variable name present: {0}. Value not displayed." -f $m.Groups[1].Value) -Recommendation 'Ensure the configured command is trusted before exposing this environment variable.'
        }
    }
}

function Register-JetBrainsAggregate {
    param([hashtable]$Map, [string]$Path)
    $root = Get-JetBrainsPluginAggregateRoot $Path
    $key = $root.ToLowerInvariant()
    if (-not $Map.ContainsKey($key)) {
        $Map[$key] = [ordered]@{ root=$root; count=0; representatives=(New-ArrayList) }
    }
    $entry = $Map[$key]
    $entry.count = [int]$entry.count + 1
    if ($entry.representatives.Count -lt 3) { Add-ListItem $entry.representatives $Path }
}

function Register-JetBrainsArchiveSkip {
    param([string]$Path)
    Add-ScanStat -Name 'jetBrainsArchivesSkipped'
    Register-JetBrainsAggregate -Map $script:Context.jetBrainsArchiveSkippedRoots -Path $Path
}

function Register-JetBrainsNativeArtifact {
    param([string]$Path)
    Add-ScanStat -Name 'jetBrainsNativeArtifacts'
    Register-JetBrainsAggregate -Map $script:Context.jetBrainsNativeRoots -Path $Path
}

function Read-JetBrainsArchiveEntryText {
    param($Entry, [int64]$MaxBytes)
    if ($null -eq $Entry -or [int64]$Entry.Length -lt 0 -or [int64]$Entry.Length -gt $MaxBytes) { return $null }
    $stream = $null
    $memory = $null
    try {
        $stream = $Entry.Open()
        $memory = New-Object System.IO.MemoryStream
        $stream.CopyTo($memory)
        if ($memory.Length -gt $MaxBytes) { return $null }
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        return $encoding.GetString($memory.ToArray()).TrimStart([char]0xFEFF)
    }
    catch { return $null }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $memory) { $memory.Dispose() }
    }
}

function ConvertFrom-JetBrainsPluginXmlText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text) -or (Test-BoundedTextRegex -Text $Text -Pattern '(?is)<!DOCTYPE|<!ENTITY')) { return $null }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 1048576
    $reader = $null
    $stringReader = $null
    try {
        $metadata = [ordered]@{ id=''; name=''; version=''; vendor=''; dependencies=(New-ArrayList) }
        $stringReader = New-Object System.IO.StringReader($Text)
        $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
        while ($reader.Read()) {
            if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $localName = $reader.LocalName.ToLowerInvariant()
            if ($localName -in @('id','name','version','vendor')) {
                $value = if ($reader.IsEmptyElement) { '' } else { $reader.ReadString().Trim() }
                if ($value.Length -gt 512) { $value = $value.Substring(0, 512) }
                $metadata[$localName] = $value
            }
            elseif ($localName -eq 'depends') {
                $value = if ($reader.IsEmptyElement) { '' } else { $reader.ReadString().Trim() }
                if (-not [string]::IsNullOrWhiteSpace($value) -and $value.Length -le 512) { Add-ListItem $metadata.dependencies $value }
            }
        }
        return $metadata
    }
    catch { return $null }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $stringReader) { $stringReader.Dispose() }
    }
}

function Scan-JetBrainsPluginMetadata {
    param($Metadata, [string]$DisplayPath)
    if ($null -eq $Metadata) { return }
    Add-ScanStat -Name 'jetBrainsPluginsInspected'
    $id = ([string]$Metadata.id).ToLowerInvariant()
    $name = ([string]$Metadata.name).ToLowerInvariant()
    $version = [string]$Metadata.version
    foreach ($ioc in @($script:Context.iocs.extensions)) {
        if ((Get-ExtensionIocPlatform $ioc) -ne 'jetbrains') { continue }
        $iocId = ([string]$ioc.id).ToLowerInvariant()
        $idMatch = (-not [string]::IsNullOrEmpty($id) -and $id -eq $iocId)
        $nameMatch = $false
        if ([bool](Get-PropertyValue $ioc 'allowNameFallback')) {
            $iocName = ([string](Get-PropertyValue $ioc 'name')).ToLowerInvariant()
            if ([string]::IsNullOrEmpty($iocName)) { $iocName = $iocId }
            $nameMatch = (-not [string]::IsNullOrEmpty($name) -and $name -eq $iocName)
        }
        if (-not $idMatch -and -not $nameMatch) { continue }
        $exactVersion = $false
        $watchlist = $false
        foreach ($badVersion in @($ioc.versions)) {
            if ([string]$badVersion -eq '*') { $watchlist = $true; continue }
            if (-not [string]::IsNullOrEmpty($version) -and (Normalize-Version ([string]$badVersion)) -eq (Normalize-Version $version)) { $exactVersion = $true }
        }
        if (-not $exactVersion -and -not $watchlist) { continue }
        $severity = if ($idMatch -and $exactVersion) { 'DANGER' } else { 'WARN' }
        $category = if ($severity -eq 'DANGER') { 'JETBRAINS_PLUGIN_KNOWN_IOC' } else { 'JETBRAINS_PLUGIN_WATCHLIST' }
        Add-Finding -Severity $severity -Category $category -Title 'JetBrains plugin metadata matches a local IOC rule' -Path $DisplayPath -SourceContext 'jetbrains-plugin' -Evidence ("platform=jetbrains; identityMatch={0}; versionMatch={1}; id={2}; version={3}" -f $(if ($idMatch) { 'id' } else { 'name-fallback' }), $(if ($exactVersion) { 'exact' } else { 'watchlist' }), $(if ($idMatch) { $id } else { '[name fallback]' }), $version) -Recommendation 'Verify plugin provenance and exact artifact hash before continuing IDE use.' -RiskType 'known-ioc' -Confidence $(if ($severity -eq 'DANGER') { 'high' } else { 'medium' }) -Check 'IdeExtensions' -DetectionMethod 'metadata'
    }
    foreach ($dependency in @($Metadata.dependencies)) {
        foreach ($ioc in @($script:Context.iocs.extensions)) {
            if ((Get-ExtensionIocPlatform $ioc) -ne 'jetbrains') { continue }
            if ([string]$dependency -ieq [string]$ioc.id) {
                Add-Finding -Severity 'WARN' -Category 'JETBRAINS_PLUGIN_REFERENCES_KNOWN_BAD_ID' -Title 'JetBrains plugin depends on a known suspicious plugin ID' -Path $DisplayPath -SourceContext 'jetbrains-plugin' -Evidence ("dependencyId={0}; installed dependency version not established" -f $dependency) -Recommendation 'Check whether the referenced plugin is installed and verify its exact version and hash.' -RiskType 'known-ioc' -Confidence 'medium' -Check 'IdeExtensions' -DetectionMethod 'metadata'
            }
        }
    }
}

function Test-IsUnsafeArchiveEntryName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $normalized = $Name -replace '\\', '/'
    return ($normalized -match '^/' -or $normalized -match '^[A-Za-z]:' -or $normalized -match '(^|/)\.\.(/|$)')
}

function Inspect-JetBrainsArchiveObject {
    param($Archive, [string]$DisplayPath, [hashtable]$State, [switch]$Nested)
    if ($null -eq $Archive) { return }
    $entryCount = [int]$Archive.Entries.Count
    if ($entryCount -gt (5000 - [int]$State.entriesInspected)) { throw 'archive entry limit exceeded' }
    $State.entriesInspected = [int]$State.entriesInspected + $entryCount
    Add-ScanStat -Name 'jetBrainsArchivesInspected'
    Add-ScanStat -Name 'jetBrainsArchiveEntriesInspected' -Amount $entryCount
    $entries = @($Archive.Entries | Sort-Object @{ Expression = {
        $name = ([string]$_.FullName).ToLowerInvariant() -replace '\\', '/'
        if ($name -match '(^|/)meta-inf/plugin\.xml$') { 0 }
        elseif ($name -match '(^|/)(install|setup|bootstrap|init|postinstall|preinstall)[^/]*\.(ps1|bat|cmd|sh|js|mjs|cjs|py)$') { 1 }
        elseif ($name -match '\.(ps1|bat|cmd|sh|js|mjs|cjs|py)$') { 2 }
        elseif ($name -match '\.(dll|so|dylib|exe|node)$') { 3 }
        else { 4 }
    } }, @{ Expression = { [string]$_.FullName } })
    foreach ($entry in $entries) {
        $entryName = [string]$entry.FullName
        if (Test-IsUnsafeArchiveEntryName $entryName) { throw 'unsafe archive entry name' }
        $lower = $entryName.ToLowerInvariant() -replace '\\', '/'
        if ($lower -match '(^|/)meta-inf/plugin\.xml$') {
            $xmlText = Read-JetBrainsArchiveEntryText -Entry $entry -MaxBytes 1048576
            $metadata = ConvertFrom-JetBrainsPluginXmlText -Text $xmlText
            if ($null -eq $metadata) { throw 'plugin.xml unavailable or malformed' }
            Scan-JetBrainsPluginMetadata -Metadata $metadata -DisplayPath ("{0}!/{1}" -f $DisplayPath, $entryName)
            continue
        }
        if ($lower -match '\.(dll|so|dylib|exe|node)$') {
            $State.nativeCount = [int]$State.nativeCount + 1
            Register-JetBrainsNativeArtifact -Path ("{0}!/{1}" -f $DisplayPath, $entryName)
            continue
        }
        if ($lower -match '\.(ps1|bat|cmd|sh|js|mjs|cjs|py)$') {
            if ([int]$State.scriptCount -ge 20 -or [int64]$entry.Length -gt 524288 -or ([int64]$State.scriptBytes + [int64]$entry.Length) -gt 5242880) {
                $State.limitExceeded = $true
                continue
            }
            $scriptText = Read-JetBrainsArchiveEntryText -Entry $entry -MaxBytes 524288
            if ($null -eq $scriptText) { continue }
            $State.scriptCount = [int]$State.scriptCount + 1
            $State.scriptBytes = [int64]$State.scriptBytes + [int64]$entry.Length
            if (Test-SecretHarvestingExternalSendPattern $scriptText) { $State.hasExfil = $true }
            if (Test-ExternalExecutionPattern $scriptText) { $State.hasFetchExec = $true }
            if (Test-BoundedTextRegex -Text $scriptText -Pattern '(?is)(https?://|curl|wget|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|fetch\s*\()') { $State.hasFetch = $true }
            if (Test-BoundedTextRegex -Text $scriptText -Pattern '(?is)(ProcessBuilder|Runtime\.getRuntime|child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe|/bin/sh)') { $State.hasProcess = $true }
            continue
        }
        if (-not $Nested -and $lower.EndsWith('.jar')) {
            if ([int]$State.nestedCount -ge 20 -or [int64]$entry.Length -gt 26214400 -or ([int64]$State.nestedBytes + [int64]$entry.Length) -gt 52428800) {
                $State.limitExceeded = $true
                continue
            }
            $stream = $null
            $memory = $null
            $nestedArchive = $null
            try {
                $State.nestedCount = [int]$State.nestedCount + 1
                $State.nestedBytes = [int64]$State.nestedBytes + [int64]$entry.Length
                $stream = $entry.Open()
                $memory = New-Object System.IO.MemoryStream
                $stream.CopyTo($memory)
                $memory.Position = 0
                $nestedArchive = New-Object System.IO.Compression.ZipArchive -ArgumentList @($memory, [System.IO.Compression.ZipArchiveMode]::Read, $false)
                Inspect-JetBrainsArchiveObject -Archive $nestedArchive -DisplayPath ("{0}!/{1}" -f $DisplayPath, $entryName) -State $State -Nested
            }
            finally {
                if ($null -ne $nestedArchive) { $nestedArchive.Dispose() }
                if ($null -ne $stream) { $stream.Dispose() }
                if ($null -ne $memory) { $memory.Dispose() }
            }
        }
    }
}

function Scan-JetBrainsArchive {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File -or -not (Test-IsJetBrainsPluginPath $File.FullName) -or $File.Extension.ToLowerInvariant() -notin @('.jar','.zip')) { return }
    if ($File.Length -gt 209715200) { Register-JetBrainsArchiveSkip -Path $File.FullName; return }
    $archive = $null
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $archive = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)
        $state = @{ nativeCount=0; scriptCount=0; scriptBytes=[int64]0; nestedCount=0; nestedBytes=[int64]0; entriesInspected=0; hasExfil=$false; hasFetchExec=$false; hasFetch=$false; hasProcess=$false; limitExceeded=$false }
        Inspect-JetBrainsArchiveObject -Archive $archive -DisplayPath $File.FullName -State $state
        if ([bool]$state.limitExceeded) { Register-JetBrainsArchiveSkip -Path $File.FullName }
        if ([bool]$state.hasExfil) {
            Add-Finding -Severity 'DANGER' -Category 'JETBRAINS_PLUGIN_SECRET_EXFIL_PATTERN' -Title 'JetBrains plugin script combines secret harvesting and external send' -Path $File.FullName -SourceContext 'jetbrains-plugin' -Evidence 'A bounded script entry matched secret harvesting plus external send. Script text and values are redacted.' -Recommendation 'Preserve the archive and verify its publisher and origin without executing it.' -RiskType 'active-exfil' -Confidence 'high' -Check 'IdeExtensions' -DetectionMethod 'archive-entry'
        }
        elseif ([bool]$state.hasFetchExec) {
            Add-Finding -Severity 'WARN' -Category 'JETBRAINS_PLUGIN_FETCH_EXECUTE_CAPABILITY' -Title 'JetBrains plugin script contains fetch-execute capability' -Path $File.FullName -SourceContext 'jetbrains-plugin' -Evidence 'A bounded executable script entry combined external retrieval with execution. Script text is redacted.' -Recommendation 'Verify plugin provenance and review the script offline before use.' -RiskType 'capability' -Confidence 'medium' -Check 'IdeExtensions' -DetectionMethod 'archive-entry'
        }
        elseif ([int]$state.nativeCount -gt 0 -and [bool]$state.hasFetch -and [bool]$state.hasProcess) {
            Add-Finding -Severity 'WARN' -Category 'JETBRAINS_PLUGIN_NATIVE_NETWORK_PROCESS_COMPOUND' -Title 'JetBrains plugin combines native artifacts with fetch and process capability' -Path $File.FullName -SourceContext 'jetbrains-plugin' -Evidence ("nativeArtifacts={0}; bounded scripts contain fetch and process indicators" -f $state.nativeCount) -Recommendation 'Verify the plugin archive hash, publisher, and expected native components.' -RiskType 'capability' -Confidence 'medium' -Check 'IdeExtensions' -DetectionMethod 'archive-entry'
        }
    }
    catch {
        Register-JetBrainsArchiveSkip -Path $File.FullName
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
    }
}

function Scan-JetBrainsPluginXml {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or $File.Name.ToLowerInvariant() -ne 'plugin.xml' -or -not (Test-IsJetBrainsPluginPath $File.FullName)) { return }
    $metadata = ConvertFrom-JetBrainsPluginXmlText -Text $Text
    if ($null -eq $metadata) { Register-JetBrainsArchiveSkip -Path $File.FullName; return }
    Scan-JetBrainsPluginMetadata -Metadata $metadata -DisplayPath $File.FullName
}

function Scan-IdeExtensionPackageJson {
    param([System.IO.FileInfo]$File, [string]$Text)
    $path = $File.FullName.ToLowerInvariant()
    $candidateMetadata=Get-SecurityCandidateMetadata $File.FullName
    if ($File.Name.ToLowerInvariant() -ne 'package.json' -or (-not (Test-IsVsCodeStyleExtensionPath $File.FullName) -and ($null -eq $candidateMetadata -or 'IdeExtensions' -notin @($candidateMetadata.ownerChecks)))) {
        return
    }
    try {
        $json = $Text | ConvertFrom-Json -ErrorAction Stop
        $publisher = [string](Get-PropertyValue $json 'publisher')
        $name = [string](Get-PropertyValue $json 'name')
        $version = [string](Get-PropertyValue $json 'version')
        $id = ''
        if (-not [string]::IsNullOrEmpty($publisher) -and -not [string]::IsNullOrEmpty($name)) {
            $id = ($publisher + '.' + $name).ToLowerInvariant()
        }
        foreach ($ioc in @($script:Context.iocs.extensions)) {
            if ((Get-ExtensionIocPlatform $ioc) -ne 'vscode') { continue }
            if ($id -eq $ioc.id) {
                foreach ($badVersion in @($ioc.versions)) {
                    if ($badVersion -eq '*' -or (Normalize-Version $badVersion) -eq (Normalize-Version $version)) {
                        $category = 'KNOWN_SUSPICIOUS_IDE_EXTENSION'
                        $title = 'Known suspicious IDE extension detected'
                        $confidence = [string]$ioc.confidence
                        if ([string]::IsNullOrEmpty($confidence)) { $confidence = 'high' }
                        if ([string]$ioc.matchType -eq 'id-watchlist') {
                            $category = 'IDE_EXTENSION_ID_WATCHLIST'
                            $title = 'IDE extension ID appears on a confirmed campaign watchlist'
                        }
                        Add-Finding -Severity $ioc.severity -Category $category -Title $title -Path $File.FullName -Evidence ("extension={0}; version={1}; matchType={2}" -f $id, $version, ([string]$ioc.matchType)) -Recommendation 'Verify the registry source, publisher, installed version, and file hashes before continuing IDE use.' -RiskType 'known-ioc' -Confidence $confidence -Check 'IdeExtensions' -DetectionMethod 'metadata' -SourceId ([string](Get-PropertyValue $ioc 'sourceId'))
                    }
                }
            }
        }

        $scripts = Get-PropertyValue $json 'scripts'
        if ($null -ne $scripts) {
            foreach ($prop in $scripts.PSObject.Properties) {
                if ($prop.Name -match '(preinstall|install|postinstall|prepare)') {
                    $scriptText = [string]$prop.Value
                    if (Test-SecretHarvestingExternalSendPattern $scriptText) {
                        Add-Finding -Severity 'DANGER' -Category 'IDE_EXTENSION_SECRET_EXFIL_PATTERN' -Title 'IDE extension lifecycle script contains secret harvesting and external send pattern' -Path $File.FullName -Evidence ("Extension script name: {0}. Script value redacted." -f $prop.Name) -Recommendation 'Preserve evidence and review extension provenance before continuing IDE use.' -RiskType 'active-exfil' -Confidence 'high'
                    }
                    elseif (Test-ExternalExecutionPattern $scriptText) {
                        Add-Finding -Severity 'DANGER' -Category 'IDE_EXTENSION_LIFECYCLE_EXTERNAL_EXECUTION' -Title 'IDE extension lifecycle script contains external execution pattern' -Path $File.FullName -Evidence ("Extension script name: {0}. Script value redacted." -f $prop.Name) -Recommendation 'Preserve evidence and review extension provenance before continuing IDE use.' -RiskType 'fetch-execute' -Confidence 'high'
                    }
                    else {
                        Add-Finding -Severity 'WARN' -Category 'IDE_EXTENSION_LIFECYCLE_SCRIPT' -Title 'IDE extension package has lifecycle script' -Path $File.FullName -Evidence ("Extension script name: {0}. Script value redacted." -f $prop.Name) -Recommendation 'Review extension package metadata before running package manager commands.'
                    }
                }
            }
        }
        $relatedIds = New-ArrayList
        Add-NpmEntrypointStrings -Value (Get-PropertyValue $json 'extensionDependencies') -List $relatedIds
        Add-NpmEntrypointStrings -Value (Get-PropertyValue $json 'extensionPack') -List $relatedIds
        foreach ($relatedId in @($relatedIds)) {
            foreach ($ioc in @($script:Context.iocs.extensions)) {
                if ((Get-ExtensionIocPlatform $ioc) -ne 'vscode') { continue }
                if ([string]$relatedId -ieq [string]$ioc.id) {
                    Add-Finding -Severity 'WARN' -Category 'IDE_EXTENSION_REFERENCES_KNOWN_BAD_ID' -Title 'Extension pack or dependency references a known suspicious extension ID' -Path $File.FullName -Evidence ("referencedExtension={0}; installed version not established" -f $relatedId) -Recommendation 'Check whether the referenced extension is installed and verify its exact version and provenance.' -RiskType 'known-ioc' -Confidence 'medium' -Check 'IdeExtensions' -DetectionMethod 'metadata'
                }
            }
        }
        if ($null -ne (Get-PropertyValue $json 'extensionDependencies')) {
            Add-Finding -Severity 'INFO' -Category 'IDE_EXTENSION_DEPENDENCIES' -Title 'IDE extension declares extension dependencies' -Path $File.FullName -Evidence 'extensionDependencies metadata present.' -Recommendation 'Verify dependency chain if extension provenance is suspect.'
        }
        if ($null -ne (Get-PropertyValue $json 'extensionPack')) {
            Add-Finding -Severity 'INFO' -Category 'IDE_EXTENSION_PACK' -Title 'IDE extension declares extension pack' -Path $File.FullName -Evidence 'extensionPack metadata present.' -Recommendation 'Verify every extension in the pack if provenance is suspect.'
        }
        if ($null -ne (Get-PropertyValue $json 'activationEvents')) {
            Add-Finding -Severity 'INFO' -Category 'IDE_EXTENSION_ACTIVATION_EVENTS' -Title 'IDE extension declares activation events' -Path $File.FullName -Evidence 'activationEvents metadata present.' -Recommendation 'Review activation surface if extension provenance is suspect.'
        }
    }
    catch {
        return
    }
}

function Scan-IdeExtensionExecutableText {
    param([System.IO.FileInfo]$File, [string]$Text)
    $path = $File.FullName.ToLowerInvariant()
    $isJetBrains = Test-IsJetBrainsPluginPath $File.FullName
    if (-not (Test-IsVsCodeStyleExtensionPath $File.FullName) -and -not $isJetBrains) {
        return
    }
    $ext = $File.Extension.ToLowerInvariant()
    if ($ext -notin @('.js','.mjs','.cjs','.ts','.tsx','.ps1','.sh','.bash','.py','.cmd','.bat')) {
        return
    }

    if (Test-SecretHarvestingExternalSendPattern $Text) {
        Add-Finding -Severity 'DANGER' -Category 'IDE_EXTENSION_SECRET_EXFIL_PATTERN' -Title 'IDE extension code contains secret harvesting and external send pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.npmrc|\.pypirc|\.netrc|\.ssh|\.aws|\.kube|process\.env|os\.environ|GITHUB_TOKEN|GH_TOKEN|TOKEN|SECRET)') -Evidence 'Extension code appears to collect credential material near an external send pattern. Values redacted.' -Recommendation 'Preserve evidence and review extension provenance before continuing IDE use.' -RiskType 'active-exfil' -Confidence 'high'
    }
    elseif (Test-ExternalExecutionPattern $Text) {
        $severity = if ($isJetBrains) { 'WARN' } else { 'DANGER' }
        Add-Finding -Severity $severity -Category 'IDE_EXTENSION_EXTERNAL_EXECUTION_PATTERN' -Title 'IDE extension code contains external execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|https?://)') -Evidence 'Extension code contains external fetch plus execution pattern. Values redacted.' -Recommendation 'Preserve evidence and review extension provenance before continuing IDE use.' -RiskType $(if ($isJetBrains) { 'capability' } else { 'fetch-execute' }) -Confidence $(if ($isJetBrains) { 'medium' } else { 'high' })
    }
}

function Scan-NativeExtensionArtifacts {
    param([System.IO.FileInfo]$File)
    $path = $File.FullName.ToLowerInvariant()
    if (Test-IsJetBrainsPluginPath $File.FullName) {
        if ($path.EndsWith('.node') -or $path.EndsWith('.dll') -or $path.EndsWith('.dylib') -or $path.EndsWith('.so') -or $path.EndsWith('.exe')) {
            Register-JetBrainsNativeArtifact -Path $File.FullName
        }
        return
    }
    if (-not (Test-IsVsCodeStyleExtensionPath $File.FullName)) {
        return
    }
    if ($path.EndsWith('.wasm')) {
        Add-ScanStat -Name 'wasmArtifactsFound'
        Add-Finding -Severity 'CAUTION' -Category 'IDE_EXTENSION_WASM_ARTIFACT' -Title 'IDE extension contains a WebAssembly artifact' -Path $File.FullName -Evidence 'WebAssembly artifact exists. File was not executed; presence alone is not proof of compromise.' -Recommendation 'Verify extension provenance and correlate with exact hash or loader-code findings.' -RiskType 'capability' -Confidence 'low' -Check 'IdeExtensions' -DetectionMethod 'metadata'
    }
    elseif ($path.EndsWith('.node') -or $path.EndsWith('.dll') -or $path.EndsWith('.dylib') -or $path.EndsWith('.so') -or $path.EndsWith('.vsix')) {
        Add-Finding -Severity 'CAUTION' -Category 'IDE_EXTENSION_NATIVE_ARTIFACT' -Title 'IDE extension contains native or packaged artifact' -Path $File.FullName -Evidence 'Native or VSIX artifact exists. File was not executed.' -Recommendation 'Verify publisher and artifact provenance if extension is unexpected.'
    }
}

function Test-KnownFileIocCheckEnabledForFile {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) { return $false }
    $pathLower = $File.FullName.ToLowerInvariant() -replace '/', '\'
    if (Test-IsJetBrainsPluginPath $File.FullName) { return (Test-CheckEnabled 'IdeExtensions') }
    if (Test-IsVsCodeStyleExtensionPath $File.FullName) { return (Test-CheckEnabled 'IdeExtensions') }
    $candidateMetadata = Get-SecurityCandidateMetadata $File.FullName
    if ($null -ne $candidateMetadata -and $candidateMetadata.ownerChecks -contains 'IdeExtensions') { return (Test-CheckEnabled 'IdeExtensions') }
    if ($null -ne $candidateMetadata -and $candidateMetadata.ownerChecks -contains 'Packages' -and (Test-CheckEnabled 'Packages')) { return $true }
    if ($pathLower -match '\\node_modules\\') { return (Test-CheckEnabled 'Packages') }
    if ($pathLower -match '\\\.github\\actions\\') { return (Test-CheckEnabled 'CiCd') }
    if (Test-CheckEnabled 'ScannerSelf') { return $true }
    foreach ($candidate in @(Get-KnownFileIocCandidates)) {
        if ($null -ne $candidate.pathRegex -and -not $candidate.pathRegex.IsMatch($File.FullName)) { continue }
        $ownerCheck = [string]$candidate.ownerCheck
        if ($ownerCheck -in $script:LeafCheckOrder -and (Test-CheckEnabled $ownerCheck) -and (Test-KnownFileIocMatch -File $File -Ioc $candidate.ioc)) { return $true }
    }
    return $false
}

function Scan-WasmLoaderBehavior {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    if ($File.Extension.ToLowerInvariant() -notin @('.js','.mjs','.cjs','.ts','.tsx','.jsx')) { return }
    if (-not (Test-BoundedTextRegex -Text $Text -Pattern '(?is)WebAssembly\.(instantiate|instantiateStreaming|compile|compileStreaming|Module)')) { return }
    $checkName = 'LifecycleScripts'
    if ((Test-IsVsCodeStyleExtensionPath $File.FullName) -or (Test-IsJetBrainsPluginPath $File.FullName)) {
        $checkName = 'IdeExtensions'
        if (-not (Test-CheckEnabled 'IdeExtensions')) { return }
    }
    elseif (-not (Test-CheckEnabled 'LifecycleScripts')) {
        return
    }
    $hasRemoteLoad = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)(fetch\s*\(|https?://|axios|request\s*\(|WebClient|HttpClient).{0,700}WebAssembly\.(instantiate|instantiateStreaming|compile|compileStreaming)') -or (Test-BoundedTextRegex -Text $Text -Pattern '(?is)WebAssembly\.(instantiate|instantiateStreaming|compile|compileStreaming).{0,700}(fetch\s*\(|https?://|axios|request\s*\()'))
    $hasDecodeProcessCompound = ((Test-BoundedTextRegex -Text $Text -Pattern '(?is)(Buffer\.from|atob\s*\(|base64|Uint8Array).{0,700}(child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe|\.vscode|\.cursor|\.claude|\.codex|\.windsurf)') -or (Test-BoundedTextRegex -Text $Text -Pattern '(?is)(child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe|\.vscode|\.cursor|\.claude|\.codex|\.windsurf).{0,700}(Buffer\.from|atob\s*\(|base64|Uint8Array)'))
    $hasKnownC2 = Test-BoundedTextRegex -Text $Text -Pattern '(?is)(dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)'
    $hasSecretExfil = Test-SecretHarvestingExternalSendPattern $Text
    $hasStrongCompound = ($hasSecretExfil -or $hasDecodeProcessCompound -or ($hasKnownC2 -and $hasRemoteLoad))
    $dependencyOrGenerated = Test-IsDependencyOrGeneratedArtifactPath $File.FullName
    $targetedDependencyPath = ($dependencyOrGenerated -and (Test-IsTargetedScanPath $File.FullName))
    if ($hasStrongCompound) {
        if ($dependencyOrGenerated -and -not $targetedDependencyPath -and -not $hasSecretExfil -and -not $hasKnownC2) {
            Add-Finding -Severity 'WARN' -Category 'WASM_EXECUTION_COMPOUND' -Title 'Dependency or generated WebAssembly loader appears near decoded process execution' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'WebAssembly\.|child_process|Buffer\.from|atob') -Evidence 'A dependency or generated artifact contains a local decode/process compound without secret exfiltration or a known C2 marker. Raw code and values are redacted.' -Recommendation 'Verify package or generated-artifact provenance before executing the loader.' -RiskType 'posture' -Confidence 'medium' -Check $checkName -DetectionMethod 'static-file'
        }
        else {
            Add-Finding -Severity 'DANGER' -Category 'WASM_EXECUTION_COMPOUND' -Title 'WebAssembly loader appears with exfiltration, known C2, or decoded process execution' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'WebAssembly\.|dodod\.lat|child_process|Buffer\.from|atob') -Evidence 'WebAssembly execution appears in a strong compound context. Raw code and values are redacted.' -Recommendation 'Preserve evidence and inspect the loader and referenced artifact without executing them.' -RiskType 'fetch-execute' -Confidence 'high' -Check $checkName -DetectionMethod 'static-file'
        }
    }
    elseif ($hasRemoteLoad) {
        Add-Finding -Severity 'CAUTION' -Category 'WASM_REMOTE_LOAD_CAPABILITY' -Title 'Code can load and execute WebAssembly from a network source' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'WebAssembly\.|fetch\s*\(|https?://') -Evidence 'Remote WebAssembly load capability detected without a strong malicious compound.' -Recommendation 'Verify the remote source, expected hash, and caller before execution.' -RiskType 'capability' -Confidence 'medium' -Check $checkName -DetectionMethod 'static-file'
    }
}

function Scan-File {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) { return }
    $completed = $false
    $oldStatPath=$script:CurrentFileStatPath
    $script:CurrentFileStatPath=$File.FullName
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    try {
        Scan-FileContent -File $File
        $completed = $true
    }
    finally {
        if ($completed) { $script:Context.processedFilePaths[$File.FullName.ToLowerInvariant()] = $true }
        $script:CurrentFileStatPath=$oldStatPath
        Register-ScannerActivityPerformance -Name 'FileProcessing' -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp()-$started) -File $File
    }
}

function Scan-FileContent {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) {
        return
    }
    Write-ScanHeartbeat -Stage 'scanning' -Path $File.FullName
    if (Test-IsVerifiedScannerArtifactSamplePath $File.FullName) {
        Add-ScanStat -Name 'filesSkipped'
        return
    }
    if (Test-IsOwnSyntheticSamplePath $File.FullName) {
        Add-ScanStat -Name 'filesSkipped'
        Add-ScanStat -Name 'syntheticSamplesSkipped'
        Add-ScanStat -Name 'syntheticSampleKnownSkipped'
        return
    }
    if (Test-IsSecretInventoryFile $File.FullName) {
        if (Test-CheckEnabled 'SecretsInventory') {
            Add-Finding -Severity 'INFO' -Category 'SECRET_FILE_PRESENT' -Title 'Credential or auth file exists' -Path $File.FullName -Evidence 'Credential file exists. Value was not read or displayed.' -Recommendation 'Rotate credentials if DANGER findings suggest compromise.' -Check 'SecretsInventory' -DetectionMethod 'inventory'
        }
        Add-ScanStat -Name 'filesSkipped'
        return
    }
    if (Test-IsNpmCacheBlobPath $File.FullName) {
        Add-ScanStat -Name 'filesSkipped'
        Add-ScanStat -Name 'cacheFilesSkipped'
        return
    }

    if (Test-KnownFileIocCheckEnabledForFile -File $File) {
        Invoke-ScannerStep -StepName 'Scan-KnownFileIocs' -File $File -ScriptBlock { Scan-KnownFileIocs -File $File }
    }
    if ((Test-CheckEnabled 'NodeRuntime') -and $File.Name.ToLowerInvariant() -eq 'node.exe') {
        $recognizedNodeRuntime = [bool](Invoke-ScannerStep -StepName 'Scan-NodeRuntimeBinary' -File $File -ScriptBlock { Scan-NodeRuntimeBinary -File $File })
        if ($recognizedNodeRuntime) {
            Add-ScanStat -Name 'filesSkipped'
            return
        }
    }
    if (Test-CheckEnabled 'IdeExtensions') {
        Invoke-ScannerStep -StepName 'Scan-NativeExtensionArtifacts' -File $File -ScriptBlock { Scan-NativeExtensionArtifacts -File $File }
        Invoke-ScannerStep -StepName 'Scan-JetBrainsArchive' -File $File -ScriptBlock { Scan-JetBrainsArchive -File $File }
    }
    $isJetBrainsPluginFile = Test-IsJetBrainsPluginPath $File.FullName
    if ($isJetBrainsPluginFile -and $File.Extension.ToLowerInvariant() -in @('.jar','.zip','.dll','.so','.dylib','.exe','.node')) {
        Add-ScanStat -Name 'filesSkipped'
        return
    }

    if ((Test-CheckEnabled 'Packages') -and $File.Name.ToLowerInvariant() -eq 'bun.lockb') {
        Add-ScanStat -Name 'filesSkipped'
        Register-CoverageFailure -Scope 'candidate' -Path $File.FullName -Kind 'lockfile' -FailureType 'unsupported-binary-lockfile' -Critical $true
        Add-Finding -Severity 'WARN' -Category 'BUN_LOCKB_UNSUPPORTED' -Title 'Binary bun.lockb cannot be structurally inspected' -Path $File.FullName -Evidence 'The binary Bun lockfile was detected but not parsed by this dependency-free PowerShell scanner.' -Recommendation 'Correlate with another approved offline parser or a text lockfile; do not treat this scan as complete dependency coverage.' -RiskType 'limitation' -Confidence 'high' -Check 'Packages' -DetectionMethod 'metadata'
        return
    }

    if (($File.Name -ieq 'METADATA') -and $File.FullName -match '(?i)[\\/]\S+\.dist-info[\\/]METADATA$' -and ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts'))) {
        Invoke-ScannerStep -StepName 'Scan-PythonDistributionMetadata' -File $File -ScriptBlock { Scan-PythonDistributionMetadata -File $File }
        return
    }

    $compressedKind=Get-CompressedFileKind -File $File
    if (-not [string]::IsNullOrEmpty($compressedKind)) {
        Add-ScanStat -Name 'filesSkipped'
        Add-ScanStat -Name 'likelyBinaryFilesSkipped'
        Add-ScanStat -Name 'compressedFilesSkipped'
        return
    }
    if (Test-IsLikelyBinaryFile -File $File) {
        Add-ScanStat -Name 'filesSkipped'
        Add-ScanStat -Name 'likelyBinaryFilesSkipped'
        return
    }

    $candidateMetadata=Get-SecurityCandidateMetadata $File.FullName
    if ($null -ne $candidateMetadata -and 'python-record' -in @($candidateMetadata.selectionReasons)) {
        $read=Read-BoundedSecurityCandidateText -File $File
        if (-not $read.ok) { Register-SecurityAnalysisLimit -File $File -FailureType ([string]$read.failureType); return }
    }
    else { $read = Read-TextFileSafe -File $File }
    if (-not $read.ok) {
        return
    }
    Add-ScanStat -Name 'filesScanned'
    $text = [string]$read.text
    $behaviorText = $text
    $fileName=$File.Name.ToLowerInvariant()
    $extension=$File.Extension.ToLowerInvariant()
    $normalizedPath=$File.FullName.ToLowerInvariant() -replace '/', '\'
    if (Test-CheckEnabled 'NodeRuntime') {
        Invoke-ScannerStep -StepName 'Scan-NodeRuntimeReference' -File $File -ScriptBlock { Scan-NodeRuntimeReference -File $File -Text $text }
    }
    if ($isJetBrainsPluginFile -and $File.Name.ToLowerInvariant() -eq 'plugin.xml') {
        if (Test-CheckEnabled 'IdeExtensions') {
            Invoke-ScannerStep -StepName 'Scan-JetBrainsPluginXml' -File $File -ScriptBlock { Scan-JetBrainsPluginXml -File $File -Text $text }
        }
        return
    }

    if (Test-CheckEnabled 'InvisibleUnicode') {
        Invoke-ScannerStep -StepName 'Scan-InvisibleUnicode' -File $File -ScriptBlock { Scan-InvisibleUnicode -File $File -Text $behaviorText }
        Invoke-ScannerStep -StepName 'Scan-GlassWormBehavior' -File $File -ScriptBlock { Scan-GlassWormBehavior -File $File -Text $behaviorText }
    }
    if ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts')) {
        if ($fileName -in @('package.json','package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb')) {
            Invoke-ScannerStep -StepName 'Scan-NpmFiles' -File $File -ScriptBlock { Scan-NpmFiles -File $File -Text $text }
        }
        if ($fileName -match '^(requirements.*\.txt|requirements\.ioc-sample|pyproject\.toml|pipfile|pipfile\.lock|poetry\.lock|uv\.lock|setup\.py|setup\.cfg|sitecustomize\.py|usercustomize\.py|direct_url\.json|record|_index\.js|\.bun_ran)$' -or $extension -eq '.pth') {
            Invoke-ScannerStep -StepName 'Scan-PythonFiles' -File $File -ScriptBlock { Scan-PythonFiles -File $File -Text $text }
        }
        if ($fileName -in @('composer.json','composer.lock','autoload_files.php','installed.json')) {
            Invoke-ScannerStep -StepName 'Scan-ComposerFiles' -File $File -ScriptBlock { Scan-ComposerFiles -File $File -Text $text }
        }
        if ($extension -in @('.js','.mjs','.cjs','.jsx','.ts','.tsx','.ps1','.cmd','.bat','.sh','.bash')) {
            Invoke-ScannerStep -StepName 'Scan-NpmRuntimeCode' -File $File -ScriptBlock { Scan-NpmRuntimeCode -File $File -Text $behaviorText }
        }
        Invoke-ScannerStep -StepName 'Scan-NpmIncidentContextMarkers' -File $File -ScriptBlock { Scan-NpmIncidentContextMarkers -File $File -Text $behaviorText }
    }
    if ((Test-CheckEnabled 'LifecycleScripts') -and $extension -eq '.gyp') {
        Invoke-ScannerStep -StepName 'Scan-GypBuildFile' -File $File -ScriptBlock { Scan-GypBuildFile -File $File -Text $behaviorText }
    }
    if ((Test-CheckEnabled 'LifecycleScripts') -or (Test-CheckEnabled 'CiCd') -or (Test-CheckEnabled 'IdeExtensions')) {
        Invoke-ScannerStep -StepName 'Scan-RuntimeTransferBehavior' -File $File -ScriptBlock { Scan-RuntimeTransferBehavior -File $File -Text $behaviorText }
    }
    if ((Test-CheckEnabled 'CiCd') -and $normalizedPath -match '\\.github\\(?:workflows\\.*\.ya?ml$|actions\\)') {
        Invoke-ScannerStep -StepName 'Scan-GitHubActions' -File $File -ScriptBlock { Scan-GitHubActions -File $File -Text $text }
    }
    if ((Test-CheckEnabled 'HooksAndTasks') -and $normalizedPath -match '\\(?:\.git\\hooks\\|\.husky\\|\.vscode\\(?:tasks|settings)\.json$)') {
        Invoke-ScannerStep -StepName 'Scan-HooksAndWorkspaceTasks' -File $File -ScriptBlock { Scan-HooksAndWorkspaceTasks -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-VscodeFolderOpenPersistence' -File $File -ScriptBlock { Scan-VscodeFolderOpenPersistence -File $File -Text $text }
    }
    if (Test-CheckEnabled 'AiMcp') {
        Invoke-ScannerStep -StepName 'Scan-McpAndAgentConfigs' -File $File -ScriptBlock { Scan-McpAndAgentConfigs -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-ClaudeSessionStartPersistence' -File $File -ScriptBlock { Scan-ClaudeSessionStartPersistence -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-ReferenceTextSecuritySamples' -File $File -ScriptBlock { Scan-ReferenceTextSecuritySamples -File $File -Text $text }
    }
    if (Test-CheckEnabled 'IdeExtensions') {
        Invoke-ScannerStep -StepName 'Scan-IdeExtensionPackageJson' -File $File -ScriptBlock { Scan-IdeExtensionPackageJson -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-IdeExtensionExecutableText' -File $File -ScriptBlock { Scan-IdeExtensionExecutableText -File $File -Text $text }
    }
    if ((Test-CheckEnabled 'LifecycleScripts') -or (Test-CheckEnabled 'IdeExtensions')) {
        Invoke-ScannerStep -StepName 'Scan-WasmLoaderBehavior' -File $File -ScriptBlock { Scan-WasmLoaderBehavior -File $File -Text $behaviorText }
    }
    if (Test-CheckEnabled 'ScannerSelf') {
        Invoke-ScannerStep -StepName 'Scan-KnownTextIocs' -File $File -ScriptBlock { Scan-KnownTextIocs -File $File -Text $behaviorText }
        Invoke-ScannerStep -StepName 'Scan-LocalSuspiciousTextPatterns' -File $File -ScriptBlock { Scan-LocalSuspiciousTextPatterns -File $File -Text $behaviorText }
    }
}

function Scan-Project {
    param([string]$RootPath)
    if ([string]::IsNullOrEmpty($RootPath)) {
        return
    }
    try {
        $resolved = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).Path
    }
    catch {
        $resolved = $RootPath
    }
    $oldCurrentScanRoot = $script:CurrentScanRoot
    $script:CurrentScanRoot = $resolved
    if ((Test-CheckEnabled 'IdeExtensions') -and $resolved -match '(?i)\.(vsix|zip)$' -and [System.IO.File]::Exists($resolved)) {
        Register-SecurityCandidateMetadata -Path $resolved -Kind 'incident-hash' -OwnerCheck 'IdeExtensions' -SelectionReason 'explicit-ide-archive' -BoundaryRoot ([System.IO.Path]::GetDirectoryName($resolved)) -Critical $true -Selected
    }
    if (Test-IsJetBrainsPluginPath $resolved) { Register-JetBrainsRoot -RootPath (Get-JetBrainsPluginAggregateRoot $resolved) }
    Add-ListItem $script:Context.scanRoots (ConvertTo-RedactedPath $resolved)
    $oldSkipOwnSyntheticSamples = $script:SkipOwnSyntheticSamples
    $oldSkipOwnReportArtifacts = $script:SkipOwnReportArtifacts
    $oldTargetedPerProjectFileLimit = $script:TargetedPerProjectFileLimit
    $isExplicitOwnSyntheticSampleRoot = Test-IsExplicitOwnSyntheticSampleRoot $resolved
    $isExplicitOwnReportArtifactRoot = Test-IsExplicitOwnReportArtifactRoot $resolved
    if ($isExplicitOwnSyntheticSampleRoot) {
        $script:Context.syntheticSamplesExplicit = $true
    }
    $script:SkipOwnSyntheticSamples = -not $isExplicitOwnSyntheticSampleRoot
    $script:SkipOwnReportArtifacts = -not $isExplicitOwnReportArtifactRoot

    if (-not $Quiet) { Write-Host ("      Project root: {0}" -f (ConvertTo-RedactedPath $resolved)) }
    try {
        if (Test-CheckEnabled 'NodeRuntime') { $script:Context.nodeRuntimeProjectScanPerformed = $true }
        $projectRoots = @()
        if ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts') -or (Test-CheckEnabled 'HooksAndTasks') -or (Test-CheckEnabled 'NodeRuntime') -or (Test-CheckEnabled 'IdeExtensions') -or (Test-CheckEnabled 'CiCd')) {
            $projectRoots = @(Get-DiscoveredProjectRoots -RootPath $resolved)
        }
        $script:TargetedPerProjectFileLimit = Get-TargetedDependencyPerProjectFileLimit -ProjectCount $projectRoots.Count
        $nodeRuntimePriority = New-ArrayList
        if (Test-CheckEnabled 'NodeRuntime') {
            foreach ($projectRoot in $projectRoots) {
                foreach ($candidate in @(Get-NodeRuntimeProjectCandidatePaths -ProjectRoot $projectRoot)) {
                    Add-NodeRuntimePriorityCandidate -List $nodeRuntimePriority -FilePath $candidate
                }
            }
        }
        $securityPriority = New-ArrayList
        foreach ($projectRoot in $projectRoots) {
            foreach ($file in @(Get-PrioritySecurityFileList -RootPath $projectRoot)) { Add-ListItem $securityPriority $file }
            Scan-BoundedGitRefIocs -ProjectRoot $projectRoot
        }
        $targeted = New-ArrayList
        if ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts') -or (Test-CheckEnabled 'HooksAndTasks') -or (Test-CheckEnabled 'IdeExtensions') -or (Test-CheckEnabled 'CiCd')) {
            foreach ($projectRoot in $projectRoots) {
                if (Test-RunFileBudgetExhausted) {
                    Register-RunFileBudgetReached -CandidatePath $projectRoot
                    break
                }
                foreach ($file in @(Get-TargetedDependencyFileList -RootPath $projectRoot)) {
                    Add-ListItem $targeted $file
                }
            }
        }
        $files = Get-SafeFileList -RootPath $resolved
        foreach ($file in @($nodeRuntimePriority) + @($securityPriority) + @($targeted) + @($files)) {
            if ($null -eq $file) { continue }
            Scan-File -File $file
        }
        Write-ScanHeartbeat -Stage 'root-complete' -Path $resolved -Force
    }
    finally {
        $script:SkipOwnSyntheticSamples = $oldSkipOwnSyntheticSamples
        $script:SkipOwnReportArtifacts = $oldSkipOwnReportArtifacts
        $script:TargetedPerProjectFileLimit = $oldTargetedPerProjectFileLimit
        $script:CurrentScanRoot = $oldCurrentScanRoot
    }
}

function Add-ExistingDirectoryCandidate {
    param(
        $List,
        [hashtable]$Seen,
        [string]$CandidatePath,
        [string]$FailureStatName
    )
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
        return
    }
    try {
        if (Test-Path -LiteralPath $CandidatePath -PathType Container) {
            $resolved = (Resolve-Path -LiteralPath $CandidatePath -ErrorAction Stop).Path
            $key = $resolved.ToLowerInvariant()
            if (-not $Seen.ContainsKey($key)) {
                $Seen[$key] = $true
                Add-ListItem $List $resolved
            }
        }
    }
    catch {
        if (-not [string]::IsNullOrEmpty($FailureStatName)) {
            Add-ScanStat -Name $FailureStatName
        }
    }
}

function Get-ValidationOnlyStaticRoots {
    param([string]$EnvName)
    if (-not $SyntheticValidation) {
        return [ordered]@{
            active = $false
            roots = @()
        }
    }

    $value = [Environment]::GetEnvironmentVariable($EnvName, 'Process')
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw ("SyntheticValidation requires {0} for this enabled host-root check." -f $EnvName)
    }

    $roots = New-ArrayList
    $seen = @{}
    $sampleRoot = Join-Path $script:BaseDir 'tests\samples'
    $reportRoot = Join-Path $script:BaseDir 'reports'
    foreach ($part in ($value -split ';')) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $candidate = $part.Trim()
        if (-not (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $sampleRoot) -and
            -not (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $reportRoot)) {
            continue
        }
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath $candidate
    }

    if ($roots.Count -eq 0) {
        throw ("SyntheticValidation rejected all roots from {0}; use an existing directory under this checker distribution tests/samples or reports directory." -f $EnvName)
    }

    return [ordered]@{
        active = $true
        roots = @($roots.ToArray())
    }
}

function Get-StaticNpmGlobalRoots {
    $validationRoots = Get-ValidationOnlyStaticRoots -EnvName 'DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_GLOBAL_ROOTS'
    if ($validationRoots.active) {
        return @($validationRoots.roots)
    }

    $roots = New-ArrayList
    $seen = @{}
    if (-not [string]::IsNullOrWhiteSpace($env:NPM_CONFIG_PREFIX)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $env:NPM_CONFIG_PREFIX 'node_modules')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $env:APPDATA 'npm\node_modules')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $env:USERPROFILE 'AppData\Roaming\npm\node_modules')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $env:ProgramFiles 'nodejs\node_modules')
    }
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $programFilesX86 'nodejs\node_modules')
    }
    return @($roots.ToArray())
}

function Add-NpmGlobalKnownPackageFinding {
    param([string]$Name, [string]$Version, [string]$PackageJsonPath)
    if ($null -eq $script:Context.iocs) { return }
    $normalizedVersion = Normalize-Version $Version
    foreach ($ioc in @($script:Context.iocs.packages)) {
        if ([string]$ioc.ecosystem -ne 'npm') { continue }
        if ([string]$ioc.name -ne $Name) { continue }
        foreach ($badVersion in @($ioc.versions)) {
            if ($badVersion -eq '*' -or (Normalize-Version $badVersion) -eq $normalizedVersion) {
                $severity = [string]$ioc.severity
                if ([string]::IsNullOrEmpty($severity)) { $severity = 'DANGER' }
                Add-Finding -Severity $severity -Category 'NPM_GLOBAL_KNOWN_COMPROMISED_PACKAGE' -Title 'Known compromised npm package found in static global root' -Path $PackageJsonPath -Evidence ("npm global package {0} version {1} matched local IOC baseline. npm was not executed." -f $Name, $normalizedVersion) -Recommendation 'Treat as high priority triage. Verify global package provenance without running npm.' -RiskType 'known-ioc' -Confidence 'high' -Check 'NpmGlobal' -DetectionMethod 'static-path'
            }
        }
    }
}

function Scan-NpmGlobalPackageJsonStatic {
    param([string]$PackageJsonPath)
    if (-not (Test-Path -LiteralPath $PackageJsonPath -PathType Leaf)) { return }
    Add-ScanStat -Name 'npmGlobalPackagesChecked'
    try {
        $file = New-Object System.IO.FileInfo($PackageJsonPath)
        $read = Read-TextFileSafe -File $file
        if (-not $read.ok) { return }
        $json = ([string]$read.text) | ConvertFrom-Json -ErrorAction Stop
        $name = [string](Get-PropertyValue $json 'name')
        $version = [string](Get-PropertyValue $json 'version')
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        Add-NpmGlobalKnownPackageFinding -Name $name -Version $version -PackageJsonPath $PackageJsonPath
        if (Test-NpmIncidentWatchlistPackageName $name) {
            Add-Finding -Severity 'INFO' -Category 'NPM_GLOBAL_INCIDENT_WATCHLIST_PACKAGE_NAME' -Title 'npm global package name appears in recent incident watchlist' -Path $PackageJsonPath -Evidence ("Package name={0}; version={1}; exact affected version not asserted. npm was not executed." -f $name, $version) -Recommendation 'Treat as context only unless exact IOC or behavior findings also appear.' -RiskType 'posture' -Confidence 'low' -Check 'NpmGlobal' -DetectionMethod 'static-path'
        }
        $scripts = Get-PropertyValue $json 'scripts'
        if ($null -ne $scripts) {
            foreach ($prop in $scripts.PSObject.Properties) {
                if ($prop.Name -match '^(preinstall|install|postinstall|prepare|prepublish|prepack|postpack)$') {
                    $scriptText = [string]$prop.Value
                    if (Test-SecretHarvestingExternalSendPattern $scriptText) {
                        Add-Finding -Severity 'DANGER' -Category 'NPM_GLOBAL_LIFECYCLE_SECRET_EXFIL_PATTERN' -Title 'npm global package lifecycle script contains secret harvesting and external send pattern' -Path $PackageJsonPath -Evidence ("Lifecycle script name: {0}. Script value redacted." -f $prop.Name) -Recommendation 'Inspect without running npm or package scripts.' -RiskType 'active-exfil' -Confidence 'high' -Check 'NpmGlobal' -DetectionMethod 'static-file'
                    }
                    elseif (Test-ExternalExecutionPattern $scriptText) {
                        Add-Finding -Severity 'DANGER' -Category 'NPM_GLOBAL_LIFECYCLE_EXTERNAL_EXECUTION' -Title 'npm global package lifecycle script contains external execution pattern' -Path $PackageJsonPath -Evidence ("Lifecycle script name: {0}. Script value redacted." -f $prop.Name) -Recommendation 'Inspect without running npm or package scripts.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'NpmGlobal' -DetectionMethod 'static-file'
                    }
                }
            }
        }
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'NPM_GLOBAL_PACKAGE_JSON_PARSE_FAILED' -Title 'npm global package.json could not be parsed' -Path $PackageJsonPath -Evidence 'Static npm global package metadata could not be parsed.' -Recommendation 'Inspect manually if this package is relevant.' -Check 'NpmGlobal' -DetectionMethod 'static-file'
    }
}

function Scan-NpmGlobalStatic {
    $roots = @(Get-StaticNpmGlobalRoots)
    if ($roots.Count -eq 0) {
        Add-Finding -Severity 'INFO' -Category 'NPM_GLOBAL_STATIC_ROOT_NOT_FOUND' -Title 'No static npm global root was found' -Path 'npm global static paths' -PathType 'virtual' -Evidence 'No common npm global node_modules folder exists in static candidate paths. npm root -g was not executed.' -Recommendation 'If a custom npm prefix is used, set NPM_CONFIG_PREFIX and rerun this check.' -Check 'NpmGlobal' -DetectionMethod 'static-path'
        return
    }
    foreach ($root in $roots) {
        Add-ScanStat -Name 'npmGlobalRootsFound'
        Add-Finding -Severity 'INFO' -Category 'NPM_GLOBAL_STATIC_ROOT' -Title 'Static npm global root inspected' -Path $root -PathType 'directory' -Evidence 'Potential npm global node_modules root found by static path. npm root -g was not executed.' -Recommendation 'Review WARN and DANGER findings under this root.' -Check 'NpmGlobal' -DetectionMethod 'static-path'
        try {
            $dirs = [System.IO.Directory]::GetDirectories($root)
            $seen = 0
            foreach ($dir in $dirs) {
                if ($seen -ge 5000) { break }
                $dirInfo = New-Object System.IO.DirectoryInfo($dir)
                if (Test-IsReparsePoint $dirInfo) { continue }
                if ($dirInfo.Name.StartsWith('@')) {
                    try {
                        foreach ($scopedDir in [System.IO.Directory]::GetDirectories($dirInfo.FullName)) {
                            if ($seen -ge 5000) { break }
                            $scopedInfo = New-Object System.IO.DirectoryInfo($scopedDir)
                            if (Test-IsReparsePoint $scopedInfo) { continue }
                            $seen++
                            Scan-NpmGlobalPackageJsonStatic (Join-Path $scopedInfo.FullName 'package.json')
                        }
                    }
                    catch {
                        Add-Finding -Severity 'INFO' -Category 'NPM_GLOBAL_STATIC_READ_LIMITATION' -Title 'Static npm global scope could not be fully enumerated' -Path $dirInfo.FullName -Evidence 'Access denied or enumeration failed while reading a scoped npm global package folder.' -Recommendation 'Run from an account with read access if this scope must be inspected.' -Check 'NpmGlobal' -DetectionMethod 'static-path'
                    }
                }
                else {
                    $seen++
                    Scan-NpmGlobalPackageJsonStatic (Join-Path $dirInfo.FullName 'package.json')
                }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'NPM_GLOBAL_STATIC_READ_LIMITATION' -Title 'Static npm global root could not be fully enumerated' -Path $root -Evidence 'Access denied or enumeration failed while reading static npm global root.' -Recommendation 'Run from an account with read access if this root must be inspected.' -Check 'NpmGlobal' -DetectionMethod 'static-path'
        }
    }
}

function Get-StaticNpmCacheRoots {
    $validationRoots = Get-ValidationOnlyStaticRoots -EnvName 'DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_CACHE_ROOTS'
    if ($validationRoots.active) {
        return @($validationRoots.roots)
    }

    $roots = New-ArrayList
    $seen = @{}
    if (-not [string]::IsNullOrWhiteSpace($env:NPM_CONFIG_CACHE)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath $env:NPM_CONFIG_CACHE -FailureStatName 'npmCacheAccessDenied'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $env:LOCALAPPDATA 'npm-cache') -FailureStatName 'npmCacheAccessDenied'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $env:APPDATA 'npm-cache') -FailureStatName 'npmCacheAccessDenied'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath (Join-Path $env:USERPROFILE '.npm') -FailureStatName 'npmCacheAccessDenied'
    }
    return @($roots.ToArray())
}

function Scan-NpmCacheTextMetadata {
    param([string]$FilePath, [string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }
    $matched = $false
    $entries = New-ArrayList
    $seen = @{}
    $entryLimit = 200
    $lineNumber = 0
    foreach ($line in ($Text -split "`r?`n")) {
        $lineNumber++
        if ($entries.Count -ge $entryLimit) { break }
        foreach ($match in [regex]::Matches($line, 'registry\.npmjs\.org/(?<name>@[^/\s"'']+/[^/\s"'']+|@[^%\s"'']+%2[fF][^/\s"'']+|[^/\s"'']+)/(?:-|[^\s"'']*)?(?<file>(?:@?[^/\s"'']+/)?[^/\s"'']+?)-(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)\.tgz', 'IgnoreCase')) {
            $name = $match.Groups['name'].Value -replace '%2[fF]','/'
            Add-UniquePackageEntry -List $entries -Seen $seen -Name $name -Version $match.Groups['version'].Value -Line $lineNumber
            if ($entries.Count -ge $entryLimit) { break }
        }
        foreach ($match in [regex]::Matches($line, '["'']name["'']\s*:\s*["''](?<name>(?:@[a-z0-9._-]+/)?[a-z0-9._-]+)["''].{0,600}?["'']version["'']\s*:\s*["''](?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)["'']', 'IgnoreCase')) {
            Add-UniquePackageEntry -List $entries -Seen $seen -Name $match.Groups['name'].Value -Version $match.Groups['version'].Value -Line $lineNumber
            if ($entries.Count -ge $entryLimit) { break }
        }
    }
    foreach ($entry in @($entries)) {
        if ($null -eq (Get-ExactPackageIocMatch -Ecosystem 'npm' -Name ([string]$entry.name) -Version ([string]$entry.version))) { continue }
        Add-Finding -Severity 'WARN' -Category 'NPM_CACHE_METADATA_KNOWN_PACKAGE' -Title 'Known npm package IOC appears in npm cache metadata' -Path $FilePath -Line $entry.line -Evidence ("Package={0}; version={1}; cache metadata only; npm cache ls was not executed." -f $entry.name,$entry.version) -Recommendation 'Cache metadata is not proof of installation or execution. Look for matching project or global package findings.' -RiskType 'posture' -Confidence 'medium' -Check 'NpmCache' -DetectionMethod 'metadata'
        $matched = $true
    }
    foreach ($watchName in @($script:NpmIncidentWatchlistNames)) {
        if (Test-BoundedTextRegex -Text $Text -Pattern ([regex]::Escape($watchName))) {
            Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_METADATA_WATCHLIST_PACKAGE' -Title 'Recent incident watchlist package appears in npm cache metadata' -Path $FilePath -Evidence ("Package name={0}; cache metadata only." -f $watchName) -Recommendation 'Treat as context only unless package is installed or behavior findings also appear.' -RiskType 'posture' -Confidence 'low' -Check 'NpmCache' -DetectionMethod 'metadata'
            $matched = $true
            break
        }
    }
    foreach ($prefix in @($script:NpmIncidentWatchlistPrefixes)) {
        if (Test-BoundedTextRegex -Text $Text -Pattern ([regex]::Escape($prefix))) {
            Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_METADATA_WATCHLIST_PACKAGE_PREFIX' -Title 'Recent incident watchlist package prefix appears in npm cache metadata' -Path $FilePath -Evidence ("Package prefix={0}; cache metadata only." -f $prefix) -Recommendation 'Treat as context only unless package is installed or behavior findings also appear.' -RiskType 'posture' -Confidence 'low' -Check 'NpmCache' -DetectionMethod 'metadata'
            $matched = $true
            break
        }
    }
    $marker = Get-NpmIncidentContextMarker -Text $Text
    if ($null -ne $marker) {
        Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_INCIDENT_MARKER_METADATA' -Title 'Recent npm incident marker appears in cache metadata' -Path $FilePath -Evidence ("marker={0}; cache metadata only." -f $marker.label) -Recommendation 'Treat as context only unless executable findings point to the same package.' -RiskType 'posture' -Confidence 'low' -Check 'NpmCache' -DetectionMethod 'metadata'
        $matched = $true
    }
    return $matched
}

function Scan-NpmCacheStatic {
    $roots = @(Get-StaticNpmCacheRoots)
    if ($roots.Count -eq 0) {
        Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_STATIC_ROOT_NOT_FOUND' -Title 'No static npm cache root was found' -Path 'npm cache static paths' -PathType 'virtual' -Evidence 'No common npm cache folder exists in static candidate paths. npm cache ls was not executed.' -Recommendation 'If a custom npm cache is used, set NPM_CONFIG_CACHE and rerun this check.' -Check 'NpmCache' -DetectionMethod 'static-path'
        return
    }

    foreach ($root in $roots) {
        Add-ScanStat -Name 'npmCacheRootsFound'
        Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_STATIC_ROOT' -Title 'Static npm cache root inspected' -Path $root -PathType 'directory' -Evidence 'Potential npm cache root found by static path. npm cache ls was not executed.' -Recommendation 'Cache findings are context only unless paired with installed package or executable findings.' -Check 'NpmCache' -DetectionMethod 'static-path'

        $contentV2 = Join-Path $root '_cacache\content-v2'
        if (Test-Path -LiteralPath $contentV2 -PathType Container) {
            Add-ScanStat -Name 'cacheFilesSkipped'
        }

        $metadataRoots = New-ArrayList
        $seen = @{}
        Add-ExistingDirectoryCandidate -List $metadataRoots -Seen $seen -CandidatePath (Join-Path $root '_cacache\index-v5') -FailureStatName 'npmCacheAccessDenied'
        Add-ExistingDirectoryCandidate -List $metadataRoots -Seen $seen -CandidatePath (Join-Path $root '_cacache\index-v6') -FailureStatName 'npmCacheAccessDenied'
        Add-ExistingDirectoryCandidate -List $metadataRoots -Seen $seen -CandidatePath (Join-Path $root '_cacache\index-v7') -FailureStatName 'npmCacheAccessDenied'
        if ($metadataRoots.Count -eq 0) {
            Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_STATIC_METADATA_NOT_FOUND' -Title 'npm cache metadata index was not found' -Path $root -Evidence 'No _cacache index-v5/v6/v7 folder was found. Cache content blobs were not decoded.' -Recommendation 'No action unless another finding points to npm cache.' -Check 'NpmCache' -DetectionMethod 'metadata'
            continue
        }

        $maxFiles = 500
        $filesSeen = 0
        foreach ($metadataRoot in @($metadataRoots)) {
            $queue = New-Object System.Collections.Queue
            $queue.Enqueue([string]$metadataRoot)
            while ($queue.Count -gt 0 -and $filesSeen -lt $maxFiles) {
                $dir = [string]$queue.Dequeue()
                try {
                    foreach ($filePath in [System.IO.Directory]::GetFiles($dir)) {
                        if ($filesSeen -ge $maxFiles) { break }
                        $filesSeen++
                        try {
                            $file = New-Object System.IO.FileInfo($filePath)
                            if ($file.Length -gt 1048576) {
                                Add-ScanStat -Name 'npmCacheMetadataFilesSkipped'
                                continue
                            }
                            $read = Read-TextFileSafe -File $file
                            if (-not $read.ok) {
                                Add-ScanStat -Name 'npmCacheMetadataFilesSkipped'
                                continue
                            }
                            Add-ScanStat -Name 'npmCacheMetadataFilesScanned'
                            [void](Scan-NpmCacheTextMetadata -FilePath $file.FullName -Text ([string]$read.text))
                        }
                        catch {
                            Add-ScanStat -Name 'npmCacheMetadataFilesSkipped'
                        }
                    }
                    foreach ($subdir in [System.IO.Directory]::GetDirectories($dir)) {
                        $subInfo = New-Object System.IO.DirectoryInfo($subdir)
                        if (Test-IsReparsePoint $subInfo) { continue }
                        $queue.Enqueue($subInfo.FullName)
                    }
                }
                catch {
                    Add-ScanStat -Name 'npmCacheAccessDenied'
                }
            }
        }
        if ($filesSeen -ge $maxFiles) {
            Add-ScanStat -Name 'npmCacheMetadataLimitReached'
            Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_STATIC_METADATA_LIMIT_REACHED' -Title 'npm cache metadata scan limit reached' -Path $root -Evidence ("Static npm cache metadata scan stopped after {0} files." -f $maxFiles) -Recommendation 'Narrow the cache path for deeper manual review if needed.' -Check 'NpmCache' -DetectionMethod 'metadata'
        }
    }
}

function Get-JetBrainsProfilePluginRoots {
    $result = New-ArrayList
    $seen = @{}
    foreach ($base in @($env:APPDATA, $env:LOCALAPPDATA)) {
        if ([string]::IsNullOrWhiteSpace($base)) { continue }
        $jetBrainsBase = Join-Path $base 'JetBrains'
        if (-not (Test-Path -LiteralPath $jetBrainsBase -PathType Container)) { continue }
        try {
            foreach ($productDir in @([System.IO.Directory]::GetDirectories($jetBrainsBase) | Sort-Object)) {
                $plugins = Join-Path $productDir 'plugins'
                if (-not (Test-Path -LiteralPath $plugins -PathType Container)) { continue }
                $full = [System.IO.Path]::GetFullPath($plugins)
                $key = $full.ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) { $seen[$key]=$true; Add-ListItem $result $full }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'JETBRAINS_ROOT_DISCOVERY_PARTIAL' -Title 'JetBrains plugin root discovery was partial' -Path $jetBrainsBase -Evidence 'A JetBrains product directory could not be enumerated.' -Recommendation 'Use an explicit -Path for a plugin folder that must be inspected.' -Check 'IdeExtensions' -DetectionMethod 'metadata'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE) -and (Test-Path -LiteralPath $env:USERPROFILE -PathType Container)) {
        try {
            foreach ($legacy in @([System.IO.Directory]::GetDirectories($env:USERPROFILE) | Sort-Object)) {
                $leaf = [System.IO.Path]::GetFileName($legacy).ToLowerInvariant()
                if ($leaf -notmatch '^\.(idea|intellijidea|pycharm|webstorm|phpstorm|rubymine|clion|datagrip|goland|rider|androidstudio)') { continue }
                $plugins = Join-Path $legacy 'config\plugins'
                if (-not (Test-Path -LiteralPath $plugins -PathType Container)) { continue }
                $full = [System.IO.Path]::GetFullPath($plugins)
                $key = $full.ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) { $seen[$key]=$true; Add-ListItem $result $full }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'JETBRAINS_LEGACY_ROOT_DISCOVERY_PARTIAL' -Title 'Legacy JetBrains plugin root discovery was partial' -Path '~' -Evidence 'Legacy product directories could not be fully enumerated.' -Recommendation 'Use an explicit -Path for a legacy plugin folder that must be inspected.' -Check 'IdeExtensions' -DetectionMethod 'metadata'
        }
    }
    foreach ($root in @($result)) { Register-JetBrainsRoot -RootPath ([string]$root) }
    return @($result | Sort-Object)
}

function Get-JetBrainsTargetedFileList {
    param([string]$RootPath)
    $result = New-ArrayList
    if ([string]::IsNullOrWhiteSpace($RootPath) -or -not (Test-Path -LiteralPath $RootPath -PathType Container)) { return $result }
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($RootPath)
    $directoriesVisited = 0
    while ($queue.Count -gt 0 -and $directoriesVisited -lt 20000) {
        $dirPath = [string]$queue.Dequeue()
        $directoriesVisited++
        try {
            $dirInfo = New-Object System.IO.DirectoryInfo($dirPath)
            if (Test-IsReparsePoint $dirInfo) { continue }
            foreach ($filePath in @([System.IO.Directory]::GetFiles($dirPath) | Sort-Object)) {
                Add-ScanStat -Name 'filesEnumerated' -FilePath $filePath
                $name = [System.IO.Path]::GetFileName($filePath).ToLowerInvariant()
                $extension = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()
                if ($name -ne 'plugin.xml' -and $extension -notin @('.jar','.zip','.dll','.so','.dylib','.exe','.node','.ps1','.bat','.cmd','.sh','.js','.mjs','.cjs','.py')) { continue }
                if (Test-IsVerifiedScannerArtifactSamplePath $filePath) { Add-ScanStat -Name 'filesSkipped' -FilePath $filePath; continue }
                if (Test-IsOwnSyntheticSamplePath $filePath) { Add-ScanStat -Name 'filesSkipped' -FilePath $filePath; Add-ScanStat -Name 'syntheticSamplesSkipped' -FilePath $filePath; Add-ScanStat -Name 'syntheticSampleKnownSkipped' -FilePath $filePath; continue }
                if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $filePath)) { Add-ScanStat -Name 'filesSkipped' -FilePath $filePath; Add-ScanStat -Name 'scannerReportArtifactsSkipped'; continue }
                if (Reserve-ScanFile -FilePath $filePath) { Add-ListItem $result (New-Object System.IO.FileInfo($filePath)) }
            }
            foreach ($subdir in @([System.IO.Directory]::GetDirectories($dirPath) | Sort-Object)) {
                $subInfo = New-Object System.IO.DirectoryInfo($subdir)
                if (-not (Test-IsReparsePoint $subInfo)) { $queue.Enqueue($subInfo.FullName) }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'JETBRAINS_PLUGIN_ENUMERATION_PARTIAL' -Title 'JetBrains plugin directory enumeration was partial' -Path $dirPath -Evidence 'An inaccessible plugin directory was skipped.' -Recommendation 'Use an account with read access if this plugin must be inspected.' -Check 'IdeExtensions' -DetectionMethod 'metadata'
        }
    }
    if ($directoriesVisited -ge 20000) {
        Add-Finding -Severity 'INFO' -Category 'JETBRAINS_PLUGIN_ENUMERATION_LIMIT_REACHED' -Title 'JetBrains plugin directory limit reached' -Path $RootPath -Evidence 'Targeted JetBrains traversal stopped after 20,000 directories.' -Recommendation 'Scan a specific plugin directory directly for deeper inspection.' -Check 'IdeExtensions' -DetectionMethod 'metadata'
    }
    return $result
}

function Scan-UserProfileMode {
    param([switch]$MajorOnly)

    if ([string]::IsNullOrEmpty($env:USERPROFILE)) {
        Add-Finding -Severity 'INFO' -Category 'USERPROFILE_NOT_AVAILABLE' -Title 'USERPROFILE environment variable is not available' -Evidence 'User profile scan could not resolve USERPROFILE.' -Recommendation 'Run with an explicit path if profile data must be inspected.'
        return
    }

    $profileScanRootsSeen = @{}
    if (-not $MajorOnly) {
        Add-ListItem $script:Context.scanRoots '~'
        $profileScanRootsSeen['~'] = $true
    }
    if (Test-CheckEnabled 'IdeExtensions') {
        foreach ($jetBrainsRoot in @(Get-JetBrainsProfilePluginRoots)) {
            if ($MajorOnly) {
                $jetBrainsRootKey = ([string]$jetBrainsRoot).ToLowerInvariant()
                if (-not $profileScanRootsSeen.ContainsKey($jetBrainsRootKey)) {
                    Add-ListItem $script:Context.scanRoots (ConvertTo-RedactedPath $jetBrainsRoot)
                    $profileScanRootsSeen[$jetBrainsRootKey] = $true
                }
            }
            foreach ($file in @(Get-JetBrainsTargetedFileList -RootPath $jetBrainsRoot)) { Scan-File -File $file }
        }
    }

    $extensionRoots = @(
        (Join-Path $env:USERPROFILE '.vscode\extensions'),
        (Join-Path $env:USERPROFILE '.vscode-insiders\extensions'),
        (Join-Path $env:USERPROFILE '.cursor\extensions'),
        (Join-Path $env:USERPROFILE '.windsurf\extensions'),
        (Join-Path $env:USERPROFILE '.vscodium\extensions'),
        (Join-Path $env:USERPROFILE '.positron\extensions'),
        (Join-Path $env:USERPROFILE '.antigravity\extensions')
    )
    foreach ($root in $extensionRoots) {
        if (-not (Test-CheckEnabled 'IdeExtensions')) { break }
        if (Test-Path -LiteralPath $root -PathType Container) {
            if ($MajorOnly) {
                $rootKey = ([string]$root).ToLowerInvariant()
                if (-not $profileScanRootsSeen.ContainsKey($rootKey)) {
                    Add-ListItem $script:Context.scanRoots (ConvertTo-RedactedPath $root)
                    $profileScanRootsSeen[$rootKey] = $true
                }
            }
            $files = Get-SafeFileList -RootPath $root
            foreach ($file in @($files)) {
                Scan-File -File $file
            }
        }
    }

    $configCandidates = New-ArrayList
    if (-not [string]::IsNullOrEmpty($env:APPDATA)) {
        Add-ListItem $configCandidates (Join-Path $env:APPDATA 'Claude\claude_desktop_config.json')
        foreach ($editor in @('Code','Code - Insiders','Cursor','Windsurf','VSCodium','Positron')) {
            Add-ListItem $configCandidates (Join-Path $env:APPDATA ($editor + '\User\settings.json'))
            Add-ListItem $configCandidates (Join-Path $env:APPDATA ($editor + '\User\mcp.json'))
        }
    }
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.cursor')
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.claude')
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.continue')
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.gemini')
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.opencode')
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.mcp.json')

    $codexRoots = New-ArrayList
    Add-ListItem $codexRoots (Join-Path $env:USERPROFILE '.codex')
    $validatedCodexHome = $null
    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
        $validatedCodexHome = Get-SafeAutomaticProfileRoot -CandidatePath $env:CODEX_HOME -EnvironmentName 'CODEX_HOME'
        if (-not [string]::IsNullOrEmpty($validatedCodexHome)) {
            Add-ListItem $codexRoots $validatedCodexHome
        }
    }
    $codexRootsSeen = @{}
    foreach ($codexRoot in @($codexRoots)) {
        $codexRootKey = [string](Get-FullPathSafe $codexRoot)
        if ([string]::IsNullOrEmpty($codexRootKey)) { $codexRootKey = [string]$codexRoot }
        $codexRootKey = $codexRootKey.ToLowerInvariant()
        if ($codexRootsSeen.ContainsKey($codexRootKey)) { continue }
        $codexRootsSeen[$codexRootKey] = $true
        if ($MajorOnly) {
            foreach ($relative in @('config.toml','mcp.json','.mcp.json','AGENTS.md','agents','rules','skills','vendor_imports\skills','plugins\cache')) {
                Add-ListItem $configCandidates (Join-Path $codexRoot $relative)
            }
        }
        else {
            Add-ListItem $configCandidates $codexRoot
        }
    }
    $claudeConfigDir = [Environment]::GetEnvironmentVariable('CLAUDE_CONFIG_DIR', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($claudeConfigDir)) {
        $validatedClaudeConfigDir = Get-SafeAutomaticProfileRoot -CandidatePath $claudeConfigDir -EnvironmentName 'CLAUDE_CONFIG_DIR'
        if (-not [string]::IsNullOrEmpty($validatedClaudeConfigDir)) {
            Add-ListItem $configCandidates $validatedClaudeConfigDir
        }
    }
    if (-not $MajorOnly) {
        Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.config')
    }
    else {
        foreach ($relative in @('.config\claude','.config\continue','.config\gemini','.config\opencode')) {
            Add-ListItem $configCandidates (Join-Path $env:USERPROFILE $relative)
        }
    }
    foreach ($candidate in $configCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            if ($MajorOnly) {
                $candidateKey = ([string](Get-FullPathSafe $candidate)).ToLowerInvariant()
                if (-not $profileScanRootsSeen.ContainsKey($candidateKey)) {
                    Add-ListItem $script:Context.scanRoots (ConvertTo-RedactedPath $candidate)
                    $profileScanRootsSeen[$candidateKey] = $true
                }
            }
            $files = Get-SafeFileList -RootPath $candidate
            foreach ($file in @($files)) {
                Scan-File -File $file
            }
        }
    }

    $secretCandidates = @(
        (Join-Path $env:USERPROFILE '.npmrc'),
        (Join-Path $env:USERPROFILE '.pypirc'),
        (Join-Path $env:USERPROFILE '.netrc'),
        (Join-Path $env:USERPROFILE '.ssh\id_rsa'),
        (Join-Path $env:USERPROFILE '.ssh\id_ed25519'),
        (Join-Path $env:USERPROFILE '.aws\credentials'),
        (Join-Path $env:USERPROFILE '.kube\config'),
        (Join-Path $env:USERPROFILE '.codex\auth.json'),
        (Join-Path $env:USERPROFILE '.gemini\oauth_creds.json'),
        (Join-Path $env:USERPROFILE '.git-credentials')
    )
    if (-not [string]::IsNullOrEmpty($validatedCodexHome)) {
        $secretCandidates += (Join-Path $validatedCodexHome 'auth.json')
    }
    foreach ($secret in $secretCandidates) {
        if (Test-Path -LiteralPath $secret -PathType Leaf) {
            if (Test-CheckEnabled 'SecretsInventory') {
                Add-Finding -Severity 'INFO' -Category 'SECRET_FILE_PRESENT' -Title 'Credential or auth file exists' -Path $secret -Evidence 'Credential file exists. Value was not read or displayed.' -Recommendation 'Rotate credentials if DANGER findings suggest compromise.' -Check 'SecretsInventory' -DetectionMethod 'inventory'
            }
        }
    }
}

function Scan-MajorLocationsMode {
    Add-Limitation 'MajorLocations mode scans common developer and AI-tool locations only; it does not scan the whole PC.'
    Add-Limitation 'MajorLocations mode does not include EndpointTelemetry unless -EndpointTelemetry is also specified.'
    Add-Limitation 'MajorLocations mode excludes Codex session history and runtime cache; use UserProfile mode when those lower-priority text surfaces are required.'
    $script:SkipOwnSyntheticSamples = $true
    if (Test-CheckEnabled 'ScannerSelf') {
        Scan-FixedKnownFileIocs
    }

    if ([string]::IsNullOrEmpty($env:USERPROFILE)) {
        Add-Finding -Severity 'INFO' -Category 'USERPROFILE_NOT_AVAILABLE' -Title 'USERPROFILE environment variable is not available' -Evidence 'Major locations scan could not resolve USERPROFILE.' -Recommendation 'Run with an explicit -Path if a project folder must be inspected.'
        return
    }

    $candidateRoots = New-ArrayList
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'CodexProjects')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'Projects')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'Project')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'repos')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'repo')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'source\repos')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'src')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'dev')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'workspace')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'workspaces')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'GitHub')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'Documents\GitHub')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'Documents\Projects')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'Documents\repos')
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'Documents\source\repos')
    foreach ($relative in @(
        'Desktop\GitHub','Desktop\Projects','Desktop\repos',
        'AndroidStudioProjects','IdeaProjects','PyCharmProjects','WebStormProjects',
        'RiderProjects','PhpStormProjects','CLionProjects','GoLandProjects',
        'RubyMineProjects','NetBeansProjects','eclipse-workspace'
    )) {
        Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE $relative)
    }
    foreach ($oneDriveEnv in @('OneDrive','OneDriveCommercial','OneDriveConsumer')) {
        $oneDriveRoot = [Environment]::GetEnvironmentVariable($oneDriveEnv, 'Process')
        if ([string]::IsNullOrWhiteSpace($oneDriveRoot)) { continue }
        $oneDriveRoot = Get-SafeAutomaticProfileRoot -CandidatePath $oneDriveRoot -EnvironmentName $oneDriveEnv
        if ([string]::IsNullOrEmpty($oneDriveRoot)) { continue }
        foreach ($relative in @('GitHub','Projects','Documents\GitHub','Documents\Projects','Documents\repos','Documents\source\repos','Desktop\GitHub','Desktop\Projects','Desktop\repos')) {
            Add-ListItem $candidateRoots (Join-Path $oneDriveRoot $relative)
        }
    }

    $seenRoots = @{}
    foreach ($root in @($candidateRoots)) {
        if ([string]::IsNullOrEmpty($root)) {
            continue
        }
        try {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) {
                continue
            }
            $resolved = (Resolve-Path -LiteralPath $root -ErrorAction Stop).Path
            $key = $resolved.ToLowerInvariant()
            if ($seenRoots.ContainsKey($key)) {
                continue
            }
            $seenRoots[$key] = $true
            Add-Finding -Severity 'INFO' -Category 'MAJOR_LOCATION_SCANNED' -Title 'Major developer location selected for scanning' -Path $resolved -Evidence 'Existing common developer folder was included in MajorLocations mode.' -Recommendation 'Review WARN and DANGER findings under this root.'
            Scan-Project -RootPath $resolved
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'MAJOR_LOCATION_SKIPPED' -Title 'Major developer location could not be scanned' -Path $root -Evidence 'Candidate major location was unavailable or could not be resolved.' -Recommendation 'Run with explicit -Path if this location must be inspected.'
        }
    }

    Scan-UserProfileMode -MajorOnly
}

function Add-EndpointTextPatternFinding {
    param([string]$Path, [string]$PatternName, [string]$Pattern)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return
        }
        $info = New-Object System.IO.FileInfo($Path)
        $read = Read-TextFileSafe -File $info
        if (-not $read.ok) { return }
        if ([string]$read.text -match $Pattern) {
            Add-Finding -Severity 'WARN' -Category $PatternName -Title 'Endpoint telemetry text pattern matched' -Path $Path -Evidence ("Pattern matched: {0}. Line content not displayed." -f $PatternName) -Recommendation 'Review this endpoint artifact manually if telemetry mode was intentionally enabled.'
        }
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'ENDPOINT_TEXT_READ_FAILED' -Title 'Endpoint telemetry file could not be read' -Path $Path -Evidence 'The telemetry artifact could not be read.' -Recommendation 'Run from an account with read access if this artifact must be inspected.'
    }
}

function Test-IsLikelyBenignRunKeyValue {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrEmpty($Name) -or [string]::IsNullOrEmpty($Value)) {
        return $false
    }
    $n = $Name.ToLowerInvariant()
    $v = $Value.ToLowerInvariant() -replace '/', '\'

    if ($n -match 'discord' -and $v -match '\\appdata\\local\\discord\\update\.exe' -and $v -match '--processstart\s+discord\.exe') {
        return $true
    }
    if ($n -match 'docker\s+desktop' -and $v -match '\\program files\\docker\\docker\\docker desktop\.exe') {
        return $true
    }
    return $false
}

function Test-IsSuspiciousRunKeyValue {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrEmpty($Value)) {
        return $false
    }
    if (Test-IsLikelyBenignRunKeyValue -Name $Name -Value $Value) {
        return $false
    }

    $v = $Value.ToLowerInvariant() -replace '/', '\'
    if ($v -match '(?is)(encodedcommand|frombase64string|invoke-expression|\biex\b|downloadstring)') { return $true }
    if ($v -match '(?is)\b(powershell|pwsh)(\.exe)?\b.{0,120}(-enc|-encodedcommand|-nop|-windowstyle\s+hidden|-w\s+hidden|-executionpolicy\s+bypass)') { return $true }
    if ($v -match '(?is)(curl|wget|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|https?://|raw\.githubusercontent|gist\.github|pastebin)') { return $true }
    if ($v -match '(?is)\\(temp|tmp)\\[^\\]+.*\.(exe|ps1|vbs|js|jse|cmd|bat|scr)\b') { return $true }
    if ($v -match '(?is)\\appdata\\(local|roaming)\\[^"]{0,160}\.(ps1|vbs|js|jse|cmd|bat|scr)\b') { return $true }
    if ($v -match '(?is)\b(wscript|cscript|mshta|regsvr32|rundll32)(\.exe)?\b.{0,160}(https?://|\\appdata\\|\\temp\\)') { return $true }
    return $false
}

function Scan-EndpointTelemetryMode {
    Add-Limitation 'Endpoint telemetry is bounded and read-only; missing telemetry does not indicate safety.'
    $since = (Get-Date).AddDays(-1 * [Math]::Abs($EndpointDays))

    try {
        $dnsRecords = Get-DnsClientCache -ErrorAction Stop
        foreach ($record in @($dnsRecords)) {
            $entry = [string]$record.Entry
            foreach ($domain in @($script:Context.iocs.domains)) {
                if ($entry -match [regex]::Escape($domain)) {
                    Add-Finding -Severity 'DANGER' -Category 'DNS_CACHE_IOC' -Title 'DNS cache contains known IOC domain' -Evidence ("DNS cache matched IOC domain: {0}" -f $domain) -Recommendation 'Preserve endpoint evidence and investigate network exposure.'
                }
            }
        }
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'DNS_CACHE_UNAVAILABLE' -Title 'DNS cache could not be read' -Evidence 'Get-DnsClientCache was unavailable or access failed.' -Recommendation 'Inspect DNS telemetry from another source if needed.'
    }

    if (-not [string]::IsNullOrEmpty($env:APPDATA)) {
        $historyPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        Add-EndpointTextPatternFinding -Path $historyPath -PatternName 'POWERSHELL_HISTORY_DANGEROUS_PATTERN' -Pattern '(?is)(irm|iwr|Invoke-WebRequest|Invoke-RestMethod).{0,80}(\|\s*iex|Invoke-Expression)|EncodedCommand|FromBase64String'
    }

    if (-not [string]::IsNullOrEmpty($env:APPDATA)) {
        $startup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
        if (Test-Path -LiteralPath $startup -PathType Container) {
            $files = Get-SafeFileList -RootPath $startup
            foreach ($file in @($files)) {
                Add-Finding -Severity 'INFO' -Category 'STARTUP_FILE_PRESENT' -Title 'Startup folder file exists' -Path $file.FullName -Evidence 'Startup item exists. File content is not automatically trusted.' -Recommendation 'Review startup entries if endpoint compromise is suspected.'
            }
        }
    }

    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        try {
            $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match '^PS') { continue }
                $value = [string]$prop.Value
                if (Test-IsSuspiciousRunKeyValue -Name $prop.Name -Value $value) {
                    Add-Finding -Severity 'WARN' -Category 'RUN_KEY_SUSPICIOUS_PATTERN' -Title 'Run key contains suspicious startup pattern' -Path $key -Evidence ("Run value name: {0}. Value redacted." -f $prop.Name) -Recommendation 'Review startup persistence manually.'
                }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'RUN_KEY_UNAVAILABLE' -Title 'Run key could not be read' -Path $key -Evidence 'Registry key unavailable or access denied.' -Recommendation 'Inspect with appropriate privileges if needed.'
        }
    }

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in @($tasks)) {
            $taskText = [string]$task.TaskName
            if ($taskText -match '(?i)(powershell|pwsh|encoded|temp|appdata)') {
                Add-Finding -Severity 'INFO' -Category 'SCHEDULED_TASK_REVIEW_CANDIDATE' -Title 'Scheduled task name has review-worthy pattern' -Evidence ("Task name: {0}" -f $task.TaskName) -Recommendation 'Review task actions manually if endpoint compromise is suspected.'
            }
        }
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'SCHEDULED_TASKS_UNAVAILABLE' -Title 'Scheduled tasks could not be listed' -Evidence 'Scheduled task enumeration failed or is unavailable.' -Recommendation 'Inspect scheduled tasks manually if needed.'
    }

    $logs = @('Microsoft-Windows-Windows Defender/Operational','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')
    foreach ($log in $logs) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$since } -MaxEvents 5000 -ErrorAction Stop
            foreach ($event in @($events)) {
                $message = [string]$event.Message
                foreach ($domain in @($script:Context.iocs.domains)) {
                    if ($message -match [regex]::Escape($domain)) {
                        Add-Finding -Severity 'DANGER' -Category 'EVENT_LOG_IOC' -Title 'Windows event log contains known IOC domain' -Path $log -Evidence ("Event log matched IOC domain: {0}" -f $domain) -Recommendation 'Preserve endpoint evidence and investigate.'
                    }
                }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'EVENT_LOG_UNAVAILABLE' -Title 'Windows event log could not be read' -Path $log -Evidence 'Event log unavailable, missing, or access denied.' -Recommendation 'Review from an account with event log access if needed.'
        }
    }
}

function Get-ExitCode {
    if ($script:Context.scannerError) {
        return 3
    }
    $overall = Get-OverallResult
    if ($overall -eq 'DANGER') { return 2 }
    if ($overall -in @('WARN','CAUTION')) { return 1 }
    return 0
}

try {
    $script:CurrentPhase = 'Initialize-ScannerContext'
    Initialize-ScannerContext
    Invoke-ScanPhase -Name 'LoadIocs' -ScriptBlock {
        $script:CurrentPhase = 'Load-BuiltinIocs'
        $script:Context.iocs = Load-BuiltinIocs
        $script:CurrentPhase = 'Load-LocalIocs'
        Load-LocalIocs
        $script:CurrentPhase = 'Load-KeyvChainDropCampaignIocs'
        Load-KeyvChainDropCampaignIocs
        $script:CurrentPhase = 'Finalize-IocIndexes'
        Finalize-IocIndexes
    }
    if (Test-CheckEnabled 'NodeRuntime') {
        Invoke-ScanPhase -Name 'NodeRuntimeMetadata' -ScriptBlock {
            $script:CurrentPhase = 'Load-LocalNodeRuntimeIocs'
            Load-LocalNodeRuntimeIocs
            Test-NodeRuntimeDataStaleness
            $script:CurrentPhase = 'Scan-HostNodeRuntimes'
            Scan-HostNodeRuntimes
        }
    }

    if ([string]::IsNullOrEmpty($Path) -and -not $UserProfile -and -not $MajorLocations -and -not $EndpointTelemetry -and (Test-EnabledChecksRequireProjectPath)) {
        $Path = (Get-Location).Path
        $script:Context.mode.path = $true
        Add-Finding -Severity 'INFO' -Category 'DEFAULT_PATH_USED' -Title 'No mode specified; current directory selected' -Path $Path -Evidence 'The scanner defaulted to the current directory.' -Recommendation 'Use -Path, -UserProfile, or -EndpointTelemetry explicitly for repeatable scans.'
    }

    if (-not [string]::IsNullOrEmpty($Path)) {
        $script:CurrentPhase = 'Scan-Project'
        Invoke-ScanPhase -Name 'Project' -ScriptBlock { Scan-Project -RootPath $Path }
    }
    if ($UserProfile) {
        $script:CurrentPhase = 'Scan-UserProfileMode'
        Invoke-ScanPhase -Name 'UserProfile' -ScriptBlock { Scan-UserProfileMode }
    }
    if ($MajorLocations) {
        $script:CurrentPhase = 'Scan-MajorLocationsMode'
        Invoke-ScanPhase -Name 'MajorLocations' -ScriptBlock { Scan-MajorLocationsMode }
    }
    if ($EndpointTelemetry) {
        $script:CurrentPhase = 'Scan-EndpointTelemetryMode'
        Invoke-ScanPhase -Name 'EndpointTelemetry' -ScriptBlock { Scan-EndpointTelemetryMode }
    }
    if (Test-CheckEnabled 'NpmGlobal') {
        $script:CurrentPhase = 'Scan-NpmGlobalStatic'
        Invoke-ScanPhase -Name 'NpmGlobal' -ScriptBlock { Scan-NpmGlobalStatic }
    }
    if (Test-CheckEnabled 'NpmCache') {
        $script:CurrentPhase = 'Scan-NpmCacheStatic'
        Invoke-ScanPhase -Name 'NpmCache' -ScriptBlock { Scan-NpmCacheStatic }
    }

    $script:CurrentPhase = 'Finalize-ScanCoverage'
    Complete-ScanExecution -Status 'completed'
    Finalize-ScanCoverage
    $completionBeforeResult = Get-CoverageStatusSummary
    if ([string]$completionBeforeResult.completionStatus -eq 'complete') {
        $script:CurrentPhase = 'Scan-Completed'
        Add-Finding -Severity 'OK' -Category 'SCAN_COMPLETED' -Title 'Scan completed' -Evidence 'Scanner completed the planned critical candidate scope without executing target project code or network calls.' -Recommendation 'Review WARN and DANGER findings manually.'
    }
    elseif ([string]$completionBeforeResult.completionStatus -eq 'partial-non-critical') {
        $script:CurrentPhase = 'Scan-Partial-NonCritical'
        Add-Finding -Severity 'INFO' -Category 'SCAN_NONCRITICAL_COVERAGE_PARTIAL' -Title 'Scan completed with non-critical coverage gaps' -Path 'scan coverage' -PathType 'virtual' -Evidence ("criticalFailures={0}; nonCriticalFailures={1}; dependencyCoverage={2}; npmCacheCoverage={3}" -f $completionBeforeResult.criticalFailures,$completionBeforeResult.nonCriticalFailures,$completionBeforeResult.dependencyCoverageStatus,$completionBeforeResult.npmCacheCoverageStatus) -Recommendation ([string]$completionBeforeResult.nextAction) -RiskType 'limitation' -Confidence 'high' -Check 'ScannerSelf' -DetectionMethod 'metadata'
    }
}
catch [System.Management.Automation.PipelineStoppedException] {
    Complete-ScanExecution -Status 'interrupted'
}
catch {
    if ($null -eq $script:Context) {
        $message = 'Scanner failed before initialization.'
        if ($null -ne $_.Exception -and -not [string]::IsNullOrEmpty($_.Exception.Message)) {
            $message = Redact-SecretLikeText $_.Exception.Message
        }
        [Console]::Error.WriteLine(("ERROR: {0}" -f $message))
        exit 4
    }
    $script:Context.scannerError = $true
    Complete-ScanExecution -Status 'error'
    if ($null -ne $script:Context.coverage) { $script:Context.coverage.scanComplete = $false }
    try {
        Add-Finding -Severity 'WARN' -Category 'SCANNER_ERROR' -Title 'Scanner encountered an unexpected error' -Evidence (Get-ScannerExceptionEvidence -ErrorRecord $_ -Phase $script:CurrentPhase) -Recommendation 'Run parser validation and inspect the scanner error in a controlled environment.'
    }
    catch {
        $errorType = 'unknown'
        if ($null -ne $_.Exception) {
            $errorType = $_.Exception.GetType().FullName
        }
        Add-ListItem $script:Context.findings ([ordered]@{
            severity = 'WARN'
            category = 'SCANNER_ERROR'
            title = 'Scanner encountered an unexpected error'
            path = $null
            pathType = 'virtual'
            line = $null
            sourceContext = 'normal'
            check = 'ScannerSelf'
            detectionMethod = 'metadata'
            riskType = 'limitation'
            confidence = 'low'
            evidence = ("Unexpected scanner error occurred. Exception type: {0}. Finding helper also failed." -f $errorType)
            recommendation = 'Run parser validation and inspect the scanner error in a controlled environment.'
        })
    }
}
finally {
    try {
        Write-Reports
    }
    catch {
        if (-not $Quiet) {
            $reportErrorType = 'unknown'
            $reportErrorMessage = ''
            if ($null -ne $_.Exception) {
                $reportErrorType = $_.Exception.GetType().FullName
                $reportErrorMessage = $_.Exception.Message
            }
            Write-Host ("Failed to write reports. Exception type: {0}. Message: {1}" -f $reportErrorType, (Redact-SecretLikeText $reportErrorMessage))
        }
        exit 3
    }
}

exit (Get-ExitCode)
