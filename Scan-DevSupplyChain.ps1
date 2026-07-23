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
    [switch]$Quiet
)

$script:ScannerName = 'Dev Supply Chain IOC Checker'
$script:ScannerVersion = '0.1.14'
$script:Context = $null
$script:WarnedMaxFiles = $false
$script:SkipOwnSyntheticSamples = $false
$script:SkipOwnReportArtifacts = $true
$script:WarnedOwnSyntheticSamplesSkipped = $false
$script:CurrentPhase = 'startup'
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
        return ([System.IO.Path]::GetFullPath($CandidatePath)).TrimEnd('\', '/')
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

function Get-ScannerDistributionInfo {
    $base = $script:BaseDir
    $scriptPath = Join-Path $base 'Scan-DevSupplyChain.ps1'
    $launcher = Join-Path $base 'run-checker.bat'
    $readme = Join-Path $base 'README.md'
    $iocDir = Join-Path $base 'iocs'
    $manifest = Join-Path $base 'tests\samples\manifest.json'

    $missing = New-ArrayList
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { Add-ListItem $missing 'Scan-DevSupplyChain.ps1' }
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { Add-ListItem $missing 'run-checker.bat' }
    if (-not (Test-Path -LiteralPath $readme -PathType Leaf)) { Add-ListItem $missing 'README.md' }
    if (-not (Test-Path -LiteralPath $iocDir -PathType Container)) { Add-ListItem $missing 'iocs' }
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
    $base = Get-FullPathSafe $script:BaseDir
    if ([string]::IsNullOrEmpty($candidate) -or [string]::IsNullOrEmpty($base)) {
        return $false
    }
    $base = $base.TrimEnd('\', '/')
    $baseWithSeparator = $base + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($baseWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    $relative = $candidate.Substring($baseWithSeparator.Length).TrimStart('\', '/') -replace '/', '\'
    if ([string]::IsNullOrEmpty($relative)) {
        return $false
    }
    $firstSegment = ($relative -split '\\')[0]
    return ($firstSegment -match '(?i)^reports.*$')
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
    try {
        return Get-Sha256HexFromBytes ([System.IO.File]::ReadAllBytes($FilePath))
    }
    catch {
        return $null
    }
}

function Test-IsNpmCacheBlobPath {
    param([string]$CandidatePath)
    if ([string]::IsNullOrEmpty($CandidatePath)) {
        return $false
    }
    $normalized = $CandidatePath.ToLowerInvariant() -replace '/', '\'
    return ($normalized -match '\\(\.npm-cache|\.npm)\\_cacache\\content-v2\\')
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

    if ($name -in @('mcp.json','claude_desktop_config.json')) {
        return 'active-ai-config'
    }
    if ($name -eq 'settings.json' -and $normalized -match '\\(\.cursor|\.claude|\.windsurf|cursor\\user|windsurf\\user|code\\user)\\') {
        return 'active-ai-config'
    }

    $isCodexPath = ($normalized -match '\\\.codex(\\|$)')
    if (-not $isCodexPath) {
        if ($normalized -match '\\(\.cursor|\.claude|\.windsurf)\\') {
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

function Get-SourceContext {
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

function Add-ScanStat {
    param([string]$Name, [int]$Amount = 1)
    if ($null -eq $script:Context -or $null -eq $script:Context.scanStats) {
        return
    }
    $allowedStats = @(
        'filesEnumerated',
        'filesScanned',
        'filesSkipped',
        'syntheticSamplesSkipped',
        'cacheFilesSkipped',
        'encodingFallbackAggregated',
        'unicodeVariationSelectorsAggregated',
        'scannerFileErrors',
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
        'nodeRuntimeVersionReadFailures'
    )
    if ($allowedStats -notcontains $Name) {
        return
    }
    $script:Context.scanStats[$Name] = [int]$script:Context.scanStats[$Name] + $Amount
}

function Get-DefaultRiskType {
    param([string]$Category, [string]$Severity)
    if ([string]::IsNullOrEmpty($Category)) { return 'posture' }
    if ($Category -match '^NODE_RUNTIME_VULNERABILITY') { return 'vulnerability' }
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
    if ($SourceContext -in @('active-ai-config','executable-tooling','reference-text','session-log','cache-data','plugin-metadata')) { return 'AiMcp' }
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
        $Vulnerability
    )

    if ($null -eq $script:Context) {
        return
    }

    $allowed = @('DANGER', 'WARN', 'INFO', 'OK')
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
    if ($RiskType -eq 'capability' -and $Severity -eq 'WARN' -and $SourceContext -ne 'active-ai-config' -and $null -ne $script:Context.capabilityFindingCountsByRoot) {
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
            Add-ScanStat -Name 'syntheticSampleKnownSkipped'
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
        Add-ScanStat -Name 'syntheticSampleKnownSkipped'
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

    Add-ScanStat -Name 'syntheticSampleKnownSkipped'
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

function New-ReportPaths {
    $outputDir = $ReportDir
    if ([string]::IsNullOrEmpty($outputDir)) {
        $outputDir = Join-Path $script:BaseDir 'reports'
    }
    if (-not (Test-Path -LiteralPath $outputDir)) {
        [void][System.IO.Directory]::CreateDirectory($outputDir)
    }

    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $textPath = $TextOut
    $jsonPath = $JsonOut
    if ([string]::IsNullOrEmpty($textPath)) {
        $textPath = Join-Path $outputDir ("dev-supplychain-report-$stamp.txt")
    }
    if ([string]::IsNullOrEmpty($jsonPath)) {
        $jsonPath = Join-Path $outputDir ("dev-supplychain-report-$stamp.json")
    }

    return [ordered]@{
        text = $textPath
        json = $jsonPath
    }
}

function Initialize-ScannerContext {
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
        capabilityFindingCountsByRoot = @{}
        queuedFilePaths = @{}
        targetedFilePaths = @{}
        targetedDependencyLimitWarned = $false
        jetBrainsRootsSeen = @{}
        jetBrainsNativeRoots = @{}
        jetBrainsArchiveSkippedRoots = @{}
        nodeRuntimeProjectScanPerformed = $false
        nodeRuntimeHostScanPerformed = $false
        nodeRuntimeBudgetWarned = $false
        nodeRuntimeUnresolvedPaths = New-ArrayList
        nodeRuntimeDataLastUpdated = '2026-07-15'
        nodeRuntimeLocalDataStatus = 'builtin-only'
        scanStats = [ordered]@{
            filesEnumerated = 0
            filesScanned = 0
            filesSkipped = 0
            syntheticSamplesSkipped = 0
            syntheticSampleKnownSkipped = 0
            syntheticSampleUnexpectedFiles = 0
            syntheticSampleHashMismatches = 0
            cacheFilesSkipped = 0
            encodingFallbackAggregated = 0
            unicodeVariationSelectorsAggregated = 0
            scannerFileErrors = 0
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
        }
        aggregatesFlushed = $false
        iocs = $null
        mode = [ordered]@{
            path = -not [string]::IsNullOrEmpty($Path)
            userProfile = [bool]$UserProfile
            deep = [bool]$Deep
            majorLocations = [bool]$MajorLocations
            endpointTelemetry = [bool]$EndpointTelemetry
        }
    }

    Add-Limitation 'No network lookup was performed.'
    Add-Limitation 'No external package manager, git, node, python, curl, or wget command was executed.'
    Add-Limitation 'YAML, TOML, and lockfiles are scanned by static pattern matching, not full semantic parsing.'
    Add-Limitation 'Node.js runtime checks use static version metadata and explicit version declarations; binaries are not executed and metadata does not prove publisher authenticity.'
    Add-Limitation 'Node.js EOL status, complete semver range evaluation, and registry-backed CVE auditing are outside scope.'
    Add-Limitation 'Absence of findings does not prove the host is clean.'
    $script:Context.ownSyntheticSampleManifest = Load-OwnSyntheticSampleManifest
    $script:Context.syntheticSampleManifestStatus = [string]$script:Context.ownSyntheticSampleManifest.status
    if ([string]$script:Context.distributionStatus -ne 'complete') {
        Add-Finding -Severity 'WARN' -Category 'SCANNER_DISTRIBUTION_INCOMPLETE' -Title 'Scanner distribution appears incomplete' -Path $script:BaseDir -PathType 'directory' -SourceContext 'scanner-self' -Evidence ("distributionStatus={0}; warnings={1}" -f $script:Context.distributionStatus, ([string]::Join('; ', [string[]]$script:Context.distributionWarnings))) -Recommendation 'For distributed use, extract the full tool folder and start from run-checker.bat.'
    }
}

function Get-ScanStatsForReport {
    $stats = [ordered]@{
        scanRoots = @($script:Context.scanRoots)
        filesEnumerated = [int]$script:Context.scanStats.filesEnumerated
        filesScanned = [int]$script:Context.scanStats.filesScanned
        filesSkipped = [int]$script:Context.scanStats.filesSkipped
        syntheticSamplesSkipped = [int]$script:Context.scanStats.syntheticSamplesSkipped
        syntheticSampleKnownSkipped = [int]$script:Context.scanStats.syntheticSampleKnownSkipped
        syntheticSampleUnexpectedFiles = [int]$script:Context.scanStats.syntheticSampleUnexpectedFiles
        syntheticSampleHashMismatches = [int]$script:Context.scanStats.syntheticSampleHashMismatches
        cacheFilesSkipped = [int]$script:Context.scanStats.cacheFilesSkipped
        encodingFallbackAggregated = [int]$script:Context.scanStats.encodingFallbackAggregated
        unicodeVariationSelectorsAggregated = [int]$script:Context.scanStats.unicodeVariationSelectorsAggregated
        scannerFileErrors = [int]$script:Context.scanStats.scannerFileErrors
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
                representativePaths = New-ArrayList
                categories = @{}
            }
        }
        $entry = $groups[$root]
        $entry.count = [int]$entry.count + 1
        if ([string]$finding.severity -eq 'WARN') {
            $entry.maxSeverity = 'WARN'
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
            if ($kind -ne 'installed-binary-metadata' -and $upstream -ne 'CRITICAL') { continue }
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
            else { 7 }
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
                info = 0
                ok = 0
            }
        }
        switch ($finding.severity) {
            'DANGER' { $result[$context]['danger'] = [int]$result[$context]['danger'] + 1 }
            'WARN' { $result[$context]['warn'] = [int]$result[$context]['warn'] + 1 }
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
            'INFO' { $result[$checkName]['info'] = [int]$result[$checkName]['info'] + 1 }
            'OK' { $result[$checkName]['ok'] = [int]$result[$checkName]['ok'] + 1 }
        }
    }
    return $result
}

function Get-CheckStats {
    $stats = [ordered]@{}
    foreach ($checkName in @($script:LeafCheckOrder)) {
        $stats[$checkName] = [ordered]@{
            enabled = [bool](Test-CheckEnabled $checkName)
        }
    }
    $stats.NpmGlobal.rootsFound = [int]$script:Context.scanStats.npmGlobalRootsFound
    $stats.NpmGlobal.packagesChecked = [int]$script:Context.scanStats.npmGlobalPackagesChecked
    $stats.NpmCache.rootsFound = [int]$script:Context.scanStats.npmCacheRootsFound
    $stats.NpmCache.metadataFilesScanned = [int]$script:Context.scanStats.npmCacheMetadataFilesScanned
    $stats.NpmCache.metadataFilesSkipped = [int]$script:Context.scanStats.npmCacheMetadataFilesSkipped
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
        Add-Finding -Severity 'WARN' -Category 'AI_REFERENCE_TEXT_EXECUTABLE_SAMPLE_RISK_AGGREGATED' -Title 'AI reference text contains executable-looking risky samples' -Path '.codex reference text' -PathType 'virtual' -SourceContext 'reference-text' -Evidence ("Aggregated {0} reference text file(s) with executable-looking fetch-execute or secret-send samples." -f $script:Context.scanStats.aiReferenceExecutableSampleAggregated) -Recommendation 'Review examples before copying them into active configs or scripts.' -RiskType 'posture' -Confidence 'medium'
    }
    if ([int]$script:Context.scanStats.capabilityFindingsAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'AI_TOOLING_CAPABILITY_FINDINGS_AGGREGATED' -Title 'Additional AI tooling capability findings aggregated' -Path 'AI tooling capability summary' -PathType 'virtual' -SourceContext 'executable-tooling' -Evidence ("Aggregated {0} additional capability-only finding(s) after per-root representative limits." -f $script:Context.scanStats.capabilityFindingsAggregated) -Recommendation 'Use capabilitySummary and representative findings for review; capability is not evidence of infection by itself.' -RiskType 'capability' -Confidence 'low'
    }
    if ([int]$script:Context.scanStats.cacheFilesSkipped -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_BLOB_SKIPPED' -Title 'npm cache content blobs skipped' -Path 'npm cache content-v2' -PathType 'virtual' -SourceContext 'cache' -Evidence ("Skipped {0} npm cache content blob file(s)." -f $script:Context.scanStats.cacheFilesSkipped) -Recommendation 'This avoids noisy binary/cache decoding. Scan package manifests or lockfiles for dependency review.'
    }
    if ([int]$script:Context.scanStats.encodingFallbackAggregated -gt 0) {
        Add-Finding -Severity 'INFO' -Category 'TEXT_DEFAULT_ENCODING_AGGREGATED' -Title 'Default encoding fallback findings aggregated' -Path 'dependency metadata' -PathType 'virtual' -SourceContext 'dependency-metadata' -Evidence ("Aggregated {0} dependency metadata file(s) decoded with default encoding." -f $script:Context.scanStats.encodingFallbackAggregated) -Recommendation 'Inspect manually only if invisible Unicode findings point to the same dependency metadata.'
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
    foreach ($finding in $script:Context.findings) {
        if ($finding.severity -eq 'DANGER') { $danger++ }
        if ($finding.severity -eq 'WARN') { $warn++ }
    }
    if ($danger -gt 0) { return 'DANGER' }
    if ($warn -gt 0) { return 'WARN' }
    return 'OK'
}

function Get-Summary {
    $summary = [ordered]@{
        danger = 0
        warn = 0
        info = 0
        ok = 0
    }
    foreach ($finding in $script:Context.findings) {
        switch ($finding.severity) {
            'DANGER' { $summary.danger++ }
            'WARN' { $summary.warn++ }
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
    [System.IO.File]::WriteAllText($FilePath, $Content, $encoding)
}

function Write-Reports {
    if ($null -eq $script:Context) {
        return
    }

    Flush-AggregatedFindings
    $summary = Get-Summary
    $overall = Get-OverallResult
    $priorityFindings = Get-PriorityFindings
    $capabilitySummary = Get-CapabilitySummary
    $nodeRuntimeSummary = Get-NodeRuntimeSummary
    $report = [ordered]@{
        schemaVersion = $script:ScannerVersion
        generatedAt = $script:Context.generatedAt
        scanner = [ordered]@{
            name = $script:ScannerName
            version = $script:ScannerVersion
            dependencyMode = 'none'
            networkAccess = $false
            readOnly = $true
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
        scanRoots = @($script:Context.scanRoots)
        scanStats = Get-ScanStatsForReport
        checkStats = Get-CheckStats
        overallResult = $overall
        summary = $summary
        summaryBySourceContext = Get-SummaryBySourceContext
        summaryByCheck = Get-SummaryByCheck
        priorityFindings = @($priorityFindings)
        capabilitySummary = @($capabilitySummary)
        nodeRuntimeSummary = @($nodeRuntimeSummary)
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
    Add-ListItem $lines ("ScannerPath: {0}" -f (ConvertTo-RedactedPath $script:ScriptPath))
    Add-ListItem $lines ("LauncherPath: {0}" -f (ConvertTo-RedactedPath $script:Context.launcherPath))
    Add-ListItem $lines ("DistributionStatus: {0}" -f $script:Context.distributionStatus)
    if (@($script:Context.distributionWarnings).Count -gt 0) {
        Add-ListItem $lines ("DistributionWarnings: {0}" -f ([string]::Join('; ', [string[]]$script:Context.distributionWarnings)))
    }
    Add-ListItem $lines ("Mode: Path={0}, UserProfile={1}, Deep={2}, MajorLocations={3}, EndpointTelemetry={4}" -f $script:Context.mode.path, $script:Context.mode.userProfile, $script:Context.mode.deep, $script:Context.mode.majorLocations, $script:Context.mode.endpointTelemetry)
    Add-ListItem $lines 'ReadOnly: true'
    Add-ListItem $lines 'NetworkAccess: false'
    Add-ListItem $lines 'ExternalCommands: none'
    Add-ListItem $lines 'TargetCodeExecution: none'
    Add-ListItem $lines ("OverallResult: $overall")
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
    Add-ListItem $lines 'NetworkAccess: none'
    Add-ListItem $lines 'ExternalCommands: none'
    Add-ListItem $lines 'TargetCodeExecution: none'
    Add-ListItem $lines ''
    Add-ListItem $lines '[SUMMARY]'
    Add-ListItem $lines ("DANGER: {0}" -f $summary.danger)
    Add-ListItem $lines ("WARN:   {0}" -f $summary.warn)
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
        Add-ListItem $lines ("{0}: DANGER={1}, WARN={2}, INFO={3}, OK={4}" -f $context, $bySource[$context].danger, $bySource[$context].warn, $bySource[$context].info, $bySource[$context].ok)
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[CHECK SUMMARY]'
    $byCheck = Get-SummaryByCheck
    foreach ($checkName in @($script:LeafCheckOrder)) {
        $item = $byCheck[$checkName]
        $enabled = Test-CheckEnabled $checkName
        Add-ListItem $lines ("{0}: Enabled={1}, DANGER={2}, WARN={3}, INFO={4}, OK={5}" -f $checkName, $enabled, $item.danger, $item.warn, $item.info, $item.ok)
    }
    Add-ListItem $lines ''
    Add-ListItem $lines '[SCAN STATS]'
    $scanStats = Get-ScanStatsForReport
    Add-ListItem $lines ("ScanRoots: {0}" -f (@($scanStats.scanRoots).Count))
    Add-ListItem $lines ("FilesEnumerated: {0}" -f $scanStats.filesEnumerated)
    Add-ListItem $lines ("UniqueFilesQueued: {0}" -f $scanStats.uniqueFilesQueued)
    Add-ListItem $lines ("FilesScanned: {0}" -f $scanStats.filesScanned)
    Add-ListItem $lines ("FilesSkipped: {0}" -f $scanStats.filesSkipped)
    Add-ListItem $lines ("SyntheticSamplesSkipped: {0}" -f $scanStats.syntheticSamplesSkipped)
    Add-ListItem $lines ("SyntheticSampleKnownSkipped: {0}" -f $scanStats.syntheticSampleKnownSkipped)
    Add-ListItem $lines ("SyntheticSampleUnexpectedFiles: {0}" -f $scanStats.syntheticSampleUnexpectedFiles)
    Add-ListItem $lines ("SyntheticSampleHashMismatches: {0}" -f $scanStats.syntheticSampleHashMismatches)
    Add-ListItem $lines ("CacheFilesSkipped: {0}" -f $scanStats.cacheFilesSkipped)
    Add-ListItem $lines ("UnicodeVariationSelectorsAggregated: {0}" -f $scanStats.unicodeVariationSelectorsAggregated)
    Add-ListItem $lines ("ScannerFileErrors: {0}" -f $scanStats.scannerFileErrors)
    Add-ListItem $lines ("CodexReferenceRiskAggregated: {0}" -f $scanStats.codexReferenceRiskAggregated)
    Add-ListItem $lines ("CodexSessionRiskAggregated: {0}" -f $scanStats.codexSessionRiskAggregated)
    Add-ListItem $lines ("CodexCacheRiskAggregated: {0}" -f $scanStats.codexCacheRiskAggregated)
    Add-ListItem $lines ("CodexPluginMetadataRiskAggregated: {0}" -f $scanStats.codexPluginMetadataRiskAggregated)
    Add-ListItem $lines ("AiTokenReferenceAggregated: {0}" -f $scanStats.aiTokenReferenceAggregated)
    Add-ListItem $lines ("AiReferenceExecutableSampleAggregated: {0}" -f $scanStats.aiReferenceExecutableSampleAggregated)
    Add-ListItem $lines ("CapabilityFindingsAggregated: {0}" -f $scanStats.capabilityFindingsAggregated)
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
    Add-ListItem $lines ''
    Add-ListItem $lines '[NODE RUNTIME SUMMARY]'
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
            Add-ListItem $lines ("[{0}] {1} finding(s) under {2}" -f $entry.maxSeverity, $entry.count, $entry.root)
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
    $jul2025 = 'https://nodejs.org/en/blog/vulnerability/july-2025-security-releases'
    $jan2026 = 'https://nodejs.org/en/blog/vulnerability/december-2025-security-releases'
    $mar2026 = 'https://nodejs.org/en/blog/vulnerability/march-2026-security-releases'
    $jun2026 = 'https://nodejs.org/en/blog/vulnerability/june-2026-security-releases'

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

    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2025-27210' 'HIGH' '2025-07-15' $jul2025 @(
        (New-NodeRuntimeRange '20.0.0' '20.19.4'), (New-NodeRuntimeRange '22.0.0' '22.17.1'), (New-NodeRuntimeRange '24.0.0' '24.4.1')
    ) @((New-NodeRuntimeFixedVersion 20 '20.19.4'),(New-NodeRuntimeFixedVersion 22 '22.17.1'),(New-NodeRuntimeFixedVersion 24 '24.4.1')) @('windows','path.join'))
    Add-ListItem $items (New-NodeRuntimeAdvisory 'CVE-2025-27209' 'HIGH' '2025-07-15' $jul2025 @(
        (New-NodeRuntimeRange '24.0.0' '24.4.1')
    ) @((New-NodeRuntimeFixedVersion 24 '24.4.1')) @('attacker-controlled-strings'))

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

    return [ordered]@{
        schemaVersion = '0.1.14'
        lastUpdated = '2026-07-15'
        expiresAfterDays = 30
        highRetentionDays = 365
        advisories = $items
    }
}

function Load-BuiltinIocs {
    $packages = New-ArrayList
    Add-BuiltinPackageIoc $packages 'npm' 'axios' @('1.14.1','0.30.4') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' 'plain-crypto-js' @('4.2.1') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' '@aifabrix/miso-client' @('4.7.2') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' '@iflow-mcp/watercrawl-watercrawl-mcp' @('1.3.0','1.3.1','1.3.2','1.3.3','1.3.4') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'python' 'litellm' @('1.82.7','1.82.8') 'Known compromised package version baseline'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/generator-helpers' @('1.1.1') 'AsyncAPI compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/generator-components' @('0.7.1') 'AsyncAPI compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/generator' @('3.3.1') 'AsyncAPI compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' '@asyncapi/specs' @('6.11.2','6.11.2-alpha.1') 'AsyncAPI compromise exact versions'
    Add-BuiltinPackageIoc $packages 'npm' 'jscrambler' @('8.14.0','8.16.0','8.17.0','8.18.0','8.20.0') 'Jscrambler compromise exact versions'
    Add-BuiltinPackageIoc $packages 'npm' 'jscrambler-webpack-plugin' @('8.6.2') 'Jscrambler related compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'gulp-jscrambler' @('8.6.2') 'Jscrambler related compromise exact version'
    Add-BuiltinPackageIoc $packages 'npm' 'grunt-jscrambler' @('8.5.2') 'Jscrambler related compromise exact version'
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
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\setup\.js$' 'a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60' 'Jscrambler malicious setup.js hash'
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\intro\.js$' 'a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86' 'Jscrambler malicious intro.js hash'
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\package\.json$' 'bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0' 'Jscrambler malicious package.json hash'
    Add-BuiltinFileHashIoc $files '\\node_modules\\jscrambler\\.*\.(exe|dll|node)$' 'b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903' 'Jscrambler malicious Windows payload hash'
    Add-BuiltinFileHashIoc $files '\\\.github\\actions\\.*\.(js|cjs|mjs)$' '9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015' 'Vendored codfish semantic-release action payload hash'

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
    $ips = New-ArrayList
    Add-ListItem $ips '164.92.88.210'

    return [ordered]@{
        packages = $packages
        extensions = $extensions
        files = $files
        actions = $actions
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

function Load-LocalIocs {
    if ($null -eq $script:Context.iocs) {
        $script:Context.iocs = Load-BuiltinIocs
    }

    $iocDir = Join-Path $script:BaseDir 'iocs'
    if (-not (Test-Path -LiteralPath $iocDir)) {
        return
    }

    $files = @(
        'known-packages.json',
        'known-extensions.json',
        'known-files.json',
        'known-actions.json',
        'suspicious-patterns.json'
    )
    foreach ($name in $files) {
        $file = Join-Path $iocDir $name
        if (-not (Test-Path -LiteralPath $file)) {
            continue
        }
        try {
            $text = [System.IO.File]::ReadAllText($file)
            if ([string]::IsNullOrWhiteSpace($text)) {
                continue
            }
            $json = $text | ConvertFrom-Json -ErrorAction Stop
            $lastUpdated = Get-PropertyValue $json 'lastUpdated'
            $expires = Get-PropertyValue $json 'expiresAfterDays'
            if (-not [string]::IsNullOrEmpty($lastUpdated) -and $null -ne $expires) {
                $updatedDate = [DateTime]::Parse($lastUpdated)
                if ($updatedDate.AddDays([int]$expires) -lt (Get-Date)) {
                    Add-Finding -Severity 'WARN' -Category 'IOC_DATA_STALE' -Title 'Local IOC file is stale' -Path $file -Evidence 'Local IOC file is older than its configured expiry.' -Recommendation 'Manually review and update local IOC JSON from trusted sources.'
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
                    })
                }
            }
        }
        catch {
            Add-Finding -Severity 'WARN' -Category 'IOC_JSON_INVALID' -Title 'Local IOC JSON could not be parsed' -Path $file -Evidence 'The IOC file was ignored because JSON parsing failed.' -Recommendation 'Fix or remove the malformed local IOC file.'
        }
    }
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
    try { [void][DateTime]::ParseExact($published, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
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
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return }
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
            $null -eq $parsedUpdated -or $parsedUpdated.Date -gt (Get-Date).Date.AddDays(1)) {
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
        $accepted = 0
        $conflicts = 0
        foreach ($entry in $localAdvisories) {
            $normalized = Normalize-NodeRuntimeAdvisory $entry
            if ($null -eq $normalized) {
                Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_IOC_ENTRY_INVALID' -Title 'Node.js runtime advisory entry is invalid' -Path $file -Evidence 'An advisory entry failed schema or trusted-source validation and was ignored.' -Recommendation 'Use an official nodejs.org security release and exact affected/fixed version boundaries.' -Check 'NodeRuntime' -DetectionMethod 'metadata'
                continue
            }
            $id = [string]$normalized.id
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
        if ($conflicts -eq 0 -and $missingBuiltin.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($lastUpdated)) {
            $script:Context.nodeRuntimeDataLastUpdated = $parsedUpdated.ToString('yyyy-MM-dd')
            $script:Context.nodeRuntimeLocalDataStatus = if ($accepted -gt 0) { 'baseline-plus-local' } else { 'baseline-parity' }
        }
    }
    catch {
        Add-Finding -Severity 'WARN' -Category 'IOC_JSON_INVALID' -Title 'Local Node.js runtime IOC JSON could not be parsed' -Path $file -Evidence 'The Node.js IOC file was ignored because JSON parsing failed; the built-in baseline remains active.' -Recommendation 'Restore or repair known-node-runtimes.json.' -Check 'NodeRuntime' -DetectionMethod 'metadata'
        $script:Context.nodeRuntimeLocalDataStatus = 'invalid-builtin-active'
    }
}

function Test-NodeRuntimeDataStaleness {
    if (-not (Test-CheckEnabled 'NodeRuntime')) { return }
    try {
        $updated = [DateTime]::ParseExact([string]$script:Context.nodeRuntimeDataLastUpdated, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        if ($updated.AddDays(30) -lt (Get-Date)) {
            Add-Finding -Severity 'WARN' -Category 'NODE_RUNTIME_DATA_STALE' -Title 'Node.js vulnerability data is older than 30 days' -Path (Join-Path $script:BaseDir 'iocs\known-node-runtimes.json') -Evidence 'The offline Node.js advisory baseline may not include recent security releases.' -Recommendation 'Manually review official Node.js security releases and update the offline baseline.' -RiskType 'limitation' -Confidence 'high' -Check 'NodeRuntime' -DetectionMethod 'metadata'
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
    $version = ConvertTo-NodeRuntimeVersion $VersionText -AllowFourth:$AllowFourth
    if ($null -eq $version) {
        Register-NodeRuntimeUnresolvedReference -Path $Path
        return
    }
    $matches = @(Get-NodeRuntimeAdvisoryMatches $version)
    if ($matches.Count -eq 0) { return }

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
    if ($p -match '\\\.npmrc$') { return $true }
    if ($p -match '\\\.pypirc$') { return $true }
    if ($p -match '\\\.netrc$') { return $true }
    if ($p -match '\\\.ssh\\id_(rsa|ed25519|ecdsa|dsa)$') { return $true }
    if ($p -match '\\\.aws\\credentials$') { return $true }
    if ($p -match '\\\.kube\\config$') { return $true }
    return $false
}

function Get-TargetedDependencyFileBudget {
    $half = [int][Math]::Floor([double]$MaxFiles * 0.5)
    return [Math]::Min(50000, [Math]::Max(0, $half))
}

function Reserve-ScanFile {
    param(
        [string]$FilePath,
        [switch]$Targeted,
        [switch]$DeepOnly
    )
    if ([string]::IsNullOrWhiteSpace($FilePath) -or $null -eq $script:Context) { return $false }
    try {
        $fullPath = [System.IO.Path]::GetFullPath($FilePath)
    }
    catch {
        return $false
    }
    $key = $fullPath.ToLowerInvariant()
    if ($script:Context.queuedFilePaths.ContainsKey($key)) { return $false }

    if ($Targeted) {
        $targetedBudget = Get-TargetedDependencyFileBudget
        if ([int]$script:Context.scanStats.targetedDependencyFilesQueued -ge $targetedBudget) {
            Add-ScanStat -Name 'targetedDependencyFilesSkippedByBudget'
            if (-not [bool]$script:Context.targetedDependencyLimitWarned) {
                $script:Context.targetedDependencyLimitWarned = $true
                Add-Finding -Severity 'WARN' -Category 'TARGETED_DEPENDENCY_LIMIT_REACHED' -Title 'Targeted dependency scan budget reached' -Path $fullPath -Evidence ("Targeted dependency files are limited to {0}, reserving at least half of MaxFiles for normal source and configuration scanning." -f $targetedBudget) -Recommendation 'Increase MaxFiles or scan the affected child project directly if deeper dependency inspection is required.' -Check 'Packages' -DetectionMethod 'metadata'
            }
            return $false
        }
    }

    if ([int]$script:Context.scanStats.uniqueFilesQueued -ge $MaxFiles) {
        if (-not $script:WarnedMaxFiles) {
            Add-Finding -Severity 'WARN' -Category 'MAX_FILES_REACHED' -Title 'Maximum unique file count reached' -Path $fullPath -Evidence "Run-wide MaxFiles limit reached: $MaxFiles." -Recommendation 'Increase MaxFiles or narrow the scan path.'
            $script:WarnedMaxFiles = $true
        }
        return $false
    }

    $script:Context.queuedFilePaths[$key] = $true
    Add-ScanStat -Name 'uniqueFilesQueued'
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
        if (Test-IsOwnSyntheticSamplePath $item.FullName) { return }
        if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $item.FullName)) { return }
        if (Reserve-ScanFile -FilePath $item.FullName) {
            Add-ScanStat -Name 'filesEnumerated'
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
    if ($validation.active -and $env:DEV_SUPPLYCHAIN_CHECKER_TEST_NODE_RUNTIME_HOST_SCOPE -eq '1') { return $true }
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
    }
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) { Add-NodeRuntimeSearchRoot $roots $seen (Join-Path $env:APPDATA 'fnm\node-versions') 5 }
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
    param($List, [string]$FilePath)
    if ([string]::IsNullOrEmpty($FilePath)) {
        return
    }
    if ($List.Count -ge 10000) {
        Add-ScanStat -Name 'targetedDependencyFilesSkippedByBudget'
        if (-not [bool]$script:Context.targetedDependencyLimitWarned) {
            $script:Context.targetedDependencyLimitWarned = $true
            Add-Finding -Severity 'WARN' -Category 'TARGETED_DEPENDENCY_LIMIT_REACHED' -Title 'Per-project targeted dependency limit reached' -Path $FilePath -Evidence 'A child project reached the 10,000 targeted-file limit; normal source and configuration scanning continues.' -Recommendation 'Scan this child project directly if deeper dependency inspection is required.' -Check 'Packages' -DetectionMethod 'metadata'
        }
        return
    }
    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
        try {
            Add-ScanStat -Name 'filesEnumerated'
            if (Test-IsVerifiedScannerArtifactSamplePath $FilePath) {
                Add-ScanStat -Name 'filesSkipped'
                return
            }
            if (Test-IsOwnSyntheticSamplePath $FilePath) {
                Add-ScanStat -Name 'filesSkipped'
                Add-ScanStat -Name 'syntheticSamplesSkipped'
                return
            }
            if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $FilePath)) {
                Add-ScanStat -Name 'filesSkipped'
                Add-ScanStat -Name 'scannerReportArtifactsSkipped'
                return
            }
            if (Reserve-ScanFile -FilePath $FilePath -Targeted) {
                Add-ListItem $List ([System.IO.FileInfo]$FilePath)
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'FILE_INFO_FAILED' -Title 'File metadata could not be read' -Path $FilePath -Evidence 'FileInfo failed while collecting targeted scan file.' -Recommendation 'Inspect manually if this path is important.'
        }
    }
}

function Get-SafeFileList {
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
        Add-Finding -Severity 'INFO' -Category 'ACCESS_DENIED' -Title 'Scan path could not be opened' -Path $RootPath -Evidence 'Access denied or path metadata unavailable.' -Recommendation 'Run from an account with read access if this path must be inspected.'
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
            Add-ScanStat -Name 'filesSkipped'
            Add-ScanStat -Name 'scannerReportArtifactsSkipped'
            return $result
        }
        Add-ScanStat -Name 'filesEnumerated'
        if (Reserve-ScanFile -FilePath $rootItem.FullName) {
            Add-ListItem $result $rootItem
        }
        return $result
    }

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([ordered]@{ path=$rootItem.FullName; deepOnly=$false })
    while ($queue.Count -gt 0) {
        $queueItem = $queue.Dequeue()
        $dirPath = [string]$queueItem.path
        $deepOnly = [bool]$queueItem.deepOnly
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
            if ($deepOnly) { Add-ScanStat -Name 'deepDirectoriesEntered' }

            $files = @([System.IO.Directory]::GetFiles($dirPath) | Sort-Object)
            foreach ($file in $files) {
                Add-ScanStat -Name 'filesEnumerated'
                if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $file)) {
                    Add-ScanStat -Name 'filesSkipped'
                    continue
                }
                if (Test-IsVerifiedScannerArtifactSamplePath $file) {
                    Add-ScanStat -Name 'filesSkipped'
                    continue
                }
                if (Test-IsOwnSyntheticSamplePath $file) {
                    Add-ScanStat -Name 'filesSkipped'
                    Add-ScanStat -Name 'syntheticSamplesSkipped'
                    continue
                }
                try {
                    if (Reserve-ScanFile -FilePath $file -DeepOnly:$deepOnly) {
                        Add-ListItem $result (New-Object System.IO.FileInfo($file))
                    }
                }
                catch {
                    Add-Finding -Severity 'INFO' -Category 'FILE_INFO_FAILED' -Title 'File metadata could not be read' -Path $file -Evidence 'File metadata access failed.' -Recommendation 'Inspect manually if this path is important.'
                }
            }

            $subdirs = @([System.IO.Directory]::GetDirectories($dirPath) | Sort-Object)
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
                    Add-Finding -Severity 'INFO' -Category 'ACCESS_DENIED' -Title 'Directory could not be enumerated' -Path $subdir -Evidence 'Access denied or directory metadata unavailable.' -Recommendation 'Run from an account with read access if this path must be inspected.'
                }
            }
        }
        catch [System.UnauthorizedAccessException] {
            Add-Finding -Severity 'INFO' -Category 'ACCESS_DENIED' -Title 'Directory could not be enumerated' -Path $dirPath -Evidence 'Access denied while enumerating directory.' -Recommendation 'Run from an account with read access if this path must be inspected.'
        }
        catch [System.IO.PathTooLongException] {
            Add-Finding -Severity 'INFO' -Category 'PATH_TOO_LONG' -Title 'Path too long to enumerate' -Path $dirPath -Evidence 'Path exceeded the runtime path length support.' -Recommendation 'Inspect manually if this path is important.'
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'ENUMERATION_FAILED' -Title 'Directory enumeration failed' -Path $dirPath -Evidence 'Directory enumeration failed and scanner continued.' -Recommendation 'Inspect manually if this path is important.'
        }
    }

    return $result
}

function Test-ProjectMarkerDirectory {
    param([string]$DirectoryPath)
    try {
        foreach ($file in [System.IO.Directory]::GetFiles($DirectoryPath)) {
            $name = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
            if ($name -in @('package.json','package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb','pyproject.toml','pipfile','poetry.lock','composer.json')) { return $true }
            if ($name -match '^requirements.*\.txt$') { return $true }
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
    $name = $Directory.Name.ToLowerInvariant()
    return ($name -in @('node_modules','.venv','venv','env','vendor','__pycache__','.tox','.mypy_cache','.pytest_cache','.next','.nuxt','.svelte-kit','dist','build','out','target','bin','obj','.cache','.tmp','tmp','reports'))
}

function Get-DiscoveredProjectRoots {
    param([string]$RootPath)
    $result = New-ArrayList
    try {
        $root = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
        if (-not $root.PSIsContainer -or (Test-IsReparsePoint $root)) { return @() }
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
            Add-Finding -Severity 'WARN' -Category 'PROJECT_DISCOVERY_LIMIT_REACHED' -Title 'Child project discovery limit reached' -Path $rootFull -Evidence 'Project discovery stopped at the configured root or directory limit; normal source scanning continues.' -Recommendation 'Scan a narrower child directory directly if a project may be beyond the discovery limit.' -Check 'Packages' -DetectionMethod 'metadata'
        }
        if ($partialFailures -gt 0) {
            Add-Finding -Severity 'INFO' -Category 'PROJECT_DISCOVERY_PARTIAL' -Title 'Some directories could not be inspected for project markers' -Path $rootFull -Evidence ("Project marker discovery continued after {0} inaccessible or unreadable directorie(s)." -f $partialFailures) -Recommendation 'Run a narrower scan with read access if those directories are important.' -Check 'Packages' -DetectionMethod 'metadata'
        }
        $ordered = @($result | Sort-Object @{Expression={ [int]$_.depth }}, @{Expression={ [string]$_.path }})
        Add-ScanStat -Name 'projectRootsDiscovered' -Amount $ordered.Count
        return @($ordered | ForEach-Object { [string]$_.path })
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'PROJECT_DISCOVERY_FAILED' -Title 'Child project discovery failed' -Path $RootPath -Evidence 'Project marker discovery failed; normal source scanning continues.' -Recommendation 'Scan a child project directly if dependency targeting is required.' -Check 'Packages' -DetectionMethod 'metadata'
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
        foreach ($match in [regex]::Matches($scriptText, '(?i)(?:^|\s)(?:node|bun)\s+(?:"([^"]+)"|''([^'']+)''|([^\s;&|]+))')) {
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
        $rootFull = [System.IO.Path]::GetFullPath($RootPath).TrimEnd('\')
        $candidateFull = [System.IO.Path]::GetFullPath($CandidatePath)
        if (-not $candidateFull.StartsWith($rootFull + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        $relative = $candidateFull.Substring($rootFull.Length + 1)
        $current = $rootFull
        foreach ($segment in ($relative -split '\\')) {
            if ([string]::IsNullOrEmpty($segment)) { continue }
            $current = Join-Path $current $segment
            if (Test-Path -LiteralPath $current) {
                $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
                if (Test-IsReparsePoint $item) { return $true }
            }
        }
    }
    catch {
        return $true
    }
    return $false
}

function Resolve-NpmPackageEntrypointFile {
    param([string]$PackageRoot, [string]$Candidate)
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

function Add-NodeModuleTargetedFiles {
    param($List, [string]$RootPath)
    $nodeModules = Join-Path $RootPath 'node_modules'
    if (-not (Test-Path -LiteralPath $nodeModules -PathType Container)) { return }
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
            if ($List.Count -ge 10000) { break }
            $packageJsonPath = Join-Path $packageRoot 'package.json'
            if (-not (Test-Path -LiteralPath $packageJsonPath -PathType Leaf)) { continue }
            Add-ScanStat -Name 'npmTargetedPackagesInspected'
            $key = ([System.IO.Path]::GetFullPath($packageJsonPath)).ToLowerInvariant()
            if (-not $seenFiles.ContainsKey($key)) {
                Add-FileIfExists $List $packageJsonPath
                $seenFiles[$key] = $true
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
                Add-ListItem $candidateGroups @($lifecycleCandidates.ToArray())
                Add-ListItem $candidateGroups @($runtimeCandidates.ToArray())
                Add-ListItem $candidateGroups @($binCandidates.ToArray())
                Add-ListItem $candidateGroups @($exportsCandidates.ToArray())
                $entrypointsAdded = 0
                $attemptedCandidates = @{}
                foreach ($candidateGroup in @($candidateGroups)) {
                    if ($entrypointsAdded -ge 4 -or $List.Count -ge 10000) { break }
                    foreach ($rawCandidate in @($candidateGroup)) {
                        $candidateKey = ([string]$rawCandidate).ToLowerInvariant()
                        if ($attemptedCandidates.ContainsKey($candidateKey)) { continue }
                        $attemptedCandidates[$candidateKey] = $true
                        $resolved = Resolve-NpmPackageEntrypointFile -PackageRoot $packageRoot -Candidate ([string]$rawCandidate)
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
                if ($entrypointsAdded -lt 4 -and $List.Count -lt 10000) {
                    foreach ($candidateGroup in @($candidateGroups)) {
                        foreach ($rawCandidate in @($candidateGroup)) {
                            if ($entrypointsAdded -ge 4 -or $List.Count -ge 10000) { break }
                            $candidateKey = ([string]$rawCandidate).ToLowerInvariant()
                            if ($attemptedCandidates.ContainsKey($candidateKey)) { continue }
                            $attemptedCandidates[$candidateKey] = $true
                            $resolved = Resolve-NpmPackageEntrypointFile -PackageRoot $packageRoot -Candidate ([string]$rawCandidate)
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
                        if ($entrypointsAdded -ge 4 -or $List.Count -ge 10000) { break }
                    }
                }
            }
            catch {
                Add-ScanStat -Name 'npmTargetedEntrypointResolutionFailures'
            }
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
        if (-not (Test-Path -LiteralPath $venv -PathType Container)) {
            continue
        }
        try {
            $queue = New-Object System.Collections.Queue
            $queue.Enqueue($venv)
            $visited = 0
            while ($queue.Count -gt 0 -and $visited -lt 10000) {
                $current = [string]$queue.Dequeue()
                $visited++
                $dirInfo = New-Object System.IO.DirectoryInfo($current)
                if (Test-IsReparsePoint $dirInfo) { continue }
                $currentFiles = [System.IO.Directory]::GetFiles($current)
                $hasSetupPth = $false
                foreach ($file in $currentFiles) {
                    $leaf = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
                    if ($leaf.EndsWith('.pth') -or $leaf -eq 'sitecustomize.py' -or $leaf -eq 'usercustomize.py' -or $leaf -eq 'direct_url.json' -or $leaf -eq 'record') {
                        Add-FileIfExists $List $file
                    }
                    if ($leaf -match '-setup\.pth$') { $hasSetupPth = $true }
                }
                if ($hasSetupPth) {
                    Add-FileIfExists $List (Join-Path $current '_index.js')
                    Add-FileIfExists $List (Join-Path $current '.bun_ran')
                }
                foreach ($subdir in [System.IO.Directory]::GetDirectories($current)) {
                    $queue.Enqueue($subdir)
                }
            }
        }
        catch {
            Add-Finding -Severity 'INFO' -Category 'TARGETED_PYTHON_ENV_FAILED' -Title 'Targeted Python environment scan failed' -Path $venv -Evidence 'Python environment metadata enumeration failed.' -Recommendation 'Inspect Python environment hooks manually if needed.'
        }
    }
}

function Get-TargetedFileList {
    param([string]$RootPath)
    $result = New-ArrayList
    if ([string]::IsNullOrEmpty($RootPath) -or -not (Test-Path -LiteralPath $RootPath -PathType Container)) {
        return $result
    }

    if ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts')) {
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

function Read-TextFileSafe {
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
        if ($File.Length -gt $maxBytes) {
            Add-Finding -Severity 'INFO' -Category 'FILE_TOO_LARGE_SKIPPED' -Title 'File skipped because it exceeds size limit' -Path $File.FullName -Evidence ("Length exceeds MaxFileSizeMB={0}." -f $MaxFileSizeMB) -Recommendation 'Increase MaxFileSizeMB or inspect manually if this file is important.'
            Add-ScanStat -Name 'filesSkipped'
            $result.skipped = $true
            return $result
        }

        $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
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
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -eq 0) {
                if (($i % 2) -eq 0) { $evenZeros++ } else { $oddZeros++ }
            }
        }
        if ($bytes.Length -gt 4 -and $oddZeros -gt ($bytes.Length / 8) -and $evenZeros -lt ($oddZeros / 4)) {
            $result.text = [System.Text.Encoding]::Unicode.GetString($bytes)
            $result.encoding = 'utf-16le-heuristic'
            $result.ok = $true
            return $result
        }
        if ($bytes.Length -gt 4 -and $evenZeros -gt ($bytes.Length / 8) -and $oddZeros -lt ($evenZeros / 4)) {
            $result.text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes)
            $result.encoding = 'utf-16be-heuristic'
            $result.ok = $true
            return $result
        }
        if (Test-IsProbablyBinary $bytes) {
            Add-ScanStat -Name 'filesSkipped'
            $result.skipped = $true
            $result.isBinary = $true
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
    catch [System.UnauthorizedAccessException] {
        Add-Finding -Severity 'INFO' -Category 'ACCESS_DENIED' -Title 'File could not be read' -Path $File.FullName -Evidence 'Access denied while reading file.' -Recommendation 'Run from an account with read access if this file must be inspected.'
        Add-ScanStat -Name 'filesSkipped'
        $result.skipped = $true
        return $result
    }
    catch [System.IO.PathTooLongException] {
        Add-Finding -Severity 'INFO' -Category 'PATH_TOO_LONG' -Title 'File path too long' -Path $File.FullName -Evidence 'Path exceeded the runtime path length support.' -Recommendation 'Inspect manually if this file is important.'
        Add-ScanStat -Name 'filesSkipped'
        $result.skipped = $true
        return $result
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'TEXT_DECODE_FAILED' -Title 'File text decode failed' -Path $File.FullName -Evidence 'The scanner could not safely read this file as text.' -Recommendation 'Inspect manually if this file is important.'
        Add-ScanStat -Name 'filesSkipped'
        $result.skipped = $true
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
    for ($i = 0; $i -lt $max; $i++) {
        if ($Text[$i] -eq "`n") {
            $line++
        }
    }
    return $line
}

function Get-FirstMatchLine {
    param([string]$Text, [string]$Pattern)
    $match = [regex]::Match($Text, $Pattern, 'IgnoreCase')
    if ($match.Success) {
        return (Get-LineNumberForIndex -Text $Text -Index $match.Index)
    }
    return $null
}

function Test-ExternalExecutionPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text -match '(?is)(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod).{0,120}(\||;|&&).{0,120}(bash|sh|powershell|pwsh|iex|Invoke-Expression|cmd\.exe)') { return $true }
    if ($Text -match '(?is)(https?://|raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com).{0,160}(iex|Invoke-Expression|bash|sh|powershell|pwsh|eval|exec)') { return $true }
    if ($Text -match '(?is)(FromBase64String|base64\s+-d|certutil\s+-decode).{0,120}(iex|Invoke-Expression|bash|sh|powershell|pwsh|eval|exec)') { return $true }
    return $false
}

function Test-IsPassiveScannerPatternLine {
    param([string]$Line)
    if ([string]::IsNullOrEmpty($Line)) { return $false }
    $trimmed = $Line.Trim()
    if ($trimmed -match '(?i)(ForbiddenLinePatterns|ForbiddenCommandPatterns|SuspiciousPatterns|PatternIoc|regex|Select-String\s+-Pattern)') {
        return $true
    }
    if ($trimmed -match '^[\''"].*[\^\(\)\[\]\\].*[\''"],?\s*$' -and $trimmed -match '(?i)(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|bash|powershell|pwsh|iex|Invoke-Expression)') {
        return $true
    }
    return $false
}

function Get-GitHubActionsExternalExecutionLine {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $lines = $Text -split "`r?`n"
    $inPassiveArray = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = [string]$lines[$i]
        $trimmed = $line.Trim()
        if ([string]::IsNullOrEmpty($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }
        if ($trimmed -match '(?i)(ForbiddenLinePatterns|ForbiddenCommandPatterns|SuspiciousPatterns|RegexPatterns)\s*=\s*@\(') {
            $inPassiveArray = $true
            continue
        }
        if ($inPassiveArray) {
            if ($trimmed -match '^\)\s*(\||$)') {
                $inPassiveArray = $false
            }
            continue
        }
        if (Test-IsPassiveScannerPatternLine $line) {
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
                if (Test-IsPassiveScannerPatternLine $nextLine) { continue }
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
    if ($Text -match ('(?is)' + $secretPattern + '.{0,300}' + $egressPattern)) { return $true }
    if ($Text -match ('(?is)' + $egressPattern + '.{0,300}' + $secretPattern)) { return $true }
    if ($Text -match ('(?is)' + $aiTokenPathPattern + '.{0,300}' + $egressPattern)) { return $true }
    if ($Text -match ('(?is)' + $egressPattern + '.{0,300}' + $aiTokenPathPattern)) { return $true }
    return $false
}

function Get-UrlHostsFromText {
    param([string]$Text)
    $hosts = New-ArrayList
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    foreach ($m in [regex]::Matches($Text, '(?i)https?://([A-Za-z0-9._:-]+)')) {
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
    if ($Text -match '(?is)(raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|discord(app)?\.com/api/webhooks|webhook)') { return $true }
    $hosts = @(Get-UrlHostsFromText -Text $Text)
    foreach ($urlHost in $hosts) {
        if (-not (Test-IsAllowedGithubHost -HostName $urlHost)) {
            return $true
        }
    }
    if ($hosts.Count -eq 0 -and $Text -match '(?is)(curl|wget|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|fetch\s*\(|request\s*\(|requests\.|urllib\.request|axios|WebClient|HttpClient).{0,160}(\$url|args\.url|param\s*\(|Read-Host|\$\{?uri\}?)') {
        return $true
    }
    return $false
}

function Test-AiTextHasOnlyAllowedGithubEgress {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text -match '(?is)(raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|discord(app)?\.com/api/webhooks|webhook)') { return $false }
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
    return ($Text -match '(?is)(\bPOST\b|\bPUT\b|\bPATCH\b|\bDELETE\b|upload|UploadString|UploadData|requests\.post|requests\.put|axios\.post|axios\.put|fetch\s*\(.{0,200}method\s*:\s*[''"]?(POST|PUT|PATCH|DELETE)|curl.{0,160}(-X\s*(POST|PUT|PATCH|DELETE)|--data|-d\s|--form|-F\s)|Invoke-RestMethod.{0,160}(-Method\s+(Post|Put|Patch|Delete)|-Body)|Invoke-WebRequest.{0,160}(-Method\s+(Post|Put|Patch|Delete)|-Body))')
}

function Test-AiTextHasTokenReference {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return ($Text -match '(?is)(GITHUB_TOKEN|GH_TOKEN|process\.env\.[A-Za-z0-9_]*(TOKEN|SECRET|KEY)|os\.environ(\.get)?\s*\(\s*[''"][A-Za-z0-9_]*(TOKEN|SECRET|KEY)|env:[A-Za-z0-9_]*(TOKEN|SECRET|KEY)|\$env:[A-Za-z0-9_]*(TOKEN|SECRET|KEY))')
}

function Test-AiAuthorizedGithubReadClient {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $hasGithubClient = ($Text -match '(?is)(GITHUB_TOKEN|GH_TOKEN|Authorization|github_request|github_api_contents_url|api\.github\.com|codeload\.github\.com)')
    if (-not $hasGithubClient) { return $false }
    if (Test-AiTextHasUntrustedEgress -Text $Text) { return $false }
    if (Test-AiTextHasWriteOrUpload -Text $Text) { return $false }
    return $true
}

function Test-AiRemoteInstallOrWriteCapability {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ((Test-AiTextHasWriteOrUpload -Text $Text) -and ($Text -match '(?is)(https?://|api\.github\.com|github\.com|codeload\.github\.com|fetch\s*\(|request\s*\(|requests\.|curl|Invoke-RestMethod|Invoke-WebRequest)')) {
        return $true
    }
    if ($Text -match '(?is)(codeload\.github\.com|https://github\.com/[^''"\s]+\.git|git@github\.com:[^''"\s]+\.git|argparse\.|--url|args\.url).{0,500}(subprocess\.run|git\s+clone|download|zip|extract|install)') {
        return $true
    }
    if ($Text -match '(?is)(subprocess\.run|git\s+clone|download|zip|extract|install).{0,500}(codeload\.github\.com|https://github\.com/[^''"\s]+\.git|git@github\.com:[^''"\s]+\.git|argparse\.|--url|args\.url)') {
        return $true
    }
    return $false
}

function Test-AiSecretExfilPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $authPathPattern = '(?is)(\.codex\\+auth\.json|CODEX_HOME.{0,160}auth\.json|\.claude\\+[^''"\s]{0,120}(auth|token|credential)|\.cursor\\+[^''"\s]{0,120}(auth|token|credential)|\.windsurf\\+[^''"\s]{0,120}(auth|token|credential)|\.ssh\\+id_rsa|\.ssh\\+id_ed25519|\.aws\\+credentials|\.config\\+gcloud|\.kube\\+config)'
    $readPattern = '(?is)(Get-Content|ReadAllText|read_text|open\s*\(|fs\.readFile|cat\s+)'
    if ($Text -match $authPathPattern -and $Text -match $readPattern -and ($Text -match '(?is)(https?://|curl|wget|Invoke-WebRequest|Invoke-RestMethod|fetch\s*\(|request\s*\(|requests\.|urllib\.request|axios|WebClient|HttpClient)')) {
        return $true
    }
    if (Test-AiAuthorizedGithubReadClient -Text $Text) { return $false }
    if ((Test-AiTextHasTokenReference -Text $Text) -and (Test-AiTextHasUntrustedEgress -Text $Text)) {
        return $true
    }
    if ((Test-AiTextHasTokenReference -Text $Text) -and (Test-AiTextHasWriteOrUpload -Text $Text) -and -not (Test-AiAuthorizedGithubReadClient -Text $Text)) {
        if (Test-AiTextHasOnlyAllowedGithubEgress -Text $Text) {
            return $false
        }
        return $true
    }
    return $false
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
        if (-not [string]::IsNullOrEmpty($domain) -and $Text -match [regex]::Escape($domain)) {
            return $true
        }
    }
    foreach ($ip in @($script:Context.iocs.ips)) {
        if (-not [string]::IsNullOrEmpty($ip) -and $Text -match [regex]::Escape($ip)) {
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
        if (-not [string]::IsNullOrEmpty($domain) -and $Text -match [regex]::Escape($domain)) {
            return [ordered]@{ type='domain'; value=$domain; pattern=[regex]::Escape($domain) }
        }
    }
    foreach ($ip in @($script:Context.iocs.ips)) {
        if (-not [string]::IsNullOrEmpty($ip) -and $Text -match [regex]::Escape($ip)) {
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
    $secretHarvestPattern = '(?is)(\.npmrc|\.pypirc|\.netrc|\.ssh\\+id_rsa|\.ssh\\+id_ed25519|\.aws\\+credentials|\.kube\\+config|\.codex\\+auth\.json|CODEX_HOME|secrets\.[A-Za-z0-9_]+|\$\{\{\s*secrets\.|process\.env(\.[A-Za-z0-9_]*(TOKEN|SECRET|KEY|PASSWORD)|\s*\[)|os\.environ(\.get)?\s*\(|Get-ChildItem\s+Env:|\$env:[A-Za-z0-9_]*(TOKEN|SECRET|KEY|PASSWORD)|env:[A-Za-z0-9_]*(TOKEN|SECRET|KEY|PASSWORD)|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN|[A-Za-z0-9_]*(API_KEY|TOKEN|SECRET|PASSWORD)\s*[:=])'
    $sendPattern = '(?is)(curl|wget|Invoke-RestMethod|Invoke-WebRequest|\biwr\b|\birm\b|fetch\s*\(|request\s*\(|requests\.post|requests\.put|axios\.post|axios\.put|WebClient|HttpClient|UploadString|UploadData).{0,220}(https?://|raw\.githubusercontent|gist\.github|pastebin|webhook|--data|-d\s|--form|-F\s|-Body|method\s*:\s*[''"]?(POST|PUT|PATCH)|POST|PUT|PATCH|upload)'
    if ($Text -match ($secretHarvestPattern + '.{0,500}' + $sendPattern)) { return $true }
    if ($Text -match ($sendPattern + '.{0,500}' + $secretHarvestPattern)) { return $true }
    return $false
}

function Test-DeveloperToolPersistenceWritePattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $toolPathPattern = '(?is)(\.vscode[\\/]+extensions|\.vscode[\\/]+settings\.json|\.cursor[\\/]+|\.claude[\\/]+|\.codex[\\/]+|\.windsurf[\\/]+|claude_desktop_config\.json|mcp\.json|settings\.json)'
    $writePattern = '(?is)(Set-Content|Add-Content|Out-File|WriteAllText|writeFile|fs\.writeFile|copyFile|cp\s+|Copy-Item|New-Item|mkdir|echo\s+.+>|>\s*[^&|])'
    if (($Text -match $toolPathPattern) -and ($Text -match $writePattern)) {
        return $true
    }
    return $false
}

function Test-ImportOrRuntimeExecutionPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-SecretHarvestingExternalSendPattern $Text) { return $true }
    if (Test-ExternalExecutionPattern $Text) { return $true }
    if ((Test-DeveloperToolPersistenceWritePattern $Text) -and ($Text -match '(?is)(https?://|curl|wget|fetch\s*\(|request\s*\(|axios|process\.env|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|TOKEN|SECRET)')) {
        return $true
    }
    return $false
}

function Get-NpmIncidentContextMarker {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $markers = @(
        @{ label='83.142.209.194'; pattern='83\.142\.209\.194' },
        @{ label='/tmp/transformers.pyz'; pattern='/tmp/transformers\.pyz|\\tmp\\transformers\.pyz' },
        @{ label='pgmonitor.py'; pattern='\bpgmonitor\.py\b' },
        @{ label='pgsql-monitor.service'; pattern='pgsql-monitor\.service' },
        @{ label='setup_bun.js'; pattern='\bsetup_bun\.js\b' },
        @{ label='bun_environment.js'; pattern='\bbun_environment\.js\b' },
        @{ label='actionsSecrets.json'; pattern='\bactionsSecrets\.json\b' },
        @{ label='truffleSecrets.json'; pattern='\btruffleSecrets\.json\b' }
    )
    foreach ($marker in @($markers)) {
        if ($Text -match [string]$marker.pattern) {
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
    if ($Text -match '(?is)(@solana/web3\.js|mainnet-beta|api\.mainnet-beta\.solana\.com|solana).{0,350}(getAccountInfo|getParsedAccountInfo|PublicKey\s*\(|Connection\s*\()') { return $true }
    if ($Text -match '(?is)(getAccountInfo|getParsedAccountInfo|PublicKey\s*\(|Connection\s*\().{0,350}(@solana/web3\.js|mainnet-beta|api\.mainnet-beta\.solana\.com|solana)') { return $true }
    if ($Text -match '(?is)(bittorrent-dht|dht-rpc|k-rpc|announce_peer|get_peers|bootstrap\.addrs)') { return $true }
    if ($Text -match '(?is)(googleapis\.com/calendar|calendar/v3|calendar\.events\.list|events\.list\s*\().{0,350}(summary|title|description)') { return $true }
    if ($Text -match '(?is)(summary|title|description).{0,350}(googleapis\.com/calendar|calendar/v3|calendar\.events\.list|events\.list\s*\()') { return $true }
    if ($Text -match '(?is)(dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)') { return $true }
    return $false
}

function Test-GlassWormExecutionOrExfilCompound {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-ExternalExecutionPattern $Text) { return $true }
    if (Test-SecretHarvestingExternalSendPattern $Text) { return $true }
    if ($Text -match '(?is)(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|Buffer\.from|atob\s*\(|FromBase64String|decodeURIComponent|String\.fromCharCode).{0,400}(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)') { return $true }
    if ($Text -match '(?is)(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz).{0,400}(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|Buffer\.from|atob\s*\(|FromBase64String|decodeURIComponent|String\.fromCharCode)') { return $true }
    return $false
}

function Test-ReferenceTextExecutableSamplePattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text -match '(?is)```[^`]{0,1800}(curl|wget|\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod).{0,220}(\|\s*(iex|bash|sh|powershell|pwsh)|Invoke-Expression|bash\s+-c|sh\s+-c|powershell\s+-|pwsh\s+-)[^`]{0,1800}```') {
        return $true
    }
    if ($Text -match '(?is)```[^`]{0,1800}(\.npmrc|\.pypirc|\.netrc|\.codex\\+auth\.json|process\.env|os\.environ|GITHUB_TOKEN|GH_TOKEN|TOKEN|SECRET).{0,500}(requests\.post|axios\.post|fetch\s*\(|Invoke-RestMethod|curl).{0,220}(https?://|--data|-d\s|-Body|method\s*:\s*[''"]?POST)[^`]{0,1800}```') {
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

function Test-KnownFileIocMatch {
    param([System.IO.FileInfo]$File, $Ioc)
    if ($null -eq $File -or $null -eq $Ioc) { return $false }
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
    $pathLower = $File.FullName.ToLowerInvariant() -replace '/', '\'
    if (Test-IsJetBrainsPluginPath $File.FullName) {
        $checkName = 'IdeExtensions'
        $category = 'JETBRAINS_PLUGIN_KNOWN_IOC'
        $title = 'Known suspicious JetBrains plugin artifact detected'
    }
    elseif ($pathLower -match '\\extensions\\') { $checkName = 'IdeExtensions' }
    elseif ($pathLower -match '\\node_modules\\') { $checkName = 'Packages' }
    elseif ($pathLower -match '\\\.github\\actions\\') { $checkName = 'CiCd' }
    Add-Finding -Severity $severity -Category $category -Title $title -Path $File.FullName -Evidence ("Known file IOC matched. Notes: {0}" -f $notes) -Recommendation 'Preserve evidence and verify endpoint context before deleting or modifying the file.' -RiskType 'known-ioc' -Confidence 'high' -Check $checkName -DetectionMethod 'metadata'
}

function Scan-KnownFileIocs {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File -or $null -eq $script:Context -or $null -eq $script:Context.iocs) { return }
    foreach ($ioc in @($script:Context.iocs.files)) {
        if (-not (Test-KnownFileIocMatch -File $File -Ioc $ioc)) { continue }
        $expectedHash = [string](Get-PropertyValue $ioc 'sha256')
        if (-not [string]::IsNullOrEmpty($expectedHash)) {
            $actualHash = Get-BytesSha256ForFile $File.FullName
            if ([string]::IsNullOrEmpty($actualHash) -or $actualHash.ToLowerInvariant() -ne $expectedHash.ToLowerInvariant()) {
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
    Add-Finding -Severity 'DANGER' -Category 'KNOWN_IOC_TEXT_PATTERN' -Title 'Known IOC text pattern detected' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern ([string]$match.pattern)) -Evidence ("Known IOC {0} matched: {1}" -f $match.type, $match.value) -Recommendation 'Preserve evidence and inspect surrounding file context without executing it.' -RiskType 'known-ioc' -Confidence 'high'
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
        try {
            $match = [regex]::Match($Text, $regex, 'IgnoreCase')
            if (-not $match.Success) { continue }
            $severity = [string](Get-PropertyValue $patternIoc 'severity')
            if ([string]::IsNullOrEmpty($severity)) { $severity = 'WARN' }
            $id = [string](Get-PropertyValue $patternIoc 'id')
            if ([string]::IsNullOrEmpty($id)) { $id = 'LOCAL_SUSPICIOUS_TEXT_PATTERN' }
            $title = [string](Get-PropertyValue $patternIoc 'title')
            if ([string]::IsNullOrEmpty($title)) { $title = 'Local suspicious text pattern matched' }
            $notes = [string](Get-PropertyValue $patternIoc 'notes')
            if ([string]::IsNullOrEmpty($notes)) { $notes = 'Local suspicious pattern matched. Line content redacted.' }
            Add-Finding -Severity $severity -Category $id.ToUpperInvariant() -Title $title -Path $File.FullName -Line (Get-LineNumberForIndex -Text $Text -Index $match.Index) -Evidence $notes -Recommendation 'Review the file context manually and update local IOC data if this is no longer relevant.'
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
        Add-Finding -Severity 'WARN' -Category 'GLASSWORM_C2_MARKER_IN_EXECUTABLE_CONTEXT' -Title 'GlassWorm-style C2 marker appears in executable context' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)') -Evidence ("context={0}; sourceContext={1}; no nearby execution or exfil pattern found" -f $textContext, $sourceContext) -Recommendation 'Verify whether this C2-like channel usage is expected.' -RiskType 'posture' -Confidence 'medium'
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
    return ($Text -match '(?is)(\.codex\\+auth\.json|CODEX_HOME|\.claude|\.cursor|\.windsurf)')
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

function Invoke-ScannerStep {
    param(
        [Parameter(Mandatory=$true)][string]$StepName,
        [System.IO.FileInfo]$File,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    $oldPhase = $script:CurrentPhase
    $script:CurrentPhase = $StepName
    try {
        & $ScriptBlock
    }
    catch {
        Add-ScanStat -Name 'scannerFileErrors'
        $path = $null
        if ($null -ne $File) {
            $path = $File.FullName
        }
        Add-Finding -Severity 'WARN' -Category 'SCANNER_FILE_ERROR' -Title 'Scanner step failed for one file' -Path $path -Evidence (Get-ScannerExceptionEvidence -ErrorRecord $_ -Phase $StepName) -Recommendation 'Review scanner logs and rerun parser validation. The scanner continued with remaining checks.'
    }
    finally {
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
    if ($path -match '\\(\.github\\workflows|\.git\\hooks|\.husky|\.vscode)\\') { return 'execution-config' }
    if ($name -in @('mcp.json','claude_desktop_config.json','settings.json')) { return 'execution-config' }
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

function Scan-InvisibleUnicode {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ([string]::IsNullOrEmpty($Text)) {
        return
    }
    $bmpPattern = '[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F]'
    $supplementPattern = '\uDB40[\uDD00-\uDDEF]'
    $bmp = [regex]::Match($Text, $bmpPattern)
    $supplement = [regex]::Match($Text, $supplementPattern)
    if (-not $bmp.Success -and -not $supplement.Success) {
        return
    }

    $textContext = Get-TextContext -File $File
    $matches = New-ArrayList
    foreach ($m in [regex]::Matches($Text, $bmpPattern)) {
        Add-ListItem $matches $m
    }
    foreach ($m in [regex]::Matches($Text, $supplementPattern)) {
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
    $isExecutableContext = ($textContext -in @('code','execution-config'))
    if ($isExecutableContext -and (Test-InvisibleUnicodeExecutionNear -Text $Text -Index $selected.Index)) {
        Add-Finding -Severity 'DANGER' -Category 'INVISIBLE_UNICODE_EXECUTION_COMPOUND' -Title 'Invisible Unicode appears near decoder or execution pattern' -Path $File.FullName -Line $line -Evidence ("codePoint={0}; context={1}; compoundPattern=execution-or-decoder-nearby" -f $selectedCodePoint, $textContext) -Recommendation 'Inspect the file from a trusted editor and compare with known-good source.'
    }
    else {
        Add-Finding -Severity 'WARN' -Category 'INVISIBLE_UNICODE_PRESENT' -Title 'Invisible Unicode character detected' -Path $File.FullName -Line $line -Evidence ("codePoint={0}; context={1}" -f $selectedCodePoint, $textContext) -Recommendation 'Inspect whether the character is intentional.'
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

function Test-IsExactPackageVersionText {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $false }
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
    $normalizedVersion = Normalize-Version $Version
    foreach ($ioc in @($script:Context.iocs.packages)) {
        if ([string]::IsNullOrEmpty($ioc.name)) { continue }
        if ($ioc.ecosystem -ne $Ecosystem) { continue }
        if ($ioc.name -ne $Name) { continue }
        foreach ($badVersion in @($ioc.versions)) {
            if ($badVersion -eq '*' -or (Normalize-Version $badVersion) -eq $normalizedVersion) {
                $sev = $ioc.severity
                if ([string]::IsNullOrEmpty($sev)) { $sev = 'DANGER' }
                $category = 'KNOWN_COMPROMISED_PACKAGE'
                $title = 'Known compromised package version detected'
                $confidence = 'high'
                if ($EvidenceKind -notin @('installed-exact','lockfile-exact','manifest-exact')) {
                    if ($sev -eq 'DANGER') { $sev = 'WARN' }
                    $category = 'KNOWN_COMPROMISED_PACKAGE_REFERENCE'
                    $title = 'Package constraint or fallback text references a known compromised version'
                    $confidence = 'medium'
                }
                Add-Finding -Severity $sev -Category $category -Title $title -Path $Path -Line $Line -Evidence ("ecosystem={0}; package={1}; version={2}; evidenceKind={3}" -f $Ecosystem, $Name, $normalizedVersion, $EvidenceKind) -Recommendation 'Confirm the resolved version in a lockfile or installed package metadata before concluding that the affected version is present.' -RiskType 'known-ioc' -Confidence $confidence -Check 'Packages' -DetectionMethod 'metadata'
            }
        }
    }
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

function Scan-KnownPackageText {
    param([System.IO.FileInfo]$File, [string]$Text, [string]$Ecosystem, [string]$EvidenceKindOverride)
    $fileName = $File.Name.ToLowerInvariant()
    $evidenceKind = 'text-fallback'
    if ($fileName -in @('package-lock.json','pnpm-lock.yaml','yarn.lock','bun.lock','poetry.lock','uv.lock')) {
        $evidenceKind = 'lockfile-exact'
    }
    if (-not [string]::IsNullOrEmpty($EvidenceKindOverride)) { $evidenceKind = $EvidenceKindOverride }
    foreach ($ioc in @($script:Context.iocs.packages)) {
        if ($ioc.ecosystem -ne $Ecosystem) { continue }
        $namePattern = [regex]::Escape($ioc.name)
        foreach ($badVersion in @($ioc.versions)) {
            if ($badVersion -eq '*') { continue }
            $versionPattern = [regex]::Escape($badVersion)
            $pattern = '(?is)' + $namePattern + '.{0,120}' + $versionPattern
            $match = [regex]::Match($Text, $pattern)
            if ($match.Success) {
                $line = Get-LineNumberForIndex -Text $Text -Index $match.Index
                $matchEvidenceKind = $evidenceKind
                if ($Ecosystem -eq 'python' -and $fileName -match '^requirements') {
                    $exactRequirementPattern = '(?im)^\s*' + $namePattern + '(?:\[[^\]]+\])?\s*==\s*' + $versionPattern + '(?:\s|;|$)'
                    if ($Text -match $exactRequirementPattern) {
                        $matchEvidenceKind = 'manifest-exact'
                    }
                    else {
                        $matchEvidenceKind = 'constraint-reference'
                    }
                }
                Add-KnownPackageFinding -Ecosystem $Ecosystem -Name $ioc.name -Version $badVersion -Path $File.FullName -Line $line -EvidenceKind $matchEvidenceKind
            }
        }
    }
}

function Scan-NpmPackageLockDependencyObject {
    param($Dependencies, [System.IO.FileInfo]$File, [int]$Depth = 0)
    if ($null -eq $Dependencies -or $Depth -gt 12) { return }
    foreach ($property in @($Dependencies.PSObject.Properties)) {
        $name = [string]$property.Name
        $entry = $property.Value
        $version = [string](Get-PropertyValue $entry 'version')
        if (-not [string]::IsNullOrEmpty($name) -and -not [string]::IsNullOrEmpty($version)) {
            Add-KnownPackageFinding -Ecosystem 'npm' -Name $name -Version $version -Path $File.FullName -Line 1 -EvidenceKind 'lockfile-exact'
            Add-NpmIncidentWatchlistFinding -Name $name -Version $version -Path $File.FullName -Line 1
        }
        Scan-NpmPackageLockDependencyObject -Dependencies (Get-PropertyValue $entry 'dependencies') -File $File -Depth ($Depth + 1)
    }
}

function Scan-NpmPackageLockJson {
    param([System.IO.FileInfo]$File, [string]$Text)
    try {
        $json = $Text | ConvertFrom-Json -ErrorAction Stop
        $packages = Get-PropertyValue $json 'packages'
        if ($null -ne $packages) {
            foreach ($property in @($packages.PSObject.Properties)) {
                $packagePath = ([string]$property.Name) -replace '\\', '/'
                if ([string]::IsNullOrEmpty($packagePath)) { continue }
                $parts = @((('/' + $packagePath) -split '/node_modules/'))
                $name = [string]$parts[$parts.Count - 1]
                $version = [string](Get-PropertyValue $property.Value 'version')
                if (-not [string]::IsNullOrEmpty($name) -and -not [string]::IsNullOrEmpty($version)) {
                    Add-KnownPackageFinding -Ecosystem 'npm' -Name $name -Version $version -Path $File.FullName -Line 1 -EvidenceKind 'lockfile-exact'
                    Add-NpmIncidentWatchlistFinding -Name $name -Version $version -Path $File.FullName -Line 1
                }
            }
        }
        Scan-NpmPackageLockDependencyObject -Dependencies (Get-PropertyValue $json 'dependencies') -File $File
        return $true
    }
    catch {
        Add-Finding -Severity 'INFO' -Category 'PACKAGE_LOCK_JSON_PARSE_FAILED' -Title 'package-lock.json could not be parsed as JSON' -Path $File.FullName -Evidence 'Falling back to bounded text IOC matching with WARN severity cap.' -Recommendation 'Check lockfile syntax if this is unexpected.' -Check 'Packages' -DetectionMethod 'metadata'
        return $false
    }
}

function Scan-NpmFiles {
    param([System.IO.FileInfo]$File, [string]$Text)
    $name = $File.Name.ToLowerInvariant()
    if ($name -notin @('package.json','package-lock.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb')) {
        return
    }

    if ((Test-CheckEnabled 'Packages') -and $name -ne 'package.json') {
        if ($name -eq 'package-lock.json') {
            if (-not (Scan-NpmPackageLockJson -File $File -Text $Text)) {
                Scan-KnownPackageText -File $File -Text $Text -Ecosystem 'npm' -EvidenceKindOverride 'text-fallback'
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
                        $severity = 'WARN'
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
                        elseif ((Test-DeveloperToolPersistenceWritePattern ([string]$prop.Value)) -and ([string]$prop.Value -match '(?is)(https?://|curl|wget|fetch\s*\(|request\s*\(|axios|process\.env|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|TOKEN|SECRET)')) {
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

    if (Test-SecretHarvestingExternalSendPattern $Text) {
        Add-Finding -Severity 'DANGER' -Category 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -Title 'Package or project code contains credential harvesting and external send pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.npmrc|\.pypirc|\.netrc|\.ssh|\.aws|\.kube|process\.env|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|TOKEN|SECRET)') -Evidence 'Code appears to collect credential material near external transmission. Values redacted.' -Recommendation 'Inspect without executing package code or lifecycle scripts.' -RiskType 'active-exfil' -Confidence 'high' -Check 'LifecycleScripts'
        return
    }
    if ((Test-DeveloperToolPersistenceWritePattern $Text) -and ($Text -match '(?is)(https?://|curl|wget|fetch\s*\(|request\s*\(|axios|process\.env|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|TOKEN|SECRET)')) {
        Add-Finding -Severity 'DANGER' -Category 'PACKAGE_CODE_DEV_TOOL_PERSISTENCE_PATTERN' -Title 'Package or project code can modify developer tool configuration' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.vscode|\.cursor|\.claude|\.codex|\.windsurf|mcp\.json|claude_desktop_config\.json)') -Evidence 'Code references developer tool configuration writes near network or token access. Values redacted.' -Recommendation 'Inspect before running package install, build, or helper scripts.' -RiskType 'active-exfil' -Confidence 'high' -Check 'LifecycleScripts'
        return
    }
    if (Test-ExternalExecutionPattern $Text) {
        Add-Finding -Severity 'DANGER' -Category 'PACKAGE_CODE_EXTERNAL_EXECUTION' -Title 'Package or project code contains external fetch and execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|https?://)') -Evidence 'Code contains external fetch plus execution pattern. Line content redacted.' -Recommendation 'Do not execute related package code until reviewed.' -RiskType 'fetch-execute' -Confidence 'high' -Check 'LifecycleScripts'
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

function Scan-PythonFiles {
    param([System.IO.FileInfo]$File, [string]$Text)
    $name = $File.Name.ToLowerInvariant()
    $path = $File.FullName.ToLowerInvariant()
    if ($name -notmatch '^(requirements.*\.txt|requirements\.ioc-sample|pyproject\.toml|poetry\.lock|uv\.lock|setup\.py|setup\.cfg|sitecustomize\.py|usercustomize\.py|direct_url\.json|record|_index\.js|\.bun_ran)$' -and -not $name.EndsWith('.pth')) {
        return
    }

    if (Test-CheckEnabled 'Packages') {
        Scan-KnownPackageText -File $File -Text $Text -Ecosystem 'python'
    }

    if ((Test-CheckEnabled 'LifecycleScripts') -and $name.EndsWith('.pth')) {
        if ($Text -match '(?is)\bimport\b' -and $Text -match '(?is)(exec|eval|subprocess|base64|requests|urllib|os\.environ|socket)') {
            Add-Finding -Severity 'DANGER' -Category 'PYTHON_PTH_EXECUTION_HOOK' -Title 'Python .pth file contains execution hook pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\bimport\b') -Evidence '.pth file contains import plus execution/network/credential pattern. Line content redacted.' -Recommendation 'Inspect this environment hook without importing the package.'
        }
        elseif ($Text -match '(?is)\bimport\b') {
            Add-Finding -Severity 'WARN' -Category 'PYTHON_PTH_IMPORT_HOOK' -Title 'Python .pth file contains import hook' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\bimport\b') -Evidence '.pth file contains an import statement.' -Recommendation 'Verify that the import hook is expected.'
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
        if ($null -ne $referencingPth -and $Text -match '(?is)(bun|bun\.sh|https?://|fetch\s*\(|request\s*\().{0,500}(subprocess|child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe)' -or $null -ne $referencingPth -and $Text -match '(?is)(subprocess|child_process|spawn\s*\(|exec\s*\().{0,500}(bun|bun\.sh|https?://|fetch\s*\(|request\s*\()') {
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
        if ($Text -match '(?is)(exec|eval|subprocess|base64|requests|urllib|os\.environ|socket|https?://)') {
            Add-Finding -Severity 'DANGER' -Category 'PYTHON_CUSTOMIZE_SUSPICIOUS' -Title 'Python startup customization contains suspicious pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(exec|eval|subprocess|base64|requests|urllib|os\.environ|socket|https?://)') -Evidence 'Python startup customization file contains execution/network/credential pattern. Line content redacted.' -Recommendation 'Inspect manually before running Python in this environment.'
        }
        else {
            Add-Finding -Severity 'WARN' -Category 'PYTHON_CUSTOMIZE_PRESENT' -Title 'Python startup customization file exists' -Path $File.FullName -Evidence 'sitecustomize.py or usercustomize.py is loaded automatically by Python.' -Recommendation 'Verify that this startup customization is expected.'
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
    if ($Text -match '(?is)autoload\s*"?\s*:\s*.*files|autoload\.files') {
        Add-Finding -Severity 'WARN' -Category 'COMPOSER_AUTOLOAD_FILES' -Title 'Composer autoload.files entry detected' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'autoload') -Evidence 'Composer autoload.files can execute PHP files automatically.' -Recommendation 'Verify that every autoloaded file is expected.'
    }
    if ($path -match '\\vendor\\composer\\autoload_files\.php$') {
        Add-Finding -Severity 'WARN' -Category 'COMPOSER_AUTOLOAD_FILES_PRESENT' -Title 'Composer autoload_files.php exists' -Path $File.FullName -Evidence 'Composer autoload_files.php is a targeted execution surface.' -Recommendation 'Review referenced files if Composer dependencies are suspect.'
    }
    if ($Text -match '(?is)(flipboxstudio\.info|shell_exec|proc_open|curl_exec|base64_decode\s*\(|eval\s*\(|assert\s*\(|file_get_contents\s*\(\s*["'']https?://)') {
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

function Scan-GitHubActionReferences {
    param([System.IO.FileInfo]$File, [string]$Text)
    $thirdPartyMutable = New-ArrayList
    foreach ($entry in @(Get-GitHubActionUsesEntries -Text $Text)) {
        $matchedKnown = $false
        foreach ($ioc in @($script:Context.iocs.actions)) {
            if ([string]$ioc.repository -ne [string]$entry.repository) { continue }
            foreach ($commit in @($ioc.compromisedCommits)) {
                if ([string]$entry.reference -ieq [string]$commit) {
                    Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_KNOWN_COMPROMISED_COMMIT' -Title 'GitHub Action references a known compromised commit' -Path $File.FullName -Line $entry.line -Evidence ("action={0}; match=compromised-commit" -f $entry.display) -Recommendation 'Disable the workflow and review runs, artifacts, and exposed credentials associated with this Action reference.' -RiskType 'known-ioc' -Confidence 'high' -Check 'CiCd' -DetectionMethod 'metadata'
                    $matchedKnown = $true
                }
            }
            foreach ($knownRef in @($ioc.compromisedRefs)) {
                if ([string]$entry.reference -ceq [string]$knownRef) {
                    Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_HISTORICALLY_COMPROMISED_REF' -Title 'GitHub Action uses a historically affected mutable ref' -Path $File.FullName -Line $entry.line -Evidence ("action={0}; match=historically-affected-ref" -f $entry.display) -Recommendation 'Pin to a reviewed full commit SHA and verify the current ref target from a trusted source.' -RiskType 'known-ioc' -Confidence 'medium' -Check 'CiCd' -DetectionMethod 'metadata'
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
    if ($path -notmatch '\\\.github\\workflows\\.*\.ya?ml$' -and $path -notmatch '\\\.github\\actions\\') {
        return
    }
    Scan-GitHubActionReferences -File $File -Text $Text
    $hasPullRequestTarget = ($Text -match '(?im)^\s*pull_request_target\s*:|^\s*on\s*:\s*\[?[^\r\n]*pull_request_target')
    $allowsUnsafeCheckout = ($Text -match '(?im)^\s*allow-unsafe-pr-checkout\s*:\s*true\s*$')
    $hasPrivilegedContext = ($Text -match '(?is)(secrets\.|GITHUB_TOKEN|permissions\s*:.{0,400}(contents|packages|id-token|pull-requests)\s*:\s*write)')
    $checkoutAnchor = [regex]::Match($Text, '(?is)uses\s*:\s*actions/checkout@[^\r\n]+.{0,900}(ref|repository)\s*:\s*[^\r\n]*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|head\.repo\.(full_name|clone_url))')
    if (-not $checkoutAnchor.Success -and $allowsUnsafeCheckout) {
        $checkoutAnchor = [regex]::Match($Text, '(?im)^\s*allow-unsafe-pr-checkout\s*:\s*true\s*$')
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
    $discussionSelfHosted = ($Text -match '(?is)on\s*:\s*(\r?\n\s*)?discussion\b' -and $Text -match '(?is)runs-on\s*:\s*(\[.*self-hosted.*\]|self-hosted)' -and $Text -match '(?is)github\.event\.discussion\.body|github\.event\.comment\.body')
    $discussionBodyInRun = ($Text -match '(?is)run\s*:\s*(\||>)?.{0,600}github\.event\.(discussion|comment)\.body')
    if ($discussionSelfHosted -and $discussionBodyInRun) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_DISCUSSION_SELF_HOSTED_EXECUTION' -Title 'GitHub Actions workflow can execute discussion text on a self-hosted runner' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'github\.event\.(discussion|comment)\.body|self-hosted|discussion') -Evidence 'Workflow combines discussion/comment body input with self-hosted runner execution context. Line content redacted.' -Recommendation 'Disable or remove this workflow unless it is a deliberately reviewed internal automation.' -RiskType 'fetch-execute' -Confidence 'high'
    }
    elseif ($discussionSelfHosted) {
        Add-Finding -Severity 'WARN' -Category 'GITHUB_ACTIONS_DISCUSSION_SELF_HOSTED_INPUT' -Title 'GitHub Actions workflow exposes discussion text to a self-hosted runner' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'github\.event\.(discussion|comment)\.body|self-hosted|discussion') -Evidence 'Workflow references discussion/comment body on a self-hosted runner, but direct run execution was not detected.' -Recommendation 'Review whether untrusted discussion text can influence commands, scripts, or action inputs.' -RiskType 'posture' -Confidence 'medium'
    }
    if ($Text -match '(?is)toJSON\s*\(\s*secrets\s*\)|secrets\.\*|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_RUNTIME_TOKEN' -and $Text -match '(?is)actions/upload-artifact|upload-artifact|artifact_path|actionsSecrets\.json|truffleSecrets\.json') {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_SECRETS_ARTIFACT_EXFIL_PATTERN' -Title 'GitHub Actions workflow can package secrets into artifacts' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'toJSON\s*\(\s*secrets\s*\)|upload-artifact|actionsSecrets\.json|truffleSecrets\.json') -Evidence 'Workflow references broad secret material near artifact upload behavior. Secret values are not printed.' -Recommendation 'Inspect workflow history and rotate exposed credentials if this workflow ran.' -RiskType 'active-exfil' -Confidence 'high'
    }
    $externalExecutionLine = Get-GitHubActionsExternalExecutionLine -Text $Text
    if ($null -ne $externalExecutionLine) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_EXTERNAL_EXECUTION' -Title 'GitHub Actions workflow contains fetch-and-execute pattern' -Path $File.FullName -Line $externalExecutionLine -Evidence 'Workflow contains external fetch plus shell/execution pattern. Passive scanner regex definitions are ignored. Line content redacted.' -Recommendation 'Review workflow provenance and disable unsafe execution paths before running CI.'
    }
    if (Test-SecretExfilPattern $Text) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_SECRET_EXFIL_PATTERN' -Title 'GitHub Actions workflow references secrets with external transmission pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(secrets\.|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_RUNTIME_TOKEN|GITHUB_TOKEN)') -Evidence 'Secret/token reference appears near external transmission pattern. Secret values are not printed.' -Recommendation 'Inspect workflow changes and rotate affected credentials if compromise is plausible.'
    }
    if (Test-SecretHarvestingExternalSendPattern $Text) {
        Add-Finding -Severity 'DANGER' -Category 'GITHUB_ACTIONS_SECRET_HARVEST_EXFIL_PATTERN' -Title 'GitHub Actions workflow contains secret harvesting and external send pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.npmrc|\.pypirc|\.netrc|\.ssh|\.aws|\.kube|process\.env|os\.environ|GITHUB_TOKEN|GH_TOKEN|TOKEN|SECRET)') -Evidence 'Workflow appears to collect credential material near an external send pattern. Values redacted.' -Recommendation 'Inspect workflow changes and rotate affected credentials if compromise is plausible.' -RiskType 'active-exfil' -Confidence 'high'
    }
    $warnPatterns = [ordered]@{
        'pull_request_target' = 'GITHUB_ACTIONS_PULL_REQUEST_TARGET'
        'workflow_dispatch' = 'GITHUB_ACTIONS_MANUAL_TRIGGER'
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
    elseif ($Text -match '(?is)(EncodedCommand|FromBase64String|Invoke-Expression|\biex\b)') {
        Add-Finding -Severity 'WARN' -Category 'WORKSPACE_HOOK_OBFUSCATION' -Title 'Hook or workspace task contains obfuscation pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(EncodedCommand|FromBase64String|Invoke-Expression|\biex\b)') -Evidence 'Hook/task contains encoded command or expression execution pattern.' -Recommendation 'Review before running project hooks or tasks.'
    }
}

function Add-McpCommandFragmentsFromObject {
    param($Object, $List, [string]$PropertyName)
    if ($null -eq $Object) {
        return
    }

    $collect = ($PropertyName -match '^(command|cmd|args|executable)$')
    if ($Object -is [string]) {
        if ($collect) {
            Add-ListItem $List ([string]$Object)
        }
        return
    }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        foreach ($item in $Object) {
            Add-McpCommandFragmentsFromObject -Object $item -List $List -PropertyName $PropertyName
        }
        return
    }

    foreach ($property in @($Object.PSObject.Properties)) {
        $name = $property.Name
        if ($name -match '^(command|cmd|args|executable)$') {
            Add-McpCommandFragmentsFromObject -Object $property.Value -List $List -PropertyName $name
        }
        elseif ($property.Value -is [System.Collections.IEnumerable] -or $property.Value -is [psobject]) {
            Add-McpCommandFragmentsFromObject -Object $property.Value -List $List -PropertyName ''
        }
    }
}

function Get-McpCommandText {
    param([string]$Text)
    $fragments = New-ArrayList
    try {
        $json = $Text | ConvertFrom-Json -ErrorAction Stop
        Add-McpCommandFragmentsFromObject -Object $json -List $fragments -PropertyName ''
    }
    catch {
    }

    if ($fragments.Count -eq 0) {
        $lines = $Text -split "`r?`n"
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrEmpty($trimmed)) { continue }
            if ($trimmed.StartsWith('#') -or $trimmed.StartsWith('//')) { continue }
            $match = [regex]::Match($trimmed, '^(command|cmd|args|executable)\s*[:=]\s*(.+)$', 'IgnoreCase')
            if ($match.Success) {
                Add-ListItem $fragments $match.Groups[2].Value
            }
        }
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
    if ($name -in @('mcp.json','claude_desktop_config.json','settings.json')) { $isTarget = $true }
    if ($role -ne 'normal') { $isTarget = $true }
    if ($path -match '\\(\.cursor|\.claude|\.windsurf)\\') { $isTarget = $true }
    if (-not $isTarget) { return }

    $commandText = Get-McpCommandText -Text $Text
    $hasCommandText = -not [string]::IsNullOrEmpty($commandText)
    $isCommandConfig = ($role -in @('active-ai-config','plugin-metadata') -or ($role -eq 'normal' -and $name -in @('mcp.json','claude_desktop_config.json','settings.json')))
    $isReferenceContext = ($role -in @('reference-text','session-log','cache-data'))

    if (($isCommandConfig -or $role -eq 'executable-tooling') -and (Test-HasUnpinnedNpx -CommandText $commandText)) {
        Add-Finding -Severity 'WARN' -Category 'MCP_UNPINNED_NPX' -Title 'MCP or agent config appears to use unpinned npx package' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\bnpx\b') -Evidence 'npx command appears without an explicit package version. Values redacted.' -Recommendation 'Pin the MCP server package version or vendor the command.'
    }
    if (($isCommandConfig -or $role -eq 'executable-tooling') -and (Test-HasUnpinnedUvx -CommandText $commandText)) {
        Add-Finding -Severity 'WARN' -Category 'MCP_UNPINNED_UVX' -Title 'MCP or agent config appears to use unpinned uvx package' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '\buvx\b') -Evidence 'uvx command appears without an explicit package version. Values redacted.' -Recommendation 'Pin the MCP server version or vendor the command.'
    }

    if ($isCommandConfig -and $hasCommandText -and (Test-AiFetchExecutePattern $commandText)) {
        Add-Finding -Severity 'DANGER' -Category 'MCP_AGENT_EXTERNAL_EXECUTION' -Title 'MCP or agent config contains external execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|raw\.githubusercontent|gist\.github|pastebin|https?://)') -Evidence 'Config command contains external fetch plus execution pattern. Values redacted.' -Recommendation 'Disable this config entry until manually reviewed.' -RiskType 'fetch-execute' -Confidence 'high'
    }
    elseif ($role -eq 'executable-tooling' -and (Test-AiFetchExecutePattern $Text)) {
        Add-Finding -Severity 'WARN' -Category 'AI_TOOLING_EXTERNAL_EXECUTION_CAPABILITY' -Title 'AI tooling script contains external execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|raw\.githubusercontent|gist\.github|pastebin|https?://)') -Evidence 'Executable AI tooling contains tightly coupled external fetch plus execution pattern. Values redacted.' -Recommendation 'Review the script before invoking this skill, plugin, or helper.' -RiskType 'fetch-execute' -Confidence 'medium'
    }
    elseif ($isReferenceContext -and ((Test-ExternalExecutionPattern $Text) -or (Test-KnownIocTextPattern $Text))) {
        Add-AiContextAggregate -Role $role
    }
    elseif ($role -eq 'plugin-metadata' -and -not $hasCommandText -and ((Test-ExternalExecutionPattern $Text) -or (Test-KnownIocTextPattern $Text))) {
        Add-AiContextAggregate -Role $role
    }

    if ($isCommandConfig -and $hasCommandText -and (Test-AiSecretExfilPattern $commandText)) {
        Add-Finding -Severity 'DANGER' -Category 'AI_TOKEN_PATH_EXFIL_PATTERN' -Title 'AI token path appears with external transmission pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.codex\\+auth\.json|CODEX_HOME|\.claude|\.cursor|\.windsurf|GITHUB_TOKEN|GH_TOKEN)') -Evidence 'AI command references credential material near untrusted or write-capable external transmission. Values redacted.' -Recommendation 'Preserve evidence and rotate affected credentials if compromise is plausible.' -RiskType 'active-exfil' -Confidence 'high'
    }
    elseif ($role -eq 'executable-tooling' -and (Test-AiSecretExfilPattern $Text)) {
        Add-Finding -Severity 'DANGER' -Category 'AI_TOKEN_PATH_EXFIL_PATTERN' -Title 'AI tooling script references token path with external transmission pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(\.codex\\+auth\.json|CODEX_HOME|\.claude|\.cursor|\.windsurf|GITHUB_TOKEN|GH_TOKEN)') -Evidence 'Executable AI tooling references credential material near untrusted or write-capable external transmission. Values redacted.' -Recommendation 'Preserve evidence and rotate affected credentials if compromise is plausible.' -RiskType 'active-exfil' -Confidence 'high'
    }
    elseif ($isReferenceContext -and (Test-AiTokenPathReference $Text)) {
        Add-AiContextAggregate -Role $role -TokenReference
    }
    elseif ($role -eq 'plugin-metadata' -and -not $hasCommandText -and (Test-AiTokenPathReference $Text)) {
        Add-AiContextAggregate -Role $role -TokenReference
    }

    if ($role -eq 'executable-tooling' -and (Test-AiRemoteInstallOrWriteCapability $Text) -and -not (Test-AiSecretExfilPattern $Text)) {
        Add-Finding -Severity 'WARN' -Category 'AI_TOOLING_REMOTE_INSTALL_OR_WRITE_CAPABILITY' -Title 'AI tooling can download, install, or write to a remote service' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(codeload\.github\.com|github\.com|api\.github\.com|--url|args\.url|POST|PUT|PATCH|DELETE|upload)') -Evidence 'Executable AI tooling has remote install/write capability. Values redacted.' -Recommendation 'Use only when the tool source and destination are trusted.' -RiskType 'capability' -Confidence 'medium'
    }
    elseif ($role -eq 'executable-tooling' -and (Test-AiAuthorizedGithubReadClient $Text)) {
        Add-Finding -Severity 'INFO' -Category 'AI_TOOLING_AUTHORIZED_API_CLIENT' -Title 'AI tooling uses an authorized GitHub API client' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(GITHUB_TOKEN|GH_TOKEN|Authorization|github_request|api\.github\.com)') -Evidence 'Tooling appears to use GitHub authorization for allowed GitHub read endpoints. Values redacted.' -Recommendation 'This is a capability note, not evidence of credential exfiltration by itself.' -RiskType 'capability' -Confidence 'low'
    }

    if ($isCommandConfig) {
        $envKeyMatches = [regex]::Matches($Text, '(?i)"([A-Za-z_][A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|KEY))"\s*:')
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
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -match '(?is)<!DOCTYPE|<!ENTITY') { return $null }
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
            if ($scriptText -match '(?is)(https?://|curl|wget|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|fetch\s*\()') { $State.hasFetch = $true }
            if ($scriptText -match '(?is)(ProcessBuilder|Runtime\.getRuntime|child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe|/bin/sh)') { $State.hasProcess = $true }
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
    if ($File.Name.ToLowerInvariant() -ne 'package.json' -or $path -notmatch '\\extensions\\') {
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
                        Add-Finding -Severity $ioc.severity -Category $category -Title $title -Path $File.FullName -Evidence ("extension={0}; version={1}; matchType={2}" -f $id, $version, ([string]$ioc.matchType)) -Recommendation 'Verify the registry source, publisher, installed version, and file hashes before continuing IDE use.' -RiskType 'known-ioc' -Confidence $confidence -Check 'IdeExtensions' -DetectionMethod 'metadata'
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
    if ($path -notmatch '\\extensions\\' -and -not $isJetBrains) {
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
    if ($path -notmatch '\\extensions\\') {
        return
    }
    if ($path.EndsWith('.wasm')) {
        Add-ScanStat -Name 'wasmArtifactsFound'
        Add-Finding -Severity 'WARN' -Category 'IDE_EXTENSION_WASM_ARTIFACT' -Title 'IDE extension contains a WebAssembly artifact' -Path $File.FullName -Evidence 'WebAssembly artifact exists. File was not executed; presence alone is not proof of compromise.' -Recommendation 'Verify extension provenance and correlate with exact hash or loader-code findings.' -RiskType 'capability' -Confidence 'low' -Check 'IdeExtensions' -DetectionMethod 'metadata'
    }
    elseif ($path.EndsWith('.node') -or $path.EndsWith('.dll') -or $path.EndsWith('.dylib') -or $path.EndsWith('.so') -or $path.EndsWith('.vsix')) {
        Add-Finding -Severity 'WARN' -Category 'IDE_EXTENSION_NATIVE_ARTIFACT' -Title 'IDE extension contains native or packaged artifact' -Path $File.FullName -Evidence 'Native or VSIX artifact exists. File was not executed.' -Recommendation 'Verify publisher and artifact provenance if extension is unexpected.'
    }
}

function Test-KnownFileIocCheckEnabledForFile {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) { return $false }
    $pathLower = $File.FullName.ToLowerInvariant() -replace '/', '\'
    if (Test-IsJetBrainsPluginPath $File.FullName) { return (Test-CheckEnabled 'IdeExtensions') }
    if ($pathLower -match '\\extensions\\') { return (Test-CheckEnabled 'IdeExtensions') }
    if ($pathLower -match '\\node_modules\\') { return (Test-CheckEnabled 'Packages') }
    if ($pathLower -match '\\\.github\\actions\\') { return (Test-CheckEnabled 'CiCd') }
    return (Test-CheckEnabled 'ScannerSelf')
}

function Scan-WasmLoaderBehavior {
    param([System.IO.FileInfo]$File, [string]$Text)
    if ($null -eq $File -or [string]::IsNullOrEmpty($Text)) { return }
    if ($File.Extension.ToLowerInvariant() -notin @('.js','.mjs','.cjs','.ts','.tsx','.jsx')) { return }
    if ($Text -notmatch '(?is)WebAssembly\.(instantiate|instantiateStreaming|compile|compileStreaming|Module)') { return }
    $checkName = 'LifecycleScripts'
    if ($File.FullName -match '(?i)\\extensions\\' -or (Test-IsJetBrainsPluginPath $File.FullName)) {
        $checkName = 'IdeExtensions'
        if (-not (Test-CheckEnabled 'IdeExtensions')) { return }
    }
    elseif (-not (Test-CheckEnabled 'LifecycleScripts')) {
        return
    }
    $hasRemoteLoad = ($Text -match '(?is)(fetch\s*\(|https?://|axios|request\s*\(|WebClient|HttpClient).{0,700}WebAssembly\.(instantiate|instantiateStreaming|compile|compileStreaming)' -or $Text -match '(?is)WebAssembly\.(instantiate|instantiateStreaming|compile|compileStreaming).{0,700}(fetch\s*\(|https?://|axios|request\s*\()')
    $hasDecodeProcessCompound = ($Text -match '(?is)(Buffer\.from|atob\s*\(|base64|Uint8Array).{0,700}(child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe|\.vscode|\.cursor|\.claude|\.codex|\.windsurf)' -or $Text -match '(?is)(child_process|spawn\s*\(|exec\s*\(|powershell|pwsh|cmd\.exe|\.vscode|\.cursor|\.claude|\.codex|\.windsurf).{0,700}(Buffer\.from|atob\s*\(|base64|Uint8Array)')
    $hasKnownC2 = ($Text -match '(?is)(dodod\.lat|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz)')
    if ((Test-SecretHarvestingExternalSendPattern $Text) -or $hasDecodeProcessCompound -or ($hasKnownC2 -and $hasRemoteLoad)) {
        Add-Finding -Severity 'DANGER' -Category 'WASM_EXECUTION_COMPOUND' -Title 'WebAssembly loader appears with exfiltration, known C2, or decoded process execution' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'WebAssembly\.|dodod\.lat|child_process|Buffer\.from|atob') -Evidence 'WebAssembly execution appears in a strong compound context. Raw code and values are redacted.' -Recommendation 'Preserve evidence and inspect the loader and referenced artifact without executing them.' -RiskType 'fetch-execute' -Confidence 'high' -Check $checkName -DetectionMethod 'static-file'
    }
    elseif ($hasRemoteLoad) {
        Add-Finding -Severity 'WARN' -Category 'WASM_REMOTE_LOAD_CAPABILITY' -Title 'Code can load and execute WebAssembly from a network source' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern 'WebAssembly\.|fetch\s*\(|https?://') -Evidence 'Remote WebAssembly load capability detected without a strong malicious compound.' -Recommendation 'Verify the remote source, expected hash, and caller before execution.' -RiskType 'capability' -Confidence 'medium' -Check $checkName -DetectionMethod 'static-file'
    }
}

function Scan-File {
    param([System.IO.FileInfo]$File)
    if ($null -eq $File) {
        return
    }
    if (Test-IsVerifiedScannerArtifactSamplePath $File.FullName) {
        Add-ScanStat -Name 'filesSkipped'
        return
    }
    if (Test-IsOwnSyntheticSamplePath $File.FullName) {
        Add-ScanStat -Name 'filesSkipped'
        Add-ScanStat -Name 'syntheticSamplesSkipped'
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

    $read = Read-TextFileSafe -File $File
    if (-not $read.ok) {
        return
    }
    Add-ScanStat -Name 'filesScanned'
    $text = [string]$read.text
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
        Invoke-ScannerStep -StepName 'Scan-InvisibleUnicode' -File $File -ScriptBlock { Scan-InvisibleUnicode -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-GlassWormBehavior' -File $File -ScriptBlock { Scan-GlassWormBehavior -File $File -Text $text }
    }
    if ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts')) {
        Invoke-ScannerStep -StepName 'Scan-NpmFiles' -File $File -ScriptBlock { Scan-NpmFiles -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-PythonFiles' -File $File -ScriptBlock { Scan-PythonFiles -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-ComposerFiles' -File $File -ScriptBlock { Scan-ComposerFiles -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-NpmRuntimeCode' -File $File -ScriptBlock { Scan-NpmRuntimeCode -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-NpmIncidentContextMarkers' -File $File -ScriptBlock { Scan-NpmIncidentContextMarkers -File $File -Text $text }
    }
    if (Test-CheckEnabled 'CiCd') {
        Invoke-ScannerStep -StepName 'Scan-GitHubActions' -File $File -ScriptBlock { Scan-GitHubActions -File $File -Text $text }
    }
    if (Test-CheckEnabled 'HooksAndTasks') {
        Invoke-ScannerStep -StepName 'Scan-HooksAndWorkspaceTasks' -File $File -ScriptBlock { Scan-HooksAndWorkspaceTasks -File $File -Text $text }
    }
    if (Test-CheckEnabled 'AiMcp') {
        Invoke-ScannerStep -StepName 'Scan-McpAndAgentConfigs' -File $File -ScriptBlock { Scan-McpAndAgentConfigs -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-ReferenceTextSecuritySamples' -File $File -ScriptBlock { Scan-ReferenceTextSecuritySamples -File $File -Text $text }
    }
    if (Test-CheckEnabled 'IdeExtensions') {
        Invoke-ScannerStep -StepName 'Scan-IdeExtensionPackageJson' -File $File -ScriptBlock { Scan-IdeExtensionPackageJson -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-IdeExtensionExecutableText' -File $File -ScriptBlock { Scan-IdeExtensionExecutableText -File $File -Text $text }
    }
    if ((Test-CheckEnabled 'LifecycleScripts') -or (Test-CheckEnabled 'IdeExtensions')) {
        Invoke-ScannerStep -StepName 'Scan-WasmLoaderBehavior' -File $File -ScriptBlock { Scan-WasmLoaderBehavior -File $File -Text $text }
    }
    if (Test-CheckEnabled 'ScannerSelf') {
        Invoke-ScannerStep -StepName 'Scan-KnownTextIocs' -File $File -ScriptBlock { Scan-KnownTextIocs -File $File -Text $text }
        Invoke-ScannerStep -StepName 'Scan-LocalSuspiciousTextPatterns' -File $File -ScriptBlock { Scan-LocalSuspiciousTextPatterns -File $File -Text $text }
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
    if (Test-IsJetBrainsPluginPath $resolved) { Register-JetBrainsRoot -RootPath (Get-JetBrainsPluginAggregateRoot $resolved) }
    Add-ListItem $script:Context.scanRoots (ConvertTo-RedactedPath $resolved)
    $oldSkipOwnSyntheticSamples = $script:SkipOwnSyntheticSamples
    $oldSkipOwnReportArtifacts = $script:SkipOwnReportArtifacts
    $isExplicitOwnSyntheticSampleRoot = Test-IsExplicitOwnSyntheticSampleRoot $resolved
    $isExplicitOwnReportArtifactRoot = Test-IsExplicitOwnReportArtifactRoot $resolved
    if ($isExplicitOwnSyntheticSampleRoot) {
        $script:Context.syntheticSamplesExplicit = $true
    }
    $script:SkipOwnSyntheticSamples = -not $isExplicitOwnSyntheticSampleRoot
    $script:SkipOwnReportArtifacts = -not $isExplicitOwnReportArtifactRoot

    if (-not $Quiet) { Write-Host '[1/5] Project file enumeration' }
    try {
        if (Test-CheckEnabled 'NodeRuntime') { $script:Context.nodeRuntimeProjectScanPerformed = $true }
        $projectRoots = @()
        if ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts') -or (Test-CheckEnabled 'HooksAndTasks') -or (Test-CheckEnabled 'NodeRuntime')) {
            $projectRoots = @(Get-DiscoveredProjectRoots -RootPath $resolved)
        }
        $nodeRuntimePriority = New-ArrayList
        if (Test-CheckEnabled 'NodeRuntime') {
            foreach ($projectRoot in $projectRoots) {
                foreach ($candidate in @(Get-NodeRuntimeProjectCandidatePaths -ProjectRoot $projectRoot)) {
                    Add-NodeRuntimePriorityCandidate -List $nodeRuntimePriority -FilePath $candidate
                }
            }
        }
        $targeted = New-ArrayList
        if ((Test-CheckEnabled 'Packages') -or (Test-CheckEnabled 'LifecycleScripts') -or (Test-CheckEnabled 'HooksAndTasks')) {
            foreach ($projectRoot in $projectRoots) {
                foreach ($file in @(Get-TargetedFileList -RootPath $projectRoot)) {
                    Add-ListItem $targeted $file
                }
            }
        }
        $files = Get-SafeFileList -RootPath $resolved
        foreach ($file in @($nodeRuntimePriority) + @($targeted) + @($files)) {
            if ($null -eq $file) { continue }
            Scan-File -File $file
        }
    }
    finally {
        $script:SkipOwnSyntheticSamples = $oldSkipOwnSyntheticSamples
        $script:SkipOwnReportArtifacts = $oldSkipOwnReportArtifacts
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
    $value = [Environment]::GetEnvironmentVariable($EnvName, 'Process')
    if ([string]::IsNullOrWhiteSpace($value)) {
        return [ordered]@{
            active = $false
            roots = @()
        }
    }

    $roots = New-ArrayList
    $seen = @{}
    $sampleRoot = Join-Path $script:BaseDir 'tests\samples'
    foreach ($part in ($value -split ';')) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $candidate = $part.Trim()
        if (-not (Test-IsPathUnderRoot -CandidatePath $candidate -RootPath $sampleRoot)) {
            continue
        }
        Add-ExistingDirectoryCandidate -List $roots -Seen $seen -CandidatePath $candidate
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
    foreach ($ioc in @($script:Context.iocs.packages)) {
        if ([string]$ioc.ecosystem -ne 'npm') { continue }
        $name = [string]$ioc.name
        if ([string]::IsNullOrEmpty($name)) { continue }
        if ($Text -notmatch [regex]::Escape($name)) { continue }
        foreach ($badVersion in @($ioc.versions)) {
            if ($badVersion -eq '*') { continue }
            if ($Text -match [regex]::Escape([string]$badVersion)) {
                Add-Finding -Severity 'WARN' -Category 'NPM_CACHE_METADATA_KNOWN_PACKAGE' -Title 'Known npm package IOC appears in npm cache metadata' -Path $FilePath -Evidence ("Package={0}; version={1}; cache metadata only; npm cache ls was not executed." -f $name, $badVersion) -Recommendation 'Cache metadata is not proof of installation or execution. Look for matching project or global package findings.' -RiskType 'posture' -Confidence 'medium' -Check 'NpmCache' -DetectionMethod 'metadata'
                $matched = $true
                break
            }
        }
    }
    foreach ($watchName in @($script:NpmIncidentWatchlistNames)) {
        if ($Text -match [regex]::Escape($watchName)) {
            Add-Finding -Severity 'INFO' -Category 'NPM_CACHE_METADATA_WATCHLIST_PACKAGE' -Title 'Recent incident watchlist package appears in npm cache metadata' -Path $FilePath -Evidence ("Package name={0}; cache metadata only." -f $watchName) -Recommendation 'Treat as context only unless package is installed or behavior findings also appear.' -RiskType 'posture' -Confidence 'low' -Check 'NpmCache' -DetectionMethod 'metadata'
            $matched = $true
            break
        }
    }
    foreach ($prefix in @($script:NpmIncidentWatchlistPrefixes)) {
        if ($Text -match [regex]::Escape($prefix)) {
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
                Add-ScanStat -Name 'filesEnumerated'
                $name = [System.IO.Path]::GetFileName($filePath).ToLowerInvariant()
                $extension = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()
                if ($name -ne 'plugin.xml' -and $extension -notin @('.jar','.zip','.dll','.so','.dylib','.exe','.node','.ps1','.bat','.cmd','.sh','.js','.mjs','.cjs','.py')) { continue }
                if (Test-IsVerifiedScannerArtifactSamplePath $filePath) { Add-ScanStat -Name 'filesSkipped'; continue }
                if (Test-IsOwnSyntheticSamplePath $filePath) { Add-ScanStat -Name 'filesSkipped'; Add-ScanStat -Name 'syntheticSamplesSkipped'; continue }
                if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $filePath)) { Add-ScanStat -Name 'filesSkipped'; Add-ScanStat -Name 'scannerReportArtifactsSkipped'; continue }
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

    Add-ListItem $script:Context.scanRoots '~'
    if (Test-CheckEnabled 'IdeExtensions') {
        foreach ($jetBrainsRoot in @(Get-JetBrainsProfilePluginRoots)) {
            foreach ($file in @(Get-JetBrainsTargetedFileList -RootPath $jetBrainsRoot)) { Scan-File -File $file }
        }
    }

    $extensionRoots = @(
        (Join-Path $env:USERPROFILE '.vscode\extensions'),
        (Join-Path $env:USERPROFILE '.vscode-insiders\extensions'),
        (Join-Path $env:USERPROFILE '.cursor\extensions'),
        (Join-Path $env:USERPROFILE '.windsurf\extensions'),
        (Join-Path $env:USERPROFILE '.vscodium\extensions'),
        (Join-Path $env:USERPROFILE '.positron\extensions')
    )
    foreach ($root in $extensionRoots) {
        if (-not (Test-CheckEnabled 'IdeExtensions')) { break }
        if (Test-Path -LiteralPath $root -PathType Container) {
            $files = Get-SafeFileList -RootPath $root
            foreach ($file in @($files)) {
                Scan-File -File $file
            }
        }
    }

    $configCandidates = New-ArrayList
    if (-not [string]::IsNullOrEmpty($env:APPDATA)) {
        Add-ListItem $configCandidates (Join-Path $env:APPDATA 'Claude\claude_desktop_config.json')
        Add-ListItem $configCandidates (Join-Path $env:APPDATA 'Code\User\settings.json')
        Add-ListItem $configCandidates (Join-Path $env:APPDATA 'Cursor\User\settings.json')
        Add-ListItem $configCandidates (Join-Path $env:APPDATA 'Windsurf\User\settings.json')
    }
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.cursor')
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.claude')
    Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.codex')
    if (-not $MajorOnly) {
        Add-ListItem $configCandidates (Join-Path $env:USERPROFILE '.config')
    }
    foreach ($candidate in $configCandidates) {
        if (Test-Path -LiteralPath $candidate) {
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
        (Join-Path $env:USERPROFILE '.codex\auth.json')
    )
    if (-not [string]::IsNullOrEmpty($env:CODEX_HOME)) {
        $secretCandidates += (Join-Path $env:CODEX_HOME 'auth.json')
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
    Add-ListItem $candidateRoots (Join-Path $env:USERPROFILE 'Documents\GitHub')

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
    if ($overall -eq 'WARN') { return 1 }
    return 0
}

try {
    $script:CurrentPhase = 'Initialize-ScannerContext'
    Initialize-ScannerContext
    $script:CurrentPhase = 'Load-BuiltinIocs'
    $script:Context.iocs = Load-BuiltinIocs
    $script:CurrentPhase = 'Load-LocalIocs'
    Load-LocalIocs
    if (Test-CheckEnabled 'NodeRuntime') {
        $script:CurrentPhase = 'Load-LocalNodeRuntimeIocs'
        Load-LocalNodeRuntimeIocs
        Test-NodeRuntimeDataStaleness
        $script:CurrentPhase = 'Scan-HostNodeRuntimes'
        Scan-HostNodeRuntimes
    }

    if ([string]::IsNullOrEmpty($Path) -and -not $UserProfile -and -not $MajorLocations -and -not $EndpointTelemetry -and (Test-EnabledChecksRequireProjectPath)) {
        $Path = (Get-Location).Path
        $script:Context.mode.path = $true
        Add-Finding -Severity 'INFO' -Category 'DEFAULT_PATH_USED' -Title 'No mode specified; current directory selected' -Path $Path -Evidence 'The scanner defaulted to the current directory.' -Recommendation 'Use -Path, -UserProfile, or -EndpointTelemetry explicitly for repeatable scans.'
    }

    if (-not [string]::IsNullOrEmpty($Path)) {
        $script:CurrentPhase = 'Scan-Project'
        Scan-Project -RootPath $Path
    }
    if ($UserProfile) {
        if (-not $Quiet) { Write-Host '[2/5] User profile scan' }
        $script:CurrentPhase = 'Scan-UserProfileMode'
        Scan-UserProfileMode
    }
    if ($MajorLocations) {
        if (-not $Quiet) { Write-Host '[3/5] Major PC locations scan' }
        $script:CurrentPhase = 'Scan-MajorLocationsMode'
        Scan-MajorLocationsMode
    }
    if ($EndpointTelemetry) {
        if (-not $Quiet) { Write-Host '[4/5] Endpoint telemetry scan' }
        $script:CurrentPhase = 'Scan-EndpointTelemetryMode'
        Scan-EndpointTelemetryMode
    }
    if (Test-CheckEnabled 'NpmGlobal') {
        if (-not $Quiet) { Write-Host '[5/5] Static npm global scan' }
        $script:CurrentPhase = 'Scan-NpmGlobalStatic'
        Scan-NpmGlobalStatic
    }
    if (Test-CheckEnabled 'NpmCache') {
        if (-not $Quiet) { Write-Host '[5/5] Static npm cache scan' }
        $script:CurrentPhase = 'Scan-NpmCacheStatic'
        Scan-NpmCacheStatic
    }

    $script:CurrentPhase = 'Scan-Completed'
    Add-Finding -Severity 'OK' -Category 'SCAN_COMPLETED' -Title 'Scan completed' -Evidence 'Scanner completed without executing target project code or network calls.' -Recommendation 'Review WARN and DANGER findings manually.'
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
