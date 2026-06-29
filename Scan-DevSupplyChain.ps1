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
$script:ScannerVersion = '0.1.11'
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
            return @('Packages','LifecycleScripts','InvisibleUnicode','CiCd','AiMcp','IdeExtensions','HooksAndTasks','SecretsInventory','ScannerSelf')
        }
        'MajorRecommended' {
            return @('Packages','LifecycleScripts','InvisibleUnicode','CiCd','AiMcp','IdeExtensions','HooksAndTasks','SecretsInventory','NpmGlobal','ScannerSelf')
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
    foreach ($checkName in @('Packages','LifecycleScripts','InvisibleUnicode','CiCd','AiMcp','IdeExtensions','HooksAndTasks','SecretsInventory')) {
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

function Get-SourceContext {
    param([string]$CandidatePath)
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
        'npmCacheAccessDenied'
    )
    if ($allowedStats -notcontains $Name) {
        return
    }
    $script:Context.scanStats[$Name] = [int]$script:Context.scanStats[$Name] + $Amount
}

function Get-DefaultRiskType {
    param([string]$Category, [string]$Severity)
    if ([string]::IsNullOrEmpty($Category)) { return 'posture' }
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
        [string]$DetectionMethod
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
    if ($RiskType -notin @('known-ioc','active-exfil','fetch-execute','capability','posture','limitation','inventory')) {
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
        $DetectionMethod
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
        Add-ListItem $items $finding
    }

    $ordered = @($items) | Sort-Object `
        @{ Expression = {
            $riskType = [string]$_.riskType
            if ($riskType -eq 'known-ioc') { 0 }
            elseif ($riskType -eq 'active-exfil') { 1 }
            elseif ($riskType -eq 'fetch-execute' -and [string]$_.sourceContext -eq 'active-ai-config') { 2 }
            elseif ($_.severity -eq 'DANGER') { 3 }
            else { 4 }
        } }, `
        @{ Expression = { if ($_.severity -eq 'DANGER') { 0 } else { 1 } } }, `
        @{ Expression = { if ([string]$_.confidence -eq 'high') { 0 } elseif ([string]$_.confidence -eq 'medium') { 1 } else { 2 } } }, `
        @{ Expression = { [string]$_.category } }
    return @($ordered | Select-Object -First 10)
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
    return $stats
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
        scanRoots = @($script:Context.scanRoots)
        scanStats = Get-ScanStatsForReport
        checkStats = Get-CheckStats
        overallResult = $overall
        summary = $summary
        summaryBySourceContext = Get-SummaryBySourceContext
        summaryByCheck = Get-SummaryByCheck
        priorityFindings = @($priorityFindings)
        capabilitySummary = @($capabilitySummary)
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

function Load-BuiltinIocs {
    $packages = New-ArrayList
    Add-ListItem $packages ([ordered]@{ ecosystem='npm'; name='axios'; versions=@('1.14.1','0.30.4'); severity='DANGER'; notes='Known compromised package version baseline' })
    Add-ListItem $packages ([ordered]@{ ecosystem='npm'; name='plain-crypto-js'; versions=@('4.2.1'); severity='DANGER'; notes='Known compromised package version baseline' })
    Add-ListItem $packages ([ordered]@{ ecosystem='npm'; name='@aifabrix/miso-client'; versions=@('4.7.2'); severity='DANGER'; notes='Known compromised package version baseline' })
    Add-ListItem $packages ([ordered]@{ ecosystem='npm'; name='@iflow-mcp/watercrawl-watercrawl-mcp'; versions=@('1.3.0','1.3.1','1.3.2','1.3.3','1.3.4'); severity='DANGER'; notes='Known compromised package version baseline' })
    Add-ListItem $packages ([ordered]@{ ecosystem='python'; name='litellm'; versions=@('1.82.7','1.82.8'); severity='DANGER'; notes='Known compromised package version baseline' })

    $extensions = New-ArrayList
    Add-ListItem $extensions ([ordered]@{ id='nrwl.angular-console'; versions=@('18.95.0'); severity='DANGER'; notes='Known compromised Nx Console exposure version' })
    Add-ListItem $extensions ([ordered]@{ id='specstudio.code-wakatime-activity-tracker'; versions=@('*'); severity='DANGER'; notes='Known suspicious extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='floktokbok.autoimport'; versions=@('*'); severity='DANGER'; notes='Known suspicious extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='quartz.quartz-markdown-editor'; versions=@('0.3.0'); severity='DANGER'; notes='Known suspicious extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.ssh-tools'; versions=@('0.5.1'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.i18n-tools-plus'; versions=@('1.6.8'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.mind-map'; versions=@('1.0.61'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })
    Add-ListItem $extensions ([ordered]@{ id='oorzc.scss-to-css-compile'; versions=@('1.3.4'); severity='DANGER'; notes='GlassWorm/OpenVSX compromised extension baseline' })

    $files = New-ArrayList
    Add-ListItem $files ([ordered]@{ path='%PROGRAMDATA%\wt.exe'; pathPattern='\\programdata\\wt\.exe$'; severity='DANGER'; notes='Axios/plain-crypto-js campaign persistence filename baseline' })

    $patterns = New-ArrayList
    $domains = New-ArrayList
    Add-ListItem $domains 'flipboxstudio.info'
    Add-ListItem $domains 'sentry.anyclaw.store'
    Add-ListItem $domains 'sfrclak.com'
    $ips = New-ArrayList
    Add-ListItem $ips '164.92.88.210'

    return [ordered]@{
        packages = $packages
        extensions = $extensions
        files = $files
        patterns = $patterns
        domains = $domains
        ips = $ips
    }
}

function Get-PropertyValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
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
                        notes = [string](Get-PropertyValue $extension 'notes')
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

function Test-IsReparsePoint {
    param($FileSystemInfo)
    if ($null -eq $FileSystemInfo) { return $false }
    return (($FileSystemInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Test-IsDefaultSkipDirectory {
    param([System.IO.DirectoryInfo]$Directory)
    $name = $Directory.Name.ToLowerInvariant()
    $fullName = $Directory.FullName.ToLowerInvariant() -replace '/', '\'
    if (@('.git', '.hg', '.svn') -contains $name) {
        return $true
    }
    if ($Deep) {
        return $false
    }
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

function Add-FileIfExists {
    param($List, [string]$FilePath)
    if ([string]::IsNullOrEmpty($FilePath)) {
        return
    }
    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
        try {
            Add-ScanStat -Name 'filesEnumerated'
            Add-ListItem $List ([System.IO.FileInfo]$FilePath)
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

    if (-not $rootItem.PSIsContainer) {
        if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $rootItem.FullName)) {
            Add-ScanStat -Name 'filesSkipped'
            Add-ScanStat -Name 'scannerReportArtifactsSkipped'
            return $result
        }
        Add-ListItem $result $rootItem
        return $result
    }

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($rootItem.FullName)
    while ($queue.Count -gt 0) {
        $dirPath = [string]$queue.Dequeue()
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

            $files = [System.IO.Directory]::GetFiles($dirPath)
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
                if ($result.Count -ge $MaxFiles) {
                    if (-not $script:WarnedMaxFiles) {
                        Add-Finding -Severity 'WARN' -Category 'MAX_FILES_REACHED' -Title 'Maximum file count reached' -Path $RootPath -Evidence "MaxFiles limit reached: $MaxFiles." -Recommendation 'Increase MaxFiles or narrow the scan path.'
                        $script:WarnedMaxFiles = $true
                    }
                    return $result
                }
                try {
                    Add-ListItem $result (New-Object System.IO.FileInfo($file))
                }
                catch {
                    Add-Finding -Severity 'INFO' -Category 'FILE_INFO_FAILED' -Title 'File metadata could not be read' -Path $file -Evidence 'File metadata access failed.' -Recommendation 'Inspect manually if this path is important.'
                }
            }

            $subdirs = [System.IO.Directory]::GetDirectories($dirPath)
            foreach ($subdir in $subdirs) {
                try {
                    $subInfo = New-Object System.IO.DirectoryInfo($subdir)
                    if (Test-IsReparsePoint $subInfo) {
                        Add-Finding -Severity 'INFO' -Category 'REPARSE_POINT_SKIPPED' -Title 'Reparse point directory skipped' -Path $subdir -Evidence 'Directory has ReparsePoint attribute and was skipped to avoid recursion loops.' -Recommendation 'Inspect manually if this target must be followed.'
                        continue
                    }
                    if (Test-IsDefaultSkipDirectory $subInfo) {
                        continue
                    }
                    if ($script:SkipOwnReportArtifacts -and (Test-IsPathUnderOwnReportArtifacts $subInfo.FullName)) {
                        Add-ScanStat -Name 'scannerReportArtifactsSkipped'
                        continue
                    }
                    $queue.Enqueue($subInfo.FullName)
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

function Add-NodeModulePackageJsonFiles {
    param($List, [string]$RootPath)
    $nodeModules = Join-Path $RootPath 'node_modules'
    if (-not (Test-Path -LiteralPath $nodeModules -PathType Container)) {
        return
    }
    try {
        $packageDirs = [System.IO.Directory]::GetDirectories($nodeModules)
        $seen = 0
        foreach ($packageDir in $packageDirs) {
            if ($seen -gt 2000) { break }
            $dirInfo = New-Object System.IO.DirectoryInfo($packageDir)
            if (Test-IsReparsePoint $dirInfo) { continue }
            if ($dirInfo.Name.StartsWith('@')) {
                $scopedDirs = [System.IO.Directory]::GetDirectories($dirInfo.FullName)
                foreach ($scoped in $scopedDirs) {
                    Add-FileIfExists $List (Join-Path $scoped 'package.json')
                    $seen++
                    if ($seen -gt 2000) { break }
                }
            }
            else {
                Add-FileIfExists $List (Join-Path $dirInfo.FullName 'package.json')
                $seen++
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
                foreach ($file in [System.IO.Directory]::GetFiles($current)) {
                    $leaf = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
                    if ($leaf.EndsWith('.pth') -or $leaf -eq 'sitecustomize.py' -or $leaf -eq 'usercustomize.py' -or $leaf -eq 'direct_url.json' -or $leaf -eq 'record') {
                        Add-FileIfExists $List $file
                    }
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

    Add-NodeModulePackageJsonFiles $result $RootPath
    Add-TargetedPythonFiles $result $RootPath
    Add-FileIfExists $result (Join-Path $RootPath 'vendor\composer\autoload_files.php')
    Add-FileIfExists $result (Join-Path $RootPath 'vendor\composer\installed.json')
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
    return $false
}

function Test-GlassWormExecutionOrExfilCompound {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if (Test-ExternalExecutionPattern $Text) { return $true }
    if (Test-SecretHarvestingExternalSendPattern $Text) { return $true }
    if ($Text -match '(?is)(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|Buffer\.from|atob\s*\(|FromBase64String|decodeURIComponent|String\.fromCharCode).{0,400}(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3)') { return $true }
    if ($Text -match '(?is)(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3).{0,400}(eval\s*\(|Function\s*\(|Invoke-Expression|\biex\b|Buffer\.from|atob\s*\(|FromBase64String|decodeURIComponent|String\.fromCharCode)') { return $true }
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
    Add-Finding -Severity $severity -Category 'KNOWN_SUSPICIOUS_FILE_IOC' -Title 'Known suspicious file IOC detected' -Path $File.FullName -Evidence ("Known file IOC matched. Notes: {0}" -f $notes) -Recommendation 'Preserve evidence and verify endpoint context before deleting or modifying the file.' -RiskType 'known-ioc' -Confidence 'high'
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
        Add-Finding -Severity 'DANGER' -Category 'GLASSWORM_C2_EXECUTION_OR_EXFIL_PATTERN' -Title 'GlassWorm-style C2 marker appears with execution or exfil pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3|sfrclak\.com)') -Evidence ("context={0}; sourceContext={1}; compoundPattern=c2-marker-with-execution-or-exfil" -f $textContext, $sourceContext) -Recommendation 'Preserve evidence and inspect this file from a trusted editor before running related tooling.' -RiskType 'fetch-execute' -Confidence 'high'
        return
    }

    if ($textContext -in @('code','execution-config')) {
        Add-Finding -Severity 'WARN' -Category 'GLASSWORM_C2_MARKER_IN_EXECUTABLE_CONTEXT' -Title 'GlassWorm-style C2 marker appears in executable context' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(@solana/web3\.js|mainnet-beta|bittorrent-dht|googleapis\.com/calendar|calendar/v3)') -Evidence ("context={0}; sourceContext={1}; no nearby execution or exfil pattern found" -f $textContext, $sourceContext) -Recommendation 'Verify whether this C2-like channel usage is expected.' -RiskType 'posture' -Confidence 'medium'
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

function Add-KnownPackageFinding {
    param([string]$Ecosystem, [string]$Name, [string]$Version, [string]$Path, $Line)
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
                Add-Finding -Severity $sev -Category 'KNOWN_COMPROMISED_PACKAGE' -Title 'Known compromised package version detected' -Path $Path -Line $Line -Evidence ("{0} package {1} version {2} matched local IOC baseline." -f $Ecosystem, $Name, $normalizedVersion) -Recommendation 'Treat as high priority triage. Preserve evidence and verify against trusted advisory sources.'
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
    param([System.IO.FileInfo]$File, [string]$Text, [string]$Ecosystem)
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
                Add-KnownPackageFinding -Ecosystem $Ecosystem -Name $ioc.name -Version $badVersion -Path $File.FullName -Line $line
            }
        }
    }
}

function Scan-NpmFiles {
    param([System.IO.FileInfo]$File, [string]$Text)
    $name = $File.Name.ToLowerInvariant()
    if ($name -notin @('package.json','package-lock.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb')) {
        return
    }

    if (Test-CheckEnabled 'Packages') {
        Scan-KnownPackageText -File $File -Text $Text -Ecosystem 'npm'
    }

    if ($name -eq 'package.json') {
        try {
            $json = $Text | ConvertFrom-Json -ErrorAction Stop
            $ownName = [string](Get-PropertyValue $json 'name')
            $ownVersion = [string](Get-PropertyValue $json 'version')
            if ((Test-CheckEnabled 'Packages') -and -not [string]::IsNullOrEmpty($ownName) -and -not [string]::IsNullOrEmpty($ownVersion)) {
                Add-KnownPackageFinding -Ecosystem 'npm' -Name $ownName -Version $ownVersion -Path $File.FullName -Line 1
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
                        Add-KnownPackageFinding -Ecosystem 'npm' -Name $dep.Name -Version ([string]$dep.Value) -Path $File.FullName -Line 1
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
    if ($name -notmatch '^(requirements.*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|setup\.py|setup\.cfg|sitecustomize\.py|usercustomize\.py|direct_url\.json|record)$' -and -not $name.EndsWith('.pth')) {
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

function Scan-GitHubActions {
    param([System.IO.FileInfo]$File, [string]$Text)
    $path = $File.FullName.ToLowerInvariant()
    if ($path -notmatch '\\\.github\\workflows\\.*\.ya?ml$' -and $path -notmatch '\\\.github\\actions\\') {
        return
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
        'uses\s*:\s*[^@\s]+@(main|master)' = 'GITHUB_ACTIONS_UNPINNED_ACTION'
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
            if ($id -eq $ioc.id) {
                foreach ($badVersion in @($ioc.versions)) {
                    if ($badVersion -eq '*' -or (Normalize-Version $badVersion) -eq (Normalize-Version $version)) {
                        Add-Finding -Severity $ioc.severity -Category 'KNOWN_SUSPICIOUS_IDE_EXTENSION' -Title 'Known suspicious IDE extension detected' -Path $File.FullName -Evidence ("Extension {0} version {1} matched local IOC baseline." -f $id, $version) -Recommendation 'Preserve evidence and verify extension provenance before continuing IDE use.'
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
    if ($path -notmatch '\\extensions\\') {
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
        Add-Finding -Severity 'DANGER' -Category 'IDE_EXTENSION_EXTERNAL_EXECUTION_PATTERN' -Title 'IDE extension code contains external execution pattern' -Path $File.FullName -Line (Get-FirstMatchLine -Text $Text -Pattern '(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|https?://)') -Evidence 'Extension code contains external fetch plus execution pattern. Values redacted.' -Recommendation 'Preserve evidence and review extension provenance before continuing IDE use.' -RiskType 'fetch-execute' -Confidence 'high'
    }
}

function Scan-NativeExtensionArtifacts {
    param([System.IO.FileInfo]$File)
    $path = $File.FullName.ToLowerInvariant()
    if ($path -notmatch '\\extensions\\') {
        return
    }
    if ($path.EndsWith('.node') -or $path.EndsWith('.dll') -or $path.EndsWith('.dylib') -or $path.EndsWith('.so') -or $path.EndsWith('.vsix')) {
        Add-Finding -Severity 'WARN' -Category 'IDE_EXTENSION_NATIVE_ARTIFACT' -Title 'IDE extension contains native or packaged artifact' -Path $File.FullName -Evidence 'Native or VSIX artifact exists. File was not executed.' -Recommendation 'Verify publisher and artifact provenance if extension is unexpected.'
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

    if (Test-CheckEnabled 'ScannerSelf') {
        Invoke-ScannerStep -StepName 'Scan-KnownFileIocs' -File $File -ScriptBlock { Scan-KnownFileIocs -File $File }
    }
    if (Test-CheckEnabled 'IdeExtensions') {
        Invoke-ScannerStep -StepName 'Scan-NativeExtensionArtifacts' -File $File -ScriptBlock { Scan-NativeExtensionArtifacts -File $File }
    }

    $read = Read-TextFileSafe -File $File
    if (-not $read.ok) {
        return
    }
    Add-ScanStat -Name 'filesScanned'
    $text = [string]$read.text

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
        $files = Get-SafeFileList -RootPath $RootPath
        $targeted = Get-TargetedFileList -RootPath $RootPath
        $seen = @{}
        foreach ($file in @($files) + @($targeted)) {
            if ($null -eq $file) { continue }
            $key = $file.FullName.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
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

function Scan-UserProfileMode {
    param([switch]$MajorOnly)

    if ([string]::IsNullOrEmpty($env:USERPROFILE)) {
        Add-Finding -Severity 'INFO' -Category 'USERPROFILE_NOT_AVAILABLE' -Title 'USERPROFILE environment variable is not available' -Evidence 'User profile scan could not resolve USERPROFILE.' -Recommendation 'Run with an explicit path if profile data must be inspected.'
        return
    }

    Add-ListItem $script:Context.scanRoots '~'
    $extensionRoots = @(
        (Join-Path $env:USERPROFILE '.vscode\extensions'),
        (Join-Path $env:USERPROFILE '.vscode-insiders\extensions'),
        (Join-Path $env:USERPROFILE '.cursor\extensions'),
        (Join-Path $env:USERPROFILE '.windsurf\extensions'),
        (Join-Path $env:USERPROFILE '.vscodium\extensions'),
        (Join-Path $env:USERPROFILE '.positron\extensions')
    )
    foreach ($root in $extensionRoots) {
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
