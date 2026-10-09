[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $repoRoot ('reports/ioc-maintenance-regression-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($artifactRoot)
$assertions = 0
$cases = 0
function Assert-Maintenance {
    param([bool]$Condition, [string]$Message)
    $script:assertions++
    if (-not $Condition) { throw $Message }
}
function Write-NewMaintenanceFile {
    param([string]$Path, [string]$Text)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Dispose() }
}

# Only data loaders and their pure helpers are evaluated. No scanner startup or host discovery runs.
$allowlist = @(
    'New-ArrayList','Add-ListItem','Get-PropertyValue','Get-ExtensionIocPlatform',
    'Normalize-Version','ConvertTo-PythonPackageVersion','Test-IsExactPackageVersionText','ConvertTo-NodeRuntimeVersion','Compare-NodeRuntimeVersion','Compare-NodeRuntimePrerelease',
    'Test-ActionAdvisoryData','Test-LocalIocEntry','Load-LocalIocs','Load-KeyvChainDropCampaignIocs','Get-CampaignIocCanonicalHash',
    'Add-BuiltinPackageIoc','Add-BuiltinFileHashIoc','Get-SecurityUpdate20261006Iocs','Load-BuiltinIocs',
    'New-NodeRuntimeRange','New-NodeRuntimeFixedVersion','New-NodeRuntimeAdvisory',
    'Load-BuiltinNodeRuntimeIocs','Normalize-NodeRuntimeAdvisory','Get-NodeRuntimeAdvisoryFingerprint',
    'Load-LocalNodeRuntimeIocs','Test-NodeRuntimeDataStaleness','Set-IocDataSetStatus','Get-IocDataSummary'
)
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'), [ref]$tokens, [ref]$errors)
Assert-Maintenance (@($errors).Count -eq 0) 'Scanner parser validation failed'
$definitions = @($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $allowlist}, $true))
Assert-Maintenance ($definitions.Count -eq $allowlist.Count) 'Loader helper allowlist mismatch'
. ([scriptblock]::Create([string]::Join([Environment]::NewLine, [string[]]@($definitions | ForEach-Object {$_.Extent.Text}))))
# Recording adapters isolate these loader tests from finding presentation and scan-mode discovery.
function ConvertTo-RedactedPath { param([string]$Path) return $Path.Replace($artifactRoot, '<SYNTHETIC>') }
function Add-Finding {
    param($Severity,$Category,$Title,$Path,$Evidence,$Recommendation,$RiskType,$Confidence,$Check,$DetectionMethod)
    [void]$script:Context.findings.Add(@{severity=$Severity;category=$Category;path=$Path})
}
function Add-ScanStat { param([string]$Name,[int]$Amount=1) $script:Context.scanStats[$Name] = [int]$script:Context.scanStats[$Name] + $Amount }
function Test-CheckEnabled { param([string]$Check) return ($Check -eq 'NodeRuntime') }
$script:KeyvChainDropApprovedPackageHash = '7da86fddcb4bc5c4352d3f2120903a07314ae2ce3071d980061862bcbc8aa497'
function Reset-MaintenanceContext {
    param([string]$Base)
    $script:BaseDir = $Base
    $builtin = Load-BuiltinNodeRuntimeIocs
    $script:Context = @{
        iocDataSets=@{}; findings=New-ArrayList; scanStats=@{}; campaignIocData=@{}
        nodeRuntimeDataLastUpdated=$builtin.lastUpdated; nodeRuntimeLocalDataStatus='builtin-only'
        iocs=@{
            packages=New-ArrayList; files=New-ArrayList; extensions=New-ArrayList
            actions=New-ArrayList; actionAdvisories=New-ArrayList; patterns=New-ArrayList
            domains=New-ArrayList; ips=New-ArrayList; nodeRuntimes=$builtin
        }
    }
}
$shipped = @{}
foreach ($name in @('known-packages.json','known-files.json','known-extensions.json','known-actions.json','suspicious-patterns.json','known-node-runtimes.json','campaign-keyv-chaindrop-20260806.json')) {
    $shipped[$name] = [IO.File]::ReadAllText((Join-Path $repoRoot ('iocs/' + $name))) | ConvertFrom-Json
}
function New-MaintenanceCase {
    param([string]$Name, [scriptblock]$Mutation)
    $root = Join-Path $artifactRoot $Name
    $data = @{}
    foreach ($name in $shipped.Keys) {
        $data[$name] = $shipped[$name] | ConvertTo-Json -Depth 15 | ConvertFrom-Json
        if ($name -eq 'campaign-keyv-chaindrop-20260806.json') { $data[$name].lastReviewed = (Get-Date).ToString('yyyy-MM-dd') }
        else { $data[$name].lastUpdated = (Get-Date).ToString('yyyy-MM-dd') }
    }
    & $Mutation $data
    foreach ($name in $data.Keys) {
        if ($data[$name] -is [string]) { $text = $data[$name] }
        else { $text = $data[$name] | ConvertTo-Json -Depth 15 }
        Write-NewMaintenanceFile (Join-Path $root ('iocs/' + $name)) $text
    }
    Reset-MaintenanceContext $root
    Load-LocalIocs
    Load-KeyvChainDropCampaignIocs
    Load-LocalNodeRuntimeIocs
    Test-NodeRuntimeDataStaleness
    $script:cases++
}
function Assert-BlockedDataset {
    param([string]$Name, [string]$Status)
    $summary = Get-IocDataSummary
    Assert-Maintenance (-not $summary.releaseReady) ('Publication gate passed for ' + $Name)
    Assert-Maintenance ($script:Context.iocDataSets[$Name].status -eq $Status) ('Wrong dataset status for ' + $Name)
    Assert-Maintenance (@($summary.datasets).Count -eq 7) 'Incomplete dataset inventory'
}
New-MaintenanceCase fresh { param($data) }
Assert-Maintenance ((Get-IocDataSummary).releaseReady -and (Get-IocDataSummary).currentCount -eq 7) 'Fresh complete synthetic datasets failed publication gate'
Assert-Maintenance ($script:Context.campaignIocData.packageVersionPairCount -eq 2235) 'Complete campaign baseline was not loaded'
$builtinFingerprints = @((Load-BuiltinNodeRuntimeIocs).advisories | ForEach-Object {Get-NodeRuntimeAdvisoryFingerprint (Normalize-NodeRuntimeAdvisory $_)})
$localFingerprints = @($shipped['known-node-runtimes.json'].advisories | ForEach-Object {Get-NodeRuntimeAdvisoryFingerprint (Normalize-NodeRuntimeAdvisory $_)})
Assert-Maintenance (@(Compare-Object $builtinFingerprints $localFingerprints).Count -eq 0) 'Built-in/local Node advisory parity failed'

foreach ($name in @('known-packages.json','known-files.json','known-extensions.json','known-actions.json','suspicious-patterns.json')) {
    $script:datasetUnderTest = $name
    New-MaintenanceCase ('future-' + $name) {param($data) $data[$script:datasetUnderTest].lastUpdated = (Get-Date).AddDays(1).ToString('yyyy-MM-dd')}
    Assert-BlockedDataset $name invalid
    Assert-Maintenance (@($script:Context.findings | Where-Object {$_.category -eq 'IOC_DATA_HEADER_INVALID'}).Count -eq 1) 'Future generic header warning missing'
    New-MaintenanceCase ('stale-' + $name) {param($data) $data[$script:datasetUnderTest].lastUpdated = (Get-Date).AddDays(-31).ToString('yyyy-MM-dd')}
    Assert-BlockedDataset $name stale
    if ($name -eq 'known-packages.json') { Assert-Maintenance ($script:Context.iocs.packages.Count -ge 65) 'Historical package indicators disappeared when stale' }
    New-MaintenanceCase ('empty-' + $name) {
        param($data)
        $section = @{'known-packages.json'='packages';'known-files.json'='files';'known-extensions.json'='extensions';'known-actions.json'='actions';'suspicious-patterns.json'='patterns'}[$script:datasetUnderTest]
        $data[$script:datasetUnderTest].$section = @()
    }
    Assert-BlockedDataset $name invalid
    New-MaintenanceCase ('invalid-entry-' + $name) {
        param($data)
        $section = @{'known-packages.json'='packages';'known-files.json'='files';'known-extensions.json'='extensions';'known-actions.json'='actions';'suspicious-patterns.json'='patterns'}[$script:datasetUnderTest]
        $data[$script:datasetUnderTest].$section = @(@{id='invalid'})
    }
    Assert-BlockedDataset $name invalid
}
New-MaintenanceCase node-future {param($data) $data['known-node-runtimes.json'].lastUpdated = (Get-Date).AddDays(1).ToString('yyyy-MM-dd')}
Assert-BlockedDataset 'known-node-runtimes.json' invalid
New-MaintenanceCase node-stale {param($data) $data['known-node-runtimes.json'].lastUpdated = (Get-Date).AddDays(-31).ToString('yyyy-MM-dd')}
Assert-BlockedDataset 'known-node-runtimes.json' stale
New-MaintenanceCase node-conflict {param($data) $data['known-node-runtimes.json'].advisories[0].upstreamSeverity = 'HIGH'}
Assert-BlockedDataset 'known-node-runtimes.json' invalid
Assert-Maintenance ($script:Context.iocs.nodeRuntimes.advisories[0].upstreamSeverity -eq 'CRITICAL') 'Local conflict overrode built-in severity'
New-MaintenanceCase node-incomplete {param($data) $data['known-node-runtimes.json'].advisories = @($data['known-node-runtimes.json'].advisories | Select-Object -Skip 1)}
Assert-BlockedDataset 'known-node-runtimes.json' invalid
New-MaintenanceCase node-invalid-extra {param($data) $data['known-node-runtimes.json'].advisories += @{id='invalid'}}
Assert-BlockedDataset 'known-node-runtimes.json' invalid
New-MaintenanceCase node-duplicate {param($data) $data['known-node-runtimes.json'].advisories += $data['known-node-runtimes.json'].advisories[0]}
Assert-BlockedDataset 'known-node-runtimes.json' invalid
New-MaintenanceCase node-future-advisory {param($data) $data['known-node-runtimes.json'].advisories[0].published = (Get-Date).AddDays(1).ToString('yyyy-MM-dd')}
Assert-BlockedDataset 'known-node-runtimes.json' invalid
New-MaintenanceCase node-missing {param($data) $data.Remove('known-node-runtimes.json')}
Assert-BlockedDataset 'known-node-runtimes.json' missing
New-MaintenanceCase node-malformed {param($data) $data['known-node-runtimes.json'] = '{'}
Assert-BlockedDataset 'known-node-runtimes.json' invalid
# A stale embedded date must never mask missing/invalid local metadata.
foreach ($name in @('missing','invalid')) {
    Reset-MaintenanceContext $artifactRoot
    Set-IocDataSetStatus -Name 'known-node-runtimes.json' -FilePath 'synthetic' -Status $name
    $script:Context.nodeRuntimeDataLastUpdated = '2020-01-01'
    Test-NodeRuntimeDataStaleness
    Assert-Maintenance ($script:Context.iocDataSets['known-node-runtimes.json'].status -eq $name) 'Built-in staleness masked a missing/invalid local file'
    $cases++
}
New-MaintenanceCase campaign-future {param($data) $data['campaign-keyv-chaindrop-20260806.json'].lastReviewed = (Get-Date).AddDays(1).ToString('yyyy-MM-dd')}
Assert-BlockedDataset 'campaign-keyv-chaindrop-20260806.json' invalid
Assert-Maintenance ($script:Context.campaignIocData.builtinFallbackActive -ne $false -and $script:Context.campaignIocData.packageVersionPairCount -eq 0) 'Invalid future campaign was partially loaded'
New-MaintenanceCase campaign-stale {param($data) $data['campaign-keyv-chaindrop-20260806.json'].lastReviewed = (Get-Date).AddDays(-31).ToString('yyyy-MM-dd')}
Assert-BlockedDataset 'campaign-keyv-chaindrop-20260806.json' stale
Assert-Maintenance ($script:Context.campaignIocData.packageVersionPairCount -eq 2235) 'Stale campaign lost exact historical indicators'
New-MaintenanceCase campaign-tampered {param($data) $data['campaign-keyv-chaindrop-20260806.json'].packages[0].versions[0] = '999.0.0'}
Assert-BlockedDataset 'campaign-keyv-chaindrop-20260806.json' invalid
New-MaintenanceCase action-invalid {param($data) $data['known-actions.json'].advisories = @(@{id='invalid'})}
Assert-BlockedDataset 'known-actions.json' invalid
Reset-MaintenanceContext $artifactRoot
Set-IocDataSetStatus -Name 'synthetic' -FilePath 'synthetic' -Status current -LastUpdated (Get-Date).AddDays(1).ToString('yyyy-MM-dd') -ExpiresAfterDays 30
Assert-Maintenance (-not (Get-IocDataSummary).releaseReady) 'Summary setter accepted a future date'
$cases++

$builtin = Load-BuiltinIocs
foreach ($name in @('jscrambler-webpack-plugin','grunt-jscrambler')) {
    Assert-Maintenance (@($builtin.packages | Where-Object {$_.name -eq $name}).Count -eq 0) 'Excluded Jscrambler wrapper remains in built-in exact IOCs'
    Assert-Maintenance (@($shipped['known-packages.json'].packages | Where-Object {$_.name -eq $name}).Count -eq 0) 'Excluded Jscrambler wrapper remains in local exact IOCs'
}
foreach ($filename in @('intro.js','setup.js')) {
    foreach ($entries in @($builtin.files, $shipped['known-files.json'].files)) {
        $entry = @($entries | Where-Object {$_.notes -match ('Jscrambler malicious ' + [regex]::Escape($filename))})[0]
        Assert-Maintenance ([regex]::IsMatch(('C:\synthetic\node_modules\jscrambler\dist\' + $filename), $entry.pathPattern)) 'Jscrambler dist payload selector missed'
        Assert-Maintenance (-not [regex]::IsMatch(('C:\synthetic\node_modules\other\dist\' + $filename), $entry.pathPattern)) 'Jscrambler selector crossed package identity'
    }
}
$marker = @($shipped['suspicious-patterns.json'].patterns | Where-Object {$_.id -eq 'keyv_chaindrop_nodereal_contract_marker'})[0]
foreach ($contract in @('0xE1f239A659B4512059A66a3616A7d1093F783562','0xE1f2395ee43e45A1556EC6438a88c31B83493103')) {
    Assert-Maintenance ([regex]::IsMatch(('eth-mainnet.nodereal.io ' + $contract), $marker.regex)) 'Approved/public contract marker missed'
    Assert-Maintenance ([regex]::IsMatch(($contract + ' eth-mainnet.nodereal.io'), $marker.regex)) 'Reverse contract/RPC ordering missed'
}
Assert-Maintenance (-not [regex]::IsMatch('eth-mainnet.nodereal.io', $marker.regex)) 'Shared RPC endpoint alone matched a campaign'
$cases++

# Audit every trust-manifest entry. Only hashed or presence-only samples within this root qualify.
$sampleRoot = Join-Path $repoRoot 'tests/samples'
$manifest = [IO.File]::ReadAllText((Join-Path $sampleRoot 'manifest.json')) | ConvertFrom-Json
$seen = @{}
$sha = [Security.Cryptography.SHA256]::Create()
try {
    foreach ($sample in $manifest.samples) {
        $relative = [string]$sample.relativePath
        $path = [IO.Path]::GetFullPath((Join-Path $sampleRoot $relative))
        Assert-Maintenance ($path.StartsWith($sampleRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) 'Manifest path escapes sample root'
        Assert-Maintenance (-not $seen.ContainsKey($relative)) ('Duplicate manifest path: ' + $relative)
        $seen[$relative] = $true
        Assert-Maintenance ([IO.File]::Exists($path)) ('Missing manifest fixture: ' + $relative)
        $mode = [string]$sample.hashMode
        Assert-Maintenance ($mode -in @('text-lf-sha256','bytes-sha256','presence-only')) 'Unsupported fixture hash mode'
        if ($mode -eq 'presence-only') { continue }
        if ($mode -eq 'bytes-sha256') { $bytes = [IO.File]::ReadAllBytes($path) }
        else { $text = [IO.File]::ReadAllText($path).Replace("`r`n","`n").Replace("`r","`n"); $bytes = [Text.Encoding]::UTF8.GetBytes($text) }
        $actual = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
        Assert-Maintenance ($actual -ceq [string]$sample.sha256) ('Fixture hash mismatch: ' + $relative)
    }
}
finally { $sha.Dispose() }
foreach ($file in @(Get-ChildItem -LiteralPath $sampleRoot -File -Recurse -Force)) {
    $relative = $file.FullName.Substring($sampleRoot.Length + 1).Replace('\','/')
    Assert-Maintenance ($relative -eq 'manifest.json' -or $seen.ContainsKey($relative)) ('Unexpected fixture: ' + $relative)
}
Assert-Maintenance ($seen.Count -eq 158) 'Fixture inventory changed without review'
$cases++
Write-NewMaintenanceFile (Join-Path $artifactRoot 'result.json') (@{status='passed';cases=$cases;assertions=$assertions;manifestEntries=$seen.Count} | ConvertTo-Json)
Write-Output ('IOC maintenance regressions passed: {0} cases, {1} assertions, {2} fixtures. Artifacts: {3}' -f $cases,$assertions,$seen.Count,$artifactRoot)
