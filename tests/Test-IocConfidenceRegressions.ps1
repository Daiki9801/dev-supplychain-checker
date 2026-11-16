[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
$scanner=Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$winPS=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$artifactRoot=Join-Path $repoRoot ('reports/ioc-confidence-regression-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($artifactRoot)
$assertions=0; $cases=0
function Assert-Confidence { param([bool]$Condition,[string]$Message); $script:assertions++; if (-not $Condition) { throw $Message } }
function Write-ConfidenceFixture {
    param([string]$Relative,[string]$Text)
    $path=[IO.Path]::GetFullPath((Join-Path $artifactRoot $Relative))
    if (-not $path.StartsWith($artifactRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture escaped synthetic root' }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
    return $path
}
function Invoke-ConfidenceScan {
    param([string]$Name,[string]$Target,[string]$Checks='Packages',[int]$ExpectedExit=1,[string]$Executable=$scanner,[string[]]$Extra=@())
    $json=Join-Path $artifactRoot ($Name+'.json'); $txt=Join-Path $artifactRoot ($Name+'.txt')
    & $winPS -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Executable -Path $Target -Checks $Checks -JsonOut $json -TextOut $txt -Quiet -NoColor @Extra | Out-Null
    $code=$LASTEXITCODE; $global:LASTEXITCODE=0
    Assert-Confidence ($code -eq $ExpectedExit) ($Name+': unexpected exit '+$code)
    $r=[IO.File]::ReadAllText($json,[Text.Encoding]::UTF8) | ConvertFrom-Json
    Assert-Confidence ($r.scanComplete -and $r.completionStatus -eq 'complete') ($Name+': incomplete scan')
    Assert-Confidence (-not $r.mode.userProfile -and -not $r.mode.majorLocations -and -not $r.mode.endpointTelemetry) ($Name+': host mode escaped')
    Assert-Confidence ($r.executionSafety.networkAccess -eq 'none' -and $r.executionSafety.externalCommands -eq 'none' -and $r.executionSafety.targetCodeExecution -eq 'none') ($Name+': execution safety')
    Assert-Confidence (@($r.findings | Where-Object {$_.category -match 'SCANNER_ERROR|SCANNER_FILE_ERROR|REGEX_SCAN_TIMEOUT'}).Count -eq 0) ($Name+': scanner failure')
    $text=[IO.File]::ReadAllText($txt,[Text.Encoding]::UTF8)
    foreach ($f in @($r.findings | Where-Object {$_.category -match 'INCIDENT_CORRELATION|KNOWN_COMPROMISED_PACKAGE|HISTORICALLY_COMPROMISED_REF|KNOWN_COMPROMISED_COMMIT'})) {
        Assert-Confidence ($text.Contains($f.title) -and $text.Contains($f.evidence)) ($Name+': TXT/JSON disagreement')
    }
    $script:cases++
    return $r
}
function Write-ConfidenceLock {
    param([string]$Relative,[string[]]$Names,[string]$Version)
    $dependencies=[ordered]@{}
    foreach ($name in $Names) {$dependencies[$name]=@{version=$Version}}
    return Write-ConfidenceFixture $Relative (@{name='synthetic-ioc-confidence';lockfileVersion=1;dependencies=$dependencies} | ConvertTo-Json -Depth 8)
}
$pending=@('@injectivelabs/wallet-cosmostation','@injectivelabs/wallet-cosmos-strategy')
$payment=@('paysafe-checkout','paysafe-vault','neteller','skrill-payments','paysafe-js','paysafe-api','paysafe-node','paysafe-cards','paysafe-fraud','paysafe-kyc','skrill','skrill-sdk','paysafe-payments')
[void](Write-ConfidenceLock 'pending/package-lock.json' $pending '1.20.21')
foreach ($name in $pending) {
    [void](Write-ConfidenceFixture ('pending/node_modules/'+$name+'/package.json') (@{name=$name;version='1.20.21'} | ConvertTo-Json))
}
$r=Invoke-ConfidenceScan 'pending-exact' (Join-Path $artifactRoot 'pending')
$matches=@($r.findings | Where-Object category -eq 'PACKAGE_INCIDENT_CORRELATION')
Assert-Confidence ($matches.Count -eq 4) 'Missing installed/lock historical pairs'
foreach ($f in $matches) {
    Assert-Confidence ($f.severity -eq 'WARN' -and $f.confidence -eq 'medium' -and $f.riskType -eq 'posture' -and $f.sourceId -eq 'S13') 'Historical pair was represented as confirmed malware'
    Assert-Confidence ($f.title -match 'unconfirmed' -and $f.evidence -match 'historical-correlation') 'Historical evidence limit missing'
}
Assert-Confidence ($r.findingClassSummary.securityEvidence -eq 0 -and $r.summary.DANGER -eq 0 -and @($r.priorityFindings | Where-Object riskType -eq 'known-ioc').Count -eq 0) 'Historical pair was counted as confirmed security evidence'
$dependencies=@{}; foreach ($name in $pending) {$dependencies[$name]='^1.20.21'}
[void](Write-ConfidenceFixture 'reference/package.json' (@{name='synthetic-reference';dependencies=$dependencies} | ConvertTo-Json))
$r=Invoke-ConfidenceScan 'pending-reference' (Join-Path $artifactRoot 'reference')
$matches=@($r.findings | Where-Object category -eq 'PACKAGE_INCIDENT_CORRELATION_REFERENCE')
Assert-Confidence ($matches.Count -eq 2) 'Missing historical manifest references'
foreach ($f in $matches) {Assert-Confidence ($f.severity -eq 'WARN' -and $f.confidence -eq 'low') 'Reference confidence was promoted'}

foreach ($version in @('1.0.1','1.0.2','1.0.3')) {[void](Write-ConfidenceLock ('payment/'+$version+'/package-lock.json') $payment $version)}
$r=Invoke-ConfidenceScan 'payment-exact' (Join-Path $artifactRoot 'payment') -ExpectedExit 2
$matches=@($r.findings | Where-Object category -eq 'KNOWN_COMPROMISED_PACKAGE')
Assert-Confidence ($matches.Count -eq 39) 'Explicit primary-report version coverage changed'
foreach ($f in $matches) {Assert-Confidence ($f.severity -eq 'DANGER' -and $f.confidence -eq 'high' -and $f.sourceId -eq 'S12' -and $f.evidence -match 'primary-report-exact') 'Confirmed report evidence weakened or provenance lost'}
foreach ($version in @('1.20.20','1.20.22')) {[void](Write-ConfidenceLock ('neighbors/'+$version+'/package-lock.json') $pending $version)}
[void](Write-ConfidenceLock 'neighbors/payment/package-lock.json' $payment '1.0.4')
$r=Invoke-ConfidenceScan 'neighbors' (Join-Path $artifactRoot 'neighbors') -ExpectedExit 0
Assert-Confidence (@($r.findings | Where-Object {$_.category -match 'INCIDENT_CORRELATION|KNOWN_COMPROMISED_PACKAGE'}).Count -eq 0) 'Neighbor version matched an IOC'

$actions=[IO.File]::ReadAllText((Join-Path $repoRoot 'iocs/known-actions.json')) | ConvertFrom-Json
$lines=@('name: Synthetic IOC refs','on: push','jobs:','  test:','    runs-on: windows-latest','    steps:')
foreach ($a in $actions.actions) {foreach ($ref in @($a.compromisedRefs)+@($a.compromisedCommits)) {$lines+='      - uses: '+$a.repository+'@'+$ref}}
[void](Write-ConfidenceFixture 'actions/.github/workflows/test.yml' ([string]::Join([char]10,$lines)))
$r=Invoke-ConfidenceScan 'action-refs' (Join-Path $artifactRoot 'actions') -Checks 'CiCd' -ExpectedExit 2
$refs=@($r.findings | Where-Object category -eq 'GITHUB_ACTIONS_HISTORICALLY_COMPROMISED_REF')
$commits=@($r.findings | Where-Object category -eq 'GITHUB_ACTIONS_KNOWN_COMPROMISED_COMMIT')
Assert-Confidence ($refs.Count -eq 15 -and $commits.Count -eq 3) 'Action IOC count changed'
foreach ($f in $refs) {Assert-Confidence ($f.severity -eq 'WARN' -and $f.evidence -match 'currentTarget=unverified' -and $f.evidence -match 'repositoryAccessAtLastCheck=blocked-tos; repositoryCheckedAt=2026-11-09') 'Historical ref was presented as a verified current target'}
foreach ($f in $commits) {Assert-Confidence ($f.severity -eq 'DANGER' -and $f.confidence -eq 'high') 'Known malicious immutable commit weakened'}

# Each fallback is a new synthetic distribution; source files are never removed.
$source=[IO.File]::ReadAllText($scanner)
foreach ($mode in @('missing','invalid')) {
    $copy=Write-ConfidenceFixture ($mode+'/Scan-DevSupplyChain.ps1') $source
    if ($mode -eq 'invalid') {[void](Write-ConfidenceFixture ($mode+'/iocs/known-packages.json') '{invalid')}
    $r=Invoke-ConfidenceScan ($mode+'-pending') (Join-Path $artifactRoot 'pending') -Executable $copy
    $matches=@($r.findings | Where-Object category -eq 'PACKAGE_INCIDENT_CORRELATION')
    Assert-Confidence ($matches.Count -eq 4 -and @($matches | Where-Object {$_.severity -ne 'WARN' -or $_.confidence -ne 'medium'}).Count -eq 0) ($mode+': fallback restored false certainty')
    Assert-Confidence (@($r.findings | Where-Object severity -eq 'DANGER').Count -eq 0) ($mode+': fallback restored DANGER')
    $r=Invoke-ConfidenceScan ($mode+'-payment') (Join-Path $artifactRoot 'payment') -Executable $copy -ExpectedExit 2
    Assert-Confidence (@($r.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE' -and $_.severity -eq 'DANGER' -and $_.sourceId -eq 'S12'}).Count -eq 39) ($mode+': fallback lost primary-report evidence')
}

# Npm metadata checks receive explicit repository-local roots and cannot fall back to the PC.
foreach ($name in $pending) {[void](Write-ConfidenceFixture ('npm-global/node_modules/'+$name+'/package.json') (@{name=$name;version='1.20.21'} | ConvertTo-Json))}
$cacheText=[string]::Join([char]10,[string[]]@($pending | ForEach-Object {'{"name":"'+$_+'","version":"1.20.21"}'}))
[void](Write-ConfidenceFixture 'npm-cache/_cacache/index-v5/aa/bb/synthetic' $cacheText)
$globalVar='DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_GLOBAL_ROOTS'; $cacheVar='DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_CACHE_ROOTS'
$oldGlobal=[Environment]::GetEnvironmentVariable($globalVar,'Process');$oldCache=[Environment]::GetEnvironmentVariable($cacheVar,'Process')
try {
    [Environment]::SetEnvironmentVariable($globalVar,(Join-Path $artifactRoot 'npm-global/node_modules'),'Process')
    [Environment]::SetEnvironmentVariable($cacheVar,(Join-Path $artifactRoot 'npm-cache'),'Process')
    $r=Invoke-ConfidenceScan 'npm-static' (Join-Path $artifactRoot 'neighbors') -Checks 'Packages,NpmGlobal,NpmCache' -Extra @('-SyntheticValidation')
    $g=@($r.findings | Where-Object category -eq 'NPM_GLOBAL_PACKAGE_INCIDENT_CORRELATION')
    $c=@($r.findings | Where-Object category -eq 'NPM_CACHE_METADATA_INCIDENT_CORRELATION')
    Assert-Confidence ($g.Count -eq 2 -and $c.Count -eq 2) 'Npm global/cache correlation missing'
    foreach ($f in @($g)+@($c)) {Assert-Confidence ($f.severity -eq 'WARN' -and $f.riskType -eq 'posture' -and $f.sourceId -eq 'S13') 'Npm static path promoted uncertain evidence'}
    foreach ($f in $c) {Assert-Confidence ($f.confidence -eq 'low') 'Cache correlation confidence was promoted'}
}
finally {
    [Environment]::SetEnvironmentVariable($globalVar,$oldGlobal,'Process')
    [Environment]::SetEnvironmentVariable($cacheVar,$oldCache,'Process')
}
[void](Write-ConfidenceFixture 'result.json' (@{status='passed';cases=$cases;assertions=$assertions;powerShell=$PSVersionTable.PSVersion.ToString()} | ConvertTo-Json))
Write-Output ('IOC confidence regressions passed: {0} cases, {1} assertions. Artifacts: {2}' -f $cases,$assertions,$artifactRoot)
