[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scannerPath = Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$artifactRoot = Join-Path $repoRoot ('reports/python-metadata-regression-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($artifactRoot)
$assertions = 0
$cases = 0
function Assert-PythonMetadata {
    param([bool]$Condition, [string]$Message)
    $script:assertions++
    if (-not $Condition) { throw $Message }
}
function Write-NewPythonFixture {
    param([string]$Path, [string]$Text, [byte[]]$Bytes)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    if ($null -eq $Bytes) { $Bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text) }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}
function Write-PythonDistribution {
    param([string]$Root, [string]$Directory, [string]$Name, [string]$Version)
    $path = Join-Path $Root ('.venv/Lib/site-packages/' + $Directory + '.dist-info/METADATA')
    Write-NewPythonFixture $path ("Metadata-Version: 2.4`nName: $Name`nVersion: $Version`n`n")
    return $path
}
function Invoke-PythonMetadataScan {
    param([string]$Name, [string]$Root, [string]$Scanner = $scannerPath, [int]$MaxSize = 10)
    $json = Join-Path $artifactRoot ($Name + '.json')
    $txt = Join-Path $artifactRoot ($Name + '.txt')
    & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Scanner -Path $Root -Checks Recommended -MaxFileSizeMB $MaxSize -JsonOut $json -TextOut $txt -Quiet -NoColor | Out-Null
    $scanExit = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    Assert-PythonMetadata ($scanExit -in @(0, 1, 2)) ($Name + ': unexpected scanner exit')
    $report = [IO.File]::ReadAllText($json) | ConvertFrom-Json
    Assert-PythonMetadata (@($report.findings | Where-Object { $_.category -in @('SCANNER_FILE_ERROR', 'SCANNER_ERROR', 'REGEX_SCAN_TIMEOUT', 'REGEX_MATCH_TIMEOUT') }).Count -eq 0) ($Name + ': scanner step error')
    Assert-PythonMetadata ($report.executionSafety.networkAccess -eq 'none' -and $report.executionSafety.externalCommands -eq 'none' -and $report.executionSafety.targetCodeExecution -eq 'none') ($Name + ': safety contract changed')
    Assert-PythonMetadata ($report.mode.path -and -not $report.mode.userProfile -and -not $report.mode.majorLocations -and -not $report.mode.endpointTelemetry -and $report.scanScope.included -contains 'explicit-target-path') ($Name + ': host scope enabled')
    Assert-PythonMetadata ([int]$report.summary.danger + [int]$report.summary.warn + [int]$report.summary.caution + [int]$report.summary.info + [int]$report.summary.ok -eq @($report.findings).Count) ($Name + ': finding counts mismatch')
    $expectedExit = if ($report.overallResult -eq 'DANGER') { 2 } elseif ($report.overallResult -in @('WARN', 'CAUTION')) { 1 } else { 0 }
    Assert-PythonMetadata ($scanExit -eq $expectedExit) ($Name + ': severity/exit mismatch')
    $script:cases++
    return $report
}

# Evaluate only these local definitions. Neither scanner startup nor target Python code is imported.
$allowlist = @(
    'Normalize-Version', 'ConvertTo-PythonPackageVersion', 'ConvertTo-PackageIocVersion', 'Test-IsExactPackageVersionText',
    'Get-PropertyValue', 'ConvertTo-PackageIocName', 'Get-ExactPackageIocMatch', 'Finalize-IocIndexes',
    'Get-IocSeverityRank', 'Read-PythonDistributionHeader', 'Add-ScanStat', 'Test-LocalIocEntry'
)
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scannerPath, [ref]$tokens, [ref]$errors)
Assert-PythonMetadata (@($errors).Count -eq 0) 'Scanner parser error'
$definitions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $allowlist }, $true))
Assert-PythonMetadata ($definitions.Count -eq $allowlist.Count) 'AST helper allowlist mismatch'
. ([scriptblock]::Create([string]::Join([Environment]::NewLine, [string[]]@($definitions | ForEach-Object { $_.Extent.Text }))))
function Test-SecurityCandidateBoundary {
    param([string]$Path)
    return [IO.Path]::GetFullPath($Path).StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}
$script:SeverityRank = @{ DANGER=4; WARN=3; CAUTION=2; INFO=1; OK=0 }
$script:Context = @{ pythonDistributionHeaders=@{}; scanStats=@{}; iocIndexes=@{packages=@{};fileHashes=@{}}; iocs=@{packages=@();files=@()} }

$validVersions = @(
    @('0', '0'), @('3', '3'), @('3.0', '3.0'), @('24.0', '24.0'), @('1.2.3.4', '1.2.3.4'),
    @('v1.0', '1.0'), @('V1.0', '1.0'), @('01.002.0003', '1.2.3'), @('0!1.0', '1.0'), @('01!01.002', '1!1.2'),
    @('1.0a', '1.0a0'), @('1.0alpha01', '1.0a1'), @('1.0-beta_2', '1.0b2'), @('1.0preview', '1.0rc0'),
    @('1.0-pre-2', '1.0rc2'), @('1.0c3', '1.0rc3'), @('1.0RC4', '1.0rc4'), @('1.0-1', '1.0.post1'),
    @('1.0.post', '1.0.post0'), @('1.0rev02', '1.0.post2'), @('1.0-r_3', '1.0.post3'), @('1.0.dev', '1.0.dev0'),
    @('1.0DEV04', '1.0.dev4'), @('1.0rc1.post2.dev3', '1.0rc1.post2.dev3'), @('1.0+ABC_01-2', '1.0+abc.1.2'),
    @('1.0+001abc', '1.0+001abc'), @(' 1.0 ', '1.0'), @('v01!01.002rc01.post02.dev03+ABC-001', '1!1.2rc1.post2.dev3+abc.1')
)
foreach ($row in $validVersions) {
    Assert-PythonMetadata ((ConvertTo-PythonPackageVersion $row[0]) -ceq $row[1]) ('Valid PEP 440 version: ' + $row[0])
    Assert-PythonMetadata (Test-IsExactPackageVersionText -Version $row[0] -Ecosystem python) ('Python exact version rejected: ' + $row[0])
    Assert-PythonMetadata (Test-LocalIocEntry @{ecosystem='python';name='synthetic-package';versions=@($row[0])} packages) ('Python IOC schema rejected: ' + $row[0])
    $script:cases++
}
$invalidVersions = @('', 'latest', '=1.0', '==1.0', '>=1.0', '~=1.0', '^1.0', '1.*', '1..0', '.1', '1.', '1.0foo',
    '1.0+local..x', '1.0+', '1!bad', '1.0.dev1.post1', '1.0rc1rc2', '1.0-abc', '1.0; marker', 'https://example.invalid/1.0',
    "1.0`nName: injected", ('1.' + ('0' * 127)))
foreach ($value in $invalidVersions) {
    Assert-PythonMetadata ([string]::IsNullOrEmpty((ConvertTo-PythonPackageVersion $value))) 'Invalid PEP 440 version accepted'
    Assert-PythonMetadata (-not (Test-IsExactPackageVersionText -Version $value -Ecosystem python)) 'Invalid Python exact version accepted'
    Assert-PythonMetadata (-not (Test-LocalIocEntry @{ecosystem='python';name='synthetic-package';versions=@($value)} packages)) 'Invalid Python IOC version accepted'
    $script:cases++
}
Assert-PythonMetadata (-not (Test-IsExactPackageVersionText '3.0')) 'Python short version changed npm version rules'
Assert-PythonMetadata (Test-IsExactPackageVersionText '3.0.0') 'Existing npm version rule regressed'
foreach ($name in @('@scope/pkg', '-package', 'package-', '.package', 'package.', ('a' * 129))) {
    Assert-PythonMetadata (-not (Test-LocalIocEntry @{ecosystem='python';name=$name;versions=@('1.0')} packages)) 'Invalid Python IOC name accepted'
    $script:cases++
}

$script:Context.iocs.packages = @(
    @{ecosystem='python';name='synthetic-package';versions=@('1.0.0');severity='DANGER'},
    @{ecosystem='python';name='synthetic-package';versions=@('1.0');severity='WARN'},
    @{ecosystem='python';name='synthetic-epoch';versions=@('1!1.0');severity='DANGER'},
    @{ecosystem='python';name='synthetic-local';versions=@('1.0+ABC_01');severity='DANGER'}
)
Finalize-IocIndexes
foreach ($value in @('1', '1.0', '1.0.0.0', 'v01.000', '0!1.0')) {
    Assert-PythonMetadata ((Get-ExactPackageIocMatch python 'SYNTHETIC_package' $value).severity -eq 'DANGER') ('Equivalent identity mismatch: ' + $value)
}
foreach ($value in @('1!1.0', '1.0+vendor', '1.0rc1', '1.0.post1', '1.0.dev1', '11.0', '1.0junk')) {
    Assert-PythonMetadata ($null -eq (Get-ExactPackageIocMatch python synthetic-package $value)) ('Distinct identity collapsed: ' + $value)
}
Assert-PythonMetadata ($null -eq (Get-ExactPackageIocMatch python synthetic-epoch '1.0')) 'Epoch was lost'
Assert-PythonMetadata ($null -ne (Get-ExactPackageIocMatch python synthetic-epoch '01!01.00')) 'Equivalent epoch missed'
Assert-PythonMetadata ($null -ne (Get-ExactPackageIocMatch python synthetic-local '1.0.0+abc-001')) 'Equivalent local identity missed'
Assert-PythonMetadata ($null -eq (Get-ExactPackageIocMatch python synthetic-local '1.0')) 'Local suffix was lost'
Assert-PythonMetadata ($script:Context.scanStats.packageIocIndexEntries -eq 3 -and $script:Context.scanStats.packageIocDuplicatesMerged -eq 1) 'Equivalent IOC deduplication failed'
$script:cases++

$headerCases = @(
    @{id='short-pycparser';text="Name: pycparser`nVersion: 3.0`n`n";failure=''},
    @{id='short-pip';text="Name: pip`r`nVersion: 24.0`r`n`r`n";failure=''},
    @{id='folded-license';text="Name: clean`nVersion: 1.0`nLicense: first`n continued`n`n";failure=''},
    @{id='duplicate-name';text="Name: clean`nVersion: 1.0`nnAmE: other`n`n";failure='metadata-duplicate-name'},
    @{id='duplicate-version';text="Name: clean`nVersion: 1.0`nvErSiOn: 2.0`n`n";failure='metadata-duplicate-version'},
    @{id='folded-name';text="Name: clean`n other`nVersion: 1.0`n`n";failure='metadata-folded-identity'},
    @{id='folded-version';text="Name: clean`nVersion: 1.0`n +vendor`n`n";failure='metadata-folded-identity'},
    @{id='orphan-fold';text=" orphan`nName: clean`nVersion: 1.0`n`n";failure='metadata-malformed-header'},
    @{id='invalid-line';text="not a header`nName: clean`nVersion: 1.0`n`n";failure='metadata-malformed-header'},
    @{id='nul';text=("Name: clean`nVersion: 1.0`nSummary: a" + [char]0 + "b`n`n");failure='metadata-malformed-header'},
    @{id='extra-cr';text="Name: clean`r`r`nVersion: 1.0`n`n";failure='metadata-malformed-header'},
    @{id='bad-name';text="Name: clean-`nVersion: 1.0`n`n";failure='metadata-identity-invalid'},
    @{id='bad-version';text="Name: clean`nVersion: 1.0junk`n`n";failure='metadata-identity-invalid'},
    @{id='unterminated';text="Name: clean`nVersion: 1.0";failure='metadata-unterminated-header'},
    @{id='byte-limit';text=("Name: clean`nVersion: 1.0`nSummary: " + ('x' * 131072) + "`n`n");failure='metadata-header-limit'},
    @{id='line-limit';text=("Name: clean`nVersion: 1.0`n" + ("Classifier: inert`n" * 1022) + "`n");failure='metadata-header-limit'},
    @{id='bom';text=([string][char]0xFEFF + "Name: clean`r`nVersion: v1.0`r`n`r`n");failure=''},
    @{id='description';text=("Name: clean`nVersion: 1.0`n`nName: litellm`nVersion: 1.82.7`n" + ('x' * 1048576));failure=''}
)
foreach ($case in $headerCases) {
    $path = Join-Path $artifactRoot ('headers/' + $case.id + '.dist-info/METADATA')
    Write-NewPythonFixture $path $case.text
    $file = New-Object IO.FileInfo($path)
    $header = Read-PythonDistributionHeader $file
    Assert-PythonMetadata ($header.ok -eq [string]::IsNullOrEmpty($case.failure)) ($case.id + ': header acceptance mismatch')
    Assert-PythonMetadata ($header.failureType -eq $case.failure) ($case.id + ': wrong failure type')
    Assert-PythonMetadata ($header.bytesRead -le 131072) ($case.id + ': header exceeded byte bound')
    $readCount = $script:Context.scanStats.pythonDistributionHeadersRead
    $cached = Read-PythonDistributionHeader $file
    Assert-PythonMetadata ([object]::ReferenceEquals($header, $cached) -and $script:Context.scanStats.pythonDistributionHeadersRead -eq $readCount) ($case.id + ': repeated header read')
    if ($case.id -eq 'description') { Assert-PythonMetadata ($header.bytesRead -lt 64 -and $header.name -eq 'clean') 'Description influenced installed identity' }
    $script:cases++
}
$invalidUtf8 = Join-Path $artifactRoot 'headers/invalid-utf8.dist-info/METADATA'
Write-NewPythonFixture -Path $invalidUtf8 -Bytes ([byte[]](78,97,109,101,58,32,255,10,10))
Assert-PythonMetadata ((Read-PythonDistributionHeader (New-Object IO.FileInfo($invalidUtf8))).failureType -eq 'decode-error') 'Invalid UTF-8 accepted'
$script:cases++

$pcRoot = Join-Path $artifactRoot 'pc-layout'
[void](Write-PythonDistribution $pcRoot 'pycparser-3.0' pycparser '3.0')
Write-NewPythonFixture (Join-Path $pcRoot '.local/python311/tools/Lib/site-packages/pip-24.0.dist-info/METADATA') "Name: pip`nVersion: 24.0`n`n"
Write-NewPythonFixture (Join-Path $pcRoot 'package.json') '{"name":"synthetic-pc-layout","version":"1.0.0"}'
$pc = Invoke-PythonMetadataScan pc-layout $pcRoot
Assert-PythonMetadata ($pc.scanComplete -and $pc.completionStatus -eq 'complete' -and [int]$pc.coverage.summary.criticalFailures -eq 0) 'Reported PC short-version layout still incomplete'
Assert-PythonMetadata ([int]$pc.scanStats.pythonDistributionHeadersRead -eq 2) 'PC metadata headers not both inspected'

$positiveRoot = Join-Path $artifactRoot 'installed-positive'
[void](Write-PythonDistribution $positiveRoot 'litellm' litellm 'v01.082.007.0')
[void](Write-PythonDistribution $positiveRoot 'paysafe' 'PAYSAFE__SDK' '0!1.0')
$positive = Invoke-PythonMetadataScan installed-positive $positiveRoot
Assert-PythonMetadata ($positive.scanComplete -and @($positive.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE' -and $_.severity -eq 'DANGER'}).Count -eq 2) 'Equivalent installed IOC identities missed'
Assert-PythonMetadata (@($positive.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE' -and $_.evidence -match 'version=0!1.0'}).Count -eq 0) 'Display version did not normalize zero epoch'

$negativeRoot = Join-Path $artifactRoot 'installed-negative'
$index = 0
foreach ($version in @('1!1.82.7', '1.82.7+vendor', '1.82.7rc1', '1.82.7.post1', '1.82.7.dev1', '1.82.70')) {
    [void](Write-PythonDistribution $negativeRoot ('variant-' + $index) litellm $version)
    $index++
}
[void](Write-PythonDistribution $negativeRoot 'name-prefix' 'my-litellm-package' '1.82.7')
$negative = Invoke-PythonMetadataScan installed-negative $negativeRoot
Assert-PythonMetadata ($negative.scanComplete -and @($negative.findings | Where-Object {$_.category -like 'KNOWN_COMPROMISED_PACKAGE*'}).Count -eq 0) 'Distinct installed version/name produced IOC match'

$badRoot = Join-Path $artifactRoot 'invalid-metadata'
$badCount = 0
foreach ($case in $headerCases | Where-Object { -not [string]::IsNullOrEmpty($_.failure) }) {
    Write-NewPythonFixture (Join-Path $badRoot ('.venv/Lib/site-packages/' + $case.id + '.dist-info/METADATA')) $case.text
    $badCount++
}
$bad = Invoke-PythonMetadataScan invalid-metadata $badRoot
Assert-PythonMetadata (-not $bad.scanComplete -and $bad.completionStatus -eq 'incomplete-critical' -and [int]$bad.coverage.summary.criticalFailures -eq $badCount) 'Invalid headers lost critical coverage'
Assert-PythonMetadata (@($bad.findings | Where-Object {$_.category -eq 'SCAN_CANDIDATE_COVERAGE_INCOMPLETE'}).Count -eq 1) 'Invalid header coverage warning missing'

$lockRoot = Join-Path $artifactRoot 'lock-positive'
Write-NewPythonFixture (Join-Path $lockRoot 'poetry.lock') "[[package]]`nname = 'litellm'`nversion = '0!1.82.7.0'`n`n[[package]]`nname = 'benign'`nversion = '1.82.7'`n"
Write-NewPythonFixture (Join-Path $lockRoot 'uv.lock') "version = 1`n[[package]]`nname = `"PAYSAFE_SDK`"`nversion = `"1.0`" # canonical alias`n[package.source]`nname = 'litellm'`nversion = '1.82.7'`n"
Write-NewPythonFixture (Join-Path $lockRoot 'Pipfile.lock') '{"default":{"paysafe-api":{"version":"==v1.0"},"litellm":{"version":"==1!1.82.7"}},"develop":{}}'
$lock = Invoke-PythonMetadataScan lock-positive $lockRoot
Assert-PythonMetadata ($lock.scanComplete -and @($lock.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE' -and $_.severity -eq 'DANGER'}).Count -eq 3) 'Literal lock identity matching failed'
Assert-PythonMetadata (@($lock.findings | Where-Object {$_.evidence -match 'package=litellm' -and $_.path -like '*Pipfile.lock'}).Count -eq 0) 'Pipfile epoch was dropped'

$lockNegativeRoot = Join-Path $artifactRoot 'lock-negative'
Write-NewPythonFixture (Join-Path $lockNegativeRoot 'poetry.lock') "[[package]]`nname = 'litellm'`nversion = '1.82.9'`n[[package]]`nname = 'clean'`nversion = '1.82.7'`n[[Package]]`nname = 'litellm'`nversion = '1.82.7'`n"
Write-NewPythonFixture (Join-Path $lockNegativeRoot 'uv.lock') "[[package]]`nname = 'litellm'`nversion = '1.82.7+vendor'`n[[package]]`nname = 'clean'`nversion = '1.82.7'`n"
Write-NewPythonFixture (Join-Path $lockNegativeRoot 'requirements.txt') "my-litellm-package==1.82.7`nlitellm==1.82.70`nlitellm==1!1.82.7`nlitellm==1.82.7+vendor`nlitellm==1.82.7rc1`n"
$lockNegative = Invoke-PythonMetadataScan lock-negative $lockNegativeRoot
Assert-PythonMetadata ($lockNegative.scanComplete -and @($lockNegative.findings | Where-Object {$_.category -like 'KNOWN_COMPROMISED_PACKAGE*'}).Count -eq 0) 'Cross-block or partial Python reference produced an IOC finding'

$quotedLockRoot = Join-Path $artifactRoot 'lock-quoted'
$example = "`n[[package]]`nname = 'litellm'`nversion = '1.82.7'`n"
$doubleTriple = '"""'
$singleTriple = ([string][char]39) * 3
Write-NewPythonFixture (Join-Path $quotedLockRoot 'poetry.lock') ('description = ' + $doubleTriple + $example + $doubleTriple + "`n[[package]]`nname = 'clean'`nversion = '1.0'`n")
Write-NewPythonFixture (Join-Path $quotedLockRoot 'uv.lock') ('description = ' + $singleTriple + $example.Replace("'", '"') + $singleTriple + "`n[[package]]`nname = 'clean'`nversion = '1.0'`n")
$quotedLock = Invoke-PythonMetadataScan lock-quoted $quotedLockRoot
Assert-PythonMetadata ($quotedLock.scanComplete -and @($quotedLock.findings | Where-Object {$_.category -like 'KNOWN_COMPROMISED_PACKAGE*'}).Count -eq 0) 'Multiline lock example was treated as a dependency'

$unclosedLockRoot = Join-Path $artifactRoot 'lock-unclosed'
Write-NewPythonFixture (Join-Path $unclosedLockRoot 'poetry.lock') ('description = ' + $doubleTriple + $example)
Write-NewPythonFixture (Join-Path $unclosedLockRoot 'uv.lock') "description = `"unclosed`n[[package]]`nname = 'litellm'`nversion = '1.82.7'`n"
$unclosedLock = Invoke-PythonMetadataScan lock-unclosed $unclosedLockRoot
Assert-PythonMetadata (-not $unclosedLock.scanComplete -and [int]$unclosedLock.coverage.summary.criticalFailures -eq 2 -and @($unclosedLock.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE'}).Count -eq 0) 'Unclosed lock string produced exact IOC evidence or complete coverage'

$badLockRoot = Join-Path $artifactRoot 'lock-invalid'
Write-NewPythonFixture (Join-Path $badLockRoot 'poetry.lock') "[[package]]`nname = 'litellm'`nversion = '1.82.7'`nversion = '1.82.9'`n"
Write-NewPythonFixture (Join-Path $badLockRoot 'uv.lock') "[[package]]`nname = 'litellm'`nversion = '1.82.7junk'`n"
Write-NewPythonFixture (Join-Path $badLockRoot 'Pipfile.lock') '{"default":{"litellm":{"version":"==1.82.7junk"},"range":{"version":">=1.0"},"number":{"version":3.0},"paysafe-api":{"version":["==1.0.0"]}},"develop":{}}'
$badLock = Invoke-PythonMetadataScan lock-invalid $badLockRoot
Assert-PythonMetadata (-not $badLock.scanComplete -and [int]$badLock.coverage.summary.criticalFailures -eq 3 -and @($badLock.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE'}).Count -eq 0) 'Invalid lock identity reported complete or exact compromise'

$badShapeRoot = Join-Path $artifactRoot 'lock-bad-shape'
Write-NewPythonFixture (Join-Path $badShapeRoot 'Pipfile.lock') '{"default":[],"develop":{}}'
Write-NewPythonFixture (Join-Path $badShapeRoot 'invalid-root/Pipfile.lock') '[{"default":{"litellm":{"version":"==1.82.7"}},"develop":{}}]'
$badShape = Invoke-PythonMetadataScan lock-bad-shape $badShapeRoot
Assert-PythonMetadata (-not $badShape.scanComplete -and [int]$badShape.coverage.summary.criticalFailures -eq 2 -and @($badShape.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE'}).Count -eq 0) 'Malformed Pipfile sections were silently treated as empty or exact evidence'

$binaryRoot = Join-Path $artifactRoot 'binary-negative'
Write-NewPythonFixture (Join-Path $binaryRoot 'osd.traineddata') ('x' * 2097152)
Write-NewPythonFixture -Path (Join-Path $binaryRoot '.signature.p7s') -Bytes ([byte[]](0x30, 0x82, 0xFF, 0x00, 0x42))
$binary = Invoke-PythonMetadataScan binary-negative $binaryRoot -MaxSize 1
Assert-PythonMetadata ($binary.scanComplete -and [int]$binary.scanStats.likelyBinaryFilesSkipped -eq 2) 'OCR/signature binary skip failed'
Assert-PythonMetadata (@($binary.findings | Where-Object {$_.category -in @('FILE_TOO_LARGE_SKIPPED','TEXT_DEFAULT_ENCODING_USED','TEXT_DEFAULT_ENCODING_AGGREGATED')}).Count -eq 0) 'Opaque binary produced text size/encoding warning'

# Create an isolated scanner/data copy, never modify the shipped IOC files or existing artifacts.
$isolatedRoot = Join-Path $artifactRoot 'isolated-checker'
$isolatedScanner = Join-Path $isolatedRoot 'Scan-DevSupplyChain.ps1'
Write-NewPythonFixture $isolatedScanner ([IO.File]::ReadAllText($scannerPath))
$hashRoot = Join-Path $artifactRoot 'binary-hash'
$modelPath = Join-Path $hashRoot 'synthetic-model.traineddata'
Write-NewPythonFixture $modelPath 'inert synthetic binary hash marker'
$modelHash = (Get-FileHash -LiteralPath $modelPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-NewPythonFixture (Join-Path $hashRoot 'oversize-model.traineddata') ('x' * 2097152)
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $repoRoot 'iocs') -Filter '*.json' -File) {
    $data = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
    if ($file.Name -eq 'known-files.json') {
        $data.files = @($data.files) + @(
            @{fileName='synthetic-model.traineddata';sha256=$modelHash;severity='DANGER';ownerCheck='Packages';notes='Synthetic regression only'},
            @{fileName='oversize-model.traineddata';sha256=('0' * 64);severity='DANGER';ownerCheck='Packages';notes='Synthetic size-bound regression only'}
        )
    }
    if ($file.Name -eq 'known-packages.json') {
        $data.packages = @($data.packages) + @(@{ecosystem='python';name='synthetic-short';versions=@('3.0');severity='DANGER'})
    }
    Write-NewPythonFixture (Join-Path $isolatedRoot ('iocs/' + $file.Name)) ($data | ConvertTo-Json -Depth 18)
}
[void](Write-PythonDistribution $hashRoot 'synthetic-short' 'synthetic-short' '3.0.0')
$hashReport = Invoke-PythonMetadataScan binary-hash $hashRoot -Scanner $isolatedScanner -MaxSize 1
Assert-PythonMetadata (@($hashReport.findings | Where-Object {$_.category -eq 'KNOWN_SUSPICIOUS_FILE_IOC' -and $_.path -like '*synthetic-model.traineddata' -and $_.severity -eq 'DANGER'}).Count -eq 1) 'Binary skip bypassed exact hash IOC'
Assert-PythonMetadata (@($hashReport.findings | Where-Object {$_.category -eq 'KNOWN_COMPROMISED_PACKAGE' -and $_.evidence -match 'package=synthetic-short'}).Count -eq 1) 'Short-version local IOC failed end-to-end'
Assert-PythonMetadata (-not $hashReport.scanComplete -and @($hashReport.coverage.candidateFailures | Where-Object {$_.kind -eq 'incident-hash' -and $_.failureType -eq 'too-large' -and $_.critical}).Count -eq 1) 'Oversize binary hash lost critical coverage'
Assert-PythonMetadata (@($hashReport.iocData.datasets | Where-Object {$_.name -in @('known-files.json','known-packages.json') -and $_.status -eq 'invalid'}).Count -eq 0) 'Synthetic IOC entries invalid'

Write-Output ("Python metadata regressions passed: {0} cases, {1} assertions. Artifacts: {2}" -f $cases, $assertions, $artifactRoot)
