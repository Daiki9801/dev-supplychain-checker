# Push前のPCテスト手順

- 対象バージョン: **0.1.27**
- 対象OS: Windows 10 / 11
- 実行環境: Windows PowerShell 5.1
- 手順更新日: 2026-10-19

この手順は、最初にリポジトリ内の合成データだけで安全に検証し、その後、必要な範囲に限って実PCを読み取り専用で確認する構成です。スキャナーはネットワーク接続、対象コード実行、修復、削除、隔離、レジストリ変更を行いません。TXT/JSONレポートだけを作成します。

公開前テストの合格は、このチェッカーが定義した境界内の動作確認です。PCやリポジトリが完全に安全であること、全依存関係・全CVE・全binaryを検査したことは意味しません。`REGEX_SCAN_TIMEOUT` は該当する本文正規表現処理が未完了であるため、合成回帰では許容せず、実PC検査では `coverage.summary` と対象ファイルを確認して、対象を狭めた再検査または手動確認を行います。

## 1. 開始前の確認

Windows PowerShell 5.1を開き、リポジトリへ移動します。

```powershell
Set-Location C:\Path\To\dev-supplychain-checker
$PSVersionTable.PSVersion
git status --short
git rev-parse HEAD

$pcTestReportRoot = Join-Path (Get-Location) 'reports'
if (Test-Path -LiteralPath $pcTestReportRoot) {
  $reportRootItem = Get-Item -LiteralPath $pcTestReportRoot -Force -ErrorAction Stop
  if (-not $reportRootItem.PSIsContainer -or
      ($reportRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'reports must be an ordinary directory inside this repository.'
  }
} else {
  New-Item -ItemType Directory -Path $pcTestReportRoot -ErrorAction Stop | Out-Null
}
```

確認事項:

- `PSVersion` の `Major` が `5` である。
- 意図しない変更や未知の未追跡ファイルがない。
- `.env`、秘密鍵、実レポート、認証ファイルをGitへ追加しない。

以降はこの開始手順で設定した `$pcTestReportRoot` を使い、今回の生成物をすべてGit除外対象の `reports/` 配下へ保存します。各テストの保存先はGUIDで分け、既存の出力を上書きしません。管理者権限は合成テストには不要です。

PowerShell 7を開いている場合も、次のようにWindows PowerShell 5.1を明示して回帰テストを実行できます。`pwsh.exe` のバージョンと、BATが使う `powershell.exe` のバージョンは別です。

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\tests\Test-PythonMetadataRegressions.ps1
```

## 2. 構文・JSON・差分検証

```powershell
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\Scan-DevSupplyChain.ps1),
  [ref]$tokens,
  [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
  $parseErrors | Format-List
  throw 'PowerShell parser validation failed.'
}

$requiredJsonPaths = @(
  '.\iocs\campaign-keyv-chaindrop-20260806.json',
  '.\iocs\known-actions.json',
  '.\iocs\known-extensions.json',
  '.\iocs\known-files.json',
  '.\iocs\known-node-runtimes.json',
  '.\iocs\known-packages.json',
  '.\iocs\suspicious-patterns.json',
  '.\tests\samples\manifest.json',
  '.\docs\ioc-maintenance-20261006-evidence.json'
)
foreach ($relativePath in $requiredJsonPaths) {
  try {
    Get-Content -LiteralPath $relativePath -Raw -Encoding UTF8 -ErrorAction Stop |
      ConvertFrom-Json -ErrorAction Stop | Out-Null
  } catch {
    throw ("Invalid or missing JSON: {0}" -f $relativePath)
  }
}

$winPS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$regressionPaths = @(
  '.\tests\Test-LauncherScopeContracts.ps1',
  '.\tests\Test-SecurityBoundaryRegressions.ps1',
  '.\tests\Test-SecurityUpdate20261006.ps1',
  '.\tests\Test-IocMaintenance.ps1',
  '.\tests\Test-PythonMetadataRegressions.ps1',
  '.\tests\Test-StaticTriageRegressions.ps1',
  '.\tests\Test-ScanExecutionRegressions.ps1',
  '.\tests\Test-ScanTriagePerformanceRegressions.ps1',
  '.\tests\Test-ScanReviewRegressions.ps1'
)
foreach ($regressionPath in $regressionPaths) {
  $regressionArgs = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$regressionPath)
  if ($regressionPath -like '*Test-SecurityBoundaryRegressions.ps1') {
    $regressionArgs += '-KeepArtifacts'
  }
  & $winPS @regressionArgs
  if ($LASTEXITCODE -ne 0) { throw ("Regression failed: {0}" -f $regressionPath) }
}

git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed.' }
```

合格条件:

- parser errorが0件。
- 必須9 JSON（7 IOC、fixture manifest、項目別証拠記録）がUTF-8で例外なく読み込める。欠落・解析エラーを無視せず、ファイル名だけで失敗を報告する。
- launcher scope契約と、実行ファイル探索・scanner-self・環境ルート境界の合成回帰テストが合格する。
- Python短縮バージョン、PEP 440の同一性、METADATAヘッダー境界、ロックファイルの対応関係、OCR/署名バイナリとハッシュ検査の合成回帰が合格する。
- 実行状態の回帰で合格メッセージが出る。`Test-ScanExecutionRegressions.ps1` はリポジトリ内の合成パイプラインだけを停止し、保存レポートの中断状態・未着手npm・圧縮判定と保持ハッシュ・キャッシュ内MCP・タイムアウト情報の秘匿を検証する。npmは明示的な合成ルートへ限定し、実プロファイル・端末ログ・実npm/Node配置は読まない。
- `Test-ScanTriagePerformanceRegressions.ps1` が合格する。通常文字列とPattern表の混在、実行コードの検出維持、大きな引用符付きキー、サブルールのタイムアウト後の検査継続、同時に出る未完了理由、キャッシュ／有効CIの区別、独自npmキャッシュ、計時配列と最大20件の遅い検査記録をリポジトリ内の合成データだけで検証する。
- `git diff --check` にエラーがない。改行コードの変換予告だけなら失敗ではありません。

`Test-ScanReviewRegressions.ps1` は大きなcompiler風テキスト、多数のPowerShell変数、escaped keyを持つJSON、深い／広いJSON、後続ルールの継続、自己参照ハッシュの改変・コピー拒否、件数、時刻と遅い活動の記録を検証します。入力コードは実行せず、生成物はGUID付きの `reports/` 配下へ保持します。`-BenchmarkOnly` は同じ合成入力形状によるヘルパー計時だけを保存します。

`Test-IocMaintenance.ps1` はmanifest内の158 fixtureを検証します。`bytes-sha256` の3ファイルは `.gitattributes` の正確なパスに `-text` を指定し、Windows checkoutの `core.autocrlf=true` でも実バイトを保持します。`Fixture hash mismatch` が出た場合は `git ls-files --eol tests/samples` と `git check-attr text -- <対象パス>` で改行・属性を確認してください。期待ハッシュの変更や検査の省略で解消しないでください。`text-lf-sha256` は従来どおりLF正規化後に検証します。

ローカル合格はGitHubの必須チェック合格を代替しません。現行workflowはPR更新とmainへのpushで起動するため、Actions追加実行が未承認の場合はpush・mergeの前に承認を得てください。既存ログの読み取りだけではActionsは起動しません。

計時はJSONの `performance.activities` を確認します。`partition=true` の活動だけを合計し、`Reading`、`PowerShellContextProof`、`McpCommandExtraction`、`steps` は再加算しません。`otherElapsedMs` は未計測の実行時間で、レポート整形・書き込み時間は含みません。`slowSteps` と `slowActivities` はそれぞれ2秒以上の処理の上位最大20件です。開始・終了時刻と経過時間は同じ単調時計の起点を使います。速度比較は同じ合成入力・検査項目・PowerShellで行い、検出結果と完了状態も確認します。合成入力での短縮率を実PCの所要時間へそのまま適用しません。

重大度別件数は `$r.summary`、分類別は `$r.findingClassSummary` を確認します。ファイル件数は各カウンター内の重複を除いたパス数で、再訪は `fileEnumerationEvents` / `fileSkipEvents` です。キュー投入前の除外もあるため、queued/scanned/skippedを単純加算しません。自己テストの4つのINFO参照は、正確なパスとソースハッシュ・ルールの一致時だけ許容します。

## 3. 全合成回帰テスト

この検査は `tests/samples` の手書き合成データだけを読みます。実ユーザープロファイル、npm global/cache、レジストリ、イベントログは読みません。

```powershell
$syntheticReportDir = Join-Path $pcTestReportRoot ('pc-test-synthetic-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $syntheticReportDir) { throw 'Synthetic test directory already exists.' }
New-Item -ItemType Directory -Path $syntheticReportDir | Out-Null

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path .\tests\samples `
  -Checks Recommended `
  -ReportDir $syntheticReportDir `
  -Quiet -NoColor
$syntheticExit = $LASTEXITCODE

if ($syntheticExit -notin @(0, 1, 2)) {
  throw "Unexpected scanner exit code: $syntheticExit"
}

$syntheticJson = Get-ChildItem -LiteralPath $syntheticReportDir -Filter *.json -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
$syntheticReport = Get-Content -LiteralPath $syntheticJson.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

if (-not [bool]$syntheticReport.scanComplete) { throw 'Synthetic scan was incomplete.' }
if ($null -eq $syntheticReport.coverage.summary -or [string]::IsNullOrWhiteSpace([string]$syntheticReport.coverage.summary.nextAction)) { throw 'Coverage summary contract failed.' }
if ($syntheticReport.completionStatus -ne 'complete' -or $syntheticReport.coverage.summary.completionLabel -ne 'COMPLETE') { throw 'Completion status contract failed.' }
if ($syntheticReport.executionSafety.networkAccess -ne 'none') { throw 'Network safety contract failed.' }
if ($syntheticReport.executionSafety.externalCommands -ne 'none') { throw 'External-command safety contract failed.' }
if ($syntheticReport.executionSafety.targetCodeExecution -ne 'none') { throw 'Target-code safety contract failed.' }

$requiredCategories = @(
  'GLASSWORM_VARIATION_SELECTOR_DECODER_COMPOUND',
  'GLASSWORM_C2_EXECUTION_OR_EXFIL_PATTERN',
  'INVISIBLE_UNICODE_EXECUTION_COMPOUND',
  'KNOWN_COMPROMISED_PACKAGE',
  'NPM_CHAINDROP_PROPAGATION_CHAIN'
)
foreach ($category in $requiredCategories) {
  if (@($syntheticReport.findings | Where-Object { $_.category -eq $category -and $_.severity -eq 'DANGER' }).Count -lt 1) {
    throw "Required synthetic DANGER category was not detected: $category"
  }
}

$manifest = Get-Content -LiteralPath .\tests\samples\manifest.json -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path .\tests `
  -Checks Recommended `
  -ReportDir $syntheticReportDir `
  -JsonOut (Join-Path $syntheticReportDir 'manifest-parent.json') `
  -TextOut (Join-Path $syntheticReportDir 'manifest-parent.txt') `
  -Quiet -NoColor
if ($LASTEXITCODE -notin @(0, 1, 2)) { throw 'Manifest parent scan failed.' }
$manifestParent = Get-Content -LiteralPath (Join-Path $syntheticReportDir 'manifest-parent.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if (-not [bool]$manifestParent.scanComplete -or $manifestParent.completionStatus -ne 'complete') { throw 'Manifest parent scan was incomplete.' }
if ([int]$manifestParent.scanStats.regexMatchTimeouts -ne 0 -or [int]$manifestParent.scanStats.scannerFileErrors -ne 0) { throw 'Manifest parent scan had analysis failures.' }
if ([int]$manifestParent.scanStats.syntheticSampleUnexpectedFiles -ne 0) { throw 'Unexpected synthetic fixture file found.' }
if ([int]$manifestParent.scanStats.syntheticSampleHashMismatches -ne 0) { throw 'Synthetic fixture hash mismatch found.' }
$parentKnownSkipped = [int]$manifestParent.scanStats.syntheticSampleKnownSkipped
if ($parentKnownSkipped -le 0 -or $parentKnownSkipped -gt (@($manifest.samples).Count + 1)) { throw 'Fixture skip count is outside manifest bounds.' }

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path .\tests\samples\node-runtime-safe `
  -Checks NodeRuntime `
  -JsonOut (Join-Path $syntheticReportDir 'node-runtime-safe.json') `
  -TextOut (Join-Path $syntheticReportDir 'node-runtime-safe.txt') `
  -Quiet -NoColor
if ($LASTEXITCODE -notin @(0, 1, 2)) { throw 'Safe Node.js report test failed.' }
$safeNodeReport = Get-Content -LiteralPath (Join-Path $syntheticReportDir 'node-runtime-safe.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ([int]$safeNodeReport.nodeRuntimeAssessment.installedBinaries.vulnerable -ne 0) { throw 'Project-only scan reported a vulnerable installed Node.js binary.' }
if ([int]$safeNodeReport.nodeRuntimeAssessment.projectReferences.notAffected -lt 1) { throw 'Safe project Node.js reference was not reported.' }
if (@($safeNodeReport.nodeRuntimeAssessment.inventory.entries | Where-Object { $_.sourceType -eq 'project-reference' -and $_.advisoryStatus -eq 'not-affected-in-offline-baseline' }).Count -lt 1) { throw 'Safe Node.js inventory contract failed.' }

[pscustomobject]@{
  ExitCode = $syntheticExit
  ScanComplete = $syntheticReport.scanComplete
  CompletionStatus = $syntheticReport.completionStatus
  Danger = $syntheticReport.summary.danger
  Warn = $syntheticReport.summary.warn
  Caution = $syntheticReport.summary.caution
  Info = $syntheticReport.summary.info
  ManifestEntries = @($manifest.samples).Count
  ManifestHashMismatches = $manifestParent.scanStats.syntheticSampleHashMismatches
  ManifestUnexpectedFiles = $manifestParent.scanStats.syntheticSampleUnexpectedFiles
  Report = $syntheticJson.FullName
}
```

全158 fixtureのハッシュ／存在確認は前節の `Test-IocMaintenance.ps1` が担当します。親フォルダー走査の `syntheticSampleKnownSkipped` は実際に列挙して検証・除外した固有パス数で、対象外の依存ディレクトリやキャッシュblob配下を含むmanifest総数とは一致しません。上限の `+ 1` はmanifest自身です。通常走査で全fixtureを数えるためにDeepを有効化したり、分類プローブをskip件数へ加算したりしないでください。

合成サンプルには意図的なDANGERが含まれるため、終了コード `2` は正常です。件数は検出追加により変わり得るので、固定件数ではなく完了性・安全契約・必須カテゴリを確認します。

全7 IOC データセットは2026-10-06に出典台帳と照合済みです。[レビュー記録](ioc-maintenance-20261006-ja.md)と[項目別の確認根拠](ioc-maintenance-20261006-evidence.json)には、直接再確認できた値と保持した歴史的出典の制限を記録しています。いずれも有効期間は30日のままで、期限内かつ欠落・不正がなければ `iocData.releaseReady` は `true` になります。これは限定的な curated baseline 全体のレビュー・整合性判定で、全公開IOCの網羅性や各歴史的 artifact の独立再検証を保証しません。未来の日付、空 section、不正 entry、Node.js の競合・重複は公開判定を止めます。警告を消す目的だけで日付や期限を変更しないでください。

```powershell
if ($null -eq $syntheticReport.iocData) { throw 'iocData summary is missing.' }
if (-not [bool]$syntheticReport.iocData.releaseReady) {
  $blocked = @($syntheticReport.iocData.datasets | Where-Object { $_.status -ne 'current' } | ForEach-Object { "{0}:{1}" -f $_.name,$_.status })
  throw ("IOC publication freshness gate failed: {0}" -f ($blocked -join ', '))
}
```

## 4. レポート非上書きとBAT特殊文字テスト

以下は `reports/pc-test-safety-*` 内の今回作成した合成ファイルだけを使います。

```powershell
$safetyRoot = Join-Path $pcTestReportRoot ('pc-test-safety-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $safetyRoot) { throw 'Safety test directory already exists.' }
New-Item -ItemType Directory -Path $safetyRoot | Out-Null

$protectedPath = Join-Path $safetyRoot 'protected.txt'
$unusedJsonPath = Join-Path $safetyRoot 'must-not-exist.json'
[System.IO.File]::WriteAllText($protectedPath, 'ORIGINAL')

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path .\tests\samples\clean-js `
  -Checks Recommended `
  -ReportDir $safetyRoot `
  -TextOut $protectedPath `
  -JsonOut $unusedJsonPath `
  -Quiet -NoColor

if ($LASTEXITCODE -ne 4) { throw 'Existing output path was not rejected.' }
if ([System.IO.File]::ReadAllText($protectedPath) -ne 'ORIGINAL') { throw 'Existing file was modified.' }
if (Test-Path -LiteralPath $unusedJsonPath) { throw 'Companion report was unexpectedly created.' }

$samePath = Join-Path $safetyRoot 'same-output.txt'
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path .\tests\samples\clean-js `
  -Checks Recommended `
  -ReportDir $safetyRoot `
  -TextOut $samePath `
  -JsonOut $samePath `
  -Quiet -NoColor
if ($LASTEXITCODE -ne 4) { throw 'Identical TXT/JSON path was not rejected.' }
if (Test-Path -LiteralPath $samePath) { throw 'Rejected identical output path was created.' }

$defaultRoot = Join-Path $safetyRoot 'default-reports'
New-Item -ItemType Directory -Path $defaultRoot | Out-Null
foreach ($attempt in 1..2) {
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
    -File .\Scan-DevSupplyChain.ps1 `
    -Path .\tests\samples\clean-js `
    -Checks Recommended `
    -ReportDir $defaultRoot `
    -Quiet -NoColor
  if ($LASTEXITCODE -notin @(0, 1, 2)) { throw 'Default report generation failed.' }
}
if (@(Get-ChildItem -LiteralPath $defaultRoot -Filter *.txt -File).Count -ne 2) { throw 'Two TXT reports were not preserved.' }
if (@(Get-ChildItem -LiteralPath $defaultRoot -Filter *.json -File).Count -ne 2) { throw 'Two JSON reports were not preserved.' }

$specialTarget = Join-Path $safetyRoot 'clean & echo BATCH_INJECTION_PROBE & rem'
New-Item -ItemType Directory -Path $specialTarget -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $specialTarget 'sample.js'), 'console.log("synthetic clean sample");')
$launcherOutput = @(& .\run-checker.bat path $specialTarget --no-pause 2>&1)
if ($LASTEXITCODE -notin @(0, 1, 2)) { throw 'BAT launcher special-character path test failed.' }
if (@($launcherOutput | Where-Object { [string]$_ -match '^BATCH_INJECTION_PROBE\s*$' }).Count -gt 0) {
  throw 'BAT launcher interpreted an ampersand as CMD syntax.'
}

$modeProbeOutput = @(& .\run-checker.bat 'invalid & echo MODE_INJECTION_PROBE & rem' --no-pause 2>&1)
$modeProbeExit = $LASTEXITCODE
if ($modeProbeExit -ne 4) { throw 'Unsupported launcher mode was not rejected.' }
if (@($modeProbeOutput | Where-Object { [string]$_ -match '^MODE_INJECTION_PROBE\s*$' }).Count -gt 0) {
  throw 'BAT launcher interpreted an unsupported mode as CMD syntax.'
}

$extraArgumentOutput = @(& .\run-checker.bat path $specialTarget --no-pause unexpected 2>&1)
if ($LASTEXITCODE -ne 4) { throw 'Extra fourth argument was not rejected.' }

$emptyCustomOutput = @(@('8', '') | & .\run-checker.bat 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Empty custom-check input did not cancel.' }
if (@($emptyCustomOutput | Where-Object { [string]$_ -match 'Cancelled\.' }).Count -lt 1) {
  throw 'Empty custom-check input was not reported as cancelled.'
}
```

合格条件:

- 既存出力を指定した実行は終了コード `4` となり、既存ファイルが `ORIGINAL` のまま残る。
- companion JSONが作られない。
- TXT/JSONに同じパスを指定した実行は終了コード `4` となり、ファイルが作られない。
- 同じ秒に既定名で2回実行しても、2組のTXT/JSONが残る。
- `&` を含む有効なパスをBATで検査でき、独立した `BATCH_INJECTION_PROBE` 行が出ない。
- `&` を含む未対応モードは終了コード `4` で拒否され、独立した `MODE_INJECTION_PROBE` 行が出ない。
- 余分な第4引数は終了コード `4` で拒否され、カスタム検査でEnterだけを押すと実行せずキャンセルされる。

### 4.1 リポジトリ自己検査

公開候補リポジトリ自体を通常検査し、テストコードや文書の自己参照がDANGERにならないことを確認します。

```powershell
$repositoryReportDir = Join-Path $pcTestReportRoot ('pc-test-repository-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $repositoryReportDir) { throw 'Repository test directory already exists.' }
New-Item -ItemType Directory -Path $repositoryReportDir | Out-Null
$repositoryJsonPath = Join-Path $repositoryReportDir 'repository.json'

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path . `
  -Checks Recommended `
  -ReportDir $pcTestReportRoot `
  -JsonOut $repositoryJsonPath `
  -TextOut (Join-Path $repositoryReportDir 'repository.txt') `
  -Quiet -NoColor
$repositoryExit = $LASTEXITCODE
if ($repositoryExit -notin @(0, 1, 2)) { throw 'Repository self-scan failed.' }

$repositoryReport = Get-Content -LiteralPath $repositoryJsonPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if (-not [bool]$repositoryReport.scanComplete) { throw 'Repository self-scan was incomplete.' }
if ($null -eq $repositoryReport.coverage.summary) { throw 'Repository coverage summary is missing.' }
if ($repositoryReport.completionStatus -ne 'complete') { throw 'Repository completion status is not complete.' }
if (@($repositoryReport.findings | Where-Object severity -eq 'DANGER').Count -ne 0) { throw 'Repository self-scan produced DANGER.' }
```

自己検査では `-ReportDir` に `reports/` 全体を指定し、出力ファイル名だけを今回の専用サブフォルダへ向けます。これにより、別の検証で保管したfixtureや過去レポートも通常の自己検査へ混入しません。`reports-service` などの一般ソースは除外しません。

## 5. 任意の開発フォルダを検査

次は、実在する1つの開発フォルダだけを読みます。コマンド中のパスを、自分が検査を許可する正確なフォルダへ置き換えてください。

```powershell
.\run-checker.bat path "C:\Path\To\TrustedProject" --no-pause
```

読み取り範囲:

- 指定フォルダ内の通常ソース、package metadata、CI/CD、hook、AI/MCP、IDE設定。
- 通常モードでは `.git`、junction/reparse point、一般的なdependency/build/cacheディレクトリを再帰走査しません。
- npm global/cache、ユーザープロファイル全体、レジストリ、イベントログは読みません。

確認事項:

- `scanComplete` が `true` で、`completionStatus` が `complete`。
- 終了コードは `0`、`1`、`2` のいずれか。
- DANGER/WARN/CAUTIONは感染確定ではなく、`Path`、`Category`、`Evidence`、`Confidence` を手動確認する。

## 6. 実PCの広い範囲を確認する場合

この章は実ホスト読み取りです。実行するコマンドと範囲を確認し、必要なものだけを1つずつ実行してください。いずれも読み取り専用で、実行前にBATが `YES` を要求します。

### 6.1 Major PC locations

```powershell
.\run-checker.bat major
```

読み取り範囲: ユーザープロファイル配下の一般的な開発フォルダ、VS Code互換拡張、JetBrains plugin metadata、AI-agent設定、認証ファイルの存在情報、既知のnpm global package metadata、既知パスのNode.js metadata。EndpointTelemetryは読みません。

### 6.2 npm global/cache metadata

```powershell
.\run-checker.bat npmstatic
```

読み取り範囲: 環境変数と既知パスから解決したnpm global package metadataおよびnpm cache metadata。`npm` コマンドは実行せず、cache blob本文は原則読みません。

### 6.3 User profile metadata

```powershell
.\run-checker.bat userprofile
```

読み取り範囲: 実ユーザープロファイルのIDE拡張、AI-agent設定、`.config`、認証ファイルの存在情報。既知の認証ファイル本文は読みません。

### 6.4 EndpointTelemetryを含むfull scan

```powershell
.\run-checker.bat full "C:\Path\To\TrustedProject"
```

読み取り範囲: 指定フォルダ、実ユーザープロファイル、npm global/cache metadata、DNS cache、PowerShell historyの危険パターン有無、Startup metadata、Run key、scheduled task名、直近30日の対象event log。履歴・registry値・event messageの生データはレポートへ出しません。

期待される影響: ローカルの読み取りと `reports` へのTXT/JSON作成のみ。ネットワーク接続、プロセス起動による対象コード実行、権限昇格、設定変更、削除、修復はありません。

## 7. レポートの秘密情報検査

実レポートを共有・commit・pushしないでください。念のため、作成したテストレポートに代表的な秘密形式が残っていないか、値を表示せずファイル名だけで確認します。

```powershell
$reportFiles = @(
  $syntheticJson.FullName,
  [IO.Path]::ChangeExtension($syntheticJson.FullName, '.txt'),
  (Join-Path $syntheticReportDir 'manifest-parent.json'),
  (Join-Path $syntheticReportDir 'manifest-parent.txt'),
  (Join-Path $syntheticReportDir 'node-runtime-safe.json'),
  (Join-Path $syntheticReportDir 'node-runtime-safe.txt'),
  $repositoryJsonPath,
  (Join-Path $repositoryReportDir 'repository.txt')
)
$reportFiles += @(Get-ChildItem -LiteralPath $defaultRoot -File |
  Where-Object { $_.Extension -in @('.json', '.txt') } |
  ForEach-Object FullName)
$secretPattern = '(?i)-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9_]{30,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|npm_[A-Za-z0-9]{30,}'
$reportCandidates = New-Object System.Collections.Generic.List[string]
foreach ($reportPath in $reportFiles) {
  $file = Get-Item -LiteralPath $reportPath -Force -ErrorAction Stop
  $ancestor = $file
  while ($null -ne $ancestor) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw 'A report path crosses a reparse point; do not read its contents.'
    }
    if ($ancestor.FullName -eq $pcTestReportRoot) { break }
    $ancestor = if ($ancestor -is [IO.DirectoryInfo]) { $ancestor.Parent } else { $ancestor.Directory }
  }
  if ($null -eq $ancestor) { throw 'A report path is outside reports/.' }
  $text = [System.IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
  if ([regex]::IsMatch($text, $secretPattern)) { $reportCandidates.Add($file.FullName) }
}
$reportCandidates
```

合格条件: 出力0件。ここではセクション3・4・4.1で今回作成したレポートだけを読みます。`reports/` 全体を再帰走査せず、過去の保管物、認証用fixture、実PCレポートは読みません。BATが作成した別のレポートを調べる場合も、確認した正確なTXT/JSONパスだけを追加してください。候補が出た場合は内容を公開せず、redaction不備として合成値で再現してください。

## 8. Push直前のGit検査

以下はGitのローカル読み取りだけを行います。

```powershell
git status --short
git diff --check
git diff --cached --name-only
git log --oneline origin/main..HEAD
git remote get-url origin
```

確認事項:

- stage対象が意図したソース、fixture、manifest、文書だけである。
- 既定の `reports/` に加え、独自名・過去のレポートフォルダ、`other/`、`.env*`、鍵、token、auth fileが含まれない。
- 実PCのレポートや個人パスを含む文書をstageしない。
- push前に予定コミットを `git show --stat --oneline` と `git show --format=fuller --name-only` で確認する。
- `origin` が `https://github.com/Daiki9801/dev-supplychain-checker` または意図したSSH等価URLを指している。

秘密・個人パス候補を値を表示せずファイル名だけで検査する例:

```powershell
$candidatePaths = @(git ls-files -co --exclude-standard)
$patterns = @(
  '(?i)[A-Z]:[\\/]+Users[\\/]+(?!(?:<)?(?:your[-_]?(?:name|user(?:name)?)|user(?:name)?|example|sample|name|you)(?:>)?(?:[\\/\s]|$))[^\\/\s]+',
  '(?i)/(?:Users|home)/(?!(?:<)?(?:your[-_]?(?:name|user(?:name)?)|user(?:name)?|example|sample|name|you)(?:>)?(?:[/\s]|$))[^/\s]+',
  '-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----',
  '(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9_]{30,}',
  'github_pat_[A-Za-z0-9_]{30,}',
  '(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}',
  '(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
  '(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}'
)
$publishCandidates = New-Object System.Collections.Generic.List[string]
$bodySkippedPaths = New-Object System.Collections.Generic.List[string]
$bodySkipPattern = '(?i)^(?:reports(?:[-_][^/]*)?|other|\.codex|\.aws|\.ssh|\.kube|tests/samples)/|(?:^|/)(?:\.aws|\.ssh|\.kube)/|(?:^|/)(?:\.env[^/]*|\.npmrc|\.pypirc|\.netrc|\.git-credentials|auth\.json|oauth_creds\.json|credentials[^/]*|secrets?[^/]*|tokens?[^/]*|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|[^/]*\.(?:pem|key|pfx|p12))$'
$textExtensions = @('.md','.txt','.ps1','.bat','.yml','.yaml','.json','.toml','.ini','.cfg','.js','.ts','.py','.html','.css','.lock')
foreach ($relativePath in $candidatePaths) {
  $normalizedPath = $relativePath.Replace('\', '/')
  if ($normalizedPath -match $bodySkipPattern -or
      ([IO.Path]::GetExtension($relativePath) -notin $textExtensions -and
       [IO.Path]::GetFileName($relativePath) -notin @('LICENSE','.gitignore','.gitattributes'))) {
    $bodySkippedPaths.Add($relativePath)
    continue
  }
  if (-not (Test-Path -LiteralPath $relativePath -PathType Leaf)) { continue }
  $file = Get-Item -LiteralPath $relativePath -Force -ErrorAction Stop
  $ancestor = $file
  while ($null -ne $ancestor -and $ancestor.FullName -ne (Get-Location).Path) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { break }
    $ancestor = if ($ancestor -is [IO.DirectoryInfo]) { $ancestor.Parent } else { $ancestor.Directory }
  }
  if ($null -eq $ancestor -or $ancestor.FullName -ne (Get-Location).Path) {
    $bodySkippedPaths.Add($relativePath)
    continue
  }
  $text = [System.IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
  foreach ($pattern in $patterns) {
    if ([regex]::IsMatch($text, $pattern)) {
      $publishCandidates.Add($relativePath)
      break
    }
  }
}
$publishCandidates | Sort-Object -Unique
$bodySkippedPaths | Sort-Object -Unique | ForEach-Object { "BODY_NOT_READ: $_" }

$pendingCommits = @(git rev-list origin/main..HEAD)
$historyCandidates = New-Object System.Collections.Generic.List[string]
$historySkippedPaths = New-Object System.Collections.Generic.List[string]
foreach ($commit in $pendingCommits) {
  $commitObject = @(git cat-file commit $commit) -join "`n"
  foreach ($pattern in $patterns) {
    if ([regex]::IsMatch($commitObject, $pattern)) {
      $historyCandidates.Add("$commit [commit metadata]")
      break
    }
  }
  $changedPaths = @(git diff-tree --no-commit-id --name-only --diff-filter=ACMRT -r $commit)
  foreach ($relativePath in $changedPaths) {
    $normalizedPath = $relativePath.Replace('\', '/')
    if ($normalizedPath -match $bodySkipPattern -or
        ([IO.Path]::GetExtension($relativePath) -notin $textExtensions -and
         [IO.Path]::GetFileName($relativePath) -notin @('LICENSE','.gitignore','.gitattributes'))) {
      $historySkippedPaths.Add("$commit $relativePath")
      continue
    }
    $blobText = @(git show "$commit`:$relativePath" 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0) { continue }
    foreach ($pattern in $patterns) {
      if ([regex]::IsMatch($blobText, $pattern)) {
        $historyCandidates.Add("$commit $relativePath")
        break
      }
    }
  }
}
$historyCandidates | Sort-Object -Unique
$historySkippedPaths | Sort-Object -Unique | ForEach-Object { "BODY_NOT_READ: $_" }
```

合格条件: 本文を読んだ公開候補に、説明済みの合成値以外の秘密・個人パス候補が0件。`BODY_NOT_READ` は合格扱いではなく、本文を読まなかったパスの一覧です。秘密・ローカル設定・レポートは公開候補から外し、合成fixtureはセクション3のmanifest/hash検証で確認します。binary等はこの簡易テキスト検査の対象外です。候補があれば値を表示・コピーせず、予定の公開範囲と原因を確認してください。Git状態の変更やpushはこの手順では実行しません。

## 9. 合格判定

Push候補として合格にする条件:

1. PowerShell 5.1 parser、JSON、`git diff --check` が合格。
2. 全合成検査が `scanComplete: true`、`completionStatus: complete` で、`coverage.summary` が存在し、安全契約3項目が `none`。
3. manifestの未知ファイルとhash mismatchが0件で、全entryが検証済み。
4. 既存レポート非上書き、既定名衝突、BAT引数・特殊文字・空入力テストが合格。
5. リポジトリ自己検査が `scanComplete: true` かつDANGER 0件。
6. 実施した実PC検査で `executionStatus`・`execution.phases`・`completionStatus`・`coverage.summary` を確認する。`interrupted` / `SCAN_INTERRUPTED`、未着手フェーズ、`SCANNER_ERROR`、`incomplete-critical`、`error` がある結果を完了検査として採用しない。`partial-non-critical` は理由と対象範囲を確認済みで、`REGEX_SCAN_TIMEOUT` は `ruleId` と処理時間を記録して再検査または手動確認を実施済み。同じファイルの問題はフォルダを絞るだけでは解消しない場合がある。
7. DANGER/WARN/CAUTIONを手動確認し、必要な修正は合成fixtureへ落として再検証済み。
8. stage予定ファイルと未pushコミットに秘密情報、個人パス、実レポート、不要生成物がない。
9. `iocData.releaseReady: true` で、同梱IOCに期限超過・欠落・不正がない。
10. GitHubへのpushは、上記確認後に別操作として明示的に実行する。

テスト用の3ディレクトリは `reports/` 配下へ保管し、自動削除しません。削除・移動する場合は、今回の正確な対象パス、件数、影響、復旧方法を確認して個別に承認してください。実PC検査の `reports` もGitへ追加せず、組織の保管方針に従って扱います。
