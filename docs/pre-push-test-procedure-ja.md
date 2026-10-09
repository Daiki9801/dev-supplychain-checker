# Push前のPCテスト手順

- 対象バージョン: **0.1.23**
- 対象OS: Windows 10 / 11
- 実行環境: Windows PowerShell 5.1

この手順は、最初にリポジトリ内の合成データだけで安全に検証し、その後、必要な範囲に限って実PCを読み取り専用で確認する構成です。スキャナーはネットワーク接続、対象コード実行、修復、削除、隔離、レジストリ変更を行いません。TXT/JSONレポートだけを作成します。

公開前テストの合格は、このチェッカーが定義した境界内の動作確認です。PCやリポジトリが完全に安全であること、全依存関係・全CVE・全binaryを検査したことは意味しません。`REGEX_SCAN_TIMEOUT` は該当する本文正規表現処理が未完了であるため、合成回帰では許容せず、実PC検査では `coverage.summary` と対象ファイルを確認して、対象を狭めた再検査または手動確認を行います。

## 1. 開始前の確認

Windows PowerShell 5.1を開き、リポジトリへ移動します。

```powershell
Set-Location C:\Path\To\dev-supplychain-checker
$PSVersionTable.PSVersion
git status --short
git rev-parse HEAD
```

確認事項:

- `PSVersion` の `Major` が `5` である。
- 意図しない変更や未知の未追跡ファイルがない。
- `.env`、秘密鍵、実レポート、認証ファイルをGitへ追加しない。

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

$jsonFiles = @(Get-ChildItem -LiteralPath .\iocs -Filter *.json -File -Force)
$jsonFiles += Get-Item -LiteralPath .\tests\samples\manifest.json
foreach ($file in $jsonFiles) {
  Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json | Out-Null
}

.\tests\Test-LauncherScopeContracts.ps1
.\tests\Test-SecurityBoundaryRegressions.ps1 -KeepArtifacts
.\tests\Test-SecurityUpdate20261006.ps1
.\tests\Test-IocMaintenance.ps1
.\tests\Test-PythonMetadataRegressions.ps1

git diff --check
```

合格条件:

- parser errorが0件。
- 全JSONが例外なく読み込める。
- launcher scope契約と、実行ファイル探索・scanner-self・環境ルート境界の合成回帰テストが合格する。
- Python短縮バージョン、PEP 440の同一性、METADATAヘッダー境界、ロックファイルの対応関係、OCR/署名バイナリとハッシュ検査の合成回帰が合格する。
- `git diff --check` にエラーがない。改行コードの変換予告だけなら失敗ではありません。

## 3. 全合成回帰テスト

この検査は `tests/samples` の手書き合成データだけを読みます。実ユーザープロファイル、npm global/cache、レジストリ、イベントログは読みません。

```powershell
$syntheticStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$syntheticReportDir = Join-Path (Get-Location) "reports-pc-test-synthetic-$syntheticStamp"
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
$syntheticReport = Get-Content -LiteralPath $syntheticJson.FullName -Raw | ConvertFrom-Json

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

$manifest = Get-Content -LiteralPath .\tests\samples\manifest.json -Raw | ConvertFrom-Json
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path .\tests `
  -Checks Recommended `
  -ReportDir $syntheticReportDir `
  -JsonOut (Join-Path $syntheticReportDir 'manifest-parent.json') `
  -TextOut (Join-Path $syntheticReportDir 'manifest-parent.txt') `
  -Quiet -NoColor
if ($LASTEXITCODE -notin @(0, 1, 2)) { throw 'Manifest parent scan failed.' }
$manifestParent = Get-Content -LiteralPath (Join-Path $syntheticReportDir 'manifest-parent.json') -Raw | ConvertFrom-Json
if ([int]$manifestParent.scanStats.syntheticSampleUnexpectedFiles -ne 0) { throw 'Unexpected synthetic fixture file found.' }
if ([int]$manifestParent.scanStats.syntheticSampleHashMismatches -ne 0) { throw 'Synthetic fixture hash mismatch found.' }
if ([int]$manifestParent.scanStats.syntheticSampleKnownSkipped -lt @($manifest.samples).Count) { throw 'Not all manifest fixtures were verified.' }

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path .\tests\samples\node-runtime-safe `
  -Checks NodeRuntime `
  -JsonOut (Join-Path $syntheticReportDir 'node-runtime-safe.json') `
  -TextOut (Join-Path $syntheticReportDir 'node-runtime-safe.txt') `
  -Quiet -NoColor
if ($LASTEXITCODE -notin @(0, 1, 2)) { throw 'Safe Node.js report test failed.' }
$safeNodeReport = Get-Content -LiteralPath (Join-Path $syntheticReportDir 'node-runtime-safe.json') -Raw | ConvertFrom-Json
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

以下は `reports-pc-test-safety` 内の合成ファイルだけを使います。

```powershell
$safetyStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$safetyRoot = Join-Path (Get-Location) "reports-pc-test-safety-$safetyStamp"
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
$repositoryReportDir = Join-Path (Get-Location) "reports-pc-test-repository-$safetyStamp"
if (Test-Path -LiteralPath $repositoryReportDir) { throw 'Repository test directory already exists.' }
New-Item -ItemType Directory -Path $repositoryReportDir | Out-Null

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\Scan-DevSupplyChain.ps1 `
  -Path . `
  -Checks Recommended `
  -ReportDir $repositoryReportDir `
  -Quiet -NoColor
$repositoryExit = $LASTEXITCODE
if ($repositoryExit -notin @(0, 1, 2)) { throw 'Repository self-scan failed.' }

$repositoryJson = Get-ChildItem -LiteralPath $repositoryReportDir -Filter *.json -File | Select-Object -First 1
$repositoryReport = Get-Content -LiteralPath $repositoryJson.FullName -Raw | ConvertFrom-Json
if (-not [bool]$repositoryReport.scanComplete) { throw 'Repository self-scan was incomplete.' }
if ($null -eq $repositoryReport.coverage.summary) { throw 'Repository coverage summary is missing.' }
if ($repositoryReport.completionStatus -ne 'complete') { throw 'Repository completion status is not complete.' }
if (@($repositoryReport.findings | Where-Object severity -eq 'DANGER').Count -ne 0) { throw 'Repository self-scan produced DANGER.' }
```

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
$reportRoots = @($syntheticReportDir, $safetyRoot, $repositoryReportDir, '.\reports')
$secretPattern = '(?i)-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9_]{30,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|npm_[A-Za-z0-9]{30,}'
$reportCandidates = New-Object System.Collections.Generic.List[string]
foreach ($root in $reportRoots) {
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
  foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse) {
    $text = [System.IO.File]::ReadAllText($file.FullName)
    if ([regex]::IsMatch($text, $secretPattern)) { $reportCandidates.Add($file.FullName) }
  }
}
$reportCandidates
```

合格条件: 出力0件。候補が出た場合は内容を公開せず、redaction不備として合成値で再現してください。

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
foreach ($relativePath in $candidatePaths) {
  if (-not (Test-Path -LiteralPath $relativePath -PathType Leaf)) { continue }
  $text = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $relativePath)))
  foreach ($pattern in $patterns) {
    if ([regex]::IsMatch($text, $pattern)) {
      $publishCandidates.Add($relativePath)
      break
    }
  }
}
$publishCandidates | Sort-Object -Unique

$pendingCommits = @(git rev-list origin/main..HEAD)
$historyCandidates = New-Object System.Collections.Generic.List[string]
foreach ($commit in $pendingCommits) {
  $commitObject = @(git cat-file commit $commit) -join "`n"
  foreach ($pattern in $patterns) {
    if ([regex]::IsMatch($commitObject, $pattern)) {
      $historyCandidates.Add("$commit [commit metadata]")
      break
    }
  }
  $changedPaths = @(git diff-tree --no-commit-id --name-only -r $commit)
  foreach ($relativePath in $changedPaths) {
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
```

合格条件: 作業ツリーとpush予定コミットの両方で、説明済みの合成fixture以外の候補が0件。候補があれば、値を表示・コピーせず、そのファイルまたはコミットをpush対象から外して原因を確認します。

## 9. 合格判定

Push候補として合格にする条件:

1. PowerShell 5.1 parser、JSON、`git diff --check` が合格。
2. 全合成検査が `scanComplete: true`、`completionStatus: complete` で、`coverage.summary` が存在し、安全契約3項目が `none`。
3. manifestの未知ファイルとhash mismatchが0件で、全entryが検証済み。
4. 既存レポート非上書き、既定名衝突、BAT引数・特殊文字・空入力テストが合格。
5. リポジトリ自己検査が `scanComplete: true` かつDANGER 0件。
6. 実施した実PC検査で `completionStatus` と `coverage.summary` を確認し、`SCANNER_ERROR`、`incomplete-critical`、`error` がない。`partial-non-critical` は理由と対象範囲を確認済みで、`REGEX_SCAN_TIMEOUT` があれば対象を狭めた再検査または手動確認を実施済み。
7. DANGER/WARN/CAUTIONを手動確認し、必要な修正は合成fixtureへ落として再検証済み。
8. stage予定ファイルと未pushコミットに秘密情報、個人パス、実レポート、不要生成物がない。
9. `iocData.releaseReady: true` で、同梱IOCに期限超過・欠落・不正がない。
10. GitHubへのpushは、上記確認後に別操作として明示的に実行する。

テスト用の3ディレクトリは自動削除しません。結果確認後、`$syntheticReportDir`、`$safetyRoot`、`$repositoryReportDir` がこのリポジトリ直下の今回作成した専用ディレクトリを指していることを確認し、その3つだけをエクスプローラー等で削除してください。実PC検査の `reports` はGitへ追加せず、組織の保管方針に従って扱います。
