# Dev Supply Chain IOC Checker v0.1.2 依存なし実装 詳細設計書

作成日: 2026-06-03  
版: v0.1.2-dependency-free-design  
対象: Windows 開発端末 / ローカル AI 開発環境 / GitHub リポジトリ / VS Code 系 IDE / npm / PyPI / Composer / MCP / CI/CD  
想定実装: BAT ランチャー + PowerShell 単体スキャナー  
基本方針: 外部依存なし / ネットワーク通信なし / 読み取り専用 / 静的解析のみ / 秘密値非表示

---

## 0. 本書の位置づけ

本書は、`Dev Supply Chain IOC Checker` を **できるだけ依存関係を使わずに実装する**ための詳細設計書である。

前版 v0.1.1 では、Glassworm、TeamPCP / Mini Shai-Hulud、Nx Console、Codex token theft、Megalodon、Laravel-Lang などの最新サプライチェーン攻撃を反映し、検査対象を広げた。v0.1.2 ではそこからさらに、実装基盤を以下に絞る。

- BAT は起動専用。
- PowerShell は静的スキャン本体。
- Node.js / Python / npm / pip / git / composer / jq / yq / 外部 PowerShell module は使わない。
- YAML / TOML は完全パースせず、危険パターンの静的テキスト検出に限定する。
- IOC は内蔵テーブル + 任意のローカル JSON 追加読み込みにする。
- オンライン更新、自動修復、削除、隔離、設定変更は実装しない。

目的は、感染確定ではなく、**証跡を壊さずに開発者端末とプロジェクトを初期スクリーニングすること**である。

---

## 1. 最新脅威を踏まえた厳格レビュー結論

### 1.1 前回案の合格点

依存なし構成として、以下は妥当である。

| 項目 | 判定 | 理由 |
|---|---|---|
| BAT をランチャー専用にする | 合格 | BAT は Unicode / JSON / 再帰走査に弱いため、解析ロジックを持たせない判断は正しい |
| PowerShell 本体で静的解析する | 合格 | Windows 標準環境で動作し、端末調査に必要な Registry / EventLog / filesystem への read-only access が可能 |
| `-NoProfile` で起動する | 合格 | PowerShell profile 自体が汚染されている可能性を避けられる |
| `node`, `npm`, `python`, `pip`, `git` を実行しない | 合格 | 侵害済みプロジェクトでは lifecycle script / import hook / git hook 実行が危険 |
| 秘密値を表示しない | 合格 | レポート自体が二次漏えい媒体になることを防ぐ |
| 修復機能を入れない | 合格 | 認証情報漏えいを前提に調査すべき事案では、自動削除が証跡破壊になり得る |

### 1.2 修正必須だった点

前回の依存なし案は方向性は正しいが、詳細設計としては以下が不足していた。

| 問題 | 重要度 | 改善方針 |
|---|---:|---|
| BAT の `%DATE%` / `%TIME%` によるタイムスタンプがロケール依存 | P0 | レポートファイル名の生成は PowerShell 本体へ移管する |
| PowerShell 5.1 と 7.x の Unicode / JSON / encoding 差分が未整理 | P0 | Windows PowerShell 5.1 互換を下限にし、PowerShell 7 は任意対応にする |
| `U+E0100` 以上の異体字セレクタ補助が PS5.1 では扱いにくい | P0 | UTF-16 surrogate pair と byte-level fallback を設計に入れる |
| `Get-Content` の既定 encoding に依存すると不可視 Unicode 検出漏れが出る | P0 | `Read-TextFileSafe` で BOM / UTF-8 strict / UTF-16LE/BE / fallback を実装する |
| `Get-ChildItem -Recurse` のアクセス拒否・巨大ディレクトリ・junction loop 対策が不足 | P0 | 独自の安全な file walker を作る。reparse point は既定で追跡しない |
| `node_modules` / `.venv` を既定 skip にすると artifact-only malware を見逃す | P0 | 既定では「全面再帰」ではなく「既知 package / entrypoint / hook の targeted scan」にする |
| YAML / TOML を regex で見る限界が曖昧 | P1 | 完全構文解析ではなく、危険 pattern scanner と明記する |
| EndpointTelemetry が重くなり得る | P1 | 既定 off。時間範囲・件数制限・権限不足時の graceful degradation を入れる |
| `ExecutionPolicy Bypass` の意味が誤解されやすい | P1 | Process scope のみ。永続的な policy 変更は行わないと明記する |
| IOC の鮮度がオフラインでは落ちる | P1 | `IOC_DATA_STALE` を出す。自動ネットワーク更新はしない |

### 1.3 v0.1.2 の設計評価

| 観点 | 評価 |
|---|---:|
| 依存なし実行性 | 95 / 100 |
| 読み取り専用・証跡保全 | 95 / 100 |
| Glassworm / IDE 拡張検出 | 88 / 100 |
| npm / PyPI / Composer 静的検査 | 84 / 100 |
| GitHub Actions / CI/CD 静的検査 | 82 / 100 |
| AI agent / MCP 設定検査 | 86 / 100 |
| EndpointTelemetry | 75 / 100 |
| 誤検知抑制 | 78 / 100 |
| 総合 | 89 / 100 |

依存なし・静的解析という制約下では、v0.1.2 は実装開始に値する。  
ただし、EDR、メモリフォレンジック、SBOM照合、オンライン脆弱性DB照合、完全な package manager audit の代替にはならない。

---

## 2. 最新脅威前提

### 2.1 Glassworm

Glassworm は、不可視 Unicode だけではなく、VS Code / OpenVSX 拡張、npm / PyPI、GitHub リポジトリ、MCP、ネイティブドロッパー、RAT、複数 C2 を含む開発者標的のサプライチェーン攻撃として扱う。

CrowdStrike は 2026-05-26 14:00 UTC に Google および Shadowserver Foundation と連携し、Glassworm の 4 系統の C2 チャネルを同時遮断したと報告している。ただし、これは感染端末が自動的に無害化されたことを意味しない。感染端末・認証情報・開発者トークン・CI/CD secret の調査は引き続き必要である。

### 2.2 Nx Console v18.95.0 型

Nx Console v18.95.0 は、短時間だけ Visual Studio Marketplace / OpenVSX で悪性版が配布された。公式 postmortem は、v18.95.0 を exposure window 中にインストール、または auto-update で有効化した可能性がある端末は compromise 前提で扱うべきとしている。

v0.1.2 では、VS Code 拡張は以下を検査する。

- extension ID
- version
- install/update time
- `package.json` の `main`, `activationEvents`, `extensionDependencies`, `extensionPack`, `scripts`
- native binary: `*.node`, `*.dll`, `*.dylib`, `*.so`
- suspicious dist / generated JS
- known artifact paths
- auto-update posture inventory

### 2.3 Codex / AI token theft 型

`codexui-android` では、GitHub のソースには存在しないコードが npm published artifact に混入し、Codex の `auth.json` を読み取り、外部送信する挙動が報告されている。

v0.1.2 では、AI 開発者端末向けに以下を検査対象にする。

- `%USERPROFILE%\.codex\auth.json`
- `%CODEX_HOME%\auth.json`
- `%USERPROFILE%\.claude`
- `%USERPROFILE%\.cursor`
- `%USERPROFILE%\.windsurf`
- MCP config 内の `env` 名
- package / dist / source map 内の AI token path 参照
- token path 参照 + HTTPS POST / fetch / request の複合

値は絶対に出力しない。

### 2.4 Mini Shai-Hulud / TeamPCP 型

Mini Shai-Hulud は npm / PyPI を横断し、CI/CD runner、OIDC token、developer/cloud credentials、AI coding agent persistence hook を狙う。SLSA provenance のような process integrity control も単独では十分ではない。

v0.1.2 では以下を検査する。

- package lifecycle script
- Python `.pth` / `sitecustomize.py` / `usercustomize.py`
- GitHub Actions `id-token: write`
- OIDC / runtime token 名の外部送信疑い
- AI agent hook / persistence config
- cloud credential path 参照

### 2.5 Megalodon 型 GitHub Actions 汚染

Megalodon は GitHub Actions workflow を注入し、CI/CD secrets、cloud key、token を窃取する型である。v0.1.2 では `.github/workflows` を P0 対象とし、YAML parser なしの静的 pattern scanner で検査する。

### 2.6 Laravel-Lang / Composer tag rewrite 型

Laravel-Lang 事案では、正規リポジトリのソースに悪性コードが commit されず、tag が悪性 fork の commit へ向けられ、Composer autoloader 経由で credential stealer が実行される手口が報告された。

v0.1.2 では、Composer が存在する場合のみ以下を検査する。

- `composer.json`
- `composer.lock`
- `vendor/composer/autoload_files.php`
- `vendor/composer/installed.json`
- `autoload.files`
- known C2 domain / marker / suspicious PHP execution patterns

---

## 3. 非依存実装の原則

### 3.1 使わないもの

以下は v0.1.2 で使用禁止とする。

```text
node
npm
npx
pnpm
yarn
bun
python
pip
uv
poetry
composer
php
git
jq
yq
curl
wget
Invoke-WebRequest による外部通信
外部 PowerShell module
インターネット通信
```

### 3.2 使ってよいもの

Windows 標準 PowerShell / .NET / OS 標準 read-only API のみ使用する。

```text
PowerShell 5.1 compatible syntax
.NET System.IO
.NET System.Text
.NET Regex
Get-ChildItem / Get-Item / Get-Content は限定的に使用可
Get-ItemProperty
Get-WinEvent
Get-DnsClientCache
Get-ScheduledTask
ConvertFrom-Json
ConvertTo-Json
Get-FileHash
```

### 3.3 禁止する副作用

以下は実装してはならない。

```text
ファイル削除
ファイル隔離
拡張機能 uninstall
npm/pip/composer install / uninstall / audit
registry 変更
環境変数変更
credential 削除
Git 操作
ネットワーク通信
PowerShell execution policy の永続変更
```

---

## 4. ファイル構成

最小構成は以下。

```text
dev-supplychain-checker/
  run-checker.bat
  scan-current-folder.bat
  scan-userprofile.bat
  scan-full.bat
  Scan-DevSupplyChain.ps1
  iocs/
    known-packages.json          # 任意。存在しなくても動作
    known-extensions.json        # 任意。存在しなくても動作
    known-files.json             # 任意。存在しなくても動作
    suspicious-patterns.json     # 任意。存在しなくても動作
  reports/
    # 実行時に自動作成
  docs/
    README.md
    limitations.md
```

### 4.1 単体配布モード

`Scan-DevSupplyChain.ps1` は単体でも動作する。

```powershell
.\Scan-DevSupplyChain.ps1 -Path .
.\Scan-DevSupplyChain.ps1 -UserProfile
.\Scan-DevSupplyChain.ps1 -Path . -UserProfile -EndpointTelemetry
```

### 4.2 IOC JSON 追加モード

`iocs/*.json` が存在する場合だけ読み込む。存在しない場合は内蔵 IOC のみで動作する。

```text
内蔵 IOC: minimum baseline
ローカル IOC JSON: 追加・上書き
オンライン更新: なし
```

---

## 5. BAT ランチャー設計

### 5.1 BAT の責務

BAT の責務は以下だけに限定する。

1. PowerShell を `-NoProfile` で起動する。
2. 実行ポリシーを process scope だけで回避する。
3. `Scan-DevSupplyChain.ps1` に mode / path を渡す。
4. 終了コードを表示する。
5. レポートの場所を案内する。

BAT で以下は行わない。

- 日付時刻の複雑な加工
- ファイル走査
- JSON 解析
- Unicode 検査
- registry / event log 参照

レポートファイル名は PowerShell 本体が生成する。これにより `%DATE%` / `%TIME%` のロケール依存や `:` などの禁止文字問題を避ける。

### 5.2 `scan-current-folder.bat`

```bat
@echo off
setlocal

set "BASE=%~dp0"
set "TARGET=%~1"

if "%TARGET%"=="" (
  set "TARGET=%CD%"
)

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%BASE%Scan-DevSupplyChain.ps1" ^
  -Path "%TARGET%" ^
  -ReportDir "%BASE%reports"

set "EXITCODE=%ERRORLEVEL%"
echo.
echo Scan finished with exit code %EXITCODE%.
echo Reports are under: %BASE%reports
echo.
pause
exit /b %EXITCODE%
```

### 5.3 `scan-userprofile.bat`

```bat
@echo off
setlocal

set "BASE=%~dp0"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%BASE%Scan-DevSupplyChain.ps1" ^
  -UserProfile ^
  -ReportDir "%BASE%reports"

set "EXITCODE=%ERRORLEVEL%"
echo.
echo Scan finished with exit code %EXITCODE%.
echo Reports are under: %BASE%reports
echo.
pause
exit /b %EXITCODE%
```

### 5.4 `scan-full.bat`

```bat
@echo off
setlocal

set "BASE=%~dp0"
set "TARGET=%~1"

if "%TARGET%"=="" (
  set "TARGET=%CD%"
)

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%BASE%Scan-DevSupplyChain.ps1" ^
  -Path "%TARGET%" ^
  -UserProfile ^
  -EndpointTelemetry ^
  -ReportDir "%BASE%reports"

set "EXITCODE=%ERRORLEVEL%"
echo.
echo Full scan finished with exit code %EXITCODE%.
echo Reports are under: %BASE%reports
echo.
pause
exit /b %EXITCODE%
```

### 5.5 `run-checker.bat`

メニュー式ランチャーは任意だが、配布性を上げるために用意してよい。

```bat
@echo off
setlocal
set "BASE=%~dp0"

echo Dev Supply Chain IOC Checker
echo.
echo 1. Scan current folder
echo 2. Scan user profile
echo 3. Full scan current folder + user profile + endpoint telemetry
echo 4. Exit
echo.
set /p MODE=Select mode: 

if "%MODE%"=="1" call "%BASE%scan-current-folder.bat"
if "%MODE%"=="2" call "%BASE%scan-userprofile.bat"
if "%MODE%"=="3" call "%BASE%scan-full.bat"
if "%MODE%"=="4" exit /b 0

exit /b %ERRORLEVEL%
```

### 5.6 `ExecutionPolicy Bypass` の扱い

BAT では `-ExecutionPolicy Bypass` を付与する。ただし、これは process scope の実行時指定であり、永続的な policy 変更ではない。`Set-ExecutionPolicy` は使わない。

設計上、以下の説明を README に必ず入れる。

```text
この BAT は PowerShell の実行ポリシーをこのプロセス内だけで回避します。
Windows の永続設定や registry は変更しません。
PowerShell execution policy はセキュリティ境界ではなく、誤実行防止の仕組みです。
```

---

## 6. PowerShell 本体設計

### 6.1 対応バージョン

下限は Windows PowerShell 5.1 とする。PowerShell 7.x でも動作するようにする。

PowerShell 5.1 互換のため、以下に注意する。

| 問題 | 方針 |
|---|---|
| `\u{E0100}` regex が使えない | UTF-16 surrogate pair で検出 |
| `Get-Content -Raw -Encoding utf8` の挙動差 | `.NET StreamReader` で安全読み込み |
| `ConvertTo-Json` の depth 既定が浅い | `-Depth 8` 以上を明示 |
| 大量ファイルで `Get-ChildItem -Recurse` が遅い | 独自 safe walker を使う |
| 長パス | まず通常 path で扱い、失敗時は `PATH_TOO_LONG` INFO/WARN を出す |

### 6.2 引数

```powershell
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$UserProfile,
    [switch]$Deep,
    [switch]$EndpointTelemetry,
    [string]$ReportDir,
    [string]$TextOut,
    [string]$JsonOut,
    [int]$MaxFileSizeMB = 10,
    [int]$MaxFiles = 200000,
    [int]$EndpointDays = 30,
    [switch]$NoColor,
    [switch]$Quiet
)
```

### 6.3 実行 mode

| 引数 | 内容 |
|---|---|
| `-Path` | 指定ディレクトリ配下のプロジェクトファイルを検査 |
| `-UserProfile` | IDE 拡張、AI agent 設定、MCP、秘密ファイルの存在、ユーザー側永続化痕跡を検査 |
| `-Deep` | `node_modules`, `.venv`, `vendor`, `dist`, `build` なども広めに検査 |
| `-EndpointTelemetry` | DNS cache、PowerShell history、Event logs、Defender logs、Scheduled Tasks などを読む |
| `-ReportDir` | 自動ファイル名で JSON/TXT を出力 |
| `-TextOut` / `-JsonOut` | 明示されたファイル名へ出力 |

### 6.4 出力ファイル名

`-ReportDir` 指定時は PowerShell 本体で生成する。

```text
dev-supplychain-report-YYYYMMDD-HHMMSS.txt
dev-supplychain-report-YYYYMMDD-HHMMSS.json
```

`-TextOut` / `-JsonOut` が明示された場合はそれを優先する。

### 6.5 終了コード

| Exit code | 意味 |
|---:|---|
| 0 | OK / INFO のみ |
| 1 | WARN あり |
| 2 | DANGER あり |
| 3 | scanner 実行エラー。ただし可能な範囲のレポートは出力 |
| 4 | 引数不正 |

---

## 7. PowerShell 関数構成

1 ファイル構成だが、関数は責務別に分離する。

```powershell
function Initialize-ScannerContext {}
function Add-Finding {}
function Get-OverallResult {}
function ConvertTo-RedactedPath {}
function Redact-SecretLikeText {}
function New-ReportPaths {}
function Write-Reports {}

function Load-BuiltinIocs {}
function Load-LocalIocs {}
function Test-IocFreshness {}

function Get-SafeFileList {}
function Test-IsReparsePoint {}
function Test-IsProbablyBinary {}
function Read-TextFileSafe {}
function Get-LineNumberForOffset {}

function Scan-Project {}
function Scan-InvisibleUnicode {}
function Scan-NpmFiles {}
function Scan-PythonFiles {}
function Scan-ComposerFiles {}
function Scan-GitHubActions {}
function Scan-GitHooksAndWorkspaceTasks {}

function Scan-UserProfile {}
function Scan-IdeExtensions {}
function Scan-McpAndAgentConfigs {}
function Scan-SecretInventory {}

function Scan-EndpointTelemetry {}
function Scan-DnsCache {}
function Scan-PowerShellHistory {}
function Scan-DefenderLogs {}
function Scan-WindowsEventLogs {}
function Scan-StartupAndRunKeys {}
function Scan-ScheduledTasks {}
```

---

## 8. 安全な file walker

### 8.1 既定除外ディレクトリ

既定では以下を全面再帰しない。

```text
.git
.hg
.svn
node_modules
.venv
venv
env
__pycache__
.tox
.mypy_cache
.pytest_cache
vendor
.next
.nuxt
.svelte-kit
dist
build
out
target
bin
obj
.cache
.tmp
tmp
```

ただし、artifact-only malware 対策のため、以下は **targeted scan** として例外的に読む。

| ディレクトリ | 既定 targeted scan |
|---|---|
| `node_modules` | 既知 package の `package.json`, `main`, `bin`, `dist`, `*.map` |
| `.venv` / `site-packages` | `*.pth`, `sitecustomize.py`, `usercustomize.py`, 既知 package metadata |
| `vendor` | `vendor/composer/autoload_files.php`, `vendor/composer/installed.json`, known Composer package |
| `dist` / `build` | project root の package entrypoint から参照される場合のみ |

`-Deep` 指定時は除外を緩めるが、`MaxFiles` と `MaxFileSizeMB` は維持する。

### 8.2 Reparse point / junction

Windows の junction / symlink loop を避けるため、既定で `ReparsePoint` を追跡しない。

検出時は必要に応じて INFO を出す。

```text
[INFO] REPARSE_POINT_SKIPPED
Path: ...
Evidence: Directory has ReparsePoint attribute and was skipped to avoid recursion loop.
```

### 8.3 Access denied

アクセス拒否はスキャン全体を止めない。

```text
[INFO] ACCESS_DENIED
Path: ...
Evidence: Access denied while enumerating or reading file.
Recommendation: Run from an account with read access if this path must be inspected.
```

### 8.4 巨大ファイル

`MaxFileSizeMB` を超えるファイルは原則 skip。

ただし lockfile / workflow / package manifest は 10MB を超えても先頭・末尾の limited read を検討する。

---

## 9. 安全なテキスト読み込み

### 9.1 `Read-TextFileSafe`

目的は、`Get-Content` の既定 encoding に依存しないこと。

処理順序:

1. bytes として読む。
2. NUL byte 比率で binary 判定。
3. BOM 判定。
4. UTF-8 strict decode。
5. UTF-16LE / UTF-16BE heuristic。
6. OS default encoding fallback。
7. 読めない場合は `TEXT_DECODE_FAILED` を出して skip。

### 9.2 binary 判定

先頭 4096 bytes に NUL byte が多い場合は binary とみなす。

ただし UTF-16 text は NUL が多く見えるため、BOM / UTF-16 heuristic を先に試す。

### 9.3 秘密ファイルの読み取り制限

以下は原則として中身を読まない。

```text
.env
.npmrc
.pypirc
.netrc
id_rsa
id_ed25519
*.pem
*.p12
*.pfx
auth.json
credentials
config.json under cloud credential directories
```

ただし、存在確認と path redaction は行う。  
どうしてもパターン確認が必要な場合でも、key 名だけを取り出し、value は保存しない。

---

## 10. Redaction 設計

### 10.1 path redaction

以下を置換する。

| 元 | 置換 |
|---|---|
| `%USERPROFILE%` | `~` |
| machine-specific temp path | `%TEMP%` |
| user SID | `<SID>` |

### 10.2 secret redaction

レポートに出す evidence は必ず `Redact-SecretLikeText` を通す。

検出対象例:

```text
ghp_
github_pat_
ghs_
gho_
sk-
AKIA
ASIA
AIza
xoxb-
xoxp-
glpat-
npm_
pypi-
Bearer <token>
長い base64 / hex / JWT 風文字列
```

方針:

- 値そのものは出さない。
- `KEY_NAME=<REDACTED>` の形にする。
- secret file は `SECRET_FILE_PRESENT` として存在だけ出す。

---

## 11. 検出カテゴリと severity

### 11.1 severity

| Severity | 意味 |
|---|---|
| OK | 問題なし、または検査完了 |
| INFO | 棚卸し情報、単独では危険ではない |
| WARN | 要レビュー。誤検知もあり得る |
| DANGER | 強い侵害疑い。端末隔離・証跡保全・認証情報ローテーションを検討 |

### 11.2 主要カテゴリ

```text
INVISIBLE_UNICODE
INVISIBLE_UNICODE_DECODER
KNOWN_BAD_PACKAGE
KNOWN_BAD_EXTENSION
KNOWN_BAD_FILE_HASH
SUSPICIOUS_LIFECYCLE_SCRIPT
PYTHON_PTH_EXECUTION
PYTHON_IMPORT_HOOK
COMPOSER_AUTOLOAD_EXECUTION
GITHUB_ACTIONS_DANGEROUS_FLOW
GITHUB_ACTIONS_RISKY_PERMISSION
MCP_UNPINNED_EXECUTION
MCP_REMOTE_SCRIPT_EXECUTION
AI_TOKEN_PATH_REFERENCE
AI_TOKEN_EXFIL_PATTERN
IDE_EXTENSION_NATIVE_BINARY
IDE_EXTENSION_DEPENDENCY_CHAIN
SECRET_FILE_PRESENT
PERSISTENCE_INDICATOR
ENDPOINT_IOC_OBSERVED
IOC_DATA_STALE
SCAN_LIMITATION
ACCESS_DENIED
```

### 11.3 複合判定

単発 pattern ではなく、複合条件で severity を上げる。

| 条件 | 判定 |
|---|---|
| 不可視 Unicode のみ | WARN |
| 不可視 Unicode + `eval` / `Function` / `Buffer.from` / `atob` / `fromCharCode` | DANGER |
| `.pth` の存在のみ | INFO |
| `.pth` + `import subprocess` / `exec` / `eval` / `base64` / `requests` 複合 | DANGER |
| `npx` のみ | INFO |
| MCP で `npx package` バージョン未固定 | WARN |
| MCP で `curl` / `iwr` + shell 実行 | DANGER |
| `pull_request_target` のみ | WARN |
| `pull_request_target` + untrusted checkout + install/build + write permission | DANGER |
| AI token path 参照のみ | WARN |
| AI token path 参照 + HTTPS POST/fetch + top-level execution | DANGER |

---

## 12. Project scan 詳細

### 12.1 不可視 Unicode 検査

対象範囲:

```text
U+FE00 - U+FE0F      Variation Selectors
U+E0100 - U+E01EF    Variation Selectors Supplement
U+E000 - U+F8FF      Private Use Area
U+200B - U+200F      Zero width / direction chars
U+202A - U+202E      Bidi override chars
U+2060 - U+206F      Invisible formatting chars
```

PowerShell 5.1 互換のため、`U+E0100 - U+E01EF` は surrogate pair で検出する。

```powershell
$VariationSelectorPattern = '[\uFE00-\uFE0F]'
$VariationSelectorSupplementPattern = [string][char]0xDB40 + '[\uDD00-\uDDEF]'
$ZeroWidthPattern = '[\u200B-\u200F]'
$BidiPattern = '[\u202A-\u202E]'
$InvisibleFormatPattern = '[\u2060-\u206F]'
$PrivateUsePattern = '[\uE000-\uF8FF]'
```

Decoder pattern:

```text
eval
Function(
Buffer.from
atob
String.fromCharCode
String.fromCodePoint
codePointAt
fromCodePoint
TextDecoder
Uint8Array
base64
```

### 12.2 npm / pnpm / yarn / bun

対象:

```text
package.json
package-lock.json
npm-shrinkwrap.json
pnpm-lock.yaml
yarn.lock
bun.lock
bun.lockb
.npmrc
.npmignore
```

検査:

- known bad package + version
- lifecycle script
- suspicious install script
- unpinned git / http dependency
- package manager posture
- lockfile resolved tarball domain
- artifact-only entrypoint scan

危険 script pattern:

```text
preinstall
install
postinstall
prepare
node-gyp
curl
wget
iwr
irm
Invoke-WebRequest
powershell
pwsh
cmd.exe
bash
sh
base64
certutil
bitsadmin
rundll32
regsvr32
```

既知 IOC baseline:

```text
@aifabrix/miso-client@4.7.2
@iflow-mcp/watercrawl-watercrawl-mcp@1.3.0-1.3.4
litellm==1.82.7
litellm==1.82.8
axios@1.14.1
axios@0.30.4
plain-crypto-js@4.2.1
@tanstack/zod-adapter@1.166.15
codexui-android >=0.1.82, if artifact contains AI token exfil pattern
```

注: IOC は陳腐化するため、known list は検出補助であり、網羅性を保証しない。

### 12.3 Python / PyPI

対象:

```text
requirements.txt
requirements.lock
pyproject.toml
poetry.lock
uv.lock
setup.py
setup.cfg
.venv/**/site-packages/*.pth
site-packages/**/sitecustomize.py
site-packages/**/usercustomize.py
site-packages/**/direct_url.json
site-packages/**/RECORD
```

特に `.pth` は Python 起動時実行に関わるため P0。

DANGER 条件:

```text
litellm==1.82.7
litellm==1.82.8
litellm_init.pth
.pth + exec/eval/subprocess/base64/requests/urllib/os.environ
setup.py + external fetch + execution
pyproject build backend + suspicious command
```

### 12.4 Composer / PHP

対象:

```text
composer.json
composer.lock
vendor/composer/autoload_files.php
vendor/composer/installed.json
```

DANGER / WARN pattern:

```text
autoload.files
flipboxstudio.info
flipboxstudio.info/payload
flipboxstudio.info/exfil
.laravel_locale
@exec
shell_exec
proc_open
curl_exec
file_get_contents(http
base64_decode + eval/assert/include
```

### 12.5 GitHub Actions / CI/CD

対象:

```text
.github/workflows/*.yml
.github/workflows/*.yaml
.github/actions/**
.github/dependabot.yml
```

DANGER 条件:

```text
curl | bash
wget | bash
iwr/irm/Invoke-WebRequest + powershell/pwsh
base64 decode + shell execution
pull_request_target + untrusted checkout + install/build
secrets.* + curl/wget/fetch/request/http
GITHUB_TOKEN + contents: write + external transmission
ACTIONS_ID_TOKEN_REQUEST_TOKEN external reference
ACTIONS_RUNTIME_TOKEN external reference
id-token: write + untrusted code execution
```

WARN 条件:

```text
pull_request_target
workflow_dispatch
schedule
repository_dispatch
contents: write
packages: write
id-token: write
npm publish
twine upload
docker push
external URL script fetch
unpinned actions reference
uses: owner/action@main
uses: owner/action@master
```

### 12.6 Git hooks / workspace tasks

対象:

```text
.git/hooks/**
.husky/**
.vscode/tasks.json
.vscode/settings.json
.cursor/**
.claude/**
.codex/**
```

危険 pattern:

```text
curl/wget/iwr/irm + shell
npx unpinned
uvx unpinned
powershell -EncodedCommand
base64 decode + execution
secret path reference + network
```

---

## 13. UserProfile scan 詳細

### 13.1 IDE extension directories

対象:

```text
%USERPROFILE%\.vscode\extensions
%USERPROFILE%\.vscode-insiders\extensions
%USERPROFILE%\.cursor\extensions
%USERPROFILE%\.windsurf\extensions
%USERPROFILE%\.vscodium\extensions
%USERPROFILE%\.positron\extensions
```

検査:

- known bad extension ID / version
- `package.json` metadata
- native binary
- install/update time
- extension dependencies
- extension pack
- activation events
- scripts
- dist / source map suspicious pattern

Known extension baseline:

```text
specstudio.code-wakatime-activity-tracker
floktokbok.autoimport
autoimport-2.7.9
quartz.quartz-markdown-editor@0.3.0
nrwl.angular-console / Nx Console v18.95.0
```

Nx Console v18.95.0 は特に DANGER。

### 13.2 MCP / AI agent configs

対象候補:

```text
%APPDATA%\Claude\claude_desktop_config.json
%APPDATA%\Code\User\settings.json
%APPDATA%\Cursor\User\settings.json
%APPDATA%\Windsurf\User\settings.json
%USERPROFILE%\.cursor
%USERPROFILE%\.claude
%USERPROFILE%\.codex
%USERPROFILE%\.config
mcp.json
settings.json
```

危険判定:

```text
npx package without @version: WARN
uvx package without version: WARN
GitHub raw / gist / pastebin fetch: DANGER if executed
curl/iwr/irm + shell: DANGER
env contains API key names: INFO, value redacted
AI token path + exfil pattern: DANGER
```

### 13.3 secret inventory

存在確認のみ行う。

```text
%USERPROFILE%\.npmrc
%USERPROFILE%\.pypirc
%USERPROFILE%\.netrc
%USERPROFILE%\.ssh\id_rsa
%USERPROFILE%\.ssh\id_ed25519
%USERPROFILE%\.aws\credentials
%USERPROFILE%\.azure
%USERPROFILE%\.kube\config
%USERPROFILE%\.codex\auth.json
%CODEX_HOME%\auth.json
```

出力例:

```text
[INFO] SECRET_FILE_PRESENT
Path: ~\.codex\auth.json
Evidence: Credential file exists. Value not read or displayed.
Recommendation: Rotate if DANGER findings suggest compromise.
```

---

## 14. EndpointTelemetry 詳細

`-EndpointTelemetry` は重いため既定 off。

### 14.1 DNS cache

`Get-DnsClientCache` を read-only で実行する。

検査:

```text
164.92.88.210
known C2 domains
flipboxstudio.info
sentry.anyclaw.store
```

DNS cache は短命なので、未検出でも安全とは言えない。未検出時は OK ではなく INFO 扱いでもよい。

### 14.2 PowerShell history

対象:

```text
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

危険 pattern:

```text
irm | iex
iwr | iex
Invoke-Expression
EncodedCommand
FromBase64String
curl | powershell
```

秘密値が含まれる可能性があるため、該当行全文は出さない。pattern 名だけ出す。

### 14.3 Defender / EventLog

`Get-WinEvent` は time-bounded / count-bounded で行う。

推奨:

```text
EndpointDays default: 30
Max events per log: 5000
Access denied: INFO and continue
```

対象候補:

```text
Microsoft-Windows-Windows Defender/Operational
Windows PowerShell
Microsoft-Windows-PowerShell/Operational
Application
System
```

### 14.4 Startup / Run keys / Scheduled tasks

読み取り対象:

```text
Startup folder
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run     # 読める場合のみ
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce # 読める場合のみ
Scheduled Tasks
PowerShell profiles
```

DANGER / WARN pattern:

```text
powershell -EncodedCommand
wscript/cscript unknown script
Temp path executable
AppData roaming executable
curl/iwr/irm + shell
node/python from suspicious temp path
```

---

## 15. IOC 設計

### 15.1 内蔵 IOC

`Load-BuiltinIocs` で最低限の IOC を内蔵する。

理由:

- 単一 `.ps1` でも動作させるため。
- `iocs/` が欠落しても baseline scan を失わないため。

### 15.2 ローカル IOC JSON

任意ファイル:

```text
iocs/known-packages.json
iocs/known-extensions.json
iocs/known-files.json
iocs/suspicious-patterns.json
```

schema 例:

```json
{
  "schemaVersion": "0.1.2",
  "lastUpdated": "2026-06-03",
  "sourceSet": "local-curated",
  "expiresAfterDays": 30,
  "packages": [
    {
      "ecosystem": "npm",
      "name": "@tanstack/zod-adapter",
      "versions": ["1.166.15"],
      "severity": "DANGER",
      "confidence": "high",
      "sourceUrl": "https://tanstack.com/",
      "notes": "Known compromised package version from TanStack-related incident"
    }
  ]
}
```

### 15.3 IOC freshness

`lastUpdated + expiresAfterDays` が過ぎている場合:

```text
[WARN] IOC_DATA_STALE
Evidence: Local IOC file is older than configured expiry.
Recommendation: Manually review and update IOC JSON from trusted sources before relying on known-IOC coverage.
```

ネットワーク更新はしない。

---

## 16. レポート設計

### 16.1 JSON schema

```json
{
  "schemaVersion": "0.1.2",
  "generatedAt": "2026-06-03T12:00:00+09:00",
  "scanner": {
    "name": "Dev Supply Chain IOC Checker",
    "version": "0.1.2",
    "dependencyMode": "none",
    "networkAccess": false,
    "readOnly": true
  },
  "host": {
    "userProfileRedacted": "~",
    "computerNameRedacted": "<COMPUTER>",
    "powershellVersion": "5.1"
  },
  "mode": {
    "path": true,
    "userProfile": true,
    "deep": false,
    "endpointTelemetry": false
  },
  "scanRoots": [
    "C:\\Projects\\example"
  ],
  "overallResult": "WARN",
  "summary": {
    "danger": 0,
    "warn": 3,
    "info": 10,
    "ok": 1
  },
  "findings": [
    {
      "severity": "WARN",
      "category": "MCP_UNPINNED_EXECUTION",
      "title": "MCP server uses unpinned npx package",
      "path": "~\\.cursor\\mcp.json",
      "line": 12,
      "evidence": "npx package without explicit version",
      "recommendation": "Pin the package version or vendor the MCP server."
    }
  ],
  "limitations": [
    "No network lookup was performed.",
    "YAML/TOML files were scanned by pattern matching, not parsed semantically.",
    "Absence of findings does not prove the host is clean."
  ]
}
```

### 16.2 Text report

```text
Dev Supply Chain IOC Checker Report
Version: 0.1.2
GeneratedAt: 2026-06-03T12:00:00+09:00
Mode: Path, UserProfile
ReadOnly: true
NetworkAccess: false
OverallResult: WARN

[SUMMARY]
DANGER: 0
WARN:   3
INFO:   10
OK:     1

[FINDINGS]
[WARN] MCP_UNPINNED_EXECUTION
Title: MCP server uses unpinned npx package
Path: ~\.cursor\mcp.json
Line: 12
Evidence: npx package without explicit version
Recommendation: Pin the package version or vendor the MCP server.

[LIMITATIONS]
- No network lookup was performed.
- YAML/TOML files were scanned by pattern matching, not parsed semantically.
- Absence of findings does not prove the host is clean.
```

### 16.3 レポート encoding

Windows PowerShell 5.1 互換のため、TXT / JSON は UTF-8 BOM 付きで出力する。

---

## 17. 誤検知と抑制

### 17.1 誤検知が多い領域

| 領域 | 誤検知理由 |
|---|---|
| 不可視 Unicode | 正当な CJK / emoji / typography / test fixture |
| lifecycle script | 正当な native build / TypeScript prepare |
| GitHub Actions | 正当な deploy / release workflow |
| MCP | 仕様上ローカル command を起動する |
| `.pth` | 正当な package path hook |
| native binary in VS Code extension | 正当な language server / native addon |

### 17.2 抑制方針

v0.1.2 では allowlist は最小限にする。  
ただし将来のために、ローカル allowlist JSON を設計上予約する。

```text
iocs/local-allowlist.json
```

初期実装では allowlist を入れすぎない。  
DANGER を消す allowlist は慎重に扱う。

---

## 18. Performance 設計

### 18.1 既定値

```text
MaxFileSizeMB: 10
MaxFiles: 200000
EndpointDays: 30
Deep: false
EndpointTelemetry: false
```

### 18.2 進捗表示

`-Quiet` がない場合は高レベル進捗のみ表示する。

```text
[1/7] Project files
[2/7] npm/Python/Composer manifests
[3/7] GitHub Actions
[4/7] IDE extensions
[5/7] MCP/AI configs
[6/7] Endpoint telemetry
[7/7] Writing reports
```

ファイル名を大量に逐次表示しない。

### 18.3 中断耐性

例外で止めず、finding / limitation として継続する。

---

## 19. テスト設計

### 19.1 最小テストサンプル

```text
tests/samples/clean-js/index.js
tests/samples/invisible-unicode-only/sample.js
tests/samples/invisible-unicode-eval/sample.js
tests/samples/npm-clean/package.json
tests/samples/npm-bad/package-lock.json
tests/samples/python-pth-clean/site-packages/clean.pth
tests/samples/python-pth-bad/site-packages/litellm_init.pth
tests/samples/github-actions-clean/.github/workflows/ci.yml
tests/samples/github-actions-danger/.github/workflows/backdoor.yml
tests/samples/vscode-extension-clean/package.json
tests/samples/vscode-extension-bad/package.json
tests/samples/mcp-unpinned/mcp.json
tests/samples/composer-autoload-bad/vendor/composer/autoload_files.php
```

### 19.2 PowerShell テスト方式

外部 test framework は使わない。

```powershell
.\Scan-DevSupplyChain.ps1 -Path .\tests\samples\invisible-unicode-eval -ReportDir .\reports
```

検証は JSON の finding count と category を確認する簡易 script を用意してよい。  
ただし Pester は依存になるため v0.1.2 では使わない。

---

## 20. 実装フェーズ

### Phase 1: 最小動作

- BAT 4種
- `Scan-DevSupplyChain.ps1` 引数処理
- レポート出力
- safe file walker
- redaction
- invisible Unicode scan
- npm package / lifecycle script scan
- GitHub Actions scan

### Phase 2: 開発者端末対応

- VS Code / Cursor / Windsurf / VSCodium / Positron extension scan
- MCP / AI agent config scan
- secret inventory
- Python `.pth` / import hook scan

### Phase 3: 最新攻撃面対応

- Composer autoload scan
- artifact-only entrypoint scan
- known file hash scan
- endpoint telemetry
- IOC JSON optional load
- IOC freshness warning

### Phase 4: 品質改善

- sample tests
- README / limitations
- false positive tuning
- performance tuning
- local allowlist design

---

## 21. Codex 実装指示ドラフト

以下を Codex に渡す実装指示の正本とする。

```md
# Goal: Dev Supply Chain IOC Checker v0.1.2 dependency-free implementation

Windows 開発端末向けに、BAT ランチャー + PowerShell 単体で動くサプライチェーン IOC チェッカーを実装してください。

## 絶対条件

- 外部依存なし。
- Node.js / npm / npx / pnpm / yarn / bun / Python / pip / uv / poetry / composer / php / git / jq / yq を実行しない。
- ネットワーク通信しない。
- 読み取り専用。
- 削除、隔離、修復、uninstall、registry 変更、設定変更をしない。
- PowerShell は Windows PowerShell 5.1 互換を下限にする。
- BAT はランチャー専用。解析ロジックを書かない。
- 秘密情報の値をレポートへ出さない。

## 作成ファイル

- run-checker.bat
- scan-current-folder.bat
- scan-userprofile.bat
- scan-full.bat
- Scan-DevSupplyChain.ps1
- README.md
- docs/limitations.md
- tests/samples/*

## PowerShell 引数

- -Path
- -UserProfile
- -Deep
- -EndpointTelemetry
- -ReportDir
- -TextOut
- -JsonOut
- -MaxFileSizeMB
- -MaxFiles
- -EndpointDays
- -Quiet

## 実装する検査

1. 不可視 Unicode + decoder/eval 複合検査
2. npm/pnpm/yarn/bun manifest/lockfile/lifecycle script 検査
3. Python requirements/pyproject/poetry/uv/.pth/import hook 検査
4. Composer autoload 検査
5. GitHub Actions / local actions / dangerous workflow pattern 検査
6. Git hooks / Husky / workspace tasks 検査
7. VS Code / Cursor / Windsurf / VSCodium / Positron extension 検査
8. MCP / AI agent config 検査
9. secret file inventory。値は読まない/出さない
10. EndpointTelemetry。DNS cache, PowerShell history, Defender/Event logs, Run keys, Scheduled tasks

## 出力

- JSON report
- TXT report
- UTF-8 BOM
- DANGER/WARN/INFO/OK counts
- exit code: 0 OK/INFO, 1 WARN, 2 DANGER, 3 scanner error, 4 invalid arguments

## 注意

- YAML/TOML は完全 parse しない。pattern scan でよい。
- Access denied / decode failure / path too long は finding または limitation にして継続する。
- ReparsePoint は既定で追跡しない。
- node_modules/.venv/vendor は既定では targeted scan のみ。-Deep で広げる。
```

---

## 22. 運用手順

### 22.1 プロジェクト検査

```bat
scan-current-folder.bat
```

または対象フォルダをドラッグ & ドロップする。

```bat
scan-current-folder.bat C:\Users\<USER>\CodexProjects\azure-project
```

### 22.2 ユーザープロファイル検査

```bat
scan-userprofile.bat
```

### 22.3 フル検査

```bat
scan-full.bat C:\Users\<USER>\CodexProjects
```

### 22.4 DANGER が出た場合

1. 対象端末のネットワークを必要に応じて切り離す。
2. レポート、該当ファイル、mtime、hash を保全する。
3. GitHub / npm / PyPI / cloud / AI tool / SSH / CI/CD secret のローテーションを検討する。
4. 該当 workflow / package / extension / MCP 設定を人間が確認する。
5. 削除や reinstall は証跡保全後に行う。

### 22.5 WARN が出た場合

1. 誤検知の可能性を前提に該当ファイルを確認する。
2. 既知 IOC と照合する。
3. unpinned / lifecycle script / extension dependency / MCP command は、必要性を確認する。
4. 可能なら pinning / ignore-scripts / minimum release age / least privilege を検討する。

---

## 23. 限界

本ツールは以下を保証しない。

- 感染していないことの証明
- メモリ上の RAT / token theft の検出
- EDR / SIEM / forensic tool の代替
- npm audit / pip audit / Composer audit の代替
- 最新 IOC の自動取得
- YAML / TOML / lockfile の完全意味解析
- hidden ADS / raw disk forensic の検出
- browser password store / cookie theft の確認
- 端末全体の完全調査

本ツールは、**安全な初期スクリーニングと優先度付け**を目的とする。

---

## 24. 参照情報

2026-06-03 時点で設計根拠にした主な公開情報。

1. CrowdStrike, “Disrupting Glassworm: Inside CrowdStrike’s Takedown of a Developer-Targeting Botnet”, 2026-05-26.  
   https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/
2. Nx, “Postmortem: Nx Console v18.95.0 supply-chain compromise”, 2026-05.  
   https://nx.dev/blog/nx-console-v18-95-0-postmortem
3. GitHub Security Advisory, “Compromised Nx Console version 18.95.0”, GHSA-c9j4-9m59-847w.  
   https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w
4. Aikido Security, “Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens”, 2026-05-27.  
   https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens
5. Tenable, “Mini Shai-Hulud: Frequently asked questions about the TeamPCP npm and PyPI supply chain campaign”, 2026-05.  
   https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions
6. Aikido Security, “Supply Chain Attack Targets Laravel-Lang Packages with Credential Stealer”, 2026-05-23.  
   https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer
7. StepSecurity, “Laravel-Lang Supply Chain Attack: Every Tag Across Multiple Composer Packages Rewritten to Steal CI Secrets”, 2026-05-22.  
   https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack
8. SecurityWeek, “Over 5,500 GitHub Repositories Infected in Megalodon Supply Chain Attack”, 2026-05-25.  
   https://www.securityweek.com/over-5500-github-repositories-infected-in-megalodon-supply-chain-attack/
9. pnpm, “Mitigating supply chain attacks / minimumReleaseAge”.  
   https://pnpm.io/supply-chain-security
10. Microsoft Learn, “about_Execution_Policies”.  
   https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies

---

## 25. 最終結論

v0.1.2 は、依存なし方針を維持しながら、現在の開発者端末向けサプライチェーン攻撃に対して実用的な初期スクリーニングを行う設計である。

採用する実装形態は以下。

```text
BAT:
  起動専用。PowerShell を -NoProfile -NonInteractive で呼び出す。

PowerShell:
  静的解析本体。Windows PowerShell 5.1 互換。外部依存なし。

IOC:
  内蔵 baseline + 任意ローカル JSON。オンライン更新なし。

出力:
  JSON + TXT。UTF-8 BOM。DANGER/WARN/INFO/OK。

安全性:
  読み取り専用。秘密値非表示。修復なし。証跡保全優先。
```

この設計であれば、まず Phase 1 から Codex で実装に入ってよい。
