# Codex Appで Dev Supply Chain IOC Checker を作成させる方法 v0.1.1-reviewed

対象設計書: `dev-supplychain-ioc-checker-dependency-free-design-v0.1.2.md`

本書は、Codex Appで **BATランチャー + Windows PowerShell 5.1互換・依存なし静的スキャナー** を安全に実装させるための手順書です。

v0.1からの主な改善点:

- Codex App / AGENTS.md / Plan mode / approval・sandbox 設定に関する公式仕様との整合を再確認。
- 「Codex AppのGit UI・worktree機能」と「shell上でのgitコマンド実行禁止」を分離。
- AGENTS.mdが長くなりすぎて読み込み上限にかかるリスクを低減。
- CodexのMCP / plugin / browser / app toolを使わせない明示ルールを追加。
- 人間側の禁止コマンド確認コマンドをWindows PowerShell 5.1互換に修正。
- Phaseごとに「Codexが実行してよいコマンド」と「実行してはいけないコマンド」を明確化。
- Review専用スレッドと人間レビューの受け入れ基準を強化。

---

## 0. 厳格レビュー結果

### 0.1 v0.1手順書の評価

| 観点 | v0.1評価 | v0.1.1での対応 |
|---|---:|---|
| 一括実装を避ける設計 | 合格 | 維持 |
| Plan / Implementation / Review分離 | 合格 | 維持・強化 |
| AGENTS.md活用 | 合格寄り | 読み込み順・上限・override注意を追加 |
| 依存禁止 | 合格 | shell git / App Git UIの扱いを分離 |
| 秘密情報保護 | 合格 | Codex App側のMCP/plugin/browser使用禁止を追加 |
| PowerShell 5.1互換 | 要改善 | 受け入れチェックの`Select-String -Recurse`を修正 |
| Codex App権限設定 | 要改善 | approval / sandbox / trust確認を追加 |
| レビュー粒度 | 合格寄り | Blocking / Non-blocking / Accepted risk分類を追加 |
| 実ホスト走査防止 | 合格 | Phase 4と人間側手順をさらに明確化 |

### 0.2 Blockingだった改善点

v0.1では以下が曖昧だったため、本版で修正した。

1. **Codex AppのGit機能とshell git禁止が混ざっていた**  
   Codex Appのdiff/worktree/Git UIはレビュー補助として使ってよい。ただし、Codexにshellで `git clone` / `git pull` / `git fetch` / `git submodule update` / `git checkout` などを実行させない。

2. **Codexのサンドボックス外ツールへの注意が不足していた**  
   Codexのshell sandboxはshell toolに対する制御であり、MCPやplugin等の外部ツールは同じ前提で安全とは限らない。そのため、このプロジェクトではCodexにMCP / app plugin / browser / connector / web取得を使わせない。

3. **Windows PowerShell 5.1で動かない可能性がある受け入れコマンドがあった**  
   `Select-String -Recurse` は互換性上避け、`Get-ChildItem -Recurse -File | Select-String` 形式に変更する。

4. **AGENTS.mdが肥大化するリスクがあった**  
   CodexのAGENTS系指示には読み込み上限があるため、AGENTS.mdは安全制約と完了条件に絞り、詳細な設計・プロンプトはdocs配下に分離する。

5. **承認・サンドボックス設定の確認手順が弱かった**  
   作業開始前チェックリストに、プロジェクト信頼、承認設定、ネットワーク、MCP/plugin無効化、実ホストスキャン禁止を追加する。

---

## 1. 基本方針

今回の実装は、Codexに一括で丸投げしない。

以下の3種類のスレッドに分ける。

1. **Planスレッド**  
   設計書を読み、実装計画とファイル構成だけを作らせる。コード変更は禁止。

2. **Implementationスレッド**  
   Phase単位で実装させる。1回の作業範囲を小さくする。

3. **Reviewスレッド**  
   セキュリティ観点で差分レビューさせる。特に「実行禁止コマンド」「秘密情報出力」「読み取り専用違反」を確認する。

このツール自体がセキュリティ用途である。Codexに対象環境を不用意に実行・走査させると、証跡破壊、秘密情報露出、または感染済みpackage lifecycleの起動につながる可能性がある。

---

## 2. 推奨リポジトリ構成

新規フォルダを作る。

```text
C:\Users\<USER>\CodexProjects\dev-supplychain-checker
```

初期状態では以下だけ置く。

```text
dev-supplychain-checker/
  AGENTS.md
  docs/
    dev-supplychain-ioc-checker-dependency-free-design-v0.1.2.md
    codex-implementation-guide-v0.1.1-reviewed.md
```

Codexに最初から大量の既存プロジェクトを読ませない。まずは空に近い専用リポジトリで作る。

---

## 3. Codex App 作業前チェックリスト

Codex Appで作業を始める前に、以下を人間が確認する。

### 3.1 プロジェクト選択

- 作業対象は専用フォルダ `dev-supplychain-checker` にする。
- 既存の本番プロジェクトやユーザープロファイル直下をCodexの作業フォルダにしない。
- 可能なら作業開始時点で空に近いフォルダにする。

### 3.2 承認・サンドボックス

- Codexの承認設定は厳しめにする。
- Codexがshellコマンドを実行しようとしたら、コマンド内容を確認してから承認する。
- ネットワークアクセス、MCP、browser、plugin、connector、app toolはこのプロジェクトでは使わせない。
- Codexのshell sandboxは万能ではない。MCPや外部pluginは別の権限境界を持ち得るため、この実装では使わない。

### 3.3 Git / worktree の扱い

使ってよいもの:

```text
- Codex Appのdiff表示
- Codex Appのreview pane
- Codex Appのworktree分離
- 人間が確認するためのGit UI
```

Codexにshellで実行させないもの:

```text
- git clone
- git fetch
- git pull
- git submodule update
- git checkout 外部branch
- git remote add
- git push
- git commit
```

理由: 今回は依存なし・オフライン・読み取り専用のセキュリティツール実装であり、Codexが外部取得や履歴改変を行う必要がないため。

### 3.4 実行禁止コマンド

Codexには、実装中に以下を実行させない。

```text
npm
pnpm
yarn
bun
pip
python
node
git shell command
curl
wget
iwr
irm
Invoke-WebRequest
Invoke-RestMethod
Start-BitsTransfer
certutil -urlcache
bitsadmin
```

PowerShell自体は、スクリプトの構文確認と `tests/samples` に対するサンプル実行に限って許可する。

---

## 4. AGENTS.md

リポジトリ直下に以下を作成する。

> 注意: AGENTS.mdは短く、強い制約に絞る。長いプロンプトや設計詳細はdocs配下に置き、各タスクプロンプトで明示的に参照させる。

```md
# AGENTS.md

## Project

This repository implements a dependency-free Windows developer environment supply-chain IOC checker.

The final tool must be:

- A BAT launcher plus a PowerShell scanner.
- Compatible with Windows PowerShell 5.1.
- Dependency-free.
- Offline-only.
- Read-only.
- Safe for security triage.

## Non-negotiable safety rules

Do not add external dependencies.
Do not use npm, pnpm, yarn, bun, pip, python, node, curl, wget, iwr, irm, Invoke-WebRequest, Invoke-RestMethod, Start-BitsTransfer, certutil URL retrieval, or bitsadmin during implementation or tests.
Do not run shell git commands such as git clone, git fetch, git pull, git submodule update, git checkout, git push, or git commit.
Using the Codex App diff/review UI is allowed, but shell git commands are not allowed unless the human explicitly approves a specific command.
Do not use network calls.
Do not use MCP servers, app plugins, browser automation, connector tools, or remote file tools for this project.
Do not implement remediation, deletion, uninstall, token rotation, registry modification, quarantine, or cleanup features.
Do not print secrets, tokens, API keys, SSH private keys, environment variable values, or contents of auth files.
Do not run the scanner against the real user profile unless explicitly asked by the human.
Do not run EndpointTelemetry against the real host unless explicitly asked by the human.

## Allowed validation

You may run PowerShell parser checks and execute the scanner only against synthetic files under tests/samples or temp test directories created inside this repository.

Allowed examples:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples
```

Forbidden examples:

```powershell
.\Scan-DevSupplyChain.ps1 -UserProfile
.\Scan-DevSupplyChain.ps1 -EndpointTelemetry
npm test
pip install
python setup.py
node script.js
git clone https://example.com/repo.git
curl https://example.com
Invoke-WebRequest https://example.com
```

## Implementation standards

- Keep the implementation in a single main PowerShell file unless there is a strong reason to split.
- BAT files must be thin launchers only.
- Prefer static file parsing and regex scanning.
- YAML/TOML do not need full parsers; use safe line-based scanning.
- JSON may use ConvertFrom-Json with text fallback.
- Use targeted scanning for node_modules, .venv, and vendor; do not recursively read everything by default.
- Avoid junction/reparse-point loops.
- Skip likely binary files unless checking filename/hash metadata.
- Enforce maximum file size limits.
- Produce both TXT and JSON reports.
- Use DANGER / WARN / INFO / OK severity.
- Findings must include category, title, path, line if available, evidence, and recommendation.
- Redact user profile paths where practical.

## Done means

A task is complete only when:

1. The requested files are created or modified.
2. The tool remains dependency-free and offline.
3. The implementation does not violate the safety rules.
4. Synthetic tests or sample runs pass where applicable.
5. The final response includes changed files, validation commands, validation results, and any skipped validation with reason.
```

---

## 5. Planスレッドに投入するプロンプト

Codex Appでプロジェクトフォルダを開き、最初はPlan modeで以下を投入する。

```text
You are working in this repository:

dev-supplychain-checker

Read:
- AGENTS.md
- docs/dev-supplychain-ioc-checker-dependency-free-design-v0.1.2.md
- docs/codex-implementation-guide-v0.1.1-reviewed.md, if present

Goal:
Create an implementation plan for a dependency-free Windows supply-chain IOC checker.

Important:
Do not modify files yet.
Do not write code yet.
Do not use MCP, app plugins, browser automation, connector tools, or web/network access.
Do not run npm, pnpm, yarn, bun, pip, python, node, git, curl, wget, iwr, irm, Invoke-WebRequest, Invoke-RestMethod, Start-BitsTransfer, certutil URL retrieval, or bitsadmin.
Do not run EndpointTelemetry or UserProfile scans.

Plan requirements:
1. Summarize the required files.
2. Split implementation into small phases.
3. Identify high-risk implementation points:
   - PowerShell 5.1 Unicode handling
   - no secret leakage
   - JSON/TXT report generation
   - safe file enumeration
   - access denied handling
   - junction/reparse-point loop avoidance
   - targeted node_modules/.venv/vendor scanning
   - GitHub Actions static detection
   - MCP/AI agent config detection
   - UserProfile and EndpointTelemetry must remain opt-in only
4. Propose synthetic test samples.
5. Define what should be validated after each phase.
6. List commands you would like to run, but do not run them.

Return only:
- Implementation plan
- Task order
- Proposed validation commands
- Risks and mitigations
```

Planの出力を確認し、問題があれば修正指示を出す。ここでまだコードを書かせない。

---

## 6. Implementationスレッド Phase 0

```text
Implement Phase 0 only.

Read AGENTS.md first.

Scope:
- Create repository structure.
- Create README.md.
- Create docs/limitations.md.
- Create docs/codex-review-checklist.md.
- Create empty or minimal iocs/ JSON files.
- Create run BAT files as thin launchers.
- Create Scan-DevSupplyChain.ps1 skeleton with parameter parsing, report object, Add-Finding, redaction helpers, and Write-Reports.

Files to create:
- README.md
- Scan-DevSupplyChain.ps1
- scan-current-folder.bat
- scan-userprofile.bat
- scan-full.bat
- iocs/known-packages.json
- iocs/known-extensions.json
- iocs/known-files.json
- iocs/suspicious-patterns.json
- docs/limitations.md
- docs/codex-review-checklist.md
- tests/samples/.gitkeep

Constraints:
- Dependency-free.
- Offline-only.
- Windows PowerShell 5.1 compatible.
- BAT files must be launchers only.
- BAT files must not generate locale-dependent timestamps. Let PowerShell generate report paths when outputs are not specified.
- Do not implement actual detection logic yet except report skeleton.
- Do not run scans against the real user profile.
- Do not run EndpointTelemetry.
- Do not run npm/pnpm/yarn/bun/pip/python/node/git/curl/wget/iwr/irm/Invoke-WebRequest/Invoke-RestMethod.

Validation:
- Run only a PowerShell parser check or a safe sample invocation against tests/samples.
- Report exactly which command was run.
- If no validation was run, explain why.
```

確認ポイント:

- BATが薄いランチャーになっているか。
- `-NoProfile` が付いているか。
- `-ExecutionPolicy Bypass` がプロセス起動内だけか。
- `Set-ExecutionPolicy` を使っていないか。
- PowerShellが引数を受け取るだけで、まだ危険な走査をしていないか。
- report生成で秘密値を出す余地がないか。

---

## 7. Implementationスレッド Phase 1

```text
Implement Phase 1 only.

Read AGENTS.md first.

Scope:
- Safe file enumeration.
- Access denied handling.
- Max file size handling.
- likely-binary skip.
- reparse point / junction avoidance.
- invisible Unicode scanning.
- decoder/eval compound detection.
- TXT and JSON report output.
- Synthetic test samples for:
  - clean JS
  - invisible Unicode only
  - invisible Unicode + eval/Buffer.from

Constraints:
- Do not add dependencies.
- Do not use PS7-only syntax.
- Must work on Windows PowerShell 5.1.
- Do not recursively scan node_modules, .venv, or vendor by default.
- Do not print full suspicious lines if they may contain secrets. Evidence must be short and redacted.
- Do not run npm/pnpm/yarn/bun/pip/python/node/git/curl/wget/iwr/irm/Invoke-WebRequest/Invoke-RestMethod.

Validation:
- Run the scanner only against tests/samples.
- Confirm expected DANGER/WARN/OK output.
- Summarize findings and changed files.
```

確認ポイント:

- `U+E0100〜U+E01EF` のサロゲートペア検出がPowerShell 5.1互換か。
- 行番号が概ね出るか。
- 不可視Unicode単体はWARN、decoder複合はDANGERか。
- ファイル内容の過剰出力がないか。
- バイナリや巨大ファイルを読みすぎないか。

---

## 8. Implementationスレッド Phase 2

```text
Implement Phase 2 only.

Read AGENTS.md first.

Scope:
- npm/package manifest and lockfile static detection.
- package lifecycle script detection.
- Python manifest detection.
- .pth execution hook detection.
- Composer manifest/autoload detection.
- Known IOC matching using built-in defaults plus optional iocs/*.json.

Detection targets:
- package.json
- package-lock.json
- pnpm-lock.yaml
- yarn.lock
- bun.lock
- requirements.txt
- pyproject.toml
- poetry.lock
- uv.lock
- setup.py
- *.pth under targeted locations
- composer.json
- composer.lock
- vendor/composer/autoload_files.php

Known examples must include at least:
- litellm 1.82.7
- litellm 1.82.8
- axios 1.14.1
- axios 0.30.4
- plain-crypto-js 4.2.1
- @aifabrix/miso-client 4.7.2
- @iflow-mcp/watercrawl-watercrawl-mcp 1.3.0 through 1.3.4

Constraints:
- Static parsing only.
- Do not run npm/pip/python/node/git.
- JSON parse with ConvertFrom-Json where possible; fallback to text scanning.
- YAML/TOML/lockfiles can be line-based regex scanning.
- Do not read or print secrets.

Validation:
- Add synthetic compromised and clean samples.
- Run scanner only against tests/samples.
```

確認ポイント:

- lockfileだけで検出できるか。
- `package.json` scriptsの `preinstall` / `postinstall` / `prepare` が拾えるか。
- `.pth` の `import subprocess` / `exec` / `base64` / `os.environ` 複合をDANGERにできるか。
- Composerの `autoload.files` が拾えるか。
- IOC JSONが壊れていてもスキャナーが停止しないか。

---

## 9. Implementationスレッド Phase 3

```text
Implement Phase 3 only.

Read AGENTS.md first.

Scope:
- GitHub Actions / CI/CD static detection.
- Git hooks / Husky / VS Code tasks detection.
- MCP config detection.
- AI agent config detection.

Targets:
- .github/workflows/*.yml
- .github/workflows/*.yaml
- .github/actions/**
- .git/hooks/**
- .husky/**
- .vscode/tasks.json
- .vscode/settings.json
- mcp.json
- claude_desktop_config.json
- .cursor/**
- .claude/**
- .codex/**

DANGER examples:
- curl | bash
- iwr/irm/Invoke-WebRequest followed by powershell execution
- base64 decode followed by execution
- secrets.* sent to external URLs
- GitHub raw/gist/pastebin downloaded and executed

WARN examples:
- pull_request_target
- workflow_dispatch
- schedule
- contents: write
- packages: write
- id-token: write
- npm publish
- twine upload
- docker push
- unpinned npx/uvx MCP server

Constraints:
- No external parsers.
- Line-based YAML scanning is acceptable.
- Do not print secret values.
- Do not execute hooks or tasks.
- Do not run npm/pnpm/yarn/bun/pip/python/node/git/curl/wget/iwr/irm/Invoke-WebRequest/Invoke-RestMethod.

Validation:
- Add synthetic clean and malicious workflow samples.
- Add synthetic MCP config samples.
- Run scanner only against tests/samples.
```

確認ポイント:

- `pull_request_target` 単体はWARNで、外部実行やsecret送信複合はDANGERか。
- MCPの `npx package` 未固定がWARNか。
- `curl | bash` 系がDANGERか。
- `.codex/auth.json` の中身を読んだり表示したりしていないか。
- `.git/hooks` は実行せず、ファイル存在と内容パターンだけを読むか。

---

## 10. Implementationスレッド Phase 4

```text
Implement Phase 4 only.

Read AGENTS.md first.

Scope:
- VS Code-compatible IDE extension detection.
- UserProfile mode directory discovery.
- EndpointTelemetry mode skeleton and safe implementation.

IDE targets:
- %USERPROFILE%\.vscode\extensions
- %USERPROFILE%\.vscode-insiders\extensions
- %USERPROFILE%\.cursor\extensions
- %USERPROFILE%\.windsurf\extensions
- %USERPROFILE%\.vscodium\extensions
- %USERPROFILE%\.positron\extensions

Extension checks:
- package.json publisher/name/version
- extensionDependencies
- extensionPack
- activationEvents
- scripts.preinstall/postinstall/prepare
- *.node
- *.dll
- *.dylib
- *.so
- *.vsix

Known examples:
- specstudio.code-wakatime-activity-tracker
- floktokbok.autoimport
- autoimport-2.7.9
- quartz.quartz-markdown-editor 0.3.0
- nx-console 18.95.0

EndpointTelemetry:
- Implement only read-only checks.
- DNS cache check if available.
- PowerShell history check.
- Windows Defender log check if accessible.
- Startup folder listing.
- HKCU Run / RunOnce listing.
- Scheduled Tasks listing.
- PowerShell profile existence.
- Glassworm beacon IOC string/IP detection.

Safety:
- Do not run UserProfile or EndpointTelemetry validation automatically.
- Only verify these functions with synthetic paths where possible.
- Final response must explicitly say these modes were not run on the real host unless the human asked.
- Do not run npm/pnpm/yarn/bun/pip/python/node/git/curl/wget/iwr/irm/Invoke-WebRequest/Invoke-RestMethod.
```

確認ポイント:

- 実ユーザープロファイルを勝手に走査していないか。
- EndpointTelemetryを勝手に実行していないか。
- VS Code拡張package.jsonの読み取りだけで済んでいるか。
- native binaryは中身を実行せず、存在のみWARNにしているか。
- HKCU Run/RunOnceは読み取りのみか。

---

## 11. Reviewスレッドに投入するプロンプト

全Phase完了後、新しいCodexスレッドでレビューだけさせる。Codex Appに `/review` 相当のレビュー機能が使える場合は、未コミット差分レビューとして使う。ただし、以下のレビュー指示を追加する。

```text
Review the current repository for safety and correctness.

Do not modify files yet.
Do not run UserProfile scans.
Do not run EndpointTelemetry.
Do not use MCP, app plugins, browser automation, connector tools, or web/network access.
Do not run npm, pnpm, yarn, bun, pip, python, node, git, curl, wget, iwr, irm, Invoke-WebRequest, Invoke-RestMethod, Start-BitsTransfer, certutil URL retrieval, or bitsadmin.

Review focus:
1. Does the tool remain dependency-free?
2. Does the scanner avoid executing target project code?
3. Are BAT files only thin launchers?
4. Are secrets never printed to TXT/JSON reports?
5. Is PowerShell 5.1 compatibility preserved?
6. Are Unicode checks implemented safely, including variation selector supplement handling?
7. Are large files, binary files, access denied errors, and reparse points handled safely?
8. Is node_modules/.venv/vendor scanning targeted by default?
9. Are UserProfile and EndpointTelemetry modes opt-in only?
10. Are DANGER/WARN/INFO/OK categories reasonable and not overclaiming infection certainty?
11. Are shell git commands absent from implementation and validation steps?
12. Are network retrieval commands absent from implementation and validation steps?
13. Are Codex/Claude/Cursor/Windsurf auth/config files never printed in report evidence?

Return:
- PASS/FAIL for each item.
- Blocking issues.
- Non-blocking issues.
- Accepted risks.
- Suggested minimal patches.

Do not change files unless I explicitly approve the patch phase.
```

レビューでBlocking Issueが出たら、修正は差分だけ依頼する。

---

## 12. 修正依頼テンプレート

Codexのレビュー結果に対しては、全文再掲ではなく差分だけ渡す。

```text
Apply only the following fixes.

Fixes:
1. <具体的な修正1>
2. <具体的な修正2>
3. <具体的な修正3>

Constraints remain unchanged:
- dependency-free
- offline-only
- read-only
- no external commands except PowerShell running this script against tests/samples
- no shell git commands
- no network calls
- no MCP/app plugins/browser/connector tools
- no secret output
- no UserProfile/EndpointTelemetry scan unless explicitly asked

After patching:
- Run only the relevant synthetic sample tests.
- Summarize changed files and validation results.
```

---

## 13. 人間側の受け入れチェック

Codex実装後、人間側で以下を見る。

### 13.1 ファイル構成

```text
README.md
AGENTS.md
Scan-DevSupplyChain.ps1
scan-current-folder.bat
scan-userprofile.bat
scan-full.bat
iocs/*.json
docs/*.md
tests/samples/**
```

### 13.2 禁止コマンド確認

Windows PowerShell 5.1互換の形で文字列検索する。

```powershell
$patterns = @(
  'npm','pnpm','yarn','bun','pip','python','node',
  'git clone','git fetch','git pull','git submodule','git push','git commit',
  'curl','wget','Invoke-WebRequest','Invoke-RestMethod','iwr','irm',
  'Start-BitsTransfer','certutil','bitsadmin'
)

Get-ChildItem -Path . -Recurse -File -Force |
  Where-Object {
    $_.FullName -notmatch '\\.git\\' -and
    $_.FullName -notmatch '\\reports\\' -and
    $_.Length -lt 5MB
  } |
  Select-String -Pattern $patterns -CaseSensitive:$false
```

ただし、README、AGENTS.md、docs内の「禁止例」として出てくる分は問題ない。PowerShell本体の実行ロジック、BAT、テストスクリプトに実行用途で含まれていないかを見る。

### 13.3 PowerShell構文チェック

```powershell
$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\Scan-DevSupplyChain.ps1),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors
```

`$errors` が空であることを確認する。

### 13.4 サンプル実行

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples
```

確認すること:

- TXTレポートが出る。
- JSONレポートが出る。
- clean sampleがOKまたはINFO止まり。
- malicious synthetic sampleが期待通りWARN/DANGERになる。
- 秘密値らしき文字列がレポートに出ない。

### 13.5 実プロジェクトへの初回実行

最初はDeepなし。

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path "C:\Users\<USER>\CodexProjects\azure-project"
```

DANGERが出た場合は、削除ではなく証跡保全、該当ファイル確認、トークン・認証情報のローテーション判断に進む。

### 13.6 UserProfile実行

サンプルで十分確認してから実行する。

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -UserProfile
```

### 13.7 EndpointTelemetry実行

重い場合があるため、最後に実行する。

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -EndpointTelemetry
```

---

## 14. Codexに一括で任せてはいけないこと

以下はCodexに任せない。

```text
実PCのUserProfileスキャン実行
EndpointTelemetryの実ホスト実行
検出結果に基づく削除・隔離・修復
トークンローテーション
GitHub/npm/PyPI/クラウド認証情報の実操作
ネットワーク経由のIOC自動取得
npm audit / pip audit の実行
未知プロジェクトでの npm install / pip install / python 実行
GitHubからのclone/fetch/pull/submodule update
MCP/plugin/browser/connectorによる外部情報取得
```

これらは人間判断で行う。

---

## 15. 推奨完了基準

v0.1実装の完了条件:

```text
- BATランチャーが3種類ある
- PowerShell 5.1で起動できる
- 外部依存がない
- ネットワーク通信がない
- 対象プロジェクトのコードを実行しない
- shell gitコマンドを実行しない
- 不可視Unicode検査がある
- npm/Python/Composer/GitHub Actions/MCP/IDE拡張の静的検査がある
- TXT/JSONレポートが出る
- 秘密値を出力しない
- tests/samplesでDANGER/WARN/OKの期待結果を確認できる
- READMEに限界とDANGER時の対応が書かれている
- ReviewスレッドでBlocking Issueがない
```

v0.1では、完全なEDRや感染確定判定は目指さない。目的は、読み取り専用の安全な初期スクリーニングと優先度付けである。

---

## 16. Codexへ渡す最初の一文テンプレート

迷ったら、各Phaseの最初に必ず以下を付ける。

```text
Before doing anything, read AGENTS.md. Confirm that you will not use network access, MCP/tools/plugins/browser, shell git commands, npm/pip/python/node, or real UserProfile/EndpointTelemetry scans. Then proceed only with the requested phase.
```

---

## 17. 参考情報

- OpenAI Codex App documentation: https://developers.openai.com/codex/app
- OpenAI Codex best practices: https://developers.openai.com/codex/learn/best-practices
- OpenAI AGENTS.md guide: https://developers.openai.com/codex/guides/agents-md
- OpenAI Codex configuration reference: https://developers.openai.com/codex/config-reference
- OpenAI engineering note on Codex agent loop and tool/sandbox context: https://openai.com/index/unrolling-the-codex-agent-loop/
