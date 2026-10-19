# IT初心者向け 使い方マニュアル

対象バージョン: **0.1.27**。更新日: **2026-10-16**。

v0.1.27では `Findings by severity` に重大度別件数も表示します。`ConfigReview=153` は分類の件数で、WARNが153件という意味ではありません。重大度、`Execution`、`Completion` をそれぞれ確認します。メニュー3・4・5は現在フォルダ内の用途別検査と共通のUnicode／IOC検査を行います。

自己テストの目印4件は、同梱ファイルの正確なパス・内容ハッシュ・ルールが一致した場合に `SCANNER_TEST_MARKER_REFERENCE` のINFOになります。変更されたファイル、外部コピー、ほかの実行・送信パターンは通常どおり検査します。正規表現の2秒上限を保ち、ローカルIOCのタイムアウト後も後続ルールを続け、未完了部分を記録します。MCP解析はノード8,192、深さ32、断片256、抽出文字65,536を上限とし、上限到達やコマンドを含む不正JSONはWARNと未完了理由になります。

ファイル件数は各カウンター内の重複を除いたパス数です。再訪回数は `fileEnumerationEvents` と `fileSkipEvents` に分けます。キュー投入前の除外もあるため、`queued = scanned + skipped` とは限りません。検証済みサンプルの目印は子プロジェクト数・予算に含めず、未知・改変ファイルは対象に残します。

時刻と経過時間の起点をそろえ、`performance.slowActivities` に遅い読み取り・ファイル処理・解析の上位20件を記録します。合計には `partition=true` の活動だけを使います。実PCの速度は再測定していません。IOC基準は2026-10-06です。読み込んだレポートを `$r` とした場合は次で確認できます。

```powershell
$r.summary
$r.coverage.summary.nextActions | Format-List
$r.performance.slowActivities | Format-Table activity, elapsedMs, path -AutoSize
```

v0.1.26は、正規表現の定義と実際の外部取得・実行を同じPowerShellファイル内で区別します。構文解析には元ソースを使うため、検査用の文字列を除いた結果が構文エラーになっても、それを元ソースのDANGER判定には使いません。プラグインキャッシュに同梱されたCI設定は、有効化不明の参考情報としてINFOになります。有効なプロジェクトのCI権限は引き続き確認します。

`_cacache\content-v2` の本文は、`npm-cache`・`.npm-cache`・独自のキャッシュ配置を問わず列挙・解読しません。`cacheBlobDirectoriesSkipped` は除外したディレクトリ数で、中のファイル数を推定した値ではありません。その構造の外にある通常のソースは検査します。メニューの番号・範囲・確認操作、重大度・終了コード、IOCの2026-10-06基準は変わりません。

v0.1.25では、検出の重大度と実行状態を分けて表示します。Ctrl+Cで中断した場合、保存できたレポートは `Execution: interrupted` と `Completion: INTERRUPTED` になります。JSONは `executionStatus=interrupted`、`completionStatus=incomplete-critical`、`scanComplete=false` です。未着手の検査は `not-started` と表示し、対象が見つからなかった検査と区別します。

正規表現だけを扱う通常の検査用文字列も精査して誤検知を減らします。圧縮データは小さい形式判定の後に本文解析を省略し、INFOへ集約します。プラグインキャッシュ内のMCP設定は、有効化を確認していないことを明示します。`@latest` などの未固定指定はCAUTIONとして残り、実際の取得・実行や秘密情報送信を示す複合パターンは引き続き検査します。IOC基準日は2026-10-06のままです。

v0.1.24は、検査用文字列や変更予定のデータを実際の危険処理と誤認しにくくします。確認できた受動的な検査用文字列はINFOとして根拠を残します。未知の消費先・動的実行・不正な構文は通常の検出対象です。INFOへの分類は、そのファイル全体の安全性を保証しません。

未完了の確認では `coverage.candidateFailures` と `coverage.directoryFailures` の `failureType` を見ます。`file-in-use` は他の処理による占有、`access-denied` は読取権限不足、`path-too-long` は実際の例外原因に基づく長いパス、`path-not-found` は消失・不存在、`io-error` はその他のI/O失敗です。補助情報は `exceptionTypes` と `hresults` に入り、例外メッセージや本文は出しません。サイズ・正規表現の上限も引き続き記録します。非重大の読取失敗や依存関係・キャッシュの検査上限でも `scanComplete=false` とPARTIALを表示します。対象を絞って原因を確認し、必要に応じて再検査してください。

このマニュアルは、Windowsで `Dev Supply Chain IOC Checker` を使うための初心者向け手順です。

このツールは、開発用フォルダの中に「危険そうな設定やファイルの痕跡」がないかを静的に確認します。ファイル削除、修復、ネットワーク通信、外部ダウンロードは行いません。

v0.1.23は2026-10-06にレビューした追加IOC、native build/runtime経路、Pythonのインストール済みメタデータを確認します。Pythonの短縮バージョン表記を正しく照合し、OCRデータや署名ファイルはハッシュ検査後にbinaryとして扱います。IOCは同梱されたオフライン基準であり、実行時に最新版を取得しません。

## 1. まず知っておくこと

- このツールは「感染しているかを確定する道具」ではありません。
- 検出がなく `complete` でも、PCやリポジトリが安全だと完全に証明するものではありません。
- 結果は「確認すべき場所の候補」です。
- `DANGER` が出ても、すぐにファイルを削除しないでください。
- `tests/samples` は検証用の作り物ファイルです。ここをスキャンすると警告が出るのは正常です。
- ユーザープロファイルや端末ログを見るモードは、明示的に選んだ時だけ動きます。

## 2. 一番簡単な使い方

1. このフォルダをエクスプローラーで開きます。
2. `run-checker.bat` をダブルクリックします。
3. 別の開発プロジェクトを調べる場合は、`2` を入力します。
4. 対象フォルダのフルパスを入力し、探索方法は `1. Recommended traversal` を選びます。
5. スキャンが終わるまで待ちます。
6. `reports` フォルダに結果ファイルが作成されます。

`1` は「起動時の現在作業フォルダ」を調べます。BATをダブルクリックした場合は、このチェッカー自身のフォルダになることがあります。別プロジェクトは `2` で明示してください。`3`・`4`・`5`・`8` も現在作業フォルダが対象です。

PowerShell 7のターミナルからBATを起動しても構いません。BATはWindows PowerShell 5.1の `powershell.exe` を使うため、`pwsh.exe` のバージョンとは別です。通常のプロジェクト検査は一般ユーザーで始め、アクセス拒否が出たらレポートの未検査範囲を確認してください。

配布されたツールを使う時は、展開したフォルダの中にある `run-checker.bat` から起動してください。`Scan-DevSupplyChain.ps1` だけを別フォルダへコピーして実行すると、レポートには `distributionStatus` の警告が出ます。これは動作停止ではありませんが、検証用サンプル除外やIOCデータの出所確認が分かりにくくなるため、通常利用では推奨しません。

## 3. メニューの意味

`run-checker.bat` を起動すると、次のような選択肢が出ます。

```text
1. Recommended project scan - current folder
2. Scan selected path - choose folder, then Recommended or Deep
3. Package / Node runtime risks - current folder
4. AI / MCP / IDE config risks only - current folder
5. CI/CD and hooks risks only - current folder
6. npm global/cache static check - PC metadata; confirm
7. Major PC locations scan - PC folders/profile; confirm
8. Custom checks for current folder - advanced
9. Comprehensive bounded scan (target + major locations + profile + endpoint) - confirm
10. Exit
```

各項目の意味は次の通りです。

| 番号 | 用途 | 初心者向けおすすめ |
|---:|---|---|
| 1 | 起動時の現在作業フォルダを推奨設定で調べる | 対象が現在作業フォルダの場合 |
| 2 | フルパスで指定したフォルダを調べる | 別プロジェクトを調べる時はこれ |
| 3 | package.json、lockfile、明示されたNode.jsバージョンと不可視Unicodeを調べる | 依存とNode.jsを見たい時 |
| 4 | AI/MCP設定、IDE拡張、不可視Unicodeを調べる | AIツール設定が心配な時 |
| 5 | GitHub Actions、hooks、不可視Unicodeを調べる | CI/CDだけ見たい時 |
| 6 | npm global/cache を静的に調べる | 必要な時だけ。実行前に確認あり |
| 7 | PC内の主要な開発関連場所だけを調べる | 不安な時に使う |
| 8 | 現在フォルダ用の検査種類を組み合わせる | 詳しい人向け。実PC範囲は追加しない |
| 9 | 指定フォルダ、主要な開発場所、ユーザー設定、端末ログをまとめて調べる | 管理者や詳しい人と一緒に |
| 10 | 終了 | 終わる時 |

`6`、`7`、`9` は実PCの情報を読むため、実行前に `YES` と入力する確認があります。

## 4. パソコンの主要箇所だけを調べる場合

メニューで `7. Major PC locations scan` を選ぶと、パソコン全体を総当たりせず、攻撃で狙われやすい主要な場所だけを確認します。

主な対象は次のような場所です。

```text
%USERPROFILE%\CodexProjects
%USERPROFILE%\Projects
%USERPROFILE%\source\repos
%USERPROFILE%\repos
%USERPROFILE%\dev
%USERPROFILE%\workspace
%USERPROFILE%\Documents\GitHub
%USERPROFILE%\GitHub
%USERPROFILE%\Documents\Projects
%USERPROFILE%\Desktop\GitHub / Projects / repos
%USERPROFILE%\IdeaProjects / PyCharmProjects / AndroidStudioProjects などの主要IDE既定プロジェクトフォルダ
`USERPROFILE` 配下の子ディレクトリとして検証できた OneDrive / OneDriveCommercial / OneDriveConsumer にある GitHub / Projects / Documents / Desktop の限定サブフォルダ
VS Code / Cursor / Windsurf などの拡張機能と、ユーザー領域のJetBrainsプラグイン
既知の配置にあるNode.js実行ファイルのバージョン情報
npm global package の静的メタデータ
Claude / Cursor / Codex / Continue / Gemini / OpenCode などのAIエージェント設定
Codex の設定、agents、rules、skills、導入済みプラグインの実行コード（`.codex\sessions`、実行時cache、履歴データは除外）
認証ファイルの存在確認
```

このモードは `C:\` 全体を調べません。`C:\Windows` や `Program Files` を丸ごと調べるものでもありません。

このツール自身の `tests/samples` は検証用の作り物なので、Major PC locations scanでは現在実行中の正規manifestと一致した既知ファイルだけを除外します。

端末ログ、DNSキャッシュ、イベントログなどは含みません。それらまで見る場合は `9. Comprehensive bounded scan` を使います。

9番は、指定フォルダに加えて7番の主要開発場所、ユーザー領域のAI/IDE設定、npm global/cache、既知配置とPATH上のNode.jsメタデータ、端末テレメトリをまとめます。ただし、ディスク全体の総当たりでもDeep走査でもありません。`node_modules`、build、cacheの中身を再帰的に確認する必要がある場合は、信頼できる対象プロジェクトに対して2番のDeepを別に実行してください。

また、Major PC locations scanでは `%USERPROFILE%\.config` 全体のような広い設定フォルダや、Codex のセッション履歴・実行時キャッシュは対象外にしています。必要な場合は、詳しい人と一緒にコマンドの `run-checker.bat userprofile` を使ってください。`CODEX_HOME`、`CLAUDE_CONFIG_DIR`、OneDrive系の自動探索ルートは、`USERPROFILE` 配下にある絶対パスの非reparse子ディレクトリだけを受け入れます。範囲外の値は警告してスキップするため、正当な外部配置は `-Path` で明示的に検査してください。既知の認証ファイルは存在確認だけで本文を読みませんが、それ以外の対象設定テキストは静的検査のために読み、レポート証拠は中央で伏せ字化します。レポートの `scanRoots` には、ユーザープロファイル全体を示す `~` ではなく、実際に存在して検査対象になった設定・拡張機能・ツールのルートだけが記録されます。

## 5. 別のフォルダを調べたい場合

メニューで `2` を選ぶと、調べたいフォルダのパスを入力できます。

例:

```text
C:\Users\yourname\Projects\my-project
```

パスが分からない場合は、まず対象フォルダをエクスプローラーで開いて、アドレスバーの内容をコピーしてください。

パス入力後は、通常の `Recommended` と `Deep` を選べます。最初は `Recommended` を選んでください。`Deep` は通常除外する `node_modules`、`.venv`、`vendor`、build、cacheの内部まで入るため時間とレポート量が増え、実行前に `YES` が必要です。Deepでもファイルは実行せず、認証ファイル本文、VCS、junction/reparse point、このツール自身のreportsは保護されます。

親フォルダを指定した場合は、深さ4まで（Deepは深さ8まで）の子プロジェクトを安全な上限内で探し、それぞれのnpm、Python、Composer依存環境へ限定検査を行います。依存検査は `min(10,000, floor(MaxFiles * 0.5))` 件までとし、見つかった子プロジェクトへ公平に配分したうえで、1プロジェクト当たり2,000件を上限にします。巨大な一部の `node_modules` が親フォルダ検査を占有せず、通常ソース、CI/CD、AI設定用に少なくとも半分の枠を残します。依存内容をさらに広く読む場合は、そのプロジェクト単体を指定するか、信頼できる1プロジェクトに対してDeepを選んでください。

長い検査では、既定で約30秒ごとに簡潔な `progress` 行を表示します。表示内容は、伏せ字化したプロジェクトルート、重複を除く検査対象数 `queued`、本文の静的検査数 `scanned`、経過時間 `elapsed` です。個々の現在ファイルや1 MiB以上のファイルの各検査段階、`slow step completed` は通常表示しません。原因調査時だけ `Scan-DevSupplyChain.ps1` へ `-VerboseProgress` を指定すると、従来の約5秒間隔の詳細表示へ切り替わります。`-Quiet` は進捗をすべて抑止します。検出位置の行番号は64 KiB単位で計算し、大きな生成済み・minify済みファイルでも1文字ずつのPowerShellループを行いません。`MaxFiles` または依存検査用の予約枠に達した場合は、該当する残りの探索を停止し、レポートに範囲不足を記録します。

ファイル本文に対する各正規表現処理には、.NET APIで明示的に2秒のタイムアウトを設定します。これはスキャン全体の制限時間ではなく、1回の正規表現処理ごとの上限です。高負荷な入力では `regex timeout` と `REGEX_SCAN_TIMEOUT` を記録し、他の検査とファイルを続行します。タイムアウトした処理を含む検査ステップの残りも省略される場合がありますが、runtimeコードの秘密情報取得サブルールでは、その後の取得・実行パターン検査を続けます。該当ルール／ステップは未完了のため、結果は `complete` にはなりません。非重大候補なら `partial-non-critical`、lockfileや有効な設定などの重大候補なら `incomplete-critical` になります。表示やレポートに対象ファイル本文は含めません。対象ファイルとルールを確認してください。同じタイムアウトは、フォルダを絞るだけでは直らない場合があります。

## 6. 検査種類を選びたい場合

v0.1.9 以降は、リスク別に検査を選べます。

| 表示 | 主な対象 |
|---|---|
| Recommended | 通常のおすすめ。プロジェクト内の依存関係、明示Node.jsバージョン、Unicode、CI/CD、AI/MCP、IDE、hooks、認証ファイル存在確認 |
| Packages | package.json、lockfile、既知パッケージIOC、最近のインシデント名の参考情報 |
| LifecycleScripts | install script、packageのmain/exports/bin、.pth、setup.py など、インストール時や読み込み時に動く可能性がある静的テキスト |
| NodeRuntime | `.nvmrc`、Volta、Docker、setup-nodeなどの明示バージョンと、主要モードでは既知配置の`node.exe`メタデータ。Node.js自体は実行しない |
| CiCd | GitHub Actions などの workflow |
| AiMcp | Codex、Claude、Cursor、Windsurf、MCP などのAI/agent設定 |
| IdeExtensions | VS Code互換拡張とJetBrainsプラグインの metadata、限定スクリプト、native artifact候補 |
| NpmGlobal | npm global package の候補パスを静的に読む。`npm root -g` は実行しない |
| NpmCache | npm cache metadata の候補パスを静的に読む。`npm cache ls` は実行しない。cache blob は読まない |

初心者は、通常は `Recommended` のままで十分です。

メニュー `8` は現在フォルダ内の個別checkだけを組み合わせます。`NpmGlobal`、`NpmCache`、`MajorRecommended`、`AllSafe` のように実PC側へ範囲を広げる指定は受け付けません。npmや主要PC範囲を確認する場合は、実行前確認のある `6`、`7`、`9` を使ってください。メニュー `3`、`4`、`5` では、それぞれの用途固有checkに加えて不可視Unicode／GlassWorm検査を横断的に実行します。

GitHubリポジトリを確認したい場合、このツールはGitHubから取得しません。ユーザーが承認済みの方法でローカルに用意したフォルダを `2. Scan selected path` で指定してください。

## 7. レポートの場所

スキャン結果は `reports` フォルダに作成されます。

例:

```text
reports\dev-supplychain-report-20260603-134138.txt
reports\dev-supplychain-report-20260603-134138.json
```

初心者は、まず `.txt` の方を開いてください。メモ帳で読めます。

`.json` は機械処理や詳しい調査向けです。

設定されたレポート出力先（既定は `reports/`）と現在のTXT/JSON出力ファイルは、通常スキャンでは除外されます。現在の出力を危険として再検出せず、`reports-service` のような無関係なソースフォルダは隠しません。

ただし、`-Path .\reports` や `-Path .\reports1` のように明示指定した場合は、調査目的としてスキャンできます。

Gitが既定で除外するのはリポジトリ直下の `/reports/` だけです。独自名や過去のレポートフォルダはcommit前に明示的に確認し、公開リポジトリや配布物へ含めないでください。

## 8. 結果の見方

レポートの上の方に、次のようなまとめがあります。

```text
OverallResult: CAUTION
Completion: COMPLETE; ScanComplete=True

[SUMMARY]
DANGER: 0
WARN:   0
CAUTION: 2
INFO:   5
OK:     1
```

意味は次の通りです。

| 表示 | 意味 | どうするか |
|---|---|---|
| OK | 大きな問題候補は見つからなかった | 通常はそのままでよい |
| INFO | 参考情報 | 必要なら確認 |
| CAUTION | 単独では低信号だが確認を勧める存在・機能・設定 | 種類と実行条件を確認する |
| WARN | 不審パターン、既知リスク、設定上の弱点、重要な検査制限 | 種類と理由を優先して読む |
| DANGER | 強く確認すべき候補 | 削除せず、詳しい人に相談 |

`DANGER` は「感染確定」ではありません。ただし、優先して確認すべきサインです。特に `RiskType` が `known-ioc` や `active-exfil` の場合は、既知の危険な目印、または秘密情報を外へ送るように見える強い候補です。

Node.jsの脆弱性では、公式情報の `Critical` / `High` と、このツールの判定 `WARN` / `INFO` を分けています。バージョンが対象範囲に入るだけでは実際に攻撃可能とは限らないため、インストール済みメタデータや明示pinは`WARN`、`engines.node`のconstraintは`INFO`です。v0.1.21以降、端末とTXTでは `Node.js installed` と `Node.js project refs` が別々に表示されます。Dockerfileの古い指定が見つかっても、グローバルNode.jsが古いという意味ではありません。

JSONの `nodeRuntimeAssessment` では、`installedBinaries` と `projectReferences` を分け、正確に評価できたバージョンを秘匿済みパスとともに最大100件記録します。`notAffected` は「同梱されたオフライン基準に一致しなかった」という意味だけです。全CVE、EOL、電子署名、発行元の真正性まで安全と保証するものではありません。脆弱性に一致した項目のCVEと修正版候補は、従来どおり `NODE RUNTIME SUMMARY` と `nodeRuntimeSummary` で確認できます。

`CAUTION` は、ライフサイクルスクリプトの存在、単独の不可視文字、悪性複合条件のないWASM読込機能などに使います。`WARN` は、C2に似た文字列、decoder signature、変更可能な外部参照など、優先度が一段高い調査候補です。どちらも感染確定ではなく、終了コードは互換性維持のため `1` です。

### CAUTIONが多い場合の精査

件数だけで判断せず、まず完了状態とIOCの状態を確認し、DANGER/WARNを優先します。CAUTIONは種類ごとにまとめてから、各findingの `Path`、`Evidence`、`Recommendation` を読みます。

JSONレポートをPowerShellで整理する例です。`$reportPath` の右辺を実際のJSONファイルのパスへ置き換えます。対象プロジェクトのコードは実行しません。

```powershell
$reportPath = 'C:\Path\To\dev-supplychain-report.json'
if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
  throw '指定したJSONレポートが見つかりません。'
}
$r = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 -ErrorAction Stop |
  ConvertFrom-Json -ErrorAction Stop
$r | Select-Object executionStatus, scanComplete, completionStatus
$r.execution.phases | Select-Object name, status, elapsedMs
$r.findingClassSummary
$r.iocData | Select-Object releaseReady, staleCount, missingCount, invalidCount
$r.findings | Where-Object severity -eq 'CAUTION' |
  Group-Object category | Sort-Object Count -Descending | Select-Object Count, Name
$r.findings | Where-Object severity -eq 'CAUTION' |
  Select-Object category, title, path, line, evidence, recommendation | Format-List
```

| 種類 | 静的に確認する内容 |
|---|---|
| install等のライフサイクルスクリプト | `package.json` の宣言、呼び出すファイル、実行条件、外部取得や秘密情報の読取・送信を確認します。`sharp`などのnative依存ではソースビルドが条件付きの場合があります。宣言の存在だけでは、そのPCで実行された証拠になりません。 |
| WASM読込やdecoder機能 | 正常なライブラリにもある機能です。実際のentrypointから到達するか、周囲にプロセス起動・外部取得・秘密情報送信があるかを読みます。 |
| 単独の不可視文字 | README・絵文字・テストデータなのか、実行ファイル内のdecoderや実行処理と結び付いているかを確認します。 |
| 設定・ツールの能力 | 手動workflow、参考文書、有効なAI/MCP設定を区別し、提供元、用途、実際に有効な設定を確認します。 |

確認結果はfindingごとに「通常機能と根拠を確認」「追加調査が必要」「別プロジェクトで対応」に分け、対象パスと根拠を手元の記録へ残します。正常なパッケージ名だけで自動除外せず、調査のためにinstall/build、`node`、`python`、hookを実行しないでください。アクセス拒否は空フォルダの証拠ではありません。`coverage.summary` と未検査パスを確認し、必要な範囲だけを許可して再検査します。

### 完了状態の読み方

最初に `executionStatus` を確認します。`completed` は予定フェーズの処理が戻ったことを示し、サイズ上限などのため `scanComplete=false` の場合もあります。`interrupted` は中断、`error` は処理失敗です。`execution.unfinishedPhases` と各 `phase.status` で、未着手・中断・失敗の範囲を確認します。`checkStats` の `enabled=true` だけで検査済みとは判断せず、`executionStatus` も見てください。

| `completionStatus` | 意味と対応 |
|---|---|
| `complete` | 選択した境界内の予定検査が完了。PC全体・全依存物の安全保証ではありません。 |
| `partial-non-critical` | 明示的に非重大とした処理または境界内解析の一部が未完了。`coverage.summary` と制限findingを確認します。 |
| `incomplete-critical` | 中断による未実施、または重要範囲の未列挙・読取・解析不能があります。陰性結果として扱わず、未完了の範囲を確認します。 |
| `error` | スキャナーまたはレポート処理が失敗。陰性結果として利用しません。 |

Ctrl+Cは中断操作です。PowerShellが終了処理を行えた場合にTXT/JSONを保存します。ウィンドウを閉じる・プロセスを終了する操作では保存を保証できません。`execution.startedAt`・`finishedAt`・`elapsedMs` は実行時刻と処理時間、`queuedFilesUnprocessed` は列挙済みの未処理ファイル数です。まだ列挙していない範囲の件数は分かりません。中断時は未実施の検査を「検出なし」と解釈しないでください。

`findingClassSummary` は、重大度とは別に所見を「根拠のある指標・挙動」「脆弱性バージョン照合」「設定確認」「機能」「検査制限」「参考情報」へ集計します。WARNの検査制限と不審な挙動を区別し、件数を感染数として扱わないでください。`REGEX_SCAN_TIMEOUT` には本文を含まない `ruleId` と処理時間が入り、`performance.steps` で遅い検査を確認できます。同じファイルのタイムアウトは、フォルダを絞るだけでは解消しない場合があります。

v0.1.26の `coverage.summary.nextActions` は、サイズ超過・正規表現タイムアウト・依存関係の上限など、同時に発生した理由をすべて案内します。各項目に理由・件数・代表パス・対処が入り、従来の `nextAction` にもまとめた文章を残します。読み込んだJSONを `$r` とした場合は次で確認できます。

```powershell
$r.coverage.summary.nextActions | Format-List reason, count, paths, action
$r.performance.activities | Format-Table activity, attempts, elapsedMs, maxElapsedMs, partition
$r.performance.slowSteps | Format-Table step, elapsedMs, timedOut, path -Wrap
```

計時の `Enumeration` は列挙、`ProjectDiscovery` は子プロジェクト探索、`TargetSelection` は依存候補選択、`Reading` は本文の読み取り・解読、`FileProcessing` はファイルごとの処理です。`partition=true` の項目は重複せず、合計が `partitionElapsedMs`、それ以外の実行時間が `otherElapsedMs` です。`Reading` と個別検査の `steps` は内訳に含まれるため、合計へ再加算しません。レポート整形・書き込み時間は計時対象外です。`slowSteps` は2秒以上かかった検査のうち遅い順に最大20件を保存し、プロファイルパスを伏せ、本文・正規表現を含めません。分類・構文・文字列マスクの再利用と検査呼び出しの削減で高速化していますが、実PCでの短縮率は対象によって変わります。

## 9. このチェッカーでできないこと

このチェッカーは、次のことはできません。

- ディスク全体、全依存物・build・cache、全archive、任意のbinary内部を漏れなく検査する
- メモリ、実行中process、実際の通信、cloud活動、remote logを調べる
- 全CVE・全依存関係を監査し、package・publisher・拡張機能・binaryの真正性を証明する
- スキャン中にregistry評判や最新IOCをオンライン取得する
- 静的な文字列が実際に実行されたこと、または悪性であることを確定する
- 未検出の侵害が存在しないと保証する、または修復・削除・隔離・credential rotationを行う

`DANGER` は優先確認候補であり感染確定ではありません。`DANGER` がないことも、安全の証明ではありません。

## 10. `tests/samples` の警告について

このプロジェクトには、ツールの動作確認用に `tests/samples` があります。

ここには、危険なパターンを検出できるか確認するための「作り物のテキストファイル」が入っています。

- ダウンロードしたマルウェアではありません。
- 実行するためのファイルではありません。
- 偽のURLや偽のトークン文字列が入っています。
- ここをスキャンすると `CAUTION`、`WARN`、`DANGER` が出るのは正常です。

一般ユーザー向けの配布物には、この fixture 本体は入れません。配布物には自己確認用の `tests\samples\manifest.json` と説明用の `tests\samples\README.md` だけを残します。ソースリポジトリでは、保守者が検出精度を落としていないか確認するために fixture 本体を管理します。

そのため、軽量配布物では `tests/samples` を直接スキャンして検出テストを行うことはできません。これは、危険に見える作り物ファイルを一般配布から外すための仕様です。実際のプロジェクトやPC主要箇所を調べる検出能力は変わりません。

このプロジェクトフォルダの親ディレクトリをスキャンした場合、このツール自身または別コピーの `tests/samples` のうち、現在実行中のツールに入っているmanifestとhashが一致した既知の検証ファイルだけを除外します。別コピー側のmanifestは信用しません。

未知のファイルや改変されたファイルが `tests/samples` に混ざっている場合は除外せず、通常どおりスキャンします。他のプロジェクトにある `tests/samples` や、名前だけ似せた偽のスキャナーフォルダも自動的には信用しません。

`tests/samples` を直接指定した場合だけ、検証用として `CAUTION`、`WARN`、`DANGER` が出ます。

## 11. レポートの場所情報の読み方

最新のレポートには、`Path:` に加えて次の情報が出ます。

| 表示 | 意味 |
|---|---|
| PathType | `file` はファイル、`directory` はフォルダ、`virtual` は実ファイルではない集約情報 |
| Line | 何行目付近で見つかったか。空の場合はファイル全体やフォルダ単位の情報 |
| SourceContext | `synthetic-sample` は検証用サンプル、`cache` はキャッシュ、`dependency-metadata` は依存関係の説明メタデータ、`active-ai-config` は実行設定、`executable-tooling` は実行用スクリプト、`reference-text` / `session-log` / `cache-data` は低優先の文書・ログ・キャッシュ系です |
| RiskType | `known-ioc` や `active-exfil` は優先確認、`capability` は「外部通信やインストール機能を持つ」という注意情報です |
| Confidence | `high`、`medium`、`low` の順で確度が高いです |
| Check | どの検査種類で見つかったか。例: `Packages`、`NodeRuntime`、`AiMcp`、`NpmCache` |
| DetectionMethod | `static-file`、`static-path`、`metadata`、`inventory`、`telemetry-opt-in` のような検出方法 |

例えば `dependency-metadata` にある絵文字用の不可視文字は、危険とは限りません。

JSONレポートには `completionStatus`、`coverage.summary`、`summaryBySourceContext`、`priorityFindings`、`capabilitySummary`、`nodeRuntimeAssessment`、`scanner.scriptPathRedacted`、`scanner.launcherPathRedacted`、`scanner.distributionStatus` も入ります。`coverage.summary` は重大・非重大の未検査件数、依存関係とnpm cacheの検査状態、次に行う限定的な操作を示します。`distributionStatus` が `complete` なら、配布フォルダとして必要な主要ファイルが揃っています。`script-only` や `incomplete` の場合は、古いコピーや単体コピーで実行していないか確認してください。

v0.1.15 以降は `traversalComplete`、`directoryCoverageComplete`、`candidateCoverageComplete`、`scanComplete` も確認してください。v0.1.21以降、「見つからなかった」を完了した境界内検査として扱うには、`scanComplete` が `true` かつ `completionStatus` が `complete` である必要があります。`completionStatus` は、`complete`、`partial-non-critical`、`incomplete-critical`、`error` の4種類です。端末の `PARTIAL (non-critical)` は重大候補の読み取り失敗ではなく、サイズ上限や一部ディレクトリなど非重大の未検査範囲がある状態です。それでもPC全体が安全という証明には使わず、`coverage.summary.nextAction` を確認してください。ツールが管理者権限を要求したり権限を書き換えたりすることはありません。

v0.1.22では、BATからWindows PowerShell 5.1を絶対パスで起動し、CI・契約テストをパスだけで自己参照扱いする例外を廃止しました。また、`CODEX_HOME`、`CLAUDE_CONFIG_DIR`、OneDrive系の自動探索を `USERPROFILE` 配下の安全な子ディレクトリに限定しています。Deepで再帰的に見つかっただけの未選択の依存物・生成物は、実際に選ばれたライフサイクル／runtime entrypointと区別します。前者にある一般的な秘密情報送信・開発ツール書込み・単独不可視文字実行・WASM decode/process複合は `WARN`、一般的な外部取得実行helperは `CAUTION` とし、既知IOC、campaign chain、第一者コード、選択済みentrypointは高い優先度を維持します。依存物内の `.github/workflows` は利用側repositoryの有効なCIとは扱いません。依存物・生成物の判定は明示スキャンルートより下の相対パスに限定し、上位フォルダ名によって第一者コードが降格されないようにしています。また、不可視文字やregexの明示的に非重大な解析上限は `partial-non-critical` と表示し、未知の残り範囲が生じる `MaxFiles` 上限は引き続き重大な未完了として扱います。埋め込まれた実行可能なhere-stringは通常の検査対象であり、target側が指定できるself-test関数名、helper名、変数名、pattern配列名だけを根拠に受動的データとして除外しません。一方、一般的なPowerShell外部取得実行判定では、元ソース上の各候補を `Active`、`Ambiguous`、`PassiveRegex` に分類します。静的な `Pattern` 値は、字句上の関数スコープが独立し、すべての直接参照が `-match` / `-notmatch` に限定され、到達可能なローカルhelperが動的スコープ経由で値を取得できない場合だけ `PassiveRegex` になります。`Active` は常に優先し、元の行番号を維持します。構文エラー、反射的な変数参照、自身のソース再読込、wrapper、property/index経由の受け渡し、実行用途、未知の使用は抑制せず、安全側の検出を維持します。

v0.1.17 では `scanScope` と `iocData` も確認できます。`scanScope.fullDisk` は常に `false` で、Deepの有無と含む範囲・除外範囲が明示されます。`iocData.releaseReady=false` は、同梱IOCの少なくとも1つが期限超過・欠落・不正であることを意味します。過去の厳密IOCは有効なままですが、保守者は公開前にデータを再確認してください。

2026年8月の Keyv ChainDrop 対応では、固定スナップショットの443パッケージ・2,235組の厳密なバージョンを照合します。インストール済みメタデータまたは正しく解析できたlockfileの完全一致は `DANGER` ですが、`package.json` の範囲指定、キャッシュ、参考文書、文字列だけの一致は確認候補です。`DANGER` でも自動削除せず、レポートの根拠と実ファイルを保全してください。

v0.1.16では、GlassWorm型の `codePointAt` decoderと連続Variation Selectorクラスタを検出します。v0.1.18では、同じ局所範囲・同じcode-point変数による範囲判定とbyte mappingをdecoder条件とし、実際のVariation Selectorクラスタがないsignature単独は最大でも `WARN` に抑えます。既知mappingの静的復号はメモリ内だけで行い、復号内容を実行せず、レポートにも書きません。また、レポート出力先に既存ファイルやTXT/JSONの同一パスを指定した場合は、上書きせず検査前に停止します。

`priorityFindings` は、まず確認すべき `known-ioc`、`active-exfil`、実行設定の fetch-execute、プロジェクトまたはcontainerで明示されたNode.jsの `Critical` / `High` 一致を上の方に集めたものです。`scanner-self` と manifest検証済みの `scanner-artifact-sample` は優先一覧から外れますが、未知・改変サンプルは外れません。

`capabilitySummary` は、Codex の skill や plugin が外部API、ダウンロード、インストール機能を持つ場合の集約です。`provenance` は配置パスから推定した分類で、署名や発行元を検証した結果ではありません。これは感染確定ではありませんが、その機能を使う前に提供元や用途を確認するための情報です。

GitHubなど許可されたAPIへの書き込み・インストール機能は、悪性複合条件がなければ `CAUTION` の `capability` として扱います。認証ファイルを読んで送る処理や、未知の送信先へトークンを送る処理は高優先度の `active-exfil` として扱います。

GlassWorm のような攻撃で使われることがある、不可視文字、Solana、DHT、Google Calendar、raw/gist/paste系URLなどの目印は、単独では調査候補です。不可視文字と `eval`、外部取得と実行、秘密情報の読み取りと送信が近くにある場合は高優先度になります。

AI skill や README の中に危険なコマンド例が書かれている場合、参考文書だけなら集約された `CAUTION` になります。アクティブなMCP設定の未固定 `npx` / `uvx` は `WARN`、外部取得して実行するアクティブ設定は `DANGER` のままです。これは文書例や受動的な補助スクリプトと、実際に読み込まれる設定を区別するためです。

## 12. DANGERが出た時にやってはいけないこと

慌てて次のことをしないでください。

- ファイルを削除する
- フォルダを丸ごと消す
- 拡張機能をアンインストールする
- 認証ファイルを編集する
- npm、pip、python、nodeなどを実行する
- 見つかったURLへアクセスする

証拠を壊す可能性があります。

## 13. DANGERが出た時にやること

1. レポートの `.txt` ファイルを保存します。
2. `Path:` に書かれているファイルの場所を確認します。
3. そのファイルを実行せず、まず内容を読むだけにします。
4. 業務PCなら、社内のIT管理者やセキュリティ担当に相談します。
5. トークンや認証情報のローテーションは、人間が状況を確認してから判断します。

## 14. よくある質問

### Q. このツールはネットに接続しますか？

いいえ。ネットワーク通信はしません。

### Q. ファイルを勝手に消しますか？

いいえ。削除、修復、隔離、アンインストールはしません。

### Q. パスワードやトークンを表示しますか？

いいえ。秘密値は表示しない設計です。認証ファイルについては、基本的に「存在する」という情報だけを出します。

### Q. `tests/samples` でDANGERが出ました。危険ですか？

いいえ。検証用の作り物ファイルなので正常です。

### Q. `tests/samples` に `manifest.json` と `README.md` しかありません。壊れていますか？

いいえ。一般配布用の軽量アーカイブでは正常です。危険に見える検証fixture本体は、保守者向けの完全なソースリポジトリとCIにだけ残します。

### Q. どのモードを使えばよいですか？

現在作業フォルダには `1`、別プロジェクトの指定には `2` を使ってください。PCの主要箇所を広めに見たい時は `7`、端末ログまで見る必要がある時だけ `9` を使います。

## 15. コマンドで使う場合

コマンドに慣れている場合は、次のように実行できます。

```bat
run-checker.bat current C:\Path\To\Project
```

依存・build・cache内部まで明示的に確認する場合:

```bat
run-checker.bat deep C:\Path\To\Project
```

Deepは `--no-pause` を受け付けず、`YES` 確認が必要です。PC全体、npm global/cache、ユーザープロファイル、端末ログを自動追加する機能ではありません。

主要箇所だけを調べる場合:

```bat
run-checker.bat major
```

またはPowerShellから直接実行できます。

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path C:\Path\To\Project -ReportDir .\reports
```

検査種類を指定する例:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path C:\Path\To\Project -Checks Packages,AiMcp,CiCd -ReportDir .\reports
```

初心者は `run-checker.bat` から始めるのがおすすめです。
