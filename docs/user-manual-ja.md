# IT初心者向け 使い方マニュアル

このマニュアルは、Windowsで `Dev Supply Chain IOC Checker` を使うための初心者向け手順です。

このツールは、開発用フォルダの中に「危険そうな設定やファイルの痕跡」がないかを静的に確認します。ファイル削除、修復、ネットワーク通信、外部ダウンロードは行いません。

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
3. メニューが表示されたら、通常は `1` を入力します。
4. Enterキーを押します。
5. スキャンが終わるまで待ちます。
6. `reports` フォルダに結果ファイルが作成されます。

通常は、まず `1. Recommended project scan` だけを使ってください。

配布されたツールを使う時は、展開したフォルダの中にある `run-checker.bat` から起動してください。`Scan-DevSupplyChain.ps1` だけを別フォルダへコピーして実行すると、レポートには `distributionStatus` の警告が出ます。これは動作停止ではありませんが、検証用サンプル除外やIOCデータの出所確認が分かりにくくなるため、通常利用では推奨しません。

## 3. メニューの意味

`run-checker.bat` を起動すると、次のような選択肢が出ます。

```text
1. Recommended project scan
2. Scan selected path
3. Package / Node runtime risks
4. AI / MCP / IDE config risks only
5. CI/CD and hooks risks only
6. npm global/cache static check
7. Major PC locations scan
8. Custom checks for current folder
9. Comprehensive bounded scan (target + major locations + profile + endpoint)
10. Exit
```

各項目の意味は次の通りです。

| 番号 | 用途 | 初心者向けおすすめ |
|---:|---|---|
| 1 | 今開いているフォルダを推奨設定で調べる | 最初はこれ |
| 2 | 自分で指定したフォルダを調べる | 慣れてから |
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

ファイル本文に対する各正規表現処理には、.NET APIで明示的に2秒のタイムアウトを設定します。これはスキャン全体の制限時間ではなく、1回の正規表現処理ごとの上限です。高負荷な入力では `regex timeout` と `REGEX_SCAN_TIMEOUT` を記録し、そのファイルの該当処理だけを飛ばして、他の検査とファイルを続行します。該当処理は完了していないため、結果は `complete` にはなりません。非重大候補なら `partial-non-critical`、lockfileや有効な設定などの重大候補なら `incomplete-critical` になります。表示やレポートに対象ファイル本文は含めません。対象を狭めるか該当ファイルを手動確認し、単にタイムアウトを延ばしたことを安全の根拠にはしないでください。

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
| CAUTION | 単独では低信号だが確認を勧める存在・機能・設定 | 時間のある時に内容を読む |
| WARN | より強い不審パターン、既知リスク、セキュリティ上の弱点 | 優先して内容を読む |
| DANGER | 強く確認すべき候補 | 削除せず、詳しい人に相談 |

`DANGER` は「感染確定」ではありません。ただし、優先して確認すべきサインです。特に `RiskType` が `known-ioc` や `active-exfil` の場合は、既知の危険な目印、または秘密情報を外へ送るように見える強い候補です。

Node.jsの脆弱性では、公式情報の `Critical` / `High` と、このツールの判定 `WARN` / `INFO` を分けています。バージョンが対象範囲に入るだけでは実際に攻撃可能とは限らないため、インストール済みメタデータや明示pinは`WARN`、`engines.node`のconstraintは`INFO`です。v0.1.21以降、端末とTXTでは `Node.js installed` と `Node.js project refs` が別々に表示されます。Dockerfileの古い指定が見つかっても、グローバルNode.jsが古いという意味ではありません。

JSONの `nodeRuntimeAssessment` では、`installedBinaries` と `projectReferences` を分け、正確に評価できたバージョンを秘匿済みパスとともに最大100件記録します。`notAffected` は「同梱されたオフライン基準に一致しなかった」という意味だけです。全CVE、EOL、電子署名、発行元の真正性まで安全と保証するものではありません。脆弱性に一致した項目のCVEと修正版候補は、従来どおり `NODE RUNTIME SUMMARY` と `nodeRuntimeSummary` で確認できます。

`CAUTION` は、ライフサイクルスクリプトの存在、単独の不可視文字、悪性複合条件のないWASM読込機能などに使います。`WARN` は、C2に似た文字列、decoder signature、変更可能な外部参照など、優先度が一段高い調査候補です。どちらも感染確定ではなく、終了コードは互換性維持のため `1` です。

### 完了状態の読み方

| `completionStatus` | 意味と対応 |
|---|---|
| `complete` | 選択した境界内の予定検査が完了。PC全体・全依存物の安全保証ではありません。 |
| `partial-non-critical` | 明示的に非重大とした処理または境界内解析の一部が未完了。`coverage.summary` と制限findingを確認します。 |
| `incomplete-critical` | 重要な予定範囲に未列挙・読取・解析不能があります。陰性結果として扱わず、対象を狭めて再実行します。 |
| `error` | スキャナーまたはレポート処理が失敗。陰性結果として利用しません。 |

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

最初は `1. Recommended project scan` を使ってください。PCの主要箇所を広めに見たい時は `7`、端末ログまで見る必要がある時だけ `9` を使います。

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
