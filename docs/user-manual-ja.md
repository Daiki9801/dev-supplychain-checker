# IT初心者向け 使い方マニュアル

このマニュアルは、Windowsで `Dev Supply Chain IOC Checker` を使うための初心者向け手順です。

このツールは、開発用フォルダの中に「危険そうな設定やファイルの痕跡」がないかを静的に確認します。ファイル削除、修復、ネットワーク通信、外部ダウンロードは行いません。

## 1. まず知っておくこと

- このツールは「感染しているかを確定する道具」ではありません。
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
3. Package / lockfile risks only
4. AI / MCP / IDE config risks only
5. CI/CD and hooks risks only
6. npm global/cache static check
7. Major PC locations scan
8. Custom checks for current folder
9. Full scan current folder + user profile + endpoint telemetry
10. Exit
```

各項目の意味は次の通りです。

| 番号 | 用途 | 初心者向けおすすめ |
|---:|---|---|
| 1 | 今開いているフォルダを推奨設定で調べる | 最初はこれ |
| 2 | 自分で指定したフォルダを調べる | 慣れてから |
| 3 | package.json や lockfile など依存関係だけを調べる | 依存だけ見たい時 |
| 4 | AI/MCP設定とIDE拡張だけを調べる | AIツール設定が心配な時 |
| 5 | GitHub Actions や hooks だけを調べる | CI/CDだけ見たい時 |
| 6 | npm global/cache を静的に調べる | 必要な時だけ。実行前に確認あり |
| 7 | PC内の主要な開発関連場所だけを調べる | 不安な時に使う |
| 8 | 自分で検査種類を組み合わせる | 詳しい人向け |
| 9 | フォルダ、ユーザー設定、端末ログをまとめて調べる | 管理者や詳しい人と一緒に |
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
VS Code / Cursor / Windsurf などの拡張機能
Claude / Cursor / Codex などのAIエージェント設定
認証ファイルの存在確認
```

このモードは `C:\` 全体を調べません。`C:\Windows` や `Program Files` を丸ごと調べるものでもありません。

このツール自身の `tests/samples` は検証用の作り物なので、Major PC locations scanでは現在実行中の正規manifestと一致した既知ファイルだけを除外します。

端末ログ、DNSキャッシュ、イベントログなどは含みません。それらまで見る場合は `9. Full scan` を使います。

また、Major PC locations scanでは `%USERPROFILE%\.config` 全体のような広い設定フォルダは対象外にしています。必要な場合は、詳しい人と一緒にコマンドの `run-checker.bat userprofile` を使ってください。

## 5. 別のフォルダを調べたい場合

メニューで `2` を選ぶと、調べたいフォルダのパスを入力できます。

例:

```text
C:\Users\yourname\Projects\my-project
```

パスが分からない場合は、まず対象フォルダをエクスプローラーで開いて、アドレスバーの内容をコピーしてください。

## 6. 検査種類を選びたい場合

v0.1.9 以降は、リスク別に検査を選べます。

| 表示 | 主な対象 |
|---|---|
| Recommended | 通常のおすすめ。プロジェクト内の依存関係、Unicode、CI/CD、AI/MCP、IDE、hooks、認証ファイル存在確認 |
| Packages | package.json、lockfile、既知パッケージIOC、最近のインシデント名の参考情報 |
| LifecycleScripts | install script、.pth、setup.py など、インストール時や読み込み時に動く可能性がある静的テキスト |
| CiCd | GitHub Actions などの workflow |
| AiMcp | Codex、Claude、Cursor、Windsurf、MCP などのAI/agent設定 |
| IdeExtensions | VS Code互換拡張の metadata や実行ファイル候補 |
| NpmGlobal | npm global package の候補パスを静的に読む。`npm root -g` は実行しない |
| NpmCache | npm cache metadata の候補パスを静的に読む。`npm cache ls` は実行しない。cache blob は読まない |

初心者は、通常は `Recommended` のままで十分です。

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

v0.1.11 以降、このツール自身の配布フォルダ直下にある `reports*` フォルダは、通常スキャンでは除外されます。過去レポート内に残ったIOC文字列を、現在の危険として再検出しないためです。

ただし、`-Path .\reports` や `-Path .\reports1` のように明示指定した場合は、調査目的としてスキャンできます。

`reports*/` はGitの管理対象からも外します。生成済みレポートは、公開リポジトリや配布物のソースには含めないでください。

## 8. 結果の見方

レポートの上の方に、次のようなまとめがあります。

```text
OverallResult: WARN

[SUMMARY]
DANGER: 0
WARN:   2
INFO:   5
OK:     1
```

意味は次の通りです。

| 表示 | 意味 | どうするか |
|---|---|---|
| OK | 大きな問題候補は見つからなかった | 通常はそのままでよい |
| INFO | 参考情報 | 必要なら確認 |
| WARN | 注意して確認すべき候補 | 内容を読む |
| DANGER | 強く確認すべき候補 | 削除せず、詳しい人に相談 |

`DANGER` は「感染確定」ではありません。ただし、優先して確認すべきサインです。特に `RiskType` が `known-ioc` や `active-exfil` の場合は、既知の危険な目印、または秘密情報を外へ送るように見える強い候補です。

`WARN` は調査候補です。例えば「外部APIを使える」「危険なコマンド例が文書に書かれている」「C2に似た文字列がある」などでも出ます。`WARN` だけで感染したとは判断しないでください。

## 9. `tests/samples` の警告について

このプロジェクトには、ツールの動作確認用に `tests/samples` があります。

ここには、危険なパターンを検出できるか確認するための「作り物のテキストファイル」が入っています。

- ダウンロードしたマルウェアではありません。
- 実行するためのファイルではありません。
- 偽のURLや偽のトークン文字列が入っています。
- ここをスキャンすると `WARN` や `DANGER` が出るのは正常です。

このプロジェクトフォルダの親ディレクトリをスキャンした場合、このツール自身または別コピーの `tests/samples` のうち、現在実行中のツールに入っているmanifestとhashが一致した既知の検証ファイルだけを除外します。別コピー側のmanifestは信用しません。

未知のファイルや改変されたファイルが `tests/samples` に混ざっている場合は除外せず、通常どおりスキャンします。他のプロジェクトにある `tests/samples` や、名前だけ似せた偽のスキャナーフォルダも自動的には信用しません。

`tests/samples` を直接指定した場合だけ、検証用として `WARN` や `DANGER` が出ます。

## 10. レポートの場所情報の読み方

最新のレポートには、`Path:` に加えて次の情報が出ます。

| 表示 | 意味 |
|---|---|
| PathType | `file` はファイル、`directory` はフォルダ、`virtual` は実ファイルではない集約情報 |
| Line | 何行目付近で見つかったか。空の場合はファイル全体やフォルダ単位の情報 |
| SourceContext | `synthetic-sample` は検証用サンプル、`cache` はキャッシュ、`dependency-metadata` は依存関係の説明メタデータ、`active-ai-config` は実行設定、`executable-tooling` は実行用スクリプト、`reference-text` / `session-log` / `cache-data` は低優先の文書・ログ・キャッシュ系です |
| RiskType | `known-ioc` や `active-exfil` は優先確認、`capability` は「外部通信やインストール機能を持つ」という注意情報です |
| Confidence | `high`、`medium`、`low` の順で確度が高いです |
| Check | どの検査種類で見つかったか。例: `Packages`、`AiMcp`、`NpmCache` |
| DetectionMethod | `static-file`、`static-path`、`metadata`、`inventory`、`telemetry-opt-in` のような検出方法 |

例えば `dependency-metadata` にある絵文字用の不可視文字は、危険とは限りません。

JSONレポートには `summaryBySourceContext`、`priorityFindings`、`capabilitySummary`、`scanner.scriptPathRedacted`、`scanner.launcherPathRedacted`、`scanner.distributionStatus` も入ります。`distributionStatus` が `complete` なら、配布フォルダとして必要な主要ファイルが揃っています。`script-only` や `incomplete` の場合は、古いコピーや単体コピーで実行していないか確認してください。

`priorityFindings` は、まず確認すべき `known-ioc`、`active-exfil`、実行設定の fetch-execute を上の方に集めたものです。`scanner-self` と manifest検証済みの `scanner-artifact-sample` は優先一覧から外れますが、未知・改変サンプルは外れません。

`capabilitySummary` は、Codex の skill や plugin が外部API、ダウンロード、インストール機能を持つ場合の集約です。これは感染確定ではありませんが、その機能を使う前に提供元や用途を確認するための情報です。古いコピーのBATや別フォルダのスクリプトを実行した時に、どのスクリプトで作られたレポートかも確認できます。

GitHubなど許可されたAPIへの書き込み・インストール機能は `WARN` の `capability` として扱います。認証ファイルを読んで送る処理や、未知の送信先へトークンを送る処理は高優先度の `active-exfil` として扱います。

GlassWorm のような攻撃で使われることがある、不可視文字、Solana、DHT、Google Calendar、raw/gist/paste系URLなどの目印は、単独では調査候補です。不可視文字と `eval`、外部取得と実行、秘密情報の読み取りと送信が近くにある場合は高優先度になります。

AI skill や README の中に危険なコマンド例が書かれている場合、文書であっても `WARN` になることがあります。これは「すでに実行された」という意味ではなく、その例をコピーして使う前に確認するための注意です。

## 11. DANGERが出た時にやってはいけないこと

慌てて次のことをしないでください。

- ファイルを削除する
- フォルダを丸ごと消す
- 拡張機能をアンインストールする
- 認証ファイルを編集する
- npm、pip、python、nodeなどを実行する
- 見つかったURLへアクセスする

証拠を壊す可能性があります。

## 12. DANGERが出た時にやること

1. レポートの `.txt` ファイルを保存します。
2. `Path:` に書かれているファイルの場所を確認します。
3. そのファイルを実行せず、まず内容を読むだけにします。
4. 業務PCなら、社内のIT管理者やセキュリティ担当に相談します。
5. トークンや認証情報のローテーションは、人間が状況を確認してから判断します。

## 13. よくある質問

### Q. このツールはネットに接続しますか？

いいえ。ネットワーク通信はしません。

### Q. ファイルを勝手に消しますか？

いいえ。削除、修復、隔離、アンインストールはしません。

### Q. パスワードやトークンを表示しますか？

いいえ。秘密値は表示しない設計です。認証ファイルについては、基本的に「存在する」という情報だけを出します。

### Q. `tests/samples` でDANGERが出ました。危険ですか？

いいえ。検証用の作り物ファイルなので正常です。

### Q. どのモードを使えばよいですか？

最初は `1. Recommended project scan` を使ってください。PCの主要箇所を広めに見たい時は `7`、端末ログまで見る必要がある時だけ `9` を使います。

## 14. コマンドで使う場合

コマンドに慣れている場合は、次のように実行できます。

```bat
run-checker.bat current C:\Path\To\Project
```

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
