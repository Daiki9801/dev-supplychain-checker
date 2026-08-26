# 安全性と設計上の約束

この文書は、Dev Supply Chain IOC Checker を配布・利用する人向けに、このツールが安全側に倒すために守っている設計をまとめたものです。

## 重要な前提

このツールは、Windows 開発環境にある supply-chain IOC の候補を静的に確認するための一次スクリーニングツールです。

感染を確定するものではありません。また、「問題がないこと」を完全に証明するものでもありません。

## 依存関係なし

このツールは、次の2種類だけで動きます。

- `run-checker.bat`
- `Scan-DevSupplyChain.ps1`

外部パッケージは使いません。

実行時に `npm`、`pip`、`python`、`node`、`git clone` などで依存を追加することもありません。

GitHubリポジトリ取得機能もありません。確認したいリポジトリは、ユーザーが承認済みの方法でローカルに用意したフォルダを指定します。

## 外部通信なし

スキャナーはオフライン前提です。

- インターネットへ接続しません。
- URLへアクセスしません。
- IOC を自動更新しません。
- npm registry、PyPI、GitHub、OpenVSX、VS Code Marketplace へ問い合わせません。
- `git clone`、`git archive`、GitHub API 取得は行いません。

IOC は、同梱されたローカル JSON とスクリプト内の静的ルールだけを使います。

## 読み取り専用

このツールは対象を変更しません。

行わないこと:

- ファイル削除
- 修復
- 隔離
- アンインストール
- レジストリ変更
- トークンローテーション
- npm / pip / python / node / GitHub Actions / hook / workflow の実行
- `npm root -g` や `npm cache ls` の実行

検出結果は、TXT と JSON のレポートとして `reports` フォルダへ保存します。

既存ファイルは上書きしません。明示した `-TextOut` / `-JsonOut` が既存項目または同一パスを指す場合は検査前に停止し、自動名が同一秒内で重なった場合は未使用のsuffixを選びます。

設定されたレポート出力先（既定は `reports/`）と現在のTXT/JSON出力ファイルは通常スキャンから除外します。現在のレポートを実ファイルリスクとして再検出せず、`reports-service` のような無関係なソースフォルダは隠しません。明示的に `-Path` で指定した場合は、調査目的としてスキャンできます。

Gitが既定で除外するのはリポジトリ直下の `/reports/` だけです。独自名や過去のレポートフォルダはcommit前に明示的に確認し、ソースや配布物へ含めないでください。

## 秘密情報を出さない

このツールは、秘密値をレポートへ出さない設計です。

代表例:

- `.codex\auth.json`
- `.npmrc`
- `.pypirc`
- `.netrc`
- SSH 秘密鍵
- cloud credentials
- kube config

これらは、原則として「存在確認」のみを行います。中身やトークン値は読みません。

それ以外の検査対象設定テキストは静的マッチングのために読みます。検出器が証拠文字列や例外文を出す場合は、中央の redaction 処理を通して値を伏せます。

## 実行しない静的検査

検査は基本的にファイルを読むだけです。

確認する代表例:

- `package.json` / lockfile
- Python requirements / lock / `.pth`
- Composer metadata
- GitHub Actions workflow
- MCP / AI agent config
- VS Code 互換 extension metadata
- `.codex` skill / plugin / session / reference text
- npm global package の候補パス。ただし `npm root -g` は実行しません。
- npm cache metadata の候補パス。ただし `npm cache ls` は実行せず、`_cacache\content-v2` blob は本文デコードしません。

対象コード、install script、hook、workflow は実行しません。

## opt-in の範囲

次の範囲は、明示的に選んだ時だけ動きます。

- MajorLocations scan
- UserProfile scan
- EndpointTelemetry scan
- Comprehensive bounded scan（旧称/コマンド名: `full`）

BAT ランチャーでは、これらのモードを実行する前に確認文を表示し、`YES` 入力を要求します。

`full` は指定パス、MajorLocations、UserProfile、npm global/cache、既知配置/PATH上のNode.jsメタデータ、EndpointTelemetryをまとめます。ただし、全ディスク走査でもDeep走査でもありません。実際の含有・除外範囲はレポートの `scanScope` に記録されます。

MajorLocations 単独では、Codex の有効な設定、agents、rules、skills、導入済みプラグインの実行コードだけを選択し、`.codex\sessions`、実行時cache、履歴データは読みません。UserProfile または `full` を選んだ場合は、セッションやcacheの文字列も実行せず低優先の集約情報として扱います。環境変数から自動検出するCodex、Claude、OneDriveのルートは、`USERPROFILE` 配下の絶対パスかつ非reparseの子ディレクトリだけを受け入れ、範囲外の配置は `-Path` で明示的に検査します。

## ファイル列挙の安全策

スキャナーは、過剰な読み取りやループを避けるために次の制限を持ちます。

- reparse point / junction / symlink を既定で追跡しない
- 最大ファイル数を制限する
- 最大ファイルサイズを制限する
- バイナリらしいファイルは本文デコード対象から外す
- access denied は制限情報として記録し、スキャンを継続する
- npm cache blob などは個別ノイズではなく統計や集約へ寄せる
- `node_modules`、`.venv`、`vendor` は targeted scan を基本にする

## リスク別チェック

v0.1.9 以降は、`-Checks` で検査種類を選べます。

- `Recommended`: 通常利用向け。プロジェクトに明記されたNode.jsバージョンを含みますが、npm global/cacheやホストのNode.js配置は探索しません。
- `MajorRecommended`: `Recommended` に静的 npm global 検査と、既知配置のNode.js実行ファイルメタデータ検査を加えます。
- `AllSafe`: EndpointTelemetry 以外の静的検査をまとめて実行します。
- 個別指定: `Packages`、`LifecycleScripts`、`NodeRuntime`、`InvisibleUnicode`、`CiCd`、`AiMcp`、`IdeExtensions`、`HooksAndTasks`、`SecretsInventory`、`NpmGlobal`、`NpmCache`、`ScannerSelf`。

`NodeRuntime`はNode.jsを起動しません。`.nvmrc`、Volta、container、CIなどの明示バージョンと、許可された範囲で列挙された`node.exe`のWindowsバージョン情報だけを読みます。公式の`Critical`/`High`は上流の深刻度であり、本ツールでは静的なバージョン一致を`WARN`または`INFO`として報告します。`nodeRuntimeAssessment`はインストール済みバイナリとプロジェクト内の指定を分離し、正確に評価できたバージョンを秘匿済みパスで最大100件記録します。`notAffected`は同梱オフライン基準に一致しなかったという限定的な結果で、完全なCVE・EOL・署名・発行元検証ではありません。

`UserProfile` と `EndpointTelemetry` は `-Checks` ではなく、明示的なモード指定です。

同梱IOCの鮮度は `iocData` にファイル単位で記録されます。期限超過・欠落・不正が1つでもある場合は `releaseReady=false` となり、公開前の手動再確認が必要です。期限超過だけを理由に過去の厳密IOCを無効化することはありません。

## 配布物の自己確認

配布時は、展開したフォルダ内の `run-checker.bat` から起動してください。

完全な配布物には、少なくとも次が含まれます。

- `Scan-DevSupplyChain.ps1`
- `run-checker.bat`
- `README.md`
- `iocs`
- `tests\samples\manifest.json`

一般ユーザー向けの配布物には、`tests/samples` の検証用fixture本体は入れません。`tests\samples\manifest.json` と `tests\samples\README.md` だけを残します。ソースリポジトリには、保守者が検出回帰を確認するためのfixture本体を残します。

このため、軽量配布物では `tests/samples` を使った検出テストは実行できません。これは検証用サンプルを配布物から外すだけで、実際の検出ルール、IOCデータ、レポート生成、実フォルダの検査能力を減らすものではありません。

レポートの `scanner.distributionStatus` が `complete` なら、実行中の配布物として必要な構成が揃っています。

`script-only` や `incomplete` の場合でも互換性のためスキャンは続行しますが、古いコピーや単体コピーで実行している可能性があります。

## tests/samples の扱い

このリポジトリの `tests/samples` は検証用の作り物です。

- 実マルウェアではありません。
- 外部から危険ファイルをダウンロードしたものではありません。
- 直接スキャンすると `DANGER`、`WARN`、`CAUTION` が出るのは正常です。

親フォルダや Major PC locations scan では、現在実行中の正規 manifest と hash が一致した既知 fixture だけをスキップします。

未知ファイル、改変ファイル、他プロジェクトの `tests/samples`、偽の scanner フォルダは通常スキャンします。

軽量配布物で `tests/samples` の中に `manifest.json` と `README.md` しかない場合、それは異常ではありません。保守者向けの完全なソース checkout だけが、危険そうな文字列を含むfixture本体を持ち、CIや回帰確認に使います。

## 結果の読み方

判定は次の意味です。

| 表示 | 意味 |
|---|---|
| `DANGER` | 既知 IOC や実行文脈の強い指標。優先して確認する候補 |
| `WARN` | より強い不審パターン、既知リスク、またはセキュリティ上の弱点 |
| `CAUTION` | 強い悪性複合条件を伴わない、存在・機能・設定上の低信号な確認候補 |
| `INFO` | 存在確認、制限、集約、参考情報 |
| `OK` | スキャン完了、または問題候補なし |

`WARN` と `CAUTION` はどちらも終了コード `1` です。既存自動化との互換性を維持しながら、人が確認する優先順位を分けます。

手動実行だけのGitHub Actions、受動的なAI補助スクリプト、参考文書中の実行例は原則 `CAUTION` です。秘密情報・書き込み権限・入力を使う手動workflowや、実際に読み込まれる未固定MCPコマンドは `WARN`、アクティブな外部取得＋実行や秘密情報送信の強い複合は `DANGER` のままです。

`DANGER` でも感染確定ではありません。削除や実行をせず、レポートの `Path`、`RiskType`、`Confidence`、`Evidence` を確認してください。

npm cache は弱い証拠として扱います。cache metadata に既知パッケージ名やversionがあっても、インストールや実行の証明ではありません。対応は、同じパッケージが project-local または npm global の installed metadata にも存在するか、実行・漏えいの挙動が近くにあるかで判断します。

## 限界

`completionStatus=complete` は、選択した境界内の予定検査が完了したという意味だけです。ディスク全体、全依存物、全archive、全binary、全脆弱性を漏れなく確認したという意味ではありません。`partial-non-critical` は明示的に非重大とした未完了範囲を示し、`incomplete-critical` と `error` は完了した陰性結果として扱えません。

本文に対する各正規表現処理は2秒で打ち切ります。`REGEX_SCAN_TIMEOUT` では、そのファイルの該当処理だけを飛ばして残りを続けますが、結果は `complete` になりません。非重大候補なら `partial-non-critical`、lockfileや有効な設定などの重大候補なら `incomplete-critical` です。これは高負荷な入力でCPUを長時間占有しないための安全策である一方、対象を狭めた再検査または手動確認が必要な未検査範囲でもあります。

このツールは次の代替にはなりません。

- EDR / AV
- SIEM
- メモリフォレンジック
- ネットワークフォレンジック
- package manager のオンライン audit
- registry の人気度・所有者・存在確認
- 完全な YAML / TOML semantic parser

また、ディスク全体、メモリ、実行中process、実通信、任意のbinary内部、全依存関係・全CVE、オンラインの評判・署名・発行元・provenanceは検査しません。感染を確定することも、侵害が存在しないことを保証することもできません。

大量侵害キャンペーンや新しい IOC は、手動で確認したうえでローカル IOC を更新する必要があります。
