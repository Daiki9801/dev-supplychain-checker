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

v0.1.11 以降は、実行中のスキャナー配布フォルダ直下にある `reports*` フォルダを通常スキャンから除外します。過去レポートや検証artifactに含まれるIOC文字列を、現在の実ファイルリスクとして再検出しないためです。明示的に `-Path` で指定した場合は、調査目的としてスキャンできます。

`reports*/` はGit管理からも除外し、commit や push に含めません。

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

検出器が証拠文字列を出す場合も、中央の redaction 処理を通して値を伏せます。

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

- UserProfile scan
- EndpointTelemetry scan
- Full scan

BAT ランチャーでは、これらのモードを実行する前に確認文を表示し、`YES` 入力を要求します。

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

- `Recommended`: 通常利用向け。npm global/cache は読みません。
- `MajorRecommended`: `Recommended` に静的 npm global 検査を加えます。
- `AllSafe`: EndpointTelemetry 以外の静的検査をまとめて実行します。
- 個別指定: `Packages`、`LifecycleScripts`、`InvisibleUnicode`、`CiCd`、`AiMcp`、`IdeExtensions`、`HooksAndTasks`、`SecretsInventory`、`NpmGlobal`、`NpmCache`、`ScannerSelf`。

`UserProfile` と `EndpointTelemetry` は `-Checks` ではなく、明示的なモード指定です。

## 配布物の自己確認

配布時は、展開したフォルダ内の `run-checker.bat` から起動してください。

完全な配布物には、少なくとも次が含まれます。

- `Scan-DevSupplyChain.ps1`
- `run-checker.bat`
- `README.md`
- `iocs`
- `tests\samples\manifest.json`

レポートの `scanner.distributionStatus` が `complete` なら、実行中の配布物として必要な構成が揃っています。

`script-only` や `incomplete` の場合でも互換性のためスキャンは続行しますが、古いコピーや単体コピーで実行している可能性があります。

## tests/samples の扱い

このリポジトリの `tests/samples` は検証用の作り物です。

- 実マルウェアではありません。
- 外部から危険ファイルをダウンロードしたものではありません。
- 直接スキャンすると `DANGER` や `WARN` が出るのは正常です。

親フォルダや Major PC locations scan では、現在実行中の正規 manifest と hash が一致した既知 fixture だけをスキップします。

未知ファイル、改変ファイル、他プロジェクトの `tests/samples`、偽の scanner フォルダは通常スキャンします。

## 結果の読み方

判定は次の意味です。

| 表示 | 意味 |
|---|---|
| `DANGER` | 既知 IOC や実行文脈の強い指標。優先して確認する候補 |
| `WARN` | 設定、機能、文脈上の注意候補 |
| `INFO` | 存在確認、制限、集約、参考情報 |
| `OK` | スキャン完了、または問題候補なし |

`DANGER` でも感染確定ではありません。削除や実行をせず、レポートの `Path`、`RiskType`、`Confidence`、`Evidence` を確認してください。

npm cache は弱い証拠として扱います。cache metadata に既知パッケージ名やversionがあっても、インストールや実行の証明ではありません。対応は、同じパッケージが project-local または npm global の installed metadata にも存在するか、実行・漏えいの挙動が近くにあるかで判断します。

## 限界

このツールは次の代替にはなりません。

- EDR / AV
- SIEM
- メモリフォレンジック
- ネットワークフォレンジック
- package manager のオンライン audit
- registry の人気度・所有者・存在確認
- 完全な YAML / TOML semantic parser

大量侵害キャンペーンや新しい IOC は、手動で確認したうえでローカル IOC を更新する必要があります。
