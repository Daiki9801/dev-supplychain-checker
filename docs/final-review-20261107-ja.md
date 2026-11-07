# IOC・HTTP2Shell・CI の最終レビュー

**2026-11-07（JST）最終追補: Git直接取得への切替とCIの合成検証範囲の整理を実装し、ローカル11スイートが合格。公開判定は保留を継続する。** このworkflowからcheckout Actionとその同梱undiciの実行経路を除いた。作業ツリーの自己検査は完了・DANGER/WARN 0件。残る必須工程は、コミット対象の確定、候補SHAでの実GitHub Actions成功、更新した配布物の検証と公開承認。過去の出典・配布検証には未解決事項と適用時点の違いがあるため、以下で区別する。

## 最終追補: Git直接取得・CI範囲整理の実装

利用者の実装依頼に基づくオフライン作業。Git取得処理のモックを実行し、実際のGit初期化・fetch・checkout、外部照会、依存追加、実PC走査、ステージ、コミット、push、PR作成、公開は行っていない。作業開始・終了時のHEADは `8e911a6`、ブランチは `codex/triage-performance-v0.1.27` のまま。

| 変更 | 実装と検証範囲 |
|---|---|
| checkout Actionの除去 | `.github/workflows/validate.yml` は実行する外部Actionなし。ランナーの `git.exe` を取得前に解決し、Git 2.32.0以上を要求する。これは設定分離機能の互換条件であり、Git自体の全脆弱性が解消済みという保証ではない |
| 固定した取得対象 | `https://github.com`、`Daiki9801/dev-supplychain-checker`、push / pull_request / workflow_dispatch、40桁小文字SHAを検証。公開HTTPSの固定URLへ深さ1・タグなし・submoduleなしで `GITHUB_SHA` をfetch。`FETCH_HEAD^{commit}` を照合後にdetached checkoutし、`HEAD` も再照合する。PRはイベントのmerge SHAを対象とする |
| 取得失敗時の停止 | 空の通常workspaceだけで初期化する。既存ファイルの消去なし。Git各段階の終了コード、取得SHA、HEADの不一致で停止し、リポジトリ内スクリプトを実行しない。REST/ZIP・ブランチ先端への代替なし |
| 認証・設定 | Gitのsystem/global設定、追加設定引数、credential helperを分離・無効化し、トークンを渡さない。TLS検証を有効にし、redirectとHTTPS以外の取得を禁止する。Gitテンプレートを使わず、`core.autocrlf=true` と既存の `.gitattributes` を併用する |
| CIのプロファイル検査 | `-UserProfile` / `-MajorLocations` の起動とプロファイル環境変数の差し替えを除去。設定・ツール・session/cache・認証ファイル名・プロジェクトmetadataの合成検査を `Test-SecurityBoundaryRegressions.ps1` の明示した `-Path` に移した。生成物は新規GUID配下に保持し、自動削除と既存ファイルへの書き込みをなくした |
| 境界関数の検証 | 内部関数 `Get-SafeAutomaticProfileRoot` に任意の `UserProfileRoot` 引数を追加。通常呼び出しの既定値は従来どおり `USERPROFILE`。テストは合成値を明示し、許可・相対パス・プロファイル外・同名接頭辞・親への脱出・ドライブ直下・ファイル・reparse等を検証。CLIに新しいホスト走査モードは追加していない |
| CI範囲の回帰 | 25個のinline PowerShellブロックを解析し、広範囲のホストモード引数とプロファイル環境変数代入を検査する。Node/npm/HTTP2Shellの専用合成分岐は引き続き `-SyntheticValidation` とリポジトリ内の許可ルートが必要。静的な検査だけで任意の将来コードの安全性を証明するものではない |

checkout同梱undiciの影響版を実行するという今回の問題は、このCI経路を除くことで対処した。上流Actionそのものを修正したわけではなく、Git・GitHubランナーや他の製品の依存関係全体を無脆弱と判定したものでもない。公開HTTPSで実際に対象SHAを取得できることは、後続の実ランナー確認が必要。

今回編集したソース・文書は10ファイル: `.github/workflows/validate.yml`、`Scan-DevSupplyChain.ps1`、`tests/Test-CheckoutContract.ps1`、`tests/Test-SecurityBoundaryRegressions.ps1`、`README.md`、`CHANGELOG.md`、`docs/pre-push-test-procedure-ja.md`、`docs/github-publication-checklist-ja.md`、`docs/github-publication-checklist-en.md`、本レポート。既存の無関係な変更は保持した。CIの内容をレビューして自己参照ハッシュを更新し、パス・ルール・ハッシュの一致条件と改変／コピー拒否は維持した。

### ローカル検証結果

Windows PowerShell **5.1.26100.9711**。構文12ファイル・必須JSON9ファイルが合格。下表11スイートはすべて終了0。再実行コマンド一覧は [Push前のPCテスト手順](pre-push-test-procedure-ja.md#2-構文json差分検証) に記載した。実行形式は `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\<スイート名>`。実際には `$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe` を明示して5.1を使用した。

| スイート | 今回の結果 |
|---|---|
| `Test-CheckoutContract.ps1` | Gitモック38ケース、CIブロック25件、402 assertions。全Git実行とworkspace照会をモック化 |
| `Test-SecurityBoundaryRegressions.ps1` | 144 assertions。以前未実行だった境界スイートを、実PC走査なしで実行可能にした |
| `Test-LauncherScopeContracts.ps1` | 合格 |
| `Test-Http2ShellAudit.ps1` | 229 assertions |
| `Test-IocMaintenance.ps1` | 39ケース、1,105 assertions、158 fixture |
| `Test-SecurityUpdate20261006.ps1` | 36ケース、231 assertions |
| `Test-PythonMetadataRegressions.ps1` | 88ケース、343 assertions |
| `Test-StaticTriageRegressions.ps1` | 56ケース、116 assertions |
| `Test-ScanExecutionRegressions.ps1` | 20ケース、54 assertions |
| `Test-ScanTriagePerformanceRegressions.ps1` | 26ケース、72 assertions |
| `Test-ScanReviewRegressions.ps1` | 22ケース、61 assertions。更新後の自己参照と改変／コピー拒否を確認 |

| 追加走査（すべて完了、regex timeout / file error 各0） | 終了 | DANGER / WARN / CAUTION | IOC current / 未確認 / releaseReady |
|---|---:|---|---|
| 作業ツリー、`-Path . -Checks Recommended` | 1 | 0 / 0 / 1 | 7 / 0 / true |
| 合成サンプル、`-Path .\tests\samples -Checks Recommended` | 2 | 49 / 38 / 26（意図したfixture） | 7 / 0 / true |
| 安全版サンプル、`-Path .\tests\samples\node-runtime-safe -Checks NodeRuntime,Http2Shell,ScannerSelf` | 0 | 0 / 0 / 0 | 7 / 0 / true、HTTP2Shell `current` |

作業ツリーのCAUTIONは既存の手動workflow起動設定。スキャナーのoffline/read-only契約は維持した。これらは作業ツリーの検証であり、確定コミット・GitHubのジョブ全体・実PCの自動探索を検証した結果ではない。

今回のログ・TXT/JSONはローカル専用の `reports/git-checkout-20261107-9b3a7e95bca642fbaafb7d489e9dbbe7/` に保持した。9つの既存スイートの記録は `regression-results.json` と `regression.log`。先行実行したcheckout契約の結果は実行出力、境界検証の生成物は `reports/security-boundary-regression-d1dfb7da57084c4e9973f9c5e95d07b6/` に保持している。配布・コミット範囲の確認用一覧は前者の `review-manifests.json`。公開用ZIPと展開先は一覧で提案するだけで、作成していない。

`git diff --check` と `git diff --cached --check` は合格。今回の10ファイルはUTF-8 BOMなし・LFを維持。削除・移動・改名・既存ファイルの丸ごと置換は各0件。既存ZIP・展開物・過去のレポートも保持した。

### 公開保留を解除するための工程と承認事項

現段階では以下の操作を実行しない。利用者の「コミット・push・公開はまだ行わない」という指定に従う。Git・外部書き込みは [AGENTS.md](../AGENTS.md) の事前明示承認、新たな配布物の作成・展開は作業境界の正確な対象／操作ごとの承認が必要。

| 順序・区分 | 具体的な後続対応と承認単位 | 完了条件 |
|---|---|---|
| 1・必須 | `review-manifests.json` のコミット候補をレビューし、既存4指示・設計文書の差分の採否を決める。`.codex/` と `reports/` は対象外。確定したファイル一覧に限定したstageと、現在のブランチへのcommitを承認する | 公開する候補SHAが確定し、対象差分・既存4ローカルコミット・秘密情報／配布対象の最終点検が済む |
| 2・必須 | `Daiki9801/dev-supplychain-checker` の対象ブランチへのpush、main向けPR作成／更新、それに伴うActions実行を承認する。公開リポジトリへの実Git取得もこのCI実行の範囲として明示する | 最終候補SHAの `windows-latest` / `Scanner contract` が成功。匿名HTTPS取得、Git版、fetch/HEAD照合、3つのbyte-hash fixtureを含む全検証を確認。失敗時に認証追加や別方式へ自動変更しない |
| 3・必須 | 更新した64ファイルの配布候補について、新規 `dev-supplychain-checker-git-candidate.zip` と `expanded-git-candidate/` の作成・展開・合成BAT検証を別途承認する。正確な絶対パス、件数、bytes、SHA-256は `review-manifests.json` の配布計画を参照する | 最終候補と一覧のハッシュが一致し、展開後BATで完了・IOC7件・HTTP2Shell基準currentを再確認。変更が入れば一覧も再確定する。前回ZIPの承認・成功は今回の内容へ流用しない |
| 4・公開判断 | IOCの限定された検証範囲を公開説明に残すことを確認し、公開時点の鮮度を再評価する。mainへのmerge、タグ、Release作成・添付／公開は、それぞれ実行内容と対象を確定して別途承認する | 技術ゲートと説明範囲が一致し、公開権限者がGoを決定する。`iocData.releaseReady=true` 単独では公開承認としない |
| 追加調査を求める場合 | 403で止まったActionsタグ15件と旧41組のアーティファクト独立検証は未完。再試行／調査拡大は、通信条件・対象・最大回数・取得物を具体化して承認する | 独立確認済みと記載するには追加根拠が必要。今回のGit方式の成立条件とは分け、現状のIOCを無害へ再分類したり確認日だけ延長したりしない |
| 実PC検証を求める場合 | `UserProfile` / `MajorLocations` / `EndpointTelemetry` / HTTP2Shell PC監査は、必要なコマンドとホスト範囲を個別承認する | 合成ファイル検証と実PCの自動探索を区別して記録。今回のローカル実装完了や、限定された公開説明の必須条件とはしない |

一般IOCの期限は `expiresOn=2026-12-07`。HTTP2Shell基準は2026-11-15 UTCからstaleになるため、公開日が延びた場合は再調査が必要。前回作成したZIPは今回のGit直接取得・CI範囲整理を含まない過去の検証用スナップショットであり、そのまま最終配布物にしてはいけない。

## 追補履歴: 残件対応と再検証（Git直接取得への切替前）

以下は各対応時点の記録。checkout暫定対策・境界スイート未実行・配布物の現行性に関する記述は、上の最終追補で更新した。

既存の作業ツリーを調査し、最初にオフラインの修正・検証を実施した。その後、利用者が64ファイルのZIP作成・展開検証と最大25リクエストの限定した公開情報照会を明示承認した。実PC走査・Git状態変更・依存追加は実施していない。前回の出典記録と、下記で今回直接確認した情報を区別する。

| 指摘 | 対応と確認 |
|---|---|
| P1: 割り当てネットワークドライブ | `DriveInfo.DriveType` を使い、属性／存在確認より前に Network / Unknown / NoRootDirectory を拒否。列挙直前にも再確認。全7種別、UNC／デバイスパス、reparse のモックで対象パスへの照会順序と拒否時0回を確認。共有には接続していない |
| P2: npm 空ルートキー | 通常走査のメモリ内正規化を `ConvertFrom-NpmLockJson` に共通化。v2/v3 × package-lock/shrinkwrap の4走査は終了0・完了・Electron 1件。ルートパッケージは部品数へ混ぜず、入力ハッシュは不変 |
| P2: 6件で公開可能になる集計 | 全7データセットの確認を必須化。JSON/TXT に未確認件数と名前を追加。専用走査は `currentCount=6`、`notCheckedCount=1`、`releaseReady=false`。欠落と未確認を区別し、走査範囲は拡大しない |
| CI の取得経路・SHA | checkout直後に `.git` ディレクトリと `git rev-parse --verify HEAD == GITHUB_SHA` を検証し、失敗時はリポジトリスクリプト実行前に停止。Git版12ケース・取得結果6ケースのモックをCIにも追加。ホスト済みランナーの実測は未実施 |

変更対象はスキャナー、CI、HTTP2Shell／IOC／October更新回帰、追加の `tests/Test-CheckoutContract.ps1`、README、CHANGELOG、Push前手順、HTTP2Shell文書、本レポート。変更した2テストとCIの内容を確認して自己参照用ハッシュを更新した。パス・ルール・ハッシュを同時に要求する条件と、改変／外部コピーの通常解析は維持し、回帰で確認した。既存の `AGENTS.md`、過去設計書、IOC値、BAT、`.codex/` は今回編集していない。

Windows PowerShell **5.1.26100.9711** で構文12ファイル、必須JSON **9ファイル**を検証した。初回レポートのJSON8ファイルに対し、今回は項目別証拠記録を含む手順上の必須一覧すべてを確認した。

| 回帰スイート | 結果（全件終了0） |
|---|---|
| `Test-Http2ShellAudit.ps1` | 229 assertions |
| `Test-IocMaintenance.ps1` | 39ケース、1,105 assertions、158 fixture |
| `Test-SecurityUpdate20261006.ps1` | 36ケース、231 assertions |
| `Test-ScanReviewRegressions.ps1` | 22ケース、61 assertions。CI更新後も再確認 |
| `Test-LauncherScopeContracts.ps1` | 合格 |
| `Test-PythonMetadataRegressions.ps1` | 88ケース、343 assertions |
| `Test-StaticTriageRegressions.ps1` | 56ケース、116 assertions |
| `Test-ScanExecutionRegressions.ps1` | 20ケース、54 assertions |
| `Test-ScanTriagePerformanceRegressions.ps1` | 26ケース、72 assertions |
| `Test-CheckoutContract.ps1` | 18ケース、23 assertions |

| 追加走査 | 終了 | 完了 | DANGER / WARN | IOC current / 未確認 / releaseReady |
|---|---:|---|---|---|
| 全合成サンプル、Recommended | 2 | complete | 49 / 38（意図したfixture） | 7 / 0 / true |
| tests親、Recommended | 0 | complete | 0 / 0 | 7 / 0 / true |
| node-runtime-safe、NodeRuntime,Http2Shell,ScannerSelf | 0 | complete | 0 / 0 | 7 / 0 / true |
| node-runtime-safe、Http2Shell,ScannerSelf | 0 | complete | 0 / 0 | 6 / 1 / false |
| 作業ツリー全体、Recommended | 1 | complete | 0 / 0（CAUTIONあり） | 7 / 0 / true |

全5走査が `scanComplete=true`、fixture改変・未登録数0。専用基準は対象2走査とも `current`。自己検査の対象は現在の作業ツリーであり、確定したコミットや配布物を検証した結果ではない。非上書き・同一出力パス拒否・同一時刻の既定名衝突・BAT特殊文字／余分な引数／空入力は、合成入力による14 assertionsで合格した。

公開候補の本文59ファイルと、全到達可能20コミットに含まれる重複除外後152テキストblobを、秘密情報・実ホームパスの定型パターンで点検し、候補0件。作業ツリーの163ファイルはローカル設定・合成fixture・画像等として本文点検から除外し、値は表示していない。あらゆる秘密の不存在を保証する検査ではない。送信候補はローカル `origin/main` に対して4コミットで、リモートの最新状態は未照会。

`.gitattributes` に基づく配布案は64ファイル（5,517,195 bytes、IOC JSON 7件）。sampleはmanifestとREADMEだけで、`.codex/` とfixture本体を除外する。正確なサイズ・ハッシュ・展開先は追加検証フォルダーの `publication-candidate-v2.json` を参照。最初の `publication-candidate.json` はWindowsのstdin改行により属性判定が不正となった暫定記録で、配布には使用していない。再照合はパスを引数で渡して例外2件と除外規則を検証した。

承認した一覧から新規作成した `dev-supplychain-checker-candidate.zip` は3,521,299 bytes、SHA-256 `58a7e3d3b0a9d6320c8f887bb1d8046dd533051bb6a9c1eadfaa4476a01de236`。`expanded-candidate/` の64ファイルのハッシュがすべて一致した。展開BATの `path <元リポジトリのtests/samples/clean-js> --no-pause` は終了0、`scanComplete=true`、`completionStatus=complete`、DANGER 0、`currentCount=7`、`releaseReady=true`、`distributionStatus=complete`。既存ファイルの上書きなし。このZIPは承認時点の検証用スナップショットで、その後の本レポートの追記は含まない。確定コミットの配布アーカイブではない。

### 承認後の公開情報再確認

公開HTTPSのGETを合計8リクエスト実施し、6件成功、タグ照会2件が403。認証情報・リポジトリ内容の送信、バイナリ取得、外部書き込みは行っていない。

- [checkoutの最新安定リリース](https://api.github.com/repos/actions/checkout/releases/latest) は `v7.0.1`。[タグの実体](https://api.github.com/repos/actions/checkout/git/ref/tags/v7.0.1) は現行固定と同じ `3d3c42e5aac5ba805825da76410c181273ba90b1`。
- [固定版のpackage-lock](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/package-lock.json) の `node_modules/undici` は `6.27.0`。[GHSA-xjj6-f33q-929c](https://github.com/advisories/GHSA-xjj6-f33q-929c) と [GHSA-2m5v-pch6-74hx](https://github.com/advisories/GHSA-2m5v-pch6-74hx) は撤回なし・Highで、6系列の修正版は両方 `6.29.1`。最新安定Actionへの更新だけではこの残件を解消できない。
- [取得処理](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/src/git-source-provider.ts) の `getGitCommandManager` は作成失敗時に `undefined` を返し、`!git` 分岐がREST取得へ進む。今回追加したcheckout後の検査はフォールバック結果を拒否するが、Action実行中のRESTリクエストを事前禁止するものではない。上流修正版または別方式のレビューまで残存リスクとして扱う。
- `actions-cool/issues-helper@v2.2.1` と `codfish/semantic-release-action@v2` のタグAPIがともに403。利用者ルールの「同じ実質的な操作失敗が2回」に従って停止し、残り13タグは照会していない。タグの現行実体は未確認のままで、過去の悪性コミット／参照を無害へ再分類していない。

出典の応答要約と固定ソースは追加検証フォルダーの `public-checkout-advisories.json`、`public-action-tags.json`、`checkout-*.source.txt` に保持した。

追加走査と安全性検証はローカルの `reports/final-followup-20261107-785a50f44228432cb5e4ad4201ac3616/` に保持。追加の安全性検証は同フォルダーの `Test-ReportSafety.ps1`、配布検証の結果は `package-verification.json`。走査の再実行では既存出力を上書きせず、新しいTXT/JSON名を指定する。

```powershell
$followupSuites = @(
  'Test-Http2ShellAudit.ps1', 'Test-IocMaintenance.ps1',
  'Test-SecurityUpdate20261006.ps1', 'Test-ScanReviewRegressions.ps1',
  'Test-LauncherScopeContracts.ps1', 'Test-PythonMetadataRegressions.ps1',
  'Test-StaticTriageRegressions.ps1', 'Test-ScanExecutionRegressions.ps1',
  'Test-ScanTriagePerformanceRegressions.ps1', 'Test-CheckoutContract.ps1'
)
foreach ($suite in $followupSuites) {
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path '.\tests' $suite)
  if ($LASTEXITCODE -ne 0) { throw ("Regression failed: " + $suite) }
}
git diff --check
git diff --cached --check
```

両diff検査は終了0。今回変更した11ファイルはUTF-8 BOMなし・LFを維持した。全行の空白点検ではスキャナー先頭行の既存空白1件だけを検出し、HEADにも同じ空白があるため保持した。削除・移動・改名・既存ファイルの丸ごと置換は各0件。ステージ・コミット・pushは行っていない。

### 追補後に残る確認

- **公開出典の残件**: 旧41組のアーティファクト独立検証は今回の限定照会に含まれない。Actions可変タグは403により現行実体を確定できず、checkout同梱undiciには既知の影響版が残る。一般IOCの `expiresOn=2026-12-07`、HTTP2Shellは11月15日UTCからstaleとなるため、公開時点の鮮度も再確認する。
- **実ランナー**: checkout修正のモックは通過。候補SHAのpush／PRと `windows-latest` 上の成功、実際のGit経路は未確認。Git操作・外部書き込みの承認前に実行しない。
- **最終コミット候補**: 検証用ZIPの作成・展開は完了。新規のHTTP2Shell／checkout回帰と関連3文書をコミット候補に含める。`.codex/config.toml` は対象外。既存の指示書・過去設計書の変更は別途採否を決める。ステージ・コミット・pushは未実行で、公開する最終候補SHAの確定とその検証は残る。
- **実PCを含むテスト**: `Test-SecurityBoundaryRegressions.ps1` と実PCのHTTP2Shell監査は未実行。前者には `-UserProfile` / `-MajorLocations` とファイル複製があり、現行の自動検証制約に従って除外した。合成HTTP2Shellホスト分岐は別途検証済み。

## 初回レビュー記録（以下は修正前）

対象は `8e911a6` に対する作業ツリーのうち、IOC 7 件、HTTP2Shell の判定基準と走査経路、`validate.yml` の checkout 暫定対策、および関連するテスト・文書。公開出典の照合結果は更新時の台帳を確認し、今回はリポジトリ内の合成検証とコードレビューを実施した。 [IOC 照合台帳](ioc-maintenance-20261107-ja.md) [HTTP2Shell の判定基準と出典](http2shell-audit-ja.md)

## 公開前に解消する項目

### [P1] HTTP2Shell の PC 監査が割り当て済みネットワークドライブへアクセスし得る

`Get-Http2ShellHostRoots` は PATH などの候補をドライブ文字付きのパスに絞る。たとえば SMB 共有を割り当てた `Z:\tools` はこの形式に合う。ドライブ種別を確かめる前にパス属性・存在を調べ、採用した候補ではファイル列挙に進む。共有への接続やメタデータ読み取りが発生し得るため、PC 監査の「ローカルドライブのみ」という契約に抵触する。コードで確認した経路で、実機の共有は使用していない。 [候補の選別](../Scan-DevSupplyChain.ps1#L4974) [属性読み取り](../Scan-DevSupplyChain.ps1#L6149) [ファイル列挙](../Scan-DevSupplyChain.ps1#L5007) [PC 監査の範囲](http2shell-audit-ja.md#L93)

パスの属性・存在を照会する前に、ドライブ種別を確認してネットワークと判定不能な候補を除外する。ローカル・ネットワーク・判定不能を模擬し、後二者では対象パスへの照会が一度も行われないことを Windows PowerShell 5.1 の回帰テストで確認する。

### [P2] npm v2・v3 ロックファイルの空キーで HTTP2Shell 監査が未完了になる

通常の npm ロックファイルにある `packages[""]` はルートパッケージを表す。専用監査はロックファイルを `ConvertFrom-Json` に直接渡すため、Windows PowerShell 5.1 は空キーを含むファイルの解析に失敗する。`electron@45.2.3` を記載した合成 `package-lock.json` の v2・v3 で、いずれも `metadata-parse-error`、`completionStatus=incomplete-critical`、終了コード `1`、部品の記録 0 件を再現した。空キーだけを除いた v3 の対照は完了し、修正済み上流版の記録が 1 件だった。既存の専用回帰 fixture も空キーを省いている。 [専用 JSON 解析](../Scan-DevSupplyChain.ps1#L4810) [既存 fixture](../tests/Test-Http2ShellAudit.ps1#L76)

通常の npm 走査には空キーの構造をメモリ内で処理するコードがある。専用監査でも同じ入力を扱えるようにし、ルートキーを含む v2・v3 の `package-lock.json` と `npm-shrinkwrap.json` で部品が記録されることを確認する。 [通常の npm ロック処理](../Scan-DevSupplyChain.ps1#L9419)

### [P2] 専用走査では 6 件の確認だけで `iocData.releaseReady=true` になる

`-Checks Http2Shell,ScannerSelf` の合成走査は `currentCount=6`、`releaseReady=true` で完了した。Node.js 用データセットの読み込みは `NodeRuntime` 選択時に限られ、集計は読み込んだデータの異常件数だけを判定する。今回の更新前からある集計の挙動で、単一の真偽値を公開ゲートに流用すると 7 件目の確認を飛ばせる。 [集計処理](../Scan-DevSupplyChain.ps1#L1766) [Node.js データの読み込み](../Scan-DevSupplyChain.ps1#L12250) [README の公開判定の説明](../README.md#L144)

公開判定では `-Checks Recommended` の `scanComplete=true`、`completionStatus=complete`、`currentCount=7`、`releaseReady=true` をセットで要求する。公開ゲートを自動化する際も 7 件の確認を明示する。HTTP2Shell の鮮度は専用レポートの `http2ShellAssessment.baselineStatus=current` で別途確認する。 [Push 前手順](pre-push-test-procedure-ja.md#L227)

## 更新内容と CI の残存リスク

- IOC は 7 データセットとも期限超過・欠落・不正が 0 件。レポートの `expiresOn` は全件 `2026-12-07`。Keyv の 443 名・2,235 組の一致を維持し、npm/PyPI の完全一致 8 版と Node.js の High 告知 4 件を追加した。古い 41 組は台帳と公開履歴の照合までで、各アーティファクトの独立再検証は残る。可変 Actions タグの現行コミットも、更新時の照会が 403 だったため未確認。 [照合範囲と保留事項](ioc-maintenance-20261107-ja.md)
- HTTP2Shell の合成レポートに `CVE-2026-111497` の CISA KEV 掲載日 `2026-10-27` が入った。基準には .NET 11 Preview/RC の完全一致と Electron 公式 11 版の照合結果が反映されている。基準日は `2026-11-07`、確認間隔は 7 日で、`2026-11-15` UTC から `stale` になる。公開日が延びる場合は専用基準を再確認する。 [基準日の計算](../Scan-DevSupplyChain.ps1#L4528) [出典と製品別基準](http2shell-audit-ja.md) [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-111497)
- CI は checkout の直前で Git `2.18.0` 以上を要求し、`ref: ${{ github.sha }}`、`contents: read`、`persist-credentials: false`、`3d3c42e5aac5ba805825da76410c181273ba90b1`（`v7.0.1`）を確認した。Git 経由でイベントのコミットを取得する構成で、REST 経路への到達を抑える。固定版には `undici@6.27.0` が残り、Action 内の Git 初期化失敗による REST フォールバックも残る。更新時の公式版確認では修正版 Action は見つかっていない。公開候補で実ランナーの Git 経路とイベント SHA を確認し、対応版が出た時点で同梱版を照合して固定 SHA を見直す。 [ワークフロー](../.github/workflows/validate.yml#L12) [固定版のロックファイル](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/package-lock.json) [checkout の取得経路](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/src/git-source-provider.ts) [公式リリース](https://github.com/actions/checkout/releases) [undici 告知 1](https://github.com/advisories/GHSA-xjj6-f33q-929c) [undici 告知 2](https://github.com/advisories/GHSA-2m5v-pch6-74hx)

## 今回のローカル検証

実行環境は Windows PowerShell `5.1.26100.9711`。以下の回帰テストはいずれも終了コード `0`。

| 実行ファイル | 結果 |
| --- | --- |
| `tests/Test-IocMaintenance.ps1` | 39 ケース、1,089 assertion、158 fixture |
| `tests/Test-Http2ShellAudit.ps1` | 163 assertion。PC 分岐はリポジトリ内の合成ルートで検証 |
| `tests/Test-SecurityUpdate20261006.ps1` | 36 ケース、231 assertion |
| `tests/Test-ScanReviewRegressions.ps1` | 22 ケース、61 assertion |
| `tests/Test-LauncherScopeContracts.ps1` | 起動時の引数と走査範囲の契約に合格 |

さらに PowerShell 構文 6 ファイル、JSON 8 ファイル、checkout 前の Git 判定モック 12 ケース、checkout の設定とワークフローの正規化 SHA-256 の一致を確認した。`git diff --check` と `git diff --cached --check` は終了コード `0`。Git は既存の作業ファイルについて LF から CRLF への変換予告を出した。

| 合成走査 | 終了コード | 完了状態 | IOC current / releaseReady | HTTP2Shell |
| --- | ---: | --- | --- | --- |
| `tests/samples`、`Recommended` | 2 | `complete` | 7 / `true` | 対象外。DANGER 49 件、WARN 38 件は合成 fixture |
| `node-runtime-safe`、`NodeRuntime,Http2Shell,ScannerSelf` | 0 | `complete` | 7 / `true` | `current` |
| `node-runtime-safe`、`Http2Shell,ScannerSelf` | 0 | `complete` | 6 / `true` | `current` |
| npm v2・v3 空キーあり、`Http2Shell,ScannerSelf` | 1 | `incomplete-critical` | 6 / `true` | `metadata-parse-error`、部品の記録 0 件 |
| npm v3 空キーなし、同じチェック | 0 | `complete` | 6 / `true` | 部品の記録 1 件 |

再実行のコマンド。出力には毎回新しい `reports/` 配下のディレクトリを使う。上表の JSON はローカルの `reports/final-review-20261107-a5908655abd441e4a4b34c672a9687fb/` に保存した。

```powershell
$reviewOptions = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass')
powershell.exe @reviewOptions -File .\tests\Test-IocMaintenance.ps1
powershell.exe @reviewOptions -File .\tests\Test-Http2ShellAudit.ps1
powershell.exe @reviewOptions -File .\tests\Test-SecurityUpdate20261006.ps1
powershell.exe @reviewOptions -File .\tests\Test-ScanReviewRegressions.ps1
powershell.exe @reviewOptions -File .\tests\Test-LauncherScopeContracts.ps1
$reviewDir = '.\reports\final-review-' + [Guid]::NewGuid().ToString('N')
powershell.exe @reviewOptions -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -Checks Recommended -ReportDir $reviewDir -Quiet -NoColor
powershell.exe @reviewOptions -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples\node-runtime-safe -Checks NodeRuntime,Http2Shell,ScannerSelf -ReportDir $reviewDir -Quiet -NoColor
powershell.exe @reviewOptions -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples\node-runtime-safe -Checks Http2Shell,ScannerSelf -ReportDir $reviewDir -Quiet -NoColor
git diff --check
git diff --cached --check
```

空キーの再現入力は、合成フォルダー直下の `package-lock.json` に次の JSON を置き、`-Path` をそのフォルダー、`-Checks Http2Shell,ScannerSelf` として走査する。v2 は `lockfileVersion` を `2` にする。

```json
{"name":"review-fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"review-fixture","version":"1.0.0"},"node_modules/electron":{"version":"45.2.3"}}}
```

## コミット・公開前に残る確認

1. **コミット対象の確定。** `tests/Test-Http2ShellAudit.ps1`、`docs/http2shell-audit-ja.md`、`docs/ioc-maintenance-20261107-ja.md` は未追跡。追跡済み差分だけのコミットでは CI がテストを見つけられず、README の参照先も欠ける。今回のレポートを含め、必要な新規ファイルを候補に含める。`.codex/config.toml` は未追跡かつ ignore 対象外のローカル設定なので、ステージ対象から外す。既存の指示書や過去の設計文書の差分は公開対象として個別に判断する。 [CI のテスト呼び出し](../.github/workflows/validate.yml#L65) [README の参照](../README.md#L9)
2. **最終候補のローカル検証。** 上記修正後に合成回帰を再実行し、対象を確定した候補ツリーでリポジトリ自己検査の `scanComplete=true`・DANGER 0 件と、非上書き・BAT の特殊文字などの Push 前手順を確認する。今回、ローカル設定と別の作業差分を含むルート全体の自己検査および手順一式の再実行は省いた。`Test-SecurityBoundaryRegressions.ps1` も `-UserProfile` を呼ぶため、ローカル自動検証から除外した。実行条件を満たす環境でのコマンドは `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-SecurityBoundaryRegressions.ps1 -KeepArtifacts`。実 PC の HTTP2Shell 監査も今回の検証範囲外。 [Push 前手順](pre-push-test-procedure-ja.md#L325) [自動検証の制約](codex-review-checklist.md#L82)
3. **候補の秘密情報と配布物の確認。** ステージ予定の差分と送信対象の履歴の確認、配布アーカイブの作成と展開後の起動確認が残る。ローカルで `export-ignore` を照合し、サンプル本体と `reports/` の除外、サンプルの README と manifest の例外を確認した。配布候補でスキャナー、BAT、IOC 7 ファイルと文書の同梱、ローカル設定・実レポートの除外を再確認する。 [属性設定](../.gitattributes) [GitHub 公開前チェックリスト](github-publication-checklist-ja.md)
4. **GitHub Actions の実行。** 候補 SHA の `windows-latest` で `Scanner contract` の成功を確認する。pull request の実行では checkout ログの Git 取得経路と、checkout 直後の `git rev-parse HEAD` が `GITHUB_SHA` と一致することを確認する。今回の 12 ケースは Git バージョン判定のローカルモック。 [CI 定義](../.github/workflows/validate.yml) [Push 後の確認](github-publication-checklist-ja.md#L68)
