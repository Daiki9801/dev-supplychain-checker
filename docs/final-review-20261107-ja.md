# IOC・HTTP2Shell・CI の最終レビュー

## 2026-11-16 公開前レビュー

IOC確度の修正とNode・HTTP2Shell更新を含む21ファイルをレビューした。公開を妨げる実装上の指摘はなく、下記のWindows PowerShell 5.1回帰結果と、テスト後のコード・データのハッシュ一致を確認した。文書では実装時点の未公開記録と後続の公開工程を区別し、HTTP2Shellの7日方針を維持する記述へ整えた。

公開対象はスキャナー、IOC 3ファイル、CI workflow、回帰テスト5ファイル、fixture 2ファイル、README・CHANGELOG、文書・台帳7ファイル。ローカル設定と実行記録は対象外。個人のPCパスと代表的な秘密値形式を差分・新規ファイルで検査するが、秘密情報が存在しないことの無条件な保証とはしない。

今回のコミット・push・CI確認・mainマージは利用者から依頼された後続工程であり、以下の実装段階に記録した「GitHub未反映・承認待ち」を引き継ぐものではない。mainの確認済みSHA `4c2eb5b563418f5e636a259c98e96465df13fe91` は変更前HEAD `e50f3496a5a531af148c2bbb335e78aa4b134647` と同一tree。通常mergeで履歴を接続し、公開候補の内容を維持する。必須 `Scanner contract` と他のCIが対象SHAで成功した後にsquash mergeする。完了状態・コミットSHA・CI実行結果は当該PRとActionsの記録で確認する。

本節はコミット前のレビュー記録であり、未実行のCIやマージの成功を先に宣言するものではない。実PCの更新、ZIP配布検証、タグ・Release作成はこの工程に含めない。削除・移動・改名・既存ファイル全置換は0件。

## 2026-11-16 追加完了：Node IOC・HTTP2Shell再照合

残件だった新規Node High 7件のIOC反映と、HTTP2Shellの公式情報再照合を完了した。NodeはJSON・内蔵定義とも **24件**、HTTP2Shellは **11月16日確認・Electron 19版**となった。以下の「未収録」「HTTP2Shellがstale」という初回調査時点の記述は履歴であり、現在の状態は本節と [追加レビュー](node-http2shell-20261116-ja.md) を参照する。

公式公開情報は42試行で39件を取得した。取得URL・時刻・SHA-256・版対応は [公開証拠台帳](node-http2shell-20261116-evidence.json) に保存した。制限環境での接続失敗3件も記録し、取得できなかったCVE APIを確認済みとは扱っていない。新規Nodeの影響系列はNode.js自身の各CVEのImpact欄、修正版は公式セキュリティリリースを根拠とした。

### 変更と判定

- `CVE-2026-123864 / 123865 / 123866 / 123872` は22・24・26系列、`CVE-2026-123863 / 126051 / 123874` は24・26系列。修正版は **22.23.5 / 24.22.3 / 26.13.1**。全IDの接頭辞は `CVE-2026-`。版の一致はWARN・上流HIGHで、条件の成立はunknownのまま。
- 既存17 Node項目の範囲を保持し、その公式告知8ページも再確認した。Nodeの期限は12月16日。他の6 IOCデータセットの期限12月7日は変更していない。
- HTTP2ShellのBrotli、Node、Bun、Python、.NETの既存修正閾値を再照合した。11月のNode CVEをBrotliの閾値へ混ぜず、24.22.1は当該Brotli CVEで修正済み参照、新規7件では対象版という違いを保持した。
- Electron 44.11.0～44.11.3、45.3.0～45.3.3の8版を追加。公式リリースとGNリンク先、Chromium 8固定版のBrotli revision、固定decoderのエラー伝播を照合した。未照合の版へ範囲を広げない。
- HTTP2Shellの7日条件は維持し、**11月24日UTCからstale**。確認日前・当日・7日後・8日後のテストを追加した。
- .NET 11.0.0 GAは固定ソースだけで上流修正との対応を確定できず、unknownを維持。製品内蔵コピー・実際のロード・入力到達・再起動完了も未確認のまま。

今回の追加対応は17ファイル。`Scan-DevSupplyChain.ps1`、`iocs/known-node-runtimes.json`、`tests/Test-NodeSecurity20261116.ps1`（新規）、`Test-IocMaintenance.ps1`、`Test-Http2ShellAudit.ps1`、`.github/workflows/validate.yml`、`tests/samples/node-runtime-safe/.nvmrc`、`tests/samples/manifest.json`、README、CHANGELOG、文書・台帳7ファイル。前段のIOC確度変更を含む作業ツリー全体では21ファイルとなる。

CIの修正済み版・合成PEの版情報を更新し、旧修正版を新規CVEの陽性ケースとして残した。新規Node回帰はIOC maintenanceから呼び出す。fixture数158と自己参照の許可パス・ルールは維持し、内容を変更したfixture1件・workflow・maintenanceテストのハッシュだけを整合させた。

### 最終ローカル検証

Windows PowerShell **5.1.26100.9818**。構文14ファイル・必須JSON10ファイル、トップレベル11スイートと子スイート2件がすべて合格した。

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-NodeSecurity20261116.ps1
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-IocMaintenance.ps1
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-Http2ShellAudit.ps1
```

全スイートのコマンドは [Push前手順](pre-push-test-procedure-ja.md#2-構文json差分検証) に記載。結果は次のとおり。

| 検証 | 結果 |
|---|---|
| 新規Node回帰 | **140境界・3走査・325 assertions**。通常・欠落・不正の各データ経路、修正版・prerelease・対象外系列、TXT / JSON、ホスト探索なし |
| HTTP2Shell | **252 assertions**。Electron追加8版・未知版と4日付境界を含む |
| IOC maintenance / confidence | **43ケース・1,121 assertions・158 fixtures** / **10ケース・289 assertions**。前段の確度変更も維持 |
| Git取得 / launcher | **39ケース・25 CIブロック・451 assertions** / 契約合格。JSON検証対象の追加後にGit取得契約を再実行 |
| SecurityBoundary / SecurityUpdate | **144 assertions** / **36ケース・231 assertions** |
| PythonMetadata / StaticTriage | **88ケース・343 assertions** / **56ケース・116 assertions** |
| ScanExecution / ScanTriagePerformance | **20ケース・54 assertions** / **26ケース・72 assertions** |
| ScanReview | **22ケース・61 assertions**。最終workflowハッシュの自己参照、改変・コピー拒否も合格 |

全合成サンプルの `-Checks Recommended` は終了2、DANGER 49 / WARN 38 / CAUTION 26で必須カテゴリを維持。`-Path tests -Checks Recommended` は終了0、manifest一致のskip 139件、未知fixture・ハッシュ不一致0件。修正済みNode fixtureのNodeRuntime単独と `NodeRuntime,Http2Shell,ScannerSelf` はともに終了0。後者はHTTP2Shell `current`、DANGER / WARN / CAUTIONすべて0件。リポジトリ自己検査は終了1、DANGER / WARN 0・既存workflowのCAUTION 1件だった。

上記5走査はすべてcomplete、一般IOC current 7件・`releaseReady=true`、network / externalCommands / targetCodeExecutionはすべてnone。実PCのNode・npm・プロファイル・端末ログへ探索を広げていない。

結果はローカル専用の `reports/node-review-suites-be8804d3e9b94ac380744aa234180787.jsonl`、`reports/node-http2shell-final-a87f6fc984a840da8e590690814c0d76/` に保持した。新規Nodeの最終結果は `reports/node-security-20261116-4ab3a5e0414247f1b1947d5830415038/result.json`。テスト作成時のscope名の期待値誤りを修正した失敗ログも保持した。実装不具合による回帰の未解決失敗はない。

### 残る境界と承認

今回依頼されたローカル実装・公式調査・回帰・文書更新は完了。実PCのNode更新、GitHubへの反映、実ランナーCI、ZIP配布検証、タグ・Release公開は未実行で、それぞれ対象・差分・操作を確定した後の承認対象となる。過去のコミット・pushの操作回数を使い回していない。

Medium / Lowや未照合majorは既存のNode収録方針の対象外。未確認Injective 2組・Actionsタグ15件の証拠限界も前段どおり保持する。.NET 11.0.0・製品内蔵コピー等を安全と断定せず、公開説明に残す。スキャナーは依存不要・offline-only・read-onlyを維持している。

HEADは `e50f3496a5a531af148c2bbb335e78aa4b134647` のまま。削除0件、移動0件、改名0件、既存ファイルの丸ごと置換0件。以前の変更、`.codex/`、調査・検証の原本を保持した。

## 2026-11-16 IOCの確度反映・Node.js更新調査

旧41組とActionsタグ15件の追跡調査を実装へ反映した。個別の悪性根拠が不足するInjective 2組はWARN、一次報告が版を明示する39組と既知悪性コミット3件はDANGERを維持する。README、出典記録、回帰手順も更新した。詳細な出典と判定は [IOCの証拠と判定の修正](ioc-confidence-20261116-ja.md) を参照する。

今回の作業はローカル実装・合成検証・承認済みNode調査まで。HEADは `e50f3496a5a531af148c2bbb335e78aa4b134647` のままで、stage・commit・push・merge・タグ・Release公開・依存導入は行っていない。以下の11月9日以前の記述は各時点の履歴であり、今回の未コミット変更のCI・配布検証結果には流用しない。

### 実装結果

| 対象 | 今回の動作 |
|---|---|
| Injective 2組 | `wallet-cosmostation@1.20.21` / `wallet-cosmos-strategy@1.20.21`（どちらも `@injectivelabs/`）。installed / lockはWARN・medium、manifest / cache等はWARN・low。見出しで個別侵害は未確認と明示し、`riskType=posture` とする |
| 内蔵定義とnpm | 外部IOCが欠落・不正でも上記2組をDANGERに戻さない。通常のPackages、npm global / cacheの静的メタデータに共通の証拠評価を適用する |
| 旧41組のうち39組 | Socketの一次報告に13パッケージ×3版を明示的に照合。厳密一致のDANGER・highを維持し、`primary-report-exact` / S12 / 照合日を記録する。全41組とも配布アーティファクト自体の独立解析は未実施 |
| Actionsタグ15件 | WARNと `currentTarget=unverified` を維持。2026-11-09に2リポジトリで観測したtosアクセス遮断はリポジトリ単位で記録し、残13タグも照会済みと表現しない。不変の悪性コミット3件のDANGERは維持 |
| 表示と分類 | TXT / JSONの見出し・根拠・信頼度を一致させる。未確認2組を既知悪性のSecurityEvidenceへ計上しない。通常のWARNとして優先表示される場合も未確認という説明を残す |
| npm cacheの完了状態 | `bounded-metadata-within-limits` が文字列 `limit` の部分一致でpartial扱いになる既存不具合を修正。実際のpartial / limit-reachedは引き続き区別する |
| HTTP2Shell回帰 | 既存lockfileテストの「常に終了0」という期待を修正。currentなら終了0、stale等なら終了1と専用WARNのみを要求し、予期しない警告は許容しない。製品側の基準日と期限切れ判定は変更しない |

変更対象は13ファイル。スキャナー1、IOC JSON 2、テスト4（新規 `Test-IocConfidenceRegressions.ps1` を含む）、README / CHANGELOG、文書4（本追補・新規出典記録・IOCレビュー・Push前手順）。既存の自己参照テスト2ファイルのハッシュは内容を確認して更新し、許可対象パス・ルールは増やしていない。

### Windows PowerShell 5.1の検証

Windows PowerShell **5.1.26100.9818**。変更した5 PowerShellファイルの構文解析と必須9 JSONが合格。トップレベル11スイートはすべて終了0で、IOC maintenanceが呼び出す追加スイートも合格した。再実行の全一覧は [Push前手順](pre-push-test-procedure-ja.md#2-構文json差分検証) にある。

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-IocMaintenance.ps1
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-Http2ShellAudit.ps1
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-ScanReviewRegressions.ps1
```

| スイート | 最終結果 |
|---|---|
| CheckoutContract | 39ケース・25 CIブロック・451 assertions |
| LauncherScopeContracts | 合格 |
| SecurityBoundaryRegressions | 144 assertions |
| SecurityUpdate20261006 | 36ケース・231 assertions |
| IocMaintenance | 43ケース・1,121 assertions・158 fixtures |
| 同上が呼ぶIocConfidenceRegressions | 10ケース・289 assertions。2組の各検出経路、39組、15タグ・3コミット、隣接版、内蔵fallback、TXT / JSONを確認 |
| Http2ShellAudit | 237 assertions |
| PythonMetadataRegressions | 88ケース・343 assertions |
| StaticTriageRegressions | 56ケース・116 assertions |
| ScanExecutionRegressions | 20ケース・54 assertions |
| ScanTriagePerformanceRegressions | 26ケース・72 assertions |
| ScanReviewRegressions | 22ケース・61 assertions。更新した自己参照と改変・コピー拒否も再確認 |

次の5走査も同じWindows PowerShell 5.1で完了し、すべて `scanComplete=true` / `completionStatus=complete`。network / externalCommands / targetCodeExecutionはすべて `none`、一般IOCはcurrent 7件・`releaseReady=true`だった。

| スキャナー引数の対象・検査 | 結果 |
|---|---|
| `-Path .\tests\samples -Checks Recommended` | 終了2。合成のDANGER 49 / WARN 38 / CAUTION 26。必須の5検出カテゴリを維持 |
| `-Path .\tests -Checks Recommended` | 終了0。manifestに一致するfixtureを139件skip、未知ファイル・ハッシュ不一致・解析エラー0 |
| `-Path .\tests\samples\node-runtime-safe -Checks NodeRuntime` | 終了0。同梱オフライン基準のnot-affected参照を確認。最新CVE全体の陰性を意味しない |
| 同じ合成ルートの `-Checks NodeRuntime,Http2Shell,ScannerSelf` | 終了1。HTTP2Shell基準staleの専用WARN 1件を確認 |
| `-Path . -Checks Recommended -ReportDir .\reports` | 終了1。DANGER 0 / WARN 0 / CAUTION 1。既存の手動workflow起動設定のCAUTIONのみ |

各TXT / JSONと結果JSONは `reports/ioc-confidence-final-045b2cf6bb61442988644eee2b653eb5/` に保持した。自己検査は `reports/` 全体を対象外にし、過去の合成生成物を混入させていない。

初回のHTTP2Shell回帰だけは、11月15日UTCからのstale WARNに対し旧テストが終了0を要求して失敗した。上記の期待値修正後に全237項目が合格した。これは期限切れの警告を検証した結果であり、専用基準の鮮度をcurrentへ戻した結果ではない。初回ログと失敗時の生成物も保持している。

### Node.jsの更新判断

承認されたnodejs.orgへの読み取り20回のうち6回を使用し、[11月11日セキュリティ告知](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases)、公式リリース一覧・サポート情報・3系列の修正版を確認した。修正版は **22.23.5 / 24.22.3 / 26.13.1**。High 7件、Medium 6件、Low 3件が含まれ、24.22.1 / 24.22.2も今回の更新対象となる。

別途承認された `Get-Command node.exe -CommandType Application -All` とFileVersionInfoの読み取りで、PATH候補2件を照合した。通常導入版は同じ24.xの修正版への更新を推奨し、Codex同梱版はアプリの更新経路・ベンダーの修正状況を確認する。個別のPCパス・版の記録はGit除外のローカルレポートだけに保存し、この公開用文書には転記していない。node.exeは実行せず、実行中プロセス・脆弱な機能への到達性・ベンダー独自バックポートは確認していない。

スキャナー自体にNode.jsは不要。通常導入版の更新も同梱ファイルの直接置換も実施していない。Nodeの陰性判定は、最新の公式修正版に達したことを保証しない。

### 残る対応と承認範囲

| 残件 | 必要な対応・境界 |
|---|---|
| Node IOCの11月11日分 | 同梱Node IOCは11月7日の内容で、新規High 7件は未収録。各CVEの影響系列・版境界・利用条件を確認してからデータ・内蔵定義・境界テストへ追加する。今回の「更新必要性の調査」では範囲を推測して追加しない |
| HTTP2Shell基準 | 11月7日のままでstale。Bun / Electron / Python / .NET等も含む再照合が必要。今回のNode公式サイトだけの通信承認では、それらの外部照会までは行わない。確認日だけの延長は禁止 |
| 実PCのNode更新 | 実際の導入・更新は未承認。導入方式、取得元、署名等の確認方法、正確な変更対象を確定して別途承認する。同梱版はアプリ側の更新を使う |
| 2組・15タグの追加証拠 | 未確認と明示して検出を維持する。2組を確定扱いに戻すには個別一次証拠が必要。タグは信頼できる現行SHAが取得できる状況を待って再照合する。今回、配布物の取得・実行は行わない |
| GitHub反映・配布 | 今回の13ファイルを含む新しい差分・対象ブランチを確定してstage / commit / pushを別途承認し、候補SHAでCIを確認する。前回の操作回数の承認は使い回さない。ZIP作成・展開、タグ・Release公開も今回の範囲外 |

一般IOCの `lastUpdated=2026-11-07`、期限2026-12-07は維持した。`iocData.releaseReady` は一般データセットの鮮度・構造の指標であり、上記の新規Node CVE収録やHTTP2Shell再照合を完了させるものではない。

Node調査のローカル記録は `reports/node-update-20261116-1a61c4428b88409dbf2647701c4b8d78.json`、公式取得の台帳は同IDの `node-review-20261116-*.jsonl`。回帰の初回台帳は `reports/ioc-confidence-suites-20261116-1a61c4428b88409dbf2647701c4b8d78.jsonl`、最終IOC結果は `ioc-maintenance-regression-b9473b2649d84d3a959b003171bc3e29/result.json` と `ioc-confidence-regression-82d5da46e3194dfda4b47f680c1d720c/result.json`（いずれも `reports/` 配下）に保持した。実PC・認証ファイルの走査は行わず、承認されたPATH候補の版情報だけを読んだ。スキャナーの依存不要・offline-only・read-onlyは維持した。

今回の削除0件、移動0件、改名0件、既存ファイルの丸ごと置換0件。既存の無関係な `.codex/` と過去の検証物は保持した。

## 2026-11-09 マージ判断の追補

利用者から「残件対応を行いマージし完成させる」との指示を受け、[PR #10](https://github.com/Daiki9801/dev-supplychain-checker/pull/10) をmainへ統合する工程に進める。11月7日に合格したスキャナー・BAT・CI・IOCデータは変更せず、未コミットだった下記の完了記録を含めて文書5ファイルを整えた。CHANGELOGの実ランナー未確認という記述、IOCレビューの旧境界テストの説明、Push前手順の版番号を現在の実装に合わせ、READMEにも出典の確認限界を明記した。

GitHubで対象head `01effcb`、main `505a278`、競合なしを再確認した。Secret scanningとpush protectionは有効で、秘密値を含めないAPI照会による未解決アラートは0件。リポジトリが許可する方式はsquash mergeだけであるため、設定を変えずにその方式を使用する。更新後のPRの先端を固定してCI成功を確認したうえで、draftを解除してマージし、main側のCIも確認する。マージの確定状態・コミットは [PR #10](https://github.com/Daiki9801/dev-supplychain-checker/pull/10)、実行結果は [Validateの記録](https://github.com/Daiki9801/dev-supplychain-checker/actions/workflows/validate.yml) を一次記録とする。

今回のマージは、Actions可変タグ15件の現行実体や旧41組の配布アーティファクトを独立確認したという判断ではない。これらは出典上の限界としてREADMEと本レポートに残し、IOC値・確認日・信頼度を変更しない。一般IOCの期限2026-12-07とHTTP2Shell基準が2026-11-15 UTCからstaleになる条件は、11月9日時点でも期限内。実PC走査、タグ付与、Releaseの作成・添付・公開は今回のマージ作業に含めない。

11月9日のローカル点検では、文書5ファイルのUTF-8 BOMなし・LFと73件のローカル参照が正常で、`git diff --check` が合格した。Windows PowerShell 5.1による `tests/samples/node-runtime-safe` の `NodeRuntime,Http2Shell,ScannerSelf` 走査は終了0・complete、IOC current 7件、`releaseReady=true`、HTTP2Shell基準 `current`。TXT/JSONと以後の実行証跡はローカル専用の `reports/merge-completion-20261109-b52af145cdcd49c3ae74cbe2f00f088b/` に保持する。

以下の11月7日の承認待ち・未コミットという記述は当時の履歴であり、上記のマージ指示とPRの状態を優先する。コードが変わらない文書追補なので、ローカルでは参照・差分の点検と日付に依存する合成走査を行い、PR・mainのCIでプロジェクト全体の契約を検証する。新しい配布候補は文書差分を反映したコミットから生成し、全64エントリの照合と、実行物が11月7日に展開検証済みのものと同一であることを確認する。既存のZIP・展開物は保持する。

## 2026-11-07 検証済み候補の記録

**2026-11-07 17:15 JST 最終結果: Git直接取得への切替、mainとの履歴の競合解消、候補コミット `01effcb` の配布検証・push・実CI確認まで完了した。`Scanner contract` は全27ステップ成功。** checkout同梱undiciを使わない取得経路が実ランナーで成立した。技術的な配布・CIゲートは合格し、mainへの反映・タグ・Release公開は承認待ち。以下の完了状態を最新とし、後続の節は各段階の履歴を残す。

## 最終候補と検証結果

| 項目 | 確定結果 |
|---|---|
| 候補コミット | [`01effcbf8913962a4a6c1c9cdab360e5805abdc3`](https://github.com/Daiki9801/dev-supplychain-checker/commit/01effcbf8913962a4a6c1c9cdab360e5805abdc3)、tree `9fd43e06c30e169279660e2fd4f5ac972c3cc38c` |
| 履歴統合 | mainの固定SHA `505a27843bb2e85a3c5af8b769c9705a875a1bd7` をfetchし、取り込み済み `8e911a6` とのtree完全一致をローカルでも確認。作業ブランチへ内容を保つmergeを行い、承認済み6ファイルを追加コミットした。親は `be18881` と `505a278`。221エントリすべてを照合し、計画外の内容・モード変更0件 |
| PR | [#10](https://github.com/Daiki9801/dev-supplychain-checker/pull/10)、open / draft、head `01effcb`、base `505a278`。CI終了後の確認で `mergeable=true` / `mergeable_state=clean`。mainとの差分は承認済み31ファイルに一致 |
| 実CI | [Validate run 42353763124](https://github.com/Daiki9801/dev-supplychain-checker/actions/runs/42353763124)、attempt 1、候補head `01effcb`。`windows-latest` の `Scanner contract` が2026-11-07 08:13:36 UTCにsuccess。準備・完了を含む27ステップすべてsuccess、失敗・skipなし |
| CIで成立した取得経路 | `Fetch event commit with Git` が成功。Git版・workspace・取得SHA・HEADの検査を通過してから、PowerShell構文、取得契約、HTTP2Shell、境界、IOC、Python、triage、各世代の合成回帰、レポート・BAT安全性、公開用表記の検査が成功した |
| 最終ZIP | `reports/ci-continuation-20261107-85c6d06176fe49d59576811e82f5c069/dev-supplychain-checker-candidate-v2.zip`。**3,521,493 bytes**、SHA-256 **`8d0dcabcc9e82d07c6e57a1ea6bf27db98b835073c0a44e57421d16013b1f1ea`** |
| 配布一致 | コミットから生成した64ファイル、展開後 **5,530,588 bytes**。承認一覧・ZIP内・`expanded-candidate-v2/` 展開後のSHA-256がすべて一致。ZIP作成・走査後も元の64ファイルが不変であることを確認 |
| 展開物の実行 | 合成 `clean-js` に対するBATと、合成 `node-runtime-safe` に対するPowerShellの `NodeRuntime,Http2Shell,ScannerSelf` がともに終了0・complete。IOC current 7件、`releaseReady=true`、HTTP2Shell基準 `current`、配布状態complete。network / externalCommands / targetCodeExecutionはすべて `none` |
| ローカル回帰・差分 | Windows PowerShell 5.1で取得契約39ケース・451 assertions、自己参照22ケース・61 assertionsが合格。先行11スイートも合格。自己検査はDANGER/WARN 0件。`git diff --check` とmain固定SHAからの候補差分の検査も合格 |

実行した追加Git操作は、承認どおり固定SHAのfetch 1回、作業ブランチ上のmerge 1回、6ファイルのstageとmerge commit 1件、通常push 1回。PR #10は維持し、追加のPR作成・本文更新は行っていない。既存コミットとZIPは保持した。追加操作での削除・移動・改名・既存ファイルの丸ごと置換は各0件。この対応全体では前段で新規生成した失敗ZIP2件だけを削除し、既存ファイルの削除は0件。

最終証跡はローカル専用の `reports/ci-continuation-20261107-85c6d06176fe49d59576811e82f5c069/` に保持した。承認対象は `continuation-plan.json` と `continuation.patch`、結果は `commit-receipt.json`、`package-receipt.json`、`push-receipt.json`、`ci-final-42353763124-1.json`。GitHub照会は合計 **GET 29/60回、PR作成 1/1回**で終了した。既存認証をGit/API内部で利用し、秘密値を表示・保存していない。

### 残る承認事項と検証の限界

| 区分 | 必要な判断・対象 |
|---|---|
| mainへ反映する場合 | draft PR #10をレビュー可能にする変更と、候補 `01effcb` のmainへのmergeを明示承認する。今回の履歴統合は作業ブランチ内だけで、mainは `505a278` のまま。反映前に先端・CI・差分を再確認する |
| タグ・Releaseを公開する場合 | タグ名、対象コミット、Release本文、添付物を確定して別途承認する。検証済み添付候補は上記ZIPとSHA-256。`iocData.releaseReady=true` やCI成功だけでは公開承認と扱わない |
| IOCの公開説明 | Actions可変タグ15件の現行実体と旧41組のアーティファクト独立確認が未完である範囲を、公開説明として受け入れる判断が必要。追加調査を要求する場合は、停止した403照会の再試行条件・対象・回数を別途承認する。確認済みと誤記しない |
| 公開時点の鮮度 | 一般IOCの期限は2026-12-07。HTTP2Shell基準は2026-11-15 UTCからstaleになる。公開日が延びる場合は再評価し、日付だけを延長しない |
| 結果追記をPR・配布にも含める場合 | この最終結果の追記はCI終了後のローカル変更で、候補 `01effcb` と検証済みZIPには含まれない。本レポート1ファイルの追加stage・commit・pushと、それを含む新しい配布候補の検証が別途必要。今回承認された追加1コミット・1pushは完了済み |

実PCの `UserProfile` / `MajorLocations` / `EndpointTelemetry`、実環境のHTTP2Shell監査は未実行。今回の結果は明示した合成ルートとCIの範囲であり、実PCの安全性を判定しない。スキャナー本体の依存不要・offline-only・read-only契約は維持した。

## 履歴: 最初の配布・GitHub確認と履歴統合の提案

**2026-11-07（JST）配布・GitHub確認追補: 承認された31ファイルを `be18881` にコミットし、コミット由来のZIP検証・通常push・[draft PR #10](https://github.com/Daiki9801/dev-supplychain-checker/pull/10) の作成まで完了した。候補SHAのCIはmainとの履歴の競合で未実行のため、公開保留を継続する。** 追加のGit候補選択修正はローカル検証済み。以下は追加承認前の状態を記録した履歴。

利用者が31ファイルのstage・1コミット、64ファイルのZIP作成・展開検証、1回の通常push、draft PR作成、最大60回のGitHub API読取とPR新規作成1回を明示承認した範囲で実行した。公開リポジトリへの送信を伴う。mainへのmerge、タグ、Release公開、force push、実PC走査は実行していない。

| 実施項目 | 結果 |
|---|---|
| コミット | `be188812f2944b965f61c1c1390d57892b969362`。親は `8e911a6ef5a255cf7bd5a8d430da4175d7dbbd44`。承認済み31ファイルのGit blobを一覧と照合し、既存4指示・設計文書の差分も承認どおり含めた。`.codex/` と `reports/` は対象外 |
| ZIP | `reports/git-checkout-20261107-9b3a7e95bca642fbaafb7d489e9dbbe7/dev-supplychain-checker-git-candidate.zip`。3,518,810 bytes、SHA-256 `9e7d33ef46c18f641b283ba6ac14fa307ed8829abe42e4d447bedfc1ca873f0b` |
| 配布内容 | 64ファイル、展開後5,521,853 bytes。承認一覧・コミット・ZIP内・展開後の全ファイルのハッシュが一致。展開先は同フォルダーの `expanded-git-candidate/`。作成前の31原本も検証時に不変だった |
| 展開後BAT | `run-checker.bat path <元リポジトリのtests/samples/clean-js> --no-pause` は終了0、完了、IOC current 7件、`releaseReady=true`、`distributionStatus=complete` |
| 展開後PowerShell | `-Path <元リポジトリのtests/samples/node-runtime-safe> -Checks NodeRuntime,Http2Shell,ScannerSelf` は終了0、完了、IOC current 7件、HTTP2Shell基準 `current`。`executionSafety` のnetwork / externalCommands / targetCodeExecutionはすべて `none` |
| GitHub | `codex/triage-performance-v0.1.27` への通常pushを1回実施し、main向けdraft PR #10を作成。候補SHAは `be18881`。mainやReleaseには反映していない |
| CI | PRは `mergeable=false` / `mergeable_state=dirty`。候補SHAの `Scanner contract` は未実行。過去のmain・旧候補の成功を今回の成功として扱わない |

配布生成では2件の問題を検出して修正した。Git実行ファイルの探索が複数候補を返し、初回はプロセスを起動できなかった。次に、`git archive` にも既存の `core.autocrlf=true` が適用され、61ファイルの改行が承認したLFバイト列と異なった。どちらも展開前に停止した。先頭Git候補を明示し、生成コマンドだけに `git -c core.autocrlf=false -c core.eol=lf archive --format=zip <SHA>` を指定して再生成したところ、全64ファイルが一致した。Git設定ファイルは変更していない。

失敗時にこの作業で新規生成した一時ZIPを、内容・絶対パス・未追跡を確認して各1件、計2件削除した。既存ファイル削除0件、移動0件、改名0件、既存ファイルの丸ごと置換0件。成功したZIP、以前のZIP、展開物、原本、履歴は保持している。

### 競合の根拠と追加の修正

GitHub上のmainは `505a27843bb2e85a3c5af8b769c9705a875a1bd7`。PR #9で以前の変更がsquash取り込みされている。mainのtreeと、今回の親 `8e911a6` のtreeは、ともに **`40c0514ca5e9684edbaa9d91c721b1b6fac58990`** で一致した。ファイル内容・パス・Gitのファイルモードは同じだが履歴が異なるため、その後の変更を含むPR #10が競合している。`be18881` のtreeは `994717f849f31d02f6618103da6e37571cff6047`。

配布生成で判明した複数Git候補の問題はCIにも該当するため、`.github/workflows/validate.yml` の実行ファイル探索を `Get-Command ... | Select-Object -First 1` に修正した。低優先度候補が実行されると失敗する合成回帰を追加し、スキャナーの自己参照用workflowハッシュとCHANGELOG・検証手順を更新した。今回追加した未コミット差分は、この5ファイルと本レポートの計6ファイル。

Windows PowerShell **5.1.26100.9711** で、変更に関係する次の2スイートが終了0。先行する11スイートの合格記録は下の実装時点の節に残した。

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CheckoutContract.ps1
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-ScanReviewRegressions.ps1
```

- `Test-CheckoutContract.ps1`: **39ケース、25 CIブロック、451 assertions**。
- `Test-ScanReviewRegressions.ps1`: **22ケース、61 assertions**。更新したworkflowの自己参照、改変・コピーの拒否を確認。

追加修正後の `-Path . -Checks Recommended` 自己検査も完了し、終了1、DANGER 0 / WARN 0 / CAUTION 1、IOC current 7件、`releaseReady=true`。CAUTIONは既存の手動workflow起動設定。`-ReportDir` に `reports/` 全体を指定して合成生成物を除外し、TXT/JSONは新規の `reports/ci-continuation-20261107-85c6d06176fe49d59576811e82f5c069/repository.*` に保存した。

証跡はローカル専用の `reports/publication-next-20261107-4a328d9877a740d5b2421bbb39c5ade0/` に保存した。`commit-receipt.json`、`package-receipt.json`、`push-receipt.json`、`pull-request-receipt.json`、`ancestry-inspection.json`、`continuation-test-results.json` を参照。GitHub APIはこの時点でGET **14/60回**、PR作成 **1/1回**を使用。必要な既存認証はGit/APIのメモリ内で利用し、秘密値の表示・保存はしていない。

### 次に必要な操作と承認範囲

すでに承認された1コミット・1pushは完了した。今回必要になった追加のfetch・履歴統合・コミット・pushは、その回数と操作の範囲を超えるため未実行。正確な6ファイルと配布64ファイル、新規出力先を `reports/ci-continuation-20261107-85c6d06176fe49d59576811e82f5c069/continuation-plan.json` に確定し、次の一連の操作を追加承認の対象とする。

1. mainの固定SHA `505a27843bb2e85a3c5af8b769c9705a875a1bd7` を1回fetchし、取得したtreeが `8e911a6` と一致すること、ローカル・リモートの候補先端が `be18881` のままであることを再確認する。不一致なら停止する。
2. 作業ブランチ上で `git merge --strategy=ours --no-ff --no-commit <mainの固定SHA>` により、すでに内容を含むmainの履歴を接続する。上記tree一致を前提に、現在のファイル内容を保つための操作。mainブランチへのmergeではない。既存コミットを改変せず、確定6ファイルだけをstageしてmerge commitを1件作成する。
3. 新コミットと一覧を照合し、新規 `dev-supplychain-checker-candidate-v2.zip` と `expanded-candidate-v2/` を同じ追補フォルダー内に作成する。64ファイルを展開し、合成BAT・NodeRuntime/HTTP2Shell検証を行う。既存ZIP・展開物を置換しない。
4. 検証が成功した新コミットを同じ作業ブランチへ通常push 1回。draft PR #10を維持し、既承認のAPI読取残数内で最終候補の `Scanner contract` を確認する。CIの失敗や想定外のリモート変更があれば停止して報告する。

この技術ゲートが成功しても、mainへのmerge、タグ、Release公開には別の承認が必要。一般IOCの期限は2026-12-07、HTTP2Shell基準は2026-11-15 UTCからstale。Actions可変タグ15件と旧41組のアーティファクト独立確認は未完であり、公開説明にこの範囲を残す。実PCの自動探索は今回も検証していない。

## 実装時点の記録: Git直接取得・CI範囲整理

**2026-11-07（JST）最終追補: Git直接取得への切替とCIの合成検証範囲の整理を実装し、ローカル11スイートが合格。公開判定は保留を継続する。** このworkflowからcheckout Actionとその同梱undiciの実行経路を除いた。作業ツリーの自己検査は完了・DANGER/WARN 0件。残る必須工程は、コミット対象の確定、候補SHAでの実GitHub Actions成功、更新した配布物の検証と公開承認。過去の出典・配布検証には未解決事項と適用時点の違いがあるため、以下で区別する。

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
