# Pythonメタデータ・検査精度の改善記録（2026-10-08）

対象は v0.1.23 のPythonパッケージ判定、関連するIOC照合・ロックファイル処理、OCR/署名ファイルの分類です。提供された `dev-supplychain-report-20261008-171513.json` とチェッカーのコードを調べ、リポジトリ内の合成データで再現・修正・回帰検証しました。実プロジェクトのファイルや権限は変更していません。

## 確認した問題と修正

| 優先度 | 問題・影響 | 修正と検証 |
| --- | --- | --- |
| P1 | `pycparser 3.0` と `pip 24.0` の正常な短縮バージョンがnpm形式の検証で拒否され、critical coverage failureになる。 | Python専用のPEP 440検証を導入。報告と同じ `.venv`／`.local` 配置の合成検査は `OK`、`complete`、critical failure 0件。 |
| P1 | 汎用バージョン抽出がepochやローカル版を切り落とし、異なるPython版を既知IOCと誤照合し得る。 | epoch・pre/post/dev・localを保持。別版の陰性ケースと、等価表記・リリース末尾ゼロの陽性ケースを検証。IOC読込・索引・検出で同じ同一性規則を使用。 |
| P1 | Poetry/uvの別パッケージ、入れ子テーブル、複数行文字列のサンプルから名前と版を組み合わせ、誤ったexact/DANGER証拠を生成し得る。 | 文字列・コメントをマスクし、同じ `[[package]]` ブロック内のliteralフィールドだけを照合。TOMLキーの大文字小文字を区別。未閉鎖文字列や重複・不正なidentityはcritical failure。 |
| P2 | 折り返されたName/Versionや不正なMETADATAヘッダーを無視してidentityを確定し得る。 | identityの折り返し・重複、孤立した継続行、制御文字、不正なヘッダーを拒否。128 KiB／1,024行制限、UTF-8 BOM、CRLF、説明本文を読まない境界、キャッシュを検証。 |
| P2 | Pipfile.lockの短縮版を読み落とす一方、配列の単一要素展開や不正なsection・versionを見逃し得る。 | JSONルート・section・entry・versionの型とexact pinを検証。`==v1.0` を評価し、配列・数値・不正なpin・バージョンをcritical failureとして保持。 |
| P2 | `.traineddata` と `.p7s` をテキストとして扱い、不要なサイズ超過・文字コード警告を出す。 | 既存のバイナリ分類に追加。本文を読まずにスキップし、該当する既知ハッシュ検査とサイズ制限によるcritical failureは維持。 |

主な実装箇所は [Scan-DevSupplyChain.ps1](../Scan-DevSupplyChain.ps1) の `Test-LocalIocEntry`、`Finalize-IocIndexes`、`Get-ExactPackageIocMatch`、`Read-PythonDistributionHeader`、`ConvertTo-PythonPackageVersion`、`Scan-PythonTextLock`、`Scan-PipfileLockJson` です。

## 変更ファイル

- `Scan-DevSupplyChain.ps1`: 判定・照合・ヘッダー・ロックファイル・バイナリ分類を改善。
- `tests/Test-PythonMetadataRegressions.ps1`: 新規合成回帰。既存のファイルを上書きせず、GUID付きの `reports/` 配下に成果物を保持。
- `tests/Test-SecurityUpdate20261006.ps1`、`tests/Test-IocMaintenance.ps1`: AST helper allowlistにPython検証を追加。
- `.github/workflows/validate.yml`: 新規回帰テストをWindows PowerShellで実行。
- `README.md`、`CHANGELOG.md`: 新しい判定境界と制限を記載。
- `docs/pre-push-test-procedure-ja.md`: 回帰テストとPowerShell 7からのWindows PowerShell 5.1呼び出し例を追加。
- この記録。

## 検証結果

Windows PowerShell 5.1で次を実行しました。テストに必要な外部依存関係の追加やネットワークアクセスはありません。

| コマンド・検証 | 結果 |
| --- | --- |
| `tests/Test-PythonMetadataRegressions.ps1` | 88ケース、343検証、合格。 |
| `tests/Test-SecurityUpdate20261006.ps1` | 36ケース、231検証、合格。 |
| `tests/Test-IocMaintenance.ps1` | 39ケース、1,082検証、158 fixture、合格。 |
| `tests/Test-LauncherScopeContracts.ps1` | 合格。 |
| `tests/Test-SecurityBoundaryRegressions.ps1 -KeepArtifacts` | 合格。プロファイル関連テストはリポジトリ内の合成ルートへリダイレクト。 |
| PowerShell parser／JSON | 6スクリプト／9 JSONファイルが合格。 |
| `Scan-DevSupplyChain.ps1 -Path tests/samples -Checks Recommended` | 終了コード2、`complete`。DANGER 49／WARN 38／CAUTION 26／INFO 19／OK 1。必須5 DANGERカテゴリを維持、全7 IOCがcurrent。 |
| `Scan-DevSupplyChain.ps1 -Path tests -Checks Recommended` | fixture検証は合格。既知fixtureスキップ183、未知fixture 0、ハッシュ不一致0。下記の既存2件だけがnon-critical gap。 |
| `Scan-DevSupplyChain.ps1 -Path tests/samples/node-runtime-safe -Checks NodeRuntime` | 安全なproject referenceのinventory契約が合格。 |
| `run-checker.bat path tests/samples/clean-js --no-pause` | 終了コード0、`OK`、`complete`。 |
| `git diff --check` | 合格。改行コードの変換予告だけ。 |

最終Python回帰成果物: `reports/python-metadata-regression-fbf92ab244a84d41b145b2bce0b6d9d0/`。
全合成・親fixture検証成果物: `reports/python-fix-validation-5382296143004f27bc42d271c8afbd11/`。
clean-js BATレポート: `reports/dev-supplychain-report-20261008-181108.json`。

## 実プロジェクト再検査（2026-10-08）

利用者が同じ実プロジェクトを通常権限と管理者権限で再検査し、提供されたJSONを比較しました。通常権限での `dev-supplychain-report-20261008-185323.json` と、管理者権限での `dev-supplychain-report-20261008-193758.json` は、いずれも v0.1.23 の `Recommended` による指定プロジェクト内の検査です。

| 項目 | 通常権限 | 管理者権限 |
| --- | --- | --- |
| completionStatus / scanComplete | `partial-non-critical` / `false` | `complete` / `true` |
| critical / non-critical coverage failure | 0 / 3 | 0 / 0 |
| DANGER / WARN / CAUTION | 0 / 0 / 48 | 0 / 0 / 48 |
| INFO / OK | 9 / 0 | 4 / 1 |
| FilesScanned / FilesSkipped | 2,428 / 175 | 2,428 / 175 |
| IOC | 全7件 current、releaseReady=true | 全7件 current、releaseReady=true |
| 終了コード | 1 | 1 |

通常権限では一時フォルダー2件の列挙拒否と、それを集約したproject discoveryの失敗1件が残りました。管理者権限でこの3件が解消しました。両JSONの48件のCAUTIONはcategory・title・path・line・evidence・recommendationが同じで、アクセス拒否の解消による新たなCAUTIONはありません。両レポートの `executionSafety` はnetworkAccess・externalCommands・targetCodeExecutionがすべて `none` です。

CAUTIONの内訳はlifecycle script 43件、WASM capability 4件、documentation中の不可視文字1件です。静的精査で47件は通常の機能として説明でき、`sharp` の条件付きソースビルド1件の設定確認は対象プロジェクト側へ引き継ぎました。配布物との独立した真正性照合や、過去のインストール処理の実行履歴を確認した結果ではありません。終了コード1はCAUTIONが残る場合の仕様です。

これは指定プロジェクトの検査完了であり、実ユーザープロファイル全体、npm global/cache、インストール済みNode.js、EndpointTelemetryを検査した結果ではありません。実PCレポートの本文・個人パスはこの記録や配布候補へコピーしません。

## 残る確認事項

2026-10-08の `tests` 全体の検査には、既存の `.security-boundary-regression-17558f93ef6642fb8fb95c3daab7b9ba` と `.security-boundary-regression-920baeefd5bb4206bdb272dbe1e9d2c2` の `dense-selector-limit/dense.js` によるvariation-selector-limit 2件があり、結果は `partial-non-critical` でした。これは制限超過を検証するための合成データです。2026-10-09に明示承認を受けて生成物を保管場所へ移し、下記の自己検査でこの2件の解消を確認しました。ディレクトリの削除や制限の引き上げは行っていません。

Pythonロックファイル処理はliteralフィールドの静的照合であり、完全なTOMLパーサーや依存解決ではありません。バイナリ本文の分析・真正性検証も対象外です。

2026-10-08の実装修正での削除・移動・改名・既存ファイルの全置換は、各0件です。

## 配布前レビュー（2026-10-09）

Windows PowerShell 5.1でリポジトリ直下を `-Path . -Checks Recommended` により自己検査しました。出力先は既存レポートを上書きしない `reports/` 配下の専用TXT/JSONです。

- 初回結果: 終了コード2、DANGER 66／WARN 20／CAUTION 3／INFO 9。`partial-non-critical`、critical failure 0、non-critical failure 2。
- 66件のDANGERはすべて前述の旧合成テスト生成物2フォルダー内。通常ソースのDANGERは0件。
- 2件の未完了は同フォルダーのvariation-selector-limitテストによる意図的な上限超過。fixture manifestの未知ファイルとハッシュ不一致は0件、全7 IOCがcurrent。
- 通常ソースのWARN 4件はCI／回帰テスト中のIOC・エンドポイントの照合用文字列。該当する合成ファイル生成とassertionを静的に確認。CAUTION 1件はCIの手動起動設定。
- 自己検査のnetworkAccess・externalCommands・targetCodeExecutionはすべて `none`。

現作業ツリーの配布候補は、Git追跡済み204ファイルと、今回の関連文書・回帰テスト8ファイルの計212ファイルです。現在の `export-ignore` により、ソースアーカイブに含まれる候補55ファイル、除外される候補157ファイルを確認しました。起動BAT・メインスキャナー・READMEは候補に存在し、アーカイブ除外されません。非fixtureのテキスト48ファイルを限定した個人パス・秘密形式パターンで確認し、候補0件でした。認証名のfixture 1ファイルの本文は読んでいません。

`.codex/` の未追跡1ファイル、保管場所へ移した旧合成テスト生成物202ファイル、無視されている実レポート・今回の監査出力は配布候補に含めていません。検証のための合成fixtureはソースリポジトリに保持し、利用者向けソースアーカイブの除外設定を維持します。

初回自己検査の出力は `reports/release-self-scan-20261009-5466b2a4f6f448c69f1bae7af9f0bb1f.json`、構文・JSON検証を含む配布候補の監査出力は `reports/release-candidate-audit-20261009-5466b2a4f6f448c69f1bae7af9f0bb1f-checked.json` です。これらの実レポート・監査ファイルは公開しません。

### 旧生成物の保管と再検査

移動元・移動先を指定した明示承認を受け、`tests/.security-boundary-regression-<id>/` を `reports/retained-security-boundary-regression-<id>/` へ移動しました。対象は下記の2フォルダーで、計202ファイル、3,121,942バイト（約2.98 MiB）です。移動先が存在しないこと、追跡済みファイルとreparse pointを含まないことを事前に確認しました。ファイル本文を読まずに、移動前後の相対パス・ファイル長・ディレクトリ構成の一致を確認しています。

| id | ファイル数 | バイト数 |
| --- | --- | --- |
| `17558f93ef6642fb8fb95c3daab7b9ba` | 101 | 1,558,318 |
| `920baeefd5bb4206bdb272dbe1e9d2c2` | 101 | 1,563,624 |

移動後に同じ `-Path . -Checks Recommended` で再検査しました。

- 終了コード1、`complete`、scanComplete=true。DANGER 0／WARN 4／CAUTION 1／INFO 8／OK 1。
- critical / non-critical coverage failureは0 / 0、FilesScanned / FilesSkippedは68 / 159。
- fixture manifestの未知ファイル0、ハッシュ不一致0、既知fixtureスキップ173。全7 IOCがcurrent、releaseReady=true。
- WARN 4件とCAUTION 1件は上記で確認したテスト用文字列とCI設定であり、終了コード1はこれらが残る場合の契約どおり。
- networkAccess・externalCommands・targetCodeExecutionはすべて `none`。

再検査出力は `reports/release-self-scan-20261009-after-retention-5d0024fa43ff482fb58518605d093596.json` です。自己検査の `complete`・DANGER 0という確認条件を満たしました。旧生成物は既存の `reports/` 除外設定の対象になり、配布候補と通常の自己検査から外れています。テスト定義・正規fixture・検出規則・解析上限は変更していません。保管した生成物の実体は残っているため、旧パスを参照する過去のテスト記録は上記の対応で読み替えます。

2026-10-09の移動・改名は2フォルダー（配下202ファイル、移動元を含む172ディレクトリ）です。削除と既存ファイルの全置換は0件です。

今回のレビューは作業ツリーと現在のアーカイブ属性の確認です。完全な秘密情報検出、到達可能な全Git履歴の監査、実際の配布アーカイブ作成、GitHub上のCIは未実施です。Git add／commit／pushや、実PCの広い範囲を読むmajor／profile／telemetryモードは実行していません。

## README・マニュアルと公開前手順の改善（2026-10-09）

README・CHANGELOG、日英の初心者／図解マニュアル、公開前手順、旧計画／検証記録と本記録の計11文書、CI設定1ファイルを更新した。日英マニュアルの現行版をv0.1.23へ統一し、旧PNGは履歴資料として案内する。CAUTIONはカテゴリ別に集計した後、ライフサイクルの実行条件、WASM等の能力、不可視文字、設定の有効性を静的に確認する手順を加えた。操作例は[初心者向けマニュアル](user-manual-ja.md)を参照する。

[公開前手順](pre-push-test-procedure-ja.md)の生成先はGUID付きの `reports/pc-test-*` とし、自己検査では `-ReportDir` に `reports/` 全体を指定する。秘密形式チェックは今回の正確なレポートパスだけを読み、過去の保管物を再帰走査しない。公開候補の簡易本文検査は既知の秘密ファイル、ローカル設定、合成fixture、binary、reparse経由のパスを除外し、未読パスを明示する。未読項目を安全と判定する機能ではない。

Windows PowerShell `5.1.26100.9444` で変更後の文書・CIコードを検証した。

| 検証 | 結果 |
|---|---|
| 文書内PowerShell／source parser | 28コード例と既存6スクリプトで構文エラー0 |
| CI JSON step | 本文を抽出してローカル実行。7 IOC・manifest・証拠台帳の必須9 JSONをUTF-8で読み込み、exit 0 |
| JSON異常系 | 証拠台帳欠落、証拠台帳の不正JSON、先頭IOCの不正JSONの3件がexit 1。後続の成功表示なし、入力本文のmarker漏えいなし |
| 文書のJSONチェック | 同じ必須9パスで成功。CIとの検査対象差分0 |
| 文書の合成・manifest・safe Node.js検査 | 全合成検査complete、必須DANGERカテゴリ検出、fixtureの未知・ハッシュ不一致0、Node.jsプロジェクト参照の安全側対照を確認。全samplesのexit 2は意図した検出 |
| 出力安全性／BAT | 既存ファイル・同一TXT/JSONパスをexit 4で拒否、2回分の既定出力を保持。特殊文字、未対応モード、余分な引数、空カスタム入力を確認 |
| レポート本文の秘密形式チェック | 今回生成した12 TXT/JSONで候補0。認証用fixtureや過去artifactの本文は対象にしない |
| 日英CAUTION集計例 | 同じ合成JSONで両方成功 |
| 公開候補の簡易本文検査 | 候補0。作業ツリー164パスと未pushコミット1パスは本文未読として明示。`.codex/config.toml` と認証名fixtureの除外を確認 |
| リポジトリ自己検査 | complete、DANGER 0／WARN 4／CAUTION 1／INFO 8／OK 1、exit 1。coverage failure 0、全7 IOC current、releaseReady=true |
| 文書の相対リンク・版表示 | 更新対象から参照する公開ファイルの欠落0、ローカル限定artifactへのMarkdownリンク0。日英4マニュアルの版・更新日が一致 |

初回のレポートチェックは、親ディレクトリのproviderプロパティによる型判定で途中停止した。`DirectoryInfo`による判定へ修正後、上記の検証はすべて合格した。ローカル検証コマンドは `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\reports\Test-DocumentationReadiness-20261009-7e462fe6aa98468aab0d852711904b30.ps1`。結果はローカル限定の `reports/doc-readiness-validation-1a4b8dd885464aeeac1b0d1acedcb85f/result.json`、自己検査は `reports/pc-test-repository-c5d186dcd3f647e295c1842920e015cc/repository.json` に保持する。

今回は文書とCIのJSON検証だけを修正したため、以前合格した5回帰suiteの全ケースは再実行していない。検出規則、fixture、IOC値、解析上限は変更していない。GitHub上のCI、remoteの最新状態、実ホストの広い範囲は未確認。今回の変更は未コミットで、stage／commit／pushは実行していない。以前からのinstruction文書4件と `.codex/` の変更は保持した。今回の削除・移動・改名・既存ファイル全置換は各0件。
