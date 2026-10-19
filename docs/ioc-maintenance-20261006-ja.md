# IOC 鮮度・fixture 整合性の修正記録（2026-10-06）

本書は2026-10-06時点の記録です。旧テスト生成物は2026-10-09に承認された移動で `reports/` へ保管し、その後の自己検査はcomplete・DANGER 0となりました。後続の修正・検証結果は[最新のローカル検証記録](python-metadata-review-20261008-ja.md)を参照してください。以下のartifactパスはローカル限定で、Git公開には含めません。

## 結果と範囲

全7 IOC データセットを出典台帳と照合し、レビュー日を2026-10-06へ更新した。有効期間は30日のままで、期限判定を緩めていない。公開情報と承認済みの旧ベースラインを比較し、出典が否定した2組の誤検知候補と、検出パス・鮮度判定の問題を修正した。

これは文書化された限定的なデータセット全体の手動レビューである。各悪性 artifact の再解析、全公開インシデントの取り込み、全旧 IOC の独立した再検証を意味しない。再確認できた値と旧出典を保持した値を、[項目別照合記録](ioc-maintenance-20261006-evidence.json)と下記に分けて記録した。

実装・検証はローカルのリポジトリと合成データに限定した。外部調査は既に許可された公開情報の読み取りだけで、スキャナー本体にネットワーク機能を加えていない。秘密、リポジトリのコード、個人情報は送信していない。

## 出典の照合

[照合記録](ioc-maintenance-20261006-evidence.json)には、公開出典74件の URL・取得結果・SHA-256、通常の124組と Keyv の2,235組の確認根拠を格納した。取得した公開資料は `reports/ioc-public-review-cb4224aaca8d450a89a01b29c21ffaa8` に保持した。OSV npm archive は229,998件、PyPI archive は26,080件を読み取り、対象の名前と正確なバージョンだけを比較した。公開コードや payload は実行していない。

| データセット | 全体の確認と修正 | 出典上の制限 |
|---|---|---|
| `known-packages.json` | 63件・124組。68組は非撤回 OSV malware の exact versions、15組は npm の明示的な compromised deprecation、41組は既存 incident-family 証拠と registry metadata を比較。誤った Jscrambler wrapper 2組を除外 | 41組について各悪性 artifact を独立に再解析したとは扱わない |
| `known-files.json` | 全27件を出典台帳と比較。16補足ハッシュ、Jscrambler の intro/Windows 2ハッシュ、codfish の1ハッシュを公開記事で再確認。Jscrambler の `dist/` 選定を修正 | 旧7ハッシュと persistence filename は歴史的な承認済み baseline を保持し、独立した artifact 再検証を主張しない |
| `known-extensions.json` | 全16件を比較。oorzc 4件、quartz、テーマ2件、AFINE に残る WakaTime/AutoImport ID を照合。platform-qualified な照合と WARN/INFO watch の段階を維持 | Nx Console と旧6 ID watch は歴史的出典を保持。IDだけで全 registry の artifact が悪性とは扱わない |
| `known-actions.json` | codfish の2 commit と14 historical ref、Mini Shai-Hulud、conflibot advisory を公開記事/APIと比較。8/14以降の Actions delta は malware 0件、reviewed 1件（収録済み conflibot） | mutable ref の現在の向き先・Action の可用性は確認済みとは扱わない |
| `suspicious-patterns.json` | domain 3件と regex 8件を台帳・旧 baseline と比較。Keyv 公開記事の contract を bounded WARN の選択肢として追加 | 旧 domain/wallet の歴史的出典を保持。共有 RPC、Solana、DHT、Calendar だけを感染証拠とは扱わない |
| `known-node-runtimes.json` | 全13 advisory を7つの公式 security-release 記事と比較。公式一覧の最新 security release は7月。Critical history と365日以内の High を維持し、範囲・修正版を変更せず builtin と一致 | 一般的な全 Node.js CVE や EOL、脆弱性の到達可能性は対象外 |
| `campaign-keyv-chaindrop-20260806.json` | 443名前・2,235組すべてを非撤回 OSV malware の exact versions で独立に照合。3 hash・4 marker・1 Git ref を記事と承認済み値に比較 | 元 BAT/report/CSV の `reviewStatus` と hash は維持。元 CSV の独立取得・復元とは区別する |

Keyv の canonical digest は `7da86fddcb4bc5c4352d3f2120903a07314ae2ce3071d980061862bcbc8aa497` のままである。Aikido の aggregate count と旧 snapshot の件数の差を推測で埋めていない。今回は snapshot 内の全2,235組を OSV 側の個別 malware record で照合できたため、その独立した根拠を追加した。

公開 source 4件は取得できなかった。旧 Nx postmortem URL、Socket campaign summary、削除済み Injective 2 version endpoint である。Nx の正しい URLと Injective の全体 metadata は取得できた。旧Koi URLと一般検索の HTTP 200 応答は本文が該当記事でないため、IOCの確認根拠に使っていない。巨大 npm metadata の追加 batch は停止して、版単位の小さい公開 metadata を20秒・4MiB制限で取得した。HTTP成功や registryからの削除だけを悪性の独立証明とは扱わない。

主な今回の追加出典:

- [SafeDep: Jscrambler](https://safedep.io/jscrambler-npm-supply-chain-compromise/)
- [Aikido: codfish GitHub Action](https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets)
- [Socket: oorzc compromise](https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise)
- [AFINE: public IOC data](https://raw.githubusercontent.com/afine-com/glassworm-hunter/main/data/ioc.json)
- [Node.js: official vulnerability index](https://nodejs.org/en/blog/vulnerability)
- [Aikido: Keyv](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack)

## 修正した問題

1. **fixture manifest の既存不一致**。158 entry を全件照合した。不一致は `tests/samples/README.md` の1件だけで、更新前 Git HEAD と現ファイルの canonical text-LF hash が同じことを確認した。本文を変更せず manifest 値だけを `df97fe2981e201c513f4c6b964c528ac8faf0f3e78032146cb16c72c09f8bccf` に修正した。重複、欠落、root escape、未知ファイルはなかった。
2. **未来日付による誤った公開判定**。汎用5 dataset、Keyv、Node.js、summary setter が未来のレビュー日を current としないようにした。Node advisory の未来の publication date も拒否する。
3. **Node.js の invalid/missing の隠蔽**。不正 entry、競合、欠落した builtin advisory、重複 ID を invalid として公開を止める。builtin の期限切れ通知が missing/invalid を stale へ置き換えないようにした。builtin の脆弱性照合は維持する。
4. **ヘッダーだけによる偽の current**。汎用5 dataset では必須 section が非空 array であることと、identity/version/hash/regex等の基本形を確認する。空・欠落・壊れた entry は valid な日付でも公開を止める。正常な historical/builtin 指標は保持する。
5. **誤った Jscrambler exact IOC**。公開 SafeDep 記事で非影響とされている `jscrambler-webpack-plugin@8.6.2`、`grunt-jscrambler@8.5.2` を local/builtin 両方から除いた。別の OSV malware record がある `gulp-jscrambler@8.6.2` と `jscrambler-metro-plugin@9.0.2` は保持する。
6. **Jscrambler payload のパス不一致**。公開記事は `dist/intro.js` と `dist/setup.js` を記載するが、旧 selector は package root だけに一致した。`dist/` を許し、別 package へ一致範囲が広がらないことをテストした。
7. **Keyv contract の不足**。公開記事の `0xE1f2395ee43e45A1556EC6438a88c31B83493103` と従来の承認済み marker を、NodeReal host との近接を必須とする同じ WARN regex に含めた。旧 marker を記事で再確認済みとは扱わない。共有 RPC だけでは一致しない。
8. **回帰テスト自身が作る repository findings**。今後の安全境界 artifact 作成先を `tests/` から `reports/` に変更した。環境境界テストは変更していない scanner と同梱 IOC の合成コピーを使い、fake profile がコピー自身の report 除外に入らないようにした。対象 root はすべてリポジトリ内で、実 profile への fallback はない。既存の保管ディレクトリを削除したり、filename exemption を増やしたりしていない。
9. **長い workflow の選定未完了**。現行 `validate.yml` は1,561行あり、CI bridge の既定1,024行の選定上限を超えた。workflow の選定だけを2,048行にし、131,072 byte・script 8件・regex 2秒の上限は維持した。1,500行後の悪性 bridge 検出と、2,049行時に critical coverage failure を明示するテストを追加した。

## 今回の変更ファイル

| ファイル | 変更内容 |
|---|---|
| `Scan-DevSupplyChain.ps1` | 鮮度・entry 整合性、Node.js 状態保持、builtin IOC、Jscrambler selector、CI workflow 選定上限 |
| `iocs/known-packages.json`、`known-files.json`、`known-extensions.json`、`known-actions.json`、`suspicious-patterns.json`、`known-node-runtimes.json`、`campaign-keyv-chaindrop-20260806.json` | 全7 dataset の出典レビューと必要な値の修正 |
| `tests/samples/manifest.json` | 既存 README の canonical hash 1件だけを修正 |
| `tests/Test-IocMaintenance.ps1`、`tests/Test-SecurityUpdate20261006.ps1`、`tests/Test-SecurityBoundaryRegressions.ps1` | 全 manifest・loader 状態・検出・選定上限の回帰、artifact 配置と fake profile の分離 |
| `.github/workflows/validate.yml` | maintenance 回帰 step |
| `README.md`、`CHANGELOG.md`、`iocs/README.md`、`docs/pre-push-test-procedure-ja.md` | 現行の契約、検証手順、出典上の制限 |
| `docs/ioc-maintenance-20261006-ja.md`、`docs/ioc-maintenance-20261006-evidence.json`、`docs/security-update-20261006-validation-ja.md` | 本記録、項目別の証拠、初回検証との関係 |

計20ファイル。更新前からある instruction・歴史的文書・`.codex/` の変更を今回の修正に含めていない。

## 検証

Windows PowerShell `5.1.26100.9444` で次を確認した。新規2 suite は計75 case・1,313 assertion が合格した。

| 検証 | 結果・証拠 |
|---|---|
| IOC maintenance | 39 case・1,082 assertion、158 fixture 全件一致。ローカル証拠: `reports/ioc-maintenance-regression-e85dbeebfac54c14a3649e5942ce8fdf/result.json` |
| October security update | 36 case・231 assertion。ローカル証拠: `reports/security-update-regression-0eae9af1c16848fba28d89135e63e48c/result.json` |
| Security boundary / launcher scope | 両方合格。ローカルartifact: `reports/security-boundary-regression-a83a4fc3be5f42aab820eb1ada4579d3/` |
| PowerShell parser / JSON | main と3 regression script の parse error 0、同梱7 IOC・manifest・証拠記録の9 JSON が妥当。ローカルscript: `reports/ioc-maintenance-parser-d1202e10aa144f2bb0a04e45aaff375e/validate.ps1` |
| 合成 samples / safe Node.js | samples は complete・意図した DANGER 49 / WARN 38・exit 2、safe Node.js は complete・DANGER/WARN 0・exit 0。IOC current 7、manifest mismatch / unexpected fixture / scanner error 0。ローカル証拠: `reports/ioc-maintenance-final-e4d64cf35ff3447ab08e7076b2adc526/samples.json`、同ディレクトリの `node-safe.json` |
| repository / tests 全体（当時） | IOC current 7・`releaseReady=true`、期限切れ・欠落・不正・manifest mismatch・未知 fixture・scanner error 0。repository の DANGER 66 は下記の旧2 directory の意図した fixture だけ。両検査はその dense Unicode fixture による `partial-non-critical` で、critical failure 0。ローカル証拠: `reports/ioc-maintenance-repository-final-31fd7e2b232746c387a26900f5e60d81/repository.json`、`reports/ioc-maintenance-final-e4d64cf35ff3447ab08e7076b2adc526/manifest-parent.json` |

主なコマンド:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-IocMaintenance.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-SecurityUpdate20261006.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-SecurityBoundaryRegressions.ps1 -KeepArtifacts
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-LauncherScopeContracts.ps1
$sampleReport = '.\reports\sample-validation-' + [Guid]::NewGuid().ToString('N')
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -Checks Recommended -ReportDir $sampleReport -NoColor -Quiet
$nodeReport = '.\reports\safe-node-validation-' + [Guid]::NewGuid().ToString('N')
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples\node-runtime-safe -Checks NodeRuntime -ReportDir $nodeReport -NoColor -Quiet
git diff --check
```

report 出力先は実行ごとに未使用の名前を指定する。意図した悪性 fixture の exit 2 は検査失敗ではなく、JSON の期待 finding と coverage を確認した。テスト検証は scanner を対象 root へ静的に実行し、fixture 自体を実行していない。

CI には `Test-IocMaintenance.ps1` を加えた。GitHub 上の CI 起動、Git 操作、公開は行っていない。実 host/profile、EndpointTelemetry、npm global/cache、registry/event log の検査は承認がないため行っていない。

## 当時の旧 test artifact と後続の整理結果

2026-10-06時点で残った repository 全体の未完了は、次の2ディレクトリの意図した dense Unicode fixture に限られた。当時は移動・削除の承認前であったため保持した。

- `tests/.security-boundary-regression-17558f93ef6642fb8fb95c3daab7b9ba`
- `tests/.security-boundary-regression-920baeefd5bb4206bdb272dbe1e9d2c2`

当時、復元用ZIPとinventoryを `reports/ioc-maintenance-artifact-recovery-72deeb32a5974f368648bd8e3e3d6376/` に用意した。ローカル限定のファイル名は `retained-boundary-artifacts.zip` と `inventory.json`。元データは202 file・172 directory（root 2件を含む）、3,121,942 byte。ZIP は645,901 byteで、当時の記録では全202 file の SHA-256 を元データと照合した。ZIP の SHA-256 は `d764a9bdda758300d1602ff6d30139c875d8ba91f6725c22f4243f4d3fcb7e10`。

2026-10-09にこの2ディレクトリの移動が明示承認され、同じIDの `reports/retained-security-boundary-regression-*` へ内容を保持して移動した。削除は行っていない。移動後の自己検査は `scanComplete=true`、`completionStatus=complete`、DANGER 0、coverage failure 0で、整理待ちは解消した。詳細は[後続の検証記録](python-metadata-review-20261008-ja.md)を参照する。

## 保持した制限

- `iocData.releaseReady` はこの限定 corpus のレビュー日・必須データ・整合性の公開条件を示す。独立再検証していない historical entry の証拠を強くする指標ではない。
- スキャナーは引き続き dependency-free / offline-only / read-only / Windows PowerShell 5.1。修復・隔離・対象実行を追加していない。
- 保管した旧安全境界テストの2ディレクトリには意図的な検知対象がある。保管先を明示スキャンした場合のfindingはtest artifactとして区別する。実ファイルの削除には個別の承認が必要である。

2026-10-06の作業は削除0、移動0、改名0、既存ファイル全置換0。更新前からある instruction・`.codex/`・歴史的文書の変更は保持した。後続の承認済み移動2件は上記の2026-10-09記録に区別した。
