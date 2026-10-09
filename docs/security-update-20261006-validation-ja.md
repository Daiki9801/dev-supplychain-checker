# 2026-10-06 セキュリティ更新 実装・検証記録

## 結果と公開状態

計画書の機能を scanner v0.1.23 として実装し、実装固有の合成回帰 36 ケース・216 検証項目、Windows PowerShell 5.1 parser、IOC JSON、既存 launcher／安全境界回帰、全既存サンプルの検査を確認した。レビューで見つかった実装固有の問題は修正済み。

初回の実装検証では、部分レビューに旧データセットの期限を更新する根拠がないため公開を保留した。その後の[IOC・fixture 修正](ioc-maintenance-20261006-ja.md)で全7データセットを出典台帳と比較し、30日の期限を維持して更新した。旧 README の manifest 不一致と、未来日付・不正 section・Node.js 競合等の公開判定も修正した。最新の確認根拠・検証結果と歴史的 IOC の証拠上の制限は同記録を参照する。以下の初回 artifact と性能測定は、当時の検証証拠として保持する。

リポジトリ全体の自己検査には、更新前からある fixture manifest の不一致と、意図的に保管した合成悪性データの検出が残る。この全体検査を「陰性・完全合格」とは報告しない。今回追加したテストコード単体の自己検査は complete、DANGER 0、scanner error 0。

実ホスト／ユーザープロファイル、npm global/cache、registry、event log、EndpointTelemetry は検査していない。今回の実装・検証に外部調査、依存インストール、Git 状態変更、対象コード実行は使用していない。

参照: [詳細実装計画書・出典台帳](security-update-20261006-detailed-implementation-plan-ja.md)。

## 変更ファイル

| ファイル | 主な変更 |
|---|---|
| [Scan-DevSupplyChain.ps1](../Scan-DevSupplyChain.ps1) | v0.1.23、built-in IOC 追加、候補 provenance、Python header/RECORD、GYP、runtime transfer、CI/IDE 選定、Action advisory、出典と集計、照合の事前準備 |
| [known-packages.json](../iocs/known-packages.json) | 9 package 名・20 exact package/version pair |
| [known-files.json](../iocs/known-files.json) | 16 SHA-256、owner/artifact role/rule/source |
| [known-actions.json](../iocs/known-actions.json) | Mini Shai-Hulud SHA／歴史的 ref、conflibot CVE の独立 advisory section |
| [known-extensions.json](../iocs/known-extensions.json) | 2 theme ID の INFO watchlist |
| [suspicious-patterns.json](../iocs/suspicious-patterns.json) | 文脈限定の endpoint marker 4件 |
| [Test-SecurityUpdate20261006.ps1](../tests/Test-SecurityUpdate20261006.ps1) | 新規合成回帰。AST allowlist と最小 context、実 scanner subprocess、create-new fixture／report |
| [Test-SecurityBoundaryRegressions.ps1](../tests/Test-SecurityBoundaryRegressions.ps1) | `-KeepArtifacts` を追加。今回は削除処理を通さず実行 |
| [validate.yml](../.github/workflows/validate.yml) | 新規回帰 runner の CI step のみ追加 |
| [README.md](../README.md)／[CHANGELOG.md](../CHANGELOG.md)／[IOC README](../iocs/README.md) | バージョン、機能、境界、部分レビューと公開保留を記載 |
| この記録 | 実行結果、レビュー修正、残る制約を記載 |

BAT launcher、Node.js baseline、Keyv snapshot、fixture manifest は変更していない。作業開始時から存在した AGENTS／旧設計書／review checklist／.codex の変更は保持した。

## 実装の境界

- Scanner は単一 PowerShell + 薄い BAT、PowerShell 5.1、依存なし、offline、read-only を維持。対象への削除・修復・設定変更は追加していない。
- GYP は 131,072 UTF-16 code units/file、65,536/scalar、64 condition、depth 32 を上限とする静的処理。式を評価しない。
- Python METADATA は UTF-8 header を最大128 KiB／1,024行まで読み、空行以降の description を読まない。Windows 上の filename 大小文字と package 名の case／punctuation を正規化する。
- 特定 distribution の RECORD は最大128 KiB／1,024行、runtime 候補は最大8件。範囲外パス、必要ファイルの欠落、読取／解析上限は critical coverage に反映する。
- npm は既存 entrypoint に加え固定候補を最大8件、package 内 total 最大16件。通常未選定 dependency code と active/selected code を区別する。
- IDE は必要な固定 IOC と、存在する main/browser payload を選定する。一般の metadata-only fixture に payload の存在を仮定しない。ID 単独は INFO、hash は別証拠。
- CI は local workflow script と literal BASH_ENV bridge を1段、project 内8 script 候補まで選定する。
- Credential→encode→DNS、bridge→credential transfer は局所的な代入関係を使い、別関数、再代入、shell literal／comment／表示例を除く。通常 npm/PyPI publish は新規 exfil DANGER にしない。
- Conversation の追加送信は同じ payload 識別子、局所 window、function scope を使う。普通の設定 API だけでは新規 WARN を出さない。完全な言語解析／実行可能性証明は行わない。
- Action numeric ref は CVE reference posture の WARN、解決不能 ref は INFO。既知 bad SHA の DANGER と分離し、mutable ref の現在の内容を offline で確認したとは扱わない。
- Hash 用パターンを一度準備し、path が一致する候補へ絞る。同一検査の複数 hash は一回の計算を共有。read/hash 失敗、上限を完了した陰性に変換しない。
- finding の `ruleId`／`sourceId`／`upstreamSeverity` と候補・制限・hash・header 集計を TXT/JSON に反映。値とコード本文は中央 redaction を通す。

## 実行した検証

以下の `powershell.exe` は実行時には System32 の Windows PowerShell を絶対パスで指定した。全 scanner 対象は repository またはその下の合成データで、host discovery は使っていない。

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-SecurityUpdate20261006.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-SecurityBoundaryRegressions.ps1 -KeepArtifacts
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-LauncherScopeContracts.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -Checks Recommended -ReportDir .\reports\<unused-directory> -Quiet -NoColor
git diff --check
```

| 検証 | 結果・証拠 |
|---|---|
| PowerShell 5.1 parser | main、新規 runner、安全境界 runner の3ファイルで error 0 |
| IOC JSON | shipped 7ファイルを ConvertFrom-Json で確認 |
| 新規回帰 | 36ケース・216 assertions 合格。[result.json](../reports/security-update-regression-f71c2598ff1c4b039dfefbf54f9bfef1/result.json) |
| Exact package | 新規20 pair それぞれを installed と npm package-lock v3／Python Pipfile.lock から検出。各 pair 2 findings を個別確認 |
| Hash | 無害な bytes と in-memory test IOC で陽性／1 byte差陰性／一回計算／owner／出典を確認。production16 hash は形式と built-in/local 一致を確認。悪性 binary は使用していない |
| Precision／coverage | 正常隣接 version、異なる prerelease、正規 anthropic、range/cache、GYP comment/escape/上限、DNS 再代入、CI literal/別関数/正常 publish、conversation 通常 API、IDE identity/hash、単独 check、重複、size/read/record/advisory failure を確認 |
| 安全境界 | `Security boundary regression tests passed.`。生成物は [保管 root](../tests/.security-boundary-regression-920baeefd5bb4206bdb272dbe1e9d2c2/) |
| Launcher | `Launcher scope contracts passed.` |
| 全既存サンプル | 4回とも scanComplete=true、140 text files、scanner error 0。既存の必須 DANGER 5 category を確認。exit 2 は意図した悪性 fixture のため |
| 新規 test source 自己検査 | complete、DANGER 0、error 0、exit 1（stale IOC 等の警告）。[report](../reports/security-update-final-source-792a522cf1784f5d9bd21257b799c7c4/dev-supplychain-report-20261006-150229.json) |
| 差分 | `git diff --check` 合格。LF→CRLF の Git 変換予告は error ではない |

性能は同じ `tests/samples -Checks Recommended`、warmup 1回 + 本計測3回で比較した。測定中には他の重い検証を並行実行していない。

| 項目 | 秒 |
|---|---:|
| 更新前 median | 17.5217473 |
| 最終 warmup | 17.1294834 |
| 本計測 | 16.3106074 / 16.2149827 / 16.2450422 |
| 最終 median | **16.2450422** |
| 合格上限 max(1.25 × base, base + 2) | 21.902184125 |

[最終 performance.json](../reports/security-update-final-performance-e93e8f0854954dac8ab635f01233cf30/performance.json)。初回には約26.97秒となり不合格だったため、IOC attribute/pattern の反復処理と check gate の重複照合を改善し、同じ corpus で再検証した。最終 median は更新前より約7.3%短い。

## レビューと改善の記録

| レビュー | 修正 |
|---|---|
| 候補・所属・出力の初回確認 | Python専用 dispatch、CI/IDE 単独 check、hash owner、source fields と JSON/TXT counter を接続。advisory validator の condition 名と依存 helper を修正 |
| サンプル回帰・自己検査 | metadata-only IDE の一般 entrypoint 欠落を incident 固定 payload 欠落と区別。テストの command/API 例を断片から組み立て、test source 自体の false DANGER を除去 |
| 性能確認 | 失敗した実測を保持。照合パターンの事前準備、早期 check gate、native attribute による reparse 確認、不要な runtime 解析を省いて再計測 |
| 最終 precision 確認 | JS／shell の再代入、単一引用符、表示用文字列、別関数、conversation scope、個別 rule の行番号、GYP file/record 上限、METADATA filename の大小文字を確認・改善 |

更新した実装に関する未修正の重大な回帰は検証範囲内では見つからなかった。静的ヒューリスティックの網羅性や感染の有無を保証する結果ではない。

## 残る制約・更新前の問題

1. **初回の鮮度阻害は対応済み**: 後続レビューで全7 dataset を比較・更新した。今後も stale/missing/invalid があれば `releaseReady=false` を無視して公開してはならない。歴史的 artifact の独立再検証とは区別する。
2. **既存 manifest の不一致は修正済み**: 更新前 HEAD と現 README が同じ canonical hash であることを確認し、manifest 値だけを `df97fe2981e201c513f4c6b964c528ac8faf0f3e78032146cb16c72c09f8bccf` に修正した。後続の maintenance 回帰で158件すべての hash/presence と path・重複・未知ファイルを検証する。
3. **保管した test artifacts**: 初回の2ディレクトリは `tests/.security-boundary-regression-*` に保持した。今後の生成先は `reports/` に修正した。既存 artifact の削除や production filename 免除は行っていない。
4. **未実行**: 実 host/profile、EndpointTelemetry、外部 service、完全な言語実行／全 CVE audit、実悪性 artifact。host scope の明示的な承認がない検査は実行していない。
5. **CI**: 新 step の runner は Windows PowerShell 5.1 でローカル合格。GitHub 上の CI 全体は起動していない。既存 workflow の全補助検査を新たに外部実行したとは扱わない。

削除0、移動0、改名0、既存ファイル全置換0。生成した fixture/report/profiling copy は repository 内に保持。Git add/commit/push と公開操作は行っていない。
