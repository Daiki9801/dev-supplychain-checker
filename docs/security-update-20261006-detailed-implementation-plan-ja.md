# 開発環境サプライチェーン セキュリティ更新 詳細実装計画

作成日と根拠確認日: 2026-10-06。当時の対象は Dev Supply Chain IOC Checker **v0.1.22**。初回更新版は **v0.1.23 を候補**とした。作成時の文書状態は **計画書 v1.0・自己レビュー合格（95/100）**で、スキャナーの実装と実行試験は未着手だった。

本書は実装前の計画と出典台帳を保持する歴史的記録である。v0.1.23の実装・検証は後続作業で完了した。実測結果と残る制限は[初回の実装検証記録](security-update-20261006-validation-ja.md)、[IOC・fixtureの確認記録](ioc-maintenance-20261006-ja.md)、[2026-10-09までの最新検証記録](python-metadata-review-20261008-ja.md)を参照する。計画の自己レビュー点数は、実装の採点や安全保証を意味しない。

本計画は、新しく確認された悪性パッケージ、GitHub Actions、IDE 拡張をローカル IOC に反映し、既存の限定探索では届かない実行経路を安全に補うためのもの。先に正確な IOC と対象候補を整え、その後に挙動判定を追加する。判定は Windows PowerShell 5.1 で静的に行い、検査対象のコードを実行しない。

今回の成果物は計画書とそのレビュー結果。以下の関数追加、JSON 更新、合成テスト、版更新は、後続の実装で行う作業として記載する。本書を作成したことは、それらを実施した証拠や Git 操作、外部への送信、実ホスト読み取りの承認を意味しない。

## 1 目的と対象範囲

対応する事案は supplychain.local、Trinitite、2026年9月の Shai-Hulud 再発、Mini Shai-Hulud の Actions 再有効化、GlassWorm 関連テーマ、anthropic-sdk と virgil-cli。conflibot の CVE は、悪性 IOC と分けた限定的な参照バージョン警告として追加する。

維持する契約:

- BAT は薄い起動用ファイル、本体は単一の `Scan-DevSupplyChain.ps1` とする。
- 外部依存、スキャン時のネットワーク通信、対象コード実行、修復、削除、隔離、権限変更を追加しない。
- `Recommended` はプロジェクト内の検査。npm global/cache、ユーザープロファイル、レジストリ、イベントログ、ホスト Node.js 探索を新たに含めない。
- `DANGER / WARN / CAUTION / INFO / OK` と終了コードの既存契約を維持する。WARN と CAUTION は `1`、DANGER は `2`。既存のエラー用コードを再定義しない。
- finding の category、title、path、line、evidence、recommendation と、TXT/JSON の出力形式を維持する。秘密値、認証ファイル本文、復号したペイロード本文を出力しない。
- 上限到達、読取失敗、解釈不能を陰性結果に置き換えない。coverage と `completionStatus` に未確認範囲を残す。

Rust、Go、Dart、Ruby のパッケージ監査、全 CVE 監査、署名や発行者の真正性証明、オンライン reputation、実マルウェアの取得・実行は対象外。Go 製の sckit は、npm/Python 配下の既知ファイルとして扱う。

## 2 現行実装と統合位置

実装開始時には最新の `README.md`、`CHANGELOG.md`、`AGENTS.md` と作業ツリーを再確認する。下表は v0.1.22 に実在する統合位置であり、歴史的な v0.1.15 計画を現行仕様として流用しない。

| 処理 | 現行の関数 | 今回の変更 |
|---|---|---|
| 通常 IOC 読込 | `Load-BuiltinIocs`、`Load-LocalIocs` | 新規 exact IOC と出典情報の読込を追加する |
| パッケージ照合 | `Get-ExactPackageIocMatch`、`Normalize-Version` | 既存 index を使い、prerelease を別バージョンとして保持する |
| Node.js データ | `Load-BuiltinNodeRuntimeIocs`、`Load-LocalNodeRuntimeIocs` | 公式ソース再確認と built-in/local の一致を維持する |
| Keyv 固定データ | `Load-KeyvChainDropCampaignIocs` | 固定スナップショットの整合検査を維持する |
| npm 候補選定 | `Resolve-NpmPackageEntrypointFile`、`Get-TargetedFileList` | `binding.gyp`、既知 loader、`.sckit` を限定追加する |
| Python 候補選定 | `Add-TargetedPythonFiles`、`Scan-PythonFiles`、`Scan-File` | `METADATA` は専用 header reader、選定済み `.py` は runtime 解析へ渡す |
| ファイル IOC | `Test-KnownFileIocMatch`、`Scan-KnownFileIocs`、`Test-KnownFileIocCheckEnabledForFile`、`Add-KnownFileIocFinding` | 実ファイル hash と Python 候補の check 所属を合わせ、計算重複を減らす |
| JS 等の挙動 | `Scan-NpmRuntimeCode`、`Get-TextContext` | 既存の active/selected/Deep 文脈を保って新しい経路を追加する |
| CI/CD | `Get-GitHubActionUsesEntries`、`Scan-GitHubActionReferences`、`Scan-GitHubActions` | 悪性 SHA、履歴 ref、CVE、publish bridge を分離する |
| IDE | `Get-TargetedFileList`、`Scan-IdeExtensionPackageJson`、`Test-IsVsCodeStyleExtensionPath`、`Scan-JetBrainsPluginMetadata` | 通常除外される固定 payload を限定選定し、配布物 hash と ID watchlist を分ける |
| 完了性と鮮度 | `Reserve-ScanFile`、`Get-CoverageCandidateKindForFile`、`Read-TextFileSafe`、`Register-CoverageFailure`、`Test-IsCriticalCandidate`、`Set-IocDataSetStatus`、`Get-IocDataSummary` | candidate の来歴を保持し、読取・hash 失敗とデータ不備を接続する |
| finding 出力 | `Add-Finding` | optional な出典・ルール情報も中央の検証・redaction を経由させる |

現行の `Scan-NpmRuntimeCode` の対象拡張子に `.gyp` はない。npm の対象実行ファイルは最大4件を選び、既知の固定候補は主に Keyv の3ファイル。Python の通常選定は `.pth`、customize、`RECORD` 等が中心で、`Scan-PythonFiles` も `METADATA` や通常の `.py` を受け付けない。候補追加と dispatch の変更を一緒に行う。

## 3 登録する指標と根拠

### 3.1 パッケージ名と正確なバージョン

下表は **9パッケージ名、20 exact package/version pair**。Python の ecosystem は既存 JSON に合わせ `python` とし、GitHub の `pip` 表記をそのまま混在させない。

| ecosystem | package | 登録候補の exact version | 根拠 |
|---|---|---|---|
| npm | `@7nohe/openapi-react-query-codegen` | `0.5.4`, `0.5.5`, `1.6.3`, `1.6.4`, `2.2.1`, `2.2.2`, `3.0.3`, `3.0.4` と下記2 prerelease | S01、S02 |
| npm | `@memtensor/memos-cloud-openclaw-plugin` | `0.1.21`, `0.1.23`, `0.1.25` | S03、S04 |
| python | `memoryos` | `2.0.34` | S03、S05 |
| npm | `feishu-docx-mcp` | `0.3.2` | S06 |
| npm | `bmc-i18n-extract-cli` | `1.1.1` | S06 |
| npm | `blueai-cli` | `0.7.0` | S06 |
| npm | `bmc-translate-utils` | `1.1.1` | S06 |
| python | `anthropic-sdk` | `0.1.0` | S07 |
| npm | `virgil-cli` | `0.1.4` | S08 |

Trinitite の prerelease は次の2件で、短縮 SHA やワイルドカードに変換しない。

- `0.0.0-365d4eb738d3146583431948d3ba6e27a32556be`
- `0.0.0-ec7876d6c917dad516ba69bbfafc948b834bf0ab`

MemTensor の `0.1.22` と `0.1.24` は S03 がクリーンと報告している。`>=0.1.21` を悪性範囲として登録しない。MemoryOS の後続版も推測で追加しない。S06 の exact 4件は当該報告に基づく限定登録で、公開アドバイザリの広い範囲を無条件に輸入しない。

### 3.2 ファイルと拡張

付録Aに、実際にファイル照合に使える **16 SHA-256 候補**を記載する。いずれも公開報告の指標であり、実マルウェアから新たに計算した値ではない。

- Trinitite の8 hash は公開されているが、版・ファイル名との一対一対応を推測しない。候補探索は報告された root loader 名に限定する。
- supplychain.local は npm/Python ごとの Windows amd64/arm64 バイナリ4 hash を優先する。tgz、wheel、sdist の hash は今回は参照情報に留め、アーカイブ展開は実装しない。
- Shai-Hulud の共通 `index.js` と、GlassWorm の VSIX、`out/extension.js`、`app.js` を登録する。
- Cosmic Nebula の復号後 stage hash は元の配布ファイルと異なる。AES 復号を実装しない本更新では、元ファイルの hash として登録しない。
- `microsoftvs.microsoftvs` と `cosmic-themes.theme-cosmic-nebula` は、報告で悪性が確認された Marketplace 配布物を基準にする。悪性版が未確定の ID 全体に `DANGER` ワイルドカードを付けない。
- この2 ID は `known-extensions.json` に `matchType=id-watchlist`、`severity=INFO`、`confidence=low` の照合を追加する案とする。`versions=["*"]` は情報用の identity 照合に限り、全版・全 registry の悪性を意味しない。artifact hash の DANGER は独立して判定する。
- Coca-Cola Christmas 等のクラスター関連だけのテーマを、同じ悪性 IOC 集合へ追加しない。VS Code/OpenVSX の出自が区別できない場合は hash を使う。

新規 file IOC は `pathPattern` または `fileName` で、列挙済み候補だけを照合する。`path` に `%TEMP%`、`%USERPROFILE%`、認証ファイル、実ホスト上の固定位置を追加しない。`temp_batch.cmd` や runtime state directory は、報告上の文脈情報であり自動ホスト探索の根拠にはしない。

### 3.3 宛先の指標

S03 の `skyleen.fr` とその subdomain、S06 の `t.m-kosche.com`、S11 の `fingercakes4sale.store` を、境界付きの静的 marker として追加する。S08 の `api.nm-streetwear.space/vx/learn` は会話の追加送信先として扱い、credential-stealing C2 と同一視しない。宛先への接続や DNS 解決は行わない。

これらは `suspicious-patterns.json.patterns` の新規、文脈付き WARN ルールに置く。既存 `domains` 配列は非文書の文字列一致を DANGER にするため、単純追加しない。host の前後境界を検証し、`skyleen.fr.example.org`、`notskyleen.fr` や一般の Solana/GitHub/npm ホストを同じ指標に含めない。marker だけ、コメント、文書、reference/session/cache は DANGER にせず、compound と exact hash/package の判定を別に保つ。

### 3.4 GitHub Actions と脆弱性

`actions-cool/issues-helper` の悪性 SHA は `a0c53dd42fc842d2f9276c5a1d4f9a26abe8713d`。S09 が示す `v2.2.1` は履歴 ref として登録し、現在のオンライン解決先は断定しない。`actions-cool/maintain-one-comment` は履歴上の影響を記録するが、報告から確定できない SHA や完全な ref 一覧を作らない。

S09 は9月16日の再有効化に加え、9月25日の再無効化も記録している。「現在も実行可能」と固定して記載しない。公開日の差分検索だけでは過去の悪性指標の再浮上を取りこぼすため、根拠確認では更新日と研究報告も確認する。

`CVE-2026-55158` は `wktk/conflibot <1.2.1` の参照バージョン警告。S10 の修正版は `1.2.1` と `2.0.0`。悪性 SHA の集合へ脆弱なタグを混在させない。

## 4 IOC データ設計と更新順序

パッケージ、hash、action は既存データ形式を利用する。既存 exact IOC を重複追加せず、読み込み後の index と finding の重複排除を確認する。各候補に出典 ID、対象 artifact、確認日、適用範囲を対応付け、`sourceSet`、`sourceUrls`、`scope`、`reviewNotes` に反映する。出典 ID を新しい entry field に持たせる場合は、`Load-LocalIocs` が落とさず保持するよう同時に変更する。

conflibot は `known-actions.json` に additive な `advisories` 配列を追加する案とする。既存 `actions` 配列の意味は変更しない。更新後のファイル schema は `0.1.23` とし、旧 `0.1.12` の actions 読込も維持する。

```json
{
  "advisories": [
    {
      "id": "CVE-2026-55158",
      "repository": "wktk/conflibot",
      "upstreamSeverity": "CRITICAL",
      "published": "2026-08-17",
      "sourceUrl": "https://github.com/advisories/GHSA-2qvg-qr73-mqxp",
      "affectedRanges": [{ "maxExclusive": "1.2.1" }],
      "fixedVersions": ["1.2.1", "2.0.0"],
      "conditions": ["pull_request_target", "attacker-controlled-head-ref"]
    }
  ]
}
```

この例は追加 section の形であり、既存ファイル全体の置換用データではない。CVE の ID、repository、日付、HTTPS source、severity、範囲、修正版を検証し、不正な section を `invalid` とする。既知の悪性 action の読込は保持する。最新 section が欠落・不正なら、限定的な built-in advisory を残し、鮮度を current に見せない。

読込順序は「header と旧 actions の検証 → advisory の検証 → 有効 entry の統合 → dataset status の1回の確定」とする。advisory が欠落した旧 schema も、歴史的 actions は利用しつつ、新版の必要情報が不足する dataset として `invalid` を報告する。現在の `Set-IocDataSetStatus` は後の呼出しで状態を上書きするため、header が新鮮であっても body の invalid を current/stale で消さない。fallback の存在は `releaseReady=true` の根拠にしない。

M1 の additive データを旧 loader で読めても、CVE の検出機能があるとは扱わない。本体・IOC・付属文書を一組で検証し、M3/M4 まで揃ったものだけを公開判定へ進める。

### 4.1 鮮度と公開可否

2026-10-06 時点の通常6 dataset は `lastUpdated=2026-08-14`、期限は `2026-09-13`。Keyv は `lastReviewed=2026-08-12`、期限は `2026-09-11`。すべて30日契約であり、実装中も期限を延長しない。

新規20 pair を追加しただけでは、既存 dataset 全体を再確認したことにならない。全体の根拠照合を終えたファイルだけ確認日を更新する。未確認の dataset は stale のまま保持し、機能回帰が合格していても公開判定を保留する。

Node.js は確認した公式一覧の最新掲載である7月の High 3件が収載済み。追加 CVE を推測せず、既存の公式 source と保持期間を再確認する。built-in と JSON の advisory fingerprint、確認日、`schemaVersion=0.1.14`、`expiresAfterDays=30`、`highRetentionDays=365` を整合させる。

Keyv の443名・2,235 pair と公開報告の集計差は、再確認課題として残る。完全な資料を再確認するか、同じ限定スナップショットを維持する根拠とその限界を明示してレビューする。追加する新規事案を、この固定 campaign snapshot に混入させない。埋め込み承認 hash を JSON の再計算だけで追認する変更も行わない。

## 5 候補ファイルを安全に選定する

### 5.1 npm の限定追加

package root の `package.json` を読んだ後、既存の entrypoint 最大4件と Keyv 候補を維持し、次を追加する。

1. root `binding.gyp` を静的候補にする。通常の implicit node-gyp install が有効か、明示 script が参照するかを metadata で判断する。存在だけで悪性としない。
2. 対象 package または locally observed loader context で `3FWCvzduYZg.js`、`nu.js`、`is_it_this_simple.js`、`index.js` を候補化する。任意の package 全体をこの名前だけで悪性にしない。
3. supplychain.local では `lib/sckit.js` と `.sckit/windows-amd64/sckit.exe`、`.sckit/windows-arm64/sckit.exe` を対象にする。JS entrypoint から許可された固定 loader への参照を、最大2 hop で追う。
4. script や loader から得たパスは、元の package root 以下の固定ローカル文字列に限定する。URI、絶対パス、UNC、`..`、動的式、reparse traversal を拒否する。

新規候補は package あたり最大8件、既存分を含めた上限は16件を案とする。すべて既存の run-wide `MaxFiles`、targeted 最大50%/10,000件、project あたり2,000件の枠内に入れる。新規枠を別カウンターだけで計算して全体上限を回避しない。既存4 entrypoint と Keyv 候補を先に保ち、新規の順序は `binding.gyp`、4 root loader 名の記載順、`lib/sckit.js`、amd64、arm64 とする。同じ canonical path は1件として数える。

### 5.2 Python の限定追加

既存の `.venv`、`venv`、`env` 以下で、distribution の `METADATA` を候補化し、Name/Version を `installed-exact` として既存パッケージ照合へ渡す。installed 情報を単なる text fallback として WARN に降格しない。`memoryos` は import 名 `memos` と同一文字列ではないため、`RECORD` による所属と既知対応を明示し、Name の部分一致で他 distribution に結び付けない。

- `memoryos` は `memos/log.py`、`memos/_stage0.py`、その package 以下の `.sckit` Windows バイナリを選ぶ。
- `anthropic-sdk` は該当 distribution の `RECORD` 内の安全な Python entrypoint を限定的に選ぶ。名前が似ている正規の `anthropic` は対象 IOC にしない。
- Python 名の比較は lowercase と `[-_.]+` のハイフン正規化を ecosystem ごとに行い、npm 名のルールへ影響させない。
- METADATA の header は128 KiB、1,024行で区切りまで読み、必要な Name/Version の重複・不正を検証する。description 本文は読まない。RECORD は128 KiB、1,024行、distribution あたり新規 runtime 候補8件を案とし、どちらも run-wide/targeted/project の既存予算を消費する。
- RECORD は引用符と escaped quote を扱う3列の CSV として限定解析し、多行・不正行は実行せず未解釈理由を残す。site-packages の canonical root 内、かつ当該 distribution が所有する行だけを module に結び付ける。通常の RECORD に含まれる対象外の `../../../Scripts` 等は追跡しない。対象 runtime を指す不正行は重要 coverage failure にする。

Python/Node の実行、import、package manager、コードの動的評価は使わない。対象 module や binary が確認できない場合は、分かっている metadata による判定と未確認の実行ファイル coverage を別に表す。

新規 `Scan-PythonDistributionMetadata` と bounded header reader を追加する案とする。`Scan-File` は secret inventory の除外後、選定済み `METADATA` を **`Read-TextFileSafe` より前**に専用処理へ渡し、汎用 text 解析へ流さない。description が長くても header が上限内なら installed 判定を行い、description の IOC 文字列を実行コードに昇格させない。Name/Version が header 上限までに確定できなければ critical coverage failure にする。

`Scan-PythonFiles` の新規 `.py` 解析は登録済み runtime 候補に限定し、任意の venv module を全面探索しない。検査対象 distribution の header を queue 前に読む必要がある場合も、先に予算を予約し、同じ bounded reader と結果を再利用する。事前読取だけを予算の外へ逃がさない。

### 5.3 パス境界と hash の実装

新規 helper は `Test-IsPathUnderRoot` と `Test-PathHasReparsePointBelowRoot` の境界検査を再利用する。確認はファイルを開く直前にも行う。拒否した candidate を、別ルートや環境変数、ホスト既知パスで探し直さない。

`Scan-KnownFileIocs` 内では、path 条件を満たした file の SHA-256 を一度求め、その呼び出し内で複数 expected hash と比較する。全ファイルの再帰 hash や永続 cache は追加しない。`MaxFileSizeMB=10` の既存制限を維持し、hash 用途でも超過した重要候補は coverage failure にする。

### 5.4 check 所属と dispatch

| 対象 | owner check | dispatch と隔離条件 |
|---|---|---|
| exact installed/lock IOC、npm/Python package の artifact hash | `Packages` | Python も `Test-KnownFileIocCheckEnabledForFile` と `Add-KnownFileIocFinding` を同じ candidate provenance で判定する |
| GYP、npm/Python runtime、DNS・会話転送の汎用挙動 | `LifecycleScripts` | 候補が active/selected/Deep のどれかを渡し、新規 GYP/Python helper を `Scan-File` から呼ぶ |
| Action SHA/ref/CVE、workflow が参照するローカル publish bridge | `CiCd` | CI candidate として読む。Packages/LifecycleScripts の有効化を前提にしない |
| IDE artifact と IDE 内の転送挙動 | `IdeExtensions` | 既存 IDE 文脈を優先し、extension payload を Packages に付け替えない |

現在は Python venv 内の hash が `ScannerSelf` に振り分けられる。`-Checks Packages` 単独でも新規 Python hash が検査され、`ScannerSelf` 単独では新しい package 探索が始まらないよう両側を修正する。check macro の展開は変更しない。複数 owner の候補は一度だけ queue し、有効な各 rule の所属を保持する。

### 5.5 IDE の固定 payload と選択された archive

`Get-TargetedFileList` に `IdeExtensions` 専用の候補選定を追加する。新規 `Add-TargetedIdeIocFiles` は、明示 `-Path` 以下、または別途承認済み mode が既に提供した IDE root の中だけで動く。`out`、`dist` 等の通常除外規則を全体で緩めない。

- VS Code 系 extension の `package.json` で完全一致する publisher/name を確認した場合、`microsoftvs.microsoftvs` の `out/extension.js`、`cosmic-themes.theme-cosmic-nebula` の `app.js` を固定候補にする。main/browser の固定ローカル参照は既存の path/reparse 境界を使い、最大2件まで選ぶ。metadata を含めて extension root あたり新規4件、既存の全体予算内とする。
- 明示された展開済み extension root も、上記 metadata を根拠に candidate の IDE 所属を保持する。通常の project の同名 `app.js` を名前だけで extension としない。
- 明示された単一 `.vsix` または `.zip` は、`IdeExtensions` が有効なときだけ既知 IDE hash の候補にする。H14 は選択済み archive の bytes、H15/H16 は選定済み payload の bytes に照合する。root から任意の ZIP を追加探索せず、VSIX/ZIP の新規展開は実装しない。
- gate と finding の owner は同じ candidate metadata を使う。現行の extension path regex に合わない明示 archive が `ScannerSelf` に落ちる状態を残さない。未展開 archive の payload まで検査したとは報告しない。

## 6 挙動判定と深刻度

以下の category 名は提案であり、実装後に既存名と重複しないことを確認する。

| 判定面 | 強い条件 | 既知 IOC がない場合の判定 |
|---|---|---|
| GYP | `conditions` の scalar に Python object traversal、builtins/import 回復、OS/process 実行が同じ式として存在 | 有効な install entrypoint は DANGER、Deep でのみ到達した未選定 dependency は WARN |
| sckit loader | 固定 `.sckit` binary、`stage0`、`--config64`、process 起動が局所的に結び付く | campaign-shaped loader は WARN。exact package/hash は独立して DANGER |
| publish bridge | `GITHUB_ENV` への `BASH_ENV` 書込と、解決した bridge 内の publish credential が campaign 宛先へ流入 | active CI の同一経路は DANGER。宛先未確定の追加送信や環境設定だけは WARN 上限 |
| DNS 送信 | credential read の同じ局所変数が encode され、DNS query name に流入 | first-party/selected entrypoint は DANGER、未選定 dependency は WARN |
| 会話送信 | conversation/tool result の同じ値が、通常の利用者指定 API と別の固定宛先へ追加送信される | WARN。通常 API の呼出しは新規 WARN なし。exact virgil-cli IOC は独立して DANGER |
| IDE loader | 配布物 hash、または既存の実行・C2・資格情報送信の強い連鎖 | hash は DANGER。theme、AES、Solana API の存在だけは DANGER にしない |
| Action の CVE | 正確な数値参照版が affected range に入る | WARN、`riskType=posture`。upstream CRITICAL を別フィールドに保持 |

GYP の専用関数は `Get-GypStaticExecutionAssessment` と `Scan-GypBuildFile` を追加する案。Python の条件を実行せず、文字列・コメント・括弧の局所解析で scalar の位置を認識する。元の source を保持し、必要な literal 内の `\u`、`\U`、`\x` だけを制限付きで正規化する。decode は最大2 pass、64 KiB、Unicode scalar 妥当性を検証し、元の行番号へ戻せるようにする。

`conditions` に属する scalar を最大64件、構文深さを最大32として走査し、再帰評価や任意式の展開はしない。64 KiB は scalar ごとの解析上限で、ファイル全体は既存10 MiB上限も守る。各 literal の source span と行番号を保持する。選定理由を metadata の implicit install、明示 lifecycle script、first-party build の別として残し、inactive な例示を active と推測しない。

正規の native addon、通常の GYP command substitution、単なる条件比較を陰性対照に含める。解釈できない構文を実行して解決したり、安全とみなしたりしない。

CI bridge と DNS の helper は、同じ function/block または直接解決したローカル script を対象にする。解析 window は2,048文字、anchor は各64件、regex timeout は既存の2秒。別関数の credential と無関係な通信をファイル全体の共起で結ばない。コメントや passive reference text の例を active 実行へ昇格させず、実行可能な設定中の値は既存の文脈規則で評価する。

bridge path は workflow から参照される script 内の固定文字列だけを、project root 以下・最大2 hop・新規8候補の範囲で解決する。環境変数や式を評価して host path を作らない。Poetry の独自 build backend は本版では generic 静的ルールと exact IOC で対応し、backend-path の専用追跡は後続課題にする。正規 npm/PyPI publish の認証送信は CI exfil の陽性条件にしない。

新規 `Scan-RuntimeTransferBehavior` は選定済み JS/Python と CI/IDE script へ共通適用する案。会話転送の正当性や同意を offline で証明できるとは扱わない。通常 API しか分からないものは新規 WARN を出さず、解決できない追加宛先は能力・未確認として CAUTION に留める。固定の追加宛先への同一値の送信は `CONVERSATION_SECONDARY_TRANSFER_PATTERN` の WARN、`riskType=posture` とし、「窃取確認」と記載しない。

### 6.1 Actions の参照版と不明な ref

advisory 専用の `Get-ActionAdvisoryAssessment` を追加する。まず bad SHA と履歴 ref を既存関数で照合し、その後に advisory の結果を独立に評価する。既知 bad SHA の DANGER を advisory WARN で置き換えない。

比較対象は `v1.2.0` のような3成分の数値タグ。`v1`、branch、40桁 SHA、式、解釈できない prerelease は、脆弱版・修正版を推測せず `INFO` の `GITHUB_ACTION_ADVISORY_REF_UNRESOLVED` とする。既存の mutable ref WARN は維持する。修正番号に達したタグでも、宣言版が範囲外という意味に限定し、オンラインの実体が安全だとは記載しない。

## 7 coverage とレポートの契約

重要 candidate の kind として `native-build-config`、`runtime-loader`、`runtime-binary`、`python-distribution-metadata` を追加し、`Test-IsCriticalCandidate`、候補登録、読取、hash、レポート生成に一貫して渡す。

`script:Context` 内に canonical path ごとの candidate metadata map を追加し、`Reserve-ScanFile`/`Add-FileIfExists` の登録時に kind、owner checks、selection reason、active/selected/Deep-only、critical を保持する。重複 queue でも metadata を統合し、後から観測した重要な来歴で昇格できるようにする。`Get-CoverageCandidateKindForFile` はこの map を優先し、`Read-TextFileSafe` と hash/限定 metadata reader は同じ critical 値を `Register-CoverageFailure` へ明示する。

- active/selected candidate の不正、読取失敗、必要な解釈の上限到達は critical とし、`completionStatus=incomplete-critical` を維持する。
- Deep の未選定 helper の限定解析失敗は non-critical として扱い、理由と candidate kind を残す。
- 既知 file IOC の hash 対象は選定文脈によらず critical。Deep-only の汎用 helper の non-critical と混同せず、後の登録で critical を降格しない。
- 明示された予算を消費した未検査候補を `OK` に含めない。未解決の動的 import を任意の全再帰探索で補わない。
- severity と完了性と IOC freshness は別概念。DANGER を発見しても complete になり得るし、陰性でも incomplete になり得る。

`scanStats` には候補数、実解析数、制限到達数、hash 計算数を additive に追加する。レポートに `ruleId`、`sourceId`、`upstreamSeverity` を追加する場合は optional field とし、`Add-Finding` の引数検証、redaction、重複排除、TXT/JSON serialization をまとめて更新する。現在の `Add-Finding` が新しい引数を受け付けるとは扱わない。source は S01〜S13 に対応する公開資料のみ。証拠は package/version、hash、条件名、元の行番号に限定し、生の code、設定値、secret、DNS query の組み立て値を出力しない。

## 8 変更するファイルと実装の順序

| 段階 | 対象ファイル | 変更内容と完了条件 |
|---|---|---|
| M0 | 本体、README、既存 test の読み取り | 最新 baseline、既存差分、check scope、カテゴリを固定する |
| M1 | `iocs/known-packages.json`、`iocs/known-files.json`、`iocs/known-actions.json`、`iocs/known-extensions.json`、`iocs/suspicious-patterns.json`、`iocs/README.md` | exact 指標と出典を追加し、JSON・重複・hash 形式を検証する |
| M2 | `Scan-DevSupplyChain.ps1` | npm/Python 候補、path 境界、hash 重複計算、coverage を追加する |
| M3 | `Scan-DevSupplyChain.ps1`、`iocs/known-actions.json` | GYP、CI bridge、DNS、会話送信、Action advisory を実装する |
| M4 | `tests/Test-SecurityBoundaryRegressions.ps1`、新規 `tests/Test-SecurityUpdate20261006.ps1`、対象 sample と `tests/samples/manifest.json` | `KeepArtifacts` を先に追加し、本計画の合成テストと既存回帰を実行する |
| M5 | `README.md`、`CHANGELOG.md`、関連使用説明、必要なら `.github/workflows/validate.yml` | 最終挙動と制限を文書化し、全受入条件を確認する |

Node.js と Keyv の鮮度再確認は M1 と並行する。データ更新が必要な場合だけ `known-node-runtimes.json`、`campaign-keyv-chaindrop-20260806.json` と対応 built-in を小さく変更する。BAT の mode や確認フロー、AGENTS、`.codex`、hook、権限、CI の permission・trigger・secret 設定は変更対象にしない。

新規テストは repository 内の新しい専用ディレクトリを作り、fixture と report を保持する。既存 `Test-SecurityBoundaryRegressions.ps1` の finally には `Remove-Item -Recurse` があるため、後続実装の最初に `-KeepArtifacts` を追加し、その指定で実行する。再帰削除を自動承認で実行する計画にはしない。保管先の整理は今回の実装とは別の操作とする。

実装の prototype は M1/M2 の限定機能を動かすものとし、M3 の全ルールが完成するまで公開版扱いにしない。各段階で対象試験とレビューを行い、失敗原因を修正してから次へ進む。同じ material operation が2回失敗したら、別 tool や command form で回避せず状態を報告する。

## 9 合成テストと期待結果

実データや実マルウェアを取得せず、metadata、短い無害な文字列、実行しないバイト列で試験する。本体に任意 IOC path の環境変数 override や test 用の production bypass を追加しない。

hash の陽性試験には、無害な fixture の hash を使った in-memory test IOC を、既存の AST allowlist 方式で抽出した安全な helper と最小 context へ渡す。candidate 選定 → check gate → hash → finding → report の接続も、必要な定義だけを抽出する test harness で検証する。本体全体を dot-source せず、production source/IOC を書き換えない。実際の scanner の subprocess は陰性 bytes で queue と read/hash counter、report、check isolation を検証する。production の16 hash は source manifest の形式・一致を別に確認する。

| ID | 入力または操作 | 必須の期待結果 |
|---|---|---|
| T01 | npm は installed package.json と package-lock v3、Python は METADATA と Pipfile.lock で新規20 pair | 各 exact pair を既知 IOC として DANGER 検知。他形式の lock へ同じ保証を拡張しない |
| T02 | MemTensor `0.1.20/22/24`、MemoryOS `2.0.33` | 対象 package IOC の DANGER なし |
| T03 | Trinitite 2 prerelease と異なる末尾 | exact は陽性、別 prerelease と version range は推測で DANGER にしない |
| T04 | manifest の range、cache-only、説明文中の IOC | WARN 以下。感染や実行済みを断定しない |
| T05 | Windows `.sckit` inert bytes と test IOC | hash 陽性。1 byte 違いは同じ hash finding を出さない |
| T06 | loader を持つ安全な package、`stage0` の説明文 | campaign-shaped 条件が揃わない場合に DANGER なし |
| T07 | Python Name `MemoryOS`、module `memos`、安全な RECORD | 対応する metadata と固定 runtime 候補を結び付ける |
| T08 | 正規 `anthropic` と偽装 `anthropic-sdk` | exact identity を混同しない |
| T09 | 有効 install 経路の GYP object traversal + OS execution | `GYP_PYTHON_EXECUTION_COMPOUND` を DANGER |
| T10 | unicode/hex escape を含む GYP scalar | 静的正規化後に同じ判定、元の行番号を保持 |
| T11 | 正規 node-gyp、通常条件、コメント内の例 | GYP の新規 DANGER なし |
| T12 | GYP 不正構文、decode 上限、極端な長さ | 対象 coverage を incomplete にし、実行しない |
| T13 | first-party と Deep 未選定 dependency の同じ GYP | 前者 DANGER、後者 WARN。ancestor directory 名で前者を降格しない |
| T14 | CI の GITHUB_ENV 書込 + bridge の credential 外送 | active 経路で `CI_PUBLISH_BRIDGE_EXFIL_PATTERN` を DANGER |
| T15 | 正規 BASH_ENV 設定、別関数の token と通信 | 新規 compound の DANGER なし |
| T16 | credential 変数を encode して DNS name に使用 | selected code の `CREDENTIAL_DNS_EXFIL_PATTERN` を DANGER |
| T17 | DNS lookup、health check、別変数の通信 | DNS compound の DANGER なし |
| T18 | virgil-cli exact、利用者指定 API、別の固定宛先への追加会話 POST | exact は DANGER、通常 API は新規 WARN なし、追加送信は WARN |
| T19 | malicious Action SHA と歴史的タグ | SHA は DANGER、履歴タグは WARN |
| T20 | conflibot `v1.2.0/v1.2.1/v2.0.0` | 最初のみ CVE WARN。修正版タグでも一般 mutable WARN は許容 |
| T21 | conflibot `v1`、branch、未知 SHA、式 | advisory は unresolved INFO。悪性 SHA と誤認しない |
| T22 | 同じ extension ID の異なる bytes/registry、展開 root の out/app.js、明示 VSIX/ZIP | 固定 payload が通常モードで選定され、harness の hash 陽性のみ DANGER。ID は INFO、任意 ZIP は追加探索しない |
| T23 | package 外参照、UNC、reparse、絶対パス | package/root 外の内容を読まず、拒否の coverage を記録 |
| T24 | global/project/package の候補数上限 | unique count と limit を守り、未検査候補を完了としない |
| T25 | binary サイズ超過と read/hash 失敗 | critical candidate の incomplete を維持 |
| T26 | 新旧 Actions JSON と不正 advisory section | 旧 actions 維持。不正 section の invalid と fallback を報告 |
| T27 | stale/missing/invalid の各 dataset | historical match は維持、`releaseReady=false` |
| T28 | built-in/Node JSON、Keyv digest の不一致 | coverage/freshness warning。大きい local snapshot を無条件採用しない |
| T29 | 現行 clean/precision/self-scan/manifest 回帰 | 既存の severity、coverage、fixture 防護を維持 |
| T30 | report 出力、重複、redaction、引数特殊文字 | 既存非上書きと finding contract を維持し、秘密値を出さない |
| T31 | `Packages`、`LifecycleScripts`、`CiCd`、`IdeExtensions`、`ScannerSelf` を各単独実行 | 新規解析 finding の所属を守る。Python hash は Packages、GYP は LifecycleScripts、bridge は CiCd、IDE は IdeExtensions。dataset 全体の鮮度 warning は別に確認 |
| T32 | 同一 path を Deep と selected から重複登録 | unique count は1、owner と critical は統合され、後の登録で重要性を降格しない |
| T33 | 新規 kind の読取失敗・parse/regex 上限、長い METADATA description と Name/Version 重複 | kind/critical/完了性を保持。長い description は読まず、正常 header は exact 判定。不正 header は critical |
| T34 | 新鮮 header と不正 advisory body、旧 schema の欠落 section | invalid が後から current/stale に上書きされず、historical match と fallback は維持 |
| T35 | 新しい宛先 marker、suffix 偽装、一般 Solana/GitHub ホスト、文書/コメント | marker だけは WARN 以下、偽装 suffix は対象 rule 陰性、文脈だけで DANGER なし |
| T36 | npm/PyPI 正規 publish の認証 POST と campaign への bridge 送信 | 前者は新規 exfil DANGER なし、後者は active 経路だけ DANGER |

各 fixture に check、category、severity、`riskType`、confidence、`detectionMethod`、行番号条件、完了性を明記する。T01 の正確な installed/構造 lock は `KNOWN_COMPROMISED_PACKAGE`・DANGER・known-ioc・high・metadata。T04 の参照は `KNOWN_COMPROMISED_PACKAGE_REFERENCE`・WARN・known-ioc・medium・metadata とし、本文から推定した pair を installed-exact にしない。hash は既存 file IOC category・known-ioc・high・metadata と owner check を確認する。全体の DANGER 件数だけで判定せず、negative case は対象カテゴリが0件であることを確認し、stale IOC 由来の既存 WARN と分離する。

## 10 検証手順と実装の合格条件

実行場所は repository root。最初の子プロセスは scanner source の parser と JSON 検証だけを行う。その後の test runner は合成対象に対して scanner を実行する。以下は後続実装の検証手順であり、本計画書の検証済み実績とは区別する。

```powershell
$taskPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $taskPowerShell -NoLogo -NoProfile -NonInteractive -Command {
    $ErrorActionPreference = 'Stop'
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
        throw 'Windows PowerShell 5.1 is required.'
    }
    $taskTokens = $null
    $taskErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath '.\Scan-DevSupplyChain.ps1').Path,
        [ref]$taskTokens,
        [ref]$taskErrors
    )
    if (@($taskErrors).Count -ne 0) { throw 'PowerShell 5.1 parser validation failed.' }
    foreach ($taskJsonFile in Get-ChildItem -LiteralPath '.\iocs' -Filter '*.json' -File) {
        Get-Content -LiteralPath $taskJsonFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop | Out-Null
    }
    Get-Content -LiteralPath '.\tests\samples\manifest.json' -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw 'Parser or JSON validation failed.' }
& $taskPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '.\tests\Test-LauncherScopeContracts.ps1'
if ($LASTEXITCODE -ne 0) { throw 'Launcher contracts failed.' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'Diff whitespace validation failed.' }
```

次の2コマンドは、KeepArtifacts と新規 test runner を実装した後に使用する。現行 checkout で新規スイッチ・ファイルが存在するものとして実行しない。

```powershell
& $taskPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '.\tests\Test-SecurityBoundaryRegressions.ps1' -KeepArtifacts
if ($LASTEXITCODE -ne 0) { throw 'Security boundary regressions failed.' }
& $taskPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '.\tests\Test-SecurityUpdate20261006.ps1'
if ($LASTEXITCODE -ne 0) { throw 'Security update regressions failed.' }
```

新規 runner は GUID 付きの未使用 `reports/security-update-test-*` を create-new で作り、現在の task が作ったディレクトリだけに書く。report も別の未使用名とし、cleanup は行わない。スキャンは `-Path` と必要な check のみ。npm/Node のホスト scope を試す場合は既存 `-SyntheticValidation` と有効な repository 内の synthetic roots を明示し、欠落や拒否時に実ホストへ fallback しないことを先に検証する。UserProfile と EndpointTelemetry は含めない。

本計画の受入条件:

1. PowerShell 5.1 parser、JSON、既存 launcher と境界回帰、新規 T01〜T36 が合格する。
2. 通常の fully covered fixture は `scanComplete=true`、`completionStatus=complete`。失敗を仕込んだ fixture は予定した critical/non-critical 状態になる。
3. `executionSafety.networkAccess/externalCommands/targetCodeExecution` はすべて `none`。scanner 自身が外部通信、package manager、対象 binary、対象 script を呼び出す経路がない。
4. 全20 pair、16 hash の根拠と対応を確認し、既存 exact IOC、Keyv の固定整合性、Node parity を維持する。
5. 同じ file への複数 hash 計算を1回に抑え、上限 fixture でも規定外の候補を読まない。性能は同一の合成 corpus、環境、引数で warm-up 1回と計測3回を行い、中央値 `Tnew <= max(1.25 * Tbase, Tbase + 2秒)` を目安とする。M0 で v0.1.22 の baseline を測り、変更後も同じ corpus を使う。各 run の TXT/JSON は別の未使用名とし、Git checkout/restore や既存出力の置換をしない。
6. 自己検査と benign case に説明できない DANGER がない。正しい positive を抑止する filename/fixture-name exemption は追加しない。
7. すべての shipped dataset の完全な手動レビューが終了し、`iocData.releaseReady=true`。機能試験の成功を、この鮮度条件の代替にしない。
8. 最終 diff、Git status、秘密候補検査を確認する。commit/push/公開は別の明示依頼で行う。

## 11 残るリスクと保留条件

| 課題 | 対応と判断 |
|---|---|
| Keyv の全 source pair が独立再構築されていない | 限定 source の継続レビューを根拠付きで完了するまで、鮮度と公開可否を保留する |
| GYP の任意 Python や多段難読化 | 完全な parser/deobfuscator を作らず、既知構文だけを解析し、重要な unknown は coverage に残す |
| 間接 import が2 hop を超える | 上限と candidate の限界を記録し、未確認の経路を自動的に安全としない |
| Poetry 独自 build backend の専用追跡 | 今回は exact IOC と選定済み script の静的判定まで。任意 backend 解決を追加したと記載しない |
| mutable Action ref と不明 SHA | offline では現在の実体を断定せず、known bad SHA と posture を分ける |
| IDE の registry と package identity の衝突 | 配布物 hash を優先し、名前・IDのみの blanket DANGER を避ける |
| JetBrains 15 plugin の悪性版が未確定 | S13 の ID は保留資料。正確な ID/version または artifact hash の確認後に別変更として追加する |
| 出典の訂正と脅威情報の追加 | dataset 全体の再レビュー時に追従し、確認日だけ更新しない |
| 自己レビューの限界 | 計画の合格は実装・第三者評価・実ホストの安全性証明を意味しない |

## 12 計画書レビューの合格基準

自己レビューを100点で採点し、**90点以上かつ未解決の P0/P1 が0件**を合格とする。実装の試験スコアとは分ける。各項目は充足10点、具体化不足5点、欠落0点。

| 項目 | 確認する内容 |
|---|---|
| A 対象と契約 | 現行版、今回の成果物、offline/read-only、host scope が明確 |
| B 出典と exact IOC | 20 pair、16 hash、CVEと悪性の分離、未確認情報の扱い |
| C 現行コードとの統合 | 既存関数、変更ファイル、依存する処理の順序 |
| D 精度と深刻度 | negative case、Deep/selected 文脈、未知 ref、cluster の上限 |
| E 読取と保護境界 | path/reparse、秘密保護、実行禁止、cleanup、承認境界 |
| F 上限と失敗 | candidate、文字列、decode、regex、coverage の連携 |
| G 回帰試験 | positive/negative/failure と明確な期待値 |
| H 検証の実行可能性 | 現行と実装後のコマンド、5.1、生成物の保持 |
| I 実装と公開の判定 | 段階、blocking 条件、freshness と機能成功の分離 |
| J 文書の整合性 | 数値、参照、命名、レビュー指摘の反映 |

初稿を読み直して指摘と修正箇所を記録し、改善後に同じ基準で再評価する。評価中の本書を実装完了の報告へ書き換えない。

## 13 レビューと改善の記録

### R1 初稿のレビュー

現行コードと初稿を照合し、**75/100・不合格**と評価した。A/B/E/I/J は各10点、C/D/F/G/H は各5点。未解決の P1 が4件あり、点数に関係なく合格扱いにしなかった。

| 指摘 | 優先度 | 初稿の不足 | 改善稿への反映 |
|---|---|---|---|
| R1-01 | P1 | Python METADATA/.py の dispatch と hash の check 所属が未接続 | 2、5.2、5.4で選定・installed-exact・Packages gate/finding を一体化 |
| R1-02 | P1 | 新規 kind と Deep/selected の重要度が汎用 reader で失われる | 7で canonical path metadata map と critical の昇格規則を定義 |
| R1-03 | P1 | advisory 不正を後の鮮度判定が消す実装順序が未定義 | 4で body を含む検証後に status を1回だけ確定 |
| R1-04 | P1 | 通常の conversation POST も WARN になる | 6と T18 で通常 API と追加固定宛先を区別 |
| R1-05 | P2 | hash 陽性が helper 単体で、gate/queue/report の接続を検証しない | 9で AST harness と実 scanner の陰性統合試験を組み合わせる |
| R1-06 | P2 | JSON 検証の非終端エラーや encoding が曖昧 | 10で子プロセスの Stop・UTF8・5.1 確認を指定 |
| R1-07 | P2 | KeepArtifacts の変更ファイルが段階表から漏れる | M4 に既存 runner の限定変更を明記 |
| R1-08 | P2 | marker の追加先、GYP/bridge の上限、性能式が曖昧 | 3.3、5〜7、10と T31〜T36 に境界・oracle を追加 |

R1 の改善は計画書だけに反映した。再レビューでは、参照関数、20 pair、16 hash、source、JSON と PowerShell block、check 所属、完了性、文書内の件数と指摘反映を確認する。

### R2 改善稿 v0.2 の再レビュー

**85/100・不合格**。C/G/H は各5点、他項目は各10点。R1 の4件の P1 は計画上解消したが、追加の P1 が2件見つかったため改善を続けた。Windows PowerShell 5.1 の parser による文書内 block 検証と参照関数の実在確認は合格し、構文検証だけでは次の設計上の不足を除けないことを確認した。

| 指摘 | 優先度 | 再レビューの不足 | v0.3 への反映 |
|---|---|---|---|
| R2-01 | P1 | IDE の out payload が通常除外され、単一 archive も check gate で落ちる | 5.5と T22/T31 に固定候補と IDE provenance を追加 |
| R2-02 | P1 | METADATA が汎用全文 reader を通ると header 上限と本文不読を守れない | 5.2で専用 reader の dispatch 順序と予算予約を指定、T33に対照を追加 |
| R2-03 | P2 | 構造 lock の種類と ID watchlist の出力が曖昧 | T01の既存構造 parser、3.2/T22の INFO identity を明記 |
| R2-04 | P2 | baseline の別配布物作成と非上書きの具体手順が不要に複雑 | M0で変更前計測し、10で同じ corpus・未使用 report 名を指定 |

### R3 最終レビュー

v0.3 の修正を読み直し、**95/100・合格**と評価した。R1/R2 の P1 はすべて計画上解消し、未解決の P0/P1 は0件。A/B/C/D/E/F/H/I/J は各10点、G は5点。G の残り5点は、全36ケースの分類と期待結果はあるものの、各 variant の fixture と全 report field の機械判定用 oracle が M4 の成果物になるため。計画書の合格後も、その作成・実行は実装受入の必須条件として残す。

本チャット内で実施した文書検証:

| 検証 | 使用したローカル処理 | 結果 |
|---|---|---|
| 文書内コード | Windows PowerShell `5.1.26100.9444` の `Parser::ParseInput` と `ConvertFrom-Json` | PowerShell 2 block は構文エラー0、JSON 1 block は正常。block の scanner/test command は実行していない |
| 現行コードとの接点 | scanner の `Parser::ParseFile` と function AST の比較 | parser エラー0、統合表の32関数はすべて実在 |
| パッケージ指標 | 表と prerelease の静的抽出・重複照合 | 9名、20 pair、重複0 |
| hash と出典 | H01〜H16 の形式検証と、承認済み公開調査で取得した本文との照合 | 16 unique SHA-256、すべて64文字、転記の一致16/16。実マルウェアの取得・検証はしていない |
| テストと参照 | ID、Markdown link、fence の静的検査 | T01〜T36 と S01〜S13 に欠番なし。ローカル参照5件は存在し、code fence は6本で対応 |
| whitespace | `git diff --check` と新規文書の末尾空白検査 | `git diff --check` は終了0、文書の末尾空白0。既存変更の LF/CRLF warning は残る |

新規文書は untracked のため、`git diff --no-index --check -- /dev/null docs/security-update-20261006-detailed-implementation-plan-ja.md` でも確認した。終了1は空ファイルとの内容差によるもので、whitespace error は出ていない。計画作成で追加したのは本書1ファイルのみ。削除・移動・改名・既存ファイル全置換は各0件。

スキャナーの合成実行、実ホスト検査、ネットワーク再調査、性能測定、公開判定は今回は実施していない。計画書の初稿を改善する依頼であり、実装・IOC 更新は次の段階である。既存 dataset の鮮度再確認と Keyv source の未完了部分は、計画書の不備とは分け、4.1/10/11の公開保留条件に残した。

## 付録A ファイル hash の登録候補

hash は64文字の小文字 hexadecimal として保持する。path は source が示す artifact の役割であり、host root を意味しない。

| ID | artifact | SHA-256 | source |
|---|---|---|---|
| H01 | Trinitite root JS payload | `8e5d1af68ca340ae0c6e8132cb00c686ec2d60502c1994d94ce353d1472ad5a3` | S02 |
| H02 | Trinitite root JS payload | `b49afb7dba04cd99b357ce7c652c823a3707f28e130bd5c6645851a7adc030d6` | S02 |
| H03 | Trinitite root JS payload | `59370c67b54a0ccaedd265e2356f04540b2fba1e1845300ef6de4d5437d99380` | S02 |
| H04 | Trinitite root JS payload | `778d6f0058045d6a2ab9a7e1d3e3be8e7e6b4d9cc217d13949bf1dfbab759a7c` | S02 |
| H05 | Trinitite root JS payload | `b24d121667f21f492cb9db34fbfd515d5922a8dd30b9c45215c7220abbb10ca8` | S02 |
| H06 | Trinitite root JS payload | `e1f1162ece9a6e6ea21a20399cbf31c563a8149d433a68711f4223870c203d5a` | S02 |
| H07 | Trinitite root JS payload | `b6012b2ff87f08f93ee53921c48db907ddbcf5461b03bb988083b01a36886237` | S02 |
| H08 | Trinitite root JS payload | `709af2fdeb50324229e94c44c679a0fab18bd8e17d3864405989c526cbb63ad8` | S02 |
| H09 | npm sckit Windows amd64 | `56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be` | S03 |
| H10 | npm sckit Windows arm64 | `d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26` | S03 |
| H11 | Python sckit Windows amd64 | `16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047` | S03 |
| H12 | Python sckit Windows arm64 | `f7c4014e284f3d56c452b8b222a287c54f73dc4a40a7e022e765ac8376362947` | S03 |
| H13 | Shai-Hulud root index.js | `e37e3ddeeaaa9e0c4fdbcb829b4895a6521031c80053fc436625b61e6ee5b1a6` | S06 |
| H14 | microsoftvs.microsoftvs VSIX/ZIP | `a276b76d3b00f302bb4dfb3690125c85ff472b16049c3c37476ac5e51096df07` | S11 |
| H15 | microsoftvs.microsoftvs out/extension.js | `5e68ca8c2097caccdb74d2752b85b85595a4bf646b442b8431a2416e87dbf268` | S11 |
| H16 | cosmic-themes.theme-cosmic-nebula app.js | `684c877a52d226d50584cb886ca8ec5bec6355d4de853f406734c79d5b387804` | S11 |

## 付録B 公開資料と現行の契約

公表日と確認日は区別する。下記は本チャットで承認された公開情報調査に基づく参照であり、将来の外部取得の一括承認ではない。GitHub Advisory の日付は source の日付を使用する。

| ID | 公開資料 | 用途 |
|---|---|---|
| S01 | [GHSA-rg27-qr39-ch6w](https://github.com/advisories/GHSA-rg27-qr39-ch6w) | Trinitite exact 10 versions |
| S02 | [Aikido Trinitite report](https://www.aikido.dev/blog/popular-code-generator-for-tanstack-query-hit-by-supply-chain-worm) | GYP、root loader、8 hash、AI 設定への書込 |
| S03 | [SafeDep MemTensor report](https://safedep.io/memtensor-sckit-worm-npm-pypi) | 悪性・クリーンの混在、Windows hash、runtime loader、CI bridge |
| S04 | [GHSA-mhjf-v53x-7p87](https://github.com/advisories/GHSA-mhjf-v53x-7p87) | npm MemTensor exact 3 versions |
| S05 | [GHSA-hxf9-rvj5-h45h](https://github.com/advisories/GHSA-hxf9-rvj5-h45h) | memoryos exact 2.0.34 |
| S06 | [Aikido Shai-Hulud resurgence](https://www.aikido.dev/blog/shai-hulud-npm-resurfaces) | 4 exact pairs と共通 hash |
| S07 | [GHSA-xxp4-7566-29xj](https://github.com/advisories/GHSA-xxp4-7566-29xj) | anthropic-sdk と DNS fallback |
| S08 | [GHSA-6j8f-g5mj-4wcj](https://github.com/advisories/GHSA-6j8f-g5mj-4wcj) | virgil-cli exact version と会話送信 |
| S09 | [Socket Mini Shai-Hulud Actions](https://socket.dev/blog/mini-shai-hulud-actions) | 悪性 SHA、再有効化と再無効化、履歴 ref |
| S10 | [GHSA-2qvg-qr73-mqxp](https://github.com/advisories/GHSA-2qvg-qr73-mqxp) | conflibot CVE と修正版 |
| S11 | [Socket GlassWorm themes](https://socket.dev/blog/glassworm-vscode-themes) | 悪性配布物3 hash、cluster-only 情報の区別 |
| S12 | [Node.js vulnerability index](https://nodejs.org/en/blog/vulnerability) と [July 2026 security releases](https://nodejs.org/en/blog/vulnerability/july-2026-security-releases) | 現行 High 3件と公式の追加確認 |
| S13 | [Aikido JetBrains report](https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys) | 悪性版未確定の保留資料 |

repository の参照は [README](../README.md)、[CHANGELOG](../CHANGELOG.md)、[IOC 更新規則](../iocs/README.md)、[Codex Review Checklist](codex-review-checklist.md)、[PC テスト手順](pre-push-test-procedure-ja.md)。現在の契約と source が食い違う箇所は、推測で解消せず対象の受入条件で止める。
