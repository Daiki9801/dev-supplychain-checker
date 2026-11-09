# 同梱 IOC 再レビュー（2026-11-07 JST）

同梱 7 データセットを既存の項目別台帳と公開出典で再照合した。一般 IOC のレビュー期間は 30 日、HTTP2Shell 専用基準は 7 日。照会したのは公開アドバイザリ、公開メタデータ、一次報告と固定ソース。公開識別子を使い、ペイロードや配布バイナリの取得・実行は伴わない。 [前回の項目別台帳](ioc-maintenance-20261006-evidence.json) [HTTP2Shell の照合結果](http2shell-audit-ja.md)

## データセットごとの照合

| データ | 照合結果 |
|---|---|
| `known-packages.json` | 既存 124 組を再照合。68 組は非撤回の OSV マルウェアレコード、15 組は npm の公開メタデータに残る開発元の侵害警告、41 組は既存のインシデント資料と npm の公開時刻・取り下げ履歴。41 組すべてに公開時刻があり、うち 39 組にバージョンの取り下げ記録があった。8 組を追加し、合計 132 組。 [npm レジストリ](https://registry.npmjs.org/) [Injective の公開報告](https://github.com/InjectiveLabs/injective-ts/issues/697) [SafeDep の Jscrambler 調査](https://safedep.io/blog/jscrambler-npm-supply-chain-compromise) |
| `known-files.json` | 27 件。追補 16 ハッシュ、Jscrambler の 3 ハッシュ、codfish の 1 ハッシュを公開出典で確認した。Jscrambler の `setup.js` は OSV、`intro.js` と Windows 実体は SafeDep にハッシュがある。旧 6 ハッシュと永続化ファイル名 1 件は過去の出典に基づく指標。 [OSV MAL-2026-10187](https://osv-vulnerabilities.storage.googleapis.com/npm/MAL-2026-10187.json) [Trinitite](https://www.aikido.dev/blog/popular-code-generator-for-tanstack-query-hit-by-supply-chain-worm) [MemTensor](https://safedep.io/blog/memtensor-sckit-worm-npm-pypi) [Shai-Hulud](https://www.aikido.dev/blog/shai-hulud-npm-resurfaces) [テーマのハッシュ](https://socket.dev/blog/glassworm-vscode-themes) |
| `known-extensions.json` | 16 件。oorzc、quartz、WakaTime、AutoImport、テーマの識別子を公開報告・IOC と照合した。照会した Open VSX の版／ID は 404。Nx Console と旧 ID ウォッチ 6 件は既存の出典で保持し、レジストリをまたぐ同一性は未確認。 [AFINE 公開 IOC](https://github.com/afine-com/glassworm-hunter/blob/main/data/ioc.json) [Open VSX ローダー調査](https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise) [テーマ調査](https://socket.dev/blog/glassworm-vscode-themes) |
| `known-actions.json` | 2 リポジトリの悪性コミット・当時の参照と conflibot の CVE を照合。対象のタグ照会は 403 で、可変参照の現行コミットは未確認。10 月 7 日以降の公開 Actions 差分はマルウェア 0 件、信頼ストア関連の `GHSA-5xjx-3w67-w9x9` 1 件。同 GHSA は CA の信頼チェーンに関する告知で、既知悪性コミット／参照と CVE を扱う現行データには登録しなかった。 [codfish 調査](https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets) [Mini Shai-Hulud](https://socket.dev/blog/mini-shai-hulud-actions) [conflibot](https://github.com/advisories/GHSA-2qvg-qr73-mqxp) [pypi-publish](https://github.com/advisories/GHSA-5xjx-3w67-w9x9) |
| `suspicious-patterns.json` | 3 ドメイン・8 パターンを公開報告と既存出典で照合。MemTensor、Shai-Hulud、GlassWorm テーマ、virgil-cli のエンドポイントは実行文脈付きの指標。古いドメイン・ウォレット・複合パターンは出典の強さを維持した。 [MemTensor](https://safedep.io/blog/memtensor-sckit-worm-npm-pypi) [Shai-Hulud](https://www.aikido.dev/blog/shai-hulud-npm-resurfaces) [GlassWorm](https://socket.dev/blog/glassworm-vscode-themes) [virgil-cli](https://github.com/advisories/GHSA-6j8f-g5mj-4wcj) |
| `campaign-keyv-chaindrop-20260806.json` | 443 名・2,235 組の集合が前回台帳と一致し、443 件の現行 OSV レコードですべて非撤回の完全一致を確認した。3 ハッシュは OSV と一次報告に一致。4 マーカーと Git 参照 1 件は承認済みスナップショット由来。原資料・CSV の `reviewStatus` とパッケージダイジェストを保持した。 [Keyv 一次報告](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack) [公開 OSV の例](https://osv-vulnerabilities.storage.googleapis.com/npm/MAL-2026-11551.json) |
| `known-node-runtimes.json` | 既存 13 件を 7 つの公式告知で再照合し、10 月公開の High 4 件を追加。High の保持期間 365 日内。11 月 11 日分は版・CVE 範囲の公表待ち。 [公式一覧](https://nodejs.org/en/blog/vulnerability) [10 月リリース](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) [11 月予告](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) |

OSV は前回の項目別台帳にある公開 ID を個別の JSON で取得し、`withdrawn` がなく、エコシステム・パッケージ・`affected.versions` が一致することを確認した。取得した 489 件は npm 482 件、PyPI 7 件。照合対象は Keyv の 2,235 組と通常 IOC の 68 組。`[ecosystem, id, modified, bodySha256]` のソート済み配列を空白なしの UTF-8 JSON にした SHA-256 は `c6564930d36d1212e6f4f44105dc20b3bee2d321ec357733672be0ffd269cdfe`。古い 41 組に対するレジストリ照合は、当時の出典と公開履歴の照合であり、各アーティファクトの独立再検証は別途必要になる。

## 新規の完全一致パッケージ

| エコシステム・名前 | 版と根拠 |
|---|---|
| npm `@cherrydotfun/miniapp-sdk` | `0.1.22`、`0.1.23`。非撤回の GitHub マルウェア告知と npm の公開履歴を照合。 [GHSA-q8jp-gq6p-hwpx](https://github.com/advisories/GHSA-q8jp-gq6p-hwpx) [npm メタデータ](https://registry.npmjs.org/%40cherrydotfun%2Fminiapp-sdk) |
| PyPI `filipt` | `0.1.0`、`0.1.1`、`0.1.2`、`0.1.3`、`0.1.4`、`0.1.5`。wheel のビルド／インストール時の悪性コードを報告した非撤回の OpenSSF レコードと一致。 [MAL-2026-18580](https://osv-vulnerabilities.storage.googleapis.com/PyPI/MAL-2026-18580.json) [GHSA-687f-xhmq-5mwg](https://github.com/advisories/GHSA-687f-xhmq-5mwg) |

## Node.js の追加境界

`CVE-2026-105482`、`CVE-2026-106069`、`CVE-2026-111497` の対象系列は 22、24、26。修正版はそれぞれ `22.23.4`、`24.22.1`、`26.12.1`。スキャナーは公式記載の系列内で修正版未満を照合し、DNS リゾルバー、TLS クライアント、信頼できない Brotli 入力の条件を個別に残す。 [Node.js 公式告知](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)

`CVE-2026-105483` は全角 IPv4 の TLS 回帰。`checkServerIdentity` が ASCII 正規化後の値で IP を判定していた版と、元のホスト名で判定しつつ正規化後の値を DNS 名照合へ渡すようになった版を比較した。初めて後者となる `24.20.0` と `26.6.0` を下限とし、修正版 `24.22.1` と `26.12.1` は範囲外。22 系は公式告知の対象外。 [24.19.0](https://github.com/nodejs/node/blob/v24.19.0/lib/tls.js) [24.20.0](https://github.com/nodejs/node/blob/v24.20.0/lib/tls.js) [26.5.1](https://github.com/nodejs/node/blob/v26.5.1/lib/tls.js) [26.6.0](https://github.com/nodejs/node/blob/v26.6.0/lib/tls.js) [24.22.1 修正記録](https://nodejs.org/en/blog/release/v24.22.1)

`iocData.releaseReady` は、これらの手動選定データの鮮度と完全性に対する公開条件。HTTP2Shell の個別鮮度は `http2ShellAssessment.baselineStatus`、実際に選択されるランタイムや到達性は個別の証拠で確認する。

## Windows PowerShell 5.1 の検証

`5.1.26100.9711` で PowerShell 構文 4 件と必須 JSON 9 件を検証した。合成回帰 9 スイートと、CI の Node.js 版マトリクス・CVE 別境界をローカルで実行した。IOC maintenance は 39 ケース・1,089 assertion・158 fixture、HTTP2Shell は 163 assertion。追加パッケージは lockfile の `0.1.22` と `0.1.5` が DANGER、同じ名前の未登録 `0.1.24` と `0.1.6` は一致 0 件だった。

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-IocMaintenance.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-Http2ShellAudit.ps1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-SecurityUpdate20261006.ps1
$verifyDir = '.\reports\ioc-refresh-verified-' + [Guid]::NewGuid().ToString('N')
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -Checks Recommended -ReportDir $verifyDir -NoColor -Quiet
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples\node-runtime-safe -Checks NodeRuntime,Http2Shell,ScannerSelf -ReportDir $verifyDir -NoColor -Quiet
git diff --check
```

通常の合成サンプルと NodeRuntime／HTTP2Shell の併用走査は両方とも `scanComplete=true`、`completionStatus=complete`、`iocData.releaseReady=true`。`currentCount=7`、期限超過・欠落・不正は 0。通常サンプルの終了コード 2 は検出用 fixture による。併用走査は終了コード 0、`http2ShellAssessment.baselineStatus=current`。

この文書の初回照合時点では、`Test-SecurityBoundaryRegressions.ps1` が `-UserProfile` を呼ぶため自動検証から除外した。その後、明示した合成ルートだけを使う方式へ改修し、ローカル144 assertionsと、候補 `01effcb` の [Windows CI](https://github.com/Daiki9801/dev-supplychain-checker/actions/runs/42353763124) が合格した。現在のコマンドは `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-SecurityBoundaryRegressions.ps1`。実PCの自動探索は検証していない。 [最終レビュー](final-review-20261107-ja.md) [レビュー手順](codex-review-checklist.md)
