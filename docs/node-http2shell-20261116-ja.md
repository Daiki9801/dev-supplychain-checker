# Node IOC追加・HTTP2Shell基準再照合（2026-11-16 JST）

Node.jsの11月11日公開High 7件を追加し、Node IOCは既存17件と合わせて24件になった。JSONと内蔵定義を同時に更新した。HTTP2Shellは製品別の公式告知・固定ソースを再照合し、確認日を11月16日、Electronの完全一致リストを19版へ更新した。

スキャナーは引き続き依存不要・offline-only・read-only。調査中に公式公開情報を取得したが、スキャナーに通信、対象コード実行、更新機能は追加していない。本書はローカル実装・合成検証時点の記録であり、この段階では実PCの再走査、Nodeのインストール・更新、Git状態変更・公開は実施していない。後続の公開前レビューは [最終レビュー](final-review-20261107-ja.md) を参照する。

## Node.jsの追加7件

[Node.js公式11月セキュリティ告知](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases)の各Impact欄を基準とする。修正版は [22.23.5](https://nodejs.org/en/blog/release/v22.23.5)、[24.22.3](https://nodejs.org/en/blog/release/v24.22.3)、[26.13.1](https://nodejs.org/en/blog/release/v26.13.1)。

| CVE | 告知の対象系列 | 付随条件・確認の限界 |
|---|---|---|
| CVE-2026-123863 | 24、26 | HTTP/2でリクエスト本文の完了前に応答するサーバー。TLS・平文の両方 |
| CVE-2026-123864 | 22、24、26 | HTTPS、本文完了前の応答処理、本文のecho／保存等。平文HTTPは対象外 |
| CVE-2026-123865 | 22、24、26 | HTTP/2の接続終了中にプロトコルエラーが生じる経路 |
| CVE-2026-123866 | 22、24、26 | 未送信の応答を持つstreamの破棄。アプリ起点のtimeout等は全3系列。遠隔peerだけで破棄を駆動する経路は24.22.0／26.9.0以降という違いがある |
| CVE-2026-126051 | 24、26 | TLSサーバーの遅延handshake callback、SNICallback／OCSPRequest／newSession／resumeSession／addContext等 |
| CVE-2026-123872 | 22、24、26 | TLS 1.2再ネゴシエーションと、ホスト名ごとに異なるクライアント証明書ポリシー |
| CVE-2026-123874 | 24、26 | HTTP/2のrespondWithFile／respondWithFDと、書き込み待機中のstream reset |

対象系列の開始版から修正版未満を範囲として保持する。これは公式Impact欄の系列指定を表現したもので、すべての過去ビルドを個別解析・再現したという意味ではない。22系列が明記されていない3件へ22の範囲を追加しない。22のリリースに関連修正コミットが含まれることだけで、公式の影響系列を広げない。EOL・告知対象外のmajorの範囲も推測しない。

版が一致した場合もスキャナーの重大度はWARN、上流重大度はHIGH、利用条件は `unknown`。実行中の版、機能の利用、外部入力の到達、悪用や侵害の成立は証明しない。Medium 6件・Low 3件は、既存の「Critical全期間・High直近365日」という収録方針の対象外。

既存17件も、各項目の参照する公式セキュリティ告知8ページを再確認した。既存の範囲・日付・条件を保持し、新規7件だけを追加した。Nodeデータの `lastUpdated` は2026-11-16、30日の期限は2026-12-16。他の6 IOCデータセットの確認日2026-11-07・期限2026-12-07は延長していない。

## HTTP2Shellの再照合

対象は引き続きBrotli decoderの **CVE-2026-111497**。11月のHTTP/2・TLS CVEをHTTP2Shellの修正版閾値へ混ぜない。たとえばNode 24.22.1はBrotliの当該CVEでは修正済み参照だが、今回追加した11月のHigh 7件では版が一致する。

| 系統 | 再照合結果 |
|---|---|
| Google Brotli | 公式リリースv1.0.10／v1.1.1／v1.2.1にCVEの修正を明示。元の各系列の閾値を維持 |
| Node.js | 10月の公式告知と照合し、当該CVEの閾値22.23.4／24.22.1／26.12.1を維持 |
| Bun | 1.4.3の固定依存はBrotli v1.2.0、1.4.4はv1.2.1。公式リリースとも照合し閾値1.4.4を維持 |
| Python | GHSA-9v8h-qqgm-4m35とPyPI公開メタデータを照合。Brotli 1.2.1、brotlicffi 1.2.1.0を維持。wheel等は取得していない |
| .NET 8／9／10 | Microsoft公式告知の8.0.33／9.0.22／10.0.14を維持。SDKやホスト版を選択ランタイムと同一視しない |
| .NET 11 Preview／RC | 公式一覧のPreview 1–7・RC 1–2、修正版11.0.0-rc.3.26522.148を再照合 |
| .NET 11.0.0 | 11月10日リリースを確認したが、取得した固定decoderソースでは上流のblock-switchエラー伝播修正との対応を確定できなかった。GA版を修正済みリストに追加せず `unknown` を維持する。これだけで配布バイナリの脆弱性やバックポートの有無を断定しない |
| Electron | 既存11版に44.11.0～44.11.3、45.3.0～45.3.3の8版を追加。公式リリース対応表・GNリンク先・Chromium 8固定版の依存記録を照合。すべてBrotli `cfa184a997ac19454d5a3ae97f6d600aac2445a6` へ対応し、固定decoderで修正を確認 |
| CISA KEV | 11月13日付の公式カタログに、掲載日2026-10-27の当該CVEが存在することを再確認 |

Electronは完全一致の19版のみを扱う。将来版、未照合の版、独自ビルドを修正済みと推定しない。アプリ内蔵のElectron／Node／Bun、ASAR、native addon、ロードされたdecoder、入力到達性、再配備・再起動の完了は引き続き要確認。

HTTP2Shellの `lastReviewed=2026-11-16`、`reviewAfterDays=7`。UTCで11月23日まではcurrent、**11月24日からstale**となる。日時を受け取る内部ヘルパーにより、確認日前・当日・7日後・8日後を合成検証する。CLIやOS時計を変更する機能は追加していない。

## 証拠と調査範囲

[公開出典・ハッシュ・版対応の台帳](node-http2shell-20261116-evidence.json)に取得URL、時刻、SHA-256、Node追加定義、Electron19版の対応を記録した。本文・固定ソースの取得原文はGit除外のローカル台帳へ保持した。

今回の公式照会は42試行、39成功。制限環境でNode 1回・CVE API 2回が接続失敗した。Nodeは通信権限付き実行で取得できた。2回失敗したCVE APIへの直接照会は停止し、そのレコードを確認済みとはしていない。Nodeの追加範囲は取得できたNode.js公式告知と修正版の一次情報に基づく。補助確認したNode security-wgのindexには新規7件がなく、その台帳から範囲を補完していない。

公開識別子だけを送信した。認証・秘密情報・リポジトリ内容の送信、バイナリ取得、インストール、取得コード実行、外部書き込みはない。各製品の未確認範囲を隠すために確認日だけを延長したものではない。

## 回帰検証

`Test-NodeSecurity20261116.ps1` は7 CVEの140境界、修正版・build metadata・prerelease・対象外major、通常／欠落／不正データでの内蔵fallback、TXT／JSON一致、ホスト走査なし、11月CVEとBrotli判定の違いを検査する。`Test-IocMaintenance.ps1` から呼び出すので既存CIにも含まれる。

`Test-Http2ShellAudit.ps1` はElectron追加8版と未知版、専用基準の4日付境界を追加した。CIの修正済み版と合成PEの版情報は11月修正版へ更新し、旧修正版を新規Highの陽性ケースとして残した。`node-runtime-safe/.nvmrc` の22.23.5への変更に合わせ、その1件のmanifestハッシュを更新した。fixtureの件数・検査の省略条件は変えていない。

Windows PowerShell 5.1での最終結果・実行コマンド・残る承認事項は [最終レビュー](final-review-20261107-ja.md) に記録した。11スイートと子スイート2件が合格し、新規Nodeは140境界・3走査・325 assertions、HTTP2Shellは252 assertions。ローカルの合成回帰成功はGitHub CIの成功や実PCの修正完了を代替しない。
