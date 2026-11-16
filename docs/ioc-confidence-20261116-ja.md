# IOCの証拠と判定の修正（2026-11-16）

2026年11月9日の公開情報照合を判定処理へ反映した。旧41組のうち39組は一次報告がパッケージ名と版を明示している。残るInjective関連2組は、公開履歴と包括的な警告に基づく要確認指標として残す。配布物そのものの独立解析は41組とも行っていない。

## 判定と出典

| 対象 | ロック／インストール情報で版が一致した場合 | 根拠 |
|---|---|---|
| 決済ブランドを名乗る13パッケージの `1.0.0～1.0.3` | DANGER、high、`known-ioc` | S12の一次調査が全4版を明示。旧41組に含まれるのはこのうち `1.0.1～1.0.3` の39組 |
| `@injectivelabs/wallet-cosmostation@1.20.21` | WARN、medium、`posture` | S13の包括的警告と公開時刻。個別の悪性を確認する資料は不足 |
| `@injectivelabs/wallet-cosmos-strategy@1.20.21` | WARN、medium、`posture` | 同上 |
| 過去に侵害されたActionsタグ15件 | WARN、medium | 過去の侵害出典は一致するが、現在の参照先は未確認 |
| 既知悪性Actionsコミット3件 | DANGER、high | 一次報告に記載された不変のSHAと一致 |

未確認2組の検出見出しは `Package version is associated with an incident; individual compromise is unconfirmed`。版の照合精度と悪性を断定できる根拠を区別する。manifest・制約式・cache等の参照だけならWARN・lowで、インストールや実行を証明したとは扱わない。通常走査、npm globalの静的メタデータ走査、npm cacheの静的走査で同じ区別を適用する。WARNの終了コードは1、DANGERは2。

| Source ID | 公開出典 | 確認した範囲 |
|---|---|---|
| S12 | [Socketの決済SDK偽装キャンペーン調査](https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps) | `Each npm package published four malicious versions (1.0.0 through 1.0.3)` と13パッケージ名の列挙。2026-11-09照合 |
| S13 | [Injective Issue #697](https://github.com/InjectiveLabs/injective-ts/issues/697) と [COLLABORATORの警告コメント](https://github.com/InjectiveLabs/injective-ts/issues/697#issuecomment-4919718904) | 本文は `sdk-ts@1.20.21` を明示。コメントは `v1.20.21 packages` 全般を警告するが、対象2名は個別に記載しない。2026-11-09照合 |
| S14 | [Aikidoのcodfish調査](https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets) | 14タグの列挙／範囲と悪性コミット2件。2026-11-09照合 |
| S09（既存） | [SocketのMini Shai-Hulud調査](https://socket.dev/blog/mini-shai-hulud-actions) | `actions-cool/issues-helper@v2.2.1` と悪性コミット1件。2026-11-09再照合 |

S12のnpmパッケージは `paysafe-checkout`、`paysafe-vault`、`neteller`、`skrill-payments`、`paysafe-js`、`paysafe-api`、`paysafe-node`、`paysafe-cards`、`paysafe-fraud`、`paysafe-kyc`、`skrill`、`skrill-sdk`、`paysafe-payments`。OSVの関連13告知は `1.0.0` のみを指定しており、OSVの範囲を他の版へ拡張解釈していない。39組の追加根拠はSocketの記事である。

## データ・内蔵定義・表示の整合

`known-packages.json` とPowerShellの内蔵IOCに `evidenceBasis`、`sourceId`、`sourceReviewedAt` を持たせた。今回追加する根拠区分は `primary-report-exact` と `historical-correlation`。後者はWARNに限定し、不明な区分、不正な確認日、断定的な重大度との矛盾はローカルデータ不正として扱う。欠落・不正時にも内蔵の2組はWARNのままで、DANGERに戻らない。

通常走査とnpmの静的走査は共通の判定処理を使う。未確認2組のcategoryは `PACKAGE_INCIDENT_CORRELATION` とその参照・npm用区分になり、`riskType=posture` となる。重大度と分類を混同せず、既知悪性を示すSecurityEvidenceとしては集計しない。通常ルートのWARNとして優先表示に載る場合も、見出し・信頼度・根拠不足の説明を保持する。

TXT/JSONには根拠区分、出典の照合日、`artifactAnalysis=not-performed` を記録する。出典IDだけを追記して悪性断定の文言を残すことはしない。別のルールが検出する悪性ハッシュや能動的な秘密情報送信は、今回の2組の区分変更の対象外。

2026-11-09の認証付きタグAPIは、両リポジトリで `Repository access blocked`、`block.reason=tos` を返した。API残枠は4,999／4,998あり、今回の403はレート制限ではない。2件で停止し残13件は直接照会していない。データはリポジトリ単位の `repositoryCheckStatus` / `repositoryCheckedAt` として保存し、レポートは `currentTarget=unverified` と `repositoryAccessAtLastCheck=blocked-tos; repositoryCheckedAt=2026-11-09` を表示する。個々の15タグを照会済みとせず、過去の観測を現在のGitHub状態とも断定しない。

一般IOC全体の `lastUpdated=2026-11-07` と期限2026-12-07は維持する。部分的な出典照合でデータセット全体の期限を延長しない。鮮度の `releaseReady` は配布物の真正性や個別IOCの証拠強度を表す指標ではない。

## Node.js更新の調査（2026-11-16）

このチェッカーはBATとWindows PowerShell 5.1だけで動作し、Node.jsの導入・更新を実行条件にしない。Git直接取得のCIもNode.jsのcheckout Actionを使わない。開発作業やアプリで別途使用するNode.jsの更新は、利用する系列と実際のランタイムごとに判断する。

[Node.jsの11月11日セキュリティ告知](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases)、[公式リリース一覧](https://nodejs.org/dist/index.json)、[サポート状況](https://nodejs.org/en/about/previous-releases)、各修正版の告知を計6リクエストで照合した。11月16日時点の公式一覧の安定版は次のとおり。

| 使用系列 | 今回のセキュリティ修正版 | 方針 |
|---|---|---|
| 22.x | [22.23.5](https://nodejs.org/en/blog/release/v22.23.5) | これより古い版は同系列の修正版へ更新する |
| 24.x | [24.22.3](https://nodejs.org/en/blog/release/v24.22.3) | 24.22.1／24.22.2も今回の更新対象 |
| 26.x | [26.13.1](https://nodejs.org/en/blog/release/v26.13.1) | これより古い版は同系列の修正版へ更新する |

公式告知はHigh 7件、Medium 6件、Low 3件を記載している。Highは `CVE-2026-123863`、`123864`、`123865`、`123866`、`126051`、`123872`、`123874`（すべて `CVE-2026-` 接頭辞）。HTTP/2、HTTPS/TLS、mTLS等の条件があり、版が古いだけで利用中アプリの悪用到達性まで確認したことにはならない。告知の影響系列と各条件はCVEごとに異なる。

通常インストールのNode.jsは、現在使っているLTS系列内の修正版を第一候補とする。アプリに同梱されたNode.jsはアプリの更新経路・ベンダーの修正状況を確認し、同梱実行ファイルだけを置き換えない。更新後は別途、選択される実行ファイル、関連プロセスの再起動、対象プロジェクトの回帰を確認する。バイナリ取得・インストール・更新は今回実施していない。

初回の更新調査時点では11月11日のHigh 7件は未収録だった。その後の追加依頼に基づき、公式告知の影響系列・修正版・条件を照合し、同梱 `known-node-runtimes.json` と内蔵定義へ反映した。現在は24件を収録する。追加範囲・確認限界と回帰は [Node IOC・HTTP2Shell再照合](node-http2shell-20261116-ja.md) を参照する。版の陰性だけで全CVEや実行時の安全性を保証するものではない。

HTTP2Shell専用基準も追加依頼でBun・Electron・Python・.NET等まで再照合し、`lastReviewed=2026-11-16` へ更新した。11月24日UTCからstaleとなる。.NET 11.0.0と製品内蔵コピーなど、未確認の範囲は引き続き要確認として残す。

## 合成回帰

`tests/Test-IocConfidenceRegressions.ps1` は、未確認2組のinstalled／lock／manifest参照、一次報告39組、対象外の隣接版、15タグ・3コミット、欠落／不正時の内蔵フォールバック、合成npm global/cache、TXT/JSON一致をWindows PowerShell 5.1で検査する。`Test-IocMaintenance.ps1` から呼び出すため、既存CIのIOC maintenanceステップにも含まれる。実プロファイルや実npm配置にはフォールバックしない。

実施した検証の結果と残る制限は [最終レビュー追補](final-review-20261107-ja.md) に記録する。既存のfixtureや公開履歴の証拠は削除しない。
