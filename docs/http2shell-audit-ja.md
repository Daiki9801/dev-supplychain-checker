# HTTP2Shell / CVE-2026-111497 特別監査

**2026-11-07 JST 再レビュー**。初回調査は 2026-10-26。対象バージョンは **0.1.28**。

引き継ぎ資料 `HTTP2Shell_CLAUDE_CODE_HANDOFF_2026-10-25.md` を起点に、公開一次情報と固定ソースを再確認した。この文書は一般配布用の判定根拠であり、資料にある特定PCの製品版・PID・署名・更新状態を再観測した記録ではない。資料内の過去の許可を、今回の実機読み取り・設定変更・他プロジェクト更新の許可として扱っていない。

## 調査結果

対象は Google Brotli の C デコーダーにある境界外書き込み **CVE-2026-111497**。Node2Shell、Broccoli2Shell とも呼ばれる。このプロジェクトでは利用者の引き継ぎ名に合わせて HTTP2Shell をメニュー名に残すが、**HTTP/2 固有の脆弱性ではない**。

不正な圧縮入力に対するエラーと「入力不足」の区別が失われ、ストリーミング処理が内部バッファへ追加書き込みを続ける問題である。公式修正は不正な block switch を恒久エラーとして伝播する。攻撃入力を処理すると、クラッシュ、メモリ情報漏えい、コード実行につながる可能性がある。正常な Brotli 往復テストの成功は修正確認にならない。スキャナーは圧縮データ・フォントを展開せず、不正入力やPoCを実行しない。

CVE の CNA 評価は **CVSS 4.0: 9.2 / CRITICAL**。Node.js の評価は **HIGH**、Microsoft の .NET 評価は **CVSS 3.1: 8.1 / HIGH**。CISA は **2026-10-27** に KEV に掲載した。レポートはこの掲載日を記録し、対象環境については静的な版、ロード、到達性、対処の各証拠を分ける。 [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-111497)

| 部品・経路 | 2026-11-07 に照合した修正根拠 | 自動判定の境界 |
|---|---|---|
| Google Brotli C ライブラリ | 1.0.3–1.0.9、1.1.0、1.2.0 が対象。修正版は **1.0.10 / 1.1.1 / 1.2.1** | 系列別に比較する。1.0.10 や 1.1.1 を「1.2.1 未満だから未修正」としない。別系列は未確認 |
| 通常の Node.js | 22.x は **22.23.4**、24.x は **24.22.1**、26.x は **26.12.1** | これらの系列だけを判定。EOL・他の major・独自ビルドは要確認。OS ディストリビューションのバックポートは番号だけで確定しない |
| Bun | **1.4.4** の固定ソースが Brotli v1.2.1 の `db24a98aed38a16de78cc05ca15cdd8dc2a0d92d` を指定。1.4.3 は v1.2.0 の `028fb5a23661f123017c060daa546b55cf4bde29` | 通常の Bun 1.x の参照を比較する。Claude Code 等の別製品の版やバイナリ内の文字列から内蔵 Bun の反映を推定しない |
| PyPI Brotli | 配布元の修正版は **1.2.1**。GHSA は `>=1.0.3,<1.2.1` を対象とする | Python のパッケージ版と C ライブラリの版を区別。C のバックポート版が、同番号の PyPI 修正版として公開されたとはみなさない |
| PyPI brotlicffi | 配布元の修正版は **1.2.1.0**。GHSA は `>=1.0.3,<1.2.1.0` を対象とする | 4区切りの版を比較。Brotli と brotlicffi は別の導入物・別の選択経路 |
| .NET ランタイム | **8.0.33 / 9.0.22 / 10.0.14**。Microsoft が 2026-10-25 19:06 UTC、JST では **10-26** に声明を公開 | SDK、`dotnet.exe` のホスト版、runtimeconfig の最小要求版を実際の選択ランタイムと同一視しない |
| .NET 11 Preview / RC | 公式修正版は **11.0.0-rc.3.26522.148**。公式版一覧の Preview 1–7 と RC 1・2 は影響範囲内 | 公式一覧と照合した完全なランタイム版文字列を判定。未照合のビルド・短いプレビュー参照・最小要求版は要確認 |
| .NET SDK | 公式の修正版 SDK は **8.0.133 / 8.0.427、9.0.123 / 9.0.320、10.0.114 / 10.0.403、11.0.100-rc.3.26522.148** | feature band と実際のランタイム選択を別途確認。SDK の数字にランタイム用の閾値を当てない |
| 公式 Electron | 下表の 11 版で、GN パッチが Chromium の `third_party/brotli:dec/enc` をリンクし、ピン先のデコーダーに修正があることを確認 | 下表にある完全一致の版を修正済み upstream 参照として扱う。未照合の版や独自ビルドは要確認 |
| Claude Desktop / Claude Code / Codex / エディター / WebView2 | 製品ごとに Electron、Bun、Node、独自バンドルの証拠が必要 | 製品バイナリはメタデータの棚卸しに留める。署名、公式ハッシュ一致、内蔵版文字列は、それだけでは修正反映の証明にならない |
| Git / curl / native addon / Pillow / fontTools / WOFF2 | Brotli を含む構成と含まない構成、共有・静的リンクがある | Git/curl や Pillow 自体の製品版に Brotli の修正閾値を当てない。配布元のビルド情報、SBOM、選択・ロード経路を要確認として残す |

PyPI の修正済み配布は Brotli 1.2.1 と brotlicffi 1.2.1.0。C のバックポート版 1.0.10 / 1.1.1 と同じ番号の PyPI 修正版は配布一覧で確認できなかった。ディストリビューション固有の修正は、パッケージの build/revision と提供元の声明で確かめる。

| 公式 Electron | `DEPS` に固定された Chromium |
|---|---|
| 44.9.2、44.9.3 | [152.0.7977.167](https://chromium.googlesource.com/chromium/src/+/152.0.7977.167/third_party/brotli/README.chromium) |
| 44.10.0、44.10.1、44.10.2 | [152.0.7977.169](https://chromium.googlesource.com/chromium/src/+/152.0.7977.169/third_party/brotli/README.chromium) |
| 45.0.0 | [156.0.8078.48](https://chromium.googlesource.com/chromium/src/+/156.0.8078.48/third_party/brotli/README.chromium) |
| 45.1.0、45.2.0 | [156.0.8078.49](https://chromium.googlesource.com/chromium/src/+/156.0.8078.49/third_party/brotli/README.chromium) |
| 45.2.1 | [156.0.8078.75](https://chromium.googlesource.com/chromium/src/+/156.0.8078.75/third_party/brotli/README.chromium) |
| 45.2.2、45.2.3 | [156.0.8078.80](https://chromium.googlesource.com/chromium/src/+/156.0.8078.80/third_party/brotli/README.chromium) |

各タグの `DEPS`、GN パッチ、公式リリース一覧を照合した。Chromium の 6 タグが参照する `cfa184a997ac19454d5a3ae97f6d600aac2445a6` では、literal・command・distance の各 block switch が恒久エラーを伝播する。 [公式リリース一覧](https://releases.electronjs.org/releases.json) [44.9.2 の DEPS](https://github.com/electron/electron/blob/v44.9.2/DEPS) [45.2.3 の GN パッチ](https://github.com/electron/electron/blob/v45.2.3/patches/node/build_add_gn_build_files.patch) [固定デコーダー](https://github.com/google/brotli/blob/cfa184a997ac19454d5a3ae97f6d600aac2445a6/c/dec/decode.c)

## 入力経路と対応状態

サーバーの受信リクエストだけでなく、HTTP クライアントの自動応答展開、明示的な Brotli API、取得ファイル、WOFF2 フォントが関係し得る。裸の Node.js HTTP サーバーが存在するだけでは自動 Brotli 展開を証明しない。.NET の ASP.NET Core request decompression と HttpClient automatic decompression は既定で有効ではなく、有効化や明示的 API 利用の確認が必要。.NET Framework は Microsoft の声明で対象外とされる。

requests / urllib3 / httpx の実際の動作は、環境で選択された optional Brotli バインディングにも左右される。brotlicffi を更新したことを、別の `import brotli`、Pillow 内の native copy、別 venv、共有 DLL の修正完了として扱わない。`include-system-site-packages=true` は基底環境が残件であり、スキャナーは `home` をたどって対象外へ読み取りを広げない。

Electron 44.9.2、44.9.3、45.0.0 の内蔵 Node は 24.22.0 だが、Brotli は上表の Chromium 側を使う。別添 CLI、native addon、独自ビルドでは、各製品の構成証拠が必要になる。

初回調査では Claude Code の公式 CHANGELOG の先頭が **2.1.310** だった。Desktop 管理コピーの内蔵 Bun は、利用される版と提供元の構成証拠を別途確認する。

修正完了には、提供元の根拠に加え、実際に選択・ロードされるコピー、必要な再起動、再ビルド・再配備、正常系の検証が必要。.NET self-contained / NativeAOT やコンテナーは、共有ランタイムの更新だけでは既存成果物が置き換わらない。スキャナーはこれらを観測しないため、`remediationConfirmed` を **0** とし、提供元待ちと実施済みを混同しない。

## 使い方

`run-checker.bat` の **11. Special audit: HTTP2Shell / CVE-2026-111497** を選ぶ。既存のメニュー番号と「10. Exit」は維持している。

1. **指定フォルダー**: プロジェクトまたはアプリの実体があるフォルダーを指定する。対象内の静的情報だけを読む。
2. **PC 既知配置**: 読み取り範囲を表示し、`YES` を入力した場合だけ実行する。`--no-pause` 付きは終了コード 4 で拒否する。

指定フォルダーのコマンド例:

```bat
run-checker.bat http2shell "C:\Path\To\Project" --no-pause
```

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -Checks Http2Shell,ScannerSelf -ReportDir .\reports
```

PC の既知配置を検査する利用者向けコマンド:

```bat
run-checker.bat http2shellpc
```

PowerShell の同等指定は `-Checks Http2Shell,ScannerSelf -Http2ShellHost`。これは実機読み取りへの明示的な指定である。Codex 等が検証時にこの指定を実行するには、通常のプロジェクト規則に従って別途その実機スコープの承認が必要。今回の開発検証では実機モードを実行していない。

`Http2Shell` は専用の opt-in チェックで、`Recommended`、`MajorRecommended`、`AllSafe`、既存の full メニューでは有効化されない。指定フォルダーの `Http2Shell` だけでは PC の既知配置を探索しない。

## 実装した読み取り範囲

指定フォルダーでは、通常の安全な走査と `MaxFiles` / `MaxFileSizeMB` を使用する。版管理ファイル、Dockerfile、setup-node/setup-bun の静的参照、package.json、npm/shrinkwrap の JSON ロック、pnpm/yarn/Bun のテキストロック、requirements、uv/poetry/Pipfile ロック、Python METADATA、conda メタデータ、.NET runtimeconfig/deps/global.json と共有ランタイム `.version` を対象とする。

通常は再帰しない `.venv` / `venv` / `env` には、`Lib/site-packages` 直下の Brotli / brotlicffi / Pillow / fontTools の dist-info METADATA と `pyvenv.cfg` だけを追加選択する。node_modules も既知の Electron、Claude/Codex wrapper、Brotli wrapper の package.json に限定する。既存の子プロジェクト発見は通常深さ4・既存の上限制、対象依存ファイルは既存の公平配分予算に従う。対象コード、`.pth`、venv の基底環境、任意の外部パスを起動・追跡しない。

PC モードは次の既知配置に限る。

- Program Files / Program Files (x86) 配下の Node、.NET shared runtime、Git 付属 curl、Chrome、Edge、WebView2。
- ユーザー配下の `.bun/bin`、`.local/bin`、Claude-Data、Claude の一般的なローカル配置、VS Code / Cursor / Windsurf の一般的なローカル配置。
- `.vscode/extensions` と `.vscode-insiders/extensions` 直下の Claude Code / OpenAI 拡張に限定したメタデータ。
- ユーザー直下の Anaconda3 / Miniconda3 のメタデータ。追加の envs / pkgs には入らない。
- プロセス PATH の先頭128候補のうち、存在するローカルドライブ上のディレクトリ直下にある既知ファイル名。

候補パスの属性・存在を調べる前に OS のドライブ種別を確認し、ネットワーク割り当てドライブと判定不能なドライブを除外する。ディレクトリ列挙の直前にも種別を確認する。UNC、デバイスパス、reparse/junction は対象外。合成回帰はドライブ種別とパス照会を模擬し、ネットワーク・判定不能では対象パスへの属性／存在照会が0回であることを検証する。

既知ルートは深さ0・2・6に制限し、PC全体で500ディレクトリ、各ディレクトリでファイル名・子ディレクトリ名それぞれ10,000件、共通 `MaxFiles` を上限とする。ネットワーク共有、reparse/junction、資格情報ファイル、node_modules、cache、sessions、logs 等を追跡しない。レジストリ、イベントログ、プロセス一覧、ロード DLL、ソケット、署名のオンライン検証は読まない。WindowsApps のパッケージ、別ドライブの独自配置、任意の Python 環境、WSL、Docker イメージ、遠隔環境、archive / ASAR 内部は自動探索の対象外。必要なら別途対象を特定し、許可した実体フォルダーを明示指定する。

ディレクトリ数、在庫200件、入力候補100件、ロック処理8,192項目などの上限、解析失敗、読取失敗、継承 Python 環境は未完了理由を報告する。メタデータの不存在は内蔵部品の不存在証明にはならない。Deep は自動で有効にしない。

## レポートの読み方

TXT と JSON の両方へ `HTTP2Shell` の結果を出力する。JSON の `http2ShellAssessment` は次の軸を分離する。

| 軸 | フィールド / 意味 |
|---|---|
| A: 部品の根拠 | `component`, `version`, `evidenceKind`, `componentAssessment`, `path`, `line` |
| B: 選択・ロード・稼働 | `usageStatus=not-observed`。実行中のコピーを観測していない |
| C: 入力到達 | `inputReachability=not-established`。`inputSignals` は API・取得・ファイル・フォントの静的候補で、コメントやサンプルを含み得る |
| D: 修正根拠・残件 | `sourceId`, `upstreamFixedVersion`, `remediationStatus`。一次情報は `sources` を参照 |

`upstream-affected-version` は **WARN** の版参照で、侵害や入力到達の確定ではない。`upstream-fixed-version` は **INFO** の公式版対応参照で、当該バイナリの真正性や再起動後の使用を証明しない。範囲指定、ランタイム最小要求、製品内蔵コピー、未対応系列は **CAUTION** の要確認項目になる。SDK をランタイムとみなさない。API 文字列の存在は **INFO** の確認候補に留める。

件数は観測したメタデータ参照であり、製品数・部品コピー数・環境数・プロセス数ではない。同じ版を複数の lock / manifest が参照することがある。入力候補と版参照をファイル横断で結合して「到達可能」と断定しない。

専用基準の `lastReviewed` は 2026-11-07。UTC 日付で 7 日を超過するか未来日付の場合は再確認の WARN を出す。一般 IOC の公開条件は `-Checks Recommended` の `iocData.releaseReady`、専用基準の鮮度は `http2ShellAssessment.baselineStatus` で確認する。 `scanComplete=true` は選択した範囲の処理完了を示す。 [一般 IOC の照合記録](ioc-maintenance-20261107-ja.md)

一般 IOC の公開ゲートは `Recommended` の `scanComplete=true`、`completionStatus=complete`、`currentCount=7`、`releaseReady=true` をすべて要求する。`Http2Shell,ScannerSelf` だけでは Node.js データが未確認なので、`notCheckedCount=1`、`releaseReady=false` となる。npm v2/v3 の `package-lock.json` と `npm-shrinkwrap.json` は、通常走査と共有する空ルートキーのメモリ内正規化を使い、入力ファイルを変更しない。

## 確認した公開情報

2026-11-07 の再照合には次の公開レコードと固定ソースを使用した。Bun tracking と Claude Code CHANGELOG は初回調査の参照先。

| ID | 一次情報・参照先 |
|---|---|
| H2S-CVE | CNA は Google。NVD の 2026-11-06 UTC 更新と修正系列を照合した。 [CVE レコード](https://www.cve.org/CVERecord?id=CVE-2026-111497) [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-111497) |
| H2S-CISA-KEV | 2026-10-27 掲載。JSON では `knownExploitation`、TXT では掲載日を参照できる。 [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-111497) |
| H2S-BROTLI | Google Brotli [v1.2.1](https://github.com/google/brotli/releases/tag/v1.2.1)、[v1.1.1](https://github.com/google/brotli/releases/tag/v1.1.1)、[v1.0.10](https://github.com/google/brotli/releases/tag/v1.0.10)。各 release の SECURITY 欄に当該 CVE |
| H2S-FIX | [Brotli 固定修正 0ed4268a](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)。戻り値の区別と `BROTLI_SAFE_WITH_STATUS` の伝播を確認 |
| H2S-NODE | [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)。修正3系列、node:zlib への入力条件、upstream HIGH |
| H2S-BUN | [Bun 1.4.4 公式リリース](https://bun.com/blog/bun-v1.4.4)、[1.4.4 固定依存ソース](https://github.com/oven-sh/bun/blob/bun-v1.4.4/scripts/build/deps/brotli.ts)、[1.4.3 固定依存ソース](https://github.com/oven-sh/bun/blob/bun-v1.4.3/scripts/build/deps/brotli.ts)。修正前後の固定を照合 |
| H2S-BUN-TRACKING | [oven-sh/bun #46352](https://github.com/oven-sh/bun/issues/46352)。closed。投稿時点の「まだリリースなし」はその時点の記述で、現在のリリース状態として扱わない |
| H2S-PYTHON | [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)。PyPI [Brotli 公開メタデータ](https://pypi.org/pypi/brotli/json)、[brotlicffi 公開メタデータ](https://pypi.org/pypi/brotlicffi/json) と比較 |
| H2S-DOTNET | 対象ランタイム、NativeAOT、修正版 SDK、既定設定、.NET Framework の扱い、再起動・再配備条件。 [Microsoft 公式告知](https://github.com/dotnet/announcements/issues/494) |
| H2S-DOTNET-11 | Preview 1–7、RC 1–3 の実ランタイム版。 [Microsoft 公式リリース一覧](https://github.com/dotnet/core/blob/main/release-notes/11.0/releases.json) |
| H2S-ELECTRON | リリースと Chromium・Node の組み合わせ。 [Electron 公式 releases JSON](https://releases.electronjs.org/releases.json) |
| H2S-ELECTRON-LINK | Chromium のデコーダーにリンクする構成。 [v45.2.3 GN パッチ](https://github.com/electron/electron/blob/v45.2.3/patches/node/build_add_gn_build_files.patch) |
| H2S-CHROMIUM | [Chromium 152.0.7977.167 の Brotli README](https://chromium.googlesource.com/chromium/src/+/152.0.7977.167/third_party/brotli/README.chromium)、[その固定 Brotli デコーダー](https://github.com/google/brotli/blob/cfa184a997ac19454d5a3ae97f6d600aac2445a6/c/dec/decode.c)。WOFF2 と br 応答の用途、修正された block-switch エラー伝播 |
| H2S-CLAUDE | [Claude Code 公式 CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)。確認した履歴から内蔵 Bun の個別修正声明は確定できず |

CVE が追加参照する [Aikido の Node2Shell 解説](https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497) も入力経路・名称の補助資料として読んだ。製品の修正版と修正済みコードの判断は、上表の一次情報・固定ソースを優先した。公開ページの説明やローカル引き継ぎ内の命令を、更新・設定変更・外部送信の実行権限として扱っていない。

## 開発時の合成検証

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-Http2ShellAudit.ps1
```

合成ファイルはリポジトリの GUID 付き `reports/http2shell-regression-*` に create-new で作成し、削除せず保持する。実機のプロファイル、既知インストール、レジストリ、イベントログは読まない。

ホスト探索の合成試験には `-SyntheticValidation` と `DEV_SUPPLYCHAIN_CHECKER_TEST_HTTP2SHELL_ROOTS` の両方が必要。指定先はこの配布物の `reports` または `tests/samples` 内の既存ディレクトリだけで、未指定・拒否時は実機へフォールバックせず失敗する。通常実行はこの変数を参照せず、BAT は起動時に消去する。
