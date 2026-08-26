# GitHub 公開前チェックリスト

この手順は、無料アカウントの範囲でできるだけ安全に公開リポジトリを運用するためのものです。

## 公開前

- `Scan-DevSupplyChain.ps1`, `run-checker.bat`, `README.md`, `docs/`, `iocs/`, `tests/samples/manifest.json` が同じ配布物に入っていることを確認する。
- 一般ユーザー向けの release/source archive には、`tests/samples/**` の synthetic fixture 本体を入れない。残すのは `tests/samples/manifest.json` と `tests/samples/README.md` だけにする。
- 既定の `reports/`、独自名・過去のレポートフォルダ、`.git/`, `other/`, 一時 token, `.env*` は配布物に入れない。
- `.gitattributes` が、既定の `reports/`、ローカル参照ファイル、一時秘密情報、synthetic fixture 本体を generated source archive から除外していることを確認する。独自レポートフォルダはGit未追跡のままにする。
- `CODEOWNERS` が公開先の GitHub アカウントまたはチームを指していることを確認する。このリポジトリでは `@Daiki9801` に設定済み。
- fork して別アカウントで公開する場合は、Code Owner review を有効化する前に `CODEOWNERS` を置き換える。
- ライセンスが MIT でよいか確認する。別ライセンスにする場合は公開前に `LICENSE` を差し替える。
- READMEとマニュアルに、境界内完了の意味、正規表現処理ごとのタイムアウト、`REGEX_SCAN_TIMEOUT`、検出や未検出だけでは感染も安全も確定しないことが目立つ形で記載されていることを確認する。

## ローカルのPush前監査

`.gitignore` は新しい誤追加を防ぐだけで、過去にコミット済みの秘密情報を消しません。Push前は、送信対象だけでなく到達可能な全履歴を確認します。

- `git remote -v` で送信先が意図したリポジトリだけであることを確認する。
- `git status --short --branch` で未追跡・未ステージ・無関係な変更がないことを確認し、`git status --short --ignored` で意図せず無視された秘密情報候補がないこともファイル名だけ確認する。
- `git log --all --format=fuller` で作者・コミッターのメールとコミットメッセージに個人情報がないことを確認する。
- `git rev-list --objects --all` で、全到達可能コミットのファイル名に `.env`、秘密鍵、token、auth、credential、実ユーザー名やローカルパスがないことを確認する。
- 全到達可能blobの内容を、秘密鍵ヘッダー、GitHub・クラウド・npm形式のtoken、JWT、資格情報付きURL、秘密値代入、実ユーザー固有のホームパスについて検索する。候補値そのものはコンソールやログへ出さず、ファイル名だけを出して個別確認する。
- `git diff --name-status origin/main..HEAD` と `git log --oneline origin/main..HEAD` で実際のPush候補を確認する。
- `git diff --check origin/main..HEAD` で空白エラーを確認し、5 MiBを超える履歴blobや不要なarchive、database、鍵コンテナがないことを確認する。
- 既定の `reports/`、すべての独自名・過去のレポートフォルダ、`other/`、一時検証物がGit追跡対象でないことを確認する。実レポートはredaction済みでも公開しない。
- synthetic fixture内のtoken・auth・攻撃文字列は、利用不能な作り物であること、`tests/samples/README.md` とmanifestで意図が説明されていることを確認する。

秘密情報の疑いがある履歴を見つけた場合はPushを中止します。単に最新コミットから削除しても履歴には残るため、値を失効させたうえで、公開前に履歴修正の必要性を個別判断します。

## GitHub リポジトリ設定

Settings で以下を有効にする。

- Visibility: Public
- Actions permissions: GitHub-owned actions only, or the most restrictive setting your account supports
- Workflow permissions: Read repository contents permission
- Dependabot alerts: On
- Dependabot security updates: On
- Secret scanning: On if available
- Push protection: On if available
- `.github/workflows/validate.yml` の `actions/checkout` は完全なcommit SHAへ固定したままにする。更新時はGitHub公式リポジトリでSHAとリリースを確認する。

RepositoryのAbout欄には、短い説明、MIT license、対象トピック（例: `windows`, `powershell`, `security`, `ioc`, `supply-chain`）を設定する。公開WebサイトやSNSは、このツールの公式配布先として管理できる場合だけ登録する。

## Branch Protection または Ruleset

`main` に対して以下を設定する。

- Require a pull request before merging
- Require approvals
- Require review from Code Owners after `CODEOWNERS` を有効化
- Require status checks to pass before merging
- Required check: `Scanner contract`
- Block force pushes
- Block deletions
- Require conversation resolution

GitHub の画面で required check を選ぶ時は、初回 workflow 実行後に表示される `Scanner contract` を選ぶ。

## 運用ルール

- IOC 追加は、確認済みの package/version または extension/version だけを高信頼として扱う。
- 大量侵害ニュースの不完全な一覧は、そのまま DANGER IOC として入れない。
- 実ホストの `-UserProfile`, `-EndpointTelemetry`, full scan は CI で実行しない。
- issue や PR に token、秘密鍵、auth file、個人情報を貼らない。
- Push後に `Scanner contract` が成功し、Securityタブのsecret scanning結果が0件であることを確認する。ローカル監査とGitHub側監査のどちらか一方だけで済ませない。
