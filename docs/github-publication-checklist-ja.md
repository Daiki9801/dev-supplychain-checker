# GitHub 公開前チェックリスト

この手順は、無料アカウントの範囲でできるだけ安全に公開リポジトリを運用するためのものです。

## 公開前

- `Scan-DevSupplyChain.ps1`, `run-checker.bat`, `README.md`, `docs/`, `iocs/`, `tests/samples/manifest.json` が同じ配布物に入っていることを確認する。
- `reports*/`, `.git/`, `other/` は配布物に入れない。
- `CODEOWNERS` が公開先の GitHub アカウントまたはチームを指していることを確認する。このリポジトリでは `@Daiki9801` に設定済み。
- fork して別アカウントで公開する場合は、Code Owner review を有効化する前に `CODEOWNERS` を置き換える。
- ライセンスが MIT でよいか確認する。別ライセンスにする場合は公開前に `LICENSE` を差し替える。

## GitHub リポジトリ設定

Settings で以下を有効にする。

- Visibility: Public
- Actions permissions: GitHub-owned actions only, or the most restrictive setting your account supports
- Workflow permissions: Read repository contents permission
- Dependabot alerts: On
- Dependabot security updates: On
- Secret scanning: On if available
- Push protection: On if available
- 厳格運用では、`.github/workflows/validate.yml` の `actions/checkout@v4` を GitHub 公式リポジトリで確認した commit SHA に固定する。

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
