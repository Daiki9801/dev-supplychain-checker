# コントリビューション

改善提案や修正は歓迎します。ただし、このツールの安全契約を壊さないことが最優先です。

## 安全ルール

変更後も次を維持してください。

- 依存関係なし
- オフラインのみ
- 読み取り専用
- Windows PowerShell 5.1 互換
- 対象プロジェクトコードを実行しない
- レポートに秘密値や auth file 内容を出さない

package manager 依存、runtime installer、外部 download を追加しないでください。

通常の検証に `npm`、`pip`、`node`、`python`、network download command、実ホスト telemetry を要求する workflow、script、手順は追加しないでください。

## 検証

通常は synthetic samples だけで検証します。保守者が明示しない限り、実 `-UserProfile`、実 `-EndpointTelemetry`、full real-host scan は使わないでください。

推奨コマンド:

```powershell
$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\Scan-DevSupplyChain.ps1),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors
```

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -ReportDir .\reports -Quiet
```

synthetic sample scan は、DANGER fixture を検出するため非ゼロ終了になることがあります。parser error、レポート未生成、JSON 不正、finding contract 欠落は失敗として扱ってください。

## Pull Request

PR には次を書いてください。

- 変更した検出またはレポート挙動
- 追加・更新した synthetic sample
- 実行した検証コマンドと結果
- 予想される false positive / false negative

IOC 更新では、確認済みの package/version または extension/version だけを高信頼 indicator として追加してください。不完全なニュース由来の大量リストをそのまま DANGER IOC にしないでください。

