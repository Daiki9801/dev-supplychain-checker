# セキュリティポリシー

## 対象

このプロジェクトは、依存関係なし、オフライン、読み取り専用の Windows 向け supply-chain IOC チェッカーです。

報告対象になる問題の例:

- 意図しない外部通信
- 対象プロジェクトコードの実行
- 秘密情報や auth file 内容の表示
- junction / reparse point などによる安全でない巡回
- レポート redaction の回避
- synthetic high-risk sample を誤って `OK` にする問題

## 脆弱性報告

GitHub で公開後は、利用可能であれば GitHub Security Advisories を使って非公開で報告してください。

Security Advisories が使えない場合、公開 issue には synthetic sample と再現手順だけを書いてください。実 token、秘密鍵、auth file、個人情報、実ホストの詳細証跡は貼らないでください。

## サポート範囲

明示的な release branch がない限り、現在の `main` branch のみを保守対象とします。

## 非対応

このツールは削除、修復、隔離、アンインストール、トークンローテーション、レジストリ変更を行いません。一次トリアージ用であり、端末が安全であることの証明ではありません。

