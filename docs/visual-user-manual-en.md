# Illustrated Manual

The current illustrated PNG manuals are Japanese-first user guides. For English distribution, use this page together with [Beginner User Manual](user-manual-en.md) and [Safety Model](safety-model-en.md).

Japanese visual manuals:

- `assets/dev-supplychain-checker-manual-ja-20260629.png`
- `assets/dev-supplychain-checker-a4-user-manual-imagegen-ja-page1-20260629.png`
- `assets/dev-supplychain-checker-a4-user-manual-imagegen-ja-page2-20260629.png`

## Quick Flow

1. Start `run-checker.bat` from the extracted checker folder.
2. Choose `Recommended project scan` first.
3. Use selected checks only when you know which risk area to review.
4. Use major/full PC modes only after reading the confirmation prompt.
5. Open the TXT report under `reports`.
6. Review `DANGER` first, then `WARN`, then `INFO`.

## Safety Summary

- No external dependencies.
- No network lookup.
- No target code execution.
- No remediation or deletion.
- No secret values in reports.
- UserProfile and EndpointTelemetry modes are opt-in.

## Result Summary

| Result | Meaning |
|---|---|
| `DANGER` | High-priority candidate. Preserve evidence and review. |
| `WARN` | Review candidate or capability note. |
| `INFO` | Context, inventory, or scanner limitation. |
| `OK` | Scan completed or no candidate for that check. |

Generated `reports*/` folders are not source files and should not be committed or distributed as source.

