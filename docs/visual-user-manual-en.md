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
4. Menu item `2` can optionally use confirmed Deep traversal; use it only for dependency/build/cache internals.
5. Use major/full PC modes only after reading the confirmation prompt.
6. Open the TXT report under `reports`.
7. Review `DANGER` first, then `WARN`, then `INFO`.

## Safety Summary

- No external dependencies.
- No network lookup.
- No target code execution.
- No remediation or deletion.
- No secret values in reports.
- UserProfile and EndpointTelemetry modes are opt-in.
- Deep does not add UserProfile, EndpointTelemetry, or npm global/cache and still protects VCS, reparse points, auth contents, and scanner reports.
- `IdeExtensions` includes bounded JetBrains plugin inspection; user-profile roots remain opt-in.
- `Recommended` statically checks explicit project Node.js versions; broader host scopes add bounded known-path `node.exe` metadata without executing Node.js.

## Result Summary

| Result | Meaning |
|---|---|
| `DANGER` | High-priority candidate. Preserve evidence and review. |
| `WARN` | Review candidate or capability note. |
| `INFO` | Context, inventory, or scanner limitation. |
| `OK` | Scan completed or no candidate for that check. |

Node.js upstream `Critical`/`High` version matches are scanner `WARN` (or `INFO` for manifest constraints), not `DANGER` from version evidence alone.

Generated `reports*/` folders are not source files and should not be committed or distributed as source.
