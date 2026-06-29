# Beginner User Manual

This manual explains how to use `Dev Supply Chain IOC Checker` on Windows.

The checker performs static, read-only triage for suspicious supply-chain indicators in developer folders, package metadata, CI/CD files, AI/MCP agent configs, IDE extension metadata, and selected opt-in host locations. It does not delete files, fix issues, run target code, download data, or contact the network.

## 1. What To Know First

- This tool does not prove that a PC or repository is infected.
- Results are review candidates.
- Do not delete files just because a `DANGER` finding appears.
- `tests/samples` contains synthetic test fixtures. Findings there are expected when scanned directly.
- User profile and endpoint telemetry modes run only when explicitly selected.

## 2. Easiest Way To Run

1. Open the extracted checker folder in Explorer.
2. Double-click `run-checker.bat`.
3. Choose `1. Recommended project scan` for the current folder, or choose `2` to enter another folder.
4. Wait for the scan to finish.
5. Open the TXT report under `reports`.

Run the launcher from the extracted checker folder. If only `Scan-DevSupplyChain.ps1` was copied elsewhere, the scan still works, but reports may show `distributionStatus=script-only` or `incomplete`.

## 3. Launcher Menu

```text
1. Recommended project scan
2. Scan selected path
3. Package / lockfile risks only
4. AI / MCP / IDE config risks only
5. CI/CD and hooks risks only
6. npm global/cache static check
7. Major PC locations scan
8. Custom checks for current folder
9. Full scan current folder + user profile + endpoint telemetry
10. Exit
```

Use `1` first for normal project triage. Modes `6`, `7`, and `9` read broader real-PC locations and require typing `YES` before running.

## 4. Risk Checks

`-Checks` can select risk categories.

| Check | Main target |
|---|---|
| `Recommended` | Default project-local static checks. Excludes npm global/cache. |
| `MajorRecommended` | Recommended plus static npm global roots. |
| `AllSafe` | All non-telemetry static checks, including npm global/cache. |
| `Packages` | package metadata, lockfiles, exact local package IOCs, watchlist context. |
| `LifecycleScripts` | install/import-time scripts and startup hooks such as `.pth` or `setup.py`. |
| `InvisibleUnicode` | invisible Unicode and GlassWorm-style compound patterns. |
| `CiCd` | GitHub Actions and CI/CD posture. |
| `AiMcp` | Codex, Claude, Cursor, Windsurf, MCP, and AI-agent configs/tooling. |
| `IdeExtensions` | VS Code-compatible extension metadata and executable indicators. |
| `NpmGlobal` | Static candidate npm global package roots. Does not run `npm root -g`. |
| `NpmCache` | Static npm cache metadata. Does not run `npm cache ls`; skips content blobs. |

`UserProfile` and `EndpointTelemetry` are explicit modes, not `-Checks` names.

## 5. Reading Results

| Severity | Meaning |
|---|---|
| `DANGER` | High-priority candidate such as an exact known IOC or strong execution/exfiltration context. |
| `WARN` | Review candidate, posture issue, or capability note. Not proof of infection. |
| `INFO` | Inventory, limitation, aggregate, or context. |
| `OK` | Scan completed or no problem candidate for that check. |

Important fields:

- `SourceContext`: context such as `normal`, `active-ai-config`, `executable-tooling`, `reference-text`, `cache-data`, `synthetic-sample`, or `scanner-self`.
- `RiskType`: `known-ioc`, `active-exfil`, and active-config `fetch-execute` are higher priority than `capability`, `posture`, `inventory`, or `limitation`.
- `PriorityFindings`: high-priority review candidates.
- `CapabilitySummary`: grouped AI skill/plugin capabilities. These are not infection proof.

## 6. Synthetic Samples And Reports

`tests/samples` contains hand-written synthetic fixtures. They were not downloaded malware.

Parent scans skip only manifest-verified known fixtures from the currently running checker distribution. Unknown, modified, or unrelated `tests/samples` files are scanned normally.

As of v0.1.11, the running checker folder's own `reports*` directories are skipped during normal scans. This prevents old JSON/TXT reports and validation artifacts from being re-detected as current risks. If you explicitly scan a report folder with `-Path`, it is scanned.

`reports*/` is also ignored by Git so generated reports are not committed or pushed.

## 7. What Not To Do After DANGER

Do not immediately:

- delete files;
- open suspicious URLs;
- run npm, pip, python, node, hooks, or workflow commands;
- paste tokens or auth files into issues or chats;
- uninstall tools before preserving evidence.

Keep the TXT and JSON reports, review the `Path`, `Category`, `RiskType`, and `Evidence`, and involve an administrator or security specialist when appropriate.

