# Beginner User Manual

This manual explains how to use `Dev Supply Chain IOC Checker` on Windows.

The checker performs static, read-only triage for suspicious supply-chain indicators in developer folders, package metadata, CI/CD files, AI/MCP agent configs, IDE extension metadata, and selected opt-in host locations. It does not delete files, fix issues, run target code, download data, or contact the network.

## 1. What To Know First

- This tool does not prove that a PC or repository is infected.
- It also does not prove that a PC or repository is clean, even when no finding appears and the scan is `complete`.
- Results are review candidates.
- Do not delete files just because a `DANGER` finding appears.
- `tests/samples` contains synthetic test fixtures in the source repository. Findings there are expected when scanned directly. End-user archives should keep only the sample manifest/readme, not the full fixture bodies.
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
3. Package / Node runtime risks
4. AI / MCP / IDE config risks only
5. CI/CD and hooks risks only
6. npm global/cache static check
7. Major PC locations scan
8. Custom checks for current folder
9. Comprehensive bounded scan (target + major locations + profile + endpoint)
10. Exit
```

Use `1` first for normal project triage. Modes `6`, `7`, and `9` read broader real-PC locations and require typing `YES` before running.

Custom menu item `8` accepts project-local checks only. It does not accept `NpmGlobal`, `NpmCache`, `MajorRecommended`, or `AllSafe`; use confirmed modes `6`, `7`, or `9` for broader host scope. Risk-specific menus `3`, `4`, and `5` retain the cross-cutting `InvisibleUnicode`/GlassWorm check for their selected files.

Mode `9` combines the explicit target, MajorLocations discovery, user-profile AI/IDE configuration, static npm global/cache, known-path/PATH Node.js metadata, and endpoint telemetry. It is not a full-disk scan and does not enable Deep dependency/build/cache recursion. Run Deep separately against a trusted project when that recursive content is required.

MajorLocations includes bounded common GitHub/Documents/Desktop project subfolders, common JetBrains/Android Studio/Eclipse/NetBeans default project roots, and project subfolders under `OneDrive`, `OneDriveCommercial`, or `OneDriveConsumer` when those environment variables resolve to a child directory under `USERPROFILE`. It also inspects static npm global metadata and bounded Program Files, local process-PATH, and version-manager Node.js file metadata. For Codex it selects active config, agents, rules, skills, installed plugin tooling, and extension roots, while excluding `.codex\sessions`, runtime cache, and history data. It does not recursively scan the whole Desktop, Documents, profile, or drive. `scanRoots` records the selected roots that actually existed instead of using `~` to imply whole-profile coverage.

After menu item `2` asks for a path, choose `Recommended` for normal use or `Deep` only when dependency, build, and cache internals must also be read. Deep requires typing `YES`, rejects `--no-pause`, and does not automatically add npm global/cache, UserProfile, or EndpointTelemetry.

A parent-folder scan discovers child npm, Python, and Composer projects within bounded depth (4 normally, 8 in Deep). Targeted dependency files use at most `min(10,000, floor(MaxFiles * 0.5))`, are divided fairly across discovered projects, and have a 2,000-file per-project ceiling. This leaves at least half of `MaxFiles` for ordinary source, CI/CD, and AI configuration files and prevents a few large dependency trees from dominating a parent scan. Scan one project directly, or use Deep on one trusted project, when broader dependency content is required.

Long scans use compact progress by default. About every 30 seconds, `progress` shows the redacted project root, run-wide deduplicated target count (`queued`), text-content scan count (`scanned`), and elapsed time. It does not normally print each current file, every stage for files of at least 1 MiB, or `slow step completed` lines. For diagnostics, pass `-VerboseProgress` directly to `Scan-DevSupplyChain.ps1` to restore five-second detailed progress; `-Quiet` suppresses progress entirely. Finding line numbers are counted in 64 KiB native string chunks instead of per-character PowerShell loops. Reaching `MaxFiles` or the reserved dependency budget stops the applicable remaining traversal and records incomplete coverage in the report.

Each full-text regular-expression operation has an explicit two-second .NET timeout; this is not a total scan time limit. Pathological input produces a `regex timeout` console line and a `REGEX_SCAN_TIMEOUT` limitation. Only that operation for that file is skipped; other checks and files continue. Because the operation was not completed, the run cannot be `complete`: it is `partial-non-critical` for a non-critical candidate or `incomplete-critical` when the affected file is a critical candidate such as a lockfile or active configuration. File contents are not included in timeout output. Narrow the scan or review the named file manually rather than treating a larger timeout as proof that it is safe.

## 4. Risk Checks

`-Checks` can select risk categories.

| Check | Main target |
|---|---|
| `Recommended` | Default project-local static checks, including declared Node.js versions. Excludes npm global/cache and host Node.js discovery. |
| `MajorRecommended` | Recommended plus static npm global roots and bounded known-path Node.js installations. |
| `AllSafe` | All non-telemetry static checks, including npm global/cache. |
| `Packages` | package metadata, lockfiles, exact local package IOCs, watchlist context. |
| `LifecycleScripts` | install/import-time scripts, package `main`/`exports`/`bin` entrypoints, and startup hooks such as `.pth` or `setup.py`. |
| `NodeRuntime` | Explicit `.nvmrc`, Volta, container, and setup-node versions; known-path `node.exe` metadata only in broader host scopes. Never executes Node.js. |
| `InvisibleUnicode` | invisible Unicode and GlassWorm-style compound patterns. |
| `CiCd` | GitHub Actions and CI/CD posture. |
| `AiMcp` | Codex, Claude, Cursor, Windsurf, MCP, and AI-agent configs/tooling. |
| `IdeExtensions` | VS Code-compatible extensions and bounded JetBrains plugin metadata, scripts, archives, and native-artifact context. |
| `NpmGlobal` | Static candidate npm global package roots. Does not run `npm root -g`. |
| `NpmCache` | Static npm cache metadata. Does not run `npm cache ls`; skips content blobs. |

`UserProfile` and `EndpointTelemetry` are explicit modes, not `-Checks` names.

JetBrains profile roots are discovered only in explicit UserProfile or MajorLocations modes. User-profile discovery also covers common Codex, Claude, Cursor, Windsurf, Continue, Gemini, OpenCode, and user-level MCP configurations while inventorying known credential files without reading their contents. Automatic `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, and OneDrive roots must be absolute non-reparse children of `USERPROFILE`; other values are reported and skipped, and intentional external roots must be scanned explicitly with `-Path`. Other in-scope configuration text is read for static matching, and secret-like report evidence is centrally redacted. Program Files and Toolbox bundled plugins are not scanned automatically; use an explicit local `-Path` when those locations must be reviewed.

Command-line Deep traversal:

```bat
run-checker.bat deep C:\Path\To\Project
```

Deep still skips VCS directories and reparse points, never reads auth-file contents, and never executes plugin, package, or project code.

## 5. Reading Results

| Severity | Meaning |
|---|---|
| `DANGER` | High-priority candidate such as an exact known IOC or strong execution/exfiltration context. |
| `WARN` | Actionable review candidate with a stronger suspicious pattern, known risk, or security weakness. Not proof of infection. |
| `CAUTION` | Lower-signal presence, capability, or posture finding that merits review but has no strong malicious compound by itself. |
| `INFO` | Inventory, limitation, aggregate, or context. |
| `OK` | Scan completed or no problem candidate for that check. |

`WARN` and `CAUTION` both use exit code `1`, preserving existing automation while making their review priority visibly different.

Completion is separate from severity:

| Completion state | Meaning and required action |
|---|---|
| `complete` | All planned checks finished within the selected bounded scope. This is not a clean-host guarantee. |
| `partial-non-critical` | At least one declared non-critical check or bounded analysis was skipped or limited. Read `coverage.summary` and the limitation finding. |
| `incomplete-critical` | Material planned coverage is unknown. Narrow or rerun the scan before relying on a negative result. |
| `error` | Scanner/report execution failed. Do not rely on a negative result. |

For Node.js runtime advisories, upstream `Critical`/`High` is separate from scanner `WARN`/`INFO`. Installed metadata and explicit pins are `WARN`; `engines.node` constraints are `INFO`; version text alone is never `DANGER`. As of v0.1.21, console and TXT output separate `Node.js installed` from `Node.js project refs`, so a vulnerable Dockerfile pin is not presented as a vulnerable global installation. JSON `nodeRuntimeAssessment` separates those sources and retains up to 100 exact evaluated versions with redacted paths. `notAffected` means no match in the shipped offline baseline, not a complete CVE, EOL, signature, or publisher-authenticity verdict. Review the vulnerable-only `NODE RUNTIME SUMMARY` for CVEs and fixed-version guidance.

Important fields:

- `SourceContext`: context such as `normal`, `active-ai-config`, `executable-tooling`, `reference-text`, `cache-data`, `synthetic-sample`, or `scanner-self`.
- `RiskType`: `known-ioc`, `active-exfil`, and active-config `fetch-execute` are higher priority than `capability`, `posture`, `inventory`, or `limitation`.
- `coverage.summary`: critical/non-critical coverage failures, dependency/cache coverage labels, and the next bounded action.
- `completionStatus`: `complete`, `partial-non-critical`, `incomplete-critical`, or `error`. The console displays the equivalent human-readable label.
- `nodeRuntimeAssessment`: separate installed-binary and project-reference counts plus a bounded, redacted exact-version inventory.
- `PriorityFindings`: high-priority review candidates, including explicit project/container Node.js `Critical`/`High` matches.
- `CapabilitySummary`: grouped AI skill/plugin capabilities with path-derived provenance labels. These labels do not verify a publisher.

As of v0.1.15, also check `traversalComplete`, `directoryCoverageComplete`, `candidateCoverageComplete`, and `scanComplete`. As of v0.1.21, treat a no-finding report as a fully completed bounded negative result only when `scanComplete` is `true` and `completionStatus` is `complete`. `partial-non-critical` distinguishes bounded non-critical gaps from `incomplete-critical` and `error`, but none of these labels proves that the host is clean. A file budget, access/read failure, malformed critical lockfile, or unsupported `bun.lockb` is reported with the affected coverage and next action; the checker never elevates itself or changes permissions.

Version 0.1.17 adds `scanScope` and `iocData`. `scanScope.fullDisk` is always `false` and states whether Deep traversal was enabled. `iocData.releaseReady=false` means at least one shipped IOC dataset is stale, missing, or invalid. Historical exact matches remain enabled, but maintainers should refresh the data before publishing a release.

The August 2026 Keyv ChainDrop snapshot compares 443 package names and 2,235 exact package/version pairs. An installed-package or structurally parsed lockfile exact match is `DANGER`; manifest constraints, cache/reference text, and marker-only matches require corroboration. Preserve the evidence and do not automatically delete a file based on the finding.

Version 0.1.16 detects the known GlassWorm `codePointAt` decoder shape and consecutive Variation Selector clusters. Version 0.1.18 requires the range checks and byte mapping to use the same locally bound code-point variable, and a decoder signature without an observed Variation Selector cluster is at most `WARN`. Version 0.1.19 reports an isolated invisible control without a nearby execution compound as `CAUTION`. Version 0.1.20 classifies manual workflows, passive tooling, and reference examples more precisely: active unpinned MCP commands remain `WARN`, passive tooling and reference examples are `CAUTION`, and active fetch-execute remains `DANGER`. Version 0.1.21 separates installed and project Node.js assessment and distinguishes non-critical partial completion. Version 0.1.22 pins the launcher executable, removes content-blind active-file self exemptions, bounds environment-defined automatic roots, and distinguishes selected package entrypoints from unselected dependency/generated code reached only by Deep traversal. Generic compounds in the latter are `WARN`/`CAUTION`, while exact IOCs, campaign chains, first-party code, and selected entrypoints retain higher priority. Dependency-owned workflow files are not treated as active consuming-repository CI, and explicitly non-critical traversal limits no longer display as critical coverage failure. Dependency/generated status is derived below the explicit scan root, so an ancestor directory name cannot downgrade first-party content. Embedded executable here-strings remain in normal analysis because target-controlled function, helper, variable, or pattern-array names do not prove that fixture text is passive. For the generic PowerShell fetch-execute heuristic only, each original-source match is classified as active, ambiguous, or passive regex data. A static `Pattern` literal is passive only when its lexical function scope and all direct consumers are proven regex-only and reachable local helpers cannot capture it through dynamic scope. Active matches retain priority and their original line. Parse errors, reflection, self-source reads, wrappers, property/index transfer, and unknown uses remain fail-safe findings. Known selector mapping is decoded only in memory for static marker checks; decoded text is neither executed nor written to reports. Existing report outputs and identical TXT/JSON paths are rejected before scanning instead of being overwritten.

## 6. Synthetic Samples And Reports

`tests/samples` contains hand-written synthetic fixtures. They were not downloaded malware.

Parent scans skip only manifest-verified known fixtures from the currently running checker distribution. Unknown, modified, or unrelated `tests/samples` files are scanned normally.

End-user archives may contain only `tests/samples/manifest.json` and `tests/samples/README.md`. In that case, the synthetic regression scan is unavailable by design. This does not reduce real scanning capability; maintainers and CI use the full source repository for fixture-based checks.

The configured report directory (default `reports/`) and current TXT/JSON output files are skipped during normal scans. This prevents current output from being re-detected without hiding unrelated source directories such as `reports-service`. If you explicitly scan a report folder with `-Path`, it is scanned.

Only the repository-root `/reports/` directory is ignored by Git. Review custom or legacy report directories explicitly so generated reports are not committed or pushed.

## 7. What This Checker Cannot Do

The checker cannot:

- inspect the whole disk, every dependency/cache/build file, every archive member, or arbitrary binary code;
- inspect memory, live process behavior, network traffic, cloud activity, or remote logs;
- replace a complete dependency/CVE audit, EDR/AV, SIEM review, or incident response;
- verify current registry reputation, package ownership, publisher identity, signatures, or provenance online;
- guarantee that static text is reachable or malicious, or guarantee that an undetected threat is absent; or
- repair, delete, quarantine, uninstall, or rotate credentials.

## 8. What Not To Do After DANGER

Do not immediately:

- delete files;
- open suspicious URLs;
- run npm, pip, python, node, hooks, or workflow commands;
- paste tokens or auth files into issues or chats;
- uninstall tools before preserving evidence.

Keep the TXT and JSON reports, review the `Path`, `Category`, `RiskType`, and `Evidence`, and involve an administrator or security specialist when appropriate.
