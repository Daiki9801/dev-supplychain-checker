# Beginner User Manual

Current scanner version: **0.1.27**. Updated: **2026-10-16**.

Version 0.1.27 prints severity totals beside finding classes. `ConfigReview=153` is not a WARN count; read `Findings by severity`, execution status and coverage completion separately. Menus 3/4/5 inspect the current folder with their selected checks and shared Unicode/IOC checks.

Four reviewed markers in this distribution's tests/workflow become INFO `SCANNER_TEST_MARKER_REFERENCE` only after exact relative-path, normalized source-hash and rule verification. Edited files, external copies and other behavior remain analyzed. Local IOC timeouts keep the two-second bound and continue later rules with incomplete coverage. MCP extraction recognizes escaped keys and is bounded to 8,192 nodes, depth 32, 256 fragments and 65,536 characters. Exhaustion or command-bearing malformed JSON yields WARN coverage information.

File counters count distinct normalized paths within each counter. `fileEnumerationEvents` / `fileSkipEvents` describe repeat visits. Exclusions can happen before queuing, so queued does not equal scanned plus skipped. Verified fixture project markers are excluded from project/budget counts; unknown/changed files remain eligible.

Timestamps and elapsed time share a monotonic origin. `performance.slowActivities` retains at most 20 redacted slow read/file/analysis records. Reading and analysis are nested; add only `partition=true` activities. Real-PC performance has not been remeasured. The IOC baseline remains 2026-10-06. With the parsed report in `$r`:

```powershell
$r.summary
$r.coverage.summary.nextActions | Format-List
$r.performance.slowActivities | Format-Table activity, elapsedMs, path -AutoSize
```

Version 0.1.26 classifies mixed passive PowerShell pattern definitions using original source syntax plus proven passive spans. A parse error caused by blanking a test literal is not treated as an original-source execution finding; active code beside passive definitions remains checked. Plugin-cache workflow copies are INFO references with activation unknown, while active repository CI posture remains checked.

`_cacache/content-v2` blob subtrees are excluded under standard and custom cache roots without decoding or enumerating their contents. `cacheBlobDirectoriesSkipped` counts excluded directories, not inferred file totals. Ordinary files outside that structural subtree remain eligible. Menu scopes, confirmations, severity/exit codes and the 2026-10-06 IOC baseline are unchanged.

Version 0.1.25 separates execution, coverage and finding severity. Ctrl+C/pipeline stops produce `executionStatus=interrupted`, an `INTERRUPTED` label, `completionStatus=incomplete-critical` and `scanComplete=false` when PowerShell can save its final report. Unstarted npm/dependency checks say `not-started`, not `not-found` or within-limits. Closing the window or killing the process cannot guarantee a report.

Ordinary regex classifier patterns receive the same conservative passive-data review as earlier test literals. Compressed/binary containers use bounded probes and aggregate INFO instead of noisy text decoding; no decompression dependency is added. Cached MCP command configs state `activation=unknown`. Mutable npx/uvx selectors in cache are CAUTION capabilities; strong command compounds remain detectable. The IOC baseline remains 2026-10-06.

Version 0.1.24 improves distinctions between passive test strings, planned operations and actual credential-send/configuration-write compounds. Proven regex-only PowerShell test literals retain INFO evidence; unknown consumers, dynamic execution and malformed syntax remain in normal analysis. INFO does not certify the rest of a file. AI key inventories and pagination properties alone do not establish exfiltration.

For incomplete coverage, inspect `failureType` in `coverage.candidateFailures` and `coverage.directoryFailures`: `file-in-use` indicates a sharing/locking conflict, `access-denied` insufficient access, `path-too-long` an actual long-path cause, `path-not-found` a missing/disappearing path, and `io-error` another I/O failure. `exceptionTypes` and `hresults` provide bounded metadata without exception messages or file contents; a directory may represent a failing child. Size and regex limits remain recorded. Non-critical read failures and dependency/cache sampling limits also set `scanComplete=false` with PARTIAL completion. Review the affected scope and rerun a narrower check when needed.

This manual explains how to use `Dev Supply Chain IOC Checker` on Windows.

The checker performs static, read-only triage for suspicious supply-chain indicators in developer folders, package metadata, CI/CD files, AI/MCP agent configs, IDE extension metadata, and selected opt-in host locations. It does not delete files, fix issues, run target code, download data, or contact the network.

Version 0.1.23 adds the reviewed October IOC supplement and bounded native-build/runtime and Python metadata checks. It correctly matches short Python version spellings and treats OCR data and signature artifacts as binary after hash checks. The shipped IOC baseline was reviewed on 2026-10-06; scans do not fetch current advisories.

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

A PowerShell 7 terminal can launch the BAT file. The BAT uses Windows PowerShell 5.1 (`powershell.exe`), independently of the `pwsh.exe` version. Start ordinary project scans as a normal user and review any recorded coverage gaps before considering broader access.

## 3. Launcher Menu

```text
1. Recommended project scan - current folder
2. Scan selected path - choose folder, then Recommended or Deep
3. Package / Node runtime risks - current folder
4. AI / MCP / IDE config risks only - current folder
5. CI/CD and hooks risks only - current folder
6. npm global/cache static check - PC metadata; confirm
7. Major PC locations scan - PC folders/profile; confirm
8. Custom checks for current folder - advanced
9. Comprehensive bounded scan (target + major locations + profile + endpoint) - confirm
10. Exit
```

Use `1` for the current working folder, or `2` to select another project explicitly. Double-clicking the launcher can make the checker folder itself the working folder. Modes `3`, `4`, `5` and `8` also default to the working folder. Modes `6`, `7`, and `9` read broader real-PC locations and require typing `YES` before running.

Custom menu item `8` accepts project-local checks only. It does not accept `NpmGlobal`, `NpmCache`, `MajorRecommended`, or `AllSafe`; use confirmed modes `6`, `7`, or `9` for broader host scope. Risk-specific menus `3`, `4`, and `5` retain the cross-cutting `InvisibleUnicode`/GlassWorm check for their selected files.

Mode `9` combines the explicit target, MajorLocations discovery, user-profile AI/IDE configuration, static npm global/cache, known-path/PATH Node.js metadata, and endpoint telemetry. It is not a full-disk scan and does not enable Deep dependency/build/cache recursion. Run Deep separately against a trusted project when that recursive content is required.

MajorLocations includes bounded common GitHub/Documents/Desktop project subfolders, common JetBrains/Android Studio/Eclipse/NetBeans default project roots, and project subfolders under `OneDrive`, `OneDriveCommercial`, or `OneDriveConsumer` when those environment variables resolve to a child directory under `USERPROFILE`. It also inspects static npm global metadata and bounded Program Files, local process-PATH, and version-manager Node.js file metadata. For Codex it selects active config, agents, rules, skills, installed plugin tooling, and extension roots, while excluding `.codex\sessions`, runtime cache, and history data. It does not recursively scan the whole Desktop, Documents, profile, or drive. `scanRoots` records the selected roots that actually existed instead of using `~` to imply whole-profile coverage.

After menu item `2` asks for a path, choose `Recommended` for normal use or `Deep` only when dependency, build, and cache internals must also be read. Deep requires typing `YES`, rejects `--no-pause`, and does not automatically add npm global/cache, UserProfile, or EndpointTelemetry.

A parent-folder scan discovers child npm, Python, and Composer projects within bounded depth (4 normally, 8 in Deep). Targeted dependency files use at most `min(10,000, floor(MaxFiles * 0.5))`, are divided fairly across discovered projects, and have a 2,000-file per-project ceiling. This leaves at least half of `MaxFiles` for ordinary source, CI/CD, and AI configuration files and prevents a few large dependency trees from dominating a parent scan. Scan one project directly, or use Deep on one trusted project, when broader dependency content is required.

Long scans use compact progress by default. About every 30 seconds, `progress` shows the redacted project root, run-wide deduplicated target count (`queued`), text-content scan count (`scanned`), and elapsed time. It does not normally print each current file, every stage for files of at least 1 MiB, or `slow step completed` lines. For diagnostics, pass `-VerboseProgress` directly to `Scan-DevSupplyChain.ps1` to restore five-second detailed progress; `-Quiet` suppresses progress entirely. Finding line numbers are counted in 64 KiB native string chunks instead of per-character PowerShell loops. Reaching `MaxFiles` or the reserved dependency budget stops the applicable remaining traversal and records incomplete coverage in the report.

Each full-text regular-expression operation has an explicit two-second .NET timeout; this is not a total scan time limit. Pathological input produces a `regex timeout` console line and a `REGEX_SCAN_TIMEOUT` limitation. Other checks and files continue, but the remaining rules in the containing step can be skipped. Runtime credential-subrule isolation specifically preserves its later execution checks. The named rule/step was not completed, so the run cannot be `complete`: it is `partial-non-critical` for a non-critical candidate or `incomplete-critical` when the affected file is a critical candidate such as a lockfile or active configuration. File contents are not included in timeout output. Review the named file and rule; narrowing a folder alone may not fix the same timeout.

## 4. Risk Checks

Read `executionStatus` before interpreting the findings. `completed` means all planned phases returned; recorded read/analysis gaps may still make coverage partial. `interrupted` means some planned work has no result; `error` means execution failed. Inspect `execution.phases` / `unfinishedPhases`, and `checkStats.<check>.executionStatus` rather than just `enabled`. Phase states distinguish not-started, running, completed, interrupted and failed.

`execution.startedAt`, `finishedAt` and `elapsedMs` describe the run; `queuedFilesUnprocessed` counts only already-queued unique paths and cannot count an unenumerated remainder. `findingClassSummary` separates security evidence, advisory version matches, configuration review, capabilities, coverage limitations and context. A coverage WARN is not malicious behavior and finding counts are not infection counts.

Timeout findings include a stable hashed `ruleId`, the timeout and elapsed milliseconds, without regex/input text. `performance.steps` contains bounded per-step timing aggregates. A narrower folder alone may not fix a timeout on the same file and rule; the two-second bound is unchanged.

`coverage.summary.nextActions` lists all concurrent failure groups and sampling limits with counts, representative paths and actions. The existing `nextAction` is retained as a combined string. `performance.activities` records Enumeration, ProjectDiscovery, TargetSelection, Reading (including decoding) and FileProcessing. Only `partition=true` activities are additive: their total is `partitionElapsedMs`; `otherElapsedMs` is remaining execution time. Reading and individual check steps are nested and must not be added again. Report formatting/writes are excluded. `performance.slowSteps` keeps at most 20 slowest records at or above two seconds, with redacted profile paths and no source/regex text. Classification, syntax and mask reuse plus applicable-file dispatch reduce work; real-PC speedups depend on the workload.

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
| `WARN` | Prioritized suspicious pattern, known risk, weakness or coverage limitation. Read its type; this is not proof of infection. |
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

### Reviewing Many CAUTION Findings

Check completion and IOC freshness first, then prioritize DANGER/WARN. Group CAUTION findings by category and inspect each path, evidence, and recommendation. Replace the example JSON path with the exact report file; these commands do not execute project code.

```powershell
$reportPath = 'C:\Path\To\dev-supplychain-report.json'
if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
  throw 'The JSON report file was not found.'
}
$r = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 -ErrorAction Stop |
  ConvertFrom-Json -ErrorAction Stop
$r | Select-Object scanComplete, completionStatus
$r.iocData | Select-Object releaseReady, staleCount, missingCount, invalidCount
$r.findings | Where-Object severity -eq 'CAUTION' |
  Group-Object category | Sort-Object Count -Descending | Select-Object Count, Name
$r.findings | Where-Object severity -eq 'CAUTION' |
  Select-Object category, title, path, line, evidence, recommendation | Format-List
```

| Kind | Static review |
|---|---|
| Lifecycle scripts | Read the declaration, called file, execution conditions, downloads, and credential access/transfer. Native packages such as `sharp` may build from source only under specific conditions; a declared script does not prove execution on this PC. |
| WASM or decoder capability | Check reachability from the selected entrypoint and nearby process, download, or secret-transfer behavior. A capability can also be normal library functionality. |
| Isolated invisible characters | Distinguish documentation, emoji, and synthetic data from characters tied to a decoder or execution flow. |
| Configuration or tooling capability | Distinguish manual workflows and reference text from active AI/MCP settings, then check purpose and provenance. |

Record each finding as explained normal functionality, needing further investigation, or being handled in its owning project, with its path and supporting evidence. Do not suppress findings solely by package name or run install/build, package code, or hooks to investigate them. Access denied does not prove that a directory is empty; review `coverage.summary` and obtain access to the exact affected scope before rerunning it.

After loading the JSON into `$r`, inspect all coverage actions and timing records with:

```powershell
$r.coverage.summary.nextActions | Format-List reason, count, paths, action
$r.performance.activities | Format-Table activity, attempts, elapsedMs, maxElapsedMs, partition
$r.performance.slowSteps | Format-Table step, elapsedMs, timedOut, path -Wrap
```

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
