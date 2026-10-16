# Dev Supply Chain IOC Checker

Dependency-free Windows developer environment supply-chain IOC checker.

This tool is a BAT launcher plus a single Windows PowerShell 5.1-compatible scanner. It performs offline, read-only static checks against project files, package metadata, explicitly declared Node.js runtime versions, CI/CD workflows, MCP/AI-agent configs, IDE extensions, and optional endpoint telemetry.

Current scanner version: **0.1.27**. Repository: [Daiki9801/dev-supplychain-checker](https://github.com/Daiki9801/dev-supplychain-checker).

v0.1.27 adds severity totals beside finding-class counts: `ConfigReview` is a classification count, not the number of WARNs. Four reviewed marker references in this distribution's own tests/workflow become INFO only when their exact relative path, normalized source SHA-256 and rule match. Changed sources and external copies receive normal analysis; active behavior and exact artifact checks remain enabled.

Credential/send matching validates anchored candidates and their original bounded neighborhoods. Local IOC rule timeouts retain the two-second limit, record the specific rule and continue subsequent rules with incomplete coverage. Regex objects are bounded and cached. PowerShell refinement indexes bindings and reuses scope results; scope cache identities include node type and both offsets. Incident marker checks use an ASCII literal preflight while retaining regex semantics for non-ASCII input.

MCP command extraction skips command-free inventories, recognizes escaped JSON keys, and limits traversal to 8,192 nodes, depth 32, 256 fragments and 65,536 extracted characters. Limit exhaustion or command-bearing malformed JSON produces WARN coverage information and `scanComplete=false`. Partial extraction is not a completed negative result.

File counters count distinct normalized paths per counter. `fileEnumerationEvents` and `fileSkipEvents` separately count repeat visits; `uniqueFilesQueued` does not equal scanned plus excluded files because exclusions can occur before queuing. Manifest probes no longer increment skipped-file counts; integrity warnings remain enabled. Verified fixture markers no longer inflate child-project discovery or dependency budget allocation. Unknown/changed markers and unrelated files remain eligible. Nonexistent targeted paths do not consume sampling events.

Execution timestamps and elapsed milliseconds share a monotonic origin; the finish timestamp is derived from the captured start and elapsed time. `performance.slowActivities` adds at most 20 redacted slow file/read/analysis records alongside `slowSteps`. Reading, PowerShell context proof and MCP extraction are nested activities; add only `partition=true` activities. Synthetic regressions exercise large compiler-like text, many PowerShell bindings and large/deep JSON on Windows PowerShell 5.1. Real-PC speed has not been remeasured. The October 6 IOC baseline and menu scopes are unchanged.

v0.1.26 fixes mixed passive PowerShell pattern definitions by parsing original source and combining proven passive spans, rather than reparsing blanked syntax. Active code beside those definitions retains its original location and priority. Plugin-cache workflow copies are INFO references with `activation=unknown`; active repository CI checks remain enabled. `_cacache/content-v2` blob subtrees are excluded under standard and custom cache roots, with `scanStats.cacheBlobDirectoriesSkipped` reporting directory exclusions without guessing their file counts. Other files under cache-named folders remain eligible.

`coverage.summary.nextActions` lists every concurrent failure group and sampling limit with counts, representative paths and appropriate actions; `nextAction` remains a combined string for compatibility. Credential-property matching avoids the reported repeated-backtracking case. A credential subrule timeout in runtime-code analysis marks coverage incomplete and allows later execution checks to run. Other timeouts can end their containing step; the reported step/rule identifies the unfinished scope.

`performance.activities` measures enumeration, project discovery, target selection, reading/decoding and file processing. Entries with `partition=true` do not overlap; their sum is `partitionElapsedMs`, and `otherElapsedMs` is remaining execution time. Reading and `performance.steps` are nested timings and must not be added to that sum. Report formatting/writes are outside the execution timing. `performance.slowSteps` retains at most 20 slowest step/path records above the two-second slow threshold, with redacted profile paths and no source/regex text. Runtime optimizations reuse path roles, original syntax and static masks, initialize statistic lookups once, and route metadata checks only to applicable file types. These changes do not establish a fixed real-PC speedup.

v0.1.25 records execution separately from findings and coverage. Ctrl+C / pipeline interruption produces `executionStatus=interrupted`, `scanComplete=false`, `completionStatus=incomplete-critical`, and an `INTERRUPTED` label. `execution.phases` distinguishes `not-started`, `running`, `completed`, `interrupted`, and `failed`; enabled checks are not proof they ran. Unstarted npm/dependency checks no longer claim `not-found` or within-limit coverage. Reports retain start/finish timestamps, elapsed milliseconds and unique queued files left unprocessed; an unenumerated remainder is still unknown. Window/process termination cannot guarantee a saved report.

Ordinary single-quoted PowerShell pattern definitions and inline regex patterns can now be proven passive in a classifier scope without I/O, execution, capture/reflection or unknown calls. Cached MCP command configs have `sourceContext=cached-ai-config`: mutable package selectors are CAUTION capabilities with `activation=unknown`, while strong fetch/execute and credential-send compounds remain detectable. Zstd signatures, ZIP-based `.nupkg` containers and binary-probed `.br` data skip text decoding after applicable filename/hash checks, with one aggregate INFO. Probes are bounded to 4 KiB; Brotli detection is heuristic, no decompressor is added, and an extension alone does not exempt readable text.

The five severity levels and normal exit codes are unchanged. `findingClassSummary` separates security evidence, advisory version matches, configuration review, capabilities, coverage limitations and context. A WARN caused by sampling or interruption is a coverage limitation, not evidence of malicious behavior. Regex timeouts retain the two-second bound and add a stable SHA-256-derived `ruleId` and timing without pattern/input text; `performance.steps` contains bounded per-step timing/count aggregates.

v0.1.24 narrows AI credential-send and developer-tool write checks. AI tooling needs a bounded credential read and direct or locally bound send argument; token-name inventories, comment URLs and pagination `.cursor` properties do not establish exfiltration. Write checks inspect the destination (including copy destinations and simple local bindings), rather than nearby planned-operation targets or payload text. Script findings preserve the original credential-access/write line. These are bounded static heuristics, not complete language or runtime proofs; indirect flows still need manual review.

A separate PowerShell parser proof distinguishes single-quoted here-string examples consumed only by regex operations or inspected local helper parameters. For generic npm behavior and known-domain/IP text checks, proven literals retain INFO evidence (`PACKAGE_CODE_PASSIVE_REGEX_DATA`, `KNOWN_IOC_REFERENCE_TEXT`) while other bytes remain analyzed with original offsets. Valid embedded PowerShell syntax in a BAT can use the same proof. Unknown consumers, capture/reflection, rebinding, execution use, parse errors and analysis bounds fall back to normal detection. Names and markers do not grant trust; package/hash checks remain independent.

Read/directory failures unwrap their .NET cause and distinguish `file-in-use`, `access-denied`, `path-too-long`, `path-not-found`, `invalid-path`, `io-error`, `decode-error` and unknown read/enumeration failures. Grouped `coverage.candidateFailures` and `directoryFailures` add bounded `exceptionTypes` and `hresults` arrays without messages or target contents. A directory can represent a failing child. Recorded non-critical read failures and dependency/cache sampling limits now also set `scanComplete=false`, consistent with PARTIAL; `candidateCoverageComplete` still reports the critical candidate scope. Existing size and regex limits remain in force. The IOC baseline remains the October 6 review.

日本語で使い始める場合は、[IT初心者向け使い方マニュアル](docs/user-manual-ja.md)または[図解マニュアル](docs/visual-user-manual-ja.md)を参照してください。

## Safety Model

- No external dependencies.
- No network access or online IOC update.
- No target project code execution.
- No remediation, deletion, uninstall, registry modification, quarantine, or cleanup.
- No secret values are printed to TXT or JSON reports.
- User profile and endpoint telemetry scans are opt-in only.

For distribution and non-technical users, see [Safety Model](docs/safety-model-en.md).

## What This Checker Cannot Prove

An `OK` result, no `DANGER` findings, or even `completionStatus=complete` does **not** prove that a PC or repository is clean. `complete` means only that the checks planned for the selected, bounded scope finished without a recorded coverage gap.

This checker does not:

- scan the entire disk or every file in dependency, build, cache, archive, or binary content;
- inspect memory, live process behavior, network traffic, cloud logs, or remote services;
- perform a complete dependency/CVE audit or prove package, publisher, extension, or binary authenticity;
- obtain live reputation or IOC updates while scanning; or
- confirm infection, rule out compromise, or remediate a finding.

Use severity as triage priority and completion state as coverage information. See [Limitations](docs/limitations.md) for the full boundary.

## Scan Flow

```mermaid
flowchart LR
    A["Select a local folder"] --> B["Offline static inspection"]
    B --> C["Packages and lockfiles"]
    B --> D["CI/CD, hooks, and AI configs"]
    B --> E["IDE and runtime metadata"]
    C --> F["Redacted TXT and JSON reports"]
    D --> F
    E --> F
    F --> X{"executionStatus"}
    X -->|interrupted| K["Review unfinished phases; not a completed result"]
    X -->|completed / error| G{"completionStatus"}
    G -->|complete| H["Review DANGER, WARN, CAUTION, then INFO"]
    G -->|partial-non-critical| I["Review bounded non-critical gaps"]
    G -->|incomplete-critical / error| J["Do not treat as a completed negative result"]
```

The scanner reads bounded local metadata and text. It does not download repositories, execute target code, or remediate findings.

Report generation is append-only with respect to existing files: explicit `-TextOut` and `-JsonOut` paths must be different and unused. Existing files are rejected before scanning, default filename collisions receive a new suffix, and report writes use create-new semantics.

## Documentation

| Audience | Japanese | English |
|---|---|---|
| First-time users | [Beginner manual](docs/user-manual-ja.md) | [Beginner manual](docs/user-manual-en.md) |
| Visual overview | [Illustrated manual](docs/visual-user-manual-ja.md) | [Illustrated manual](docs/visual-user-manual-en.md) |
| Safety and limits | [Safety model](docs/safety-model-ja.md) / [Limitations](docs/limitations.md) | [Safety model](docs/safety-model-en.md) / [Limitations](docs/limitations.md) |
| Maintainers | [PC pre-push test procedure](docs/pre-push-test-procedure-ja.md) / [Publication checklist](docs/github-publication-checklist-ja.md) / [Contributing](docs/contributing-ja.md) | [Publication checklist](docs/github-publication-checklist-en.md) / [Contributing](CONTRIBUTING.md) |
| IOC maintainers | [Local IOC data](iocs/README.md) | [Local IOC data](iocs/README.md) |

The beginner manuals include commands to group and review CAUTION findings without executing target code, inspect all coverage actions, and read timing partitions, slow-step and slow-activity records. The illustrated guides describe v0.1.27; older PNGs are labeled historical. The [PC pre-push procedure](docs/pre-push-test-procedure-ja.md) keeps synthetic artifacts under `reports/`, validates all nine required JSON files as UTF-8, and checks publication candidates without reading known secret-file bodies. The [October metadata validation record](docs/python-metadata-review-20261008-ja.md) covers the earlier fixes and repository self-scan.

## Usage

Menu `1` scans the current working folder; double-clicking the BAT may make this checker folder the target. Use `2` to enter another project folder and start with Recommended traversal. Entries `3`, `4`, `5` and `8` also use the working folder by default. Entries `6`, `7` and `9` identify broader PC scope and require confirmation; their numbers and scopes are unchanged.

Beginner-friendly Japanese manual:

- [IT初心者向け 使い方マニュアル](docs/user-manual-ja.md)
- [図解マニュアル: Dev Supply Chain IOC Checker](docs/visual-user-manual-ja.md)
- [安全性と設計上の約束](docs/safety-model-ja.md)

English manuals:

- [Beginner User Manual](docs/user-manual-en.md)
- [Illustrated Manual](docs/visual-user-manual-en.md)
- [Safety Model](docs/safety-model-en.md)

Scan the current folder:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path . -ReportDir .\reports
```

Run only selected risk checks:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path . -Checks Packages,AiMcp,CiCd -ReportDir .\reports
```

Valid `-Checks` values are:

- `Recommended`: default project-local static checks, including declared/pinned Node.js versions and already-enumerated `node.exe` files. Does not read npm global/cache or search host Node.js locations.
- `MajorRecommended`: `Recommended` plus static npm global package roots and bounded known-path/PATH Node.js installations.
- `AllSafe`: all non-telemetry static checks, including static npm global/cache.
- `Packages`, `LifecycleScripts`, `NodeRuntime`, `InvisibleUnicode`, `CiCd`, `AiMcp`, `IdeExtensions`, `HooksAndTasks`, `SecretsInventory`, `NpmGlobal`, `NpmCache`, `ScannerSelf`.

`InvisibleUnicode` reports an isolated invisible control as `CAUTION` and adds bounded handling for consecutive Variation Selector clusters. It recognizes the known GlassWorm `codePointAt` decoder shape only when the same locally bound code-point variable performs both selector-range checks and byte-offset mappings. A decoder signature without an observed selector cluster is at most `WARN`; unrelated APIs elsewhere in a large bundle are not combined into `DANGER`. The scanner safely maps `U+FE00-U+FE0F` and `U+E0100-U+E01EF` clusters to bytes in memory and checks decoded UTF-8 only for static execution or secret-access markers. Analysis iterates only matched selectors instead of every character; analyzed selector matches and each cluster's static decode buffer are capped at 8,192. Over-limit input records incomplete candidate coverage after a bounded tail-cluster check. Decoded payload text is never executed or copied into reports.

`UserProfile` and `EndpointTelemetry` are still explicit mode switches, not `-Checks` names.

Reports include a machine-readable `scanScope` object and an `iocData` freshness inventory. `scanScope` distinguishes bounded comprehensive triage from Deep or full-disk traversal. `iocData.releaseReady` is `false` whenever a shipped IOC dataset is stale, missing, or invalid; historical exact indicators remain active, but maintainers should refresh the affected data before publishing a release. `releaseReady=true` covers only the documented bounded datasets and never claims that the checker is a complete live threat feed.

Run the single BAT launcher:

```bat
run-checker.bat
```

For a selected folder, menu item `2` now offers `Recommended` or explicit `Deep` traversal. The command form is:

```bat
run-checker.bat deep C:\Path\To\Project
```

Deep traversal requires typing `YES`. It enters dependency, build, and cache directories, but it does not add npm global/cache, UserProfile, or EndpointTelemetry scanning. VCS directories, reparse points, auth-file contents, and the running checker's own reports remain protected.

Deep findings distinguish code selected as an active package lifecycle/runtime entrypoint from code reached only by recursive traversal. Exact IOC/campaign matches and strong behavior in first-party or selected entrypoint code retain `DANGER`. Generic secret-send, developer-tool write, single invisible-Unicode execution, or local WASM decode/process compounds in unselected dependency/generated code are `WARN`; an unselected fetch-execute helper is `CAUTION`. A dependency-owned `.github/workflows` file is not active CI for the consuming repository, so CI-specific checks ignore it while other applicable static code checks still run.

Embedded executable fixtures are scanned as ordinary target content. A filename, test-like function name, helper shape, or fixture-/pattern-like variable or array name does not suppress behavior or IOC text. The running distribution's own synthetic sample bodies are protected through the bounded manifest/path controls below. Separately, four reviewed posture-marker references in three exact shipped test/workflow sources receive INFO after source-hash verification; this does not exclude their bodies or refine other findings. Source changes require manual review and an explicit update of the source identities in `Test-VerifiedSelfTestMarkerReference`.

PowerShell source receives one narrow context refinement for generic fetch-execute detection. Matches are classified on the original source as `Active`, `Ambiguous`, or `PassiveRegex`; the source text is never rewritten for this decision. A static `Pattern` value is `PassiveRegex` only when its table is literal data, its lexical function scope is independent, every observed value use is a direct `-match`/`-notmatch` consumer, and reachable local helpers cannot recover or execute the value through dynamic scope. An `Active` match always wins over passive definitions and retains its original line number. Parse errors, reflection, wrappers, self-source reads, index/property transfer, execution-oriented use, and unresolved flow remain fail-safe findings. This refinement does not apply to exact IOC or other behavior checks.

For distributed use, run `run-checker.bat` from the extracted checker folder. The folder should contain `Scan-DevSupplyChain.ps1`, `run-checker.bat`, `README.md`, `iocs`, and `tests\samples\manifest.json`. If the launcher sees an incomplete copy, it prints a warning and requires typing `YES` before continuing.

End-user archives should not include the full `tests\samples` fixture tree. This source repository keeps synthetic fixtures for maintainer validation, but GitHub-generated source archives exclude fixture bodies through `.gitattributes` and keep only the sample manifest/readme needed for distribution self-checks.

Non-interactive synthetic validation can call the launcher with a path and no pause:

```bat
run-checker.bat current .\tests\samples\clean-js --no-pause
```

This validation command requires a maintainer source checkout that includes fixture bodies. It is not expected to work from an end-user archive that intentionally omits those fixtures. Omitting fixtures from the archive does not change scanner rules, IOC data, report generation, or real target scanning.

The `major`, `userprofile`, and `full` launcher modes ask for explicit confirmation before scanning broader real-PC, user-profile, or endpoint data:

```bat
run-checker.bat major
run-checker.bat userprofile
run-checker.bat full C:\Path\To\Project
```

`major` scans common developer folders plus IDE and AI-agent metadata. Project-root discovery includes common GitHub/Documents/Desktop subfolders, JetBrains/Android Studio/Eclipse/NetBeans default project roots, and `OneDrive`, `OneDriveCommercial`, or `OneDriveConsumer` project subfolders when those environment variables resolve to a child directory under `USERPROFILE`. It also performs static npm global metadata checks and bounded Program Files, local process-PATH, and version-manager Node.js file-metadata checks. For Codex, this mode selects active config, agent/rule/skill content, installed plugin tooling, and extension roots; it excludes `.codex\sessions`, runtime cache, and history data. It does not scan the whole user profile or `C:\` drive and does not include endpoint telemetry.

`full` is a bounded comprehensive host-triage profile. It combines the explicit target, MajorLocations discovery, user-profile AI/IDE configuration, static npm global/cache checks, known-path/PATH Node.js metadata, and endpoint telemetry. It is not a full-disk scan and does not enable Deep dependency/build/cache recursion. Run `deep` separately against a trusted project when that recursive content is required.

Automatic roots read from `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, `OneDrive`, `OneDriveCommercial`, and `OneDriveConsumer` are accepted only as absolute, non-reparse child directories under `USERPROFILE`. Relative paths, profile or filesystem roots, profile-external paths, and reparse-point paths are skipped with `AUTOMATIC_ENVIRONMENT_ROOT_REJECTED`. Scan an intentional external configuration or project directory explicitly with `-Path` instead.

User-profile discovery includes common VS Code-compatible extension roots and active configuration for Codex, Claude, Cursor, Windsurf, Continue, Gemini, OpenCode, and user-level `mcp.json`. Known auth/credential files are inventoried without reading their contents. Other in-scope configuration text is read for static matching, while secret-like report evidence passes through central redaction. Project scans also prioritize active AI instruction files such as `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Cursor rules, and GitHub Copilot instruction files.

Recommended project scans discover bounded child projects under a selected parent (depth 4; Deep depth 8) and apply targeted npm, Python, and Composer checks to each discovered dependency environment. Structural lockfile coverage includes `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, Yarn/Bun text locks, and `Pipfile.lock`. Targeted dependency files are capped at `min(10,000, floor(MaxFiles * 0.5))` and divided fairly across discovered projects with a 2,000-file per-project ceiling, so a parent-folder scan cannot let the first few large `node_modules` trees consume the run. Deep remains a separate, intentionally broader mode for one trusted project.

The October 2026 supplement adds bounded incident candidates: at most eight fixed files per npm package (16 total including existing metadata/entrypoint candidates); UTF-8 `.dist-info/METADATA` headers limited to 128 KiB and 1,024 lines, stopping before descriptions; and at most eight `RECORD` runtime paths per selected Python distribution. Python package names normalize case and runs of `.`, `_`, and `-`. Python versions follow PEP 440, including short releases such as `3.0` and `24.0`; equivalent spellings and release zero padding normalize for IOC lookup, while epoch, pre/post/dev, and local suffixes remain distinct. Duplicate or folded identity headers, malformed headers, and invalid versions preserve critical incomplete coverage. `memoryos` maps to `memos` runtime files without importing them. Hash comparisons share one hash calculation per file inspection; binary content is not parsed as text.

Python `Pipfile.lock` exact pins and literal `name`/`version` fields in a single Poetry/uv `[[package]]` block provide lockfile evidence. Names and versions from separate blocks, nested tables, comments, or multiline strings are not combined. Unclosed strings and invalid/duplicate identity fields preserve critical incomplete coverage. Other Python manifest/constraint text remains reference evidence; this is bounded static matching rather than a full TOML or dependency resolver.

`LifecycleScripts` evaluates GYP condition scalars statically, including bounded Unicode/hex escapes (131,072 UTF-16 code units per file, 65,536 per scalar, 64 conditions, and depth 32), and correlates credential access, encoding, and DNS query arguments in local windows. Active/selected code can produce `DANGER`; unselected dependency or generated code is capped at `WARN`. A sckit/stage0/configuration loader compound is `WARN` unless a known hash or exact package version independently matches. No GYP condition, package import, decoder payload, or DNS query is executed.

`CiCd` selects local workflow scripts and one literal `BASH_ENV` bridge hop (eight script candidates per project), then checks credential-derived transfers. Campaign-destination flows on the selected bridge can be `DANGER`; normal npm/PyPI publishing is not classified as exfiltration by this rule. GitHub Action advisory tags produce a reference-version `WARN`, unresolved major tags/branches/SHAs produce `INFO`, and verified bad commit hashes remain `DANGER`. A patched numeric tag does not authenticate the mutable remote artifact.

`IdeExtensions` selects bounded extension metadata and at most three fixed/main/browser payload files per extension, including reported `out/extension.js` or `app.js` artifacts. An explicitly selected VSIX/ZIP can be hash-checked; arbitrary archives are not expanded for this supplement. The two new theme IDs are `INFO` watchlist context across registries, while exact artifact hashes provide stronger evidence. Conversation/tool-result forwarding to a reported additional destination is `WARN`; an ordinary user-configured API call alone is not reported by the new transfer rule.

New findings may carry `ruleId`, `sourceId`, and `upstreamSeverity` in TXT and JSON. Selection, analysis-limit, hash, and Python-header counters appear in `scanStats`. Required candidate failures preserve incomplete coverage. These bounded static heuristics do not perform complete language/dataflow analysis; indirect calls, dynamic paths, encryption, complex control flow, and unsupported syntax can require manual review.

Long scans use compact progress by default: one aggregate heartbeat about every 30 seconds plus a root-complete line, showing the redacted root, queued/scanned counts, and elapsed time without printing every current file or scanner stage. Pass `-VerboseProgress` directly to `Scan-DevSupplyChain.ps1` when five-second, per-file, large-file-stage, and slow-step diagnostics are needed; `-Quiet` still suppresses progress output. Finding line numbers are counted in 64 KiB native string chunks rather than per-character PowerShell loops. Targeted npm runtime entrypoints exclude non-executable `.d.ts`/`.d.mts`/`.d.cts` declarations and source maps while retaining package metadata and executable entrypoints. BOM-less UTF-16 detection examines a bounded 64 KiB prefix before decoding the complete text, and common binary extensions, including OCR `.traineddata` and CMS signature `.p7s`, skip text parsing only after exact hash and relevant artifact-metadata checks. A required hash candidate over the size limit still makes coverage critically incomplete. Windows PowerShell 5.1 remains supported.

Every full-text regular-expression operation has an explicit two-second .NET timeout; a process-wide default remains as defense in depth for short metadata and path checks. The timeout is per operation, not a total scan time limit. A timeout records `REGEX_SCAN_TIMEOUT` and continues other checks and files. It can skip the remaining rules in its containing step; runtime credential-subrule isolation specifically preserves the later execution checks. The named rule/step was not completed, so the run cannot be `complete`: it becomes `partial-non-critical` for a non-critical candidate or `incomplete-critical` when the affected file is a critical candidate such as a lockfile or active configuration. Target text is not included in the timeout message. Review the named file and rule; narrowing a folder alone may not resolve the same timeout.

The launcher also provides risk-specific modes for package/Node-runtime, AI/MCP/IDE-only, CI/CD-only, and npm global/cache static checks. The package, AI/MCP/IDE, and CI/CD modes keep the cross-cutting `InvisibleUnicode`/GlassWorm check enabled. Custom menu item `8` accepts project-local checks only; use confirmed modes `6`, `7`, or `9` for npm or broader host scope. The npm static mode reads bounded candidate folders only; it does not execute `npm root -g`, `npm cache ls`, `node`, or package scripts.

GitHub repositories are not downloaded by this tool. To check a GitHub repository, manually obtain a local copy using your normal approved process, then scan that local folder with `-Path` or `run-checker.bat path`.

## Reports

Reports are written as UTF-8 with BOM:

- `dev-supplychain-report-YYYYMMDD-HHMMSS.txt`
- `dev-supplychain-report-YYYYMMDD-HHMMSS.json`

Findings use `DANGER`, `WARN`, `CAUTION`, `INFO`, and `OK`. `CAUTION` sits between `WARN` and `INFO` for low-signal presence, capability, or posture findings that merit review but do not contain a strong malicious compound. `WARN` and `CAUTION` both retain exit code `1`; `DANGER` remains `2`, scanner errors `3`, invalid arguments `4`, and `INFO`/`OK`-only runs `0`.

TXT reports also show:

- `PathType`: whether the path is a file, directory, virtual target, or unknown.
- `Line`: the line number when a text finding can be located safely.
- `SourceContext`: `normal`, `synthetic-sample`, `scanner-self`, `scanner-artifact`, `scanner-artifact-sample`, `scanner-artifact-untrusted`, `cache`, `dependency-metadata`, `active-ai-config`, `executable-tooling`, `reference-text`, `session-log`, `cache-data`, `plugin-metadata`, `jetbrains-plugin`, or `node-runtime`.

JSON reports include `scanStats` with observed files, run-wide unique queued files, child-project discovery, targeted dependency budget use, Deep-only traversal, JetBrains archive inspection, Node.js runtime candidates/version evidence, synthetic sample skips, bounded npm cache status, mutable GitHub Action refs, and WASM artifact counts.
They also include `completionStatus`, `coverage.summary`, `selectedChecks`, `expandedChecks`, `skippedChecks`, `summaryByCheck`, `checkStats`, `summaryBySourceContext`, `priorityFindings`, `capabilitySummary.provenance`, `nodeRuntimeAssessment`, `scanner.severityOrder`, `scanner.cautionExitCode`, `scanner.scriptPathRedacted`, `scanner.launcherPathRedacted`, and `scanner.distributionStatus`. `coverage.summary` separates critical and non-critical failures, labels dependency/cache coverage, and provides the next bounded action. `completionStatus` remains `complete`, `partial-non-critical`, `incomplete-critical`, or `error`; interrupted execution uses `incomplete-critical` with the separate `executionStatus=interrupted` and `INTERRUPTED` label. The existing `scanComplete` Boolean remains for compatibility and strict completed-negative-result checks.

`scanScope.included` is the planned scope. Use `execution.phases` for actual phase progress, `checkStats.<check>.executionStatus` for check-group execution, and `coverage.summary` for recorded read/analysis gaps. A completed execution can still have partial coverage. Critical/non-critical failure counters count observed failures; they do not count unknown work skipped by cancellation. `execution.queuedFilesUnprocessed` counts only unique queued paths whose file processing did not return.

v0.1.15 adds `traversalComplete`, `directoryCoverageComplete`, `candidateCoverageComplete`, and `scanComplete`. As of v0.1.21, treat a no-finding report as a fully completed bounded negative result only when `scanComplete` is `true` and `completionStatus` is `complete`. A non-critical skip can produce `partial-non-critical` even when the planned critical candidate scope completed. Budget exhaustion, malformed critical lockfiles, unsupported `bun.lockb`, or access/read failures are reported with the affected coverage area without attempting elevation.

`traversalComplete=false` does not by itself mean a critical candidate was missed. If all recorded gaps are explicitly non-critical, such as a bounded selector or regex analysis limit, `completionStatus` is `partial-non-critical`; `coverage.summary.criticalFailures` and `candidateCoverageComplete` identify critical candidate gaps. Run-wide `MaxFiles` exhaustion remains critical because the unenumerated remainder is unknown.

`NodeRuntime` keeps upstream advisory severity separate from scanner severity. A static Critical/High version match is `WARN` (or `INFO` for `engines.node` constraints), never `DANGER` from version text alone. Explicit project/container `HIGH` matches are included in `priorityFindings` alongside installed-runtime matches, with a three-item Node.js cap. JSON keeps the vulnerable-only `nodeRuntimeSummary` for compatibility and adds `nodeRuntimeAssessment`, which separately counts installed binaries and project references and records evaluated exact versions in a bounded, path-redacted inventory. `notAffected` means only that the exact version did not match the shipped offline advisory baseline; it is not a complete CVE, EOL, signature, or publisher-authenticity verdict. Project-local `Recommended` scans read version declarations and already-enumerated `node.exe` metadata without searching host locations. `MajorRecommended`, `AllSafe`, MajorLocations, and UserProfile host scopes additionally inspect bounded known-path, local process-PATH, and version-manager `node.exe` file metadata. The scanner never executes Node.js, queries the registry, or verifies binary authenticity.

Every finding includes `check` and `detectionMethod` so a report can show whether a result came from package metadata, lifecycle/static code scanning, CI/CD text scanning, AI/MCP config scanning, static npm global roots, npm cache metadata, or inventory-only checks.

`.codex` files are not ignored. The scanner separates active configs and executable tooling from reference text, session logs, cache data, and plugin metadata. Unpinned execution in an active MCP config remains `WARN`; passive tooling capability and executable-looking reference examples are `CAUTION`; active fetch-execute or secret-exfiltration compounds remain `DANGER`. Capability provenance labels are path-derived context, not independent publisher verification.

## Local IOC Updates

The scanner uses a small built-in IOC baseline plus optional local JSON files under `iocs/`.
These files are offline data only; the scanner does not fetch or refresh IOC data from the internet.

The current local baseline includes manually reviewed indicators for Axios/plain-crypto-js, GlassWorm/GlassWASM/OpenVSX, recent AsyncAPI/Jscrambler/Injective and related npm incidents, Python hook campaigns, compromised GitHub Action refs, selected C2 or persistence markers, a bounded Node.js runtime advisory set (official Critical releases from 2020 onward plus the maintained recent-High window), and the fixed 2026-08 Keyv ChainDrop campaign snapshot.

The supplement reviewed on 2026-10-06 adds 20 exact package/version pairs, 16 artifact hashes, Mini Shai-Hulud Action references, the conflibot `CVE-2026-55158` reference advisory, two theme ID watchlists, and four contextual endpoint markers. A subsequent [complete bounded corpus comparison](docs/ioc-maintenance-20261006-ja.md) reviewed all seven datasets on that date with unchanged 30-day expiry contracts, removed two inaccurate Jscrambler wrapper pairs, and fixed payload path selectors. Readiness concerns the documented corpus review and integrity; it does not independently reverify every retained historical artifact. See the [item-level evidence](docs/ioc-maintenance-20261006-evidence.json), [implementation plan](docs/security-update-20261006-detailed-implementation-plan-ja.md), and [local IOC guidance](iocs/README.md).

The Windows PowerShell 5.1 synthetic runner is `tests/Test-SecurityUpdate20261006.ps1`; it retains create-new artifacts under `reports`. See the [initial implementation validation record](docs/security-update-20261006-validation-ja.md) for the tested scope and performance comparison.

`tests/Test-ScanTriagePerformanceRegressions.ps1` covers mixed passive/active PowerShell definitions, large quoted credential keys, isolated subrule timeouts, simultaneous coverage actions, cached versus active CI, custom cache blob roots, applicable metadata dispatch, and bounded/redacted timing records. It runs only repository-local synthetic inputs and is included in Windows PowerShell 5.1 CI.

`tests/Test-PythonMetadataRegressions.ps1` additionally verifies PEP 440 identities, malformed/bounded headers, Python lockfile precision, the reported PC metadata layout, and binary/hash coverage using repository-local synthetic files only. See the [2026-10-08 review and validation record](docs/python-metadata-review-20261008-ja.md) for the fixes and remaining coverage limits.
The Keyv snapshot contains 443 package names and 2,235 exact package/version pairs plus bounded hash, marker, persistence, workflow, and propagation checks. Exact installed/structural-lock matches and exact hashes are high-priority evidence; manifest/cache/fallback mentions and markers require corroboration. All 2,235 pairs were independently corroborated in non-withdrawn OSV malware records on 2026-10-06. Original supplied-source provenance and the canonical digest remain unchanged; see [Local IOC Data](iocs/README.md) for the separate source CSV and aggregate-count limits.
For mass supply-chain campaigns, add only individually verified package or extension versions. Do not paste incomplete news-derived package lists into the IOC files. Broad campaign names such as TanStack, Mistral, and Red Hat npm families are treated as low-confidence context unless an exact bad version or strong behavior chain is also present.

See [Local IOC Data](iocs/README.md) before updating IOC JSON.

## Public Repository Safety

This repository includes GitHub publication support files:

- `.github/workflows/validate.yml`: parser, JSON, and synthetic-sample validation on Windows.
- `.github/dependabot.yml`: GitHub Actions update PRs only.
- `.github/CODEOWNERS`: active ownership rules for `@Daiki9801`; forks must replace the owner before enabling Code Owner review.
- `.github/ISSUE_TEMPLATE/`: public bug-report guidance that explicitly rejects secrets and host forensic data.
- `.github/pull_request_template.md`: safety and synthetic-validation checklist for contributions.
- `.gitattributes`: excludes the default `reports/` output, local reference files, temporary secrets, and synthetic fixture bodies from generated source archives; custom report directories must remain untracked.
- `SECURITY.md`: vulnerability reporting scope and safety expectations.
- `CONTRIBUTING.md`: contribution and validation rules.
- `CHANGELOG.md`: user-visible scanner changes beginning with v0.1.15.
- `docs/pre-push-test-procedure-ja.md`: ordered Windows PowerShell 5.1, synthetic, optional real-host, report-safety, and Git publication checks.
- `docs/github-publication-checklist-ja.md` / `docs/github-publication-checklist-en.md`: recommended GitHub settings for a public repository.

Japanese companion docs are also available for [security policy](docs/security-policy-ja.md) and [contribution rules](docs/contributing-ja.md).

The workflow uses synthetic samples only. It must not run real `-UserProfile`, `-EndpointTelemetry`, npm, git clone/fetch/pull, node, python, or network retrieval commands.

## Validation

Only run synthetic validation against `tests/samples` unless a human explicitly asks for real host scans.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -ReportDir .\reports
```

The `tests/samples` directory contains hand-written synthetic fixtures for source-level regression tests. They were not downloaded, are not real malware, and are expected to produce `CAUTION`/`WARN`/`DANGER` findings when scanned directly. Parent-directory and Major PC scans skip only manifest-verified fixture files matching the currently running checker distribution. Unrelated projects named `tests/samples`, unknown sample files, modified sample files, and fake scanner folders are scanned normally.

Test-only redirection of Node.js/npm host roots requires the explicit `-SyntheticValidation` switch and an existing root under this checkout's `tests/samples` or `reports` directory. Ambient test-root environment variables are ignored during normal scanner use and cleared by `run-checker.bat`.

For non-technical users, distribute an archive that omits the fixture bodies and keeps only `tests\samples\manifest.json` plus `tests\samples\README.md`. This repository's `.gitattributes` applies that rule to GitHub-generated source archives.

Tradeoff: users of the lightweight archive cannot run the synthetic sample regression scan because the intentionally suspicious fixture files are absent. Maintainers and CI still run those checks from the full source repository, so real detection capability is not reduced.

The configured report directory (default: `reports/`) and the current TXT/JSON output files are skipped during normal scans. This prevents current report output from being re-detected as target risk without hiding unrelated source directories such as `reports-service`. Only the repository-root `/reports/` directory is ignored by Git; custom or legacy report directories must be reviewed explicitly before commit. Scan a report folder explicitly with `-Path` only when reviewing report contents intentionally.

## Important Limits

Completion and severity answer different questions:

| Field or result | Correct interpretation |
|---|---|
| `DANGER` | High-priority evidence to review; not automatic proof of infection. |
| No `DANGER` | No high-priority match was found in completed checks; not proof of safety. |
| `complete` | The selected bounded scan plan completed; not full-disk or exhaustive coverage. |
| `partial-non-critical` | A declared non-critical check or bounded analysis was skipped or limited. Review `coverage.summary` and the limitation finding. |
| `incomplete-critical` / `error` | Material coverage or scanner execution is unknown. Do not use the result as a completed negative. |

This is a triage tool. It does not replace EDR/AV, memory or network forensics, package-manager audit services, SIEM review, or incident response.
