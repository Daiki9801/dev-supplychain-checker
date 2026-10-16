# Changelog

User-visible changes are documented here beginning with version 0.1.15. Earlier development history remains available in the Git commit history.

## [0.1.27] - 2026-10-16

### Fixed

- Anchors credential candidates and checks bounded send neighborhoods in both directions. Caches bounded regex objects, adds a necessary-literal preflight for the exact shipped host-marker expression, and records each local rule timeout while continuing subsequent rules.
- Indexes PowerShell bindings, reuses lexical-scope results and prevents root/function cache collisions with type/start/end identities. Adds an ASCII incident-marker preflight without changing non-ASCII regex case semantics.
- Skips command-free MCP inventories and bounds command extraction by node count, depth, fragment count and text length. Escaped JSON keys remain parsed; exhausted extraction and malformed command-bearing JSON are reported as incomplete coverage.
- Counts distinct paths separately from enumeration/skip events. Keeps manifest probes from incrementing skipped-file counters, excludes verified fixture markers from project/budget counting, and avoids sampling events for nonexistent targeted paths. Integrity warnings remain enabled.
- Refines four reviewed self-test posture markers to INFO using exact distribution-relative paths, normalized source hashes and rule identities. Modified sources, copied files, active behavior and exact artifact checks retain normal analysis.

### Reporting and validation

- Prints severity totals alongside finding classes. Aligns start/finish timestamps and elapsed time to one monotonic origin, and adds bounded redacted slow-activity records for reading, file processing and analysis.
- Adds Windows PowerShell 5.1 synthetic regressions for compiler-shaped input, many bindings, escaped/deep/wide JSON, timeout continuation, source identity, counters and timing. Updates CI, README, the PC procedure and Japanese/English manuals. The IOC baseline remains 2026-10-06; real-host performance is not claimed.

## [0.1.26] - 2026-10-16

### Fixed

- Parses original PowerShell source when classifying fetch/execute, combining proven passive spans without reparsing blanked syntax. Mixed scalar/inline patterns and Pattern tables no longer turn a scanner-induced parse error into DANGER; active and unproven consumers remain checked at original locations.
- Removes repeated backtracking in quoted credential-property matching. A credential subrule timeout in runtime-code analysis records incomplete coverage and allows the later execution checks to continue. Other timeouts identify the affected rule or containing step; the two-second bound remains unchanged.
- Anchors the credential recipient binding to the read's immediate prefix rather than the first preceding newline-delimited assignment. Restores the existing PowerShell auth-file transfer fixture while retaining overwrite checks.
- Classifies plugin-cache workflow copies as INFO references with activation unknown. Active repository workflow posture and other applicable code/IOC checks remain in force.
- Recognizes `_cacache/content-v2` beneath standard or custom cache roots and skips blob-directory contents without decoding or inferring file counts. Ordinary source outside that structural cache subtree remains checked.
- Adds `coverage.summary.nextActions` for all concurrent failure groups and sampling limits, preserving the existing combined `nextAction` string. TXT lists each reason, count and representative path.

### Performance and validation

- Reuses path-role classifications and original parsed syntax, initializes statistic-name lookups once, routes metadata checks only to applicable file types, and reuses static code masks. Negative token prefilters and native padding reduce unnecessary full-bundle masking work.
- Adds `performance.activities` for enumeration, project discovery, target selection, reading/decoding and file processing, plus partition/other elapsed time. Reading and check steps are nested measurements; report formatting and output writes are excluded. `performance.slowSteps` retains at most 20 slowest redacted path/step records without source or regex text.
- Adds Windows PowerShell 5.1 synthetic regressions for the five reported issues, positive detection retention, timeout isolation, report fields and bounded timing retention; integrates them into CI and the PC procedure. README and Japanese/English manuals describe the new fields. Menu scopes, severity/exit codes and the October 6 IOC baseline are unchanged.

## [0.1.25] - 2026-10-15

### Fixed

- Records execution phases, timestamps, duration and unique queued files left unprocessed. Ctrl+C/pipeline stops retain an interrupted report when PowerShell can finish its finally block. Interrupted runs cannot report completed critical scope; unstarted npm/dependency checks no longer report not-found or within-limit coverage. Existing completion-status values and severity/exit-code contracts remain compatible.
- Extends passive PowerShell data proof to ordinary single-quoted pattern bindings and inline patterns in classifier scopes without I/O, execution, reflection/capture or unknown calls. Unknown, rebound and active consumers remain analyzed.
- Skips Zstd-signature, ZIP-container and binary-probed Brotli data before text decoding, after applicable IOC/hash checks. A bounded 4 KiB probe never decompresses content; readable text with these extensions remains analyzed. Compression skips are aggregated into one INFO.
- Distinguishes cached MCP command configs from enabled configuration. Unpinned cached npx/uvx selectors are CAUTION capabilities with activation unknown; strong command compounds remain detectable.
- Adds a stable hashed regex rule identity and timeout timing without pattern/input text, plus bounded per-step performance aggregates. The two-second timeout is unchanged.

### Usability and validation

- Adds finding-class counts to distinguish security evidence, version matches, configuration review, capabilities and coverage limitations. Budget/discovery-limit warnings are limitations rather than security posture claims.
- Clarifies current-folder versus selected-folder menu entries and PC confirmation scopes without renumbering or expanding them. Reports label scope as planned and show execution separately from severity.
- Adds Windows PowerShell 5.1 regressions for real synthetic pipeline cancellation, incomplete phases, pending-file accounting, compressed/text probes, retained hash detection, cached/pinned/active MCP commands and timeout privacy. Extends scalar-pattern regressions and updates CI, README and Japanese/English manuals. The October 6 IOC baseline is unchanged.

## [0.1.24] - 2026-10-14

### Fixed

- Requires bounded credential-read/send flow for AI tooling instead of whole-file token-name inventories, URLs and POST strings. Script findings retain the credential-access line; pagination `.cursor` properties are not credential paths.
- Checks actual developer-tool write/copy destinations and simple local bindings rather than nearby planned-operation targets or payload text.
- Separates statically proven regex-only PowerShell here-string examples from generic npm behavior and domain/IP text findings, retaining INFO evidence and original offsets. Unknown consumers, capture/reflection, malformed syntax and active examples remain analyzed; names do not grant exemptions.
- Unwraps file/directory causes to distinguish sharing violations, access denial, missing/long/invalid paths, decoding and other I/O failures. Grouped coverage adds bounded exception-type/HRESULT metadata without messages or contents.
- Keeps `scanComplete=false` for non-critical candidate read failures and dependency/cache sampling limits, consistent with PARTIAL. Security-critical candidate coverage remains separately reported.

### Validation and documentation

- Adds Windows PowerShell 5.1 synthetic regressions for passive/active examples, original finding lines, destination binding, wrapped exceptions, a real local sharing violation and recovery, and size limits. Artifacts are retained under `reports/`.
- Adds the suite to CI and the PC procedure; updates README and Japanese/English beginner and illustrated manuals. The IOC baseline remains the October 6 review; this change does not refresh advisories.

## [0.1.23] - 2026-10-06

### Added

- Adds the reviewed October supplement: 20 exact npm/Python package-version pairs, 16 artifact SHA-256 indicators, Mini Shai-Hulud Action references, a separate conflibot CVE reference advisory, two INFO theme ID watchlists, and four contextual endpoint markers.
- Adds bounded npm native-build/runtime, Python distribution-header/RECORD, IDE payload, and local CI BASH_ENV bridge candidates with merged owner, selection, and critical-coverage metadata.
- Adds static GYP sandbox-escape/process compounds, credential-to-encoded-DNS flows, sckit/stage0 loader compounds, and conversation/tool-result secondary-transfer checks. Target code, expressions, imports, payloads, and network queries are never executed.
- Adds optional finding provenance fields to TXT/JSON and selection, limit, hash, and Python-header counters.
- Adds a Windows PowerShell 5.1 synthetic regression runner for the new IOC/rule/selection/report contracts. Artifacts stay under the repository reports directory. The existing boundary runner supports `-KeepArtifacts` for validation without cleanup.

### Changed

- Python distribution identities use normalized case and punctuation; installed METADATA is parsed only through a bounded header reader and description text is not scanned as installed-package evidence.
- Known-hash candidates remain inspectable with their owning check, including Packages-only Python binaries and IdeExtensions-only explicit VSIX/ZIP files. Multiple hash indicators for one inspected file share one calculation.
- Action advisory body validation cannot be overwritten by a fresh header. Historical Action entries and the built-in advisory survive an invalid or old-schema local section.

### Publication status

- All seven bounded datasets were compared with their source registers on 2026-10-06, keeping 30-day expiry contracts. The evidence record distinguishes direct corroboration from retained historical provenance. All 443 Keyv names and 2,235 pairs were independently corroborated in OSV malware records without changing the approved snapshot digest or original source statuses.

### Fixed

- Accepts Python PEP 440 short releases such as `pycparser 3.0` and `pip 24.0`; preserves epoch and local/pre/post/dev identity during IOC matching instead of extracting a partial npm-style version. Equivalent release padding and spellings normalize consistently in installed metadata and local IOC data.
- Rejects folded/duplicate identity and malformed METADATA headers, and matches Poetry/uv package identities within one literal package block. Python version/name suffixes and unrelated lock entries no longer provide false exact IOC evidence. A focused Windows PowerShell 5.1 regression suite covers these contracts.
- Treats OCR `.traineddata` and CMS signature `.p7s` as binary artifacts after hash checks, avoiding text size/encoding warnings. Required oversize hash candidates still retain critical incomplete coverage.
- Repairs the pre-existing sample README hash in the fixture trust manifest; all 158 fixture entries are validated by a dedicated maintenance regression suite.
- Rejects future review dates, missing/empty required sections, and malformed entries. Node.js conflicts, invalid or duplicate advisories, and missing built-in entries block readiness; built-in staleness cannot mask a missing/invalid local dataset.
- Removes the two Jscrambler wrapper pairs explicitly excluded by the trusted report and includes the reported `dist/` directory in setup/intro hash selectors. Adds the public Keyv contract alongside the approved historical marker, with shared-RPC proximity still required.
- Creates future security-boundary artifacts under `reports/` so retained synthetic fixtures do not enter ordinary source traversal. Existing retained directories are preserved.
- Bounds CI workflow bridge selection at 2,048 lines while keeping the 128 KiB byte cap; late bridge detection and explicit critical coverage failure on over-limit workflows have synthetic regression coverage.

### Documentation and validation procedure - 2026-10-09

- Updates Japanese and English user/illustrated manuals for v0.1.23, adds grouped CAUTION review steps, and labels the June PNGs as historical.
- Keeps PC-test artifacts under ignored `reports/` and excludes all retained reports from repository self-scans. Report privacy checks read only the current test outputs; publication checks skip known secret-file bodies and reparse paths.
- Validates the seven IOC datasets, sample manifest, and evidence register as UTF-8 in CI and the PC-test procedure. Missing or malformed required JSON fails without printing its contents.
- Replaces private artifact links with local-only path labels and links historical records to the completed October 9 validation.

## [0.1.22] - 2026-08-26

### Added

- Adds focused Windows PowerShell 5.1 regression tests for launcher executable-search hijacking, active scanner-distribution workflow/script detection, and environment-defined host-scope boundaries.
- Adds synthetic precision regressions for active versus unselected dependency code, dependency-owned workflow files, bounded credential/send correlation, and non-critical selector-analysis limits.

### Changed

- Constructs synthetic malicious strings from fragments inside CI and regression code so the generated fixtures remain testable without exempting active repository files from normal scanning.
- Documents that automatic Codex, Claude, and OneDrive roots must be safe child directories under `USERPROFILE`; intentional external roots require an explicit `-Path` scan.
- Classifies generic secret-send, developer-tool write, single invisible-Unicode execution, and local WASM decode/process compounds found only by Deep traversal in unselected dependency or generated code as `WARN`; unselected fetch-execute helpers are `CAUTION`. Exact IOCs, campaign chains, first-party code, and selected lifecycle/runtime entrypoints retain their higher-priority behavior.
- Applies that Deep-only context to common dependency, virtual-environment, framework-output, build-output, and cache directory markers relative to the explicit scan root; an ancestor marker outside the root cannot downgrade first-party content.
- Treats `.github/workflows` files nested under dependency or generated-artifact directories as inactive in the consuming repository while retaining other applicable static code checks.
- Uses the Windows PowerShell parser to classify each original fetch-execute match as active, ambiguous, or passive regex data without rewriting source text. Static `Pattern` tables are scoped by lexical function, reachable local helpers are checked for dynamic-scope capture, and active matches retain priority and their original line number. Unknown data flow, self-source reads, reflective variable access, parse failure, and non-regex Pattern use remain fail-safe findings.
- Evaluates embedded PowerShell here-strings as ordinary executable content; attacker-controlled function names or helper shapes cannot remove payload text from behavior analysis.
- Evaluates external execution patterns without trusting fixture-, sample-, test-, marker-, or scanner-pattern variable names as passive data.
- Clarifies in README, manuals, safety documentation, and publication checks that completion is bounded, each full-text regex operation has a two-second timeout, timed-out operations create an explicit coverage gap, and neither findings nor their absence prove infection or safety.

### Security

- Pins every BAT launcher invocation to the system Windows PowerShell 5.1 executable, preventing a scanned current directory from supplying a spoofed `powershell.exe`.
- Removes content-blind scanner-self exemptions for the active validation workflow and launcher contract, preserving IOC, fetch-execute, and secret-exfiltration detection when those files change.
- Rejects relative, filesystem-root, profile-root, profile-external, and reparse-point automatic roots supplied through `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, and OneDrive environment variables.
- Requires a bounded local credential-harvest/send compound instead of whole-file signal co-presence before reporting generic package secret exfiltration.
- Classifies dependency and generated-artifact paths relative to the explicit scan root, preventing an ancestor directory named `vendor`, `node_modules`, or another dependency marker from downgrading first-party code or hiding active workflows.
- Removes generic here-string fixture masking because arbitrary target code cannot be proven passive from function names and a dynamic-execution denylist.

### Fixed

- Stores the intentionally vulnerable Pipfile lock data under a non-manifest fixture name and materializes `Pipfile.lock` only in an ephemeral CI directory, preventing GitHub's dependency graph from reporting scanner test data as a real vulnerable dependency. Dependabot version updates also exclude synthetic sample paths.
- Reports selector/regex and other traversal limits as `partial-non-critical` when the affected candidate is explicitly non-critical; critical candidates and run-wide `MaxFiles` exhaustion remain `incomplete-critical` unknown-scope failures.
- Prevents independent sibling functions with static PowerShell regex tables from producing `PACKAGE_CODE_EXTERNAL_EXECUTION` solely because command names and regex alternation appear together inside quoted Pattern definitions, while preserving findings for dynamic-scope helpers, wrappers, `.Values`, `.Clone()`, indexers, reflection, parse errors, and loop-item escape.

## [0.1.21] - 2026-08-21

### Added

- Adds `nodeRuntimeAssessment` to JSON, separating installed Node.js binaries from project/container/CI version references and retaining a bounded, redacted inventory for both affected and baseline-not-affected exact versions.
- Adds `completionStatus` and a human-readable completion label so non-critical partial coverage is distinct from critical incompleteness and scanner errors.
- Adds synthetic regression coverage for safe and vulnerable installed/project Node.js separation and the non-critical partial completion label.

### Changed

- Prints compact installed-Node and project-reference counts separately in console and TXT summaries, preventing a vulnerable Dockerfile pin from being mistaken for a vulnerable global Node.js installation.
- Emits `SCAN_COMPLETED` only for `completionStatus=complete`; non-critical partial runs receive a single informational coverage finding instead.
- Documents that `notAffected` means no match in the shipped offline baseline, not a complete CVE, EOL, signature, or publisher-authenticity verdict.
- Retains `scanComplete`, `nodeRuntimeSummary`, and existing Node.js counters for compatibility.

### Fixed

- Removes the filename/marker-based exemption for the legacy Keyv/ChainDrop checker so a spoofed name cannot bypass IOC, GlassWorm, or secret-exfiltration behavior checks.
- Requires the explicit `-SyntheticValidation` switch and at least one accepted synthetic root before test-only Node.js/npm host-root overrides can replace normal discovery; distributed launcher runs clear inherited override variables.
- Binds scanner report exclusion to the configured report directory and exact current output files instead of every `reports*` path, and limits the repository Git ignore rule to `/reports/`.

## [0.1.20] - 2026-08-21

### Added

- Adds `coverage.summary` to JSON and compact coverage details to TXT/console output, including critical/non-critical failure totals, dependency and npm-cache coverage status, grouped reasons, and a bounded next action.
- Adds path-derived provenance labels to aggregated AI tooling capability summaries without treating those labels as publisher verification.
- Adds synthetic regression coverage for manual workflow triggers, active versus passive MCP/tooling execution, reference examples, HIGH Node.js priority entries, incomplete scan explanations, and npm cache limits.

### Changed

- Classifies `workflow_dispatch` alone as `CAUTION`; it remains `WARN` when combined with secrets, write permissions, or manual input consumed by a command step.
- Keeps unpinned `npx`/`uvx` in active MCP or agent command configuration at `WARN`, while passive tooling helpers are `CAUTION` capability findings.
- Classifies executable-looking AI reference examples and passive tooling fetch-execute capability as `CAUTION`; active config fetch-execute and secret-exfiltration compounds remain `DANGER`.
- Includes explicit project/container Node.js `HIGH` matches in `priorityFindings`, retaining the existing three-entry Node.js cap.
- Clarifies that a directory `PathTooLongException` can identify the containing directory when the exact child entry is unavailable.

## [0.1.19] - 2026-08-18

### Added

- Adds `CAUTION` between `WARN` and `INFO` for low-signal presence, capability, and posture findings that still merit human review.
- Adds `caution` counts to the overall, per-check, and per-source summaries and declares the severity order in JSON scanner metadata.

### Changed

- Reclassifies generic package lifecycle-script presence, isolated invisible Unicode, remote WebAssembly capability without a malicious compound, capability-only IDE artifacts, and similar passive execution surfaces from `WARN` to `CAUTION`.
- Keeps exit-code compatibility: both `WARN` and `CAUTION` return `1`; `DANGER` remains `2`.
- Adds synthetic regression assertions for the new severity contract while retaining existing `DANGER` detections.

## [0.1.18] - 2026-08-17

### Changed

- Makes console progress compact by default: a 30-second aggregate heartbeat without per-file paths, per-stage large-file output, or slow-step lines. `-VerboseProgress` restores the detailed five-second diagnostics, while `-Quiet` remains fully silent.
- Restricts VS Code-compatible extension classification to actual `.vscode`, `.vscode-insiders`, `.vscode-server`, and `.cursor` extension roots instead of every folder named `extensions`.
- Ignores dependency-owned `node_modules/**/package.json` Volta and engine metadata when identifying a project's selected Node.js runtime.
- Recognizes exact canonical setuptools `distutils-precedence.pth` content as an informational compatibility hook.
- Treats the bundled validation workflow as a scanner self-reference while retaining active behavior checks for external files regardless of filename or embedded identity markers.

### Fixed

- Keeps invisible-Unicode and GlassWorm detection enabled in the package/Node, AI/MCP/IDE, and CI/CD/hooks launcher profiles.
- Restricts custom menu item `8` to project-local checks so its current-folder label cannot silently enable npm global/cache or host Node.js discovery; broader host checks remain available through confirmed modes `6`, `7`, and `9`.
- Makes MajorLocations and UserProfile confirmation text disclose static npm and bounded Program Files/PATH/version-manager Node.js metadata where applicable.
- Replaces the absolute secret-content no-read claim with the actual boundary: known credential files are inventory-only, other in-scope configuration text is statically read, and secret-like report evidence is centrally redacted.
- Reports actual ChainDrop behavior-signal keys from ordered dictionaries instead of collection adapter properties such as `Count`, `Keys`, and `Values`.
- Tightens generic secret-harvest and external-execution compounds to avoid treating ordinary token variables or JavaScript regular-expression `.exec()` calls as execution/exfiltration by themselves.
- Prevents large JavaScript bundles from producing a GlassWorm decoder `DANGER` by combining unrelated `codePointAt`, Variation Selector range, and execution API references; decoder mapping is now locally coupled and requires an observed selector cluster for `DANGER`.
- Prevents MajorLocations from recursively scanning Codex session history and runtime cache. It now records only the selected profile configs, rules, skills, installed plugin tooling, and extension roots that were actually included instead of reporting the whole user profile as a scan root.
- Bounds GlassWorm decoder discovery with literal prefilters and small local regular-expression windows, avoiding multi-megabyte full-file decoder timeouts while preserving locally coupled decoder detection.
- Aggregates decoder examples without observed selectors in reference text, plus decoder-shaped text in session and cache contexts, instead of emitting one warning per inert example, transcript, or cache file; actual hidden selectors in reference text remain inspectable.

## [0.1.17] - 2026-08-14

### Added

- Adds `scanScope` to JSON/TXT/console summaries so bounded comprehensive, Deep, full-disk exclusion, and actual included surfaces are explicit.
- Adds per-file `iocData` freshness inventory with `releaseReady=false` for stale, missing, or invalid shipped datasets.
- Adds structural exact-version checks for `npm-shrinkwrap.json` and `Pipfile.lock` with critical coverage failure on malformed locks.
- Adds common Continue, Gemini, OpenCode, editor MCP, custom Codex/Claude config, Antigravity extension, and active AI instruction-file coverage.

### Changed

- Launcher mode 9 is labeled a comprehensive bounded scan and now includes MajorLocations in addition to its target, user profile, AllSafe checks, and endpoint telemetry; it remains non-Deep and non-full-disk.
- MajorLocations adds common GitHub/Documents/Desktop, IDE-default, and OneDrive/OneDriveCommercial/OneDriveConsumer project roots, while broader Node.js host checks add bounded local process-PATH and common version-manager roots.
- Known credential files under newly scanned AI configuration roots are inventoried without reading their contents.
- Refreshes the bounded IOC datasets from documented public sources, while labeling them as curated rather than an exhaustive live threat feed.
- Updates the official Node.js baseline with the July 2026 High advisories and their fixed versions, and expires July 2025 High entries under the declared 365-day retention policy.
- Adds the Keyv ChainDrop `npm-cache.com` domain IOC and a compound NodeReal endpoint plus campaign-contract marker without treating the shared RPC hostname alone as malicious.
- Bounds BOM-less UTF-16 encoding probes to the first 64 KiB, skips ordinary text decoding for known binary extensions after hash/artifact checks, and stops main or dependency-targeting traversal as soon as its file budget is exhausted.
- Replaces the repeated generic project phase label with the redacted project root and emits five-second progress heartbeats with enumerated, queued, scanned, and elapsed counters.
- Applies an explicit two-second timeout to every full-text regular-expression check, with a process-wide default as defense in depth; timed-out file checks are reported as incomplete coverage and remaining checks continue instead of consuming a CPU core indefinitely.
- Uses cheap secret/send anchor checks before evaluating the more expensive credential-harvest compound, avoiding pathological work on large generated files that contain no credential markers.
- Replaces full-text PowerShell character iteration in Variation Selector analysis with selector-only matching, caps analyzed selector matches and static cluster decode buffers at 8,192 each, performs a bounded tail-cluster check after the limit, caches repeated source-context classification, and excludes non-executable TypeScript declarations and source maps from npm runtime-entrypoint targeting.
- Emits per-stage progress for text candidates of at least 1 MiB and reports completed scanner steps that took at least two seconds, making the last expensive file and check visible during long scans.
- Computes finding line numbers in 64 KiB native string chunks instead of interpreted per-character PowerShell loops, preventing multi-megabyte generated or minified files from pinning a CPU core after a match.
- Caps targeted dependency files at 10,000 run-wide and fairly divides that budget across discovered projects with a 2,000-file per-project ceiling, preventing broad parent-folder scans from being dominated by a few large dependency trees.

### Security

- Stale historical IOCs remain active, but release readiness can no longer appear current when a shipped dataset is stale, missing, invalid, or has malformed freshness metadata.
- AI instruction files with fetch-execute or credential-send shaped guidance are surfaced as review candidates without treating text alone as proof of execution.
- Exact IOC hashes and IDE/native artifact metadata are still evaluated before binary-extension text skipping, preserving high-confidence artifact detection while avoiding unbounded PowerShell byte loops.

## [0.1.16] - 2026-08-13

### Security

- Detects the known GlassWorm Variation Selector decoder signature and consecutive payload clusters.
- Safely decodes the known Variation Selector byte mapping in memory for bounded static marker checks without executing or reporting decoded payload text.
- Adds `getSignaturesForAddress` and `getTransaction` to the existing compound Solana channel fingerprint.
- Refuses to overwrite existing TXT/JSON outputs, rejects identical report paths, and uses create-new writes to preserve target files under output-path mistakes or races.
- Quotes BAT status output for valid paths containing CMD metacharacters and validates custom check names before command-line expansion.
- Validates launcher modes and prompt responses without expanding untrusted text into CMD comparisons, including the incomplete-distribution confirmation path.
- Rejects extra launcher arguments and cancels an empty custom-check prompt instead of retaining the initial default selection.
- Builds decoder regression strings from split literals so this validation workflow needs no trust exception while generated external workflow content remains detectable.
- Adds focused malicious and benign synthetic regression coverage while preserving low-risk isolated emoji selector aggregation.

## [0.1.15] - 2026-08-12

### Added

- Offline Keyv/ChainDrop campaign data covering 443 package names and 2,235 exact package/version pairs.
- Structural npm lockfile v1/v2/v3, pnpm lockfile, Yarn lockfile, and installed-package checks.
- Bounded correlation checks for incident file hashes, lifecycle behavior, VS Code tasks, Claude `SessionStart` hooks, and GitHub Actions artifacts.
- `traversalComplete`, `directoryCoverageComplete`, `candidateCoverageComplete`, and `scanComplete` report fields.
- Positive and negative synthetic fixtures for campaign detections and common benign installer/release patterns.

### Changed

- Campaign IOC loading now validates a fixed approved package hash and exact bounded indicator sets before enabling the full snapshot.
- File hashing is streamed and respects the configured maximum file size.
- Critical lockfile parse, depth, access, and unsupported-format gaps are represented as incomplete scan coverage instead of a clean negative result.

### Security

- Tightened local script command resolution and Claude hook scoping to reduce path ambiguity and unrelated-config correlation.
- Preserved the offline-only, read-only, dependency-free, and no-secret-output guarantees.

[0.1.15]: https://github.com/Daiki9801/dev-supplychain-checker/commit/10fe64b21f58b9274168427beb167a3acb522feb
[0.1.16]: https://github.com/Daiki9801/dev-supplychain-checker
[0.1.17]: https://github.com/Daiki9801/dev-supplychain-checker
[0.1.18]: https://github.com/Daiki9801/dev-supplychain-checker
[0.1.19]: https://github.com/Daiki9801/dev-supplychain-checker
[0.1.20]: https://github.com/Daiki9801/dev-supplychain-checker
[0.1.21]: https://github.com/Daiki9801/dev-supplychain-checker
[0.1.22]: https://github.com/Daiki9801/dev-supplychain-checker
