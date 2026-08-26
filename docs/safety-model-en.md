# Safety Model

This document summarizes the safety guarantees and boundaries of `Dev Supply Chain IOC Checker`.

## Scope

The checker is a Windows PowerShell 5.1-compatible, dependency-free, offline, read-only triage tool for developer supply-chain indicators.

It does not prove that a host is clean, and it does not prove infection by itself. Findings are review candidates.

## Dependency-Free

The runtime consists of:

- `run-checker.bat`
- `Scan-DevSupplyChain.ps1`

No npm, pip, Python, Node.js, GitHub download helper, or external package is required to run the scanner.

## Offline

The scanner does not:

- contact the internet;
- fetch IOC updates;
- query npm, PyPI, GitHub, OpenVSX, or VS Code Marketplace;
- clone or archive GitHub repositories;
- run `curl`, `wget`, `iwr`, `irm`, `Invoke-WebRequest`, or `Invoke-RestMethod`.

GitHub repositories must be supplied as local folders by the user.

## Read-Only

The scanner does not:

- delete, fix, quarantine, uninstall, or rotate tokens;
- modify registry entries or settings;
- run package managers, target code, hooks, workflows, or build scripts;
- run `npm root -g` or `npm cache ls`.

Reports are written to `reports` unless another report directory is selected.

Existing files are never overwritten. Explicit `-TextOut` and `-JsonOut` paths must be different and unused; default timestamp collisions receive an unused suffix.

## Secret Handling

Known auth files are inventory-only where possible. The scanner reports existence but does not print secret values or auth file contents.

Other in-scope configuration text is read for static matching. Secret-like evidence and exception text pass through central redaction before TXT/JSON output.

Examples:

- `.codex\auth.json`
- `.npmrc`
- `.pypirc`
- `.netrc`
- SSH private keys
- cloud credentials
- kube configs

All evidence passes through central redaction before report output.

## Opt-In Modes

The following are explicit modes only:

- MajorLocations scan
- UserProfile scan
- EndpointTelemetry scan
- Comprehensive bounded scan (legacy command name: `full`)

The BAT launcher requires `YES` before running broader real-PC checks.

`full` combines the explicit target, MajorLocations, UserProfile, static npm global/cache, known-path/PATH Node.js metadata, and EndpointTelemetry. It is neither full-disk nor Deep traversal. The report's `scanScope` records the actual included and excluded surfaces.

MajorLocations alone selects active Codex config, agents, rules, skills, and installed plugin tooling without reading `.codex\sessions`, runtime cache, or history data. UserProfile or `full` may read those text surfaces, but treats them as non-executable, lower-priority aggregates. Environment-defined automatic Codex, Claude, and OneDrive roots are accepted only as absolute non-reparse child directories under `USERPROFILE`; external roots require an explicit `-Path` scan.

## Safe Enumeration

The scanner:

- skips reparse points by default;
- enforces file count and file size limits;
- skips likely binary files for text decoding;
- continues on access denied;
- avoids broad dependency directory recursion where targeted metadata is safer.

`NodeRuntime` does not launch Node.js. It reads explicit project version declarations and, only in broader host scopes, Windows file-version metadata from bounded known locations and existing process-PATH directories. Upstream `Critical`/`High` labels remain separate from scanner `WARN`/`INFO` severity. `nodeRuntimeAssessment` separates installed binaries from project references and records at most 100 exact evaluated versions with redacted paths. `notAffected` is limited to the shipped offline baseline and is not complete CVE, EOL, signature, or publisher verification.

The report's `iocData` section records freshness per shipped dataset. Any stale, missing, or invalid dataset makes `releaseReady=false` without disabling historical exact indicators.

## Scanner Artifacts

The checker treats its own generated artifacts specially.

- `tests/samples` contains synthetic fixtures and is skipped only when manifest-verified during parent scans.
- Unknown or modified sample files are scanned normally.
- End-user archives should omit the synthetic fixture bodies and keep only `tests/samples/manifest.json` plus `tests/samples/README.md`. The source repository keeps fixture bodies for maintainer regression tests.
- Tradeoff: lightweight archives cannot run the synthetic fixture scan. This only removes the local validation samples from the archive; it does not remove scanner detections, IOC data, report output, or real target scanning.
- The configured report directory (default `reports/`) and current report output files are skipped during normal scans; unrelated `reports-*` source directories are not treated as scanner output.
- Explicitly scanning a report folder still scans it.
- Only the default repository-root `/reports/` directory is ignored by Git. Custom or legacy report directories must be reviewed explicitly and should not be committed or distributed as source.

## Severity Meaning

| Severity | Meaning |
|---|---|
| `DANGER` | High-priority candidate such as exact known IOC, active exfiltration pattern, or active execution configuration. |
| `WARN` | Higher-priority review candidate such as a stronger suspicious pattern, known risk, or security weakness. |
| `CAUTION` | Lower-signal presence, capability, or posture finding without a strong malicious compound. |
| `INFO` | Inventory, limitation, aggregation, or context. |
| `OK` | Scan completed or no candidate finding. |

`WARN` and `CAUTION` both return exit code `1`; the extra level changes triage priority without breaking existing automation.

AI tooling capability findings mean a skill/plugin can access a network/API/install/write surface. Passive tooling and reference examples are normally `CAUTION`; active command configuration and strong execution/exfiltration compounds remain higher priority. Path-derived provenance labels are context only and do not verify a publisher.

## Limits

`completionStatus=complete` means only that planned checks completed inside the selected bounded scope. It does not mean full-disk, exhaustive dependency, archive, binary, or vulnerability coverage. `partial-non-critical` identifies a declared non-critical gap; `incomplete-critical` and `error` must not be used as completed negative results.

Every full-text regex operation is limited to two seconds. `REGEX_SCAN_TIMEOUT` skips only the affected operation for that file and allows the rest of the scan to continue, but the run cannot be `complete`. A non-critical candidate produces `partial-non-critical`; a critical candidate such as a lockfile or active configuration produces `incomplete-critical`. This prevents an untrusted pathological input from consuming a CPU indefinitely; it also creates a documented blind spot that requires narrower or manual review.

The checker is not a replacement for EDR, AV, SIEM review, memory forensics, network forensics, package-manager audit services, or incident response. It cannot confirm infection or prove that compromise is absent.

It does not perform whole-disk traversal, live process or network inspection, general binary reverse engineering, full YAML/TOML semantic parsing, complete dependency/CVE resolution, online reputation checks, registry popularity checks, signature/provenance verification, maintainer trust checks, or slopsquatting detection without exact offline IOCs.
