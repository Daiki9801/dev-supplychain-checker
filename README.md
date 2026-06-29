# Dev Supply Chain IOC Checker

Dependency-free Windows developer environment supply-chain IOC checker.

This tool is a BAT launcher plus a single Windows PowerShell 5.1-compatible scanner. It performs offline, read-only static checks against project files, package metadata, CI/CD workflows, MCP/AI-agent configs, IDE extensions, and optional endpoint telemetry.

## Safety Model

- No external dependencies.
- No network access or online IOC update.
- No target project code execution.
- No remediation, deletion, uninstall, registry modification, quarantine, or cleanup.
- No secret values are printed to TXT or JSON reports.
- User profile and endpoint telemetry scans are opt-in only.

For distribution and non-technical users, see [安全性と設計上の約束](docs/safety-model-ja.md).

## Usage

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

- `Recommended`: default project-local static checks. Does not read npm global/cache.
- `MajorRecommended`: `Recommended` plus static npm global package roots.
- `AllSafe`: all non-telemetry static checks, including static npm global/cache.
- `Packages`, `LifecycleScripts`, `InvisibleUnicode`, `CiCd`, `AiMcp`, `IdeExtensions`, `HooksAndTasks`, `SecretsInventory`, `NpmGlobal`, `NpmCache`, `ScannerSelf`.

`UserProfile` and `EndpointTelemetry` are still explicit mode switches, not `-Checks` names.

Run the single BAT launcher:

```bat
run-checker.bat
```

For distributed use, run `run-checker.bat` from the extracted checker folder. The folder should contain `Scan-DevSupplyChain.ps1`, `run-checker.bat`, `README.md`, `iocs`, and `tests\samples\manifest.json`. If the launcher sees an incomplete copy, it prints a warning and requires typing `YES` before continuing.

Non-interactive synthetic validation can call the launcher with a path and no pause:

```bat
run-checker.bat current .\tests\samples\clean-js --no-pause
```

The `userprofile` and `full` launcher modes ask for explicit confirmation before scanning real user profile or endpoint telemetry data:

```bat
run-checker.bat major
run-checker.bat userprofile
run-checker.bat full C:\Path\To\Project
```

`major` scans common developer folders plus IDE and AI-agent metadata. It does not scan the whole `C:\` drive and does not include endpoint telemetry.

The launcher also provides risk-specific modes for package-only, AI/MCP/IDE-only, CI/CD-only, and npm global/cache static checks. The npm static mode reads bounded candidate folders only; it does not execute `npm root -g`, `npm cache ls`, `node`, or package scripts.

GitHub repositories are not downloaded by this tool. To check a GitHub repository, manually obtain a local copy using your normal approved process, then scan that local folder with `-Path` or `run-checker.bat path`.

## Reports

Reports are written as UTF-8 with BOM:

- `dev-supplychain-report-YYYYMMDD-HHMMSS.txt`
- `dev-supplychain-report-YYYYMMDD-HHMMSS.json`

Findings use `DANGER`, `WARN`, `INFO`, and `OK`.

TXT reports also show:

- `PathType`: whether the path is a file, directory, virtual target, or unknown.
- `Line`: the line number when a text finding can be located safely.
- `SourceContext`: `normal`, `synthetic-sample`, `scanner-self`, `scanner-artifact`, `scanner-artifact-sample`, `scanner-artifact-untrusted`, `cache`, `dependency-metadata`, `active-ai-config`, `executable-tooling`, `reference-text`, `session-log`, `cache-data`, or `plugin-metadata`.

JSON reports include `scanStats` with scan roots, scanned/skipped file counts, synthetic sample skips, and npm cache blob skips.
They also include `selectedChecks`, `expandedChecks`, `skippedChecks`, `summaryByCheck`, `checkStats`, `summaryBySourceContext`, `priorityFindings`, `scanner.scriptPathRedacted`, `scanner.launcherPathRedacted`, and `scanner.distributionStatus`, which helps identify reports produced by an older copy, script-only copy, or a BAT outside the intended folder.

Every finding includes `check` and `detectionMethod` so a report can show whether a result came from package metadata, lifecycle/static code scanning, CI/CD text scanning, AI/MCP config scanning, static npm global roots, npm cache metadata, or inventory-only checks.

`.codex` files are not ignored. The scanner separates active configs and executable tooling from reference text, session logs, cache data, and plugin metadata so documentation examples do not hide real executable findings.

## Local IOC Updates

The scanner uses a small built-in IOC baseline plus optional local JSON files under `iocs/`.
These files are offline data only; the scanner does not fetch or refresh IOC data from the internet.

The current local baseline includes manually reviewed indicators for Axios/plain-crypto-js, GlassWorm/OpenVSX extension versions, Shai-Hulud style payload markers, and selected C2 or persistence markers.
For mass supply-chain campaigns, add only individually verified package or extension versions. Do not paste incomplete news-derived package lists into the IOC files. Broad campaign names such as TanStack, Mistral, and Red Hat npm families are treated as low-confidence context unless an exact bad version or strong behavior chain is also present.

See [Local IOC Data](iocs/README.md) before updating IOC JSON.

## Public Repository Safety

This repository includes GitHub publication support files:

- `.github/workflows/validate.yml`: parser, JSON, and synthetic-sample validation on Windows.
- `.github/dependabot.yml`: GitHub Actions update PRs only.
- `.github/CODEOWNERS`: commented template; replace the owner before enabling Code Owner review.
- `SECURITY.md`: vulnerability reporting scope and safety expectations.
- `CONTRIBUTING.md`: contribution and validation rules.
- `docs/github-publication-checklist-ja.md` / `docs/github-publication-checklist-en.md`: recommended GitHub settings for a public repository.

Japanese companion docs are also available for [security policy](docs/security-policy-ja.md) and [contribution rules](docs/contributing-ja.md).

The workflow uses synthetic samples only. It must not run real `-UserProfile`, `-EndpointTelemetry`, npm, git clone/fetch/pull, node, python, or network retrieval commands.

## Validation

Only run synthetic validation against `tests/samples` unless a human explicitly asks for real host scans.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -ReportDir .\reports
```

The `tests/samples` directory contains hand-written synthetic fixtures. They were not downloaded, are not real malware, and are expected to produce `WARN`/`DANGER` findings when scanned directly. Parent-directory and Major PC scans skip only manifest-verified fixture files matching the currently running checker distribution. Unrelated projects named `tests/samples`, unknown sample files, modified sample files, and fake scanner folders are scanned normally.

Generated `reports*/` directories are ignored by Git and are skipped during normal scans when they are directly under the running checker folder. This prevents historical reports or validation artifacts from being re-detected as current target risks. Scan a report folder explicitly with `-Path` only when reviewing report contents intentionally.

## Important Limits

This is a triage tool, not proof that a host is clean. It does not replace EDR, memory forensics, package-manager audit tools, SIEM review, or incident response.
