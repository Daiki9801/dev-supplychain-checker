\# AGENTS.md

## Project

This repository implements a dependency-free Windows developer environment supply-chain IOC checker.

The final tool must be:

* A BAT launcher plus a PowerShell scanner.
* Compatible with Windows PowerShell 5.1.
* Dependency-free.
* Offline-only.
* Read-only.
* Safe for security triage.

## Non-negotiable safety rules

Do not add external dependencies.
Do not use npm, pnpm, yarn, bun, pip, python, node, curl, wget, iwr, irm, Invoke-WebRequest, Invoke-RestMethod, Start-BitsTransfer, certutil URL retrieval, or bitsadmin during implementation or tests.
Do not run shell git commands such as git clone, git fetch, git pull, git submodule update, git checkout, git push, or git commit.
Using the Codex App diff/review UI is allowed, but shell git commands are not allowed unless the human explicitly approves a specific command.
Do not use network calls.
Do not use MCP servers, app plugins, browser automation, connector tools, or remote file tools for this project.
Do not implement remediation, deletion, uninstall, token rotation, registry modification, quarantine, or cleanup features.
Do not print secrets, tokens, API keys, SSH private keys, environment variable values, or contents of auth files.
Do not run the scanner against the real user profile unless explicitly asked by the human.
Do not run EndpointTelemetry against the real host unless explicitly asked by the human.

## Mandatory approval gate for real-host reads

Do not invoke any scanner mode or check that can read outside the explicitly requested project or synthetic test root without prior, explicit human approval for that real-host read. Metadata reads, existence checks, directory enumeration, registry reads, event-log reads, and cache or package metadata reads all count as real-host reads even when they are read-only.

This approval gate includes, but is not limited to:

* `-UserProfile`, `-MajorLocations`, and `-EndpointTelemetry`.
* `-Checks MajorRecommended` and `-Checks AllSafe`.
* `NpmGlobal` and `NpmCache` checks.
* `NodeRuntime` host-known-path discovery caused by a mode or check macro.
* BAT launcher modes that expand to any of the above.

Before requesting approval, expand all check macros and state the exact command, normalized target roots, candidate host roots, metadata types to be read, and expected read-only impact. A request to implement, review, validate, or test the scanner is not approval to inspect the real host. The names `AllSafe` and `MajorRecommended` are not approval by themselves.

If explicit approval is absent, ambiguous, or does not cover every resolved real-host root, stop before invoking the scanner. Do not continue with a narrower host scan, a different launcher, a direct PowerShell invocation, or another tool as a workaround. Use project-local `Recommended` validation or ask one focused approval question instead.

Automated validation may exercise host-scope logic only when every relevant root is redirected to synthetic directories inside this repository through the validation-only environment variables. Verify the resolved roots before execution and stop if any check can fall back to `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%ProgramFiles%`, the registry, event logs, or another real-host location.

## Allowed validation

You may run PowerShell parser checks and execute the scanner only against synthetic files under tests/samples or temp test directories created inside this repository.

Allowed examples:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\\\\Scan-DevSupplyChain.ps1 -Path .\\\\tests\\\\samples
```

Forbidden examples:

```powershell
.\\\\Scan-DevSupplyChain.ps1 -UserProfile
.\\\\Scan-DevSupplyChain.ps1 -EndpointTelemetry
npm test
pip install
python setup.py
node script.js
git clone https://example.com/repo.git
curl https://example.com
Invoke-WebRequest https://example.com
```

## Implementation standards

* Keep the implementation in a single main PowerShell file unless there is a strong reason to split.
* BAT files must be thin launchers only.
* Prefer static file parsing and regex scanning.
* YAML/TOML do not need full parsers; use safe line-based scanning.
* JSON may use ConvertFrom-Json with text fallback.
* Use targeted scanning for node\_modules, .venv, and vendor; do not recursively read everything by default.
* Avoid junction/reparse-point loops.
* Skip likely binary files unless checking filename/hash metadata.
* Enforce maximum file size limits.
* Produce both TXT and JSON reports.
* Use DANGER / WARN / INFO / OK severity.
* Findings must include category, title, path, line if available, evidence, and recommendation.
* Redact user profile paths where practical.

## Done means

A task is complete only when:

1. The requested files are created or modified.
2. The tool remains dependency-free and offline.
3. The implementation does not violate the safety rules.
4. Synthetic tests or sample runs pass where applicable.
5. The final response includes changed files, validation commands, validation results, and any skipped validation with reason.

```

