# AGENTS.md

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

* Do not add external runtime dependencies to the delivered tool.
* The delivered scanner itself must not make network calls or require network access.
* During implementation, review, or testing, network access and external-service use are prohibited by default. They may be used only with prior, explicit human approval for the specific purpose or bounded operation. Such approval does not authorize adding network behavior to the scanner or changing its offline-only requirement.
* Commands or tools that can access the network, including package managers, `curl`, `wget`, `iwr`, `irm`, `Invoke-WebRequest`, `Invoke-RestMethod`, `Start-BitsTransfer`, `certutil` URL retrieval, `bitsadmin`, MCP servers, app plugins, browser automation, connector tools, and remote file tools, require prior explicit human approval before use.
* Do not install packages or dependencies with npm, pnpm, yarn, bun, pip, or similar package managers unless the human explicitly approves that installation. Approved development-only tooling must not become a runtime dependency of the delivered scanner.
* Local read-only Git inspection is allowed without approval, including `git status`, `git diff`, `git log`, `git show`, and `git rev-parse`.
* Git operations that access a remote or modify repository/worktree/history state require prior explicit human approval. This includes, but is not limited to, `git clone`, `git fetch`, `git pull`, `git submodule update`, `git checkout`, `git switch`, `git restore`, `git reset`, `git add`, `git commit`, `git merge`, `git rebase`, and `git push`.
* Do not implement remediation, deletion, uninstall, token rotation, registry modification, quarantine, or cleanup features. The scanner must remain read-only.
* Do not print secrets, tokens, API keys, SSH private keys, environment variable values, or contents of auth files.
* Do not run the scanner against the real user profile unless explicitly approved by the human.
* Do not run EndpointTelemetry against the real host unless explicitly approved by the human.

## Approval gate for real-host reads

Do not invoke a scanner mode or check that reads outside the explicitly requested project or synthetic test root without prior, explicit human approval for that real-host read. Metadata reads, existence checks, directory enumeration, registry reads, event-log reads, and cache or package metadata reads all count as real-host reads even when they are read-only.

This approval gate includes, but is not limited to:

* `-UserProfile`, `-MajorLocations`, and `-EndpointTelemetry`.
* `-Checks MajorRecommended` and `-Checks AllSafe`.
* `NpmGlobal` and `NpmCache` checks.
* `NodeRuntime` host-known-path discovery caused by a mode or check macro.
* BAT launcher modes that expand to any of the above.

A human may approve either an exact command or a clearly named scanner mode/check and host scope. Approval of a named mode/check covers the normal read-only roots that the current implementation resolves for that mode/check, provided the scope is not materially broadened afterward.

Before execution, state the command to be run, the requested mode/check, the host-scope categories it will read, and the expected read-only impact. Exact enumeration of every resolved path is required only when a path is outside the normal scope of the approved mode/check, is ambiguous, or materially broadens the approved scope.

A request to implement, review, validate, or test the scanner is not by itself approval to inspect the real host. If approval is absent or ambiguous, use project-local or synthetic validation instead. Do not substitute a different host-scanning path as a workaround.

Automated validation should use synthetic directories inside this repository by default. Host-scope logic may be exercised against the real host only when that specific real-host scope has been explicitly approved. When using synthetic redirection, verify that relevant roots cannot fall back to `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%ProgramFiles%`, the registry, event logs, or another real-host location.

## Allowed validation

Without additional approval, you may:

* Run PowerShell parser checks.
* Execute the scanner against synthetic files under `tests/samples` or temporary test directories created inside this repository.
* Use local read-only Git inspection commands.
* Use already-installed local development tools such as Python or Node only when they are genuinely useful for validation and do not add dependencies, access the network, or modify external state.

Example:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\\Scan-DevSupplyChain.ps1 -Path .\\tests\\samples
```

The following require prior explicit human approval because they access the real host, access a network/remote service, install dependencies, or modify Git state:

```powershell
.\\Scan-DevSupplyChain.ps1 -UserProfile
.\\Scan-DevSupplyChain.ps1 -EndpointTelemetry
pip install <package>
git fetch
git commit -m "..."
git clone https://example.com/repo.git
curl https://example.com
Invoke-WebRequest https://example.com
```

## Implementation standards

* Keep the implementation in a single main PowerShell file unless there is a strong reason to split.
* BAT files must be thin launchers only.
* Prefer static file parsing and regex scanning.
* YAML/TOML do not need full parsers; use safe line-based scanning.
* JSON may use `ConvertFrom-Json` with text fallback.
* Use targeted scanning for `node_modules`, `.venv`, and `vendor`; do not recursively read everything by default.
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
2. The delivered scanner remains dependency-free, offline-only, and read-only.
3. The implementation does not violate the safety rules.
4. Targeted synthetic tests or sample runs pass where applicable; explicitly approved real-host validation may be used when relevant.
5. The final response includes changed files, validation commands, validation results, and any skipped validation with reason.
