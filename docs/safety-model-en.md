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

## Secret Handling

Known auth files are inventory-only where possible. The scanner reports existence but does not print secret values or auth file contents.

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

- UserProfile scan
- EndpointTelemetry scan
- Full scan

The BAT launcher requires `YES` before running broader real-PC checks.

## Safe Enumeration

The scanner:

- skips reparse points by default;
- enforces file count and file size limits;
- skips likely binary files for text decoding;
- continues on access denied;
- avoids broad dependency directory recursion where targeted metadata is safer.

## Scanner Artifacts

The checker treats its own generated artifacts specially.

- `tests/samples` contains synthetic fixtures and is skipped only when manifest-verified during parent scans.
- Unknown or modified sample files are scanned normally.
- The running checker folder's own `reports*` directories are skipped during normal scans as of v0.1.11.
- Explicitly scanning a report folder still scans it.
- Generated `reports*/` directories are ignored by Git and should not be committed or distributed as source.

## Severity Meaning

| Severity | Meaning |
|---|---|
| `DANGER` | High-priority candidate such as exact known IOC, active exfiltration pattern, or active execution configuration. |
| `WARN` | Review candidate, risky posture, or capability. |
| `INFO` | Inventory, limitation, aggregation, or context. |
| `OK` | Scan completed or no candidate finding. |

AI tooling capability warnings mean a skill/plugin can access a network/API/install/write surface. They are not infection proof by themselves.

## Limits

The checker is not a replacement for EDR, AV, SIEM review, memory forensics, network forensics, package-manager audit services, or incident response.

It does not perform full YAML/TOML semantic parsing, online reputation checks, registry popularity checks, maintainer trust checks, or slopsquatting detection without exact offline IOCs.

