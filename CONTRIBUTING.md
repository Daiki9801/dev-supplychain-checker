# Contributing

Thank you for helping improve this checker.

## Safety Rules

Contributions must preserve the tool's core contract:

- dependency-free;
- offline-only;
- read-only;
- compatible with Windows PowerShell 5.1;
- no target project code execution;
- no secret values or auth file contents in reports.

Do not add package-manager dependencies or runtime installers.

Do not add GitHub Actions, scripts, or documentation that require contributors to run `npm`, `pip`, `node`, `python`, network download commands, or real-host telemetry to validate ordinary changes.

## Validation

Use synthetic samples only unless a maintainer explicitly requests a real-host validation.

Recommended local checks:

```powershell
$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\Scan-DevSupplyChain.ps1),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors
```

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Scan-DevSupplyChain.ps1 -Path .\tests\samples -ReportDir .\reports -Quiet
```

Do not run validation with `-UserProfile`, `-EndpointTelemetry`, or full real-host scans unless the maintainer explicitly asks for that scope.

The synthetic sample scan is expected to return a non-zero exit code when it detects DANGER fixtures. Treat parser errors, missing reports, unreadable JSON, or missing report contract fields as failures.

## Pull Requests

Keep changes focused. Include:

- what detection or report behavior changed;
- which synthetic samples were added or updated;
- validation commands and results;
- any expected false positives or false negatives.

For IOC updates, include a source reference and add only verified exact package or extension versions as high-confidence indicators.
