# Local IOC Data

This directory contains manually curated offline IOC data.

The scanner never downloads IOC updates. Update these files only after manual review of trusted advisories, vendor posts, incident reports, or internal security guidance.

## Files

- `known-packages.json`: exact package ecosystem, name, and version matches.
- `known-extensions.json`: exact VS Code/OpenVSX-compatible extension ID and version matches.
- `known-files.json`: fixed path, filename, path pattern, or optional SHA-256 file indicators.
- `suspicious-patterns.json`: bounded regex patterns and domain/IP text indicators.

## Update Rules

- Add only exact package versions or exact extension versions unless there is a verified wildcard advisory.
- Do not paste secrets, token values, private URLs, or incident-specific confidential evidence into IOC files.
- Keep `lastUpdated`, `sourceSet`, and `expiresAfterDays` current.
- Prefer `DANGER` for known-bad IOC matches and `WARN` for behavioral or marker-only patterns.
- Do not add incomplete package lists from mass-campaign news. Add only entries that have been individually verified.
- Broad campaign family names without exact affected versions belong in scanner watchlist context, not in exact IOC JSON.
- npm cache metadata hits should remain `WARN` or `INFO` context unless the same package/version is also installed or executable behavior is present.

## Current Manual Baseline

The 2026-06-24 baseline includes manually reviewed public reporting for:

- Axios/plain-crypto-js package compromise indicators.
- GlassWorm/OpenVSX compromised extension versions.
- A reported Axios/plain-crypto-js Windows persistence filename.
- GlassWorm-style C2 marker patterns that require manual review when found in executable context.
- Shai-Hulud style payload and workflow markers such as `setup_bun.js`, `bun_environment.js`, `actionsSecrets.json`, `truffleSecrets.json`, discussion-triggered self-hosted workflow execution, and secrets artifact packaging.
- Watchlist context for reported npm campaign family names is handled in the scanner as low-confidence `INFO`, not as exact local IOC data.
