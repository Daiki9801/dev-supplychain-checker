# Local IOC Data

This directory contains manually curated offline IOC data.

The scanner never downloads IOC updates. Update these files only after manual review of trusted advisories, vendor posts, incident reports, or internal security guidance.

## Files

- `known-packages.json`: exact package ecosystem, name, and version matches.
- `known-extensions.json`: platform-qualified IDE extension/plugin ID and version matches. Missing `platform` means `vscode`; JetBrains entries use `platform: jetbrains`.
- `known-files.json`: fixed path, filename, path pattern, or optional SHA-256 file indicators.
- `known-actions.json`: GitHub Action repositories, known compromised commits, and historically affected mutable refs.
- `known-node-runtimes.json`: official Node.js Critical and recent-High advisory version ranges used for static runtime-version comparison.
- `suspicious-patterns.json`: bounded regex patterns and domain/IP text indicators.

## Update Rules

- Add only exact package versions or exact extension versions unless there is a verified wildcard advisory.
- Keep IDE identities platform-qualified. A VS Code/OpenVSX ID must not match a JetBrains plugin ID with the same text.
- For JetBrains, prefer the `<id>` from `META-INF/plugin.xml`. Name fallback requires `allowNameFallback: true` and is capped at `WARN` unless exact ID/version or hash evidence is also available.
- Do not paste secrets, token values, private URLs, or incident-specific confidential evidence into IOC files.
- Keep `lastUpdated`, `sourceSet`, and `expiresAfterDays` current.
- Prefer `DANGER` for known-bad IOC matches and `WARN` for behavioral or marker-only patterns.
- Do not add incomplete package lists from mass-campaign news. Add only entries that have been individually verified.
- Broad campaign family names without exact affected versions belong in scanner watchlist context, not in exact IOC JSON.
- npm cache metadata hits should remain `WARN` or `INFO` context unless the same package/version is also installed or executable behavior is present.
- Node.js advisory entries must use official `nodejs.org` security-release sources, exact half-open affected ranges, and fixed versions for each listed major. The header must remain `schemaVersion=0.1.14`, `expiresAfterDays=30`, and `highRetentionDays=365`; a malformed header or local conflict cannot override the built-in baseline.

## Current Manual Baseline

The 2026-07-15 baseline includes manually reviewed public vendor and security-research reporting for:

- Axios/plain-crypto-js package compromise indicators.
- GlassWorm/OpenVSX compromised extension versions.
- A reported Axios/plain-crypto-js Windows persistence filename.
- GlassWorm-style C2 marker patterns that require manual review when found in executable context.
- Shai-Hulud style payload and workflow markers such as `setup_bun.js`, `bun_environment.js`, `actionsSecrets.json`, `truffleSecrets.json`, discussion-triggered self-hosted workflow execution, and secrets artifact packaging.
- Watchlist context for reported npm campaign family names is handled in the scanner as low-confidence `INFO`, not as exact local IOC data.
- AsyncAPI, Jscrambler, Injective, Bitwarden CLI, React Native, SAP CAP, and payment-brand typosquat package incidents with exact affected versions.
- The `codfish/semantic-release-action` compromised commits and historically affected mutable refs. Exact bad commits are `DANGER`; historical refs remain `WARN` because the scanner cannot resolve their current target offline.
- GlassWASM/OpenVSX WASM, VSIX, and native installer hashes, plus the `dodod.lat` campaign domain and a marker-only wallet identifier.
- Python Miasma/Hades-style `*-setup.pth`, `_index.js`, `.bun_ran`, and Bun bootstrap behavior.
- Node.js official Critical releases from 2020 onward and High releases within the manually maintained 365-day window as of 2026-07-15. These are static version indicators, not proof that vulnerability preconditions are reachable.

The Node.js runtime baseline uses only official Node.js security-release pages: February 2020, September 2020, February 2021, July 2025, December 2025/January 2026, March 2026, and June 2026. Each advisory entry stores its exact source URL, publication date, affected half-open ranges, fixed versions by major, and additional conditions. Review date: 2026-07-15.

The review set was compiled from vendor advisories and public research published by Aikido, Socket, Jscrambler, Bitwarden, GitHub, and incident-response researchers. Every exact IOC records a review date and should be removed or downgraded only when a trusted correction shows that the value was inaccurate.

## Deliberate Exclusions

- `ExarGD/vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1` are not ID/version IOC entries because the same identity was reported across different registries with conflicting provenance. They require a matching hash or suspicious behavior.
- No production JetBrains IOC is included without a separately verified ID/version or artifact hash. v0.1.13 implements the schema and bounded detection path without inventing indicators.
- General Node.js CVE coverage, EOL classification, registry resolution, and binary authenticity verification remain outside scope; only the bounded offline runtime advisory baseline is evaluated.
- npm v12 script restrictions are preventive guidance, not evidence that an installed package is safe or malicious.
