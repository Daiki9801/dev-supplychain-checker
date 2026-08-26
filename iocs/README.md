# Local IOC Data

This directory contains manually curated offline IOC data. It is a bounded incident-response baseline, not a complete malware feed or a substitute for current vendor, registry, EDR, or threat-intelligence data.

The scanner never downloads IOC updates. Update these files only after manual review of trusted advisories, vendor posts, incident reports, or internal security guidance.

## Files

- `known-packages.json`: exact package ecosystem, name, and version matches.
- `known-extensions.json`: platform-qualified IDE extension/plugin ID and version matches. Missing `platform` means `vscode`; JetBrains entries use `platform: jetbrains`.
- `known-files.json`: fixed path, filename, path pattern, or optional SHA-256 file indicators.
- `known-actions.json`: GitHub Action repositories, known compromised commits, and historically affected mutable refs.
- `known-node-runtimes.json`: official Node.js Critical and recent-High advisory version ranges used for static runtime-version comparison.
- `campaign-keyv-chaindrop-20260806.json`: fixed, reviewable Keyv ChainDrop campaign snapshot with exact package/version pairs, file hashes, marker patterns, and a bounded Git ref.
- `suspicious-patterns.json`: bounded regex patterns and domain/IP text indicators.

## Update Rules

- Add only exact package versions or exact extension versions unless there is a verified wildcard advisory.
- Keep IDE identities platform-qualified. A VS Code/OpenVSX ID must not match a JetBrains plugin ID with the same text.
- For JetBrains, prefer the `<id>` from `META-INF/plugin.xml`. Name fallback requires `allowNameFallback: true` and is capped at `WARN` unless exact ID/version or hash evidence is also available.
- Do not paste secrets, token values, private URLs, or incident-specific confidential evidence into IOC files.
- Keep `lastUpdated`, `sourceSet`, and `expiresAfterDays` current.
- Keep `sourceUrls` and `scope` accurate when a dataset uses them. `scope` must make deliberate coverage limits explicit.
- Never advance `lastUpdated` or extend `expiresAfterDays` merely to clear a warning. The date means the complete dataset was manually compared with its documented trusted sources.
- Before publication, run a synthetic report and require `iocData.releaseReady=true`. This means the shipped bounded datasets passed their own freshness contracts; it does not mean all public malware indicators are present. A stale dataset continues to supply historical exact matches but blocks publication readiness.
- Prefer `DANGER` for known-bad IOC matches and `WARN` for behavioral or marker-only patterns.
- Do not add incomplete package lists from mass-campaign news. Add only entries that have been individually verified.
- Broad campaign family names without exact affected versions belong in scanner watchlist context, not in exact IOC JSON.
- npm cache metadata hits should remain `WARN` or `INFO` context unless the same package/version is also installed or executable behavior is present.
- Node.js advisory entries must use official `nodejs.org` security-release sources, exact half-open affected ranges, and fixed versions for each listed major. The header must remain `schemaVersion=0.1.14`, `expiresAfterDays=30`, and `highRetentionDays=365`; a malformed header or local conflict cannot override the built-in baseline.
- Campaign snapshots are loaded all-or-nothing. Keep `schemaVersion`, `campaignId`, exact counts, unique lower-case package names, exact semantic versions, and `integrity.sha256` consistent. The package digest, three file hash/path indicators, four marker names, and Git ref must also match the scanner's embedded approved snapshot values; recomputing a digest after changing the JSON does not authorize the change. A missing, malformed, truncated, unapproved, or count/hash-mismatched file falls back to the small built-in safety baseline and emits a coverage warning.
- Do not silently replace campaign source metadata. Record the supplied artifact hashes, review date, review-after period, and whether the source was independently reverified. This checker never performs that reverification online.

## Keyv ChainDrop Snapshot (2026-08-12)

`campaign-keyv-chaindrop-20260806.json` contains 443 package names and 2,235 exact package/version pairs transcribed from the incident checker and report supplied for this update. It also contains three supplied SHA-256 indicators, four marker patterns, and one bounded Git-ref indicator. The package/version canonical digest is `7da86fddcb4bc5c4352d3f2120903a07314ae2ce3071d980061862bcbc8aa497`.

An exact installed-package or structurally parsed lockfile match is `DANGER`. A manifest constraint, cache-only occurrence, fallback-text occurrence, or marker-only match is capped at `WARN` unless independent execution, persistence, exfiltration, or exact-hash evidence corroborates it. This prevents incident write-ups and benign release tooling from becoming false `DANGER` findings.

The snapshot records the SHA-256 of the supplied BAT and report. On 2026-08-14, the package-family names and three reported payload hashes were cross-checked against Aikido's public Keyv incident report. All 16 package names explicitly listed by that report were present in the snapshot. Aikido reports an aggregate of at least 444 packages across 1,381 versions, which differs from this supplied snapshot's 443 names and 2,235 exact pairs; the article does not publish a complete pair list that can safely resolve the difference. The full source CSV was therefore not independently reconstructed or speculatively changed, and the snapshot's original provenance status remains unchanged. Review or replace it after its 30-day review window using approved, independently verified sources.

## Current Manual Baseline (reviewed 2026-08-14)

The bounded baseline includes manually reviewed public vendor and security-research reporting for:

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
- Node.js official Critical releases from 2020 onward and High releases within the manually maintained 365-day window as of 2026-08-14. These are static version indicators, not proof that vulnerability preconditions are reachable.

The Node.js runtime baseline uses only official Node.js security-release pages: February 2020, September 2020, February 2021, December 2025/January 2026, March 2026, June 2026, and July 2026. High advisories older than the declared 365-day retention window are removed; Critical history is retained. Each advisory entry stores its exact source URL, publication date, affected half-open ranges, fixed versions by major, and additional conditions. Review date: 2026-08-14.

The 2026-08-14 refresh used official OSV npm/PyPI snapshots, GitHub's public global-advisory API, public npm package metadata, the official Node.js July 2026 security release, Aikido's Keyv and GlassWorm reports, and AFINE's GlassWorm research. GitHub's public API rate limit prevented exhaustive pagination of every npm/PyPI malware advisory; therefore `known-packages.json` remains explicitly curated rather than claiming ecosystem-wide completeness. The public GitHub Actions delta query returned no additions, while the historical `codfish/semantic-release-action` tag endpoint was unavailable; immutable commit IOCs were retained and mutable historical refs remain `WARN`. Every exact IOC should be removed or downgraded only when a trusted correction shows that the value was inaccurate.

## Deliberate Exclusions

- `ExarGD/vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1` are not ID/version IOC entries because the same identity was reported across different registries with conflicting provenance. They require a matching hash or suspicious behavior.
- No production JetBrains IOC is included without a separately verified ID/version or artifact hash. v0.1.13 implements the schema and bounded detection path without inventing indicators.
- General Node.js CVE coverage, EOL classification, registry resolution, and binary authenticity verification remain outside scope; only the bounded offline runtime advisory baseline is evaluated.
- npm v12 script restrictions are preventive guidance, not evidence that an installed package is safe or malicious.
