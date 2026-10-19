# Local IOC Data

This directory contains manually curated offline IOC data. It is a bounded incident-response baseline, not a complete malware feed or a substitute for current vendor, registry, EDR, or threat-intelligence data.

The scanner never downloads IOC updates. Update these files only after manual review of trusted advisories, vendor posts, incident reports, or internal security guidance.

## Files

- `known-packages.json`: exact package ecosystem, name, and version matches.
- `known-extensions.json`: platform-qualified IDE extension/plugin ID and version matches. Missing `platform` means `vscode`; JetBrains entries use `platform: jetbrains`.
- `known-files.json`: fixed path, filename, path pattern, or optional SHA-256 file indicators.
- `known-actions.json`: GitHub Action repositories, known compromised commits, historically affected mutable refs, and a separate reference-version advisory section (`schemaVersion=0.1.23`).
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
- Record the comparison basis and retained historical provenance in `reviewRecord`. A complete manual corpus comparison is distinct from fresh independent verification of every old artifact; document any such limits explicitly. Future review dates, missing/empty required sections, malformed entries, and Node.js advisory conflicts/duplicates block readiness.
- Before publication, run a synthetic report and require `iocData.releaseReady=true`. This means the shipped bounded datasets passed their own freshness contracts; it does not mean all public malware indicators are present. A stale dataset continues to supply historical exact matches but blocks publication readiness.
- Prefer `DANGER` for known-bad IOC matches and `WARN` for behavioral or marker-only patterns.
- Do not add incomplete package lists from mass-campaign news. Add only entries that have been individually verified.
- Broad campaign family names without exact affected versions belong in scanner watchlist context, not in exact IOC JSON.
- npm cache metadata hits should remain `WARN` or `INFO` context unless the same package/version is also installed or executable behavior is present.
- Node.js advisory entries must use official `nodejs.org` security-release sources, exact half-open affected ranges, and fixed versions for each listed major. The header must remain `schemaVersion=0.1.14`, `expiresAfterDays=30`, and `highRetentionDays=365`; a malformed header or local conflict cannot override the built-in baseline.
- Campaign snapshots are loaded all-or-nothing. Keep `schemaVersion`, `campaignId`, exact counts, unique lower-case package names, exact semantic versions, and `integrity.sha256` consistent. The package digest, three file hash/path indicators, four marker names, and Git ref must also match the scanner's embedded approved snapshot values; recomputing a digest after changing the JSON does not authorize the change. A missing, malformed, truncated, unapproved, or count/hash-mismatched file falls back to the small built-in safety baseline and emits a coverage warning.
- Do not silently replace campaign source metadata. Record the supplied artifact hashes, review date, review-after period, and whether the source was independently reverified. This checker never performs that reverification online.

## October 2026 Supplement

The `supplementLastReviewed=2026-10-06` fields describe the additions documented in the [implementation plan/source register](../docs/security-update-20261006-detailed-implementation-plan-ja.md). The subsequent [complete bounded corpus comparison](../docs/ioc-maintenance-20261006-ja.md) reviewed all seven datasets on 2026-10-06 with unchanged 30-day expiry contracts. Review dates were advanced after that comparison. The [item-level evidence record](../docs/ioc-maintenance-20261006-evidence.json) distinguishes direct malware/advisory confirmation, publisher metadata, and retained historical evidence. Readiness does not upgrade the evidence for historical artifacts that were not independently reverified.

The supplement contains nine package names with 20 exact affected pairs, including both Trinitite prereleases. `@memtensor/memos-cloud-openclaw-plugin` versions 0.1.22 and 0.1.24 and `memoryos` 2.0.33 are not included as compromised versions. `anthropic-sdk` is distinct from the legitimate `anthropic` distribution. `virgil-cli` 0.1.4 concerns undisclosed conversation/tool-result forwarding; the indicator does not assert credential theft.

Sixteen exact SHA-256 indicators include npm payloads, Windows sckit binaries, and the reported theme artifacts. New file entries declare `ownerCheck`, `artifactRole`, `ruleId`, and `sourceId`. IDE artifact hashes require extension provenance or an explicitly selected archive. Theme IDs alone remain INFO watchlist context. Hash-to-package-version correspondence is not invented when the report did not publish it.

Action advisories accept bounded numeric half-open ranges, exact fixed versions, a CVE ID, GitHub advisory source URL, source ID, publication date, upstream severity, and condition names. The section is bounded to 128 advisories, four ranges, and eight fixed versions per advisory. Missing/invalid/old-schema sections make the dataset invalid and retain the embedded fallback and historical bad-commit/ref entries. Numeric tag matches are reference posture, not immutable compromise evidence.

Endpoint markers are context-limited WARN patterns, with host boundaries that exclude suffix lookalikes. The conversation-forwarding endpoint is not an unconditional credential-C2 indicator. No new endpoint is added to the unconditional DANGER domain list. The scanner never contacts any of these endpoints.

## Keyv ChainDrop Snapshot (2026-08-12)

`campaign-keyv-chaindrop-20260806.json` contains 443 package names and 2,235 exact package/version pairs transcribed from the incident checker and report supplied for this update. It also contains three supplied SHA-256 indicators, four marker patterns, and one bounded Git-ref indicator. The package/version canonical digest is `7da86fddcb4bc5c4352d3f2120903a07314ae2ce3071d980061862bcbc8aa497`.

An exact installed-package or structurally parsed lockfile match is `DANGER`. A manifest constraint, cache-only occurrence, fallback-text occurrence, or marker-only match is capped at `WARN` unless independent execution, persistence, exfiltration, or exact-hash evidence corroborates it. This prevents incident write-ups and benign release tooling from becoming false `DANGER` findings.

The snapshot records the SHA-256 of the supplied BAT and report. The 2026-08-14 review confirmed Aikido's 16 explicitly listed package families and three payload hashes. On 2026-10-06, all 443 names and 2,235 exact pairs were independently corroborated in non-withdrawn OSV malware records; the pair-to-advisory mapping is in the evidence record. Aikido's aggregate of at least 444 packages across 1,381 versions still differs from the supplied snapshot. No speculative count correction or source CSV reconstruction was performed. The original supplied-source `reviewStatus` and hashes remain unchanged, with OSV corroboration recorded separately. The 30-day review window remains in force.

## Current Manual Baseline (reviewed 2026-10-06)

The bounded baseline includes manually reviewed public vendor and security-research reporting for:

- Axios/plain-crypto-js package compromise indicators.
- GlassWorm/OpenVSX compromised extension versions.
- A reported Axios/plain-crypto-js Windows persistence filename.
- GlassWorm-style C2 marker patterns that require manual review when found in executable context.
- Shai-Hulud style payload and workflow markers such as `setup_bun.js`, `bun_environment.js`, `actionsSecrets.json`, `truffleSecrets.json`, discussion-triggered self-hosted workflow execution, and secrets artifact packaging.
- Watchlist context for reported npm campaign family names is handled in the scanner as low-confidence `INFO`, not as exact local IOC data.
- AsyncAPI, Jscrambler, Injective, Bitwarden CLI, React Native, SAP CAP, and payment-brand typosquat package incidents with exact affected versions. The Jscrambler wrapper pairs `jscrambler-webpack-plugin@8.6.2` and `grunt-jscrambler@8.5.2` were removed after the trusted report explicitly excluded those wrappers.
- The `codfish/semantic-release-action` compromised commits and historically affected mutable refs. Exact bad commits are `DANGER`; historical refs remain `WARN` because the scanner cannot resolve their current target offline.
- GlassWASM/OpenVSX WASM, VSIX, and native installer hashes, plus the `dodod.lat` campaign domain and a marker-only wallet identifier.
- Python Miasma/Hades-style `*-setup.pth`, `_index.js`, `.bun_ran`, and Bun bootstrap behavior.
- Node.js official Critical releases from 2020 onward and High releases within the manually maintained 365-day window as of 2026-10-06. These are static version indicators, not proof that vulnerability preconditions are reachable.

The Node.js runtime baseline uses only official Node.js security-release pages: February 2020, September 2020, February 2021, December 2025/January 2026, March 2026, June 2026, and July 2026. All 13 entries and the current official vulnerability index were compared on 2026-10-06. High advisories older than the declared 365-day retention window are removed; Critical history is retained. Each advisory entry stores its exact source URL, publication date, affected half-open ranges, fixed versions by major, and additional conditions. Version boundaries remain unchanged and match the built-in baseline.

The 2026-08-14 refresh used official OSV npm/PyPI snapshots, GitHub's public global-advisory API, public npm package metadata, the official Node.js July 2026 security release, Aikido's Keyv and GlassWorm reports, and AFINE's GlassWorm research. GitHub's public API rate limit prevented exhaustive pagination of every npm/PyPI malware advisory; therefore `known-packages.json` remains explicitly curated rather than claiming ecosystem-wide completeness. The public GitHub Actions delta query returned no additions, while the historical `codfish/semantic-release-action` tag endpoint was unavailable; immutable commit IOCs were retained and mutable historical refs remain `WARN`. Every exact IOC should be removed or downgraded only when a trusted correction shows that the value was inaccurate.

## Deliberate Exclusions

- `ExarGD/vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1` are not ID/version IOC entries because the same identity was reported across different registries with conflicting provenance. They require a matching hash or suspicious behavior.
- No production JetBrains IOC is included without a separately verified ID/version or artifact hash. v0.1.13 implements the schema and bounded detection path without inventing indicators.
- General Node.js CVE coverage, EOL classification, registry resolution, and binary authenticity verification remain outside scope; only the bounded offline runtime advisory baseline is evaluated.
- npm v12 script restrictions are preventive guidance, not evidence that an installed package is safe or malicious.
