# Synthetic Test Samples

These files are intentionally small, synthetic, non-executable fixtures for scanner validation.

End-user source archives may intentionally include only this README and `manifest.json`. That is expected. The full fixture bodies are kept in the maintainer source repository for regression tests and are omitted from lightweight archives because they intentionally contain suspicious-looking text.

- They were not downloaded from the internet.
- They are not real malware samples.
- They contain static text patterns such as fake package versions, fake URLs, and fake token placeholders.
- Some samples intentionally contain invisible Unicode, package-manager command names, or cache-like paths.
- Some samples intentionally contain synthetic GlassWorm-style C2 markers, AI skill documentation examples, known extension IDs, or secret-exfiltration shaped text.
- v0.1.12 samples also cover exact-versus-range package evidence, bounded npm entrypoint resolution, GitHub Action refs, benign WASM metadata, and Python `.pth`/Bun bootstrap shapes.
- v0.1.13 samples add bounded child-project discovery, a Deep-only unselected dependency file, and an exploded JetBrains plugin tree. The `.dll` fixture is plain text and is not a valid native binary.
- v0.1.14 samples add Node.js runtime version pins and constraints only. They contain no Node.js executable and do not execute any runtime or project code.
- v0.1.15 samples add Keyv/ChainDrop exact package and npm lockfile v1/v2/v3 shapes, incident-named harmless scripts, VS Code/Claude startup correlation, GitHub artifact correlation, and benign release/build negatives. They contain no real malware body or usable credential.
- v0.1.16 adds one harmless GlassWorm-style Variation Selector decoder fixture with a consecutive BMP/supplementary selector cluster. Its decoded text is a synthetic marker only and is never executed by validation.
- v0.1.17 adds structural `npm-shrinkwrap.json` and `Pipfile.lock` IOC fixtures; both are static metadata and are never installed or executed.
- v0.1.18 adds a benign bundled-utility negative fixture where `codePointAt`, Variation Selector range checks, and execution-related APIs occur in unrelated functions.
- v0.1.19 uses existing lifecycle, isolated-Unicode, and remote-WASM fixtures to verify the new `CAUTION` tier without weakening strong `WARN` or `DANGER` detections.
- v0.1.20 adds triage-precision fixtures for manual GitHub Actions triggers, active versus passive unpinned MCP tooling, reference-text examples, active fetch-execute controls, and a spoofed legacy checker name that must not bypass secret-exfiltration detection. Validation never executes these files or contacts their synthetic `.invalid` URLs.
- v0.1.21 reuses the safe and affected Node.js version fixtures to verify separate installed/project counters, bounded redacted inventory entries, and non-critical partial completion reporting.
- The Keyv network IOC fixture stores public endpoint and contract indicators as inert text. Validation never resolves or connects to them.
- JetBrains archive tests are generated temporarily with PowerShell/.NET during validation and are removed afterward; no executable plugin archive or malware byte sequence is stored here.
- The `.wasm` fixture is plain benign text, not a valid WebAssembly module. No malware bytes or usable credential is included.
- Standard dependency manifest names should avoid real vulnerable package versions unless the goal is to test GitHub/Dependabot behavior. Use non-installable text or scanner-specific fixtures for IOC examples.
- The scanner should detect several files in this directory as `CAUTION`, `WARN`, or `DANGER`; that is expected.
- Do not use this directory to judge whether the scanner project itself is compromised.

The fake secret marker used in samples is `FAKE_DO_NOT_PRINT`; validation checks confirm this value is not emitted in reports.
