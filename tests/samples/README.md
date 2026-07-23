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
- JetBrains archive tests are generated temporarily with PowerShell/.NET during validation and are removed afterward; no executable plugin archive or malware byte sequence is stored here.
- The `.wasm` fixture is plain benign text, not a valid WebAssembly module. No malware bytes, live C2 endpoint, or usable credential is included.
- Standard dependency manifest names should avoid real vulnerable package versions unless the goal is to test GitHub/Dependabot behavior. Use non-installable text or scanner-specific fixtures for IOC examples.
- The scanner should detect several files in this directory as `WARN` or `DANGER`; that is expected.
- Do not use this directory to judge whether the scanner project itself is compromised.

The fake secret marker used in samples is `FAKE_DO_NOT_PRINT`; validation checks confirm this value is not emitted in reports.
