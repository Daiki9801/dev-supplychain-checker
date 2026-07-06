# Synthetic Test Samples

These files are intentionally small, synthetic, non-executable fixtures for scanner validation.

End-user source archives may intentionally include only this README and `manifest.json`. That is expected. The full fixture bodies are kept in the maintainer source repository for regression tests and are omitted from lightweight archives because they intentionally contain suspicious-looking text.

- They were not downloaded from the internet.
- They are not real malware samples.
- They contain static text patterns such as fake package versions, fake URLs, and fake token placeholders.
- Some samples intentionally contain invisible Unicode, package-manager command names, or cache-like paths.
- Some samples intentionally contain synthetic GlassWorm-style C2 markers, AI skill documentation examples, known extension IDs, or secret-exfiltration shaped text.
- Standard dependency manifest names should avoid real vulnerable package versions unless the goal is to test GitHub/Dependabot behavior. Use non-installable text or scanner-specific fixtures for IOC examples.
- The scanner should detect several files in this directory as `WARN` or `DANGER`; that is expected.
- Do not use this directory to judge whether the scanner project itself is compromised.

The fake secret marker used in samples is `FAKE_DO_NOT_PRINT`; validation checks confirm this value is not emitted in reports.
