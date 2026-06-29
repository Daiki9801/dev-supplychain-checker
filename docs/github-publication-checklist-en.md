# GitHub Publication Checklist

Use this checklist before publishing the repository publicly.

## Before Publishing

- Include `Scan-DevSupplyChain.ps1`, `run-checker.bat`, `README.md`, `docs/`, `iocs/`, and `tests/samples/manifest.json`.
- Do not include generated `reports*/`, `.git/`, or `other/` in release/source distribution.
- Confirm that `.github/CODEOWNERS` points to the publishing GitHub account or team. This repository is set to `@Daiki9801`.
- If you fork or republish under another account, replace `CODEOWNERS` before enabling Code Owner review.
- Confirm that MIT is the intended license. Replace `LICENSE` before publishing if not.

## GitHub Settings

Enable the most restrictive free-account settings available:

- Public visibility, if you intend public release.
- GitHub-owned actions only, or the most restrictive allowed action policy available.
- Workflow permissions: read repository contents.
- Dependabot alerts.
- Dependabot security updates.
- Secret scanning and push protection if available.

For strict operation, pin `actions/checkout@v4` in `.github/workflows/validate.yml` to a verified GitHub-owned commit SHA after checking the official repository.

## Branch Protection Or Ruleset

Protect `main` with:

- pull requests before merge;
- approvals;
- Code Owner review after CODEOWNERS is configured;
- required status checks;
- required check: `Scanner contract`;
- blocked force pushes;
- blocked deletions;
- conversation resolution.

The `Scanner contract` check appears after the first workflow run.

## Operating Rules

- Add high-confidence IOC entries only for verified package/version or extension/version pairs.
- Do not paste incomplete campaign package lists as `DANGER` IOCs.
- Do not run real `-UserProfile`, real `-EndpointTelemetry`, or full real-host scans in CI.
- Do not paste tokens, private keys, auth files, or personal data into issues or PRs.
