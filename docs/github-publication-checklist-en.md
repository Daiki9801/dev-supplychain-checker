# GitHub Publication Checklist

Use this checklist before publishing the repository publicly.

## Before Publishing

- Include `Scan-DevSupplyChain.ps1`, `run-checker.bat`, `README.md`, `docs/`, `iocs/`, and `tests/samples/manifest.json`.
- Do not include full synthetic fixture bodies from `tests/samples/**` in end-user release/source archives. Keep only `tests/samples/manifest.json` and `tests/samples/README.md`.
- Do not include the default `reports/`, custom or legacy report directories, `.git/`, `other/`, temporary tokens, or `.env*` files in release/source distribution.
- Confirm `.gitattributes` excludes the default `reports/`, local reference files, temporary secrets, and synthetic fixture bodies from generated source archives; custom report directories must remain untracked.
- Confirm that `.github/CODEOWNERS` points to the publishing GitHub account or team. This repository is set to `@Daiki9801`.
- If you fork or republish under another account, replace `CODEOWNERS` before enabling Code Owner review.
- Confirm that MIT is the intended license. Replace `LICENSE` before publishing if not.
- Confirm README and manuals prominently explain bounded completion, the per-regex-operation timeout, `REGEX_SCAN_TIMEOUT`, and that neither findings nor their absence prove infection or safety.

## Local Pre-Push Audit

`.gitignore` prevents some new mistakes; it does not remove sensitive data that was committed previously. Audit both the proposed push and every reachable commit.

- Confirm the only intended destination with `git remote -v`.
- Confirm there are no unrelated tracked, untracked, or unstaged changes with `git status --short --branch`; also review file names from `git status --short --ignored` for accidentally ignored sensitive material.
- Review author and committer emails plus commit messages with `git log --all --format=fuller`.
- Inspect `git rev-list --objects --all` for `.env`, private-key, token, auth, credential, real username, or local-path file names.
- Scan every reachable blob for private-key headers, GitHub/cloud/npm token formats, JWTs, credential-bearing URLs, sensitive-value assignments, and user-specific home paths. Print candidate file names only; never print a suspected value into a terminal or log.
- Review the exact push set with `git diff --name-status origin/main..HEAD` and `git log --oneline origin/main..HEAD`.
- Run `git diff --check origin/main..HEAD`; also confirm there are no historical blobs over 5 MiB or unnecessary archives, databases, or key containers.
- Confirm the default `reports/`, every custom or legacy report directory, `other/`, and temporary validation output are untracked. Do not publish real reports even when their normal output is redacted.
- Confirm token, auth, and attack-shaped text under synthetic fixtures is unusable test data and is documented by `tests/samples/README.md` and the manifest.

Stop before pushing if history contains suspected sensitive data. Deleting it only from the latest commit is insufficient; revoke any exposed value and decide explicitly whether pre-publication history rewriting is required.

## GitHub Settings

Enable the most restrictive free-account settings available:

- Public visibility, if you intend public release.
- GitHub-owned actions only, or the most restrictive allowed action policy available.
- Workflow permissions: read repository contents.
- Dependabot alerts.
- Dependabot security updates.
- Secret scanning and push protection if available.

Keep `actions/checkout` in `.github/workflows/validate.yml` pinned to a full commit SHA. Verify the SHA and release in the official GitHub repository before updating it.

Set a concise repository description, the MIT license, and relevant topics such as `windows`, `powershell`, `security`, `ioc`, and `supply-chain`. Add a website or social link only if it is an official distribution channel you control.

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
- After pushing, confirm `Scanner contract` succeeds and the Security tab reports no secret-scanning alerts. Keep both the local and GitHub-side checks; neither replaces the other.
