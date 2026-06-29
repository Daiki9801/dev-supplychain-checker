# Security Policy

## Scope

This project is a dependency-free, offline, read-only Windows supply-chain IOC checker.

Security reports should focus on issues that could weaken those guarantees, including:

- unintended network access;
- execution of target project code;
- printing secrets or auth file contents;
- unsafe traversal such as following junctions into loops;
- bypasses in report redaction;
- false `OK` results for synthetic high-risk samples.

## Reporting A Vulnerability

After this repository is published on GitHub, prefer GitHub Security Advisories for private vulnerability reports when available.

If private advisories are not available on the repository, open a public issue only with non-sensitive reproduction steps and synthetic samples. Do not include host-specific evidence in a public issue.

Do not paste real tokens, private keys, auth files, host forensic data, or personal information into public issues. If evidence is needed, use synthetic samples or redacted excerpts.

## Supported Version

Only the current `main` branch is maintained unless a release branch is explicitly announced.

## Non-Goals

This tool does not remediate, delete, quarantine, uninstall, rotate tokens, or modify registry entries. It is a triage aid, not proof that a host is clean.
