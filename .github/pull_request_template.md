## Summary

Describe the detection, reporting, documentation, or IOC behavior changed by this pull request.

## Safety checklist

- [ ] The change remains dependency-free, offline-only, read-only, and Windows PowerShell 5.1 compatible.
- [ ] It does not execute target code, package managers, downloaded content, or remediation actions.
- [ ] It does not print or commit tokens, private keys, auth-file contents, personal paths, or real host evidence.
- [ ] New IOC entries are exact, source-reviewed package/version or extension/version indicators, or are clearly lower-confidence context.
- [ ] GitHub Actions remain pinned to full commit SHAs and use read-only repository permissions.

## Validation

- [ ] PowerShell parser check completed.
- [ ] Local JSON data parsed successfully.
- [ ] Relevant synthetic positive and negative samples passed.
- [ ] No real `-UserProfile`, `-EndpointTelemetry`, npm global/cache, registry, event-log, or network validation was used.

List the exact local validation commands and results below. Do not paste real tokens, host paths, or unredacted reports.
