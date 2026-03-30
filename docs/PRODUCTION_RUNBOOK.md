# Production Runbook

This runbook covers basic operating guidance for live scans against authorized targets.

## Core Rules

- Confirm the program explicitly allows the level of automation you plan to use.
- Use only in-scope assets and respect program-specific rate limits.
- Keep ZAP off unless the program clearly allows active scanning.
- Prefer a shallow pass first, then increase depth only if the target remains stable and the signal is useful.
- Stop immediately if you see sustained `429`, WAF escalation, captchas, or signs of service degradation.

## Wrapper Timeout Guidance

If you launch scans through an external wrapper (for example, the Codex shell tool), the wrapper can stop waiting before `scanner.py` finishes. Use a timeout that matches the scan size.

| Scan Size | Typical Use | Recommended `timeout_ms` |
| --- | --- | --- |
| Shallow | `--skip-nuclei`, low crawl depth, low path depth | `180000` |
| Medium | Nuclei enabled, moderate crawl/path depth | `300000` |
| Deep | Larger crawl/path depth, broader template coverage | `600000` |

These values are wrapper wait times, not scanner limits. If you run `python .\scanner.py ...` directly in your own terminal, this wrapper timeout does not apply.

## Suggested Escalation Path

1. Start with a shallow pass against one confirmed in-scope host.
2. Review the output for false positives, bot defenses, and target stability.
3. Increase to a medium pass only if the shallow pass produces useful application coverage.
4. Use deep scans only when the target policy allows it and the earlier passes were stable.

## Reporting Standard

- Do not treat scanner output as submission-ready by itself.
- Manually verify each candidate finding.
- Capture exact reproduction steps, affected URL, parameter or input, payload, and observed impact.
- Submit one vulnerability per report unless chaining is required to explain impact.
