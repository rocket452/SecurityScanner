# Udemy Shallow Scan

This runbook is for a low-impact first pass against Udemy using this scanner.

## Current Policy Fit

- Udemy's public HackerOne policy says to "minimize the mayhem" and not use automated tools in a way that seriously impacts server performance.
- The public scope currently shows only two bounty-eligible web targets:
  - `https://www.udemy.com`
  - `https://yourcompany.udemy.com`

Use `https://www.udemy.com` for the first run.

Do not scan arbitrary `yourcompany.udemy.com` tenant hosts unless you control the tenant or have explicit permission.

## Why This Profile Is Conservative

- ZAP stays off.
- Stored XSS form workflows are disabled to avoid posting content into production forms.
- Payload count, crawl depth, ffuf threads, and nuclei rate are reduced.
- The scanner still uses safe-mode XSS checks with bounded payloads.

## One-Time Setup

PowerShell:

```powershell
$env:SECURITYSCANNER_CONFIG = "profiles/udemy_shallow.yaml"
```

This keeps your main `config.yaml` unchanged and makes the scanner use the Udemy profile for this shell session.

## Recommended First Command

```powershell
python .\scanner.py https://www.udemy.com `
  --safe `
  --skip-nuclei `
  --path-scan-depth 1 `
  --path-scan-max-urls 8 `
  --format html `
  --output .\reports\udemy_shallow.html
```

## Wrapper Timeout Guidance

If you launch scans through an external wrapper (like the Codex shell tool), the wrapper can time out before `scanner.py` finishes. Use a timeout that matches the scan size.

| Scan Size | Typical Use | Recommended `timeout_ms` |
| --- | --- | --- |
| Shallow | `--skip-nuclei`, low crawl depth, low path depth | `180000` |
| Medium | Nuclei enabled, moderate crawl/path depth | `300000` |
| Deep | Larger crawl/path depth, broader template coverage | `600000` |

These are wrapper wait times, not scanner limits. If you run `python .\scanner.py ...` directly in your own terminal, this wrapper timeout does not apply.

## Notes

- Use a full URL target. That skips subdomain discovery and keeps the run focused on the confirmed in-scope host.
- `--skip-nuclei` keeps the first pass focused on low-noise web checks and XSS signal.
- Add `--browser-verify` only after you get a small set of candidate XSS findings and want higher-confidence confirmation.
- If the site starts returning `429`, heavy bot defenses, or shows instability, stop immediately and lower scan intensity further.
