# OWASP ZAP Integration Guide

## Overview

This SecurityScanner integrates OWASP ZAP following a **hybrid approach**:

1. **Subdomain Discovery**: Use specialized tools (Subfinder, Amass) to enumerate subdomains
2. **Vulnerability Scanning**: Feed discovered subdomains to ZAP for comprehensive security testing

## Why This Approach?

ZAP is not designed for subdomain enumeration. It excels at:
- Crawling web applications (spidering)
- Passive vulnerability analysis
- Active security testing (with permission)
- Comprehensive reporting

By combining tools, we get:
- ✅ Complete subdomain coverage from Subfinder/Amass
- ✅ Deep vulnerability scanning from ZAP
- ✅ Automated workflow in a single tool

## Setup

### Option 1: Docker (Recommended)

Run ZAP in daemon mode:

```bash
docker run -u zap -p 8080:8080 -d zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=true
```

### Option 2: Local Installation

1. Download ZAP from: https://www.zaproxy.org/download/
2. Start in daemon mode:
   ```bash
   zap.sh -daemon -port 8080 -config api.disablekey=true
   ```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

This includes `python-owasp-zap-v2.4` for ZAP API integration.

## Usage

### Basic Scan with ZAP

```bash
python scanner.py example.com --zap
```

This will:
1. Discover subdomains with Subfinder & Amass
2. Spider each subdomain with ZAP
3. Run passive scans (safe, non-invasive)
4. Generate combined report

### Active Scanning (Requires Permission!)

**⚠️ WARNING**: Active scanning performs actual attacks. Only use on systems you own or have explicit permission to test.

```bash
python scanner.py example.com --zap --zap-active
```

### ZAP-Only Scan (Skip Nuclei)

```bash
python scanner.py example.com --zap --skip-nuclei
```

### Custom ZAP Settings

```bash
python scanner.py example.com --zap \
  --zap-proxy http://localhost:8090 \
  --zap-timeout 600
```

## Configuration

Edit `config.yaml` to customize ZAP settings:

```yaml
zap:
  enabled: true
  proxy_url: "http://localhost:8080"
  api_key: null  # Set if ZAP requires API key
  timeout: 300
  spider: true
  passive_scan: true
  active_scan: false  # Set to true ONLY if you have permission
  max_spider_depth: 5
```

## Workflow Details

### 1. Subdomain Discovery Phase

```
┌─────────────┐     ┌─────────────┐
│  Subfinder  │────▶│  Subdomains │
└─────────────┘     │    List     │
                    │             │
┌─────────────┐     │             │
│    Amass    │────▶│  (merged &  │
└─────────────┘     │deduplicated)│
                    └──────┬──────┘
                           │
                           ▼
```

### 2. ZAP Scanning Phase

```
┌──────────────────┐
│ For each domain: │
└────────┬─────────┘
         │
         ▼
┌─────────────────┐
│  Spider URLs    │  (Discover pages & endpoints)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Passive Scan   │  (Analyze traffic, no attacks)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Active Scan    │  (Optional: Attack to find vulns)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Collect Alerts  │
└─────────────────┘
```

### 3. Combined Results

Vulnerabilities from ZAP are merged with results from:
- Admin panel detection
- Backup file scanning
- XSS detection
- Directory fuzzing
- Nuclei templates

## Report Output

ZAP findings are included in all report formats:

- **JSON**: Machine-readable with ZAP alert details
- **HTML**: Visual report with ZAP vulnerabilities highlighted
- **Markdown**: Documentation-friendly format
- **CSV**: Spreadsheet-compatible data

Additionally, generate ZAP-specific reports:

```python
from scanners.zap_scanner import ZAPScanner

scanner = ZAPScanner()
scanner.generate_report('/reports/zap_report.html', format='html')
```

## ZAP Scanner Module

The `scanners/zap_scanner.py` module provides:

### Key Functions

- `spider_url(url)` - Crawl a website to discover pages
- `passive_scan(url)` - Safe vulnerability analysis
- `active_scan(url)` - Active penetration testing
- `scan_subdomain_list(subdomains)` - Batch scan multiple targets
- `get_alerts()` - Retrieve discovered vulnerabilities
- `generate_report()` - Create detailed ZAP reports

### Example Usage

```python
from scanners.zap_scanner import ZAPScanner

# Initialize scanner
scanner = ZAPScanner(proxy_url='http://localhost:8080')

# Check if ZAP is running
if not scanner.check_zap_running():
    print('Start ZAP first!')
    exit(1)

# Scan subdomains
subdomains = ['https://app.example.com', 'https://api.example.com']
results = scanner.scan_subdomain_list(
    subdomains,
    spider=True,
    passive=True,
    active=False  # Set True only with permission
)

# Get vulnerabilities
for subdomain, alerts in results.items():
    print(f'{subdomain}: {len(alerts)} issues found')
    vulns = scanner.parse_alerts_to_vulns(alerts)
    for vuln in vulns:
        print(f"  - [{vuln['severity']}] {vuln['description']}")
```

## Troubleshooting

### ZAP Not Accessible

```
[ERROR] ZAP not accessible at http://localhost:8080
```

**Solution**: Ensure ZAP is running:
```bash
# Check Docker containers
docker ps | grep zap

# Or restart ZAP
docker restart <zap-container-name>
```

### Connection Timeout

```
[ERROR] ZAP scan timeout
```

**Solution**: Increase timeout in config or command line:
```bash
python scanner.py example.com --zap --zap-timeout 900
```

### No Vulnerabilities Found

This could mean:
- ✅ Target is secure (good!)
- ⚠️ Target blocked ZAP's user agent
- ⚠️ Scan didn't reach vulnerable endpoints

**Solution**: Review ZAP logs and adjust spider settings.

## Security Considerations

### Active Scanning Ethics

**🚨 CRITICAL**: Active scanning generates real attacks against targets.

- ✅ **DO**: Test your own applications
- ✅ **DO**: Get written permission for third-party systems
- ✅ **DO**: Use passive scanning when in doubt
- ❌ **DON'T**: Scan systems without authorization
- ❌ **DON'T**: Use in production environments without approval

### Rate Limiting

ZAP respects the existing rate limiting configuration:

```yaml
rate_limiting:
  zap_requests_per_minute: 60
  zap_concurrent_threads: 10
```

### Legal Compliance

Unauthorized security testing may violate:
- Computer Fraud and Abuse Act (CFAA) in the US
- Computer Misuse Act in the UK
- Similar laws in other jurisdictions

Always obtain proper authorization before scanning.

## Performance Tips

1. **Limit spider depth** for faster scans:
   ```yaml
   max_spider_depth: 3
   ```

2. **Use passive-only mode** when time-constrained:
   ```bash
   python scanner.py example.com --zap --no-active
   ```

3. **Scan subdomains in parallel** (future enhancement):
   ```yaml
   parallel_scanning: true
   max_parallel_targets: 5
   ```

## Further Reading

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [ZAP API Documentation](https://www.zaproxy.org/docs/api/)
- [ZAP Python API](https://github.com/zaproxy/zap-api-python)
- [ZAP Docker Guide](https://www.zaproxy.org/docs/docker/)

## Support

For issues or questions:
1. Check ZAP is running: `curl http://localhost:8080`
2. Review scanner logs in console output
3. Test ZAP module: `python scanners/zap_scanner.py`
4. Open an issue in this repository
