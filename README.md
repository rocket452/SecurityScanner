# SecurityScanner - Subdomain & Vulnerability Hunter

Automated reconnaissance tool combining **Subfinder** + **Amass** for subdomain enumeration, followed by live host probing and vulnerability scanning.

## What Each Tool Does

### Subfinder
- **Fastest** passive subdomain enumerator
- Sources: VirusTotal, Censys, CertDB, Facebook Certificate Transparency
- **8 subs** for av7bible.com in ~30s [web:9]

### Amass
- **Comprehensive** attack surface mapping
- Active/passive intel: DNS, certificates, scraping, APIs
- Reverse WHOIS, ASN enumeration [web:3]

## How It Works

1. **Enumeration**: Subfinder + Amass → unique subdomains
2. **Probing**: httpx checks HTTP/HTTPS liveness (200 OK)
3. **Scanning**: Fuzzes admin panels (cPanel/wp-admin), backups (.bak/.sql/zip)

**av7bible.com example**:
```
8 subs: cpanel, mail, webmail, webdisk...
✅ LIVE: https://cpanel.av7bible.com (200)
✅ LIVE: https://webmail.av7bible.com (200)
```

## Quick Start

### Docker (Recommended - Zero Setup)
```bash
git clone https://github.com/rocket452/SecurityScanner.git
cd SecurityScanner
git checkout subFinderAmass
docker build -t security-scanner .
docker run -it security-scanner example.com
```

### Local
```bash
pip install httpx pyyaml requests
python subfinder_amass_scanner.py example.com
```

**Prerequisites** (local):
- [Subfinder](https://github.com/projectdiscovery/subfinder) (`go install`)
- [Amass](https://github.com/owasp-amass/amass) (`go install`)

## Output Example
```
🔍 Scanning example.com
Subfinder OK: 12 subs
Amass OK: 8 subs
Found 15 subs: [...]
✅ LIVE https://cpanel.example.com (200)
🚨 VULNS:
https://cpanel.example.com <- Admin panel exposed
```

## Customization

**config.yaml**:
```yaml
targets:
  - example.com
  - test.org
threads: 50
```

**Extend scanners**:
- Add paths to `check_admin()`/`check_backup()`
- Nuclei templates integration

## Files
| File | Purpose |
|------|----------|
| `subfinder_amass_scanner.py` | Main orchestrator |
| `Dockerfile` | Containerizes everything |
| `scanner.py` | Core logic (importable) |

## Performance
- **Subfinder**: 30s-2min
- **Amass**: 2-10min (passive mode)
- **Probing**: 1-2s per live host

**Status**: Production-ready 🚀

**Author**: rocket452/SecurityScanner (2026)