# SecurityScanner - Advanced Vulnerability Discovery Tool

Automated security reconnaissance tool combining **subdomain enumeration**, **recursive directory fuzzing**, **exposed storage detection**, and **vulnerability scanning** with Nuclei integration.

## 🚀 Features

### Subdomain Discovery
- **Subfinder**: Fast passive subdomain enumeration from multiple sources
- **Amass**: Comprehensive attack surface mapping with active/passive intelligence
- Automatic deduplication and live host probing

### Directory & Path Discovery
- **Recursive Directory Fuzzing**: 3-level deep recursive scanning
  - Discovers `/file-service/` → `/file-service/static/` → `/file-service/static/uploads/`
- **Exposed Storage Detection**: Checks 18+ common bucket/storage patterns
  - `/file-service/static/`, `/uploads/`, `/s3/`, `/storage/`, etc.
- **Smart Detection**: Identifies directory listings, accessible paths, and forbidden-but-existing paths

### Vulnerability Scanning
- **Nuclei Integration**: Industry-standard vulnerability scanner
- **Admin Panel Detection**: Scans for exposed admin interfaces
- **Backup File Discovery**: Detects accessible backup files (.bak, .sql, .zip)
- **Custom Scanners**: Modular design for easy extension

## 📋 How It Works

```
1. Subdomain Enumeration
   ├─ Subfinder (passive sources)
   ├─ Amass (DNS, certs, APIs)
   └─ Deduplicate & include base domain

2. Live Host Probing
   ├─ Test HTTPS/HTTP connectivity
   └─ Accept 200-499 status codes

3. Vulnerability Scanning (per live host)
   ├─ Check exposed buckets/storage (18+ patterns)
   ├─ Recursive directory fuzzing (depth: 3)
   ├─ Admin panel detection
   ├─ Backup file scanning
   └─ Nuclei vulnerability templates

4. Report Results
   └─ Detailed vulnerability report with paths and status codes
```

## 🐳 Quick Start (Docker - Recommended)

### Build the Container
```bash
git clone https://github.com/rocket452/SecurityScanner.git
cd SecurityScanner
git checkout cleanupProcess
docker build -t security-scanner .
```

### Run a Scan
```bash
# Basic scan
docker run -it security-scanner example.com

# Scan specific target
docker run -it security-scanner prime.platacard.mx
```

### Example Output
```
🔍 prime.platacard.mx
============================================================
[INFO] Subfinder found 5 subdomain(s)
[OK]   → api.prime.platacard.mx
[OK]   → www.prime.platacard.mx

============================================================
📊 SUMMARY: 6 total target(s) to scan
============================================================
  • api.prime.platacard.mx
  • prime.platacard.mx
  • www.prime.platacard.mx
============================================================

[INFO] Checking for exposed buckets/storage
🚨 EXPOSED BUCKET: https://prime.platacard.mx/file-service/static/ [200]
[INFO] Starting recursive directory fuzzing (max depth: 3)
  Fuzzing at depth 0: https://prime.platacard.mx
    └─ file-service [200]
  Fuzzing at depth 1: https://prime.platacard.mx/file-service
    └─ static [200]
    └─ api [403]

🚨 VULNERABILITIES:
https://prime.platacard.mx: Exposed directory listing: /file-service/static/ [200]
https://prime.platacard.mx: Discovered path: /file-service [200]
https://prime.platacard.mx: Discovered path: /file-service/static [200]
```

## 💻 Local Installation

### Prerequisites
```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest

# Install Python dependencies
pip install -r requirements.txt
```

### Run Locally
```bash
python scanner.py example.com
```

## ⚙️ Configuration

### Rate Limiting & Performance

Edit `config.yaml` to customize scan behavior:
```yaml
rate_limiting:
  ffuf_threads: 20              # Directory fuzzing threads (5-100)
  nuclei_rate_limit: 150        # Nuclei requests per minute
  nuclei_concurrency: 25        # Parallel Nuclei templates
  http_timeout: 10              # Request timeout in seconds
  request_delay: 0              # Delay between requests (ms)
```

### API Keys for Enhanced Discovery

Add API keys to `config.yaml` for significantly better subdomain discovery:
```yaml
api_keys:
  shodan: "your-api-key"
  virustotal: "your-api-key"
  securitytrails: "your-api-key"
  # ... more services
```

Free API key sources:
- [Shodan](https://account.shodan.io/register) - 100 results/month
- [Censys](https://censys.io/register) - 250 queries/month
- [VirusTotal](https://www.virustotal.com/gui/join-us) - 500 requests/day
- [SecurityTrails](https://securitytrails.com/app/signup) - 50 queries/month
- [GitHub](https://github.com/settings/tokens) - Unlimited for public repos

### Customizing Scans

Edit `scanners/directory_scanner.py` to add custom paths:
```python
bucket_patterns = [
    '/file-service/static/',
    '/uploads/',
    '/your-custom-path/',  # Add your paths here
]
```

### Adjusting Recursion Depth

In `scanner.py`, change the `max_depth` parameter:
```python
discovered = fuzz_directories(url, timeout=180, recursive=True, max_depth=3)
#                                                                        ↑
#                                                          Increase for deeper scans
```

## 📂 Project Structure

```
SecurityScanner/
├── scanner.py                    # Main entry point
├── config.yaml                   # Configuration & rate limiting
├── requirements.txt              # Python dependencies
├── Dockerfile                    # Container configuration
├── README.md                     # This file
│
├── config/                       # Configuration files
│   ├── amass-config.ini         # Amass API keys
│   └── subfinder-config.yaml    # Subfinder API keys
│
└── scanners/                     # Scanner modules
    ├── __init__.py              # Package initializer
    ├── admin_scanner.py         # Admin panel detection
    ├── backup_scanner.py        # Backup file discovery
    └── directory_scanner.py     # Recursive fuzzing & bucket detection
```

## 🔧 Key Features Explained

### Recursive Fuzzing
Unlike traditional single-level fuzzing, this scanner:
1. Finds `/file-service/` at depth 0
2. Automatically fuzzes inside it to find `/file-service/static/` at depth 1
3. Continues up to 3 levels deep
4. Limits recursion to first 10 paths per level to prevent explosion

### Exposed Storage Detection
Checks common patterns before fuzzing:
- Cloud storage: `/s3/`, `/bucket/`, `/cdn/`
- File services: `/file-service/`, `/storage/`, `/uploads/`
- Static content: `/static/`, `/assets/`, `/media/`
- Documents: `/documents/`, `/files/`, `/resources/`

Detects three types of exposures:
- **Directory Listings** (200 with listing indicators)
- **Accessible Paths** (200 but no obvious listing)
- **Forbidden But Existing** (403 - path exists but blocked)

### Smart Logging
- Shows each discovered subdomain in real-time
- Visual tree structure for recursive fuzzing
- Limits verbose output (first 20 paths) to avoid spam
- Color-coded vulnerability levels

## 📊 Performance

| Component | Speed | Notes |
|-----------|-------|-------|
| Subfinder | 30s-2min | Fast passive enumeration |
| Amass | 2-10min | Comprehensive but slower |
| Live Probing | 1-2s/host | Parallel HTTP requests |
| Bucket Check | ~5s | 18 patterns tested |
| Recursive Fuzzing | 2-5min | Depends on depth & wordlist |
| Nuclei | 1-3min | Template-based scanning |

**Total scan time**: 5-20 minutes per domain (depending on findings)

## 🛡️ Security & Ethics

⚠️ **Important**: Only scan domains you own or have explicit permission to test.

- This tool is for authorized security testing only
- Unauthorized scanning may be illegal in your jurisdiction
- Always obtain written permission before scanning
- Use responsibly and ethically

## 🐛 Troubleshooting

### No subdomains found
- Target may have no public subdomains
- Try adding API keys for Subfinder (see Configuration section)
- Base domain will still be scanned

### Fuzzing times out
- Increase timeout: `fuzz_directories(url, timeout=300)`
- Reduce recursion depth: `max_depth=2`
- Use a smaller wordlist

### Docker build fails
- Ensure Docker is installed and running
- Check internet connectivity (downloads tools)
- Try: `docker system prune -a` to clean cache

### Import errors
- Ensure you're running from the project root directory
- Check that `scanners/` directory exists with `__init__.py`
- Verify all dependencies: `pip install -r requirements.txt`

## 📝 Output Interpretation

### Status Codes
- **200-299**: Success - resource is accessible
- **301-308**: Redirect - follow to find destination
- **401**: Unauthorized - authentication required
- **403**: Forbidden - exists but access denied
- **404**: Not found - doesn't exist

### Vulnerability Types
- **Exposed directory listing**: High risk - files can be enumerated
- **Accessible path**: Medium risk - sensitive path exposed
- **Forbidden but exists**: Low risk - path exists but protected
- **Admin panel exposed**: High risk - potential unauthorized access
- **Backup file found**: Critical - may contain sensitive data

## 🤝 Contributing

Contributions welcome! Feel free to:
- Add new scanner modules to `scanners/`
- Improve detection patterns
- Enhance recursive fuzzing logic
- Add new wordlists or templates

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

rocket452 - [GitHub](https://github.com/rocket452/SecurityScanner)

---

**Version**: 3.0 (Reorganized Structure)  
**Last Updated**: January 2026  
**Status**: Production Ready 🚀
