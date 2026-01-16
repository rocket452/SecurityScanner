# SecurityScanner - Advanced Vulnerability Discovery Tool

Automated security reconnaissance tool combining **subdomain enumeration**, **recursive directory fuzzing**, **exposed storage detection**, **XSS vulnerability testing**, and **vulnerability scanning** with Nuclei integration.

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
- **XSS Scanner**: Tests for reflected and DOM-based cross-site scripting vulnerabilities
- **Nuclei Integration**: Industry-standard vulnerability scanner
- **Admin Panel Detection**: Scans for exposed admin interfaces
- **Backup File Discovery**: Detects accessible backup files (.bak, .sql, .zip)
- **Custom Scanners**: Modular design for easy extension

### Report Generation
- **Multiple Formats**: JSON, HTML, Markdown, CSV
- **Detailed Findings**: Includes severity levels, vulnerability types, and descriptions
- **XSS Details**: Parameter names, payloads used, and vulnerability context
- **Auto-saved**: Reports automatically saved to `/reports` directory

## 🐳 Quick Start (Docker - Recommended)

### Build the Container
```bash
git clone https://github.com/rocket452/SecurityScanner.git
cd SecurityScanner
docker build -t security-scanner .
```

### Run a Scan - Simple!

**Just mount the `/reports` volume once and you're done:**

```bash
# Basic scan with JSON report (default)
docker run -v $(pwd)/reports:/reports -it security-scanner example.com

# HTML report
docker run -v $(pwd)/reports:/reports -it security-scanner example.com -f html

# Markdown report
docker run -v $(pwd)/reports:/reports -it security-scanner example.com -f markdown

# CSV report
docker run -v $(pwd)/reports:/reports -it security-scanner example.com -f csv

# Console output only (no file)
docker run -it security-scanner example.com --no-file
```

**Windows PowerShell:**
```powershell
# Basic scan
docker run -v ${PWD}/reports:/reports -it security-scanner example.com
```

**That's it!** Reports are automatically saved to `./reports/` on your host machine.

### Command Line Options
```bash
Usage: scanner.py [-h] [-o OUTPUT] [-f {json,html,markdown,csv}] [--no-file] target

Positional arguments:
  target                Target domain to scan

Optional arguments:
  -h, --help           Show help message
  -o OUTPUT, --output OUTPUT
                       Output file path (default: /reports/report_<target>_<timestamp>.<format>)
  -f {json,html,markdown,csv}, --format {json,html,markdown,csv}
                       Report format (default: json)
  --no-file            Skip saving report to file (console only)
```

### Example Output
```
🔍 example.com
============================================================
[INFO] Subfinder found 5 subdomain(s)
[OK]   → api.example.com
[OK]   → www.example.com

============================================================
📊 SUMMARY: 6 total target(s) to scan
============================================================
  • api.example.com
  • example.com
  • www.example.com
============================================================

[INFO] Running XSS scanner on https://example.com
[INFO] Testing XSS on parameter: search
[VULN] XSS FOUND: search with payload: <script>alert('XSS')</script>
[INFO] Checking for exposed buckets/storage
🚨 EXPOSED BUCKET: https://example.com/file-service/static/ [200]

🚨 VULNERABILITIES:
https://example.com: Reflected XSS found in parameter "search"
https://example.com: Exposed directory listing: /file-service/static/ [200]

[INFO] Report saved to: /reports/report_example_com_20260116_025823.json
```

**Your report will be in `./reports/` on your computer!**

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
# Create reports directory
mkdir reports

# Run scan with JSON report (default) - saves to ./reports/
python scanner.py example.com

# Run scan with HTML report
python scanner.py example.com -f html

# Run scan with custom output path
python scanner.py example.com -o /path/to/report.json

# Console output only (no file)
python scanner.py example.com --no-file
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

**Recommendations:**
- **Stealth mode**: `ffuf_threads: 5`, `nuclei_rate_limit: 50`, `request_delay: 200`
- **Balanced**: `ffuf_threads: 20`, `nuclei_rate_limit: 150` (default)
- **Aggressive**: `ffuf_threads: 50`, `nuclei_rate_limit: 300`, `nuclei_concurrency: 50`

### API Keys for Enhanced Discovery

Add API keys to `config.yaml` for significantly better subdomain discovery:
```yaml
api_keys:
  shodan: "your-api-key"
  virustotal: "your-api-key"
  securitytrails: "your-api-key"
  github: "your-github-token"
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

### Custom Wordlists

To use your own wordlist:
```bash
# Docker: Mount custom wordlist
docker run -v $(pwd)/reports:/reports -v /path/to/wordlist.txt:/app/wordlist.txt -it security-scanner example.com

# Local: Modify scanners/directory_scanner.py
# Change wordlist='/app/wordlist.txt' to your path
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
    ├── directory_scanner.py     # Recursive fuzzing & bucket detection
    └── xss_scanner.py           # XSS vulnerability testing
```

## 🔧 Key Features Explained

### XSS Vulnerability Testing
The XSS scanner tests for two types of vulnerabilities:

**Reflected XSS:**
- Tests 15 different XSS payloads (script tags, event handlers, etc.)
- Automatically detects URL parameters and tests them
- Tests common parameter names if none found (search, q, id, etc.)
- Validates that payloads are exploitable (not just reflected but unescaped)
- Reports parameter name, payload used, and full vulnerable URL

**DOM-based XSS:**
- Scans JavaScript code for dangerous patterns
- Detects `document.write()`, `innerHTML`, `eval()`, etc.
- Identifies potential client-side injection points
- Provides code context for manual verification

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

### Real-Time Output
- All findings are printed to console in real-time
- Structured logging with severity levels
- Visual tree structure for recursive fuzzing results
- Detailed report automatically saved to `/reports` directory

## 📊 Performance

| Component | Speed | Notes |
|-----------|-------|-------|
| Subfinder | 30s-2min | Fast passive enumeration |
| Amass | 2-10min | Comprehensive but slower |
| Live Probing | 1-2s/host | Parallel HTTP requests |
| XSS Testing | 10-30s/host | Tests multiple payloads |
| Bucket Check | ~5s | 18 patterns tested |
| Recursive Fuzzing | 2-5min | Depends on depth & wordlist |
| Nuclei | 1-3min | Template-based scanning |

**Total scan time**: 5-25 minutes per domain (depending on findings)

## 🛡️ Security & Ethics

⚠️ **Important**: Only scan domains you own or have explicit permission to test.

- This tool is for authorized security testing only
- Unauthorized scanning may be illegal in your jurisdiction
- Always obtain written permission before scanning
- Use responsibly and ethically

## 🐛 Troubleshooting

### Report file not found
- **Docker**: Make sure you mounted the volume: `-v $(pwd)/reports:/reports`
- **Local**: Reports are saved to `/reports/` directory by default
- Check the console output for the exact path: `[INFO] Report saved to: ...`

### Permission denied when saving report
- **Docker**: The `/reports` directory needs write permissions
- **Fix**: The Docker container creates the directory automatically, but if you pre-created it, run: `chmod 777 ./reports`

### No subdomains found
- Target may have no public subdomains
- Try adding API keys for Subfinder (see Configuration section)
- Base domain will still be scanned

### Fuzzing times out
- Increase timeout: `fuzz_directories(url, timeout=300)`
- Reduce recursion depth: `max_depth=2`
- Use a smaller wordlist

### Docker build fails
- Ensure Docker Desktop is running
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
- **Reflected XSS**: High risk - user input reflected without sanitization
- **Potential DOM XSS**: Medium risk - dangerous JavaScript patterns detected
- **Exposed directory listing**: High risk - files can be enumerated
- **Accessible path**: Medium risk - sensitive path exposed
- **Forbidden but exists**: Low risk - path exists but protected
- **Admin panel exposed**: High risk - potential unauthorized access
- **Backup file found**: Critical - may contain sensitive data
- **Nuclei findings**: Varies by template - check Nuclei docs

## 📤 Report Formats

### JSON Report (Default)
```json
{
  "target": "example.com",
  "scan_date": "2026-01-16T02:58:23.123456",
  "total_targets": 3,
  "total_vulnerabilities": 5,
  "results": [
    {
      "url": "https://example.com",
      "vulnerability_count": 2,
      "vulnerabilities": [
        {
          "type": "reflected_xss",
          "parameter": "search",
          "payload": "<script>alert('XSS')</script>",
          "severity": "high",
          "description": "Reflected XSS found in parameter 'search'"
        }
      ]
    }
  ]
}
```

### HTML Report
- Color-coded severity levels
- Responsive design
- Summary cards with statistics
- Organized by target URL
- Professional styling

### Markdown Report
- Easy to read in text editors
- Great for documentation
- Can be converted to PDF
- Version control friendly

### CSV Report
- Import into Excel/Google Sheets
- Easy data analysis
- Filter and sort vulnerabilities
- Columns: Target, URL, Type, Description, Severity, Status Code

## 🤝 Contributing

Contributions welcome! Feel free to:
- Add new scanner modules to `scanners/`
- Improve detection patterns
- Enhance XSS payloads and detection logic
- Add new report formats
- Improve recursive fuzzing logic
- Add new wordlists or templates

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

rocket452 - [GitHub](https://github.com/rocket452/SecurityScanner)

---

**Version**: 4.0 (XSS Scanner Integration)  
**Last Updated**: January 2026  
**Status**: Production Ready 🚀
