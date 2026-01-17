# SecurityScanner

A comprehensive, containerized security scanning platform that combines multiple industry-standard tools into a unified pipeline for web application security assessment.

## 🎯 Overview

SecurityScanner automates the discovery and assessment of web application vulnerabilities by orchestrating multiple specialized security tools. It performs subdomain enumeration, vulnerability scanning, directory fuzzing, and generates unified reports that eliminate duplicate findings across scanners.

## 🔧 Tools & Technologies

### Core Scanning Tools

| Tool | Purpose | Integration |
|------|---------|-------------|
| **OWASP ZAP** | Web application vulnerability scanner | Containerized, API-based |
| **Nuclei** | Template-based vulnerability detection | CLI integration |
| **Subfinder** | Passive subdomain enumeration | CLI integration |
| **Amass** | Advanced subdomain discovery | CLI integration |
| **ffuf** | High-performance directory/file fuzzing | CLI integration |
| **httpx** | Fast HTTP toolkit for probing | Python library |

### Custom Scanners

- **XSS Scanner**: Detects reflected and stored XSS vulnerabilities
- **Admin Panel Scanner**: Discovers exposed administrative interfaces
- **Backup File Scanner**: Finds leaked backup files and archives
- **Directory Scanner**: Identifies exposed storage buckets and directories
- **Path Discovery**: Recursive directory and file enumeration

## 🔄 Scanning Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    1. SUBDOMAIN DISCOVERY                       │
├─────────────────────────────────────────────────────────────────┤
│  • Subfinder → Passive DNS enumeration                          │
│  • Amass     → Certificate transparency, web scraping           │
│  • Dedup     → Remove duplicate subdomains                      │
│  • Output    → Unique list of target domains                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    2. DOMAIN PROBING                            │
├─────────────────────────────────────────────────────────────────┤
│  • httpx     → Test HTTP/HTTPS connectivity                     │
│  • Filter    → Keep only live, accessible domains               │
│  • Output    → List of (url, status_code) tuples               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    3. VULNERABILITY SCANNING                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────┐      ┌──────────────────────┐        │
│  │   ZAP SCANNER        │      │  TRADITIONAL SCANS   │        │
│  ├──────────────────────┤      ├──────────────────────┤        │
│  │ • Spider (crawl)     │      │ • Admin panels       │        │
│  │ • Passive scan       │      │ • Backup files       │        │
│  │ • Active scan (opt)  │      │ • XSS injection      │        │
│  │ • AJAX spider        │      │ • Storage exposure   │        │
│  └──────────────────────┘      │ • Directory fuzzing  │        │
│            │                   │ • Nuclei templates   │        │
│            │                   └──────────────────────┘        │
│            │                             │                     │
│            └──────────┬──────────────────┘                     │
│                       ↓                                        │
│              Merge all findings                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    4. DEDUPLICATION                             │
├─────────────────────────────────────────────────────────────────┤
│  • Fingerprint → Create MD5 hash from (type|desc|url)          │
│  • Detect      → Identify duplicate findings                    │
│  • Track       → Record which scanners found each issue         │
│  • Output      → Deduplicated vulnerabilities with sources      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    5. REPORT GENERATION                         │
├─────────────────────────────────────────────────────────────────┤
│  • Console   → Terminal output with severity levels             │
│  • JSON      → Machine-readable structured data                 │
│  • HTML      → Styled web report with severity colors           │
│  • Markdown  → Documentation-friendly format                    │
│  • CSV       → Spreadsheet-compatible tabular data              │
│  • ZAP HTML  → ZAP-specific detailed report (optional)          │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/rocket452/SecurityScanner.git
cd SecurityScanner

# Start all services (ZAP + Scanner)
docker-compose up -d --build

# Verify ZAP is running
curl http://localhost:8080
```

### Running Your First Scan

```bash
# Basic scan (all tools except ZAP)
docker-compose run scanner example.com

# With ZAP integration
docker-compose run scanner example.com --zap

# ZAP with active scanning (requires authorization!)
docker-compose run scanner example.com --zap --zap-active
```

## 📖 Usage Examples

### Standard Workflow

```bash
# Comprehensive scan with all tools
docker-compose run scanner target.com --zap

# Skip Nuclei (faster scan)
docker-compose run scanner target.com --zap --skip-nuclei

# ZAP only (skip custom scanners)
docker-compose run scanner target.com --zap-only
```

### Custom Output Formats

```bash
# HTML report
docker-compose run scanner target.com --zap -f html -o my_report.html

# Markdown documentation
docker-compose run scanner target.com -f markdown -o scan_results.md

# CSV for spreadsheet analysis
docker-compose run scanner target.com -f csv -o vulnerabilities.csv

# Console only (no file)
docker-compose run scanner target.com --zap --no-file
```

### Advanced Options

```bash
# Custom ZAP proxy URL
docker-compose run scanner target.com --zap --zap-proxy http://zap:8080

# Extended ZAP timeout
docker-compose run scanner target.com --zap --zap-timeout 600

# Scan specific subdomain or URL
docker-compose run scanner api.example.com --zap
docker-compose run scanner example.com:8443/app --zap
```

## ⚙️ Configuration

### config.yaml

Customize scanner behavior by editing `config.yaml`:

```yaml
rate_limiting:
  nuclei_rate_limit: 150      # Nuclei requests per minute
  nuclei_concurrency: 25       # Concurrent Nuclei templates
  http_timeout: 10             # HTTP connection timeout
  ffuf_threads: 20             # ffuf concurrent threads

zap:
  enabled: false               # Auto-enable ZAP (or use --zap flag)
  proxy_url: 'http://zap:8080' # ZAP proxy endpoint
  api_key: null                # Optional API key for auth
  timeout: 300                 # Scan timeout in seconds
  spider: true                 # Enable web crawling
  passive_scan: true           # Enable passive vulnerability detection
  active_scan: false           # Enable active scanning (invasive!)
  max_spider_depth: 5          # Maximum crawl depth
```

### Docker Compose Services

**docker-compose.yml** defines two services:

```yaml
services:
  zap:
    # Official OWASP ZAP stable image
    image: ghcr.io/zaproxy/zaproxy:stable
    ports:
      - "8080:8080"  # ZAP API/Proxy port
    # Configured for API access without authentication
    
  scanner:
    # Main security scanner application
    build: .
    volumes:
      - ./reports:/reports  # Report output directory
    depends_on:
      - zap
```

## 🔍 How Each Tool Works

### 1. Subdomain Discovery

**Subfinder**
- Sources: DNS records, certificate transparency logs, search engines
- Speed: Fast passive enumeration
- Output: List of discovered subdomains

**Amass**
- Sources: DNS, certificates, web archives, APIs
- Techniques: Brute force, alterations, recursive queries
- Output: Comprehensive subdomain list with metadata

### 2. Vulnerability Detection

**OWASP ZAP**
- **Spider**: Crawls web application to map attack surface
- **Passive Scan**: Analyzes traffic without sending attacks
- **Active Scan**: Sends attack payloads (requires permission)
- **Detects**: XSS, SQLi, CSRF, header issues, SSL problems, etc.

**Nuclei**
- **Template-based**: Uses YAML templates for specific vulnerabilities
- **Coverage**: CVEs, misconfigurations, exposed panels
- **Customizable**: Add custom templates for specific checks

**Custom Scanners**
- **XSS Scanner**: Tests common reflection points with payloads
- **Admin Scanner**: Checks for `/admin`, `/wp-admin`, etc.
- **Backup Scanner**: Looks for `.bak`, `.backup`, `.sql` files
- **Directory Scanner**: Fuzzes for exposed S3, Azure, GCP buckets

### 3. Directory Fuzzing

**ffuf**
- **Recursive**: Discovers nested directories up to max_depth
- **Smart filtering**: Ignores 404s, tracks 403s separately
- **Wordlist**: Uses curated list of common paths
- **Output**: Accessible paths with status codes

### 4. Deduplication Engine

**How it works:**
1. Creates fingerprint: `MD5(type|description|url)`
2. Compares all findings across scanners
3. Merges duplicates, tracks sources
4. Example output: `[Detected by: ZAP, Nuclei, XSS Scanner]`

**Benefits:**
- Reduces noise in reports
- Shows consensus across tools (higher confidence)
- Highlights unique findings from specific scanners

## 📊 Report Formats

### JSON (Default)
```json
{
  "target": "example.com",
  "scan_date": "2026-01-17T09:45:00",
  "total_vulnerabilities": 12,
  "results": [
    {
      "url": "https://example.com",
      "vulnerabilities": [
        {
          "type": "xss",
          "description": "Reflected XSS in search parameter",
          "severity": "high",
          "sources": ["ZAP", "XSS Scanner"]
        }
      ]
    }
  ]
}
```

### HTML
- Styled web report with color-coded severity levels
- Responsive design for mobile/desktop viewing
- Sortable/filterable vulnerability lists
- Source attribution for each finding

### Markdown
- Perfect for GitHub/GitLab documentation
- Easy to version control and diff
- Human-readable format

### CSV
- Import into Excel, Google Sheets, or databases
- Easy filtering and pivot tables
- Columns: Target, URL, Type, Description, Severity, Sources

## 🏗️ Architecture

### Why Docker Compose?

**Previous Challenges:**
- `python-owasp-zap-v2.4` library dependency issues
- Version conflicts between Python packages
- Complex ZAP installation and configuration

**Current Solution:**
- ZAP runs in official container (always up-to-date)
- Scanner communicates via REST API (language-agnostic)
- Clean separation of concerns
- Easy to scale or replace components

### Container Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Host                          │
│                                                         │
│  ┌──────────────────┐         ┌──────────────────┐    │
│  │  ZAP Container   │         │ Scanner Container │    │
│  │                  │         │                   │    │
│  │  • ZAP Daemon    │←────────│  • Python App     │    │
│  │  • API Server    │ REST API│  • CLI Tools      │    │
│  │  • Port 8080     │         │  • Custom Scans   │    │
│  └──────────────────┘         └──────────────────┘    │
│         ↑                              ↓               │
│         │                              │               │
│         │                         /reports (volume)    │
│         │                              │               │
│         └──────────────────────────────┘               │
└─────────────────────────────────────────────────────────┘
                    ↓
            Target Website
```

## 🔒 Security Considerations

### ⚠️ Active Scanning Warnings

**Never use `--zap-active` without authorization!**

Active scanning:
- Sends actual attack payloads
- May trigger security alerts or IDS/IPS
- Can cause service disruption
- May violate terms of service
- Could be illegal on unauthorized targets

**Only use on:**
- Systems you own
- Explicitly authorized penetration tests
- Isolated test environments

### Rate Limiting

Default rate limits prevent overwhelming targets:
- Nuclei: 150 requests/minute
- Nuclei concurrency: 25 templates
- HTTP timeout: 10 seconds

Adjust in `config.yaml` for faster/slower scanning.

### Responsible Disclosure

If you discover vulnerabilities:
1. Document findings with screenshots/PoC
2. Contact security team via responsible disclosure channel
3. Allow reasonable time for patching (typically 90 days)
4. Avoid public disclosure before patch is available

## 📁 Project Structure

```
SecurityScanner/
├── scanner.py              # Main orchestration script
├── scanners/               # Modular scanner components
│   ├── admin_scanner.py    # Admin panel detection
│   ├── backup_scanner.py   # Backup file discovery
│   ├── directory_scanner.py # Directory fuzzing & buckets
│   ├── xss_scanner.py      # XSS vulnerability testing
│   ├── zap_scanner.py      # ZAP API integration
│   └── deduplicator.py     # Duplicate finding removal
├── config.yaml             # Scanner configuration
├── docker-compose.yml      # Service orchestration
├── Dockerfile              # Scanner container build
├── requirements.txt        # Python dependencies
└── reports/                # Output directory (created at runtime)
```

## 🛠️ Troubleshooting

### ZAP Not Accessible

```bash
# Check if ZAP is running
docker-compose ps

# View ZAP logs
docker-compose logs zap

# Restart ZAP
docker-compose restart zap

# Test ZAP API
curl http://localhost:8080
```

### Scanner Errors

```bash
# View scanner logs
docker-compose logs scanner

# Rebuild scanner container
docker-compose down
docker-compose up -d --build

# Check if required tools are installed
docker-compose run scanner which nuclei subfinder amass ffuf
```

### No Subdomains Found

- Verify target domain is correct
- Some domains have minimal subdomains
- Check Subfinder/Amass are installed correctly
- Try manual subdomain list with `-o` flag

### Permission Denied Errors

```bash
# Fix report directory permissions
sudo chown -R $USER:$USER ./reports
chmod -R 755 ./reports
```

## 🔄 Updates & Maintenance

### Update Scanner Code

```bash
git pull origin main
docker-compose down
docker-compose up -d --build
```

### Update ZAP

```bash
# Pull latest ZAP image
docker-compose pull zap

# Restart with new image
docker-compose up -d zap
```

### Update Nuclei Templates

```bash
# Inside scanner container
docker-compose run scanner nuclei -update-templates
```

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional custom scanners (API testing, GraphQL, etc.)
- More vulnerability templates
- Enhanced reporting features
- Performance optimizations
- Integration with bug bounty platforms

## 📄 License

MIT License - see LICENSE file for details

## ⚖️ Legal Disclaimer

This tool is for authorized security testing only. Users are responsible for:
- Obtaining proper authorization before scanning
- Complying with applicable laws and regulations
- Using findings responsibly and ethically

The authors assume no liability for misuse or damage caused by this tool.

## 📞 Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/rocket452/SecurityScanner/issues
- Documentation: This README
- ZAP Documentation: https://www.zaproxy.org/docs/

---

**Happy Hunting! 🎯🔍**