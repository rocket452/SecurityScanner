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

- **Enhanced Breakout XSS Scanner**: Detects context-aware XSS with template literal, JSON, and multi-encoding detection
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

### 1. Clone and build

```bash
git clone https://github.com/rocket452/SecurityScanner.git
cd SecurityScanner

# Build scanner image and start ZAP service
docker-compose up -d --build
```

This will:
- Build the main scanner image
- Start OWASP ZAP on port 8080
- Create / use the reports/ directory for output

## 📖 Basic Usage

### Scan a single target

```bash
# Generic target (domain or host:port)
docker-compose run scanner target.com
```

Examples:

```bash
# Public test site
docker-compose run scanner testphp.vulnweb.com

# Local app (e.g., running on your host)
docker-compose run scanner host.docker.internal:3000
```

## 🎯 Enhanced Breakout XSS Scanner

### What is Breakout XSS?

Breakout XSS occurs when user input is reflected in a **restricted context** (JavaScript strings, JSON, template literals) where simple payloads like `<script>alert(1)</script>` are blocked, but **context-specific escape sequences** allow XSS execution.

**Example Scenarios:**
```javascript
// JavaScript String Context
var search = 'USER_INPUT';  // Payload: ';alert(1);//

// Template Literal Context  
const msg = `Hello ${USER_INPUT}`;  // Payload: ${alert(1)}

// JSON Context
{"query": "USER_INPUT"}  // Payload: "};alert(1);//
```

### Features

✅ **Template Literal Detection** - Detects `` `${payload}` `` contexts  
✅ **JSON Context Breakout** - Escapes JSON structures with `"}` patterns  
✅ **Multi-Layer Encoding** - Detects URL, HTML, Unicode, and JavaScript encoding  
✅ **JavaScript String Contexts** - Single/double quote escape detection  
✅ **WAF Bypass Payloads** - Encoding variations to evade filters  
✅ **Context Snippets** - Shows exact code where input is reflected  
✅ **CVSS Scoring** - Automated severity calculation  
✅ **Arjun Integration** - Automatic hidden parameter discovery  

### Enable Enhanced Breakout XSS Scanning

```bash
# Enable advanced breakout detection
docker-compose run scanner target.com --xss-deep
```

- Runs the enhanced breakout XSS scanner
- Uses 62+ payloads with context detection (HTML, JS string, template literal, JSON, attribute, URL, CSS)
- Generates detailed exploitation proof with code snippets

### Choose XSS Mode

```bash
# Basic (fewer payloads, faster)
docker-compose run scanner target.com --xss-deep --xss-mode basic

# Advanced (recommended for breakout detection)
docker-compose run scanner target.com --xss-deep --xss-mode advanced

# Exploitation / blind XSS (requires callback URL)
docker-compose run scanner target.com \
  --xss-deep \
  --xss-mode exploitation \
  --xss-callback https://your-callback.example/xss
```

### Example: Known Vulnerable Test Sites

```bash
# testphp.vulnweb.com (basic reflected XSS)
docker-compose run scanner "http://testphp.vulnweb.com/listproducts.php?cat=1" \
  --xss-deep \
  --skip-nuclei \
  -f html

# PortSwigger Web Security Academy (breakout XSS labs)
docker-compose run scanner "https://YOUR-LAB-ID.web-security-academy.net/?search=test" \
  --xss-deep \
  --skip-nuclei \
  -f html
```

### Breakout XSS Report Features

The HTML report includes:
- 🎯 **Breakout Context** - Highlighted yellow section showing context type (template literal, JSON, JS string)
- 📝 **Code Snippets** - Exact source code showing where input is reflected
- 🔐 **Encoding Layers** - List of detected encoding (URL, HTML, Unicode, etc.)
- 💥 **Working Payloads** - The exact payload that bypassed filters
- 📊 **CVSS Scoring** - Automated severity with reasoning
- 🔧 **Reproduction Steps** - cURL commands and browser instructions
- 🛡️ **Context-Specific Remediation** - Tailored security advice

## 🧪 Setting Up Local Breakout XSS Test Environment

To test the breakout detector with your own vulnerable pages, set up a local PHP server with Docker.

### Method 1: Quick PHP Test (Docker CLI)

```bash
# Create a test PHP file
mkdir test-breakout
cd test-breakout

# Create breakout-test.php
cat > breakout-test.php << 'EOF'
<?php
$search = $_GET['search'] ?? '';
?>
<!DOCTYPE html>
<html>
<head><title>Breakout XSS Test</title></head>
<body>
<h1>Search Results</h1>

<!-- JavaScript String Context - Single Quote -->
<script>
var searchTerm = '<?php echo addslashes($search); ?>';
document.write('<p>Search: ' + searchTerm + '</p>');
</script>

<!-- Template Literal Context -->
<script>
const query = `<?php echo $search; ?>`;
console.log('Query:', query);
</script>

<!-- JSON Context -->
<script>
var data = {"search": "<?php echo addslashes($search); ?>"};
console.log('Data:', data);
</script>

</body>
</html>
EOF

# Run PHP server in Docker
docker run -d --name php-test -p 8080:80 -v "$(pwd):/var/www/html" php:8.2-apache

# Scan the test page
docker-compose run scanner "http://host.docker.internal:8080/breakout-test.php?search=test" --xss-deep --skip-nuclei -f html

# Cleanup when done
docker stop php-test
docker rm php-test
```

### Method 2: Persistent PHP Environment (docker-compose)

Add to your `docker-compose.yml`:

```yaml
services:
  # ... existing services (zap, scanner) ...

  php-test:
    image: php:8.2-apache
    ports:
      - "8080:80"
    volumes:
      - ./test-breakout:/var/www/html
    networks:
      - scanner-network

networks:
  scanner-network:
    driver: bridge
```

Then:

```bash
# Start PHP test server
docker-compose up -d php-test

# Create test files in ./test-breakout/
mkdir -p test-breakout

# Create various test scenarios
cat > test-breakout/js-string.php << 'EOF'
<?php
$input = $_GET['q'] ?? '';
?>
<script>
var userInput = '<?php echo addslashes($input); ?>';
alert('Search: ' + userInput);
</script>
EOF

cat > test-breakout/template.php << 'EOF'
<?php
$input = $_GET['q'] ?? '';
?>
<script>
const msg = `User typed: ${<?php echo json_encode($input); ?>}`;
console.log(msg);
</script>
EOF

cat > test-breakout/json.php << 'EOF'
<?php
$input = $_GET['q'] ?? '';
header('Content-Type: application/json');
echo json_encode(['query' => $input]);
?>
EOF

# Scan each test
docker-compose run scanner "http://php-test/js-string.php?q=test" --xss-deep --skip-nuclei -f html
docker-compose run scanner "http://php-test/template.php?q=test" --xss-deep --skip-nuclei -f html
docker-compose run scanner "http://php-test/json.php?q=test" --xss-deep --skip-nuclei -f html
```

### Expected Breakout Detections

**JavaScript String Context (`js-string.php`):**
```
✅ Context: js_string_single
✅ Payload: ';alert(1);//
✅ Type: breakout_xss
```

**Template Literal Context (`template.php`):**
```
✅ Context: js_template_literal
✅ Payload: ${alert(1)}
✅ Type: breakout_xss
```

**JSON Context (`json.php`):**
```
✅ Context: json_context
✅ Payload: "};alert(1);//
✅ Type: breakout_xss
```

### Manual Testing URLs

Test your PHP server manually first:

```bash
# JavaScript String - should be blocked by addslashes()
http://localhost:8080/js-string.php?q=<script>alert(1)</script>

# But breakout payload should work:
http://localhost:8080/js-string.php?q=%27;alert(1);//

# Template literal - simple HTML blocked:
http://localhost:8080/template.php?q=<script>alert(1)</script>

# But template injection works:
http://localhost:8080/template.php?q=${alert(1)}
```

## 📊 Output and Reports

By default, reports are written inside the container to `/app/reports` and are mounted to the local `./reports` folder.

### Choose output format

```bash
# HTML report (recommended for humans)
docker-compose run scanner target.com --xss-deep -f html

# JSON (for tooling / automation)
docker-compose run scanner target.com --xss-deep -f json

# Markdown
docker-compose run scanner target.com --xss-deep -f markdown

# CSV
docker-compose run scanner target.com --xss-deep -f csv
```

### Specify output filename

```bash
docker-compose run scanner target.com \
  --xss-deep \
  -f html \
  -o my_scan_report.html
```

### Where to find reports

On your host (from the repo root):

```bash
# List reports
ls reports/

# On Windows:
dir reports

# Open latest HTML report (Windows)
start reports\report_*.html

# Open latest HTML report (Linux/Mac)
open reports/report_*.html
```

## 🐳 Running Against Local Apps (Docker Desktop)

If your target is running on your host (e.g., OWASP Juice Shop, DVWA):

Use `host.docker.internal` instead of `localhost` from inside the scanner container.

Examples:

```bash
# Juice Shop on host port 3000
docker-compose run scanner "http://host.docker.internal:3000" --xss-deep --xss-mode advanced -f html

# DVWA on host port 8090
docker-compose run scanner "http://host.docker.internal:8090" --xss-deep --skip-nuclei -f html

# Local PHP test server on port 8080
docker-compose run scanner "http://host.docker.internal:8080/test.php?search=test" --xss-deep --skip-nuclei -f html
```

## 📚 Advanced Usage Examples

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

xss:
  mode: 'advanced'             # XSS scanning mode: basic, advanced, exploitation
  timeout: 10                  # XSS request timeout
  callback_url: null           # Blind XSS callback URL (e.g., Burp Collaborator)
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
- **Enhanced Breakout XSS Scanner**: Context-aware detection with template literal, JSON, and multi-encoding support
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
          "type": "breakout_xss",
          "context_type": "js_string_single",
          "description": "Breakout XSS in search parameter",
          "severity": "high",
          "payload": "';alert(1);//",
          "encoding_layers": ["javascript", "addslashes"],
          "sources": ["Enhanced Breakout XSS Scanner"]
        }
      ]
    }
  ]
}
```

### HTML
- Styled web report with color-coded severity levels
- Breakout context highlighted in yellow boxes
- Code snippets showing exact reflection points
- Encoding detection badges
- Responsive design for mobile/desktop viewing
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
├── scanner.py                      # Main orchestration script
├── scanners/                       # Modular scanner components
│   ├── admin_scanner.py            # Admin panel detection
│   ├── backup_scanner.py           # Backup file discovery
│   ├── directory_scanner.py        # Directory fuzzing & buckets
│   ├── xss_scanner.py              # Basic XSS vulnerability testing
│   ├── xss_advanced.py             # Advanced XSS with context detection
│   ├── xss_breakout_detector.py    # Enhanced breakout XSS detection engine
│   ├── xss_breakout_scanner_patch.py  # Integration layer for breakout detection
│   ├── xss_payloads.py             # Payload generation and categorization
│   ├── param_discovery.py          # Arjun integration for hidden params
│   ├── zap_scanner.py              # ZAP API integration
│   └── deduplicator.py             # Duplicate finding removal
├── config.yaml                     # Scanner configuration
├── docker-compose.yml              # Service orchestration
├── Dockerfile                      # Scanner container build
├── requirements.txt                # Python dependencies
├── reports/                        # Output directory (created at runtime)
└── test-breakout/                  # Local PHP test files (optional)
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

### No XSS Found on Known Vulnerable Site

**Common issues:**

1. **Wrong URL format** - Must include `http://` or `https://`
   ```bash
   # ❌ Wrong
   docker-compose run scanner testphp.vulnweb.com/search.php
   
   # ✅ Correct
   docker-compose run scanner "http://testphp.vulnweb.com/search.php?test=1"
   ```

2. **Target requires specific parameters**
   ```bash
   # Include known parameters
   docker-compose run scanner "http://testphp.vulnweb.com/listproducts.php?cat=1"
   ```

3. **POST-only vulnerability** - Scanner primarily tests GET parameters
   ```bash
   # Test with form detection enabled (automatic with --xss-deep)
   docker-compose run scanner "http://target.com/search.php" --xss-deep
   ```

### Breakout XSS Not Detected

**Breakout XSS only triggers when:**
- Simple payloads (`<script>alert(1)</script>`) are **blocked/encoded**
- But context-specific payloads succeed

If the report shows `context: html`, it's **not a breakout scenario** - simple payloads work, so no breakout is needed.

**To test true breakout detection:**
1. Use PortSwigger Web Security Academy labs with JavaScript string contexts
2. Create local PHP test files with `addslashes()` or JSON encoding
3. Test sites where HTML tags are stripped but JavaScript contexts exist

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

### PHP Test Server Issues

```bash
# Check if PHP container is running
docker ps | grep php-test

# View PHP logs
docker logs php-test

# Restart PHP server
docker restart php-test

# Test PHP server directly
curl http://localhost:8080/breakout-test.php?search=test
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
- GitHub Issues: [https://github.com/rocket452/SecurityScanner/issues](https://github.com/rocket452/SecurityScanner/issues)
- Documentation: This README
- ZAP Documentation: [https://www.zaproxy.org/docs/](https://www.zaproxy.org/docs/)

---

**Happy Hunting! 🎯🔍**
