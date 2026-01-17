# SecurityScanner

Comprehensive security scanner with OWASP ZAP integration, subdomain discovery, and vulnerability assessment.

## Features

- **Subdomain Discovery**: Uses Subfinder and Amass
- **OWASP ZAP Integration**: Containerized ZAP for web application scanning
- **Vulnerability Scanning**: Nuclei, XSS detection, admin panel discovery, backup file detection
- **Directory Fuzzing**: Recursive directory and file discovery
- **Multiple Report Formats**: JSON, HTML, Markdown, CSV

## Quick Start

### Using Docker Compose (Recommended)

1. **Start ZAP service**:
   ```bash
   docker-compose up -d zap
   ```

2. **Run a scan**:
   ```bash
   python3 scanner.py example.com --zap
   ```

### Without Docker

If you prefer to run ZAP manually:

```bash
# Start ZAP daemon
docker run -u zap -p 8080:8080 -d ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=true

# Install dependencies
pip install -r requirements.txt

# Run scanner
python3 scanner.py example.com --zap
```

## Usage

### Basic Scan
```bash
python3 scanner.py example.com
```

### With ZAP Passive Scanning
```bash
python3 scanner.py example.com --zap
```

### With ZAP Active Scanning (Requires Permission!)
```bash
python3 scanner.py example.com --zap --zap-active
```

### ZAP Only (Skip Traditional Scanners)
```bash
python3 scanner.py example.com --zap-only
```

### Custom Output
```bash
# HTML report
python3 scanner.py example.com --zap -f html -o my_report.html

# Markdown report
python3 scanner.py example.com --zap -f markdown -o report.md
```

## Configuration

Edit `config.yaml` to customize scan settings:

```yaml
rate_limiting:
  nuclei_rate_limit: 150      # Requests per minute
  nuclei_concurrency: 25       # Concurrent templates
  http_timeout: 10             # HTTP timeout in seconds

zap:
  enabled: true                # Enable ZAP by default
  proxy_url: 'http://localhost:8080'
  api_key: null                # Optional API key
  timeout: 300                 # Scan timeout in seconds
  spider: true                 # Enable spidering
  passive_scan: true           # Enable passive scanning
  active_scan: false           # Enable active scanning (use with caution!)
  max_spider_depth: 5          # Maximum spider depth
```

## Architecture Changes

### Previous Implementation
- Used `python-owasp-zap-v2.4` Python library
- Required installing Python package dependencies
- Library dependency management issues

### New Implementation (Containerized)
- **ZAP runs as a Docker container** using official `ghcr.io/zaproxy/zaproxy:stable` image
- **Uses ZAP's REST API directly** - no Python library needed
- **Docker Compose** for easy service orchestration
- **Health checks** ensure ZAP is ready before scanning
- **Better isolation** between scanner and ZAP engine
- **Easier updates** - just pull the latest ZAP image

## Docker Compose Services

- **zap**: OWASP ZAP proxy daemon (port 8080)
- **scanner**: Main security scanner application

## Requirements

- Docker & Docker Compose
- Python 3.8+
- External tools (for full functionality):
  - subfinder
  - amass
  - nuclei
  - ffuf (for directory fuzzing)

## Reports

Reports are saved to `/reports` directory by default with timestamp and target information.

## Security Warning

⚠️ **Active scanning can be intrusive!** Only use `--zap-active` on systems you own or have explicit permission to test.

## License

MIT License
