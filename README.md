# SecurityScanner - Modular Bug Bounty Tool

Automated vulnerability scanner for HackerOne reports.

## Quick Start
1. Install dependencies:
```
pip install requests pyyaml
# Install subfinder (Go tool)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

2. Edit config.yaml with target domain

3. Run:
```
python scanner.py
```

## Modules
- s3_scanner.py: Exposed cloud buckets
- git_scanner.py: .git exposure
- admin_scanner.py: Admin panels
- backup_scanner.py: Backup files

Output: vuln_report.json (HackerOne ready)