# SecurityScanner + AutoRecon Integration

## Overview
Processes AutoRecon results with custom high-value vulnerability checks

## Prerequisites

### AutoRecon Setup (Choose One)

#### Option 1: Docker (Recommended)
```powershell
# Community image
docker run -it --rm -v E:\projects\results:/app/results darkstar7471/autorecon platacard.mx -vv

# OR build from source (in AutoRecon folder)
docker build -t autorecon .
docker run -it --rm -v E:\projects\results:/app/results autorecon platacard.mx
```

#### Option 2: WSL2 Kali (Full Features)
```powershell
# Admin PowerShell (one-time)
wsl --install -d kali-linux
# Restart PC → Launch 'Kali Linux' from Start
```
**In Kali terminal**:
```bash
sudo apt update && sudo apt install python3-pip git seclists nmap
cd /mnt/e/projects/autorecon
pipx install .
autorecon platacard.mx -vv
```

#### Option 3: Native Windows (Basic - Nmap only)
```powershell
pipx install git+https://github.com/Tib3rius/AutoRecon.git
pipx inject autorecon windows-curses
pipx ensurepath
refreshenv
autorecon platacard.mx --plugins nmap
```

## Usage Workflow
1. **Run AutoRecon** → Creates `./results/platacard.mx/`
2. **Process results**:
```bash
cd SecurityScanner
python autorecon_processor.py
# Input: results/platacard.mx/
```
3. **Review** `security_scanner_report.json`

## Features
- Parses Nmap XML for HTTP services (80/443/8080+)
- Runs your hardcoded_secrets + SQL injection checks
- Generates prioritized exploit chains

## Competitive Edge
AutoRecon finds 1000 assets → **Your scanner validates 5 exploitable vulns**

## Troubleshooting
- Docker pipe error → Docker Desktop → Troubleshoot → Reset
- termios error → Use Docker/WSL2
- Missing tools → AutoRecon skips gracefully

## Next: Add These Checks
- GraphQL introspection
- JWT weak secrets
- Cloud metadata endpoints (SSRF)

---
*Builds on AutoRecon commodity recon with your high-value validation*