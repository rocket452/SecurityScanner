#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import yaml

# Logging
def log(msg, level='INFO'):
    print(f'[{level}] {msg}')

def run_subfinder(target):
    log(f'Subfinder on {target}')
    cmd = ['subfinder', '-d', target, '-silent']
    try:
        log(f'Running: {" ".join(cmd)}')
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
        if subs:
            log(f'Subfinder success ({len(subs)} subs)', 'OK')
            return subs
    except subprocess.TimeoutExpired:
        log('Timeout', 'WARN')
    except FileNotFoundError:
        log('Subfinder not installed', 'WARN')
    except subprocess.CalledProcessError as e:
        log(f'Error {e.returncode}: {e.stderr[:200]}...', 'ERROR')
    except Exception as e:
        log(f'Unexpected: {e}', 'ERROR')
    return set()

def run_amass(target):
    log(f'Amass on {target}')
    cmd = ['amass', 'enum', '-passive', '-d', target, '-silent']
    try:
        log(f'Running: {" ".join(cmd)}')
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
        subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
        if subs:
            log(f'Amass success ({len(subs)} subs)', 'OK')
            return subs
    except subprocess.TimeoutExpired:
        log('Timeout', 'WARN')
    except FileNotFoundError:
        log('Amass not installed', 'WARN')
    except subprocess.CalledProcessError as e:
        log(f'Exit {e.returncode}: {e.stderr[:300] or e.stdout[:300]}...', 'ERROR')
    except Exception as e:
        log(f'Unexpected: {e}', 'ERROR')
    return set()

def scan_vulnerabilities(url):
    vulns = []
    try:
        # Basic scanners
        from admin_scanner import check_admin
        from backup_scanner import check_backup
        if check_admin(url):
            vulns.append('Admin panel exposed')
            log(f'ADMIN on {url}', 'VULN')
        if check_backup(url):
            vulns.append('Backup file found')
            log(f'BACKUP on {url}', 'VULN')
        
        # Directory fuzzing
        log(f'Fuzzing directories on {url}', 'INFO')
        from directory_scanner import fuzz_directories
        discovered = fuzz_directories(url, timeout=120)
        if discovered:
            log(f'Discovered {len(discovered)} paths via fuzzing', 'OK')
            for path, status in discovered[:10]:  # Limit output to top 10
                vulns.append(f'Discovered path: /{path} [{status}]')
                log(f'FUZZ: /{path} [{status}]', 'VULN')
        else:
            log('No paths discovered via fuzzing', 'INFO')
        
        # Nuclei scan (increased timeout)
        log(f'Running Nuclei on {url}', 'INFO')
        result = subprocess.run(
            ['nuclei', '-u', url, '-silent', '-nc', '-severity', 'critical,high,medium'],
            capture_output=True, text=True, timeout=180
        )
        if result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    vulns.append(f'Nuclei: {line.strip()}')
                    log(f'NUCLEI: {line.strip()}', 'VULN')
    except subprocess.TimeoutExpired:
        log('Nuclei timeout', 'WARN')
    except FileNotFoundError:
        log('Nuclei not installed', 'WARN')
    except Exception as e:
        log(f'Scanner error: {e}', 'WARN')
    return vulns

def probe_subdomains(subdomains):
    live = []
    with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
        for sub in sorted(subdomains):
            for proto in ['https', 'http']:
                try:
                    resp = client.get(f'{proto}://{sub}')
                    # Accept any 2xx, 3xx, or 4xx status code (scan reachable hosts even if blocked)
                    if 200 <= resp.status_code < 500:
                        vulns = scan_vulnerabilities(f'{proto}://{sub}')
                        live.append((f'{proto}://{sub}', vulns))
                        print(f'✅ {proto}://{sub} ({resp.status_code})')
                        break
                    else:
                        log(f'{proto}://{sub} returned {resp.status_code}', 'DEBUG')
                except Exception as e:
                    log(f'{proto}://{sub} unreachable: {str(e)[:50]}', 'DEBUG')
    return live

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Security Scanner with Nuclei Integration')
    parser.add_argument('target', help='Target domain')
    args = parser.parse_args()
    
    print(f'🔍 {args.target}')
    subs1 = run_subfinder(args.target)
    subs2 = run_amass(args.target)
    all_subs = subs1.union(subs2)
    
    # Always include base domain in scan
    all_subs.add(args.target)
    log(f'Including base domain in scan: {args.target}', 'INFO')
    
    print(f'{len(all_subs)} targets: {sorted(all_subs)}')
    
    live_scans = probe_subdomains(all_subs)
    print('\n🚨 VULNERABILITIES:')
    for url, vulns in live_scans:
        for v in vulns:
            print(f'{url}: {v}')
    
    if not any(vulns for _, vulns in live_scans):
        print('No vulnerabilities detected.')
