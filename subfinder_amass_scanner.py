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
    cmds = [
        ['subfinder', '-d', target, '-silent'],
        ['docker', 'run', '--rm', 'projectdiscovery/subfinder:latest', '-d', target, '-silent']
    ]
    for i, cmd in enumerate(cmds):
        try:
            log(f'Try {i+1}: {" ".join(cmd[:3])}...')
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
            if subs:
                log(f'Subfinder success ({len(subs)} subs)', 'OK')
                return subs
        except subprocess.TimeoutExpired:
            log('Timeout', 'WARN')
        except FileNotFoundError as e:
            log(f'Missing: {cmd[0]}', 'WARN')
        except subprocess.CalledProcessError as e:
            log(f'Error {e.returncode}: {e.stderr[:200]}...', 'ERROR')
        except Exception as e:
            log(f'Unexpected: {e}', 'ERROR')
    return set()

def run_amass(target):
    log(f'Amass on {target}')
    cmds = [
        ['amass', 'enum', '-passive', '-d', target, '-silent'],
        ['docker', 'run', '--rm', 'owaspamass/amass:latest', 'enum', '-passive', '-d', target, '-silent']
    ]
    for i, cmd in enumerate(cmds):
        try:
            log(f'Try {i+1}: {" ".join(cmd[:4])}...')
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
            subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
            if subs:
                log(f'Amass success ({len(subs)} subs)', 'OK')
                return subs
        except subprocess.TimeoutExpired:
            log('Timeout', 'WARN')
        except FileNotFoundError as e:
            log(f'Missing: {cmd[0]}', 'WARN')
        except subprocess.CalledProcessError as e:
            log(f'Exit {e.returncode}: {e.stderr[:300] or e.stdout[:300]}...', 'ERROR')
        except Exception as e:
            log(f'Unexpected: {e}', 'ERROR')
    return set()

def scan_vulnerabilities(url):
    vulns = []
    try:
        from admin_scanner import check_admin
        from backup_scanner import check_backup
        if check_admin(url):
            vulns.append('Admin panel exposed')
            log(f'ADMIN on {url}', 'VULN')
        if check_backup(url):
            vulns.append('Backup file found')
            log(f'BACKUP on {url}', 'VULN')
    except Exception as e:
        log(f'Scanner error: {e}', 'WARN')
    return vulns

def probe_subdomains(subdomains):
    live = []
    with httpx.Client(timeout=10.0, follow_redirects=True) as client:
        for sub in sorted(subdomains):
            for proto in ['https', 'http']:
                try:
                    resp = client.get(f'{proto}://{sub}')
                    if resp.status_code == 200:
                        vulns = scan_vulnerabilities(f'{proto}://{sub}')
                        live.append((f'{proto}://{sub}', vulns))
                        print(f'✅ {proto}://{sub} (200)')
                        break
                except:
                    pass
    return live

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Security Scanner w/ Detailed Logs')
    parser.add_argument('target', help='Target domain')
    args = parser.parse_args()
    
    print(f'🔍 {args.target}')
    subs1 = run_subfinder(args.target)
    subs2 = run_amass(args.target)
    all_subs = subs1.union(subs2)
    print(f'{len(all_subs)} subs: {sorted(all_subs)}')
    
    live_scans = probe_subdomains(all_subs)
    print('\n🚨 VULNERABILITIES:')
    for url, vulns in live_scans:
        for v in vulns:
            print(f'{url}: {v}')
