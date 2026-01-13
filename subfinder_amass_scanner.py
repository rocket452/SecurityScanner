#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import yaml

def run_subfinder(target):
    """Try local first, then Docker if available"""
    cmds = [
        ['subfinder', '-d', target, '-silent'],  # Local
        ['docker', 'run', '--rm', 'projectdiscovery/subfinder:latest', '-d', target, '-silent']  # Docker fallback
    ]
    for cmd in cmds:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
            if subs:
                print(f'Subfinder OK ({cmd[0]}): {len(subs)} subs')
                return subs
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            continue
    print('Subfinder failed')
    return set()

def run_amass(target):
    """Try local first, then Docker"""
    cmds = [
        ['amass', 'enum', '-passive', '-d', target, '-silent'],  # Local
        ['docker', 'run', '--rm', 'owaspamass/amass:latest', 'enum', '-passive', '-d', target, '-silent']  # Docker
    ]
    for cmd in cmds:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
            subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
            if subs:
                print(f'Amass OK ({cmd[0]}): {len(subs)} subs')
                return subs
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            continue
    print('Amass failed')
    return set()

def scan_vulnerabilities(url):
    vulns = []
    try:
        # Your local scanners
        from admin_scanner import check_admin
        from backup_scanner import check_backup
        if check_admin(url):
            vulns.append('Admin panel exposed')
        if check_backup(url):
            vulns.append('Backup file found')
    except ImportError:
        pass  # Graceful if not available
    return vulns

def probe_subdomains(subdomains):
    live = []
    with httpx.Client(timeout=10.0, follow_redirects=True) as client:
        for sub in sorted(subdomains):
            for proto in ['https', 'http']:
                try:
                    resp = client.get(f'{proto}://{sub}')
                    if resp.status_code == 200:
                        live.append((f'{proto}://{sub}', scan_vulnerabilities(f'{proto}://{sub}')))
                        print(f'✅ LIVE: {proto}://{sub} (200)')
                        break
                except:
                    continue
    return live

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    args = parser.parse_args()
    
    print(f'🔍 Scanning {args.target}')
    subs1 = run_subfinder(args.target)
    subs2 = run_amass(args.target)
    all_subs = subs1.union(subs2)
    print(f'Found {len(all_subs)} subs: {sorted(all_subs)}')
    
    live_scans = probe_subdomains(all_subs)
    print('\n🚨 VULNS:')
    for url, vulns in live_scans:
        for v in vulns:
            print(f'  {url}: {v}')
    if not live_scans:
        print('No live hosts or vulns found')
