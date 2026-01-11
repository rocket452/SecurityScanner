import subprocess
import yaml
import json
import os
from s3_scanner import scan_s3_bucket
from git_scanner import scan_git_exposure
from admin_scanner import scan_admin_panels
from backup_scanner import scan_backups

# Load config
def load_config():
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)

def get_subdomains(domain):
    print(f"[*] Enumerating subdomains for {domain}...")
    result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
    return [s.strip() for s in result.stdout.splitlines() if s.strip()]

def main():
    config = load_config()
    target = config['target_domain']
    report = {'target': target, 'timestamp': '2026-01-10', 'vulnerabilities': []}
    
    subdomains = get_subdomains(target)
    print(f"[*] Found {len(subdomains)} subdomains. Scanning...")
    
    for sub in subdomains:
        base_url = f"https://{sub}"
        print(f"[*] Scanning {base_url}")
        
        # Run all scanners
        if scan_s3_bucket(base_url):
            report['vulnerabilities'].append({
                'type': 's3_bucket', 'url': f'{base_url}/file-service/static/', 'severity': 'high'
            })
        
        if scan_git_exposure(base_url):
            report['vulnerabilities'].append({'type': 'git_exposure', 'url': f'{base_url}/.git/HEAD', 'severity': 'critical'})
        
        admin_hits = scan_admin_panels(base_url)
        for hit in admin_hits:
            report['vulnerabilities'].append({'type': 'admin_panel', 'url': hit, 'severity': 'medium'})
        
        backup_hits = scan_backups(base_url)
        for hit in backup_hits:
            report['vulnerabilities'].append({'type': 'backup_file', 'url': hit, 'severity': 'high'})
    
    # Save report
    with open('vuln_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved: vuln_report.json ({len(report['vulnerabilities'])} vulns found)")

if __name__ == '__main__':
    main()