#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_admin(url, headers=None, max_workers=8):
    """Check for common admin panels/backdoors"""
    admin_paths = [
        '/admin', '/administrator', '/wp-admin', '/cpanel', '/webmail',
        '/phpmyadmin', '/adminer', '/login', '/panel', '/dashboard'
    ]
    keywords = ['admin', 'login', 'panel', 'cpanel', 'dashboard']

    # First check if root is accessible to establish baseline
    root_status = None
    try:
        root_resp = requests.get(url, timeout=5, verify=False, headers=headers)
        root_status = root_resp.status_code
    except:
        pass
    
    # If entire domain returns 403 for root, don't flag admin paths
    if root_status == 403:
        return False

    try:
        workers = int(max_workers)
    except (TypeError, ValueError):
        workers = 8
    workers = max(1, min(workers, len(admin_paths)))

    def probe_admin_path(path):
        test_url = f'{url.rstrip("/")}{path}'
        try:
            resp = requests.get(test_url, timeout=5, verify=False, headers=headers)
        except Exception:
            return False

        body = (resp.text or '').lower()
        if resp.status_code == 200:
            title_match = re.search(r'<title[^>]*>([^<]+)', resp.text or '', re.I)
            title = title_match.group(1).strip().lower() if title_match else ''
            return any(x in body or x in title for x in keywords)
        if resp.status_code == 403 and root_status != 403:
            return True
        return 'directory listing' in body

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(probe_admin_path, path) for path in admin_paths]
        for future in as_completed(futures):
            try:
                if future.result():
                    return True
            except Exception:
                continue
    return False

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    print(f'{check_admin(url)=}')
