#!/usr/bin/env python3
import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_admin(url):
    """Check for common admin panels/backdoors"""
    admin_paths = [
        '/admin', '/administrator', '/wp-admin', '/cpanel', '/webmail',
        '/phpmyadmin', '/adminer', '/login', '/panel', '/dashboard',
        '/backup', '/db_backup', '/site.bak', '.git/HEAD'
    ]
    try:
        for path in admin_paths:
            test_url = f'{url.rstrip("/")}{path}'
            resp = requests.get(test_url, timeout=5, verify=False)
            if resp.status_code == 200:
                title = re.search(r'<title[^>]*>([^<]+)', resp.text, re.I)
                title = title.group(1).strip() if title else ''
                if any(x in resp.text.lower() or x in title.lower() for x in ['admin', 'login', 'panel', 'cpanel', 'dashboard']):
                    return True
            elif resp.status_code == 403 or 'directory listing' in resp.text.lower():
                return True  # Forbidden or dirlist often indicates panel
        return False
    except:
        return False

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    print(f'{check_admin(url)=}')