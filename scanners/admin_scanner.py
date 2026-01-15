#!/usr/bin/env python3
import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_admin(url):
    """Check for common admin panels/backdoors"""
    admin_paths = [
        '/admin', '/administrator', '/wp-admin', '/cpanel', '/webmail',
        '/phpmyadmin', '/adminer', '/login', '/panel', '/dashboard'
    ]
    
    # First check if root is accessible to establish baseline
    root_status = None
    try:
        root_resp = requests.get(url, timeout=5, verify=False)
        root_status = root_resp.status_code
    except:
        pass
    
    # If entire domain returns 403 for root, don't flag admin paths
    if root_status == 403:
        return False
    
    try:
        for path in admin_paths:
            test_url = f'{url.rstrip("/")}{path}'
            resp = requests.get(test_url, timeout=5, verify=False)
            
            # Flag if admin path returns 200 with admin keywords
            if resp.status_code == 200:
                title = re.search(r'<title[^>]*>([^<]+)', resp.text, re.I)
                title = title.group(1).strip() if title else ''
                if any(x in resp.text.lower() or x in title.lower() for x in ['admin', 'login', 'panel', 'cpanel', 'dashboard']):
                    return True
            # Flag if admin path returns 403 but root doesn't
            elif resp.status_code == 403 and root_status != 403:
                return True
            elif 'directory listing' in resp.text.lower():
                return True
        return False
    except:
        return False

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    print(f'{check_admin(url)=}')
