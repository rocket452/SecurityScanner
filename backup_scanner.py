#!/usr/bin/env python3
import requests
import urllib3
import re

def check_backup(url):
    """Hunt for backup files/downloads"""
    backup_paths = [
        '/backup.zip', '/backup.tar.gz', '/db.sql', '/database.sql',
        '/wp-config.php.bak', '/config.bak', '/.env.bak', '/site.zip',
        '/backup/', '/old/', '/files.zip', 'config.php~', '.bak'
    ]
    try:
        for path in backup_paths:
            test_url = f'{url.rstrip("/")}{path}'
            resp = requests.get(test_url, timeout=5, verify=False)
            if resp.status_code == 200:
                content = resp.text.lower()
                if any(ext in test_url.lower() for ext in ['.bak', '.old', '.zip', '.sql', '.tar', 'backup']):
                    if len(resp.content) > 100:  # Non-trivial file
                        return True
                elif 'database' in content or 'password' in content or 'mysql' in content:
                    return True
        return False
    except:
        return False

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    print(f'{check_backup(url)=}')
