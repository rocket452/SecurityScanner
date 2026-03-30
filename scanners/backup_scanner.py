#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_backup(url, headers=None, max_workers=8):
    """Hunt for backup files/downloads"""
    backup_paths = [
        '/backup.zip', '/backup.tar.gz', '/db.sql', '/database.sql',
        '/wp-config.php.bak', '/config.bak', '/.env.bak', '/site.zip',
        '/backup/', '/old/', '/files.zip', 'config.php~', '.bak'
    ]
    file_markers = ['.bak', '.old', '.zip', '.sql', '.tar', 'backup']

    try:
        workers = int(max_workers)
    except (TypeError, ValueError):
        workers = 8
    workers = max(1, min(workers, len(backup_paths)))

    def probe_backup_path(path):
        test_url = f'{url.rstrip("/")}{path}'
        try:
            resp = requests.get(test_url, timeout=5, verify=False, headers=headers)
        except Exception:
            return False

        if resp.status_code != 200:
            return False

        content = (resp.text or '').lower()
        if any(ext in test_url.lower() for ext in file_markers):
            return len(resp.content or b'') > 100
        return 'database' in content or 'password' in content or 'mysql' in content

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(probe_backup_path, path) for path in backup_paths]
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
    print(f'{check_backup(url)=}')
