#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_backup(url, headers=None, max_workers=8):
    """Hunt for backup files/downloads"""
    import hashlib

    backup_paths = [
        '/backup.zip', '/backup.tar.gz', '/db.sql', '/database.sql',
        '/wp-config.php.bak', '/config.bak', '/.env.bak', '/site.zip',
        '/backup/', '/old/', '/files.zip', 'config.php~', '.bak'
    ]
    file_markers = ['.bak', '.old', '.zip', '.sql', '.tar', 'backup']

    # Establish root/SPA baseline
    root_hash = None
    root_content_type = ''
    is_spa = False
    try:
        root_resp = requests.get(url, timeout=5, verify=False, headers=headers)
        root_hash = hashlib.md5((root_resp.text or '').encode()).hexdigest()
        root_content_type = root_resp.headers.get('content-type', '').lower()
    except Exception:
        pass

    # SPA detection: junk URL returning 200 means all 200s are catch-all
    try:
        junk_resp = requests.get(
            f'{url.rstrip("/")}/definitely-not-real-xzqy9173.zip',
            timeout=5, verify=False, headers=headers,
        )
        if junk_resp.status_code == 200:
            junk_hash = hashlib.md5((junk_resp.text or '').encode()).hexdigest()
            root_len = len(root_resp.text or '') if root_hash else 0
            if junk_hash == root_hash or abs(len(junk_resp.text or '') - root_len) < 200:
                is_spa = True
    except Exception:
        pass

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

        # On SPA sites, every URL returns 200 — require a non-HTML content type
        # (application/zip, application/octet-stream, text/plain, etc.)
        # to distinguish real files from catch-all routes.
        resp_ct = resp.headers.get('content-type', '').lower()
        if is_spa:
            if 'text/html' in resp_ct or not resp_ct:
                return False

        # Skip if content is identical to root (SPA catch-all returning index page)
        if root_hash:
            path_hash = hashlib.md5((resp.text or '').encode()).hexdigest()
            if path_hash == root_hash:
                return False

        content = (resp.text or '').lower()
        if any(ext in test_url.lower() for ext in file_markers):
            # For file-extension paths, only report if content looks like a real file
            # (not HTML) and has meaningful size
            if 'text/html' in resp_ct:
                return False
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
