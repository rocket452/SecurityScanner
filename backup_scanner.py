import requests

BACKUP_PATHS = [
    '/.bak', '/.old', '/.backup', '/backup.tar.gz', '/db.sql',
    '/config.bak', '/wp-config.php~', '/.env.bak', '/database.sql.gz'
]

def scan_backups(base_url):
    hits = []
    for path in BACKUP_PATHS:
        url = base_url + path
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and len(resp.content) > 100:
                print(f"  [HIGH] Backup file: {url}")
                hits.append(url)
        except:
            pass
    return hits