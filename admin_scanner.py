import requests

ADMIN_PATHS = [
    '/admin/', '/administrator/', '/login/', '/wp-admin/', '/wp-login.php',
    '/admin.php', '/manager/', '/dashboard/', '/controlpanel/'
]

def scan_admin_panels(base_url):
    hits = []
    for path in ADMIN_PATHS:
        url = base_url + path
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code in [200, 401]:
                print(f"  [MEDIUM] Admin panel: {url} (Status: {resp.status_code})")
                hits.append(url)
        except:
            pass
    return hits