import requests

def scan_git_exposure(base_url):
    git_url = base_url + '.git/HEAD'
    try:
        resp = requests.get(git_url, timeout=5)
        if resp.status_code == 200 and 'ref:' in resp.text:
            print(f"  [CRITICAL] .git exposed: {git_url}")
            return True
    except:
        pass
    return False