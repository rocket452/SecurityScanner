import requests

def scan_s3_bucket(base_url):
    paths = ['/static/', '/assets/', '/file-service/static/', '/uploads/', '/media/', '/bucket/', '/s3/']
    for path in paths:
        url = base_url + path
        try:
            resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if '<ListBucketResult' in resp.text or 'ListBucketResult' in resp.text:
                print(f"  [HIGH] Exposed S3 bucket: {url}")
                return True
            # Azure/Google signatures
            if 'EnumerationResults' in resp.text:
                print(f"  [HIGH] Exposed Azure Blob: {url}")
                return True
        except:
            pass
    return False