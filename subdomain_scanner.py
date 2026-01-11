import subprocess
import requests

# 1. Configuration
target_domain = "platacard.mx"
# Common paths where S3 buckets are often proxy-mounted
critical_paths = ["/static/", "/assets/", "/file-service/static/", "/uploads/", "/media/"]

def get_subdomains(domain):
    print(f"[*] Discovering subdomains for {domain}...")
    # This calls 'subfinder', a popular tool. You'll need it installed: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
    result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
    return result.stdout.splitlines()

def scan_for_s3(url):
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        # The S3 XML Signature check
        if "<ListBucketResult" in response.text:
            return True
    except:
        pass
    return False

# 2. Execution Loop
subdomains = get_subdomains(target_domain)
print(f"[*] Found {len(subdomains)} subdomains. Starting S3 scan...")

for sub in subdomains:
    for path in critical_paths:
        test_url = f"https://{sub}{path}"
        print(f"Checking: {test_url}", end="\r")
        
        if scan_for_s3(test_url):
            print(f"\n[!!!] VULNERABILITY FOUND: {test_url}")
            # Save to a file for your report
            with open("found_buckets.txt", "a") as f:
                f.write(test_url + "\n")

print("\n[*] Scan complete.")