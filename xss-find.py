import requests
import urllib.parse
from bs4 import BeautifulSoup

# Load XSS payloads from a file
def load_payloads(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# Load URLs from a file
def load_urls(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# Inject payload into URL parameters
def inject_payload(url, payload):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    injected_qs = {k: payload for k in qs} if qs else {"q": payload}
    new_qs = urllib.parse.urlencode(injected_qs, doseq=True)
    new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
    return new_url

# Check if the payload appears in the HTML response
def is_payload_reflected(response_text, payload):
    soup = BeautifulSoup(response_text, "html.parser")
    return payload in response_text or payload in soup.text

# Scan each URL with each payload
def scan_xss(url_file, payload_file):
    urls = load_urls(url_file)
    payloads = load_payloads(payload_file)
    print(f"[+] Loaded {len(urls)} URLs")
    print(f"[+] Loaded {len(payloads)} payloads")

    for url in urls:
        print(f"\n[*] Testing: {url}")
        for payload in payloads:
            test_url = inject_payload(url, payload)
            try:
                res = requests.get(test_url, timeout=5)
                if is_payload_reflected(res.text, payload):
                    print(f"[!!] Possible XSS Found!\nURL: {test_url}\nPayload: {payload}")
                    break  # Stop testing this URL after first positive payload
            except requests.RequestException as e:
                print(f"[-] Error requesting {test_url}: {e}")

# Entry point
if __name__ == "__main__":
    scan_xss("wordlist.txt", "payloads.txt")

