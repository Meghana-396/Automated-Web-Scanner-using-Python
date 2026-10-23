"""
Automated Web Security Header Scanner
Use only on websites you own or have explicit permission to assess.
This tool makes one normal HTTP GET request and checks common response headers.
It does not exploit vulnerabilities or perform intrusive testing.
"""
import sys
import requests
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce some cross-site scripting risks.",
    "Strict-Transport-Security": "Tells browsers to prefer HTTPS for future visits.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps control whether the page can be framed.",
    "Referrer-Policy": "Controls referrer information sent by the browser.",
    "Permissions-Policy": "Controls access to selected browser features.",
}

def normalize_url(value):
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError("Please enter a valid domain or URL.")
    return value

def scan(url):
    print(f"\nScanning: {url}")
    print("-" * 60)
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Educational-Web-Header-Scanner/1.0"}
        )
    except requests.RequestException as exc:
        print(f"Request failed: {exc}")
        return 1

    print(f"HTTP status: {response.status_code}")
    print(f"Final URL: {response.url}")
    print("\nSecurity header checks:")
    missing = []
    for header, purpose in SECURITY_HEADERS.items():
        value = response.headers.get(header)
        if value:
            print(f"[PRESENT] {header}: {value}")
        else:
            print(f"[MISSING] {header} — {purpose}")
            missing.append(header)

    cors = response.headers.get("Access-Control-Allow-Origin")
    print("\nCORS observation:")
    if cors == "*":
        print("[REVIEW] Access-Control-Allow-Origin is '*'. This may be appropriate for public resources; review based on the endpoint and credentials.")
    elif cors:
        print(f"[INFO] Access-Control-Allow-Origin: {cors}")
    else:
        print("[INFO] No Access-Control-Allow-Origin header was returned.")

    print("\nSummary:")
    print(f"Security headers present: {len(SECURITY_HEADERS) - len(missing)}/{len(SECURITY_HEADERS)}")
    if missing:
        print("Headers to review: " + ", ".join(missing))
    else:
        print("All checked headers were present.")
    print("\nNote: Missing headers are observations, not proof of a vulnerability.")
    return 0

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter a website URL you are authorized to test: ")
    try:
        target = normalize_url(target)
    except ValueError as err:
        print(err)
        sys.exit(2)
    sys.exit(scan(target))
