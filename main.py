import sys
import requests
from urllib.parse import urlparse
from datetime import datetime


Security_Headers = {
    "X-Frame-Options": {
        "description": "Prevents Clickjacking by controlling iframe embedding.",
        "severity": "CRITICAL",
        "recommended": "DENY or SAMEORIGIN",
    },
    "Content-Security-Policy": {
        "description": "Mitigates XSS and data injection attacks.",
        "severity": "CRITICAL",
        "recommended": "Define allowed content sources explicitly.",
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS).",
        "severity": "CRITICAL",
        "recommended": "max-age=31536000; includeSubDomains",
    },
"X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing attacks.",
        "severity": "HIGH",
        "recommended": "nosniff",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info is sent with requests.",
        "severity": "HIGH",
        "recommended": "no-referrer or strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Restricts access to browser features (camera, mic, etc.).",
        "severity": "HIGH",
        "recommended": "Restrict unused features explicitly.",
    },
    "X-XSS-Protection": {
        "description": "Enables browser's built-in XSS filter (legacy).",
        "severity": "MEDIUM",
        "recommended": "1; mode=block",
    },
    "Cache-Control": {
        "description": "Controls caching of sensitive responses.",
        "severity": "MEDIUM",
        "recommended": "no-store for sensitive pages",
    },
}


def calculate_grade(found_headers: list[str], all_headers: dict) -> tuple[str, str]:
    critical = [h for h, v in Security_Headers.items() if v["severity"] == "CRITICAL"]
    high_medium = [h for  h, v in Security_Headers.items() if v["severity"] in ("HIGH","MEDIUM")]

    critical_found = sum(1 for h in critical if h in found_headers)
    bonus_found = sum(1 for h in high_medium if h in found_headers)

    if critical_found == 3 and bonus_found >= 2:
        grade, summary = "A", "Excellent security posture."
    elif critical_found == 3:
        grade, summary = "B", "Good — all critical headers present. Add more hardening."
    elif critical_found == 2:
        grade, summary = "C", "Fair — missing one critical header. Significant risk."
    elif critical_found == 1:
        grade, summary = "D", "Poor — most critical headers missing. High vulnerability."
    else:
        grade, summary = "F", "Failing — no critical security headers detected!"

    return grade, summary


def normalize(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    return url


def fetch_headers(url: str) -> tuple[str, str]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }
    response = requests.get(
        url,
        headers=headers,
        timeout=10,
        allow_redirects=True,
    )
    return dict(response.headers), response.status_code, response.url

def print_banner():
    print("\n" + "=" * 60)
    print(fr"""
	       ___           ___           ___           ___     
              /  /\         /  /\         /__/\         /  /\    
             /  /:/_       /  /:/_        \  \:\       /  /:/_   
            /  /:/ /\     /  /:/ /\        \  \:\     /  /:/ /\  
           /  /:/ /::\   /  /:/ /::\   _____\__\:\   /  /:/ /::\ 
          /__/:/ /:/\:\ /__/:/ /:/\:\ /__/::::::::\ /__/:/ /:/\:\
          \  \:\/:/~/:/ \  \:\/:/~/:/ \  \:\~~\~~\/ \  \:\/:/~/:/
           \  \::/ /:/   \  \::/ /:/   \  \:\  ~~~   \  \::/ /:/ 
            \__\/ /:/     \__\/ /:/     \  \:\        \__\/ /:/  
              /__/:/        /__/:/       \  \:\         /__/:/   
              \__\/         \__\/         \__\/         \__\/    

      """)
    print("=" * 60)

def print_report(url: str, raw_headers: dict, status_code: int, final_url: str):
    found_headers = []
    missing_headers = []
    raw_lower = {k.lower(): v for k, v in raw_headers.items()}

    for header, meta in Security_Headers.items():
        if header.lower() in raw_lower:
            found_headers.append(header)
        else:
            missing_headers.append(header)

    grade, grade_summary = calculate_grade(found_headers, Security_Headers)
    print("\n" + "-" * 60)
    print(f"  SECURITY GRADE:  {grade}  —  {grade_summary}")
    print("-" * 60)

    print(f"\n PRESENT HEADERS ({len(found_headers)}/{len(Security_Headers)}):")
    print()
    if found_headers:
        for header in found_headers:
            value = raw_lower[header.lower()]
            severity = Security_Headers[header]["severity"]
            display_val = value if len(value) <= 60 else value[:57] + "..."
            print(f"    [{severity:<8}]  {header}")
            print(f"               Value: {display_val}")
            print()
    else:
        print("    None found.\n")

    print(f"\n MISSING HEADERS ({len(missing_headers)}/{len(Security_Headers)}):")
    print()
    if missing_headers:
        for header in missing_headers:
            meta = Security_Headers[header]
            print(f"    [{meta['severity']:<8}]  {header}")
            print(f"               Why it matters : {meta['description']}")
            print(f"               Recommended    : {meta['recommended']}")
            print()
    else:
        print("    All audited headers are present\n")

    print("-" * 60)
    print(f"\n ALL RAW RESPONSE HEADERS ({len(raw_headers)} total)")
    print()
    for key, value in sorted(raw_headers.items()):
        display_val = value if len(value) <= 55 else value[:52] + "..."
        print(f"    {key}: {display_val}")

    print("\n" + "=" * 60 + "\n")

def scan(url: str):
    url = normalize(url)
    print(f"\n  Scanning: {url} ...")

    try:
        raw_headers, status_code, final_url = fetch_headers(url)
        print_report(url, raw_headers, status_code, final_url)

    except requests.exceptions.SSLError:
        print(f"\nSSL Error — certificate issue on {url}")
        print("      Try scanning with http:// instead.\n")
    except requests.exceptions.ConnectionError:
        print(f"\nConnection Error — could not reach {url}")
        print("      Check the URL and your internet connection.\n")
    except requests.exceptions.Timeout:
        print(f"\nTimeout — {url} took too long to respond.\n")
    except requests.exceptions.InvalidURL:
        print(f"\nInvalid URL: {url}\n")
    except requests.exceptions.RequestException as e:
        print(f"\n Request failed: {e}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        print_banner()
        scan(target_url)
    else:
        print("\nNo target URL given.\n")
        sys.exit(1)
