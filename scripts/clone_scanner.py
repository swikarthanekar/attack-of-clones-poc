import sys
import requests
import urllib.parse
import json
import re

def search_codesearch(regex_pattern):
    # query codesearch.debian.net using regex mode

    encoded_query = urllib.parse.quote(regex_pattern)
    search_url = f"https://codesearch.debian.net/search?q={encoded_query}&regexp=1"

    print(f"[+] querying codesearch with pattern:\n{regex_pattern}\n")

    try:
        response = requests.get(search_url, timeout=15)
    except requests.RequestException as err:
        print(f"[!] request failed: {err}")
        return []

    if response.status_code != 200:
        print(f"[!] codesearch returned status {response.status_code}")
        return []
    html_page = response.text
    link_matches = re.findall(r'href="/([^"]+)"', html_page)
    source_hits = [link for link in link_matches if "/src/" in link]

    return list(set(source_hits))

def scan_signature_file(signature_path):

    print(f"[+] loading signature from {signature_path}")

    with open(signature_path, "r", encoding="utf-8") as f:
        signature_data = json.load(f)
    if not signature_data:
        print("[!] signature file is empty")
        return
    regex_signature = signature_data[0]["generated_signature"]
    print(f"[+] using generated signature:\n{regex_signature}\n")

    matches = search_codesearch(regex_signature)

    print("Matches found: ")

    for match in matches[:20]:
        print(match)
    print("\nTotal matches:", len(matches))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python clone_scanner.py <signature_json>")
        sys.exit(1)
    signature_file = sys.argv[1]

    scan_signature_file(signature_file)