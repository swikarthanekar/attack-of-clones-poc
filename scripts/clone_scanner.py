import sys
import requests
import urllib.parse
import json
import re
import time


def search_codesearch(regex_pattern, debug=False):
    """
    Query codesearch.debian.net with a regex pattern.
    Returns a list of dicts: {package, file, url}
    """
    encoded_query = urllib.parse.quote(regex_pattern)
    search_url = f"https://codesearch.debian.net/search?q={encoded_query}&regexp=1"

    print(f"[+] querying: {search_url}\n")

    try:
        response = requests.get(search_url, timeout=20,
                                headers={"User-Agent": "Mozilla/5.0"})
    except requests.RequestException as err:
        print(f"[!] request failed: {err}")
        return []

    if response.status_code != 200:
        print(f"[!] codesearch returned status {response.status_code}")
        return []

    html = response.text

    if debug:
        # print a slice of HTML around the first result link to understand structure
        idx = html.find("grepped")
        if idx >= 0:
            print("[debug] HTML around result count:")
            print(html[max(0,idx-50):idx+200])
        idx2 = html.find("/show/")
        if idx2 >= 0:
            print("[debug] HTML around first /show/ link:")
            print(html[max(0,idx2-50):idx2+200])
        else:
            # show all unique href prefixes to understand structure
            all_hrefs = re.findall(r'href="([^"]{1,60})"', html)
            print("[debug] No /show/ links found. Sample hrefs:")
            for h in list(dict.fromkeys(all_hrefs))[:20]:
                print(" ", repr(h))

    results = []

    # codesearch.debian.net actual link format (confirmed from debug):
    # /show?file=package_version%2fpath%2fto%2ffile.c&line=N#LN
    # %2f is URL-encoded slash
    seen = set()
    for match in re.finditer(r'/show\?file=([^&"]+)&line=\d+', html):
        file_encoded = match.group(1)
        file_path = urllib.parse.unquote(file_encoded)  # decode %2f → /
        parts = file_path.split("/", 1)
        package = parts[0]
        filepath = parts[1] if len(parts) > 1 else file_path
        key = file_path
        if key not in seen:
            seen.add(key)
            results.append({
                "package": package,
                "file": filepath,
                "url": f"https://codesearch.debian.net/show?file={file_encoded}"
            })

    return results

    return results


def scan_signature_file(signature_path, debug=False):
    """
    Load a signatures JSON file and run codesearch for every
    generated_signature found in it. Reports all matches.
    """
    print(f"[+] loading signatures from {signature_path}")

    with open(signature_path, "r", encoding="utf-8") as f:
        signature_data = json.load(f)

    if not signature_data:
        print("[!] signature file is empty")
        return

    all_matches = {}

    for finding in signature_data:
        sig = finding.get("generated_signature")
        removed = finding.get("removed_line", "")

        if not sig:
            continue

        print(f"[+] pattern from: {removed[:60]}")
        matches = search_codesearch(sig, debug=debug)
        all_matches[removed[:60]] = matches

        print(f"    found {len(matches)} match(es)")
        for m in matches[:10]:
            if m.get("package"):
                print(f"    → {m['package']} : {m['file']}")
            else:
                print(f"    → {m['url']}")

        time.sleep(1)

    total = sum(len(v) for v in all_matches.values())
    print(f"\nTotal matches across all patterns: {total}")
    return all_matches


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python clone_scanner.py <signature_json> [--debug]")
        sys.exit(1)

    debug_mode = "--debug" in sys.argv
    scan_signature_file(sys.argv[1], debug=debug_mode)