import re
import sys
import requests
import json
import os

sys.path.insert(0, os.path.dirname(__file__))
from analyze_patch import analyze_patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACKER_PATH = os.path.abspath(
    os.path.join(BASE_DIR, "..", "security-tracker", "data", "CVE", "list")
)

def _looks_like_c_patch(patch_text):
    """
    Heuristic to check if a patch is predominantly C/C++ code.
    Warns before wasting codesearch queries on PHP/Python/hex-data patches.
    """
    c_score = 0
    other_score = 0
    for line in patch_text.splitlines():
        if not line.startswith(('+', '-')):
            continue
        code = line[1:]
        # strong C/C++ indicators
        if any(p in code for p in [
            '#include', 'sizeof(', 'NULL', 'malloc(', 'free(',
            'nullptr', '::', 'if (!', 'if (!'  # C++ null checks
        ]):
            c_score += 2
        if '->' in code:
            c_score += 2   # pointer dereference - almost exclusively C/C++
        if code.strip().endswith(';') and '(' in code and '$' not in code:
            c_score += 1
        # non-C indicators
        if '$' in code:
            other_score += 2
        if any(p in code for p in ['def ', 'import ', '<?php', 'require ']):
            other_score += 3
        if re.search(r'=\s*[0-9A-F]{20,}', code):
            other_score += 5   # hex test data (crypto test vectors etc.)
    return c_score > 2 and c_score > other_score

def find_commit_for_cve(cve_id):
    """
    Search the Debian security tracker CVE list for a commit URL
    associated with the given CVE id.
    """
    with open(TRACKER_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    inside_entry = False

    for line in lines:
        if line.startswith(cve_id):
            inside_entry = True

        if inside_entry and "NOTE: Fixed by:" in line:
            match = re.search(r'(https://github\.com/.+?/commit/[a-f0-9]+)', line)
            if match:
                return match.group(1)

        # blank line ends the CVE block
        if inside_entry and line.strip() == "":
            inside_entry = False
    return None

def download_patch(commit_url):
    """
    Download the .patch file for a GitHub commit URL.
    Saves to samples/temp_patch.patch and returns the file path.
    """
    patch_url = commit_url + ".patch"
    print(f"[+] downloading patch: {patch_url}")

    try:
        response = requests.get(patch_url, timeout=20)
    except requests.RequestException as err:
        print(f"[!] download failed: {err}")
        return None

    if response.status_code != 200:
        print(f"[!] patch download failed (status {response.status_code})")
        return None

    samples_dir = os.path.join(BASE_DIR, "samples")
    os.makedirs(samples_dir, exist_ok=True)
    patch_path = os.path.join(samples_dir, "temp_patch.patch")

    with open(patch_path, "w", encoding="utf-8") as f:
        f.write(response.text)

    return patch_path

def save_signature(cve_id, findings):
    """Write findings list to signatures/<CVE>.json"""
    sig_dir = os.path.join(BASE_DIR, "signatures")
    os.makedirs(sig_dir, exist_ok=True)
    out_path = os.path.join(sig_dir, f"{cve_id}.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)

    print(f"[+] signature written to {out_path}")
    return out_path

def main(cve_id):
    print(f"[+] searching tracker for {cve_id}")
    commit_url = find_commit_for_cve(cve_id)

    if not commit_url:
        print("[!] no commit reference found for this CVE")
        return

    print(f"[+] found commit: {commit_url}")

    patch_path = download_patch(commit_url)
    if not patch_path:
        return

    print("[+] analyzing patch")
    with open(patch_path, "r", encoding="utf-8") as f:
        patch_text = f.read()

    # warn if patch doesn't look like C/C++ - non-C patches produce
    # patterns that cause RE2 errors or zero codesearch matches
    if not _looks_like_c_patch(patch_text):
        print("[!] warning: patch does not look like C/C++ code")
        print("    codesearch results may be empty or produce 400 errors")

    # call analyze_patch directly as a function - no subprocess needed
    findings = analyze_patch(patch_text)

    if not findings:
        print("[!] no findings extracted from patch")
        return

    print(f"[+] extracted {len(findings)} pattern(s)")
    save_signature(cve_id, findings)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python cve_to_signature.py CVE-XXXX-XXXX")
        sys.exit(1)
    main(sys.argv[1])