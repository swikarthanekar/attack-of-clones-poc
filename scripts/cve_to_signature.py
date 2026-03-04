import re
import sys
import requests
import subprocess
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TRACKER_PATH = os.path.join(BASE_DIR, "..", "security-tracker", "data", "CVE", "list")
TRACKER_PATH = os.path.abspath(TRACKER_PATH)

def find_commit_for_cve(cve_id):
    with open(TRACKER_PATH, "r", encoding="utf-8") as tracker_file:
        tracker_lines = tracker_file.readlines()
    inside_entry = False

    for line in tracker_lines:
        if line.startswith(cve_id):
            inside_entry = True
        if inside_entry and "NOTE: Fixed by:" in line:
            match = re.search(r'(https://github\.com/.+?/commit/[a-f0-9]+)', line)
            if match:
                return match.group(1)
        if inside_entry and line.strip() == "":
            inside_entry = False
    return None

def download_patch_file(commit_url):
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

    patch_filename = os.path.join(BASE_DIR, "samples", "temp_patch.patch")

    with open(patch_filename, "w", encoding="utf-8") as patch_file:
        patch_file.write(response.text)

    return patch_filename

def run_patch_analyzer(patch_file):
    print("[+] running patch analyzer")
    analyzer_script = os.path.join(BASE_DIR, "scripts", "analyze_patch.py")
    process = subprocess.run(
        ["python", analyzer_script, patch_file],
        capture_output=True,
        text=True
    )

    if process.returncode != 0:
        print("[!] analyzer failed")
        print(process.stderr)
        return []
    output = process.stdout.strip()

    match = re.search(r'(\[\s*{.*}\s*\])', output, re.DOTALL)

    if not match:
        print("[!] could not extract JSON from analyzer output")
        print(output)
        return []

    json_text = match.group(1)

    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        print("[!] analyzer output was not valid JSON")
        return []

def save_signature(cve_id, findings):

    signatures_dir = os.path.join(BASE_DIR, "signatures")
    os.makedirs(signatures_dir, exist_ok=True)
    output_file = os.path.join(signatures_dir, f"{cve_id}.json")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)

    print(f"[+] signature written to {output_file}")

def main(cve_id):
    print(f"[+] searching tracker for {cve_id}")
    commit_url = find_commit_for_cve(cve_id)

    if not commit_url:
        print("[!] no commit reference found for this CVE")
        return

    print(f"[+] found commit: {commit_url}")

    patch_file = download_patch_file(commit_url)

    if not patch_file:
        return
    findings = run_patch_analyzer(patch_file)

    if not findings:
        print("[!] analyzer returned no findings")
        return

    save_signature(cve_id, findings)

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python scripts/cve_to_signature.py CVE-XXXX-XXXX")
        sys.exit(1)

    cve_identifier = sys.argv[1]

    main(cve_identifier)