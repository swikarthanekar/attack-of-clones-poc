import os
import json
import sys
from datetime import datetime, UTC

def generate_report(signature_path):
    print(f"[+] generating report from {signature_path}")

    with open(signature_path, "r", encoding="utf-8") as f:
        signature_data = json.load(f)

    if not signature_data:
        print("[!] signature file is empty")
        return

    finding = signature_data[0]
    vulnerability_type = finding.get("vulnerability_type", "unknown")
    added_condition = finding.get("added_condition", "N/A")
    signature_regex = finding.get("generated_signature", "N/A")
    timestamp = datetime.now(UTC).isoformat()

    report_text = f"""
# Attack of Clone Report

Generated: {timestamp} UTC

## Vulnerability Type

{vulnerability_type}

## Patch Condition Introduced

{added_condition}

## Generated Detection Signature
{signature_regex}

## Description

This signature was derived automatically from a security patch.
The goal is to capture the vulnerable coding pattern in a form
that can be searched across the Debian archive.

Using tools like `codesearch.debian.net`, this pattern can be used
to identify potential clones of the vulnerable logic that may not
yet have received the upstream fix.

## Suggested Next Step

Run the generated signature against the Debian archive and
review the results for possible duplicated vulnerable code.
"""
    output_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "attack_of_clone_report.md")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_text.strip())
    print(f"[+] report written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_report.py <signature_json>")
        sys.exit(1)
    signature_file = sys.argv[1]

    generate_report(signature_file)