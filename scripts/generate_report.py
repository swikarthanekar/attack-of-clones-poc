import os
import json
import sys
from datetime import datetime, timezone

def generate_report(signature_path):
    """
    Generate a Markdown attack-of-clone report from a signatures JSON file.
    Handles multiple findings (not just the first one).
    """
    print(f"[+] generating report from {signature_path}")

    with open(signature_path, "r", encoding="utf-8") as f:
        signature_data = json.load(f)

    if not signature_data:
        print("[!] signature file is empty")
        return

    # derive CVE id from filename
    cve_id = os.path.splitext(os.path.basename(signature_path))[0]
    timestamp = datetime.now(timezone.utc).isoformat()

    lines = []
    lines.append(f"# Attack of Clone Report — {cve_id}\n")
    lines.append(f"Generated: {timestamp} UTC\n")
    lines.append("## Overview\n")
    lines.append(
        "This report was generated automatically by analyzing the security patch "
        f"for {cve_id}. Each section below corresponds to one removed code pattern "
        "extracted from the patch diff. The generated regex signature can be used "
        "with codesearch.debian.net to search for potential vulnerable clones "
        "across the Debian archive.\n"
    )
    lines.append(f"**Patterns extracted:** {len(signature_data)}\n")
    lines.append("---\n")

    for idx, finding in enumerate(signature_data, start=1):
        removed = finding.get("removed_line", "N/A")
        signature = finding.get("generated_signature", "N/A")

        lines.append(f"## Pattern {idx}\n")
        lines.append("**Removed line from patch:**\n")
        lines.append(f"```c\n{removed}\n```\n")
        lines.append("**Generated regex signature:**\n")
        lines.append(f"```\n{signature}\n```\n")
        lines.append(
            "**Suggested action:** Search the Debian archive using:\n"
            f"https://codesearch.debian.net/search?q={signature}&regexp=1\n"
        )
        lines.append("---\n")

    lines.append("## Next Steps\n")
    lines.append(
        "1. Run each generated signature against codesearch.debian.net\n"
        "2. Review matching packages for unfixed copies of the vulnerable pattern\n"
        "3. File bugs or notify package maintainers where clones are confirmed\n"
    )

    report_text = "\n".join(lines)

    reports_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports"
    )
    os.makedirs(reports_dir, exist_ok=True)
    out_path = os.path.join(reports_dir, f"{cve_id}_report.md")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"[+] report written to {out_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_report.py <signature_json>")
        sys.exit(1)

    generate_report(sys.argv[1])