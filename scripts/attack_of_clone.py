import sys
import subprocess
import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
from analyze_patch import analyze_patch


def run(cmd):
    print(f"\n[+] running: {' '.join(cmd)}")
    subprocess.run(cmd)


def run_from_local_patch(cve_id, patch_path):
    """
    Bypass the tracker and run the pipeline directly from a local patch file.
    Useful for testing and for CVEs where the tracker commit is not C code.

    Usage:
        python scripts/attack_of_clone.py CVE-XXXX-XXXX --patch samples/my_patch.patch
    """
    print(f"\n Attack of Clone pipeline for {cve_id} (local patch mode) ")
    print(f"[+] reading patch from: {patch_path}")

    with open(patch_path, "r", encoding="utf-8") as f:
        patch_text = f.read()

    findings = analyze_patch(patch_text)

    if not findings:
        print("[!] no patterns extracted from patch")
        return

    print(f"[+] extracted {len(findings)} pattern(s)")

    sig_dir = os.path.join(BASE_DIR, "signatures")
    os.makedirs(sig_dir, exist_ok=True)
    sig_path = os.path.join(sig_dir, f"{cve_id}.json")

    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)

    print(f"[+] signature written to {sig_path}")

    run([sys.executable, os.path.join(BASE_DIR, "scripts", "clone_scanner.py"), sig_path])
    run([sys.executable, os.path.join(BASE_DIR, "scripts", "generate_report.py"), sig_path])
    print("\nPipeline finished.")


def main(cve, patch_path=None):
    if patch_path:
        run_from_local_patch(cve, patch_path)
        return

    print(f"\n Attack of Clone pipeline for {cve} ")
    run([sys.executable, os.path.join(BASE_DIR, "scripts", "cve_to_signature.py"), cve])
    sig = os.path.join(BASE_DIR, "signatures", f"{cve}.json")
    run([sys.executable, os.path.join(BASE_DIR, "scripts", "clone_scanner.py"), sig])
    run([sys.executable, os.path.join(BASE_DIR, "scripts", "generate_report.py"), sig])
    print("\nPipeline finished.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scripts/attack_of_clone.py CVE-XXXX-XXXX")
        print("  python scripts/attack_of_clone.py CVE-XXXX-XXXX --patch samples/my_patch.patch")
        sys.exit(1)

    cve_arg = sys.argv[1]
    patch_arg = None

    if "--patch" in sys.argv:
        idx = sys.argv.index("--patch")
        if idx + 1 < len(sys.argv):
            patch_arg = sys.argv[idx + 1]
        else:
            print("[!] --patch requires a file path argument")
            sys.exit(1)

    main(cve_arg, patch_arg)