import sys
import subprocess
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    print(f"\n[+] running: {' '.join(cmd)}")
    subprocess.run(cmd)

def main(cve):
    print(f"\n Attack of Clone pipeline for {cve} ")
    run(["python", os.path.join(BASE_DIR, "scripts", "cve_to_signature.py"), cve])
    sig = os.path.join(BASE_DIR, "signatures", f"{cve}.json")
    run(["python", os.path.join(BASE_DIR, "scripts", "clone_scanner.py"), sig])
    run(["python", os.path.join(BASE_DIR, "scripts", "generate_report.py"), sig])
    print("\nPipeline finished.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scripts/attack_of_clone.py CVE-XXXX-XXXX")
        sys.exit(1)

    main(sys.argv[1])
