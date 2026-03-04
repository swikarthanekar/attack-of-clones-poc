import re
import json
import sys

# common unsafe functions seen in security patches
UNSAFE_FUNCS = [
    "memcpy",
    "strcpy",
    "sprintf"
]

def find_removed_unsafe_calls(patch_text):
    removed_calls = []
    for line in patch_text.splitlines():
        if not line.startswith("-"):
            continue
        code = line[1:].strip()
        for func in UNSAFE_FUNCS:
            if f"{func}(" in code:
                removed_calls.append((func, code))
    return removed_calls

def generate_signature(func_name):

    # intentionally loose pattern for codesearch
    if func_name == "memcpy":
        return r"memcpy\s*\([^,]+,[^,]+,[^)]*\)"
    if func_name == "strcpy":
        return r"strcpy\s*\([^,]+,[^)]*\)"
    if func_name == "sprintf":
        return r"sprintf\s*\([^,]+,[^)]*\)"
    return None

def analyze_patch(patch_text):
    findings = []
    unsafe_calls = find_removed_unsafe_calls(patch_text)
    for func_name, line in unsafe_calls:
        signature = generate_signature(func_name)
        if not signature:
            continue
        findings.append({
            "vulnerability_type": "unsafe_memory_copy",
            "function": func_name,
            "removed_call": line,
            "generated_signature": signature
        })

    return findings

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python analyze_unsafe_copy_patch.py <patch_file>")
        sys.exit(1)

    patch_file = sys.argv[1]

    print(f"[+] scanning patch for unsafe memory copies: {patch_file}")

    with open(patch_file, "r", encoding="utf-8") as f:
        patch_text = f.read()

    results = analyze_patch(patch_text)

    print(json.dumps(results, indent=4))