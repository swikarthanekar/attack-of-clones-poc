import re
import json
import sys

def find_added_validation_guards(patch_text):
    # scan the diff for newly added if-statements that terminate execution
    # these are often added as security checks in patches

    guard_conditions = []
    diff_lines = patch_text.splitlines()
    for line_index, line in enumerate(diff_lines):
        if not line.startswith("+"):
            continue
        if "if (" not in line:
            continue
        condition = line[1:].strip()
        nearby_block = "\n".join(diff_lines[line_index:line_index + 5])

        if "exit(" in nearby_block or "return" in nearby_block:
            guard_conditions.append(condition)
    return guard_conditions


def build_signature():
    # simple regex describing "guard condition -> exit"
    # intentionally loose so it can match similar patterns

    return r"if\s*\(.*\)\s*\{[^}]*exit\s*\("

def analyze_patch(patch_text):
    guard_conditions = find_added_validation_guards(patch_text)
    findings = []

    for condition in guard_conditions:
        findings.append({
            "vulnerability_type": "missing_validation_guard",
            "added_condition": condition,
            "generated_signature": build_signature()
        })
    return findings

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_memcpy_patch.py <patch_file>")
        sys.exit(1)
    patch_file = sys.argv[1]

    print(f"[+] scanning patch for validation guards: {patch_file}")

    with open(patch_file, "r", encoding="utf-8") as f:
        patch_text = f.read()
    results = analyze_patch(patch_text)

    print(json.dumps(results, indent=4))