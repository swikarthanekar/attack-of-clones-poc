import re
import json
import sys


def collect_diff_blocks(patch_text):
    # gather removed (-) and added (+) blocks from a unified diff
    removed_blocks = []
    added_blocks = []
    lines = patch_text.splitlines()
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        if line.startswith('-'):
            block = [line[1:]]
            idx += 1
            while idx < len(lines) and lines[idx].startswith('-'):
                block.append(lines[idx][1:])
                idx += 1
            removed_blocks.append(" ".join(l.strip() for l in block))
            continue

        if line.startswith('+'):
            block = [line[1:]]
            idx += 1
            while idx < len(lines) and lines[idx].startswith('+'):
                block.append(lines[idx][1:])
                idx += 1
            added_blocks.append(" ".join(l.strip() for l in block))
            continue
        idx += 1

    return removed_blocks, added_blocks

def find_modified_loops(removed_blocks, added_blocks):
    # look for loops that appear in both removed and added sections
    loop_pairs = []

    for removed_line in removed_blocks:
        if "for (" not in removed_line:
            continue
        for added_line in added_blocks:
            if "for (" in added_line:
                loop_pairs.append((removed_line.strip(), added_line.strip()))
    return loop_pairs


def detect_upper_bound_added(old_loop, new_loop):
    # check if the new loop adds something like "i < MAX"
    old_match = re.search(r'for\s*\((.*?);(.*?);(.*?)\)', old_loop)
    new_match = re.search(r'for\s*\((.*?);(.*?);(.*?)\)', new_loop)

    if not old_match or not new_match:
        return None

    old_condition = old_match.group(2)
    new_condition = new_match.group(2)

    added_bound = (
        ('<' in new_condition or '<=' in new_condition)
        and ('<' not in old_condition and '<=' not in old_condition)
    )

    if added_bound:
        return new_condition.strip()
    return None


def build_regex_signature(loop_line):
    # build a loose regex for loops indexing arrays without a bound
    match = re.search(r'for\s*\(\s*(\w+)\s*=\s*0\s*;', loop_line)
    if not match:
        return None

    loop_var = match.group(1)

    pattern = (
        r"for\s*\(\s*"
        r"\w+\s*=\s*0\s*;\s*"
        r"[^;]*\[\s*\w+\s*\][^;]*;\s*\+\+\w+\s*"
        r"\)"
    )
    return pattern


def analyze_patch(patch_text):
    removed_blocks, added_blocks = collect_diff_blocks(patch_text)
    loop_pairs = find_modified_loops(removed_blocks, added_blocks)
    findings = []

    for old_loop, new_loop in loop_pairs:
        added_condition = detect_upper_bound_added(old_loop, new_loop)

        if not added_condition:
            continue
        signature = build_regex_signature(old_loop)
        if not signature:
            continue

        findings.append({
            "vulnerability_type": "missing_loop_upper_bound",
            "removed_loop": old_loop,
            "added_loop": new_loop,
            "added_condition": added_condition,
            "generated_signature": signature
        })

    return findings

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python analyze_patch.py <patch_file>")
        sys.exit(1)

    patch_file = sys.argv[1]

    print(f"[+] analyzing patch: {patch_file}")

    with open(patch_file, "r", encoding="utf-8") as f:
        patch_text = f.read()
    results = analyze_patch(patch_text)

    print(json.dumps(results, indent=4))