import re
import json
import sys

# Lines from diff headers we want to skip - they are not real code
SKIP_PREFIXES = ("---", "+++", "@@", "diff ", "index ", "Author:", "Date:", "Subject:")

def extract_removed_lines(patch_text):
    """
    Extract all removed lines (-) from a unified diff.
    Skips diff metadata lines (---, +++, @@, etc).
    Returns a list of raw code strings.
    """
    removed = []
    for line in patch_text.splitlines():
        if line.startswith("-") and not any(line.startswith(p) for p in SKIP_PREFIXES):
            code = line[1:].strip()
            if code:
                removed.append(code)
    return removed

def is_meaningful(line):
    """
    Filter out lines that are too short or purely structural
    to be useful as a search pattern.
    """
    if len(line) < 8:
        return False
    # skip lines that are just braces, comments, or blank structure
    if re.match(r'^[{}\s/*]+$', line):
        return False
    # skip pure comment lines (doc comments, inline comments)
    if re.match(r'^\s*(//|\*|#)', line):
        return False
    # skip pure variable declarations - too generic to be useful
    if re.match(r'^\s*(const\s+)?[\w\s\*]+\s+\*?\w+\s*;$', line) and '(' not in line:
        return False
    return True


# Characters that re.escape() backslash-escapes but that RE2 treats as
# invalid escape sequences (RE2 only allows \\ \^ \$ \. \| \? \* \+ \( \) \[ \] \{ \})
# Anything else like \& \! \, \; \: \= \< \> \~ must be unescaped to literal
_RE2_UNESCAPE = set('&!,;:=<>~@#%')

def generalize_to_regex(line):
    """
    Convert a removed code line into a loose RE2-compatible regex pattern.

    Strategy (simple stupid):
      1. Strip language-specific variable sigils ($ in PHP)
      2. Escape the line for regex use
      3. Unescape chars that re.escape() escapes but RE2 rejects (& ; = etc.)
      4. Replace identifiers with \\w+
      5. Replace numeric literals with \\d+
      6. Collapse whitespace to \\s{1,10}  (RE2 does not support \\s+)
    """
    # strip PHP/Perl variable sigils - \$ in RE2 is end-anchor, causes 400
    line = line.replace('$', '')

    pattern = re.escape(line)

    # unescape chars that re.escape() escapes unnecessarily for RE2
    for ch in _RE2_UNESCAPE:
        pattern = pattern.replace('\\' + ch, ch)

    # replace identifier tokens with \w+
    pattern = re.sub(r'\b[a-zA-Z_]\w*\b', r'\\w+', pattern)

    # replace numeric literals with \d+
    pattern = re.sub(r'\b\d+\b', r'\\d+', pattern)

    # collapse whitespace to \s{1,10}
    # RE2 (used by codesearch.debian.net) does not support \s+
    # confirmed by bastien: use \s{1,10} instead
    pattern = re.sub(r'\\ | ', r'\\s{1,10}', pattern)

    # collapse consecutive \s{1,10} into one
    pattern = re.sub(r'(\\s\{1,10\})+', r'\\s{1,10}', pattern)

    return pattern

def score_pattern(line):
    """
    Score a removed line by how likely it is to be a useful
    search pattern. Higher = more useful.
    Prefers lines with function calls, operators, and keywords
    over generic assignments or single-word lines.
    """
    score = 0
    if '(' in line:
        score += 3   # function call — most useful for clone detection
    if any(op in line for op in ['<', '>', '<=', '>=']):
        score += 2   # comparison — good for bounds-check patterns
    if any(kw in line for kw in ['if ', 'for ', 'while ', 'return ']):
        score += 2   # control flow keyword
    if '=' in line:
        score += 1
    score -= line.count(' ') // 8  # penalize very long lines (too specific)
    return score

def analyze_patch(patch_text, max_patterns=10):
    """
    Main entry point.
    Returns a list of up to max_patterns findings, ranked by usefulness.
    Each finding has:
      - removed_line: the original code line from the patch
      - generated_signature: the loose RE2-compatible regex pattern
    """
    removed_lines = extract_removed_lines(patch_text)
    candidates = []

    for line in removed_lines:
        if not is_meaningful(line):
            continue
        signature = generalize_to_regex(line)
        candidates.append({
            "removed_line": line,
            "generated_signature": signature,
            "_score": score_pattern(line)
        })

    # sort by score descending, take top max_patterns
    candidates.sort(key=lambda x: x["_score"], reverse=True)
    findings = []
    for c in candidates[:max_patterns]:
        findings.append({
            "removed_line": c["removed_line"],
            "generated_signature": c["generated_signature"]
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