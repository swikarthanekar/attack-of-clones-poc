# Attack of the Clones - Patch-Based Code Clone Detection (PoC)

A proof-of-concept prototype built while exploring the
**"Attack of the Clones"** project idea from the Debian GSoC 2026 project list.

The goal is to automatically detect duplicated vulnerable code across the Debian
archive by converting security patches into loose regex search signatures.

When a vulnerability is fixed upstream, other copies of the same code may still
exist unfixed in unrelated packages. This tool helps surface those copies.

---

## How It Works

```
Debian Security Tracker
        ↓
Extract upstream patch commit
        ↓
Download patch diff
        ↓
Extract removed (-) lines → generalize to RE2 regex patterns
        ↓
Query codesearch.debian.net
        ↓
Generate attack-of-clone report
```

The approach is intentionally simple: take every removed line from the patch
diff, strip specifics (variable names → `\w+`, numbers → `\d+`, whitespace →
`\s{1,10}`), and search the archive for the structural pattern that remains.

The regex patterns are kept compatible with
[RE2](https://github.com/google/re2/wiki/Syntax) since
[codesearch.debian.net](https://codesearch.debian.net) uses RE2 internally.

---

## Example

Running the pipeline on **CVE-2026-31897** (FreeRDP):

```
python3 scripts/attack_of_clone.py CVE-2026-31897
```

Output:
```
[+] found commit: https://github.com/FreeRDP/FreeRDP/commit/cd27c8f...
[+] extracted 2 pattern(s)
[+] pattern from: if (!pSrcData)
    found 3 match(es)
    → util-linux_2.41.3-4 : libblkid/src/superblocks/bitlocker.c
    → util-linux_2.41.3-4 : lib/mangle.c
    → util-linux_2.41.3-4 : lsfd-cmd/lsfd.c
[+] pattern from: WLog_ERR(TAG, "Invalid argument pSrcData=nullptr");
    found 5 match(es)
    → qtbase-opensource-src_5.15.17+dfsg-7 : src/3rdparty/libpng/pngrtran.c
    → mariadb_1:11.8.6-3 : libmariadb/unittest/libmariadb/ps_bugs.c
    ...
Total matches across all patterns: 8
[+] report written to reports/CVE-2026-31897_report.md
```

---

## Repository Structure

```
attack-of-clones-poc/
├── scripts/
│   ├── attack_of_clone.py       main pipeline orchestrator
│   ├── cve_to_signature.py      CVE lookup + patch download + signature generation
│   ├── analyze_patch.py         patch diff → RE2 regex signatures
│   ├── clone_scanner.py         codesearch.debian.net query + result parser
│   └── generate_report.py       Markdown report generator
│
├── samples/
│   ├── sample_patch.patch       vim terminal buffer overflow (CVE-2026-28420)
│   └── libtiff_patch.patch      libtiff buffer overflow sample
│
├── signatures/                  generated signature JSON files
├── reports/                     generated Markdown reports
├── requirements.txt
└── README.md
```

The Debian security tracker repository must be cloned alongside this repo:

```
parent/
├── attack-of-clones-poc/
└── security-tracker/          ← clone from salsa.debian.org
```

Clone the tracker:
```bash
git clone https://salsa.debian.org/security-tracker-team/security-tracker.git
```

---

## Setup

Python 3.10+ required.

```bash
pip install -r requirements.txt
```

---

## Usage

### Full pipeline from CVE ID

```bash
python3 scripts/attack_of_clone.py CVE-XXXX-XXXX
```

Looks up the CVE in the Debian tracker, downloads the upstream patch, extracts
patterns, queries codesearch, and writes a report.

### Local patch file (bypass tracker)

```bash
python3 scripts/attack_of_clone.py CVE-XXXX-XXXX --patch samples/my_patch.patch
```

Useful for testing or for CVEs where the tracker commit points to a non-C patch.

### Analyze a patch directly

```bash
python3 scripts/analyze_patch.py samples/sample_patch.patch
```

Prints the extracted patterns and generated signatures as JSON.

---

## Regex Generalization Strategy

For each removed line from the patch diff, the analyzer:

1. Strips language-specific sigils (`$` in PHP/Perl)
2. Escapes the line with `re.escape()`
3. Unescapes characters that RE2 treats as invalid escapes (`&`, `;`, `=`, etc.)
4. Replaces identifiers with `\w+`
5. Replaces numeric literals with `\d+`
6. Collapses whitespace to `\s{1,10}` (RE2 does not support `\s+`)

Lines are ranked by usefulness (function calls > comparisons > control flow)
and the top 10 patterns per patch are used for searching.

---

## Limitations

- Regex signatures may produce false positives - results need manual review.
- The tracker does not always link to a C patch; non-C patches produce fewer
  useful patterns (the tool warns when this is detected).
- Codesearch results are limited to the first page per query.
- Pattern generalization is structural, not semantic.

---

## Motivation

Debian contains tens of thousands of packages. Tracking duplicated vulnerable
code across the entire archive manually is not feasible. If security patches
can be automatically converted into search signatures, it becomes possible to
identify unfixed clones at scale.

This prototype demonstrates the core workflow described in the
[Debian GSoC 2026 project idea](https://wiki.debian.org/SummerOfCode/Projects).

---

## Acknowledgement

Built while exploring the Debian GSoC 2026 project:

**"Attack Of The Clones: Fight Back Using Code Duplication Detection from
Security Patches"**

Mentor: Bastien Roucaries (rouca AT debian.org)
