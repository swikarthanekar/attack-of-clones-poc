## Debian Security Tracker Dependency

This prototype reads vulnerability metadata from the Debian security tracker.

The tool expects the tracker repository to be present locally so it can read
the `data/CVE/list` file and locate upstream patch references.

Clone the security tracker repository:
## Debian Security Tracker Dependency

This prototype reads vulnerability metadata from the Debian security tracker.

The tool expects the tracker repository to be present locally so it can read
the `data/CVE/list` file and locate upstream patch references.

Clone the security tracker repository:
git clone https://salsa.debian.org/security-tracker-team/security-tracker.git

The pipeline reads CVE entries from:
security-tracker/data/CVE/list

Each CVE entry often contains a reference to the upstream commit that fixed
the vulnerability. The prototype extracts that commit and downloads the patch
diff for analysis.





# Attack of the Clones – Patch Based Code Clone Detection (PoC)

This repository contains a small proof-of-concept prototype built while exploring the **"Attack of the Clones"** project idea from the Debian GSoC project list.

The goal of the project is to investigate whether security patches can be used to automatically detect **duplicated vulnerable code across a large software archive** such as Debian.

Security bugs often appear in multiple places because developers copy and reuse code.  
When a vulnerability is fixed upstream, other copies of the same code may still remain unfixed elsewhere.  
This project explores a simple way to detect such situations automatically.

The prototype pipeline implemented here attempts to:

1. Extract security patch information from the Debian security tracker
2. Download the upstream patch that fixes the vulnerability
3. Analyze the patch to identify the vulnerable coding pattern
4. Convert the pattern into a loose regex signature
5. Search the Debian source archive for similar code
6. Generate a simple report describing the potential clone pattern

---

# How the Prototype Works

The workflow implemented in this repository looks like this:

Debian Security Tracker
      ↓
Extract upstream patch
      ↓
Analyze patch diff
      ↓
Generate vulnerability signature
      ↓
Search Debian archive (codesearch.debian.net)
      ↓
Generate attack-of-clone report

The system is intentionally simple.  
The focus here is on experimenting with the idea rather than building a production-ready tool.

---

# Vulnerability Patterns Currently Detected

While experimenting with patches, three common types of fixes were implemented.

### 1. Missing Loop Upper Bound

Example vulnerable pattern:
for (i = 0; arr[i] != 0; ++i)

Fix introduced in patch:
for (i = 0; i < MAX && arr[i] != 0; ++i)


The analyzer detects that a **loop boundary condition was added** and generates a signature that searches for similar loops without bounds.

---

### 2. Missing Validation Guard

Some vulnerabilities are fixed by adding input validation checks.

Example patch fix:
if (page_count < 1 || bnum + page_count > limit) {
exit(EXIT_FAILURE);
}


The analyzer detects when **guard conditions are added before dangerous operations**.

---

### 3. Unsafe Memory Copy Operations

Certain vulnerabilities come from unsafe memory functions such as:
strcpy
memcpy
sprintf


If a patch replaces these with safer alternatives such as:
strncpy
snprintf
checked memcpy


the analyzer extracts the removed unsafe function and creates a search signature.

---

# Repository Structure

```
|
├─ attack_of_clone_poc
|    │
|    ├─ scripts
|    │  attack_of_clone.py
|    │  cve_to_signature.py
|    │  analyze_patch.py
|    │  analyze_memcpy_patch.py
|    │  analyze_unsafe_copy_patch.py
|    │  clone_scanner.py
|    │  generate_report.py
|    │
|    ├─ samples
|    │  sample_patch.patch
|    │  libtiff_patch.patch
|    │  unsafe_copy_test.patch
|    │
|    ├─ signatures
|    │  (generated vulnerability signatures)
|    │
|    ├─ reports
|    │  attack_of_clone_report.md
|    │
|    ├─ requirements.txt
|    └─ README.md
│
├─ security-tracker
    ├─ data
        ├─ CVE
            ├─ list
```

The Debian **security-tracker dataset is expected to be located outside this directory**:

```
clone/
│
├─ attack_of_clone_poc
└─ security-tracker
```

The prototype reads CVE patch metadata from:

```
security-tracker/data/CVE/list
```

# Requirements

Python 3.10+ should work fine.

Install dependencies:

```
pip install -r requirements.txt
```


---

# Running the Prototype

The easiest way to run the full pipeline is:
python scripts/attack_of_clone.py CVE-XXXX-XXXX

Example:
python scripts/attack_of_clone.py CVE-2026-28420

This will:

1. Look up the CVE in the Debian security tracker
2. Find the upstream commit that fixed the vulnerability
3. Download the patch
4. Analyze the patch to derive a vulnerability signature
5. Search for similar code using Debian codesearch
6. Generate a simple report

---

# Example Output

Example pipeline execution:
=== Attack of Clone pipeline for CVE-2026-28420 ===

[+] searching tracker for CVE
[+] downloading upstream patch
[+] analyzing patch diff
[+] generating vulnerability signature
[+] querying Debian codesearch
[+] generating report

Pipeline finished.


The final report is saved as:
reports/attack_of_clone_report.md

---

# Limitations

This repository is only an early prototype.

Some limitations:

* The pattern extraction is intentionally simple.
* Regex signatures may produce false positives.
* Only a few vulnerability patterns are currently supported.
* Codesearch results are not deeply analyzed yet.

A more complete system would likely require:

* better pattern generalization
* AST-based code analysis
* integration with Debian package metadata
* automatic triaging of potential clone matches

---

# Motivation

Large distributions like Debian contain **tens of thousands of packages**.  
Tracking duplicated vulnerable code across such a large ecosystem is extremely difficult manually.

If security patches can be converted into **automatic detection signatures**, it could help identify vulnerable clones that remain unfixed in other packages.

This prototype explores that idea in a simple and practical way.

---

# Acknowledgement

This work was done while exploring the Debian GSoC project idea:

**"Attack Of The Clones: Fight Back Using Code Duplication Detection from Security Patches"**

The goal was to better understand the workflow described in the project proposal and experiment with possible approaches.

---

## Status

This repository is an experimental prototype built while exploring
possible approaches for the Debian GSoC "Attack of the Clones" idea.
The implementation focuses on understanding the workflow rather than
building a production-ready detection system.