# Sec-n-ThreatForge

**Security, Threat Generation & Malware Analysis Framework**

Sec-n-ThreatForge is a Python-based security research framework designed to study the relationship between **controlled threat generation, static file analysis, detection techniques, and threat assessment**.

The project follows a dual-purpose security model:

```text
                    Sec-n-ThreatForge
                           │
             ┌─────────────┴─────────────┐
             │                           │
        Threat Generation            Threat Detection
             │                           │
      Controlled Samples           Static Analysis
      Test Artifacts              Signature Detection
             │                     Heuristic Analysis
             │                           │
             └─────────────┬─────────────┘
                           ↓
                    Threat Assessment
                           │
                           ↓
                       Reporting
```

> **Note:** The threat-generation component is intended for controlled security research and detector evaluation. It does not aim to produce deployable malware.

---

## Current Version

**v0.4.0**

### v0.4.0 Features

* File metadata analysis
* File type / MIME detection
* SHA-256, SHA-1 and MD5 hashing
* Printable string extraction
* Shannon entropy analysis
* PE executable identification
* ELF executable identification
* PE/ELF architecture and entry-point analysis
* PE/ELF section analysis (names, types, sizes, permissions/flags)
* PE import table parsing (DLLs, imported functions, ordinal imports)
* PE export table parsing (exported names, ordinals, RVAs)
* ELF dynamic symbol table parsing (`.dynsym` / `.dynstr`)
* ELF dynamic dependency parsing (`DT_NEEDED` shared-library dependencies)
* Structured detection findings
* Controlled test signatures
* Context-aware risk scoring
* Weighted heuristic contributions
* Category-based score limits
* Contextual indicator combinations
* Explainable risk-score breakdown
* Terminal security reports
* JSON report generation
* Controlled test-sample generation

> **Deep dive:** For a detailed breakdown of how the PE and ELF parsers work internally, see [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/README.md).

---

## Architecture

```text
Sec-n-ThreatForge/
│
├── src/
│   └── threatforge/
│       │
│       ├── main.py
│       │
│       ├── core/
│       │   └── result.py
│       │
│       ├── analyzer/
│       │   ├── entropy.py
│       │   ├── executable/
│       │   │   ├── detector.py
│       │   │   ├── elf.py
│       │   │   ├── __init__.py
│       │   │   └── pe.py
│       │   ├── fileinfo.py
│       │   ├── filetype.py
│       │   ├── hashing.py
│       │   ├── __init__.py
│       │   └── strings.py
│       │
│       ├── detector/
│       │   ├── signatures.py
│       │   ├── rules.py
│       │   └── scoring.py
│       │
│       ├── generator/
│       │   └── samples.py
│       │
│       └── reporting/
│           ├── terminal.py
│           └── json_report.py
│
├── README.md
├── LICENSE
├── pyproject.toml
└── .gitignore
```

---

## Analysis Pipeline

When a file is submitted for analysis:

```text
                         Input File
                             │
                             ↓
                     File Identification
                             │
              ┌──────────────┼──────────────┐
              ↓              ↓              ↓
          Metadata         Hashes        File Type
              │              │              │
              └──────────────┼──────────────┘
                             ↓
                      Static Analysis
                             │
              ┌──────────────┼──────────────┐
              ↓              ↓              ↓
          Strings          Entropy    Executable Format
                                          (PE / ELF)
                             │              │
                             └──────┬───────┘
                                    ↓
                             Detection Engine
                                    │
                           ┌────────┴────────┐
                           ↓                 ↓
                       Signatures         Heuristics
                           │                 │
                           └────────┬────────┘
                                    ↓
                              Risk Scoring
                                    │
                                    ↓
                              AnalysisResult
                              /            \
                             ↓              ↓
                        Terminal           JSON
                          Report          Report
```

---

# Installation

## Requirements

* Python 3.12+
* Git
* Linux recommended
* `file` / `libmagic`

On Arch Linux:

```bash
sudo pacman -S python python-pip git file
```

Clone the project and enter the directory:

```bash
git clone <repository-url>
cd Sec-n-ThreatForge
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

---

# CLI

Display help:

```bash
threatforge --help
```

Display version:

```bash
threatforge --version
```

Display framework information:

```bash
threatforge info
```

---

# File Analysis

Analyze a file:

```bash
threatforge analyze <file>
```

Example:

```bash
threatforge analyze samples/benign/test.txt
```

The analyzer currently collects:

```text
File name
File path
File size
Extension
MIME type
File description
MD5
SHA-1
SHA-256
Entropy
Printable strings
Executable format (PE / ELF)
Architecture
Entry point
PE/ELF sections
Section sizes
Section permissions / flags
PE imports (DLLs + functions/ordinals)
PE exports (name, ordinal, RVA)
ELF dynamic dependencies (DT_NEEDED)
ELF dynamic symbols (.dynsym)
Detection findings
Risk score
Classification
```

See [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/README.md) for details on exactly what is parsed from PE and ELF binaries and how.

---

# JSON Reporting

Analysis results can be exported as JSON with the `--json` flag:

```bash
threatforge analyze samples/test-threats/marker.txt --json
```

The resulting report contains structured analysis data:

```json
{
    "file": {},
    "hashes": {},
    "file_type": {},
    "executable": {},
    "entropy": 0.0,
    "strings": [],
    "findings": [],
    "risk": {}
}
```

The `executable` block is populated only when the analyzed file is a recognized PE or ELF binary, and contains the format-specific fields described in [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/README.md) (sections, imports/exports for PE, dependencies/symbols for ELF).

JSON output is intended to make Sec-n-ThreatForge usable by other tools and future automation.

---

# Controlled Sample Generation

The generator currently creates **non-executable controlled samples** for testing the detection engine.

Generate a benign sample:

```bash
threatforge generate \
    --type benign \
    --output samples/benign/test.txt
```

Generate a controlled marker sample:

```bash
threatforge generate \
    --type marker \
    --output samples/test-threats/marker.txt
```

Generate a controlled suspicious-pattern sample:

```bash
threatforge generate \
    --type suspicious \
    --output samples/test-threats/suspicious.txt
```

These samples allow the detection pipeline to be tested deterministically without requiring real malware.

---

# Detection Engine

The detection engine combines multiple static indicators and evaluates their
relationships before producing a risk assessment.

```text
                         Detection Engine
                                │
                  ┌─────────────┴─────────────┐
                  ↓                           ↓
             Signatures                  Heuristics
                  │                           │
                  ↓                           ↓
          Controlled markers        File / PE indicators
                  │                           │
                  └─────────────┬─────────────┘
                                ↓
                            Findings
                                │
                                ↓
                       Context-Aware Scoring
                                │
                  ┌─────────────┴─────────────┐
                  ↓                           ↓
           Base Contributions          Context Bonuses
                  │                           │
                  └─────────────┬─────────────┘
                                ↓
                           Risk Score
                                │
                                ↓
                         Classification
```

## Signature Detection

The framework currently contains controlled Sec-n-ThreatForge test signatures such as:

```text
TF_TEST_MARKER
TF_SUSPICIOUS_PATTERN
```

These are **test indicators**, not production malware signatures.

## Suspicious String Detection

The detector can identify selected strings associated with potentially
security-sensitive execution mechanisms.

Examples include:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
rundll32.exe
regsvr32.exe
```

These indicators are treated as heuristic evidence. Their presence alone does not establish malicious intent.

## Entropy Analysis

Sec-n-ThreatForge calculates Shannon byte entropy:

```text
0 ───────────────────────── 8
low                         high
```

High entropy can occur in compressed, encrypted, packed, or random data. Therefore, entropy is treated as a **weak heuristic** rather than proof of malicious activity.

## PE Import Heuristics

PE imports are inspected for selected security-sensitive APIs, including memory-management and process-manipulation functions.

Examples include:

```text
VirtualAlloc
VirtualProtect
WriteProcessMemory
CreateRemoteThread
OpenProcess
```

Import presence represents **static capability evidence**. It does not mean that the application actually calls or misuses the imported API.

## PE Section Heuristics

PE section permissions are also examined for unusual combinations such as writable and executable sections.

A writable/executable section may be relevant during malware analysis, but it can also occur for legitimate technical reasons. It is therefore treated as heuristic evidence.

---

# Risk Assessment

Sec-n-ThreatForge uses a context-aware static risk-scoring system.

Individual findings have a declared severity, but severity is not necessarily added directly to the final score. Heuristic indicators may receive reduced weights, while related indicators can produce additional contextual risk contributions.

The scoring process is:

```text
Individual Findings
        │
        ↓
Deduplication
        │
        ↓
Weighted Contributions
        │
        ↓
Category Caps
        │
        ↓
Contextual Combinations
        │
        ↓
Final Score
```

Weak indicators receive reduced weight so that common characteristics do not dominate the assessment.

For example:

```text
High entropy
```

is weaker evidence than a combination such as:

```text
VirtualAlloc
      +
WriteProcessMemory
      +
CreateRemoteThread
```

Related indicators can therefore produce additional contextual risk contributions.

### Current Classification

```text
0 – 19      LOW
20 – 39     MEDIUM
40 – 69     HIGH
70 – 100    CRITICAL
```

The risk result also records:

```text
Base Score
Context Bonus
Category Breakdown
Contextual Risk Factors
```

This makes the assessment more explainable than a single unexplained score.

> A risk score represents an assessment based on collected static indicators. It is not a definitive malware verdict.

# Security Philosophy

Sec-n-ThreatForge is intended for:

* Security education
* Malware-analysis research
* Defensive tooling research
* Detection-engine development
* Controlled adversarial testing
* Authorized penetration-testing laboratories

Testing should only be performed against systems and files for which the operator has appropriate authorization.

The project deliberately separates **controlled security research artifacts** from deployable malicious software. The PE and ELF parsers are read-only static analyzers: they inspect file structure on disk and never execute, load, or map the analyzed binary.

---

# Technology Stack

| Component           | Technology               |
| ------------------- | ------------------------ |
| Language            | Python                   |
| CLI                 | Click                    |
| Terminal UI         | Rich                     |
| File identification | libmagic / python-magic  |
| Hashing             | Python `hashlib`         |
| Entropy             | Shannon entropy          |
| Executable parsing  | Python `struct` (manual PE/ELF header parsing) |
| Reporting           | JSON                     |
| Testing             | Python testing ecosystem |
| Version control     | Git                      |

---

# Development

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Install in editable mode:

```bash
pip install -e .
```

Run:

```bash
threatforge
```

---

# Documentation

* [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/README.md) — how the PE and ELF static analyzers work, field-by-field, including format layout notes and current limitations.

---

# Project Status

**Current release: v0.4.0**

The v0.4.x development line introduces context-aware static threat detection and risk assessment.

Sec-n-ThreatForge is currently an early-stage security research framework. Its static-analysis and detection capabilities are experimental and should not be considered a replacement for established antivirus, EDR, sandboxing, or malware-analysis solutions.

---

## License

See [`LICENSE`](LICENSE) for licensing information.