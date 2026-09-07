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

**v0.3.3**

### v0.3.3 Features

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
* Heuristic risk scoring
* Terminal security reports
* JSON report generation
* Controlled test-sample generation

> **Deep dive:** For a detailed breakdown of how the PE and ELF parsers work internally, see [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/EXECUTABLE_ANALYSIS.md).

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

See [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/EXECUTABLE_ANALYSIS.md) for details on exactly what is parsed from PE and ELF binaries and how.

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

The `executable` block is populated only when the analyzed file is a recognized PE or ELF binary, and contains the format-specific fields described in [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/EXECUTABLE_ANALYSIS.md) (sections, imports/exports for PE, dependencies/symbols for ELF).

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

The current detection engine combines multiple indicators.

```text
                  Detection Engine
                         │
             ┌───────────┴───────────┐
             ↓                       ↓
       Signature Rules          Heuristics
             │                       │
             ↓                       ↓
        Known test markers      File indicators
             │                       │
             └───────────┬───────────┘
                         ↓
                     Findings
                         ↓
                    Risk Score
```

### Signature detection

The current version contains controlled Sec-n-ThreatForge test signatures such as:

```text
TF_TEST_MARKER
TF_SUSPICIOUS_PATTERN
```

These are **test indicators**, not production malware signatures.

### Entropy analysis

Sec-n-ThreatForge calculates Shannon byte entropy:

```text
0 ───────────────────────── 8
low                         high
```

High entropy can occur in compressed, encrypted, packed, or random data. Therefore, entropy is treated only as a **weak heuristic** and is not independently considered proof of malicious activity.

### Executable-format analysis

PE and ELF binaries additionally go through structural parsing (sections, imports/exports, dynamic symbols and dependencies). This is **static, read-only parsing** — no PE or ELF file is ever executed, loaded, or mapped by Sec-n-ThreatForge. See [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/EXECUTABLE_ANALYSIS.md) for the full breakdown.

---

# Risk Assessment

Findings contribute to a cumulative risk score.

Current classification:

```text
0 – 19      LOW
20 – 39     MEDIUM
40 – 69     HIGH
70 – 100    CRITICAL
```

The scoring system is intentionally simple and will be expanded as additional analysis capabilities are introduced.

A risk score represents an **assessment based on collected indicators**, not a definitive malware verdict.

---

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

* [`EXECUTABLE_ANALYSIS.md`](src/threatforge/analyzer/executable/EXECUTABLE_ANALYSIS.md) — how the PE and ELF static analyzers work, field-by-field, including format layout notes and current limitations.

---

# Project Status

**Current release: v0.3.3**

The v0.3.x development line adds executable-format analysis, including PE/ELF identification, section-level static analysis, PE import/export table parsing, and ELF dynamic symbol/dependency parsing.

Sec-n-ThreatForge is currently an early-stage security research framework. Its static-analysis and detection capabilities are experimental and should not be considered a replacement for established antivirus, EDR, sandboxing, or malware-analysis solutions.

---

## License

See [`LICENSE`](LICENSE) for licensing information.