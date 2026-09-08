from .signatures import TEST_SIGNATURES, SUSPICIOUS_STRINGS

def scan_strings(strings: list[str]) -> list[dict]:
    findings = []

    for string in strings:
        for signature, metadata in TEST_SIGNATURES.items():

            if signature.lower() in string.lower():
                findings.append({
                    "type": "signature",
                    "signature": signature,
                    "description": metadata["description"],
                    "severity": metadata["severity"],
                    "category": metadata["category"],
                    "matched_string": string,
                })

    return findings


def scan_entropy(entropy: float) -> list[dict]:
    findings = []

    if entropy >= 7.5:
        findings.append({
            "type": "heuristic",
            "indicator": "high_entropy",
            "description": "File has unusually high byte entropy",
            "severity": 10,
            "category": "entropy",
            "value": entropy,
        })

    return findings

def scan_suspicious_strings(strings: list[str]) -> list[dict]:
    # Look for potentially interesting strings. These indicators are not malware verdicts.
    findings = []
    reported = set()
    for string in strings:
        normalized = string.lower()
        for indicator, metadata in SUSPICIOUS_STRINGS.items():
            if indicator.lower() not in normalized:
                continue

            if indicator in reported:
                continue

            reported.add(indicator)

            findings.append({
                "type": "heuristic",
                "indicator": f"string:{indicator}",
                "description": metadata["description"],
                "severity": metadata["severity"],
                "category": "string",
                "matched_string": string,
            })

    return findings

def scan_pe_sections(executable: dict) -> list[dict]:       # Detect unusual PE section permissions.
    findings = []
    if executable.get("format") != "PE":
        return findings

    for section in executable.get("sections", []):
        name = section.get("name", "<unknown>")
        permissions = section.get("permissions", "")

        if "X" in permissions and "W" in permissions:
            findings.append({
                "type": "heuristic",
                "indicator": "pe_writable_executable_section",
                "description": ("PE section is both writable and executable"),
                "severity": 20,
                "category": "pe_section",
                "section": name,
                "permissions": permissions,
            })

    return findings

def scan_pe_imports(executable: dict) -> list[dict]:
    # Detect potentially security-sensitive PE imports. Import presence alone is not proof of malicious behavior.
    findings = []
    if executable.get("format") != "PE":
        return findings

    interesting_imports = {
        "VirtualAlloc": 15,
        "VirtualProtect": 15,
        "WriteProcessMemory": 20,
        "CreateRemoteThread": 20,
        "OpenProcess": 10,
        "WinExec": 15,
        "ShellExecuteA": 10,
        "ShellExecuteW": 10,
    }
    reported = set()

    for library in executable.get("imports", []):
        dll = library.get("dll", "<unknown>")
        for function in library.get("functions", []):
            name = function.get("name")

            if name not in interesting_imports:
                continue

            if name in reported:
                continue

            reported.add(name)

            findings.append({
                "type": "heuristic",
                "indicator": f"pe_import:{name}",
                "description": (f"Potentially security-sensitive API import: {name}"),
                "severity": interesting_imports[name],
                "category": "pe_import",
                "library": dll,
                "function": name,
            })

    return findings

def run_detection_rules(result) -> list[dict]:      # Run all static detection rules against an AnalysisResult.
    findings = []

    # Generic rules
    findings.extend(scan_strings(result.strings))
    findings.extend(scan_suspicious_strings(result.strings))
    findings.extend(scan_entropy(result.entropy))

    # Executable-specific rules
    if result.executable:
        findings.extend(scan_pe_sections(result.executable))
        findings.extend(scan_pe_imports(result.executable))

    return findings