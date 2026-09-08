from collections import defaultdict

# Weak heuristic indicators should not dominate the final risk score.
CATEGORY_WEIGHTS = {
    "entropy": 0.25,
    "string": 0.50,
    "pe_import": 0.35,
    "pe_section": 0.75,
    "test": 1.00,
}

# Prevent a single category from dominating the entire risk score.
CATEGORY_CAPS = {
    "entropy": 10,
    "string": 20,
    "pe_import": 25,
    "pe_section": 30,
    "test": 100,
}

def finding_identifier(finding: dict) -> str | None:
    return (finding.get("indicator") or finding.get("signature"))       # Return a stable identifier for a finding.

def deduplicate_findings(findings: list[dict]) -> list[dict]:       # Remove duplicate findings with the same identifier.
    unique = {}
    anonymous = []
    for finding in findings:
        identifier = finding_identifier(finding)
        if not identifier:
            anonymous.append(finding)
            continue

        if identifier not in unique:
            unique[identifier] = finding

    return list(unique.values()) + anonymous

def calculate_base_contribution(finding: dict) -> int:
    # Calculate the initial risk contribution of a finding.

    severity = finding.get("severity", 0)
    category = finding.get("category", "")
    weight = CATEGORY_WEIGHTS.get(category, 0.50)
    contribution = round(severity * weight)

    return max(contribution, 0)

def apply_category_caps(contributions: list[tuple[dict, int]]) -> tuple[int, dict]:
    category_totals = defaultdict(int)
    for finding, contribution in contributions:
        category = finding.get("category", "unknown")
        category_totals[category] += contribution

    capped_totals = {}

    for category, total in category_totals.items():
        cap = CATEGORY_CAPS.get(category, 25)
        capped_totals[category] = min(total, cap)

    return sum(capped_totals.values()), dict(capped_totals)


def calculate_context_bonus(findings: list[dict]) -> tuple[int, list[str]]:
    # Add additional risk only when multiple related indicators occur together.

    identifiers = {
        finding_identifier(finding)
        for finding in findings
    }

    bonus = 0
    reasons = []

    memory_api_pair = {
        "pe_import:VirtualAlloc",
        "pe_import:VirtualProtect",
    }

    if memory_api_pair.issubset(identifiers):
        bonus += 5
        reasons.append("VirtualAlloc and VirtualProtect are both imported")

    process_injection_pattern = {
        "pe_import:VirtualAlloc",
        "pe_import:WriteProcessMemory",
        "pe_import:CreateRemoteThread",
    }

    if process_injection_pattern.issubset(identifiers):
        bonus += 20
        reasons.append("VirtualAlloc, WriteProcessMemory and CreateRemoteThread are imported together")

    process_memory_pattern = {
        "pe_import:OpenProcess",
        "pe_import:WriteProcessMemory",
    }

    if process_memory_pattern.issubset(identifiers):
        bonus += 10
        reasons.append("OpenProcess and WriteProcessMemory are imported together")

    execution_memory_pattern = {
        "pe_import:VirtualAlloc",
        "pe_import:CreateRemoteThread",
    }

    if execution_memory_pattern.issubset(identifiers):
        bonus += 10
        reasons.append("VirtualAlloc and CreateRemoteThread are imported together")

    if ("pe_writable_executable_section" in identifiers and "pe_import:VirtualProtect" in identifiers):
        bonus += 10
        reasons.append("Writable/executable PE section combined with VirtualProtect")

    return bonus, reasons

def calc_risk(findings: list[dict]) -> dict:        # Calculate context-aware risk from detection findings.
    findings = deduplicate_findings(findings)
    contributions = []
    for finding in findings:
        contribution = calculate_base_contribution(finding)
        contributions.append((finding, contribution))

    base_score, category_breakdown = apply_category_caps(contributions)
    context_bonus, context_reasons = calculate_context_bonus(findings)
    score = base_score + context_bonus
    score = min(score, 100)

    if score >= 70:
        classification = "CRITICAL"

    elif score >= 40:
        classification = "HIGH"

    elif score >= 20:
        classification = "MEDIUM"

    else:
        classification = "LOW"

    return {
        "score": score,
        "classification": classification,
        "base_score": base_score,
        "context_bonus": context_bonus,
        "category_breakdown": category_breakdown,
        "context_reasons": context_reasons,
    }