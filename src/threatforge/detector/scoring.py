def calc_risk(findings: list[dict]) -> dict:
    score = sum(
        finding.get("severity", 0)
        for finding in findings
    )
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
    }