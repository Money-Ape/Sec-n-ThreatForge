from .signatures import TEST_SIGNATURES

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
            "description": ("File has unusually high byte entropy"),
            "severity": 10,
            "category": "entropy",
            "value": entropy,
        })

    return findings