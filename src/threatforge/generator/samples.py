from pathlib import Path

def generate_test_sample(output: str, sample_type: str) -> Path:
    output_path = Path(output)

    samples = {
        "benign": (
            "Sec-n-ThreatForge benign test sample.\n"
            "This file contains ordinary test data.\n"
        ),
        "marker": (
            "Sec-n-ThreatForge controlled test sample.\n"
            "TF_TEST_MARKER\n"
        ),
        "suspicious": (
            "Sec-n-ThreatForge controlled analysis sample.\n"
            "TF_SUSPICIOUS_PATTERN\n"
        )
    }

    if sample_type not in samples:
        raise ValueError(
            f"Unknown sample type: {sample_type}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(samples[sample_type])

    return output_path