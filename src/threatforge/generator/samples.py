from pathlib import Path

def generate_test_sample(output: str, sample_type: str) -> Path:        # Generate a controlled evaluation sample.

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
        ),

        "marker-case": (
            "Sec-n-ThreatForge controlled variant.\n"
            "tf_test_marker\n"
        ),

        "marker-context": (
            "Sec-n-ThreatForge controlled variant.\n"
            "ordinary data before marker\n"
            "TF_TEST_MARKER\n"
            "ordinary data after marker\n"
        ),

        "marker-duplicate": (
            "Sec-n-ThreatForge controlled variant.\n"
            "TF_TEST_MARKER\n"
            "TF_TEST_MARKER\n"
        ),

        "marker-spaced": (
            "Sec-n-ThreatForge controlled variant.\n"
            "TF_TEST_MARKER    \n"
        ),

        "marker-mixed-case": (
            "Sec-n-ThreatForge controlled variant.\n"
            "Tf_TeSt_MaRkEr\n"
        ),

        "powershell-string": (
            "Sec-n-ThreatForge controlled string test.\n"
            "powershell.exe\n"
        ),

        "cmd-string": (
            "Sec-n-ThreatForge controlled string test.\n"
            "cmd.exe\n"
        ),

        "multiple-suspicious-strings": (
            "Sec-n-ThreatForge controlled string test.\n"
            "powershell.exe\n"
            "cmd.exe\n"
            "wscript.exe\n"
        )
    }

    if sample_type not in samples:
        raise ValueError(
            f"Unknown sample type: {sample_type}"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    output_path.write_text(
        samples[sample_type],
        encoding="utf-8",
    )

    return output_path