import json
from dataclasses import dataclass
from pathlib import Path

@dataclass
class CorpusSample:     # A single sample definition in the evaluation corpus.
    name: str
    path: str
    expected_detection: bool
    expected_risk: str | None = None
    category: str = "unknown"

def load_corpus(manifest_path: str | Path) -> list[CorpusSample]:       # Load evaluation samples from a corpus manifest.

    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Corpus manifest not found: {manifest_path}")

    with manifest_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    samples = []
    for entry in data.get("samples", []):
        samples.append(
            CorpusSample(
                name=entry["name"],
                path=entry["path"],
                expected_detection=entry["expected_detection"],
                expected_risk=entry.get("expected_risk"),
                category=entry.get("category", "unknown"),
            )
        )

    return samples