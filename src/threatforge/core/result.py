from dataclasses import dataclass, field

@dataclass
class AnalysisResult:
    file: dict = field(default_factory=dict)
    hashes: dict = field(default_factory=dict)
    file_type: dict = field(default_factory=dict)
    executable: dict = field(default_factory=dict)

    entropy: float = 0.0

    strings: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)

    risk: dict = field(default_factory=dict)