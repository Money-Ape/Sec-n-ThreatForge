from dataclasses import dataclass
from pathlib import Path
from threatforge.analyzer.entropy import calc_entropy
from threatforge.analyzer.fileinfo import get_file_info
from threatforge.analyzer.filetype import detect_file_type
from threatforge.analyzer.hashing import calc_hashes
from threatforge.analyzer.strings import extract_strings
from threatforge.analyzer.executable.detector import detect_executable_format
from threatforge.analyzer.executable.pe import analyze_pe
from threatforge.analyzer.executable.elf import analyze_elf
from threatforge.core.result import AnalysisResult
from threatforge.detector.rules import run_detection_rules
from threatforge.detector.scoring import calc_risk
from threatforge.evaluation.corpus import CorpusSample

@dataclass
class EvaluationResult:     # Result of evaluating one corpus sample.

    name: str
    path: str
    category: str

    expected_detection: bool
    actual_detection: bool

    expected_risk: str | None
    actual_risk: str

    score: int
    correct: bool

def analyze_file(path: str | Path) -> AnalysisResult:
    # Run the normal ThreatForge static-analysis pipeline. This is intentionally the same analysis pipeline used by the CLI.

    path = str(path)

    file_info = get_file_info(path)
    hashes = calc_hashes(path)
    file_type = detect_file_type(path)
    entropy = calc_entropy(path)
    strings = extract_strings(path)

    executable = {}
    exec_format = detect_executable_format(path)
    if exec_format == "PE":
        executable = analyze_pe(path)

    elif exec_format == "ELF":
        executable = analyze_elf(path)

    result = AnalysisResult(
        file=file_info,
        hashes=hashes,
        file_type=file_type,
        executable=executable,
        entropy=entropy,
        strings=strings,
    )

    result.findings = run_detection_rules(result)
    result.risk = calc_risk(result.findings)

    return result

def evaluate_sample(sample: CorpusSample, root: str | Path = ".",) -> EvaluationResult:
    # Analyze one corpus sample and compare its actual detection state with the expected detection state.

    root = Path(root)
    sample_path = root / sample.path
    result = analyze_file(sample_path)
    actual_detection = bool(result.findings)

    actual_risk = result.risk.get("classification", "UNKNOWN")
    score = result.risk.get("score", 0)
    correct = (actual_detection == sample.expected_detection)

    return EvaluationResult(
        name=sample.name,
        path=str(sample_path),
        category=sample.category,
        expected_detection=sample.expected_detection,
        actual_detection=actual_detection,
        expected_risk=None,
        actual_risk=actual_risk,
        score=score,
        correct=correct,
    )

def run_corpus(samples: list[CorpusSample], root: str | Path = ".",) -> list[EvaluationResult]:     # Evaluate every sample in the corpus.

    results = []
    for sample in samples:
        results.append(evaluate_sample(sample, root=root))

    return results