import json
from dataclasses import asdict
from pathlib import Path
from threatforge.core.result import AnalysisResult
from threatforge.evaluation.metrics import EvaluationMetrics
from threatforge.evaluation.runner import EvaluationResult

def save_json_report(result: AnalysisResult, output: str) -> None:
    # Save a single file analysis as JSON.
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(result)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def save_evaluation_json_report(results: list[EvaluationResult], metrics: EvaluationMetrics, output: str) -> None:
    # Save a complete corpus evaluation as JSON.
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "evaluation": {
            "samples": [
                {
                    "name": result.name,
                    "path": result.path,
                    "category": result.category,
                    "expected_detection":
                        result.expected_detection,
                    "actual_detection":
                        result.actual_detection,
                    "expected_risk":
                        result.expected_risk,
                    "actual_risk":
                        result.actual_risk,
                    "score":
                        result.score,
                    "correct":
                        result.correct,
                }
                for result in results
            ],

            "metrics": {
                "total":
                    metrics.total,

                "true_positive":
                    metrics.true_positive,

                "true_negative":
                    metrics.true_negative,

                "false_positive":
                    metrics.false_positive,

                "false_negative":
                    metrics.false_negative,

                "detection_rate":
                    metrics.detection_rate,

                "false_positive_rate":
                    metrics.false_positive_rate,

                "accuracy":
                    metrics.accuracy,

                "precision":
                    metrics.precision,

                "recall":
                    metrics.recall,

                "risk_correct":
                    metrics.risk_correct,

                "risk_incorrect":
                    metrics.risk_incorrect,

                "risk_accuracy":
                    metrics.risk_accuracy,
            },
        }
    }

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)