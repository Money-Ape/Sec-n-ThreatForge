from dataclasses import dataclass
from threatforge.evaluation.runner import EvaluationResult

@dataclass
class EvaluationMetrics:        # Aggregate detection metrics for a corpus.
    total: int

    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int

    detection_rate: float
    false_positive_rate: float

    accuracy: float
    precision: float
    recall: float

    risk_correct: int
    risk_incorrect: int
    risk_accuracy: float

def calculate_metrics(results: list[EvaluationResult], ) -> EvaluationMetrics:

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    risk_correct = 0
    risk_incorrect = 0

    for result in results:
        # Detection metrics
        if result.expected_detection:
            if result.actual_detection:
                true_positive += 1

            else:
                false_negative += 1

        else:
            if result.actual_detection:
                false_positive += 1

            else:
                true_negative += 1

        # Risk regression metrics
        if result.expected_risk is None:
            risk_correct += 1

        elif (result.expected_risk.upper() == result.actual_risk.upper()):
            risk_correct += 1

        else:
            risk_incorrect += 1

    total = len(results)

    detection_rate = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0.0
    )

    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if (false_positive + true_negative)
        else 0.0
    )

    accuracy = (
        (true_positive + true_negative) / total
        if total
        else 0.0
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )

    recall = detection_rate
    risk_accuracy = (
        risk_correct / total
        if total
        else 0.0
    )

    return EvaluationMetrics(
        total=total,
        true_positive=true_positive,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        detection_rate=detection_rate,
        false_positive_rate=false_positive_rate,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        risk_correct=risk_correct,
        risk_incorrect=risk_incorrect,
        risk_accuracy=risk_accuracy
    )