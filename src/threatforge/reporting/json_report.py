import json
from dataclasses import asdict
from threatforge.core.result import AnalysisResult

def save_json_report(result: AnalysisResult, output: str) -> None:
    data = asdict(result)
    with open(output, "w",encoding="utf-8" ) as file:
        json.dump(data, file, indent=4)