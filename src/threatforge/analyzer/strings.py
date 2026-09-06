import re
from pathlib import Path

def extract_strings(path: str, minimum_length: int=4) -> list[str]:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    data = file_path.read_bytes()
    pattern = rb"[ -~]{" + str(minimum_length).encode() + rb",}"
    matches = re.findall(pattern, data)

    return [
        match.decode("arcii", error="ignore")
        for match in matches
    ]
    