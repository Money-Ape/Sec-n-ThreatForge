import math
from pathlib import Path

def calc_entropy(path: str) -> float:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found : {path}")

    data = file_path.read_bytes()
    if not data:
        return 0.0

    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1

    entropy = 0.0
    length = len(data)

    for count in frequencies:
        if count == 0:
            continue

        probability = count/length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)