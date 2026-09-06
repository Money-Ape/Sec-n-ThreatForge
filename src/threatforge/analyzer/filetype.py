import magic
from pathlib import Path

def detect_file_type(path: str) -> dict:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    mime_type = magic.from_file(str(file_path), mime=True)
    description = magic.from_file(str(file_path))

    return {
        "mime": mime_type,
        "description": description,
    }