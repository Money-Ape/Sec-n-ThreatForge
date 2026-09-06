from pathlib import Path

def get_file_info(path: str) -> dict:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    stat = file_path.stat()

    return {
        "name": file_path.name,
        "path": str(file_path.resolve()),
        "size": stat.st_size,
        "extension": file_path.suffix or "none",
    }