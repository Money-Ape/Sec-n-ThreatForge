from pathlib import Path

def detect_executable_format(path: str) -> str:
    """
    Detect whether a file is a PE or ELF executable.
    Returns:
        "PE"
        "ELF"
        "UNKNOWN"
    """

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file_path, "rb") as file:
        header = file.read(64)

    # ELF magic:
    # 0x7F + "ELF"
    if header[:4] == b"\x7fELF":
        return "ELF"

    # PE files start with:
    # "MZ"
    if header[:2] == b"MZ":
        return "PE"

    return "UNKNOWN"