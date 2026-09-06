import struct
from pathlib import Path

def analyze_pe(path: str) -> dict:
    # Perform basic static PE analysis, This function does not execute the file.

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file_path, "rb") as file:     # DOS header
        dos_header = file.read(64)

        if dos_header[:2] != b"MZ":
            raise ValueError("Not a valid PE file")

        # Offset of PE header is stored at 0x3C
        pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]

        # Move to PE header
        file.seek(pe_offset)
        pe_signature = file.read(4)
        if pe_signature != b"PE\x00\x00":
            raise ValueError("Invalid PE signature")

        # COFF header
        coff_header = file.read(20)
        machine, section_count, timestamp, symbol_table, number_of_symbols, optional_header_size, characteristics = struct.unpack("<HHIIIHH", coff_header)

        return {
            "format": "PE",
            "machine": machine,
            "section_count": section_count,
            "timestamp": timestamp,
            "optional_header_size": optional_header_size,
            "characteristics": characteristics,
        }