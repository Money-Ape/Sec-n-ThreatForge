import struct
from pathlib import Path

def analyze_elf(path: str) -> dict:
    # Perform basic static ELF analysis, This function does not execute the file.

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file_path, "rb") as file:
        header = file.read(64)

    if header[:4] != b"\x7fELF":
        raise ValueError("Not a valid ELF file")

    elf_class = header[4]
    data_encoding = header[5]

    # ELF64
    if elf_class == 2:
        architecture_class = "ELF64"

    # ELF32
    elif elf_class == 1:
        architecture_class = "ELF32"

    else:
        architecture_class = "UNKNOWN"

    if data_encoding == 1:
        endian = "little"

    elif data_encoding == 2:
        endian = "big"

    else:
        endian = "unknown"

    # e_machine is located at offset 18
    if elf_class == 2:
        machine = struct.unpack_from("<H" if data_encoding == 1 else ">H", header, 18)[0]

    else:
        machine = struct.unpack_from("<H" if data_encoding == 1 else ">H", header, 18)[0]

    # Entry point:
    # ELF64 -> offset 24, 8 bytes
    # ELF32 -> offset 24, 4 bytes
    if elf_class == 2:
        entry_point = struct.unpack_from("<Q" if data_encoding == 1 else ">Q", header, 24)[0]

    else:
        entry_point = struct.unpack_from("<I" if data_encoding == 1 else ">I", header, 24)[0]

    return {
        "format": "ELF",
        "class": architecture_class,
        "endianness": endian,
        "machine": machine,
        "entry_point": hex(entry_point),
    }