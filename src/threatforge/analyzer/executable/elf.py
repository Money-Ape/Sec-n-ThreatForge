import struct
from pathlib import Path


def machine_name(machine: int) -> str:
    """
    Convert ELF machine identifier into
    a human-readable architecture name.
    """

    machines = {
        0x03: "x86",
        0x3E: "x86-64",
        0x28: "ARM",
        0xB7: "AArch64",
        0x08: "MIPS",
        0xF3: "RISC-V",
    }

    return machines.get(
        machine,
        f"Unknown (0x{machine:04X})"
    )


def elf_type_name(elf_type: int) -> str:
    """
    Convert ELF file type into a readable name.
    """

    types = {
        1: "Relocatable",
        2: "Executable",
        3: "Shared Object",
        4: "Core",
    }

    return types.get(
        elf_type,
        f"Unknown ({elf_type})"
    )


def analyze_elf(path: str) -> dict:
    # Perform basic static ELF analysis, This function only reads the executable. It does not execute the file.

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file_path, "rb") as file:
        header = file.read(64)

    if len(header) < 16:
        raise ValueError("File is too small to contain an ELF header")

    if header[:4] != b"\x7fELF":
        raise ValueError("Invalid ELF file")

    elf_class = header[4]       # -------------------- ELF Class
    if elf_class == 1:
        architecture_class = "ELF32"

    elif elf_class == 2:
        architecture_class = "ELF64"

    else:
        architecture_class = "Unknown"

    data_encoding = header[5]       # -------------------- ENDIANNESS
    if data_encoding == 1:
        endian = "<"
        endian_name = "Little Endian"

    elif data_encoding == 2:
        endian = ">"
        endian_name = "Big Endian"

    else:
        raise ValueError("Unknown ELF byte order")

    elf_type = struct.unpack_from(endian + "H", header, 16)[0]      # -------------------- ELF type
    machine = struct.unpack_from(endian + "H", header, 18)[0]       # -------------------- Machine

# -------------------- Entry Point
    if elf_class == 1:
        entry_point = struct.unpack_from(endian + "I", header, 24)[0]

    elif elf_class == 2:
        entry_point = struct.unpack_from(endian + "Q", header, 24)[0]

    else:
        entry_point = 0

    return {
        "format": "ELF",
        "class": architecture_class,
        "endianness": endian_name,
        "type": elf_type_name(elf_type),
        "architecture": machine_name(machine),
        "entry_point": hex(entry_point),
    }