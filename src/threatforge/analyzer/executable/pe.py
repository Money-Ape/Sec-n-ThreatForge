import struct
from pathlib import Path

def machine_name(machine: int) -> str:
    # Convert PE machine identifier into a human-readable architecture name.

    machines = {
        0x014C: "x86",
        0x8664: "x86-64",
        0x01C0: "ARM",
        0xAA64: "ARM64",
    }

    return machines.get(machine, f"Unknown (0x{machine:04X})")

def subsystem_name(subsystem: int) -> str:
    # Convert PE subsystem identifier into a human-readable name.

    subsystems = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows Console",
        5: "OS/2 Console",
        7: "POSIX Console",
        9: "Windows CE GUI",
        10: "EFI Application",
        11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver",
        13: "EFI ROM",
        14: "XBOX",
        16: "Windows Boot Application",
    }

    return subsystems.get(subsystem, f"Unknown ({subsystem})")

def parse_pe_sections(file, section_count: int) -> list[dict]:
    # Parse PE section headers. The file object must already be positioned at the beginning of the PE section table.

    sections = []
    for _ in range(section_count):
        section_header = file.read(40)

        if len(section_header) < 40:
            raise ValueError("Incomplete PE section header")

# -------------------- Section Name
        raw_name = section_header[0:8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")

# -------------------- Section Information
        virtual_size = struct.unpack_from("<I", section_header, 8)[0]
        virtual_address = struct.unpack_from("<I", section_header, 12)[0]
        raw_size = struct.unpack_from("<I", section_header, 16)[0]
        raw_pointer = struct.unpack_from("<I", section_header, 20)[0]
        characteristics = struct.unpack_from("<I", section_header,36)[0]

        sections.append({
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": hex(virtual_address),
            "raw_size": raw_size,
            "raw_pointer": hex(raw_pointer),
            "characteristics": hex(characteristics),
            "permissions": section_permissions(characteristics),
        })

    return sections

def section_permissions(characteristics: int) -> str:
    # Convert PE section memory characteristics into readable permissions.

    permissions = ""

    if characteristics & 0x20000000:
        permissions += "X"

    if characteristics & 0x40000000:
        permissions += "R"

    if characteristics & 0x80000000:
        permissions += "W"

    return permissions or "-"

def analyze_pe(path: str) -> dict:
    # Perform basic static PE analysis, This function only reads the executable. It does not execute the file.

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file_path, "rb") as file:
        dos_header = file.read(64)      # -------------------- DOS Header
        if len(dos_header) < 64:
            raise ValueError("File is too small to contain a valid DOS header")

        if dos_header[:2] != b"MZ":
            raise ValueError("Invalid PE file: missing MZ signature")

        # e_lfanew: Offset 0x3C contains the location of the PE header.
        pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]

        file.seek(pe_offset)        # -------------------- PE Signature
        pe_signature = file.read(4)
        if pe_signature != b"PE\x00\x00":
            raise ValueError("Invalid PE file: missing PE signature")

        coff_header = file.read(20)     # -------------------- COFF Header
        if len(coff_header) < 20:
            raise ValueError("Incomplete PE COFF header")

        (machine, section_count, timestamp, symbol_table, number_of_symbols, optional_header_size, characteristics) = struct.unpack("<HHIIIHH",coff_header)

        optional_header = file.read(optional_header_size)       # -------------------- Optional Header
        if len(optional_header) < 2:
            raise ValueError("Missing PE optional header")

        sections = parse_pe_sections(file, section_count)

        # First field tells us whether this is:
        #
        # 0x10B -> PE32
        # 0x20B -> PE32+
        #
        optional_magic = struct.unpack_from("<H", optional_header, 0)[0]
        if optional_magic == 0x10B:
            pe_format = "PE32"

        elif optional_magic == 0x20B:
            pe_format = "PE32+"

        else:
            pe_format = "Unknown"

        entry_point = struct.unpack_from("<I", optional_header, 16)[0]      # -------------------- Entry Point
        if optional_magic == 0x10B:
            image_base = struct.unpack_from("<I", optional_header, 28)[0]

        elif optional_magic == 0x20B:       # -------------------- IMAGE BASE
            image_base = struct.unpack_from("<Q", optional_header, 24)[0]

        else:
            image_base = 0

        # Subsystem is located at offset 68 inside the Optional Header.     # -------------------- SUB SYSTEM
        if len(optional_header) >= 70:
            subsystem = struct.unpack_from("<H", optional_header, 68)[0]

        else:
            subsystem = 0

        return {
            "format": "PE",
            "architecture": machine_name(machine),
            "pe_format": pe_format,
            "section_count": section_count,
            "sections": sections,
            "timestamp": timestamp,
            "entry_point": hex(entry_point),
            "image_base": hex(image_base),
            "subsystem": subsystem_name(subsystem),
            "characteristics": hex(characteristics),
        }