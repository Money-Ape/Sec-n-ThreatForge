import struct
from pathlib import Path


def machine_name(machine: int) -> str:
    # Convert ELF machine identifier into a human-readable architecture name.

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
    # Convert ELF file type into a readable name.

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

def parse_elf_sections(file, elf_class: int, endian: str, section_offset: int, section_size: int, section_count: int, string_table_index: int) -> list[dict]:
    # Parse ELF section headers and resolve their names.

# -------------------- Read Section Headers
    sections = []
    file.seek(section_offset)

    raw_sections = []
    for _ in range(section_count):
        data = file.read(section_size)
        if len(data) < section_size:
            raise ValueError("Incomplete ELF section header")

        raw_sections.append(data)

# -------------------- Parse Section Headers
    for data in raw_sections:
        if elf_class == 2:
            # ELF64
            name_offset = struct.unpack_from(endian + "I", data, 0)[0]
            section_type = struct.unpack_from(endian + "I", data, 4)[0]
            flags = struct.unpack_from(endian + "Q", data, 8)[0]
            address = struct.unpack_from(endian + "Q", data, 16)[0]
            offset = struct.unpack_from(endian + "Q", data, 24)[0]
            size = struct.unpack_from(endian + "Q", data, 32)[0]

        else:
            # ELF32
            name_offset = struct.unpack_from(endian + "I", data, 0)[0]
            section_type = struct.unpack_from(endian + "I", data, 4)[0]
            flags = struct.unpack_from(endian + "I", data, 8)[0]
            address = struct.unpack_from(endian + "I", data, 12)[0]
            offset = struct.unpack_from(endian + "I", data, 16)[0]
            size = struct.unpack_from(endian + "I", data, 20)[0]

        sections.append({
            "name_offset": name_offset,
            "type": section_type_name(section_type),
            "flags": section_flags_name(flags),
            "address": hex(address),
            "offset": hex(offset),
            "size": size,
        })

# -------------------- Section Name
    if (string_table_index >= section_count or string_table_index < 0):
        return sections

    string_section = sections[string_table_index]
    file.seek(int(string_section["offset"], 16))

    string_table = file.read(string_section["size"])

    for section in sections:
        name_offset = section["name_offset"]
        if name_offset >= len(string_table):
            section["name"] = "<invalid>"
            continue

        end = string_table.find(b"\x00", name_offset)
        if end == -1:
            end = len(string_table)

        section["name"] = (string_table[name_offset:end].decode("utf-8",errors="replace"))

        del section["name_offset"]

    return sections

def section_type_name(section_type: int) -> str:
    # Convert ELF section type to a readable name.

    types = {
        0: "NULL",
        1: "PROGBITS",
        2: "SYMTAB",
        3: "STRTAB",
        4: "RELA",
        5: "HASH",
        6: "DYNAMIC",
        7: "NOTE",
        8: "NOBITS",
        9: "REL",
        11: "DYNSYM",
        14: "INIT_ARRAY",
        15: "FINI_ARRAY",
    }

    return types.get(section_type, f"UNKNOWN ({section_type})")

def section_flags_name(flags: int) -> str:
    # Convert ELF section flags into readable flags.

    result = ""

    if flags & 0x1:
        result += "W"

    if flags & 0x2:
        result += "A"

    if flags & 0x4:
        result += "X"

    return result or "-"

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

        if elf_class == 2:
            section_offset = struct.unpack_from(endian + "Q", header, 40)[0]
            section_entry_size = struct.unpack_from(endian + "H", header, 58)[0]
            section_count = struct.unpack_from(endian + "H", header, 60)[0]
            string_table_index = struct.unpack_from(endian + "H", header, 62)[0]

        else:
            section_offset = struct.unpack_from(endian + "I", header, 32)[0]
            section_entry_size = struct.unpack_from(endian + "H", header, 46)[0]
            section_count = struct.unpack_from(endian + "H", header, 48)[0]
            string_table_index = struct.unpack_from(endian + "H", header, 50)[0]

        sections = parse_elf_sections(
            file=file,
            elf_class=elf_class,
            endian=endian,
            section_offset=section_offset,
            section_size=section_entry_size,
            section_count=section_count,
            string_table_index=string_table_index,
        )

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
            "section_count": section_count,
            "sections": sections
        }