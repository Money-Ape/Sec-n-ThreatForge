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

    return machines.get(machine, f"Unknown (0x{machine:04X})")


def elf_type_name(elf_type: int) -> str:
    # Convert ELF file type into a readable name.

    types = {
        1: "Relocatable",
        2: "Executable",
        3: "Shared Object",
        4: "Core",
    }

    return types.get(elf_type, f"Unknown ({elf_type})")

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

def symbol_binding_name(binding: int) -> str:
    # Convert ELF symbol binding identifier into a readable name.

    bindings = {
        0: "LOCAL",
        1: "GLOBAL",
        2: "WEAK",
        10: "GNU_UNIQUE"
    }

    return bindings.get(binding, f"UNKNOWN ({binding})")


def symbol_type_name(symbol_type: int) -> str:
    # Convert ELF symbol type identifier into a readable name.

    types = {
        0: "NOTYPE",
        1: "OBJECT",
        2: "FUNC",
        3: "SECTION",
        4: "FILE",
        5: "COMMON",
        6: "TLS",
        10: "GNU_IFUNC"
    }

    return types.get(symbol_type, f"UNKNOWN ({symbol_type})")

def parse_elf_symbols(file, sections: list[dict], elf_class: int, endian: str) -> list[dict]:
    # Parse the ELF .dynsym section and resolve dynamic symbol names using the .dynstr section.
    # Supports:
    #   - ELF32
    #   - ELF64
    #   - Little Endian
    #   - Big Endian
    # The function performs static parsing only. It does not execute the ELF file.

    dynsym_section = None
    dynstr_section = None

    # -------------------- Locate Required Sections

    for section in sections:
        if section.get("name") == ".dynsym":
            dynsym_section = section

        elif section.get("name") == ".dynstr":
            dynstr_section = section

    if dynsym_section is None or dynstr_section is None:
        return []

    # -------------------- Read Dynamic String Table

    dynstr_offset = int(dynstr_section["offset"], 16)
    dynstr_size = dynstr_section["size"]
    file.seek(dynstr_offset)
    dynstr = file.read(dynstr_size)

    if len(dynstr) < dynstr_size:
        raise ValueError("Incomplete ELF dynamic string table")

    # -------------------- Read Dynamic Symbol Table

    dynsym_offset = int(dynsym_section["offset"], 16)
    dynsym_size = dynsym_section["size"]
    file.seek(dynsym_offset)
    dynsym = file.read(dynsym_size)
    if len(dynsym) < dynsym_size:
        raise ValueError("Incomplete ELF dynamic symbol table")

    # -------------------- Determine Symbol Entry Size
    if elf_class == 2:
        entry_size = 24     # ELF64 symbol entry = 24 bytes

    elif elf_class == 1:
        entry_size = 16     # ELF32 symbol entry = 16 bytes

    else:
        raise ValueError("Unsupported ELF class")

    # -------------------- Parse Symbols
    symbols = []
    for offset in range(0, dynsym_size, entry_size):
        if offset + entry_size > len(dynsym):
            break

        # -------------------- ELF64
        if elf_class == 2:
            # ELF64:
            # st_name   -> 4 bytes
            # st_info   -> 1 byte
            # st_other  -> 1 byte
            # st_shndx  -> 2 bytes
            # st_value  -> 8 bytes
            # st_size   -> 8 bytes
            name_offset = struct.unpack_from(endian + "I", dynsym, offset)[0]
            info = dynsym[offset + 4]
            other = dynsym[offset + 5]
            section_index = struct.unpack_from(endian + "H", dynsym, offset + 6)[0]
            value = struct.unpack_from(endian + "Q", dynsym, offset + 8)[0]
            size = struct.unpack_from(endian + "Q", dynsym, offset + 16)[0]

        # -------------------- ELF32
        else:
            # ELF32:
            # st_name   -> 4 bytes
            # st_value  -> 4 bytes
            # st_size   -> 4 bytes
            # st_info   -> 1 byte
            # st_other  -> 1 byte
            # st_shndx  -> 2 bytes
            name_offset = struct.unpack_from(endian + "I", dynsym, offset)[0]
            value = struct.unpack_from(endian + "I", dynsym, offset + 4)[0]
            size = struct.unpack_from(endian + "I", dynsym, offset + 8)[0]
            info = dynsym[offset + 12]
            other = dynsym[offset + 13]
            section_index = struct.unpack_from(endian + "H", dynsym, offset + 14)[0]

        # -------------------- Decode st_info

        binding = info >> 4
        symbol_type = info & 0x0F
        binding_name = symbol_binding_name(binding)
        symbol_type_name_value = symbol_type_name(symbol_type)

        # -------------------- Resolve Symbol Name

        if name_offset >= len(dynstr):
            name = "<invalid>"

        else:
            end = dynstr.find(b"\x00", name_offset)
            if end == -1:
                end = len(dynstr)

            name = dynstr[name_offset:end].decode("utf-8", errors="replace")

        # -------------------- Store Symbol
        symbols.append({
            "name": name,
            "value": hex(value),
            "size": size,
            "section_index": section_index,
            "binding": binding_name,
            "type": symbol_type_name_value,
            "info": info,
            "other": other,
        })

    return symbols

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

        # GNU extensions
        0x6FFFFFF6: "GNU_HASH",
        0x6FFFFFFD: "GNU_VERDEF",
        0x6FFFFFFE: "GNU_VERNEED",
        0x6FFFFFFF: "GNU_VERSYM",
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

def parse_elf_dynamic(file, sections: list[dict], elf_class: int, endian: str) -> list[str]:
    # Parse the ELF .dynamic section and extract DT_NEEDED shared-library dependencies.
    # The function performs static parsing only, It does not execute the ELF file.

    dynamic_section = None
    dynstr_section = None

    # -------------------- Locate Required Sections

    for section in sections:

        if section.get("name") == ".dynamic":
            dynamic_section = section

        elif section.get("name") == ".dynstr":
            dynstr_section = section

    if dynamic_section is None or dynstr_section is None:
        return []

    # -------------------- Read Dynamic String Table

    dynstr_offset = int(dynstr_section["offset"], 16)
    dynstr_size = dynstr_section["size"]

    file.seek(dynstr_offset)
    dynstr = file.read(dynstr_size)
    if len(dynstr) < dynstr_size:
        raise ValueError("Incomplete ELF dynamic string table")

    # -------------------- Read Dynamic Section

    dynamic_offset = int(dynamic_section["offset"], 16)
    dynamic_size = dynamic_section["size"]

    file.seek(dynamic_offset)
    dynamic_data = file.read(dynamic_size)
    if len(dynamic_data) < dynamic_size:
        raise ValueError("Incomplete ELF dynamic section")

        # -------------------- Determine Dynamic Entry Size

    if elf_class == 2:
        # ELF64:
        # d_tag -> 8 bytes
        # d_val -> 8 bytes
        # Total -> 16 bytes
        entry_size = 16
        value_format = "Q"

    elif elf_class == 1:
        # ELF32:
        # d_tag -> 4 bytes
        # d_val -> 4 bytes
        # Total -> 8 bytes
        entry_size = 8
        value_format = "I"

    else:
        raise ValueError("Unsupported ELF class")

    # -------------------- Parse Dynamic Entries
    dependencies = []

    for offset in range(0, dynamic_size, entry_size):
        if offset + entry_size > len(dynamic_data):
            break

        tag = struct.unpack_from(endian + value_format, dynamic_data, offset)[0]
        value = struct.unpack_from(endian + value_format, dynamic_data, offset + (8 if elf_class == 2 else 4))[0]

        # DT_NULL terminates the dynamic section.
        if tag == 0:
            break

        # DT_NEEDED = 1, value is an offset into .dynstr.
        if tag == 1:
            if value >= len(dynstr):
                continue

            end = dynstr.find(b"\x00", value)
            if end == -1:
                end = len(dynstr)

            library = dynstr[value:end].decode("utf-8", errors="replace")
            if library:
                dependencies.append(library)

    return dependencies

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

        dependencies = parse_elf_dynamic(
            file=file,
            sections=sections,
            elf_class=elf_class,
            endian=endian
        )

        symbols = parse_elf_symbols(
            file=file,
            sections=sections,
            elf_class=elf_class,
            endian=endian
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
            "sections": sections,
            "dependencies": dependencies,
            "symbols": symbols
        }