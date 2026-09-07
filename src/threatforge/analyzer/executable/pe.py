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

def rva_to_file_offset(rva: int, sections: list[dict]) -> int | None:
    # Convert a PE RVA into a raw file offset.

    for section in sections:
        virtual_address = int(section["virtual_address"], 16)
        virtual_size = section["virtual_size"]
        raw_size = section["raw_size"]
        raw_pointer = int(section["raw_pointer"], 16)

        # The RVA must fall within the section's virtual range.
        section_size = max(virtual_size, raw_size)
        if not (virtual_address <= rva < virtual_address + section_size):
            continue

        raw_offset = (raw_pointer + (rva - virtual_address))

        # RVA may refer to zero-filled virtual space that doesn't exist in the file.
        if (rva - virtual_address >= raw_size):
            return None

        return raw_offset

    return None

def parse_pe_data_directories(optional_header: bytes, pe_format: str) -> dict:
    # Parse PE Optional Header data directories. Returns the important directory RVA/size pairs.
    if pe_format == "PE32":
        # PE32:
        # NumberOfRvaAndSizes -> offset 92
        # DataDirectory       -> offset 96
        number_offset = 92
        directory_offset = 96

    elif pe_format == "PE32+":
        # PE32+:
        # NumberOfRvaAndSizes -> offset 108
        # DataDirectory       -> offset 112
        number_offset = 108
        directory_offset = 112

    else:
        return {}

    if number_offset + 4 > len(optional_header):
        return {}

    number_of_directories = struct.unpack_from("<I", optional_header, number_offset)[0]

    directories = {}

    # Each IMAGE_DATA_DIRECTORY entry is 8 bytes:
    # VirtualAddress -> 4 bytes
    # Size           -> 4 bytes
    for index in range(min(number_of_directories, 16)):
        offset = (directory_offset + (index * 8))
        if offset + 8 > len(optional_header):
            break

        rva = struct.unpack_from("<I", optional_header, offset)[0]
        size = struct.unpack_from("<I", optional_header, offset + 4)[0]

        directories[index] = {
            "rva": rva,
            "size": size
        }

    return directories

def parse_pe_imports(file, sections: list[dict], data_directories: dict, pe_format: str) -> list[dict]:
    # Parse the PE Import Directory, The function performs static parsing only. It does not execute the PE file.

    IMPORT_DIRECTORY_INDEX = 1
    directory = data_directories.get(IMPORT_DIRECTORY_INDEX)
    if not directory:
        return []

    import_rva = directory["rva"]
    import_size = directory["size"]
    if import_rva == 0 or import_size == 0:
        return []

    import_offset = rva_to_file_offset(import_rva, sections)

    if import_offset is None:
        return []

    file.seek(import_offset)
    imports = []

    # IMAGE_IMPORT_DESCRIPTOR = 20 bytes
    descriptor_size = 20
    while True:
        descriptor = file.read(descriptor_size)
        if len(descriptor) < descriptor_size:
            break

        (original_first_thunk, timestamp, forwarder_chain, name_rva, first_thunk) = struct.unpack("<IIIII", descriptor)

        # A completely zeroed descriptor marks the end of the Import Directory.
        if (original_first_thunk == 0 and timestamp == 0 and forwarder_chain == 0 and name_rva == 0 and first_thunk == 0):
            break

        # -------------------- DLL Name
        name_offset = rva_to_file_offset(name_rva, sections)
        if name_offset is None:
            dll_name = "<invalid>"

        else:
            file.seek(name_offset)
            name_data = bytearray()
            while True:
                byte = file.read(1)
                if not byte or byte == b"\x00":
                    break

                name_data.extend(byte)

            dll_name = name_data.decode("ascii", errors="replace")

        # -------------------- Import Lookup Table
        thunk_rva = (
            original_first_thunk
            if original_first_thunk != 0
            else first_thunk
        )

        thunk_offset = rva_to_file_offset(thunk_rva, sections)
        if thunk_offset is None:
            continue

        if pe_format == "PE32":
            thunk_size = 4
            ordinal_flag = 0x80000000

        else:
            thunk_size = 8
            ordinal_flag = 0x8000000000000000

        functions = []
        thunk_index = 0
        while True:
            file.seek(thunk_offset + (thunk_index * thunk_size))
            thunk_data = file.read(thunk_size)
            if len(thunk_data) < thunk_size:
                break

            thunk_index += 1

            if pe_format == "PE32":
                thunk_value = struct.unpack("<I", thunk_data)[0]

            else:
                thunk_value = struct.unpack("<Q", thunk_data)[0]

            # Zero terminates the thunk table.
            if thunk_value == 0:
                break

            # -------------------- Import By Ordinal
            if thunk_value & ordinal_flag:
                ordinal = (thunk_value & 0xFFFF)

                functions.append({
                    "name": None,
                    "ordinal": ordinal,
                    "import_type": "ORDINAL",
                })
                continue

            # -------------------- Import By Name
            hint_name_rva = (
                thunk_value &
                0x7FFFFFFF
                if pe_format == "PE32"
                else thunk_value &
                0x7FFFFFFFFFFFFFFF
            )

            hint_name_offset = rva_to_file_offset(hint_name_rva, sections)
            if hint_name_offset is None:
                continue

            file.seek(hint_name_offset)

            # IMAGE_IMPORT_BY_NAME:
            # Hint   -> 2 bytes
            # Name   -> null-terminated string
            hint_data = file.read(2)
            if len(hint_data) < 2:
                break

            hint = struct.unpack("<H", hint_data)[0]
            name_data = bytearray()
            while True:
                byte = file.read(1)
                if not byte or byte == b"\x00":
                    break

                name_data.extend(byte)

            function_name = name_data.decode("ascii", errors="replace")
            functions.append({
                "name": function_name,
                "hint": hint,
                "ordinal": None,
                "import_type": "NAME",
            })

        imports.append({
            "dll": dll_name,
            "functions": functions,
        })

    return imports

def parse_pe_exports(file, sections: list[dict], data_directories: dict) -> list[dict]:
    # Parse the PE Export Directory, The function performs static parsing only. It does not execute the PE file.

    EXPORT_DIRECTORY_INDEX = 0
    directory = data_directories.get(EXPORT_DIRECTORY_INDEX)
    if not directory:
        return []

    export_rva = directory["rva"]
    export_size = directory["size"]
    if export_rva == 0 or export_size == 0:
        return []

    export_offset = rva_to_file_offset(export_rva, sections)

    if export_offset is None:
        return []

    file.seek(export_offset)

    # IMAGE_EXPORT_DIRECTORY = 40 bytes
    export_data = file.read(40)
    if len(export_data) < 40:
        raise ValueError("Incomplete PE export directory")

    (characteristics, timestamp, major_version, minor_version, name_rva, ordinal_base, address_table_entries, number_of_name_pointers, export_address_table_rva, name_pointer_rva, ordinal_table_rva) = struct.unpack("<IIHHIIIIIII", export_data)

    # -------------------- Read Export Names
    name_pointer_offset = rva_to_file_offset(name_pointer_rva, sections)
    ordinal_table_offset = rva_to_file_offset(ordinal_table_rva,sections)
    export_address_offset = rva_to_file_offset(export_address_table_rva, sections)
    if (name_pointer_offset is None or ordinal_table_offset is None or export_address_offset is None):
        return []

    exports = []
    for index in range(number_of_name_pointers):

        # -------------------- Function Name RVA
        file.seek(name_pointer_offset + (index * 4))
        name_rva_data = file.read(4)
        if len(name_rva_data) < 4:
            break

        function_name_rva = struct.unpack("<I", name_rva_data)[0]
        name_offset = rva_to_file_offset(function_name_rva, sections)
        if name_offset is None:
            function_name = "<invalid>"

        else:
            file.seek(name_offset)
            name_data = bytearray()
            while True:
                byte = file.read(1)
                if not byte or byte == b"\x00":
                    break

                name_data.extend(byte)

            function_name = name_data.decode("ascii", errors="replace")

        # -------------------- Ordinal Index
        file.seek(ordinal_table_offset + (index * 2))
        ordinal_data = file.read(2)
        if len(ordinal_data) < 2:
            break

        ordinal_index = struct.unpack("<H", ordinal_data)[0]
        ordinal = (ordinal_base + ordinal_index)

        # -------------------- Function RVA
        if ordinal_index >= address_table_entries:
            continue

        file.seek(export_address_offset + (ordinal_index * 4))
        function_rva_data = file.read(4)

        if len(function_rva_data) < 4:
            break

        function_rva = struct.unpack("<I", function_rva_data)[0]

        exports.append({
            "name": function_name,
            "ordinal": ordinal,
            "rva": hex(function_rva),
        })

    return exports

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

        data_directories = parse_pe_data_directories(optional_header, pe_format)        # -------------------- Data Directories
        imports = parse_pe_imports(file=file, sections=sections, data_directories=data_directories, pe_format=pe_format)        # -------------------- Imports
        exports = parse_pe_exports(file=file, sections=sections, data_directories=data_directories)     # -------------------- Exports

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
            "imports": imports,
            "exports": exports,
        }