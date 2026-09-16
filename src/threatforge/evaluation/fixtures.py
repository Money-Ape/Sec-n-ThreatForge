from pathlib import Path
import struct

def create_elf_fixture(output: str | Path, variant: str = "basic") -> Path:
    # Create a small deterministic ELF64 fixture for static analysis tests.

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if variant == "basic":
        data = _build_basic_elf()

    elif variant == "dependency":
        data = _build_dependency_elf()

    else:
        raise ValueError(f"Unknown ELF fixture variant: {variant}")

    output_path.write_bytes(data)
    return output_path

def _build_basic_elf() -> bytes:
    """ Build a minimal ELF64 file containing:
        - ELF64 header
        - one section header table
        - .shstrtab
        - .text
    """

    header = bytearray(64)      # ELF magic + 64-bit + little-endian
    header[0:4] = b"\x7fELF"
    header[4] = 2          # ELFCLASS64
    header[5] = 1          # Little endian
    header[6] = 1          # ELF version

    struct.pack_into("<H", header, 16, 2)       # ET_EXEC
    struct.pack_into("<H", header, 18, 0x3E)        # x86-64
    struct.pack_into("<I", header, 20, 1)       # ELF version
    struct.pack_into("<Q", header, 24, 0x400000)        # Entry point
    struct.pack_into("<Q", header, 32, 0)       # Program header offset

    # Section header offset
    section_offset = 0x100
    struct.pack_into("<Q", header, 40, section_offset)
    struct.pack_into("<H", header, 52, 64)      # ELF header size

    # Program header size/count
    struct.pack_into("<H", header, 54, 0)
    struct.pack_into("<H", header, 56, 0)
    struct.pack_into("<H", header, 58, 64)      # Section header size

    # Sections:
    # 0 = NULL
    # 1 = .text
    # 2 = .shstrtab

    struct.pack_into("<H", header, 60, 3)
    struct.pack_into("<H", header, 62, 2)       # .shstrtab index

    text_offset = 0x80
    text_data = b"THREATFORGE_ELF_TEST\x00"

    shstrtab_offset = 0xA0
    shstrtab = b"\x00.text\x00.shstrtab\x00"

    data = bytearray(
        max(
            section_offset + (3 * 64),
            shstrtab_offset + len(shstrtab),
            text_offset + len(text_data),
        )
    )

    data[0:64] = header
    data[text_offset:text_offset + len(text_data)] = text_data
    data[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab

    # Section 1: .text
    section = section_offset + 64

    struct.pack_into("<I", data, section + 0, 1)
    struct.pack_into("<I", data, section + 4, 1)       # PROGBITS
    struct.pack_into("<Q", data, section + 8, 0x6)     # ALLOC + EXEC
    struct.pack_into("<Q", data, section + 16, 0x400000)
    struct.pack_into("<Q", data, section + 24, text_offset)
    struct.pack_into("<Q", data, section + 32, len(text_data))
    struct.pack_into("<Q", data, section + 48, 1)

    # Section 2: .shstrtab
    section = section_offset + (2 * 64)

    struct.pack_into("<I", data, section + 0, 11)
    struct.pack_into("<I", data, section + 4, 3)       # STRTAB
    struct.pack_into("<Q", data, section + 24, shstrtab_offset)
    struct.pack_into("<Q", data, section + 32, len(shstrtab))
    struct.pack_into("<Q", data, section + 48, 1)

    return bytes(data)

def _build_dependency_elf() -> bytes:
    # Create a deterministic ELF fixture containing a textual

    data = _build_basic_elf()
    marker = (
        b"\x00"
        b"libthreatforge-test.so"
        b"\x00"
    )
    return data + marker