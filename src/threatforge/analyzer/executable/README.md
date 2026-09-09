# Executable Analysis (PE / ELF)

This document describes how Sec-n-ThreatForge's executable analyzer works: format detection, and the PE and ELF parsers under `src/threatforge/analyzer/executable/`.

Everything described here is **static, read-only parsing**. The analyzer opens the target file in binary mode, seeks around it to read headers/tables, and never executes, loads, maps, or otherwise runs the analyzed binary.

```text
src/threatforge/analyzer/executable/
├── detector.py   # Format detection (PE / ELF / UNKNOWN)
├── pe.py         # PE (Windows) parser
├── elf.py        # ELF (Linux) parser
└── __init__.py
```

---

## 1. Format Detection — `detector.py`

`detect_executable_format(path)` reads the first 64 bytes of the file and checks the magic bytes:

| Magic bytes        | Format    |
| ------------------- | --------- |
| `7F 45 4C 46` (`\x7fELF`) | `"ELF"`   |
| `4D 5A` (`MZ`)      | `"PE"`    |
| anything else       | `"UNKNOWN"` |

This is a cheap pre-check used by `main.py` to decide whether to call `analyze_pe()` or `analyze_elf()`. It does not validate the rest of the file structure — that happens inside each format-specific parser, which will raise a `ValueError` if the file is malformed or truncated.

---

## 2. PE Analysis — `pe.py`

`analyze_pe(path)` performs a full static walk of a Windows Portable Executable file.

### 2.1 Parsing order

```text
DOS Header (64 bytes)
   │  validate "MZ", read e_lfanew (offset 0x3C)
   ↓
PE Signature ("PE\0\0") at e_lfanew
   ↓
COFF File Header (20 bytes)
   │  machine, number of sections, timestamp,
   │  optional header size, characteristics
   ↓
Optional Header (variable size)
   │  PE32 vs PE32+ magic, entry point,
   │  image base, subsystem, data directories
   ↓
Section Headers (40 bytes each)
   ↓
Data Directories → Import Table → Export Table
```

### 2.2 Key steps

* **DOS header** — the first 64 bytes must start with `MZ`. `e_lfanew` (a 4-byte little-endian value at offset `0x3C`) points to where the real PE header begins.
* **PE signature** — 4 bytes (`PE\x00\x00`) at `e_lfanew`. If this doesn't match, the file is rejected as an invalid PE.
* **COFF header** — 20 bytes containing the machine type, section count, timestamp, symbol table info, and the size of the Optional Header that follows. `machine_name()` maps the raw machine ID (e.g. `0x8664`) to a readable architecture (`x86-64`, `x86`, `ARM`, `ARM64`).
* **Optional header** — its first 2 bytes are a magic value that tells us the executable's bitness:
  * `0x10B` → **PE32** (32-bit)
  * `0x20B` → **PE32+** (64-bit)

  From here the parser reads `AddressOfEntryPoint`, `ImageBase` (4 or 8 bytes depending on PE32 vs PE32+), and `Subsystem` (mapped to a name by `subsystem_name()`, e.g. `Windows GUI`, `Windows Console`, `EFI Application`).
* **Section headers** (`parse_pe_sections`) — 40 bytes per section, giving each section's name, virtual size/address, raw size/pointer on disk, and `Characteristics`. `section_permissions()` decodes the characteristics bitmask into an `X` / `R` / `W` permission string.
* **RVA → file offset translation** (`rva_to_file_offset`) — most PE data (imports, exports) is addressed by Relative Virtual Address (RVA), not raw file offset. This helper walks the section table to find which section contains a given RVA and maps it back to where those bytes actually live on disk. It correctly handles RVAs that fall in the zero-filled tail of a section (present in memory, absent from the file) by returning `None`.
* **Data directories** (`parse_pe_data_directories`) — the Optional Header ends with up to 16 `IMAGE_DATA_DIRECTORY` entries (RVA + size pairs). The offsets differ between PE32 (`96`) and PE32+ (`112`). Index `0` is the Export table, index `1` is the Import table — these are the two directories Sec-n-ThreatForge currently parses.
* **Imports** (`parse_pe_imports`) — walks the `IMAGE_IMPORT_DESCRIPTOR` array (20 bytes each, zero-filled entry marks the end). For each descriptor it resolves the DLL name and then walks its Import Lookup Table, resolving each thunk as either:
  * an **ordinal import** (high bit of the thunk value set), or
  * a **named import** (thunk points to an `IMAGE_IMPORT_BY_NAME` hint + null-terminated string).
* **Exports** (`parse_pe_exports`) — reads the single `IMAGE_EXPORT_DIRECTORY` (40 bytes), then walks the name-pointer table, ordinal table, and export address table in lockstep to produce `{name, ordinal, rva}` entries.

### 2.3 Fields returned by `analyze_pe()`

```json
{
  "format": "PE",
  "architecture": "x86-64",
  "pe_format": "PE32+",
  "section_count": 6,
  "sections": [ { "name": ".text", "virtual_size": 0, "virtual_address": "0x1000",
                  "raw_size": 0, "raw_pointer": "0x400", "characteristics": "0x60000020",
                  "permissions": "XR" } ],
  "timestamp": 0,
  "entry_point": "0x1000",
  "image_base": "0x140000000",
  "subsystem": "Windows Console",
  "characteristics": "0x22",
  "imports": [ { "dll": "KERNEL32.dll",
                 "functions": [ { "name": "ExitProcess", "hint": 0,
                                  "ordinal": null, "import_type": "NAME" } ] } ],
  "exports": [ { "name": "MyExportedFunc", "ordinal": 1, "rva": "0x1050" } ]
}
```

### 2.4 Known limitations

* Only the Import and Export directories are parsed; other directories (resources, relocations, debug info, TLS, digital signature, etc.) are not currently read.
* No checksum, digital signature, or Authenticode verification is performed.
* Packed or heavily obfuscated PE files may have malformed or intentionally misleading directory tables that cause imports/exports to come back empty — this is a parsing limitation, not a detection result.

---

## 3. ELF Analysis — `elf.py`

`analyze_elf(path)` performs a static walk of a Linux ELF binary, supporting both **32-bit and 64-bit** classes and **little- and big-endian** byte orders.

### 3.1 Parsing order

```text
ELF Identification (e_ident, first 16 bytes)
   │  magic \x7fELF, class (32/64), data encoding (endianness)
   ↓
ELF Header (rest of the fixed header)
   │  e_type, e_machine, e_entry, section header table info
   ↓
Section Headers (via parse_elf_sections)
   │  resolve names using the section header string table (shstrtab)
   ↓
.dynamic section  → parse_elf_dynamic  → DT_NEEDED dependencies
.dynsym section   → parse_elf_symbols  → dynamic symbol table
```

### 3.2 Key steps

* **Identification bytes** — byte `4` is the ELF class (`1` = ELF32, `2` = ELF64) and byte `5` is the data encoding (`1` = little-endian, `2` = big-endian). These two values determine the `struct` format string (`endian`) and field widths used for every subsequent read.
* **Header fields** — depending on class, the section header table offset/size/count and the string-table index live at different fixed offsets (e.g. `e_shoff` at byte 40 for ELF64 vs byte 32 for ELF32). `e_type` and `e_machine` are decoded by `elf_type_name()` (Relocatable / Executable / Shared Object / Core) and `machine_name()` (x86, x86-64, ARM, AArch64, MIPS, RISC-V).
* **Entry point** — a 4-byte (ELF32) or 8-byte (ELF64) field, reported as a hex string.
* **Sections** (`parse_elf_sections`) — reads every section header struct (fixed size per class), decoding `sh_type` via `section_type_name()` and `sh_flags` via `section_flags_name()` (`W`/`A`/`X` for write/alloc/execute). Section *names* aren't stored inline — each header only has an offset into the section header string table (`shstrtab`), identified by `e_shstrndx`. The parser reads that string table once all headers are known, then resolves every section's name from it.
* **Dynamic dependencies** (`parse_elf_dynamic`) — locates the `.dynamic` and `.dynstr` sections by name, then walks the array of `Elf_Dyn` entries (`{tag, value}` pairs, 8 or 16 bytes depending on class). Entries with `d_tag == DT_NEEDED` (`1`) have `d_val` as an offset into `.dynstr`, giving the required shared library names (e.g. `libc.so.6`). Parsing stops at `DT_NULL` (`tag == 0`), which terminates the table.
* **Dynamic symbols** (`parse_elf_symbols`) — locates `.dynsym` and `.dynstr`, then walks fixed-size `Elf_Sym` entries (16 bytes for ELF32, 24 bytes for ELF64). For each symbol it decodes:
  * `st_info` into a **binding** (`LOCAL`, `GLOBAL`, `WEAK`, `GNU_UNIQUE` via `symbol_binding_name()`) and a **type** (`NOTYPE`, `OBJECT`, `FUNC`, `SECTION`, `FILE`, `COMMON`, `TLS`, `GNU_IFUNC` via `symbol_type_name()`),
  * `st_name` resolved against `.dynstr`,
  * `st_value` (reported as hex) and `st_size`.

### 3.3 Fields returned by `analyze_elf()`

```json
{
  "format": "ELF",
  "class": "ELF64",
  "endianness": "Little Endian",
  "type": "Shared Object",
  "architecture": "x86-64",
  "entry_point": "0x1060",
  "section_count": 27,
  "sections": [ { "name": ".text", "type": "PROGBITS", "flags": "AX",
                  "address": "0x1060", "offset": "0x1060", "size": 4096 } ],
  "dependencies": [ "libc.so.6" ],
  "symbols": [ { "name": "printf", "value": "0x0", "size": 0,
                 "section_index": 0, "binding": "GLOBAL", "type": "FUNC",
                 "info": 18, "other": 0 } ]
}
```

### 3.4 Known limitations

* Only `.dynsym`/`.dynstr` (dynamic symbols) are parsed — the full static symbol table (`.symtab`/`.strtab`), if present and not stripped, is not currently read.
* Only `DT_NEEDED` entries are extracted from `.dynamic`; other dynamic tags (`DT_RPATH`, `DT_RUNPATH`, `DT_FLAGS`, etc.) are ignored.
* Program headers (`e_phoff` / segments) are not parsed — only section headers are used, which means stripped binaries with no section headers will yield an incomplete or empty picture even though the binary is still loadable by the OS.
* No relocation, GOT/PLT, or symbol-versioning (`GNU_VERSYM`/`GNU_VERNEED`) parsing yet, even though the relevant section-type constants are already recognized by `section_type_name()`.

---

## 4. Integration with Detection and Risk Scoring

The executable analyzer provides structural evidence to the detection engine.

For PE files, information such as:

* section permissions,
* imported DLLs,
* imported functions,
* exported functions,
* executable structure

can be consumed by detection rules.

The detection engine treats these characteristics as static evidence rather than proof of malicious behavior.

For example, importing `VirtualAlloc` or `VirtualProtect` alone does not indicate malware. Multiple related indicators may receive additional contextual risk contribution when they appear together.

For ELF files, the analyzer currently exposes sections, dynamic dependencies, and dynamic symbols as static evidence. These fields are available to downstream detection logic even where no current heuristic is applied.

The executable analyzer itself remains read-only and does not execute or load the analyzed binary.

---

## 5. Reporting

Both `analyze_pe()` and `analyze_elf()` return a single `dict`, stored as `AnalysisResult.executable` (see `core/result.py`).

The terminal reporter (`reporting/terminal.py`) renders this into:

* a summary row block (format, architecture, entry point, plus PE-only fields like PE format / image base / subsystem / timestamp / characteristics),
* an **Executable Sections** table,
* a **PE Imports** listing (grouped by DLL),
* a **PE Exports** table,
* a **Dependencies** list (ELF `DT_NEEDED` entries),
* a **Dynamic Symbols** table (ELF `.dynsym`),
* detection findings,
* risk score, classification, base score, and context bonus,
* contextual risk factors when applicable.

The JSON reporter (`reporting/json_report.py`) serializes the same `AnalysisResult` (including the full `executable` dict) via `dataclasses.asdict()`, so every field documented above is also available in JSON reports for downstream tooling.

---

## 6. Adding the results to a report


Both `analyze_pe()` and `analyze_elf()` return a single `dict`, stored as `AnalysisResult.executable` (see `core/result.py`). The terminal reporter (`reporting/terminal.py`) renders this into:

* a summary row block (format, architecture, entry point, plus PE-only fields like PE format / image base / subsystem / timestamp / characteristics),
* an **Executable Sections** table (shared rendering for both PE and ELF, since both expose `name` / `type` / `size` / `flags`-or-`permissions`),
* a **PE Imports** listing (grouped by DLL),
* a **PE Exports** table,
* a **Dependencies** list (ELF `DT_NEEDED` entries),
* a **Dynamic Symbols** table (ELF `.dynsym`).

The JSON reporter (`reporting/json_report.py`) serializes the same `AnalysisResult` (including the full `executable` dict) via `dataclasses.asdict()`, so every field documented above is also available in JSON reports for downstream tooling.