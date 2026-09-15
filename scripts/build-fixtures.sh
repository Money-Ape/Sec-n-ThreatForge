#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FIXTURE_DIR="$ROOT_DIR/corpus/test-threats/executables"
ELF_DIR="$ROOT_DIR/tests/fixtures/elf"
PE_DIR="$ROOT_DIR/tests/fixtures/pe"

mkdir -p "$FIXTURE_DIR"

echo "[*] Building ELF fixtures..."

gcc \
    -O0 \
    -o "$FIXTURE_DIR/elf-basic" \
    "$ELF_DIR/basic.c"

gcc \
    -shared \
    -fPIC \
    -o "$FIXTURE_DIR/libthreatforge_test.so" \
    "$ELF_DIR/testlib.c"

gcc \
    -O0 \
    -Wl,-rpath,'$ORIGIN' \
    -L"$FIXTURE_DIR" \
    -o "$FIXTURE_DIR/elf-dependency" \
    "$ELF_DIR/dependency.c" \
    -lthreatforge_test

echo "[+] ELF fixtures built."

echo
echo "[*] Checking MinGW compiler..."

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then

    echo "[*] Building PE fixtures..."

    x86_64-w64-mingw32-gcc \
        -O0 \
        -s \
        -mwindows \
        -o "$FIXTURE_DIR/pe-basic.exe" \
        "$PE_DIR/basic.c"

    x86_64-w64-mingw32-gcc \
        -O0 \
        -s \
        -o "$FIXTURE_DIR/pe-imports.exe" \
        "$PE_DIR/imports.c"

    echo "[+] PE fixtures built."

else

    echo "[!] MinGW compiler not found."
    echo "[!] ELF fixtures were built."
    echo "[!] PE fixtures were skipped."
    echo
    echo "Install a MinGW-w64 cross compiler and run this script again."

fi

echo
echo "[+] Fixture build complete."
echo
echo "Generated fixtures:"
find "$FIXTURE_DIR" -maxdepth 1 -type f -printf '  %f\n' | sort