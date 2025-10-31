#!/bin/bash
set -e

echo "[*] Building tmux with AFL++ instrumentation..."

# Generate configure script
./autogen.sh

# Configure with AFL++ compiler
export CC=afl-clang-fast
export CXX=afl-clang-fast++
./configure

# Build tmux
make clean
make -j$(nproc)

# Build the fuzzer
echo "[*] Building input-fuzzer..."
$CC -o input-fuzzer fuzz/input-fuzzer.c \
    -I. -I/usr/include \
    *.o compat/*.o \
    -levent -lncurses -lutil -lm -lresolv

echo "[*] Creating input/output directories..."
mkdir -p fuzz_input fuzz_output

# Create a basic seed input (simple escape sequence)
echo -ne '\x1b[H' > fuzz_input/seed1
echo -ne '\x1b[2J' > fuzz_input/seed2
echo -ne '\x1b[1;32m' > fuzz_input/seed3

echo "[*] Starting AFL++ fuzzer..."
echo "    Input dir: fuzz_input/"
echo "    Output dir: fuzz_output/"
echo ""
echo "Press Ctrl+C to stop fuzzing"
echo ""

afl-fuzz -i fuzz_input -o fuzz_output -x fuzz/input-fuzzer.dict -- ./input-fuzzer
