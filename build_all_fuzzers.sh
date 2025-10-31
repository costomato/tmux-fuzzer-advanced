#!/bin/bash
set -e

echo "[*] Building tmux with AFL++ LTO instrumentation..."

./autogen.sh

export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LAF_ALL=1
./configure

make clean
make -j$(nproc)

echo "[*] Building persistent fuzzer with proper AFL support..."
$CC -o input-fuzzer-persistent-fixed fuzz/input-fuzzer-persistent-fixed.c \
    -I. *.o compat/*.o \
    -levent -lncurses -lutil -lm -lresolv

echo "[*] Fuzzer built!"
ls -lh input-fuzzer-persistent-fixed
