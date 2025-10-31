#!/bin/bash

echo "[*] Generating seeds..."
./generate_seeds.sh

echo "[*] Starting AFL++ with comprehensive corpus..."

afl-fuzz -i fuzz_input/corpus -o fuzz_output -M fuzzer1 \
    -x fuzz/input-fuzzer-persistent.dict \
    -- ./input-fuzzer-persistent-fixed

