#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Builds the fuzz preset and runs every libFuzzer target for a limited time.
# Usage: tools/run_fuzzers.sh [seconds-per-target]   (default 60)
set -euo pipefail

seconds="${1:-60}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${root}/build/fuzz/libs/wifi-analyze/fuzz"
corpus_src="${root}/libs/wifi-analyze/fuzz/corpus"
work="${root}/build/fuzz/corpus"

cmake --preset fuzz -S "${root}" >/dev/null
cmake --build --preset fuzz

for target in split_elements parse_hex format_message; do
    # Work corpus lives in the build tree; the checked-in seeds stay untouched.
    mkdir -p "${work}/${target}"
    echo "== fuzz_${target} (${seconds}s)"
    (cd "${work}" && "${build}/fuzz_${target}" -max_total_time="${seconds}" -print_final_stats=1 \
        "${work}/${target}" "${corpus_src}/${target}")
done
