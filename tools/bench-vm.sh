#!/usr/bin/env bash
# ISA11 runtime-witness/control + global-segment/LZW VM benchmark.
#
# Reports per-target VM/native run times (best of N, milliseconds) and enforces
# two whole-script regression gates that are independent of compression:
#   1. script budget -- golden bytes <= documented cap (raise deliberately)
#   2. smoke timing  -- a single VM run stays under the catastrophe bound
#
# The compression contract is tested in Rust at the correct boundary: the
# complete LZW frame (including its 16-byte header) must be smaller than the
# uncompressed private semantic bytecode. Generated Lua is never compared with
# an older ISA to decide whether compression succeeded.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNS=${OBF_BENCH_RUNS:-15}
VM_BOUND_MS=${OBF_BENCH_VM_BOUND_MS:-1500}
# K0/K10: whole-script size budget gate, re-pinned after the emit.rs stage
# split. Measured worst case over 8 seeds: Lua51 100,049 B, Luau 109,825 B
# (fixed goldens 98,889/109,049 B), so this keeps ~2% of growth headroom and
# still trips on a real size regression. OBF_BENCH_SCRIPT_CAP=off suspends this
# gate only, for a construction window; the strict LZW-frame contract never is.
SCRIPT_CAP=${OBF_BENCH_SCRIPT_CAP:-112000}

LUA51_VM="$ROOT/vm_lua51.out.lua"
LUAU_VM="$ROOT/vm_luau.out.lua"
LUA51_SRC="$ROOT/tests/fixtures/vm_lua51.lua"
LUAU_SRC="$ROOT/tests/fixtures/vm_luau.lua"
LUA51_BIN="$ROOT/toolchains/bin/lua5.1"
LUAU_BIN="$ROOT/toolchains/bin/luau"

best_ms() { # <runner> <script>
    local best=''
    for _ in $(seq 1 "$RUNS"); do
        local start end elapsed
        start=$(date +%s%N)
        "$1" "$2" >/dev/null
        end=$(date +%s%N)
        elapsed=$(( (end - start) / 1000000 ))
        if [[ -z $best || $elapsed -lt $best ]]; then best=$elapsed; fi
    done
    printf '%s' "$best"
}

check() { # <name> <vm> <src> <runner> <script-cap>
    local size cap vm_ms native_ms
    size=$(wc -c <"$2")
    cap=$5
    if [[ $cap != off && $size -gt $cap ]]; then
        echo "[bench] error: $1 golden script is ${size}B, over the independent ${cap}B budget" >&2
        exit 1
    fi
    vm_ms=$(best_ms "$4" "$2")
    native_ms=$(best_ms "$4" "$3")
    if [[ $vm_ms -gt $VM_BOUND_MS ]]; then
        echo "[bench] error: $1 VM best run ${vm_ms}ms exceeds the ${VM_BOUND_MS}ms bound" >&2
        exit 1
    fi
    printf '[bench] %s script-size=%s/%sB vm-best=%sms native-best=%sms ratio=%.1fx\n' \
        "$1" "$size" "$cap" "$vm_ms" "$native_ms" \
        "$(awk -v a="$vm_ms" -v b="$native_ms" 'BEGIN{if(b==0)b=1;printf "%.1f", a/b}')"
}

[[ -x $LUA51_BIN && -x $LUAU_BIN ]] || {
    echo 'error: reference runners missing (run tools/build-reference-tools.sh)' >&2
    exit 1
}
[[ -f $LUA51_VM && -f $LUAU_VM ]] || {
    echo 'error: goldens missing (obf virtualize or run tools/test-matrix.sh)' >&2
    exit 1
}

check lua51 "$LUA51_VM" "$LUA51_SRC" "$LUA51_BIN" "$SCRIPT_CAP"
check luau "$LUAU_VM" "$LUAU_SRC" "$LUAU_BIN" "$SCRIPT_CAP"
echo '[bench] PASS'
