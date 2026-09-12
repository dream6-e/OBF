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
#
# 2026-09-11 K18 construction window (user instruction: 完成前关闭体积门): the
# default is now `off`, so the 120,000 B pin is reported but not enforced while
# failure-path diversification, PRNG-family work and the scatter batch land. The
# pin is NOT deleted: 120000 stays as CAP_PIN, and a runaway ceiling at 1.5x the
# pin still fails the run so an explosion cannot hide inside the window. Restore
# by setting the default back to ${OBF_BENCH_SCRIPT_CAP:-$CAP_PIN}.
CAP_PIN=120000
CAP_RUNAWAY=180000
SCRIPT_CAP=${OBF_BENCH_SCRIPT_CAP:-off}

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
    local size cap vm_ms native_ms report
    size=$(wc -c <"$2")
    cap=$5
    if [[ $cap == off ]]; then
        # Construction window: the pin is reported, never enforced. A runaway
        # ceiling still aborts, so a size explosion cannot hide in the window.
        if (( size > CAP_RUNAWAY )); then
            echo "[bench] error: $1 golden script is ${size}B, over the ${CAP_RUNAWAY}B runaway ceiling (pin ${CAP_PIN}B, gate suspended)" >&2
            exit 1
        fi
        echo "[bench] WARN $1 whole-script gate suspended (pin ${CAP_PIN}B, measured ${size}B)"
        report="${size}/${CAP_PIN}B(gate off)"
    else
        if [[ $size -gt $cap ]]; then
            echo "[bench] error: $1 golden script is ${size}B, over the independent ${cap}B budget" >&2
            exit 1
        fi
        report="${size}/${cap}B"
    fi
    vm_ms=$(best_ms "$4" "$2")
    native_ms=$(best_ms "$4" "$3")
    if [[ $vm_ms -gt $VM_BOUND_MS ]]; then
        echo "[bench] error: $1 VM best run ${vm_ms}ms exceeds the ${VM_BOUND_MS}ms bound" >&2
        exit 1
    fi
    printf '[bench] %s script-size=%s vm-best=%sms native-best=%sms ratio=%.1fx\n' \
        "$1" "$report" "$vm_ms" "$native_ms" \
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
