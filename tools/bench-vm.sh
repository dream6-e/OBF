#!/usr/bin/env bash
# M7 performance benchmark and size budget for the default VM backend.
#
# Reports per-target VM/native run times (best of N, milliseconds) for the
# checked-in goldens and enforces two hard gates:
#   1. size budget  -- golden bytes <= documented cap (raise deliberately)
#   2. smoke timing -- a single VM run must stay under the catastrophe bound
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNS=${OBF_BENCH_RUNS:-15}
VM_BOUND_MS=${OBF_BENCH_VM_BOUND_MS:-1500}

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

check() { # <name> <vm> <src> <runner> <cap>
    local size cap vm_ms native_ms
    size=$(wc -c <"$2")
    cap=$5
    if [[ $size -gt $cap ]]; then
        echo "[bench] error: $1 golden is ${size}B, over the ${cap}B budget" >&2
        exit 1
    fi
    vm_ms=$(best_ms "$4" "$2")
    native_ms=$(best_ms "$4" "$3")
    if [[ $vm_ms -gt $VM_BOUND_MS ]]; then
        echo "[bench] error: $1 VM best run ${vm_ms}ms exceeds the ${VM_BOUND_MS}ms bound" >&2
        exit 1
    fi
    printf '[bench] %s size=%s/%sB vm-best=%sms native-best=%sms ratio=%.1fx\n' \
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

check lua51 "$LUA51_VM" "$LUA51_SRC" "$LUA51_BIN" 24000
check luau "$LUAU_VM" "$LUAU_SRC" "$LUAU_BIN" 26000
echo '[bench] PASS'
