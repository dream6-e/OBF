#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if [[ -n "${OBF_CARGO:-}" ]]; then
    CARGO=$OBF_CARGO
elif [[ -x "$ROOT/.toolchains/rust-1.88.0/bin/cargo" ]]; then
    CARGO="$ROOT/.toolchains/rust-1.88.0/bin/cargo"
elif command -v cargo >/dev/null; then
    CARGO=$(command -v cargo)
else
    echo 'error: Cargo was not found; run tools/bootstrap-rust.sh first' >&2
    exit 1
fi
# @rustbin installs cargo and rustc side by side; ensure cargo can resolve its
# compiler even when OBF_CARGO is an absolute path outside the current PATH.
export PATH="$(dirname "$CARGO"):$PATH"

LUA="$ROOT/toolchains/bin/lua5.1"
LUAC="$ROOT/toolchains/bin/luac5.1"
LUAU="$ROOT/toolchains/bin/luau"
LUAUC="$ROOT/toolchains/bin/luau-compile"
for tool in "$LUA" "$LUAC" "$LUAU" "$LUAUC"; do
    [[ -x "$tool" ]] || {
        echo "error: missing reference tool $tool; run tools/build-reference-tools.sh" >&2
        exit 1
    }
done

printf '[matrix] Rust compiler: '
"$(dirname "$CARGO")/rustc" --version
printf '[matrix] Cargo: '
"$CARGO" --version
"$CARGO" fmt --all -- --check
"$CARGO" test --all-targets
"$CARGO" build
"$CARGO" build --release
OBF="$ROOT/target/debug/obf"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

run_target() {
    local target=$1 source=$2 output=$3
    "$OBF" check --target "$target" "$source"
    "$OBF" minify --target "$target" --output "$output" "$source"
    if [[ $(wc -l <"$output") -ne 0 ]]; then
        echo "error: $target output contains a physical newline" >&2
        exit 1
    fi
}

printf '%s\n' '[matrix] Lua 5.1: parse, minify, compile, execute, bytecode inspect'
run_target lua51 tests/fixtures/lua51.lua "$tmp/lua51.min.lua"
"$LUAC" -p tests/fixtures/lua51.lua
"$LUAC" -p "$tmp/lua51.min.lua"
"$LUA" tests/fixtures/lua51.lua >"$tmp/lua51.original.out"
"$LUA" "$tmp/lua51.min.lua" >"$tmp/lua51.minified.out"
cmp "$tmp/lua51.original.out" "$tmp/lua51.minified.out"
"$LUAC" -o "$tmp/lua51.luac" tests/fixtures/lua51.lua
"$OBF" inspect-bytecode --target lua51 "$tmp/lua51.luac" >"$tmp/lua51.inspect"
head -c -1 "$tmp/lua51.luac" >"$tmp/lua51.truncated"
if "$OBF" inspect-bytecode --target lua51 "$tmp/lua51.truncated" >/dev/null 2>&1; then
    echo 'error: Lua 5.1 parser accepted truncated bytecode' >&2
    exit 1
fi

printf '%s\n' '[matrix] Luau: parse, minify, compile, execute, bytecode inspect'
run_target luau tests/fixtures/luau.lua "$tmp/luau.min.lua"
"$LUAUC" tests/fixtures/luau.lua >/dev/null
"$LUAUC" "$tmp/luau.min.lua" >/dev/null
"$LUAU" tests/fixtures/luau.lua >"$tmp/luau.original.out"
"$LUAU" "$tmp/luau.min.lua" >"$tmp/luau.minified.out"
cmp "$tmp/luau.original.out" "$tmp/luau.minified.out"
"$LUAUC" --binary tests/fixtures/luau.lua >"$tmp/luau.luauc"
"$OBF" inspect-bytecode --target luau "$tmp/luau.luauc" >"$tmp/luau.inspect"
head -c -1 "$tmp/luau.luauc" >"$tmp/luau.truncated"
if "$OBF" inspect-bytecode --target luau "$tmp/luau.truncated" >/dev/null 2>&1; then
    echo 'error: Luau parser accepted truncated bytecode' >&2
    exit 1
fi

# Probe the custom runner environment required by the project: loadstring,
# filesystem require, and the sandbox are all installed by setupState.
cat >"$tmp/module.luau" <<'LUAU'
return 17
LUAU
cat >"$tmp/environment.luau" <<'LUAU'
local compiled = assert(loadstring("return 40 + 2"))
assert(compiled() == 42)
assert(require("./module") == 17)
local mutable = pcall(function()
    math.abs = nil
end)
assert(not mutable)
print("runner-environment:ok")
LUAU
"$LUAU" "$tmp/environment.luau" >"$tmp/environment.out"
grep -qx 'runner-environment:ok' "$tmp/environment.out"

printf '%s\n' '[matrix] Lua 5.1 VM: private lowering, deterministic seed, compile, execute'
"$LUA" tests/fixtures/vm_lua51.lua >"$tmp/vm51.original.out"
"$OBF" virtualize --target lua51 --seed 7001 -o "$tmp/vm51.lua" tests/fixtures/vm_lua51.lua
"$OBF" virtualize --target lua51 --seed 7001 -o "$tmp/vm51.same.lua" tests/fixtures/vm_lua51.lua
"$OBF" virtualize --target lua51 --seed 7002 -o "$tmp/vm51.other.lua" tests/fixtures/vm_lua51.lua
cmp "$tmp/vm51.lua" "$tmp/vm51.same.lua"
if cmp -s "$tmp/vm51.lua" "$tmp/vm51.other.lua"; then
    echo 'error: Lua 5.1 VM layout did not change with seed' >&2
    exit 1
fi
"$LUAC" -p "$tmp/vm51.lua"
"$LUAC" -l -p tests/fixtures/vm_lua51.lua >"$tmp/vm51.opcodes"
lua51_opcode_count=$(awk '/^[[:space:]]*[0-9]+[[:space:]]+\[/ {print $3}' "$tmp/vm51.opcodes" | sort -u | wc -l)
if [[ $lua51_opcode_count -ne 38 ]]; then
    echo "error: Lua 5.1 VM fixture covers $lua51_opcode_count of 38 opcodes" >&2
    exit 1
fi
"$LUA" "$tmp/vm51.lua" >"$tmp/vm51.virtual.out"
cmp "$tmp/vm51.original.out" "$tmp/vm51.virtual.out"

printf '%s\n' '[matrix] Luau VM: private lowering, deterministic seed, compile, execute'
"$LUAU" tests/fixtures/vm_luau.lua >"$tmp/vmluau.original.out"
"$OBF" virtualize --target luau --seed 7351 -o "$tmp/vmluau.lua" tests/fixtures/vm_luau.lua
"$OBF" virtualize --target luau --seed 7351 -o "$tmp/vmluau.same.lua" tests/fixtures/vm_luau.lua
"$OBF" virtualize --target luau --seed 7352 -o "$tmp/vmluau.other.lua" tests/fixtures/vm_luau.lua
cmp "$tmp/vmluau.lua" "$tmp/vmluau.same.lua"
if cmp -s "$tmp/vmluau.lua" "$tmp/vmluau.other.lua"; then
    echo 'error: Luau VM layout did not change with seed' >&2
    exit 1
fi
"$LUAUC" "$tmp/vmluau.lua" >/dev/null
"$LUAUC" --text -O1 -g0 tests/fixtures/vm_luau.lua >"$tmp/vmluau.opcodes"
luau_opcode_count=$(awk '{line=$0; sub(/^L[0-9]+: /,"",line); if(line ~ /^[A-Z][A-Z0-9_]+([[:space:]]|$)/){split(line,a,/ /); if(a[1]!="REMARK") print a[1]}}' "$tmp/vmluau.opcodes" | sort -u | wc -l)
if [[ $luau_opcode_count -lt 60 ]]; then
    echo "error: Luau VM fixture only covers $luau_opcode_count core opcodes" >&2
    exit 1
fi
"$LUAU" "$tmp/vmluau.lua" >"$tmp/vmluau.virtual.out"
cmp "$tmp/vmluau.original.out" "$tmp/vmluau.virtual.out"

for vm in "$tmp/vm51.lua" "$tmp/vmluau.lua"; do
    if [[ $(wc -l <"$vm") -ne 0 ]]; then
        echo "error: VM output $vm contains a physical newline" >&2
        exit 1
    fi
    if grep -q 'loadstring' "$vm"; then
        echo "error: VM output $vm unexpectedly delegates to loadstring" >&2
        exit 1
    fi
    if grep -Eq "error\\(['\"]" "$vm"; then
        echo "error: VM output $vm contains a generated error message" >&2
        exit 1
    fi
done
if grep -Eq '0[bB][01_]' "$tmp/vm51.lua"; then
    echo 'error: Lua 5.1 VM output contains a Luau binary literal' >&2
    exit 1
fi
if ! grep -Eq '0[bB][01_]' "$tmp/vmluau.lua"; then
    echo 'error: seeded Luau VM output did not exercise binary numeric spelling' >&2
    exit 1
fi
for vm in "$tmp/vm51.lua" "$tmp/vmluau.lua"; do
    if ! grep -q 'local B=' "$vm"; then
        echo "error: VM output $vm is missing its private bytecode blob" >&2
        exit 1
    fi
    if grep -Eq 'P\[[0-9]+\]=\{' "$vm"; then
        echo "error: VM output $vm contains legacy inline instruction tables" >&2
        exit 1
    fi
done
if [[ $(find src/vm/opcode -maxdepth 1 -name 'lua51_*.rs' | wc -l) -ne 38 ]]; then
    echo 'error: Lua 5.1 opcode folder does not contain 38 instruction files' >&2
    exit 1
fi
if [[ $(find src/vm/opcode -maxdepth 1 -name 'luau_*.rs' | wc -l) -ne 91 ]]; then
    echo 'error: Luau opcode folder does not contain 91 instruction files' >&2
    exit 1
fi

printf '%s\n' '[matrix] reports'
cat "$tmp/lua51.inspect"
cat "$tmp/luau.inspect"
printf '[matrix] Lua 5.1 output: '; tr '\n' '|' <"$tmp/lua51.original.out"; echo
printf '[matrix] Luau output: '; tr '\n' '|' <"$tmp/luau.original.out"; echo
printf '[matrix] Lua 5.1 VM output: '; tr '\n' '|' <"$tmp/vm51.virtual.out"; echo
printf '[matrix] Luau VM output: '; tr '\n' '|' <"$tmp/vmluau.virtual.out"; echo
printf '[matrix] VM opcode coverage: Lua 5.1=%s/38, Luau core=%s/91\n' \
    "$lua51_opcode_count" "$luau_opcode_count"
printf '[matrix] VM sizes: Lua 5.1=%s bytes, Luau=%s bytes\n' \
    "$(wc -c <"$tmp/vm51.lua")" "$(wc -c <"$tmp/vmluau.lua")"
printf '%s\n' '[matrix] PASS'
