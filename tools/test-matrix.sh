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

printf '%s\n' '[matrix] reports'
cat "$tmp/lua51.inspect"
cat "$tmp/luau.inspect"
printf '[matrix] Lua 5.1 output: '; tr '\n' '|' <"$tmp/lua51.original.out"; echo
printf '[matrix] Luau output: '; tr '\n' '|' <"$tmp/luau.original.out"; echo
printf '%s\n' '[matrix] PASS'
