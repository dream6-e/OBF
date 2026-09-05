#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
JOBS=${JOBS:-2}

cleanup() {
    make -C "$ROOT/vendor/lua-5.1.5/src" clean >/dev/null 2>&1 || true
    make -C "$ROOT/vendor/luau-0.735" clean >/dev/null 2>&1 || true
    rm -rf "$ROOT/vendor/luau-0.735/build" \
        "$ROOT/vendor/luau-0.735/luau" "$ROOT/vendor/luau-0.735/luau-compile"
}
trap cleanup EXIT

printf '%s\n' '[tools] building Lua 5.1.5 with gcc'
make -C "$ROOT/vendor/lua-5.1.5/src" clean >/dev/null
make -C "$ROOT/vendor/lua-5.1.5/src" generic \
    CC="${CC:-gcc}" CFLAGS='-O2 -Wall -Wextra' >/dev/null
install -m755 "$ROOT/vendor/lua-5.1.5/src/lua" "$ROOT/toolchains/bin/lua5.1"
install -m755 "$ROOT/vendor/lua-5.1.5/src/luac" "$ROOT/toolchains/bin/luac5.1"

printf '%s\n' '[tools] building Luau 0.735 compiler and runner with g++'
make -C "$ROOT/vendor/luau-0.735" clean >/dev/null
make -C "$ROOT/vendor/luau-0.735" config=release luau luau-compile \
    CXX="${CXX:-g++}" -j"$JOBS" >/dev/null

LUAU="$ROOT/vendor/luau-0.735"
BUILD="$LUAU/build/release"
CXX=${CXX:-g++}
"$CXX" "$ROOT/tools/luau_runner_main.cpp" \
    -O2 -DNDEBUG -std=c++17 \
    -I"$LUAU/CLI/include" -I"$LUAU/Common/include" -I"$LUAU/VM/include" \
    -c -o "$BUILD/obf_luau_runner_main.o"

"$CXX" \
    "$BUILD/CLI/src/FileUtils.cpp.o" \
    "$BUILD/CLI/src/Flags.cpp.o" \
    "$BUILD/CLI/src/Profiler.cpp.o" \
    "$BUILD/CLI/src/Coverage.cpp.o" \
    "$BUILD/CLI/src/Counters.cpp.o" \
    "$BUILD/CLI/src/Repl.cpp.o" \
    "$BUILD/obf_luau_runner_main.o" \
    "$BUILD/CLI/src/ReplRequirer.cpp.o" \
    "$BUILD/CLI/src/VfsNavigator.cpp.o" \
    "$BUILD/libluaucompiler.a" \
    "$BUILD/libluaujitinliner.a" \
    "$BUILD/libluaubytecode.a" \
    "$BUILD/libluauast.a" \
    "$BUILD/libluaucodegen.a" \
    "$BUILD/libluauvm.a" \
    "$BUILD/libluaurequire.a" \
    "$BUILD/libluauconfig.a" \
    "$BUILD/libisocline.a" \
    "$BUILD/libluaucommon.a" \
    -lpthread -o "$BUILD/obf-luau"

install -m755 "$BUILD/obf-luau" "$ROOT/toolchains/bin/luau"
install -m755 "$BUILD/luau-compile" "$ROOT/toolchains/bin/luau-compile"
strip "$ROOT/toolchains/bin/lua5.1" "$ROOT/toolchains/bin/luac5.1" \
    "$ROOT/toolchains/bin/luau" "$ROOT/toolchains/bin/luau-compile"

printf '[tools] '
"$ROOT/toolchains/bin/lua5.1" -v 2>&1
printf '[tools] '
"$ROOT/toolchains/bin/luau" --obf-runtime-version
