# Vendored reference runtimes

These sources are used only to build the pinned compatibility-test tools.

- `lua-5.1.5`: Lua 5.1.5 source distribution, mirrored from `rce-incorporated/lua51` commit `528486bda7ae480307738721a314f33575553e55`; see `lua-5.1.5/COPYRIGHT`.
- `luau-0.735`: the build-required subset of `luau-lang/luau` tag `0.735`, commit `367f9d83cc29804a6d5938ec85b6116d34d8743b`; see `luau-0.735/LICENSE.txt`.

Run `tools/build-reference-tools.sh` to rebuild `toolchains/bin` with the system GCC/G++ toolchain.
