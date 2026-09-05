# OBF — KRYVEX Lua Obfuscator

A Lua source obfuscator written in Rust (project name: **KRYVEX Ob / Kryvex v2.2**).
It protects Lua scripts via **VM-based (virtualization) obfuscation**: the input
source is compiled to Lua 5.1 bytecode, disassembled into a custom virtual
instruction set, and then re-emitted as a heavily obfuscated Lua program that
interprets its own bytecode at runtime.

> Source originally shipped inside `kkryvex3.zip`; it has been extracted and
> committed here at the repository root.

## How it works (pipeline)

`src/main.rs` drives the full pipeline:

1. `compiler::codegen` + `compiler::dump` — parse/compile the Lua source and
   dump it to Lua 5.1 bytecode (self-contained compiler, no `luac` needed).
2. `BytecodeCompiler::virtualizer::Deserializer` — disassemble the bytecode into
   an IR (`chunk` / `instruction` / `opcode`).
3. `VM::VM_Backend::{Context,Serializer}` — serialize the private payload.
4. `VM::VM_Backend::Generator` — generate the obfuscated Lua VM that executes it.
5. `compressor::Compressor` — rename/minify (scopes, custom codegen).
6. `VM::RadixSieve` — obfuscate numeric constants (anti-static-analysis).
7. Optional `MB` mode → `packer::pack_lua` — XOR + base122 + decoder stub.

## Layout

```
Cargo.toml          # workspace: lib `kryvex_ob` + bin `kryvex-simple` + CLI
src/                # core obfuscation library
  compiler/         # Lua lexer/parser/AST/codegen/dump (5.1 bytecode)
  BytecodeCompiler/ # IR + virtualizer (deserializer, vopcode)
  VM/               # the virtual machine: Opcodes, Control_Flow, RadixSieve,
                    #   VM_Backend (Generator, Serializer, Context, Lua_core,
                    #   AntiTamper, Sandbox, packer)
  compressor/       # minifier / renamer
  packer/           # XOR encryptor + base122 + stub generator
CLI/                # optional TUI launcher (crossterm, 3D splash)
test/               # sample scripts (Prometheus suite, roblox.lua, …)
obfuscated.lua      # latest build output (git-ignored, regenerated on run)
伪装.lua             # anti-tamper / anti-debug shell (Roblox-oriented)
如何使用.md         # 中文使用说明
```

## Build & run

Requires a Rust toolchain (`cargo`) and, to execute the output, a Lua
interpreter (5.2/5.3 with `bit32`, or 5.4 with a `bit32` shim).

```bash
# build
cargo build --release

# obfuscate test.lua  ->  obfuscated.lua
cargo run --release -- test.lua
# compressed + packed variant
cargo run --release -- test.lua MB

# run the obfuscated result
lua obfuscated.lua
```

Dependencies: `rand`, `regex` (library) and `crossterm` (CLI binary).
