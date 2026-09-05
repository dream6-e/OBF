# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox** 的 std-only Rust 工具链。当前版本已经建立源码解析、单行词法压缩、字节码安全解析和双环境验证基础；虚拟机与私有字节码按 [`总路线.md`](总路线.md) 分阶段实现。

## 当前命令

```text
obf check --target <lua51|luau> <input|->
obf minify --target <lua51|luau> [-o FILE] <input|->
obf inspect-bytecode --target <lua51|luau> <input>
```

示例：

```bash
./tools/bootstrap-rust.sh
./.toolchains/rust-1.88.0/bin/cargo build

target/debug/obf check --target lua51 script.lua
target/debug/obf minify --target lua51 -o script.min.lua script.lua
target/debug/obf inspect-bytecode --target lua51 script.luac
```

## 固定环境

仓库包含：

- `vendor/lua-5.1.5` 与 `toolchains/bin/{lua5.1,luac5.1}`；
- `vendor/luau-0.735` 与 `toolchains/bin/{luau,luau-compile}`；
- `tools/luau_runner_main.cpp`：带 `loadstring`、`require` 和 `luaL_sandbox` 的 CLI 兼容入口；
- `tools/bootstrap-rust.sh`：从固定 `@rustbin` 包安装 Rust/Cargo 1.88.0；
- `tools/build-reference-tools.sh`：使用 Debian gcc/g++ 重建参考环境。

项目没有第三方 crate 依赖。

## 强制测试

每次代码修改后运行：

```bash
./tools/test-matrix.sh
```

矩阵会在 Lua 5.1 与 Luau 中分别检查原始及处理后的代码、比较运行输出，并生成真实字节码交给内部解析器验证。

## Anti 状态

按当前要求，`src/anti/` 暂时留空，等待后续具体实现。
