# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox** 的 std-only Rust 工具链。当前版本包含源码语法检查、保语义单行压缩、防御式字节码解析，以及可执行的随机私有寄存器 VM。`virtualize` 会先调用固定目标编译器，再把原生指令、常量、prototype、闭包与 AUX/data word 序列化为真正的版本化二进制私有字节码。输出脚本只嵌入一个带目标标记、payload 长度和 Adler-32 完整性字段的 byte string，由生成的 decoder 恢复 VM 状态并直接解释，**不会用 Lua table 伪装字节码，也不会用 `load`/`loadstring` 重新加载原始源码**。

## 命令

```text
obf check --target <lua51|luau> <input|->
obf minify --target <lua51|luau> [-o FILE] <input|->
obf virtualize --target <lua51|luau> [--seed N] [-o FILE] <input|->
obf inspect-bytecode --target <lua51|luau> <input>
```

示例：

```bash
./tools/bootstrap-rust.sh
./.toolchains/rust-1.88.0/bin/cargo build

target/debug/obf check --target lua51 script.lua
target/debug/obf minify --target lua51 -o script.min.lua script.lua
target/debug/obf virtualize --target lua51 --seed 123 -o script.vm.lua script.lua
target/debug/obf virtualize --target luau --seed 0x735 -o script.vm.luau script.luau
target/debug/obf inspect-bytecode --target lua51 script.luac
```

`--seed` 接受十进制或 `0x` 十六进制 `u64`。相同输入、目标和 seed 会生成逐字节相同的结果；不同 seed 会重新分配私有 opcode、重排 dispatcher，并改变安全的比较分支和数字写法。Lua 5.1 输出只使用其支持的十进制/十六进制数字；Luau 输出还可以使用二进制与数字分隔符。两个目标的最终结果都没有物理换行。

所有 VM 指令都平铺在唯一的 `src/vm/opcode/` 文件夹内：Lua 5.1 共 38 个 `lua51_*.rs` 文件，Luau 0.735 共 91 个 `luau_*.rs` 文件。每个文件只负责一条指令，并通过固定的 `code() -> &'static str` 返回该指令的解释器代码；`src/vm/opcode/mod.rs` 仅负责注册和按 opcode 取用。

编译器查找顺序为 `OBF_LUAC51` / `OBF_LUAU_COMPILE` 环境变量、仓库 `toolchains/bin`，然后是 `PATH`。

## 固定环境

仓库包含：

- `vendor/lua-5.1.5` 与 `toolchains/bin/{lua5.1,luac5.1}`；
- `vendor/luau-0.735` 与 `toolchains/bin/{luau,luau-compile}`；
- `tools/luau_runner_main.cpp`：带 `loadstring`、`require` 和 `luaL_sandbox` 的 CLI 兼容入口；
- `tools/bootstrap-rust.sh`：从固定 `@rustbin` 包安装 Rust/Cargo 1.88.0；
- `tools/build-reference-tools.sh`：使用 Debian gcc/g++ 12 重建参考环境。

项目没有第三方 crate 依赖。代码以 Rust 1.88.0 为最低版本，并保持与要求的 rustc 1.96.0 源码兼容；当前离线仓库可直接复现并执行的是 1.88.0 工具链。

## 强制测试

每次修改后运行：

```bash
./tools/test-matrix.sh
```

矩阵会：

1. 运行 Rust 全目标测试及 debug/release 构建；
2. 在 Lua 5.1 与 Luau 中检查、编译并执行原始/单行压缩 fixture；
3. 生成真实原生字节码并交给内部解析器验证，同时检查截断拒绝；
4. 对两个目标各生成三份 VM 输出，验证同 seed 可复现、异 seed 布局不同；
5. 验证输出包含版本化私有 byte string，且不再出现旧的 prototype/instruction table 字面量；
6. 验证单一 `src/vm/opcode/` 文件夹中恰好注册 Lua 5.1 的 38 个和 Luau 的 91 个独立指令文件；
7. 用 `luac5.1` / `luau-compile` 检查 VM 输出，并与原 fixture 做运行输出逐字节比较；
8. 确认 VM 输出为单物理行且不包含 `loadstring` 委托。

VM 覆盖 fixture 位于 `tests/fixtures/vm_lua51.lua` 与 `tests/fixtures/vm_luau.lua`，包含闭包/upvalue、vararg、多返回值、调用、循环、泛型迭代、table、元表/方法、分支、算术以及 Luau 专属语法路径。

## 当前边界与后续工作

当前 VM 已具备可执行的二进制私有 register bytecode，运行时 table 只由 bytecode decoder 动态构造，不再作为编译结果中的伪字节码字面量。当前 binary blob 仍是可逆明文容器；分阶段字节加密、拆分隐藏密钥、局部变量安全改名、更多 handler 等价模板与 Roblox-only bit32 后端仍按 [`总路线.md`](总路线.md) 后续里程碑推进。

## Anti 状态

按当前要求，`src/anti/` 暂时留空，等待用户提供具体 Anti 实现。
