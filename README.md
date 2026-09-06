# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox** 的 std-only Rust 工具链。当前版本包含带 byte span 的 owned AST 源码前端、基于作用域的安全局部变量短名、单行压缩、防御式字节码解析，以及可执行的随机私有寄存器 VM。`virtualize` 会先调用固定目标编译器，再把原生指令、常量、prototype、闭包与 AUX/data word 序列化为真正的版本化二进制私有字节码。输出脚本只嵌入一个带目标标记、payload 长度和 Adler-32 完整性字段的 byte string，由生成的 decoder 恢复 VM 状态并直接解释，**不会用 Lua table 伪装字节码，也不会用 `load`/`loadstring` 重新加载原始源码**。

新接手开发者请先阅读 [`项目交接总结.md`](项目交接总结.md)，其中集中记录架构、硬约束、测试门禁、常见陷阱和下一阶段优先级。

## 命令

```text
obf check --target <lua51|luau> <input|->
obf minify --target <lua51|luau> [--no-rename] [-o FILE] <input|->
obf virtualize --target <lua51|luau> [--seed N] [-o FILE] <input|->
obf inspect-bytecode --target <lua51|luau> <input>
```

示例：

```bash
./tools/bootstrap-rust.sh
./.toolchains/rust-1.88.0/bin/cargo build

target/debug/obf check --target lua51 script.lua
target/debug/obf minify --target lua51 -o script.min.lua script.lua
target/debug/obf minify --target luau --no-rename -o script.lexical.luau script.luau
target/debug/obf virtualize --target lua51 --seed 123 -o script.vm.lua script.lua
target/debug/obf virtualize --target luau --seed 0x735 -o script.vm.luau script.luau
target/debug/obf inspect-bytecode --target lua51 script.luac
```

`--seed` 接受十进制或 `0x` 十六进制 `u64`。相同输入、目标和 seed 会生成逐字节相同的结果；不同 seed 会重新分配私有 opcode、重排 dispatcher，并改变安全的比较分支和数字写法。Lua 5.1 输出只使用其支持的十进制/十六进制数字；Luau 输出还可以使用二进制与数字分隔符。两个目标的最终结果都没有物理换行。

## AST 源码前端

`obf::parse(source, target)` 返回公开的 `ast::Chunk`。AST 完全拥有名称及字面量文本，并为 chunk、block、statement、expression、binding、function、table field、attribute 和 Luau type 节点保留原源码的半开 UTF-8 byte span。`obf::check` 保持原来的 `Result<(), Diagnostic>` 验证接口，`minify` 和 VM 路径也继续经过同一解析器。

前端分别执行 Lua 5.1 与 Luau 目标规则。Lua 5.1 覆盖完整核心 statement/expression/function/table 语法；Luau 额外构造类型标注、type alias/type function、type pack、泛型默认值、table access type、if expression、复合赋值、attribute、value export、const、显式 type instantiation 和插值字符串 AST。插值字符串内每个表达式现在由内部词法器/解析器递归构造，并使用全局源码 span，不再作为不透明字符串交给外部编译器兜底。

安全门限为 64 MiB 源码、1,000,000 token、1,000,000 AST 节点和 64 层递归/插值嵌套，以及每层最多 64 次线性运算/后缀链接。后者防止迭代构造的深 AST 在析构时发生栈溢出。公开的 token-array 入口会验证 UTF-8 边界、顺序、EOF、位置和目标，并重新词法化比较，畸形或与源码不一致的 token stream 只返回 `Diagnostic`。针对 Lua 5.1 与 Luau 的 AST 语料分别位于 `tests/fixtures/ast_lua51.lua` 和 `tests/fixtures/ast_luau.lua`。

## 安全压缩（M3 第一阶段）

`obf minify` 默认先解析 AST、建立 lexical scope 与 local/parameter/upvalue 绑定身份，再只对安全的局部绑定分配 `a,b,c,...,aa,ab,...` 短名。按引用频率优先分配，相同输入和目标始终生成相同结果；不使用随机性，不需要 seed。新短名全局唯一，并避开原有 local/global/type 名称、目标保留字和标准库/Roblox API 保留集合。**只在名称更短时改写，不做跨作用域短名复用、常量折叠或死代码删除。**

已处理：

- local 初始化表达式先引用旧作用域，再引入同一声明中的全部新绑定；local function 的函数体可递归引用自身；
- 同名遮蔽、闭包写入与跨多层函数的 upvalue 捕获、循环绑定，以及 `repeat` 内局部变量在 `until` 条件中的可见性；
- 方法的隐式 `self`，以及固定 Lua 5.1.5 的 `LUA_COMPAT_VARARG` 隐式 `arg`；AST 新增 `FunctionBody.has_vararg` 区分无类型标注的 `...` 与非变参函数；
- Luau `typeof` 中的值引用和 `Module.Type` 中的局部模块前缀；函数签名按固定 0.735 parser 的外层值作用域解析；
- 嵌套插值中的引用、函数和局部声明；表达式内部的多行空白/注释会压缩，字面文本的换行、花括号、反引号及转义按值保留。

全局、表字段、方法、未限定的类型名称和泛型名称不会改名；Luau value export 的公开名称保持不变。type function 函数体暂时保持原有名称，涉及的外层绑定也保守保留。改写后会**重新解析最终单行输出并核对 scope、每个引用的绑定身份、global 和 upvalue 集合**，校验失败则拒绝输出。

遇到已知反射/动态环境访问（如 `debug`、`_G`、`_ENV`、`getfenv`、`setfenv`、`loadstring`、`string.dump`，以及可静态识别的反射字段，包括转义/拼接字符串 key）时，默认整份源码退回仅词法压缩。通过未知宿主回调传入的任意反射能力无法静态证明安全，此时请显式使用：

```bash
target/debug/obf minify --target lua51 --no-rename -o script.min.lua script.lua
```

两个模式都不承诺保留源码行号、调试位置信息、dump 字节或错误文本中的位置；`--no-rename` 保留的是名称，不是原始源码布局。

公共接口为 `obf::scope::analyze(source, target)`、`obf::minify(...)` 和 `obf::minify_with_options(..., MinifyOptions { rename_locals: false })`。原有低层 `obf::minify::minify(source, tokens, target)` 仍为词法模式，并验证外部 token stream。作用域分析使用显式工作栈，scope/binding/reference 各限 1,000,000 项，工作项限 8,000,000。

## 私有字节码与 VM

所有 VM 指令都平铺在唯一的 `src/vm/opcode/` 文件夹内：Lua 5.1 共 38 个 `lua51_*.rs` 文件，Luau 0.735 共 91 个 `luau_*.rs` 文件。每个文件只负责一条指令，并通过固定的 `code() -> &'static str` 返回该指令的解释器代码；`src/vm/opcode/mod.rs` 仅负责注册和按 opcode 取用。生成时只装入当前 chunk 实际使用的 handler，不再输出无用 dispatcher 分支。

私有 instruction record 已压缩为 `u16 private-opcode + u32 native-word`。A/B/C/Bx/sBx/D/E 在目标端从原始 32-bit word 恢复，不再重复存储六份字段。生成器自身的错误提示字符串也已删除，所有内部失败路径统一使用短 `E()` 调用。

编译器查找顺序为 `OBF_LUAC51` / `OBF_LUAU_COMPILE` 环境变量、仓库 `toolchains/bin`，然后是 `PATH`。

仓库根目录同时提交两份可直接检查和运行的生成结果：

- `vm_lua51.out.lua`：由 `tests/fixtures/vm_lua51.lua` 生成的 Lua 5.1 私有字节码 VM；
- `vm_luau.out.lua`：由 `tests/fixtures/vm_luau.lua` 生成的 Luau 私有字节码 VM。

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
2. 在 Lua 5.1 与 Luau 中检查、编译并执行原始/单行压缩 fixture，并额外运行两套 focused AST corpus；
3. 生成真实原生字节码并交给内部解析器验证，同时检查截断拒绝；
4. 对两个目标各生成三份 VM 输出，验证同 seed 可复现、异 seed 布局不同；
5. 验证输出包含版本化私有 byte string，且不再出现旧的 prototype/instruction table 字面量；
6. 验证单一 `src/vm/opcode/` 文件夹中恰好注册 Lua 5.1 的 38 个和 Luau 的 91 个独立指令文件；
7. 验证 Lua 5.1 fixture 实际覆盖 38/38 opcode，Luau fixture 覆盖至少 60 条可由固定编译器产生的核心 opcode；
8. 用 `luac5.1` / `luau-compile` 检查 VM 输出，并与原 fixture 做运行输出逐字节比较；
9. 确认 VM 输出为单物理行、不包含生成器错误消息且不委托 `loadstring`；
10. 对 `scope_lua51.lua` / `scope_luau.lua` 比较原始、仅词法、默认安全压缩的目标编译和运行结果，并验证确定性及实际缩短；
11. 对 `reflection_lua51.lua` / `reflection_luau.lua` 验证反射可观察名称不变，自动保留输出与 `--no-rename` 逐字节一致。

`tests/scope.rs` 与 `tests/safe_minify.rs` 还包含绑定图断言、导入类型前缀、CLI 参数、元方法求值顺序、重复绑定、变参兼容及超长链拒绝回归。2026-09-06 完整矩阵通过，Rust 单元/集成测试合计 47 项。

VM 覆盖 fixture 位于 `tests/fixtures/vm_lua51.lua` 与 `tests/fixtures/vm_luau.lua`，包含闭包/upvalue、vararg、多返回值、调用、循环、泛型迭代、table、元表/方法、分支、算术以及 Luau 专属语法路径。

## 当前边界与后续工作

当前 owned AST、lexical scope、local/upvalue 绑定解析和保守的安全短名改写已完成第一阶段；跨作用域名字复用、常量折叠/死代码删除及更全面的宿主反射模型尚未实现。VM 已具备可执行的二进制私有 register bytecode，运行时 table 只由 bytecode decoder 动态构造，不再作为编译结果中的伪字节码字面量。VM wrapper 因包含 `getfenv` / `_G` 访问继续保守保持原有局部名称；当前 binary blob 仍是可逆明文容器；分阶段字节加密、拆分隐藏密钥、进一步的安全压缩优化、更多 handler 等价模板与 Roblox-only bit32 后端仍按 [`总路线.md`](总路线.md) 后续里程碑推进。

## Anti 状态

按当前要求，`src/anti/` 暂时留空，等待用户提供具体 Anti 实现。
