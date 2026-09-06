# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox** 的 std-only Rust 工具链。当前版本包含带 byte span 的 owned AST 源码前端、基于作用域的安全随机短名、单行压缩、防御式字节码解析，以及可执行的随机私有寄存器 VM。`virtualize` 会先调用固定目标编译器，再把原生指令、常量、prototype、闭包与 AUX/data word 序列化为真正的版本化二进制私有字节码。输出脚本只嵌入一个带目标标记、payload 长度和 Adler-32 完整性字段的 byte string，由生成的 decoder 恢复 VM 状态并直接解释，**不会用 Lua table 伪装字节码，也不会用 `load`/`loadstring` 重新加载原始源码**。

新接手开发者请先阅读 [`项目交接总结.md`](项目交接总结.md)，其中集中记录架构、硬约束、测试门禁、常见陷阱和下一阶段优先级。

## 命令

```text
obf check --target <lua51|luau> <input|->
obf minify --target <lua51|luau> [--seed N | --no-rename] [-o FILE] <input|->
obf virtualize --target <lua51|luau> [--seed N] [-o FILE] <input|->
obf inspect-bytecode --target <lua51|luau> <input>
```

示例：

```bash
./tools/bootstrap-rust.sh
export PATH="$PWD/.toolchains/rust-1.88.0/bin:$PATH"
cargo build

target/debug/obf check --target lua51 script.lua
# 不指定 seed：每次生成重新随机命名，stderr 报告可复现的 seed
target/debug/obf minify --target lua51 -o script.min.lua script.lua
# 指定 seed：相同输入/目标/配置得到相同结果
target/debug/obf minify --target lua51 --seed 123 -o script.min.lua script.lua
target/debug/obf minify --target luau --no-rename -o script.lexical.luau script.luau
target/debug/obf virtualize --target lua51 --seed 123 -o script.vm.lua script.lua
target/debug/obf virtualize --target luau --seed 0x735 -o script.vm.luau script.luau
target/debug/obf inspect-bytecode --target lua51 script.luac
```

`--seed` 对 `minify` 和 `virtualize` 都有效，接受十进制或 `0x` 十六进制 `u64`。省略时每次生成选取新 seed，并仅在 **stderr** 输出 `seed: N`，stdout 仍是纯脚本。相同输入、目标、配置和 seed 可逐字节复现；`--seed` 不能与 `--no-rename` 合用，也不接受在 `check` / `inspect-bytecode` 上使用。

seed 控制最终变量随机短名；对 VM 还控制私有 opcode、dispatcher 顺序、比较分支和数字写法。命名与 VM 布局使用独立随机流，避免前序随机调用消耗命名状态。Lua 5.1 只使用十进制/十六进制数字；Luau 还可使用二进制与数字分隔符。两个目标的最终结果都没有物理换行。随机化不是加密；名称池有限、没有可改名 local 或触发保留策略时，不承诺任意两个 seed 的输出一定不同。

## AST 源码前端

`obf::parse(source, target)` 返回公开的 `ast::Chunk`。AST 完全拥有名称及字面量文本，并为 chunk、block、statement、expression、binding、function、table field、attribute 和 Luau type 节点保留原源码的半开 UTF-8 byte span。`obf::check` 保持原来的 `Result<(), Diagnostic>` 验证接口，`minify` 和 VM 路径也继续经过同一解析器。

前端分别执行 Lua 5.1 与 Luau 目标规则。Lua 5.1 覆盖完整核心 statement/expression/function/table 语法；Luau 额外构造类型标注、type alias/type function、type pack、泛型默认值、table access type、if expression、复合赋值、attribute、value export、const、显式 type instantiation 和插值字符串 AST。插值字符串内每个表达式现在由内部词法器/解析器递归构造，并使用全局源码 span，不再作为不透明字符串交给外部编译器兜底。

安全门限为 64 MiB 源码、1,000,000 token、1,000,000 AST 节点和 64 层递归/插值嵌套，以及每层最多 64 次线性运算/后缀链接。后者防止迭代构造的深 AST 在析构时发生栈溢出。公开的 token-array 入口会验证 UTF-8 边界、顺序、EOF、位置和目标，并重新词法化比较，畸形或与源码不一致的 token stream 只返回 `Diagnostic`。针对 Lua 5.1 与 Luau 的 AST 语料分别位于 `tests/fixtures/ast_lua51.lua` 和 `tests/fixtures/ast_luau.lua`。

本轮解析器审计补齐了 contextual `continue`、prefix/suffix 限制、跨行括号调用、Luau 类型断言优先级、方法 `receiver:m<<T>>(...)`、const 初始化/写入检查，以及模块 return/export 冲突。`ExpressionKind::Call.type_arguments` 保存显式方法类型实参；绑定分析记录 `LocalBinding.is_const` 与 `Reference.is_write`，区分修改 const 绑定和修改它引用的表。type function 的签名/函数体/嵌套函数均不得捕获外层运行时 local。

`check` **只检查词法、语法及上述绑定规则，不等价于原生编译成功**；例如 Luau `continue` 跳过 `repeat` 局部初始化的控制流检查、目标寄存器/局部变量资源上限仍由编译器负责。安全限制内的有限差分回归不代表解析器已被证明对任意输入完全正确。`tests/parser_audit.rs` 对固定参考编译器检查接受/拒绝案例、生成式运算符组合和三种压缩配置，并固定记录 parser/compiler 边界。

## 安全压缩与最终随机命名（M3）

`obf minify` 默认解析 AST、建立 lexical scope 与 local/parameter/upvalue 绑定身份，再对全部可安全改名的绑定分配 **1–2 个小写字母**，例如 `d`、`q`、`ab`、`ef`。单字母池和双字母池分别按 seed 洗牌，引用频率高的绑定优先使用单字母。**原本已是一、两字母的安全局部变量也必须换成不同的名称**，不是固定按 `a,b,c` 顺序缩短。

新名字在整份输出中唯一，避开 global、类型/泛型、受保护的 local、目标保留字及标准库/Roblox API 集合。可以使用另一个将被同时替换的 local 的旧拼写；改写按绑定 ID 和原始 span 一次完成，不按文本全局替换。不做跨作用域短名复用、常量折叠或死代码删除。

字母池最多 `26 + 26×26 = 702` 个候选，排除保留名称后更少。若不能为全部可改名绑定安全分配不同于各自原名的短名，则返回诊断，**不输出三字母名、不部分改名、不写出失败结果**；`minify` 可显式 `--no-rename`，或拆分源码。严格全局唯一可能使某些原本大量复用单字母的代码稍长，这是本轮“全部重新随机命名”的明确取舍。

已处理：

- local 初始化表达式先引用旧作用域，再引入同一声明中的全部新绑定；local function 的函数体可递归引用自身；
- 同名遮蔽、闭包写入与跨多层函数的 upvalue 捕获、循环绑定，以及 `repeat` 内局部变量在 `until` 条件中的可见性；
- 方法的隐式 `self`，以及固定 Lua 5.1.5 的 `LUA_COMPAT_VARARG` 隐式 `arg`；AST 新增 `FunctionBody.has_vararg` 区分无类型标注的 `...` 与非变参函数；
- Luau `typeof` 中的值引用和 `Module.Type` 中的局部模块前缀；函数签名按固定 0.735 parser 的外层值作用域解析；
- 嵌套插值中的引用、函数和局部声明；表达式内部的多行空白/注释会压缩，字面文本的换行、花括号、反引号及转义按值保留。

全局、表字段、方法、未限定的类型名称和泛型名称不会改名；Luau value export 的公开名称保持不变。type function 内部名称暂时保持原样；外层运行时 local 捕获按 Luau 规则拒绝，而不是通过保留名称放行。改写后会**重新解析最终单行输出并核对 scope、每个引用的绑定身份、global 和 upvalue 集合**，校验失败则拒绝输出。

遇到已知反射/动态环境访问（如 `debug`、`_G`、`_ENV`、`getfenv`、`setfenv`、`loadstring`、`string.dump`，以及可静态识别的反射字段，包括转义/拼接字符串 key）时，默认整份源码退回仅词法压缩。通过未知宿主回调传入的任意反射能力无法静态证明安全，此时请显式使用：

```bash
target/debug/obf minify --target lua51 --no-rename -o script.min.lua script.lua
```

两个模式都不承诺保留源码行号、调试位置信息、dump 字节或错误文本中的位置；`--no-rename` 保留的是名称，不是原始源码布局。

公共接口为 `obf::scope::analyze(source, target)`、默认使用新 seed 的 `obf::minify(...)`，以及 `obf::minify_with_options(..., MinifyOptions::seeded(123))` / `MinifyOptions::lexical()`。`MinifyOptions` 现在含 `rename_locals` 和 `seed`；推荐使用上述构造方法。原有低层 `obf::minify::minify(source, tokens, target)` 仍为词法模式，并验证外部 token stream。作用域分析使用显式工作栈，scope/binding/reference 各限 1,000,000 项，工作项限 8,000,000。

## 私有字节码与 VM

所有 VM 指令都平铺在唯一的 `src/vm/opcode/` 文件夹内：Lua 5.1 共 38 个 `lua51_*.rs` 文件，Luau 0.735 共 91 个 `luau_*.rs` 文件。每个文件只负责一条指令，并通过固定的 `code() -> &'static str` 返回该指令的解释器代码；`src/vm/opcode/mod.rs` 仅负责注册和按 opcode 取用。生成时只装入当前 chunk 实际使用的 handler，不再输出无用 dispatcher 分支。

decoder、runtime、dispatcher、全部已用 handler 和执行尾部**全部组装完成后**，`vm::virtualize` 仅调用一次内部 `minify::finalize_vm`，随后不再追加代码。该阶段统一随机命名所有显式 local、局部函数、参数与循环变量，并在最终单行输出中再次核对绑定图、名称长度与确实已换名；隐式 Lua 5.1 `arg` 不属于源码中的显式声明。

生成器只有一个严格审计的环境捕获例外：`local G=(getfenv and getfenv(0))or _G`。仅内部生成路径可使用，额外检测到的反射/环境访问（barrier）或受保护显式绑定会导致生成失败。普通 `minify` 对同样的源码仍执行保守保留策略，没有公开的“强制忽略反射”选项。全局、字段、方法和私有 bytecode/string 内容不会随局部变量改名；这也不承诺模拟任意宿主反射、调试栈或原始调试名称。

私有 instruction record 已压缩为 `u16 private-opcode + u32 native-word`。A/B/C/Bx/sBx/D/E 在目标端从原始 32-bit word 恢复，不再重复存储六份字段。生成器自身的错误提示字符串也已删除，所有内部失败路径统一调用局部错误函数（模板中的 `E` 也参与最终随机改名）。

编译器查找顺序为 `OBF_LUAC51` / `OBF_LUAU_COMPILE` 环境变量、仓库 `toolchains/bin`，然后是 `PATH`。

仓库根目录同时提交两份可直接检查和运行的生成结果：

- `vm_lua51.out.lua`：`tests/fixtures/vm_lua51.lua`，seed **7001**，**16,491 B**；
- `vm_luau.out.lua`：`tests/fixtures/vm_luau.lua`，seed **7351**，**24,491 B**。

生成器或命名策略变更后需同步再生成这两份文件；测试矩阵会与固定 seed 新生成结果逐字节比较。

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
5. 按 AST/字节内容验证私有 blob 的 magic、版本、目标、长度、Adler-32 和改名前后字节一致；与变量拼写无关地检查旧 inline metadata，允许正常 Luau NAMECALL 函数包装表；
6. 验证单一 `src/vm/opcode/` 文件夹中恰好注册 Lua 5.1 的 38 个和 Luau 的 91 个独立指令文件；
7. 验证 Lua 5.1 fixture 实际覆盖 38/38 opcode，Luau fixture 覆盖至少 60 条可由固定编译器产生的核心 opcode；
8. 用 `luac5.1` / `luau-compile` 检查所有 VM seed 变体并逐份执行，与原 fixture 逐字节比较；根目录示例也必须与固定 seed 生成结果一致；
9. 确认 VM 输出为单物理行、不包含生成器错误消息且不委托 `loadstring`；
10. 对 `scope_lua51.lua` / `scope_luau.lua` 比较原始、仅词法、seed 735/736 安全压缩的编译和运行结果，验证固定 seed 确定性、异 seed 换名及这些 fixture 的实际缩短；
11. 对 `reflection_lua51.lua` / `reflection_luau.lua` 验证反射可观察名称不变，自动保留输出与 `--no-rename` 逐字节一致。

`tests/scope.rs`、`tests/random_names.rs`、`tests/safe_minify.rs` 及内部 VM 测试还覆盖：所有可改名 local 的 `[a-z]{1,2}`/唯一性/换名断言，短名重分配，末位冲突修复，名称池耗尽，CLI seed 报告/复现/参数拒绝/失败不覆盖文件，并发新 seed，以及原有绑定、类型、元方法、插值、变参和超长链回归。原生运行差分包含 seed `0`、`1`、`0x735`、`u64::MAX`；650 个已是单字母的 locals 也经过双目标编译/运行。

2026-09-06 完整矩阵通过，Rust 单元/集成测试合计 **72 项**（24 单元 + 48 集成，其中 11 项 parser audit），debug/release 构建通过。

VM 覆盖 fixture 位于 `tests/fixtures/vm_lua51.lua` 与 `tests/fixtures/vm_luau.lua`，包含闭包/upvalue、vararg、多返回值、调用、循环、泛型迭代、table、元表/方法、分支、算术以及 Luau 专属语法路径。

## 当前边界与后续工作

当前 owned AST、lexical scope、local/upvalue 绑定解析、保守安全改名和完整 VM 生成后的随机一/两字母命名已完成；跨作用域名字复用、常量折叠/死代码删除及更全面的宿主反射模型尚未实现。VM 已具备可执行的二进制私有 register bytecode，instruction/prototype 状态表由 bytecode decoder 动态构造，不再作为编译结果中的伪字节码字面量。VM wrapper 已经通过私有审计路径统一随机命名，但 binary blob 仍是可逆明文容器；分阶段字节加密、拆分隐藏密钥、进一步的安全压缩优化、更多 handler 等价模板与 Roblox-only bit32 后端仍按 [`总路线.md`](总路线.md) 后续里程碑推进。

## Anti 状态

按当前要求，`src/anti/` 暂时留空，等待用户提供具体 Anti 实现。
