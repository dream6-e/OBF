# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox 方向** 的 std-only Rust 工具链。默认 `virtualize` 已实现真正的 **AST → IR → 自定义 Bytecode → 寄存器 VM**：固定 **32-byte Header**、**4 bytes/instruction**、独立常量/捕获/prototype。生成器不依赖原生 compiler，不用 `load/loadstring` 委托执行；原生后端只通过 `--backend native` 显式选择。当前不做加密、压缩、随机 section 或随机 opcode；所有脚本生成完后才统一随机一/两字母 local 并输出为单行。

新接手开发者请先阅读 [`项目交接总结.md`](项目交接总结.md)，其中集中记录架构、硬约束、测试门禁、常见陷阱和下一阶段优先级。

## 命令

```text
obf check --target <lua51|luau> <input|->
obf minify --target <lua51|luau> [--seed N | --no-rename] [-o FILE] <input|->
obf virtualize --target <lua51|luau> [--backend ast|native] [--seed N] [-o FILE] <input|->
obf dump-ir --target <lua51|luau> [-o FILE] <input|->
obf compile --target <lua51|luau> [-o FILE] <input|->
obf wrap-bytecode --target <lua51|luau> [--seed N] [-o FILE] <input.obf|->
obf inspect-bytecode --target <lua51|luau> <input|->
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
target/debug/obf dump-ir --target lua51 -o target/script.ir script.lua
target/debug/obf compile --target lua51 -o target/script.obf script.lua
target/debug/obf inspect-bytecode --target lua51 target/script.obf
target/debug/obf wrap-bytecode --target lua51 --seed 123 -o script.from-bytecode.lua target/script.obf
# 可选旧后端，不是默认 fallback
target/debug/obf virtualize --backend native --target lua51 --seed 123 -o script.legacy.lua script.lua
```

`--seed` 对 `minify`、`virtualize`、`wrap-bytecode` 有效，接受十进制或 `0x` 十六进制 `u64`。省略时每次生成新 seed，仅在 **stderr** 输出 `seed: N`，stdout 保持纯脚本；同源、同目标、同配置、同 seed 可逐字节复现。`compile` 输出 binary，`dump-ir` 输出可读 IR，二者不接受 seed；`--no-rename` 只用于 minify，`--backend` 只用于 virtualize。

默认 AST/v2 路径的 seed **仅影响最终变量名**，bytecode 与布局不随机化；不做加密、压缩或随机 section。显式 `--backend native` 才保留旧 OBF v1 的随机 opcode/dispatcher/数字写法。脚本输出均是单物理行；IR/inspect 报告和二进制文件不适用“脚本单行”的限制。随机短名不是加密，有限名称空间不保证任意两个 seed 都产生不同文本。

## AST 源码前端

`obf::parse(source, target)` 返回公开的 `ast::Chunk`。AST 完全拥有名称及字面量文本，并为 chunk、block、statement、expression、binding、function、table field、attribute 和 Luau type 节点保留原源码的半开 UTF-8 byte span。`obf::check` 保持原来的 `Result<(), Diagnostic>` 验证接口，`minify` 和 VM 路径也继续经过同一解析器。

前端分别执行 Lua 5.1 与 Luau 目标规则。Lua 5.1 覆盖完整核心 statement/expression/function/table 语法；Luau 额外构造类型标注、type alias/type function、type pack、泛型默认值、table access type、if expression、复合赋值、attribute、value export、const、显式 type instantiation 和插值字符串 AST。插值字符串内每个表达式现在由内部词法器/解析器递归构造，并使用全局源码 span，不再作为不透明字符串交给外部编译器兜底。

安全门限为 64 MiB 源码、1,000,000 token、1,000,000 AST 节点和 64 层递归/插值嵌套，以及每层最多 64 次线性运算/后缀链接。后者防止迭代构造的深 AST 在析构时发生栈溢出。公开的 token-array 入口会验证 UTF-8 边界、顺序、EOF、位置和目标，并重新词法化比较，畸形或与源码不一致的 token stream 只返回 `Diagnostic`。针对 Lua 5.1 与 Luau 的 AST 语料分别位于 `tests/fixtures/ast_lua51.lua` 和 `tests/fixtures/ast_luau.lua`。

本轮解析器审计补齐了 contextual `continue`、prefix/suffix 限制、跨行括号调用、Luau 类型断言优先级、方法 `receiver:m<<T>>(...)`、const 初始化/写入检查，以及模块 return/export 冲突。`ExpressionKind::Call.type_arguments` 保存显式方法类型实参；绑定分析记录 `LocalBinding.is_const` 与 `Reference.is_write`，区分修改 const 绑定和修改它引用的表。type function 的签名/函数体/嵌套函数均不得捕获外层运行时 local。

`check` **只检查词法、语法及上述绑定规则，不等价于原生编译成功**；例如 Luau `continue` 跳过 `repeat` 局部初始化的控制流检查、目标寄存器/局部变量资源上限仍由编译器负责。安全限制内的有限差分回归不代表解析器已被证明对任意输入完全正确。`tests/parser_audit.rs` 对固定参考编译器检查接受/拒绝案例、生成式运算符组合和三种压缩配置，并固定记录 parser/compiler 边界。

## 安全压缩、作用域复用与最终随机命名（M3）

`obf minify` 默认解析 AST、建立 lexical scope 与 local/parameter/upvalue 绑定身份，再对全部可安全改名的绑定分配 **1–2 个小写字母**，例如 `d`、`q`、`ab`、`ef`。单字母池和双字母池分别按 seed 洗牌，引用频率高的绑定优先使用单字母。**原本已是一、两字母的安全局部变量也必须换成不同的名称**，不是固定按 `a,b,c` 顺序缩短。

新名字**同域唯一，跨域安全复用**，覆盖 function、if/elseif/else、while、do、for 和 repeat。每个命名域内的所有可改名声明保持不同，包括未使用及原先同名遮蔽的 locals；函数参数与直接函数体 locals 共用命名域，for 变量与直接循环体 locals 也共用命名域。`Scope.name_scope` 表示这个唯一性分组，不改变原有 lexical scope ID、parent 或可见性。

复用不是逐块重置名称池：分析声明实际生效的顺序，禁止会截获外层引用、闭包/upvalue 或写入目标的同名分配；已被原拼写遮蔽的声明也纳入约束。globals、类型/泛型、受保护 local、保留字和标准库/Roblox API 仍全局排除。原本必须保留的同名遮蔽保持原样，不引入新冲突。改写按绑定 ID 和原始 span 一次完成，可以使用其他同时改名 local 的旧拼写；不做文本全局替换、常量折叠或死代码删除。

字母池最多 `26 + 26×26 = 702` 个候选，排除保留名称后更少，但**整份源码的绑定数不再受 702 限制**。分配使用按引用频率排序的 seeded 着色，同域冲突以名称占用表表示，跨域使用有界稀疏干涉边；末位冲突通过同域迭代匹配修复，其他域的颜色保持固定。它不是全局最优着色器：某域超出候选池、当前有界分配找不到安全方案或超出资源门限时返回诊断，**不输出三字母名、不部分改名、不写出失败结果**；可显式 `--no-rename` 或拆分源码。

已处理：

- local 初始化表达式先引用旧作用域，再引入同一声明中的全部新绑定；local function 的函数体可递归引用自身；
- 同名遮蔽、闭包写入与跨多层函数的 upvalue 捕获、循环绑定，以及 `repeat` 内局部变量在 `until` 条件中的可见性；
- 方法的隐式 `self`，以及固定 Lua 5.1.5 的 `LUA_COMPAT_VARARG` 隐式 `arg`；AST 新增 `FunctionBody.has_vararg` 区分无类型标注的 `...` 与非变参函数；
- Luau `typeof` 中的值引用和 `Module.Type` 中的局部模块前缀；函数签名按固定 0.735 parser 的外层值作用域解析；
- 嵌套插值中的引用、函数和局部声明；表达式内部的多行空白/注释会压缩，字面文本的换行、花括号、反引号及转义按值保留。

全局、表字段、方法、未限定的类型名称和泛型名称不会改名；Luau value export 的公开名称保持不变。type function 内部名称暂时保持原样；外层运行时 local 捕获按 Luau 规则拒绝，而不是通过保留名称放行。改写后会**重新解析最终单行输出，核对 scope、声明生效顺序、每个引用/写入的绑定身份、global 和 upvalue 集合，并独立检查同域不产生重复名称**；后者还能发现仅靠引用图无法发现的未使用变量撞名，任何校验失败均拒绝输出。

遇到已知反射/动态环境访问（如 `debug`、`_G`、`_ENV`、`getfenv`、`setfenv`、`loadstring`、`string.dump`，以及可静态识别的反射字段，包括转义/拼接字符串 key）时，默认整份源码退回仅词法压缩。通过未知宿主回调传入的任意反射能力无法静态证明安全，此时请显式使用：

```bash
target/debug/obf minify --target lua51 --no-rename -o script.min.lua script.lua
```

两个模式都不承诺保留源码行号、调试位置信息、dump 字节或错误文本中的位置；`--no-rename` 保留的是名称，不是原始源码布局。

公共接口为 `obf::scope::analyze(source, target)`、默认使用新 seed 的 `obf::minify(...)`，以及 `obf::minify_with_options(..., MinifyOptions::seeded(123))` / `MinifyOptions::lexical()`。`MinifyOptions` 现在含 `rename_locals` 和 `seed`；推荐使用上述构造方法。原有低层 `obf::minify::minify(source, tokens, target)` 仍为词法模式，并验证外部 token stream。作用域分析使用显式工作栈，scope/binding/reference 各限 1,000,000 项，工作项限 8,000,000。名称复用另有 8,000,000 次工作预算及 1,000,000 条跨域干涉边上限，同域不构造平方规模的两两边。

## 自定义字节码与寄存器 VM（默认 AST 后端）

```text
source → 现有 AST / BindingId → typed register IR / basic blocks
       → 自定义指令选择 / 标签回填 → OBF v2
       → 校验 / decoder / register VM → 完整生成后随机短名 / 单行化
```

这条链路**不调用原生 compiler，不存 native word，也不默默 fallback**。新 `ir::Module` 包含函数、常量、cell/upvalue 捕获和带符号后继的基本块；IR 的 branch 生成 `Test + Jump + Jump`，每条均为 4 bytes。Header 固定 **32 bytes**，含版本、目标、端序、宽度、文件长度、prototype 数量、入口、ISA 版本和 Adler-32。完整逐字段规范与 **49 条 ISA** 见 [`自定义字节码.md`](自定义字节码.md)。

- Lua 5.1：46 个 `src/vm/opcode/lua51/c*.rs`；Luau：49 个 `src/vm/opcode/luau/c*.rs`。每条有效 opcode 有一份独立固定 handler，不以 NOP 代替未实现语义。
- 每 frame 为寄存器文件；local 使用 heap cell，临时值为普通寄存器，闭包引用 cell。循环的新一轮/复用寄存器不会破坏逃逸闭包。
- 显式 pack.n 处理多返回值、尾部 nil、vararg、调用/返回；VM→VM 尾调用替换 frame。支持宿主函数、元方法、回调及 coroutine。
- 两端分别处理赋值/方法求值顺序、numeric-for、表构造器刷新和 Lua51 隐式 `arg`；Luau 另有 `//`、插值、泛型擦除、`__iter`、userdata NAMECALL、精确 i64 及冻结导出表。
- Rust reader 与生成的 decoder 都做范围/格式验证；指令流为 byte string，每步直接 fetch 4 bytes，不是源码 table 中的伪字节码。

Rust API：`ir::compile/lower`、`bytecode::custom::{encode,decode,serialize}`、`vm::custom::{compile,emit}`，以及默认 `vm::virtualize`。`inspect-bytecode` 自动区分 OBF v2 与原生 chunk；`wrap-bytecode` 可把已保存的 `.obf` 独立包装为 VM。

所有 decoder、runtime、dispatcher、字节码中出现的 handler 和执行尾部组装完后，只调用一次私有 `minify::finalize_vm`；之后不追加代码。该阶段统一随机一/两字母名，重解析复核绑定图、同域唯一性、名称长度、确实换名和 bytecode 字节不变。唯一生成器环境例外仍是严格审计的 `local G=(getfenv and getfenv(0))or _G`，没有公开忽略反射的开关。

### 显式兼容后端

`virtualize --backend native` / `vm::virtualize_native` 保留原来的 `compiler → native reader → OBF v1`。旧根目录 `lua51_*.rs`（38）与 `luau_*.rs`（91）不移动、仍单独测试。只有这个后端使用旧 13-byte Header、6-byte `u16 private-opcode + u32 native-word` 及随机布局。

旧 backend 的 compiler 查找依次为 `OBF_LUAC51` / `OBF_LUAU_COMPILE`、仓库 `toolchains/bin`、`PATH`。默认 AST 后端在这些变量指向不存在文件时仍可正常编译/生成；原生工具仍用于门禁的语法/运行对照。

### 已提交示例

| 文件 | 来源 | seed | v2 bytecode | 最终单行脚本 |
|---|---|---:|---:|---:|
| `vm_lua51.out.lua` | `tests/fixtures/vm_lua51.lua` | 7001 | 6,879 B | 32,524 B |
| `vm_luau.out.lua` | `tests/fixtures/vm_luau.lua` | 7351 | 8,489 B | 33,980 B |

生成器或命名策略变更后必须再生成两份示例。矩阵比较默认生成、独立 compile/wrap、debug/release 及 golden 的逐字节一致性。本版优先完整可执行与格式清晰，不声称体积比旧 native backend 更小。

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

1. 运行 Rust 全目标测试、rustfmt 与 debug/release 构建；
2. 对原有 basic/AST/scope/reflection 语料保持双端源码/压缩的语法、运行、seed、反射保留和短名安全门禁；
3. 检查原生 chunk，同时验证 OBF v2 Header、4-byte 大小、截断、字节损坏、恶意结构、round-trip 与资源上限；
4. 对 v2 执行逐 opcode fetch-loop 覆盖：**Lua51 46/46，Luau 49/49**；不是只数未执行的指令；
5. 编译/执行每份 VM seed 变体，确认单行、不委托 loadstring、没有生成器错误消息、所有显式 local 最后才改名且 payload 字节不变；
6. 检查新目标目录的 46/49 个 handler 和旧兼容目录的 38/91 个 handler；
7. 独立执行 `dump-ir → compile → inspect → wrap`，证明缺少原生 compiler 也能生成默认 VM；
8. 比较 debug/release 的 binary 和 VM、默认虚拟化与独立 wrap、根目录 golden；
9. 显式执行旧 `--backend native` 的完整语料、多 seed、语法/运行回归，保留其原生 opcode coverage（Lua51 38/38、Luau ≥60）；
10. 额外覆盖多返回值/nil、变量求值时机、闭包、循环、20k 尾调用、coroutine/回调、i64、导出模块、userdata NAMECALL、GC 及 CLI 失败不覆盖文件。

`tests/scope.rs`、`tests/scope_reuse.rs`、`tests/random_names.rs`、`tests/safe_minify.rs` 及内部 VM 测试还覆盖：所有可改名 local 的 `[a-z]{1,2}`/同域唯一性/换名断言，短名跨域复用、闭包读写、声明时序、原先遮蔽的声明、参数/body 共域，多步匹配修复、小图穷举重解析、工作门限、名称池耗尽、CLI seed 报告/复现/参数拒绝/失败不覆盖文件，并发新 seed，以及原有绑定、类型、元方法、插值、变参和超长链回归。原生运行差分包含 seed `0`、`1`、`0x735`、`u64::MAX`；650 个已是单字母的 locals 也经过双目标编译/运行；10,000 个相邻块加一个累计变量的压力测试安全复用两个单字母名，另有 96 种生成式遮蔽/初始化程序的双目标多 seed 运行差分。

2026-09-06 默认 AST 后端接入后的完整矩阵 **PASS 114**（32 单元 + 82 集成）：在原 84 项基础上新增 30 项 IR/bytecode/VM/CLI 回归，debug/release 构建、binary/脚本一致性及两套后端均通过。

VM 覆盖 fixture 位于 `tests/fixtures/vm_lua51.lua` 与 `tests/fixtures/vm_luau.lua`，包含闭包/upvalue、vararg、多返回值、调用、循环、泛型迭代、table、元表/方法、分支、算术以及 Luau 专属语法路径。

## 当前边界与后续工作

默认 AST/IR/v2 register VM、独立 reader/encoder、完整 ISA 与最终随机短名已可运行。后续优先扩展语义/压力差分、寄存器/pack 的体积和运行开销、IR 数据流验证及宿主接口边界；按本次要求，暂不推进复杂加密、压缩、随机 section 或多模板随机化。

当前限制必须保留：不模拟原始 debug/环境反射与错误位置；`repeat/continue` 跳过条件所用 local 初始化时保守拒绝；不可见/被隐藏元表的 generalized iterator 不属于已支持保证，Roblox executor 尚未实机验证。结构验证不是沙箱或任意输入的语义等价证明。详细限制及 16 MiB/256 registers 等门限见 [`自定义字节码.md`](自定义字节码.md)。

## Anti 状态

按当前要求，`src/anti/` 暂时留空，等待用户提供具体 Anti 实现。
