# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox 方向** 的 std-only Rust 工具链。默认 `virtualize` 已实现真正的 **AST → IR → 自定义 Bytecode → 寄存器 VM**：固定 **32-byte Header**、指令操作数以 **7-bit varint** 序列化（小数值 1 byte，较大值 2~N bytes），独立常量/捕获/prototype。生成器不依赖原生 compiler，不用 `load/loadstring` 委托执行；原生后端只通过 `--backend native` 显式选择。`.obf` 文件保持明文 canonical 格式；生成脚本内嵌的 payload blob 则按已授权的 M6 方案做**字节级传输加密**（seed 派生 Lehmer 密钥流 XOR，提高熵值），运行时由**三个各自验证环境的探针函数**（如 `debug.info(loadstring,"s")`）按 seed 洗牌的顺序交回密钥份额并结合解密。不做压缩容器、随机 section 或随机 opcode；所有脚本生成完后才统一随机一/两字母 local 并输出为单行。

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

默认 AST/v2 路径的 seed **影响最终 local 名称、私有 prototype 字段名、包装方法名/数字键、密钥份额与探针调用顺序及嵌入密文**；解密后的 payload 与 `.obf` 文件本身与 seed 无关、逐字节确定。不做压缩容器或随机 section。显式 `--backend native` 才保留旧 OBF v1 的随机 opcode/dispatcher/数字写法。脚本输出均是单物理行；IR/inspect 报告和二进制文件不适用“脚本单行”的限制。随机短名不是加密，有限名称空间不保证任意两个 seed 都产生不同文本。

## AST 源码前端

`obf::parse(source, target)` 返回公开的 `ast::Chunk`。AST 完全拥有名称及字面量文本，并为 chunk、block、statement、expression、binding、function、table field、attribute 和 Luau type 节点保留原源码的半开 UTF-8 byte span。`obf::check` 保持原来的 `Result<(), Diagnostic>` 验证接口，`minify` 和 VM 路径也继续经过同一解析器。

前端分别执行 Lua 5.1 与 Luau 目标规则。Lua 5.1 覆盖完整核心 statement/expression/function/table 语法；Luau 额外构造类型标注、type alias/type function、type pack、泛型默认值、table access type、if expression、复合赋值、attribute、value export、const、显式 type instantiation 和插值字符串 AST。插值字符串内每个表达式现在由内部词法器/解析器递归构造，并使用全局源码 span，不再作为不透明字符串交给外部编译器兜底。

安全门限为 64 MiB 源码、1,000,000 token、1,000,000 AST 节点和 64 层递归/插值嵌套，以及每层最多 64 次线性运算/后缀链接。后者防止迭代构造的深 AST 在析构时发生栈溢出。公开的 token-array 入口会验证 UTF-8 边界、顺序、EOF、位置和目标，并重新词法化比较，畸形或与源码不一致的 token stream 只返回 `Diagnostic`。针对 Lua 5.1 与 Luau 的 AST 语料分别位于 `tests/fixtures/ast_lua51.lua` 和 `tests/fixtures/ast_luau.lua`。

本轮解析器审计补齐了 contextual `continue`、prefix/suffix 限制、跨行括号调用、Luau 类型断言优先级、方法 `receiver:m<<T>>(...)`、const 初始化/写入检查，以及模块 return/export 冲突。`ExpressionKind::Call.type_arguments` 保存显式方法类型实参；绑定分析记录 `LocalBinding.is_const` 与 `Reference.is_write`，区分修改 const 绑定和修改它引用的表。type function 的签名/函数体/嵌套函数均不得捕获外层运行时 local。

`check` **只检查词法、语法及上述绑定规则，不等价于原生编译成功**；例如 Luau `continue` 跳过 `repeat` 局部初始化的控制流检查、目标寄存器/局部变量资源上限仍由编译器负责。安全限制内的有限差分回归不代表解析器已被证明对任意输入完全正确。`tests/parser_audit.rs` 对固定参考编译器检查接受/拒绝案例、生成式运算符组合和三种压缩配置，并固定记录 parser/compiler 边界。

## 安全压缩、作用域复用与最终随机命名（M3）

压缩采用**分号优先的语句分隔**：例如 `--no-rename` 将 `local a=1 local b=2 return a+b` 输出为 `local a=1;local b=2;return a+b`。

- 完整语句之间，以及非空块最后一条语句与 `end/else/elseif/until` 之间用 `;`，不再用空格作为语句分隔。已有分号不重复，EOF 不额外补分号，空块不插入空语句。
- `local a`、`return a`、`then f()`、循环头、`a and b`、`- -`、数字/点号等语法必需的空格仍保留；不拆开函数表达式与调用后缀，不改表字段分隔、字符串值或字节码。
- 解析器提供完整语句结束位置，覆盖函数表达式、`typeof`、type function 和嵌套插值；改名后重新计算偏移，最终仍重解析并验证绑定。
- 默认 minify、`--no-rename`、低层 token-array API 和两套 VM 的最终输出共享这条规则。即便原先可直接相连的语句也补分号，因此这是分隔策略，不承诺进一步缩小体积；与 bytecode 加密/压缩无关。

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

这条链路**不调用原生 compiler，不存 native word，也不默默 fallback**。新 `ir::Module` 包含函数、常量、cell/upvalue 捕获和带符号后继的基本块；IR 的 branch 生成 `Test + Jump + Jump`。Header 固定 **32 bytes**，含版本、目标、端序、宽度码、文件长度、prototype 数量、入口、ISA 版本和 Adler-32。指令流按每条 opcode 的 Form 列写成 `[opcode][各字段 varint]`（A/AB/ABC/ABx/Ax，2~7 bytes），目标端校验后展开回定长 4-byte 指令串执行。完整逐字段规范与 **49 条 ISA** 见 [`自定义字节码.md`](自定义字节码.md)。

- Lua 5.1：46 个 `src/vm/opcode/lua51/c*.rs`；Luau：49 个 `src/vm/opcode/luau/c*.rs`。每条有效 opcode 有一份独立固定 handler，不以 NOP 代替未实现语义。
- 每 frame 为寄存器文件；local 使用 heap cell，临时值为普通寄存器，闭包引用 cell。循环的新一轮/复用寄存器不会破坏逃逸闭包。
- 显式 pack.n 处理多返回值、尾部 nil、vararg、调用/返回；VM→VM 尾调用替换 frame。支持宿主函数、元方法、回调及 coroutine。
- 两端分别处理赋值/方法求值顺序、numeric-for、表构造器刷新和 Lua51 隐式 `arg`；Luau 另有 `//`、插值、泛型擦除、`__iter`、userdata NAMECALL、精确 i64 及冻结导出表。
- Rust reader 与生成的 decoder 都做范围/格式验证；文件内指令流为 7-bit varint byte string，目标 decoder 校验 canonical 编码并展开回定长指令串，执行时每步 fetch 4 bytes，不是源码 table 中的伪字节码。
- **整体输出包装**：chunk 只有两条语句——`local x={}` 与 `return setmetatable({...},x):m()`。全部 VM 代码以**多个函数**的形式存放在载荷表内：5 个随机数字键 section 函数（宿主捕获预导、bytecode decoder、操作数校验、运行时辅助、解释器簇）+ 1 个随机单字母字符串键的入口方法。`:m()` 直接命中载荷表自有键进入入口函数，按顺序串联各 section 并返回程序结果；chunk 真正读取 `...` 时调用写为 `:m(...)`。方法名与数字键来自独立 seeded 随机流；不改 bytecode、最终 local 或私有字段名。

### 运行语义兼容性增量

已修复 Luau callable iterator、`__iter` 原始查找/false 处理、常用闭包共享与递归身份差异；增加运行时捕获裁剪、只读标量传播与可达性分析，原先因死分支 `continue` 被拒绝的一批合法源码现在可执行。Lua51 的已有赋值/数值/闭包语义仍单独回归。

默认产物为 **OBF v2 / ISA 修订 2**，只增加经过双侧验证的闭包共享 metadata，Header/指令宽度/49 个稳定编号不变。**修订 1 仍可读取、执行、原样序列化**，CLI 显示实际文件版本。

“运行输出与原始源码一致”的支持条件、测试证据与已知反例边界见 [`虚拟机兼容性.md`](虚拟机兼容性.md)。有限差分不能推出任意源码等价，也不能把 opcode 覆盖率当作语言兼容率。

Rust API：`ir::compile/lower`、`bytecode::custom::{encode,decode,serialize}`、`vm::custom::{compile,emit}`，以及默认 `vm::virtualize`。`inspect-bytecode` 自动区分 OBF v2 与原生 chunk；`wrap-bytecode` 可把已保存的 `.obf` 独立包装为 VM。

所有 decoder、runtime、dispatcher、handler、静态方法适配器和执行尾部组装完后，自定义 VM 先缩短私有字段，再调用一次私有 `minify::finalize_vm` 统一随机 local、分号分隔和单行化；之后不追加代码。重解析复核绑定图、同域唯一性、名称长度、确实换名和解密后 bytecode 字节不变。生成器环境例外仍严格审计：`local G=(getfenv and getfenv(0))or _G`，加上三个 payload 密钥函数内**形状完全固定**的环境探针（Luau `debug and debug.info(loadstring,"s")` 结果须为 `"[C]"`；Lua 5.1 `debug and debug.getinfo(loadstring,"S")` 须 `what=="C"`）。探针不通过则静默中止、无任何输出；没有公开忽略反射的开关。

### 嵌入 payload 传输加密（M6 已授权部分）

- 生成时用 seed 派生的 **Lehmer 密钥流（48271 mod 2147483647）** 对内嵌 blob 逐字节 XOR，密文字节分布均匀（Shannon 熵 > 7.5 bits/byte，测试断言高于明文）；所有中间量 < 2^53，Lua 双精度与 Rust 逐位一致。
- 密钥 **动态生成、零字面量**：三个份额不在脚本中存储，由每个探针函数在运行时从脚本自身结构（入口传入的 payload 表数字键对 `(a,b)`：`x=(a*31+b)%2147483647` 再叠 3/5/7 轮 `x=48271*x%2147483647` 步进）计算得出；探针通过后才计算并返回份额。
- **常量池独立加密（第二层）**：嵌入镜像中每个常量记录的 payload（布尔值字节、数字/整数 8 字节、字符串内容）在外层加密之前，再用**另一把结构密钥**（不同 wrapper 键对 + 11 轮步进 + 长度混合）单独 XOR；字符串长度保留明文作框架元数据。剥掉外层密文后常量仍是密文；密钥同样零字面量。
- **base86 传输层 + 分段打乱**：双重加密后的镜像整体 base86 编码（86 个可打印字符、约 1.25 字符/字节，比 4 字符十进制转义便宜得多），切成三段并按 seed 洗牌分放到三个 `[数字]=function` 分段函数；**每个分段函数先重跑 loadstring 原生探针再解码自己的分段**（连同份额探针共 6 个探针函数）。验证侧 `extract_embedded` 通过试全部 6 种段序 + 全镜像 Adler-32 找出唯一有效顺序——顺序本身不在脚本中存储。
- **固定水印 `XXS:` + 隐藏式双函数检测**：base86 流解码后的前 4 字节固定为 `XXS:`（明文传输水印）。检测被拆成两个 payload 函数：一个通用的大端 4 字节打包器 + 一个不透明 u32 常数比较器——两个函数都不出现 "XXS:" 字样，脚本全文亦无该字符串（测试断言）；不匹配即静默中止。水印同时把“哪个段是流首段”钉死，加强段序判定。
- **M7 结构随机化（不含外层包装变体）**：seed 驱动的等价结构变体进入默认 v2 路径——① F3 校验与 F5 解释器的每条 opcode dispatch 随机取四形态之一（`o==K`/`K==o`/`not(o~=K)`/`o-K==0`，复用旧后端已审计的变体机）；② 整数边界检查随机取三形态（`x>K`/`K<x`/`not(x<=K)`，操作数恒为整数，无 NaN/元方法语义）；③ 元方法 dispatch 分支变体（Call 包装器缓存分支反转、userdata 守卫等值序翻转，均为纯控制流/字符串原比较等价）。另有**性能基准与体积预算**：`tools/bench-vm.sh` 进入矩阵，golden 体积硬上限 24,000/26,000 B、VM 单次运行灾难阈值 1500ms（当前 10-12ms，约为原生 4-5×）。
- **不透明真假分支（M7 第二批）**：入口方法体整体包进 `if <恒真式> then 实际链 else 不运行的真指令 end`（或 seed 翻转的 `if <恒假式> then 诱饵 else 实际链`）；F3/F5 dispatch 链尾部各加 2 条**永不可达的死 elseif 臂**（比较 200..254 的不可能 opcode 号，同样随机取四拼写），臂内是逼真但绝不执行的真指令。诱饵分支由构造保证死路：F3 的 FM 门在 dispatch 前拒绝未知 opcode，入口守卫是常数恒真/恒假式；全部原生/VM 差分证明它们从不执行。
- 入口按 **seed 洗牌的顺序**调用三个函数并传入各自的结构键对，decoder 段以 `1+(s1+s2+s3+31*#B)%2147483646`（混入密文长度）重建密钥流解出明文 payload，再做原有的 magic/Adler/结构校验；份额与密钥流初态的十进制串不出现在脚本任何位置（单元测试逐 seed 断言）。`.obf` 文件与 `compile` 输出保持明文 canonical、与 seed 无关；`vm::custom::decrypt_embedded` 提供验证助手。
- 这是提高静态分析成本的混淆层，**不是密码学加密**；密钥派生自 seed，不能抵御持有脚本的攻击者。

**VM 私有字段也压缩为一/两字母**：`code`、`tags`、`parent`、`flags`、`shared`、`self`、`cached` 及原有短字段共 14 个，当前全部可分配为互不冲突的随机单字母。decoder、校验器、运行时、缓存和 opcode handler 的构造/读/写共用同一映射；同 seed 复现，使用独立随机流，不改变既有 local 名称或 bytecode。

这是 crate-owned、不会逃逸的 prototype schema 的专用处理，**不是任意 `.field` 文本替换**。模板通过私有标记明确授权，词法 token/span 改写后复核所有未标记 token 和字面量不变；用户 table 字段、导出键、字符串、`string.byte` 等宿主 API、`__mode/__iter` 等元方法及 `object:code()` 等 NAMECALL 名称不改。普通 `minify` 不启用这项私有字段策略，显式旧 native backend 保持原行为。

### 显式兼容后端

`virtualize --backend native` / `vm::virtualize_native` 保留原来的 `compiler → native reader → OBF v1`。旧根目录 `lua51_*.rs`（38）与 `luau_*.rs`（91）不移动、仍单独测试。只有这个后端使用旧 13-byte Header、6-byte `u16 private-opcode + u32 native-word` 及随机布局。

旧 backend 的 compiler 查找依次为 `OBF_LUAC51` / `OBF_LUAU_COMPILE`、仓库 `toolchains/bin`、`PATH`。默认 AST 后端在这些变量指向不存在文件时仍可正常编译/生成；原生工具仍用于门禁的语法/运行对照。

### 已提交示例

| 文件 | 来源 | seed | v2 bytecode | 最终单行脚本 |
|---|---|---:|---:|---:|
| `vm_lua51.out.lua` | `tests/fixtures/vm_lua51.lua` | 7001 | 5,525 B | 21,401 B |
| `vm_luau.out.lua` | `tests/fixtures/vm_luau.lua` | 7351 | 6,575 B | 23,647 B |

生成器、命名或分隔策略变更后必须再生成两份示例。矩阵比较默认生成、独立 compile/wrap、debug/release 及 golden 的逐字节一致性。本版优先完整可执行与格式清晰，不声称体积比旧 native backend 更小。

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
3. 检查原生 chunk，同时验证 OBF v2 Header、varint 指令流、截断、字节损坏、恶意结构、round-trip 与资源上限；
4. 对 v2 执行逐 opcode fetch-loop 覆盖：**Lua51 46/46，Luau 49/49**；不是只数未执行的指令；
5. 编译/执行每份 VM seed 变体，确认单行、不委托 loadstring、没有生成器错误消息、所有显式 local 最后才改名且 payload 字节不变；
6. 检查新目标目录的 46/49 个 handler 和旧兼容目录的 38/91 个 handler；
7. 独立执行 `dump-ir → compile → inspect → wrap`，证明缺少原生 compiler 也能生成默认 VM；
8. 比较 debug/release 的 binary 和 VM、默认虚拟化与独立 wrap、根目录 golden；
9. 显式执行旧 `--backend native` 的完整语料、多 seed、语法/运行回归，保留其原生 opcode coverage（Lua51 38/38、Luau ≥60）；
10. 额外覆盖多返回值/nil、变量求值时机、闭包、循环、20k 尾调用、coroutine/回调、i64、导出模块、userdata NAMECALL、GC 及 CLI 失败不覆盖文件；
11. `tests/semicolons.rs` 检查双目标语句分隔、必需空格、调用后缀、嵌套函数/类型/插值、字符串字节、已有分号、空块、非法源码、CLI/两 VM 后端；内部测试覆盖所有语料的边界完整性、改名偏移、幂等性和 10,000 相邻块；
12. `tests/vm_parity.rs` 的 145 个生成式组合及应用式语料检查求值顺序、闭包身份、迭代器、捕获、返回值/模块和控制流；额外执行应用语料的 debug/release binary/VM 与原生 stdout 对照，检查修订 1 兼容性；
13. `tests/private_fields.rs` 与私有字段内部测试检查 14 字段双射、单/双字母池、关键字/冲突/越界拒绝、marker-like 用户方法名、公开字段/导出保护、CLI/修订 1 包装，以及字段之外的全部 token/变量名/字面量和 payload 不变。

`tests/scope.rs`、`tests/scope_reuse.rs`、`tests/random_names.rs`、`tests/safe_minify.rs` 及内部 VM 测试还覆盖：所有可改名 local 的 `[a-z]{1,2}`/同域唯一性/换名断言，短名跨域复用、闭包读写、声明时序、原先遮蔽的声明、参数/body 共域，多步匹配修复、小图穷举重解析、工作门限、名称池耗尽、CLI seed 报告/复现/参数拒绝/失败不覆盖文件，并发新 seed，以及原有绑定、类型、元方法、插值、变参和超长链回归。原生运行差分包含 seed `0`、`1`、`0x735`、`u64::MAX`；650 个已是单字母的 locals 也经过双目标编译/运行；10,000 个相邻块加一个累计变量的压力测试安全复用两个单字母名，另有 96 种生成式遮蔽/初始化程序的双目标多 seed 运行差分。

2026-09-06 VM 私有字段压缩后的完整矩阵 **PASS 149**（40 单元 + 109 集成）：此前 140 项全部保留，新增 4 项内部和 5 项集成测试。原生/VM 输出、debug/release、两套后端及 46/49 实际执行覆盖均通过。两份示例分别减少 **164 / 159 B**，除私有字段外所有 token（含原 seed 的 local 名称和字面量）完全一致，内嵌与独立 bytecode 逐字节不变；seed 现在控制最终 local 与私有字段名，不控制 v2 binary。

2026-09-06 输出整体改为 `local x={};return setmetatable({...},x):m()` 的分函数载荷形式后的完整矩阵 **PASS 150**（41 单元 + 109 集成）：此前 149 项全部保留，形状/差分单元测试改为断言新结构。默认后端与 `wrap-bytecode` 的全部代码位于载荷表的 5 个随机数字键 section 函数与 1 个随机字母键入口函数中；环境捕获审计下降到各 section 函数体内执行，根表检查允许数字/字符串键函数字段。两份示例相对私有字段批次各增加 **484 B**；seed 额外控制包装方法名与数字键。旧 `--backend native` 输出保持原状。

2026-09-06 嵌入 payload 字节级加密 + 三探针密钥拆分后的完整矩阵 **PASS 153**（42 单元 + 111 集成）：此前 151 项全部保留，新增 1 项密文熵值/解密等价单元测试与 1 项环境篡改 fail-closed 集成测试（Lua51 替换 `loadstring`、Luau 经 `setfenv` 注入，脚本必须无输出中止）。内嵌 blob 为 seed 派生 Lehmer 密钥流密文（熵 > 7.5 bits/byte），三个 payload 函数各先验证环境再交回密钥份额，调用顺序 seed 洗牌，decoder 结合解密后走原有校验；`.obf` 文件与解密后 payload 逐字节不变。golden 为 **27,223 / 30,888 B**。同日后续把密钥改为**结构动态推导**（份额由表键对+密文长度运行时计算，密钥零字面量，逐 seed 断言份额与初态的十进制串不出现在任何数字字面量中）达 **PASS 154**；再为常量池加独立第二层加密（常量在外层密文内仍是密文、长度保留框架明文、双新单元测试 + 破坏性测试改为“生成器或目标端二选一拒绝”）达 **PASS 156**；最后叠加 base86 传输层与三段打乱（每段一个探针门控的分段函数，新增 codec 回归）达 **PASS 157**；再加固定水印 `XXS:` 与隐藏式双函数检测（单元 + 集成回归：外科手术式只改水印字节组必须静默中止）达 **PASS 159**；M7 结构随机化（dispatch/边界/元方法分支变体 + 体积预算与基准）再增 2 项单元测试达 **PASS 161**；不透明真假分支（入口包装 + 永不可达死臂，两种用户指定形态）再加 1 项单元测试达 **PASS 162**（49 单元 + 113 集成），golden 21,401/23,647 B。生成器环境审计扩展为“1 个 getfenv 捕获 + 恰好 3 个固定形状探针”；矩阵的 loadstring 检查改为只匹配调用、blob 检查改为包装形状，Luau 二进制字面量检查收窄到 legacy（语法由 `luac5.1 -p` 全量保证）。

2026-09-06 指令序列化改为 7-bit varint 后的完整矩阵 **PASS 151**（41 单元 + 110 集成）：此前 150 项全部保留，`custom_bytecode` 新增 1 项 varint codec 回归（canonical/非最小编码、字段上限、带外 code 字节数、尾随字节、varint 截断与逐 Word 语义拒绝）。文件内指令按 Form 列写成 `[opcode][字段 varint]`（2~7 bytes），prototype header 追加 `code_byte_count`（20→24 bytes），Header 宽度码改为 `0`；目标 decoder 校验后展开回定长 4-byte 指令串，fetch-loop/handler/ISA 编号完全不变。两份示例 bytecode 缩小 **19.7% / 20.4%**（6,879→5,525 / 8,257→6,575 B），脚本 33,316→29,356 / 34,066→28,729 B；ISA 修订 1/2 语义、46/49 执行覆盖、debug/release 一致性不变。

VM 覆盖 fixture 位于 `tests/fixtures/vm_lua51.lua` 与 `tests/fixtures/vm_luau.lua`，包含闭包/upvalue、vararg、多返回值、调用、循环、泛型迭代、table、元表/方法、分支、算术以及 Luau 专属语法路径。

## 当前边界与后续工作

默认 AST/IR/v2 register VM、独立 reader/encoder、完整 ISA 与最终随机短名已可运行。后续优先扩展语义/压力差分、寄存器/pack 的体积和运行开销、IR 数据流验证及宿主接口边界；按本次要求，暂不推进复杂加密、压缩、随机 section 或多模板随机化。

当前限制必须保留：不模拟原始 debug/环境反射与错误位置；消除已证明的死路径后，仍对可能跳过条件所用 local 初始化的 `repeat/continue` 保守拒绝；隐藏元表、GC/分配时机、含洞 table 的 `#` 和布局敏感遍历不属于完全等价保证，Roblox executor 尚未实机验证。原生所有优化相关的函数身份也尚未完整模拟。结构验证不是沙箱或任意输入的语义等价证明。详见 [`虚拟机兼容性.md`](虚拟机兼容性.md) 和 [`自定义字节码.md`](自定义字节码.md)。

## Anti 状态

按当前要求，`src/anti/` 暂时留空，等待用户提供具体 Anti 实现。
