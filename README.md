# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox 方向** 的 std-only Rust 工具链。默认 `virtualize` 实现 **AST → IR → 自定义 Bytecode → 寄存器 VM**：公开 `.obf` 固定 32-byte Header 与 canonical ISA2/7-bit varint，保持明文且与 seed 无关；生成脚本则降为 seed-specific **private ISA15**。ISA14 在 ISA12-A 每 prototype 异构 operand ABI（4 种物理 record family、3 种分量旋转与 2,731 个稀疏 lane，32,772 个无碰撞 profile 覆盖 32,767 prototype 上限；四种轮换返回绑定，无 canonical `6+3*i` bridge 或实际 opcode 标记）、ISA12-B per-prototype register ABI（模 `4×127×257=130,556` 的 family/stride/shift profile，逻辑 `0..255` 单射到四个互斥 257-key bank，每 frame 推导一次，不输出 256 项映射表）与 ISA12-C carried-value fusion（仅安全相邻项生成 `RF(index,target,value)` 转发的 2-op fragment，保留 `nil/false`；不安全/多写/控制项保持单 fragment；入口为六状态 seed-shuffled stage graph）之上，进一步去除 parser 字段顺序的自文档化：record header 的 4 个 u16 槽位按每 prototype 的 factorial 置换（`(pid×M+A)%24`，M 与 24 互素）重排，segment 的 3 个 token 按每 segment 的 factorial 置换（`(slot×M+A)%6`）重排，两端用同一 id/slot 实时重算；dictionary entry header、prototype metadata 的 u32×4/u16×3/u8×2 宽度组与内存 record tuple 槽位则用 per-image 置换直接 baked 进生成 parser 文本。ISA14 再把 capture/constant 从 header 后连续区移入两个全局洗牌池，每记录携带掩码 owner/slot/index/tag token 并按 per-record factorial profile 重排匿名槽位，parser 先读池后按 prototype 切片。固定宽度的 slot 读取位置不变，只有语义归属按 profile 变化，错序触发既有 label/token/operand/count 门 fail closed。ISA15 再把 transport 换成逐 image 混合 base86（4-char 长度前缀、链式 4/5/6-char 组、随机高位填充、VAL 表解码，字母表为 28..=126 的逐 image 86 子集），随后仍按 `bounded LZW → inner ChaCha8 → strict frame v2 → outer ChaCha8 → 混合 base86 三段` 交付。ChaCha8 使用标准 IETF 256-bit key/32-bit counter/96-bit nonce 布局与 8 rounds；目标端字运算按目标分叉——Lua 5.1 用纯算术多态工具箱，Luau 用经隐藏名池捕获的 `bit32`/`buffer` 多态工具箱（每操作 3 种结构变体、hot xor/rotate 双闭包；模数拼写与求和项序逐 use-site 抽取）——并拆成 32-bit XOR/rotate、quarter-round、block、KDF/stream、anti-hook 五个随机数字键 sibling fields，随全部 payload fields 全局洗牌。最终 key/nonce/counter 由三个运行时 source-witness shares、重建的 `pv`、domain/context 和 anti-hook attestation 经 ChaCha8 block 动态派生，不作为脚本字面量保存；外/内两次解密前都执行 anti-hook，检查关键 native source、generated helper 同源、基础 primitive 行为和 ChaCha8 known-answer test，任一异常在 frame/LZW/semantic parser 与用户代码前 fail closed。该设计仍是可逆混淆：ciphertext、decoder、salt、register/dataflow/field-order profile 与规范环境都随客户端交付，持有完整脚本者仍可执行或精确模拟恢复；ISA15 已削弱统一 record/segment/dictionary/metadata 字段顺序、per-prototype capture/constant 邻接、`I[2]/I[3]/I[1]` 静态 fetch 锚点、逐 primitive 原始 handler 边界、顶层稳定入口链、transport 固定分组、连续字母表与基数漂亮常数，但 pool token 掩码/置换规则、factorial 置换规则、fusion 条件、`RF`、primitive 运算、parser inverse 与依赖图仍在客户端，不能宣称已解决全部静态语义恢复。K 系列后续批次继续在同一边界上收敛：K7 把目标端字运算分叉为多态工具箱（Lua51 纯算术 / Luau 隐藏名捕获 `bit32`+`buffer`，每操作 3 变体 + hot 双闭包），K8 给每次 fetch 加 per-prototype payload-derived indirect route（第 16 个私有字段 `routes`），K9 对 Form 1–5 的 operand wire value 做 per-lane affine key（Form 4 用模 65536 逆元），2026-09-10 又把 frame v2 的完整性字段从 Adler-32 换成 keyed dual-lane（模 65,521）链式 hash——三者都仍是可逆门，不改变“无客户端秘密”的结论。

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

默认 AST/v2 路径的 seed **影响 ISA13 recipe/token/fragment/segment graph、per-prototype operand/register/dataflow/field-order profile、record/segment factorial 乘加参数、dictionary/metadata/tuple 的 per-image 字段序、capture/constant 池洗牌与池顺序翻转、真实 fusion 的非重叠配对与 fragment binding 顺序、六状态 entry graph、live descriptor camouflage、reachable neutral edge split、深层状态/死臂、prototype/record/field 布局、最终 local/私有字段、包装键、source-witness share 参数、fetch/dispatch control mask、ChaCha8 KDF salts/nonce salts/counter、frame-v2 参数、LZW helper 拆分、探针调用顺序及嵌入密文**；公开 `.obf` 与 seed 无关，但私有 semantic image 与脚本 transport 随 seed 变化且同 seed 确定。LZW 算法及 8 KiB reset 边界、ChaCha8 的标准轮函数固定；salt、context、domain 和运行时 attestation 改变实际 material。显式 `--backend native` 另保留旧 OBF v1。脚本输出均为单物理行；随机短名不是加密，有限名称空间也不保证任意两个 seed 都产生不同文本。

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
- 默认 minify、`--no-rename` 与低层 token-array API 继续在每个已证明的语句边界保留 `;`。只有 crate-owned 的最终 VM 在完成全部组装后启用更紧的可选分隔：当前 token 为块关键字，或前一 token 为 `)`/`]`/`}` 且下一语句从标识符开始时可省略分号；`f();(g)()` 这类歧义调用边界必须保留。最终文本仍重新解析并复核绑定，公共/用户源码不启用这项 private-VM 体积优化。

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
       → 自定义指令选择 / 标签回填 → canonical OBF v2 / ISA2
       → seed semantic lowering（camouflaged descriptor + edge/recipe token + neutral graph）
       → private ISA15（operand/register/field-order ABI + carried-value fragments + segment graph + capture/constant pools
         + K8 per-prototype indirect route + K9 per-lane affine operand value key）
       → bounded LZW → inner ChaCha8 → strict frame v2 → outer ChaCha8 → 混合 base86 三段
       → runtime source transcript + anti-hook attestation → key/nonce/counter + masked fetch/dispatch
       → 目标端 fail-closed 逆序校验 / register VM → 最终随机短名 / 单行化
```

这条链路**不调用原生 compiler，不存 native word，也不默默 fallback**。新 `ir::Module` 包含函数、常量、cell/upvalue 捕获和带符号后继的基本块；IR 的 branch 生成 `Test + Jump + Jump`。公开文件 Header 固定 **32 bytes**，含版本、目标、端序、宽度码、文件长度、prototype 数量、入口、ISA 版本和 Adler-32；canonical 指令流按 Form 写成 `[opcode][各字段 varint]`（A/AB/ABC/ABx/Ax，2~7 bytes）。`compile`/`inspect-bytecode`/`serialize` 仍遵守该公开 ISA2 规范；只有 `virtualize`/`wrap-bytecode` 在生成脚本内部把已验证 Program 重编码为 ISA15 camouflaged-recipe/edge-token/segment-graph/pool，并在目标 parser、frame setup 与 fragment 之间使用 per-prototype operand/register/field-order ABI，严格无损压缩后再进入双 ChaCha8 与 frame v2 transport。完整逐字段规范与 **49 条 primitive ISA** 见 [`自定义字节码.md`](自定义字节码.md)。

- Lua 5.1：46 个 `src/vm/opcode/lua51/c*.rs`；Luau：49 个 `src/vm/opcode/luau/c*.rs`。它们是 primitive 语义模板；生成器先以 lexer token span 处理 register access，再对每个 1~4-op recipe 求最大非重叠安全配对。只有“首操作是单语句 `R[a]` producer、次操作至少有一个可安全转发的 read”的相邻项才形成 2-op fragment：producer 保存一次求值结果并照常写回，consumer 的 read 改走 per-frame `RF` carry；其他项各自成为 1-op fragment。所有 fragment 仍经随机 `sid` continuation 和全局打乱执行，不在 use-site 上放固定 opcode marker，也不为每个 prototype 复制整套 handler。
- 每 frame 为寄存器文件；local 使用 heap cell，临时值为普通寄存器，闭包引用 cell。循环的新一轮/复用寄存器不会破坏逃逸闭包。
- 显式 pack.n 处理多返回值、尾部 nil、vararg、调用/返回；VM→VM 尾调用替换 frame。支持宿主函数、元方法、回调及 coroutine。
- 两端分别处理赋值/方法求值顺序、numeric-for、表构造器刷新和 Lua51 隐式 `arg`；Luau 另有 `//`、插值、泛型擦除、`__iter`、userdata NAMECALL、精确 i64 及冻结导出表。
- Rust reader 先完整验证 canonical `.obf`；semantic lowering 再按 CFG leader 切分（Jump/Test/terminal 不跨 bundle），给 recipe 分配随机非零 u16 ID，把 Jump 目标改为随机 label，并在入口与抽样 next/test 边插入 neutral trampoline。record 的 `next/skip` 槽存放绑定 source/prototype/edge-kind 的三层 token；目标端验证和每次 fetch 都动态解出后继，再把真实后继作为五层 recipe token 的上下文。持久 `code[label]` 不缓存明文 successor；不存在可按 `pc += 4` 排序的内嵌原始指令串。
- ISA12-A 不再把每个 recipe operation 固定写到 `I[6+3*i..8+3*i]`。prototype id 经三个 seed-derived 可逆仿射分量选择 family/rotation/lane；parser 分别写入 packed-u24、反向 AC+B、转置三列或嵌套 tuple，运行时共享 getter 按相同 profile 恢复。全 private prototype id 范围内 profile 不碰撞；四种 getter 返回顺序按 operation 轮换并周期重洗牌。该实现共享 getter/store，不为每函数复制 handler，因此尺寸增长有界。
- ISA12-B 不再让所有 frame 共享逻辑 `R[0..255]` 的物理键。prototype id 的 family/stride/shift 分别运行在模 4/127/257 的可逆仿射周期内，组合周期 130,556；family 选择互斥 257-key bank，域内四种仿射/反向形态均对 256 个合法逻辑寄存器单射。`SETUP` 先建立 frame-local mapper并用它初始化参数及 Lua51 legacy arg/vararg cell；`Clear` 连续区间、numeric-for 的 `a+1/a+2`、动态 `Closure` capture `d[2]`、cell/upvalue/callback/tailcall handler 也经同一 mapper。产物只含常数规模推导公式，不含 256 项 `register_map`。
- ISA14 不再让 record/segment/dictionary/metadata 共用一套固定字段顺序（ISA15 保留）；K8 再给每次 fetch 加一层 per-prototype payload-derived indirect route（新私有字段 `routes`，`%65521` 选表后按 `route_info[pc]` 校验 rid 与 bundle 宽度），K9 对 Form 1–5 的 operand wire value 做 per-lane affine key（runtime 经 `FM[op]` 恢复 Form 后执行 `AK` 逆变换，Form 4 用模 65536 逆元）；2026-09-10 起 frame v2 的 tag 由 Adler-32 改为以运行时 key state 为输入的双 lane 模 65,521 链式 keyed hash（公开 `.obf` 与 LZW header 的 Adler 门不变）；capture/constant 移入两个全局洗牌池（3 匿名 u16 token/记录，per-record factorial profile，池顺序按 image 翻转）。record 4 槽按 `(pid×M+A)%24` 的 factorial 置换逐 prototype 重排，segment 3 token 按 `(slot×M+A)%6` 逐 segment 重排，两端各用 id/slot 实时重算同一映射；dictionary entry header、metadata 宽度组（u32×4/u16×3/u8×2）与内存 tuple 槽用 per-image 置换 baked 进 parser。fetch/validator 的 `I[2]/I[3]/I[1]` 静态下标随 seed 变化，错序在用户代码前 fail closed。
- **整体输出包装**：chunk 只有两条语句——`local x={}` 与 `return setmetatable({...},x):m()`。全部 VM 代码以**多个函数**的形式存放在载荷表内：5 个随机数字键 section 函数（宿主捕获预导、bytecode decoder、操作数校验、运行时辅助、解释器簇）+ 1 个随机单字母字符串键的入口方法。`:m()` 直接命中载荷表自有键进入入口函数，按顺序串联各 section 并返回程序结果；chunk 真正读取 `...` 时调用写为 `:m(...)`。方法名与数字键来自独立 seeded 随机流；不改 bytecode、最终 local 或私有字段名。

### 运行语义兼容性增量

已修复 Luau callable iterator、`__iter` 原始查找/false 处理、常用闭包共享与递归身份差异；增加运行时捕获裁剪、只读标量传播与可达性分析，原先因死分支 `continue` 被拒绝的一批合法源码现在可执行。Lua51 的已有赋值/数值/闭包语义仍单独回归。

默认产物为 **OBF v2 / ISA 修订 2**，只增加经过双侧验证的闭包共享 metadata，Header/指令宽度/49 个稳定编号不变。**修订 1 仍可读取、执行、原样序列化**，CLI 显示实际文件版本。

“运行输出与原始源码一致”的支持条件、测试证据与已知反例边界见 [`虚拟机兼容性.md`](虚拟机兼容性.md)。有限差分不能推出任意源码等价，也不能把 opcode 覆盖率当作语言兼容率。

Rust API：`ir::compile/lower`、`bytecode::custom::{encode,decode,serialize}`、`vm::custom::{compile,emit}`，以及默认 `vm::virtualize`。`inspect-bytecode` 自动区分 OBF v2 与原生 chunk；`wrap-bytecode` 可把已保存的 `.obf` 独立包装为 VM。

所有 decoder、runtime、dispatcher、handler 与执行尾部组装完后，自定义 VM 先缩短私有字段，再由 `minify::finalize_vm` 统一随机 local、安全省略可选分号并单行化；之后不追加代码。最终文本会重解析并复核绑定。验证侧按 `outer ChaCha8 → frame v2 → inner ChaCha8 → LZW` 逆序恢复，并要求结果等于同一 Program/seed 的 deterministic ISA13 semantic re-encode，而非输入 canonical `.obf`。生成器环境例外只允许审计过的 `local G=(getfenv and getfenv(1))or _G` 与 **12 个直接 probe observation**：三个 share probe、三个 segment probe，以及 anti-hook 字段对 `loadstring`、`string.byte`、anti-hook 自身、stream/KDF、ChaCha block、X8 的六次 source 检查。缺少任一项或多出部分集合都会被 scope 计划拒绝。

### 私有 semantic image 与 ChaCha8 payload transport

- **ISA15 私有像 / ISA15 生成结构**：wire schema 继承 ISA12 的 validation-equivalent descriptor、三层 edge token、五层 recipe token、reachable neutral bundle、synthetic subtree、record/prototype 洗牌、cross-prototype two-node code-segment graph、per-prototype operand ABI、无完整映射表的 register ABI、carried-value fragment 数据流与六状态 entry graph；ISA13 再把 record/dictionary/segment/metadata/tuple 的字段顺序逐 seed 重排（record 4 槽与 segment 3 token 用 per-id/slot factorial 置换，dictionary/metadata/tuple 用 per-image 置换）。ISA14 再把 capture/constant 移入全局洗牌池（掩码 owner/slot/index/tag token，per-record factorial profile，池顺序按 image 翻转；header 仅保留 24 字节 metadata，nu/nk 留作池计数）。header revision 升为 15；ISA15 另把 transport 换成逐 image 混合 base86（长度前缀、链式变宽组、随机高位填充、VAL 表解码），错序由既有 label/token/operand/count 门在用户代码前 fail closed。
- **有界无损 LZW**：semantic image 每 8,192-byte 输出重置 dictionary，并保存连续 canonical LSB-first bitstream。16-byte header 为 `LZW\1 | original_len:u32 | bit_len:u32 | Adler32:u32`；完整 frame 不严格小于原像时生成失败。按golden seed的正确比较边界（2026-09-10 实测）：Lua51 seed 7001 `14,073→13,475 B`（含header，减少598 B），Luau seed 7351 `17,763→17,527 B`（含header，减少236 B）。目标端限制原长≤16 MiB、reset≤2,048，并拒绝截断、越界/forward code、非canonical literal、输出越界、非零padding、未完整消费和checksum不符。
- **标准 ChaCha8、两个 domain**：inner domain 只加密 LZW body，clear header 全字段及 body 长度进入 context；frame v2 包住整个 inner frame后，outer domain 再加密 frame 全字节。二者共用标准 IETF state layout，但 domain、context、nonce salt 与 counter 分离，不复用 stream。
- **拆分组合而非单体 decoder**：32-bit nibble-XOR/rotate、quarter-round、ChaCha8 block、KDF/stream、anti-hook 分属 wrapper keys 24..28 对应的五个 sibling fields；实际 numeric keys、字段位置、分隔符和最终 local 名均由 seed 打乱。entry 只在运行时局部组装依赖，LZW 仍独立拆为二或三个字段。
- **运行时动态 material**：三个 `loadstring` source transcript-bound shares、forms 字段重建的 `pv`、outer ciphertext length 或 inner LZW header context、domain 及 anti-hook attestation先构成 base state，再执行一次 ChaCha8 block；其输出前 8 word 为最终 256-bit key，后续 word 形成 96-bit nonce 与 counter。测试扫描最终脚本，禁止 share、frame key、两个 domain 的最终 key/nonce/counter 和 attestation 作为数字字面量泄漏。
- **每次解密前 anti-hook**：outer 和 inner 调用各先独立运行 gate。Lua 5.1 要求关键 native 为 `what=="C"`、`source=="=[C]"` 的规范形式、generated crypto helper 同 chunk；Luau 要求 native source 为 `[C]` 且 generated helper 同源。随后验证 `string.byte/char`、`table.concat`、`math.floor`、X8 的基础行为，并执行 zero-key/zero-nonce/counter-0 ChaCha8 known-answer test（检查 block word 1/8/16）。任一 metadata、primitive、helper 或 KAT 异常立即 `error()`；attestation 同时进入 KDF，错误值即使绕过早期 gate也会导出错误 stream并在下一层失败。
- **strict transport frame v2**：16-byte header 保存动态 descriptor/version、原长、cookie 与 keyed integrity tag，后接 payload 和 0~3 byte deterministic padding。目标端在暴露 inner frame 前检查总长、4-byte 对齐、descriptor、精确 padded length、cookie、tag 与每个 padding byte。该完整性层用于 bounded fail-closed 与损坏检测，并非声称经过密码学证明的 AEAD/MAC。
- **运行时控制依赖保留**：`(c1+c2+c3)%65520` 继续选择两套互异 fetch/dispatch 物理 state，再按模 65,521 掩码表示；wrong witness 同时改变对应 share、control parity、ChaCha material 与 frame key。
- **混合 base86/水印/唯一段序（ISA15）**：`XXS:` 水印加 outer ciphertext 后按字节三等分，每段独立混合 base86（4-char 长度前缀、链式 4/5/6-char 组、随机高位填充），字母表为逐 image 的 28..=126 86 子集，三段按 seed 洗牌放到三个独立字段；基数/字节宽/长度模数全部以不透明加法对隐藏，slot 键避开 85/86、状态号避开 256。每段仍执行 native-loadstring probe。验证侧尝试六种段序，只有通过水印、双 ChaCha8、frame v2、LZW 和 semantic Adler 的唯一顺序可接受。
- **安全边界**：Lua 5.1 走纯算术路径（目标无 bit 库），Luau 走隐藏名捕获的 `bit32`/`buffer` 路径；双目标中间整数保持在 double 精确范围（发射侧 `2^53` 上确界门禁）。专项测试覆盖标准 vector、双 domain round-trip/context 差分、wrong attestation、wrong witness/seed、每个 outer ciphertext byte corruption、native wrapper hook、generated helper tamper、双目标语法/runtime 与 deterministic seed。硬体积预算为 98,000/98,000 B，灾难运行阈值 1,500 ms。
- `.obf`/`compile` 仍是明文 canonical ISA2；`extract_embedded` 返回 body 仍由 inner ChaCha8 保护的 LZW frame，`decrypt_embedded` 返回完整 ISA15 image。客户端同时持有 ciphertext、decoder、salt 和规范 runtime 条件，故可通过执行或精确模拟恢复；这里提高的是静态恢复/hook/tamper 成本，不是服务端秘密、不可逆保护或“已解决全部静态恢复”。

**VM 私有字段也压缩为一/两字母**：`code`、`tags`、`parent`、`flags`、`shared`、`self`、`cached`、ISA12 保留的 control mask、K8 新增的 `routes` 及原有短字段共 **16 个**（`k tags u parent m p flags nu nk nc shared self code cached control routes`），当前全部可分配为互不冲突的随机单字母。decoder、校验器、运行时、缓存和 opcode handler 的构造/读/写共用同一映射；同 seed 复现，使用独立随机流，不改变 bytecode。

这是 crate-owned、不会逃逸的 prototype schema 的专用处理，**不是任意 `.field` 文本替换**。模板通过私有标记明确授权，词法 token/span 改写后复核所有未标记 token 和字面量不变；用户 table 字段、导出键、字符串、`string.byte` 等宿主 API、`__mode/__iter` 等元方法及 `object:code()` 等 NAMECALL 名称不改。普通 `minify` 不启用这项私有字段策略，显式旧 native backend 保持原行为。

### 显式兼容后端

`virtualize --backend native` / `vm::virtualize_native` 保留原来的 `compiler → native reader → OBF v1`。旧根目录 `lua51_*.rs`（38）与 `luau_*.rs`（91）不移动、仍单独测试。只有这个后端使用旧 13-byte Header、6-byte `u16 private-opcode + u32 native-word` 及随机布局。

旧 backend 的 compiler 查找依次为 `OBF_LUAC51` / `OBF_LUAU_COMPILE`、仓库 `toolchains/bin`、`PATH`。默认 AST 后端在这些变量指向不存在文件时仍可正常编译/生成；原生工具仍用于门禁的语法/运行对照。

### 已提交示例

| 文件 | 来源 | seed | v2 bytecode | 最终单行脚本 |
|---|---|---:|---:|---:|
| `vm_lua51.out.lua` | `tests/fixtures/vm_lua51.lua` | 7001 | 5,525 B | **98,889 B** |
| `vm_luau.out.lua` | `tests/fixtures/vm_luau.lua` | 7351 | 6,575 B | **108,938 B** |

脚本 SHA-256：Lua51 `c01c17d47828852a484ff63354decdc53d5049003740b9d8ec6c505053c999b0`；Luau `daa1e765a5e36376e7af703b22fe7a629e238f2dc6dfa2080b50bf5b66c38f6e`（2026-09-10 复核，与当前构建逐字节 `cmp` 一致）。对应公开 `.obf` 仍为 5,525 / 6,575 B，SHA-256 `a33b5dcb81b02d1f9f2e00ce71c10d55706020e2b28fd516fc69f6444bb81140` / `def67d59b5c79832709c4dbaa33293058195c2dc347f9578c8aaf61cd45fa1d7`，自 varint 批次起未变。

生成器、命名或分隔策略变更后必须再生成两份示例。矩阵比较默认生成、独立 compile/wrap、debug/release 及 golden 的逐字节一致性。**压缩大小的唯一硬契约**是：完整 LZW frame（包括 16-byte header）必须严格小于其压缩前 private semantic bytecode；Lua decoder、ChaCha8、anti-hook、包装和最终整份 `.lua` 均不进入该比较。`tools/bench-vm.sh` 的 98,000/98,000 B 仅是独立的整脚本膨胀预算，不用于判断压缩是否成功；不可压缩输入由生成器拒绝。

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

1. 先强制 `src/**/*.rs` 单文件不超过 **80 KiB（81,920 B）**，再运行 Rust 全目标测试、rustfmt 与 debug/release 构建；
2. 对原有 basic/AST/scope/reflection 语料保持双端源码/压缩的语法、运行、seed、反射保留和短名安全门禁；
3. 检查原生 chunk，同时验证 OBF v2 Header、varint 指令流、截断、字节损坏、恶意结构、round-trip 与资源上限；
4. 对 ISA15 fetch 在 ED/RD 动态解出 edge/recipe token 后做运行插桩，再按独立 `sid` fragment graph 展开真实 primitive 序列确认覆盖 **Lua51 46/46、Luau 49/49**；同时证明入口 neutral recipe 实际执行、未引用 poison recipe 不执行、live descriptor 谎报不弱于 45%，并断言每个 2-op fragment 恰有一次 producer carry、至少一次 consumer `RF` read，完整 fixture 的 live fusion 数量超过 poison 上限；
5. 编译/执行每份 VM seed 变体，确认单行、不委托 loadstring、没有生成器错误消息、所有显式 local 最后才改名，并验证 `outer ChaCha8→frame v2→inner ChaCha8→LZW` 逆序结果等于同 Program/seed 的 deterministic semantic re-encode；codec 专项覆盖全部截断、逐 frame byte 损坏、随机畸形 bitstream、dictionary/reset/output/padding/完整消费/checksum 与 incompressible rejection；
6. 检查新目标目录的 46/49 个 handler 和旧兼容目录的 38/91 个 handler；
7. 独立执行 `dump-ir → compile → inspect → wrap`，证明缺少原生 compiler 也能生成默认 VM；
8. 比较 debug/release 的 binary 和 VM、默认虚拟化与独立 wrap、根目录 golden；
9. 显式执行旧 `--backend native` 的完整语料、多 seed、语法/运行回归，保留其原生 opcode coverage（Lua51 38/38、Luau ≥60）；
10. 额外覆盖多返回值/nil、变量求值时机、闭包、循环、20k 尾调用、coroutine/回调、i64、导出模块、userdata NAMECALL、GC 及 CLI 失败不覆盖文件；
11. `tests/semicolons.rs` 检查双目标语句分隔、必需空格、调用后缀、嵌套函数/类型/插值、字符串字节、已有分号、空块、非法源码、CLI/两 VM 后端；内部测试覆盖所有语料的边界完整性、改名偏移、幂等性和 10,000 相邻块；
12. `tests/vm_parity.rs` 的 145 个生成式组合及应用式语料检查求值顺序、闭包身份、迭代器、捕获、返回值/模块和控制流；额外执行应用语料的 debug/release binary/VM 与原生 stdout 对照，检查修订 1 兼容性；
13. `tests/private_fields.rs` 与私有字段内部测试检查 16 字段双射、单/双字母池、关键字/冲突/越界拒绝、marker-like 用户方法名、公开字段/导出保护、CLI/修订 1 包装，以及输入 `.obf` 仍 canonical、最终解压内容严格为 ISA15 semantic image；ISA12-A operand 专项验证 32,767 个 prototype profile 全域无碰撞、4 种 layout/4 种 binding 均出现、旧固定 slot bridge 与实际 opcode marker 消失；ISA12-B register 专项验证 130,556 profile 周期覆盖允许域、每个受测 prototype 的 256 个逻辑槽单射且物理键有界、无完整映射表、全部双目标 primitive `R[...]` token 被 mapper 包裹；ISA12-C 再检查 structural producer/consumer eligibility、carry/read 数量恒等式、四种 frame-family forwarding、entry 第九个状态机与旧线性导出锚点消失，并运行覆盖 `nil/false`、alias、元方法、求值顺序、cells/captures/callbacks/errors；ISA13 字段序专项验证 factorial 全范围置换合法、record/segment 双端重算一致、parser `sont` 顺序与固定测试 seed 期望一致且跨 seed 变化、record-slot/segment-token/dictionary-header/metadata-slot/pool 五类错序在 Lua51/Luau 双目标均无输出拒绝；新增 ISA14 capture/constant 池 corruption 门（掩码/token/profile 合法、池洗牌 coverage、池序翻转一致）；segment 专项检查跨 seed 全局洗牌、ID/owner/next/root/两节点链/完整覆盖，并在 Lua51/Luau 目标端对 duplicate、missing、越界、错误 owner/root、cycle、截断和尾随做用户代码前无输出拒绝；witness/crypto 专项逐 probe 改 transcript，并覆盖 ChaCha8 vector/domain/context、wrong attestation、frame-v2 全 ciphertext byte 损坏、行为等价 native hook 与 helper tamper；双目标均要求 user code 前无 stdout 失败；size 专项分别锁住“LZW完整frame严格小于压缩前semantic bytecode”和独立的98,000/98,000 B整脚本预算；不再以ISA7整文件作压缩判据。

`tests/scope.rs`、`tests/scope_reuse.rs`、`tests/random_names.rs`、`tests/safe_minify.rs` 及内部 VM 测试还覆盖：所有可改名 local 的 `[a-z]{1,2}`/同域唯一性/换名断言，短名跨域复用、闭包读写、声明时序、原先遮蔽的声明、参数/body 共域，多步匹配修复、小图穷举重解析、工作门限、名称池耗尽、CLI seed 报告/复现/参数拒绝/失败不覆盖文件，并发新 seed，以及原有绑定、类型、元方法、插值、变参和超长链回归。原生运行差分包含 seed `0`、`1`、`0x735`、`u64::MAX`；650 个已是单字母的 locals 也经过双目标编译/运行；10,000 个相邻块加一个累计变量的压力测试安全复用两个单字母名，另有 96 种生成式遮蔽/初始化程序的双目标多 seed 运行差分。

当前状态（2026-09-10 复核，HEAD `7106908`）：门数为 **159 单元 + 116 集成 = 275**，实测 **272 绿 / 3 红**。绿门覆盖 Lua51/Luau 原生语法与运行、debug/release、golden 逐字节一致、ChaCha8/anti-hook/corruption、operand/register/field-order ABI、capture/constant pools、dataflow fusion、entry graph、K8 route/K9 affine round-trip、混合 base86 段传输与 **semantic-bytecode→完整LZW-frame strict-smaller**；执行覆盖仍为 Lua51 **46/46**、Luau **49/49**。

**3 个红灯是 2026-09-10 frame-tag 批次留下的，必须先处理**：`heuristic_surface_pins_hold_on_both_audit_configs`（pin 漂移）、`k7_bit_library_names_are_never_spelled`（Luau probe 明文拼出 `buffer|bit32|table.freeze|debug.info`，违反 K7/T7 契约，见 `src/vm/custom/emit.rs`）、`product_text_audit_pins_hold_on_both_goldens`（check1/check9 pin 漂移）。逐条定位与修法见 [`项目交接总结.md`](项目交接总结.md) 第 0.1 节。

整脚本体积门在 K 系列施工期暂停：`OBF_BENCH_SCRIPT_CAP` 默认 98,000 B 已被两份 golden（98,889 / 108,938 B）超出，`tools/test-matrix.sh` 导出 `off` 暂停该门但仍报尺寸；因此裸跑 `cargo test --all-targets` 会多 1 个预算红灯。15-run `tools/bench-vm.sh`（`OBF_BENCH_SCRIPT_CAP=off`）为 Lua51 **383 ms / 191.5x**、Luau **103 ms / 34.3x**——相对 K7 时的 262/91 ms 明显退化，K10 shrink 批必须一并回看。golden 与历史 ISA 的大小关系仅作信息展示，不是压缩验收条件。（K0/K5/K7/K8/K9/K9a 已落地，K9b/K6/K2/K3-FULL/K4 待办，见`总路线.md` §5。）

2026-09-09 P1 seed-ISA逐seed等价变形第五批（11臂臂内变形）完成：52站点表`P5_SITES`（36比较对偶 + 16行内temp-split），覆盖MOV/T/NEW/CALL/BR/RET/STORE/LOAD/IDX/SET全部11个非ALU臂（ALU归B4a，op12体不可达除外）；split安全性由双目标求值序探针钉死（store键先值后、多重赋值/索引从左到右，双端一致），只hoist先求值侧，失败优先级逐位相同；行中性（0行增长，`seed.rs`零改动，80 KiB上限无压力）。门禁先行：双RED（52站点穷举witness落点 + 共享span守恒/单有span XOR/临时量单定义锁，64/16种子）+ 实现内`count==1` fail-closed针 + 变体吞canon组合检查；实现曾一次炸穿28项（S5d缺分号`w7end`语法融合 + S2/S7b覆盖B4b witness），修分号并把T-arm/RET witness换成P5稳定定位子（锁强度不变），另把register-ABI测试的STORE拼写改为XOR双拼写。固定seed golden为84,779/93,688 B（+38/+50），SHA-256见上表，预算维持98,000/98,000 B（8种子实测最坏lua51 85,711 B、luau 94,660 B）；完整矩阵 **PASS239（124单元 + 115集成）**，15-run bench为Lua51 121 ms / 40.3x、Luau 136 ms / 45.3x。

2026-09-09 P1 seed-ISA逐seed等价变形第四批（模板内ALU/操作数链/死临时量）完成：10处ALU站点双形态（比较对偶拼写 + `local uN=x;` temp-split，求值序装饰性互换），20条操作数链按pin规则置换（仅全total操作数或已证数值输入可换序，`tgtc`/`nargs`类型检查置首，refd-head/stix零自由度排除，组合约2^12×6^6×24），6处死临时量`local qN=<digit>;`（≤6行）；三域独立子流（ALU `^6`/链 `^7`/死临时量 `^8`），位于Batch-1结构pass之后、respeller之前，行数断言放宽为base..=base+6（deformer内精确记账）。门禁先行：五门（ALU双形态/链变序/分裂形态/死临时量/插入锁，64种子扫描）+ 数字拼写→值归一化比对锁（respell免疫）；40向量双目标直接差分曾抓到未pin `or` 置换破坏类型收窄（37/40，s6/f1/f2报原生算术错而非seedfail），pin规则修复后转绿。固定seed golden为84,741/93,638 B（+40/+100），SHA-256见上表，预算维持98,000/98,000 B（8种子实测最坏lua51 85,052 B、luau 94,531 B）；完整矩阵 **PASS237（122单元 + 115集成）**，15-run bench为Lua51 122 ms / 61.0x、Luau 134 ms / 44.7x。

2026-09-09 P1 seed-ISA逐seed等价变形第三批（helper/reader发射层）完成：CV/SV在`if cell[2]`与精确`not`取反两形态间翻转（条件与读序列逐路径一致），Luau Lookup方法链按seed置换（方法互斥，等值臂可交换；现有夹具仅1方法，门内自建双方法夹具锁接线），六字节reader（b8/b16/b32/take/str/pos）按seed拓扑序（Kahn+seeded选择）重排发射；四域独立子流（HELPER×3/POOLS×1），其余seed选择逐字节不动。门禁先行：四RED（CV/SV双形态、Lookup变序、reader变序，64种子扫描）+ 双锁（raw接线、链序精确比对）+ 拓扑合法/置换/确定性锁。固定seed golden为84,701/93,538 B（+4/+4），SHA-256见上表，预算维持98,000/98,000 B（8种子实测最坏lua51 85,276 B、luau 94,565 B）；完整矩阵 **PASS232（117单元 + 115集成）**，15-run bench为Lua51 120 ms / 60.0x、Luau 135 ms / 45.0x。P1 item 1三批至此收官：模板/routine/arm/helper/reader五层逐seed变形，跨样本统一指纹打破。

2026-09-09 P1 seed-ISA逐seed等价变形第二批（routine/arm发射层）完成：`routine_lua` 按每槽位独立子流重拼3+位routine字（沿用模板拼写器与round-trip断言），Test臂在`if-elseif`与嵌套`if`两形态间翻转，TailCall臂置换两路动作检查顺序（Jump/Return/默认臂为单语句、无干净等价类，保持固定可grep）；SEEDT/STAB/SEEDH槽位语义固定，不置换。门禁先行：routine跨seed相异/Test双形态/TailCall双序三RED门 + 测试侧独立解析器round-trip锁（全目标全op四种子逐字比对）。bad-kind-tag腐蚀手术改为直接构造`{{7,1,9004000}}`（原`{7,1,8`锚点跨入重拼字，意图不变）。固定seed golden为84,697/93,534 B（-34/+27），SHA-256见上表，预算维持98,000/98,000 B（8种子实测最坏lua51 85,272 B、luau 94,561 B）；完整矩阵 **PASS226（111单元 + 115集成）**，15-run bench为Lua51 119 ms / 59.5x、Luau 134 ms / 44.7x。

2026-09-09 P1 seed-ISA逐seed等价变形第一批（模板层）完成：`seed_loop_lua` 新增 image-seed 参数，模板经 `src/vm/custom/seed_deform.rs` 后处理（12臂op链/13路ALU/8路取值/3路返回/2路跳转置换 + expect三形态 + 十六进制/科学计数数字重拼，五域独立子流，同seed字节确定），打破跨样本统一模板指纹；审计面保持十进制（seedfail码/操作数/燃料预算`100000`豁免）。门禁先行：先提交8种子两两相异+确定性双跑RED门与数字拼写双目标acceptance（GREEN），再实现；every/control/85/40/Jump/sweep/tailcall行为套件全部多seed化。固定seed golden为84,731/93,507 B（+4/+5 B），SHA-256见上表，整脚本预算按变形开销+后续批次headroom调整为98,000/98,000 B（实测8种子最坏lua51 85,274 B、luau 94,531 B）；完整矩阵 **PASS222（107单元 + 115集成）**，15-run bench为Lua51 120 ms / 60.0x、Luau 135 ms / 45.0x。`seed.rs`因80 KiB源文件上限拆出`seed_deform.rs`（拆分前后golden逐字节一致）。

2026-09-09 P0 seed-ISA 第一切片完成 **seed loop + jump/test/return 迁移**：新增 `src/vm/custom/seed.rs`（7-op MOV/T/NEW/ALU/CALL/BR/RET 汇编器、构建期验证器、双目标 `SEED(prog,site,R,RX,K,STAB,SEEDH)` 模板），`emit.rs` 以 dual-form 发射 jump/test/return seed 臂（固定 routine 数据 + 七槽 site `{a,b,c,k,j,skip1,pc}`），hidden 全局池新增 `pcall→PC` 并穿入解释器模块供 CALL 保护调用；wire 保持 private ISA14 不变。固定 seed golden 为 84,626/92,850 B，SHA-256 为 `7469993baba87a364ef60086e65f0c4729f04ce5bfa1c357bb3af32f7105e695` / `0d87bd8afbca99e44c39a199bbdd587e49029e002375741d8bea807e5a4e2481`，整脚本预算按 seed 固定成本 +2% headroom 调整为 87,000/95,000 B；完整矩阵 **PASS214（99 单元 + 115 集成）**，15-run bench 为 Lua51 101 ms / 50.5x、Luau 120 ms / 40.0x。门禁新增 14 项：验证器 36 拒收/14 接纳形状、79 向量双目标直接差分、8 类 routine 腐蚀双目标拒绝、经典控制文本零残留；classic 路径保留作 dual-form 对照，字节打包与 arm 瘦身计划在 slice 4 前落地。

2026-09-08 第九阶段第五个结构子阶段完成 **ISA14 capture/constant pools**：`src/vm/custom/semantic.rs` 把 capture/constant 从 header 后连续区移入两个全局洗牌池（`pools_flipped` 按 image 翻转池顺序），每记录 3 匿名 u16 token 携带掩码 owner/slot/index/tag 并按 per-record factorial profile 重排，header 仅保留 24 字节 metadata；`emit.rs` 目标 parser 先验证两池再按 owner 切片，`CU/CK` 经 `slot_rewrite` g-slots 共享。record/segment factorial、dictionary/metadata/tuple per-image 置换、operand/register ABI、fusion/entry、LZW/ChaCha/frame-v2 全部保留；wire/header 升为 private ISA14。fixed-seed golden 为 **81,515/89,777 B**，SHA-256 为 `d6392170a448f3e400ea5786920f5517e00dd80cbd96a030149f3bed93154eee` / `ca21e582f5d3cbcb24eb0646728ed200f2b2fb163bb0421bbc2f73852dfacde1`，位于独立 85,000/94,000 B 整脚本预算；完整矩阵 **PASS200（85 单元 + 115 集成）**，15-run bench 为 Lua51 102 ms / 51.0x、Luau 122 ms / 40.7x。边界：池掩码/置换规则与全部 inverse 随脚本交付；未做函数结构变换，不得宣称不可逆或静态恢复已解决。

2026-09-08 第九阶段第四个结构子阶段完成 **ISA13 parser field-order de-canonicalization**：`src/vm/custom/lowering.rs` 新增 `FieldLayout`/`field_perm`/`emit_field_perm_lua`——record 4 槽按 `(pid×M+A)%24`、segment 3 token 按 `(slot×M+A)%6` 的 factorial 置换逐 id/slot 重排，乘子固定在与阶乘互素的候选集内保证全范围滑窗覆盖 24/6 种顺序；`semantic.rs` 编码侧、validator、`minfo`、`seg`、`__obf_proto_` tuple 与 fetch 文本按同一 profile 逐项重算，dictionary/metadata/tuple 则把 per-image 置换 baked 进 parser，Lua 侧用新 `sont` helper 做 keyed 字段查找。固定宽度与 opcode/edge/recipe 语义不变，错序由既有门 fail closed。新增2项测试：结构单元固定 parser 字段序并证明跨 seed 变化，双目标集成对 record-slot/segment-token/dictionary-header/metadata-slot 四类错序（checksum 修复后）均要求无输出拒绝。完整矩阵 **PASS192（77 单元 + 115 集成）**；golden为 **79,426/87,873 B**，SHA-256为`f6ece30c4bbdea852a8fd365d8902a1285d03618c7e0d1636469443f6904bd92` / `d5980b569759fead1099e88802890373328528d2bb281c21162fdb89c2ea49c8`，bench为98/116 ms。wire升为private ISA13，factorial 置换规则与全部 inverse 仍随客户端交付；这不是不可逆保护，也没有完成captures/constants全局池或函数结构变换。

2026-09-08 第九阶段第三个结构子阶段完成 **ISA12-C carried-value dataflow fusion + entry stage graph**：`src/vm/custom/lowering.rs` 对 crate-owned handler token 做受控结构分析；首项仅接受单语句 `R[a]=expr`，次项只接受单赋值或不直接改 register slot 且至少含一个 read 的形态，control、多写、嵌套 `R[R[..]]` 等退回 single fragment。planner 在最长4项 recipe 上枚举最大非重叠配对；每个 pair 先保存逻辑目标/物理key/一次求值结果并保持写回，再把 consumer read 改为 `RF(index,target,value)`，四个 register family 分别使用逻辑相等、反向条件、物理key相等与shifted-mod-257相等，完整保留 `nil/false`，且不复制 per-prototype handler。原 entry 的稳定线性 stage 接线改为六状态、分支序和比较拼写随 seed 的 graph；依赖顺序仍严格。新增1项结构单元和1项双目标集成差分，完整 fixture sampled seeds 每份产生50~60个 fused fragments（65~85个 forwarded reads），超过四个 poison recipe 可承载的上限，证明 live recipe 路径实际使用。完整矩阵 **PASS190（75 单元 + 115 集成）**；golden为 **78,706/87,167 B**，SHA-256为`a9ef0ee9782615c9ca2eaa5c7b5a36aaa83b8e0900fc37ec0f47b1b9db26477b` / `d43482096f2bb4f9f89e69f0607f4c508a4d82b5498c5d65a1ff8b689967c68a`，bench为96/117 ms。wire仍是private ISA12，所有fusion规则、`RF`、parser字段语义和inverse均随客户端交付；这不是不可逆保护，也没有完成constants/captures全局池或函数结构变换。

2026-09-08 第九阶段第二个结构子阶段完成 **ISA12-B per-prototype register ABI**：`src/vm/custom/lowering.rs` 从独立 seed stream 生成 family/stride/shift 仿射参数，模数 4/127/257 的组合周期为 130,556，覆盖 32,767 个 private prototype id 且 profile 不碰撞。四个 family 使用互斥 257-key bank和不同域内仿射/反向公式，把合法逻辑寄存器 `0..255` 单射为物理键；每 frame 只派生一次 mapper，不输出 256 项映射表。生成器通过 lexer token span 把全部受控 primitive 模板的 `R[index]` 降为 `R[RX(index)]`，自然覆盖连续 `Clear`、numeric-for 相邻槽和动态 `d[2]` capture；`SETUP` 的参数及 legacy vararg cell也使用同一 ABI，不复制 per-prototype handler。专项静态/唯一性/seed/双目标语法与 runtime 回归新增 2 项，完整矩阵为 **PASS188（74 单元 + 114 集成）**；golden为 **74,540/83,040 B**，SHA-256为`927b84824299ab9a45df3a5aad3db67d016ed11a7ab31bc2155ea1029e4e7dd1` / `135514905e4e101cc282b0d58b098426fb2dc2bee5a9e4424bb46113685f758c`，bench为96/115 ms。本批仍保留可逆 mapper与可读 primitive 运算结构；真正跨 primitive dataflow fusion、parser入口去自文档化、captures/constants全局池和函数结构变换尚未完成。

2026-09-08 第九阶段升级 private ISA12（ISA12-A operand ABI 首个子阶段）：新增 `src/vm/custom/lowering.rs`，由 seed 派生 family/rotation/lane 三个仿射分量。模数 4、3、2,731 两两互素，组合周期 32,772，覆盖 private image 32,767 prototype 上限且 profile 全域不碰撞；四种 record family 分别使用 packed-u24、反向 AC+B、转置三列与嵌套 tuple。目标 parser 直接按 profile 写入，validator 和 runtime fragment 经共享 `OG` 恢复；fragment 的五返回值使用四种绑定顺序，按 operation 轮换且每周期重洗牌。旧 `I[6+3*i..]` bridge 和 `o=<actual opcode>` 赋值删除，没有复制 per-function handler。新增双目标、多 seed、full-range profile、layout/binding、旧静态锚点消失和 payload round-trip 门。该阶段当时只切断统一 operand-slot→handler 桥；register ABI与handler register-access lowering已由上列ISA12-B补齐，真正跨 primitive dataflow fusion仍须后续推进。

2026-09-08 第八阶段升级 private ISA11：用两个 domain-separated 标准 ChaCha8 pass 替换旧 inner/outer custom XOR streams，并为回收 decoder 体积移除 generalized Feistel，仅保留升级后的 strict frame v2。目标实现拆为五个随机 sibling fields；KDF 由 runtime shares、`pv`、domain/context 与 anti-hook attestation 经 ChaCha8 block 生成最终 key/nonce/counter，最终 material 不写入脚本字面量。outer/inner 每次解密前运行 anti-hook：source metadata、helper 同源、primitive behavior 与 published zero-state KAT 任一不符即 fail closed。新增标准 vector、双 domain/context/material 差分、wrong attestation、全 ciphertext byte corruption、native wrapper hook 和 helper tamper 门；Lua 5.1/Luau 共用纯算术路径。该升级提高恢复与 hook 成本，但 ciphertext 与 decoder 同时交付，仍不创造客户端秘密或不可逆保护。

2026-09-08 第七阶段升级 private ISA10：三个 share 从“仅 wrapper key + seeded rounds”改为额外折叠目标运行时 `loadstring` source transcript；Rust 只按规范 Lua51/Luau transcript 加密，错误 transcript 使 outer/block/frame fail closed。解释器以 share 和模 65,520 建立 runtime mask，parity 选择双物理 fetch/dispatch state，再按模 65,521 表示和比较；关键路由不再只依赖 seed 常量，也不是统一可约平移。final fragment 的公共回边集中到一个出口。新增逐 witness/share/control/parity/block 差分与“仅 hook 前三次 source、后三次 segment probe 正常”的双目标回归。`src/vm/custom/tests.rs` 按永久 80 KiB 源文件规则拆成三份 include 子文件，拆分前后 ISA9 golden 逐 byte 相同；矩阵新增全 `src/**/*.rs <= 81,920 B` 门。该批不创造客户端秘密：静态恢复仍可通过执行或精确模拟规范 transcript 与完整 dataflow 完成。

2026-09-06 VM 私有字段压缩后的完整矩阵 **PASS 149**（40 单元 + 109 集成）：此前 140 项全部保留，新增 4 项内部和 5 项集成测试。原生/VM 输出、debug/release、两套后端及 46/49 实际执行覆盖均通过。两份示例分别减少 **164 / 159 B**，除私有字段外所有 token（含原 seed 的 local 名称和字面量）完全一致，内嵌与独立 bytecode 逐字节不变；seed 现在控制最终 local 与私有字段名，不控制 v2 binary。

2026-09-06 输出整体改为 `local x={};return setmetatable({...},x):m()` 的分函数载荷形式后的完整矩阵 **PASS 150**（41 单元 + 109 集成）：此前 149 项全部保留，形状/差分单元测试改为断言新结构。默认后端与 `wrap-bytecode` 的全部代码位于载荷表的 5 个随机数字键 section 函数与 1 个随机字母键入口函数中；环境捕获审计下降到各 section 函数体内执行，根表检查允许数字/字符串键函数字段。两份示例相对私有字段批次各增加 **484 B**；seed 额外控制包装方法名与数字键。旧 `--backend native` 输出保持原状。

2026-09-06 嵌入 payload 字节级加密 + 三探针密钥拆分后的完整矩阵 **PASS 153**（42 单元 + 111 集成）：此前 151 项全部保留，新增 1 项密文熵值/解密等价单元测试与 1 项环境篡改 fail-closed 集成测试（Lua51 替换 `loadstring`、Luau 经 `setfenv` 注入，脚本必须无输出中止）。内嵌 blob 为 seed 派生 Lehmer 密钥流密文（熵 > 7.5 bits/byte），三个 payload 函数各先验证环境再交回密钥份额，调用顺序 seed 洗牌，decoder 结合解密后走原有校验；`.obf` 文件与解密后 payload 逐字节不变。golden 为 **27,223 / 30,888 B**。同日后续把密钥改为**结构动态推导**（份额由表键对+密文长度运行时计算，密钥零字面量，逐 seed 断言份额与初态的十进制串不出现在任何数字字面量中）达 **PASS 154**；再为常量池加独立第二层加密（常量在外层密文内仍是密文、长度保留框架明文、双新单元测试 + 破坏性测试改为“生成器或目标端二选一拒绝”）达 **PASS 156**；最后叠加 base86 传输层与三段打乱（每段一个探针门控的分段函数，新增 codec 回归）达 **PASS 157**；再加固定水印 `XXS:` 与隐藏式双函数检测（单元 + 集成回归：外科手术式只改水印字节组必须静默中止）达 **PASS 159**；M7 结构随机化（dispatch/边界/元方法分支变体 + 体积预算与基准）再增 2 项单元测试达 **PASS 161**；不透明真假分支（入口包装 + 永不可达死臂，两种用户指定形态）再加 1 项单元测试达 **PASS 162**；全代码随机化（payload 字段整体 seed 洗牌：每个解密/探针/分段/水印函数的表内位置逐 seed 变化；加密参数 seed 派生：Lehmer 乘子 16807/48271/65539、混合常数 31/33/37/41、探针与常量轮数逐 seed 变化，双端同 seed 字节复现）再加 1 项单元测试达 **PASS 163**；特征拆分隐藏（操作数验证器一分为三：形态表改为 per-seed 旋转打包串的独立重建字段、varint 读取+操作数形状链独立成解码字段、逐 opcode 边界臂独立成验证字段，三字段随全代码随机化落入随机表位）再加 1 项单元测试达 **PASS 164**；随机 opcode 重编号（canonical ISA 编号只保留在 `.obf` 与加密 varint 流内，脚本侧 F3/F5 分派与边界臂全部改跑 per-seed 单射重编号：64 槽位经 seed 盐拒绝采样映射到 0..255，Lua 侧由打包 base86 串（每槽 2 字符、`~` 标记前缀防与传输分段混淆）重建同一置换表并在展开时重写操作码字节，死臂改从重编号像之外取值）再加 1 项单元测试达 **PASS 165**；分派链二级拆分（F3 边界链与 F5 解释器链各自按 seed 拆成 2..4 条子链，选择器 `o%G==g` 四拼写、每臂按重编号值模数落链、链长分布逐 seed 变化，子链各自保留 fail-closed else，空残基组恒不可达直接中止）再加 1 项单元测试达 **PASS 166**；全字段解除锚定+微变体（入口与解释器字段进洗牌池，17 个字段位置完全随机、文件尾仅剩包装收口；字段分隔符 `,`/`;` 逐字段 seed 随机（尾随分隔符合法）；prelude 捕获语句序+返回序+entry 解构序三方独立洗牌，唯一依赖 Z→SC 保持）再加 1 项单元测试达 **PASS 167**；全局名隐藏（prelude 内 string/math/error/tonumber/type/select/debug/loadstring 等 23-26 个名字全部不再明文：单字符函数池 per-seed 洗牌分配、每名字随机取直接拼接或表驱动 helper 两种格式、经块级环境 `getfenv(1)` 索取；探针改收参数 DB/GI/LS，`debug/loadstring/getinfo` 明文归零；仅保留外层 setmetatable 与审计捕获行 getfenv×2/_G×1 明文；体积门有意识上调 24,000/26,000→25,500/27,000 B）再加 1 项单元测试达 **PASS 168**；随机 section 拆分（单体解码器扁平化为平级字段：解密字段 + 6 个 helper 组按 seed 随机切成 2..4 簇（流读取/浮点重建/常量密钥流/XOR/加密读取/num 族各簇参数-导出链精确推导）+ 解析 core 字段，全部进布局洗牌；bp 保持簇内 upvalue、终检经 pos() 访问器导出；字段总数 20..22 逐 seed 变化）再加 1 项单元测试达 **PASS 169**；全阶段控制流扁平化（base86 分段/外层解密/解析 core/解释器 fetch-dispatch 全部改为 per-seed 状态机：随机三位状态数、打乱分支序、四拼写条件；帧 setup 拆出 SETUP 函数、逐 prototype 三段拆出 PH/PU/PK 局部函数，定义序洗牌；体积门有意识上调 27,500/28,500 B）再加 1 项单元测试达 **PASS 170**（58 单元 + 112 集成），golden 24,933/27,315 B。顺序键表字面量（`[0]=3,[1]=4,…`）在产物中不复存在。生成器环境审计扩展为“1 个 getfenv 捕获 + 恰好 3 个固定形状探针”；矩阵的 loadstring 检查改为只匹配调用、blob 检查改为包装形状，Luau 二进制字面量检查收窄到 legacy（语法由 `luac5.1 -p` 全量保证）。随后 **g 槽位表**批次（2026-09-07）：全部非递归阶段的活局部（payload 解密、三个 base86 分段、forms 形态表重建、varint decode、validate 边界臂、解析 core 驱动、F3 校验循环，以及解释器 SETUP 的中间量）改写为 `local g={}` 槽位读写——每个变量绑定一个 per-seed 随机数字 key，名字消失、值持续流经同一槽位，作用域尾部 `g=nil` 清空；解释器帧寄存器 F/R/va 是实测例外（pcall/闭包经 SETUP 递归时嵌套帧会覆写单槽），保留普通 local。字符池/base86 文本不受影响（重写器跳过字符串字面量）。体积门 luau 28,500→29,800 B（`g[key]` 比短名 local 长；Lua51 27,500 不变）。再加 1 项单元测试（槽位计数/跨 seed key 集/无裸 local 对/复现+差分+运行等价）达 **PASS 171**（59 单元 + 112 集成），golden 26,848/29,400 B；`.obf` 与其 SHA-256 不变。同日复核发现 validate 字段的槽化调用在 F5 二分清理时丢失（`ok` 仍是裸 local，宽松的 8..10 计数区间掩盖了它）：补回 `slot_rewrite`，槽位表计数收紧为**恰 10 张**，vld 结尾锚点改为槽化无关形态；golden 更新为 27,080/29,646 B（仍在门 27,500/29,800 B 内），`.obf` SHA 仍不变。随后针对一份对 golden 的**纯静态破解报告**（黑盒复刻 handler I/O、Adler-32 当锚点、重建重编号表、45 条 ISA 全部还原）落地反制批次：**A1 像内诱饵语义臂**——F5 分派链为程序未用的全部 opcode 槽位（每 seed 随机弃 0..2 个）发射以"另一 opcode 的真实 handler 文本"为体的假臂，键=perm[未用槽] 落在置换像内、静态重建重编号表无法过滤，运行不可达性由形态表（未用槽=非法形态，decode 先中止）保证——误信假臂的反编译器会输出错误语义且程序自身 assert 无法证伪；旧像外诱饵改用完整 64 槽像避免与假臂撞键。**C1 假锚点**——entry 死侧新增与真重编号串同形的 129 字节假打包 base86 串+假重建循环、真表键参与的假 LCG 份额派生、假 Adler 校验门（恒不可达、无下游验证），"从校验和下手"的方法论必须先排除假锚点。体积门 27,500/29,800→29,500/31,800 B；新增单元测试 `decoy_arms_and_fake_anchors_poison_static_recovery`（四拼写臂扫描+像内覆盖+毒化断言+真假打包串甄别），重编号测试改为"恰 2 条 129 字节 tilde 串、恰 1 条解出置换"。达 **PASS 172**（60 单元 + 112 集成），golden 28,106/30,539 B；`.obf` SHA 不变。随后 **A2 密钥流原语族 + B1 跨阶段密钥派生**批次：payload 层与常量层各自独立从三族算术流原语中抽取——Lehmer（单乘子 mod 2^31-1）、双 Lehmer 求和（两状态 `(u+v)%2^31-1`）、mod-2^32 LCG（小奇乘子 + 奇加数，输出取高 8 位避开低位短周期）——族与参数逐 seed 变化，静态复刻必须先识族再定参；B1 把两级密钥与前级输出耦合：payload 种子混入 `pv=1+(PT[i1]*31+PT[i2]*7+PT[i3])%2^31-2`（PT=forms 字段重建的重编号表，i1..i3 为 per-seed 三个槽位，forms 字段调用前移到解密之前），常量层种子混入 `ka2=SB(B,33)*31+SB(B,#B)`（B=外层解密后镜像的两个框架字节——首 proto 头第 1 字节与末尾代码字节，均落在一切加密常量范围之外，双端取值恒同）——逐段黑盒复刻被迫按依赖序模拟整条管线。全部运算保持 <2^53 精确双精度；新增单元测试 `keystream_families_and_cross_stage_terms_couple_the_pipeline`（族形态断言/跨 seed 族分布≥2/pv 先于解密调用/ka2 后于解密/差分运行等价）。达 **PASS 173**（61 单元 + 112 集成），golden 28,360/30,777 B（门 29,500/31,800 内）；`.obf` SHA 不变。2026-09-07 针对该破解报告继续完成 **ISA3 semantic virtualization**：canonical `.obf` 仍为 ISA2 且 SHA 不变，但生成脚本改嵌 seed-specific recipe dictionary、1~4 primitive superhandler、随机 label/显式后继 graph、物理 record 洗牌、兄弟 prototype 重排、2~4 节点 synthetic unreachable prototype subtree 及四个 graph-unreferenced mismatched decoy recipe；目标端先完整重建/验证 graph 后按 label 执行，运行覆盖插桩也改按 live recipe 展开 primitive。破坏性测试现直接损坏 ISA3 recipe/label/prototype metadata 并证明用户代码执行前拒绝；golden 更新为 **64,599/71,598 B**，体积门有意识提高到 68,000/74,000 B，测试总数因替换旧“一对一重编号”契约而仍为 **PASS173**。

2026-09-08 分阶段复杂化第一批将 private wire 提升为 **ISA4**：record 不再直接携带 recipe ID，而是使用绑定 `label/next/skip/prototype` 与交叉项的五阶段 context token；验证与每次 fetch 共用乱序逆变换状态机，每个 live stage 包含 4~5 层动态不透明谓词，另有五个高密度算术/repeat 死状态。新增 token 双端逆变换、上下文差异、深度/死代码密度与双目标语法执行回归。固定 seed golden 为 **68,344/75,615 B**，位于新预算 72,000/80,000 B 内；完整门禁 **PASS174（62 单元 + 112 集成）**，bench 为 Lua51 40 ms / 20.0x、Luau 57 ms / 19.0x。

2026-09-08 第二批将 private wire 提升为 **ISA5**：next/skip 改为 source/prototype/edge-kind 绑定的三阶段 token，新增 3-live/3-dead `ED`，validator 与每次 fetch 动态恢复后继且不缓存明文；每个真实 prototype 入口及抽样 CFG 边插入可达/可执行 neutral bundle。新增 edge-token 逆元与 64-context 差异、unknown successor fail-closed、neutral 实际执行/poison 不执行及双状态机密度回归。固定 seed golden 为 **71,084/78,081 B**，SHA-256 分别为 `d6bd86191a05ccd45cc5fd59634e2e5948a8b9837fd46c595a17cbe3023c7fef` / `a3ea405964c01727681d11e277a5bb8c7c6021be4ca47253a76b35dc21e26c71`；预算仍为 72,000/80,000 B。完整门禁 **PASS175（63 单元 + 112 集成）**；bench 为 Lua51 46 ms / 23.0x、Luau 62 ms / 20.7x。

2026-09-08 第三批将 private wire 提升为 **ISA6**：live dictionary 不再自描述真实 primitive 序列，而是在严格相同 Form、validator 与控制类别的 family 内 seed-random camouflage；专项门要求超过三分之一 live recipe、至少 45% live op 的 descriptor 与执行语义不同。所有多 primitive recipe 被拆成 1~2 primitive fragments，`rid` 只路由随机入口 `sid`，fragment arms 跨 recipe 全局洗牌并形成独立 grouped dispatch；3/4-op recipe 保留随机 2-op fusion。固定 seed golden 为 **80,369/89,149 B**，SHA-256 分别为 `1be51fd30c946c4803d311b9c9cb3cbb7fbfe05b7d09826a5afc316209e06f78` / `3009575f7aef69b4ecfa331c09cfdc68fb0e9c4791efa3c8b88e0abf08508cfa`；预算有意识调整为 85,000/94,000 B。完整门禁 **PASS176（64 单元 + 112 集成）**；bench 为 Lua51 47 ms / 23.5x、Luau 64 ms / 21.3x。当时动态密钥/自定义分组加密仍属后续阶段。

2026-09-08 第四批将 private wire 提升为 **ISA7** 并加入独立 **block transport v1**：constant-encrypted semantic image 先封入 16-byte 严格 frame，再进入 seed-specific 7~10 轮、三 family 的 32-bit generalized Feistel 与 ciphertext chaining，最后才走既有 outer stream。双 key state 由运行时探针份额、opcode permutation 项与 padded length 非对称派生，最终值零字面量；目标端校验 descriptor/version/round count/block width、原长、cookie、tag 与 padding 后才把 image 交给 parser。新增 direct roundtrip/wrong-seed/全 ciphertext 逐字节 corruption/schedule diversity/key non-leak 单元门，以及保持 base86 和水印有效的双目标首中尾密文 corruption 静默失败集成门。固定 seed golden 为 **83,640/92,116 B**，SHA-256 分别为 `499ebc32d10ba9543f233380aa20b894a4b921740bac4fc7e77e4e31e2f87afa` / `35c80e5e890c42a7b8f029aacab790d781cc8fcb672eeaffdb55b637c62e8607`；预算保持 85,000/94,000 B。完整门禁 **PASS178（65 单元 + 113 集成）**；bench 为 Lua51 58 ms / 29.0x、Luau 81 ms / 27.0x。该层仍是可逆混淆，不改变 ISA6 语义层威胁结论；全局 prototype/function segment pool 与函数 inlining/outlining/reorder 仍属后续阶段。

2026-09-08 第五批将 private wire 升为 **ISA8** 并优先落地 bytecode compression：选择 std-only、目标端可审计的 bounded LZW，而非引入 ZSTD 依赖或大型 Lua decoder。semantic image 在任何 cipher 之前按 8 KiB reset 压成连续 canonical bitstream；16-byte frame 记录原长、精确 bit 数和全像 Adler-32，完整 frame 不严格缩小时生成器拒绝。原 constant stream 不删除，而是扩大为覆盖全部 compressed body；随后保持 block transport、outer stream、水印和 base86。Lua bit reader/LZW/frame inverse 按 seed 拆成二或三个 payload fields并参与全局洗牌；专项门还用重新封装的合法上游 transport 把 checksum/body 畸形 frame 直接送入双目标 Lua inverse，均在用户代码前无输出拒绝。固定seed golden为 **82,572/92,022 B**；它们低于ISA7的 **83,640/92,116 B** 只是一项历史整脚本信息，不是压缩判据；SHA-256 为 `50917035eeaf57c78f44f4efd5b2f3073b1c72e3360d499574da4a901b03b34c` / `fb3a850f5087685d0ffd3563d374312def42fdda503c2158f32bfc752a3ff7ea`。完整矩阵 **PASS179（66 单元 + 113 集成）**；bench 为 Lua51 66 ms / 33.0x、Luau 86 ms / 28.7x。压缩可逆且不改变 ISA6/7 的静态恢复边界；全局 prototype/function segment pool 与 inlining/outlining/reorder 在该历史节点仍暂缓。

2026-09-08 第六批将 private wire 升为 **ISA9** 并实现第一阶段 global prototype code-segment pool：每个已洗牌 prototype 的完整 semantic code 以 owner/context-derived 比例拆成两个非空节点，metadata 中原 reserved u16 改存 masked unique root；节点携带分别 context-masked 的 `id/owner/next`，在所有 prototype metadata/constant 之后做全局全记录洗牌。Lua parser 严格读取 `2×np` 个节点，验证 ID 全域唯一且完整、显式 owner、唯一 root、两跳 next 链、terminal 0、无环、总长和 pool 精确消费，再交给原 recipe/edge validator。专项门覆盖 duplicate/missing/out-of-range/wrong-owner/wrong-root/cycle/truncation/trailing，Lua51/Luau 均须在用户代码前无输出失败。为控制整脚本膨胀，仅 crate-owned VM finalizer 在可证明无歧义的块关键字和 `)`/`]`/`}`→identifier 语句边界省略可选分号，公共 minify 保持原严格分号策略，歧义 `;(` 永不删除且最终仍重解析/复核绑定。ISA8 descriptor camouflage、recipe/edge token、neutral CFG、synthetic subtree、fragment graph、bounded LZW、block/outer/base86、水印与环境探针全部保留。固定seed golden为 **82,729/91,722 B**；其低于ISA7 **83,640/92,116 B** 的关系仅作历史整脚本信息；SHA-256 为 `be0757fd570a13cb2262a315e96eceeaac2ed78b64463de11f9b8e5dc9e9ff2f` / `b7963ed55553718179c8e4a22376adc1638fc6a45dc801bec0ce27360060bf14`。完整矩阵 **PASS182（69 单元 + 113 集成）**；默认 15-run bench 为 Lua51 68 ms / 34.0x、Luau 88 ms / 29.3x。本批没有全局化 captures/constants，也没有宣称完成安全 inlining/outlining/reorder、跨 primitive dataflow fusion 或不可逆静态防护。

2026-09-06 指令序列化改为 7-bit varint 后的完整矩阵 **PASS 151**（41 单元 + 110 集成）：此前 150 项全部保留，`custom_bytecode` 新增 1 项 varint codec 回归（canonical/非最小编码、字段上限、带外 code 字节数、尾随字节、varint 截断与逐 Word 语义拒绝）。文件内指令按 Form 列写成 `[opcode][字段 varint]`（2~7 bytes），prototype header 追加 `code_byte_count`（20→24 bytes），Header 宽度码改为 `0`；目标 decoder 校验后展开回定长 4-byte 指令串，fetch-loop/handler/ISA 编号完全不变。两份示例 bytecode 缩小 **19.7% / 20.4%**（6,879→5,525 / 8,257→6,575 B），脚本 33,316→29,356 / 34,066→28,729 B；ISA 修订 1/2 语义、46/49 执行覆盖、debug/release 一致性不变。

VM 覆盖 fixture 位于 `tests/fixtures/vm_lua51.lua` 与 `tests/fixtures/vm_luau.lua`，包含闭包/upvalue、vararg、多返回值、调用、循环、泛型迭代、table、元表/方法、分支、算术以及 Luau 专属语法路径。

## 当前边界与后续工作

默认 AST/IR/v2 register VM、完整 primitive ISA、private ISA15 semantic graph、per-prototype operand/register/field-order ABI、capture/constant pools、carried-value fusion、六状态 entry graph、runtime-witness/data-dependent control、bounded LZW、双 ChaCha8、每次解密 anti-hook、frame v2 与最终随机短名均已可运行。破解报告暴露的统一 `6+3*i` operand slot、canonical actual-op marker、全像统一逻辑 `R[index]` 物理键、逐 primitive 原始 handler 拼接边界、顶层稳定线性入口链、统一 record/segment/dictionary/metadata 字段顺序及 per-prototype capture/constant 邻接均已被针对性削弱；但 pool token 掩码、profile/fusion/置换规则、`RF`、primitive算术/表操作、parser字段及全部 inverse 仍随客户端交付，计算或模拟后仍可逆。K8 per-prototype indirect route、K9 per-lane affine operand value key 与 capture/constant 全局池都已落地；下一步是 K10（体积 shrink 与静态表面收紧），更进一步的函数结构变换须独立评估；继续堆叠 encryption/encoding/compression 不能替代这些结构工作，也不得宣称客户端秘密、不可逆或“静态恢复已解决”。

当前限制必须保留：不模拟原始 debug/环境反射与错误位置；消除已证明的死路径后，仍对可能跳过条件所用 local 初始化的 `repeat/continue` 保守拒绝；隐藏元表、GC/分配时机、含洞 table 的 `#` 和布局敏感遍历不属于完全等价保证，Roblox executor 尚未实机验证。原生所有优化相关的函数身份也尚未完整模拟。结构验证不是沙箱或任意输入的语义等价证明。详见 [`虚拟机兼容性.md`](虚拟机兼容性.md) 和 [`自定义字节码.md`](自定义字节码.md)。

## Anti 状态

本阶段的 anti-hook 与 ChaCha8 material 紧耦合，实现在 `src/vm/custom/chacha.rs` 的独立 payload field，而非通用 `src/anti/`：这样每次 decrypt 都必须先得到 attestation，且 scope 可直接审计六个 source observation。`src/anti/` 仍保留给未来面向用户源码/通用运行环境的 Anti；不得把当前 gate 描述为不可绕过。
