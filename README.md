# OBF

面向 **Lua 5.1.5** 与 **Luau 0.735 / Roblox 方向** 的 std-only Rust 工具链。默认 `virtualize` 已实现真正的 **AST → IR → 自定义 Bytecode → 寄存器 VM**：公开 `.obf` 固定 **32-byte Header**，指令操作数以 **7-bit varint** 序列化（小数值 1 byte，较大值 2~N bytes），并有独立常量/捕获/prototype。生成器不依赖原生 compiler，不用 `load/loadstring` 委托执行；原生后端只通过 `--backend native` 显式选择。`.obf` 文件保持明文 canonical ISA2、与 seed 无关；包装成脚本时先降为私有 seed-specific **ISA6 semantic image**：use-site 不带 opcode、稳定 recipe ID 或明文 successor，而是携带三阶段 edge token 与绑定动态后继的五阶段 recipe token。live dictionary 只公开与真实 primitive **编码形式、目标 validator 和控制类别严格等价**的伪 descriptor；真实 1~4 primitive recipe 被拆为 1~2 primitive fragment，recipe ID 只选随机入口 stage，全部 stage 再跨 recipe 全局打乱。每次 fetch 因而依次经过 edge、recipe 与独立 semantic-stage 三维分派。每个真实 prototype 的入口和抽样 CFG 边还会插入实际可达、实际执行的中性 bundle；record、兄弟 prototype 与 synthetic subtree 继续洗牌。随后才叠加 M6 双层传输混淆、base86 分段和最终一/两字母改名。该设计针对“dictionary 展开后逐 recipe 连续翻译”的静态恢复路径，但仍是可逆混淆，不宣称不可破解。

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

默认 AST/v2 路径的 seed **影响 ISA6 recipe ID/mask、live descriptor camouflage、semantic fragment 边界/入口/stage、三阶段 edge-token 与五阶段 recipe-token 参数、reachable neutral edge split、深层状态/谓词/死臂、label graph、record/prototype 顺序、最终 local/私有字段、包装键、密钥份额、探针调用顺序及嵌入密文**；公开 `.obf` 与 seed 无关，但解密后的私有 semantic image 随 seed 改变且同 seed 确定。不做压缩容器。显式 `--backend native` 另保留旧 OBF v1 的随机 opcode/dispatcher/数字写法。脚本输出均是单物理行；IR/inspect 报告和二进制文件不适用“脚本单行”的限制。随机短名不是加密，有限名称空间不保证任意两个 seed 都产生不同文本。

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
       → 自定义指令选择 / 标签回填 → canonical OBF v2 / ISA2
       → seed semantic lowering（camouflaged descriptor + edge/recipe token + neutral graph）
       → private ISA6（global semantic fragments）→ 目标端校验 / register VM
       → 最终随机短名 / 单行化
```

这条链路**不调用原生 compiler，不存 native word，也不默默 fallback**。新 `ir::Module` 包含函数、常量、cell/upvalue 捕获和带符号后继的基本块；IR 的 branch 生成 `Test + Jump + Jump`。公开文件 Header 固定 **32 bytes**，含版本、目标、端序、宽度码、文件长度、prototype 数量、入口、ISA 版本和 Adler-32；canonical 指令流按 Form 写成 `[opcode][各字段 varint]`（A/AB/ABC/ABx/Ax，2~7 bytes）。`compile`/`inspect-bytecode`/`serialize` 仍遵守该公开 ISA2 规范；只有 `virtualize`/`wrap-bytecode` 在生成脚本内部把已验证 Program 重编码为 ISA6 camouflaged-recipe/edge-token graph。完整逐字段规范与 **49 条 primitive ISA** 见 [`自定义字节码.md`](自定义字节码.md)。

- Lua 5.1：46 个 `src/vm/opcode/lua51/c*.rs`；Luau：49 个 `src/vm/opcode/luau/c*.rs`。它们现在是 primitive 语义模板；生成器把程序的 1~4-op recipe 拆成 1~2-op fragments，经随机 `sid` continuation 执行，而不是在 use-site 上做固定 opcode→handler 或 recipe→连续 body 分派。
- 每 frame 为寄存器文件；local 使用 heap cell，临时值为普通寄存器，闭包引用 cell。循环的新一轮/复用寄存器不会破坏逃逸闭包。
- 显式 pack.n 处理多返回值、尾部 nil、vararg、调用/返回；VM→VM 尾调用替换 frame。支持宿主函数、元方法、回调及 coroutine。
- 两端分别处理赋值/方法求值顺序、numeric-for、表构造器刷新和 Lua51 隐式 `arg`；Luau 另有 `//`、插值、泛型擦除、`__iter`、userdata NAMECALL、精确 i64 及冻结导出表。
- Rust reader 先完整验证 canonical `.obf`；semantic lowering 再按 CFG leader 切分（Jump/Test/terminal 不跨 bundle），给 recipe 分配随机非零 u16 ID，把 Jump 目标改为随机 label，并在入口与抽样 next/test 边插入 neutral trampoline。record 的 `next/skip` 槽存放绑定 source/prototype/edge-kind 的三层 token；目标端验证和每次 fetch 都动态解出后继，再把真实后继作为五层 recipe token 的上下文。持久 `code[label]` 不缓存明文 successor；不存在可按 `pc += 4` 排序的内嵌原始指令串。
- **整体输出包装**：chunk 只有两条语句——`local x={}` 与 `return setmetatable({...},x):m()`。全部 VM 代码以**多个函数**的形式存放在载荷表内：5 个随机数字键 section 函数（宿主捕获预导、bytecode decoder、操作数校验、运行时辅助、解释器簇）+ 1 个随机单字母字符串键的入口方法。`:m()` 直接命中载荷表自有键进入入口函数，按顺序串联各 section 并返回程序结果；chunk 真正读取 `...` 时调用写为 `:m(...)`。方法名与数字键来自独立 seeded 随机流；不改 bytecode、最终 local 或私有字段名。

### 运行语义兼容性增量

已修复 Luau callable iterator、`__iter` 原始查找/false 处理、常用闭包共享与递归身份差异；增加运行时捕获裁剪、只读标量传播与可达性分析，原先因死分支 `continue` 被拒绝的一批合法源码现在可执行。Lua51 的已有赋值/数值/闭包语义仍单独回归。

默认产物为 **OBF v2 / ISA 修订 2**，只增加经过双侧验证的闭包共享 metadata，Header/指令宽度/49 个稳定编号不变。**修订 1 仍可读取、执行、原样序列化**，CLI 显示实际文件版本。

“运行输出与原始源码一致”的支持条件、测试证据与已知反例边界见 [`虚拟机兼容性.md`](虚拟机兼容性.md)。有限差分不能推出任意源码等价，也不能把 opcode 覆盖率当作语言兼容率。

Rust API：`ir::compile/lower`、`bytecode::custom::{encode,decode,serialize}`、`vm::custom::{compile,emit}`，以及默认 `vm::virtualize`。`inspect-bytecode` 自动区分 OBF v2 与原生 chunk；`wrap-bytecode` 可把已保存的 `.obf` 独立包装为 VM。

所有 decoder、runtime、dispatcher、handler、静态方法适配器和执行尾部组装完后，自定义 VM 先缩短私有字段，再调用一次私有 `minify::finalize_vm` 统一随机 local、分号分隔和单行化；之后不追加代码。重解析复核绑定图、同域唯一性、名称长度和确实换名；双层解密后的内容须等于同一 Program/seed 确定性重编码出的 ISA6 semantic image，而不再等于输入 canonical `.obf`。生成器环境例外仍严格审计：`local G=(getfenv and getfenv(0))or _G`，加上三个 payload 密钥函数内**形状完全固定**的环境探针（Luau `debug and debug.info(loadstring,"s")` 结果须为 `"[C]"`；Lua 5.1 `debug and debug.getinfo(loadstring,"S")` 须 `what=="C"`）。探针不通过则静默中止、无任何输出；没有公开忽略反射的开关。

### 私有 semantic image 与 payload 传输层

- **ISA6 语义虚拟化（针对静态破解报告，第三阶段）**：`generate` 不再嵌入调用者传入的 canonical 指令 bytes，而是从已验证 `Program` 确定性构造 seed-specific image。ISA5 的 1~4 primitive recipe、三层 edge token、五层 recipe token、reachable neutral bundle、record/prototype 洗牌和 synthetic subtree 全部保留。ISA6 将 live recipe dictionary 改为伪 descriptor：只在 encoding Form、目标 operand validator 与 control/terminal graph class 完全相同的六类 family 内替换，测试要求超过三分之一 live recipe 且至少 45% live primitive 被 camouflage；真实执行序列只留在 emitter。每个多 primitive recipe 必定拆为多个 1~2 primitive fragment；3/4-op recipe 至少保留一个 2-op fused fragment。`rid` 分派只把控制交给随机三位入口 `sid`，所有 fragment 的 `sid` arm 跨 recipe 全局打乱并独立分成 2~4 组；只有 final fragment 回到 fetch，Return/TailCall 保持词法终止。持久 code record 仍不缓存明文后继、recipe ID 或 stage。
- 生成时用 seed 派生的 **Lehmer 密钥流（48271 mod 2147483647）** 对上述 ISA6 image 逐字节 XOR，密文字节分布均匀（Shannon 熵 > 7.5 bits/byte，测试断言高于明文）；所有中间量 < 2^53，Lua 双精度与 Rust 逐位一致。
- 密钥 **动态生成、零字面量**：三个份额不在脚本中存储，由每个探针函数在运行时从脚本自身结构（入口传入的 payload 表数字键对 `(a,b)`：`x=(a*31+b)%2147483647` 再叠 3/5/7 轮 `x=48271*x%2147483647` 步进）计算得出；探针通过后才计算并返回份额。
- **常量池独立加密（第二层）**：嵌入镜像中每个常量记录的 payload（布尔值字节、数字/整数 8 字节、字符串内容）在外层加密之前，再用**另一把结构密钥**（不同 wrapper 键对 + 11 轮步进 + 长度混合）单独 XOR；字符串长度保留明文作框架元数据。剥掉外层密文后常量仍是密文；密钥同样零字面量。
- **base86 传输层 + 分段打乱**：双重加密后的镜像整体 base86 编码（86 个可打印字符、约 1.25 字符/字节，比 4 字符十进制转义便宜得多），切成三段并按 seed 洗牌分放到三个 `[数字]=function` 分段函数；**每个分段函数先重跑 loadstring 原生探针再解码自己的分段**（连同份额探针共 6 个探针函数）。验证侧 `extract_embedded` 通过试全部 6 种段序 + 全镜像 Adler-32 找出唯一有效顺序——顺序本身不在脚本中存储。
- **固定水印 `XXS:` + 隐藏式双函数检测**：base86 流解码后的前 4 字节固定为 `XXS:`（明文传输水印）。检测被拆成两个 payload 函数：一个通用的大端 4 字节打包器 + 一个不透明 u32 常数比较器——两个函数都不出现 "XXS:" 字样，脚本全文亦无该字符串（测试断言）；不匹配即静默中止。水印同时把“哪个段是流首段”钉死，加强段序判定。
- **M7 结构随机化（不含外层包装变体）**：seed 驱动的等价结构变体进入默认路径——F3 primitive 校验按 `o`、ISA6 recipe 入口按 `rid`、semantic fragment 按 `sid` 形成三维 dispatch；各维独立拆为 2~4 个 grouped chain，每条比较随机取 `x==K`/`K==x`/`not(x~=K)`/`x-K==0`。整数边界与元方法分支也有独立等价变体。`tools/bench-vm.sh` 继续看护性能；descriptor camouflage 与 fragment routing 有意识用体积换去连续同构，当前硬预算为 **85,000/94,000 B**（Lua51/Luau），单次运行灾难阈值仍为 1500ms。
- **不透明真假分支与三类 semantic camouflage**：入口方法体仍以恒真/恒假式包住实际链和不运行的真指令，F3 还保留不可能 primitive 值的死臂。ISA6 同时保留 graph-unreferenced poison recipe、两套 token decoder dead state、graph-referenced/executed neutral bundle，并新增**真实 live recipe 上的 validation-equivalent descriptor 谎报**。前两类仍可分别靠 reachability/中性效果分析过滤；live descriptor 不能按“未引用”删除，必须继续关联全局 fragment stage 才能恢复真实语义。
- 入口按 **seed 洗牌的顺序**调用三个函数并传入各自的结构键对，decoder 段以 `1+(s1+s2+s3+31*#B)%2147483646`（混入密文长度）重建密钥流并继续 magic/Adler/ISA6 descriptor/edge/recipe-token/图结构校验；份额与密钥流初态的十进制串不出现在脚本任何位置（单元测试逐 seed 断言）。`.obf` 文件与 `compile` 输出保持明文 canonical、与 seed 无关；`vm::custom::decrypt_embedded` 现在返回解开两层后的**私有 ISA6 image**，用于和同 Program/seed 的 deterministic semantic re-encode 对照。
- 这是提高静态分析成本的混淆层，**不是密码学加密**；密钥派生自 seed，不能抵御持有脚本的攻击者。

**VM 私有字段也压缩为一/两字母**：`code`、`tags`、`parent`、`flags`、`shared`、`self`、`cached` 及原有短字段共 14 个，当前全部可分配为互不冲突的随机单字母。decoder、校验器、运行时、缓存和 opcode handler 的构造/读/写共用同一映射；同 seed 复现，使用独立随机流，不改变既有 local 名称或 bytecode。

这是 crate-owned、不会逃逸的 prototype schema 的专用处理，**不是任意 `.field` 文本替换**。模板通过私有标记明确授权，词法 token/span 改写后复核所有未标记 token 和字面量不变；用户 table 字段、导出键、字符串、`string.byte` 等宿主 API、`__mode/__iter` 等元方法及 `object:code()` 等 NAMECALL 名称不改。普通 `minify` 不启用这项私有字段策略，显式旧 native backend 保持原行为。

### 显式兼容后端

`virtualize --backend native` / `vm::virtualize_native` 保留原来的 `compiler → native reader → OBF v1`。旧根目录 `lua51_*.rs`（38）与 `luau_*.rs`（91）不移动、仍单独测试。只有这个后端使用旧 13-byte Header、6-byte `u16 private-opcode + u32 native-word` 及随机布局。

旧 backend 的 compiler 查找依次为 `OBF_LUAC51` / `OBF_LUAU_COMPILE`、仓库 `toolchains/bin`、`PATH`。默认 AST 后端在这些变量指向不存在文件时仍可正常编译/生成；原生工具仍用于门禁的语法/运行对照。

### 已提交示例

| 文件 | 来源 | seed | v2 bytecode | 最终单行脚本 |
|---|---|---:|---:|---:|
| `vm_lua51.out.lua` | `tests/fixtures/vm_lua51.lua` | 7001 | 5,525 B | 80,369 B |
| `vm_luau.out.lua` | `tests/fixtures/vm_luau.lua` | 7351 | 6,575 B | 89,149 B |

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
4. 对 ISA6 fetch 在 ED/RD 动态解出 edge/recipe token 后做运行插桩，再按独立 `sid` fragment graph 展开真实 primitive 序列确认覆盖 **Lua51 46/46、Luau 49/49**；同时证明入口 neutral recipe 实际执行、未引用 poison recipe 不执行，并检查 live descriptor 谎报不弱于 45%；
5. 编译/执行每份 VM seed 变体，确认单行、不委托 loadstring、没有生成器错误消息、所有显式 local 最后才改名，并验证双层解密结果等于同 Program/seed 的 deterministic semantic re-encode；
6. 检查新目标目录的 46/49 个 handler 和旧兼容目录的 38/91 个 handler；
7. 独立执行 `dump-ir → compile → inspect → wrap`，证明缺少原生 compiler 也能生成默认 VM；
8. 比较 debug/release 的 binary 和 VM、默认虚拟化与独立 wrap、根目录 golden；
9. 显式执行旧 `--backend native` 的完整语料、多 seed、语法/运行回归，保留其原生 opcode coverage（Lua51 38/38、Luau ≥60）；
10. 额外覆盖多返回值/nil、变量求值时机、闭包、循环、20k 尾调用、coroutine/回调、i64、导出模块、userdata NAMECALL、GC 及 CLI 失败不覆盖文件；
11. `tests/semicolons.rs` 检查双目标语句分隔、必需空格、调用后缀、嵌套函数/类型/插值、字符串字节、已有分号、空块、非法源码、CLI/两 VM 后端；内部测试覆盖所有语料的边界完整性、改名偏移、幂等性和 10,000 相邻块；
12. `tests/vm_parity.rs` 的 145 个生成式组合及应用式语料检查求值顺序、闭包身份、迭代器、捕获、返回值/模块和控制流；额外执行应用语料的 debug/release binary/VM 与原生 stdout 对照，检查修订 1 兼容性；
13. `tests/private_fields.rs` 与私有字段内部测试检查 14 字段双射、单/双字母池、关键字/冲突/越界拒绝、marker-like 用户方法名、公开字段/导出保护、CLI/修订 1 包装，以及输入 `.obf` 仍 canonical、内嵌内容则严格为 ISA6 semantic image。

`tests/scope.rs`、`tests/scope_reuse.rs`、`tests/random_names.rs`、`tests/safe_minify.rs` 及内部 VM 测试还覆盖：所有可改名 local 的 `[a-z]{1,2}`/同域唯一性/换名断言，短名跨域复用、闭包读写、声明时序、原先遮蔽的声明、参数/body 共域，多步匹配修复、小图穷举重解析、工作门限、名称池耗尽、CLI seed 报告/复现/参数拒绝/失败不覆盖文件，并发新 seed，以及原有绑定、类型、元方法、插值、变参和超长链回归。原生运行差分包含 seed `0`、`1`、`0x735`、`u64::MAX`；650 个已是单字母的 locals 也经过双目标编译/运行；10,000 个相邻块加一个累计变量的压力测试安全复用两个单字母名，另有 96 种生成式遮蔽/初始化程序的双目标多 seed 运行差分。

2026-09-06 VM 私有字段压缩后的完整矩阵 **PASS 149**（40 单元 + 109 集成）：此前 140 项全部保留，新增 4 项内部和 5 项集成测试。原生/VM 输出、debug/release、两套后端及 46/49 实际执行覆盖均通过。两份示例分别减少 **164 / 159 B**，除私有字段外所有 token（含原 seed 的 local 名称和字面量）完全一致，内嵌与独立 bytecode 逐字节不变；seed 现在控制最终 local 与私有字段名，不控制 v2 binary。

2026-09-06 输出整体改为 `local x={};return setmetatable({...},x):m()` 的分函数载荷形式后的完整矩阵 **PASS 150**（41 单元 + 109 集成）：此前 149 项全部保留，形状/差分单元测试改为断言新结构。默认后端与 `wrap-bytecode` 的全部代码位于载荷表的 5 个随机数字键 section 函数与 1 个随机字母键入口函数中；环境捕获审计下降到各 section 函数体内执行，根表检查允许数字/字符串键函数字段。两份示例相对私有字段批次各增加 **484 B**；seed 额外控制包装方法名与数字键。旧 `--backend native` 输出保持原状。

2026-09-06 嵌入 payload 字节级加密 + 三探针密钥拆分后的完整矩阵 **PASS 153**（42 单元 + 111 集成）：此前 151 项全部保留，新增 1 项密文熵值/解密等价单元测试与 1 项环境篡改 fail-closed 集成测试（Lua51 替换 `loadstring`、Luau 经 `setfenv` 注入，脚本必须无输出中止）。内嵌 blob 为 seed 派生 Lehmer 密钥流密文（熵 > 7.5 bits/byte），三个 payload 函数各先验证环境再交回密钥份额，调用顺序 seed 洗牌，decoder 结合解密后走原有校验；`.obf` 文件与解密后 payload 逐字节不变。golden 为 **27,223 / 30,888 B**。同日后续把密钥改为**结构动态推导**（份额由表键对+密文长度运行时计算，密钥零字面量，逐 seed 断言份额与初态的十进制串不出现在任何数字字面量中）达 **PASS 154**；再为常量池加独立第二层加密（常量在外层密文内仍是密文、长度保留框架明文、双新单元测试 + 破坏性测试改为“生成器或目标端二选一拒绝”）达 **PASS 156**；最后叠加 base86 传输层与三段打乱（每段一个探针门控的分段函数，新增 codec 回归）达 **PASS 157**；再加固定水印 `XXS:` 与隐藏式双函数检测（单元 + 集成回归：外科手术式只改水印字节组必须静默中止）达 **PASS 159**；M7 结构随机化（dispatch/边界/元方法分支变体 + 体积预算与基准）再增 2 项单元测试达 **PASS 161**；不透明真假分支（入口包装 + 永不可达死臂，两种用户指定形态）再加 1 项单元测试达 **PASS 162**；全代码随机化（payload 字段整体 seed 洗牌：每个解密/探针/分段/水印函数的表内位置逐 seed 变化；加密参数 seed 派生：Lehmer 乘子 16807/48271/65539、混合常数 31/33/37/41、探针与常量轮数逐 seed 变化，双端同 seed 字节复现）再加 1 项单元测试达 **PASS 163**；特征拆分隐藏（操作数验证器一分为三：形态表改为 per-seed 旋转打包串的独立重建字段、varint 读取+操作数形状链独立成解码字段、逐 opcode 边界臂独立成验证字段，三字段随全代码随机化落入随机表位）再加 1 项单元测试达 **PASS 164**；随机 opcode 重编号（canonical ISA 编号只保留在 `.obf` 与加密 varint 流内，脚本侧 F3/F5 分派与边界臂全部改跑 per-seed 单射重编号：64 槽位经 seed 盐拒绝采样映射到 0..255，Lua 侧由打包 base86 串（每槽 2 字符、`~` 标记前缀防与传输分段混淆）重建同一置换表并在展开时重写操作码字节，死臂改从重编号像之外取值）再加 1 项单元测试达 **PASS 165**；分派链二级拆分（F3 边界链与 F5 解释器链各自按 seed 拆成 2..4 条子链，选择器 `o%G==g` 四拼写、每臂按重编号值模数落链、链长分布逐 seed 变化，子链各自保留 fail-closed else，空残基组恒不可达直接中止）再加 1 项单元测试达 **PASS 166**；全字段解除锚定+微变体（入口与解释器字段进洗牌池，17 个字段位置完全随机、文件尾仅剩包装收口；字段分隔符 `,`/`;` 逐字段 seed 随机（尾随分隔符合法）；prelude 捕获语句序+返回序+entry 解构序三方独立洗牌，唯一依赖 Z→SC 保持）再加 1 项单元测试达 **PASS 167**；全局名隐藏（prelude 内 string/math/error/tonumber/type/select/debug/loadstring 等 23-26 个名字全部不再明文：单字符函数池 per-seed 洗牌分配、每名字随机取直接拼接或表驱动 helper 两种格式、经块级环境 `getfenv(1)` 索取；探针改收参数 DB/GI/LS，`debug/loadstring/getinfo` 明文归零；仅保留外层 setmetatable 与审计捕获行 getfenv×2/_G×1 明文；体积门有意识上调 24,000/26,000→25,500/27,000 B）再加 1 项单元测试达 **PASS 168**；随机 section 拆分（单体解码器扁平化为平级字段：解密字段 + 6 个 helper 组按 seed 随机切成 2..4 簇（流读取/浮点重建/常量密钥流/XOR/加密读取/num 族各簇参数-导出链精确推导）+ 解析 core 字段，全部进布局洗牌；bp 保持簇内 upvalue、终检经 pos() 访问器导出；字段总数 20..22 逐 seed 变化）再加 1 项单元测试达 **PASS 169**；全阶段控制流扁平化（base86 分段/外层解密/解析 core/解释器 fetch-dispatch 全部改为 per-seed 状态机：随机三位状态数、打乱分支序、四拼写条件；帧 setup 拆出 SETUP 函数、逐 prototype 三段拆出 PH/PU/PK 局部函数，定义序洗牌；体积门有意识上调 27,500/28,500 B）再加 1 项单元测试达 **PASS 170**（58 单元 + 112 集成），golden 24,933/27,315 B。顺序键表字面量（`[0]=3,[1]=4,…`）在产物中不复存在。生成器环境审计扩展为“1 个 getfenv 捕获 + 恰好 3 个固定形状探针”；矩阵的 loadstring 检查改为只匹配调用、blob 检查改为包装形状，Luau 二进制字面量检查收窄到 legacy（语法由 `luac5.1 -p` 全量保证）。随后 **g 槽位表**批次（2026-09-07）：全部非递归阶段的活局部（payload 解密、三个 base86 分段、forms 形态表重建、varint decode、validate 边界臂、解析 core 驱动、F3 校验循环，以及解释器 SETUP 的中间量）改写为 `local g={}` 槽位读写——每个变量绑定一个 per-seed 随机数字 key，名字消失、值持续流经同一槽位，作用域尾部 `g=nil` 清空；解释器帧寄存器 F/R/va 是实测例外（pcall/闭包经 SETUP 递归时嵌套帧会覆写单槽），保留普通 local。字符池/base86 文本不受影响（重写器跳过字符串字面量）。体积门 luau 28,500→29,800 B（`g[key]` 比短名 local 长；Lua51 27,500 不变）。再加 1 项单元测试（槽位计数/跨 seed key 集/无裸 local 对/复现+差分+运行等价）达 **PASS 171**（59 单元 + 112 集成），golden 26,848/29,400 B；`.obf` 与其 SHA-256 不变。同日复核发现 validate 字段的槽化调用在 F5 二分清理时丢失（`ok` 仍是裸 local，宽松的 8..10 计数区间掩盖了它）：补回 `slot_rewrite`，槽位表计数收紧为**恰 10 张**，vld 结尾锚点改为槽化无关形态；golden 更新为 27,080/29,646 B（仍在门 27,500/29,800 B 内），`.obf` SHA 仍不变。随后针对一份对 golden 的**纯静态破解报告**（黑盒复刻 handler I/O、Adler-32 当锚点、重建重编号表、45 条 ISA 全部还原）落地反制批次：**A1 像内诱饵语义臂**——F5 分派链为程序未用的全部 opcode 槽位（每 seed 随机弃 0..2 个）发射以"另一 opcode 的真实 handler 文本"为体的假臂，键=perm[未用槽] 落在置换像内、静态重建重编号表无法过滤，运行不可达性由形态表（未用槽=非法形态，decode 先中止）保证——误信假臂的反编译器会输出错误语义且程序自身 assert 无法证伪；旧像外诱饵改用完整 64 槽像避免与假臂撞键。**C1 假锚点**——entry 死侧新增与真重编号串同形的 129 字节假打包 base86 串+假重建循环、真表键参与的假 LCG 份额派生、假 Adler 校验门（恒不可达、无下游验证），"从校验和下手"的方法论必须先排除假锚点。体积门 27,500/29,800→29,500/31,800 B；新增单元测试 `decoy_arms_and_fake_anchors_poison_static_recovery`（四拼写臂扫描+像内覆盖+毒化断言+真假打包串甄别），重编号测试改为"恰 2 条 129 字节 tilde 串、恰 1 条解出置换"。达 **PASS 172**（60 单元 + 112 集成），golden 28,106/30,539 B；`.obf` SHA 不变。随后 **A2 密钥流原语族 + B1 跨阶段密钥派生**批次：payload 层与常量层各自独立从三族算术流原语中抽取——Lehmer（单乘子 mod 2^31-1）、双 Lehmer 求和（两状态 `(u+v)%2^31-1`）、mod-2^32 LCG（小奇乘子 + 奇加数，输出取高 8 位避开低位短周期）——族与参数逐 seed 变化，静态复刻必须先识族再定参；B1 把两级密钥与前级输出耦合：payload 种子混入 `pv=1+(PT[i1]*31+PT[i2]*7+PT[i3])%2^31-2`（PT=forms 字段重建的重编号表，i1..i3 为 per-seed 三个槽位，forms 字段调用前移到解密之前），常量层种子混入 `ka2=SB(B,33)*31+SB(B,#B)`（B=外层解密后镜像的两个框架字节——首 proto 头第 1 字节与末尾代码字节，均落在一切加密常量范围之外，双端取值恒同）——逐段黑盒复刻被迫按依赖序模拟整条管线。全部运算保持 <2^53 精确双精度；新增单元测试 `keystream_families_and_cross_stage_terms_couple_the_pipeline`（族形态断言/跨 seed 族分布≥2/pv 先于解密调用/ka2 后于解密/差分运行等价）。达 **PASS 173**（61 单元 + 112 集成），golden 28,360/30,777 B（门 29,500/31,800 内）；`.obf` SHA 不变。2026-09-07 针对该破解报告继续完成 **ISA3 semantic virtualization**：canonical `.obf` 仍为 ISA2 且 SHA 不变，但生成脚本改嵌 seed-specific recipe dictionary、1~4 primitive superhandler、随机 label/显式后继 graph、物理 record 洗牌、兄弟 prototype 重排、2~4 节点 synthetic unreachable prototype subtree 及四个 graph-unreferenced mismatched decoy recipe；目标端先完整重建/验证 graph 后按 label 执行，运行覆盖插桩也改按 live recipe 展开 primitive。破坏性测试现直接损坏 ISA3 recipe/label/prototype metadata 并证明用户代码执行前拒绝；golden 更新为 **64,599/71,598 B**，体积门有意识提高到 68,000/74,000 B，测试总数因替换旧“一对一重编号”契约而仍为 **PASS173**。

2026-09-08 分阶段复杂化第一批将 private wire 提升为 **ISA4**：record 不再直接携带 recipe ID，而是使用绑定 `label/next/skip/prototype` 与交叉项的五阶段 context token；验证与每次 fetch 共用乱序逆变换状态机，每个 live stage 包含 4~5 层动态不透明谓词，另有五个高密度算术/repeat 死状态。新增 token 双端逆变换、上下文差异、深度/死代码密度与双目标语法执行回归。固定 seed golden 为 **68,344/75,615 B**，位于新预算 72,000/80,000 B 内；完整门禁 **PASS174（62 单元 + 112 集成）**，bench 为 Lua51 40 ms / 20.0x、Luau 57 ms / 19.0x。

2026-09-08 第二批将 private wire 提升为 **ISA5**：next/skip 改为 source/prototype/edge-kind 绑定的三阶段 token，新增 3-live/3-dead `ED`，validator 与每次 fetch 动态恢复后继且不缓存明文；每个真实 prototype 入口及抽样 CFG 边插入可达/可执行 neutral bundle。新增 edge-token 逆元与 64-context 差异、unknown successor fail-closed、neutral 实际执行/poison 不执行及双状态机密度回归。固定 seed golden 为 **71,084/78,081 B**，SHA-256 分别为 `d6bd86191a05ccd45cc5fd59634e2e5948a8b9837fd46c595a17cbe3023c7fef` / `a3ea405964c01727681d11e277a5bb8c7c6021be4ca47253a76b35dc21e26c71`；预算仍为 72,000/80,000 B。完整门禁 **PASS175（63 单元 + 112 集成）**；bench 为 Lua51 46 ms / 23.0x、Luau 62 ms / 20.7x。

2026-09-08 第三批将 private wire 提升为 **ISA6**：live dictionary 不再自描述真实 primitive 序列，而是在严格相同 Form、validator 与控制类别的 family 内 seed-random camouflage；专项门要求超过三分之一 live recipe、至少 45% live op 的 descriptor 与执行语义不同。所有多 primitive recipe 被拆成 1~2 primitive fragments，`rid` 只路由随机入口 `sid`，fragment arms 跨 recipe 全局洗牌并形成独立 grouped dispatch；3/4-op recipe 保留随机 2-op fusion。固定 seed golden 为 **80,369/89,149 B**，SHA-256 分别为 `1be51fd30c946c4803d311b9c9cb3cbb7fbfe05b7d09826a5afc316209e06f78` / `3009575f7aef69b4ecfa331c09cfdc68fb0e9c4791efa3c8b88e0abf08508cfa`；预算有意识调整为 85,000/94,000 B。完整门禁 **PASS176（64 单元 + 112 集成）**；bench 为 Lua51 47 ms / 23.5x、Luau 64 ms / 21.3x。动态密钥/自定义分组加密、全局 prototype/function segment pool 与函数 inlining/outlining/reorder 仍属后续阶段。

2026-09-06 指令序列化改为 7-bit varint 后的完整矩阵 **PASS 151**（41 单元 + 110 集成）：此前 150 项全部保留，`custom_bytecode` 新增 1 项 varint codec 回归（canonical/非最小编码、字段上限、带外 code 字节数、尾随字节、varint 截断与逐 Word 语义拒绝）。文件内指令按 Form 列写成 `[opcode][字段 varint]`（2~7 bytes），prototype header 追加 `code_byte_count`（20→24 bytes），Header 宽度码改为 `0`；目标 decoder 校验后展开回定长 4-byte 指令串，fetch-loop/handler/ISA 编号完全不变。两份示例 bytecode 缩小 **19.7% / 20.4%**（6,879→5,525 / 8,257→6,575 B），脚本 33,316→29,356 / 34,066→28,729 B；ISA 修订 1/2 语义、46/49 执行覆盖、debug/release 一致性不变。

VM 覆盖 fixture 位于 `tests/fixtures/vm_lua51.lua` 与 `tests/fixtures/vm_luau.lua`，包含闭包/upvalue、vararg、多返回值、调用、循环、泛型迭代、table、元表/方法、分支、算术以及 Luau 专属语法路径。

## 当前边界与后续工作

默认 AST/IR/v2 register VM、独立 reader/encoder、完整 primitive ISA、私有 ISA6 camouflaged-descriptor/edge-token/fragment lowering、可达 neutral CFG split 与最终随机短名均已可运行。后续优先扩展真实业务语料、语义/压力差分、寄存器/pack 开销及宿主边界，并继续实现动态密钥/自定义分组加密、全局 prototype/function segment pool 及函数 inlining/outlining/reorder；不能把现有 recipe/fragment graph 描述成不可逆，也不应再以单纯增加传输加密替代反虚拟化结构改进。

当前限制必须保留：不模拟原始 debug/环境反射与错误位置；消除已证明的死路径后，仍对可能跳过条件所用 local 初始化的 `repeat/continue` 保守拒绝；隐藏元表、GC/分配时机、含洞 table 的 `#` 和布局敏感遍历不属于完全等价保证，Roblox executor 尚未实机验证。原生所有优化相关的函数身份也尚未完整模拟。结构验证不是沙箱或任意输入的语义等价证明。详见 [`虚拟机兼容性.md`](虚拟机兼容性.md) 和 [`自定义字节码.md`](自定义字节码.md)。

## Anti 状态

按当前要求，`src/anti/` 暂时留空，等待用户提供具体 Anti 实现。
