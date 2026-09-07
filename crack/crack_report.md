# OBF `5.1vm.lua` 静态破解报告

> 目标：<https://github.com/dream6-e/OBF> 仓库中的 `5.1vm.lua`（27,080 字节）。
> 约束：**全程纯静态分析，目标文件从未被执行**——所有结论均来自自写的 Python 解码器 / 反汇编器 / 反编译器。
> 结论：**破解完成（100%）**。混淆层（字符串加密 → 自定义字节码载荷 → 隐藏 VM 指令集）被完整剥离，14 个函数原型（proto）共 **1,436 条指令**（主脚本 1,250 + 子函数 186）全部还原为可读 Lua 源码，重构源码见 `reconstructed.lua`，反编译器机械输出见 `full_decomp.txt`。

---

## 1. 侦察：这个文件是什么

用字符频率 + 引号结构对 `5.1vm.lua` 做分词后发现，它不是普通 Lua 脚本，而是：

- 一张**巨大的字符串常量表**（几十个长字符串，内容看起来是乱码）；
- 一个**解释器**：一段 Lua 代码通过 `string.char`/`string.byte` 动态构造函数，互相调用。

字符串名字全被混淆成无意义标识符，但每个函数在文件中的**声明顺序**稳定。按声明顺序编号后（记 handler `[id]`，id 取自解密后的调度表），整条混淆管线是：

| 处理器 | 作用 |
|---|---|
| `[9025]` | 23 字符自定义字母表：`p b o i d k x g m w l e a q s f h n c r y t u` |
| `[1199]` / `[6382]` / `[400]` | 全局串 `h`（载荷）、`df`、`mu` 的提供者 |
| `[2352]` | 校验载荷魔数（从 `h` 前 4 字节派生） |
| `[2086]` | 载荷解密（LCG 流密码） |
| `[9820]` | 载荷反序列化（自定义格式，非 Lua 官方 chunk） |
| `[8948]` / `[6983]` / `[1226]` / `[7244]` | 指令解码（变长编码 + 操作码重映射） |
| `[4632]` | VM 主循环（45 条自定义操作码） |
| `[5571]` | 反序列化阶段的字符串流密钥 |

**突破点 ①**：不试图"读懂"混淆代码，而是把每个 handler 当黑盒，用 Python 重实现其 I/O 行为，再交叉验证。这样绕开了"变量名全混淆"的可读性问题。

---

## 2. 剥离字符串混淆

三个关键全局串 `h`、`df`、`mu` 由 `[1199]`/`[6382]`/`[400]` 生成：它们把一长串被 `[9025]` 字母表索引编码的字节还原成二进制。用 Python 实现该还原后得到约 22 个 handler 的**明文 Lua 源码**（存于 `work/funcs/f_*.lua`）。这一步之后，混淆管线不再是黑盒。

`h` 的内容即 5,525 字节的加密载荷；`[2086]` 解密后头部为：

```
偏移  内容
0    'O','B','F'          魔数
3    版本 = 2
4    0x51                  目标 Lua 5.1
5    (1, 0, 0)             格式标志
8    u32 = 32              头部大小
12   u32 = 5525            载荷长度
16   u32 = 14              proto 数量
24   u32 = 2               常量池版本/附加段数
28   u32 = 0xEFFBA9E0      Adler-32 校验（实测吻合 ✓）
```

魔数校验值 `1482183482 = 0x5858533A`，恰为 `h` 前 4 字节 ✓。

**突破点 ②**：先攻校验和（Adler-32）与固定偏移字段，确认头部布局，后面所有解析都建立在这个地基上。

---

## 3. 载荷解密 `[2086]`（LCG 流密码）

- 种子派生：三个中间值 `wu/jr/hg` 分别由 LCG（乘数 48271，模 2^31−1）从
  `(4861·31+2003) % 2^31`、`(7244·31+8266) % 2^31`、`(9025·31+4632) % 2^31` 迭代得到；
- `seed = 1 + (wu + jr + hg + 31·len) % 2147483646`（`len` = 载荷长度 5525）；
- 解密：逐字节 `seed = 48271·seed % 2147483647; out[i] ^= seed % 256`。

**突破点 ③**：`31·len` 这一项把长度混进种子——若按固定种子解密会在第一个字节就失败；对照 Adler-32 才定位到长度参与种子这一细节。

字符串常量的二次加密由 `[5571]` 提供密钥流：

```
state = (4632·31 + 8961) % 2147483647
重复 11 次: state = state·65539 % 2147483647
state = 1 + (state + 31·5525) % 2147483646
每读 1 字节: state = state·48271 % 2147483647; byte ^= state % 256
（长度前缀不加密；number = 2×LE u32 的 double）
```

---

## 4. 反序列化 `[9820]` 与指令编码

**突破点 ④**：`[9820]` 是自定义序列化器，字段缩写全部单字母、语义靠对照推断。最终确定（这些字段名极易误读，最终以反汇编验证为准）：

- `.j` = 常量数，`.l` = 指令数；
- `.h` = maxstack（u16），`.r` = 参数个数（u8）；
- 常量类型：0=nil, 1=bool, 2=double, 3/5=string；
- upvalue 描述 = `(kind, idx)`，kind 0..2 = 父寄存器 / 父 upvalue / 环境。

**突破点 ⑤**：指令编码 `[8948]` 是三层odings 叠加，最费时的一环：

1. **类别表**：`cv(c) = (c > 92) ? c-1 : c`，类别 = `(cv(c)-61) % 86 + 1`：
   - 类 1 = op + A + l16；类 2 = op + A；类 3 = op + A + B；类 4 = op + A + u16；类 5 = op + A + B + C；
2. **操作码重映射**：`we = (cv(c1)-35) + (cv(c2)-35)·86`（每条指令的操作码字段是两字符基-86 编码，经 `we` 查表得真实操作码）；
3. **操作数**：varint（低 7 位分组）；特例——操作码 173/83/185 的指令额外跳 4 字节槽位；`JMP(62)`/`LOADI(185)` 用 `h24 = A + l16·256` 的 24 位有符号跳距；`LOADK(98)/GETGLOBAL(108)/SETGLOBAL(47)/CLOSURE(169)` 的 K 索引取 l16；`GETTAB_I(35)` 用 B, C 两个寄存器号。

---

## 5. 指令集：45 条自定义操作码

通过 `[4632]` 主循环逐条还原语义（编号为 `we` 重映射后的值）：

| 组 | 操作码 |
|---|---|
| 算术/比较（`x[A]=x[B]⊗x[C]`） | ADD201 SUB66 MUL246 DIV213 MOD5 POW227 CONCAT150(`..`) EQ57 LT167 LE121 |
| 一元 | UNM195 NOT27 LEN212 |
| 特殊比较 | LE_S14：`C>0 ? x[B]<=x[B+1] : x[B]>=x[B+1]` |
| 装载 | LOADK98 LOADI185 LOADNIL159 LOADNILS191(`x[A..B]=nil`) MOVE85 VARARG217 GETUPVAL187 SETUPVAL34 GETGLOBAL108 SETGLOBAL47 CLOSURE169 NEWTABLE105 |
| 表/盒 | GETTABLE233 GETGEN138 GETTAB_SK173 GETTAB_I35（`x[A]=x[B][C]`） SETTABLE52 |
| 盒（闭包捕获） | PACK1 106（`x[A]={x[B]}` 单元素盒） SETBOX29 UNBOX235 |
| 多值 pack | NEWPACK89 APPEND79 APPENDPACK215 SETN59 |
| 调用 | CALL135（多返回值进 pack） CALL2 58（`call(q[1],{q[2],q[3]})`） TAILCALL55 SPREAD40（pack 展开 → 表/寄存器） |
| 控制 | JMP62（绝对跳） TEST83（`not x[A]` 跳过下条） FORPREP170 FORLOOP65 RETURN245 |

**突破点 ⑥**：这套 VM 用**"盒"（单元素 table）实现 Lua 闭包 upvalue**、用 **"pack"（数组）实现多返回值/变参**。识别出 `PACK1/SETBOX/UNBOX` 与 `NEWPACK/APPEND/APPENDPACK` 两组机制，是看懂所有高级结构（闭包、多赋值、`assert(f()==5)` 这类调用内嵌表达式）的前提。

---

## 6. 14 个 proto 与控制流恢复

载荷含 14 个 proto（id: maxstack, nparam, flags, nup, #instr, #konst）：

| id | 参数 | 恢复出的语义 |
|---|---|---|
| 0 | 主脚本 | 1,250 条指令，见第 7 节 |
| 1 | `(...)` | `return ...`（变参透传） |
| 2 | `(f, ...)` | `return f(...)` |
| 3 | `(x)` | 累加器工厂：`return function(y) x=x+y; return x end` |
| 4 | `(y)` | `uv0 = uv0 + v0; return uv0`（即上者内层） |
| 5/6 | — | 三层闭包工厂的前两层 |
| 7 | `(y)` | `return uv0 + v0`（最内层，捕获 9） |
| 8 | `(x)` | `return x * 2` |
| 9 | `(a,b)` | `return a/b, a%b, a^b, not a, a and b, a or b` |
| 10 | — | `return uv0`（捕获主脚本 box17） |
| 11 | `(self,v)` | `self.value = self.value + v; return self.value`（`add` 方法） |
| 12 | `(a,b)` | `__add`：新盒 `value = a.value+b.value`，`setmetatable(t, uv0)` |
| 13 | `(a)` | `__tostring`：`return "box:" .. a.value` |

**突破点 ⑦（反编译器）**：手写反编译器 `decomp4.py`，关键技术：

- **支配树求回边**：`JMP` 目标 ≤ 当前地址且目标支配当前地址 → 回边 → 自然循环；`FORLOOP` 且前两条是 `FORPREP` → 数值 `for`；
- **循环形态判别**：循环内 `TEST` 的真/假出口 —— 双出边在环外 = `while cond do`；真假出口互换且"假路径沿直线流回环头" = `repeat ... until cond`；环头有 `CALL2` 构造 `(iter, state, ctrl)` 且条件是 `ret==nil` = `for-in ipairs`；
- **and/or 折叠**：`EQ/LT/LE → MOVE → TEST → 双 JMP` 且中间块只为条件服务时，折叠成 `(a and b)` / `(a or b)`——需允许块内出现 CALL（如 `assert(v16 and (v15() == 5))`），但禁止有真副作用的语句；
- **callret 延迟冲洗**：每个 CALL 产生 `callret{id, expr, used, consumed, inplace}` 记录，直到其寄存器被 `LOADNILS` 清杀时才决定输出形态：
  - 结果 1 被就地取回（`GETTAB_I A==B`）→ 语句 `f(...)`；
  - 结果 k（k≥2）被取用 → `local retN_k = select(k, f(...))`；
  - 结果被多处组合赋值 → `local a, b, c = f(...)`；
  - 仍存活在 pending pack 里 → 推迟，等 pack 销毁再定；
  - 关键配套：**读集失效**（寄存器被杀/被重写时清除 read 标记，且 `LOADNILS` 自身必须延后清除，否则误判"无人使用"导致语句丢失或重复）；
- **盒的名字化**：`PACK1/SETBOX` 一旦声明 `local vN = ...`，盒 N 此后一律以变量名 `vN` 出现——循环携带变量（累加器 `v19`、计数器 `v20`）因此自动正确。

**突破点 ⑧（两处险些误判的结构）**：

1. `[355..405]` 的 `TEST` 头 + 回边 `390→360`：若按普通 if 处理，会把后半脚本整个包进 `if v16 then ... end`。实际上"真出口"392 上的块服务于 `TEST@369` 的 and 链——正确输出是
   `if v16 then v16 = (v15() == 5) end` + `assert((v16 and (v15() == 5)))`；
2. 主脚本尾部 `[833..1060]` 的 55 项大表：编译器把字面量拆成两个 pack + 两次 `SPREAD` 写入（1..50、51..55），且第一个 `SPREAD` 的处理若把条目写回寄存器会污染表名寄存器（出现 `23[51] = 51` 这类乱码）——SPREAD 只读不写寄存器后自然还原为 `{1..55}`。

---

## 7. 最终成果：重构源码

机械反编译输出 `full_decomp.txt`（14 proto 全量、无遗漏、无多余语句）；语义等价、变量重命名后的可读版本见 **`reconstructed.lua`**。主脚本逻辑一览：

```lua
-- 1) 有状态累加器闭包
local acc = make_accumulator(10)
assert(acc(2) == 12)  assert(acc(-5) == 7)

-- 2) 三层闭包工厂（9 被最内层捕获）
assert(make_closure3(9)()(4) == 13)

-- 3) 变参透传 + 多返回值
local a, b, c = identity(1, nil, 3)
assert(a == 1 and b == nil and c == 3)

-- 4) 高阶函数
assert(apply(twice, 9) == 18)

-- 5) 一次断言六种运算
local r1, r2, r3, r4, r5, r6 = ops(8, 3)  -- 8/3, 2, 512, false, 3, 8
assert(r1 == 8/3 and r2 == 2 and r3 == 512)
assert(r4 == false and r5 == 3 and r6 == 8)

-- 6) 闭包捕获 + 条件 + 短路
local ok, n = true, 5
local get_value = function() return n end
if ok then ok = (get_value() == 5) end
assert(ok and (get_value() == 5)) -- 短路求值：ok 才调第二次
n = 16

-- 7) 一元/关系/连接断言链（-16、#"abcd"==4、"ab3"、…）
-- 8) 方法调用
local obj = { value = 4 }
obj.add = box_add
assert(obj:add(6) == 10)

-- 9) 循环全家桶
sum = 0
for i = 1, 5, 1   do sum = sum + i end   -- 15
for i = 5, 1, -2  do sum = sum + i end   -- +9  = 24
for _, v in ipairs{2, 4, 6} do sum = sum + v end  -- +12 = 36
assert(sum == 36)
while cnt < 3 do cnt = cnt + 1 end
repeat cnt = cnt - 1 until cnt == 0

-- 10) 55 项大表字面量（编译期拆两个 SPWRITE 段）
local big = {1,2,...,55};  assert(big[55] == 55)

-- 11) 元表 OOP：__add + __tostring
local z = setmetatable({value=2}, MT) + setmetatable({value=8}, MT)
assert(tostring(z) == "box:10")

-- 12) 全局环境探针
_G.__obf_vm_probe = 41; _G.__obf_vm_probe = _G.__obf_vm_probe + 1
assert(_G.__obf_vm_probe == 42); _G.__obf_vm_probe = nil

print("vm:lua51:ok")
```

### 静态验证

虽未运行目标，但每条 `assert` 都做了静态求值复核：

| 断言 | 静态求值 |
|---|---|
| `acc(2)==12`, `acc(-5)==7` | 10+2=12；12−5=7 ✓ |
| `make_closure3(9)()(4)==13` | 9+4 ✓ |
| `identity(1,nil,3)` | 1, nil, 3 ✓ |
| `apply(twice,9)==18` | 9·2 ✓ |
| `ops(8,3)` 六值 | 8/3=2.666…, 8%3=2, 8³=512, false, 3, 8 ✓（与常量 `-1295.69…` 附近的 2.6666666666666665 精确一致） |
| `sum==36` | 15+9+12 ✓ |
| `obj:add(6)==10` | 4+6 ✓ |
| `tostring(z)=="box:10"` | 2+8 ✓ |
| `_G` 探针 | 41+1=42 ✓ |

一个值得注意的语义细节：`get_value` 捕获的是**活盒**（box17）而非值快照——`n = 16` 之后若再调用 `get_value()` 将返回 16。载荷作者刻意把两次调用都安排在改写之前，这正是用来测试 VM upvalue 语义是否正确的探针。

---

## 8. 产物清单

| 文件 | 内容 |
|---|---|
| `work/crack_report.md` | 本报告 |
| `work/reconstructed.lua` | 重构源码（可读版，语义与反编译输出一一对应） |
| `work/full_decomp.txt` | 反编译器机械输出（14 proto 全量） |
| `work/decomp4.py` | 现役反编译器（支配树/回边/循环判别/盒/pack/callret） |
| `work/stage2.py → stage2.pkl` | 魔数校验 + [2086] 解密 + [5571] 字符串流 |
| `work/stage3.py → protos.pkl` | [9820] 反序列化（14 proto 原始结构） |
| `work/stage4.py → protos2.pkl` | [6983]+类表+we 重映射 → 规范指令 |
| `work/disasm.py → dis0.txt` | proto0 反汇编（常量表+操作码名） |
| `work/funcs/f_*.lua` | 22 个 handler 还原出的明文源码 |

## 9. 方法论小结

1. **不读混淆码，读 I/O**：把 22 个 handler 当黑盒，用 Python 复刻行为再交叉验证，绕开命名混淆；
2. **从校验和下手**：Adler-32/魔数这类"必须完全正确"的值是格式推断的锚点；
3. **让密码学自己暴露**：LCG 种子里混入 `31·len` 这类细节，只有拿"解密结果必须通过下游校验"当反馈才调得出来；
4. **语义驱动的反编译**：先识别 VM 的两个核心抽象（盒=upvalue，pack=多值），高级结构（闭包/多赋值/短路）自然浮现；
5. **反编译器的正确性靠"无输出"守护**：丢语句（assert 消失）和重复语句（`f()` 执行两次）是两类对称 bug，分别对应"冲洗过早"与"冲洗过晚"，用 read 集失效 + pending-pack 推迟把两者一起解决。
