# Luraph v15 静态还原报告
样本: `OBF/Luraph15💀💀.lua` (171,753 B, 3 行; 第 3 行 171,676 字符 = 整个程序)
方法: 纯静态 (词法/结构解析 + 我自己写的算术求值). **样本从未被执行.**
工具: `tools/an.py` (结构解析), `tools/pretty.py`, `tools/ops.py` (dispatch 树重建),
      `tools/lph_codec.py` (容器解码器), `tools/handlers.json` / `imports.json`

## 1. 攻击目标
最终目标 = 把 `return setmetatable({...},{}):FC()(...)` 这一坨还原成
(a) 可读的 VM 语义 (指令集/寄存器/帧布局), (b) 常量与字符串, (c) 容器编码链, (d) 防御机制.
最理想 = 离线解出 chunk 拿到原始源码. 实际拿到 (a)(c)(d) 全部 + (b) 的一半; (理想) 卡在最后一层白化.

## 2. 逐步流程 (假设 → 操作 → 观察 → 结论)
1. **识别混淆族**. 假设:未知. 操作:`head -c 500`. 观察:第 1 行是
   `-- This file was protected using Luraph Obfuscator v15.0 [https://lura.ph/]`.
   结论:厂商自报名号(省了我一步指纹工作), 目标锁定 Luraph v15 的 VM+flatten 组合.
2. **整体骨架**. 假设:一个表达式. 操作:正则扫 `X=function` + 字符直方图.
   观察:130 个 `X=function` 平铺; `,{}):FC()(...)` 结尾; `[57]=buffer.writeu32`、`[51]=buffer.create` 混在函数之间.
   结论:程序 = `setmetatable(表, {}):FC()(...)`; 表既是 handler 集合又是运行期全局池.
3. **入口点**. 假设:`FC` 是解释器入口. 操作:读 `FC` 源码.
   观察:`FC=function(b,...) local ...=b:_L() ... while u do if V<=3 then ... b:qL(...) else b:HL(...) else b:eL(...) end`.
   结论:确认 flatten 状态机入口; `_L` 是"取初始状态"蹦床 (`return true,3,nil*10`).
4. **全局池 = 数字槽**. 假设:表里的 `[N]=<函数>` 是 import. 操作:按 table-depth-0 切分条目, 抽出全部非函数值.
   观察:68 个数字槽 + 14 个字符串槽, 全部是 `buffer.* / bit32.* / string.* / table.* / coroutine.* / rawget / setfenv / typeof / Vector3.new`.
   结论:**完整 import 表**(§4.1). 这就是"环境"的全部——脚本可见的全局只有这 68 个.
5. **payload 定位**. 假设:大字符串表=字节码/常量池. 操作:抽所有字符串字面量按长度排序.
   观察:唯一一条 74,566 字符长串, 值挂在键 `RC`, 以 `LPH:` 开头; 另有 10 个 5 字符短串挂在 `pC`.
   结论:容器 = `b.RC`, `b.dL="LPH:"` 是签名前缀.
6. **容器解码**. 假设:`b.XC`/`b.pC` 是 gsub 转义表. 操作:读 `HL` 的 `K<=2` 反分支.
   观察:`local u=b[118](b[93](b.RC,5),b.XC,b.pC); local z,Z,K=b[107](u),#u-1,5+0; return 2,{nil,0-K,K,Z+0,o},0,{},z,w`
   代入 import → `u=string.gsub(string.sub(RC,5),"[ -'}~]",pC); z=buffer.fromstring(u); reader={nil,-5,5,#u-1,…}`.
   结论:先展开转义, 再 fromstring; 读窗口 = 1-based 第 5 到 #u-1 字符 (→ 前 4 字符是 IV/垃圾头).
7. **radix-85 判定**. 假设:字母表是 base64 变体. 操作:统计 `u` 的字符集与频次.
   观察:**恰好 85 个**高频字符 = `(`(40)..`|`(124), 频次 670–972 平坦; 另外 10 个字符各出现 3–4 次,
   正好是 `pC` 的 10 个键, 且它们正好落在字母表**之外**; 展开后长度 74,690, 窗口 74,685 = 5×14,937.
   又:文件里出现字面量 `52200625`(=85⁴) 1 次、`614125`(=85³) 1 次、`7225`(=85²) 1 次, 全在 `qL`/`eL`;
   `qL`: `w+(z-40)*7225+(u-40)*85+(o-40)+(G-40)*614125`, `eL`: `52200625*(H-40)`.
   结论:**Ascii85 变体: digit=ord(c)-40, 5 字符→1 个 32bit 字, MSB first**, 权重常数直接在代码里.
   (489 组值 ≥2³² = 85⁵/2³²=1.033 的固有冗余, 不是我的对齐错误.)
8. **数字格式**. 假设:varint. 操作:扫所有 `(x-128)`/`*128`/`*16384`/`*2097152` 组合与 `>=128` 判定.
   观察:反复出现 `readu8(buf,k+3)` → `(b-128) + 128*(b-128) + 16384*(b-128) + 2097152*b`, 以及
   `q<128 and STATE_A or STATE_B` 的续读判定, 和长度选择器 `p<16384 and 7 or(p<2097152 and 14 or 21)`.
   结论:**7-bit 分组 varint + 续字节 +128 偏置**; 1/2/3/4 组; 位权 7/14/21 直接写在源码里.
9. **opaque arithmetic**. 假设:`b:iL`/`b:vL` 是算术混淆原语. 操作:读二者定义 + 数值探针.
   观察:`vL(x)=x%2^32`; `iL(a,b)=(a*b)%2^32` (用 band/rshift/lshift 拼 16bit 部分积).
   恒等式 `iL(K,0xFFFFFFFF)≡-K`, `iL(K,x)+iL(K,bnot x)≡K*(x+~x)≡-K`; 且每个站点两个干扰常数**恰好相加=2^32**.
   我用 Python 只对折叠后的表达式求值(不跑样本), 6 个站点里 5 个塌成 `operand ^ K` (K=7,12,101,111,113),
   1 个是仿射 `R=(1291219581*d+1087330548) mod 2^32` (斜率对所有探针点恒定, 已验证).
   结论:整类"大数乘加噪声"可静态消除; 提取到 **b[18] 内 52 个、b[73] 内 9 个 per-lane XOR key**.
10. **主解释器**. 假设:`b[18]`/`b[73]` 是核心. 操作:比长度/内部 handler 调用数/比较变量分布.
    观察:`b[18]`=32,695B, 503 次 `b:X(`, 377 个 if, 状态变量 `q` 有 269 个阈值, 另一个变量 `O` 有 38 个阈值;
    `b[73]`=3,366B, 5 个 callee, 内层 `while true do local f=m[x] if f>=4 then…`.
    结论:`b[18]` = **主 VM 循环**; `b[73]` = **调用桥 + 惰性操作数解码器**; 其余 143 个是 handler 池.
11. **帧布局**. 假设:`u[N]` 是帧字段. 操作:抽 `b[18]`/`b[73]` 里全部 `u[数字]` 读取并交叉比对.
    观察:两边 `u[16]` 都是取指令的数组(`J[Q]`/`m[x]`), `u[12]` 都是 PC, `u[15]/u[11]/u[14]/u[13]` 是操作数/常量通道,
    `u[9]` 喂给 `table.create` 分配寄存器窗 `n`.
    结论:字节码是 **struct-of-arrays**(不是指令 struct), 见 §4.5.
12. **指令语义**. 假设:叶语句就是 opcode 语义. 操作:`tools/ops.py` 走 if/then/else/end 嵌套, 对判别变量做区间传播(else 取补).
    观察:1,219 个叶语句, 13 个区间, 形如 `n[y[Q]]=n[m[Q]]+y[Q]`、`n[R[Q]]=t[Q]`、`Q=m[Q]`.
    结论:拿到 §4.6 的指令表(只覆盖第一棵 dispatch 树, 其余树被 flatten 的状态变量 `q` 打散, 见 §5).
13. **字符串/段加密**. 假设:带 `readu8+writeu8+bxor+buffer.create` 的 handler 是解密器. 操作:批量反别名后看方程.
    观察:统一形如 `writeu8(dst,i, bxor(salt, readu8(src,pos+i), k)); k=(k*213+225)%256`,
    `buffer.create` 的尺寸类 = 1/2/4/8/12/16(+动态), 解完立刻按类型读回 `readu16/readi16/readu32/readi32/readf32/readf64/readstring`
    或 `vector.create(readf32×3)` / `Vector2.new` / `Vector3.new`. 文件中 `213`×25、`225`×28.
    结论:**每常量一条 LCG 密钥流的 XOR 加密 + 尺寸分类 + 类型化回读**(§4.3).
14. **防御**. 假设:有反调试/防提取. 操作:核对可疑助记子与死代码.
    观察:见 §4.4 (`nL` 的 `error(…,0)`、`Y` 造的 `__index` 代理、`b[2]=nil`/`(...)[...]=nil` 自擦、
    `b[94]` 运行期写槽、`b.h` 9 个 u32 **全文件零引用**、重复形参 `function(b,u,z,z,z,z,z)`).
    结论:防 dump/防 hook/防静态调用图 三类都有; `b.h` 是伪密钥诱饵.
15. **白化墙**. 假设:解出的字流应显出结构. 操作:统计 14,937 字的熵/零串/重复.
    观察:熵 7.9958 bit/B, 零字节占比 0.0048(基线 0.0039), 最长常量 run=1, 14,895/14,937 互不相同;
    **但** 42 处重复的距离 gcd=64 (组) = 256 B, 且 32 个转义标记全部落在同一窗口(group 13162..13684).
    结论:框架全对, 内容被 per-lane key 白化; 最后一层需要模拟 loader 才能剥.

## 3. 依赖的特征 (突破点清单)
| # | 特征 | 它告诉了我什么 |
|---|---|---|
|1| 第 1 行 banner `Luraph Obfuscator v15.0` | 直接锁定方案与版本(不必猜混淆器)|
|2| 全部语句挤在第 3 行、只有 3 行 | 机器生成 + 反 diff/反 grep 排版 |
|3| `X=function` 两字母名 + `C`/`L` 后缀家族, 平铺 130+ 个 | flatten:每个基本块被提升成表字段 |
|4| 表里混入 `[57]=buffer.writeu32`、`[51]=buffer.create`、`[17]=Vector3.new` | **`b` 是"数字槽→全局"的 import 表**; 拿到它=拿到运行期可见的全部 API |
|5| `b[66]` 257 次、`b[47]` 91 次、`b[8]`/`b[20]`/`b[10]`/`b[99]` 高频 | readu8/writeu8/bxor/bit32 → "按字节读流 + 按字节写缓冲 + XOR" = 解码器骨架 |
|6| 形如 `local B,j,d=f[1],f[3],f[2]; local Y,_=B+j,j<=0; local B,j,g=not _,Y>=d,Y<=d; d=_ and j or B and g; f[1]=Y; if d then return A else return B` | **被 flatten 的数值 for 循环/回边**(三元件:累加、符号位、双向区间测试)——用它我认出哪些 handler 是循环体 |
|7| `if K<=2 then … else local u=b[118](b[93](b.RC,5),b.XC,b.pC) …` | gsub/sub/fromstring 三连 = **容器解码点**(整个 payload 只有 1 处) |
|8| 长串以 `LPH:` 起头, 且 `dL="LPH:"` 单独存在 | 容器 magic; 也用于 `nL` 的错误前缀 |
|9| 字符集恰好 **85** 个连续 ASCII (`(`..`|`), 频次平坦, 另有 10 个"表外"字符各 3–4 次 | 85 进制(而非 64), 10 个字符是**单字符快捷转义**, 且它们不可能与数据混淆 |
|10| 展开后 74,690 与窗口 74,685 都被 5 整除 | 5 字符一组 → 确认组边界 |
|11| 源码里出现 `52200625`/`614125`/`7225`/`85` 各 1 次(=85⁴/85³/85²/85) | **radix 与 digit 权重被直接证实**, 不用再猜 |
|12| `string.sub(RC,5)` + reader 元组 `{nil,-5,5,#u-1}` | 跳 4 字节头; 步长 5; 上界 `#u-1` → 精确读窗口(少算这条会错位)|
|13| 大量 `(x-128)`、`*128`、`*16384`、`*2097152` 与 `…>=128 and A or B` | base-128 varint + 续字节 +128 偏置 |
|14| `p<16384 and 7 or(p<2097152 and 14 or 21)` | 操作数位宽 7/14/21 → **每操作数 varint 的字节数选择器** |
|15| `4294967295`(111 次)/`4294967296`(16 次)/`65535`(30 次)/`2147483648`/`2147483647`/`2147483649` | 一切算术都在 mod 2³² 上; 末尾两个数=−1/−2 的模像 → 用于混淆减法 |
|16| `iL(K,0xFFFFFFFF)` 与 `iL(K,x)+iL(K,bnot x)` 成对出现, 两常数之和恒为 2³² | **可折叠的伪随机噪声**; 认出这条恒等式=把 32KB 天书折成 `^K` |
|17| `b:vL(` 出现 239 次、`b:iL(` 330 次, 只被这两个用到 | 这两个 handler 就是"归一化/乘"原语, 优先折它们收益最大 |
|18| `local Z,o,w,K,…=b[22],b[34],b[102],…` 每个巨型函数的开场 | **全局→局部的别名表**; 反别名后所有方程立刻可读(我做成了自动 `rd()`) |
|19| 重复形参名 `function(b,u,z,z,z,z,z)` / `function(b,u,z,Z,Z,Z,Z)` | 反静态参数推断; 也标出这两个是**被特别加固的巨型函数** |
|20| `x-=1` / `p+=1` / `..=` 不存在但有 `+=`/`-=`(84 处) + `continue`(45 处) + `if` 作表达式(17 处) | **运行时=Roblox Luau, 不是 Lua5.1/5.3**(luaparse 直接在这三处炸)|
|21| `Q=if n[y[Q]]then R[Q]else m[Q]end` | 分支无关的 cmov 写法做**条件跳转**, 专治"按 if 找控制流"的工具 |
|22| `J[Q]=12`、`R[Q],y[Q],m[Q],J[Q]=197,77,228,12`、`J[x],R[x],t[x],m[x]=231,200,146,2` | **自修改 dispatch**:执行完把当前指令改写成下一条的入口 → 静态调用图断链 |
|23| `local O=J[Q]; if O>=19 then if O<29 then if O>=24 then if O<26 then` | 二叉搜索式 opcode 分发 → 这就是"靠元组槽认路由"的等价物 |
|24| `D[4]=D;D[6]=n[q];D[7]=6;o[q]=nil` (多处) | Luau **闭包 upvalue 关闭**编码(4=自我引用/6=值/7=状态=6)|
|25| `buffer.create(4/8/16) → 逐字节 bxor → buffer.readu32/readf32/readstring` | 常量按"尺寸类"独立加密, 解完按类型回读 → 常量池是**惰性**的 |
|26| `(k*213+225)%256` / `213`×25, `225`×28 | 字符串密钥流的 LCG 参数 |
|27| `b.h={9 个 u32}` 全文件 0 次引用 | **伪密钥诱饵**(我确认 `b.h`/`b["h"]` 都不存在)|
|28| `b[94]` 初值 `(0)`, 运行期被 `DL` 写, 再被 `eL` 用作 `b[z[4]]` 的下标 | **运行期填的 vtable** → 静态看不到谁调谁 |
|29| `M=function(b,b)b[2]=nil;return true,19,nil…` / `K=function(b,...)(...)[...]=nil` | 自擦(把槽位清空)→ 防 dump/防二次读取 |
|30| `nL`: `type(msg)=="string"` + `string.match(msg,":(%d+)[:\13\10]")` + `error("LPH:".."?"..": "..msg, 0)` | **错误信息规范化 + level 0 去掉 file:line**(反 traceback 泄漏/反插桩探测)|
|31| `Y` 造 `{ [b.BL]="__index" = function(q,M) …73 个 handler… end }` | 全局读被劫进 VM → **懒解析全局**, 静态看不到脚本真正用了哪些 API |
|32| 14,937 字中只有 42 处重复, 距离 gcd=**64** 组(=256B), 且与 32 个转义标记同窗口 | 证明组对齐/窗口正确, 并暴露出那段是高度重复明文(被固定 key 加密) |

## 4. 实际还原出的东西
### 4.1 运行期 import 表(完整, 68 槽 + 14 名) — 确证
```
buffer : create[51] fromstring[107] tostring[55] len[36] copy[56] fill[1]
         readu8[66] readu16[69] readi16[68] readi32[46] readu32[108]
         readf32[125] readf64[91] readstring[42] writeu8[47] writei8[83] writeu32[57]
bit32  : band[20] bor[122] bxor[8] bnot[71] rshift[10] lshift[99] countrz[23]
string : sub[93] gsub[118] gmatch[41] match[67] find[70] rep[24] byte[104] char[109]
         format[116] pack[72] unpack[7]
table  : create[22] pack[13] insert[90] concat[39] move[102]
coroutine: resume[21] wrap[31] yield[38] status[35] close[77] create[112] running[28] isyieldable[113]
misc   : pcall[81] xpcall[14] error[16] assert[76] type[84] typeof[58] tostring[97] tonumber[37]
         select[53] next[15] unpack[114] rawget[75] rawset[64] getmetatable[43] setmetatable[124]
         getfenv[34] setfenv[25] Vector2.new[60] Vector3.new[17] vector.create[126]
特殊   : [94]=0(运行期改写)
常量   : AL="n"  BL="__index"  cL="string"  dL="LPH:"  EL=": "  PL="?"
         XC="[ -'}~]"  gL=":(%d+)[:\13\10]"  QL=false  s={}  pC=<10项转义表>
         h={24123,4121909815,113887313,3257834490,808597170,2484518445,3813836768,1149546688,3906211916}  ← 死码诱饵
         RC=[=[LPH:...]]=]  (74,566 字符)
```
### 4.2 容器编解码链(可运行, `tools/lph_codec.py`) — 确证
```
pay  = RC[5:]                                   -- 去 "LPH:"
u    = gsub(pay, "[ -'}~]", pC)                 -- 10 字符 ↔ 5 字符 快捷展开
win  = u[5 : #u-1]                              -- 1-based; 74,685 = 5×14,937
w    = Σ (win[i+j]-40)·85^(4-j)                  -- radix85, offset 40, MSB first
chunk= concat( writeu32(w_k) )                   -- 14,937 字 = 59,748 B, 熵 7.9958
```
pC(原样抄回): `'"'→"=W8+C"  "'"→"*cZ7D"  '%'→"]JEL>"  ' '→"{5Cw,"  '$'→"--vv@"  '!'→"2[,6K"  '~'→"ix|L9"  '#'→"3;MLo"  '}'→",;^6{"  '&'→"kTXL7"`
### 4.3 常量/字符串加密方程 — 确证(25 个 handler 同一模板)
```
buf = buffer.create(N)                          -- N ∈ {1,2,4,8,12,16, len}
k   = (salt + C) % 256
for i = 0, N-1:  buf[i] = bxor( salt, src[pos+i], k );  k = (k*213 + 225) % 256
value = readu32(buf,0) | readu16 | readi16 | readf32×3 → vector.create | readf64 | readstring(N)
```
观测到的 salt 值: 10,18,36,52,53,54,83,88,155,185,201,224,234 ; 一个变体用 `bxor(byte, d)`(b[73] f==6).
### 4.4 防御 / 反分析机制 — 确证
1. **懒全局解析**: `Y` 生成 `{__index=function(...) <VM> end}`; 全局读进 VM ⇒ 静态看不见 `game`/`workspace`/executor API.
2. **mod 2³² 域上的算术混淆** + opaque predicate(恒等式 `x+~x=2³²-1`).
3. **控制流扁平化**: 136 个状态号(1..236), 344 个 `return <state>,…` 站点, 145 个 handler, 寄存器每块轮转别名.
4. **自修改 dispatch**(把下一条指令的入口写回当前槽) + **惰性操作数解码并回写**.
5. **运行期 vtable**(`b[94]=…` 然后 `b[z[4]](…)`)打断静态调用图.
6. **自擦/防 dump**: `b[2]=nil`、`(...)[...]=nil`、`table.create(n)` 后逐槽清零(`buffer.fill` 142 次).
7. **反 traceback**: `error("LPH:?: "..msg, 0)` 抹掉 file:line; 用 `type()`+`:(%d+)[:\r\n]` 探测消息是否已被外部包装.
8. **pcall/xpcall/assert 包裹**, `setmetatable/getmetatable/rawget/rawset` 绕 hook, `getfenv/setfenv` 换环境.
9. **可 yield 的 VM**(`UL` 用 `coroutine.yield(true,b,w)`, `isyieldable`)——为的是脚本里能 `wait()`, 同时让 traceback 只暴露 VM.
10. **死码/诱饵**: `h` 9×u32; 假形参遮蔽 `z,z,z,z,z`; `RC` 前 4 字符垃圾头; 489 个 ≥2³² 的组(冗余位).
11. **反拷贝**: `gsub`+`pC` 使得"只把 `LPH:` 后面抄走"得到错误的字节流.
### 4.5 VM 帧与寄存器模型 — 高置信推断
```
u  = 帧(struct-of-arrays) : u[16]=OP[]  u[15]=A[] u[11]=B[] u[14]=C[] u[13]=K[](常量)
                            u[12]=PC    u[9]=栈大小 u[7]=类型/mode u[10],u[8],u[6],u[5]=其余上下文
n  = table.create(u[9])  寄存器窗       A = getfenv()   z/t = 宿主对象数组
取指: local O = J[Q]                     步进: Q+=1 / Q-=1
分发: 二叉比较树 (O>=19 / O<29 / O~=28 …) + 状态变量 q (0..236) 双层
跳转: Q = if n[y[Q]] then R[Q] else m[Q] end   (Luau 表达式, 无分支)
```
### 4.6 已确认的指令语义(逐字摘出, 编号只覆盖第一棵 dispatch 树)
```
O<=18  n[y[Q]](n[m[Q]])                                  CALL(A=1 arg)
O 4..5 n[R[Q]]=t[Q]                                      LOADK  (t=常量通道)
O 7    n[R[Q]]=n[m[Q]]+y[Q]                              ADD
       p=R[Q]+1 ; for q=1,m[Q],1 do I=bxor(band(y[Q],q),127) end
O 11   p=z[m[Q]]; n[R[Q]]=p[4][p[7]][n[y[Q]]]            GETUPVAL→GETTABLE
O 13   p=n[R[Q]]; n[m[Q]]=table.pack(unpack(p,y[Q],p.n)) CALL/MULTRET
O 24   S,Q=m[i],R[i]+1; break                            JMP+返回(带 PC 回写)
O 25   p,I={...},y[i]; table.move(p,1,m[i],I,n)          VARARG
O 27   p=z[m[Q]]; p[4][p[7]]=n[R[Q]]                     SETUPVAL
O 28   Q = if n[y[Q]] then R[Q] else m[Q]                TESTJUMP(真)
O 29   n[y[Q]]=n[R[Q]]                                   MOVE
O<=30  n[y[Q]]=n[R[Q]]%m[Q]                              MOD
O<=36  Q=m[Q]                                            JMP
O 37   T={["n"]=I-p+1}; table.move(n,p,I,1,T)            MULTRET 准备
O 20   n[R[Q]]=n[y[Q]](A[Q])                             CALL 1
O 21   table.move + pack(select(o,...))                  VARARGPUSH
O 22/23 见 29 形式                                       MOVE/自变体
b[73]  f==1 l[R[x]]=A[k[x]]  GETGLOBAL ; f==0 VARARG ; f==5 1-arg CALL ;
       f==6 字符串解密并把指令改写成 (op=2,lane=(231,200,146)) ; f==8 关闭 upvalue ;
       f==4 三通道 varint 重排+回写 ; 常量解密: bxor(v,287072149)
统计:   主循环里 [Q] 索引 859 次, 通道热度 m:233 R:168 y:160 J:152 A:27 t:17 X:15 D:14
opcode 上界证据: `if S==251 then` 与比较阈值最大值 236 → **≈250 个操作码**
```
### 4.7 入口控制流(还原的伪码, 结构确证)
```lua
function FC(b, ...)                      -- = setmetatable(TBL,{}):FC()(...)
  local ok, pc = b:_L()                  -- true, 3
  while ok do
    if pc <= 1 then pc,… = b:qL(…)       -- 组解码推进 (radix85 累加)
    elseif pc <= 3 then
      pc,regs,lim,buf,src,… = b:HL(…)     -- state3: gsub+fromstring, 建 reader{-5,5,#u-1}
                                          -- state<=2: for 回边 (pos+=5, pos<=#u-1)
    else
      s,… = b:eL(…)                      -- state4: writeu32(dst,w,val); w+=4
                                          -- state5: val = 85^4*(c0-40) + 其余位权
                                          -- state6: b[b[94]](b, z, b.s={}, nil)  ← 交给 chunk 解析器
                                          -- state1: return B
    end
  end
end
```

## 5. 卡在哪
1. **最后一层白化**:容器链(escape→radix85→u32→窗口)已 100% 对齐(证据: 组数被 5 整除、5 个权重常数原样存在、
   重复距离 gcd=64), 但 14,937 个字的统计与随机无异 ⇒ 每个 lane 另有 key. 那些 key **嵌在 per-opcode 的
   解码站点里**(52+9 个 `^K`、1 个仿射乘加), 必须先知道 chunk 的分段布局才能回代 ⇒ 需要把 `a`(46 handler)、
   `L`(9)、`Y`(73)、`eL/qL/kC/jL/…` 的读游标语义完整复刻成离线模拟器. 我估计还需 >100 步, 且任一处 off-by-one
   就整段崩掉 —— 判定为超出"纯静态一次性"合理预算, 主动停在字节流层.
2. **writeu32 vs Z[M]=u 的二义性**: 5 字符组的值域 85⁵=4,437,053,125 > 2³², 489 组溢出. 代码里同时存在
   "写进数字表"(`Z[M]=u`, 不截断)与"writeu32"(截断). 哪一条喂给 chunk 解析器我无法静态判定, 而这一条正好是
   离线解码的开关. 这是我最想让你知道的一个"未决分叉".
3. **静态调用图**: `b[z[4]](b,z,b.s,nil)` 的被调下标来自解码后的数据 ⇒ 反扁平化只能给出"每棵 dispatch 树"内部,
   跨树边不可见. `tools/ops.py` 因此只重建了第一棵树(其余树的判别变量是状态号 `q` 而非 `O`).
4. **Luau 语法**: `+=/-=`(84)、`continue`(45)、if-表达式(17) 让任何 Lua 解析器直接报错; 我为解析做了
   等长改写(`op=`→`= `, if-expr→`and/or`), 但那 17 处 `Q=if C then A else B` 的 `end` 归属(共享给外层 if)
   我没能形式化证实 —— 只影响局部可读性, 不影响结论.
5. **原始语义**: 没有常量池就没有字符串. 唯一内容线索是**静态存在 Vector2.new/Vector3.new/vector.create 常量类**
   与 `buffer.readf32×3`、`readf64` ⇒ 原脚本处理屏幕/世界坐标与浮点 ⇒ 典型 Roblox 作弊/UI 脚本形态. 仅此而已.
6. 6 个 import 槽我映射了但没找到用途: `countrz[23]`、`rep[24]`、`pack[72]`/`unpack[7]`、`insert[90]`、`close[77]`.

## 6. 自评
- 步数: **40 次工具调用**, 15 个"假设→操作→观察→结论"循环, 0 次执行样本, 0 次网络依赖(只装了个 parser).
- 覆盖度: 结构/编解码/防御 **接近完整**; 常量与原始源码 **未拿到**.
- 置信度(逐项): import 表 **99%**(直接抄自表构造, 只有一处 `(0)` 是运行期覆盖);
  radix-85+窗口+权重 **95%**(三处独立证据互洽; 扣分在 2³² 二义性);
  varint/位宽选择器 **92%**; opaque-predicate 折叠 **97%**(数值验证); 字符串 LCG 密钥流 **90%**;
  帧布局/SoA **85%**; opcode **编号 55%**(叶语句逐字 100%, 但编号只覆盖一棵树);
  "≈250 个操作码" **60%**(只有 251/236 两个上界证据); "Roblox 作弊/UI 脚本" **40%**.
- 猜的: `Z[M]=u` 那条路的用途; 489 溢出组是冗余位而非我的错误; `S==251` 是"帧类型"而不是校验和;
  4 个蹦床 `_L/KL/zL/M` 属于"每类例程的初始状态获取器".
- 如果给我 1 个运行时 hook 点(`buffer.fromstring` 的入参/回参, 或第一次 `readu32` 的 buffer), 这层壳当场就开了.

## 7. 全部混淆技术清单(本样本实测)
分类速览: **结构类** 全局表化 handler / 控制流扁平化(136 状态) / 状态号分发 / 自修改 dispatch /
双 while 巨型循环内联 / 寄存器轮转别名 / 全局→局部别名 / 重复形参遮蔽 / 表达式化条件跳转(cmov) /
数字槽 import 表(把符号名换成下标) / 运行期 vtable 与槽位覆写(`b[94]`) / 入口蹦床 `_L` 型"取初始状态".
**数据类** ASCII-armour(85 进制, 偏移 40) / 单字符快捷转义表 `pC` / `LPH:` 头 + 4 字节垃圾头 /
read 窗口带界(#u-1) / 每常量独立盐值 + LCG 密钥流 XOR / 尺寸类分桶(1,2,4,8,12,16) / 惰性解密+按类型回读 /
base-128 varint +128 偏置 / 位宽选择器(7/14/21) / 常量以 u32 打包 + per-lane XOR key /
仿射 lane key(乘+加 mod 2³²) / 值域冗余(85⁵>2³² 的无信息位).
**算术类** mod 2³² 归一化原语 `vL` / 16bit 部分积拼出的 `iL` 乘法 / 恒等式噪声 `x+~x=2³²-1` /
`K*0xFFFFFFFF ≡ -K` 伪装减法 / 大素数乘性掩码 / `%256` 密钥流.
**防御类** 反 traceback(error level 0 + `LPH:?:` 前缀 + 消息形状探测) / 自擦(`b[2]=nil`、`(...)[...]=nil`) /
死码伪密钥表 `h` / `__index` 代理懒解析全局(隐藏 API 足迹) / rawget/rawset/getmetatable 绕 hook /
pcall-xpcall 包裹 / getfenv-setfenv 环境替换 / coroutine 化(可 yield, 掩人耳目) /
`buffer`(不可变字节对象, 难以中途篡改) / 无 `game`/`syn` 等明文 API 名 /
机器生成单行输出(反 grep/反 diff) / 高密度随机命名(b,u,z,Z,o,w,K,G,q,M,F,H,E,V,f,B,j,d,Y,_,g,l,k,m,x,R,t,J,S,O,y,A,a,X,N).
