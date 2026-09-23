# XXSV5.lua 逆向静态分析报告

> 纯静态逆向，未执行原文件。所有中间产物通过 Python 复现解码逻辑得到，可在 `/tmp` 验证。

## 1. 攻击目标：你最终试图还原什么

- **外层加载器**：`local t={} return setmetatable({[9088]=..., ["g"]=..., [1910]=..., [901]=..., [7594]=...},t):g()`。`[9088]` 是 userdata/add 检测工具，`["g"]` 是主 VM 入口，`[1910]` 返回 51 个标准库别名，`[901]` 是 proto 解析器，`[7594]` 是 VM 执行器。
- **第一层 Base86 容器**：`w[8255]/w[7919]/w[5850]` 三个同构解码器，字母表 86 字符，碎片首字符路由，二次 Base86 解码得到 3×5920 字节二进制，密钥链 `sm -> ac -> sv`，最终通过 `h(sm..ac..sv,5)` + `w[5189]` + `w[7667]` 解出主字节码 `n`。
- **第二层 Base85+压缩**：`w[7240]` 内含 `Y0RObv?USM!(Jq|c7N8Hu1$j6&;Q@a>2kl#X*Ez5~)={nfrZC9w<+}_P3toIWpKdgyx`4FDsmi^G%ThBe-ALV` 85 字符表 + `it` 85幂表 + `q` 256幂表，`z` 25420 字符 Base85 → 20336 字节 → LZ77+Adler 解压 → 32852 字节 Lua（`/tmp/decompressed2.lua`），内含 Roblox 检测 + 第二层 hg 解密。
- **第三层 hg 流加密**：`decompressed2.lua` 中的 `wi=8151, nj={9,11,6,3,8,10,12,7,4,1,5,2}, hg=12×~680 字节`，通过 `wv XOR` + `ml LE` + `to/uy/qp/km` ChaCha-like 流密码解密得到 `ANIT2` + Adler 校验 + 8142 字节 `anti_rbx.lua`（`/tmp/final.lua`）。
- **反调试套件**：`final.lua` 63 个 `ok()` 检查，`PIN_CHECKS=63 PIN_FINAL=4189635056 MASK_SEED=0x9E3779B9`，覆盖 F20 C hook 检测、F21 同源断言、F22 库行为自测、D13 traceback 形状、D14 error 通道、executor 指纹、timing、gethook、metatable locked、F25 抗补丁、getgenv 桥接。
- **VM 指令语义**：`w[901]` 原型解析（`d(s,i,x,0)` 混淆算术、`y(p,i,cx,is,x)` 校验）、`w[7315]` 指令合法性校验（200+ 分支）、`w[7594]` 执行器（弱表缓存 `__mode="kv"`、opcode 表 `n={{8,t.af,...}}`、`op.h=(mp+le+qt)%65520`）。
- **标准库隐藏**：`w[1910]` 通过单字母函数表拼出 `select, error, pcall, unpack, string, byte, sub, format, table, concat, char, math, floor, tonumber, type, tostring, next, getmetatable, setmetatable, rawget, rawequal, debug, loadstring, integer, fromstring, info, bit32, buffer, bxor, band, bor, bnot, lrotate, lshift, rshift, create, writeu8, readu8, readu16, readu32, readf64, len`。

最终目标是拿到**原始源码逻辑**（Roblox exploit 的反调试 + VM + 主作弊逻辑）和**可验证中间产物**。

---

## 2. 逐步流程：假设 → 操作 → 观察 → 结论

### Step 1: 外层结构
- **假设**：`setmetatable({[9088]=..., ["g"]=...},t):g()` 是 XXS/Luraph 入口。
- **操作**：`grep -o "w\[\d+\]=function"` 统计；查看尾部 `},t):g()`；用 Python 提取 `setmetatable({` 到 `},t):g()` 内的 `[xxxx]=function`。
- **观察**：外层表含 `[9088], ["g"], [1910], [901], [7594]`；`["g"]` 内 `while true do if not(q~=396) then w[7919]=...` 循环定义 `7919,7240,5850,572,9086×2,1324,6142,3227,8687,102,7869,615,9602,9080,5189,7315,1283,3572,3328,7667,8255,7015` 共 24 个。
- **结论**：两阶段 `q` 状态机：第一阶段定义所有 `w`，第二阶段在 `w[1910]()` 后加载 VM。`w[901]` 与 `w[7594]` 是外层表的 proto 解析与执行器，不是内层定义的。

### Step 2: Base86 解码器
- **假设**：`j[51]="6?...` 是字母表，`j[25]={...}` 是碎片，`j[53]=86, j[3]=256, j[20]=16777216` 是 Base86 常量。
- **操作**：Python 提取 `j[48]/j[51]` 的 `..` 拼接，Lua 转义 `\30,\x21,\065` 解码，得到 86 字符；提取 `j[52]/j[25]` 的 `{...}` 碎片。
- **观察**：`w[7919]` 13 碎片，`w[8255]` 13 碎片，`w[5850]` 9 碎片，首字符各异；`j[66]` 计算 `for x=1,#q do j[66]=(j[66]+byte(q,x))*256%86; j66=(j66+len)%86`，`j[73][byte(alphabet,x)]=(x-1+j66)%86`。
- **结论**：首字符路由：`j9=(map[first]-hash)%86`，`ordered[j9]=sub(frag,2)`。这是突破点，靠 `c(j[25][t],2)` 去头可认出。

### Step 3: 二次 Base86 状态机
- **假设**：`j[96]` 扁平化状态，`114` 入口，`132,953,983` 等为出口。
- **操作**：提取 `j[96]` while 循环，识别 `j[38]=0;j[80]=1;for t=1,j[7] do j[50]=byte(j76,j36+t-1); j16=map[j50]; j38+=j16*j80; j80*=86 end`。
- **观察**：头部 4 字符 little-endian base86 解出 `remain = value % 16777216` 为剩余长度；`mod=last%3` 决定下次读 4/5/6 字符 → 3/4 字节；`%256` 提取字节。
- **结论**：实现通用解码器，`w[8255]` 解出 5920 字节 `/tmp/out.bin`，`w[7919]` 5920 `/tmp/out7919.bin`，`w[5850]` 同理 5920 `/tmp/out5850.bin`，验证 `j66=32` 对 `sm`。

### Step 4: w[7240] Base85+压缩
- **假设**：`v` 85 字符表 + `it` 85幂 + `q` 256幂 = Base85。
- **操作**：提取 `local z="YYY0{QRm#)...` 下一个 `"` 为结尾，长度 25420，%5==0，建 `char->val` 表，5→4 big-endian 解码得 20336 字节；再按 `n=5字节BE, u,w,qb,oq 2字节, flag bit` 的 LZ77 解码。
- **观察**：解压得 32852 字节 Lua，头 `do local uo = ( typeof ~= nil ) and ( type ( game ) ~= 'nil' )...`，含 `wi=8151, nj, hg`；Adler `u==qb` 校验通过。
- **结论**：`w[7240]` 是第二层加载器，成功还原 `/tmp/decompressed2.lua`。

### Step 5: hg 流加密（第二层 → final.lua）
- **假设**：`hg` 12 碎片需按 `nj` 逆序，`mj/ju/zz` 与 `py/bv/fd` 为 XOR 密钥。
- **操作**：Python 实现 `lua_unescape`、`wv`：`bxor(byte, (c+wh*7)%256)`、`ml` LE 32-bit、`to`：`jm[1]+=cw+mn; jm[2]=lrotate(bxor(jm[2],cw),13); jm[3]+=lrotate(jm[7],7); jm[4]=lrotate(bxor(jm[4],jm[6]),17); jm[5]+=jm[2]; jm[6]=lrotate(bxor(jm[6],jm[3]),9); jm[7]+=jm[1]+cw; jm[8]=lrotate(bxor(jm[8],jm[5]),3)`、`uy`：`bxor(state0, rol(state3,11), state2+rol(state5,7), state7)`、`qp`：`for vf=1,8 do to(jm, me[(vf-1)%3+1]+0x9E3779B9*vf, 0)`、`km`：`ry=fj+ir*256+ct*65536+bz*16777216; lb=bxor(ry, uy(jm)); to(jm, ry, mn)`、`wb` 为 `nj` 逆序 `[10,12,4,9,11,3,8,5,1,6,2,7]`、`JR` 顺序读 `hg[wb[xv]][kg]`。
- **观察**：`zo` 32 字节 `5\x8a=óÍ´0;\x90_ú...`，`cf` 12 字节 `Ñé\x8fô£\x10f\x92\x8aZ5Â`，`sp=[4080896565,...]` 8个，`me=[4103072209,2456162467,3258276490]`，`vp=qp(ml(zo),ml(cf))`，`oy=4321 mm=3845` → `tb=mm*65536+oy=2969611504`，`ha=ANTI2`，`od=True`，`lp=8151`，`su` 8142 字节。
- **结论**：完全破解，得到 `/tmp/final.lua` 8142 字节 `anti_rbx.lua`，`loadstring(mq,"rbx-core")` 后 `iy.run()`。

### Step 6: final.lua 反调试
- **假设**：`PIN_CHECKS=63 PIN_FINAL=4189635056` 为魔数链。
- **操作**：阅读 `final.lua`，统计 `ok()` 调用，分类 `rbx hard gate, cap fingerprint, F20 C hook, F21 origin, F22 lib, D14 error, D13 trace, timing, gethook, metatable locked, F25 anti-patch, getgenv bridge`。
- **观察**：63 个检查：0 rbx 硬门，2..8 能力指纹（identifyexecutor/islclosure/iscclosure/getgenv/getrenv/getreg/getrawmetatable），9..10 finger，11..34 F20 24 个 C 函数（loadstring/pcall/error/type/tostring/tonumber/rawget/rawset/rawequal/getmetatable/setmetatable/select/next/ipairs/pairs/unpack/string.byte/char/sub/rep/table.concat/insert/math.floor/bit32.bxor），35..42 F21 8 个 origin vs pcall，43..52 F22 10 个 lib 行为（byte/char/floor/bor/bxor/rep/concat/select/max/min/tostring(nan)），53..55 D14 error 通道（error/pcall/xpcall 完整性），56..57 D13 traceback 形状（`=[C]` 或 `:%d+` 与 `:%d+:`），58 timing（4000 次 bxor <0.5s），59 gethook 清空，60 metatable locked（`The metatable is locked`），61 F25 抗补丁重算（拆字节+XOR掩码+读回校验），62..63 getgenv 桥接，最终 `chain=mix(chain,bit)` 与 `PIN_FINAL` 封缄。
- **结论**：通用反调试套件，失败动作为 `error("script error (tag)",0)` 伪装普通错误，顶层 error 中止整个 chunk。

### Step 7: ChaCha 与 VM
- **假设**：`w[615]` 含 ChaCha 常量。
- **操作**：计算 `1634760921-116=0x61707865` 等。
- **观察**：`0x61707865,0x3320646e,0x79622d32,0x6b206574` = "expa","nd 3","2-by","te k"；`w[3572]` quarter-round `+ xor lrotate`；`w[102]` S-box；`w[2902]` 流加密 `f(w[f(x/4)+1]/2^(8*(x%4)))` 取字节。
- **结论**：`w[615]` ChaCha20 block，`w[3572]` quarter-round，`w[102]` 密钥初始化，`w[2902]` 流加密，`w[572]` LEB128 varint，`w[9086]` 4 字节 BE，`w[901]` proto 解析 `d(s,i,x,0)` 混淆算术，`w[7315]` 校验，`w[7594]` 执行器弱表缓存。

---

## 3. 依赖的特征（最重要）

1. **Base86 三元组**：`j[53]=86, j[3]=256, j[20]=16777216` + 字母表含控制字符 `\30\29\28` + `it` 85幂 `q` 256幂。
2. **首字符路由**：`j[9]=(map[byte(first)]-hash)%86` + `if j9<1 or j9>#frags or ordered[j9] then error end; ordered[j9]=sub(frag,2)`。
3. **二次解码循环**：`j38=0;j80=1;for t=1,need do j50=byte(enc,pos+t-1); j16=map[j50]; j38+=j16*j80; j80*=86 end; for _=1,outBytes do out+=char(j38%256); j38//=256 end`。
4. **哈希 shuffle**：`hash=0; for b in key: hash=(hash+b)*256%86; hash=(hash+len)%86; map[byte(alphabet,x)]=(x-1+hash)%86`。
5. **Base85 指纹**：`v` 85 字符 + `it={[0]=1,85,7225,614125,52200625}` + `q={[0]=1,256,65536,16777216}`。
6. **LZ77+Adler**：`if r%2==1 then literal else distance+len (3+sum until <255)` + `%65447` Adler + `XXS e6,e7,e8,e9`。
7. **hg 流密码**：`wv` XOR `(c+wh*7)%256`，`ml` LE，`to` 8-int state lrotate 13/7/17/9/3，`uy=bxor(state0, rol(state3,11), state2+rol(state5,7), state7)`，`qp` key schedule `0x9E3779B9*vf`，`km` 4-byte block xor，`wb` 逆序 `nj`，`JR` 顺序读，`ANTI2` 头 + `65521` Adler + `tb==mm*65536+oy`。
8. **ChaCha 指纹**：`1634760921-116, 107220109*8+6, 2036477286-52, 898642618*2` 同时出现。
9. **标准库拼串**：`local j={function()return"w"end,...} local x=function(w,x) local j=""; for t=1,#x do j=j..w[x[t]]() end return j end` + `x(j,{17,25,20,25,4,2})` => `select`。
10. **VM 扁平化**：`local q=((i~=i-1)and(95*2-1)or(...)) while true do if not(q~=396) then ...` + `//1==` / `%2==` 恒真判断 + `j[96]=114,132,953,983` 等状态。
11. **反调试**：`m and d(e,"s")` 检查 `[C]`，`userdata==t(j) and x=="add"`，`table.freeze`，`select("#",...)`，`XXS eX`，`if w==w then`。
12. **Roblox 指纹**：`typeof, game, getgenv, loadstring` 四连 + `wi=8151` + `nj` 顺序表 + `hg` 12 碎片。
13. **魔数链**：`mix(x,bit)=(x*31+bit)%4294967296` + `PIN_FINAL=4189635056` + `PIN_CHECKS=63`。

---

## 4. 实际还原出的东西

### 4.1 常量表
- `t.e=256, t.h=4294967296, t.u=32161, t.aa=4294967295, t.ab=65536, t.ac=65479, t.ad=16777216, t.ae=3001000, t.af=8000000`
- Base86 字母表 w7919：`6?`... 86 字符，w8255：`!4fdWU ...` 86，w5850：`Aa;#*)461K7`... 86
- Base85 字母表 w7240：`Y0RObv?USM!(Jq|c7N8Hu1$j6&;Q@a>2kl#X*Ez5~)={nfrZC9w<+}_P3toIWpKdgyx`4FDsmi^G%ThBe-ALV` 85
- 幂表 `it`, `q`，ChaCha `0x61707865...`

### 4.2 解码产物
- `w[8255]` → 5920 字节 `/tmp/out.bin`，`j66=32`
- `w[7919]` → 5920 `/tmp/out7919.bin`
- `w[5850]` → 5920 `/tmp/out5850.bin`（本次新增，header 解出长度 5920，5→4 base86）
- `w[7240]` → 32852 字节 `/tmp/decompressed2.lua`，Roblox 检测 + hg 解密状态机
- `hg` 12 碎片 → 8151 字节 wi，`ANTI2` 头，`oy=4321 mm=3845 tb=2969611504`，`su` 8142 字节 `/tmp/final.lua`

### 4.3 final.lua 逻辑
```lua
-- anti_rbx.lua 通用反调试套件
local PIN_CHECKS=63
local PIN_FINAL=4189635056
local MASK_SEED=0x9E3779B9
local function mix(x,bit) return (x*31+bit)%4294967296 end
-- 0 rbx hard gate
-- 2..8 cap fingerprint
-- 9..10 finger
-- 11..34 F20 24 C hook
-- 35..42 F21 8 origin vs pcall
-- 43..52 F22 10 lib behavior
-- 53..55 D14 error channel
-- 56..57 D13 traceback shape
-- 58 timing 4000 bxor <0.5s
-- 59 gethook clear
-- 60 metatable locked
-- 61 F25 anti-patch recompute
-- 62..63 getgenv bridge
-- final seal checks==63 and chain==PIN_FINAL else error("script error (tag)",0)
```

### 4.4 VM 结构
- `w[1910]` 返回 51 个别名，已解出 `string, byte, sub, format, table, concat, char, math, floor, tonumber, type, tostring, next, getmetatable, setmetatable, rawget, rawequal, debug, loadstring, bit32, bxor, band, bor, bnot, lrotate, lshift, rshift, buffer, select, error, pcall, unpack` 等。
- `w[572]` LEB128 varint，`w[9086]` 4 字节 BE，`w[615]` ChaCha block，`w[3572]` quarter-round，`w[102]` S-box，`w[2902]` 流加密。
- `w[901]` proto 解析：`d(s,i,x,0)` 混淆算术决定操作数槽位，`y(p,i,cx,is,x)` 校验，`q[j].l` 原型表，`l` 字节码，`v` hash，`g` 常量。
- `w[7594]` 执行器：弱表 `__mode="kv"`，opcode 表 `n={{8,t.af,...}}` 50+ 条，`op.h=(mp+le+qt)%65520`。

---

## 5. 卡在哪

1. **主字节码容器 w[5189]+w[7667]**：`sm..ac..sv` 17760 字节，`h(...,5)` 后 17756 字节，头部 `n,w,o,mp` 的 `q` 读取器不是简单 LE，而是依赖 `mp,le,qt,ii` 等种子（`w[3328]/w[9080]/w[1283]`），`k=1+(d*19+e*11+...)%2147483646` 等校验未完全静态推导，`w` 读出 558M 不合理，说明 `q` 有额外变换。已尝试 LE/BE 和 4098 模式搜索无果。
2. **VM 指令语义**：`w[7315]` 200+ 分支检查 `c<256 and m==0` 等，`w[7594]` opcode 表每项含义（如 8=LOADK, 7=JMP）需动态 trace，纯静态只能猜 60%。
3. **w[2902] 流加密密钥**：`q={2131147480,...}` 8 常量，`p` 密钥调度，`n(p,d,h)` 调用 ChaCha 核心，密钥来自 `w[1910]` 的 `jy` 等字符串，静态难定。
4. **完整原始作弊逻辑**：`final.lua` 只是反调试，主作弊逻辑应在 `sm..ac..sv` 解出的 `n` 中，`n` 需经 `w[3227]` 的 byte/varint reader + `w[9602]` double 解码 + `w[7240]` 已被 anti_rbx 占用（实际应为 proto 解析，但被重写为 anti_rbx），导致 `op,ns,nr=w[7240](n,...)` 返回 nil，`w[901]` 无法继续，需进一步理清 `q` 状态机中 `w[7240]` 是否在 anti_rbx 执行后被重定义为 proto 解析器。
5. **无 Lua 解释器**：环境无 `lua/luajit`，无法直接运行 `w[1910]()` 拿到真实函数表，只能靠字符串拼表推测，`ii="integer"` 等异常字符串未解。

---

## 6. 自评

- **信心**：
  - Base86 解码器、Base85+LZ77、ChaCha 常量、Varint、标准库拼串、hg 流密码 `wv/ml/to/uy/qp/km/wb/JR`、Adler 校验、ANTI2 头、PIN_CHECKS/PIN_FINAL：**95% 确定**（Python 复现解出 5920×3 和 32852 和 8142 字节，校验通过）。
  - 碎片路由、状态机扁平化、`mix` 魔数链、F20/F21/F22/D13/D14 分类：**90% 确定**。
  - VM 原型解析 `w[901]`、执行器 `w[7594]`、校验器 `w[7315]` 的具体 opcode 语义：**60% 猜的**，基于 Luraph 14.9 报告和常见 Lua VM 模式。
  - 主作弊逻辑（`sm..ac..sv` → `n` → `op,ns,nr` → `wo,kl,yr,mj`）：**30% 猜的**，卡在 `w[5189]/w[7667]` 容器。
- **花费步数**：约 30 步（提取 `w` 列表、字母表、碎片重组、二次 Base86、Base85+LZ77、hg 解密、final.lua 分类、ChaCha、varint、标准库拼串、VM 结构）。
- **确定还原 vs 猜的**：
  - 确定：`w[7919]/w[5850]/w[8255]` 模板、`w[7240]` 解压、`hg` 解密全链路（`zo` 32B `cf` 12B `sp` 8int `me` 3int `vp` 8int `oy/mm/tb` `wb` 逆序 `JR`）、`final.lua` 63 检查、`t.*` 常量、`v` 字母表、`it/q` 幂表、`XXS eX`。
  - 猜的：`w[901]` 的 `d/y` 算术对应操作数含义、`w[7315]` 每分支真实 opcode、`w[7594]` 中 `n` 表每项含义、`sm..ac..sv` 容器的 `q` 读取器和 `k/c` 种子。

---

## 7. 关键特征总结（防御/检测）

- **大数字表**：`it={[0]=1,85,...}` Base85，`q={[0]=1,256,...}` Base256，`j[53]=86 + j[20]=16777216` Base86。
- **首字符路由**：`local X=T[Y];if X` + `c(T,2)` 去头 + `k(T)` 拼接。
- **哈希 shuffle**：`for x=1,#q do hash=(hash+byte(q,x))*256%86`。
- **状态机**：`j[96]=114,132,953,983` / `j[98]=460,747,870,899` / `q=189,396` + `//1==` / `%2==` 恒真。
- **ChaCha**：`1634760921-116` 四算术同现。
- **标准库拼串**：`j={function()return"w"end,...} x(j,{17,25,20,25,4,2})`。
- **Adler**：`%65519` / `%65447` / `%65521`。
- **Roblox**：`typeof, game, getgenv, loadstring` + `wi=8151` + `nj` + `hg` 12 碎片 + `ANTI2`。
- **反调试魔数**：`PIN_CHECKS=63, PIN_FINAL=4189635056, MASK_SEED=0x9E3779B9, mix(x,bit)=(x*31+bit)%4294967296` + `ok()` 63 次 + `whatis` 含 `[C]` + `:%d+:` error 形状 + `The metatable is locked`。

以上可用于静态检测 XXSV5 变种，第二层 `decompressed2.lua` 与第三层 `final.lua` 已完全还原，主容器 `sm/ac/sv` 仍需动态辅助。
