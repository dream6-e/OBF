# Luau 专属语法与函数实测

> 测试日期：2026-10-19
> 测试环境：`toolchains/bin/luau`（Luau 0.735，`_VERSION == "Luau"`，构建标注 "OBF CLI-compatible runner"）与 `toolchains/bin/lua5.1`（Lua 5.1.5）
> 方法：同一段源码分别交给两个解释器执行，对比解析结果、运行结果与报错；另用 `luau-compile --text -O0/-O1/-O2` 观察编译期优化。
> 说明：本文只记录调研结论，未修改混淆器任何代码；测试脚本为临时文件，不随仓库分发。

---

## 0. 结论速览

按“对混淆器的实际价值”排序：

1. **`bit32`**（15 个函数）：原生位运算。实测 20 万次 `bxor` 仅 0.0024s，而现有“算术模拟 bxor”需 0.1678s，约 **70×** 差距；同时源码更短。
2. **`buffer`**（28 个函数）：字节/位级读写、精确浮点位型、`fromstring/tostring`、重叠区间拷贝（memmove 语义）；是一等类型，`type()` 返回 `"buffer"`。
3. **`integer` 类型**（由 `buffer.readinteger` 产生）：有符号 64 位，不能算术/拼接，`tonumber` 返回 nil，和同值 number 在表中是两个不同 key——目前发现的**最不可伪造**的数据类型。
4. **`vector`**（14 个函数）：3×float32 不可变值类型，可哈希、可作表键、支持运算符，`type()`/`typeof()` 返回 `"vector"`。
5. **`table.freeze/isfrozen`**：浅冻结常量表，普通赋值和 `rawset` 都被拦截。
6. **`debug.info`**：读源码名/行号/参数个数；配合 `loadstring(src, "=Fake")` 与换行填充可伪造函数来源和行号。
7. **Luau 专属语法**：`continue`、if 表达式、复合赋值、`//`、字符串插值、广义迭代 `for k,v in t`、类型标注（编译期完全擦除）。
8. **`string.pack/unpack`、`utf8`、`math.noise`、`coroutine.close`** 等库级原语。

> 这些能力绝大多数在 Lua 5.1 下要么解析失败、要么运行期缺函数，只能用于 **Luau 专属目标**（例如 Roblox 伪装件的独立模式），不能混进当前“双端都能跑”的产物。

---

## 1. 语法差异

| 特性 | Luau 0.735 | Lua 5.1.5 | 混淆用途 |
|---|---|---|---|
| `x += 1`、`t.x ..= "y"`、`x //= 2` | ✅ | ❌ 解析失败 | 压缩表达式、读写耦合、目标只求值一次 |
| `local x: T`、`expr :: T` | ✅ | ❌ | 类型擦除后的诱饵/假签名 |
| `type T = ...`、`export type`、泛型 `<T>`、泛型方法 | ✅ | ❌ | 源码级假类型结构，编译期擦除 |
| `continue`（必须是块内最后一条语句） | ✅ | ❌ | 打散循环控制流，替代 goto |
| 反引号字符串插值 `` `v={x+1}` `` | ✅ | ❌ | 内联表达式、压缩拼接；可嵌 if 表达式、`\{` 转义 |
| if 表达式 `if c then a elseif d then b else e` | ✅ | ❌ | 值级派发，替代查表 |
| 广义迭代 `for k,v in t do` | ✅ | ❌ | 去掉 `pairs` 痕迹 |
| `//` 整除 | ✅ `-7//2 == -4`，`1//0 == inf` | ❌ | 精确整数运算、位提取 |
| `0b1010`、`1_000_000` | ✅ | ❌ | 词法噪声（编译期会被折叠） |
| `@native`、`@checked` 函数属性 | ✅ | ❌ | 配合 `--codegen` 才有实际作用，否则仅标记 |
| 类型化可变参数 `...: number` | ✅ | ❌ | 假签名 |
| `\x41`、`\u{41}`、`\z` 转义 | ✅ `A` / `A` / 跳空白 | ⚠️ 不报错但值不同：`x41` / `u{41}` / `z` | **仅 Luau 专用**；双端会静默分歧 |
| `!=` | ❌（提示用 `~=`） | ❌ | — |
| `goto` / `::label::` | ❌ | ❌ | — |
| `<const>` / `<close>` | ❌ | ❌ | — |

### 1.1 语法实测摘录

```text
syntax  compound +=            luau ok  -> 3        lua5.1 ERR: '=' expected near '+'
syntax  type annotation        luau ok  -> 42       lua5.1 ERR: unexpected symbol near ':'
syntax  continue for           luau ok  -> 1 | 3    lua5.1 ERR: '=' expected near 'end'
syntax  string interpolation   luau ok  -> v=42     lua5.1 ERR: unexpected symbol near '`'
syntax  if-expression          luau ok  -> 1        lua5.1 ERR: unexpected symbol near 'if'
syntax  generalized iter       luau ok  -> 3        lua5.1 ERR: '=' expected near '+'
syntax  floor div              luau ok  -> 3  -4    lua5.1 ERR: unexpected symbol near '/'
syntax  binary literal         luau ok  -> 10       lua5.1 ERR: malformed number near '0b1010'
syntax  numeric separators     luau ok  -> 1000000  lua5.1 ERR: malformed number near '1_000_000'
syntax  escape x41             luau ok  -> A        lua5.1 ok  -> x41        <-- 静默分歧
syntax  escape u brace         luau ok  -> A        lua5.1 ok  -> u{41}      <-- 静默分歧
syntax  escape z               luau ok  -> ab       lua5.1 ok  -> az...b     <-- 静默分歧
syntax  bang neq               luau ERR            lua5.1 ERR
syntax  goto label             luau ERR            lua5.1 ERR
```

`continue` 的限制：必须是所在块的最后一条语句，否则报 `Expected 'end' ... got ...`；在 `repeat` 中 `continue` 会跳到 `until` 条件判断；嵌套循环只作用于最内层。

### 1.2 类型标注的编译期擦除

带类型标注与不带标注的同一段代码，`luau-compile --text -O1` 的指令完全一致，差异仅在源码行号注释：

```lua
-- typed
type T = {number}
local function f(x: T, n: number): number
  local y: number = x[1] + n
  return y
end
```

结论：类型标注、类型别名、泛型、`::` 断言、`export type` 都**不产生任何运行期指令**，可作为零成本的源码级诱饵/假签名，但也会让 `luac5.1 -p` 直接失败。

---

## 2. 库与类型差异

| 能力 | Luau 0.735 | Lua 5.1.5 | 备注 |
|---|---|---|---|
| `buffer` | ✅ 28 个函数 | ❌ 无此全局 | `type()`/`typeof()` 返回 `"buffer"` |
| `bit32` | ✅ 15 个函数 | ❌ | 原生位运算 |
| `vector` | ✅ 14 个函数 | ❌ | 3×float32；`type()`/`typeof()` 返回 `"vector"` |
| `utf8` | ✅ 5 个函数 | ❌ | `char/codepoint/codes/len/offset` |
| `string.split` | ✅ | ❌ | 支持 plain 标志 |
| `string.pack/unpack/packsize` | ✅ | ❌ | 支持 `i1..i8 I1..I8 f d n j J s z x <>=!` |
| `table.create/clone/find/freeze/isfrozen/move/clear` | ✅ | ❌ | `clone` 保留元表；`freeze` 是浅冻结 |
| `table.pack/table.unpack` | ✅ | ❌ | 全局 `unpack` 两端都有 |
| `math.clamp/sign/round/noise/lerp/map` | ✅ | ❌ | `math.noise` 跨进程确定 |
| `coroutine.close/isyieldable` | ✅ | ❌ | `close` 可关闭 suspended 协程 |
| `debug.info` | ✅ | ❌ | 字段 `s/l/n/f/a`；`debug.getinfo` 在 Luau 为 nil |
| `typeof` / `rawlen` | ✅ | ❌ | `typeof` 能区分 `buffer`/`vector`/`integer` |
| `newproxy`、`table.getn`、`table.maxn`、`math.frexp/ldexp/modf/fmod/atan2` | ✅ | ✅ | 双端可用 |
| `string.dump` / `load` / `debug.getinfo` | ❌（nil） | ✅ | Luau 不能做字节码转储/加载 |
| `io` / `os.exit` | ❌（nil） | ✅ | Luau CLI 无 io/os.exit |
| `module` / `arg` | ❌（nil） | ✅ | 5.1 的历史入口 |
| `math.mod` / `string.gfind` | ❌ | ✅ | 5.1 遗留别名 |
| `_G` | **冻结**（`table.isfrozen(_G)==true`） | 可写 | Luau CLI 下 `_G.X=1` 直接报 readonly |
| `getfenv/setfenv` | CLI 有；`getfenv(0)~=_G`；`setfenv(0,...)` 实测不生效 | 有；`setfenv(0,...)` 报错 | Roblox 侧需另行验证 |
| `loadstring` | ✅（CLI） | ✅ | Roblox 默认禁用 |
| `collectgarbage("stop"/"restart")` | ❌ pcall false | ✅ | `"count"`/`"collect"` 可用 |

### 2.1 可用函数清单（Luau 0.735 实测）

```text
buffer (28): copy, create, fill, fromstring, len, readbits, readf32, readf64,
             readi16, readi32, readi8, readinteger, readstring, readu16, readu32,
             readu8, tostring, writebits, writef32, writef64, writei16, writei32,
             writei8, writeinteger, writestring, writeu16, writeu32, writeu8

vector (14): abs, angle, ceil, clamp, create, cross, dot, floor, lerp,
             magnitude, max, min, normalize, sign

bit32  (15): arshift, band, bnot, bor, btest, bxor, byteswap, countlz, countrz,
             extract, lrotate, lshift, replace, rrotate, rshift

utf8   (5):  char, codepoint, codes, len, offset

coroutine (8): close, create, isyieldable, resume, running, status, wrap, yield

debug  (2):  info, traceback
os     (4):  clock, date, difftime, time
```

`table`、`string`、`math` 的函数数量分别为 17、17、37；`_G` 中可调用全局为 27 个（含 Luau 新增的 `typeof`、`rawlen`、`buffer`、`vector`、`bit32`、`utf8` 等）。

### 2.2 类型系统新增

```lua
print(type(buffer.create(1)), typeof(buffer.create(1)))  --> buffer   buffer
print(type(vector.create(1,2,3)), typeof(vector.create(1,2,3)))  --> vector  vector
local tok = buffer.readinteger(buffer.fromstring("\1\2\3\4\5\6\7\8"), 0)
print(type(tok), typeof(tok))  --> integer  integer
```

`buffer`、`vector`、`integer` 都是一等类型，不能由 table/userdata 伪造；可用于“类型即能力令牌”的校验。

---

## 3. `integer` 类型（本构建新发现）

```lua
local tok = buffer.readinteger(buffer.fromstring("\1\2\3\4\5\6\7\8"), 0)
```

实测结果：

| 操作 | 结果 |
|---|---|
| `type(tok)` / `typeof(tok)` | `"integer"` |
| `tostring(tok)` | `"72340172838076673"` |
| `string.format("%d", tok)` | `"72340172838076673"` |
| `string.format("%s", tok)` | ❌ `string expected, got integer` |
| `tok + 1`、`tok + tok` | ❌ `attempt to perform arithmetic ... on integer` |
| `tok .. ""` | ❌ `attempt to concatenate integer with string` |
| `tonumber(tok)` | **nil** |
| `math.floor(tok)` | ❌ `number expected, got integer` |
| `bit32.band(tok, 255)` | ❌ `number expected, got integer` |
| `tok == 72340172838076673` | **false** |
| `{[tok]='a',[72340172838076673]='b'}` | 两个不同槽位，互不覆盖 |
| `buffer.writeinteger(b, 0, tok)` | ✅ 仅接受 integer 类型；普通 number 报 `integer expected, got number` |

字节序与符号（`readinteger` 固定 8 字节，第三个参数在本构建中未改变读取宽度）：

```text
"\0\0\0\0\0\0\0\128" -> -9223372036854775808
"\255\255\255\255\255\255\255\127" -> 9223372036854775807
"\255\255\255\255\255\255\255\255" -> -1
offset=2 的 8 字节读取正常
```

产生途径：目前只发现 `buffer.readinteger` 能产生 `integer`；`string.unpack('j')` 返回的是普通 **number**（可参与算术）。这意味着 integer 值无法用数字字面量伪造，也无法用 `%d` 字符串直接还原成 integer；只能回到同一段字节。

> 版本风险：`integer` 与 `buffer.readinteger/writeinteger` 是本构建（0.735）实测可用；目标 Roblox 版本是否支持需上线前验证。

---

## 4. 元方法与语义差异

| 行为 | Luau 0.735 | Lua 5.1.5 | 说明 |
|---|---|---|---|
| `__len` 作用在 table 上 | ✅ `#t` 生效；`rawlen(t)` 绕过 | ❌ 忽略 `__len` | 双端混用会静默分歧 |
| `__idiv` | ✅ | ❌ | Luau 专属运算符元方法 |
| `__iter` | ✅ 支持 `for k,v in t` | ❌ | 自定义迭代协议 |
| `__type` | ❌ 实测被忽略（仍返回 `userdata`） | — | 不能伪造 `typeof` |
| `__gc`（newproxy userdata） | ❌ 20 次 collect 仍 0 次触发 | ✅ 触发 | 本构建实测 |
| `__namecall` | ❌ | ❌ | 两端都没有 |
| `__concat`、`__call`、`__eq`、`__tostring`、`__index`、`__newindex` | ✅ | ✅ | 行为一致 |
| `coroutine.running()` 主线程 | 返回 `thread, nil` | 返回 `nil` | 可用于环境指纹 |
| `coroutine.isyieldable()` | ✅ 主线程/协程均为 true | ❌ 无此函数 | — |
| `coroutine.close(co)` | suspended → `true`；running → `cannot close running coroutine` | ❌ 无此函数 | — |
| `math.log(8, 2)` | **3**（支持底数） | **2.079…**（忽略第二参） | 静默分歧 |
| `tostring(1e15)` | `1000000000000000` | `1e+15` | 数字格式化差异 |
| `tostring(2^63)` | `9223372036854776000` | `9.2233720368548e+18` | 数字格式化差异 |
| `tostring(0.1+0.2)` | `0.30000000000000004` | `0.3` | 数字格式化差异 |
| `tostring(0/0)` | `nan` | `-nan` | 数字格式化差异 |
| `string.format('%s', 0.1+0.2)` | 全精度 | `0.3` | 静默分歧 |
| `string.format('%*d', 3, 7)` | 返回 `"3d"`（非标准） | ❌ `invalid option '%*'` | 不要使用 |
| `table.sort` 混合类型报错 | `attempt to compare string < number` | `attempt to compare string with number` | 文本指纹 |
| 索引 nil 报错 | `attempt to index nil with 'x'` | `attempt to index local 't' (a nil value)` | 文本指纹 |
| `math.randomseed(42)` 首个随机数 | 554209 | 33470 | 序列不同 |
| `math.noise(0.25)` | `0.146484375`，跨进程一致 | ❌ | — |
| `1 // 0` | `inf` | ❌ 无 `//` | — |
| `1 % 0` | `nan` | `-nan` | 符号差异 |

`__iter` 示例（Luau 专属）：

```lua
local relay = setmetatable({[1]=h1, [2]=h2}, {
  __iter = function(self) return next, self end,
})
for k, v in relay do v() end
```

---

## 5. 编译器优化对混淆的影响

`luau` CLI 默认 **-O1**；`luau-compile` 可显式 `-O0/-O1/-O2`。

### 5.1 -O1 实测

- 字面量折叠：`1 + 2*3` → `LOADN 7`；`"a".."b"` → 常量 `"ab"`。
- 死代码删除：`if false then ... end` 整段消失。
- 常量条件简化：`if true then f = f + 1 end` 只留 `ADDK`。
- 常量传播：`local a = 7; ... (a-a)+a` 直接用 `a`。
- 未使用局部变量被 DCE：`local unused = 999` 不产生存储。
- **不会**做符号化简：`(x-x)+x`、`x+0`、`x*1`、`x*0`、`x%1`、`(x+1)-1`、`x and x or x` 都保留。

### 5.2 -O2 额外行为

- **展开常量次数循环**：`for i=1,1`、`for i=1,2`、`for i=1,5`、`while g<1`（g 已知为 0）、`repeat ... until h>=1`（h 已知）全部被展开。
- **内联小函数**：立即调用的匿名函数、单表达式小函数被内联。
- **折叠常量参数的内建调用**：`math.floor(2.9)` → 2、`bit32.bxor(1,2)` → 3、`string.char(65,66)` → `"AB"`、`#"abc"` → 3。

```text
===== O2 =====
REMARK loop unroll succeeded (iterations 1, cost 4, profit 1.25x)
REMARK inlining succeeded (cost 0, profit 3.00x, depth 0)
REMARK loop unroll succeeded (iterations 5, cost 20, profit 1.25x)
```

### 5.3 对混淆的直接结论

1. 常量型垃圾/诱饵在 O1/O2 会被折叠或删除；诱饵必须依赖**运行期值**（宿主调用、表内容、函数参数）。
2. `for i=1,1` 这类常量循环在 O2 会被直接展开；这也是目标五把它改掉的原因之一。
3. `string.char(65,66)` 在编译期会变成常量字符串进入字节码常量表——想隐藏字符串**不能**用常量参数的 `string.char`，必须让运行期密钥参与。
4. `(x-x)+x`、`x+0`、`x*1` 等不会被编译器符号化简，但仍然是可读的恒等式；人工分析能识别，不能当作强混淆。
5. 未使用局部变量会被删除，因此“只声明不引用”的诱饵没有意义。

---

## 6. Luau 专属混淆方案（可直接落地）

> 以下全部是 Luau-only；使用后产物无法再通过 `luac5.1 -p`，只能进 Luau 专属模式（如 Roblox 伪装件的独立目标）。

### 6.1 `bit32` 替换算术位运算（收益最大）

```lua
local bxor, rol = bit32.bxor, bit32.lrotate
local k = bxor(a, rol(b, 7))
```

实测 20 万次 `bxor`：算术模拟 0.1678s，`bit32` 0.0024s，约 **70×**。

`bit32` 还提供 `extract/replace/countlz/countrz/byteswap/arshift`，可直接替代现有的手写位操作。

### 6.2 `buffer` 常量池与精确位型

```lua
local pool = buffer.fromstring("\185\121\55\158\1\0\192\127")
local k0  = buffer.readu32(pool, 0)   -- 0x9E3779B9，源码中没有该字面量
local nan = buffer.readf32(pool, 4)   -- 0x7FC00001 的自定义 NaN
```

- `writeu32`/`readf32`/`readf64` 可精确制造 `-0`、次正规数、任意 NaN payload、任意 double 位型。
- `writebits/readbits` 支持 0–32 位宽的非字节对齐字段：

```lua
local b = buffer.create(4)
buffer.writebits(b, 0, 3, 5)
buffer.writebits(b, 3, 3, 7)
print(buffer.readu8(b, 0))  --> 61
```

- `copy` 支持重叠区间（类似 memmove）；`readstring/writestring` 可直接搬运字节串。

### 6.3 `integer` 能力令牌（最不可伪造）

```lua
local tok = buffer.readinteger(buffer.fromstring("\1\2\3\4\5\6\7\8"), 0)
-- type(tok) == "integer"
-- tok + 1 报错；tonumber(tok) == nil
-- t[tok] 与 t[72340172838076673] 是两个不同键
```

适合做：状态码、路由键、令牌、表键。攻击者即使知道十进制值，也无法用数字字面量伪造，且无法对它做算术推导。

### 6.4 `vector` 打包三元状态 / 类型伪装

```lua
local v = vector.create(1.5, -2.25, 3)
local sum = v + vector.create(1, 1, 1)
print(type(v), tostring(v))  --> vector  2.5, -1.25, 4
```

- 不可变（`v.X=9` 报错），可哈希，可作表键（按值相等）。
- **分量是 f32**：`0.1` → `0.10000000149011612`，`1/3` → `0.3333333432674408`，`16777217` → `16777216`；不能存 53 位 double，也不能存完整 32 位整数。
- 只能通过 `.X/.Y/.Z` 读分量，不能用 `v[1]`。

### 6.5 `table.freeze` 常量表 + 自检

```lua
local K = table.freeze({0x9E3779B9, 0x85EBCA6B})
if not table.isfrozen(K) then return end
-- K[1] = 0 或 rawset(K, 1, 0) 都会抛 "attempt to modify a readonly table"
```

`freeze` 是浅冻结：嵌套表仍可改；`table.clone(frozen)` 返回可写副本，且保留元表。

### 6.6 `debug.info` 来源/行号校验与伪造

```lua
local f = loadstring("\n\n\nlocal function g() return 1 end\nreturn g", "=Core")()
print(debug.info(f, "s"), debug.info(f, "l"), debug.info(f, "n"))  --> Core  4  g
```

可用于：

- 自完整性校验：比对函数源码名、行号、参数个数（`'a'` 返回 `numparams, is_vararg`）。
- 伪造栈帧：`loadstring(src, "=Name")` 控制 source，换行填充控制 line。
- `debug.info(print, 's'/'n'/'a')` → `[C]` / `print` / `0, true`。

### 6.7 `__iter` + 广义迭代做隐藏派发

```lua
local relay = setmetatable({[1]=h1, [2]=h2}, {
  __iter = function(self) return next, self end,
})
for k, v in relay do v() end
```

不需要 `pairs`，也不需要显式迭代器函数；表本身即可作为分派器。

### 6.8 语法层打散

```lua
for i = 1, 8 do
  if i % 2 == 0 then continue end
  x += (i // 2) * 3
end

local mode = if x > 10 then "big" elseif x > 0 then "small" else "none"
local s = `k={bit32.bxor(x, 0x5A)}`
```

### 6.9 二进制令牌

```lua
local token = string.pack("<I4I4", a, b)
local a2, b2 = string.unpack("<I4I4", token)
```

`string.pack('s', 'hello')` 的长度为 9（4 字节长度前缀 + 5 字节内容），`unpack` 返回下一个位置 10。

### 6.10 `math.noise` 做确定性掩码源

```lua
local m = math.floor(math.noise(seed, step) * 0x100000000) % 0x100
```

同参数跨进程结果一致（实测 `math.noise(0.25) == 0.146484375`），可以避免把随机种子表写进产物；但不同 Luau 版本的 noise 实现是否稳定需验证。

### 6.11 类型标注作为零成本诱饵

```lua
type K = {[string]: number}
local keys: K = nil :: any
```

编译期完全擦除，不产生任何指令；源码层可写任意类型名（甚至不存在的 `SomeApiName`），`luau-compile` 不做类型检查。

### 6.12 `@native` / `--codegen`

```lua
@native
local function hot(x) return x * 2 end
```

`luau`/`luau-compile` 支持 `--codegen`；`@native` 在该模式下触发生成本机代码。对纯源码分发的混淆价值有限，但可用于性能关键路径，且能作为“看起来像引擎代码”的标记。

---

## 7. 双端（Lua 5.1 + Luau）还能用的增量

很少：

- `math.frexp/ldexp`（拆 double 为尾数/指数）
- `math.modf/fmod/atan2`
- `string.char`（但常量参数会被 Luau 折叠）
- `setmetatable` / `newproxy`
- `\ddd` 十进制转义（两端语义一致）
- `table.getn`、`table.maxn`、全局 `unpack`

Luau 的库要么不存在于 5.1（`bit32/buffer/vector/utf8/table.freeze/...`），要么语义不同（`math.log` 底数、数字格式化、`__len`）。

---

## 8. 风险清单

1. **静默分歧最危险**：`\x`、`\u{}`、`\z` 在 5.1 不报错但值不同；`math.log(x, base)`、浮点 `tostring`、`%s`、`__len`、`__gc` 同理。双端产物必须避开。
2. **Luau 专属语法会让 `luac5.1 -p` 失败**，只能在新的 Luau 目标模式里用。
3. **Luau CLI 的 `_G` 是冻结的**：`_G.X=1` 直接报 readonly；`getfenv(0) ~= _G`；`setfenv(0, ...)` 实测不生效。
4. **缺失 API**：`io`、`os.exit`、`string.dump`、`load`、`debug.getinfo`、`module`、`arg`、`math.mod`、`string.gfind`。
5. **`__gc` 在 0.735 CLI 不触发**（newproxy userdata 实测 20 次 collect 为 0），`__type` 也不生效；不要照 Roblox 文档假设。
6. **`vector` 是 f32**：0.1、1/3、16777217 都会丢精度，不能拿来存 53 位 double 或完整 32 位整数。
7. **`integer` / `vector` / `buffer` 在目标 Roblox 版本的可用性**需再验证；本仓库 CLI 0.735 全部可用，但它是 “OBF CLI-compatible runner” 构建。
8. **`loadstring`、`getfenv/setfenv` 在 Roblox 受限**，CLI 能跑不代表线上能跑。
9. **O2 会展开常量循环、内联小函数**，所有诱饵必须是运行期值驱动。
10. `string.format('%*d')` 在 Luau 下行为非标准（返回 `"3d"`），不要使用。
11. `math.randomseed` 的序列与 5.1 不同；`math.noise` 跨版本实现是否稳定未验证。
12. `buffer.readinteger` 在本构建中固定读取 8 字节，第三个参数未改变宽度；`writeinteger` 只接受 integer 类型。

---

## 9. 落地建议

如果后续要加 **Luau 目标模式**，建议优先级：

1. `bit32`：替换手写位运算，速度与体积双收益。
2. `buffer`：常量池、精确浮点位型、位域读写。
3. `integer`：状态码/令牌/表键，利用“不可伪造类型”。
4. `table.freeze` + `table.isfrozen`：常量表与自检。
5. `debug.info`：来源/行号/参数个数校验。
6. 语法层：`continue`、if 表达式、复合赋值、`//`、字符串插值。
7. `string.pack/unpack`、`utf8`、`math.noise`、`coroutine.close`。

**双端模式保持不动**：现有产物继续只使用 Lua 5.1 与 Luau 的交集；上述能力不要混入，否则会破坏 `luac5.1 -p` 门禁或造成静默行为分歧。

真正落地前，建议先用目标 Roblox 版本验证五项：`buffer.readinteger`、`vector`、`debug.info`、`table.freeze`、`__iter`。

---

## 附录 A：可复现测试方法

```bash
# 单个用例
cat > probe.lua <<'LUA'
local x = 1
x += 2
print(x, `v={x}`)
LUA
toolchains/bin/luau probe.lua
toolchains/bin/lua5.1 probe.lua

# 查看编译期优化
toolchains/bin/luau-compile --text -O1 probe.lua
toolchains/bin/luau-compile --text -O2 probe.lua

# 查看函数清单
cat > inv.lua <<'LUA'
local function list(name, t)
  local ks = {}
  for k, v in pairs(t) do if type(v) == 'function' then ks[#ks+1] = tostring(k) end end
  table.sort(ks)
  print(name .. ' (' .. #ks .. '): ' .. table.concat(ks, ', '))
end
list('buffer', buffer)
list('vector', vector)
list('bit32', bit32)
list('utf8', utf8)
list('debug', debug)
list('os', os)
LUA
toolchains/bin/luau inv.lua
```

## 附录 B：关键实测输出

```text
-- integer
type(tok)              -> integer
tostring(tok)          -> 72340172838076673
tok + 1                -> ERR: attempt to perform arithmetic (add) on integer and number
tonumber(tok)          -> nil
tok == 72340172838076673 -> false
{[tok]='a',[72340172838076673]='b'} -> 两个不同键

-- buffer
buffer.writebits(b,0,3,5); buffer.writebits(b,3,3,7) -> readu8 = 61
buffer.writebits(b,0,33,0) -> ERR: bit count is out of range of [0; 32]
buffer.readu8(b,4) on 4-byte buffer -> ERR: buffer access out of bounds

-- vector
vector.create(0.1, 1/3, 16777217) -> 0.10000000149011612, 0.3333333432674408, 16777216
vector.create(1,2,3) + vector.create(1,1,1) -> 2, 3, 4
vector.create(1,2,3) == vector.create(1,2,3) -> true

-- table.freeze
table.isfrozen(table.freeze({1})) -> true
table.freeze({1})[1] = 2 -> ERR: attempt to modify a readonly table
table.freeze({x={}}).x.y = 1 -> 1（浅冻结）

-- debug.info
debug.info(f, 'sln') on loadstring(..., '=Core') -> Core  4  g
debug.info(print, 'sna') -> [C]  print  0  true

-- 数字格式化
tostring(1e15)      Luau 1000000000000000      Lua5.1 1e+15
tostring(2^63)      Luau 9223372036854776000   Lua5.1 9.2233720368548e+18
tostring(0.1+0.2)   Luau 0.30000000000000004  Lua5.1 0.3
tostring(0/0)       Luau nan                   Lua5.1 -nan

-- 语义
math.log(8,2)       Luau 3                     Lua5.1 2.0794415416798
1//0                Luau inf                   Lua5.1 无 //
```

## 附录 C：优化级别对常见写法的处理

| 写法 | -O1 | -O2 |
|---|---|---|
| `local a = 1 + 2*3` | 折叠为 `7` | 折叠为 `7` |
| `if false then ... end` | 删除 | 删除 |
| `local unused = 999` | DCE | DCE |
| `for i=1,1 do ... end` | 保留循环 | **展开** |
| `for i=1,5 do ... end` | 保留循环 | **展开** |
| `while g<1`（g 已知 0） | 保留循环 | **展开** |
| `math.floor(2.9)` | 保留调用 | **折叠为 2** |
| `bit32.bxor(1,2)` | 保留调用 | **折叠为 3** |
| `string.char(65,66)` | 保留调用 | **折叠为 "AB"** |
| `(x-x)+x` | 保留 | 保留（不符号化简） |
| `x+0` / `x*1` / `x*0` / `x%1` | 保留 | 保留（不符号化简） |
| `if x then return true else return true` | 保留两个返回臂 | 保留（不合并） |
| 立即调用的小匿名函数 | 保留调用 | **内联** |
| `pcall(function() return 1 end)` | 保留 pcall | 内层函数被折叠，pcall 保留 |
| `table.freeze({1,2})` | 保留 | 保留（运行期调用） |
| `buffer.create(4)` | 保留 | 保留（运行期调用） |
