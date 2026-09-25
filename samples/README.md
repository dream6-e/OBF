# 混淆产物样本

按 README 的要求，每次更新都上传：混淆文件、MB 压缩后的混淆文件、混淆后的“伪装.lua”。

| 文件 | 说明 |
|---|---|
| `print.obfuscated.lua`    | `test/print.lua`（557 B）的普通模式产物，96,812 B |
| `print.obfuscated.MB.lua` | 同一输入的 MB 模式产物（新自解压外壳），51,516 B |
| `U4f2aU88c5.obfuscated.lua` | 仓库根目录 `#U4f2a#U88c5.lua`（“伪装.lua”，12,365 B）的普通模式产物，124,476 B |

前两个都用 `toolchains/bin/lua5.1` 跑过，stdout 与原文件逐字节一致（19 行）。

产物现在是 Luraph 风格（见 `项目交接总结.md` §5.9）：单层 `while true do` 驱动、
每个指令块是一个随机名方法、调用点全是 `self:随机名(...)`、状态存在 `self[随机大整数]`
槽位里、分发树按随机大整数状态号路由；不含任何二进制字面量。
池解码器、毒表守卫（§5.11）已做逻辑/数据流打乱；脚本头那段原生 `loadstring` 探测里
9 个字符串（`getinfo`/`what`/`source`/`getgenv`/`getrenv`/`loadstring`/`load`/`C`/`=[C]`）已 XOR 加密，
产物里不出现明文。
十六进制数字一律写成 `0X` 前缀 + 大写 A-F；ChaCha 的 4 个 sigma 常量不再以字面量出现，
改成逐产物由随机 key 派生；载荷解码链（bxor/rotr/read_dec/u32/字符串/状态机）已整体换形（§5.13），
解码器外层（m_main/m_init_map）也已打乱并可反美化（行号校验守卫，§5.14）——产物被拆行格式化后会失效。
MB 模式改用了新的自解压外壳（DP/LZ + base85，§5.15）：同一输入下比上一代管线小 9%、
启动（解压 + 加载）快 31%。
探测串与守卫池改用「位置相关」的两字节密钥混合（§5.16）：单字节 XOR 可以拿两次调用
比对反推密钥，现在同一明文字符在不同位置、不同串上的密文都不同。
所有守卫的字符串都走池（类型名 `table`/`function`/`nil`、`S`/`l`、`linedefined`/`currentline`、
`what`、`loadstring`/`load`、元方法名、`__mode`/`k` 等），产物里**查不到任何可读的 API 名**；
行号校验（反美化）也改成隐式判定（§5.17）：两路线号折成残差，用 `r*r` 当表键在正常/异常
增量之间取值，全程没有一句「判断对错」的语句。

**§5.18（本轮：代码块互锁 + 常量动态生成 + 加密特征打散）之后**：守卫网表不再用 0/1/2…
顺序下标，每块挂在随机键上、由上一块传下的状态残差串起来（删/改/换序任何一块都跑不完）；
VM 的槽位常量改成运行期由线性同余序列生成（产物里查不到那些大整数）；池键哈希参数与
载荷滚动变换的常数逐产物随机（原来的 djb2 指纹 5381/33 与 0x42/0x1B/×3/旋 1、2、3 都已消失）。

自己复现：

```bash
cargo run --release -- test/print.lua                    # 生成 obfuscated.lua
cargo run --release -- test/print.lua MB                 # 生成 MB 模式产物
cargo run --release -- '#U4f2a#U88c5.lua'                # 生成“伪装.lua”产物
```

第三项是 **Roblox 专用**脚本（用到 `hookfunction` / `isfunctionhooked` / `game` 等
执行器全局），在标准 Lua 下跑不起来 —— 原文件在 `hookfunction` 处报
`attempt to call global 'hookfunction' (a nil value)`，产物在 VM 启动阶段就报
`attempt to call field '?' (a nil value)`（产物运行前要先建 VM，这一步依赖 Roblox 环境），
改版前后行为一致。这边只做了能做的检查：

- 混淆器能正常编译它；
- 产物过 `toolchains/bin/lua5.1` 语法检查与 `luau-compile --binary` 语法检查；
- 产物里不含明文字段名（`项目交接总结.md` §5.8），也不含 `U4f2a` / `Instance` /
  `WaitForChild` 这类原始脚本里的明文标识符。

**实际功能由用户自己在 Roblox 里验证。**

注意产物**不可逐字节复现**：每次运行的种子（`VmContext::seed`、指令布局种子、
常量池 ChaCha 密钥、方法/状态名、分发树形状）都是随机取的，所以每次生成的字节都不同，
但行为一致。
