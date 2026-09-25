# Roblox 报错定位：更早三个版本的产物

当前 GitHub 上的版本（③④⑤ 收官，`908f795`）在你的执行器上仍报
`loadstring) is not available in RobloxScript context`，这里是**再往前三次**的产物，
每次两个文件（print 小样 + 伪装样本），用于一次测试圈出分界点。

| 文件 | 对应提交 | 大小 |
|---|---|---|
| `v1-e9d6d8e-print.lua`    | `e9d6d8e` MB 模式换新自解压外壳（最旧） | 104,493 B |
| `v1-e9d6d8e-disguise.lua` | 同上，伪装样本产物 | 138,476 B |
| `v2-a181d92-print.lua`    | `a181d92` 字符串加密加强 + 行号守卫去明文 | 105,530 B |
| `v2-a181d92-disguise.lua` | 同上，伪装样本产物 | 133,332 B |
| `v3-a45467a-print.lua`    | `a45467a` 明文全清 + 行号校验隐式化 | 107,287 B |
| `v3-a45467a-disguise.lua` | 同上，伪装样本产物 | 139,859 B |

全部用 `luac5.1 -p` 验过语法；三个 print 产物在本机 lua5.1 下输出与原脚本一致。
伪装样本依赖 Roblox 环境（`hookfunction` 等），本机只能验到「能加载、报和原脚本同形的错」。

建议测试顺序：先跑 v1-print（最旧），依次 v2、v3；哪个先开始报错，分界就是它前面那个版本。
