# 混淆产物样本

按 README 的要求，每次更新都上传混淆文件和 MB 压缩后的混淆文件。

| 文件 | 说明 |
|---|---|
| `print.obfuscated.lua`    | `test/print.lua`（557 B）的普通模式产物，67,329 B |
| `print.obfuscated.MB.lua` | 同一输入的 MB 模式产物（加壳 + 二次压缩），43,259 B |

两个都用 `toolchains/bin/lua5.1` 跑过，stdout 与原文件逐字节一致（19 行）。

自己复现：

```bash
cargo run --release -- test/print.lua        # 生成 obfuscated.lua
cargo run --release -- test/print.lua MB     # 生成 MB 模式产物
```

注意产物**不可逐字节复现**：每次运行的种子（`VmContext::seed`、指令布局种子、
常量池 ChaCha 密钥）都是随机取的，所以每次生成的字节都不同，但行为一致。
