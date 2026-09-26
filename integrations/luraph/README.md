# Luraph 反混淆项目与最终输出

更新：2026-09-27。现在仓库包含**完整修复后源码**，不再依赖 `/home/user` 下可能消失的外部克隆。

## 入口

| 内容 | 路径 |
|---|---|
| 完整反混淆源码 | [`../../tools/luraph/`](../../tools/luraph/) |
| 主命令 | `tools/luraph/Deobfuscator/deobf/deob.py` |
| 14.x 显式版本入口 | `tools/luraph/Deobfuscator/deobf/cli.py` |
| 14.8 最终业务逻辑 | [`reports/artifacts/main-v148/logic-excerpt.luau`](reports/artifacts/main-v148/logic-excerpt.luau) |
| 14.8 全部可读记录 | [`reports/artifacts/main-v148/observed.trace.luau`](reports/artifacts/main-v148/observed.trace.luau) |
| 14.7 最终逻辑与说明 | [`reports/artifacts/main-v147/`](reports/artifacts/main-v147/) |
| 测试/源文本观察器 | `tests/`、`probes/capture_loadstrings.py` |

## 部署（Linux，Python 3.10+、make、g++、ar）

在 OBF 仓库根目录运行：

```bash
python3 -B integrations/luraph/setup_tools.py --jobs 2
python3 -B integrations/luraph/validate.py
```

部署使用仓库已有 `Environment.zip` 及固定 Luau 0.735 的 AST 编码器补充源码，**不需要重新克隆反混淆器，也不访问网络**。原版工具与源码保持在 `.tools/Environment/`；分析专用运行时从独立源码副本构建，只放开 vector 元表的只读限制，另外构建 `luau-ast`。引擎 `bin/` 使用本地链接。

`.tools/` 是已部署工具与构建工作区，**不要作为垃圾删除**；它被 Git 忽略，二进制/缓存不上传。再次执行部署脚本会增量构建，不删除工具；压缩包改变时拒绝盲目覆盖。Windows/macOS 未验证此部署脚本。

验证命令会检查来源/补丁/最终输出哈希、全部交付 Python 和 Lua/Luau 的语法（包括原有根目录样本及四个测试输入），再运行全部回归。它不执行主库用户样本或把记录输出当作完整脚本执行。

## 使用

建议将输入副本放在 Git 忽略的 `artifacts/` 下，避免在原始文件旁产生工作目录。

```bash
# 默认尝试完整静态反虚拟化
python3 -B tools/luraph/Deobfuscator/deobf/deob.py artifacts/input.lua \
  --no-pypy --timeout 40 -o artifacts/restored.lua

# 明确指定版本（特别是没有 banner 的输入）
python3 -B tools/luraph/Deobfuscator/deobf/cli.py artifacts/input.lua \
  --engine 14.8 --timeout 40 -o artifacts/restored.lua

# 完整静态失败时，仍导出全部已观察逻辑，保留原始记录
python3 -B tools/luraph/Deobfuscator/deobf/deob.py artifacts/input.lua \
  --obfuscator generic --no-devirt --no-hooks --no-pypy \
  --no-tidy --no-fold --timeout 40 \
  --raw artifacts/runtime.raw.txt -o artifacts/observed.trace.luau
```

追加 `--cfg dump_strings=true` 采集运行时字符串。具体 loadstring 参数的可选观察器：

```bash
python3 -B integrations/luraph/probes/capture_loadstrings.py \
  tools/luraph/Deobfuscator/deobf artifacts/input.lua \
  --obfuscator generic --no-devirt --no-hooks --no-pypy \
  --no-tidy --no-fold --timeout 40 \
  --raw artifacts/sources.raw.txt -o artifacts/sources.trace.luau
```

观察器不替换输入或 loadstring 源码，不将模拟 HTTP 代理视为真实库源码。成功编译的具体字符串按十六进制保存在 raw 的 `LOADSTRING_SOURCE` 记录；`source_records()` 可取回原始字节。它仍可能影响敏感程序，须与无观察器的基线比较。

## 用户明确的交付约定

**能完整反虚拟化就交付还原代码；不能完整反虚拟化，也要保存并展示全部已捕获的可读源码逻辑，不能只报告失败。** 包括回调操作、字符串和具体 loadstring 源文本（如能捕获）。区分实际源码字节、模拟记录、摘录和推断；标注缺失、截断与未覆盖路径。不能虚构成功分支、猜测动态边界或放宽完整静态还原门槛，也不声称未经测量的覆盖率。

## 当前支持边界

- 上游自带 14.7 / 14.8 / 14.9 / v15 四个小样本均静态还原并执行成功；不是全版本兼容保证。
- 主库 **14.7**：修复寄存器尾部清理与同会话入口保持，但仍有 3 处动态循环边界；已交付 56 条运行操作。
- 主库 **14.8**：静态仍有入口刷新与动态循环边界问题；已交付 328 条操作、437 行含说明记录、376 条字符串和一段 2444 字节的函数包装源码。业务功能已部分可读，仍有作用域/代理值/回调试探等缺失，不是可直接运行的等价源码。
- 主库 **14.9**：GUI 布局与闭包/辅助函数问题仍未解决；Studio 校准探针只做过语法检查。

详细证据保留在 `reports/`；其中早期 `/home/user/...` 路径是历史实验路径，不是当前依赖。记录中的 HTTP 调用没有实际获取远程资源；本地模拟器不是经过审计的安全边界。

## 清理与来源

完整源树保留运行模块、资源表、上游文档、研究工具及样本。已移除上游缓存、Windows EXE/RAR、`bin/` 内重复整套源码、旧 `_work`/output 和生成结果；输出目录只保留最终逻辑、字符串、截获源文本及摘要，不上传重复 raw/debug 日志。原始 OBF 样本和 `Environment.zip` 未删除或修改。

源码已包含累计补丁，不要再次应用。`upstream.patch`、`manifest.json` 用于审计；`apply_patch.py` 仅用于另一个位于固定提交的独立 Git 克隆。完整源树的逐文件来源见 [`SOURCE_MANIFEST.json`](../../tools/luraph/SOURCE_MANIFEST.json)，授权边界见 [`SOURCE_NOTICE.md`](../../tools/luraph/SOURCE_NOTICE.md)。上游未附独立 LICENSE，不擅自为其声明新许可证。
