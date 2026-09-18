# XXSV4.lua 静态逆向分析

纯静态分析（未执行任何 Lua 代码）。完整报告见 **[REPORT.md](REPORT.md)**。

## 结论

`XXSV4.lua` 是一个面向 **Luau/Roblox** 的多层打包器 + 自定义寄存器式虚拟机。
五层外壳已全部剥离，最内层 VM 字节码容器已完整还原。

```
XXSV4.lua (148 KB, 单行)
  └─ 不透明谓词 + 状态机平坦化      → 已折叠/重命名 (artifacts/XXSV4.deobf.lua)
      └─ Base-86 三段链式编码        → blob_full.bin   17,740 B  magic "XXS:"
          └─ ChaCha8 + 密文反馈      → payload.bin     17,718 B  magic "LZW\x01"   [4/4 校验通过]
              └─ 自定义 LZW          → bytecode.bin    18,038 B  magic "OBF\x02"   [Adler-32 匹配]
                  └─ 容器 + 常量池   → 18 个原型 / 68 个常量全部明文还原
```

## 复现

```bash
cd analysis/tools
node fold2.js && node rename.js && node pp.js   # 反混淆外壳
node b86b.js                                     # L1 base-86
python3 decrypt.py                               # L2 ChaCha8 + 校验
python3 stage2.py                                # L3 LZW + Adler
python3 parse2_obf.py                            # L4 容器
python3 consts.py                                # L5 常量池
```

## 关键密钥材料（静态求得）

```
mp = 678919948   le = 809326533   qt = 1052881061   ii = 158665
指纹 IS = 2392745008   (debug.info(C函数,"s") 恒为 "[C]" → 完全可静态计算)
```

## 还原出的原始程序性质

常量表含 `'vm:luau:ok'`、`'__obf_luau_import_probe'`、`'__idiv'`、`'value:64'`、
`'left'/'right'`、`'alpha'/'beta'` —— 被保护的脚本是一个
**Luau VM 一致性 / 回归自测脚本**（验证 64 位整数、`__idiv` 元方法、`buffer`、
`pcall`、元表、`ipairs`/`pairs` 行为）。
