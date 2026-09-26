# 主库 luraph14.9：环境记录与继续反虚拟化

日期：2026-09-27。

## 结论

按用户要求，先尝试不带 VM 捕获钩子的环境记录，再继续静态反虚拟化诊断。**已取得不完整模拟运行记录，仍未完整还原。** 没有关闭 GUI 未知值检查、没有猜测坐标、没有跳过特定原型，也没有把辅助函数占位代码当成恢复源码。

输入为主库文件的副本，原文件未改动。SHA-256：

`2b8e2e5087c0a093ba65019e17abd6caba4634c6a6406897f2f6082faeba78bf`

## 1. 环境记录

运行方式：

```bash
python3 -B /home/user/luraph-v15-v14.x-deobfuscator/Deobfuscator/deobf/deob.py \
  /home/user/obf-v149-runtime/input.lua \
  --obfuscator generic --no-devirt --no-hooks --no-pypy \
  --no-fold --keep-preamble --no-tidy --cfg ptrace=true \
  --timeout 30 --budget 15 \
  --raw /home/user/obf-v149-runtime/environment.raw.txt \
  -o /home/user/obf-v149-runtime/environment.trace.luau
```

这是 Linux Luau 中的模拟执行，不是把不可信输入放入真实 Roblox 项目运行；未启用真实网络访问。关闭 VM 捕获钩子不等于没有模拟环境拦截：环境记录仍由代理实现。

实测约 **0.56 秒**，记录 **92 条行为语句、132 条属性读写调试条目**。两者存在重叠，不能相加成“执行代码行数”。主要内容是调度调用、Path2D 构造/查询，以及 ScreenGui、Frame、TextLabel、UIScale、UISizeConstraint、UIPadding 的创建与属性赋值。

停止原因：

```text
aborted: unsupported environment: GUI layout unavailable for TextLabel.AbsolutePosition
```

显式环境记录模式返回码为 0，表示成功写出了所请求的轨迹文件，**不表示目标脚本运行完成**。轨迹头部明确保留了 `aborted` 状态及 `NOT reconstructed source` 标识。

环境记录只展示模拟执行中观察到的外部行为，不记录全部纯计算、每一条 VM 指令或未走到的分支；轨迹中的空回调也不能证明原脚本回调内容为空。当前记录不能用于认定整个脚本的业务行为或安全性。

文件在 `/home/user/obf-v149-runtime/`：

- `environment.trace.luau`：主要交付，已通过 Luau 语法检查，但不是完整可重放源码。
- `environment.access.txt`：属性访问顺序和实例 ID。
- `environment.raw.txt`、`environment.log`、`environment-summary.json`：原始诊断和运行摘要。

## 2. 环境记录未能跑完，继续检查静态提升

重新启用捕获后，得到 **447 个原型、4897 个表对象**，仍有 **2 次执行前快照失败**。捕获产物位于 `.input.luraph_v14_9_work/input.protos.json`。

对这份新捕获做独立静态分析：

- 当前入口仅提升了 1 个函数，仍依赖 **3 个未还原运行时辅助函数**。
- 即使未提升块/非结构化跳转计数都是 0，这些依赖也足以使结果不完整。诊断片段仅存为 `static-root-diagnostic.txt`，没有作为恢复源码输出。
- 对此前观察到的 GUI 相关原型继续定位：研究中的原型 144、状态 `0:371` 仍被 `WalkIncomplete` 拒绝。已具体定位到闭包捕获列表遍历：循环上界是无法具体化的表字段长度（`Len(NilIndex(slot=4))`），不是一个已知数字。
- 这说明“直接静态提升并绕开布局执行”目前也受闭包原型信息不完整阻碍；信息无法具体化究竟来自未执行初始化、捕获不足还是模型缺陷，尚未确认。没有将研究原型编号写入生产入口选择规则。

相关诊断：`static-stats.json`、`static-root-diagnostic.txt`、`symbolic-bounds.log`。没有成功的 `restored.lua`。

## 3. 本轮通用工具修复

继续分析时发现 v14.x 的 `--op` 指令检查器假定每个 dispatcher 都有模式条件，遇到无条件 dispatcher 会抛出 `KeyError`；对括号包裹的 opcode 读取也没有正确解包。

已对 v14.7/v14.8/v14.9 检查器修复这两处形状兼容问题，并新增合成测试，覆盖无条件/有条件 dispatcher、括号读取、强制 opcode 与错误模式。该修复只改善检查工具，不宣称解决 GUI 或闭包恢复。

**48 项测试通过（24.023 秒）**，上游四个版本示例仍静态还原通过。累计补丁和清单已更新；本轮日志在 `/home/user/obf-v149-runtime/regression.log`。
