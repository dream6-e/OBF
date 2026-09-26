# 主库 Luraph14.7.lua 反虚拟化实测

日期：2026-09-27。

**最新结果：已实现通用寄存器尾部清理与 14.7 常驻入口保持，原 `0:904` 阻断已越过；仍有 3 处动态数值循环边界未解，未生成还原源码。详见文末“本轮算法改进与对照复测”。以下先保留首次失败记录。**

## 首次测试记录（改进前）

**已测试用户 GitHub 主库的真实 `Luraph14.7.lua`，不是上游工具的演示样本。当前未完整反虚拟化，未生成 restored.lua。**

此次与主库 v14.9 不同：模拟运行正常返回，捕获快照无失败，但静态提升被寄存器表遍历操作阻断。未关闭完整性检查，未使用轨迹回退冒充源码。

## 输入来源

当前工作分支的旧快照未包含该新文件，因此从 GitHub 主库固定提交读取原始副本，在外部验证目录测试，没有切换分支、合并远程 main 或修改主库现有输入。

- 仓库：`dream6-e/OBF`
- 文件：`Luraph14.7.lua`
- 提交：`25ab486f4eb506cd870082984fd2b6963c1d8e31`
- 大小：263,647 字节
- Git blob：`878e55fc66d954b1da5d054380969b7c53b1aa5f`（下载后用 git hash-object 核对一致）
- SHA-256：`6b9eebdc53fc1452e4f68788fd8f55d4c3ff46f04e2abf48e02e3fa6c1703bf5`

文件没有版本 banner；按用户指定使用 `--engine 14.7`。

## 环境恢复与验证

当前工作区已没有先前外部工具目录。重新解压主库 Environment.zip，恢复固定上游提交 `d6158608bb512e919afe4e6485f6146598738274` 并应用仓库中保存的累计补丁。基于压缩包提供的 Luau 0.735 源码恢复分析专用 Luau 和 AST 工具，原版工具保留。

- 原版 `luau-compile --null`：输入语法通过。
- `luau-ast`：输入解析通过。
- 原有 **48 项回归测试通过（19.828 秒）**；包含上游四版本的成功案例，不代表本文件成功。
- 本轮没有修改反虚拟化算法或累计 upstream.patch。

## 实际命令与结果

```bash
python3 -B /home/user/luraph-v15-v14.x-deobfuscator/Deobfuscator/deobf/cli.py \
  /home/user/obf-v147-validation/input.lua \
  --engine 14.7 --timeout 60 --debug \
  --raw /home/user/obf-v147-validation/runtime.raw.txt \
  -o /home/user/obf-v147-validation/restored.lua
```

| 项目 | 结果 |
|---|---|
| 返回码 | 1 |
| 本轮耗时 | 约 1.21 秒 |
| 模拟运行状态 | finished |
| 原型条目 | 35 |
| 捕获表对象 | 3206 |
| 快照失败 | 0 |
| 当前入口 | 运行链推断为原型 26；仅诊断编号，无编号特判 |
| 静态提升 | 1 个未解析 VM 状态，拒绝不完整输出 |
| restored.lua | 不存在 |

随后对同一捕获直接执行严格单原型提升，仍返回码 1：

```text
WalkIncomplete: refusing partial devirtualization:
1 unresolved VM state(s): 0:904: symbolic generic for
```

进一步定位到 VM 内部寄存器表清理：

```lua
for O in Q do
    if O > V then
        Q[O] = nil
    end
end
```

解释器中的 `Q` 是符号化寄存器文件（RegFile），当前符号解释器不能枚举它，因此在该指令停下。这不是输入语法错误，也不是本次出现了 v14.9 的 GUI AbsolutePosition 阻断。不能简单删除该循环：它会清理寄存器，忽略它可能改变后续语义。

## 已观察到的运行路径及边界

模拟轨迹在环境探测之后进入一段白名单相关逻辑：取得 Players/StarterGui、调用 gethwid、请求远程白名单资源、清理文本、尝试 JSONDecode，随后显示“白名单数据格式错误，请联系管理员”并调用 Kick（“❌ 数据解析失败”）。

**测试未联网获取白名单内容；这些是模拟响应下的失败分支，不意味着真实远程白名单格式有错误，也不能代表脚本的全部行为。** `finished` 只说明本次模拟路径返回，不等于完整运行覆盖或反虚拟化成功。没有修改或绕过白名单检查。

## 诊断目录

`/home/user/obf-v147-validation/`：

- `input.lua`：固定提交下载的输入副本。
- `summary.json`、`run.log`：命令、返回码、输入校验和及结果。
- `runtime.raw.txt`：原始模拟运行与捕获。
- `.input.luraph_v14_7_work/input.protos.json`：捕获数据。
- `root.raw-ir.txt`：部分指令中间表示，不是恢复源码。
- `diagnose.log`、`strict-lift.log`：寄存器遍历阻断定位与严格提升错误。
- `regression.log`：48 项回归日志。

下一步可针对符号寄存器表的遍历/清理语义补通用支持，再验证闭包和其他分支；本次尚未实现该支持，不能承诺修复一处后就能完整还原。


## 本轮算法改进与对照复测

本次用户明确授权改进 14.7 后，已经修改实际算法，不再只是恢复依赖。原始输入 SHA-256 不变；再次查询 GitHub 主库 `Luraph14.7.lua`，当前 blob 仍为上方同一值。实验均在独立副本执行。

### 实现与安全边界

1. 新模块 `deobf/register_cleanup.py` 精确匹配寄存器尾部删除。实际遇到的是等价的 `if not(key > cutoff) then else registers[key] = nil end`，也通过通用 AST 结构处理；不使用 opcode、状态编号或变量名特判。
2. 共享解释器增加可选 generic-for 前端钩子，目前仅 14.7 接入。确定有限数值截止点后，清除相关 pack 缓存及寄存器数值别名，并记录 `ClearRegistersAbove` 副作用；稀疏事实映射只更新已有键，不发明未知寄存器范围。
3. 在后端生成前检查完整指令图，包括条件、返回、调用参数、闭包捕获和后续才出现的寄存器读取，按全部可观察物理槽位展开 nil 写入。编译器临时变量不被清理；清理保持原分支和执行位置。
4. 动态寄存器存储、帧逃逸、未知 IR 效果、非整数物理键或物理槽位与编译器临时变量区冲突时拒绝静态展开。未知/非有限截止点、额外副作用、不同目标表等不作为可支持清理。没有把 `table.create` 的容量误当作最大索引，也没有跳过有意义的删除操作。
5. 修复 14.7 常驻解码轮次的入口丢失：仅在常驻握手轨迹验证通过后，使用该同一会话的首轮运行链为后续 dump 提供候选入口；候选还必须存在于新 dump。握手不同、启动失败或请求失败转为新运行时，不复用旧会话编号。**14.8 驱动未应用本次修改。**

### 同一输入的三组对照

| 配置 | 第一轮 | 第二轮 | 最终结果 |
|---|---|---|---|
| 关闭新清理钩子，仅作对照 | `0:904: symbolic generic for`；0 个新常量请求 | 不进入 | 返回 1，无源码 |
| 完整新补丁、默认常驻会话 | 3 个动态数值循环边界未解；60 个新常量请求 | 同样 3 处；0 个新请求 | 返回 1，无源码 |
| 完整新补丁、`DEOB_NO_SERVE=1` | 同上 | 同上 | 返回 1，无源码 |

对照是在单独 Python 进程临时禁用新前端钩子，没有改写生产源文件或用户输入。三次均捕获 35 个原型、3206 个表、0 次快照失败，入口为 26。完整补丁的常驻模式耗时约 2.44 秒，新进程模式约 2.37 秒；耗时仅作诊断。

实际命令（独立工作目录中的输入副本）：

```bash
DEVIRT_ERRS=1 PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /home/user/luraph-v15-v14.x-deobfuscator/Deobfuscator/deobf/cli.py \
  /home/user/obf-v147-improvement/patched/input.lua \
  --engine 14.7 --timeout 40 --debug \
  --raw /home/user/obf-v147-improvement/patched/runtime.raw.txt \
  -o /home/user/obf-v147-improvement/patched/restored.lua
```

剩余错误为：

```text
0:163:  numeric for with symbolic bounds
0:1584: numeric for with symbolic bounds
0:1540: numeric for with symbolic bounds
```

原来停在较早指令，现在能走到后续三个阻断点；错误数量由 1 变成 3 不意味着新增三个语义回归。常驻/新进程结果一致，排除了此次入口丢失造成的假象。

状态 163 的诊断显示：清理之后发生寄存器帧辅助函数、间接调用和多返回值包装，随后复制循环的终点仍含 `TempVal + 88 - 1`，不能具体化。这里的辅助函数计数/解包语义尚未证明，因此没有假定返回个数、硬填循环上界或改写白名单分支。60 是新常量**请求数**，不代表已完整解码全部程序。

### 验证与交付

- 累计 **63 项测试通过（31.337 秒）**，其中新增 15 项清理与会话入口测试。
- 使用真实 Luau 比较稀疏表原始删除循环和后端生成代码：负数/零/小数/大截止点、false、nil、后续覆盖与仅在未来读取的槽位；另执行双分支用例，验证清理没有移出所属分支。
- 测试词法/表身份拒绝、附加效果拒绝、缓存/事实失效、未来读取与闭包捕获、动态/逃逸帧拒绝、编译器临时变量隔离及常驻会话失败回退。
- 四个上游示例仍可静态还原并执行，其成功不代表当前用户输入成功。
- 上游当前跟踪的 137 个 Python 源文件语法通过；31 个 Lua/Luau 文件中 30 个通过，唯一失败仍是未经修改的上游历史 `SON.trace.luau` 说明文字（不是本次生成的结果）。
- 累计补丁覆盖 23 个上游源码文件，包含新增模块；干净固定基线应用后与实测源码逐字节相同。补丁哈希见 `../manifest.json`。
- 未关闭完整性检查，未使用轨迹回退，未输出所谓恢复源码。没有联网抓取被分析程序请求的资源、没有绕过白名单、没有修改原输入；没有提交或推送 Git。

外部诊断目录 `/home/user/obf-v147-improvement/` 包含 `comparison.json`、`comparison.log`、`regression.log`、`syntax.json`，以及 `baseline/`、`patched/`、`patched-fresh/` 下各自的 `run.log`、`summary.json`、`runtime.raw.txt` 和工作区 dump。大体积输入与运行产物不纳入 Git。

**当前结论：第一处实际阻断已修复并有语义回归覆盖，但该主库 14.7 文件仍未完整还原。下一步需要证明并建模多返回值辅助函数/动态寄存器复制，而不是继续安装依赖或猜测循环边界。**


## 追加：已导出可读逻辑，不再只报告完整性失败

按用户“只要有源码逻辑的都算”的要求，重新用同一输入导出离线运行记录：56 条可观察操作，包括环境探测、白名单请求、响应清理、JSON 解析及失败通知/Kick。原始网络请求未执行，没有虚构成功分支。这次只运行 generic 行为记录模式，不是又一次完整静态提升。

**持久化输出与说明见 [14.7 可读逻辑](artifacts/main-v147/README.md)，全部记录为 [observed.trace.luau](artifacts/main-v147/observed.trace.luau)，业务摘录为 [logic-excerpt.luau](artifacts/main-v147/logic-excerpt.luau)。** 两份 Luau 文件通过语法检查，仅供分析，不作为可运行还原源码。
