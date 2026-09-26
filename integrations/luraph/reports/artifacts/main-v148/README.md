# 主库 14.8：可读逻辑与全部已捕获输出

日期：2026-09-27。

**本次不再只报告“静态还原失败”：已保存 328 条可观察操作、434 行原始代码式记录（附中文说明后 437 行），以及 376 条运行时字符串和一段 2444 字节的具体 loadstring 源文本。** 没有测量或声称“80% 源码覆盖率”。

## 先看这两个文件

- **[logic-excerpt.luau](logic-excerpt.luau)**：从业务服务获取、UI 库调用、窗口构造到各按钮与玩家事件的摘录；保留先前出现的 RunService 定义，省略前面的环境探测/钩子操作。
- **[observed.trace.luau](observed.trace.luau)**：完整可读记录，包括上述业务逻辑和前面的探测、钩子调用、目录检查、控制台字段写入、取消任务与截断说明。没有手工补写缺失逻辑。

这两份文件是**代码式运行记录**，不是保证能运行的静态还原程序。它们已通过 Luau 语法检查，但仍有作用域、对象别名、原始条件与未执行路径缺失，不能直接拿到真实游戏中执行。

## 已经看到了哪些逻辑

以下行号对应 `observed.trace.luau`，是观察位置，不是原文件行号。

| 位置 | 已观察内容 |
|---|---|
| 前部至第 70 行 | ScreenGui/Frame/Path2D 构造、曲线控制点和查询；Destroying 事件连接、断开；对象创建、命名、销毁等环境探测 |
| 71–89 | hookfunction 调用、对 HttpGet 的钩子调用、检查 HttpGetFolder/WebhookFolder/RequestFolder 的循环，以及 rconsoleprint 等字段置 nil；记录中的空钩子不代表原钩子为空 |
| 90–104 | 获取 Players/Lighting/TweenService，请求并调用 UI 库；建立 `Qcq制作` 主题及颜色配置 |
| 105–127 | 标题为 `死冯夺舍 ` 的窗口，背景图片、移动按钮、侧栏宽度、顶部栏及 `乐子Yes` / `Qcq` 标签 |
| 128–155 | RainbowStroke、GlowEffect 彩虹渐变边框，Heartbeat 更新，以及 BlurEffect/Tween 的调用 |
| 157–263 | `随机伪装` 按钮：读取玩家，检查角色，克隆目标角色为 `PossessedClone`；修改本体透明度、碰撞/PlatformStand/Anchored，连接 Heartbeat，切换 LocalPlayer.Character 与摄像机，重启 Animate，记录死亡回调和成功提示 |
| 265–296 | `重置回本体` 按钮：断开连接、销毁克隆、调整角色状态/透明度，设置 Character 与摄像机，发出提示；原始本体变量的准确绑定未恢复 |
| 299–321 | `选择玩家` 下拉框和 `刷新玩家列表` 按钮；读取玩家名称并调用 Dropdown:Refresh |
| 323–420 | `伪装选中玩家` 按钮：根据 Dropdown.Value 查找玩家，随后出现克隆、隐藏本体、固定本体、切换角色/摄像机、重启动画及死亡回调等操作 |
| 421–437 | 初始刷新列表；PlayerAdded/PlayerRemoving 回调中重新获取玩家并刷新下拉框 |

例如，克隆与角色切换相关调用已经可读：

```lua
v.Character.Archivable = true
local clone = v.Character:Clone()
clone.Name = "PossessedClone"
clone.Parent = workspace
-- 中间还有本体隐藏、状态设置、Heartbeat 等已记录操作，见完整文件。
Players.LocalPlayer.Character = clone
workspace.CurrentCamera.CameraSubject = Humanoid3
```

上面只是逐项调用摘录，不填补 `v`、`Humanoid3` 在原程序中的完整定义与控制关系。

### 网址也已显示

- 请求的 UI 库：`https://raw.githubusercontent.com/dream6-e/rbx/refs/heads/main/main.lua`
- 窗口背景参数：`https://raw.githubusercontent.com/dream6-e/rbx/main/pppp.png`

**未真实请求这两个资源，也没有获取或执行远程 UI 库源码。** HttpGet 返回模拟代理，后续库方法与回调是模拟器记录；这不是真实 Roblox 中的运行验证。

## 最终保留的输出

| 文件 | 含义 |
|---|---|
| `observed.trace.luau` | 完整可读记录，437 行含说明 |
| `logic-excerpt.luau` | 业务逻辑摘录，未虚构缺失代码 |
| `captured-strings.txt` | 376 条字符串，含 API 名及编码数据，不等于 376 条业务逻辑 |
| `captured-loadstring-01.luau` | 按原始字节保存的 2444 字节 loadstring 参数；主要为图案注释和函数包装代码，不是远程 UI 库 |
| `metadata.json` | 输入身份、实验命令、状态、输出哈希、语法检查与清理清单 |

按用户要求，重复 raw/debug 日志已从上传内容中清理；不是删除逻辑语句。静态失败的关键结果保留在 metadata.json 及下文。需要重采集时可执行后面的命令，保留在自己的隔离输出目录。

字符串文件保持工具输出；非 UTF-8 编码数据可能已经被显示为替换字符，不作为可逆二进制。loadstring 文件则由十六进制记录按字节恢复并验证长度、哈希。

## 这些记录有哪些明确缺口

- 模拟器会试探调用回调，输出的 `if state` 等结构不保证对应原程序的条件；没有据此重写业务代码。
- `v`、`v9` 等循环变量在某些输出位置已经超出词法作用域，`clone4` / `connection10` 等引用也暴露出跨回调绑定缺失。**没有用猜测的变量替换它们来冒充修复。**
- `UIGradient.Rotation` 是本次观察到的数值，不代表原始动画公式就是一个常数。
- 两处循环有重复截断说明；延迟 671 秒的任务未执行。空回调也不能证明原函数没有内容。
- 玩家列表、对象属性和 UI 库返回值来自代理环境，不能据此保证真实角色切换逻辑可用。
- 所以这里交付的是“全部已捕获且可导出的逻辑记录”，不是“整个脚本所有路径已经覆盖”。

## 本次完整静态尝试

重新读取 GitHub main 提交 `a1fb37bd0e772c22f7e9224a24009ab4e7bd724d` 的 `luraph14.8.lua`：

- 164,188 字节；blob `1398c9bb846777a29f4cdd32ee59d813562d2d9a`。
- SHA-256 `d55a76cbe6273d530aa406de045030fcd071e0df903f4943bb97a4f818f774b3`，与上次输入相同，未修改。

| 模式 | 结果 |
|---|---|
| 默认静态 | 返回 1；入口在常驻常量回复后丢失；最终不完整 helper/常量门槛拒绝源码 |
| `DEOB_NO_SERVE=1` 静态 | 返回 1；保留入口 35，仍有 `0:324: numeric for with symbolic bounds`；无 restored.lua |
| generic 原始记录 | 返回 0；finished，328 条可观察操作；只表示行为记录成功 |
| generic 字符串采集 | 返回 0；finished，另输出 376 条字符串 |
| 同栈帧 loadstring 采集 | 返回 0；finished，328 条记录及一段 2444 字节源文本 |

静态采集两次均为 69 个原型、1073 个表对象、2 次执行前快照失败；第一轮各请求 5 个新常量。没有关闭完整性检查或把零未提升块当作成功。**本次没有修复 14.8 算法或更改累计 upstream.patch。**

## 采集方法与验证

基础命令（先将输入复制到独立目录）：

```bash
python3 -B /path/to/engine/deob.py /isolated/input.lua \
  --obfuscator generic --no-devirt --no-hooks --no-pypy \
  --no-tidy --no-fold --timeout 40 \
  --raw /isolated/runtime.raw.txt -o /isolated/observed.trace.luau
```

字符串追加 `--cfg dump_strings=true`。具体源文本使用仓库的诊断观察器：

```bash
python3 -B integrations/luraph/probes/capture_loadstrings.py \
  /path/to/engine /isolated/input.lua \
  --obfuscator generic --no-devirt --no-hooks --no-pypy \
  --no-tidy --no-fold --timeout 40 \
  --raw /isolated/loadstrings.raw.txt -o /isolated/capture.trace.luau
```

观察器只在生成的 harness 原有 loadstring 栈帧中保留已编译成功的具体字符串，执行结束后输出十六进制记录；不替换用户输入、不获取 URL、不改写源码参数、不把代理 HTTP 响应当成真实源码。插入点不匹配时直接拒绝。原始元数据保留在 `--raw`，从可读轨迹中单独排除。

最初尝试额外包装 loadstring 增加了栈帧，使运行停滞并超时；已放弃该方案，未采用该失败实验目录中的陈旧输出。同栈帧方案与基线的可读记录，除耗时和动态观察的渐变角度外逐行一致；这只是本次比较，不是对所有输入的无干扰证明。

三个交付 Luau 文件均通过 `luau-compile --null`，未重新执行它们。完整 **66 项回归通过（23.979 秒）**，新增 3 项覆盖观察器插入点拒绝、原始字节/长度处理、真实 Luau 的源捕获和协议元数据隔离。原有四个上游示例也保持成功。

最终输出小文件保存在本目录。大体积 VM dump、构建中间产物、重复诊断日志和实验输入副本不上传；本轮已按用户要求准备提交与推送，分支为 `arena/01a0de62-obf`。完整源码和离线部署方法见上级项目 README。
