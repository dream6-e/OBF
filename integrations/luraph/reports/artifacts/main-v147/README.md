# 主库 14.7：现在可直接阅读的逻辑

日期：2026-09-27。输入是主库 `Luraph14.7.lua` 的未修改副本，SHA-256 见 `metadata.json`。

这次按“只要有源码逻辑的都算”的要求导出已有可读内容，不要求静态提升完全成功后才展示。**记录了 56 条可观察操作，不是 56 行原始源码，也没有测量源码覆盖率。**

## 文件

- **`observed.trace.luau`**：全部可读行为记录；仅增加中文限制说明，保留运行器的原始输出头。
- **`logic-excerpt.luau`**：业务相关调用摘录。保留 HttpService 定义及从 Players/StarterGui 开始的后续语句；省略前面的环境探测。没有添加推测的条件或成功分支。
- 原始 raw 日志属于重复诊断内容，本次按用户清理要求不再上传；完整可读操作仍保存在 `observed.trace.luau`。
- `metadata.json`：输入身份、记录数、验证状态与文件哈希。

## 已经能看到什么

1. 创建 ScreenGui、Frame、Path2D，设置五个控制点，查询曲线长度、位置及切线，随后销毁 ScreenGui。这里能看到具体尺寸、控制点和查询参数。
2. 对 game、workspace、Folder、HttpService、RunService 的 AttributeChanged 进行连接/断开等环境探测，以及对象创建、命名、等待与销毁。
3. 取得 Players、StarterGui，调用 `gethwid()`。记录没有提供可据此恢复其原始存储变量的证据，不能自行补上。
4. 调用 `game:HttpGet` 请求白名单地址；完整地址保留在两个 Luau 文件中。**本次只用了模拟响应，没有真实获取远程文件。**
5. 对响应执行三步处理：移除开头 UTF-8 BOM、去掉 `--` 行注释、去掉 `]` / `}` 前的尾逗号。
6. 调用 `HttpService:JSONDecode`。
7. 本次随后观察到标题为 `Bacon head`、文字为“白名单数据格式错误，请联系管理员”、持续 5 秒的通知，等待 1 秒，再以“❌ 数据解析失败”为由调用 LocalPlayer:Kick。

记录中还出现两个 task.spawn 和一个延迟 370 秒但被模拟器取消的任务。**输出里的空函数不能证明原函数没有内容，取消任务也不能视为已恢复。**

## 如何理解限制

这是“环境探测 + 白名单获取/清理 + 解析失败路径”的可读逻辑，不是整个脚本的控制流。调用周围的原始 `if`、`pcall`、返回值数量、纯 Lua 运算及未执行分支不能仅靠这份日志补全。失败后的原始控制关系也没有由摘录重建。

两个 Luau 文件均通过 `luau-compile --null` **语法检查**；没有把它们重新执行，也不宣称可直接运行或与原程序等价。不要把包含真实 HttpGet 和 Kick 调用的轨迹当作待运行脚本。

## 本次复现方式

先从固定上游提交恢复工具，应用仓库保存的 `upstream.patch`（SHA-256 `fc18db9f57be377c0eb7c4c2db57ad7d3db0f5f7d863f275c92b0368713b5d1f`）。这次只取可读运行逻辑，使用 Environment.zip 的原版 Luau 0.735，不需要重新构建 AST 工具，也没有修改反虚拟化算法。

```bash
cd /home/user/luraph-v15-v14.x-deobfuscator/Deobfuscator/deobf
python3 -B deob.py /home/user/obf-v147-output/input.lua \
  --obfuscator generic --no-devirt --no-hooks --no-pypy \
  --timeout 40 --debug \
  --raw /home/user/obf-v147-output/generic.raw.txt \
  -o /home/user/obf-v147-output/generic.trace.luau
```

本次返回码 0 仅表示请求的行为记录已导出，不表示静态还原成功。没有进行新的完整静态提升或 VM 原型捕获；之前报告中的 35 个原型及 3 处静态阻断仍是前次实验结论，不是本次重新测出的统计。

另外尝试 `--cfg dump_strings=true` 捕获到 606 条去重字符串记录，包含大量乱码/编码数据及环境 API 名，没有据此发现可额外确认的业务流程，故没有把它们充作还原源码。

可读输出已保存到仓库报告目录，避免依赖临时路径。输入未修改；本轮按用户授权准备提交/推送。现在完整修复后源码位于 `tools/luraph/`，旧 `/home/user/...` 命令仅是此前实验记录，当前部署与运行见 `integrations/luraph/README.md`。
