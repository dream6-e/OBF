# Roblox Studio GUI 布局校准

用途：给离线模拟器提供真实引擎的布局参考，继续分析主库 v14.9 的环境阻断。**这不是还原结果，也不保证拿到数据后全部阻断都会消失。**

## 推荐操作

1. 打开 Roblox Studio，新建一个空白 **Baseplate** 项目。不要使用正式游戏项目；无需发布。
2. 打开 **Explorer（资源管理器）** 和 **Output（输出）** 面板。
3. 在 **StarterPlayer → StarterPlayerScripts** 下新建一个 **LocalScript**。
4. 清空默认代码，把同目录 `gui_layout_probe.luau` 的完整内容粘进去。
5. 按 **Play / F5**，等待输出中出现 `GUI_LAYOUT_PROBE_DONE`。
6. 复制所有以 `GUI_LAYOUT_PROBE_` 开头的输出，包括 META、全部 PART 和 DONE。粘贴到聊天，或保存为 `.txt` 上传。保留行首时间和 `Client` 标签也可以。
7. 停止 Play。测试 GUI 会由脚本自行销毁；测试脚本可删除，空白项目无需保存。

## 注意

- **不要粘贴或运行 `luraph14.9.lua`。** 这里只运行明确可读的 GUI 校准脚本。
- 不需要开启 HTTP Requests，不需要任何插件、账号令牌或发布权限。
- 脚本不执行混淆代码、不调用 loadstring、不联网；只创建未挂载的 ScreenGui 及其子对象，读取布局后销毁。
- `HttpService` 仅用于 JSON 编码，不发送请求。
- 使用 Play 是为了同时采集即时值及等待 Heartbeat 后的值；无需切换成 Run。
- 输出按每段最多 2000 字符分割。请发回所有段，而不只是第一段或 DONE；若有红色报错，也一并复制。
- 当前已通过 Luau 语法检查，但尚未在真实 Studio 中执行验证。真实引擎版本和客户端/运行状态会写入报告。
