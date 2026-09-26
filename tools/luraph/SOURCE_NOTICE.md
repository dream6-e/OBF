# 来源与打包说明

本目录包含当前反混淆项目的完整有效源码、模块、资源表、研究工具和回归样本，不是只有补丁或下载链接。运行入口为 `Deobfuscator/deobf/deob.py`、`Deobfuscator/deobf/cli.py`；根目录的早期 Python 实现也保留。

- 上游：<https://github.com/KryptIT/luraph-v15-v14.x-deobfuscator>
- 固定提交：`d6158608bb512e919afe4e6485f6146598738274`
- 本地修复：已应用 `../../integrations/luraph/upstream.patch`；不要再次应用。
- `SOURCE_MANIFEST.json`：逐文件 SHA-256、上游提交、补丁哈希及明确排除的路径。

保留 101 个上游及修复后有效文件。排除的是 Python 缓存、Windows EXE、RAR、旧 `_work`/output、生成结果和 `bin/` 内整套重复源码。重复的 deobf/SON.LUA 与 v14.9.txt 内容相同，只保留后者；根目录 SON.LUA 是独立 v15 回归输入，保留。没有删除运行模块或用 stub 替代实现。

上游 `Deobfuscator/CLAUDE.md` 作为历史开发文档保存在 `Deobfuscator/UPSTREAM-DEVELOPMENT.md`；其中的旧环境路径/工作指令不作为本仓库部署流程。部署与运行以本项目 `integrations/luraph/README.md` 为准。

## 授权边界

该固定上游快照未包含独立 LICENSE 文件，无法确认上游授予了怎样的再分发许可。本次按仓库所有者要求保留来源并上传源码；这不表示源码为公有领域，也不自行授予上游代码新的许可证。后续公开分发或商业使用应向原作者确认授权。

Luau 的源码与补充 AST 编码器另有 MIT 许可证，见 Environment.zip 内的 LICENSE.txt 和 `integrations/luraph/toolchain/LICENSE.txt`。本目录源码不因此自动获得 Luau 的 MIT 授权。
