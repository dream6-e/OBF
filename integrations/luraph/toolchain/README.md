# Luau AST 编码器补充文件

Environment.zip 内的 Luau 0.735 源码缺少 Analysis 中的 AST JSON 编码器。本目录补齐同版本文件，供 setup_tools.py 离线构建 luau-ast，不需要部署时联网。

- 仓库：https://github.com/luau-lang/luau
- 提交：`367f9d83cc29804a6d5938ec85b6116d34d8743b`
- `AstJsonEncoder.cpp` 来源：`Analysis/src/AstJsonEncoder.cpp`
- `Luau/AstJsonEncoder.h` 来源：`Analysis/include/Luau/AstJsonEncoder.h`
- 原 MIT 许可证：`LICENSE.txt`（同版本 Environment.zip 中原文）。

两个源码文件未修改。CLI 的错误位置显示适配在部署脚本生成的 `.tools/ast-cli.cpp` 中完成，避免链接整个 Analysis 库。
