# Kryvex
这是一个rust编写的lua5.1/luau混淆器，在压缩包里包含需要的工具(rust lua5.1 luau)这些工具部署后一定要固定下来，不要清除，在每次更新时，都要进行所有语法测试，保持全部通过才能上传GitHub，并且要保持项目可读性和可维护性，用户没有给你的要求你不要擅自添加已经拥有的步骤也不要自己修改，如果要修改的话需要询问用户，单个rs文件不要超过80kb，如果超过了就必须拆分成多个文件，而且最后输出和功能不变，因为这是一个长期项目，在你接手，部署成功工具后，编写一个项目交接总结.md，里面要包含对本项目的描述与使用方法(如果已经有这个文件了，那在你有提示的时候也可以写入)
部署rust手册(新手必看):https://raw.githubusercontent.com/dream6-e/OBF/arena/01a0ce56-obf/rust-from-zero-for-ai.md
库里的Luraph14.9.lua是作为参考文件，大体结构要参考这个，但是不要照抄


## Luraph 反混淆项目与最终逻辑输出

- [完整修复后源码](tools/luraph/)（包含运行模块、资源、工具和样本，不是只有补丁）
- [离线部署、运行与测试说明](integrations/luraph/README.md)
- [14.8 最终可读逻辑](integrations/luraph/reports/artifacts/main-v148/README.md)
- [14.7 最终可读逻辑](integrations/luraph/reports/artifacts/main-v147/README.md)
- [打包验证结果](integrations/luraph/PACKAGE_VALIDATION.md)

主库输入尚未完整静态还原；以上输出包含已捕获的可读逻辑及明确限制，不冒充完整可运行源码。原始样本和 Environment.zip 保留。
