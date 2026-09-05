echo -e "\033[34m一键运行中\033[0m"
cd ~
rm -rf ~/kkryvex3
cp -r /storage/emulated/0/64/kkryvex3 ~/
cd ~/kkryvex3

echo -e "\033[33m开始混淆...\033[0m"
cargo run -- test.lua

echo -e "\033[32m运行输出:\033[0m"
lua obfuscated.lua

cp obfuscated.lua /storage/emulated/0/64/kkryvex3
echo -e "\033[32m已复制输出文件\033[0m"
echo -e "\033[32m完成\033[0m"
cd ~/kkryvex3