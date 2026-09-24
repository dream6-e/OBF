pub mod utils;
pub mod compressor;
pub mod encryptor;
pub mod stub_generator;
pub mod shell;

/// MB 模式：把已经处理好的最终脚本包一层自解压外壳。
///
/// 用的是用户上传的 `压缩.rs` 的算法（DP/LZ + base85 + 折叠校验 + 自解码外壳）。
/// 上一代实现是 `pack_lua_stub_v1`（LZ + 滚动 XOR + base122 + 生成式 stub），
/// 保留在下面作对照：同一输入（`test/print.lua`）下新外壳产物 **51.8 KB / 122 ms**，
/// 旧管线 **55.3 KB / 191 ms**（越小越快，故按用户要求换成新的）。
pub fn pack_lua(input: &str) -> String {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5EED_1234_ABCD_9876);
    match shell::wrap(input, seed) {
        Some(sh) => sh.script,
        // 压不出收益（负载 + 外壳开销不比原文小）时退回旧管线，产物仍然可用。
        None => pack_lua_stub_v1(input),
    }
}

/// 上一代 MB 外壳：LZ 压缩 → 滚动 XOR → base122 → 生成的 stub。已不参与产物生成。
#[allow(dead_code)]
pub fn pack_lua_stub_v1(input: &str) -> String {
    let compressed = compressor::Compressor::compress(input.as_bytes());
    let (mut encrypted, keys) = encryptor::Encryptor::xor_stream(&compressed);
    // 4 字节对齐的补位必须用「解密后为 0」的字节。
    // 解码端会对**所有**字节（含补位）做一遍 XOR 再喂给 LZ 解码器：补 0 的话
    // 补位会变成 keys[i%16]，偶尔被当成合法记号，多解出一段垃圾拼在源码尾巴上，
    // 表现为产物偶发 "attempt to call a nil value"。补 keys[i%16] 则解出 0，
    // 解码器读到 0 头字节后流已耗尽即正常收尾。
    while encrypted.len() % 4 != 0 {
        let i = encrypted.len();
        encrypted.push(keys[i % 16]);
    }
    let (payload, alphabet) = encryptor::Encryptor::base122_encode(&encrypted);
    stub_generator::StubGenerator::build_decoder(&payload, &keys, &alphabet)
}