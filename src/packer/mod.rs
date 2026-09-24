pub mod utils;
pub mod compressor;
pub mod encryptor;
pub mod stub_generator;

pub fn pack_lua(input: &str) -> String {
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