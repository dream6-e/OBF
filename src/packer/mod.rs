pub mod utils;
pub mod compressor;
pub mod encryptor;
pub mod stub_generator;
pub mod shell;

/// MB 模式：把已经处理好的最终脚本包一层自解压外壳。
///
/// 用的是用户上传的 `压缩.rs` 的算法（DP/LZ + base85 + 折叠校验 + 自解码外壳）。
/// 上一代实现 `pack_lua_stub_v1`（LZ + 自定义滚动流 + base122 + 生成式 stub）
/// 仍用作压缩收益为负时的兼容回退。
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

/// 上一代 MB 外壳回退：LZ 压缩 → 自定义滚动变换 → base122 → 生成式 stub。
#[allow(dead_code)]
pub fn pack_lua_stub_v1(input: &str) -> String {
    let mut compressed = compressor::Compressor::compress(input.as_bytes());
    // 先在明文流补零，保证 base122 不会再添加未经滚动变换的字节。
    // LZ 解码器以零结束标记收尾，因此这些字节不会成为源码尾部垃圾。
    while compressed.len() % 4 != 0 {
        compressed.push(0);
    }
    let (encrypted, keys) = encryptor::Encryptor::custom_stream(&compressed);
    let (payload, alphabet) = encryptor::Encryptor::base122_encode(&encrypted);
    stub_generator::StubGenerator::build_decoder(&payload, &keys, &alphabet)
}
#[cfg(test)]
mod fallback_stub_tests {
    use super::pack_lua_stub_v1;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn generated_legacy_stub_executes_under_lua_51() {
        let lua = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() { return; }
        let source = "io.write('LEGACY_STUB_OK')";
        let packed = pack_lua_stub_v1(source);
        let out = Command::new(lua).arg("-e").arg(packed).output().expect("run bundled Lua 5.1");
        assert!(out.status.success(), "legacy stub failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("LEGACY_STUB_OK"));
    }
}
