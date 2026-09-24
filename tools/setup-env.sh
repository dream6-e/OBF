#!/usr/bin/env bash
# 一键复原 Kryvex 的开发环境（幂等，可重复执行）。
#
# 沙箱/容器重启后，仓库以外的东西（Rust 工具链、离线 crate 源、~/.cargo）都会被清空，
# 而仓库内的 toolchains/bin 参考运行时始终在。跑这个脚本即可回到可构建状态。
#
#   bash tools/setup-env.sh              # 完整复原 + 构建 + 自检
#   bash tools/setup-env.sh --no-build   # 只复原环境，不构建
#
# 可选环境变量：
#   OBF_RUST_PREFIX   Rust 安装位置，默认 /usr/local/obf-rust-1.88.0
#                     （想让它跟着仓库一起留存，就设成 $PWD/.toolchains/rust-1.88.0，代价是约 600 MB）
#   OBF_VENDOR_DIR    离线 crate 源目录，默认 /usr/local/obf-crates-vendor
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUST_PREFIX=${OBF_RUST_PREFIX:-/usr/local/obf-rust-1.88.0}
VENDOR_DIR=${OBF_VENDOR_DIR:-/usr/local/obf-crates-vendor}
DO_BUILD=1
[[ ${1:-} == --no-build ]] && DO_BUILD=0

printf '%s\n' '[env] ① 参考运行时执行位（zip 打包会丢掉 x 位）'
chmod +x "$ROOT"/toolchains/bin/*
for tool in lua5.1 luac5.1 luau luau-compile; do
    printf '[env]   %s: ' "$tool"
    "$ROOT/toolchains/bin/$tool" -v 2>&1 | head -1 || true
done

printf '%s\n' '[env] ② Rust 1.88.0'
OBF_RUST_PREFIX="$RUST_PREFIX" bash "$ROOT/tools/bootstrap-rust.sh"
export PATH="$RUST_PREFIX/bin:$PATH"
rustc --version
cargo --version

printf '%s\n' '[env] ③ 第三方依赖'
if curl -sS --max-time 8 -o /dev/null https://index.crates.io/config.json 2>/dev/null; then
    printf '%s\n' '[env]   crates.io 可达，用官方源，不做离线处理'
    rm -f "$HOME/.cargo/config.toml"
else
    printf '%s\n' '[env]   crates.io 不可达 → 从 GitHub 组装离线 directory 源'
    VENDOR_DIR="$VENDOR_DIR" CARGO_LOCK="$ROOT/Cargo.lock" python3 "$ROOT/tools/offline-crates/vendor_crates.py"
    VENDOR_DIR="$VENDOR_DIR" CARGO_LOCK="$ROOT/Cargo.lock" PROJECT_ROOT="$ROOT" \
        python3 "$ROOT/tools/offline-crates/stub_crates.py"
    mkdir -p "$HOME/.cargo"
    cat >"$HOME/.cargo/config.toml" <<EOF
# 由 tools/setup-env.sh 生成：crates.io 不可达时改用本地 directory 源
[source.crates-io]
replace-with = "obf-vendored"

[source.obf-vendored]
directory = "$VENDOR_DIR"

[net]
offline = true
EOF
    printf '[env]   %s 个 crate 就绪\n' "$(ls "$VENDOR_DIR" | wc -l)"
fi

if [[ $DO_BUILD == 0 ]]; then
    printf '%s\n' "[env] 完成。使用前执行: export PATH=\"$RUST_PREFIX/bin:\$PATH\""
    exit 0
fi

printf '%s\n' '[env] ④ 构建 + 自检'
cd "$ROOT"
cargo build
cargo test
printf '%s\n' '[env] ✅ 环境就绪'
printf '%s\n' "[env] 后续命令记得先: export PATH=\"$RUST_PREFIX/bin:\$PATH\""
