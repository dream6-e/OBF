# RS 环境：Rust 工具链与离线编译

本文档记录在本仓库沙箱里**如何安装 Rust 工具链并离线编译 KRYVEX 混淆器**。
普通电脑（能访问 crates.io）直接 `cargo run -- test.lua` 即可；本文档只针对
**crates.io 被网络封锁**的沙箱环境，说明如何用 GitHub 源码离线把依赖喂给 cargo。

---

## 1. 网络现状（沙箱）

- ❌ 不可达：`rust-lang.org`、`static.crates.io`、`index.crates.io`、`crates.io`（含
  Fastly 全链路 TLS 握手失败）、`deb.debian.org`、以及所有国内 Rust 镜像
  （rsproxy / tuna / ustc 等）。
- ✅ 可达：`github.com`、`api.github.com`、`codeload.github.com`（走 `-L` 跟随
  重定向后可用）、`registry.npmjs.org`（npm 也可用）。

结论：Rust 工具链与 crate 依赖**都无法从官方源获取**，但 **GitHub 上的源码可以拉**，
因此离线编译的方案是：**从 GitHub 拉源码 + `[patch.crates-io]` 指向本地路径**。

---

## 2. 安装 Rust 工具链（来自 npm `@rustbin`）

沙箱里没有 `rustc`/`cargo`，且 rustup 主机被挡。改用 npm 上的 `@rustbin` 预编译包
（与 `HANDOFF.md §4` 一致）：

```bash
T=/home/user/OBF/.tools          # 放在仓库内，已 gitignore
mkdir -p "$T/bin" "$T/lib"
cd /tmp
for p in rustc cargo rust-std; do
  npm pack "@rustbin/$p-1.88.0-x86_64-unknown-linux-gnu" >/dev/null 2>&1
  rm -rf "x_$p"; mkdir -p "x_$p"
  tar xzf rustbin-$p-*.tgz -C "x_$p"
  mkdir -p "$T/lib/$p"; cp -r "x_$p/package/." "$T/lib/$p/"
done
# 把 rust-std 合并进 rustc 的 rustlib（cargo 才能找到标准库）
cp -rn "$T/lib/rust-std/rust-std-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/." \
      "$T/lib/rustc/rustc/lib/rustlib/x86_64-unknown-linux-gnu/"
ln -sf ../lib/rustc/rustc/bin/rustc "$T/bin/rustc"
ln -sf ../lib/cargo/cargo/bin/cargo "$T/bin/cargo"
"$T/bin/rustc" --version   # rustc 1.88.0
"$T/bin/cargo" --version   # cargo 1.88.0
```

使用时：

```bash
export PATH=/home/user/OBF/.tools/bin:$PATH
export CARGO_HOME=/home/user/OBF/.tools/cargo   # patch 配置写在这里
```

---

## 3. 离线获取依赖（核心：GitHub 源码 + patch）

`crates.io` 不可达，所以把依赖从 GitHub 拉到本地目录 `/home/user/vendor`，再用
`$CARGO_HOME/config.toml` 里的 `[patch.crates-io]` 把每个 crate 重定向到本地路径。

### 3.1 下载每个 crate

每个 crate 从 `codeload.github.com` 拉 release tag 的 tarball，解压即可：

```bash
V=/home/user/vendor; rm -rf "$V"; mkdir -p "$V"
fetch() { local repo=$1 tag=$2 out=$3; local o=/tmp/_d; rm -rf "$o"; mkdir -p "$o"
  curl -4 -sSL -m 150 -o "$o/t.tgz" "https://codeload.github.com/$repo/tar.gz/refs/tags/$tag" 2>/dev/null
  tar xzf "$o/t.tgz" -C "$o"; local top; top=$(ls -d "$o"/*/ | head -1)
  cp -r "$top/." "$out"; }

# 注意：有些仓库「根目录就是 crate 本身」，有些是「根目录 = workspace，子包在子目录」
fetch rust-random/rand        0.9.4    "$V/rand"            # 根=rand，含 rand_chacha/ rand_core/ 兄弟目录
fetch rust-random/getrandom  v0.3.4    "$V/getrandom"
fetch cryptocorrosion/cryptocorrosion  ppv-lite86-0.2.21  "$V/ppv-lite86"   # 实际子目录 utils-simd/ppv-lite86/
fetch rust-lang/regex         1.12.4    "$V/regex"           # 根=regex，含 regex-automata/ regex-syntax/
fetch BurntSushi/aho-corasick 1.1.4     "$V/aho-corasick"
fetch BurntSushi/memchr       2.8.2     "$V/memchr"
fetch google/zerocopy         v0.8.52   "$V/zerocopy/zerocopy"          # 嵌套一层
fetch google/zerocopy         v0.8.52   "$V/zerocopy/zerocopy-derive"   # 子目录 zerocopy/zerocopy-derive
fetch dtolnay/proc-macro2     1.0.106   "$V/proc-macro2"
fetch dtolnay/quote           1.0.45    "$V/quote"
fetch dtolnay/syn             2.0.117   "$V/syn"
fetch dtolnay/unicode-ident   1.0.24   "$V/unicode-ident"
fetch rust-lang/cfg-if        v1.0.4    "$V/cfg-if"
fetch rust-lang/log           0.4.33    "$V/log"
fetch rust-lang/libc          0.2.186   "$V/libc"
```

> **版本漂移说明**：GitHub 上 `getrandom` 只 tag 到 `0.3.4`（lock 里是 `0.3.14`，
> 未打 tag），`rand_core` 在 `rand 0.9.4` 里是 `0.9.3`（lock 是 `0.9.0`）。都在 `^` 范围内，
> 编译通过，但会偏离原始 `Cargo.lock`。见 §6。

### 3.2 多 crate 仓库的 manifest 手术

`rand` / `regex` / `zerocopy` 是 workspace，子包直接拿来做独立目录会断，需要修 manifest：

- **删掉 `[workspace]` 表**（让该 crate 作为独立包，不再加载其它 workspace 成员）；
- 把 `include.workspace = true` 换成具体值，例如
  `include = ["src/**/*.rs", "Cargo.toml", "LICENSE-MIT", "LICENSE-APACHE", "README.md"]`
  （`include` 只影响打包，不影响编译，给个通用值即可）；
- 把内部 `path = "../x"` 依赖改成 `version = "..."`（交给 patch 解析）；
- **删掉 `[dev-dependencies]`**：我们只 `build` 不 `test`，但 cargo 解析时仍会要求这些
  未 vendor 的 dev 依赖，直接删掉最省事。

### 3.3 wasm-only 依赖用空 stub

`getrandom` 等有一堆**按目标平台划分的可选依赖**（`wasip2`、`wasm-bindgen`、`js-sys`、
`r-efi`、`wasm-bindgen-test`，分别对应 wasi / wasm / uefi 等）。cargo 解析 lock 时会把它们
全拉进来，但 **linux 构建永远不会真正编译它们**。给它们各造一个空 stub crate
（只满足版本，源码为空）即可：

```bash
S=/home/user/stub; mkdir -p "$S"
mkstub() { local name=$1 ver=$2; mkdir -p "$S/$name/src"
  printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n' "$name" "$ver" > "$S/$name/Cargo.toml"
  : > "$S/$name/src/lib.rs"; }
mkstub wasip2 1.0.0
mkstub wasm-bindgen 0.2.98
mkstub js-sys 0.3.77
mkstub r-efi 5.1.0
mkstub wasm-bindgen-test 0.3.0
```

### 3.4 patch 配置

写到 `$CARGO_HOME/config.toml`（即 `/home/user/OBF/.tools/cargo/config.toml`）：

```toml
[patch.crates-io]
rand            = { path = "/home/user/vendor/rand" }
rand_core       = { path = "/home/user/vendor/rand/rand_core" }
getrandom       = { path = "/home/user/vendor/getrandom" }
ppv-lite86      = { path = "/home/user/vendor/ppv-lite86" }
regex           = { path = "/home/user/vendor/regex" }
regex-automata  = { path = "/home/user/vendor/regex/regex-automata" }
regex-syntax    = { path = "/home/user/vendor/regex/regex-syntax" }
aho-corasick    = { path = "/home/user/vendor/aho-corasick" }
memchr          = { path = "/home/user/vendor/memchr" }
zerocopy        = { path = "/home/user/vendor/zerocopy/zerocopy" }
zerocopy-derive = { path = "/home/user/vendor/zerocopy/zerocopy-derive" }
proc-macro2     = { path = "/home/user/vendor/proc-macro2" }
quote           = { path = "/home/user/vendor/quote" }
syn             = { path = "/home/user/vendor/syn" }
unicode-ident   = { path = "/home/user/vendor/unicode-ident" }
cfg-if         = { path = "/home/user/vendor/cfg-if" }
log             = { path = "/home/user/vendor/log" }
libc            = { path = "/home/user/vendor/libc" }
# wasm-only 依赖（linux 不编译，空 stub 仅用于满足 lock 解析）
wasip2             = { path = "/home/user/stub/wasip2" }
wasm-bindgen       = { path = "/home/user/stub/wasm-bindgen" }
js-sys             = { path = "/home/user/stub/js-sys" }
r-efi              = { path = "/home/user/stub/r-efi" }
wasm-bindgen-test  = { path = "/home/user/stub/wasm-bindgen-test" }
```

`rand_chacha` 不需要 patch——它是 `rand` 仓库内的本地 `path` 依赖，随 `rand` 一起解析。

---

## 4. 编译

`cargo build` 默认会解析**整个 workspace**（含 `CLI`，需要 `crossterm` 一整棵依赖树）。
为缩小离线范围，只编混淆器本体 `kryvex-simple`（默认成员），**临时把 `CLI` 移出 workspace**，
并把 `Cargo.lock` 挪开让 cargo 重新解析（因为 §3.1 的版本漂移）：

```bash
cd /home/user/OBF
# 临时去掉 CLI 成员
sed -i 's/^members = \["CLI"\]/# members = ["CLI"]  # 离线编译时临时禁用/' Cargo.toml
# 挪开原 Cargo.lock（其 pin 的 getrandom 0.3.14 在 GitHub 没有源码）
[ -f Cargo.lock ] && mv Cargo.lock /tmp/Cargo.lock.orig

cargo build --offline            # 产物在 target/debug/kryvex-simple
cargo run  --offline -- test.lua # 读取 test.lua，生成 obfuscated.lua
```

> 若想编完整 workspace（含 CLI），需额外把 `crossterm` 及其依赖树（mio / signal-hook /
> parking_lot / libc / log / errno …）也按同样方式 vendor 进来。

---

## 5. 运行验证

仓库里的 `obfuscated.lua` 是 `print'67'` 的混淆结果。沙箱没有 Lua，可用 GitHub 源码
自编一个 Lua 5.4 解释器（注意混淆产物用到了 `bit32`，5.4 已移除，需加垫片）：

```bash
# 自编 Lua 5.4（详见 如何使用.md / 下面片段）
#   curl -4 -sSL ... codeload.github.com/lua/lua/tar.gz/refs/tags/v5.4.7 | tar xzf -
#   cd lua-5.4.7 && make -f makefile linux  （去掉 -DLUA_USE_READLINE 后编）
LUA=/tmp/lua/lua-5.4.7/lua

cat > /tmp/bit32.lua <<'EOF'
local function m(x) return (x & 0xFFFFFFFF) end
bit32 = { band=function(a,b)return m(a&b) end, bor=function(a,b)return m(a|b) end,
  bxor=function(a,b)return m(a~b) end, bnot=function(a)return m(~a) end,
  lshift=function(a,b)return m(a<<b) end, rshift=function(a,b)return m((a&0xFFFFFFFF)>>b) end,
  arshift=function(a,b)return m((a&0xFFFFFFFF)>>b) end, xor=function(a,b)return m(a~b) end }
EOF

cat /tmp/bit32.lua obfuscated.lua > /tmp/run.lua
"$LUA" /tmp/run.lua     # 应输出 67，与 test.lua 一致
```

---

## 6. 已知坑 / 注意事项

- **依赖闭包无法纯离线从 GitHub 还原**：`getrandom 0.3.14` 在 GitHub 没打 tag、`ppv-lite86`
  是 `cryptocorrosion` 单仓库的子目录且自身又依赖 `zerocopy`、`zerocopy` 是大 workspace
  （`zerocopy-derive` 用 `path`/`testutil` 内部依赖）。所以用了版本漂移 + manifest 手术 +
  wasm stub 的组合拳；能编通，但 `Cargo.lock` 与原始 pin 不同。
- **`.tools/` 与 `target/`、生成的 `obfuscated.lua` 都已 gitignore**；`/home/user/vendor`
  与 `/home/user/stub` 在仓库外，不会进版本库。需要复现时按本文重做即可。
- **正常环境**（crates.io 可达）不需要以上任何步骤，直接
  `cargo run -- test.lua` 即可。本文档只是为被网络封锁的沙箱准备的离线 workaround。
