# 从零部署「可编译的 Rust」执行手册（给其他 AI agent 用）

> 本文件与任何具体项目无关。目标只有一个：**在一台干净机器上，得到一个能真正编译出可执行文件的 Rust 工具链**。
> 版本基准：本文以 **rustc/cargo 1.88.0** 为例（可替换为任意稳定版），命令在 Debian 12 / x86_64 上实测过，失败样例的报错文本为实测原文。

---

## 0. 成功判据（做不到这三条就不算部署成功）

1. `rustc --version` 与 `cargo --version` 返回同一版本的稳定版，退出码 0。
2. **零依赖**的最小项目能编译并运行：`cargo new` → `cargo build --offline` → 跑出预期输出。
3. 不能用「装上了工具链」代替「能编译」：必须真的产出一个二进制并执行它。

任何一步失败，都不要猜「大概是版本问题」——把**完整报错原文**贴出来再对照 §9 处置。

---

## 1. 先做决策：三条路线

| 条件 | 走哪条 | 跳转 |
|---|---|---|
| 能访问 `sh.rustup.rs` / `static.rust-lang.org`（最常见） | **路线 A：rustup** | §2 |
| 完全无外网，但能拿到发行包或别人的工具链目录 | **路线 B：发行包 / 目录搬运** | §3 |
| 只有镜像源可达（国内、企业内网、沙箱），或被墙 | **路线 C：镜像 / 替代分发** | §4 |

三种都要先满足 **§5 的系统前置条件（链接器）**，否则编译期会在最后一步报 `linker not found`。

---

## 2. 路线 A：rustup（标准做法，全平台）

### 2.1 一次性非交互安装

```bash
# Linux / macOS：装 1.88.0（精简 profile + rustfmt/clippy），不提示、不交互
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
  -y \
  --default-toolchain 1.88.0 \
  --profile minimal \
  -c rustfmt,clippy
```

- `-s --` 之后的参数全部传给 `rustup-init`；`-y` = `--no-confirm`（**AI 必须加，否则会卡在交互提示**）。
- 不想让它改你的 shell 配置：追加 `--no-modify-path`，然后自行 export PATH。
- 只要最新稳定版就把 `--default-toolchain 1.88.0` 换成 `--default-toolchain stable`。

```bash
# Windows（PowerShell，管理员或用户级均可）
winget install --id Rustlang.Rustup -e
rustup-init.exe -y --default-toolchain 1.88.0 --profile minimal -c rustfmt,clippy
# 或双击/命令行运行 rustup-init.exe（下载自 https://win.rustup.rs/x86_64）
```

### 2.2 让它在当前 shell 生效

```bash
export PATH="$HOME/.cargo/bin:$PATH"     # 每个新 shell 都需要
# 或者：
. "$HOME/.cargo/env"                     # rustup 生成的环境片段
command -v rustc && rustc --version
```

**AI 注意**：`export PATH` 只在当前进程有效。跨命令/跨会话要写进 `~/.bashrc` / `~/.profile`，或在每条命令里显式 `PATH="$HOME/.cargo/bin:$PATH" cmd`。

### 2.3 目录与环境变量（排查时先看这里）

| 变量 | 默认值 | 作用 |
|---|---|---|
| `RUSTUP_HOME` | `~/.rustup` | 工具链本体（每套约 500–700 MB） |
| `CARGO_HOME` | `~/.cargo` | `bin/`、registry 缓存、`config.toml` |
| `PATH` | 追加 `$CARGO_HOME/bin` | 找到 `cargo`/`rustc`/`rustfmt` |

无 sudo 的受限机器：把两个变量指到可写目录即可，例如
`export RUSTUP_HOME=/work/.rustup CARGO_HOME=/work/.cargo`，随后 `curl … | sh -s -- -y --no-modify-path …`。

### 2.4 常用后续命令

```bash
rustup toolchain install 1.88.0 --profile minimal -c rustfmt,clippy   # 补装指定版本
rustup component add clippy rustfmt                                   # 补装组件（默认不装 clippy）
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-gnu # 补装交叉目标 std
rustup show                                                           # 当前默认/已装工具链
rustup default 1.88.0                                                 # 改默认版本
rustup override set 1.88.0                                            # 只对当前目录树生效（写 ~/.rustup，不动仓库）
```

### 2.5 固定版本（可复现的关键）

在项目根放 `rust-toolchain.toml`，此后该目录内所有 `cargo`/`rustc` 自动用指定版本（rustup 会按需下载）：

```toml
[toolchain]
channel = "1.88.0"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

临时指定版本：`cargo +1.88.0 build`。

---

## 3. 路线 B：发行包直装 / 目录搬运（完全离线、无 rustup）

### 3.1 官方发行包（推荐用于离线机器）

在有网的机器上下载（文件名规则：`rust-<版本>-<目标三元组>.tar.xz`）：

```bash
# 例：https://static.rust-lang.org/dist/rust-1.88.0-x86_64-unknown-linux-gnu.tar.xz
curl -LO https://static.rust-lang.org/dist/rust-1.88.0-x86_64-unknown-linux-gnu.tar.xz
tar -xf rust-1.88.0-x86_64-unknown-linux-gnu.tar.xz
cd rust-1.88.0-x86_64-unknown-linux-gnu
./install.sh --prefix=/opt/rust-1.88.0 --disable-ldconfig \
             --components=rustc,rust-std-x86_64-unknown-linux-gnu,cargo,rustfmt
export PATH="/opt/rust-1.88.0/bin:$PATH"
rustc --version && cargo --version
```

- `--prefix` 指向**专用目录**（不要指向 `/usr`、home 根或已有工作目录）。
- `--disable-ldconfig` = 不写系统动态库缓存 ⇒ 无需 sudo、不污染系统。
- 包里还有 `components/` 子目录，可单独安装 `rust-std-*`（交叉目标）、`clippy`、`rust-src` 等。

### 3.2 直接搬运一份已装好的工具链（最快）

Rust 发行版是**可搬迁**的（实测：把整个工具链目录 `cp -a` 到别的路径，`rustc`/`cargo` 照常工作，不依赖原路径）：

```bash
cp -a /source/.toolchains/rust-1.88.0 /opt/rust-1.88.0
/opt/rust-1.88.0/bin/rustc --version      # 立刻可用
export PATH="/opt/rust-1.88.0/bin:$PATH"
```

若已经有 rustup，可以把手工目录注册进去：`rustup toolchain link my-1.88 /opt/rust-1.88.0`，之后用 `cargo +my-1.88 build`。
tarball 直装（§3.1）与目录搬运（§3.2）得到的都是**普通 rustc 发行布局**（`bin/` + `lib/rustlib/<target>/`），不含 rustup 的版本管理。

---

## 4. 路线 C：镜像 / 替代分发（受限网络）

### 4.1 rustup 与 crates.io 走镜像（中国大陆常用）

```bash
# rustup 本体与工具链下载
export RUSTUP_DIST_SERVER=https://rsproxy.cn
export RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup
# 备用镜像：https://mirrors.ustc.edu.cn/rust-static  https://mirrors.tuna.tsinghua.edu.cn/rustup

curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh -s -- -y --default-toolchain 1.88.0 --profile minimal
```

crates.io 换源（写 `$CARGO_HOME/config.toml`，全局生效）：

```toml
[source.crates-io]
replace-with = "mirror"

[source.mirror]
registry = "sparse+https://rsproxy.cn/index/"

[net]
git-fetch-with-cli = true      # git 依赖走系统 git，避免 libgit2 问题
```

### 4.2 只有 npm registry 可达时（实测过的替代通道）

出现「`static.rust-lang.org` 不可达，但 npm 能用」的沙箱很常见。此时可用 npm 上分发工具链的包：

```bash
npm pack @rustbin/rustc-1.88.0-x86_64-unknown-linux-gnu
npm pack @rustbin/rust-std-1.88.0-x86_64-unknown-linux-gnu
npm pack @rustbin/cargo-1.88.0-x86_64-unknown-linux-gnu
npm pack @rustbin/rustfmt-1.88.0-x86_64-unknown-linux-gnu
for p in *.tgz; do tar -xzf "$p"; ./package/install.sh --prefix=/opt/rust-1.88.0 --disable-ldconfig; rm -rf package; done
export PATH="/opt/rust-1.88.0/bin:$PATH"
```

注意：这类包的平台是写死的（例如 `x86_64-unknown-linux-gnu`），非 Linux/非 x86_64 不适用。
同类替代通道还有：公司内网制品库里的 rustup 发行包、Docker 基础镜像 `rust:1.88`（拉镜像后 `docker run` 里直接有工具链）。

### 4.3 有 HTTP 代理时

```bash
export HTTPS_PROXY=http://proxy.corp:8080 HTTP_PROXY=http://proxy.corp:8080
# cargo 走 git 依赖时也继承这两个变量；必要时显式：
export CARGO_HTTP_PROXY=http://proxy.corp:8080
```

### 4.4 依赖离线（crates.io 也要离线时）

```bash
# 在有网机器上（项目内）：
cargo vendor                      # 生成 vendor/ 并打印需要写入的配置
# 把打印出来的配置写进 .cargo/config.toml：
#   [source.crates-io]
#   replace-with = "vendored-sources"
#   [source.vendored-sources]
#   directory = "vendor"
# 目标机（无网）：
cargo build --offline             # 或 export CARGO_NET_OFFLINE=true
```

整个 `$CARGO_HOME/registry/` 目录也可以直接搬运（缓存复用，免下载）。

---

## 5. 系统前置条件：链接器（最常被忽略的一步）

Rust 自己负责编译，**链接要交给系统 C 链接器**。没有它，代码编译过但链接失败。

```bash
# 检查
command -v cc gcc clang ld
```

```bash
# Debian/Ubuntu（无 sudo 时：sudo apt-get install -y build-essential 或让管理员装）
apt-get update && apt-get install -y build-essential pkg-config ca-certificates curl
# RHEL/Fedora/CentOS
dnf groupinstall -y "Development Tools" && dnf install -y pkg-config
# Alpine
apk add --no-cache build-base
# macOS
xcode-select --install
# Windows（MSVC 工具链，推荐）
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
# Windows（GNU 工具链替代，配合 --default-host x86_64-pc-windows-gnu）
winget install -e --id MartinStorsjo.LLVM-MinGW     # 或 choco install mingw
```

缺链接器时的确切报错：

```
error: linker `cc` not found
  |
  = note: No such file or directory (os error 2)
```

---

## 6. 最小验证（三条，必须全过）

```bash
# ① 版本 + 路径
command -v rustc cargo
rustc --version          # 期望：rustc 1.88.0 (6b00bc388 2025-06-23)
cargo --version          # 期望：cargo 1.88.0 (873a06493 2025-05-10)

# ② 零依赖项目：建、离线编、跑（隔离网络与依赖问题）
cargo new hello && cd hello
cargo build --offline        # 实测 0.6 秒
./target/debug/hello         # 期望输出：Hello, world!

# ③ 不走 cargo，直接编译（验证 rustc 本身与链接器）
printf 'fn main(){println!("direct-ok");}\n' > d.rs
rustc d.rs -o d && ./d       # 期望输出：direct-ok
```

②③ 都过 = 工具链可用。只过 ① 不算。把 `Hello, world!` 的真实输出贴出来，不要用「应该可以」代替。

多项目复用编译缓存（AI 反复建临时项目时很省时间）：

```bash
export CARGO_TARGET_DIR=/tmp/rust-target        # 所有项目共用一份 target
export CARGO_INCREMENTAL=1
cargo build --release                           # 生产构建
```

---

## 7. 交叉编译与静态产物（按需）

```bash
rustup target add x86_64-unknown-linux-musl      # 静态链接，可拷到同架构其他机器直接跑
rustup target add aarch64-unknown-linux-gnu      # ARM64 服务器
rustup target add x86_64-pc-windows-gnu          # Windows，GNU 工具链（需 mingw-w64）
cargo build --release --target x86_64-unknown-linux-musl
```

- 目标 std 没装时的确切报错：
  `error[E0463]: can't find crate for `std` … the `x86_64-unknown-linux-musl` target may not be installed … consider downloading the target with `rustup target add …``。
- `musl` 目标通常自带 `rust-lld` 可自包含静态链接；若报找不到链接器，再补 `musl-tools`（Debian）或换 `-C linker=…`。
- 需要更省事的交叉环境时可用 `cargo-zigbuild`（Zig 提供链接器），但那是额外工具，不是部署 Rust 的必需项。

---

## 8. Docker / CI 一条龙（可复制）

```dockerfile
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates build-essential pkg-config && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
        -y --default-toolchain 1.88.0 --profile minimal -c rustfmt,clippy
WORKDIR /work
```

或用官方镜像（最省事，注意镜像 tag 固定版本）：`FROM rust:1.88-slim`，再补 `apt-get install -y build-essential`。

---

## 9. 报错 → 处置表（文本均为实测原文）

| 报错 | 含义 | 处置 |
|---|---|---|
| `error: linker \`cc\` not found` + `No such file or directory (os error 2)` | 缺系统 C 链接器 | §5 安装 `build-essential` / Xcode CLT / MSVC 或 mingw |
| `error: no matching package named \`serde\` found` / `location searched: crates.io index` / `As a reminder, you're using offline mode (--offline)…` | 离线模式且本地无该依赖 | 去 `--offline` 联网解析，或先 `cargo vendor` / 搬 `$CARGO_HOME/registry` |
| `error: failed to get \`x\` as a dependency … Caused by: download of config.json failed` + `warning: spurious network error (3 tries remaining): [35] SSL connect error` | crates.io 不可达（被墙/代理） | §4.1 换 sparse 镜像，或 §4.3 设代理，或 §4.4 vendor |
| `error[E0463]: can't find crate for \`std\` … may not be installed` | 目标平台 std 未装 | `rustup target add <目标>`，或装 `rust-std-<目标>` 发行包组件 |
| `error: toolchain 'stable-x86_64-unknown-linux-gnu' is not installed` | 指定版本没装 | `rustup toolchain install 1.88.0` |
| `error: no default toolchain configured` | 装完没设默认 | `rustup default 1.88.0` |
| `Blocking waiting for file lock on package cache` | 另一个 cargo 在跑 | 等待或分开 `CARGO_TARGET_DIR`；不要 `rm` 掉锁所在目录 |
| `error: package \`x\` requires rustc 1.85 or newer` / `edition2024 requires…` | 版本太旧 | 装/R 切换新版：`rustup toolchain install 1.9x && cargo +1.9x build` |
| `command not found: cargo`（装完却找不到） | PATH 未生效 | `export PATH="$HOME/.cargo/bin:$PATH"`；用绝对路径 `~/.cargo/bin/cargo` 验证 |
| `Permission denied` / `cannot execute`（工具链目录内） | 挂载点 `noexec` 或无执行位 | 换到有 exec 位的前缀（如 `$HOME/.toolchains`）；`mount \| grep noexec` 确认 |
| `error: Unrecognized option: 'linker'` | 命令行参数写错 | 用 `-C linker=<path>`，不是 `--linker` |
| rustup 卡住不动（无输出） | 缺 `-y` 在等交互，或网络慢 | 重跑并加 `-y`；设 `RUSTUP_DIST_SERVER` 镜像；`curl -I` 先测端点 |

**HTTP 000 / 连接超时**表示端点**根本不可达**（不是慢）：先 `curl -sI -m 8 <url>` 确认，再直接跳到 §4。

---

## 10. 给 AI 的执行纪律（避免「假成功」）

1. **不要用系统包管理器的 rustc 当固定版本**（Debian 12 自带 1.63，多数现代项目编译不了）。系统包只用于快速验证，不用于交付。
2. **不要 sudo 装全局**：`rustup` 全程用户级即可；需要系统前缀时用 `--prefix` + `--disable-ldconfig`。仓库/项目目录里也不要 sudo（会产生 root 所有的文件）。
3. **不要在没有链接器时说「代码有问题」**：先排除 §5。
4. **不要把 `--offline` 的解析失败当成代码 bug**：先确认依赖是否已 vendor/缓存。
5. **不要只看 `cargo build` 的退出码**：跑一次二进制、贴出真实 stdout。
6. **不要漏掉 PATH 的作用域**：每条独立命令都要保证 PATH 生效，或在命令里用绝对路径。`command -v` 是廉价的自检。
7. **不要跨会话假设环境还在**：沙箱/容器重启后 `~/.rustup`、`~/.cargo`、`target/` 都可能消失。持久化的做法是把工具链放在工作区内的固定路径（如 `<workspace>/.toolchains/rust-1.88.0`，实测可整目录搬运），并把 `target/` 与缓存排除在版本控制外。
8. **不要用 `RUSTC_BOOTSTRAP=1` 之类绕过手段**让不匹配的版本编过稳定版代码；需要新特性就装新工具链。
9. **不要声称成功而没跑过 §6 三条验证**；报错时贴**完整原文**，不要转述。
10. **每次交付记录**：`rustc --version`、工具链绝对路径、安装方式（rustup / 发行包 / 搬运）、是否离线、验证输出。

---

## 11. 一页速查（联网 + Linux x86_64）

```bash
# 1) 系统依赖
sudo apt-get update && sudo apt-get install -y curl build-essential pkg-config ca-certificates

# 2) 装 Rust 1.88.0（非交互、最小 profile）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
  -y --default-toolchain 1.88.0 --profile minimal -c rustfmt,clippy
export PATH="$HOME/.cargo/bin:$PATH"

# 3) 验证（三条全过才算成功）
rustc --version && cargo --version
cargo new hello && cd hello && cargo build --offline && ./target/debug/hello
printf 'fn main(){println!("direct-ok");}\n' > d.rs && rustc d.rs -o d && ./d
```

镜像环境把第 2 步替换为：

```bash
export RUSTUP_DIST_SERVER=https://rsproxy.cn RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup
curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh -s -- \
  -y --default-toolchain 1.88.0 --profile minimal -c rustfmt,clippy
```

---

## 12. 连不上 crates.io（或其他 registry）怎么办

**先分清两件事**：`rustc`/`cargo` 本体**不需要** crates.io；只有引入第三方依赖（`[dependencies]`）时才需要 registry。
所以「装好 Rust 但访问不了 crates.io」通常**不影响**编译零依赖项目——实测：`CARGO_NET_OFFLINE=true` + 清空 `target/` + `HOME` 未设置，`cargo build` 与 `cargo run` 全部成功。

> 本章所有「实测 ✓」= 在只开放 `github.com` 与 `registry.npmjs.org`、**crates.io 与所有国内镜像均不可达**的沙箱里跑通的真实命令与输出。

### 12.1 第一步：判定到底什么被挡住（不要靠猜）

```bash
for u in https://crates.io https://static.crates.io https://index.crates.io/config.json \
         https://rsproxy.cn/index/config.json https://github.com https://registry.npmjs.org; do
  printf '%-58s ' "$u"; curl -s -o /dev/null -m 8 -w '%{http_code}\n' "$u" || echo FAIL
done
```

- `200` = 可用；**`000` = 这个端点根本连不上**（不是慢、不是重试能好）。
- 某次实测样本：`crates.io` 000、`static.crates.io` 000、`index.crates.io` 000、`rsproxy/ustc/tuna` 000，而 **`github.com` 200、`registry.npmjs.org` 200**。
  ⇒ 这种环境下的正确策略是「**绕开 registry，把依赖换成源码**」，而不是换镜像（镜像也不通）。

### 12.2 六条可用路线（按推荐顺序，附实测状态）

#### 路线 0：零依赖（std-only）——什么都不用配 ✓ 实测

自写代码只用标准库时，直接构建即可，网络完全不参与：

```bash
cargo new solo && cd solo && CARGO_NET_OFFLINE=true cargo build && ./target/debug/solo
```

#### 路线 1：本地 path 依赖 ✓ 实测

依赖源码就在本机（自己拆的模块、拷来的库）时最省事：

```toml
[dependencies]
foo = { path = "../foo" }
```

#### 路线 2：vendor 目录 + directory source（**最通用的离线方案**）✓ 实测

原理：把每个依赖的源码目录放进 `vendor/`，并让 cargo 用「目录源」替代 crates.io。

```toml
# 项目内 .cargo/config.toml（或 $CARGO_HOME/config.toml 全局）
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/abs/path/to/vendor"      # 建议绝对路径
```

有网机器上生成（推荐，会写正确的 checksum）：

```bash
cargo vendor --versioned-dirs vendor   # 并把它打印出来的配置抄进 .cargo/config.toml
```

无网机器上只要 `vendored-sources` 里能找齐全部依赖（含传递依赖）即可：

```bash
CARGO_NET_OFFLINE=true cargo build
```

- 手工凑 vendor 目录也**可行**（实测）：`vendor/<crate>/{Cargo.toml,src/,…}` + `.cargo-checksum.json`，内容写 `{"files":{}}` 即被接受（真实 `cargo vendor` 会写逐文件 sha256；手写空表能用但失去校验）。
- 缺依赖时的确切报错（据此判断是「源里没有」而不是「代码错」）：
  `error: no matching package found / searched package name: \`bar\` … location searched: directory source \`…\` (which is replacing registry \`crates-io\`)`。

#### 路线 3：把依赖换成 GitHub 上的 git 依赖 ✓ 实测

GitHub 通常比 crates.io 更容易放行；用 tag/rev 钉死版本保证可复现：

```toml
[dependencies]
itoa = { git = "https://github.com/dtolnay/itoa", tag = "1.0.15" }
# 或 rev = "<40位commit>"；内部 GitLab/Gitea 同理填其 https 地址
```

```bash
cargo build                 # 首次必须允许联网到该 git 主机
cargo build --offline       # 缓存到 $CARGO_HOME/git/ 之后可离线
```

两个实测到的坑：

- **`--offline` 不接受首次 clone**：`can't checkout from '…': you are in the offline mode (--offline)`。先联网跑一次即可。
- `cargo vendor --versioned-dirs` 对 git 依赖同样有效，并会打印这种配置（实测原文）：
  ```toml
  [source."git+https://github.com/dtolnay/itoa?tag=1.0.15"]
  git = "https://github.com/dtolnay/itoa"
  tag = "1.0.15"
  replace-with = "vendored-sources"

  [source.vendored-sources]
  directory = "/abs/path/vend-gh"
  ```

#### 路线 4：GitHub 源码 tarball → 手工 vendor ✓ 实测

适合「依赖仓库在 GitHub，但构建机连不上 crates.io 也连不上 git 协议」：

```bash
curl -sL -o itoa.tar.gz https://github.com/dtolnay/itoa/archive/refs/tags/1.0.15.tar.gz
mkdir -p vendor && tar -xzf itoa.tar.gz -C vendor && mv vendor/itoa-1.0.15 vendor/itoa
printf '{"files":{}}\n' > vendor/itoa/.cargo-checksum.json    # 然后按路线 2 配 directory source
CARGO_NET_OFFLINE=true cargo build                            # 实测 ✓
```

（crate 源码目录里有 `Cargo.toml` 就能作为 vendor 项；版本必须与 `Cargo.toml`/`Cargo.lock` 的要求相容。）

#### 路线 5：搬运依赖缓存（有网机器 → 无网机器）

```bash
# 有网机器（同一项目先构建一次）
tar -C ~/.cargo -czf cargo-cache.tgz registry git
# 无网机器
tar -C ~/.cargo -xzf cargo-cache.tgz
CARGO_NET_OFFLINE=true cargo build --locked
```

`Cargo.lock` 必须一起带过去（它锁版本；`--locked`/`--frozen` = 锁定 + 离线），否则解析会去找 registry。
（本沙箱从未从 crates.io 下载过 crate，故这条**未实测**，属标准做法。）

#### 路线 6：镜像 / 代理（**只在端点可达时才有用**）

```toml
# $CARGO_HOME/config.toml —— 三选一，替换 with 的名字随意
[source.crates-io]
replace-with = "mirror"

[source.mirror]
registry = "sparse+https://rsproxy.cn/index/"                                  # 字节跳动
# registry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"             # 中科大
# registry = "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/"    # 清华

[net]
git-fetch-with-cli = true      # git 依赖交给系统 git，兼容代理/凭据助手
```

纪律：**配置前先 `curl -sI -m 8 <index-url>` 确认 200**；本次沙箱三个镜像全 000 ⇒ 配了也没用，属「先验证再配置」的典型场景。

企业代理 / TLS 拦截环境：

```bash
export HTTPS_PROXY=http://proxy.corp:8080 HTTP_PROXY=http://proxy.corp:8080
export CARGO_HTTP_PROXY=http://proxy.corp:8080
export CARGO_HTTP_CAINFO=/path/to/corp-ca.pem      # 自签 CA 时
export CARGO_HTTP_MULTIPLEXING=false               # 某些代理下更稳
export CARGO_HTTP_TIMEOUT=60 CARGO_NET_RETRY=5
```

#### 路线 7：`[patch.crates-io]` 用本地源码顶替 ✓ 实测

已有 `foo = "0.1"` 形式的声明、手上又有源码时，可以不动依赖行：

```toml
[dependencies]
foo = "0.1.0"

[patch.crates-io]
foo = { path = "../foo" }
```

实测在 `CARGO_NET_OFFLINE=true` 下可直接构建。限制：**传递依赖仍需能解析**（即其余依赖要么也在 patch/vendor 里，要么已在缓存），故只适合替换少量 crate。

### 12.3 新增的确切报错 → 处置（实测原文）

| 报错 | 含义 | 处置 |
|---|---|---|
| `error: no matching package found / searched package name: \`bar\` … location searched: directory source \`…\` (which is replacing registry \`crates-io\`)` | vendor 目录里没有这个（含传递）依赖 | 把该 crate 源码补进 vendor，或改走 git/tarball 路线 |
| `can't checkout from 'file:///…': you are in the offline mode (--offline)` | `--offline` 下首次拉 git 依赖被拒（即使 URL 是本机 `file://`） | 先允许联网构建一次完成 checkout，之后 `--offline` 即可；或把依赖改成 vendor 目录 |
| `error: the crate \`serde\` could not be found in registry index.` （`cargo add`） | 离线/registry 不通时无法 `cargo add` | 手工编辑 `Cargo.toml` 写依赖；不要在断网时用 `cargo add`/`cargo search` |
| `There is no dependency to vendor in this project.` | `cargo vendor` 的对象为空 | 先在 `Cargo.toml` 写依赖，再 vendor |
| `warning: spurious network error (3 tries remaining): [35] SSL connect error` → `download of config.json failed` | registry 端点不可达（被墙/无代理） | 走本章路线 0–4；或先做 §12.1 的端点探测，别反复重试 |
| 构建成功但运行时报缺共享库 | 动态链接到本机没有的 `.so` | 用 `musl` 静态目标：`rustup target add x86_64-unknown-linux-musl` + `cargo build --target x86_64-unknown-linux-musl` |

### 12.4 明确的「不要做」

1. **不要指望 npm 上能找到 crate**：npm 上没有 crates.io 的通用镜像/对应物；能用的是 GitHub 通道（路线 3/4）。
2. **不要删掉 `Cargo.lock` 试图「重解析」**：离线环境下它恰恰是能构建的依据。
3. **不要反复重试网络**：`000` 端点是硬不可达，`--offline` + 源码方案才是出路。
4. **不要把 `--offline` 的解析失败当成代码 bug**，也不要为绕过它而删依赖、删测试。
5. **不要在多台机器上依赖「本地 home 里碰巧有的缓存」而不写进仓库**：可复现的离线交付应把 `vendor/` + `.cargo/config.toml` 或 git 依赖（带 tag/rev）提交进版本库。

---

### 附：实测过的数据（供估算）

| 项 | 实测值 |
|---|---|
| 工具链磁盘占用（1.88.0，minimal + rustfmt，Linux x86_64） | **560 MB**（`bin/` 59 MB + `lib/` 486 MB） |
| 目录搬运耗时（同一磁盘） | **0.9 秒**（560 MB，`cp -a`） |
| 空项目 `cargo build --offline` | **0.6 秒** |
| `rustc` 直接编译 hello world | < 1 秒 |
| 通过 npm 分发通道安装整套工具链（npm 缓存已热） | **14 秒** |
| 首次 rustup 联网安装 | 取决于带宽，通常 1–5 分钟 |
