#!/usr/bin/env python3
"""按 Cargo.lock 的精确版本，从 GitHub 源码 tarball 组装 cargo 的 directory 离线源。

为什么需要它：部分环境（含本项目的开发沙箱）把 crates.io 全线拦在 TLS 层
（index.crates.io / static.crates.io / S3 源桶 / 各国内镜像全部 SSL_ERROR_SYSCALL），
但 npm 与 GitHub 可达。此脚本只用 GitHub，把 Cargo.lock 里钉死的每个版本
换成对应 tag 的源码，Cargo.lock 一个字节都不改。

用法：
    python3 vendor_crates.py                 # 处理 Cargo.lock 里全部第三方包
    python3 vendor_crates.py rand regex      # 只处理指定 crate

环境变量：
    VENDOR_DIR   目标目录，默认 /usr/local/obf-crates-vendor
    CARGO_LOCK   锁文件路径，默认取本仓库根的 Cargo.lock
    GH_CACHE     tarball 缓存目录，默认 /tmp/obf-gh-cache

关键实现点（换机器会再踩一遍，别删注释）：
  1. tag 命名千奇百怪：`1.1.4` / `v0.3.4` / `lock_api-v0.4.14` / `mio-v0.2.5` /
     `ppv-lite86-0.2.21`，还要忽略 `+wasi-snapshot-preview1` 这类构建元数据。
  2. monorepo 要靠 tarball 内 `name` + `version` 双匹配来定位子目录，
     不能靠猜目录名（zerocopy-derive、regex-automata、rand_chacha、ppv-lite86 都是）。
  3. `BurntSushi/regex` 是 2021 年停更的 fork（根 manifest 写着 regex 0.2.0），
     真仓库是 `rust-lang/regex`。
  4. `rand_core 0.9.5` 没有任何 tag，只在 `backports/v0.9` 的提交 a34dab266970 上。
  5. manifest 里的 `version       = "0.8.11"`（对齐空格）和
     `version = { workspace = true }` 都要能识别；继承字段必须内联，
     否则 cargo 报 `error inheriting ... from workspace root manifest`。
  6. `.cargo-checksum.json` 的 package 必须填 Cargo.lock 里的校验和，
     否则 cargo 报 `unable to verify that X is the same as when the lockfile was generated`。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

OUT = os.environ.get("VENDOR_DIR", "/usr/local/obf-crates-vendor")
LOCK = os.environ.get("CARGO_LOCK", os.path.join(ROOT, "Cargo.lock"))
CACHE = os.environ.get("GH_CACHE", "/tmp/obf-gh-cache")

# crate -> owner/repo
REPO = {
    "aho-corasick": "BurntSushi/aho-corasick",
    "bitflags": "bitflags/bitflags",
    "cfg-if": "rust-lang/cfg-if",
    "crossterm": "crossterm-rs/crossterm",
    "errno": "lambda-fairy/rust-errno",
    "getrandom": "rust-random/getrandom",
    "libc": "rust-lang/libc",
    "lock_api": "Amanieu/parking_lot",
    "log": "rust-lang/log",
    "memchr": "BurntSushi/memchr",
    "mio": "tokio-rs/mio",
    "parking_lot": "Amanieu/parking_lot",
    "parking_lot_core": "Amanieu/parking_lot",
    "ppv-lite86": "cryptocorrosion/cryptocorrosion",
    "proc-macro2": "dtolnay/proc-macro2",
    "quote": "dtolnay/quote",
    "r-efi": "r-efi/r-efi",
    "rand": "rust-random/rand",
    "rand_chacha": "rust-random/rand",
    "rand_core": "rust-random/rand_core",
    "redox_syscall": "redox-os/syscall",
    "regex": "rust-lang/regex",
    "regex-automata": "rust-lang/regex",
    "regex-syntax": "rust-lang/regex",
    "scopeguard": "bluss/scopeguard",
    "signal-hook": "vorner/signal-hook",
    "signal-hook-mio": "vorner/signal-hook",
    "signal-hook-registry": "vorner/signal-hook",
    "smallvec": "servo/rust-smallvec",
    "syn": "dtolnay/syn",
    "unicode-ident": "dtolnay/unicode-ident",
    "wasi": "bytecodealliance/wasi",
    "wasip2": "bytecodealliance/wasi",
    "wit-bindgen": "bytecodealliance/wit-bindgen",
    "zerocopy": "google/zerocopy",
    "zerocopy-derive": "google/zerocopy",
}

# 没有对应 tag 的版本，直接钉住提交
PINNED_REF = {"rand_core": "a34dab266970"}

# 这些包由 stub_crates.py 生成占位包（仅 windows 目标参与构建，GitHub 上没有对应 tag）
DELEGATED = {
    "crossterm_winapi", "winapi", "winapi-i686-pc-windows-gnu",
    "winapi-x86_64-pc-windows-gnu", "windows-link", "windows-sys",
    "windows-targets", "windows_aarch64_gnullvm", "windows_aarch64_msvc",
    "windows_i686_gnu", "windows_i686_msvc", "windows_x86_64_gnu",
    "windows_x86_64_gnullvm", "windows_x86_64_msvc",
}

SKIP = {"kryvex_ob", "kryvex_cli"} | DELEGATED


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def read_lock(path):
    """-> [(name, version, checksum)]"""
    txt = open(path, encoding="utf-8").read()
    out = []
    for block in txt.split("[[package]]")[1:]:
        n = re.search(r'^name = "(.+?)"', block, re.M)
        v = re.search(r'^version = "(.+?)"', block, re.M)
        c = re.search(r'^checksum = "([0-9a-f]{64})"', block, re.M)
        if n and v:
            out.append((n.group(1), v.group(1), c.group(1) if c else None))
    return out


_tag_cache = {}


def get_tags(repo):
    if repo not in _tag_cache:
        r = sh(f'GIT_TERMINAL_PROMPT=0 git ls-remote --tags https://github.com/{repo} 2>/dev/null')
        _tag_cache[repo] = [
            line.split("\t")[-1].strip()[len("refs/tags/"):]
            for line in r.stdout.splitlines()
            if line.split("\t")[-1].strip().startswith("refs/tags/")
            and not line.split("\t")[-1].strip().endswith("^{}")
        ]
    return _tag_cache[repo]


def candidate_refs(repo, crate, ver):
    esc = re.escape(ver.split("+")[0])          # 忽略 +wasi-snapshot-preview1 这类元数据
    if crate in PINNED_REF:
        return [(PINNED_REF[crate], "pinned-commit")]
    short = crate.split("-")[-1]                 # signal-hook 仓库用 mio-vX / registry-vX 短前缀
    pats = [rf"^{crate}-v?{esc}$", rf"^{crate}/v?{esc}$", rf"^v?{esc}$",
            rf"^{crate.replace('-', '_')}-v?{esc}$", rf"^{short}-v?{esc}$"]
    got, refs, seen = get_tags(repo), [], set()
    for p in pats:
        for t in got:
            if re.match(p, t) and t not in seen:
                seen.add(t)
                refs.append(("refs/tags/" + t, t))
    refs += [(f"refs/heads/{b}", b) for b in ("main", "master")]
    return refs


def download(repo, ref):
    key = f"{repo.replace('/', '_')}__{ref.replace('/', '_')}"
    path = os.path.join(CACHE, key + ".tgz")
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    os.makedirs(CACHE, exist_ok=True)
    tmp = path + ".part"
    r = sh(f'curl -sSLf -o {tmp} "https://codeload.github.com/{repo}/tar.gz/{ref}"')
    if r.returncode != 0 or not os.path.exists(tmp) or os.path.getsize(tmp) < 512:
        if os.path.exists(tmp):
            os.remove(tmp)
        return None
    os.rename(tmp, path)
    return path


def root_workspace(tgz):
    """tar 包根的 [workspace]（拿 package / dependencies 继承表）"""
    with tarfile.open(tgz, "r:gz") as tf:
        for m in tf.getmembers():
            if m.name.endswith("Cargo.toml") and m.name.count("/") == 1:
                try:
                    return tomllib.loads(tf.extractfile(m).read().decode("utf-8", "replace")).get("workspace", {})
                except Exception:
                    return {}
    return {}


def find_crate_dir(tgz, crate, ver):
    """在 tarball 里找 name==crate 且 version==ver 的 crate 目录（monorepo 靠这个定位）"""
    ws_ver = root_workspace(tgz).get("package", {}).get("version")
    with tarfile.open(tgz, "r:gz") as tf:
        hits = []
        for m in tf.getmembers():
            if not m.name.endswith("Cargo.toml") or m.name.count("/") < 1:
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            head = f.read(4096).decode("utf-8", "replace")
            nm = re.search(r'^name\s*=\s*"([^"]+)"', head, re.M)
            vv = re.search(r'^version\s*=\s*"([^"]+)"', head, re.M)
            if not vv and re.search(r'^version(\.workspace = true|\s*=\s*\{\s*workspace\s*=\s*true)', head, re.M):
                vv = re.match(r"(.*)", str(ws_ver or ""))
            if nm and vv and nm.group(1) == crate:
                hits.append((os.path.dirname(m.name), vv.group(1)))
    for d, v in hits:
        if v == ver:
            return d, True
    return (hits[0][0] if hits else None), False


def to_toml(v):
    """把 python 值写成合法 TOML（内联表用 = 分隔，键名不加引号）"""
    if isinstance(v, dict):
        return "{ " + ", ".join("%s = %s" % (k, to_toml(x)) for k, x in v.items()) + " }"
    if isinstance(v, list):
        return "[" + ", ".join(to_toml(x) for x in v) + "]"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(v)


def inline_ws(dest, tgz):
    """把 Cargo.toml 里所有 xxx.workspace = true 换成仓库根 workspace 表里的真实值。

    依赖表里的走 [workspace.dependencies]，其余走 [workspace.package]；
    [lints] / [profile.*] 整表继承直接丢掉，不影响构建产物。
    """
    path = os.path.join(dest, "Cargo.toml")
    txt = open(path).read()
    if "workspace = true" not in txt:
        return
    wsdata = root_workspace(tgz)
    wpkg, wdeps = wsdata.get("package", {}), wsdata.get("dependencies", {})

    out, table, skip = [], "", False
    for line in txt.splitlines():
        hm = re.match(r"^\[([^\]]+)\]\s*$", line)
        if hm:
            table, skip = hm.group(1).strip(), False
            out.append(line)
            continue
        if re.match(r"^workspace = true\s*$", line) and table.split(".")[0] in ("lints", "profile"):
            out.pop()                     # 连表头一起丢
            table, skip = "", True
            continue
        if skip:
            continue
        m1 = re.match(r"^([\w-]+)\.workspace = true\s*$", line)
        m2 = re.match(r"^([\w-]+)\s*=\s*(\{[^}]*workspace\s*=\s*true[^}]*\})\s*$", line)
        if not (m1 or m2):
            out.append(line)
            continue
        key = (m1 or m2).group(1)
        extra = {}
        if m2:
            try:
                extra = tomllib.loads("x = " + m2.group(2))["x"]
            except Exception:
                extra = {}
            extra.pop("workspace", None)
        src = wdeps if table.endswith("dependencies") else wpkg
        if key not in src:
            out.append(line)
            continue
        val = src[key]
        if isinstance(val, dict):
            val = {**val, **extra}
        elif extra:
            val = {"version": val, **extra}
        out.append("%s = %s" % (key, to_toml(val)))
    open(path, "w").write("\n".join(out) + "\n")


def vendor_one(crate, ver, checksum):
    dest = os.path.join(OUT, f"{crate}-{ver}")
    if os.path.isfile(os.path.join(dest, "Cargo.toml")):
        print(f"  = {crate}-{ver} 已存在")
        return True
    repo = REPO.get(crate)
    if not repo:
        print(f"  ! {crate}-{ver} 没有仓库映射")
        return False
    for ref, label in candidate_refs(repo, crate, ver):
        tgz = download(repo, ref)
        if not tgz:
            continue
        sub, exact = find_crate_dir(tgz, crate, ver)
        if sub is None or not exact:
            continue
        with tempfile.TemporaryDirectory() as td:
            with tarfile.open(tgz, "r:gz") as tf:
                tf.extractall(td)
            # sub 已含 tar 顶层目录名，直接接在解包根后面
            src = os.path.join(td, sub) if sub else os.path.join(td, os.listdir(td)[0])
            if not os.path.isfile(os.path.join(src, "Cargo.toml")):
                continue
            os.makedirs(dest, exist_ok=True)
            for item in os.listdir(src):
                s, d = os.path.join(src, item), os.path.join(dest, item)
                shutil.copytree(s, d, symlinks=True) if os.path.isdir(s) else shutil.copy2(s, d)
        shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)
        inline_ws(dest, tgz)
        with open(os.path.join(dest, ".cargo-checksum.json"), "w") as f:
            json.dump({"files": {}, "package": checksum}, f)
        print(f"  + {crate}-{ver}  <-  {repo}@{label}" + (f"/{sub}" if sub else ""))
        return True
    print(f"  ! {crate}-{ver} 在 {repo} 里找不到精确版本")
    return False


def main():
    os.makedirs(OUT, exist_ok=True)
    pkgs = [(n, v, c) for n, v, c in read_lock(LOCK) if n not in SKIP]
    only = sys.argv[1:]
    if only:
        pkgs = [p for p in pkgs if p[0] in only]
    bad = [f"{n} {v}" for n, v, c in pkgs if not vendor_one(n, v, c)]
    print(f"\n目录源 {OUT} 现有 {len(os.listdir(OUT))} 个 crate")
    if bad:
        print("缺失: " + ", ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
