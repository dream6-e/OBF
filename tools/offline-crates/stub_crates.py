#!/usr/bin/env python3
"""为「仅 windows 目标参与构建、GitHub 上又没有对应 tag」的 crate 生成解析用占位包。

cargo 的解析图包含所有平台，所以哪怕在 linux 上构建，`crossterm_winapi`、
`winapi`、`windows-sys` 这些包的 manifest 也必须在源里能找到，否则
`cargo metadata` 直接失败：

    error: no matching package named `crossterm_winapi` found
    required by package `crossterm v0.27.0`

它们在 x86_64-unknown-linux-gnu 上永远不会被编译，所以：
  * manifest 的 name/version/依赖 全部照 Cargo.lock 抄，保证解析图不变；
  * 被依赖方（crossterm 等）真实 manifest 里 `features = [...]` 请求过的 feature
    要补成空 feature，否则报
    `package crossterm depends on winapi with feature winerror but winapi does not have that feature`；
  * lib.rs 里放 compile_error!，一旦被误编译立刻失败，不会静默产出错误结果。

用法： python3 stub_crates.py
环境变量： VENDOR_DIR / CARGO_LOCK / PROJECT_ROOT（默认本仓库根）
"""
import collections
import json
import os
import re
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("PROJECT_ROOT", os.path.dirname(os.path.dirname(HERE)))
LOCK = os.environ.get("CARGO_LOCK", os.path.join(ROOT, "Cargo.lock"))
OUT = os.environ.get("VENDOR_DIR", "/usr/local/obf-crates-vendor")

STUB = {
    "crossterm_winapi", "winapi", "winapi-i686-pc-windows-gnu",
    "winapi-x86_64-pc-windows-gnu", "windows-link", "windows-sys",
    "windows-targets", "windows_aarch64_gnullvm", "windows_aarch64_msvc",
    "windows_i686_gnu", "windows_i686_msvc", "windows_x86_64_gnu",
    "windows_x86_64_gnullvm", "windows_x86_64_msvc",
}


def read_lock(path):
    txt = open(path, encoding="utf-8").read()
    pkgs = []
    for block in txt.split("[[package]]")[1:]:
        n = re.search(r'^name = "(.+?)"', block, re.M)
        v = re.search(r'^version = "(.+?)"', block, re.M)
        c = re.search(r'^checksum = "([0-9a-f]{64})"', block, re.M)
        d = re.search(r"dependencies = \[(.*?)\]", block, re.S)
        pkgs.append((n.group(1), v.group(1), c.group(1) if c else None,
                     re.findall(r'"([^"]+)"', d.group(1)) if d else []))
    return pkgs


def collect_manifests():
    """占位包要补哪些 feature，得看真实依赖方（crossterm / mio / getrandom…）怎么写的"""
    files = []
    for d in os.listdir(OUT):
        f = os.path.join(OUT, d, "Cargo.toml")
        if os.path.isfile(f):
            files.append(f)
    for base, dirs, fs in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in ("target", "vendor", ".git")]
        files += [os.path.join(base, f) for f in fs if f == "Cargo.toml"]
    return files


def requested_features(stub_names):
    feat = collections.defaultdict(set)
    for path in collect_manifests():
        try:
            data = tomllib.load(open(path, "rb"))
        except Exception:
            continue

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in ("dependencies", "build-dependencies", "dev-dependencies", "target"):
                        walk(v)
                    elif isinstance(v, dict) and k in stub_names:
                        feat[k].update(v.get("features", []))
                    walk(v)
            elif isinstance(node, list):
                for x in node:
                    walk(x)

        walk(data)
        txt = open(path, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r'"(' + "|".join(map(re.escape, stub_names)) + r')/([\w-]+)"', txt):
            feat[m.group(1)].add(m.group(2))       # 特征转发写法：winapi/winerror
    return feat


def main():
    pkgs = read_lock(LOCK)
    resolved = collections.defaultdict(list)
    for n, v, _, _ in pkgs:
        resolved[n].append(v)
    feat = requested_features(sorted(STUB))

    made = 0
    for name, ver, checksum, deps in pkgs:
        if name not in STUB:
            continue
        dest = os.path.join(OUT, f"{name}-{ver}")
        os.makedirs(os.path.join(dest, "src"), exist_ok=True)

        lines = ["[package]", f'name = "{name}"', f'version = "{ver}"', 'edition = "2018"',
                 'description = "resolution-only placeholder (windows-only dependency, never built here)"', ""]
        parsed = []
        for d in deps:
            parts = d.split()
            dn = parts[0]
            dv = parts[1] if len(parts) > 1 else (resolved[dn][0] if len(resolved.get(dn, [])) == 1 else None)
            if dv is None:
                print(f"  ! 无法确定 {name} 的依赖 {d} 的版本")
                return 1
            parsed.append(f'{dn} = "={dv}"')
        if parsed:
            lines += ["[dependencies]"] + parsed + [""]
        if feat.get(name):
            lines += ["[features]"] + [f"{x} = []" for x in sorted(feat[name])] + [""]

        open(os.path.join(dest, "Cargo.toml"), "w").write("\n".join(lines))
        open(os.path.join(dest, "src", "lib.rs"), "w").write(
            f'compile_error!("{name} {ver} 是 windows 专用依赖，不应在 linux 目标上被编译");\n')
        json.dump({"files": {}, "package": checksum},
                  open(os.path.join(dest, ".cargo-checksum.json"), "w"))
        print(f"  ~ {name}-{ver}  (占位: {len(parsed)} 依赖, {len(feat.get(name, ()))} feature)")
        made += 1
    print(f"\n生成 {made} 个占位包")
    return 0


if __name__ == "__main__":
    sys.exit(main())
