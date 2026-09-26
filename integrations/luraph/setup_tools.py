#!/usr/bin/env python3
"""Provision Linux analysis tools from the repository's Environment.zip.

Original tools/source stay intact under .tools/Environment. Only a separate
source copy receives the writable-vector-metatable analysis patch. No network,
package installer, Git operations, or deletion of previously deployed tools.
"""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
EXTRAS = Path(__file__).resolve().parent / 'toolchain'


def run(args, cwd):
    print('+', ' '.join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--jobs', type=int, default=2)
    args = ap.parse_args()
    if not sys.platform.startswith('linux'):
        ap.error('This provisioner supports Linux; bundled reference executables are Linux binaries.')
    if args.jobs < 1:
        ap.error('--jobs must be positive')
    for name in ('make', 'g++', 'ar'):
        if not shutil.which(name):
            ap.error(f'{name} is missing; install a C++ build toolchain first')
    archive = ROOT / 'Environment.zip'
    cache = ROOT / '.tools'
    cache.mkdir(exist_ok=True)
    env = cache / 'Environment'
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    stamp = cache / 'environment.sha256'
    if not stamp.exists():
        if env.exists():
            ap.error('Existing .tools/Environment has no provenance stamp; refusing to overwrite it.')
        with zipfile.ZipFile(archive) as z:
            for item in z.infolist():
                path = (cache / item.filename).resolve()
                if not path.is_relative_to(cache.resolve()):
                    ap.error('Unsafe path in Environment.zip')
            z.extractall(cache)
        stamp.write_text(digest + '\n')
    elif stamp.read_text().strip() != digest:
        ap.error('Environment.zip changed; deployed tools were preserved, not overwritten.')
    for p in (env / 'toolchains/bin').iterdir():
        if p.is_file():
            p.chmod(p.stat().st_mode | 0o111)
    source = cache / 'deobf-src/luau-0.735'
    if not source.exists():
        shutil.copytree(env / 'vendor/luau-0.735', source)
    vector = source / 'VM/src/lveclib.cpp'
    text = vector.read_text()
    old = '    lua_setreadonly(L, -1, true);\n    lua_pop(L, 1); // pop the metatable\n'
    new = '    // Analysis build: envlog installs Roblox vector members.\n    lua_pop(L, 1); // pop the metatable\n'
    if old in text:
        if text.count(old) != 1:
            ap.error('Ambiguous vector patch site')
        vector.write_text(text.replace(old, new))
    elif new not in text:
        ap.error('Vector source changed; refusing an unverified patch')
    run(['make', 'config=release', f'-j{args.jobs}', 'luau'], source)
    ast_cli = (source / 'CLI/src/Ast.cpp').read_text()
    old = 'fprintf(stderr, "  %s - %s\\n", toString(error.getLocation()).c_str(), error.getMessage().c_str());'
    new = 'fprintf(stderr, "  %u:%u - %s\\n", error.getLocation().begin.line + 1, error.getLocation().begin.column + 1, error.getMessage().c_str());'
    if ast_cli.count(old) != 1:
        ap.error('AST CLI source changed; refusing an unverified adaptation')
    ast_cli = ast_cli.replace('#include "Luau/ToString.h"', '').replace(old, new)
    cli_path = cache / 'ast-cli.cpp'
    cli_path.write_text(ast_cli)
    binary = env / 'toolchains/deobf-bin'
    binary.mkdir(exist_ok=True)
    run(['g++', '-std=c++17', '-O2', '-DNDEBUG', '-ICommon/include', '-IAst/include',
         '-ICLI/include', '-I' + str(EXTRAS), cli_path, EXTRAS / 'AstJsonEncoder.cpp',
         'CLI/src/FileUtils.cpp', 'build/release/libluauast.a', 'build/release/libluaucommon.a',
         '-o', binary / 'luau-ast'], source)
    shutil.copy2(source / 'build/release/luau', binary / 'luau')
    if shutil.which('strip'):
        run(['strip', '--strip-debug', binary / 'luau', binary / 'luau-ast'], source)
    engine_bin = ROOT / 'tools/luraph/Deobfuscator/deobf/bin'
    engine_bin.mkdir(exist_ok=True)
    for name in ('luau', 'luau-ast'):
        dest = engine_bin / name
        if dest.is_symlink():
            dest.unlink()
        elif dest.exists():
            ap.error(f'{dest} is not a symlink; refusing to replace it')
        dest.symlink_to(binary / name)
    print('Ready:', engine_bin)
    print('Original tools retained:', env / 'toolchains/bin')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
