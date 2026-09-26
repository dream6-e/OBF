#!/usr/bin/env python3
"""Apply the pinned upstream compatibility patch, without changing git branches."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repo', type=Path, help='existing KryptIT/luraph-v15-v14.x-deobfuscator checkout')
    parser.add_argument('--check', action='store_true', help='only validate; do not change files')
    args = parser.parse_args()
    repo = args.repo.expanduser().resolve()
    manifest = json.loads((HERE / 'manifest.json').read_text())
    patch = HERE / 'upstream.patch'
    if hashlib.sha256(patch.read_bytes()).hexdigest() != manifest['patch_sha256']:
        parser.error('patch checksum mismatch')
    head = git(repo, 'rev-parse', 'HEAD')
    if head.returncode or head.stdout.strip() != manifest['upstream_commit']:
        parser.error('checkout must be at pinned upstream commit ' + manifest['upstream_commit'])
    forward = git(repo, 'apply', '--check', str(patch))
    if forward.returncode:
        reverse = git(repo, 'apply', '--reverse', '--check', str(patch))
        if reverse.returncode == 0:
            print('Compatibility patch is already applied.')
            return 0
        parser.error('patch conflicts with local changes; no files modified:\n' + forward.stderr)
    if args.check:
        print('Patch can be applied cleanly; no files modified.')
        return 0
    result = git(repo, 'apply', str(patch))
    if result.returncode:
        parser.error(result.stderr)
    print('Compatibility patch applied. Run the regression tests before relying on its output.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
