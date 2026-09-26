#!/usr/bin/env python3
"""Verify packaged source/output hashes, compile all shipped scripts, run tests."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / 'tools/luraph'
INTEGRATION = ROOT / 'integrations/luraph'


def main():
    source = json.loads((BUNDLE / 'SOURCE_MANIFEST.json').read_text())
    for name, expected in source['files_sha256'].items():
        actual = hashlib.sha256((BUNDLE / name).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f'Packaged upstream source changed: {name}')
    patch_hash = hashlib.sha256((INTEGRATION / 'upstream.patch').read_bytes()).hexdigest()
    manifest = json.loads((INTEGRATION / 'manifest.json').read_text())
    if patch_hash != source['applied_patch_sha256'] or patch_hash != manifest['patch_sha256']:
        raise RuntimeError('Cumulative patch hash mismatch')
    for meta in (INTEGRATION / 'reports/artifacts').glob('*/metadata.json'):
        for name, expected in json.loads(meta.read_text())['artifact_sha256'].items():
            if hashlib.sha256((meta.parent / name).read_bytes()).hexdigest() != expected:
                raise RuntimeError(f'Output hash mismatch: {meta.parent / name}')
    files = [p for base in (BUNDLE, INTEGRATION) for p in base.rglob('*')
             if p.is_file() and not p.is_symlink() and not any(
                 part in ('bin', '__pycache__', 'output') or part.endswith('_work')
                 for part in p.relative_to(ROOT).parts)]
    py = [p for p in files if p.suffix == '.py']
    for p in py:
        ast.parse(p.read_text(encoding='utf-8-sig'), filename=str(p))
    lua = {p for p in files if p.suffix.lower() in ('.lua', '.luau')}
    lua.update(p for p in ROOT.iterdir() if p.suffix.lower() in ('.lua', '.luau'))
    for fixture in manifest['fixtures']:
        p = BUNDLE / fixture['path']
        if hashlib.sha256(p.read_bytes()).hexdigest() != fixture['sha256']:
            raise RuntimeError(f'Fixture changed: {p}')
        lua.add(p)
    compiler = ROOT / '.tools/Environment/toolchains/bin/luau-compile'
    if not compiler.exists():
        raise RuntimeError('Run python3 integrations/luraph/setup_tools.py first')
    for p in sorted(lua):
        subprocess.run([str(compiler), '--null', str(p)], check=True, timeout=60)
    print(f'Hashes verified; Python syntax: {len(py)}/{len(py)}; Lua/Luau syntax: {len(lua)}/{len(lua)}.', flush=True)
    env = dict(os.environ, LURAPH_REPO=str(BUNDLE), PYTHONDONTWRITEBYTECODE='1')
    return subprocess.call([sys.executable, '-B', '-m', 'unittest', 'discover',
                            '-s', str(INTEGRATION / 'tests'), '-v'], cwd=ROOT, env=env)


if __name__ == '__main__':
    raise SystemExit(main())
