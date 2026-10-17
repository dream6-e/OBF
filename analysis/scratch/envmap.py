#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Statically resolve the Kryvex runtime environment table built by bR().

bR(self, b=Ry_env, R=RP_strings, k=RB_decoder, v=256, y=vM) performs two kinds
of assignment:

    R[<numconst>] = k({ <byte exprs> }, <key>)      -- decode a string literal
    b[<hash>]     = RR[R[<numconst>]]               -- env[hash] = _ENV[that string]
    b[<hash>]     = R[<numconst>]                   -- env[hash] = that string
    b[<hash>]     = (RC and RC[R[<numconst>]])      -- env[hash] = math[R[...]] etc.

This script recovers every one of them, which pins down the *only*
environment-dependent term in kF's RZ hash chain:
    b[0x2267BA0C]  compared against type(0xB948*1)
"""
import re, sys, json
sys.path.insert(0, '/home/user/OBF/analysis/tools')
from dec import dec_bytes

src = open('/home/user/OBF/analysis/scratch/fn/bR_370151.lua', encoding='utf-8', errors='replace').read()

# ---------------------------------------------------------------- byte exprs
def evalexpr(e):
    """Evaluate the tiny arithmetic used inside the {...} byte lists:  v == 256."""
    e = e.strip()
    e = re.sub(r'\bv\b', '256', e)
    e = e.replace('0X', '0x').replace('0x', '0x')
    if not re.fullmatch(r'[0-9xXa-fA-F+\-*%/\(\)\s]+', e):
        raise ValueError('bad expr: %r' % e)
    return int(eval(e)) & 0xFF


# R[<n>] = k({ ... }, <key>)
strdef = {}
pat = re.compile(r'R\[(0X[0-9A-F]+|\d+)\]\s*=\s*k\(\{(.*?)\}\s*,\s*(0X[0-9A-F]+|\d+)\)',
                 re.I | re.S)
for m in pat.finditer(src):
    idx = int(m.group(1), 0)
    body = m.group(2)
    key = int(m.group(3), 0)
    # split top-level commas (no nesting deeper than one paren level)
    parts, depth, cur = [], 0, ''
    for ch in body:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur); cur = ''
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    arr = [evalexpr(p) for p in parts]
    try:
        s = dec_bytes(arr, key)
    except Exception as ex:
        s = '<decode failed: %s>' % ex
    strdef[idx] = (arr, key, s)

print("decoded %d string literals from bR\n" % len(strdef))

# ---------------------------------------------------------------- b[hash] = ...
envmap = {}
# capture: b[HASH] = <rhs up to next  " if " / " b[" / " R[" statement boundary>
pat2 = re.compile(r'b\[(0X[0-9A-F]+|\d+)\]\s*=\s*', re.I)
positions = [(m.group(1), m.end()) for m in pat2.finditer(src)]
for n, (h, start) in enumerate(positions):
    end = positions[n + 1][1] - len(positions[n + 1][0]) - 6 if n + 1 < len(positions) else len(src)
    # trim at the first " if " / "if not" / "if R[" boundary
    rhs = src[start:min(end, start + 260)]
    cut = re.search(r'\bif\b', rhs)
    if cut:
        rhs = rhs[:cut.start()]
    rhs = rhs.strip()
    envmap[int(h, 0)] = rhs

# ---------------------------------------------------------------- resolve
def resolve(rhs):
    """Turn a bR right-hand side into (kind, name)."""
    rhs = rhs.strip().rstrip()
    m = re.fullmatch(r'(?:\((\w+) and \1)?\[?R\[(0X[0-9A-F]+|\d+)\]\]?\)?', rhs, re.I)
    nums = [int(x, 0) for x in re.findall(r'R\[(0X[0-9A-F]+|\d+)\]', rhs, re.I)]
    names = [strdef.get(i, (None, None, '<unknown>'))[2] for i in nums]
    direct = rhs.startswith('R[') and 'RR' not in rhs and 'and' not in rhs
    src_tbl = None
    m2 = re.match(r'\((\w+)\s+and\s+\1\[R\[', rhs)
    if m2:
        src_tbl = m2.group(1)
    elif rhs.startswith('RR[R['):
        src_tbl = 'RR(_ENV)'
    elif rhs.startswith('(RP and RP())') or rhs.startswith('RR['):
        src_tbl = 'RR(_ENV)'
    return direct, src_tbl, names, rhs


rows = []
for h in sorted(envmap):
    direct, tbl, names, rhs = resolve(envmap[h])
    rows.append((h, direct, tbl, names, rhs))

print("%-12s %-8s %-14s %s" % ("env hash", "literal", "lookup-in", "resolved name(s) / rhs"))
print("-" * 110)
for h, direct, tbl, names, rhs in rows:
    tag = "STRING" if direct and not tbl else ("->" + str(tbl) if tbl else "?")
    print("0x%08X   %-8s %-14s %s" % (h, tag, '', " | ".join(repr(n) for n in names) if names else rhs[:70]))

print()
print("=" * 70)
CRIT = 0x2267BA0C
print("CRITICAL  env[0x%08X] (compared with type(0xB948*1) in kF):" % CRIT)
d, t, nm, rhs = resolve(envmap.get(CRIT, ''))
print("   rhs      =", rhs)
print("   resolves =", nm)
print("   => equals 'number' ?", (nm == ['number']))
json.dump({'%d' % h: {'rhs': envmap[h], 'names': resolve(envmap[h])[2]} for h in envmap},
          open('/home/user/OBF/analysis/scratch/envmap.json', 'w'), indent=1)
print("\nwrote envmap.json")
