#!/usr/bin/env python3
"""
Luraph v15 chunk container - codec recovered purely statically from
"OBF/Luraph15💀💀.lua"  (the sample itself was never executed).

Recovered chain, byte-for-byte identical to what the VM does:

  HL state 3:
     u = string.gsub(string.sub(b.RC, 5), b.XC, b.pC)     -- [ -'}~] -> 5-char escapes
     z = buffer.fromstring(u)
     reader = {nil, -5, 5, #u-1, ...}    -> window = chars 5 .. #u-1  (1-based)
  qL state 0 (per 5-char group):
     value = w + (c1-40)*614125 + (c2-40)*7225 + (c3-40)*85 + (c4-40)
     eL state 5 supplies  w = (c0-40)*52200625            -- 52200625=85^4, 614125=85^3, 7225=85^2
  eL state 4:
     buffer.writeu32(dst, w, value); w += 4     (so 5 chars -> 4 bytes, LE on x86/ARM)

=> a radix-85 ASCII-armour with alphabet  chr(40+i), i=0..84  ('(' .. '|'),
   10 out-of-alphabet chars used as single-char shortcuts for 10 fixed groups.
"""
import re, sys, collections

ALPHA_LO = 40
RADIX = 85
P85 = [RADIX ** k for k in range(5)]           # [1,85,7225,614125,52200625]


def load_payload(path):
    src = open(path, encoding="utf-8").read().split("\n")[2]
    k = src.find("RC=[=[")
    raw = src[k + 6: src.find("]=]", k + 6)]
    assert raw[:4] == "LPH:", raw[:4]
    j = src.find("pC={")
    seg = src[j + 3: src.index("},", j) + 1]
    esc = {re.sub(r'\\(.)', r'\1', m.group(1)): m.group(2)
           for m in re.finditer(r'\["((?:[^"\\]|\\.)*)"\]="([^"]*)"', seg)}
    return raw[4:], esc


def unescape(pay, esc):
    """string.gsub(s, '[ -\\'~}]', pC)"""
    return "".join(esc.get(c, c) for c in pay)


def groups(u, size=5):
    """reader window: 1-based [5 .. #u-1]  ==  0-based u[4:len(u)-1]"""
    win = u[4:len(u) - 1]
    win = win[:len(win) - len(win) % size]
    return [win[i:i + size] for i in range(0, len(win), size)]


def group_value(g):
    """radix-85, digit = ord(c)-40, MSB first"""
    v = 0
    for c in g:
        v = v * RADIX + (ord(c) - ALPHA_LO)
    return v


def decode(path):
    pay, esc = load_payload(path)
    u = unescape(pay, esc)
    gs = groups(u)
    vals = [group_value(g) for g in gs]
    stream = b"".join((v & 0xFFFFFFFF).to_bytes(4, "little") for v in vals)
    return dict(pay=pay, esc=esc, u=u, gs=gs, vals=vals, stream=stream)


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else "Luraph15💀💀.lua"
    d = decode(p)
    print(f"payload chars      : {len(d['pay'])}")
    print(f"escape shortcuts   : {len(d['esc'])} entries, {sum(d['pay'].count(c) for c in d['esc'])} uses")
    print(f"after unescape     : {len(d['u'])}")
    print(f"decode window      : {len(d['u'][4:len(d['u'])-1])} chars -> {len(d['gs'])} groups of 5")
    print(f"decoded words      : {len(d['vals'])} x 32-bit  ({len(d['stream'])} bytes)")
    over = sum(1 for v in d["vals"] if v >= 1 << 32)
    print(f"groups > 2^32 (radix slack, 85^5={85**5}): {over}")
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/chunk.bin"
    open(out, "wb").write(d["stream"])
    print(f"wrote {out}")
    print("\nNOTE: the word stream is whitened (uniform entropy, no zero runs); each VM operand")
    print("lane is additionally de-keyed at runtime with per-site XOR keys (^7/^12/^101/^111/^113 ...)")
    print("and one affine lane  R = (1291219581*d + 1087330548) mod 2^32.  See REPORT.md §5.")
