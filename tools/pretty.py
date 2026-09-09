#!/usr/bin/env python3
"""Re-indent one handler body: insert newlines at statement boundaries, indent by block depth.
Pure text transform (no character is added/removed other than whitespace/newlines).
usage: pretty.py <key> [maxlines]
"""
import re, sys, json

M = json.load(open("tools/handlers.json"))
key = sys.argv[1]
txt = M[key]["src"]

STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
LONG = re.compile(r"\[(=*)\[")
NAME = re.compile(r"[A-Za-z_]\w*")

TOK = []; i = 0; L = len(txt)
while i < L:
    c = txt[i]
    if c == "-" and txt.startswith("--", i):
        m = LONG.match(txt, i + 2)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"
            j = txt.find(t, m.end()); j = L if j < 0 else j + len(t)
            TOK.append([i, "s", txt[i:j]]); i = j; continue
        j = txt.find("\n", i); j = L if j < 0 else j
        TOK.append([i, "s", txt[i:j]]); i = j; continue
    if c == "[":
        m = LONG.match(txt, i)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"
            j = txt.find(t, m.end()); j = L if j < 0 else j + len(t)
            TOK.append([i, "s", txt[i:j]]); i = j; continue
    if c in "\"'":
        m = STR.match(txt, i)
        if m: TOK.append([i, "s", m.group()]); i = m.end(); continue
    m = NAME.match(txt, i)
    if m: TOK.append([m.start(), "n", m.group()]); i = m.end(); continue
    TOK.append([i, "o", c]); i += 1

# expression-if?  previous significant token
EXPIF = set(); prev = None
for e in TOK:
    k, t = e[1], e[2]
    if k == "s": prev = None; continue
    if k == "n" and t == "if" and prev in {"=", "(", ",", "{", "[", "and", "or", "then", "else", "elseif", "+", "-", "*", "/", "%", "^", "#", "not", "return", "==", "~=", "<", ">"}:
        EXPIF.add(e[0])
    prev = t

# depth per token index
depth = {}
st = []
bd = 0
for e in TOK:
    p, k, t = e
    if k == "s": depth[p] = len(st) + bd; continue
    if k == "o":
        if t in "([{": bd += 1
        elif t in ")]}": bd -= 1
        depth[p] = len(st) + max(0, bd)
        continue
    if t == "if":
        if p not in EXPIF: st.append(p)
        depth[p] = len(st) + max(0, bd)
        continue
    if t in ("do", "repeat", "function"):
        st.append(p); depth[p] = len(st) + max(0, bd); continue
    if t in ("end", "until"):
        if st: st.pop()
        depth[p] = len(st) + max(0, bd); continue
    depth[p] = len(st) + max(0, bd)

# cut points: after ';' after 'then' after 'do' before/after 'end' around else/elseif
cuts = set([0, L])
for e in TOK:
    p, k, t = e
    if k != "o" and k != "n": continue
    if k == "o" and t == ";": cuts.add(p + 1)
    if k == "n":
        if t == "then": cuts.add(p + 4)
        elif t == "do": cuts.add(p + 2)
        elif t in ("end", "else", "elseif", "until", "return"): cuts.add(p)
        if t in ("else", "elseif", "end", "until"):
            pass
# also cut after each 'end'
for e in TOK:
    if e[1] == "n" and e[2] == "end": cuts.add(e[0] + 3)
cuts = sorted(c for c in cuts if 0 <= c <= L)

lines = []
for a, b in zip(cuts, cuts[1:]):
    if b <= a: continue
    seg = txt[a:b]
    if not seg.strip(): continue
    d = depth.get(min(depth, key=lambda q: abs(q - a)), 0)
    lines.append((a, d, seg.strip()))

outl = []
for a, d, s in lines:
    s = re.sub(r"\s+", " ", s)
    dd = d
    if s.startswith(("end", "else", "elseif", "until")): dd = max(0, d - 1)
    outl.append("  " * dd + s + ("  /*@%d*/" % a if "--ann" in sys.argv else ""))
res = "\n".join(outl)
mx = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
print("\n".join(res.split("\n")[:mx]))
