#!/usr/bin/env python3
"""Proper Lua lexer-based structural analysis of the Luraph file. Purely static."""
import re, sys, collections, json

SRC = "Luraph15\U0001f480\U0001f480.lua"
raw = open(SRC, encoding="utf-8").read()
LINES = raw.split("\n")
BODY = LINES[2]
BOFF = sum(len(l) + 1 for l in LINES[:2])   # global offset of BODY[0]


class Lexer:
    """Minimal Lua lexer: yields (pos, kind, text). Skips strings/comments correctly."""
    PATS = [
        ("lcmt", re.compile(r"--\[(=*)\[")),
        ("line", re.compile(r"--[^\n]*")),
        ("ls", re.compile(r"\[(=*)\[")),
        ("dq", re.compile(r'"(?:[^"\\\n]|\\.)*"')),
        ("sq", re.compile(r"'(?:[^'\\\n]|\\.)*'")),
        ("num", re.compile(r"0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")),
        ("name", re.compile(r"[A-Za-z_]\w*")),
    ]

    def __init__(self, s):
        self.s = s

    def long_end(self, i, level):
        term = "]" + "=" * level + "]"
        j = self.s.find(term, i)
        if j < 0:
            raise ValueError("unterminated long string at %d" % i)
        return j + len(term)

    def items(self, frm=0, to=None):
        s = self.s
        to = len(s) if to is None else to
        i = frm
        while i < to:
            c = s[i]
            if c == "-" and s.startswith("--", i):
                m = self.PATS[0][1].match(s, i)
                if m:
                    j = self.long_end(m.end(), len(m.group(1)))
                    yield i, "comment", s[i:j]; i = j; continue
                m = self.PATS[1][1].match(s, i)
                yield i, "comment", s[i:m.end()]; i = m.end(); continue
            if c == "[":
                m = self.PATS[2][1].match(s, i)
                if m:
                    j = self.long_end(m.end(), len(m.group(1)))
                    yield i, "string", s[i:j]; i = j; continue
            if c in "\"'":
                m = self.PATS[3 if c == '"' else 4][1].match(s, i)
                if m:
                    yield i, "string", m.group(); i = m.end(); continue
            m = self.PATS[5][1].match(s, i)
            if m and (c.isdigit() or (c == "." and i + 1 < to and s[i+1].isdigit())):
                yield i, "num", m.group(); i = m.end(); continue
            m = self.PATS[6][1].match(s, i)
            if m:
                yield i, "name", m.group(); i = m.end(); continue
            yield i, "op", c
            i += 1


LX = Lexer(BODY)
ITEMS = list(LX.items())          # full token stream of the body
KIND = {p: (k, t) for p, k, t in ITEMS}

BLOCK_OPEN = {"function", "do", "then", "else"}
BLOCK_CLOSE = {"end"}


def match_end(frm):
    """frm = index of a 'function' token; return end index of its block."""
    depth = 0
    for p, k, t in ITEMS:
        if p < frm: continue
        if k in ("string", "comment"): continue
        if t in ("function", "do", "then", "repeat"):
            depth += 1
        elif t in ("end", "until"):
            depth -= 1
            if depth == 0:
                return p + 3
    return -1


# ---------- locate outer table constructor ----------
m0 = re.search(r'setmetatable\s*\(\s*\{', BODY)
tb = m0.end() - 1
depth = 0; cb = None
for p, k, t in ITEMS:
    if p < tb: continue
    if k in ("string", "comment"): continue
    if t in "{[(": depth += 1
    elif t in ")]}":
        depth -= 1
        if depth == 0:
            cb = p; break
assert cb is not None

# ---------- split entries at depth 0 ----------
entries = []
start = tb + 1
depth = 0
for p, k, t in ITEMS:
    if p <= tb: continue
    if p > cb: break
    if k in ("string", "comment"): continue
    if t in "{[(": depth += 1
    elif t in ")]}": depth -= 1
    elif t == "," and depth == 0:
        entries.append((start, p)); start = p + 1
entries.append((start, cb))

ENTRIES = []
for a, b in entries:
    if BODY[a:b].strip() == "": continue
    seg = BODY[a:b]
    m = re.match(r'\s*(?:([A-Za-z_]\w*)|\["([^"]*)"\]|\[\'([^\']*)\'\]|\[(\d+)\])\s*=\s*', seg)
    if not m:
        ENTRIES.append({"key": None, "raw": seg, "a": a, "b": b, "kind": "pos"})
        continue
    key = m.group(1) or m.group(2) or m.group(3) or m.group(4)
    isnum = m.group(4) is not None
    rest = seg[m.end():]
    ENTRIES.append({"key": key, "numkey": isnum, "a": a, "b": b,
                    "kind": "func" if rest.startswith("function") else "value",
                    "vstart": a + m.end(), "raw": seg})

FUNC = {e["key"]: e for e in ENTRIES if e["kind"] == "func"}
VAL = {e["key"]: e for e in ENTRIES if e["kind"] == "value"}
POS = [e for e in ENTRIES if e["kind"] == "pos"]


def extents(e):
    """absolute [start,end) of the function body text"""
    seg = BODY[e["a"]:e["b"]]
    fp = e["a"] + seg.index("function")
    return fp, match_end(fp)


def ftext(e):
    fp, en = extents(e)
    return BODY[fp:en]


if __name__ == "__main__":
    print(f"outer table: BODY[{tb}:{cb}] len={cb-tb}")
    print(f"entries={len(ENTRIES)} funcs={len(FUNC)} values={len(VAL)} positional={len(POS)}")
    print("\n--- value entries (non-function) ---")
    for k, e in VAL.items():
        v = BODY[e["vstart"]:e["b"]]
        print(f"  [{k}] = {v[:80]!r}  (len {len(v)})")
    for e in POS:
        print("  POSITIONAL:", e["raw"][:80])
    sizes = sorted(((len(ftext(e)), k) for k, e in FUNC.items()), reverse=True)
    print("\n--- 15 largest handler functions ---")
    for sz, k in sizes[:15]: print(f"   {k:5s} {sz}")
    print("--- 10 smallest ---")
    for sz, k in sizes[-10:]: print(f"   {k:5s} {sz}")
    print("\ntotal func bytes:", sum(s for s, _ in sizes))
    ar = collections.Counter(len(BODY[e["a"]:e["b"]].split("(")[1].split(")")[0].split(",")) for e in FUNC.values())
    print("arities:", dict(sorted(ar.items())))
