#!/usr/bin/env python3
"""Static structural parser for the Luraph-flattened Lua file (no execution).
Parses the top-level table constructor into named function entries, and builds
per-handler metadata (params, callees, numeric slots, states, constants).
"""
import re, sys, json, collections

SRC = sys.argv[1] if len(sys.argv) > 1 else "Luraph15\U0001f480\U0001f480.lua"
raw = open(SRC, encoding="utf-8").read()
LINES = raw.split("\n")
BODY = LINES[2]
OFF0 = sum(len(l) + 1 for l in LINES[:2])

KW_START = {"function", "do", "then", "else", "repeat", "for", "while", "if"}
KW_END = {"end", "until"}
TOKEN = re.compile(r"""
    (?P<comment>--\[=*\[.*?\]=*\])
  | (?P<longstr>\[=*\[.*?\]=*\])
  | (?P<dq>"(?:[^"\\]|\\.)*")
  | (?P<sq>'(?:[^'\\]|\\.)*')
  | (?P<word>[A-Za-z_]\w*)
""", re.VERBOSE | re.DOTALL)


def scan(s, frm=0, to=None):
    """yield (idx, kind, text) skipping strings/comments"""
    to = len(s) if to is None else to
    i = frm
    while i < to:
        m = TOKEN.match(s, i)
        if m:
            yield m.start(), m.lastgroup, m.group()
            i = m.end()
        else:
            yield i, "char", s[i]
            i += 1


def match_end(s, fnpos):
    """fnpos at the 'function' keyword -> index just past its matching 'end'."""
    depth = 0
    for i, kind, txt in scan(s, fnpos):
        if kind in ("comment", "longstr", "dq", "sq"):
            continue
        if txt in KW_START:
            depth += 1
        elif txt in KW_END:
            depth -= 1
            if depth == 0:
                return i + 3
    return -1


# ---- top-level table constructor ----
ob = BODY.index("{")
depth = 0; i = ob; cb = None
while i < len(BODY):
    ch = BODY[i]
    if ch in "[\"'":                      # crude string skip
        m = TOKEN.match(BODY, i)
        if m and m.lastgroup in ("longstr", "dq", "sq"):
            i = m.end(); continue
    if ch in "{[(":
        depth += 1
    elif ch in ")]}":
        depth -= 1
        if depth == 0:
            cb = i; break
    i += 1

TBL_START, TBL_END = ob + 1, cb          # BODY slice of the constructor contents

# ---- collect function entries:  NAME=function(...) ... end   /  ["x"]= / [N]=
FUNC_DEF = re.compile(r'(?:([A-Za-z_]\w*)|\["([^"]*)"\]|\[(\d+)\])=function')
funcs = {}     # key -> dict
order = []
for m in re.finditer(FUNC_DEF, BODY):
    if not (TBL_START <= m.start() < TBL_END):
        # still record but flag as nested
        pass
    key = m.group(1) or m.group(2) or int(m.group(3))
    fnpos = m.end() - len("function")
    endpos = match_end(BODY, fnpos)
    p0 = BODY.index("(", m.end()) + 1
    p1 = BODY.index(")", p0)
    params = BODY[p0:p1]
    text = BODY[m.start():endpos]
    funcs[key] = {"key": key, "params": params, "abs": m.start(), "end": endpos,
                  "body": BODY[m.end():endpos - 3], "tbl": TBL_START <= m.start() < TBL_END}
    order.append(key)

# non-function top-level entries (numeric slots, RC payload, pC map...)
ENTRY_DEF = re.compile(r'(?:([A-Za-z_]\w*)|\[(\d+)\])=')
values = {}
for m in re.finditer(ENTRY_DEF, BODY):
    if not (TBL_START <= m.start() < TBL_END):
        continue
    key = m.group(1) or int(m.group(2))
    if key in funcs:
        # skip: it's a function entry -> jump past it
        continue
    values[key] = m.end()

# recover value texts by taking up to next top-level comma
def value_text(start):
    depth = 0; i = start
    while i < len(BODY):
        ch = BODY[i]
        m = TOKEN.match(BODY, i)
        if m and m.lastgroup in ("longstr", "dq", "sq"):
            i = m.end(); continue
        if ch in "{[(": depth += 1
        elif ch in ")]}": depth -= 1
        elif ch == "," and depth == 0: break
        elif ch == "}" and depth == 0: break
        i += 1
    return BODY[start:i]


if __name__ == "__main__":
    print(f"table constructor BODY[{TBL_START}:{TBL_END}]  len={TBL_END-TBL_START}")
    topf = [k for k in order if funcs[k]["tbl"]]
    print(f"function entries at top level: {len(topf)} / total 'X=function' defs: {len(order)}")
    ar = collections.Counter(len(funcs[k]["params"].split(",")) for k in topf)
    print("arities:", dict(ar))
    # which named funcs are 'L' vs 'C' suffixed
    suff = collections.Counter(k[-1] if isinstance(k, str) else "?" for k in topf)
    print("name suffixes:", dict(suff))
    print("names:", " ".join(sorted(map(str, topf))))
