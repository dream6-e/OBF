#!/usr/bin/env python3
"""Robust static analyser for the Luraph v15 file. No execution.
 - single-pass tokenizer with a block stack -> pairs every `function` with its `end`
 - keeps only depth-1 entries of the outer setmetatable table
 - builds: import table, handler catalogue, dispatch graph, opcode-candidate table
"""
import re, sys, json, collections

SRC = sys.argv[1] if len(sys.argv) > 1 else "Luraph15\U0001f480\U0001f480.lua"
BODY = open(SRC, encoding="utf-8").read().split("\n")[2]

LONG = re.compile(r"\[(=*)\[")
STRQ = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
NAME = re.compile(r"[A-Za-z_]\w*")
OPCH = "{}()[]<>=~+-*/%^#,:;.|"

OPENERS = {"function", "do", "repeat", "if"}
CLOSERS = {"end", "until"}


def toks(s):
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "-" and s.startswith("--", i):
            m = LONG.match(s, i + 2)
            if m:
                t = "]" + "=" * len(m.group(1)) + "]"
                j = s.find(t, m.end()); j = n if j < 0 else j + len(t)
                yield i, "skip", s[i:j]; i = j; continue
            j = s.find("\n", i); j = n if j < 0 else j
            yield i, "skip", s[i:j]; i = j; continue
        if c == "[":
            m = LONG.match(s, i)
            if m:
                t = "]" + "=" * len(m.group(1)) + "]"
                j = s.find(t, m.end()); j = n if j < 0 else j + len(t)
                yield i, "skip", s[i:j]; i = j; continue
        if c in "\"'":
            m = STRQ.match(s, i)
            if m:
                yield i, "skip", m.group(); i = m.end(); continue
        m = NAME.match(s, i)
        if m:
            yield m.start(), "name", m.group(); i = m.end(); continue
        yield i, "op", c; i += 1


T = list(toks(BODY))
# ---- pass: depth of the outer table + block pairing ----
m0 = re.search(r"setmetatable\s*\(\s*\{", BODY)
tb = m0.end() - 1
depth = 0
tdepth = [0] * (len(BODY) + 1)   # table-constructor nesting depth per token
stack = []                        # (kind, tokindex, pos)
FUNCEND = {}                      # pos of 'function' -> pos after matching 'end'
BLK = []
cb = None
for ti, (p, k, t) in enumerate(T):
    if p < tb:
        continue
    if k == "skip":
        continue
    if cb is None:
        if t == "{": depth += 1
        elif t == "}":
            depth -= 1
            if depth == 0: cb = p
    tdepth[p] = depth
    if t in OPENERS:
        stack.append((t, ti, p))
    elif t in CLOSERS:
        if stack:
            kind, ti0, p0 = stack.pop()
            if kind == "function":
                FUNCEND[p0] = p + 3

TBL_END = cb
# ---- entries at table depth 1 ----
entries = []
start = tb + 1
depth = 0
for p, k, t in T:
    if p <= tb or p > TBL_END or k == "skip":
        continue
    if t in "{[(": depth += 1
    elif t in ")]}": depth -= 1
    elif t in OPENERS: depth += 1
    elif t in CLOSERS: depth -= 1
    elif t == "," and depth == 0:
        if BODY[start:p].strip(): entries.append((start, p))
        start = p + 1
if BODY[start:TBL_END].strip(): entries.append((start, TBL_END))

KEYED = re.compile(r'\s*(?:([A-Za-z_]\w*)|\["((?:[^"\\]|\\.)*)"\]|\[\'((?:[^\'\\]|\\.)*)\'\]|\[(\d+)\])\s*=\s*', re.S)

IMPORT = {}      # slot -> raw source text of value
FUNCS = {}       # key -> dict
UNPARSED = []
for a, b in entries:
    seg = BODY[a:b]
    m = KEYED.match(seg)
    if not m:
        UNPARSED.append((a, seg[:60])); continue
    key = m.group(1) or m.group(2) or m.group(3) or m.group(4)
    if m.group(4) is not None: key = int(m.group(4))
    rest = seg[m.end():]
    if rest.startswith("function"):
        fpos = a + m.end()
        end = FUNCEND.get(fpos, b)
        p0 = BODY.index("(", fpos) + 1
        p1 = BODY.index(")", p0)
        FUNCS[key] = {"key": key, "start": a, "fpos": fpos, "end": end,
                      "params": BODY[p0:p1], "text": BODY[a:end]}
    else:
        IMPORT[key] = BODY[a + m.end():b].strip()

# ---- metadata ----
CALL = re.compile(r'\bb[:.]([A-Za-z_]\w*)\b')
SLOT = re.compile(r'\bb\[(\d+)\]')
DOTSLOT = re.compile(r'\bb\.([A-Za-z_]\w*)\b')
NUM = re.compile(r'(?<![\w.])\d+(?![\w.])')
SETSTATE = re.compile(r'\breturn\s+(-?\d+)\b')
CMPNUM = re.compile(r'(\w+)\s*(<=|>=|<|>|==|~=)\s*(-?\d+)')
ASSIGNSLOT = re.compile(r'\bb\[(\d+)\]\s*=[^=]')


def analyse(k, f):
    txt = f["text"]
    # blank out string literals for numeric noise removal
    return {
        "key": k, "start": f["start"], "len": f["end"] - f["start"],
        "params": f["params"],
        "nparams": len(f["params"].split(",")) if f["params"].strip() else 0,
        "calls": collections.Counter(CALL.findall(txt)),
        "slots": collections.Counter(int(x) for x in SLOT.findall(txt)),
        "dotslots": collections.Counter(DOTSLOT.findall(txt)),
        "writeslots": collections.Counter(int(x) for x in SETSTATE and ASSIGNSLOT.findall(txt)),
        "retstates": collections.Counter(int(x) for x in SETSTATE.findall(txt)),
        "comps": collections.Counter((m.group(1), m.group(2), int(m.group(3))) for m in CMPNUM.finditer(txt)),
        "nums": collections.Counter(int(x) for x in NUM.findall(txt)),
        "nif": len(re.findall(r'\bif\b', txt)),
    }


META = {k: analyse(k, f) for k, f in FUNCS.items()}

if __name__ == "__main__":
    print(f"outer table BODY[{tb}:{TBL_END}]  entries={len(entries)} funcs={len(FUNCS)} values={len(IMPORT)} unparsed={len(UNPARSED)}")
    print("\n########## IMPORT / CONSTANT TABLE (slot -> global) ##########")
    num = sorted((k, v) for k, v in IMPORT.items() if isinstance(k, int))
    nam = sorted((k, v) for k, v in IMPORT.items() if isinstance(k, str))
    print("-- numeric slots (%d) --" % len(num))
    for k, v in num: print(f"   b[{k:3d}] = {v}")
    print("-- named constants (%d) --" % len(nam))
    for k, v in nam: print(f"   b.{k} = {v}")
    for a, s in UNPARSED[:10]: print("  UNPARSED@", a, repr(s))
    print("\n########## HANDLER CATALOGUE ##########")
    print(f"{'name':6s}{'start':>8s}{'len':>7s}{'par':>4s}{'ifs':>4s}{'calls':>6s}{'callees':>8s}{'states':>7s}  slot-uses (n) / callees")
    rows = sorted(META.values(), key=lambda r: r["start"])
    for r in rows:
        sl = ",".join(f"{s}:{n}" for s, n in sorted(r["slots"].items(), key=lambda x: -x[1])[:8])
        cl = ",".join(f"{c}" for c, _ in r["calls"].most_common(8))
        print(f"{str(r['key']):6s}{r['start']:8d}{r['len']:7d}{r['nparams']:4d}{r['nif']:4d}{sum(r['calls'].values()):6d}{len(r['calls']):8d}{len(r['retstates']):7d}  [{sl}] -> {cl}")
    json.dump({"import": {str(k): v for k, v in IMPORT.items()},
               "meta": {str(k): {kk: (dict(vv) if isinstance(vv, collections.Counter) else vv)
                                 for kk, vv in m.items()} for k, m in META.items()}},
              open("tools/catalog.json", "w"), indent=1)
    with open("tools/handlers.lua.txt", "w") as fh:
        for k in FUNCS:
            fh.write(f"\n##### b[{k!r}]  @ {FUNCS[k]['start']} len {META[k]['len']} params({FUNCS[k]['params']})\n")
            fh.write(FUNCS[k]["text"] + "\n")
    print("\nwrote tools/catalog.json and tools/handlers.lua.txt")
