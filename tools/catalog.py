#!/usr/bin/env python3
"""Full static catalogue of the Luraph VM handlers.
Usage: python3 tools/catalog.py [--json out.json]
"""
import re, sys, json, collections

SRC = "Luraph15\U0001f480\U0001f480.lua"
raw = open(SRC, encoding="utf-8").read()
BODY = raw.split("\n")[2]

LONG = re.compile(r"\[(=*)\[")
STRQ = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
NAME = re.compile(r"[A-Za-z_]\w*")
NUM = re.compile(r"\d+")


def items(s, frm=0, to=None):
    """token-ish scan: skips comments & strings correctly"""
    to = len(s) if to is None else to
    i = frm
    while i < to:
        if s.startswith("--", i):
            m = LONG.match(s, i + 2)
            if m:
                t = "]" + "=" * len(m.group(1)) + "]"
                j = s.find(t, m.end()) + len(t)
                yield i, "skip", s[i:j]; i = j; continue
            j = s.find("\n", i); j = len(s) if j < 0 else j
            yield i, "skip", s[i:j]; i = j; continue
        if s[i] == "[":
            m = LONG.match(s, i)
            if m:
                t = "]" + "=" * len(m.group(1)) + "]"
                j = s.find(t, m.end()) + len(t)
                yield i, "skip", s[i:j]; i = j; continue
        if s[i] in "\"'":
            m = STRQ.match(s, i)
            if m:
                yield i, "skip", m.group(); i = m.end(); continue
        m = NAME.match(s, i)
        if m:
            yield m.start(), "name", m.group(); i = m.end(); continue
        yield i, "op", s[i]; i += 1


# ---------- outer table ----------
m0 = re.search(r"setmetatable\s*\(\s*\{", BODY)
tb = m0.end() - 1
depth = 0; cb = None
for p, k, t in items(BODY, tb):
    if k == "skip": continue
    if t == "{": depth += 1
    elif t == "}":
        depth -= 1
        if depth == 0: cb = p; break

# entries at depth 0, counting function/end blocks as depth too
entries = []; start = tb + 1; depth = 0
toks = [x for x in items(BODY, tb + 1, cb)]
for idx, (p, k, t) in enumerate(toks):
    if k == "skip": continue
    if t == "{": depth += 1
    elif t == "}": depth -= 1
    elif t == "(": depth += 1
    elif t == ")": depth -= 1
    elif t == "[": depth += 1
    elif t == "]": depth -= 1
    elif t in ("function", "do", "repeat", "if"): depth += 1
    elif t in ("end", "until"): depth -= 1
    elif t == "," and depth == 0:
        entries.append((start, p)); start = p + 1
entries.append((start, cb))

KEYED = re.compile(r'\s*(?:([A-Za-z_]\w*)|\["([^"]*)"\]|\[\'([^\']*)\'\]|\[(\d+)\])\s*=\s*')
E = []
for a, b in entries:
    seg = BODY[a:b]
    m = KEYED.match(seg)
    if not m:
        E.append({"key": None, "a": a, "b": b, "kind": "positional"})
        continue
    key = m.group(1) or m.group(2) or m.group(3) or m.group(4)
    numkey = m.group(4) is not None
    rest = seg[m.end():]
    E.append({"key": key, "numkey": numkey, "a": a, "b": b,
              "kind": "func" if rest.startswith("function") else "value",
              "vstart": a + m.end()})

bykey = collections.defaultdict(list)
for e in E:
    bykey[e["key"]].append(e)
dups = {k: v for k, v in bykey.items() if len(v) > 1}

funcs = [e for e in E if e["kind"] == "func"]
vals = [e for e in E if e["kind"] == "value"]

# ---------- per-function metadata ----------
CALL = re.compile(r'\b([A-Za-z_]\w*)[:.]([A-Za-z_]\w*)\b')
IDX = re.compile(r'\b([A-Za-z_]\w*)\[(\d+)\]')
RET = re.compile(r'\breturn\s+(-?\d+)')
CMP = re.compile(r'\b(\w+)\s*(<=|>=|<|>|==|~=)\s*(-?\d+)\b')
LOCALN = re.compile(r'\blocal\s+')
STRIT = re.compile(r"\[\[.*?\]\]|\[=.*?=]|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'", re.S)

CAT = {}
for e in funcs:
    a, b = e["a"], e["b"]
    txt = BODY[a:b]
    seg = STRIT.sub('""', txt)
    calls = [m.group(2) for m in CALL.finditer(seg) if m.group(1) in ("b", "self")]
    idxs = collections.Counter(int(m.group(2)) for m in IDX.finditer(seg))
    states = collections.Counter(int(m.group(1)) for m in RET.finditer(seg))
    cat = {
        "key": e["key"], "start": a, "len": b - a,
        "nparams": len(txt.split("(", 1)[1].split(")", 1)[0].split(",")),
        "nlocal": len(LOCALN.findall(seg)),
        "calls": calls,
        "ncalls": len(calls),
        "slots": dict(idxs),
        "states": dict(states),
        "nstates": len(states),
        "nbranches": len(re.findall(r'\bif\b', seg)),
        "strings": STRIT.findall(txt),
        "text": txt,
    }
    CAT[e["key"]] = cat

IMPORT = {e["key"]: BODY[e["vstart"]:e["b"]] for e in vals}

if __name__ == "__main__":
    print(f"outer table BODY[{tb}:{cb}] entries={len(E)} funcs={len(funcs)} values={len(vals)} pos={sum(1 for x in E if x['kind']=='positional')}")
    if dups: print("DUPLICATE KEYS:", {k: len(v) for k, v in dups.items()})
    print("\n===== IMPORT / CONSTANT SLOTS (top-level, non-function entries) =====")
    for k, v in sorted(IMPORT.items(), key=lambda kv: (isinstance(kv[0], str), kv[0])):
        print(f"  b[{k!r}] = {v.strip()}")
    print("\n===== HANDLER CATALOGUE =====")
    hdr = f"{'name':6s} {'off':>7s} {'len':>6s} {'ar':>3s} {'loc':>4s} {'call':>4s} {'st':>4s} {'if':>4s}  slots"
    print(hdr)
    for k, c in sorted(CAT.items(), key=lambda kv: kv[1]["start"]):
        sl = ",".join(str(s) for s in sorted(c["slots"], key=lambda x: -c["slots"][x])[:6])
        print(f"{str(k):6s} {c['start']:7d} {c['len']:6d} {c['nparams']:3d} {c['nlocal']:4d} {c['ncalls']:4d} {c['nstates']:4d} {c['nbranches']:4d}  {sl}")
    tot = collections.Counter()
    for c in CAT.values():
        for s in c["slots"]: tot[s] += 1
    print("\nslots referenced across handlers:", dict(sorted(tot.items(), key=lambda kv: -kv[1])[:20]))
    allnames = set(CAT)
    ext = collections.Counter()
    for c in CAT.values():
        for t in c["calls"]:
            if t not in allnames: ext[t] += 1
    print("called-but-not-a-handler:", dict(ext.most_common(20)))
    json.dump({"import": {str(k): v for k, v in IMPORT.items()},
               "cat": {str(k): {kk: vv for kk, vv in c.items() if kk != "text"} for k, c in CAT.items()}},
              open("tools/catalog.json", "w"), indent=1)
    with open("tools/handlers.txt", "w") as f:
        for k, c in CAT.items():
            f.write(f"##### {k} @ {c['start']} len {c['len']}\n{c['text']}\n\n")
    print("\nwrote tools/catalog.json , tools/handlers.txt")
