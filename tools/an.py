#!/usr/bin/env python3
"""
Luraph v15 static analyser.  Parse-only: the sample is never executed.

Emits:
  tools/imports.json   b[N]/b.name -> global symbol / constant
  tools/handlers.json  per-handler: params, slot refs, callee graph, state numbers, constants
  tools/model.json     whole-model dump (dispatch graph, opcode candidates)
"""
import re, sys, json, collections

SRC = sys.argv[1] if len(sys.argv) > 1 else "Luraph15\U0001f480\U0001f480.lua"
src = open(SRC, encoding="utf-8").read()
parts = src.split("\n")
BODY = parts[2]
B0 = sum(len(p) + 1 for p in parts[:2])

RE_LONG = re.compile(r"\[(=*)\[")
RE_STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
RE_NAME = re.compile(r"[A-Za-z_]\w*")
RE_NUM = re.compile(r"(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?")
EXPR_IF_PREV = {"=", "(", ",", "{", "[", "and", "or", "return", "then", "else", "elseif",
                "+", "-", "*", "/", "%", "^", "#"}


def toks(s, frm=0, to=None):
    to = len(s) if to is None else to
    i = frm
    while i < to:
        c = s[i]
        if c == "-" and s.startswith("--", i):
            m = RE_LONG.match(s, i + 2)
            if m:
                t = "]" + "=" * len(m.group(1)) + "]"
                j = s.find(t, m.end()); j = to if j < 0 else j + len(t)
                yield i, "str", s[i:j]; i = j; continue
            j = s.find("\n", i); j = to if j < 0 else j
            yield i, "str", s[i:j]; i = j; continue
        if c == "[":
            m = RE_LONG.match(s, i)
            if m:
                t = "]" + "=" * len(m.group(1)) + "]"
                j = s.find(t, m.end()); j = to if j < 0 else j + len(t)
                yield i, "str", s[i:j]; i = j; continue
        if c in "\"'":
            m = RE_STR.match(s, i)
            if m: yield i, "str", m.group(); i = m.end(); continue
        m = RE_NUM.match(s, i)
        if m and c.isdigit():
            yield m.start(), "num", m.group(); i = m.end(); continue
        m = RE_NAME.match(s, i)
        if m: yield m.start(), "name", m.group(); i = m.end(); continue
        yield i, "op", c; i += 1


T = list(toks(BODY))
EXPR_IF = set()
_ps = None
for p, k, t in T:
    if k == "str": _ps = None; continue
    if k == "name" and t == "if" and _ps in EXPR_IF_PREV: EXPR_IF.add(p)
    if k == "name" or k == "num" or k == "op": _ps = t

# ---- block pairing (if-expressions do not open a block) ----
stack, blocks = [], []
prev_sig = None
for p, k, t in T:
    if k == "str": prev_sig = None; continue
    if k == "op":
        if t not in " \t\n": prev_sig = t
        continue
    if t == "if":
        if p not in EXPR_IF: stack.append(("if", p))
    elif t in ("do", "function", "repeat"):
        stack.append((t, p))
    elif t in ("end", "until"):
        if stack:
            kind, o = stack.pop(); blocks.append((o, p + 3, kind))
    prev_sig = t
FSTART = {o: c for o, c, kind in blocks if kind == "function"}
print(f"[+] {len(blocks)} blocks paired, {len(stack)} unclosed, {len(FSTART)} function bodies, {len(EXPR_IF)} if-expressions")

# ---- outer table ----
m0 = re.search(r"setmetatable\s*\(\s*\{", BODY)
tb = m0.end() - 1
depth = 0; cb = None
for p, k, t in T:
    if p < tb: continue
    if k == "str": continue
    if t == "{": depth += 1
    elif t == "}":
        depth -= 1
        if depth == 0: cb = p; break

fstarts = sorted(FSTART)
import bisect
def fn_end(p):
    """if p is the start of a function body, return its end"""
    return FSTART.get(p)

entries = []
start = tb + 1
d = 0
i = 0
while i < len(T):
    p, k, t = T[i]
    if p <= tb: i += 1; continue
    if p > cb: break
    if k == "str": i += 1; continue
    if t in "{[(":
        d += 1; i += 1; continue
    if t in ")]}":
        d -= 1; i += 1; continue
    if k == "name" and t == "function" and d == 0:
        # a table field value begins here: skip to its end
        e = FSTART.get(p)
        if e:
            i = bisect.bisect_left([x[0] for x in T], e)
            continue
    if t == "," and d == 0:
        if BODY[start:p].strip(): entries.append((start, p))
        start = p + 1
    i += 1
if BODY[start:cb].strip(): entries.append((start, cb))
print(f"[+] outer table BODY[{tb}:{cb}] -> {len(entries)} top-level fields")

KEYRE = re.compile(r'\s*(?:([A-Za-z_]\w*)|\["((?:[^"\\]|\\.)*)"\]|\[\'((?:[^\'\\]|\\.)*)\'\]|\[(\d+)\])\s*=\s*', re.S)
FUNCS, VALS, POS = {}, {}, []
for a, b in entries:
    seg = BODY[a:b]
    m = KEYRE.match(seg)
    if not m: POS.append((a, seg[:60])); continue
    key = m.group(1) or m.group(2) or m.group(3) or (int(m.group(4)) if m.group(4) else None)
    if m.end() < len(seg) and seg[m.end():].startswith("function"):
        fpos = a + m.end()
        end = FSTART.get(fpos, b)
        p0 = BODY.index("(", fpos) + 1
        p1 = BODY.index(")", p0)
        FUNCS[key] = {"key": key, "start": a, "fstart": fpos, "end": end,
                      "params": BODY[p0:p1], "text": BODY[a:end]}
    else:
        VALS[key] = {"key": key, "start": a, "src": BODY[a + m.end():b].strip()}
print(f"[+] {len(FUNCS)} function fields / {len(VALS)} value fields / {len(POS)} positional")

IMPORT = {k: v["src"] for k, v in VALS.items()}
NAME2SYM = {}
for k, v in IMPORT.items():
    NAME2SYM[k] = v

RX_CALL = re.compile(r'\bb[:.]([A-Za-z_]\w*)\b')
RX_SLOT = re.compile(r'\bb\[(\d+)\]')
RX_DOT = re.compile(r'\bb\.([A-Za-z_]\w*)\b')
RX_RET = re.compile(r'\breturn\s+(-?\d+)\b')
RX_CMP = re.compile(r'\b([A-Za-z_]\w*)\s*(<=|>=|<|>|==|~=)\s*(-?\d+)')
RX_ASSG = re.compile(r'\bb\[(\d+)\]\s*=[^=]')
RX_NUM = re.compile(r'(?<![\w.])\d+(?![\w.])')

META = {}
for k, f in FUNCS.items():
    txt = f["text"]
    META[k] = {
        "key": k, "start": f["start"], "end": f["end"], "len": f["end"] - f["start"],
        "params": f["params"], "arity": len([x for x in f["params"].split(",") if x.strip()]),
        "calls": dict(collections.Counter(RX_CALL.findall(txt))),
        "slots": dict(collections.Counter(int(x) for x in RX_SLOT.findall(txt))),
        "dots": dict(collections.Counter(RX_DOT.findall(txt))),
        "ws": dict(collections.Counter(int(x) for x in RX_ASSG.findall(txt))),
        "states": sorted(set(int(x) for x in RX_RET.findall(txt))),
        "cmps": [[a, o, int(n)] for a, o, n in RX_CMP.findall(txt)],
        "nums": dict(collections.Counter(int(x) for x in RX_NUM.findall(txt))),
        "src": txt,
    }

json.dump({"import": {str(k): v for k, v in IMPORT.items()}}, open("tools/imports.json", "w"), indent=1)
json.dump(META, open("tools/handlers.json", "w"), indent=0)
json.dump({"funcs": {str(k): {"start": v["start"], "end": v["end"]} for k, v in FUNCS.items()},
           "blocks": blocks, "cb": cb, "tb": tb}, open("tools/structure.json", "w"), indent=0)
print("[+] wrote tools/imports.json tools/handlers.json tools/structure.json")

with open("tools/handlers.lua", "w") as fh:
    for k, f in FUNCS.items():
        fh.write(f"\n-- ===== b[{k!r}]   BODY@{f['start']}..{f['end']}  params({f['params']}) =====\n")
        fh.write(f["text"] + "\n")
with open("tools/values.lua", "w") as fh:
    for k, v in VALS.items(): fh.write(f"b[{k!r}] = {v['src']}\n")

if POS: print("[!] unparsed positional fields:", POS[:6])
