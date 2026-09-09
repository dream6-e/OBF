#!/usr/bin/env python3
"""Pretty-print a Luraph handler body with real indentation (token-driven, no fake parser),
then optionally reconstruct the flattened dispatch (opcode partition).
Usage: pp.py <key> [pretty|ops]   (> /tmp/x)
"""
import re, sys, json, collections

BODY = open("Luraph15\U0001f480\U0001f480.lua", encoding="utf-8").read().split("\n")[2]
M = json.load(open("tools/handlers.json"))
key = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "pretty"
txt = M[key]["src"]

STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'', re.S)
LONG = re.compile(r"\[(=*)\[")
NAME = re.compile(r"[A-Za-z_]\w*")
EXPR_PREV = {"=", "(", ",", "{", "[", "and", "or", "return", "then", "else", "elseif",
             "+", "-", "*", "/", "%", "^", "#"}

TOK = []; i = 0; L = len(txt)
while i < L:
    c = txt[i]
    if c == "-" and txt.startswith("--", i):
        m = LONG.match(txt, i + 2)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"; j = txt.find(t, m.end())
            j = L if j < 0 else j + len(t); TOK.append((i, "s", txt[i:j])); i = j; continue
        j = txt.find("\n", i); j = L if j < 0 else j; TOK.append((i, "s", txt[i:j])); i = j; continue
    if c == "[":
        m = LONG.match(txt, i)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"; j = txt.find(t, m.end())
            j = L if j < 0 else j + len(t); TOK.append((i, "s", txt[i:j])); i = j; continue
    if c in "\"'":
        m = STR.match(txt, i)
        if m: TOK.append((i, "s", m.group())); i = m.end(); continue
    m = NAME.match(txt, i)
    if m: TOK.append((m.start(), "n", m.group())); i = m.end(); continue
    TOK.append((i, "op", c)); i += 1

EXPIF = set(); prev = None
for idx, (p, k, t) in enumerate(TOK):
    if k == "s": prev = None; continue
    if k == "n" and t == "if" and prev in EXPR_PREV: EXPIF.add(idx)
    prev = t

lines = []          # (depth, start, end)
bd = 0              # bracket depth
depth = 0
seg = None
def cut(endpos, d=None):
    global seg
    if seg is None: return
    s = txt[seg:endpos].strip().strip(";").strip()
    if s: lines.append((d if d is not None else depth, seg, endpos, s))
    seg = None

for idx, (p, k, t) in enumerate(TOK):
    if k == "s":
        if seg is None: seg = p
        seg = seg; continue
    if k == "op":
        if t in "([{":
            bd += 1
        elif t in ")]}":
            bd -= 1
        elif t == ";" and bd == 0:
            cut(p)
        if seg is None and t != ";": seg = p
        continue
    # name
    if bd == 0:
        if t in ("function", "do", "repeat") or (t == "if" and idx not in EXPIF):
            cut(p)
            if t == "do": depth += 1
            elif t == "repeat": depth += 1
            seg = p
        elif t == "end":
            cut(p)
            depth = max(0, depth - 1)
            seg = None
        elif t == "then":
            cut(p + 4); depth += 1; seg = None
        elif t in ("else", "elseif"):
            cut(p)
            depth = max(0, depth - 1)
            seg = p
            # else/elseif line itself gets its own depth
            j = idx
            # find the matching 'then' for elseif
            if t == "elseif":
                d2 = 0
                while j < len(TOK):
                    p2, k2, t2 = TOK[j]
                    if k2 == "n" and t2 == "then" and d2 == 0: break
                    if k2 == "n" and t2 == "if": d2 += 1
                    j += 1
                seg = p
                s = txt[p:p2 + 4].strip()
                lines.append((depth, p, p2 + 4, s))
                depth += 1; seg = None
                i2 = j + 1
                # skip to next token index after j
                while idx < len(TOK) - 1 and TOK[idx][0] < TOK[j][0]: idx += 1
            else:
                s = txt[p:p + 4].strip()
                lines.append((depth, p, p + 4, s))
                depth += 1; seg = None
        elif t == "until":
            cut(p); depth = max(0, depth - 1); seg = p
        else:
            if seg is None: seg = p
    else:
        if seg is None: seg = p
cut(len(txt))

# de-dup overlapping / fix: keep only lines whose text is not just a keyword already emitted
out = []
for d, a, b, s in lines:
    if s in ("then", "do", "end", "else"): continue
    out.append("  " * d + s)
res = "\n".join(out)
if mode == "pretty":
    print(res)
else:
    # attach enclosing conditions to each line using the printed indentation
    toks = out
    stack = {}
    leaves = []
    for ln in out:
        d = (len(ln) - len(ln.lstrip())) // 2
        s = ln.strip()
        stack[d] = s
        for kk in list(stack):
            if kk > d: del stack[kk]
        if not re.match(r'^(if|elseif|else|while|for|local .*=\s*function|function|return)\b', s) or d >= 3:
            path = " & ".join(stack.get(x, "") for x in range(d) if stack.get(x, "").startswith(("if", "elseif", "else")))
            leaves.append((d, path, s))
    varre = re.compile(r'\b(\w+)\s*(>=|<=|<|>|==|~=)\s*(-?\d+)')
    ops = collections.defaultdict(list)
    for d, path, s in leaves:
        by = collections.defaultdict(lambda: [-1 << 60, 1 << 60])
        for v, o, n in varre.findall(path):
            n = int(n)
            if o == ">=": by[v][0] = max(by[v][0], n)
            elif o == ">": by[v][0] = max(by[v][0], n + 1)
            elif o == "<=": by[v][1] = min(by[v][1], n)
            elif o == "<": by[v][1] = min(by[v][1], n - 1)
            elif o == "==": by[v][0] = max(by[v][0], n); by[v][1] = min(by[v][1], n)
        for v, (lo, hi) in by.items():
            if lo <= hi and s: ops[v].append((lo, hi, s))
    for v, lst in sorted(ops.items(), key=lambda kv: -len(kv[1]))[:3]:
        print(f"\n### discriminator {v!r}: {len(lst)} leaves")
        seen = set()
        for lo, hi, s in sorted(lst):
            if lo == hi: tag = f"{lo}"
            elif lo == -1 << 60: tag = f"<={hi}"
            elif hi == 1 << 60: tag = f">={lo}"
            else: tag = f"{lo}..{hi}"
            k2 = (tag, s[:60])
            if k2 in seen: continue
            seen.add(k2)
            print(f"  [{tag:>9s}] {s[:170]}")
