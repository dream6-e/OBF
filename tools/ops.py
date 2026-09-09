#!/usr/bin/env python3
"""
Rebuild the opcode dispatch tree of a flattened Luraph interpreter loop.
Tracks  if COND then / else / elseif / end  nesting over the token stream, propagates the
interval of the discriminator variable (default O) down each branch, negating on else.
usage: ops.py [handlerkey] [discriminator]
"""
import re, sys, json, collections

M = json.load(open("tools/handlers.json"))
key = sys.argv[1] if len(sys.argv) > 1 else "18"
DISC = sys.argv[2] if len(sys.argv) > 2 else "O"
txt = M[key]["src"]

STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
LONG = re.compile(r"\[(=*)\[")
NAME = re.compile(r"[A-Za-z_]\w*")
TOK = []
i = 0; L = len(txt)
while i < L:
    c = txt[i]
    if c == "-" and txt.startswith("--", i):
        m = LONG.match(txt, i + 2)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"; j = txt.find(t, m.end()); j = L if j < 0 else j + len(t)
            TOK.append(("s", txt[i:j])); i = j; continue
        j = txt.find("\n", i); j = L if j < 0 else j; TOK.append(("s", txt[i:j])); i = j; continue
    if c == "[":
        m = LONG.match(txt, i)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"; j = txt.find(t, m.end()); j = L if j < 0 else j + len(t)
            TOK.append(("s", txt[i:j])); i = j; continue
    if c in "\"'":
        m = STR.match(txt, i)
        if m: TOK.append(("s", m.group())); i = m.end(); continue
    m = NAME.match(txt, i)
    if m: TOK.append(("n", m.group(), m.start())); i = m.end(); continue
    TOK.append(("o", c, i)); i += 1
TOK = [t if len(t) == 3 else (t[0], t[1], 0) for t in TOK]

INF = 1 << 40


def refine(iv, op, n, negate=False):
    """iv = list of (lo,hi) ranges; apply comparison on DISC"""
    def inter(a, b):
        out = []
        for lo, hi in a:
            for clo, chi in b:
                lo2, hi2 = max(lo, clo), min(hi, chi)
                if lo2 <= hi2: out.append((lo2, hi2))
        return out
    if op == ">=": c = [(n, INF)]
    elif op == ">": c = [(n + 1, INF)]
    elif op == "<=": c = [(-INF, n)]
    elif op == "<": c = [(-INF, n - 1)]
    elif op == "==": c = [(n, n)]
    elif op == "~=": c = None
    else: return iv
    if negate:
        if c is None: return iv
        # complement of c
        comp = []
        pts = sorted(c)
        prev = -INF
        for lo, hi in pts:
            if prev <= lo - 1: comp.append((prev, lo - 1))
            prev = hi + 1
        if prev <= INF: comp.append((prev, INF))
        return inter(iv, comp)
    if c is None:
        return iv
    return inter(iv, c)


class Sc:
    def __init__(self): self.i = 0
    def at(self, w, o=0):
        j = self.i + o
        return j < len(TOK) and TOK[j][0] == "n" and TOK[j][1] == w
    def skip(self): self.i += 1


def parse_block(sc, iv, out, stop=("end", "else", "elseif")):
    """collect statements until a stop keyword at this level"""
    buf = []
    while sc.i < len(TOK):
        k, t = TOK[sc.i][0], TOK[sc.i][1]
        if k == "n":
            if t in stop:
                if buf: out.append((iv, "".join(buf).strip()))
                return buf and out or out
            if t == "if":
                if buf: out.append((iv, "".join(buf).strip())); buf = []
                sc.i += 1
                # read condition until 'then' at bracket depth 0
                cstart = sc.i; d = 0
                while sc.i < len(TOK):
                    kk, tt = TOK[sc.i][0], TOK[sc.i][1]
                    if kk == "o":
                        if tt in "([{": d += 1
                        elif tt in ")]}": d -= 1
                    elif kk == "n" and tt == "then" and d == 0: break
                    sc.i += 1
                cond = "".join(x[1] for x in TOK[cstart:sc.i])
                sc.i += 1  # past then
                # condition may or may not be on DISC
                m = re.fullmatch(rf'\s*{DISC}\s*(>=|<=|>|<|==|~=)\s*(\d+)\s*', cond)
                niv = refine(iv, m.group(1), int(m.group(2))) if m else iv
                parse_block(sc, niv, out, stop=("end", "else", "elseif"))
                # now at 'end' or 'else'/'elseif'
                while sc.i < len(TOK) and TOK[sc.i][1] in ("end", "else", "elseif"):
                    if TOK[sc.i][1] == "end":
                        sc.i += 1; break
                    if TOK[sc.i][1] == "else":
                        sc.i += 1
                        niv2 = refine(iv, m.group(1), int(m.group(2)), negate=True) if m else iv
                        parse_block(sc, niv2, out, stop=("end",))
                        if sc.i < len(TOK) and TOK[sc.i][1] == "end": sc.i += 1
                        break
                    if TOK[sc.i][1] == "elseif":
                        sc.i += 1
                        c2 = sc.i; d = 0
                        while sc.i < len(TOK):
                            kk, tt = TOK[sc.i][0], TOK[sc.i][1]
                            if kk == "o":
                                if tt in "([{": d += 1
                                elif tt in ")]}": d -= 1
                            elif kk == "n" and tt == "then" and d == 0: break
                            sc.i += 1
                        cond2 = "".join(x[1] for x in TOK[c2:sc.i]); sc.i += 1
                        m2 = re.fullmatch(rf'\s*{DISC}\s*(>=|<=|>|<|==|~=)\s*(\d+)\s*', cond2)
                        # else-branch of the chain: negate everything seen so far
                        niv3 = iv
                        if m: niv3 = refine(niv3, m.group(1), int(m.group(2)), negate=True)
                        if m2: niv3 = refine(niv3, m2.group(1), int(m2.group(2)))
                        parse_block(sc, niv3, out, stop=("end", "else", "elseif"))
                        break
                continue
        if k == "o" and t == ";" and iv is not None:
            s = "".join(buf).strip()
            if s: out.append((iv, s))
            buf = []; sc.i += 1; continue
        buf.append(t); sc.i += 1
    if buf: out.append((iv, "".join(buf).strip()))


sc = Sc()
out = []
# start scanning from the fetch site  local O = <arr>[Q]
start = 0
for j in range(len(TOK)):
    if TOK[j][0] == "n" and TOK[j][1] == "local" and j + 1 < len(TOK) and TOK[j + 1][1] == DISC:
        start = j; break
sc.i = start
parse_block(sc, [(-INF, INF)], out, stop=("__none__",))

res = collections.defaultdict(list)
for iv, s in out:
    s = re.sub(r"\s+", " ", s).strip()
    if not s or s in ("end", "else"): continue
    for lo, hi in iv:
        res[(lo, hi)].append(s)
print(f"[{key}] discriminator {DISC}: {len(res)} intervals from {len(out)} leaves\n")
rows = []
for (lo, hi), ss in res.items():
    if lo == -INF and hi == INF: continue
    if lo <= 0 and hi >= INF: continue
    rows.append((lo, hi, ss))
rows.sort()
for lo, hi, ss in rows:
    tag = str(lo) if lo == hi else (f"{lo}" if hi >= INF else (f"<={hi}" if lo <= -INF else f"{lo}..{hi}"))
    print(f"  OP {tag:>9s} : " + " ;; ".join(x[:120] for x in ss[:3]))
json.dump([[lo, hi, ss] for lo, hi, ss in rows], open(f"/tmp/ops_{key}_{DISC}.json", "w"), indent=1)
