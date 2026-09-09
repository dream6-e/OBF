#!/usr/bin/env python3
"""
Flattening reconstructor: pretty-prints one handler function of the Luraph VM as a
nested if/then tree so the flattened dispatch becomes readable again, and reports
the decision variable's thresholds (the opcode partition).
Usage:  python3 tools/vm.py <handler-key> [--depth N] [--ops]
"""
import re, sys, json, collections

SRC = "Luraph15\U0001f480\U0001f480.lua"
BODY = open(SRC, encoding="utf-8").read().split("\n")[2]
M = json.load(open("tools/handlers.json"))

key = sys.argv[1]
show_ops = "--ops" in sys.argv
f = M[key]
txt = f["src"]

RE_LONG = re.compile(r"\[(=*)\[")
RE_STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
RE_NAME = re.compile(r"[A-Za-z_]\w*")
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
        m = RE_NAME.match(s, i)
        if m: yield m.start(), "name", m.group(); i = m.end(); continue
        yield i, "op", c; i += 1


TK = list(toks(txt))
EXPR_IF = set(); _p = None
for p, k, t in TK:
    if k == "str": _p = None; continue
    if k == "name" and t == "if" and _p in EXPR_IF_PREV: EXPR_IF.add(p)
    _p = t


class P:
    """tiny recursive-descent for the if/then/else/end + statement structure"""
    def __init__(self):
        self.i = 0
        self.n = len(TK)

    def cur(self):
        return TK[self.i] if self.i < self.n else (None, None, None)

    def peek_kw(self, off=0):
        j = self.i + off
        while j < self.n and TK[j][1] == "str":
            j += 1
        return TK[j] if j < self.n else (None, None, None)

    def raw_until(self, stop_depth0=True):
        """collect text up to the next ';'/'else'/'elseif'/'end' at bracket depth 0"""
        start = self.i
        d = 0
        while self.i < self.n:
            p, k, t = TK[self.i]
            if k == "str": self.i += 1; continue
            if t in "{[(": d += 1
            elif t in ")]}": d -= 1
            elif d == 0 and k == "name":
                if t in ("else", "elseif", "end", "until"): break
                if t == "if" and p not in EXPR_IF: break
                if t == "function": break
            elif d == 0 and t == ";" and k == "op":
                self.i += 1
                break
            self.i += 1
        return txt[start:TK[self.i - 1][0] if self.i < self.n and TK[self.i-1][1] != "str" else self.i].strip().rstrip(";").strip()

    def block(self, terminators):
        """parse statements until a token in terminators at depth 0"""
        out = []
        while self.i < self.n:
            p, k, t = self.cur()
            if k == "str": self.i += 1; continue
            if t in terminators: return out
            if t in terminators and k == "name": return out
            if k == "name" and t in terminators: return out
            if k == "op" and t == ";": self.i += 1; continue
            stmt = self.stmt()
            if stmt is not None: out.append(stmt)
        return out

    def stmt(self):
        p, k, t = self.cur()
        if k == "name" and t == "if" and p not in EXPR_IF:
            self.i += 1
            cond = self.raw_until()
            if self.cur()[2] == "then": self.i += 1
            then_b = self.block({"else", "elseif", "end"})
            branches = [("then", then_b)]
            while True:
                c = self.cur()
                if c[1] == "name" and c[2] == "elseif":
                    self.i += 1
                    ec = self.raw_until()
                    if self.cur()[2] == "then": self.i += 1
                    branches.append(("elseif " + ec, self.block({"else", "elseif", "end"})))
                elif c[1] == "name" and c[2] == "else":
                    self.i += 1
                    branches.append(("else", self.block({"end"})))
                elif c[1] == "name" and c[2] == "end":
                    self.i += 1
                    break
                else:
                    break
            return ("if", cond, branches)
        if k == "name" and t in ("while", "for"):
            self.i += 1
            head = self.raw_until()
            if self.cur()[2] == "do": self.i += 1
            body = self.block({"end"})
            if self.cur()[2] == "end": self.i += 1
            return (t + " " + head, body)
        if k == "name" and t == "local":
            s = self.raw_until()
            return ("raw", s)
        s = self.raw_until()
        if s == "": self.i += 1
        return ("raw", s)


def emit(node, ind=0, path=None, sink=None):
    pad = "  " * ind
    kind = node[0]
    if kind == "raw":
        if sink is not None and node[1]:
            sink.append((ind, node[1], path))
        if node[1]:
            print(f"{pad}{node[1]};")
    elif kind.startswith(("if",)):
        cond = node[1]
        print(f"{pad}if {cond} then")
        for br, bl in node[2]:
            if br != "then": print(f"{pad}{br}")
            for x in bl:
                emit(x, ind + 1, path + " " + (cond if br == "then" else br), sink)
        print(f"{pad}end")
    else:
        print(f"{pad}{kind} do")
        for x in node[1]:
            emit(x, ind + 1, path, sink)
        print(f"{pad}end")


# parse: skip the "KEY=function(params)" prefix
m = re.match(r'.*?\bfunction\s*\([^)]*\)', txt, re.S)
start = m.end()
# find where the body starts in token stream
idx = 0
for i, (p, k, t) in enumerate(TK):
    if p >= start: idx = i; break
P.i = 0
pr = P()
pr.i = idx
top = pr.block(set())
sink = []
if show_ops:
    import io
    buf = io.StringIO(); old = sys.stdout; sys.stdout = buf
    for x in top: emit(x, 0, "", sink)
    sys.stdout = old
    # analyse: path conditions on a single var -> opcode map
    varre = re.compile(r'(\w+)\s*(>=|<=|<|>|~?=)\s*(\d+)')
    ops = collections.defaultdict(list)
    for ind, stmt, path in sink:
        cons = varre.findall(path)
        if not cons: continue
        # build an approximate interval per discriminator var
        byvar = collections.defaultdict(lambda: [0, 1 << 60])
        for v, o, n in cons:
            n = int(n)
            if o == ">=": byvar[v][0] = max(byvar[v][0], n)
            elif o == ">": byvar[v][0] = max(byvar[v][0], n + 1)
            elif o == "<=": byvar[v][1] = min(byvar[v][1], n)
            elif o == "<": byvar[v][1] = min(byvar[v][1], n - 1)
        for v, (lo, hi) in byvar.items():
            if lo <= hi and (lo != 0 or hi != (1 << 60)):
                ops[v].append((lo, hi, stmt))
    for v, lst in sorted(ops.items(), key=lambda kv: -len(kv[1]))[:4]:
        print(f"\n### discriminator variable {v!r}: {len(lst)} leaves")
        for lo, hi, stmt in sorted(lst):
            r = "OP" if lo == hi else f"{lo}..{hi}"
            print(f"  [{r:>10s}]  {stmt[:150]}")
    open("/tmp/vm_pretty.lua", "w").write(buf.getvalue())
    print("\n(pretty print written to /tmp/vm_pretty.lua, %d lines)" % buf.getvalue().count("\n"))
else:
    for x in top: emit(x, 0, "", sink)
