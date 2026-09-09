#!/usr/bin/env python3
"""
De-obfuscation pass for Luraph v15's "opaque modular arithmetic".

Recovered instruction semantics of the two helper handlers:
    b:vL(x)      = x % 2^32                       (normalise)
    b:iL(a,b)    = (a*b) % 2^32                   (32-bit mul built from 16-bit partial products)
Aliases coming from the runtime import table (per-function `local` prologue):
    b[20]=bit32.band  b[122]=bit32.bor  b[8]=bit32.bxor  b[71]=bit32.bnot
    b[99]=bit32.lshift  b[10]=bit32.rshift
Rewrite rules implement the algebraic identities Luraph relies on, e.g.
    iL(K,x) + iL(K,~x)  ==  K*(x + bnot x)  ==  K*0xFFFFFFFF  ==  -K   (mod 2^32)
    iL(K,0xFFFFFFFF)    ==  -K
so a whole nest collapses down to `x ^ const` / `x + const`.
"""
import re, sys, json

MOD = 1 << 32
BAND = MOD - 1

# ---------------------------------------------------------------- tree
# ('num',v) ('var',name) ('idx',base,expr) ('call',fn,[args]) ('un',op,x)
# ('bin',op,a,b)   op in + - * % ^ .. and or
# ('f', fname, [args])   for band/bxor/... we use bin ops directly
class Node:
    __slots__ = ("t", "a", "b", "c")
    def __init__(self, t, a=None, b=None, c=None): self.t, self.a, self.b, self.c = t, a, b, c
    def __repr__(self):
        if self.t == "num": return str(self.a)
        if self.t == "var": return self.a
        if self.t == "idx": return f"{self.a}[{self.b}]"
        if self.t == "un": return f"~({self.a})"
        if self.t == "bin": return f"({self.a} {self.b} {self.c})"
        if self.t == "mod": return f"({self.a} mod2^32)"
        return "?"


# ---------------------------------------------------------------- expr parser
class E:
    def __init__(self, s):
        self.s = s; self.i = 0; self.n = len(s)
    def ws(self):
        while self.i < self.n and self.s[self.i] in " \t": self.i += 1
    def peek(self, k=1):
        self.ws(); return self.s[self.i:self.i + k]
    def eat(self, lit):
        self.ws()
        if self.s.startswith(lit, self.i): self.i += len(lit); return True
        return False
    def parse(self):
        r = self.or_(); self.ws(); return r
    def or_(self):
        a = self.and_()
        while True:
            self.ws()
            if re.match(r'\bor\b', self.s[self.i:]):
                self.i += 2; a = Node("bin", a, "or", self.and_())
            else: return a
    def and_(self):
        a = self.cmp()
        while True:
            self.ws()
            if re.match(r'\band\b', self.s[self.i:]):
                self.i += 3; a = Node("bin", a, "and", self.cmp())
            else: return a
    def cmp(self):
        a = self.concat()
        while True:
            self.ws()
            for op in ("<=", ">=", "~=", "==", "<", ">"):
                if self.s.startswith(op, self.i):
                    self.i += len(op); a = Node("bin", a, op, self.concat()); break
            else: return a
    def concat(self):
        a = self.add()
        while self.eat(".."): a = Node("bin", a, "..", self.add())
        return a
    def add(self):
        a = self.mul()
        while True:
            self.ws()
            for op in ("+", "-"):
                if self.eat(op): a = Node("bin", a, op, self.mul()); break
            else: return a
    def mul(self):
        a = self.unary()
        while True:
            self.ws()
            for op in ("*", "/", "%", "^"):
                if self.eat(op): a = Node("bin", a, op, self.unary()); break
            else: return a
    def unary(self):
        self.ws()
        if self.eat("-"): return Node("bin", Node("num", 0), "-", self.unary())
        if re.match(r'not\b', self.s[self.i:]):
            self.i += 3; return Node("un", ("not", self.unary()))
        return self.prim()
    def prim(self):
        self.ws()
        if self.eat("("):
            e = self.or_(); self.eat(")"); return e
        if self.s[self.i] == "#":
            self.i += 1; return Node("un", ("len", self.prim()))
        m = re.match(r"0x[0-9a-fA-F]+|\d+", self.s[self.i:])
        if m: self.i += len(m.group()); return Node("num", int(m.group(), 0))
        m = re.match(r"[A-Za-z_]\w*", self.s[self.i:])
        if m:
            name = m.group(); self.i += len(name)
            self.ws()
            if self.s[self.i] == "[" if self.i < self.n else False:
                self.i += 1; idx = self.or_(); self.eat("]")
                return Node("idx", name, idx)
            if self.i < self.n and self.s[self.i] == "(":
                self.i += 1; args = []
                if not self.eat(")"):
                    while True:
                        args.append(self.or_())
                        if self.eat(","): continue
                        self.eat(")"); break
                return Node("call", name, args)
            return Node("var", name)
        raise ValueError("parse fail @%d in %r" % (self.i, self.s))


# ---------------------------------------------------------------- rewriter
def isnum(x): return x.t == "num"

def fold(n, env=None):
    if n.t == "num": return n
    if n.t in ("var", "idx"): return n
    if n.t == "un":
        o, x = n.a
        x = fold(x, env)
        if o == "len": return Node("un", ("len", x))
        if o == "not": return Node("un", ("not", x))
        return Node("un", (o, x))
    if n.t == "call":
        return Node("call", n.a, [fold(a, env) for a in n.b])
    op, a, b = n.b, fold(n.a, env), fold(n.c, env)
    if op == "+":
        if isnum(a) and isnum(b): return Node("num", a.a + b.a)
        # a*K + b*K -> (a+b)*K   ;   K*x + K*y -> K*(x+y)
        ka, xa = split_mul(a); kb, xb = split_mul(b)
        if ka is not None and kb is not None and ka.t == "num" and kb.t == "num" and ka.a == kb.a:
            return Node("bin", ka, "*", Node("bin", xa, "+", xb))
        # x + (-x) -> 0
        if neg_of(a, b) or neg_of(b, a): return Node("num", 0)
        return Node("bin", a, "+", b)
    if op == "-":
        if isnum(a) and isnum(b): return Node("num", a.a - b.a)
        return Node("bin", a, "-", b)
    if op == "*":
        if isnum(a) and isnum(b): return Node("num", a.a * b.a)
        # K * (x + bnot x) -> K * 0xFFFFFFFF
        if isnum(a):
            s = maybe_bnot_sum(b)
            if s: return Node("num", a.a * s)
        if isnum(b):
            s = maybe_bnot_sum(a)
            if s: return Node("num", b.a * s)
        return Node("bin", a, "*", b)
    return Node("bin", a, op, b)


def split_mul(x):
    """return (const, other) if x is const*other or other*const"""
    if x.t == "bin" and x.b == "*":
        if isnum(x.a): return x.a, x.c
        if isnum(x.c): return x.c, x.a
    return None, x

def neg_of(x, y):
    """x == -y ?"""
    return y.t == "bin" and y.b == "-" and y.a.t == "num" and y.a.a == 0 and repr(y.c) == repr(x)

def maybe_bnot_sum(e):
    if e.t == "bin" and e.b == "+":
        a, b = e.a, e.c
        if a.t == "var" and b.t == "un" and b.a[0] == "bnot" and repr(b.a[1]) == repr(a):
            return BAND
        if b.t == "var" and a.t == "un" and a.a[0] == "bnot" and repr(a.a[1]) == repr(b):
            return BAND
    return None

# ---------------------------------------------------------------- text pre-rewrite
def canon(src, alias):
    """replace b:vL(...)/b:iL(...)/b[N](...)/alias(...) with canonical ops"""
    src = re.sub(r'\bb:vL\s*\(', '(', src)                    # mod 2^32 handled post-parse
    src = re.sub(r'\bb:iL\s*\(([^,()]*),([^()]*?)\)', r'((\1)*(\2))', src)
    src = re.sub(r'\bb:iL\s*\(', 'MUL(', src)
    for slot, name in alias.items():
        src = re.sub(r'\bb\[%d\]' % slot, name, src)
    return src

ALIASSLOT = {20: "band", 122: "bor", 8: "bxor", 71: "bnot", 99: "lshift", 10: "rshift",
             66: "rd8", 47: "wr8", 51: "bufcreate", 108: "rd32", 107: "fromstring",
             93: "sub", 118: "gsub", 69: "rd16", 68: "rdi16", 46: "rdi32", 125: "rdf32",
             91: "rdf64", 42: "rdstr", 36: "buflen", 55: "tostring", 56: "copy", 1: "fill",
             83: "wri8", 57: "wr32", 22: "tcreate", 24: "rep", 39: "concat", 90: "insert",
             102: "move", 13: "pack", 53: "select", 114: "unpack", 15: "next", 37: "tonumber",
             97: "ts", 116: "fmt", 109: "char", 104: "byte", 70: "find", 67: "match", 41: "gmatch",
             72: "packstr", 7: "unpackstr", 14: "xpcall", 81: "pcall", 16: "err", 76: "assert",
             64: "rawset", 75: "rawget", 43: "getmt", 124: "setmt", 84: "type", 58: "typeof",
             25: "setfenv", 34: "getfenv", 23: "countrz", 21: "co_resume", 28: "co_running",
             31: "co_wrap", 35: "co_status", 38: "co_yield", 77: "co_close", 112: "co_create",
             113: "co_yieldable"}

NAME2OP = {"band": "&", "bxor": "^x", "bor": "|", "bnot": "~"}


def to_expr(node):
    """print a folded node as Lua-ish text with bit ops"""
    if node.t == "num":
        return str(node.a)
    if node.t == "var":
        return node.a
    if node.t == "idx":
        return f"{node.a}[{to_expr(node.b)}]"
    if node.t == "un":
        o, x = node.a
        return f"~{to_expr(x)}" if o == "bnot" else f"#{to_expr(x)}" if o == "len" else f"not {to_expr(x)}"
    if node.t == "call":
        return f"{node.a}({','.join(to_expr(x) for x in node.b)})"
    if node.t == "mod":
        return f"%({to_expr(node.a)}, 2^32)"
    a, op, b = node.a, node.b, node.c
    return f"{to_expr(a)} {op} {to_expr(b)}"


def simplify_call_expr(s):
    """s like:  vL( ... )  already canon'd -> parse, fold, mod 2^32 the top-level + / * chains"""
    e = fold(E(s).parse())
    return to_expr(mod32(e))


def mod32(n):
    if n.t == "bin" and n.b == "+":
        a, b = mod32(n.a), mod32(n.c)
        if isnum(a) and isnum(b): return Node("num", (a.a + b.a) % MOD)
        aa, ka = split_mul(a); bb, kb = split_mul(b)
        # K*x + K*y -> K*(x+y)
        if ka is not None and kb is not None and ka.t == "num" and kb.t == "num" and ka.a == kb.a:
            return Node("bin", ka, "*", Node("bin", aa, "+", bb))
        return Node("bin", a, "+", b)
    if n.t == "bin" and n.b == "-":
        a, b = mod32(n.a), mod32(n.c)
        if isnum(a) and isnum(b): return Node("num", (a.a - b.a) % MOD)
        return Node("bin", a, "-", b)
    if n.t == "bin" and n.b == "*":
        a, b = mod32(n.a), mod32(n.c)
        if isnum(a) and isnum(b): return Node("num", (a.a * b.a) % MOD)
        if isnum(a) and a.a == BAND: return Node("bin", b, "-", Node("bin", a, "*", b))
        if isnum(b) and b.a == BAND: return Node("bin", a, "-", Node("bin", b, "*", a))
        if isnum(a): s = bnot_sum(b)
        else: s = None
        if s is not None: return Node("num", (a.a * s) % MOD)
        if isnum(b): s = bnot_sum(a) if s is None else None
        if s is not None: return Node("num", (b.a * s) % MOD)
        return Node("bin", a, "*", b)
    if n.t == "un" and n.a[0] in ("len", "not"): return n
    return n

def bnot_sum(e):
    if e.t == "bin" and e.b == "+":
        a, b = e.a, e.c
        if a.t == "var" and b.t == "un" and b.a[0] == "bnot" and to_expr(b.a[1]) == to_expr(a): return BAND
        if b.t == "var" and a.t == "un" and a.a[0] == "bnot" and to_expr(a.a[1]) == to_expr(b): return BAND
    return None


if __name__ == "__main__":
    tests = [
        "b:vL(b:iL(2820270878,d)+b:iL(2820270878,4)+(b:iL(2949392836,(lshift(d,4)))+b:iL(2820270879,(bxor(d,4)))))",
        "b:vL(p(b:vL(V),113)+b:iL(815525529,4294967295)+(b:iL(3479441767,113)+b:iL(3479441767,(bnot(113)))))",
        "b:vL(b:iL(2147483649,4294967295)+b:iL(2147483648,i)+(b:iL(2147483648,0)+b:iL(2147483647,(bnot((band(i,0)))))))",
    ]
    for t in tests:
        t2 = t.replace("p(", "bxor(").replace("lshift(", "lshift(")
        print("\nIN :", t)
        try:
            print("OUT:", to_expr(mod32(fold(E(t2).parse()))))
        except Exception as ex:
            print("  (parser err:", ex, ")")
