#!/usr/bin/env python3
"""
Transliterate Luraph's obfuscated arithmetic into plain Python and *identify the closed
form* by probing a few values.  Only my own generated arithmetic is evaluated; the sample
itself is never run.
"""
import re, json, sys, collections

M32 = 0xFFFFFFFF
M = json.load(open("tools/handlers.json"))

def translit(e):
    """expression text -> python"""
    e = e.strip()
    e = re.sub(r'\bb:vL\s*\(', '((', e)
    # balance the extra '(' from vL: wrap its argument -> handled by appending ')' before matching close
    # simpler: do a recursive rewrite on b:iL(a,b) and b:vL(x)
    def repl_call(s, name, f):
        out = ''
        i = 0
        while True:
            j = s.find(name, i)
            if j < 0: out += s[i:]; break
            k = s.index('(', j + len(name) - 1) if s[j + len(name)] == '(' else None
            if k is None: out += s[i:j + len(name)]; i = j + len(name); continue
            # find matching close
            d = 0; p = k
            while p < len(s):
                if s[p] == '(': d += 1
                elif s[p] == ')':
                    d -= 1
                    if d == 0: break
                p += 1
            args = split_args(s[k + 1:p])
            out += s[i:j] + f(args)
            i = p + 1
        return out
    def split_args(s):
        d = 0; cur = ''; res = []
        for c in s:
            if c in '([{': d += 1
            elif c in ')]}': d -= 1
            if c == ',' and d == 0: res.append(cur); cur = ''
            else: cur += c
        res.append(cur)
        return res
    e = repl_call(e, 'b:iL', lambda a: f'(({{0}})*({{1}}))'.replace('{0}', a[0]).replace('{1}', a[1]))
    e = repl_call(e, 'b:vL', lambda a: f'(({a[0]}) & {M32})'.replace(f'(({a[0]}) &', f'(({a[0]}) &', 1))
    e = repl_call(e, 'b:vL', lambda a: f'(({a[0]}) & 0xFFFFFFFF)')
    slot = {20: '({0} & {1})', 122: '({0} | {1})', 8: '({0} ^ {1})', 99: '(({0} << {1}) & 0xFFFFFFFF)',
            10: '({0} >> {1})'}
    for n, tmpl in slot.items():
        e = re.sub(r'\bb\[%d\]\(' % n, '__OP%d__(' % n, e)
        def mk(tmpl):
            return lambda a: '(' + tmpl.format(*a) + ')'
        # need per-slot call rewrite
    for n in list(slot):
        e = re.sub(r'__OP%d__\((.*?)\)' % n, lambda mm, t=slot[n]: '(' + t.format(*split_args_safe(mm.group(1))) + ')', e)
    e = re.sub(r'\bb\[71\]\(([^()]*)\)', r'((~\1) & 0xFFFFFFFF)', e)
    e = re.sub(r'\bb\[66\]', 'RD8', e)
    e = re.sub(r'\bb\[47\]', 'WR8', e)
    e = e.replace('(', '(').replace(')) & 0xFFFFFFFF)', ') & 0xFFFFFFFF)')
    return e

def split_args_safe(s):
    d = 0; cur = ''; res = []
    for c in s:
        if c in '([{': d += 1
        elif c in ')]}': d -= 1
        if c == ',' and d == 0: res.append(cur); cur = ''
        else: cur += c
    res.append(cur)
    if len(res) == 1: res = [res[0], "0"]
    return res


def probe(expr, var, vals=None):
    vals = vals or [0, 1, 2, 3, 5, 7, 8, 15, 16, 100, 127, 128, 129, 255, 256, 1000, 16383, 16384, 4294967295]
    env = {}
    free = set(re.findall(r'\b[A-Za-z_]\w*\b', expr)) - {var}
    free = {f for f in free if not f.isdigit()}
    out = []
    for v in vals:
        loc = {var: v}
        for f in free: loc[f] = 3          # unknown operands: fix to a constant
        try:
            out.append((v, eval(expr, {"__builtins__": {}}, loc)))
        except Exception as e:
            return None, str(e)
    return out, None


def guess(samples, var):
    if not samples: return None
    cands = {}
    for K in (1, 2, 3, 4, 7, 8, 12, 16, 24, 25, 28, 32, 40, 62, 64, 77, 92, 98, 101, 111, 113, 128, 197, 200, 231, 255, 287072149, 4294967295):
        if all(r == ((v ^ K) & M32) for v, r in samples): cands[f"{var} ^ {K}"] = 1
        if all(r == ((v + K) & M32) for v, r in samples): cands[f"{var} + {K}"] = 1
        if all(r == ((v - K) & M32) for v, r in samples): cands[f"{var} - {K}"] = 1
        if all(r == ((v * K) & M32) for v, r in samples): cands[f"{var} * {K}"] = 1
    for K in (1, 2, 3, 4, 7, 8):
        if all(r == ((v << K) & M32) for v, r in samples): cands[f"{var} << {K}"] = 1
        if all(r == (v >> K) for v, r in samples): cands[f"{var} >> {K}"] = 1
    if all(r == v for v, r in samples): cands[f"identity({var})"] = 1
    if all(r == (v & M32) for v, r in samples): cands[f"{var} & 0xFFFFFFFF"] = 1
    return list(cands)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self":
        exprs = [
            "b:vL(b:iL(2820270878,d)+b:iL(2820270878,4)+(b:iL(2949392836,(lshift(d,4)))+b:iL(2820270879,(bxor(d,4)))))",
        ]
        for x in exprs: print(x, "->", translit(x))
        sys.exit(0)
    t = M[sys.argv[1] if len(sys.argv) > 1 else "73"]["src"]
    # all  LHS = b:vL(...)  assignments
    pats = re.findall(r'([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*=\s*(b:vL\([^\n]*?\)(?=\s*[;,]))', t)
    print(f"[{sys.argv[1] if len(sys.argv)>1 else '73'}] {len(pats)} obfuscated assignments\n")
    seen = set()
    for lhs, rhs in pats:
        py = translit(rhs)
        vs = sorted({v for v in re.findall(r'\b([A-Za-z_]\w*)\b', rhs) if len(v) == 1 and v not in ("b",)})
        best = None
        for v in (vs or ["x"]):
            s, err = probe(py, v)
            if s:
                g = guess(s, v)
                if g: best = (v, g); break
        key = (lhs, rhs[:0])
        if rhs in seen: continue
        seen.add(rhs)
        print(f"  {lhs:12s} = " + (("<%s>  ==>  %s" % (best[0], " | ".join(best[1]))) if best else "???"))
        if not best:
            print(f"      raw: {rhs[:150]}")
