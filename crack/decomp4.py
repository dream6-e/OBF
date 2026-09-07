import pickle, sys, re
sys.setrecursionlimit(100000)
protos = pickle.load(open('protos2.pkl','rb'))

OPNAME = {
 195:'UNM', 201:'ADD', 66:'SUB', 138:'GETGEN', 105:'NEWTABLE', 159:'LOADNIL',
 150:'CONCAT', 57:'EQ', 135:'CALL', 246:'MUL', 27:'NOT', 213:'DIV', 108:'GETGLOBAL',
 40:'SPREAD', 58:'CALL2', 85:'MOVE', 52:'SETTABLE', 121:'LE', 34:'SETUPVAL',
 169:'CLOSURE', 79:'APPEND', 106:'PACK1', 217:'VARARG', 187:'GETUPVAL', 235:'UNBOX',
 55:'TAILCALL', 167:'LT', 89:'NEWPACK', 173:'GETTAB_SK', 47:'SETGLOBAL', 212:'LEN',
 14:'LE_S', 62:'JMP', 29:'SETBOX', 185:'LOADI', 227:'POW', 59:'SETN', 191:'LOADNILS',
 215:'APPENDPACK', 83:'TEST', 170:'FORPREP', 65:'FORLOOP', 5:'MOD', 98:'LOADK',
 35:'GETTAB_I', 245:'RETURN', 233:'GETTABLE',
}
PURE = {'LOADNIL','LOADNILS','LOADK','MOVE','UNBOX','SETBOX','PACK1','NEWPACK','APPEND',
        'APPENDPACK','SETN','GETTAB_I','GETTABLE','GETTAB_SK','GETGEN','GETGLOBAL',
        'ADD','SUB','MUL','DIV','MOD','POW','UNM','NOT','LEN','CONCAT','EQ','LT','LE','LE_S',
        'GETUPVAL','CLOSURE','LOADI','CALL','CALL2'}
STMT_CALL = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_]\w*|\[[^\]]+\])*\(')

def kstr(c):
    if isinstance(c, bytes): return '"' + c.decode('latin-1').replace('\\','\\\\').replace('"','\\"') + '"'
    if isinstance(c, bool): return 'true' if c else 'false'
    if c is None: return 'nil'
    if isinstance(c, float) and c == int(c) and abs(c) < 1e15: return str(int(c))
    return repr(c)

def build_cfg(instrs):
    n = len(instrs)
    OP = lambda i: OPNAME[instrs[i][0]]
    def tgt(i):
        _, A, B, C = instrs[i]
        return A + (B + C*256)*256
    succ = {}
    for i in range(n):
        o = OP(i)
        S = []
        if o == 'JMP': S = [tgt(i)]
        elif o == 'TEST': S = [tgt(i+1), tgt(i+2)]
        elif o == 'RETURN' or o == 'TAILCALL': S = []
        else: S = [i+1] if i+1 < n else []
        succ[i] = [s for s in S if 0 <= s < n]
    # dominators (iterative)
    preds = {i: [] for i in range(n)}
    for i, S in succ.items():
        for s in S: preds[s].append(i)
    dom = {0: {0}}
    changed = True
    allset = set(range(n))
    for i in range(1, n): dom[i] = set(allset)
    while changed:
        changed = False
        for i in range(1, n):
            ps = [p for p in preds[i] if p in dom and dom[p]]
            if not ps: continue
            new = set.intersection(*[dom[p] for p in ps]) | {i}
            if new != dom[i]:
                dom[i] = new; changed = True
    return succ, preds, dom, tgt

class Decomp:
    def __init__(self, pi):
        p = protos[pi]
        self.pi = pi
        self.instrs = p['instrs']
        self.consts = p['consts']
        self.n = len(self.instrs)
        self.succ, self.preds, self.dom, self.tgtf = build_cfg(self.instrs)
        self.headers = set()
        self.loops = {}
        for s in range(self.n):
            if OPNAME[self.instrs[s][0]] == 'JMP':
                h = self.tgtf(s)
                if h <= s and h in self.dom.get(s, set()):
                    self.headers.add(h)
                    self.loops.setdefault(h, set()).add(s)
        self.reg = {}; self.pack = {}; self.box = {}
        self.callret = {}
        self.out = []
        self.visited = set()
        self.tmp = 0
        self.read = set()

    def op(self, i): return OPNAME[self.instrs[i][0]]
    def thread(self, i):
        seen = set()
        while i < self.n and self.op(i) == 'JMP' and i not in seen:
            seen.add(i); i = self.tgtf(i)
        return i
    def s(self, r):
        self.read.add(r)
        return self.reg.get(r, f'v{r}')

    def consume_callres(self, expr):
        for cr in self.callret.values():
            if not cr.get('consumed') and cr.get('expr') == expr:
                cr['consumed'] = True

    def emit(self, ind, txt): self.out.append('  '*ind + txt)

    def loop_nodes(self, h):
        backsrcs = self.loops[h]
        nodes = {h}
        stack = list(backsrcs)
        while stack:
            x = stack.pop()
            if x in nodes: continue
            nodes.add(x)
            for pr in self.preds[x]:
                if pr >= h: stack.append(pr)
        return nodes

    DESTOPS = {'LOADNIL','LOADNILS','LOADK','MOVE','UNBOX','GETTAB_I','GETTABLE','GETTAB_SK',
               'GETGEN','GETGLOBAL','ADD','SUB','MUL','DIV','MOD','POW','UNM','NOT','LEN',
               'CONCAT','EQ','LT','LE','LE_S','CALL','CALL2','VARARG','CLOSURE','LOADI',
               'GETUPVAL','SPREAD','FORPREP','FORLOOP'}

    def exec_lin(self, i, ind, silent=False):
        op, A, B, C = self.instrs[i]
        name = OPNAME[op]
        reg, pack, box = self.reg, self.pack, self.box
        stmt = None
        if name in self.DESTOPS and name != 'LOADNILS': self.read.discard(A)
        if name == 'LOADNIL': reg[A] = 'nil'
        elif name == 'LOADNILS':
            for r in range(A, B+1):
                e = reg.get(r)
                cr = self.callret.get(r)
                if not silent:
                    if cr is not None:
                        used = cr['used']
                        pending = any(isinstance(it, tuple) and isinstance(it[1], dict) and it[1] is cr
                                      for pkv in self.pack.values() for it in pkv)
                        if pending or cr.get('consumed'):
                            pass
                        elif used and (used - {1}):
                            maxc = max(used)
                            names = ', '.join(f"ret{cr['id']}_{k}" for k in range(2, maxc+1))
                            self.emit(ind, f'local {names} = select(2, {cr["expr"]})')
                        elif cr.get('inplace') and r not in self.read:
                            self.emit(ind, cr['expr'])
                        elif not used and r not in self.read:
                            self.emit(ind, cr['expr'])
                        elif used == {1}:
                            pat1 = f'ret{cr["id"]}_1'
                            referenced = any(isinstance(x, str) and pat1 in x
                                             for rr, x in reg.items() if rr != r) or \
                                         any(isinstance(x, str) and pat1 in x for x in self.box.values())
                            if referenced: self.emit(ind, f'local ret{cr["id"]}_1 = {cr["expr"]}')
                    elif e and STMT_CALL.match(e) and r not in self.read:
                        self.emit(ind, e)
                self.callret.pop(r, None)
                reg.pop(r, None); pack.pop(r, None); self.read.discard(r)
        elif name == 'LOADK': reg[A] = kstr(self.consts[B + C*256])
        elif name == 'MOVE': reg[A] = self.s(B)
        elif name == 'UNBOX': reg[A] = self.box.get(B, f'v{B}')
        elif name == 'SETBOX':
            box.setdefault(A, None)
            if not silent and box[A] != self.s(B):
                self.consume_callres(self.s(B))
                if box[A] is None: self.emit(ind, f'local v{A} = {self.s(B)}')
                else: self.emit(ind, f'v{A} = {self.s(B)}')
            box[A] = f'v{A}'; reg[A] = f'v{A}'
        elif name == 'PACK1':
            box.setdefault(A, None)
            if not silent and box[A] != self.s(B):
                self.consume_callres(self.s(B))
                if box[A] is None: self.emit(ind, f'local v{A} = {self.s(B)}')
                else: self.emit(ind, f'v{A} = {self.s(B)}')
            box[A] = f'v{A}'; pack.pop(A, None)
        elif name == 'NEWPACK': pack[A] = []
        elif name == 'APPEND': pack.setdefault(A, []).append(self.s(B))
        elif name == 'APPENDPACK':
            dst = pack.setdefault(A, [])
            if B in pack: dst.extend(pack[B])
            elif B in self.callret: dst.append(('CALLRES', self.callret[B]))
            else: dst.append(self.s(B))
        elif name == 'SETN': pass
        elif name == 'CALL':
            expr = f'{self.s(B)}({", ".join(pack.get(C, []))})'
            self.tmp += 1
            reg[A] = expr
            self.callret[A] = {'id': self.tmp, 'expr': expr, 'used': set()}
            pack.pop(C, None)
        elif name == 'CALL2':
            q = pack.get(B)
            if q and len(q) >= 3:
                f0 = q[0]; a1 = q[1]; a2 = q[2]
                if isinstance(a1, tuple): a1 = a1[1]
                if isinstance(a2, tuple): a2 = a2[1]
                self.tmp += 1
                expr = f'{f0}({a1}, {a2})'
                reg[A] = expr
                self.callret[A] = {'id': self.tmp, 'expr': expr, 'used': set()}
            else: reg[A] = f'CALL2:{self.s(B)}'
        elif name == 'GETTAB_I':
            pk = pack.get(B)
            crx_any = None
            if pk:
                for it in pk:
                    if isinstance(it, tuple) and isinstance(it[1], dict): crx_any = it[1]; break
            if crx_any is None and B in self.callret and C == 1:
                cr = self.callret[B]
                cr['used'].add(C)
                if A == B:
                    cr['inplace'] = True; reg[A] = cr['expr']
                else:
                    cr['consumed'] = True; reg[A] = cr['expr']
                continue2 = True
            elif crx_any is not None:
                crx = crx_any
                if C >= 2:
                    crx['used'].add(C); reg[A] = f'ret{crx["id"]}_{C}'
                else:
                    reg[A] = crx['expr']
                    if A == B: crx['inplace'] = True
                    else: crx['consumed'] = True
            elif pk is not None and len(pk) < C:
                reg[A] = 'nil'
            elif pk is not None and len(pk) >= C:
                v = pk[C-1]
                if isinstance(v, tuple):
                    crx = v[1]
                    if isinstance(crx, dict):
                        if C >= 2:
                            crx['used'].add(C)
                            v = f'ret{crx["id"]}_{C}'
                        else:
                            v = crx['expr']
                    else: v = crx
                reg[A] = v
            elif C == 1 and '(' in self.reg.get(B, ''):
                reg[A] = self.reg.get(B)
            else:
                bx = self.s(B)
                reg[A] = f'{bx}[{C}]'
        elif name in ('GETTABLE','GETTAB_SK','GETGEN'): reg[A] = f'{self.s(B)}[{self.s(C)}]'
        elif name == 'GETGLOBAL': reg[A] = self.consts[B + C*256].decode('latin-1')
        elif name == 'SETGLOBAL': stmt = f'{self.consts[B + C*256].decode("latin-1")} = {self.s(A)}'
        elif name == 'SETTABLE': stmt = f'{self.s(A)}[{self.s(B)}] = {self.s(C)}'
        elif name == 'NEWTABLE':
            self.tmp += 1; tname = f'tbl{self.tmp}'
            reg[A] = tname
            if not silent: self.emit(ind, f'local {tname} = {{}}')
        elif name == 'GETUPVAL': reg[A] = f'uv{B}'
        elif name == 'SETUPVAL': stmt = f'uv{B} = {self.s(A)}'
        elif name == 'CLOSURE': reg[A] = f'FUNC[{B + C*256}]'
        elif name == 'VARARG': reg[A] = '...'
        elif name == 'ADD': reg[A] = f'({self.s(B)} + {self.s(C)})'
        elif name == 'SUB': reg[A] = f'({self.s(B)} - {self.s(C)})'
        elif name == 'MUL': reg[A] = f'({self.s(B)} * {self.s(C)})'
        elif name == 'DIV': reg[A] = f'({self.s(B)} / {self.s(C)})'
        elif name == 'MOD': reg[A] = f'({self.s(B)} % {self.s(C)})'
        elif name == 'POW': reg[A] = f'({self.s(B)} ^ {self.s(C)})'
        elif name == 'UNM': reg[A] = f'(-{self.s(B)})'
        elif name == 'NOT': reg[A] = f'(not {self.s(B)})'
        elif name == 'LEN': reg[A] = f'#{self.s(B)}'
        elif name == 'CONCAT': reg[A] = f'{self.s(B)} .. {self.s(C)}'
        elif name == 'EQ': reg[A] = f'({self.s(B)} == {self.s(C)})'
        elif name == 'LT': reg[A] = f'({self.s(B)} < {self.s(C)})'
        elif name == 'LE': reg[A] = f'({self.s(B)} <= {self.s(C)})'
        elif name == 'LE_S':
            reg[A] = f'({self.s(B)} <= {self.s(B+1)})' if C > 0 else f'({self.s(B)} >= {self.s(B+1)})'
        elif name == 'SPREAD':
            try: start = int(self.s(C))
            except Exception: start = None
            items = pack.get(B)
            if items is not None and start is not None:
                tgt_tbl = reg.get(A)
                for k, e in enumerate(items):
                    if isinstance(e, tuple): e = e[1]['expr'] if isinstance(e[1], dict) else e[1]
                    if tgt_tbl is not None and not silent:
                        self.emit(ind, f'{tgt_tbl}[{start + k}] = {e}')
            else: stmt = f'-- SPREAD {self.s(B)} into {self.s(A)}[{self.s(C)}..]'
        elif name == 'TAILCALL':
            def _sx2(e):
                if isinstance(e, tuple): e = e[1]['expr'] if isinstance(e[1], dict) else e[1]
                return str(e)
            stmt = f'return {self.s(A)}({", ".join(_sx2(e) for e in pack.get(B, []))})'
        elif name == 'RETURN':
            pk = pack.get(A)
            if pk is not None and A in pack:
                def _sx(e):
                    if isinstance(e, tuple): e = e[1]['expr'] if isinstance(e[1], dict) else e[1]
                    return str(e)
                stmt = ('return ' + ', '.join(_sx(e) for e in pk)) if pk else 'return'
            else: stmt = f'return {self.s(A)}'
        elif name == 'FORPREP':
            self.forprep = (A, self.s(A), self.s(A+1), self.s(A+2))
            reg[A] = f'v{A}'
            for rr in (A+1, A+2): reg.pop(rr, None)
        elif name in ('FORLOOP','TEST','JMP'): pass
        else: stmt = f'-- ?? {name} {A} {B} {C}'
        if stmt: self.emit(ind, stmt)

    def block_pure_andor(self, lo, hi, A):
        j = lo
        block = []
        while j < hi:
            o = self.op(j)
            if o == 'JMP':
                if j == hi-1 and self.thread(j) == hi: j += 1; break
                return None, False
            if o in ('SETGLOBAL','SETTABLE','SETUPVAL','RETURN','TAILCALL','SPREAD','TEST','FORPREP','FORLOOP'):
                return None, False
            if o not in PURE: return None, False
            block.append(j); j += 1
        if j != hi: return None, False
        save = (dict(self.reg), dict(self.pack), dict(self.box), dict(self.callret))
        rsave = set(self.read)
        outsave = list(self.out)
        for jj in block: self.exec_lin(jj, 0, silent=True)
        newv = self.reg.get(A)
        self.reg, self.pack, self.box, self.callret = save
        self.read = rsave
        self.out = outsave
        return newv, True

    def walk(self, pc, stops, ind):
        while pc is not None and pc < self.n and pc not in stops:
            if pc in self.visited: return pc
            o = self.op(pc)
            # ---------- loop headers ----------
            if pc in self.headers and pc not in self.visited:
                nodes = self.loop_nodes(pc)
                # numeric for: FORPREP right before with JMP to pc and op(pc)==FORLOOP
                if o == 'FORLOOP' and pc >= 2 and self.op(pc-2) == 'FORPREP' and self.thread(pc-1) == pc:
                    self.visited.add(pc)  # handled at FORPREP; shouldn't reach here
                    pc += 1; continue
                # find cond TEST: a TEST in nodes with a target outside nodes
                testi = None; exit_t = None; body_t = None; inverted = False
                for j in sorted(nodes):
                    if self.op(j) == 'TEST':
                        T = self.thread(j+1); F = self.thread(j+2)
                        if T not in nodes and F in nodes:
                            testi, exit_t, body_t, inverted = j, T, F, True; break
                        if F not in nodes and T in nodes:
                            testi, exit_t, body_t, inverted = j, F, T, False; break
                if testi is None:
                    self.visited.add(pc)
                    self.exec_lin(pc, ind); pc += 1; continue
                back = max(self.loops[pc])
                hdr = list(range(pc, testi))
                cond = self.s(self.instrs[testi][1])
                # ipairs for-in: inverted loop whose header built (iter,state,ctrl) via CALL2
                forin = False
                cr = None
                if inverted:
                    for j in hdr:
                        if self.op(j) == 'CALL2':
                            pk = self.pack.get(self.instrs[j][2])
                            if pk and len(pk) >= 1 and isinstance(pk[0], tuple) and isinstance(pk[0][1], dict):
                                cr = pk[0][1]
                                forin = True
                    if forin:
                        kname, vname = f'v{self.instrs[testi][1]}_k', f'v{self.instrs[testi][1]}_v'
                        cr['consumed'] = True
                        self.emit(ind, f'for {kname}, {vname} in {cr["expr"]} do')
                        save = (dict(self.reg), dict(self.pack), dict(self.box), dict(self.callret))
                        b1 = b2 = None
                        pro = testi+3
                        for j in range(testi+3, back+1):
                            oo = self.op(j)
                            if oo == 'PACK1' and b1 is None:
                                b1 = self.instrs[j][1]; self.box[b1] = kname
                            elif oo == 'PACK1' and b2 is None:
                                b2 = self.instrs[j][1]; self.box[b2] = vname
                            elif oo in ('GETTAB_I','LOADNILS','CALL2','GETTAB_SK','MOVE','UNBOX'):
                                pro = j+1
                            else:
                                pro = j
                                break
                        for j in range(testi+3, pro): self.visited.add(j)
                        self.walk(pro, stops | {pc, exit_t}, ind+1)
                        self.reg, self.pack, self.box, self.callret = save
                        self.emit(ind, 'end')
                        for r in range(self.instrs[pc][1], self.instrs[pc][1]+4):
                            self.reg.pop(r, None)
                        pc = exit_t
                        continue
                # repeat-until: truthy -> exit ; falsy path flows back to header
                def _flows_back(start):
                    q2 = start
                    for _ in range(50):
                        if q2 >= self.n: return False
                        o2 = self.op(q2)
                        if o2 == 'JMP': return self.thread(q2) == pc
                        if o2 in ('TEST','RETURN','TAILCALL'): return False
                        q2 += 1
                    return False
                Tt = self.thread(testi+1); Ft = self.thread(testi+2)
                if not forin and Tt not in nodes and Ft in nodes and _flows_back(Ft):
                    body = list(range(pc, testi+1))
                    self.emit(ind, 'repeat')
                    save = (dict(self.reg), dict(self.pack), dict(self.box), dict(self.callret))
                    for j in body:
                        if j == testi: continue
                        self.visited.add(j)
                        self.exec_lin(j, ind+1)
                    cond = self.s(self.instrs[testi][1])
                    self.reg, self.pack, self.box, self.callret = save
                    self.emit(ind, f'until {cond}')
                    for j in body: self.visited.add(j)
                    pc = self.thread(testi+1)
                    continue
                # generic while
                if not inverted:
                    hdrpure = all(self.op(j) in PURE for j in hdr)
                    if hdrpure:
                        for j in hdr: self.exec_lin(j, ind, silent=True)
                        cond = self.s(self.instrs[testi][1])
                        self.emit(ind, f'while {cond} do')
                    else:
                        self.emit(ind, 'while true do')
                        for j in hdr: self.exec_lin(j, ind+1)
                        cond = self.s(self.instrs[testi][1])
                        self.emit(ind+1, f'if {cond} then break end')
                else:
                    self.emit(ind, 'while true do')
                    for j in hdr: self.exec_lin(j, ind+1)
                    cond = self.s(self.instrs[testi][1])
                    self.emit(ind+1, f'if {cond} then break end')
                save = (dict(self.reg), dict(self.pack), dict(self.box), dict(self.callret))
                self.walk(body_t, stops | {pc, exit_t}, ind+1)
                self.reg, self.pack, self.box, self.callret = save
                self.emit(ind, 'end')
                pc = exit_t
                continue
            # ---------- if / and / or ----------
            if o == 'TEST' and pc+2 < self.n and self.op(pc+1) == 'JMP' and self.op(pc+2) == 'JMP':
                self.visited.add(pc)
                T = self.thread(pc+1); F = self.thread(pc+2)
                A = self.instrs[pc][1]
                cond = self.s(A)
                if T < F:
                    newv, ok = self.block_pure_andor(T, F, A)
                    if ok and newv is not None:
                        self.reg[A] = f'({cond} and {newv})'
                        pc = F; continue
                if T > F:
                    newv, ok = self.block_pure_andor(F, T, A)
                    if ok and newv is not None:
                        self.reg[A] = f'({cond} or {newv})'
                        pc = T; continue
                self.emit(ind, f'if {cond} then')
                save = (dict(self.reg), dict(self.pack), dict(self.box), dict(self.callret))
                self.walk(T, stops | {F}, ind+1)
                self.reg, self.pack, self.box, self.callret = save
                E = None
                for j in sorted(self.visited):
                    if T <= j < F and self.op(j) == 'JMP':
                        t2 = self.thread(j)
                        if t2 > F: E = t2; break
                if E is not None:
                    self.emit(ind, 'else')
                    save2 = (dict(self.reg), dict(self.pack), dict(self.box), dict(self.callret))
                    self.walk(F, stops | {E}, ind+1)
                    self.reg, self.pack, self.box, self.callret = save2
                    self.emit(ind, 'end')
                    pc = E
                else:
                    self.emit(ind, 'end')
                    pc = F
                continue
            if o == 'FORPREP':
                self.visited.add(pc)
                self.exec_lin(pc, ind)
                H = self.thread(pc+1)
                assert H < self.n and self.op(H) == 'FORLOOP', (pc, H)
                back = None
                for j in range(H+1, self.n):
                    if self.op(j) == 'JMP' and self.thread(j) == H: back = j
                testi = None
                for j in range(H, back):
                    if self.op(j) == 'TEST': testi = j; break
                A, iv, lv, sv = self.forprep
                body = self.thread(testi+1); exit_t = self.thread(testi+2)
                self.emit(ind, f'for v{A} = {iv}, {lv}, {sv} do')
                save = (dict(self.reg), dict(self.pack), dict(self.box), dict(self.callret))
                self.walk(body, stops | {H, exit_t}, ind+1)
                self.reg, self.pack, self.box, self.callret = save
                self.emit(ind, 'end')
                for r in range(A, A+3): self.reg.pop(r, None)
                pc = exit_t
                continue
            if o == 'GETTAB_I':
                _, GA, GB, GC = self.instrs[pc]
                pk = self.pack.get(GB)
                def _callres_of(p, k):
                    if not p: return None
                    for it in p:
                        if isinstance(it, tuple) and isinstance(it[1], dict): return it[1]
                    return None
                crx0 = _callres_of(pk, GC)
                item = (pk[GC-1] if (pk and len(pk) >= GC) else None)
                if crx0 is not None and self.op(pc+1) == 'PACK1' and GC == 1:
                    crx = crx0
                    j = pc; boxes = []; cc = GC; ok = True
                    while True:
                        if j >= self.n or self.op(j) != 'GETTAB_I': break
                        _, A2, B2, C2 = self.instrs[j]
                        pk2 = self.pack.get(B2)
                        cr2 = _callres_of(pk2, C2)
                        if cr2 is None or cr2 is not crx: break
                        if C2 != cc or self.op(j+1) != 'PACK1': break
                        boxes.append(self.instrs[j+1][1]); cc += 1; j += 2
                    if boxes:
                        expr = crx['expr']
                        names = [f'v{b}' for b in boxes]
                        if len(names) == 1: self.emit(ind, f'local {names[0]} = {expr}')
                        else: self.emit(ind, 'local ' + ', '.join(names) + ' = ' + expr)
                        for b in boxes: self.box[b] = f'v{b}'
                        crx['consumed'] = True
                        self.visited.update(range(pc, j))
                        pc = j
                        continue
            if o in ('RETURN','TAILCALL'):
                self.visited.add(pc)
                self.exec_lin(pc, ind)
                return None
            if o == 'FORLOOP':
                self.visited.add(pc); pc += 1; continue
            if o == 'JMP':
                self.visited.add(pc)
                t = self.thread(pc)
                if t in stops or t in self.visited or t <= pc:
                    return t if t in stops else None
                pc = t
                continue
            self.visited.add(pc)
            self.exec_lin(pc, ind)
            pc += 1
        return pc

    def run(self):
        self.walk(0, set(), 0)
        return self.out

if __name__ == '__main__':
    for pi in range(14):
        d = Decomp(pi)
        try: lines = d.run()
        except Exception:
            import traceback; traceback.print_exc(); break
        print(f"==== proto {pi} ====")
        for L in lines: print(L)
        print()
