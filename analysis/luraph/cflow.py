# -*- coding: utf-8 -*-
"""Control-flow-exec-trace disassembly over program.json.
Jump bias: K=target then K+=1  -> effective next = transform(target)+1.
Uncond-family v1: {122,131,5,49,58,127,151,10,36,46(guarded?),73,102,154}
   122/131/5/49/58: QK(B-channel) uncond jump
   127/46/73: kK(C-channel) guarded jump (46/73/127 are cond: record edge, fallthrough)
   151/10/102: lK(A-channel) guarded/uncond
"""
import json, sys

P = json.load(open('/home/user/OBF/analysis/luraph/program.json'))
CONSTS = [c.get('v') if c['t']!='nil' else None for c in P['consts']]
def cval(i):
    if not isinstance(i,int) or not (0 <= i < len(CONSTS)): return f'k{i}'
    v=CONSTS[i]
    if isinstance(v,str): return repr(v if len(v)<=40 else v[:37]+'…')
    return repr(v)

def ch(kind,x,pc):
    if kind==1: return cval(x)
    if kind==3: return f'proto[{x}]'
    if kind==4: return x
    if kind==5: return pc-x
    if kind==6: return pc+x
    return f'r{x}'

def jt(kind,x,pc):
    if kind==4: return x+1
    if kind==5: return pc-x+1
    if kind==6: return pc+x+1
    return None

UNC_B={122:'JMP',131:'JMP',5:'JMP',49:'JMP',58:'JMP'}        # uncond via B-channel
COND_B={}
COND_C={46:'CJMP',73:'CJMP',127:'CJMP',135:'FORLOOP'}
COND_A={151:'CJMP',10:'CJMP',102:'CJMP',154:'CJMP',36:'CJMP'}
RETS={27,37,40,94,148+256}

OPS={}
def op(v,n,f): OPS[v]=(n,f)
def reg(x):
    # x is ch-rendered; add r only when raw int string
    return x
op(66,'MOVE', lambda A,B,C,ra,rb,rc: f'{A} = {C}')
op(115,'LOADK', lambda A,B,C,ra,rb,rc: f'{C} = {A}')
op(78,'LOADNIL', lambda A,B,C,ra,rb,rc: f'{B} = nil')
op(61,'NEWTABLE', lambda A,B,C,ra,rb,rc: f'{B} = {{}}')
op(55,'GETTABLE', lambda A,B,C,ra,rb,rc: f'{A} = {C}[{B}]')
op(82,'GETTABLE_R', lambda A,B,C,ra,rb,rc: f'{C} = {B}[{A}]')
op(43,'SETTABLE', lambda A,B,C,ra,rb,rc: f'{C}[{A}] = {B}')
op(117,'SETTABLE_R', lambda A,B,C,ra,rb,rc: f'{A}[{B}] = {C}')
op(35,'SETTABLE_LIT', lambda A,B,C,ra,rb,rc: f'{A}[{B}] = {C}')
op(157,'SETTABLE_KL', lambda A,B,C,ra,rb,rc: f'{C}[{A}] = {B}')
op(88,'GETENV', lambda A,B,C,ra,rb,rc: f'{B} = env[{C}]')
op(144,'GETENV0', lambda A,B,C,ra,rb,rc: f'{C} = env[{B}]')
op(121,'GETENVX', lambda A,B,C,ra,rb,rc: f'{C} = env[{B}][{A}]')
op(108,'SETENV', lambda A,B,C,ra,rb,rc: f'env[{C}][{A}] = {B}')
op(113,'ADD', lambda A,B,C,ra,rb,rc: f'{A} = {C} + {B}')
op(9,'SUB', lambda A,B,C,ra,rb,rc: f'{B} = {C} - {A}')
op(156,'MUL', lambda A,B,C,ra,rb,rc: f'{C} = {B} * {A}')
op(92,'MULK', lambda A,B,C,ra,rb,rc: f'{A} = {C} * {B}')
op(106,'MULK2', lambda A,B,C,ra,rb,rc: f'{A} = {B} * {C}')
op(74,'DIV', lambda A,B,C,ra,rb,rc: f'{A} = {B} / {C}')
op(87,'DIVK', lambda A,B,C,ra,rb,rc: f'{B} = {C} / {A}')
op(13,'MOD', lambda A,B,C,ra,rb,rc: f'{C} = {B} % {A}')
op(77,'MODK', lambda A,B,C,ra,rb,rc: f'{A} = {C} % {B}')
op(54,'IDIV', lambda A,B,C,ra,rb,rc: f'{B} = {C} // {A}')
op(128,'IDIV2', lambda A,B,C,ra,rb,rc: f'{B} = {C} // {A}')
op(34,'POW', lambda A,B,C,ra,rb,rc: f'{C} = {B} ^ {A}')
op(155,'UNM', lambda A,B,C,ra,rb,rc: f'{A} = -{B}')
op(152,'NOT', lambda A,B,C,ra,rb,rc: f'{A} = not {C}')
op(72,'LEN', lambda A,B,C,ra,rb,rc: f'{C} = #{A}')
op(0,'CONCAT', lambda A,B,C,ra,rb,rc: f'{A} = {B} .. {C}')
op(79,'ADDK', lambda A,B,C,ra,rb,rc: f'{B} = {C} + {A}')
op(129,'ADDK2', lambda A,B,C,ra,rb,rc: f'{B} = {A} + {C}')
op(138,'SUBK', lambda A,B,C,ra,rb,rc: f'{B} = {C} - {A}')
op(84,'BANDK', lambda A,B,C,ra,rb,rc: f'{B} = band({A}, {C})')
op(81,'BXORK', lambda A,B,C,ra,rb,rc: f'{A} = bxor({B}, {C})')
op(100,'BXOR', lambda A,B,C,ra,rb,rc: f'{B} = bxor({A}, {C})')
op(30,'SHRK', lambda A,B,C,ra,rb,rc: f'{C} = rshift({B}, {A})')
op(25,'EQ', lambda A,B,C,ra,rb,rc: f'{A} = ({C} == {B})')
op(17,'NEQK', lambda A,B,C,ra,rb,rc: f'{A} = ({B} ~= {C})')
op(97,'NEQ', lambda A,B,C,ra,rb,rc: f'{C} = ({A} ~= {B})')
op(93,'EQK', lambda A,B,C,ra,rb,rc: f'{B} = ({C} == {A})')
op(125,'LEQ', lambda A,B,C,ra,rb,rc: f'{A} = ({B} <= {C})')
op(96,'GEQ', lambda A,B,C,ra,rb,rc: f'{B} = ({C} >= {A})')
op(83,'SELF', lambda A,B,C,ra,rb,rc: f'r{rc+1} = {B}; {C} = {B}[{A}]')
op(86,'CALL1', lambda A,B,C,ra,rb,rc: f'r{ra} = r{ra}(r{ra+1})')
op(140,'CALL2', lambda A,B,C,ra,rb,rc: f'r{rc} = r{rc}(r{rc+1}, r{rc+2})')
op(47,'CALL0', lambda A,B,C,ra,rb,rc: f'r{rb} = r{rb}()')
op(64,'CALLN1', lambda A,B,C,ra,rb,rc: f'r{rb} = r{rb}(r{rb+1}..r{rb+rc-1})')
op(118,'CALLX1', lambda A,B,C,ra,rb,rc: f'r{rc} = r{rc}(..e-range)')
op(22,'CALL1_0', lambda A,B,C,ra,rb,rc: f'r{rb}(r{rb+1})')
op(23,'CALL2_0', lambda A,B,C,ra,rb,rc: f'r{rc}(r{rc+1}, r{rc+2})')
op(134,'CALL0_0', lambda A,B,C,ra,rb,rc: f'r{rb}()')
op(95,'CALLN_0', lambda A,B,C,ra,rb,rc: f'r{rc}(r{rc+1}..r{rc+rb-1})')
op(123,'CALLX_0', lambda A,B,C,ra,rb,rc: f'r{ra}(..e-range)')
op(116,'CALLMV', lambda A,B,C,ra,rb,rc: f'multicall r{rb} nargs={ra} -> r{rc}?')
op(27,'RET', lambda A,B,C,ra,rb,rc: f'return r{rb}')
op(37,'RETQ', lambda A,B,C,ra,rb,rc: 'return')
op(20,'VARARG', lambda A,B,C,ra,rb,rc: f'args -> r1..r{rb}')
op(45,'VARARG2', lambda A,B,C,ra,rb,rc: f'args -> r1..r{ra} (g={ra}+1)')
op(148,'VARARG3', lambda A,B,C,ra,rb,rc: f'args-tail -> r{ra}..')
op(70,'TMOVE', lambda A,B,C,ra,rb,rc: f'table.move(regs,.., toff={rb+1})')
op(8,'TMOV2', lambda A,B,C,ra,rb,rc: f'table.move(regs, {ra}+1..{ra}+{rc}, {rb}+1, u)')
op(137,'CLOSURE', lambda A,B,C,ra,rb,rc: f'r{rb} = closure({A})')
op(85,'UPVCLOSE', lambda A,B,C,ra,rb,rc: f'close-upvals >= r{rc}')
op(16,'TFORCALL', lambda A,B,C,ra,rb,rc: f'r{ra+1},r{ra+2} = E(); -> {C}')
op(90,'FORPREP', lambda A,B,C,ra,rb,rc: f'n=r{rc+2}; W=r{rc+1}; E=r{rc}-n; ->loop {A}')
op(33,'LOOPSTATE', lambda A,B,C,ra,rb,rc: 'E=H2; W=H5; n=H4')
op(62,'ITERCALL', lambda A,B,C,ra,rb,rc: f'iter-call @e r{ra}')
op(143,'CLEAR', lambda A,B,C,ra,rb,rc: f'clear r{rb}..r{ra}')
op(2,'GETFRAME', lambda A,B,C,ra,rb,rc: f'{C} = frame[{B}]')
op(60,'STRPACK', lambda A,B,C,ra,rb,rc: f'strpack(aux@{B}[{A}])')
op(26,'ENVSETUP', lambda A,B,C,ra,rb,rc: f'envchain Z={B}')
op(103,'LDSPEC', lambda A,B,C,ra,rb,rc: f'r{rb} = Qtable')
op(105,'LDARR_A', lambda A,B,C,ra,rb,rc: f'r{rc} = A-array')
op(110,'LDARR_J', lambda A,B,C,ra,rb,rc: f'r{ra} = opcode-array')
op(112,'LDCUR', lambda A,B,C,ra,rb,rc: f'r{ra} = cursor')
op(124,'LDBLOB', lambda A,B,C,ra,rb,rc: f'r{rc} = blob')
op(76,'LDBASE', lambda A,B,C,ra,rb,rc: f'r{ra} = <regfile>')
op(146,'LDOBJ', lambda A,B,C,ra,rb,rc: f'r{rb} = <O>')

op(40,'RETRANGE', lambda A,B,C,ra,rb,rc: f'return r{rb}..r{rb+ra-2}')
op(153,'RET1C', lambda A,B,C,ra,rb,rc: f'close-upvals; return r{ra}')
op(94,'RETC', lambda A,B,C,ra,rb,rc: f'close-upvals; return r{rc}..r{rc+ra-1}')
op(91,'GETUPVAL', lambda A,B,C,ra,rb,rc: f'r{rc} = upvals[{B}].get()')
op(114,'SETUPVALK', lambda A,B,C,ra,rb,rc: f'upvals[{C}].set({A})')
op(42,'SETUPVAL', lambda A,B,C,ra,rb,rc: f'upvals[{C}].set(r{rb})')
op(136,'RETVC', lambda A,B,C,ra,rb,rc: f'close-upvals; return r{rb}..e-range')
op(11,'NEWTABLEN', lambda A,B,C,ra,rb,rc: f'r{rc} = table.create({ra})')
# chains: template uses {a} {b} {c} = channel reads; cc/bk = const-materialized C/B
CHAIN={
 3:  ('u=u[X]; X=regs; p={a}','mid'),
 4:  ('u=regs; X={a}','mid'),
 6:  ('u=u[X]; X={cc}; u+=X','mid'),
 7:  ('u={c}; X=I','mid'),
 12: ('u=u[X]','mid'),
 28: ('u=regs','mid'),
 29: ('I=regs; Z={c}','mid'),
 31: ('X=X[p]; u=u[X]; I[Z]=u','commit'),
 32: ('X={b}; I=I[X]; (Z)[u]=I','commit'),
 38: ('X={c}; u=u[X]','mid'),
 39: ('p=2','mid'),
 41: ('I=regs; Z={a}; u=regs','mid'),
 44: ('I=I[Z]; Z=I; u=2','mid'),
 48: ('I=I[Z]; Z={a}','mid'),
 50: ('Z=Z[u]; u=I; I=1','mid'),
 51: ('X={b}; u=u[X]','mid'),
 52: ('u=I','mid'),
 53: ('X=X[p]; (Z)[u]=X','commit'),
 56: ('I=envfn','mid'),
 57: ('I=envfn; Z={c}','mid'),
 59: ('X={cc}; u=u[X]; I[Z]=u','commit'),
 65: ('I={b}','mid'),
 67: ('u=u[X]; X={a}','mid'),
 68: ('Z={a}; u={bk}','mid'),
 69: ('(Z)[u]=I','commit'),
 71: ('I=regs; Z={b}; u=nil','mid'),
 75: ('u=u[I]; I={a}','mid'),
 98: ('Z={a}','mid'),
 99: ('I=1','mid'),
 101:('Z={c}','mid'),
 104:('X={bk}','mid'),
 107:('u=frame; X={b}','mid'),
 109:('u=env; X={b}','mid'),
 111:('X={b}','mid'),
 119:('u=u[X]; X={a}; u=u[X]','mid'),
 120:('u={a}; I[Z]=u','commit'),
 126:('I=regs','mid'),
 130:('p=I; I=1; p=p[I]','mid'),
 132:('I=I[Z]; Z=I','mid'),
 139:('I=regs; Z={b}','mid'),
 141:('Z={b}; I=I[Z]; Z=regs','mid'),
 142:('u=u[I]; I=regs','mid'),
 145:('X=X[p]','mid'),
 147:('I[Z]=u','commit'),
 149:('u-=X; I[Z]=u','commit'),
 158:('Z={b}; u=regs; X={c}','mid'),
 159:('u=2; Z=Z[u]','mid'),
}
FOLD={1,14,15,18,24,63,89}
CHAIN.update({
 19: ('I=regs; Z={c}; I=I[Z]','mid'),
 21: ('I=regs; Z={c}; u=regs','mid'),
})


def dis(pi, trace=True):
    it=P['items'][pi]
    out=[f'=== proto #{pi} icount={it["icount"]} ===']
    pc=1; seen=set(); steps=0
    # symbolic chain state
    st={'I':'I','Z':'Z','u':'u','X':'X','p':'p'}; chaining=False
    def flush():
        nonlocal chaining
        chaining=False
        st.update({'I':'I','Z':'Z','u':'u','X':'X','p':'p'})
    while 1 <= pc <= it['icount'] and steps < it['icount']*4:
        steps+=1
        op_=it['ops'][pc-1]
        v1,kA,pA,kB,pB,k4,pC=op_
        if pc in seen:
            out.append(f'  [{pc:4d}] <loop-back>')
            break
        seen.add(pc)
        def rr(kind,x): return ch(kind,x,pc)
        A=rr(kA,pA); B=rr(kB,pB); C=rr(k4,pC)
        def clit(kind,x):   # const-or-literal materialization
            if kind==1: return cval(x)
            if kind in (4,5,6): return rr(kind,x)
            return repr(x)
        if v1 in UNC_B:
            flush()
            tgt=jt(kB,pB,pc)
            out.append(f'  [{pc:4d}] JMP -> {tgt}')
            pc = tgt or pc+1
            continue
        if v1 in COND_C:
            flush()
            tgt=jt(k4,pC,pc)
            if v1==135:
                out.append(f'  [{pc:4d}] FORLOOP    r{pB}+3=E; if-cont -> {tgt}')
            else:
                out.append(f'  [{pc:4d}] {COND_C[v1]} (cond) -> {tgt}')
            pc+=1
            continue
        if v1 in COND_A:
            flush()
            tgt=jt(kA,pA,pc)
            out.append(f'  [{pc:4d}] {COND_A[v1]} (cond) -> {tgt}')
            pc+=1
            continue
        if v1 in OPS:
            flush()
            nm,f=OPS[v1]
            try: body=f(A,B,C,pA,pB,pC)
            except Exception: body='?'
            out.append(f'  [{pc:4d}] {nm:11s} {body}')
            pc+=1
            continue
        if v1 in CHAIN:
            tpl, kind = CHAIN[v1]
            def ci(kind,x):
                if kind==1: return cval(x)
                return str(x)
            cA,cB,cC = ci(kA,pA), ci(kB,pB), ci(k4,pC)
            txt = tpl.format(a=cA,b=cB,c=cC,cc=clit(k4,pC),bk=clit(kB,pB))
            # symbolic execute against st: each stmt "u=u[X]", "I[Z]=u" ...
            for stmt in [s.strip() for s in txt.split(';')]:
                if not stmt: continue
                if stmt.endswith('[Z]=u') and stmt.startswith('I'):      # commit I[Z]=u
                    out.append(f'  [{pc:4d}]            {simplify(st["I"])}[{simplify(st["Z"])}] = {simplify(st["u"])}')
                    flush(); continue
                if stmt=='(Z)[u]=I':
                    out.append(f'  [{pc:4d}]            {simplify(st["Z"])}[{simplify(st["u"])}] = {simplify(st["I"])}')
                    flush(); continue
                if stmt=='Z[u]=X':
                    out.append(f'  [{pc:4d}]            {simplify(st["Z"])}[{simplify(st["u"])}] = {simplify(st["X"])}')
                    flush(); continue
                if '=' in stmt:
                    lhs,rhs=stmt.split('=',1)
                    lhs=lhs.strip(); rhs=rhs.strip()
                    if lhs in st:
                        for k in ('I','Z','u','X','p'):
                            rhs=rhs.replace(k, st[k])
                        rhs=rhs.replace('regsregs','regs')
                        st[lhs]=simplify(rhs)
                        chaining=True
                    continue
                if stmt=='u-=X':
                    st['u']=f'({st["u"]}-{st["X"]})'; continue
                if stmt=='u+=X':
                    st['u']=f'({st["u"]}+{st["X"]})'; continue
            pc+=1
            continue
        if v1 in FOLD:
            flush()
            out.append(f'  [{pc:4d}] FOLD52     r? = <folded-const>')
            pc+=1
            continue
        out.append(f'  [{pc:4d}] v={v1} A({kA})={pA} B({kB})={pB} C({k4})={pC}')
        pc+=1
    out.append(f'  [exit] pc={pc}')
    return '\n'.join(out)

import re as _re
def simplify(x):
    return _re.sub(r'regs\[([^\]]+)\]', lambda m: m.group(1) if m.group(1).startswith('r') else 'r'+m.group(1), x)

if __name__=='__main__':
    for a in (sys.argv[1:] or [str(P['entry_idx'])]):
        print(dis(int(a)))



