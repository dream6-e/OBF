import pickle, struct
protos = pickle.load(open('protos2.pkl','rb'))

OPNAMES = {
 195:'UNM', 201:'ADD', 66:'SUB', 138:'GETGEN', 105:'NEWTABLE', 159:'LOADNIL',
 150:'CONCAT', 57:'EQ', 135:'CALL', 246:'MUL', 27:'NOT', 213:'DIV', 108:'GETGLOBAL',
 40:'SPREAD', 58:'CALL2', 85:'MOVE', 52:'SETTABLE', 121:'LE', 34:'SETUPVAL',
 169:'CLOSURE', 79:'APPEND', 106:'PACK1', 217:'VARARG', 187:'GETUPVAL', 235:'UNBOX',
 55:'TAILCALL', 167:'LT', 89:'NEWPACK', 173:'GETTAB_SK', 47:'SETGLOBAL', 212:'LEN',
 14:'LE_S', 62:'JMP', 29:'SETBOX', 185:'LOADI', 227:'POW', 59:'SETN', 191:'LOADNILS',
 215:'APPENDPACK', 83:'TEST', 170:'FORPREP', 65:'FORLOOP', 5:'MOD', 98:'LOADK',
 35:'GETTAB_I', 245:'RETURN', 233:'GETTABLE',
}

def disasm(p, pi):
    consts = p['consts']
    print(f"=== proto {pi}: id={p['id']} maxstack={p['maxstack']} nparam={p['numparams']} flags={p['flags']} ninstr={p['ninstr']} nconst={p['nconst']} nup={p['nupvals']}")
    if p['nupvals']:
        print("    upvals:", p['upvals'])
    for i,cc in enumerate(consts):
        r = repr(cc)
        if len(r)>60: r = r[:60]+'...'
        t = p['ctypes'][i]
        print(f"    K[{i}] (t{t}) = {r}")
    z = p['z']
    for idx,(op,A,B,C) in enumerate(p['instrs']):
        l16 = B + C*256
        h24 = A + l16*256
        name = OPNAMES.get(op, f"OP{op}")
        extra = ""
        if op == 98:   # LOADK
            extra = f"  ; K[{l16}] = {consts[l16]!r}"
        elif op in (108, 47):
            extra = f"  ; {consts[l16]!r}"
        elif op == 62:
            extra = f"  ; -> {h24} (abs idx {h24})"
        elif op == 169:
            extra = f"  ; proto[{l16}]"
        elif op in (173, 138, 233, 52):
            pass
        print(f"  [{idx:>4}] {name:<10} A={A:<3} B={B:<3} C={C:<3} l16={l16:<6} h24={h24:<8}{extra}")

disasm(protos[0], 0)
