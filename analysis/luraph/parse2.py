#!/usr/bin/env python3
"""LurAPH 14.9 stage1.bin — full container parser.
Mechanical transcription of the field functions (yG / slot65 / fU / xU / jU / ZG ...).
Goal: consume the byte stream exactly how the VM does and dump its structure."""
import struct, sys, collections

D = open('stage1.bin','rb').read()
POS = 0
def u8():
    global POS; v = D[POS]; POS += 1; return v
def u16():
    global POS; v = struct.unpack_from('<H', D, POS)[0]; POS += 2; return v
def i32():
    global POS; v = struct.unpack_from('<i', D, POS)[0]; POS += 4; return v
def u32():
    global POS; v = struct.unpack_from('<I', D, POS)[0]; POS += 4; return v
def f32():
    global POS; v = struct.unpack_from('<f', D, POS)[0]; POS += 4; return v
def f64():
    global POS; v = struct.unpack_from('<d', D, POS)[0]; POS += 8; return v
def varint():
    acc = 0; shift = 1
    while True:
        b = u8()
        acc += (b - 128 if b > 127 else b) * shift
        if b < 128: break
        shift *= 128
    return acc
uvarint = varint
def v53():                      # T[55]-style: varint, then XU bias
    v = varint()
    if v >= 4503599627370496:   # R[51] = 2^52
        v -= 9007199254740992   # R[24] = 2^53
    return v
def u64():
    lo = u32(); hi = u32()
    if hi >= 2**31: hi -= 2**32
    return lo + hi * 2**32
def sstr():
    n = varint(); global POS
    s = D[POS:POS+n]; POS += n; return s

def read_const(tag):
    if tag == 0: return u16()
    if 1 <= tag <= 11: return f32()
    if tag == 12: return True
    if 13 <= tag <= 30: return u8()
    if 31 <= tag <= 49:
        s = sstr()
        try: return s.decode('utf-8')
        except: return s
    if tag == 50: return i32()
    if 51 <= tag <= 52: return u64()
    if 53 <= tag <= 95: return u16()
    if 96 <= tag <= 134: return f64()
    if 135 <= tag <= 229: return -u8()
    if tag == 233: return u32()
    return False

def lua_type(v):
    if v is None: return 'nil'
    if isinstance(v, bool): return 'boolean'
    if isinstance(v, (int, float)): return 'number'
    if isinstance(v, (str, bytes)): return 'string'
    return 'table'

STRTAB = {}   # j[48]

def gU(xjunk, f_count):
    O = [None] * f_count
    xjunk[4] = O
    for f in range(1, f_count + 1):
        v = varint()
        if v in STRTAB:                      # lU
            O[f-1] = STRTAB[v]
        else:                                # MU / DU
            pair = (v // 4, v % 4)
            STRTAB[v] = pair                 # DU: strtab[v] = pair
            O[f-1] = pair
    return O

def ZG_pool(j_start, shared):
    """ZG T==8: u32 pool; even -> shared[j]=T/2; odd -> two extra u32s then fill."""
    j = j_start
    cnt = u32()
    for _ in range(cnt):
        T = u32()
        O = T / 2
        if T % 2 != 0:                       # WG
            a2 = u32(); b2 = u32()           # hG two reads
            shared[j] = ('odd', a2, b2)      # record-only (range fill elided)
        else:
            shared[j] = int(O - O % 1)
        j += 1
    return j

def slot65(shared, y5, consts, j49):
    # ---- pU ----
    hidden = varint()                        # stashed junk-array [7]
    f2 = varint()                            # gU count
    aux = gU([None]*11, f2)                  # returns (hidden_array-ish) via gU; record aux
    # ---- dU ----
    icount = varint() - 12950
    l3, J3, h3 = [None]*icount, [None]*icount, [None]*icount
    # ---- uU / yU : no stream reads (create tables only; QU/LU/kU are alloc/junk) ----
    P = [None]*icount
    # ---- per-instruction loop ----
    ops = []
    for K in range(1, icount + 1):
        # fU: v1, vA, vB
        v1 = v53()
        vA = v53(); vB = v53()               # via GU (2 calls)
        tagA = vA % 8
        tagB = vB % 8
        # xU: v4
        v4 = v53()
        # payloads
        B = (vA - tagA) >> 3                 # (a - y)/8 with a=vA, y=tagA
        J = (vB - tagB) >> 3                 # (P - Q)/8
        T = (v4 - v4 % 8) >> 3               # (k - C)/8
        # jU routing (no stream reads): kinds tagB(T) and tagV=Q=v4%8
        ops.append(dict(K=K, v1=v1, vA=vA, vB=vB, v4=v4,
                        kA=tagA, kB=tagB, k4=v4 % 8,
                        pA=B, pB=J, p4=T))
        l3[K-1] = J                          # (j)[l] = J  -> code array
        P[K-1] = B                           # h[l] = B
    # ---- ZG (k=8: u32 pool; k=123: varint -> end) ----
    j_extra = ZG_pool(0, shared)
    val9 = varint()                          # O[9] = a[54]()
    return dict(aux=aux, icount=icount, ops=ops, code=l3, P=P,
                hidden=hidden, f2=f2, val9=val9, pool_end=j_extra)

def yG():
    STRTAB.clear()                           # NG: strtab reset per group
    ccount = varint() - 61018
    flag = u8() != 0                         # EG -> j[49]
    consts = []
    for _ in range(ccount):
        tag = u8()
        c = read_const(tag)
        consts.append([c, lua_type(c), tag]) # always record tag for analysis
    x = varint() - 41577
    y5 = []                                  # patch triples (appended by jU slot65s — record-only)
    shared = {}
    items = [slot65(shared, y5, consts, flag) for _ in range(x)]
    entry_idx = varint()
    entry = items[entry_idx] if entry_idx < len(items) else None
    return dict(ccount=ccount, x=x, consts=consts, items=items,
                entry_idx=entry_idx, flag=flag, shared=shared)

def main():
    global POS
    g = 0
    while POS < len(D):
        start = POS
        grp = yG()
        g += 1
        print(f'[group {g}] @{start}..{POS}  consts={grp["ccount"]}  items={grp["x"]}  '
              f'entry={grp["entry_idx"]}  flag={grp["flag"]}  instrs={sum(i["icount"] for i in grp["items"])}')
    print(f'EOF check: pos={POS} len={len(D)}  {"EXACT" if POS==len(D) else "MISMATCH!!"}')
    import pickle as pk
    pk.dump(groups if False else None, open('/dev/null','wb')) if False else None

# stash the parsed structure for later reuse
import pickle as pk
GROUPS = []
def main2():
    global POS
    while POS < len(D):
        try:
            GROUPS.append(yG())
            print(f'[group {len(GROUPS)}] pos={POS}/{len(D)}', file=sys.stderr)
        except Exception as e:
            print(f'[!] stopping at {POS}/{len(D)}: {e!r} -> tail treated as trailer', file=sys.stderr)
            break
    pk.dump(GROUPS, open('groups.pkl','wb'))
    print(f'parsed_end={POS} len={len(D)} trailer={len(D)-POS}')

if __name__ == '__main__':
    main2()
