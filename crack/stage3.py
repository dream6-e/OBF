import struct, pickle, math

d = pickle.load(open('stage2.pkl','rb'))
b = d['b']; ab = d['ab']; we = d['we']

pos = 32  # after header
class Reader:
    def __init__(self, buf, pos=0):
        self.buf = buf; self.pos = pos
    def u8(self):
        v = self.buf[self.pos]; self.pos += 1; return v
    def u16(self):
        v = struct.unpack_from('<H', self.buf, self.pos)[0]; self.pos += 2; return v
    def u32(self):
        v = struct.unpack_from('<I', self.buf, self.pos)[0]; self.pos += 4; return v
    def raw(self, n):
        v = self.buf[self.pos:self.pos+n]; self.pos += n; return v

r = Reader(b, 32)

# ---------------- keystream for xor reads ([5571]) ----------------
ks_seed = (4632*31 + 8961) % 2147483647
for _ in range(11):
    ks_seed = 65539 * ks_seed % 2147483647
ks_state = 1 + (ks_seed + 31*len(b)) % 2147483646
def ks_next():
    global ks_state
    ks_state = 65539 * ks_state % 2147483647
    return ks_state % 256
def xor_u8():
    return r.u8() ^ ks_next()
def xor_u32():
    return xor_u8() | xor_u8()<<8 | xor_u8()<<16 | xor_u8()<<24
def xor_str():
    n = r.u32()          # plain length
    return bytes(r.u8() ^ ks_next() for _ in range(n))
def xor_double():
    lo = xor_u32(); hi = xor_u32()
    return struct.unpack('<d', struct.pack('<II', lo, hi))[0]

# ---------------- proto parsing ([9820]) ----------------
protos = []
acc = 0
for pi in range(14):
    p = {}
    p['id'] = r.u32()
    p['maxstack'] = r.u16()    # .h
    p['numparams'] = r.u8()    # .r
    p['flags'] = r.u8()
    p['nupvals'] = r.u16()
    pad = r.u16(); assert pad == 0, pad
    p["nconst"] = r.u32()   # .j field = constant count
    p["ninstr"] = r.u32()   # .l field = instruction count
    bcsz = r.u32()
    # integrity checks
    assert 1 <= p['maxstack'] <= 256
    assert p['numparams'] <= p['maxstack']
    assert p['nupvals'] <= 256
    assert p['nconst'] <= 65536
    assert p['ninstr'] >= 1
    assert p['flags'] <= 15
    assert bcsz >= p['ninstr']*2 and bcsz <= p['ninstr']*7
    a_flag = math.floor(p['flags']/8) % 2 == 1
    assert not a_flag, "vararg proto -> would error"
    if pi == 0:
        assert p['id'] == 0xFFFFFFFF
        assert p['nupvals'] == 0
        assert math.floor(p['flags']/2) % 2 == 0
    else:
        assert p['id'] < pi
    bit1 = math.floor(p['flags']/2) % 2
    assert not (bit1 == 1 and (p['flags'] % 2 == 0 or p['numparams'] >= p['maxstack']))
    assert not (math.floor(p['flags']/4) % 2 == 1 and bit1 == 0)
    # upvalues
    upvals = []
    for i in range(p['nupvals']):
        kind = r.u8(); idx = r.u8()
        assert kind <= 2
        parent = protos[p['id']]
        if kind != 1 and idx >= parent['maxstack']: raise AssertionError('upval stack idx')
        if kind == 1 and idx >= parent['nupvals']: raise AssertionError('upval parent idx')
        upvals.append((kind, idx))
    p['upvals'] = upvals
    # constants
    consts = []; ctypes = []
    for i in range(p["nconst"]):
        t = r.u8()
        assert t in (0,1,2,3,5), f"bad const type {t}"
        if t == 0: v = None
        elif t == 1:
            bb = xor_u8(); assert bb <= 1; v = (bb == 1)
        elif t == 2: v = xor_double()
        else: v = xor_str()
        consts.append(v); ctypes.append(t)
    p['consts'] = consts; p['ctypes'] = ctypes
    p['z'] = r.raw(bcsz)
    acc += p['nupvals'] + p['ninstr'] + p['nconst']
    assert acc <= 1000000
    protos.append(p)

print("consumed:", r.pos, "of", len(b), "(must equal len)")
assert r.pos == len(b)
print(f"{'#':>2} {'id':>10} {'npar':>4} {'maxs':>4} {'flg':>3} {'upv':>3} {'ins':>4} {'kon':>4} {'bcs':>4}")
for i,p in enumerate(protos):
    nc, ni = p["nconst"], p["ninstr"]
    print(f"{i:>2} {p['id']:>10} {p['maxstack']:>4} {p['numparams']:>4} {p['flags']:>3} {p['nupvals']:>3} {ni:>4} {nc:>4} {len(p['z']):>4}")
pickle.dump(protos, open('protos.pkl','wb'))
