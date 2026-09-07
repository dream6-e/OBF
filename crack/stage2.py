import re, struct, pickle, math

# ---------------- stage 1: blobs & tables ----------------
def get_blob(fn):
    src = open(fn).read()
    strs = re.findall(r'"((?:[^"\\]|\\.)*)"', src)
    return max(strs, key=len)

def base86_decode(s):
    s = s.encode('latin-1')
    out = bytearray(); n = len(s); full = n - n % 5; pos = 0
    def charval(c):
        assert 35 <= c <= 121 and c != 92, f"bad char {c}"
        return c - 36 if c > 92 else c - 35
    while pos < full:
        v = 0; mul = 1
        for q in range(5):
            v += charval(s[pos+q]) * mul; mul *= 86
        assert v <= 0xFFFFFFFF
        for _ in range(4):
            out.append(v % 256); v = (v - v % 256)//256
        pos += 5
    rem = n % 5
    if rem == 1: raise ValueError("rem1")
    if rem > 0:
        v = 0; mul = 1
        for q in range(rem):
            v += charval(s[n-rem+q])*mul; mul *= 86
        assert v <= 256**(rem-1)-1
        for _ in range(rem-1):
            out.append(v % 256); v = (v - v%256)//256
    return bytes(out)

h  = base86_decode(get_blob('funcs/f_1199.lua'))
df = base86_decode(get_blob('funcs/f_6382.lua'))
mu = base86_decode(get_blob('funcs/f_400.lua'))
print("blob bytes:", len(h), len(df), len(mu))

# opcode class table & canonical remap table  ([8948])
lits = re.findall(r'"((?:[^"\\]|\\.)*)"', open('funcs/f_8948.lua').read())
def cv(c): return c-1 if c > 92 else c
cls_s, rem_s = lits[0], lits[1]
ab = {}
for q in range(2, len(cls_s)+1):        # lua 1-based
    c = cv(ord(cls_s[q-1]))
    ab[q-2] = (c-61) % 86 + 1
we = {}
q = 2; idx = 0
while q+1 <= len(rem_s):
    c1 = cv(ord(rem_s[q-1])); c2 = cv(ord(rem_s[q]))
    we[idx] = (c1-35) + (c2-35)*86
    q += 2; idx += 1
print("class entries:", len(ab), " remap entries:", len(we))
print("classes used:", sorted(set(ab.values())))

# ---------------- magic check ([2352] on h) ----------------
magic = ((h[0]*256 + h[1])*256 + h[2])*256 + h[3]
print("magic u32 =", magic, "(expect 1482183482)", hex(magic))

# ---------------- [2086] keystream decryption ----------------
def lcg48271(seed, iters):
    j = seed
    for _ in range(iters):
        j = 48271 * j % 2147483647
    return j

wu = lcg48271((4861*31 + 2003) % 2147483647, 6)   # [8961]
jr = lcg48271((7244*31 + 8266) % 2147483647, 6)   # [2003]
hg = lcg48271((9025*31 + 4632) % 2147483647, 6)   # [4861]
blob_all = h + df + mu
b_in = blob_all[4:]                                # sub(_,5)
seed = 1 + (wu + jr + hg + 31*len(b_in)) % 2147483646
out = bytearray()
s_ = seed
for byte in b_in:
    s_ = 48271 * s_ % 2147483647
    out.append(byte ^ (s_ % 256))
b = bytes(out)
print("decrypted len:", len(b))
print("header:", b[:32].hex(' '))
print("magic4:", list(b[:4]), [chr(x) for x in b[:4]], "subver:", b[4], "ver:", list(b[5:8]))
hdr_size = struct.unpack('<I', b[12:16])[0]
file_size = struct.unpack('<I', b[16:20])[0]
nprotos = struct.unpack('<I', b[20:24])[0]
f56 = struct.unpack('<I', b[24:28])[0]
f4 = struct.unpack('<I', b[28:32])[0]
adler_stored = struct.unpack('<I', b[32:36])[0]
print(f"hdr_size={hdr_size} file_size={file_size} nprotos={nprotos} x56={f56} flag={f4} adler={adler_stored}")
a1, a2 = 1, 0
for byte in b[32:]:
    a1 = (a1 + byte) % 65521
    a2 = (a2 + a1) % 65521
print("adler computed:", a1 + a2*65536, "match:", a1 + a2*65536 == adler_stored)
pickle.dump({'b': b, 'ab': ab, 'we': we, 'h':h,'df':df,'mu':mu}, open('stage2.pkl','wb'))
