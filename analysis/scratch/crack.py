#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clean-room re-implementation of the Kryvex stage-2 inner cipher,
transcribed directly from the dumped Lua source (fn/kF, fn/kI, fn/kA,
fn/yJ, fn/yS, fn/kd, fn/bk and the vu()/RS() text inside fn/kn).

Nothing here is shared with oracle.py on purpose: this is an independent
second opinion used to localise the transcription fault.
"""
import math, sys, json

M   = 0x100000000          # 2^32
RC_ = 0x7FFFFFFF           # RS()'s modulus


# ---------------------------------------------------------------- bk (24 slots)
# RR[i][j] = xor-type  ->  xor(xor(a,b), KEY)
# RR[i][j] = add-type  ->  a + b - BIAS
XOR_SLOTS = {
    (0x35, 0x20): 0x074F4577, (0x60, 0x2D): 0x006C4CE3,
    (0x26, 0x32): 0x01EDBF73, (0x6A, 0x52): 0x0559A1A1,
    (0x75, 0x4C): 0x013AC7D1, (0x62, 0x78): 0x0569D8D9,
    (0x79, 0x4C): 0x06FC84C3, (0x6F, 0x51): 0x0644F76D,
    (0x7B, 0x21): 0x06138015, (0x1D, 0x20): 0x05EB887B,
}
ADD_SLOTS = {
    (0x35, 0x64): 0x7D0E8B9D, (0x60, 0x27): 0x7FBECC03,
    (0x26, 0x33): 0x73E976CB, (0x6A, 0x1B): 0x72903A7F,
    (0x75, 0x68): 0x4E85C005, (0x62, 0x64): 0x7436E41F,
    (0x79, 0x6B): 0x4D33E13B, (0x6F, 0x5E): 0x4B0DACD1,
    (0x7B, 0x63): 0x6B33BDB9, (0x1D, 0x51): 0x5969A577,
}


def O(i, j, a, b):
    """Evaluate R[i][j](a,b)."""
    if (i, j) in XOR_SLOTS:
        return (a ^ b ^ XOR_SLOTS[(i, j)])
    if (i, j) in ADD_SLOTS:
        return a + b - ADD_SLOTS[(i, j)]
    raise KeyError(hex(i) + "," + hex(j))


# ------------------------------------------------------- yJ: Ro (xor32), Rd (rotl32)
def Ro(a, b):
    """yJ's Rk(): byte-table 32-bit xor.  Drops everything above bit 31."""
    return (a % M) ^ (b % M)


def Rd(v, k):
    """yJ's Rb(): ((v*2^k) % 2^32) + floor(v/(2^32/2^k))  ==  rotl32."""
    v %= M
    return ((v << k) % M) + (v >> (32 - k)) if k else v % M


# ------------------------------------------------------------ kA: RX (xor), Rk (rotr8)
def kA_xor(a, b):
    """kA's RR(): schoolbook bit adder == xor for non-negative ints."""
    return (a % M) ^ (b % M)


def rotr8(r, k):
    """kA's Rv(): ((R*(256/2^k))%256) + ((R-R%2^k)/2^k)  ==  rotr8."""
    r &= 0xFF
    if k == 0:
        return r
    return ((r << (8 - k)) & 0xFF) + (r >> k)


# ------------------------------------------------------------------------ kF -> RZ
def lua_number_tostring(x):
    """Lua 5.1 / Luau  %.14g  rendering of a double."""
    return ('%.14g' % x)


def compute_RZ(verbose=False):
    RR = 395934548
    terms = []

    # t1 = string.byte( string.sub( floor(0x60EB8AC9F93) ), 9 )
    s1 = lua_number_tostring(float(math.floor(0x60EB8AC9F93)))
    t1 = ord(s1[8]) if len(s1) >= 9 else 0
    terms.append(("t1 byte9 of %r" % s1, t1))
    RR = (RR * 0x6BFD + t1) % M

    # t2 = 0x1B142453 % 0xA7FF
    t2 = 0x1B142453 % 0xA7FF
    terms.append(("t2 const", t2))
    RR = (RR * 0x8C2D + t2) % M

    # t3 = #string.sub( floor(0x33669CD7BAC) )
    s3 = lua_number_tostring(float(math.floor(0x33669CD7BAC)))
    t3 = len(s3)
    terms.append(("t3 #digits of %r" % s3, t3))
    RR = (RR * 60685 + t3) % M

    # t4 = floor(sqrt(0x536C3806B9)) % 256
    t4 = int(math.floor(math.sqrt(0x536C3806B9))) % 0x100
    terms.append(("t4 floor sqrt %%256", t4))
    RR = (RR * 0x18BD + t4) % M

    # t5 = (type(0xB948*1)=="number") and 0x1D88 or 59214
    t5 = 0x1D88
    terms.append(("t5 type==number", t5))
    RR = (RR * 25445 + t5) % M

    # t6 = string.byte("`wqrB",2)
    t6 = ord('w')
    terms.append(("t6 byte2 `wqrB", t6))
    RR = (RR * 0x20D7 + t6) % M

    # t7 = floor(0x5E8478790C6/7) % 37661
    t7 = int(math.floor(0x5E8478790C6 / 7.0)) % 37661
    terms.append(("t7 floor(/7)%%37661", t7))
    RR = (RR * 0xF4B7 + t7) % M

    if verbose:
        for n, v in terms:
            print("   %-28s = %d" % (n, v))
    return RR


# --------------------------------------------------------------------------- kI
def Rf(b, k, y):
    """kI's inner PRF.  v = Ro(xor32), j = Rd(rotl32)."""
    RR = Ro(b, (O(0x6A, 0x1B, 0xF8A866FE, 404704570) * (k + 1)) % M)
    RR = Ro(Rd(RR, 0xD), Rd(RR, 0x7))
    lo = RR % 0x10000
    hi = (RR - lo) // 0x10000
    Rj = (lo * (0x1F3A5 + k * 0x9E37) + hi * (0x2C1B3 + k * 0x4F17)
          + 0x13F7 * (k + 1)) % M
    return Ro(Rj, (O(0x60, 0x27, 0xEA5040AB, 458905027) * (y + 1)) % M)


def kI(RZ, k0, b0, y0, C0, verbose=False):
    """Rb,Rf,RU,k,b,y,C = kI(Rv,vX,RZ,Ro,Rd,vy,Rc,RF,Ru,Rx).  f(=vX) is irrelevant
    because both parity branches are algebraically identical."""
    RCa = [O(0x6A, 0x1B, 3922843976, 0x26D26433), O(0x75, 0x4C, 0x9EB4D866, 0x1108A892),
           O(0x6A, 0x1B, 0x113B86CD1, 0x0020C037AD), O(0x6F, 0x51, 0xB2750C21, 0x32B6226B),
           O(0x26, 0x32, 0x009EF73CD4, 1040712794), O(0x79, 107, 0x3205757E, 0x1C26AAC1),
           O(53, 0x64, 0xA64891D1, 0x2A7D83D3), O(117, 104, 0x524748BB, 0x3FBE373F)]
    RXa = [O(29, 32, 2563150964, 277228403), O(0x6A, 82, 0xFB5791F7, 340768680),
           O(0x6A, 0x52, 0x350809FA, 361509376), O(123, 0x63, 0x14ED16EC9, 0x10FEEBB7),
           O(0x75, 0x68, 0x00BE7C1AFE, 0x36E1A6AC), O(0x6A, 0x1B, 0xC5B65069, 0x29E7076C),
           O(0x6F, 0x51, 0x0000B10A0470, 422166317), O(0x75, 0x68, 0x9053EB43, 912679284)]
    Rsa = [O(111, 81, 0x191CD804, 0x1F582F6A), O(0x1D, 0x51, 0x0037559378, 571740672),
           O(53, 0x000064, 0x5CF1384C, 538792791), O(121, 0x00006B, 901970920, 393274714),
           O(0x35, 100, 0x65AFE157, 392079950), O(0x62, 120, 0x1F0B0FC1, 442685210),
           O(0x0026, 51, 873077588, 0x3FDF5B7B), O(0x26, 0x32, 0x2D5FCDDE, 0x00002CB272A8)]

    Rb = {}
    for i in range(8):
        Rb[Rsa[i]] = (Ro(RCa[i], RXa[i]) + 0x243DB52F + 0xDBC24AD1) % M
    if verbose:
        print("   Rb keys      =", sorted(Rb.keys()))
        print("   Rb values    =", [Rb[x] for x in sorted(Rb.keys())])

    key1 = O(0x62, 120, 0x1F0B0FC1, 0x1A62D71A)
    kk   = O(0x60, 0x2D, 0x11415767, 0x112D1BDE)
    yy   = O(0x35, 0x64, 0x696EF5DD, 0x139F95C9)
    Ry   = Rf(Ro(Rb[key1], (RZ * 0x07A05 + 0x2452BA5D) % M), kk, yy)
    if verbose:
        print("   key1=%d kk=%d yy=%d  Ry=%d" % (key1, kk, yy, Ry))

    k = Ro(k0, Ry % M)
    b = Ro(b0, math.floor(Ry / M) % M)
    y = Ro(y0, math.floor(Ry / 0x10000) % M)
    C = Ro(C0, math.floor(Ry / 0x1000000) % M)

    key2 = O(0x079, 0x0006B, 901970920, 393274714)
    yy2  = O(0x26, 0x000033, 987394387, 0x390F057F)
    mod  = O(121, 76, 0x658BE47A, 478715719)
    RU = ((Rf(Ro(Rb[key2], (RZ * 0x4BBD + 0x48221848) % M), kk, yy2)
           + k * 0x10001 + b * 0x101 + y * 0x11 + C) % mod) + 1
    if verbose:
        print("   key2=%d yy2=%d mod=%d" % (key2, yy2, mod))
        print("   va(RU)=%d   k,b,y,C = %d,%d,%d,%d" % (RU, k, b, y, C))
    return Rb, RU, k, b, y, C


def compute_RV(Rp, RZ, verbose=False):
    """RV = RT(Ro(Rp[idx],(RZ*0x1F33+0xB7D0034E)%2^32), k2, y3)"""
    idx = O(0x00026, 51, 873077588, 0x3FDF5B7B)
    k2  = O(0x62, 0x64, 0x447C0104, 0x2FBAE375)
    y3  = O(0x0006A, 0x52, 0x0003848B5A5, 0x3D111408)
    b   = Ro(Rp[idx], (RZ * 0x001F33 + 0xB7D0034E) % M)
    if verbose:
        print("   RV: idx=%d k2=%d y3=%d b=%d" % (idx, k2, y3, b))
    return Rf(b, k2, y3)


# --------------------------------------------------------------------- RS / Rw / kj
P1 = O(0x79, 0x6B, 240575207, 0x0003EDEBA07) % 0x10000          # 48051
P2 = O(38, 0x32, 0x71479ABB, 606349989) % 0x10000               # 3949
XV = O(0x26, 0x32, 0x71479ABB, 606349989)                       # full xor value
A1 = O(0x79, 0x6B, 240575207, 1054784007) % 0x1D
A2 = O(0x26, 0x32, 0x71479ABB, 606349989)


class Cipher:
    """vf()/RS()/Rw()/kj() over the stage-2 byte string."""

    def __init__(self, data, va, st):
        self.d = data
        self.pos = 0            # 0-based cursor;  Rm = pos+1
        self.va = va
        self.Rc, self.RF, self.Ru, self.Rx = st
        self.vU = 4
        self.n = 0

    # vf(): RR = string.byte(vh,Rm,Rm); Rm = Rm+1
    def vf(self):
        b = self.d[self.pos]
        self.pos += 1
        return b

    # RR[41] RR[48] RR[82] RR[22]
    def c41(self, R):
        return (R + 256 - ((self.Rx + (self.vU % 256) * 7) % 256)) % 256

    def c48(self, R):
        return rotr8(R, 3)

    def c82(self, R):
        return kA_xor(R, self.Ru)

    def c22(self, R):
        return (R + 256 - ((self.Rc + self.RF + (self.vU % 256) * 0xC3) % 256)) % 256

    # RR[44] RR[96] RR[12] RR[40]
    def u44(self, R, v):
        self.Rc = kA_xor(rotr8((self.Rc + R + self.Rx + (self.vU % 256)) % 256, 5), v)

    def u96(self, R, v):
        self.RF = rotr8((self.RF * 5 + v + kA_xor(R, self.Rc)) % 256, 2)

    def u12(self, R, v):
        self.Ru = kA_xor(rotr8((self.Ru + R + v + self.RF + 7) % 256, 5), self.Rx)

    def u40(self, R, v):
        self.Rx = rotr8((self.Rx + v + R + self.Rc + self.Ru + 7) % 256, 1)

    def RS(self):
        RW = self.vf()
        self.vU = self.pos            # Rm-1 where Rm is post-increment
        Rz = RW
        for fn in (self.c41, self.c48, self.c82, self.c22):
            Rz = fn(Rz)
        Ry = Rz
        RO = self.vU % RC_
        Rt = self.va % RC_
        RE = (Rt + RO * P1 + (XV % RC_)) % RC_
        RL = (Rt * 0x101 + RO * P2 + P1 * 0x11) % RC_
        for _ in range(3):
            nRE = (RE * ((RL % 0x10000) + P1 + 0x101) + RL * 0x101
                   + RO * (0x11 + XV % 0x1F) + Rt) % RC_
            nRL = (RL * ((nRE % 0x10000) + P2 + 0x107) + nRE * 0x81
                   + RO * (0x17 + A1) + XV) % RC_
            RE, RL = nRE, nRL
        RA = (RE % 256 + (RL % 256) * 3 + (RO % 256) * 5
              + ((RE - RE % 256) // 256) % 256
              + ((RL - RL % 256) // 256) % 256) % 256
        Ry = kA_xor(Ry, RA)
        self.u44(Ry, RW)
        self.u96(Ry, RW)
        self.u12(Ry, RW)
        self.u40(Ry, RW)
        self.n += 1
        return Ry % M

    # yS's Rv()  -> little endian u32
    def Rw(self):
        a, b, c, d = self.RS(), self.RS(), self.RS(), self.RS()
        return a + d * 16777216 + b * 256 + c * 0x10000

    # yS's RC()  -> sign-extended u32
    def kj(self):
        v = self.Rw()
        return v - 0x80000000 - 0x80000000 if v >= 0x80000000 else v


def run(verbose=True):
    data = open('/home/user/OBF/analysis/stage2_bytecode.bin', 'rb').read()
    if verbose:
        print("stage2 len =", len(data), " first8 =", list(data[:8]))

    RZ = compute_RZ(verbose)
    print("RZ = %d = 0x%08X" % (RZ, RZ))

    c0 = Cipher(data, 0, (0, 0, 0, 0))
    b0 = [c0.vf() for _ in range(4)]
    print("initial 4 bytes (Rc,RF,Ru,Rx seeds) =", b0)

    Rp, va, k1, b1, y1, C1 = kI(RZ, b0[0], b0[1], b0[2], b0[3], verbose)
    RV = compute_RV(Rp, RZ, verbose)
    print("va = %d      RV = %d = 0x%08X" % (va, RV, RV))
    print("post-kI state (Rc,RF,Ru,Rx) = %d,%d,%d,%d" % (k1, b1, y1, C1))

    c = Cipher(data, va, (k1, b1, y1, C1))
    c.pos = 4

    kE = kA_xor(c.Rw(), RV)
    kz = kA_xor(c.Rw(), kA_xor(Rd(kE, 0x5), Rd(RV, 0xB)))
    kP = kA_xor(c.Rw(), kA_xor(Rd(kE, 0xD), Rd(RV, 0x13)))
    yE, yt, yl, yQ = c.RS(), c.RS(), c.RS(), c.RS()
    print("kE=0x%08X kz=0x%08X kP=%d(0x%08X)" % (kE, kz, kP, kP))
    print("yE=%d yt=%d yl=%d yQ=%d" % (yE, yt, yl, yQ))

    # kd: kQ = xor32(Rw(), xor32(rotl(kE,11), rotl(RV,7)))
    kQ = Ro(c.Rw(), Ro(Rd(kE, 0xB), Rd(RV, 0x7)))
    print("kQ = %d" % kQ)

    ok_yt = yt <= 8
    ok_yQ = yQ <= 64
    ok_kQ = 0 < kQ < 30000
    print("ORACLE: yt<=8 %s | yQ<=64 %s | 0<kQ<30000 %s"
          % (ok_yt, ok_yQ, ok_kQ))
    return dict(RZ=RZ, va=va, RV=RV, kE=kE, kz=kz, kP=kP,
                yE=yE, yt=yt, yl=yl, yQ=yQ, kQ=kQ)


if __name__ == '__main__':
    run()
