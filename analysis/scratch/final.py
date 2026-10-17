#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fresh, third clean-room implementation of the Kryvex stage-2 inner cipher.
Every numeric literal is taken from the verbatim dumps in fn/*.lua read this
round.  Prints every intermediate so divergences are visible.

KEY REALISATION: there is NO unknown key.  Every input to RS()/Rw() is derived
from (a) vh = stage2_bytecode.bin, (b) RZ = a pure constant, (c) the four
initial bytes vh[1..4].  So a failing kQ means a transcription/semantics bug,
not a missing secret.
"""
import math, sys

class Fail(Exception):
    pass


M = 0x100000000          # 2^32
RC7 = 0x7FFFFFFF         # RS()'s modulus

# ------------------------------------------------------------------ bk slots
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


def O(i, j, *args):
    """Evaluate Rv[i][j](args...).  Lua semantics:
       xor slot -> bit32.bxor(KEY, bit32.bxor(b,a))  == (a^b^KEY) normalised u32
       add slot -> a + b - BIAS                      (NO normalisation)"""
    if len(args) == 1:
        if (i, j) == (0x6C, 0x11):
            return args[0]
        if (i, j) == (0x66, 0x19):
            return args[0] & 0xFFFFFFFF      # Rb(R,0xFFFFFFFF) = band
        if (i, j) == (0x66, 122):
            return (args[0] - args[0] % 2) // 2   # RC(R,1) = rshift
        raise KeyError((hex(i), hex(j)))
    a, b = args
    if (i, j) in XOR_SLOTS:
        return ((a % M) ^ (b % M) ^ XOR_SLOTS[(i, j)]) % M
    if (i, j) in ADD_SLOTS:
        return a + b - ADD_SLOTS[(i, j)]
    raise KeyError((hex(i), hex(j)))


# ------------------------------------------------- yJ returns: vz(table), Ro(xor32), Rd(rotl32)
def Ro(v, k):
    """yJ's inner Rk(): 4-byte table xor -> exact u32 xor."""
    return (int(v) % M) ^ (int(k) % M)


def Rd(v, k):
    """yJ's inner Rb(): ((v*2^k)%2^32) + floor(v/(2^32/2^k)) == rotl32."""
    v = int(v) % M
    k = int(k)
    if k == 0:
        return v
    return ((v << k) % M) + (v >> (32 - k))


# ----------------------------------------- kA returns: RX(xor), Rk(rotr8-within-a-byte)
def RX(a, b):
    return (int(a) % M) ^ (int(b) % M)


def rotr8(R, v):
    """kA's Rv(): ((R*(256/2^v))%256) + ((R-R%2^v)/2^v)  == rotate-right v in 8 bits."""
    R = int(R) % 256
    v = int(v)
    if v == 0:
        return R
    return ((R << (8 - v)) & 0xFF) + (R >> v)


# --------------------------------------------------------- kF -> vX(host), RZ(const)
def g14(x):
    """Lua 5.1/Luau tostring() of an integral double == '%.14g'."""
    return '%.14g' % x


def compute_RZ(verbose=True):
    RR = 395934548
    t = []
    # t1 = string.byte(tostring(math.floor(0x60EB8AC9F93)), 9)
    s1 = g14(float(math.floor(0x60EB8AC9F93)))
    t1 = ord(s1[8]) if len(s1) >= 9 else None
    t.append(('t1', 'string.byte(tostring(floor(0x60EB8AC9F93)),9)', s1, t1))
    RR = (RR * 0x6BFD + t1) % M
    # t2 = 0x1B142453 % 0xA7FF
    t2 = 0x1B142453 % 0xA7FF
    t.append(('t2', '0x1B142453 %% 0xA7FF', '', t2))
    RR = (RR * 0x8C2D + t2) % M
    # t3 = #tostring(math.floor(0x33669CD7BAC))
    s3 = g14(float(math.floor(0x33669CD7BAC)))
    t3 = len(s3)
    t.append(('t3', '#tostring(floor(0x33669CD7BAC))', s3, t3))
    RR = (RR * 60685 + t3) % M
    # t4 = math.floor(math.sqrt(0x536C3806B9)) % 0x100
    t4 = int(math.floor(math.sqrt(float(0x536C3806B9)))) % 0x100
    t.append(('t4', 'floor(sqrt(0x536C3806B9))%%256', '', t4))
    RR = (RR * 0x18BD + t4) % M
    # t5 = type(0xB948*1)=="number" and 0x1D88 or 59214
    t5 = 0x1D88
    t.append(('t5', 'type==number -> 0x1D88', '', t5))
    RR = (RR * 25445 + t5) % M
    # t6 = string.byte("`wqrB",2)
    t6 = ord('`wqrB'[1])
    t.append(('t6', 'string.byte("`wqrB",2)', '', t6))
    RR = (RR * 0x20D7 + t6) % M
    # t7 = math.floor(0x5E8478790C6/0x7) % 37661
    t7 = int(math.floor(float(0x5E8478790C6) / 7.0)) % 37661
    t.append(('t7', 'floor(0x5E8478790C6/7)%%37661', '', t7))
    RR = (RR * 0xF4B7 + t7) % M
    if verbose:
        for n, d, s, v in t:
            print('   %-4s %-42s %-16s = %s' % (n, d, repr(s), v))
    return RR


# ---------------------------------------------------------------- the byte stream
class Stream:
    """vh / Rm / vf() / RS() / Rw() / kj() exactly as in kn."""

    def __init__(self, data, verbose=False):
        self.vh = data
        self.Rm = O(0x26, 0x32, 0x22F953DC, 0x2314ECAE)   # == 1
        assert self.Rm == 1
        self.v = verbose
        # local Rc,RF,Ru,Rx = vf(),vf(),vf(),vf()
        self.Rc = self.vf(); self.RF = self.vf()
        self.Ru = self.vf(); self.Rx = self.vf()
        self.va = 0
        self.vU = 0x4
        self.nRS = 0

    def vf(self):
        """local function vf() local RR=Rq(vh,Rm,Rm) Rm=Rm+1 return RR end"""
        if self.Rm < 1 or self.Rm > len(self.vh):
            raise Fail('vf out of range Rm=%d len=%d' % (self.Rm, len(self.vh)))
        b = self.vh[self.Rm - 1]
        self.Rm += 1
        return b

    # ---- the eight RR[] closures of the do-block ----
    def RR48(self, R):
        return rotr8(R, 0x03)

    def RR41(self, R):
        RR = 0x100
        return (R + RR - ((self.Rx + (self.vU % RR) * 7) % RR)) % RR

    def RR40(self, R, v):
        self.Rx = rotr8((self.Rx + v + R + self.Rc + self.Ru + 0x7) % 0x100, 1)

    def RR60(self, R, v):
        self.RF = rotr8((self.RF * 5 + v + RX(R, self.Rc)) % 0x100, 2)

    def RR12(self, R, v):
        self.Ru = RX(rotr8((self.Ru + R + v + self.RF + 0x7) % 0x100, 0x5), self.Rx)

    def RR44(self, R, v):
        self.Rc = RX(rotr8((self.Rc + R + self.Rx + (self.vU % 0x100)) % 0x100, 0x5), v)

    def RR82(self, R):
        return RX(R, self.Ru)

    def RR22(self, R):
        RR = 0x100
        return (R + RR - ((self.Rc + self.RF + (self.vU % RR) * 0xC3) % RR)) % RR

    Rb_chain = [41, 48, 82, 0x16]

    def RS(self):
        """RS() verbatim from kn_pp.lua lines 2216-2251."""
        RC, Rk, Rj, Rf, RU, RM, Rd_ = 0x7FFFFFFF, 0x100, 0x71479ABB, 606349989, 0x10000, 0x101, 0x32
        Ry = 0
        Rs = -3
        while True:
            RW = self.vf()
            self.vU = self.Rm - 1
            Rz = RW
            RQ = 1
            while RQ <= 4:
                idx = self.Rb_chain[RQ - 1]
                Rz = {41: self.RR41, 48: self.RR48, 82: self.RR82, 0x16: self.RR22}[idx](Rz)
                RQ += 1
            Ry = Rz
            RO = self.vU % RC
            RP = O(0x79, 0x6B, 240575207, 0x3EDEBA07) % RU
            RH = O(0x26, 0x32, Rj, Rf) % RU
            Rt = self.va % RC
            RE = (Rt + RO * RP + (O(0x26, 0x32, Rj, Rf) % RC)) % RC
            RL = (Rt * RM + RO * RH + RP * 0x11) % RC
            for _ in range(3):
                RR2 = (RE * ((RL % RU) + RP + RM) + RL * RM + RO * (0x11 + O(0x26, 0x32, Rj, Rf) % 0x1F) + Rt) % RC
                Rk2 = (RL * ((RR2 % RU) + RH + 0x107) + RR2 * 0x81 + RO * (0x17 + O(0x79, 0x6B, 240575207, 1054784007) % 0x1D) + O(0x26, 0x32, Rj, Rf)) % RC
                RE, RL = RR2, Rk2
            RA = (RE % Rk + (RL % Rk) * 0x3 + (RO % Rk) * 0x5 + ((RE - RE % Rk) // Rk) % Rk + ((RL - RL % Rk) // Rk) % Rk) % Rk
            Ry = RX(Ry, RA)
            self.RR44(Ry, RW)
            self.RR60(Ry, RW)
            self.RR12(Ry, RW)
            self.RR40(Ry, RW)
            if Rs > 81:
                Rs = -2
            Rs += 1
            if Rs >= -2:
                break
        self.nRS += 1
        return Ry

    def snap(self):
        return (self.Rm, self.Rc, self.RF, self.Ru, self.Rx, self.va, self.vU, self.nRS)

    def restore(self, sn):
        self.Rm, self.Rc, self.RF, self.Ru, self.Rx, self.va, self.vU, self.nRS = sn

    # ---- yS's returned readers ----
    def Rw(self):
        """yS's Rv(): 4 bytes little-endian u32 (the +-parity term always cancels)."""
        Rk, Ry, RC, Rb = self.RS(), self.RS(), self.RS(), self.RS()
        return (Rk + Rb * 16777216 + Ry * 256 + RC * 0x10000) + (Rk % 2 if Rk % 2 == 0 else (Rk % 2) - 1)

    def kj(self):
        """yS's RC(): signed interpretation of the LE u32."""
        Rk = self.Rw()
        Rb = 2147483648
        if Rk % 2 == 0:
            return (Rk - Rb - Rb) + (Rk % 2) if Rk - Rb >= 0 else Rk + (Rk % 2)
        return (Rk - Rb - Rb) + ((Rk % 2) - 1) if Rk - Rb >= 0 else Rk + ((Rk % 2) - 1)

    def ks(self):
        """yS's Ry(): u32 length then that many bytes."""
        n = self.Rw()
        if n == O(0x35, 0x20, 630668047, 0x22D87E78):
            return ''
        return bytes(self.RS() for _ in range(n))


# -------------------------------------------------------------------- kI
def kI(RZ, Rc, RF, Ru, Rx, verbose=True):
    """kI(self,R=Rv,f=vX,s=RZ,v=Ro,j=Rd,X=floor,k=Rc,b=RF,y=Ru,C=Rx)
       returns Rb(table), Rf(func), RU(=va), k,b,y,C"""
    RR = M
    Rj = lambda a, b: O(0x26, 0x32, a, b)          # R[38][0x32] = xor 0x1EDBF73

    RCa = [O(0x6A, 0x1B, 3922843976, 0x26D26433),
           O(0x75, 0x4C, 0x9EB4D866, 0x1108A892),
           O(0x6A, 0x1B, 0x113B86CD1, 0x20C037AD),
           O(0x6F, 0x51, 0xB2750C21, 0x32B6226B),
           O(0x26, 0x32, 0x9EF73CD4, 1040712794),
           O(0x79, 0x6B, 0x3205757E, 0x1C26AAC1),
           O(0x35, 0x64, 0xA64891D1, 0x2A7D83D3),
           O(0x75, 0x68, 0x524748BB, 0x3FBE373F)]
    RXa = [O(0x1D, 0x20, 2563150964, 277228403),
           O(0x6A, 0x52, 0xFB5791F7, 340768680),
           O(0x6A, 0x52, 0x350809FA, 361509376),
           O(0x7B, 0x63, 0x14ED16EC9, 0x10FEEBB7),
           O(0x75, 0x68, 0xBE7C1AFE, 0x36E1A6AC),
           O(0x6A, 0x1B, 0xC5B65069, 0x29E7076C),
           O(0x6F, 0x51, 0xB10A0470, 422166317),
           O(0x75, 0x68, 0x9053EB43, 912679284)]
    Rsa = [O(0x6F, 0x51, 0x191CD804, 0x1F582F6A),
           O(0x1D, 0x51, 0x37559378, 571740672),
           O(0x35, 0x64, 0x5CF1384C, 538792791),
           O(0x79, 0x6B, 901970920, 393274714),
           O(0x35, 0x64, 0x65AFE157, 392079950),
           O(0x62, 0x78, 0x1F0B0FC1, 442685210),
           O(0x26, 0x33, 873077588, 0x3FDF5B7B),
           O(0x26, 0x32, 0x2D5FCDDE, 0x2CB272A8)]
    if verbose:
        print('   RC =', RCa)
        print('   RX =', RXa)
        print('   Rs =', Rsa, '  (expect a permutation of 1..8)')

    Rb = {}
    for n in range(8):
        Rb[Rsa[n]] = (Rj(RCa[n], RXa[n]) + 0x243DB52F + 0xDBC24AD1) % RR
    if verbose:
        print('   Rb (key->val) =', {k: Rb[k] for k in sorted(Rb)})

    def Rf(b, k, y):
        Rv, Rk = M, 0x10000
        _unused = b % Rk
        RRx = Ro(b, (O(0x6A, 0x1B, 0xF8A866FE, 404704570) * (k + 1)) % Rv)
        RRx = Ro(Rd(RRx, 0xD), Rd(RRx, 0x7))
        Rb2 = RRx % Rk
        Ry2 = (RRx - Rb2) // Rk
        RCx = 0x1F3A5 + k * 0x9E37
        RXx = 0x2C1B3 + k * 0x4F17
        Rsx = 0x13F7 * (k + 1)
        Rj2 = (Rb2 * RCx + Ry2 * RXx + Rsx) % Rv
        return Ro(Rj2, (O(0x60, 0x27, 0xEA5040AB, 458905027) * (y + 1)) % Rv)

    kk1 = O(0x60, 0x2D, 0x11415767, 0x112D1BDE)
    if verbose:
        print('   Rf k-arg (all three calls) =', kk1)

    Ry0 = Rf(Ro(Rb[O(0x62, 0x78, 0x1F0B0FC1, 0x1A62D71A)], (RZ * 0x7A05 + 0x2452BA5D) % RR),
             kk1,
             O(0x35, 0x64, 0x696EF5DD, 0x139F95C9))
    if verbose:
        print('   Ry0 (=Rf#1)  =', Ry0, hex(Ry0))

    # kI's header is `local RR,Rv,Rk=0X100000000,0X100,0X6A`  ==>  Rv == 256 here!
    # k=v(k,Ry%Rv)  b=v(b,X(Ry/Rv)%Rv)  y=v(y,X(Ry/0X10000)%Rv)  C=v(C,X(Ry/0X1000000)%Rv)
    Rv256 = 0x100
    k = Ro(Rc, Ry0 % Rv256)
    b = Ro(RF, math.floor(Ry0 / Rv256) % Rv256)
    y = Ro(Ru, math.floor(Ry0 / 0x10000) % Rv256)
    C = Ro(Rx, math.floor(Ry0 / 0x1000000) % Rv256)
    if verbose:
        print('   Ry0 bytes (lo->hi) =', [Ry0 % 256, (Ry0 // 256) % 256, (Ry0 // 65536) % 256, (Ry0 // 16777216) % 256])
        print('   after rekey: Rc,RF,Ru,Rx =', k, b, y, C, '(all must be < 256)')
        assert max(k, b, y, C) < 256, 'rekey must keep byte range'

    RU = ((Rf(Ro(Rb[O(0x79, 0x6B, 901970920, 393274714)], (RZ * 0x4BBD + 0x48221848) % RR),
              kk1,
              O(0x26, 0x33, 987394387, 0x390F057F))
           + k * 0x10001 + b * 0x101 + y * 0x11 + C) % O(0x79, 0x4C, 0x658BE47A, 478715719)) + 1
    if verbose:
        print('   modulus O(0x79,0x4C) =', O(0x79, 0x4C, 0x658BE47A, 478715719))
        print('   va (=RU) =', RU)
    return Rb, Rf, RU, k, b, y, C


# --------------------------------------------------------------------- main
def main():
    data = open('data.bin', 'rb').read()
    print('vh len =', len(data), ' first 8 =', list(data[:8]))

    print('\n[1] kF -> RZ')
    RZ = compute_RZ()
    print('   RZ =', RZ, '= 0x%08X' % RZ)

    S = Stream(data)
    print('\n[2] init: Rm=1, Rc,RF,Ru,Rx = vh[1..4] =', S.Rc, S.RF, S.Ru, S.Rx, ' Rm now', S.Rm)

    print('\n[3] kI')
    Rp, RT, va, Rc2, RF2, Ru2, Rx2 = kI(RZ, S.Rc, S.RF, S.Ru, S.Rx)
    S.va, S.Rc, S.RF, S.Ru, S.Rx = va, Rc2, RF2, Ru2, Rx2

    print('\n[4] RV1 = RT(Ro(Rp[Rs7],(RZ*0x1F33+0xB7D0034E)%2^32), arg2, arg3)')
    Rs7 = O(0x26, 0x33, 873077588, 0x3FDF5B7B)
    arg2 = O(0x62, 0x64, 0x447C0104, 0x2FBAE375)
    arg3 = O(0x6A, 0x52, 0x3848B5A5, 0x3D111408)
    print('   Rs7=%d arg2=%d arg3=%d  Rp[Rs7]=%d' % (Rs7, arg2, arg3, Rp[Rs7]))
    RV1 = RT(Ro(Rp[Rs7], (RZ * 0x1F33 + 0xB7D0034E) % M), arg2, arg3)
    print('   RV1 =', RV1, '= 0x%08X' % RV1)

    print('\n[5] vu state 3358  (Rm=%d before)' % S.Rm)
    w1 = S.Rw(); kE = RX(w1, RV1)
    w2 = S.Rw(); kz = RX(w2, RX(Rd(kE, 0x5), Rd(RV1, 0xB)))
    w3 = S.Rw(); kP = RX(w3, RX(Rd(kE, 0xD), Rd(RV1, 0x13)))
    yE = S.RS(); yt = S.RS(); yl = S.RS(); yQ = S.RS()
    print('   Rw1..3 = %d %d %d' % (w1, w2, w3))
    print('   kE=0x%08X kz=0x%08X kP=0x%08X' % (kE, kz, kP))
    print('   yE=%d yt=%d yl=%d yQ=%d' % (yE, yt, yl, yQ))
    print('   Rm now', S.Rm, ' nRS', S.nRS)

    print('\n[6] kd: kQ = RX(Rw(), RX(rotl(kE,11), rotl(RV1,7)))')
    w5 = S.Rw()
    kQ = RX(w5, RX(Rd(kE, 0xB), Rd(RV1, 0x7)))
    print('   Rw =', w5, ' -> kQ =', kQ)
    print('   ORACLE: kQ must be <= 7461   ==>  %s' % ('PASS' if 0 <= kQ <= 7461 else 'FAIL'))


if __name__=='__main__':
    main()


# ============================================================================
#  FULL RECURSIVE vu() PARSE
# ============================================================================
OPS = {}
RI_KEY_4  = O(0x1D, 0x20, 0x15D0CC6B, 0x103B4414)     # -> ks()  (string)
RI_KEY_26 = O(0x1D, 0x51, 893299098, 0x242AFBF7)      # -> 8 bytes
RI_KEY_56 = O(0x6F, 0x5E, 0x229043FB, 0x287D690E)     # -> 8 bytes
RI_KEY_44 = O(0x79, 0x6B, 867642701, 427602970)       # -> 0 bytes
RI_KEY_228 = 228                                      # -> 0 bytes
RC_VU = 2          # vu()'s  local RU,RW,RC,Rs = 0X208FEE2B,646378259,0X2,0X7F
RS_VU = 0x7F


class Proto(dict):
    pass


def vu(S, RV, depth, log, CTX):
    """One full vu() invocation.  Returns (proto, RV_after)."""
    p = Proto()
    # ---------------- state 3358 ----------------
    p['kE'] = RX(S.Rw(), RV)
    p['kz'] = RX(S.Rw(), RX(Rd(p['kE'], 0x5), Rd(RV, 0xB)))
    p['kP'] = RX(S.Rw(), RX(Rd(p['kE'], 0xD), Rd(RV, 0x13)))
    p['yE'] = S.RS(); p['yt'] = S.RS(); p['yl'] = S.RS(); p['yQ'] = S.RS()
    hdr_end = S.Rm
    # ---------------- state 6806 -> kd ----------------
    kM, kL, kW, kO = {}, {}, {}, {}
    Rs_ = p['kz']; Rk_ = p['kP']
    Rj_ = RX(Rs_, Rk_)
    Rd_ = RX(Rs_, Rj_)          # == kP
    RM_ = RX(Rk_, Rj_)          # == kz
    RL_ = RX(RX(RX(589742, 0x720EE), 0xC33D6FB1), RX(Rd(p['kE'], 3), Rd(RV, 7)))
    RW_ = RX(RX(RX(0x10599, 0x8B73), 4132475171), RX(Rd(Rs_, 9), Rd(RV, 0xD)))
    RO_ = RX(RX(RX(152743, 491838), 1555620535), RX(Rd(Rk_, 0xF), Rd(p['kE'], 0x15)))
    RE_ = RX(RX(RX(331361, 863629), 1213750126), RX(Rd(RV, 0x11), Rd(Rs_, 0x19)))
    RRr = RX(RX(p['kE'], Rd(Rs_, 7)), RX(Rd(Rk_, 0xD), Rd(RV, 0x13)))

    def kd_Rf(v, k, b, y):
        if v < 0:
            v += M
        v = RX(RX(v, b), RX(k, y))
        if v >= 0x80000000:
            v -= M
        return v

    kQ = RX(S.Rw(), RX(Rd(p['kE'], 0xB), Rd(RV, 0x7)))
    p['kQ'] = kQ
    if kQ > 7461:
        raise Fail('kQ=%d exceeds budget' % kQ)
    extra = 0
    raw = []
    for Rb_i in range(1, kQ + 1):
        Ryv = S.Rw()                       # raw u32  = field 1 (opcode word)
        RCv = RX(Ryv, RX(Rs_, RRr % 0x10000000))
        kM[Rb_i + Rk_] = RCv
        X1 = S.kj()                        # raw signed = field 2
        RXv = RX(X1 % M, RX(Rd(RRr, 5), p['kE']))
        kL[Rb_i + Rk_] = RX(RXv, Rj_)
        RUv = RX(RL_, Rd(RRr, 0xB))
        RQv = RX(RW_, Rd(RRr, 0x11))
        X2 = S.kj()                        # raw signed = field 3
        kW[Rb_i + Rk_] = RX(kd_Rf(X2, RCv, RUv, RO_) % M, Rd_)
        X3 = S.kj()                        # raw signed = field 4
        kO[Rb_i + Rk_] = RX(kd_Rf(X3, RCv, RQv, RE_) % M, RM_)
        raw.append((Ryv, X1, X2, X3))
        RRr = RX((Rd(RRr, 7) + RCv) % M, RXv)
        Rz = ((Ryv - (Ryv % 0x20000000)) // 0x20000000) % 4
        for _ in range(Rz):
            RRr = (Rd(RRr, 3) + S.RS() + 0x3D) % M
            extra += 1
    p['raw'] = raw
    p['extra'] = extra
    RV2 = RX(RV, Rd(RRr, 9))
    kd_end = S.Rm
    # ---------------- state 12057 ----------------
    RH = S.RS()
    if RH not in (0, 1, 2, 3) and not (RH >= 3):
        raise Fail('RH=%d' % RH)
    ENVV, _k, _c, _y = kH_envval(RH, CTX['Rp'], CTX['RZ'], CTX['Rf'])
    cpool, cpool2, RE2, words = kH_full(p, kM, kL, kW, kO, RH, ENVV)
    p['words'] = words; p['cpool'] = cpool; p['cpool2'] = cpool2
    Rz2 = RX(RX(RX(p['kE'], Rd(p['kz'], 0xB)), RX(Rd(p['kP'], 0x13), Rd(RE2, 5))), Rd(RV2, 0x17))
    Rs2 = RX(RX(RX(p['kE'], p['kz']), RX(Rd(p['kP'], 7), Rd(RE2, 0xD))), Rd(RV2, 0x11))
    Rh = RX(S.Rw(), RX(Rd(p['kE'], 9), Rd(RV2, 0xF)))
    p['RH'] = RH; p['Rh'] = Rh
    consts = {}
    if Rh > 100000: raise Fail('Rh=%d implausible' % Rh)
    for RQ2 in range(1, Rh + 1):
        op = S.RS()
        _Rv = RX(S.Rw(), RX(Rs2, RX(Rd(p['kz'], (RQ2 % 0xD) + 1), (RQ2 * 0x4003) % M))) + 1
        OPS[op] = OPS.get(op,0)+1
        if op == RI_KEY_4:
            n = S.Rw()
            if n > 8192: raise Fail('ks length %d implausible at Rm=%d' % (n, S.Rm))
            consts[_Rv] = ('str', bytes(S.RS() for _ in range(n)))
        elif op in (RI_KEY_26, RI_KEY_56):
            consts[_Rv] = (op, bytes(S.RS() for _ in range(8)))
        elif op in (RI_KEY_44, RI_KEY_228):
            consts[_Rv] = (op, None)
        else:
            consts[_Rv] = ('plain', op)
        # Rs2 running checksum (does not affect the byte stream)
    RV3 = RX(RX(Rd(RV2, 7), Rd(RE2, 0xD)), RX(Rs2, p['kE']))
    s12057_end = S.Rm
    if depth == 0:
        known = {RI_KEY_4, RI_KEY_26, RI_KEY_56, RI_KEY_44, RI_KEY_228}
        tot = sum(OPS.values()); hit = sum(v for k, v in OPS.items() if k in known)
        print('   [12057] RH=%d  Rh=%d  bytes %d..%d' % (RH, Rh, kd_end, s12057_end))
        print('   [12057] opcode histogram: %d rounds, %d hit the 5 RI keys (%.1f%%)' % (tot, hit, 100.0*hit/max(tot,1)))
        print('   [12057] top opcodes:', sorted(OPS.items(), key=lambda kv: -kv[1])[:14])
        print('   [12057] RE2(kH checksum)=%d  Rs2=0x%08X Rz2=0x%08X RV2=0x%08X RV3=0x%08X' % (RE2, Rs2, Rz2, RV2, RV3))
    # ---------------- state 15450 ----------------
    Rw4 = S.Rw()
    budget_left = len(S.vh) - (S.Rm - 1)
    nChild, RV3, children, RVafter = search_nchild(S, Rw4, p['kE'], depth, budget_left)
    if depth == 0:
        A = RX(Rd(RV2, 7), Rd(RE2, 0xD))
        Rs_final = RX(A, RX(RV3, p['kE']))
        print('   [15450] Rw4=0x%08X  A=0x%08X  SOLVED nChild=%d -> RV3=0x%08X  (implies Rs_final=0x%08X)'
              % (Rw4, A, nChild, RV3, Rs_final))
    p['nChild'] = nChild
    p['children'] = children
    p['kM'], p['kL'], p['kW'], p['kO'] = kM, kL, kW, kO
    p['consts'] = consts
    p['RV3'] = RV3
    # ---------------- states 19613 / 23216 : no bytes ----------------
    return p, RVafter


# yD's method-body-scope `local Rb` == Ry[0x679BA927], used by kH when RH==1.
#   local Rb=b(X(y[R[0X6F][0X51](421320708,0X1F582F6A)],(C*0X0D3B7+0X51B8D476)%Ry),1,R[0X7B][33](0X36D2BB15,0X30C13B09))
# kG's == Ry[0x79FA2C07] (RH==0);  ki/ku's are the RH==2 / RH==3 variants.
# kH's RC seed picks one of four env entries by C(=RH).  All four are NUMBERS of
# the identical shape  Rf( Ro(Rp[key],(RZ*0xD3B7+0x51B8D476)%2^32), kk, y3 ):
#   RH==0 -> Ry[0x79FA2C07] = kG's method-scope `local Rb`   (kk=0)
#   RH==1 -> Ry[0x679BA927] = yD's method-scope `local Rb`   (kk=1)
#   RH==2 -> Ry[0x5083305B] = ki's method-scope `local Ry`   (kk=2)
#   else  -> Ry[0x5053C894] = ku's method-scope `local Ry`   (kk=3)
_ENVVAR = {
    0: (0x191CD804, 0x1F582F6A, 0x6F, 0x51, 0, (0x35, 0x64, 0x3DFD00BF, 0x3F118AE7)),
    1: (421320708,  0x1F582F6A, 0x6F, 0x51, 1, (0x7B, 0x21, 0x36D2BB15, 0x30C13B09)),
    2: (421320708,  0x1F582F6A, 0x6F, 0x51, 2, (0x60, 0x2D, 0x196E1538, 419584466)),
    3: (421320708,  0x1F582F6A, 0x6F, 0x51, 3, (0x75, 0x4C, 612762105,  633128481)),
}


def kH_envval(RH, Rp, RZ, Rf):
    a1, a2, i, j, kk, (yi, yj, y1, y2) = _ENVVAR[RH if RH in (0, 1, 2) else 3]
    key = O(i, j, a1, a2)
    c = (RZ * 0x0D3B7 + 0x51B8D476) % M
    y3 = O(yi, yj, y1, y2)
    return Rf(Ro(Rp[key], c), kk, y3), key, c, y3


def kH_checksum(v, kM, kL, kW, kO, C, ENVVAL):
    """kH()'s returned Rf (the final RC).  Reads no stream bytes."""
    RR, RXs, Rs_ = M, 0x8000000, 0x100
    Ry = v['kP']
    RU = RX(v['kz'], v['kP'])
    Rk = (RU * RX(RX(519472, 0xE1DFF), 604610) + RX(RX(RX(497181, 0xD9DB3), 1990525440), v['kP'])) % RR
    RM = RX(v['kz'], RX(v['kz'], v['kP']))
    RL = RX(v['kP'], RX(v['kz'], v['kP']))
    RW = RX(0x64C3B691, ((v['kE'] % 0x10000) * 2) + 1)
    RO = RX(0xC8337262, RX(v['kz'], Rd(v['kP'], 9)))
    RE = RX(0x7FDABEEE, Rd(v['kE'], 3))
    RQ = RX(0xE83036F7, Rd(v['kz'], 5))
    Rdv = ((0xB + (v['kE'] % 0xF) * 2) % 0x1E) + 1
    k = 4294967296.0
    RC = RX(RX(RX(RX(899760, 0xB9559), 3513384928), ENVVAL), v['kE'])
    Rv_i = Ry
    Rz = Ry + v['kQ']
    while Rv_i < Rz:
        Rv_i += 1
        RP = kM[Rv_i]
        Rt = RX(kL[Rv_i], RU)
        Rf = RX(kW[Rv_i], RM)
        if Rf >= RXs:
            Rf -= RR
        Rzz = RX(kO[Rv_i], RL)
        if Rzz >= RXs:
            Rzz -= RR
        RP = (RP - (Rk % Rs_) * 2 - RX(RX(0x5F44, 158443), 0x11DDD361)) % RR
        Rt = (Rt - ((Rk - (Rk % Rs_)) // Rs_) % Rs_) % RR
        RH2 = (Rk * 0x10001) % RR
        Rf = RX(Rf % RR, RH2)
        if Rf >= RXs:
            Rf -= RR
        Rzz = RX(Rzz % RR, (RH2 * 0x45D9 + Rk) % RR)
        if Rzz >= RXs:
            Rzz -= RR
        Rk = (Rk * 3 + RP * 0x101 + Rt * 0x1001 + Rf % RR + (Rzz % RR) * 0x11) % RR
        RI = Rd(RC, 7)
        RC = (RX(RI, RP) + Rt % k + RX(Rf % k, Rzz % k) % k) % k
    return int(RC)


def kH_full(v, kM, kL, kW, kO, C, ENVVAL):
    """kH(self,y=Ry,v=proto,C=RH,k=2^32,R=RX,b=Rd) -> Rb,Rj,Rf.
    Rb/Rj are the reconstructed numeric constant tables, Rf the trace checksum.
    Also yields the DECODED instruction words (RP,Rt,Rf_,Rz) for every slot."""
    RR, RXs, Rs_ = M, 0x8000000, 0x100
    k = float(M)                       # kH's `k` param is 4294967296 (a Lua double)
    Rb, Rj = {}, {}
    Ry = v['kP']
    RU = RX(v['kz'], v['kP'])                       # kz ^ kP
    Rk = (RU * RX(RX(519472, 0xE1DFF), 604610)
          + RX(RX(RX(497181, 0xD9DB3), 1990525440), v['kP'])) % RR
    RM = RX(v['kz'], RX(v['kz'], v['kP']))          # == kP
    RL = RX(v['kP'], RX(v['kz'], v['kP']))          # == kz
    RW = RX(0x64C3B691, ((v['kE'] % 0x10000) * 2) + 1)
    RO = RX(0xC8337262, RX(v['kz'], Rd(v['kP'], 9)))
    RE = RX(0x7FDABEEE, Rd(v['kE'], 3))
    RQ = RX(0xE83036F7, Rd(v['kz'], 5))
    Rdv = ((0xB + (v['kE'] % 0xF) * 2) % 0x1E) + 1
    RC = RX(RX(RX(RX(899760, 0xB9559), 3513384928), ENVVAL), v['kE'])
    words = []
    Rv_i = Ry
    Rz_end = Ry + v['kQ']
    while Rv_i < Rz_end:
        Rv_i += 1
        RP = kM[Rv_i]
        Rt = RX(kL[Rv_i], RU)
        Rf_ = RX(kW[Rv_i], RM)
        if Rf_ >= RXs:
            Rf_ -= RR
        Rzz = RX(kO[Rv_i], RL)
        if Rzz >= RXs:
            Rzz -= RR
        RP = (RP - (Rk % Rs_) * 2 - RX(RX(0x5F44, 158443), 0x11DDD361)) % RR
        Rt = (Rt - ((Rk - (Rk % Rs_)) // Rs_) % Rs_) % RR
        RH2 = (Rk * 0x10001) % RR
        Rf_ = RX(Rf_ % RR, RH2)
        if Rf_ >= RXs:
            Rf_ -= RR
        Rzz = RX(Rzz % RR, (RH2 * 0x45D9 + Rk) % RR)
        if Rzz >= RXs:
            Rzz -= RR
        Rk = (Rk * 3 + RP * 0x101 + Rt * 0x1001 + Rf_ % RR + (Rzz % RR) * 0x11) % RR
        RA = RX(((Rv_i - Ry) * RW) % k, RO)
        RI = Rd(RC, 7)
        RC = (RX(RI, RP) + Rt % k + RX(Rf_ % k, Rzz % k) % k) % k
        if (RX(Rd(RP, 4), RE)) % 0x64 < 0x44:
            t = Rf_ - 0x80 if Rf_ > 0x7F else Rf_
            idx = (t * 0x4003 + 0xEDD533 + v['kz']) % k
            Rb[idx] = (Rd(Rb.get(idx, 0), ((t * Rdv + (Rv_i - Ry)) % 0xF) + 1) + RA) % k
            Rj[idx] = RC
        if (RX(Rd(RP, 6), RQ)) % 0x64 < 0x38:
            t = Rzz - 0x80 if Rzz > 0x7F else Rzz
            idx = (t * 0x4003 + 0xEDD533 + v['kz']) % k
            Rb[idx] = (Rd(Rb.get(idx, 0), ((t * Rdv + (Rv_i - Ry)) % 0xF) + 1) + RA) % k
            Rj[idx] = RC
        words.append((RP, Rt, Rf_, Rzz))
    return ({int(a_): int(b_) for a_, b_ in Rb.items()},
            {int(a_): int(b_) for a_, b_ in Rj.items()}, int(RC), words)


def rotr32(v, k):
    v = int(v) % M
    k = int(k) % 32
    return ((v >> k) | (v << (32 - k))) % M if k else v


HITS = []


def search_nchild(S, Rw4, kE, depth, budget_left):
    """RV3 is polluted by the running `Rs` checksum the RI handlers maintain
    (that needs yD's constant decoders + yo's Rx hash), so invert instead:
         nChild = Rw4 ^ rotl(kE,15) ^ rotl(RV3,5)
      => RV3    = rotr32(Rw4 ^ nChild ^ rotl(kE,15), 5)
    Only the TRUE nChild yields the true RV3, and only the true RV3 lets the
    children parse -- so this is an exact search, not a heuristic.
    n=0 is tried LAST because it validates nothing (no children to parse).

    Returns (nChild, RV3, children, RV_after) where RV_after is the value the
    shared `RV` upvalue holds when vu() exits: the LAST child's exit value, or
    this node's own RV3 when nChild==0."""
    T = RX(Rw4, Rd(kE, 0xF))
    hi = max(0, min(6000, budget_left // 41))
    # Cheap pre-filter: the keystream does NOT depend on RV, so read the first
    # child's header words ONCE and then test every candidate by pure arithmetic.
    sn0 = S.snap()
    pre = None
    try:
        w = [S.Rw(), S.Rw(), S.Rw()]
        yb = [S.RS(), S.RS(), S.RS(), S.RS()]
        w5 = S.Rw()
        pre = (w, yb, w5)
    except Fail:
        pre = None
    S.restore(sn0)
    cap = max(1, (budget_left - 4 - 25) // 16)

    def plausible(rv3):
        if pre is None:
            return True
        w, yb, w5 = pre
        cke = RX(w[0], rv3)
        ckQ = RX(w5, RX(Rd(cke, 0xB), Rd(rv3, 0x7)))
        if ckQ > min(7461, cap):
            return False
        if yb[1] > 32 or yb[0] > 32:      # yt = numparams, yE
            return False
        return True

    order = [n for n in range(1, hi + 1) if plausible(rotr32(T ^ n, 5))] + [0]
    for n in order:
        RV3 = rotr32(T ^ n, 5)
        sn = S.snap()
        try:
            kids = []
            cur = RV3
            for _ in range(n):
                kid, cur = vu(S, cur, depth + 1, [], CTX)
                kids.append(kid)
            if depth == 0:
                used = S.Rm - 1
                HITS.append((n, used, len(S.vh) - used))
                if used != len(S.vh):
                    raise Fail('root budget %d != %d' % (used, len(S.vh)))
            return n, RV3, kids, cur
        except Fail:
            S.restore(sn)
    raise Fail('no plausible nChild <= %d at depth %d' % (hi, depth))


CTX = {}


def full():
    data = open('data.bin', 'rb').read()
    RZ = compute_RZ(False)
    S = Stream(data)
    Rp, RT, va, Rc2, RF2, Ru2, Rx2 = kI(RZ, S.Rc, S.RF, S.Ru, S.Rx, verbose=False)
    S.va, S.Rc, S.RF, S.Ru, S.Rx = va, Rc2, RF2, Ru2, Rx2
    Rs7 = O(0x26, 0x33, 873077588, 0x3FDF5B7B)
    RV1 = RT(Ro(Rp[Rs7], (RZ * 0x1F33 + 0xB7D0034E) % M),
             O(0x62, 0x64, 0x447C0104, 0x2FBAE375),
             O(0x6A, 0x52, 0x3848B5A5, 0x3D111408))
    CTX.clear()
    CTX.update(Rp=Rp, Rf=RT, RZ=RZ)
    print('RZ=0x%08X va=%d RV1=0x%08X  state=(%d,%d,%d,%d)' % (RZ, va, RV1, Rc2, RF2, Ru2, Rx2))
    ev, k_, c_, y_ = kH_envval(1, Rp, RZ, RT)
    print('kH envval (RH==1, yD Rb) = %d = 0x%08X   [key=%d c=0x%08X y=%d]' % (ev, ev, k_, c_, y_))
    log = []
    try:
        p, RVf = vu(S, RV1, 0, log, CTX)
    except Fail as e:
        print('root search failed:', e)
        print('candidates whose children all parsed (nChild, bytesUsed, leftover):')
        for h in sorted(HITS, key=lambda t: abs(t[2]))[:40]:
            print('   nChild=%-5d used=%-7d leftover=%d' % h)
        raise SystemExit(1)
    print()
    print('root kE=0x%08X kz=0x%08X kP=%d yE=%d yt=%d yl=%d yQ=%d'
          % (p['kE'], p['kz'], p['kP'], p['yE'], p['yt'], p['yl'], p['yQ']))
    print('root kQ=%d RH=%d Rh=%d nChild=%d' % (p['kQ'], p['RH'], p['Rh'], p['nChild']))
    for l in log:
        print('  ', l)
    print('BYTES CONSUMED = %d / %d   LEFTOVER = %d' % (S.Rm - 1, len(data), len(data) - (S.Rm - 1)))
    return S, p


def walk(p, d=0, out=None):
    if out is None:
        out = []
    out.append((d, p))
    for c in p.get('children', []):
        walk(c, d + 1, out)
    return out


def dump(S, p, outdir='/home/user/OBF/analysis'):
    import json, os
    protos = walk(p)
    known = {RI_KEY_4, RI_KEY_26, RI_KEY_56, RI_KEY_44, RI_KEY_228}
    L = []
    tot_instr = tot_const = 0
    L.append('# Kryvex V2.7.lua -- stage-2 VM bytecode, FULLY DECRYPTED PROTO TREE')
    L.append('# bytes consumed %d / %d   leftover %d' % (S.Rm - 1, len(S.vh), len(S.vh) - (S.Rm - 1)))
    L.append('# protos %d' % len(protos))
    L.append('')
    L.append('idx depth   kP     kQ   yt yE yl yQ RH   Rh  nChild  nStr nBlob  cpool')
    js = []
    for i, (d, q) in enumerate(protos):
        tot_instr += q['kQ']; tot_const += q['Rh']
        ct = q['consts']
        nstr = sum(1 for v in ct.values() if v[0] == 'str')
        nblob = sum(1 for v in ct.values() if isinstance(v[0], int) and v[0] in (RI_KEY_26, RI_KEY_56))
        L.append('%3d %5d  %-6d %-4d %-2d %-2d %-2d %-2d %-2d %-4d %-6d  %-4d %-5d %-5d'
                 % (i, d, q['kP'], q['kQ'], q['yt'], q['yE'], q['yl'], q['yQ'],
                    q['RH'], q['Rh'], q['nChild'], nstr, nblob, len(q['cpool'])))
        js.append(dict(idx=i, depth=d, kP=q['kP'], kQ=q['kQ'], kE=q['kE'], kz=q['kz'],
                       yE=q['yE'], yt=q['yt'], yl=q['yl'], yQ=q['yQ'], RH=q['RH'], Rh=q['Rh'],
                       nChild=q['nChild'],
                       words=[list(w) for w in q['words']],
                       raw=[list(w) for w in q['raw']],
                       cpool={str(a): b for a, b in q['cpool'].items()},
                       cpool2={str(a): b for a, b in q['cpool2'].items()},
                       consts=[[a, v[0], (v[1].hex() if isinstance(v[1], bytes) else v[1])]
                               for a, v in sorted(ct.items())]))
    L.append('')
    L.append('TOTAL instructions %d   TOTAL constant slots %d' % (tot_instr, tot_const))
    # --- raw instruction stream, human readable ---
    R = []
    R.append('# Kryvex stage-2 VM raw instruction stream (recovered)')
    R.append('# each instruction = 4 fields: F1=u32 (Rw), F2/F3/F4=signed i32 (kj)')
    R.append('# F1 top 2 bits select how many extra cipher bytes follow (kd Rz)')
    for i, (d, q) in enumerate(protos):
        R.append('')
        R.append('=== proto %d  depth %d  kP=%d  kQ=%d  yt(numparams)=%d  yE=%d  yQ=%d  RH=%d  Rh=%d  nChild=%d'
                 % (i, d, q['kP'], q['kQ'], q['yt'], q['yE'], q['yQ'], q['RH'], q['Rh'], q['nChild']))
        R.append('  pc     F1(u32)      F1hex        F2        F3        F4    extra')
        for pc, w in enumerate(q['raw'], 1):
            R.append('  %-6d %-12d 0x%08X  %-9d %-9d %-9d %d'
                     % (pc, w[0], w[0], w[1], w[2], w[3], (w[0] >> 29) & 3))
    open(os.path.join(outdir, 'stage2_instructions.txt'), 'w').write('\n'.join(R) + '\n')
    txt = '\n'.join(L) + '\n'
    open(os.path.join(outdir, 'stage2_prototree.txt'), 'w').write(txt)
    json.dump(js, open(os.path.join(outdir, 'stage2_protos.json'), 'w'))
    print(txt)
    return js


if __name__ == '__main__':
    S, p = full()
    dump(S, p)
