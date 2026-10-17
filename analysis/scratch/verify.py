#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify.py -- decisive filter for brute2 candidates.

Continues the parse past kd()'s kQ loop, exactly as vu() does:

  state 0x1A96  RV2 = kd()  = xor32(RV, rotl32(RR_final,9))     [16..19 bytes/iter]
  state 12057   RH  = RS()                                       [1]
                Rf,RO,RE = kH(...)   (no stream I/O, RE=checksum)
                Rh  = xor32(Rw(), xor32(rotl32(kE,9), rotl32(RV2,15)))   [4]
                Rh rounds of { RS(); Rw(); RI-handler extras }   [5 + 0/8/ks()]
                RV3 = xor32(xor32(rotl32(RV2,7),rotl32(RE,13)), xor32(Rs,kE))
  state 0x3C5A  nChild = xor32(Rw(), xor32(rotl32(kE,15), rotl32(RV3,5))) [4]
                then nChild immediate vu() calls (recursive)

Accepts only if the whole recursive parse stays inside the 119405-byte budget.
"""
import sys, math
sys.path.insert(0, '/home/user/OBF/analysis/scratch')
from crack import O, Ro, Rd as rotl32, kA_xor, rotr8, compute_RZ, Rf, kI, compute_RV, P1, P2, XV, A1

M = 1 << 32
RC_ = 0x7FFFFFFF
DATA = open('/home/user/OBF/analysis/stage2_bytecode.bin', 'rb').read()
LIMIT = len(DATA)

RI_KEYS = {O(0x1D, 0x20, 0x15D0CC6B, 0x103B4414): 'str',      # 4
           O(0x1D, 0x51, 893299098, 0x242AFBF7): 'b8',        # 26
           O(0x6F, 0x5E, 0x229043FB, 0x287D690E): 'b8',       # 56
           O(0x79, 0x6B, 867642701, 427602970): 'nop',        # 44
           228: 'nop'}


class C:
    def __init__(self, va, st):
        self.va = va
        self.Rc, self.RF, self.Ru, self.Rx = st
        self.pos = 4
        self.vU = 4

    def RS(self):
        if self.pos >= LIMIT:
            raise EOFError
        RW = DATA[self.pos]; self.pos += 1
        self.vU = self.pos; vU = self.vU
        z = RW
        z = (z + 256 - ((self.Rx + (vU % 256) * 7) % 256)) % 256
        z = rotr8(z, 3)
        z = kA_xor(z, self.Ru)
        z = (z + 256 - ((self.Rc + self.RF + (vU % 256) * 0xC3) % 256)) % 256
        Ry = z
        RO = vU % RC_; Rt = self.va % RC_
        RE = (Rt + RO * P1 + (XV % RC_)) % RC_
        RL = (Rt * 0x101 + RO * P2 + P1 * 0x11) % RC_
        for _ in range(3):
            n1 = (RE * ((RL % 0x10000) + P1 + 0x101) + RL * 0x101 + RO * (0x11 + XV % 0x1F) + Rt) % RC_
            n2 = (RL * ((n1 % 0x10000) + P2 + 0x107) + n1 * 0x81 + RO * (0x17 + A1) + XV) % RC_
            RE, RL = n1, n2
        RA = (RE % 256 + (RL % 256) * 3 + (RO % 256) * 5
              + ((RE - RE % 256) // 256) % 256 + ((RL - RL % 256) // 256) % 256) % 256
        Ry = kA_xor(Ry, RA)
        R, v = Ry, RW
        self.Rc = kA_xor(rotr8((self.Rc + R + self.Rx + (vU % 256)) % 256, 5), v)
        self.RF = rotr8((self.RF * 5 + v + kA_xor(R, self.Rc)) % 256, 2)
        self.Ru = kA_xor(rotr8((self.Ru + R + v + self.RF + 7) % 256, 5), self.Rx)
        self.Rx = rotr8((self.Rx + v + R + self.Rc + self.Ru + 7) % 256, 1)
        return Ry % M

    def Rw(self):
        a, b, c, d = self.RS(), self.RS(), self.RS(), self.RS()
        return (a + d * 16777216 + b * 256 + c * 65536) % M

    def kj(self):
        v = self.Rw()
        return v - M if v >= 0x80000000 else v

    def ks(self):
        n = self.Rw()
        if n == 0:
            return ''
        for _ in range(n):
            self.RS()
        return 'x' * n


def kd(c, kE, kz, kP, RV):
    """Returns (kQ, RR_final, kM, kL, kW, kO)."""
    Rj = Ro(kz, kP)
    Rdl = Ro(kz, Rj)          # = kP
    RMl = Ro(kP, Rj)          # = kz
    RL = Ro(Ro(Ro(589742, 0x720EE), 0xC33D6FB1), Ro(rotl32(kE, 3), rotl32(RV, 7)))
    RWc = Ro(Ro(Ro(0x10599, 0x8B73), 4132475171), Ro(rotl32(kz, 9), rotl32(RV, 13)))
    ROc = Ro(Ro(Ro(152743, 491838), 1555620535), Ro(rotl32(kP, 15), rotl32(kE, 21)))
    REc = Ro(Ro(Ro(331361, 863629), 1213750126), Ro(rotl32(RV, 17), rotl32(kz, 25)))
    RR = Ro(Ro(kE, rotl32(kz, 7)), Ro(rotl32(kP, 13), rotl32(RV, 19)))
    kQ = Ro(c.Rw(), Ro(rotl32(kE, 11), rotl32(RV, 7)))
    if not (0 < kQ < 8000):
        raise ValueError('kQ=%d' % kQ)

    def Rf4(v, k, b, y):
        if v < 0:
            v += M
        v = Ro(Ro(v, b), Ro(k, y))
        return v - M if v >= 0x80000000 else v

    kM, kL, kW, kO = {}, {}, {}, {}
    for i in range(1, kQ + 1):
        Ryv = c.Rw()
        RCv = Ro(Ryv, Ro(kz, RR % 0x10000000))
        kM[i + kP] = RCv
        RXv = Ro(c.kj() % M, Ro(rotl32(RR, 5), kE))
        kL[i + kP] = Ro(RXv, Rj)
        RUv = Ro(RL, rotl32(RR, 0xB))
        RQv = Ro(RWc, rotl32(RR, 0x11))
        kW[i + kP] = Ro(Rf4(c.kj(), RCv, RUv, ROc) % M, Rdl)
        kO[i + kP] = Ro(Rf4(c.kj(), RCv, RQv, REc) % M, RMl)
        RR = Ro((rotl32(RR, 7) + RCv) % M, RXv)
        Rz = ((Ryv - Ryv % 0x20000000) // 0x20000000) % 4
        for _ in range(Rz):
            RR = (rotl32(RR, 3) + c.RS() + 0x3D) % M
    return kQ, RR, kM, kL, kW, kO


def kH_checksum(kE, kz, kP, kQ, RH, kM, kL, kW, kO):
    """kH's 3rd return: the final running checksum RC."""
    R = Ro
    RU = R(kz, kP)
    Rk = (RU * R(R(519472, 0xE1DFF), 604610) + R(R(R(497181, 0xD9DB3), 1990525440), kP)) % M
    RM = R(kz, R(kz, kP))
    RL = R(kP, R(kz, kP))
    RWc = R(0x64C3B691, ((kE % 0x10000) * 2) + 1)
    ROc = R(0xC8337262, R(kz, rotl32(kP, 9)))
    REc = R(0x7FDABEEE, rotl32(kE, 3))
    RQ = R(0xE83036F7, rotl32(kz, 5))
    Rdl = ((0xB + (kE % 0xF) * 2) % 0x1E) + 1
    RC = R(R(R(R(899760, 0xB9559), 3513384928),
             {0: 0x79FA2C07, 1: 0x679BA927, 2: 0x5083305B}.get(RH, 0x5053C894)), kE)
    Rv = kP
    Rz = kP + kQ
    while Rv < Rz:
        Rv += 1
        RP = kM[Rv]
        Rt = R(kL[Rv], RU)
        Rf = R(kW[Rv], RM)
        if Rf >= 0x80000000: Rf -= M
        Rzz = R(kO[Rv], RL)
        if Rzz >= 0x80000000: Rzz -= M
        RP = (RP - (Rk % 0x100) * 2 - R(R(0x5F44, 158443), 0x11DDD361)) % M
        Rt = (Rt - ((Rk - Rk % 0x100) // 0x100) % 0x100) % M
        RH2 = (Rk * 0x10001) % M
        Rf = R(Rf % M, RH2)
        if Rf >= 0x80000000: Rf -= M
        Rzz = R(Rzz % M, (RH2 * 0x45D9 + Rk) % M)
        if Rzz >= 0x80000000: Rzz -= M
        Rk = (Rk * 3 + RP * 0x101 + Rt * 0x1001 + Rf % M + (Rzz % M) * 0x11) % M
        RA = R(((Rv - kP) * RWc) % M, ROc)
        RI = rotl32(RC, 7)
        RC = (R(RI, RP) + Rt % M + R(Rf % M, Rzz % M) % M) % M
        if (R(rotl32(RP, 4), REc)) % 0x64 < 0x44:
            pass
        if (R(rotl32(RP, 6), RQ)) % 0x64 < 0x38:
            pass
    return RC


def parse(c, RV, depth=0, maxdepth=6):
    kE = Ro(c.Rw(), RV)
    kz = Ro(c.Rw(), Ro(rotl32(kE, 5), rotl32(RV, 11)))
    kP = Ro(c.Rw(), Ro(rotl32(kE, 13), rotl32(RV, 19)))
    yE, yt, yl, yQ = c.RS(), c.RS(), c.RS(), c.RS()
    kQ, RRfin, kM, kL, kW, kO = kd(c, kE, kz, kP, RV)
    RV2 = Ro(RV, rotl32(RRfin, 9))
    RH = c.RS()
    RE = kH_checksum(kE, kz, kP, kQ, RH, kM, kL, kW, kO)
    Rs = Ro(Ro(Ro(kE, kz), Ro(rotl32(kP, 7), rotl32(RE, 13))), rotl32(RV2, 17))
    Rh = Ro(c.Rw(), Ro(rotl32(kE, 9), rotl32(RV2, 15)))
    if Rh > 20000:
        raise ValueError('Rh=%d' % Rh)
    for RQ in range(1, Rh + 1):
        b = c.RS()
        c.Rw()
        h = RI_KEYS.get(b)
        if h == 'str':
            c.ks()
        elif h == 'b8':
            for _ in range(8):
                c.RS()
    RV3 = Ro(Ro(rotl32(RV2, 7), rotl32(RE, 13)), Ro(Rs, kE))
    nChild = Ro(c.Rw(), Ro(rotl32(kE, 15), rotl32(RV3, 5)))
    if nChild > 4000:
        raise ValueError('nChild=%d' % nChild)
    if depth < maxdepth:
        for _ in range(nChild):
            parse(c, RV3, depth + 1, maxdepth)
    return dict(kE=kE, kz=kz, kP=kP, yE=yE, yt=yt, yl=yl, yQ=yQ,
                kQ=kQ, RH=RH, Rh=Rh, nChild=nChild, pos=c.pos, depth=depth)


def run(ry, verbose=True):
    Rc = (DATA[0] ^ ry) % M
    RF = DATA[1]
    Ru = (DATA[2] ^ (ry >> 16)) % M
    Rx = (DATA[3] ^ (ry >> 24)) % M
    RF2 = 4066890930
    va = ((RF2 + Rc * 0x10001 + RF * 0x101 + Ru * 0x11 + Rx) % 2147483646) + 1
    RZ = compute_RZ()
    Rp, _va, _k, _b, _y, _C = kI(RZ, DATA[0], DATA[1], DATA[2], DATA[3])
    RV = compute_RV(Rp, RZ)
    c = C(va, (Rc, RF, Ru, Rx))
    try:
        info = parse(c, RV)
    except (EOFError, ValueError, KeyError) as e:
        return None, str(e)
    return info, None


if __name__ == '__main__':
    fn = sys.argv[1] if len(sys.argv) > 1 else 'hits_ry.txt'
    import re
    lines = []
    for l in open(fn).read().splitlines():
        m = re.match(r'ry=\s*(\d+)\s', l)
        if m: lines.append(int(m.group(1)))
    lines = list(dict.fromkeys(lines))
    print("verifying %d candidates" % len(lines))
    ok = []
    for ry in lines:
        info, err = run(ry)
        if info:
            print("  *** FULL PARSE OK *** ry=%d  %s" % (ry, info))
            ok.append((ry, info))
        else:
            print("  ry=%-12d rejected: %s" % (ry, err))
    print("\n%d / %d survived the full recursive parse" % (len(ok), len(lines)))
