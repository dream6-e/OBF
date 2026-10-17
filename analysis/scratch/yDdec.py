#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Layer 4: yD's constant-payload cipher, transcribed from fn/yD_full.lua.

Everything yD needs is static EXCEPT one bit: `z` = vX = kF's first return,
which folds in floor(collectgarbage("count")) -- a genuinely runtime-dependent
value.  It only enters RE() as `((b+v+z) % 2)`, i.e. a branch selector.
So we try both parities and keep the one whose 285 string constants come out
printable.  That is a decisive oracle, not a guess.

yD's method-scope locals (fn/yD_full.lua @57 / @152):
   Rk=0x2A78B299  Ry=2^32  RC=0x100  Rf=0x10000  RX=0x62
   Rs=0x75        RU=0x10  Rd=0x6A   RM=0x79     RR=2^32
yD's params (call R:yD(Rv,Ry,RT,Rp,RZ,Ro,Rd,RX,vz,vP,vX,Rq,vy,vC,vb,Ra,Ri,Rn,RW,RM,RO)):
   R=bk ops  s=env  b=RT(kI PRF)  y=Rp  C=RZ  X=Ro(xor32)  j=Rd(rotl32)
   v=RX(xor) f=vz(256x256 xor tables)  Q=vP(yF quarter-round)  z=vX
   d=string.byte  k=math.floor  U=string.char  M=table.concat
   L=Rn  W=RW  O=RM  E=RO      (W/O/E are the tamper flags: False in the clean case)
"""
from final import (O, Ro, Rd, RX, M, g14, Fail)
import math as _math


def mulmod(a, b, m=None):
    """(a*b) % 2^32 emulating Lua/Luau DOUBLE arithmetic (rounds first if > 2^53)."""
    m = M if m is None else m
    p = a * b
    if abs(p) < 2 ** 53:
        return int(p) % m
    return int(_math.fmod(float(a) * float(b), float(m))) % m

RKm = 0x2A78B299          # yD's Rk
RL16 = [33, 1, 0x29, 0xD, 0x35, 49, 0x25, 0x1D, 0x15, 0x5, 0x9, 0x19, 0x3D, 0x2D, 0x39, 0x11]
RP8 = [0x5, 0x7, 0x6, 1, 0x3, 0x4, 0x2, 0x8]
QROUNDS = [[2, 16, 1, 6], [4, 8, 14, 13], [11, 12, 3, 15], [10, 9, 7, 5],
           [4, 16, 7, 15], [2, 9, 3, 13], [10, 12, 14, 6], [11, 8, 1, 5]]


def fx(a, b):
    """yD's `f` param = vz = yJ's 256x256 xor table:  f[a][b] == a xor b."""
    return (int(a) % 256) ^ (int(b) % 256)


class YD:
    def __init__(self, Rp, RZ, Rf, vXparity):
        """Rp = kI's 8-value table,
        RZ = kI's constant, Rf = kI's PRF, vXparity = vX % 2 (0 or 1)."""
        self.Rp, self.RZ, self.Rf = Rp, RZ, Rf
        self.z2 = vXparity

        def prf(keyexpr, mul, add, slot, u, v):
            return Rf(Ro(Rp[O(*keyexpr)], (RZ * mul + add) % M), slot, O(*u, v) if False else O(slot and 0 or 0, 0, 0))

        # ---- yD's 8-entry `Rv` table  (@177) ----
        self.T8 = {}
        spec = [
            ((0x1D, 0x51, 764102583, 735993286), 0x07A05, 0x2452BA5D, (0x62, 0x78, 0x1F0B0FC1, 442685210), (0x1D, 0x51, 764102583, 735993286)),
            ((0x26, 0x32, 0x14154479, 0x15F8FB0E), 0x4BBD, 0x48221848, (0x79, 0x6B, 901970920, 393274714), (0x26, 0x32, 0x14154479, 368638734)),
            ((0x6A, 0x52, 0x241F863C, 558245791), 0xB9E7, 3560960021, (0x1D, 0x51, 0x37559378, 571740672), (0x6A, 0x52, 0x241F863C, 0x2146279F)),
            ((0x79, 0x4C, 0x38ACB0E6, 1045443622), 17025, 0xA72F84FE, (0x35, 0x64, 0x5CF1384C, 538792791), (0x79, 0x4C, 950841574, 1045443622)),
            ((0x75, 0x68, 0x10224368, 0x3E637CA2), 49901, 0xF554F14D, (0x35, 0x64, 0x65AFE157, 0x175EAA4E), (0x75, 0x68, 0x10224368, 0x3E637CA2)),
            ((0x75, 0x68, 330461813, 986926487), 0x1F33, 0xB7D0034E, (0x26, 0x33, 873077588, 0x3FDF5B7B), (0x75, 0x68, 330461813, 0x3AD34D97)),
            ((0x7B, 0x21, 0x34CBA150, 0x32D82144), 0xD3B7, 0x51B8D476, (0x6F, 0x51, 421320708, 0x1F582F6A), (0x7B, 0x21, 0x34CBA150, 853025092)),
            ((0x62, 0x78, 0x2041FD75, 623388068), 0x4987, 558832363, (0x26, 0x32, 0x2D5FCDDE, 749892264), (0x62, 0x78, 541195637, 623388068)),
        ]
        for ks, mul, add, yk, ys in spec:
            self.T8[O(*ks)] = Rf(Ro(Rp[O(*yk)], (RZ * mul + add) % M), 1, O(*ys))

        # ---- RW / Rb / RO  (@1362, @1480, @1607) ----
        self.RWv = Rf(Ro(Rp[O(0x1D, 0x51, 0x37559378, 0x22141200)], (RZ * 0xB9E7 + 3560960021) % M), 1,
                      O(0x60, 0x27, 0x504DDB73, 0x2F70F09A))
        self.Rbv = Rf(Ro(Rp[O(0x6F, 0x51, 421320708, 0x1F582F6A)], (RZ * 0xD3B7 + 0x51B8D476) % M), 1,
                      O(0x7B, 0x21, 0x36D2BB15, 0x30C13B09))
        self.ROv = Rf(Ro(Rp[O(0x35, 0x64, 0x5CF1384C, 0x201D5357)], (RZ * 17025 + 2804909310) % M), 1,
                      O(0x79, 0x6B, 0x2E86D239, 0x1EAD0F0D))

        # ---- RN (16 entries, @1728) = (constant + Rk) % 2^32 ----
        T = self.T8
        c = lambda i, j, a, b: O(i, j, a, b)
        self.RN = [
            (T[c(0x75, 0x68, 0x18A528D5, 0x35E09735)] + RKm) % M,
            ((c(0x7B, 0x63, 0xF053B4A5, 654600907) + c(0x6A, 0x1B, 3979509071, 0x3AA9D3DE)) % M + RKm) % M,
            (T[c(0x62, 0x78, 314214092, 0x17D35E12)] + RKm) % M,
            ((c(0x62, 0x78, 0xDDA56D1C, 993399745) + c(0x6A, 0x52, 2658480422, 470364151)) % M + RKm) % M,
            (0 + RKm) % M,
            (0 + RKm) % M,
            (T[c(0x62, 0x78, 0x1E47ABE4, 0x1B2E733B)] + RKm) % M,
            (T[c(0x35, 0x64, 0x55DD1F9F, 0x27316C02)] + RKm) % M,
            (T[c(0x6F, 0x5E, 0x19F328F9, 0x311A83DA)] + RKm) % M,
            ((c(0x79, 0x4C, 0x73825D67, 0x39B8E17C) + c(0x1D, 0x20, 0xC6E6F645, 0x255755A8)) % M + RKm) % M,
            ((c(0x6A, 0x1B, 0x1ADE92AD, 0x10E05859) + c(0x6F, 0x5E, 3742049179, 0x2C3605E1)) % M + RKm) % M,
            (T[c(0x6F, 0x51, 452202161, 0x1CB0F9DF)] + RKm) % M,
            (0 + RKm) % M,
            (T[c(0x7B, 0x63, 1085410106, 0x2A81B287)] + RKm) % M,
            (0 + RKm) % M,
            (T[c(0x60, 0x2D, 0x25E331D1, 0x258F7D33)] + RKm) % M,
        ]
        # branch-A raw constants (same shapes, without the +Rk)
        self.Aconst = {
            1:  T[c(0x75, 0x68, 0x18A528D5, 0x35E09735)],
            2:  (c(0x7B, 0x63, 0xF053B4A5, 654600907) + c(0x6A, 0x1B, 0xED327D4F, 0x3AA9D3DE)) % M,
            3:  T[c(0x62, 0x78, 0x12BA86CC, 0x17D35E12)],
            4:  (c(0x62, 0x78, 0xDDA56D1C, 993399745) + c(0x6A, 0x52, 2658480422, 470364151)) % M,
            7:  T[c(0x62, 0x78, 0x1E47ABE4, 0x1B2E733B)],
            8:  T[c(0x35, 0x64, 0x55DD1F9F, 0x27316C02)],
            9:  T[c(0x6F, 0x5E, 0x19F328F9, 823821274)],
            10: (c(0x79, 0x4C, 0x73825D67, 0x39B8E17C) + c(0x1D, 0x20, 0xC6E6F645, 0x255755A8)) % M,
            11: (c(0x6A, 0x1B, 0x1ADE92AD, 0x10E05859) + c(0x6F, 0x5E, 3742049179, 0x2C3605E1)) % M,
            12: T[c(0x6F, 0x51, 452202161, 0x1CB0F9DF)],
            14: T[c(0x7B, 0x63, 1085410106, 0x2A81B287)],
            16: T[c(0x60, 0x2D, 0x25E331D1, 630160691)],
        }
        # branch-B overwrite slots
        self.Bslot = {'b': O(0x62, 0x78, 625887520, 539464191),
                      'y': O(0x60, 0x2D, 511135027, 0x1E1B01D5),
                      'v': O(0x35, 0x20, 659323554, 0x20033FDA),
                      'C': O(0x62, 0x78, 604691578, 0x216304AE)}

        # ---- S-box Rj and the four round keys (@6641, @6890) ----
        RRb, Rv2, Rk2 = self.Rbv % 256, self.RWv % 256, self.ROv % 256
        self.S = [0] * 256
        for X in range(256):
            b2 = (X * 0x8B + RRb) % 256
            s2 = fx(b2, (b2 - b2 % 16) // 16)
            y2 = (s2 * 0x15 + Rv2) % 256
            f2 = fx(y2, (y2 - y2 % 16) // 16)
            self.S[X] = (f2 * 0x45 + Rk2) % 256
        self.Rt = (self.ROv + (self.Rbv % 0x10000) * 0x7 + 0x37) % M
        self.RH = (self.ROv + (self.Rbv % 0x10000) * 0xB + 0x4D) % M
        self.RA = (self.RWv + (self.Rbv % 0x10000) * 0x3 + 0x11) % M
        self.RI = (self.RWv + (self.Rbv % 0x10000) * 0x5 + 0x23) % M

    # ------------------------------------------------------------------ RE
    def RE(self, y, v, C, b):
        """RE(y,v,C,b) -> 64-byte key schedule (1-based dict)."""
        Ry = {}
        if (b + v + self.z2) % 2 == 0:
            A = self.Aconst
            for i in (1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 14, 16):
                Ry[i] = A[i]
            Ry[5], Ry[6], Ry[13], Ry[15] = y, b, C, v
        else:
            for i in range(1, 17):
                Ry[i] = (self.RN[i - 1] + 0xD5874D67) % M
            Ry[self.Bslot['b']] = b
            Ry[self.Bslot['y']] = y
            Ry[self.Bslot['v']] = v
            Ry[self.Bslot['C']] = C
        RC = {i: Ry[i] for i in range(1, 17)}
        for _ in range(5):
            for q in QROUNDS:
                self._Q(Ry, q[0], q[1], q[2], q[3])
        Rb = {}
        for RR in range(1, 17):
            Rv = RL16[RR - 1]
            x = (Ry[RR] + RC[RR]) % M
            Rb[Rv] = x % 256
            Rb[Rv + 1] = (x // 256) % 256
            Rb[Rv + 2] = (x // 0x10000) % 256
            Rb[Rv + 3] = (x // 0x1000000) % 256
        return Rb

    @staticmethod
    def _Q(st, i1, i2, i3, i4):
        """yF's returned function: two ChaCha-style quarter-rounds."""
        st[i1] = (st[i1] + st[i2]) % M
        st[i4] = RX(st[i4], st[i1]); st[i4] = Rd(st[i4], 16)
        st[i3] = (st[i3] + st[i4]) % M
        st[i2] = RX(st[i2], st[i3]); st[i2] = Rd(st[i2], 12)
        st[i1] = (st[i1] + 0x17F89CED) % M
        st[i1] = (st[i1] + 0xE8076313) % M
        st[i1] = (st[i1] + st[i2]) % M
        st[i4] = RX(st[i4], st[i1]); st[i4] = Rd(st[i4], 8)
        st[i3] = (st[i3] + st[i4]) % M
        st[i2] = RX(st[i2], st[i3]); st[i2] = Rd(st[i2], 7)

    # ------------------------------------------------------------------ RQ
    def RQ(self, y, C, X, k, b):
        """8-byte xor against RE()'s first 8 key bytes."""
        RC = RX(RX(self.Rbv, b or 0), k or 0)
        Rk = Rd(b or 0, 7)
        RXv = RX(RX(Rk, (C * 6 + X) % M), Rd(k or 0, 0xD))
        Rs = RX(RX(self.Rbv, Rd(Rk, 7)), Rd(k or 0, 5))
        key = self.RE(RC, RXv, Rs, O(0x6F, 0x5E, 3706357943, 0x3A0F5948))
        return [fx(y[i - 1], key[i]) for i in range(1, 9)]

    # ------------------------------------------------------------------ Rz
    def Rz(self, bs, C, X, k, y):
        """64-byte-block chained xor stream cipher over a byte string."""
        Rs = RX(RX(self.Rbv, y or 0), k or 0)
        RC = Rd(y or 0, 7)
        Rj = RX(RX(RC, (C * 6 + X) % M), Rd(k or 0, 0xD))
        Rf = RX(RX(self.Rbv, Rd(RC, 7)), Rd(k or 0, 5))
        n = len(bs)
        out = [0] * (n + 1)
        pos = 1
        chain = O(0x6F, 0x5E, 3706357943, 0x3A0F5948)
        while pos <= n:
            key = self.RE(Rs, Rj, Rf, chain)
            end = min(pos + 0x3F, n)
            cnt = 0
            fb = 0
            mul = 1
            while pos <= end:
                cnt += 1
                kk = fx(bs[pos - 1], key[cnt])
                out[pos] = kk
                if cnt <= 8:
                    fb = (fb + kk * mul) % M
                    mul = (mul * 0x100) % M
                pos += 1
            chain = (chain + O(0x35, 0x20, 0x25D04295, 816239511) + fb) % M
        return out[1:n + 1]

    # ------------------------------------------------------- mask helper
    @staticmethod
    def _mask(i, n, key, step, blk=0x40, keep=8):
        return 0 if (((i - 1) % blk) < keep and (i - ((i - 1) % blk) + blk) <= n) else (key + i * step) % 256

    # -------------------------------------------------------------- RK / RB
    def RK(self, Rstr, k, b, y, C=0, X=0):
        RRm, Rv = 0x100, 0x40
        Rf = ((C or 0) * 0x25C5 + (X or 0) * 0x552D + (k or 0) * 0x757B + 0x6987824E) % M
        n = len(Rstr)
        RU = [c ^ self._mask(i, n, Rf, 0x67, Rv, 8) for i, c in enumerate(Rstr, 1)]
        dec = self.Rz(bytes(RU), k, self.RA, b, y)
        m = len(dec)
        RXv = ((self.RA % RRm) + (k or 0) * 0x9F + ((b or 0) % RRm) + ((y or 0) % RRm)) % RRm
        out = []
        for i in range(1, m + 1):
            Ry = dec[i - 1] ^ self._mask(i, m, Rf, 0x67, Rv, 8)
            out.append(self.S[(Ry + RXv + i * 0x35) % RRm])
            RXv = (RXv * 0xFA + Ry + 0xDF) % RRm
        return bytes(out)

    def RB(self, Rstr, k, b, y, C=0, X=0):
        RRm, Rv = 0x100, 0x40
        RXv = ((C or 0) * 0x3FDB + (X or 0) * 0x369 + (k or 0) * 0x39E7 + 0xC555984B) % M
        n = len(Rstr)
        Rs = [c ^ self._mask(i, n, RXv, 0x85, Rv, 8) for i, c in enumerate(Rstr, 1)]
        dec = self.Rz(bytes(Rs), k, self.RI, b, y)
        m = len(dec)
        Ry = ((self.RI % RRm) + (k or 0) * 0x9F + ((b or 0) % RRm) + ((y or 0) % RRm)) % RRm
        out = []
        for i in range(1, m + 1):
            RC = dec[i - 1] ^ self._mask(i, m, RXv, 0x85, Rv, 8)
            out.append(self.S[(RC + Ry + i * 0x35) % RRm])
            Ry = (Ry * 0xFA + RC + 0xDF) % RRm
        # `local Rb=RU while Rb>0 do RC=U(Rk[Rb])..RC Rb=Rb-1 end` PREPENDS while
        # Rb descends, so the result is in ASCENDING order -- NOT reversed.
        return bytes(out)

    # -------------------------------------------------------------- RG / Rr
    def _double(self, RRb):
        sign = 1 - 2 * ((RRb[8] - RRb[8] % 128) // 128)
        exp = (RRb[8] % 128) * 16 + (RRb[7] - RRb[7] % 16) // 16
        mant = ((RRb[7] % 16) * 2 ** 48 + RRb[6] * 2 ** 40 + RRb[5] * 2 ** 32
                + RRb[4] * 2 ** 24 + RRb[3] * 2 ** 16 + RRb[2] * 2 ** 8 + RRb[1])
        if exp == 0x7FF:
            return (float('inf') if mant == 0 else float('nan')) * sign
        if exp == 0:
            return sign * mant * 2.0 ** (-1074)
        return sign * (mant + 2.0 ** 52) * 2.0 ** (exp - 1075)

    def RG(self, y, R, k, b, C=0, X=0):
        Rv = 0x100
        RU = ((C or 0) * 0xC84B + (X or 0) * 0xECBD + R * 0x194F + 0xDD3AF7FA) % M
        Rdv = [y[i - 1] ^ ((RU + i * 0x3D) % Rv) for i in range(1, len(y) + 1)]
        Ry = self.RQ(Rdv, R, self.Rt, k, b)
        RC = ((self.Rt % Rv) + (R or 0) * 0x9F + ((k or 0) % Rv) + ((b or 0) % Rv)) % Rv
        RM = RX(RX(self.Rbv, R or 0), RX(k or 0, b or 0)) % Rv
        for i in range(1, len(Ry) + 1):
            Rk = Ry[i - 1] ^ ((RU + i * 0x3D) % Rv)
            Ry[i - 1] = self.S[(Rk + RC + i * 0x35) % Rv]
            RC = (RC * 0xFA + Rk + 0xDF) % Rv
        RRb = {}
        for i in range(1, 9):
            RRb[RP8[i - 1]] = (Ry[i - 1] + 0x10000 - RM - i * 0x29) % Rv
        return self._double(RRb), [RRb[i] for i in range(1, 9)]

    def Rr(self, y, R, k, b, C=0, X=0):
        Rv, RCm = 0x100, 0x10
        Rdv = ((C or 0) * 0xD2CD + (X or 0) * 0xC09 + R * 0xCBDD + 0x947B1426) % M
        RM = [y[i - 1] ^ ((Rdv + i * 0x5F) % Rv) for i in range(1, len(y) + 1)]
        RXv = self.RQ(RM, R, self.RH, k, b)
        Rs = ((self.RH % Rv) + (R or 0) * 0x9F + ((k or 0) % Rv) + ((b or 0) % Rv)) % Rv
        RL = RX(RX(self.Rbv, R or 0), RX(k or 0, b or 0)) % Rv
        for i in range(1, len(RXv) + 1):
            Rk = RXv[i - 1] ^ ((Rdv + i * 0x5F) % Rv)
            RXv[i - 1] = self.S[(Rk + Rs + i * 0x35) % Rv]
            Rs = (Rs * 0xFA + Rk + 0xDF) % Rv
        RRb = {}
        for i in range(1, 9):
            RRb[RP8[i - 1]] = (RXv[i - 1] + 0x10000 - RL - i * 0x29) % Rv
        return self._double(RRb), [RRb[i] for i in range(1, 9)]

    # ------------------------------------------------------- RY / RV dispatch
    def RY(self, v, R, k, b, y=0, C=0):
        return self.RK(v, R, k, b, y, C) if (R or 0) % 2 == 0 else self.RB(v, R, k, b, y, C)

    def RV(self, v, R, k, b, y=0, C=0):
        return self.RG(v, R, k, b, y, C) if (R or 0) % 2 == 0 else self.Rr(v, R, k, b, y, C)


# ------------------------------------------------------------- yo's Rx hash
PREFIX = 'KryvexObf_'          # kg-decoded RP[RU], cross-checks the known Kryvex prefix
_C1 = O(0x7B, 0x21, 0x33CD8F89, 0x1D084B76)
_C2 = O(0x62, 0x78, 2181449457, 0x26B2EA71)
_C3 = O(0x1D, 0x51, 0x29A76FCF, 0x2FC235B5)
_C4s = O(0x7B, 0x21, 0xCDC87BD3, 0x1413A203)
_C4t = O(0x7B, 0x21, 0xCDC87BD3, 336830979)
_C5 = O(0x6A, 0x1B, 0x3CFA3C24, 0x3595FE6E)


def Rx(X, j=0, f=0, U=0):
    """yo's 6th return value: hash of the decoded constant."""
    if isinstance(X, bytes):
        seq = list(X); is_str = True
    elif isinstance(X, (list, tuple)):
        seq = list(X); is_str = False
    else:
        seq = (PREFIX + g14(X)).encode('latin-1'); is_str = True
    RR = _C1
    RR = RX(RR, mulmod(_C2, (j or 0)))
    RR = RX(RR, (f or 0) % M)
    RR = RX(RR, Rd(U or 0, _C3))
    mul = _C4s if is_str else _C4t
    for c in seq:
        RR = (RR + c * mul) % M
        RR = RX(RR, Rd(RR, _C5))
    return RR
