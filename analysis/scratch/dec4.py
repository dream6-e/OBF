#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Layer 4, generalised: one parameterised decoder class + a spec per host method.
kG/yD/ki/ku each register their OWN copy of the same construction into the env
table; vu() picks one by RH (0->kG, 1->yD, 2->ki, >=3->ku).

Self-test: SPEC_yD must reproduce the strings already proven in round 4
('Topbar','Callback','fromHex',...) and Rs_final=0x5965A85E / RV3=0xF1DD0813 /
nChild=18 for the root proto.
"""
import math as _math
from final import O, Ro, Rd, RX, M, g14

M32 = 0x100000000


def mulmod(a, b, m=M32):
    p = a * b
    if abs(p) < 2 ** 53:
        return int(p) % m
    return int(_math.fmod(float(a) * float(b), float(m))) % m


def fx(a, b):
    """the 256x256 xor lookup table (yJ's first return) == a xor b on bytes"""
    return (int(a) % 256) ^ (int(b) % 256)


class Dec:
    """spec keys:
       kk        : the 2nd arg this method passes to kI's PRF (0/1/2/3)
       T8        : list of (keyexpr, ykeyexpr, mul, add, yslotexpr)
       ENV       : (ykeyexpr, mul, add, yslotexpr)   -> the value kH xor's into RC
       P2        : (ykeyexpr, mul, add, yslotexpr)   -> S-box driver #2 / round keys RA,RI
       P3        : (ykeyexpr, mul, add, yslotexpr)   -> S-box driver #3 / round keys Rt,RH
       BRANCHA   : list of 16 entries; each ('T8',expr) | ('SUM',e1,e2) | ('ARG',which)
       BSLOT     : {'b':e,'y':e,'v':e,'C':e}   branch-B overwrite positions (must match A)
       SCATTER   : 16 ints
       ROUNDS    : int
       RMAT      : 8 tuples of 4
       SBOX      : (mul, shift, aff1, aff2)
       PERM      : 8 ints
       RKCOEF    : (c7, a7, cB, aB, c3, a3, c5, a5)  round keys from (P3,P3,P2,P2)
       CHAIN     : (init_expr, step_expr)   for the 64-byte block cipher
       XOR8      : key_expr
       NUM       : {'even': (kc, step, rkey_name), 'odd': (...)}
       STR       : {'even': (kc, step, rkey_name), 'odd': (...)}
       kc        : (c1, c2, c3, K)
       rollcoef  : coefficient of idx in the layer-2 roll init
       sboxstep / rollmul / rolladd / numsub : shared per method
    """

    def __init__(self, Rp, RZ, PRF, spec):
        self.Rp, self.RZ, self.PRF, self.S_ = Rp, RZ, PRF, spec
        self.T8 = {}
        for ke, yk, mul, add, ys in spec['T8']:
            self.T8[O(*ke)] = PRF(Ro(Rp[O(*yk)], (RZ * mul + add) % M32), spec['kk'], O(*ys))
        self.ENV = self._prf(spec['ENV'])
        self.P2 = self._prf(spec['P2'])
        self.P3 = self._prf(spec['P3'])
        # S-box
        mul, sh, a1, a2 = spec['SBOX']
        A, B, Cc = self.ENV % 256, self.P2 % 256, self.P3 % 256
        self.S = [0] * 256
        for X in range(256):
            t = (X * mul + A) % 256
            t = fx(t, (t - t % (1 << sh)) // (1 << sh))
            u = (t * a1 + B) % 256
            u = fx(u, (u - u % (1 << sh)) // (1 << sh))
            self.S[X] = (u * a2 + Cc) % 256
        # round keys
        c7, a7, cB, aB, c3, a3, c5, a5 = spec.get('RKCOEF', (7, 0x37, 0xB, 0x4D, 3, 0x11, 5, 0x23))
        e = self.ENV % 0x10000
        self.RKA = (self.P3 + e * c7 + a7) % M32
        self.RKI = (self.P3 + e * cB + aB) % M32
        self.RKN = (self.P2 + e * c3 + a3) % M32
        self.RKG = (self.P2 + e * c5 + a5) % M32
        self.RKEY = {'RA': self.RKA, 'RI': self.RKI, 'RN': self.RKN, 'RG': self.RKG}
        self.CHAIN0 = O(*spec['CHAIN'][0])
        self.CHAINSTEP = O(*spec['CHAIN'][1])
        self.XOR8K = O(*spec['XOR8'])
        self.nbranch = 0

    def _prf(self, sp):
        yk, mul, add, ys = sp
        return self.PRF(Ro(self.Rp[O(*yk)], (self.RZ * mul + add) % M32), self.S_['kk'], O(*ys))

    # ---------------- key expansion (yD's RE / kG's Rz) ----------------
    def keyexp(self, y, v, C, b):
        sp = self.S_
        st = {}
        for i, e in enumerate(sp['BRANCHA'], 1):
            if e[0] == 'T8':
                st[i] = self.T8[O(*e[1])]
            elif e[0] == 'SUM':
                st[i] = (O(*e[1]) + O(*e[2])) % M32
            else:
                st[i] = {'y': y, 'b': b, 'C': C, 'v': v}[e[1]]
        snap = dict(st)
        for _ in range(sp['ROUNDS']):
            for q in sp['RMAT']:
                self._Q(st, q[0], q[1], q[2], q[3])
        out = {}
        for i in range(1, 17):
            Rv = sp['SCATTER'][i - 1]
            x = (st[i] + snap[i]) % M32
            out[Rv] = x % 256
            out[Rv + 1] = (x // 256) % 256
            out[Rv + 2] = (x // 0x10000) % 256
            out[Rv + 3] = (x // 0x1000000) % 256
        return out

    @staticmethod
    def _Q(st, i1, i2, i3, i4):
        st[i1] = (st[i1] + st[i2]) % M32
        st[i4] = RX(st[i4], st[i1]); st[i4] = Rd(st[i4], 16)
        st[i3] = (st[i3] + st[i4]) % M32
        st[i2] = RX(st[i2], st[i3]); st[i2] = Rd(st[i2], 12)
        st[i1] = (st[i1] + 0x17F89CED) % M32
        st[i1] = (st[i1] + 0xE8076313) % M32
        st[i1] = (st[i1] + st[i2]) % M32
        st[i4] = RX(st[i4], st[i1]); st[i4] = Rd(st[i4], 8)
        st[i3] = (st[i3] + st[i4]) % M32
        st[i2] = RX(st[i2], st[i3]); st[i2] = Rd(st[i2], 7)

    # ---------------- 8-byte xor (yD's RQ / kG's RP) ----------------
    def xor8(self, y, C, X, k, b):
        RC = RX(RX(self.ENV, b or 0), k or 0)
        Rk = Rd(b or 0, 7)
        RXv = RX(RX(Rk, (C * 6 + X) % M32), Rd(k or 0, 0xD))
        Rs = RX(RX(self.ENV, Rd(Rk, 7)), Rd(k or 0, 5))
        key = self.keyexp(RC, RXv, Rs, self.XOR8K)
        return [fx(y[i - 1], key[i]) for i in range(1, 9)]

    # ---------------- 64-byte block xor stream (yD's Rz / kG's Rt) ----------------
    def block(self, bs, C, X, k, y):
        Rs = RX(RX(self.ENV, y or 0), k or 0)
        RC = Rd(y or 0, 7)
        Rj = RX(RX(RC, (C * 6 + X) % M32), Rd(k or 0, 0xD))
        Rf = RX(RX(self.ENV, Rd(RC, 7)), Rd(k or 0, 5))
        n = len(bs)
        out = [0] * n
        pos = 0
        chain = self.CHAIN0
        while pos < n:
            key = self.keyexp(Rs, Rj, Rf, chain)
            end = min(pos + 64, n)
            cnt = 0
            fb = 0
            mul = 1
            while pos < end:
                kk = fx(bs[pos], key[cnt + 1])
                out[pos] = kk
                cnt += 1
                if cnt <= 8:
                    fb = (fb + kk * mul) % M32
                    mul = (mul * 0x100) % M32
                pos += 1
            chain = (chain + self.CHAINSTEP + fb) % M32
        return out

    @staticmethod
    def _mask(i, n, key, step):
        return 0 if (((i - 1) % 64) < 8 and (i - ((i - 1) % 64) + 64) <= n) else (key + i * step) % 256

    # ---------------- the four decoders ----------------
    def _num(self, y, R, k, b, kc, step, rkey):
        c1, c2, c3, K = kc
        sp = self.S_
        KK = ((0) * c1 + (0) * c2 + R * c3 + K) % M32
        d = [y[i - 1] ^ ((KK + i * step) % 256) for i in range(1, len(y) + 1)]
        e = self.xor8(d, R, self.RKEY[rkey], k, b)
        roll = ((self.RKEY[rkey] % 256) + (R or 0) * sp['rollcoef'] + ((k or 0) % 256) + ((b or 0) % 256)) % 256
        rm = RX(RX(self.ENV, R or 0), RX(k or 0, b or 0)) % 256
        for i in range(1, len(e) + 1):
            t = e[i - 1] ^ ((KK + i * step) % 256)
            e[i - 1] = self.S[(t + roll + i * sp['sboxstep']) % 256]
            roll = (roll * sp['rollmul'] + t + sp['rolladd']) % 256
        RRb = {}
        for i in range(1, 9):
            RRb[sp['PERM'][i - 1]] = (e[i - 1] + 0x10000 - rm - i * sp['numsub']) % 256
        return self._double(RRb), [RRb[i] for i in range(1, 9)]

    def _str(self, Rstr, R, k, b, kc, step, rkey):
        c1, c2, c3, K = kc
        sp = self.S_
        KK = ((0) * c1 + (0) * c2 + R * c3 + K) % M32
        n = len(Rstr)
        L1 = [cc ^ self._mask(i, n, KK, step) for i, cc in enumerate(Rstr, 1)]
        dec = self.block(bytes(L1), k, self.RKEY[rkey], b, y=None) if False else \
              self.block(bytes(L1), R, self.RKEY[rkey], k, b)
        m = len(dec)
        roll = ((self.RKEY[rkey] % 256) + (R or 0) * sp['rollcoef'] + ((k or 0) % 256) + ((b or 0) % 256)) % 256
        out = []
        for i in range(1, m + 1):
            t = dec[i - 1] ^ self._mask(i, m, KK, step)
            out.append(self.S[(t + roll + i * sp['sboxstep']) % 256])
            roll = (roll * sp['rollmul'] + t + sp['rolladd']) % 256
        return bytes(out)

    @staticmethod
    def _double(RRb):
        sign = 1 - 2 * ((RRb[8] - RRb[8] % 128) // 128)
        exp = (RRb[8] % 128) * 16 + (RRb[7] - RRb[7] % 16) // 16
        mant = ((RRb[7] % 16) * 2 ** 48 + RRb[6] * 2 ** 40 + RRb[5] * 2 ** 32
                + RRb[4] * 2 ** 24 + RRb[3] * 2 ** 16 + RRb[2] * 2 ** 8 + RRb[1])
        if exp == 0x7FF:
            return (float('inf') if mant == 0 else float('nan')) * sign
        if exp == 0:
            return sign * mant * 2.0 ** (-1074)
        return sign * (mant + 2.0 ** 52) * 2.0 ** (exp - 1075)

    # ---------------- dispatchers ----------------
    def num(self, v, R, k, b, y=0, C=0):
        w = 'even' if (R or 0) % 2 == 0 else 'odd'
        kc, step, rkey = self.S_['NUM'][w]
        return self._num(v, R, k, b, kc, step, rkey)

    def string(self, v, R, k, b, y=0, C=0):
        w = 'even' if (R or 0) % 2 == 0 else 'odd'
        kc, step, rkey = self.S_['STR'][w]
        return self._str(v, R, k, b, kc, step, rkey)


# =============================================================== yD spec (RH==1)
SPEC_yD = dict(
    kk=1,
    T8=[
        ((0x1D, 0x51, 764102583, 735993286), (0x62, 0x78, 0x1F0B0FC1, 442685210), 0x07A05, 0x2452BA5D, (0x1D, 0x51, 764102583, 735993286)),
        ((0x26, 0x32, 0x14154479, 0x15F8FB0E), (0x79, 0x6B, 901970920, 393274714), 0x4BBD, 0x48221848, (0x26, 0x32, 0x14154479, 368638734)),
        ((0x6A, 0x52, 0x241F863C, 558245791), (0x1D, 0x51, 0x37559378, 571740672), 0xB9E7, 3560960021, (0x6A, 0x52, 0x241F863C, 0x2146279F)),
        ((0x79, 0x4C, 0x38ACB0E6, 1045443622), (0x35, 0x64, 0x5CF1384C, 538792791), 17025, 0xA72F84FE, (0x79, 0x4C, 950841574, 1045443622)),
        ((0x75, 0x68, 0x10224368, 0x3E637CA2), (0x35, 0x64, 0x65AFE157, 0x175EAA4E), 49901, 0xF554F14D, (0x75, 0x68, 0x10224368, 0x3E637CA2)),
        ((0x75, 0x68, 330461813, 986926487), (0x26, 0x33, 873077588, 0x3FDF5B7B), 0x1F33, 0xB7D0034E, (0x75, 0x68, 330461813, 0x3AD34D97)),
        ((0x7B, 0x21, 0x34CBA150, 0x32D82144), (0x6F, 0x51, 421320708, 0x1F582F6A), 0xD3B7, 0x51B8D476, (0x7B, 0x21, 0x34CBA150, 853025092)),
        ((0x62, 0x78, 0x2041FD75, 623388068), (0x26, 0x32, 0x2D5FCDDE, 749892264), 0x4987, 558832363, (0x62, 0x78, 541195637, 623388068)),
    ],
    ENV=((0x6F, 0x51, 421320708, 0x1F582F6A), 0xD3B7, 0x51B8D476, (0x7B, 0x21, 0x36D2BB15, 0x30C13B09)),
    P2=((0x1D, 0x51, 0x37559378, 0x22141200), 0xB9E7, 3560960021, (0x60, 0x27, 0x504DDB73, 0x2F70F09A)),
    P3=((0x35, 0x64, 0x5CF1384C, 0x201D5357), 17025, 2804909310, (0x79, 0x6B, 0x2E86D239, 0x1EAD0F0D)),
    BRANCHA=[('T8', (0x75, 0x68, 0x18A528D5, 0x35E09735)),
             ('SUM', (0x7B, 0x63, 0xF053B4A5, 654600907), (0x6A, 0x1B, 0xED327D4F, 0x3AA9D3DE)),
             ('T8', (0x62, 0x78, 0x12BA86CC, 0x17D35E12)),
             ('SUM', (0x62, 0x78, 0xDDA56D1C, 993399745), (0x6A, 0x52, 2658480422, 470364151)),
             ('ARG', 'y'), ('ARG', 'b'),
             ('T8', (0x62, 0x78, 0x1E47ABE4, 0x1B2E733B)),
             ('T8', (0x35, 0x64, 0x55DD1F9F, 0x27316C02)),
             ('T8', (0x6F, 0x5E, 0x19F328F9, 823821274)),
             ('SUM', (0x79, 0x4C, 0x73825D67, 0x39B8E17C), (0x1D, 0x20, 0xC6E6F645, 0x255755A8)),
             ('SUM', (0x6A, 0x1B, 0x1ADE92AD, 0x10E05859), (0x6F, 0x5E, 3742049179, 0x2C3605E1)),
             ('T8', (0x6F, 0x51, 452202161, 0x1CB0F9DF)),
             ('ARG', 'C'),
             ('T8', (0x7B, 0x63, 1085410106, 0x2A81B287)),
             ('ARG', 'v'),
             ('T8', (0x60, 0x2D, 0x25E331D1, 630160691))],
    BSLOT={'b': (0x62, 0x78, 625887520, 539464191), 'y': (0x60, 0x2D, 511135027, 0x1E1B01D5),
           'v': (0x35, 0x20, 659323554, 0x20033FDA), 'C': (0x62, 0x78, 604691578, 0x216304AE)},
    SCATTER=[33, 1, 0x29, 0xD, 0x35, 49, 0x25, 0x1D, 0x15, 0x5, 0x9, 0x19, 0x3D, 0x2D, 0x39, 0x11],
    ROUNDS=5,
    RMAT=[[2, 16, 1, 6], [4, 8, 14, 13], [11, 12, 3, 15], [10, 9, 7, 5],
          [4, 16, 7, 15], [2, 9, 3, 13], [10, 12, 14, 6], [11, 8, 1, 5]],
    SBOX=(0x8B, 4, 0x15, 0x45),
    PERM=[5, 7, 6, 1, 3, 4, 2, 8],
    RKCOEF=(7, 0x37, 0xB, 0x4D, 3, 0x11, 5, 0x23),
    CHAIN=((0x6F, 0x5E, 3706357943, 0x3A0F5948), (0x35, 0x20, 0x25D04295, 816239511)),
    XOR8=(0x6F, 0x5E, 3706357943, 0x3A0F5948),
    rollcoef=0x9F, sboxstep=0x35, rollmul=0xFA, rolladd=0xDF, numsub=0x29,
    NUM={'even': ((0xC84B, 0xECBD, 0x194F, 0xDD3AF7FA), 0x3D, 'RA_Rt'),
         'odd':  ((0xD2CD, 0xC09, 0xCBDD, 0x947B1426), 0x5F, 'RA_Rt2')},
    STR={'even': ((0x25C5, 0x552D, 0x757B, 0x6987824E), 0x67, 'RK_RA'),
         'odd':  ((0x3FDB, 0x369, 0x39E7, 0xC555984B), 0x85, 'RK_RI')},
)
# yD's numeric pair uses round keys Rt / RH (built from RO=P3), string pair RA / RI (from RW=P2)
SPEC_yD['NUM'] = {'even': ((0xC84B, 0xECBD, 0x194F, 0xDD3AF7FA), 0x3D, 'Tt'),
                  'odd':  ((0xD2CD, 0xC09, 0xCBDD, 0x947B1426), 0x5F, 'TH')}
SPEC_yD['STR'] = {'even': ((0x25C5, 0x552D, 0x757B, 0x6987824E), 0x67, 'RA'),
                  'odd':  ((0x3FDB, 0x369, 0x39E7, 0xC555984B), 0x85, 'RI')}


def _build_rkeys(self):
    c7, a7, cB, aB, c3, a3, c5, a5 = self.S_['RKCOEF']
    e = self.ENV % 0x10000
    self.RKEY = {}
    for nm, base, cc, aa in self.S_['RKSRC']:
        self.RKEY[nm] = (base + e * cc + aa) % M32


# =============================================================== kG spec (RH==0)
SPEC_kG = dict(
    kk=0,
    T8=[
        ((0x62, 0x78, 0x25D47C44, 549299354), (0x26, 0x33, 873077588, 0x3FDF5B7B), 7987, 0xB7D0034E, (0x62, 0x78, 0x25D47C44, 549299354)),
        ((0x6F, 0x5E, 0x2DA29150, 0x1D6B1B85), (0x79, 0x6B, 0x35C2FBE8, 0x1770E55A), 0x4BBD, 0x48221848, (0x6F, 0x5E, 0x2DA29150, 0x1D6B1B85)),
        ((0x79, 0x6B, 0x1699B0B4, 0x369A3088), (0x6F, 0x51, 421320708, 0x1F582F6A), 0xD3B7, 0x51B8D476, (0x79, 0x6B, 0x1699B0B4, 0x369A3088)),
        ((0x60, 0x27, 1102114514, 1041095988), (0x35, 0x64, 0x5CF1384C, 538792791), 17025, 2804909310, (0x60, 0x27, 0x41B0EED2, 0x3E0DDD34)),
        ((0x35, 0x20, 0x3B1A7114, 0x3C55346B), (0x26, 0x32, 0x2D5FCDDE, 749892264), 0x4987, 0x214F1AEB, (0x35, 0x20, 0x3B1A7114, 0x3C55346B)),
        ((0x35, 0x20, 0x11E70A73, 0x16A84F01), (0x35, 0x64, 0x65AFE157, 392079950), 49901, 0xF554F14D, (0x35, 0x20, 0x11E70A73, 0x16A84F01)),
        ((0x35, 0x64, 0x6A26F94E, 317166161), (0x1D, 0x51, 928355192, 0x22141200), 0xB9E7, 3560960021, (0x35, 0x64, 1780939086, 0x12E79251)),
        ((0x1D, 0x20, 436273927, 535464826), (0x62, 0x78, 0x1F0B0FC1, 0x1A62D71A), 0x7A05, 0x2452BA5D, (0x1D, 0x20, 0x1A010307, 535464826)),
    ],
    ENV=((0x6F, 0x51, 0x191CD804, 0x1F582F6A), 0xD3B7, 0x51B8D476, (0x35, 0x64, 0x3DFD00BF, 0x3F118AE7)),
    P2=((0x1D, 0x51, 928355192, 0x22141200), 0xB9E7, 3560960021, (0x26, 0x33, 1068252417, 0x343D39D4)),
    P3=((0x35, 0x64, 0x5CF1384C, 538792791), 17025, 2804909310, (0x79, 0x4C, 0x160C9F31, 0x10F01BF9)),
    BRANCHA=[('T8', (0x1D, 0x20, 0x2B99A408, 0x2E722C7B)),
             ('ARG', 'y'), ('ARG', 'C'),
             ('T8', (0x7B, 0x63, 1365552575, 0x19CF0FFF)),
             ('SUM', (0x7B, 0x63, 0x9D637170, 0x10E9A53B), (0x75, 0x68, 0x6E04E5E4, 382316129)),
             ('T8', (0x6F, 0x5E, 0x1224637C, 0x38E9495C)),
             ('ARG', 'b'),
             ('T8', (0x6F, 0x5E, 0x17FEE03C, 0x330ECC99)),
             ('T8', (0x79, 0x4C, 0x2C4B1495, 716673111)),
             ('ARG', 'v'),
             ('T8', (0x62, 0x64, 1182231081, 0x2DBF79F8)),
             ('SUM', (0x6F, 0x51, 1746807910, 0x16BC37C3), (0x6A, 0x52, 3698542026, 832794614)),
             ('T8', (0x35, 0x64, 0x627919FC, 446001575)),
             ('SUM', (0x35, 0x20, 2595951223, 0x29960D92), (0x79, 0x4C, 0xAA304439, 443730456)),
             ('T8', (0x6F, 0x5E, 0x10272F76, 0x3AE67D5E)),
             ('SUM', (0x1D, 0x51, 0x9E611604, 0x3129B67A), (0x62, 0x78, 0x8E7EF4CA, 937955700))],
    BSLOT={'b': (0x79, 0x6B, 0x1ABD7895, 0x327668AD), 'y': (0x60, 0x27, 1850345039, 0x1174C5B6),
           'v': (0x62, 0x78, 0x2BAFDFBB, 784729960), 'C': (0x35, 0x64, 0x5D73E327, 0x1F9AA879)},
    SCATTER=[0x2D, 0x35, 61, 0x21, 9, 0x29, 0x31, 29, 17, 0x39, 0x15, 1, 0x25, 13, 0x19, 5],
    ROUNDS=4,
    RMAT=[[0xE, 0x8, 1, 3], [16, 11, 13, 2], [5, 0xF, 6, 10], [0xC, 9, 4, 7],
          [0xC, 0xB, 6, 3], [5, 8, 4, 2], [16, 15, 1, 7], [14, 9, 0xD, 10]],
    SBOX=(0x79, 4, 0x5B, 0x77),
    PERM=[2, 7, 5, 1, 6, 3, 4, 8],
    RKCOEF=(7, 0x37, 0xB, 0x4D, 3, 0x11, 5, 0x23),
    CHAIN=((0x79, 0x4C, 0x276CF7, 0x26118CE9), (0x6F, 0x51, 0x9015094, 0x201F8E68)),
    XOR8=(0x79, 0x4C, 0x276CF7, 0x26118CE9),
    rollcoef=0x4D, sboxstep=0xD3, rollmul=0xB2, rolladd=0x2F, numsub=0xB9,
    NUM={'even': ((0x4CE5, 0xB3F5, 0x36B7, 0x51588D0E), 0xE1, 'RA'),
         'odd':  ((0x10A7, 0x1C9B, 0x8BDD, 0xFB74CD90), 0x37, 'RI')},
    STR={'even': ((0x5013, 0x9B0F, 0xFC59, 0xD688C2AB), 0xDB, 'RN'),
         'odd':  ((0xE957, 0xA20F, 0x8B93, 0x4498FC72), 0x69, 'RG')},
    # kG: RA,RI come from RE(=P3); RN,RG come from RQ(=P2)
    RKSRC=[('RA', 'P3', 7, 0x37), ('RI', 'P3', 0xB, 0x4D),
           ('RN', 'P2', 3, 0x11), ('RG', 'P2', 5, 0x23)],
)
# yD: RA,RI from RW(=P2); Rt,RH from RO(=P3)
SPEC_yD['RKSRC'] = [('RA', 'P2', 3, 0x11), ('RI', 'P2', 5, 0x23),
                    ('Tt', 'P3', 7, 0x37), ('TH', 'P3', 0xB, 0x4D)]

Dec._build_rkeys = _build_rkeys
_orig_init = Dec.__init__


def _init(self, Rp, RZ, PRF, spec):
    _orig_init(self, Rp, RZ, PRF, spec)
    srcs = {'P2': self.P2, 'P3': self.P3, 'ENV': self.ENV}
    self.RKEY = {}
    for nm, base, cc, aa in spec['RKSRC']:
        self.RKEY[nm] = (srcs[base] + (self.ENV % 0x10000) * cc + aa) % M32


Dec.__init__ = _init

# =============================================================== ki spec (RH==2)
SPEC_ki = dict(
    kk=2,
    T8=[
        ((0x1D,0x20,0x1043A2AE,363342557),(0x26,0x32,0x2D5FCDDE,0x2CB272A8),0x4987,0x214F1AEB,(0x1D,0x20,0x1043A2AE,363342557)),
        ((0x35,0x64,0x6511D7E8,402437052),(0x26,0x33,0x340A1B54,0x3FDF5B7B),0x1F33,0xB7D0034E,(0x35,0x64,0x6511D7E8,0x17FCB3BC)),
        ((0x35,0x64,0x41AEFE63,996117821),(0x35,0x64,0x5CF1384C,538792791),17025,2804909310,(0x35,0x64,0x41AEFE63,0x3B5F8D3D)),
        ((0x79,0x6B,0x3641EC42,0x16F1F4FF),(0x62,0x78,0x1F0B0FC1,442685210),31237,0x2452BA5D,(0x79,0x6B,0x3641EC42,384955647)),
        ((0x26,0x33,0x3B6D778A,0x387BFF45),(0x79,0x6B,901970920,0x1770E55A),0x4BBD,0x48221848,(0x26,0x33,0x3B6D778A,0x387BFF45)),
        ((0x6A,0x52,331865969,0x169E7ED1),(0x6F,0x51,421320708,0x1F582F6A),54199,0x51B8D476,(0x6A,0x52,331865969,379485905)),
        ((0x1D,0x20,0x2426E3DE,0x21CD6BA7),(0x1D,0x51,0x37559378,571740672),47591,3560960021,(0x1D,0x20,0x2426E3DE,0x21CD6BA7)),
        ((0x62,0x78,0x1566B719,0x100F6FC5),(0x35,0x64,0x65AFE157,392079950),0xC2ED,0xF554F14D,(0x62,0x78,359053081,0x100F6FC5)),
    ],
    ENV=((0x6F,0x51,421320708,0x1F582F6A),0xD3B7,0x51B8D476,(0x60,0x2D,0x196E1538,419584466)),
    P2=((0x1D,0x51,928355192,571740672),47591,0xD43FF015,(0x7B,0x63,0x3EA84316,747338413)),
    P3=((0x35,0x64,0x5CF1384C,0x201D5357),17025,0xA72F84FE,(0x26,0x33,1337905162,0x242AA6CC)),
    BRANCHA=[('SUM',(0x1D,0x51,0x7922A452,351803729),(0x6F,0x51,0x1AD10E89,0x302A99DD)),
             ('T8',(0x6F,0x5E,960300590,298886824)),('T8',(0x60,0x2D,0x1993DC7F,0x19FF909F)),
             ('T8',(0x62,0x64,0x5F89BCD9,0x14AD274C)),('T8',(0x79,0x6B,0x230020C7,0x2A33C07B)),
             ('T8',(0x7B,0x21,0x3A7A1EA0,0x3C699EBD)),
             ('SUM',(0x6F,0x5E,3976880791,668758274),(0x26,0x32,0xB0B9EDE4,0x10136C3B)),
             ('ARG','y'),('T8',(0x35,0x20,0x3FFBB958,0x38B4FC2E)),('T8',(0x75,0x68,0x1DA1C329,0x30E3FCE0)),
             ('ARG','v'),
             ('SUM',(0x7B,0x63,1394801098,0x3049620B),(0x79,0x4C,0xAE53814,0x16FE7A85)),
             ('SUM',(0x26,0x32,0x4644AB7F,808575491),(0x79,0x4C,984909938,0x3D813B92)),
             ('ARG','C'),('ARG','b'),('T8',(0x75,0x68,467955033,0x32A152AE))],
    BSLOT={'b':(0x1D,0x51,0x2B4AA031,0x2E1F0555),'y':(0x26,0x33,0x4562B8A4,0x2E86BE2F),
           'v':(0x6A,0x52,0x34E4F0AE,0x31BD5104),'C':(0x60,0x27,0x5D655F8F,0x22596C82)},
    SCATTER=[1,33,25,37,41,0x2D,13,53,17,0x1D,0x39,5,9,0x3D,0x31,0x15],
    ROUNDS=4,
    RMAT=[[0xD,3,5,11],[7,0xA,6,14],[1,9,2,0xF],[12,0x10,4,8],
          [0xD,0xA,2,8],[7,9,4,0xB],[0xC,3,6,0xF],[1,16,5,0xE]],
    SBOX=(0xA5,4,0x99,0x6B),
    PERM=[1,8,4,3,5,6,2,7],
    CHAIN=((0x75,0x4C,0xC490FB8,0x1A896198),(0x6A,0x1B,0x6C782752,0x35C5DF46)),
    XOR8=(0x75,0x4C,0xC490FB8,0x1A896198),
    rollcoef=0xE9, sboxstep=0xB5, rollmul=0x16, rolladd=0xCB, numsub=0x9B,
    NUM={'even':((0x4CF3,0x559,0xF289,0x5775F750),0x91,'RH'),
         'odd' :((0x18F1,0x880F,0x2C25,0xC40A849B),0x45,'RA')},
    STR={'even':((0xE1D,0x134D,0x7F29,0x3433D592),0x3,'RI'),
         'odd' :((0xB273,0x4DE1,0x4A7F,0xF8582F51),0x81,'RN')},
    RKSRC=[('RH','P3',7,0x37),('RA','P3',0xB,0x4D),('RI','P2',3,0x11),('RN','P2',5,0x23)],
)

# =============================================================== ku spec (RH>=3)
SPEC_ku = dict(
    kk=3,
    T8=[
        ((0x35,0x20,0x1D9DEA7E,0x1AD2AF01),(0x26,0x32,0x2D5FCDDE,0x2CB272A8),0x4987,0x214F1AEB,(0x35,0x20,0x1D9DEA7E,0x1AD2AF01)),
        ((0x35,0x64,0x58581D39,0x24B66E6B),(0x26,0x33,873077588,0x3FDF5B7B),7987,0xB7D0034E,(0x35,0x64,0x58581D39,615935595)),
        ((0x1D,0x20,0x1B67DA78,0x1E8C5205),(0x62,0x78,0x1F0B0FC1,0x1A62D71A),0x7A05,0x2452BA5D,(0x1D,0x20,0x1B67DA78,0x1E8C5205)),
        ((0x75,0x68,0x2A2C07F8,0x2459B810),(0x35,0x64,0x5CF1384C,0x201D5357),17025,0xA72F84FE,(0x75,0x68,0x2A2C07F8,0x2459B810)),
        ((0x6A,0x52,0x3518F2F4,0x30415357),(0x1D,0x51,0x37559378,571740672),47591,3560960021,(0x6A,0x52,0x3518F2F4,0x30415357)),
        ((0x7B,0x63,0x38DEC498,0x3254F925),(0x79,0x6B,901970920,0x1770E55A),0x4BBD,0x48221848,(0x7B,0x63,0x38DEC498,0x3254F925)),
        ((0x35,0x20,0x3B8A2272,0x3CC56704),(0x6F,0x51,421320708,0x1F582F6A),0xD3B7,0x51B8D476,(0x35,0x20,0x3B8A2272,0x3CC56704)),
        ((0x62,0x64,0x45430DA9,787732091),(0x35,0x64,0x65AFE157,392079950),0xC2ED,0xF554F14D,(0x62,0x64,0x45430DA9,0x2EF3D67B)),
    ],
    ENV=((0x6F,0x51,421320708,0x1F582F6A),0xD3B7,0x51B8D476,(0x75,0x4C,612762105,633128481)),
    P2=((0x1D,0x51,0x37559378,571740672),0xB9E7,3560960021,(0x79,0x4C,0x2AE1A61E,740106967)),
    P3=((0x35,0x64,0x5CF1384C,538792791),0x4281,0xA72F84FE,(0x60,0x2D,0x3B8F78EA,0x3BE33402)),
    BRANCHA=[('SUM',(0x79,0x4C,0x9404D766,0x26ABCF32),(0x1D,0x51,0xFFADDF90,0x10888EC4)),
             ('ARG','C'),('T8',(0x60,0x27,0x4CDEF0C5,0x32DFDB45)),('ARG','v'),
             ('T8',(0x7B,0x21,0x20D09A74,650320487)),
             ('SUM',(0x35,0x20,0xBB4BEB0,0x2C0681E3),(0x75,0x4C,0xBD7B9EA,0x18CF9471)),
             ('T8',(0x35,0x20,0x19DBC3A6,0x1E9486D0)),('T8',(0x26,0x33,0x5082EA54,593923193)),
             ('SUM',(0x75,0x68,1034757159,0x1AB10E8C),(0x60,0x27,0x987720DE,0x3EDFB0DC)),
             ('T8',(0x79,0x4C,0x11A6A8A2,0x175A2C69)),('T8',(0x62,0x78,0x1C679624,420368120)),
             ('T8',(0x75,0x4C,871735546,852453160)),('T8',(0x79,0x6B,0x19D6C7F8,0x335D1947)),
             ('ARG','b'),
             ('SUM',(0x35,0x20,4208865665,0x38FCFF09),(0x1D,0x20,0x8F3BA202,958696266)),
             ('ARG','y')],
    BSLOT={'b':(0x35,0x20,0x1383E267,348956446),'y':(0x6F,0x5E,0x2E466525,0x1CC747BC),
           'v':(0x6F,0x5E,512785319,746402094),'C':(0x79,0x6B,0x3990452D,0x13A39C10)},
    SCATTER=[0xD,61,0x29,0x39,0x25,5,0x11,0x15,1,45,0x21,0x19,0x1D,0x31,9,53],
    ROUNDS=6,
    RMAT=[[15,0xC,3,4],[1,13,0xA,2],[6,8,5,0x10],[9,7,0xB,14],
          [0xF,0xD,0xB,0x10],[1,7,5,4],[9,8,3,2],[6,12,10,0xE]],
    SBOX=(0x45,4,0xC9,0x9B),
    PERM=[4,3,7,1,5,2,8,6],
    CHAIN=((0x7B,0x63,0xAA723BCD,0x1A5D51E4),(0x79,0x6B,0xC40B279C,0x3B45E17C)),
    XOR8=(0x7B,0x63,0xAA723BCD,0x1A5D51E4),
    rollcoef=0xBB, sboxstep=0x37, rollmul=0x6, rolladd=0xE7, numsub=0x2B,
    NUM={'even':((0xA5DD,0x1AA5,0x2C2B,0x6E8D97BD),0xB5,'RH'),
         'odd' :((0xC069,0x2E1F,0xC1E7,0x59BF9FCD),0xFD,'RA')},
    STR={'even':((0xA7AB,0x9FFF,0xFAB7,0xFBAE65EC),0x85,'RI'),
         'odd' :((0x305D,0xD1DB,0x7D1D,0x10EF8897),0xB7,'RN')},
    RKSRC=[('RH','P3',7,0x37),('RA','P3',0xB,0x4D),('RI','P2',3,0x11),('RN','P2',5,0x23)],
)
SPECS = {0: SPEC_kG, 1: SPEC_yD, 2: SPEC_ki, 3: SPEC_ku}
