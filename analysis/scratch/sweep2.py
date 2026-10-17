#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wide structural sweep over the stage-2 inner cipher.

Every branch of the transcription has now been verified against the Lua source
(bk slot table triple-checked via the RI/RN handler keys 4/26/56; env table
fully resolved via bR; yS/yJ/kA/kF/kI/kd/vu argument bindings all confirmed by
the ':'-method-call convention).  Yet the kQ oracle still fails, so this sweep
looks for a *structural* fault instead of a constant fault.

Oracle (all from vu()/kd()/the interpreter):
  yt = RS()#14  = numparams      -> must be <= #args, so tiny (0..8)
  yQ = RS()#16  = frame offset   -> small
  kQ            = kd loop bound  -> 0 < kQ < 8000  (16 bytes/iter, 119405 budget)
  Rh            = const-setup rounds -> small
"""
import sys, itertools, math
sys.path.insert(0, '/home/user/OBF/analysis/scratch')
from crack import (O, Ro, Rd as rotl32, kA_xor, rotr8, compute_RZ, Rf, kI,
                   compute_RV, P1, P2, XV, A1)

M = 1 << 32
RC_ = 0x7FFFFFFF
DATA = open('/home/user/OBF/analysis/stage2_bytecode.bin', 'rb').read()


def rotr32(v, k):
    v %= M
    return ((v >> k) | (v << (32 - k))) % M if k else v % M


class C:
    """Parameterised RS()/Rw() so every suspect dimension can be varied."""

    def __init__(self, va, st, pos0, vUdelta=0, rot=rotl32,
                 c82src='Ru', c48dir='rotr', pack='src', sign=+1):
        self.va, self.pos, self.vUd = va, pos0, vUdelta
        self.Rc, self.RF, self.Ru, self.Rx = st
        self.vU = 4
        self.rot, self.c82src, self.c48dir, self.pack, self.sign = \
            rot, c82src, c48dir, pack, sign

    def vf(self):
        b = DATA[self.pos]
        self.pos += 1
        return b

    def RS(self):
        RW = self.vf()
        self.vU = self.pos + self.vUd
        vU = self.vU
        z = RW
        # RR[41]
        z = (z + 256 - ((self.Rx + (vU % 256) * 7) % 256)) % 256
        # RR[48]
        z = rotr8(z, 3) if self.c48dir == 'rotr' else ((z << 3) | (z >> 5)) & 0xFF
        # RR[82]
        z = kA_xor(z, getattr(self, self.c82src))
        # RR[22]
        z = (z + 256 - ((self.Rc + self.RF + (vU % 256) * 0xC3) % 256)) % 256
        Ry = z
        RO = vU % RC_
        Rt = self.va % RC_
        RE = (Rt + RO * P1 + (XV % RC_)) % RC_
        RL = (Rt * 0x101 + RO * P2 + P1 * 0x11) % RC_
        for _ in range(3):
            n1 = (RE * ((RL % 0x10000) + P1 + 0x101) + RL * 0x101
                  + RO * (0x11 + XV % 0x1F) + Rt) % RC_
            n2 = (RL * ((n1 % 0x10000) + P2 + 0x107) + n1 * 0x81
                  + RO * (0x17 + A1) + XV) % RC_
            RE, RL = n1, n2
        RA = (RE % 256 + (RL % 256) * 3 + (RO % 256) * 5 * self.sign
              + ((RE - RE % 256) // 256) % 256
              + ((RL - RL % 256) // 256) % 256) % 256
        Ry = kA_xor(Ry, RA)
        R, v = Ry, RW
        self.Rc = kA_xor(rotr8((self.Rc + R + self.Rx + (vU % 256)) % 256, 5), v)
        self.RF = rotr8((self.RF * 5 + v + kA_xor(R, self.Rc)) % 256, 2)
        self.Ru = kA_xor(rotr8((self.Ru + R + v + self.RF + 7) % 256, 5), self.Rx)
        self.Rx = rotr8((self.Rx + v + R + self.Rc + self.Ru + 7) % 256, 1)
        return Ry % M

    def Rw(self):
        q = [self.RS() for _ in range(4)]
        if self.pack == 'src':                      # Rk + Rb*2^24 + Ry*2^8 + RC*2^16
            return q[0] + q[3] * 16777216 + q[1] * 256 + q[2] * 65536
        if self.pack == 'le':
            return q[0] | (q[1] << 8) | (q[2] << 16) | (q[3] << 24)
        if self.pack == 'be':
            return (q[0] << 24) | (q[1] << 16) | (q[2] << 8) | q[3]
        raise ValueError(self.pack)


def probe(**kw):
    """Run vu() state 3358 + kd's kQ for one variant.  Returns dict or None."""
    off = kw.pop('pos0', 0)
    RZ = kw.pop('RZ', None) or compute_RZ()
    seed = [DATA[off + i] for i in range(4)]
    Rp, va, k1, b1, y1, C1 = kI(RZ, seed[0], seed[1], seed[2], seed[3])
    RV = compute_RV(Rp, RZ)
    if kw.pop('rawstate', False):
        k1, b1, y1, C1 = seed
    rotfn = {'rotl': rotl32, 'rotr': rotr32}[kw.pop('rot', 'rotl')]
    c = C(va, (k1, b1, y1, C1), off + 4, rot=rotfn, **kw)
    rot = rotfn
    try:
        kE = kA_xor(c.Rw(), RV)
        kz = kA_xor(c.Rw(), kA_xor(rot(kE, 0x5), rot(RV, 0xB)))
        kP = kA_xor(c.Rw(), kA_xor(rot(kE, 0xD), rot(RV, 0x13)))
        yE, yt, yl, yQ = c.RS(), c.RS(), c.RS(), c.RS()
        kQ = Ro(c.Rw(), Ro(rot(kE, 0xB), rot(RV, 0x7)))
    except IndexError:
        return None
    return dict(va=va, RV=RV, kE=kE, kz=kz, kP=kP, yE=yE, yt=yt, yl=yl,
                yQ=yQ, kQ=kQ, state=(k1, b1, y1, C1))


def score(r):
    if r is None:
        return -1
    s = 0
    if r['yt'] <= 8:      s += 4
    if r['yt'] <= 2:      s += 4
    if r['yQ'] <= 64:     s += 2
    if 0 < r['kQ'] < 8000: s += 10
    if 0 < r['kQ'] < 200000: s += 2
    return s


if __name__ == '__main__':
    print("baseline (source-faithful):")
    base = probe()
    print("  ", {k: (hex(v) if isinstance(v, int) and v > 255 else v)
                  for k, v in base.items() if k != 'state'}, "score", score(base))
    print()

    best = []
    dims = dict(
        pos0=[0, 1, 2, 3, 4, 5, 6, 7, 8],
        vUdelta=[0, -1, +1],
        rot=['rotl', 'rotr'],
        c82src=['Ru', 'Rx', 'Rc', 'RF'],
        c48dir=['rotr', 'rotl'],
        pack=['src', 'le', 'be'],
        sign=[+1, -1],
        rawstate=[False, True],
    )
    keys = list(dims)
    total = 1
    for k in keys:
        total *= len(dims[k])
    print("sweeping %d variants..." % total)
    n = 0
    for combo in itertools.product(*[dims[k] for k in keys]):
        kw = dict(zip(keys, combo))
        label = " ".join("%s=%s" % (k, v) for k, v in kw.items())
        r = probe(**dict(kw))
        s = score(r)
        n += 1
        if s >= 6:
            best.append((s, label, r))
            print("  [%2d] %-70s yt=%-4d yQ=%-4d kQ=%-12d" %
                  (s, label, r['yt'], r['yQ'], r['kQ']))
    print("\ntested %d, %d pass the >=6 threshold" % (n, len(best)))
    best.sort(reverse=True, key=lambda t: t[0])
    for s, label, r in best[:10]:
        print("  %2d  %s" % (s, label))
        print("      ", r)
