#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Driver: run the full vu() parse WITH layer-4 constant decoding.
The only unknown in the whole system is one bit -- vX % 2, where vX is kF's
host/runtime-dependent fingerprint (it folds in floor(collectgarbage("count"))).
It enters only as RE()'s branch selector, so we try both parities and keep the
one whose string constants come out printable.
"""
import sys, json, collections
sys.path.insert(0, '/home/user/OBF/analysis/scratch')
import final2 as F
from yDdec import YD


def printable(b):
    return sum(1 for c in b if 32 <= c < 127) / max(len(b), 1)


def run(parity, verbose=True):
    data = open('/home/user/OBF/analysis/scratch/data.bin', 'rb').read()
    RZ = F.compute_RZ(False)
    S = F.Stream(data)
    Rp, RT, va, Rc2, RF2, Ru2, Rx2 = F.kI(RZ, S.Rc, S.RF, S.Ru, S.Rx, verbose=False)
    S.va, S.Rc, S.RF, S.Ru, S.Rx = va, Rc2, RF2, Ru2, Rx2
    Rs7 = F.O(0x26, 0x33, 873077588, 0x3FDF5B7B)
    RV1 = RT(F.Ro(Rp[Rs7], (RZ * 0x1F33 + 0xB7D0034E) % F.M),
             F.O(0x62, 0x64, 0x447C0104, 0x2FBAE375),
             F.O(0x6A, 0x52, 0x3848B5A5, 0x3D111408))
    F.CTX.clear()
    F.CTX.update(Rp=Rp, Rf=RT, RZ=RZ, YD=YD(Rp, RZ, RT, parity))
    F.OPS.clear()
    p, RVf = F.vu(S, RV1, 0, [], F.CTX)
    protos = F.walk(p)
    strs = []
    nums = []
    for d, q in protos:
        for slot, (op, val, idx, kb, yb) in q['decoded'].items():
            if op == F.RI_KEY_4:
                strs.append((q['idx'] if 'idx' in q else d, val))
            elif op in (F.RI_KEY_26, F.RI_KEY_56):
                nums.append(val)
    return S, p, protos, strs, nums


for par in (0, 1):
    try:
        S, p, protos, strs, nums = run(par)
    except F.Fail as e:
        print('vX%%%d == %d : parse FAILED -> %s' % (2, par, e))
        continue
    good = sum(1 for _, v in strs if v and printable(v) == 1.0)
    avg = sum(printable(v) for _, v in strs) / max(len(strs), 1)
    print('vX %% 2 == %d : bytes %d/%d  protos %d  strings %d (fully printable %d, avg %.3f)'
          % (par, S.Rm - 1, len(S.vh), len(protos), len(strs), good, avg))
    print('   sample:', [v[:24] for _, v in strs[:8]])
    print()
