import sys, json, collections; sys.path.insert(0,'.')
import io, final2 as F
from yDdec import YD
data=open('data.bin','rb').read(); RZ=F.compute_RZ(False); S=F.Stream(data)
Rp,RT,va,a,b,c,d=F.kI(RZ,S.Rc,S.RF,S.Ru,S.Rx,verbose=False)
S.va,S.Rc,S.RF,S.Ru,S.Rx=va,a,b,c,d
RV1=RT(F.Ro(Rp[F.O(0x26,0x33,873077588,0x3FDF5B7B)],(RZ*0x1F33+0xB7D0034E)%F.M),
       F.O(0x62,0x64,0x447C0104,0x2FBAE375),F.O(0x6A,0x52,0x3848B5A5,0x3D111408))
F.CTX.clear(); F.CTX.update(Rp=Rp,Rf=RT,RZ=RZ,YD_BY_RH={1:YD(Rp,RZ,RT,0)}); F.OPS.clear()
o=sys.stdout; sys.stdout=io.StringIO()
try: p,_=F.vu(S,RV1,0,[],F.CTX)
finally: sys.stdout=o
protos=F.walk(p)
print('BYTES %d / %d   leftover %d   protos %d'%(S.Rm-1,len(S.vh),len(S.vh)-(S.Rm-1),len(protos)))
def dbl(bb):
    import struct
    return struct.unpack('<d', bytes(bb))[0]
allstr=[]; allnum=[]; L=[]
L.append('# Kryvex V2.7.lua -- STAGE-2 常量池明文 (第4层 yD 解码器已实现)')
L.append('# %d 原型 / %d 指令 / 字节 %d/%d 闭合'%(len(protos),sum(q['kQ'] for _,q in protos),S.Rm-1,len(S.vh)))
L.append('')
for i,(dep,q) in enumerate(protos):
    ds=sorted([(v[2],v[1]) for v in q['decoded'].values() if v[0]==F.RI_KEY_4])
    dn=sorted([(v[2],dbl(v[1])) for v in q['decoded'].values() if v[0] in (F.RI_KEY_26,F.RI_KEY_56)])
    for _,v in ds: allstr.append(v)
    for _,v in dn: allnum.append(v)
    L.append('=== proto %d  depth %d  kP=%d kQ=%d numparams=%d yE=%d yQ=%d RH=%d Rh=%d nChild=%d'%(i,dep,q['kP'],q['kQ'],q['yt'],q['yE'],q['yQ'],q['RH'],q['Rh'],q['nChild']))
    L.append('  -- %d string constants --'%len(ds))
    for idx,v in ds: L.append('   [%3d] %s'%(idx,repr(v)[2:-1]))
    L.append('  -- %d numeric constants (double) --'%len(dn))
    for idx,v in dn: L.append('   [%3d] %r'%(idx,v))
    L.append('')
pr=sum(1 for v in allstr if v and all(32<=c<127 for c in v))
L.insert(3,'# 字符串常量共 %d 个, 其中 100%% 可打印 ASCII 的有 %d 个 (%.1f%%)'%(len(allstr),pr,100*pr/max(len(allstr),1)))
open('/home/user/OBF/analysis/stage2_constants_decoded.txt','w').write('\n'.join(L)+'\n')
uniq=sorted(set(allstr))
open('/home/user/OBF/analysis/stage2_strings_plaintext.txt','w').write('\n'.join(repr(u)[2:-1] for u in uniq)+'\n')
json.dump({'strings':[s.decode('latin-1') for s in allstr],'numbers':allnum},open('/home/user/OBF/analysis/stage2_constants.json','w'))
print('strings total %d (unique %d) printable %.1f%%   numbers %d'%(len(allstr),len(uniq),100*pr/max(len(allstr),1),len(allnum)))
print()
print('--- unique strings (%d) ---'%len(uniq))
for u in uniq: print('  ',u.decode('latin-1'))
