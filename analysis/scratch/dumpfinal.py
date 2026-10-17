import sys, json, struct, re; sys.path.insert(0,'.')
import io, final2 as F
from dec4 import Dec, SPECS
Dec.RY = Dec.string; Dec.RV = Dec.num
data=open('data.bin','rb').read(); RZ=F.compute_RZ(False); S=F.Stream(data)
Rp,RT,va,a,b,c,d=F.kI(RZ,S.Rc,S.RF,S.Ru,S.Rx,verbose=False)
S.va,S.Rc,S.RF,S.Ru,S.Rx=va,a,b,c,d
RV1=RT(F.Ro(Rp[F.O(0x26,0x33,873077588,0x3FDF5B7B)],(RZ*0x1F33+0xB7D0034E)%F.M),
       F.O(0x62,0x64,0x447C0104,0x2FBAE375),F.O(0x6A,0x52,0x3848B5A5,0x3D111408))
F.CTX.clear(); F.CTX.update(Rp=Rp,Rf=RT,RZ=RZ,YD_BY_RH={rh:Dec(Rp,RZ,RT,sp) for rh,sp in SPECS.items()}); F.OPS.clear()
o=sys.stdout; sys.stdout=io.StringIO()
try: p,_=F.vu(S,RV1,0,[],F.CTX)
finally: sys.stdout=o
protos=F.walk(p)
BAD=[]
def dbl(bb):
    if not isinstance(bb,(list,bytes)) or len(bb)!=8:
        BAD.append(bb); return None
    return struct.unpack('<d',bytes(bb))[0]
OUT='/home/user/OBF/analysis/'
exact=sum(1 for _,q in protos if q.get('Rs_exact'))
L=[]
L.append('# Kryvex V2.7.lua -- Stage-2 VM 全量还原 (第2/3/4 层全部打穿, 4 套解码器全部实现)')
L.append('# 字节 %d/%d 精确闭合, 剩余 %d'%(S.Rm-1,len(S.vh),len(S.vh)-(S.Rm-1)))
L.append('# 原型 %d 个 (其中 %d 个 Rs 链精确前推, %d 个靠反解回退) ; 指令 %d 条 ; 常量槽 %d 个'
         %(len(protos),exact,len(protos)-exact,sum(q['kQ'] for _,q in protos),sum(q['Rh'] for _,q in protos)))
L.append('# RH 选择解码器: 0->kG  1->yD  2->ki  >=3->ku   (四套同形, 常量互不相同)')
L.append('')
L.append('idx dep   kP    kQ   np yE yQ RH   Rh  nChild Rs链  字符串 数值  idx排列')
ts=tn=0
for i,(dep,q) in enumerate(protos):
    ds=sorted([(v[2],v[1]) for v in q.get('decoded',{}).values() if v[0]==F.RI_KEY_4])
    dn=sorted([(v[2],dbl(v[1])) for v in q.get('decoded',{}).values() if v[0] in (F.RI_KEY_26,F.RI_KEY_56)])
    ts+=len(ds); tn+=len(dn)
    ids=sorted(v[2] for v in q.get('decoded',{}).values())
    perm = ids==list(range(0,len(ids)))
    L.append('%3d %3d %-5d %-4d %-2d %-2d %-2d %-2d %-4d %-6d %-5s %-5d %-4d %s'
             %(i,dep,q['kP'],q['kQ'],q['yt'],q['yE'],q['yQ'],q['RH'],q['Rh'],q['nChild'],
               'exact' if q.get('Rs_exact') else 'inv',len(ds),len(dn),'YES' if perm else 'no'))
L.append('')
L.append('# 合计: 字符串 %d 个, 数值(double) %d 个, 共 %d (常量槽总数 %d, 差额是 opcode 44/228 不建值槽)'
         %(ts,tn,ts+tn,sum(q['Rh'] for _,q in protos)))
alls=[]; alln=[]
for i,(dep,q) in enumerate(protos):
    ds=sorted([(v[2],v[1]) for v in q['decoded'].values() if v[0]==F.RI_KEY_4])
    dn=sorted([(v[2],dbl(v[1])) for v in q['decoded'].values() if v[0] in (F.RI_KEY_26,F.RI_KEY_56)])
    alls+= [v for _,v in ds]; alln+=[v for _,v in dn]
    L.append('')
    L.append('===== proto %d  depth %d  kP=%d  kQ=%d  numparams=%d  yE=%d  yQ=%d  RH=%d(->%s)  Rh=%d  nChild=%d'
             %(i,dep,q['kP'],q['kQ'],q['yt'],q['yE'],q['yQ'],q['RH'],{0:'kG',1:'yD',2:'ki',3:'ku'}[min(q['RH'],3)],q['Rh'],q['nChild']))
    L.append('  strings (%d):'%len(ds))
    for idx,v in ds: L.append('    [%3d] %s'%(idx,v.decode('latin-1')))
    L.append('  numbers (%d):'%len(dn))
    for idx,v in dn: L.append('    [%3d] %r'%(idx,v))
open(OUT+'stage2_constants_decoded.txt','w').write('\n'.join(L)+'\n')
u=sorted(set(alls))
open(OUT+'stage2_strings_plaintext.txt','w').write('\n'.join(x.decode('latin-1') for x in u)+'\n')
json.dump({'strings':[x.decode('latin-1') for x in alls],'numbers':alln,
           'protos':[dict(idx=i,depth=dep,kP=q['kP'],kQ=q['kQ'],yt=q['yt'],yE=q['yE'],yQ=q['yQ'],
                          RH=q['RH'],Rh=q['Rh'],nChild=q['nChild'],Rs_exact=q.get('Rs_exact',False),
                          decoder={0:'kG',1:'yD',2:'ki',3:'ku'}[min(q['RH'],3)],
                          strings=[[w[0],w[1].decode('latin-1')] for w in sorted([(v[2],v[1]) for v in q['decoded'].values() if v[0]==F.RI_KEY_4])],
                          numbers=[[w[0],dbl(w[1])] for w in sorted([(v[2],v[1]) for v in q['decoded'].values() if v[0] in (F.RI_KEY_26,F.RI_KEY_56)])],
                          words=[list(w) for w in q['words']],
                          raw=[list(w) for w in q['raw']]) for i,(dep,q) in enumerate(protos)]},
          open(OUT+'stage2_full.json','w'))
print('\n'.join(L[:34]))
pr=sum(1 for v in alls if v and all(32<=c<127 for c in v))
print()
print('TOTAL strings %d (unique %d, printable %.1f%%)  numbers %d (unique %d)'%(len(alls),len(u),100*pr/len(alls),len(alln),len(set(alln))))
print('protos with exact Rs chain: %d/%d'%(exact,len(protos)))
print('malformed numeric payloads:',len(BAD), BAD[:5])
