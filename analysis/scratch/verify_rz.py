import re,sys
sys.path.insert(0,'.')
import verify
from verify import C, parse, DATA, M
from crack import O, Ro, Rf, compute_RV, kI
RZc=None
Rp0,_,_,_,_,_=kI(0,0,0,0,0) if False else (None,)*6
# Rb values are RZ-independent; recompute once via kI at the true RZ
from crack import compute_RZ
Rp,_,_,_,_,_ = kI(compute_RZ(), DATA[0],DATA[1],DATA[2],DATA[3])
RB2,RB4,RB7 = Rp[2],Rp[4],Rp[7]
from crack import O as _O
K1C=_O(0x60,0x2D,0x11415767,0x112D1BDE); Y1C=_O(0x35,0x64,0x696EF5DD,0x139F95C9)
Y2C=_O(0x26,0x33,987394387,0x390F057F); K3C=_O(0x62,0x64,0x447C0104,0x2FBAE375); Y3C=_O(0x6A,0x52,0x3848B5A5,0x3D111408)
print('K1C=%d Y1C=%d Y2C=%d K3C=%d Y3C=%d'%(K1C,Y1C,Y2C,K3C,Y3C))
def run_rz(RZ):
    Ry = Rf(Ro(RB2,(RZ*0x7A05+0x2452BA5D)%M), K1C, Y1C)
    Rc=Ro(DATA[0],Ry); RF=DATA[1]; Ru=Ro(DATA[2],Ry>>16); Rx=Ro(DATA[3],Ry>>24)
    Rf2= Rf(Ro(RB7,(RZ*0x4BBD+0x48221848)%M), K1C, Y2C)
    va=((Rf2+Rc*0x10001+RF*0x101+Ru*0x11+Rx)%2147483646)+1
    RV = Rf(Ro(RB4,(RZ*0x1F33+0xB7D0034E)%M), K3C, Y3C)
    c=C(va,(Rc,RF,Ru,Rx))
    try: return parse(c,RV),None
    except (EOFError,ValueError,KeyError) as e: return None,str(e)
hits=[]
for l in open(sys.argv[1] if len(sys.argv)>1 else 'hits_rz.txt'):
    m=re.match(r'RZ=\s*(\d+)\s+Ry=\s*(\d+)\s+va=\s*(\d+)\s+RV=\s*(\d+)\s+kQ=\s*(\d+)\s+yt=\s*(\d+)\s+yQ=\s*(\d+)',l)
    if m: hits.append(tuple(int(m.group(i)) for i in range(1,8)))
print("total kQ-survivors so far: %d"%len(hits))
soft=[h for h in hits if h[5]<=8 and h[6]<=64]
print("after soft pre-filter yt<=8 & yQ<=64: %d"%len(soft))
surv=0
for RZ,Ry,va,RV,kQ,yt,yQ in soft:
    info,err=run_rz(RZ)
    if info:
        surv+=1
        print("  *** FULL PARSE OK *** RZ=%d %s"%(RZ,info))
    else:
        print("  RZ=%-11d kQ=%-6d yt=%-3d yQ=%-3d rejected: %s"%(RZ,kQ,yt,yQ,err[:40]))
print("\n%d / %d survived the full recursive parse"%(surv,len(soft)))
