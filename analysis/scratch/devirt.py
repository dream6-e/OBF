import sys, json, math, collections; sys.path.insert(0,'.')
import io, final2 as F
from dec4 import Dec, SPECS
Dec.RY=Dec.string; Dec.RV=Dec.num
M=1<<32
bx=lambda a,b:(int(a)%M)^(int(b)%M)

# ---- yL's nine IIFE constants ----
Yy = bx(bx(0x639A1,0x31A12),271282)
Yc = bx(bx(353988,87827),0x431C6)
Yv = bx(bx(710434,63957),667639)
YX = bx(bx(551515,348352),0xD3B9A)
Ys = bx(bx(0x14204,0x1D335),0x8130)
Yj = bx(bx(0x111AA,289037),343422)
Yb = bx(bx(0xC5C3A,0xECF0E),0x29336)
Yf = bx(bx(824584,0x47E15),584478)
Bc = bx(bx(126299,832393),299022364)
print('yL consts: Ry=%d RC=%d Rv=%d RX=%d Rs=%d Rj=%d Rb=%d Rf=%d  b=%d'%(Yy,Yc,Yv,YX,Ys,Yj,Yb,Yf,Bc))
print('  magnitudes: yH*Rf max=%.3e  (RL-b)*RX max=%.3e  RQ*Rs max=%.3e  RM*RC max=%.3e   2^53=%.3e'
      %(4.29e9*Yf,4.29e9*YX,4.29e9*Ys,4.29e9*Yc,2**53))

def fm(a,b):   # Lua/Luau double a*b (IEEE round)
    return float(a)*float(b)
def lmod(a,b): # Lua/Luau double a % b
    return float(a)%float(b)

def yH0(kP,kz):
    A=bx(kz,kP); Bm=bx(bx(76832,0xB0865),716104); C=bx(bx(bx(309731,0x15CE4),0x76AAECA9),kP)
    return int(lmod(fm(A,Bm)+C, M))

def decode(kM,kL,kW,kO,kP,kQ,kz):
    """yL's per-instruction state machine.  X=kM C=kL j=kW s=kO (roles fixed algebraically)."""
    yH=yH0(kP,kz); kT=bx(kP,kz); kh=kP; ka=kz
    out=[]
    for i in range(kP+1, kP+kQ+1):
        RO=kM[i]
        RE=lmod(fm(yH,Yy),M)
        Rt=lmod(fm(RE,Yj)+yH,M)
        Rz=lmod(yH,Yv)*Yb
        RP=lmod((yH-lmod(yH,Yv))/Yv, Yv)
        Rd=bx(bx(kW[i],kh),RE);  Rd=Rd-M if Rd>=0x80000000 else Rd
        RQ=lmod(bx(kL[i],kT)-RP, M)
        RM=bx(bx(kO[i],ka),Rt);  RM=RM-M if RM>=0x80000000 else RM
        RL=lmod(RO-Rz,M)
        yH=lmod(fm(yH,Yf)+fm(RL-Bc,YX)+fm(RQ,Ys)+lmod(Rd,M)+fm(lmod(RM,M),Yc), M)
        RH=RQ-(RL-Bc)
        if lmod(RL,Yb)!=0: Rd,RM=RM,Rd
        out.append((int(RL)%M, RH, Rd, RM))
        yH=int(yH)
    return out

# ---- run the full parse, then decode every proto ----
data=open('data.bin','rb').read(); RZ=F.compute_RZ(False); S=F.Stream(data)
Rp,RT,va,a,b,c,d=F.kI(RZ,S.Rc,S.RF,S.Ru,S.Rx,verbose=False)
S.va,S.Rc,S.RF,S.Ru,S.Rx=va,a,b,c,d
RV1=RT(F.Ro(Rp[F.O(0x26,0x33,873077588,0x3FDF5B7B)],(RZ*0x1F33+0xB7D0034E)%F.M),
       F.O(0x62,0x64,0x447C0104,0x2FBAE375),F.O(0x6A,0x52,0x3848B5A5,0x3D111408))
F.CTX.clear(); F.CTX.update(Rp=Rp,Rf=RT,RZ=RZ,YD_BY_RH={r:Dec(Rp,RZ,RT,sp) for r,sp in SPECS.items()}); F.OPS.clear()
o=sys.stdout; sys.stdout=io.StringIO()
try: p,_=F.vu(S,RV1,0,[],F.CTX)
finally: sys.stdout=o
protos=F.walk(p)
al=json.load(open('alias_table.json')); OPS=set(al['ops']); HIDX=al['hidx']; RW=al['RW']
OP2H={RW[2*i]:HIDX[i] for i in range(438)}
tot=hit=0; opc=collections.Counter(); hc=collections.Counter()
for i,(dep,q) in enumerate(protos):
    ins=decode(q['kM'],q['kL'],q['kW'],q['kO'],q['kP'],q['kQ'],q['kz'])
    q['ins']=ins
    h=sum(1 for w in ins if w[0] in OPS)
    tot+=len(ins); hit+=h
    for w in ins: opc[w[0]]+=1; hc[OP2H.get(w[0],0)]+=1
    if i<3 or h!=len(ins):
        print('proto %-2d kQ=%-5d f1-in-alias-table %d/%d'%(i,q['kQ'],h,len(ins)))
print()
print('TOTAL instructions %d, f1 in the 438-opcode alias table: %d (%.2f%%)'%(tot,hit,100*hit/tot))
print('distinct f1 values used: %d of 438'%len([k for k in opc if k in OPS]))
print('distinct handler ids used: %d of 88'%len([k for k in hc if k]))
print('top handlers:',hc.most_common(14))
json.dump([[w[0],w[1],w[2],w[3]] for _,q in protos for w in q['ins']], open('/tmp/ins.json','w'))
