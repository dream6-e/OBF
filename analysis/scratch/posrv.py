import sys,subprocess,os
sys.path.insert(0,'.')
from crack import O,Ro,Rd,Rf,kI,compute_RZ,compute_RV,rotr8,kA_xor,P1,P2,XV,A1
DATA=open('/home/user/OBF/analysis/stage2_bytecode.bin','rb').read()
M=1<<32; RC_=0x7FFFFFFF
RZ=compute_RZ(); Rp,va0,k1,b1,y1,C1=kI(RZ,DATA[0],DATA[1],DATA[2],DATA[3]); RV0=compute_RV(Rp,RZ)
class K:
    def __init__(s,va,st,pos): s.va=va; s.Rc,s.RF,s.Ru,s.Rx=st; s.pos=pos; s.vU=4
    def RS(s):
        RW=DATA[s.pos]; s.pos+=1; s.vU=s.pos; vU=s.vU
        z=RW
        z=(z+256-((s.Rx+(vU%256)*7)%256))%256
        z=rotr8(z,3); z=kA_xor(z,s.Ru)
        z=(z+256-((s.Rc+s.RF+(vU%256)*0xC3)%256))%256
        Ry=z; RO=vU%RC_; Rt=s.va%RC_
        RE=(Rt+RO*P1+(XV%RC_))%RC_; RL=(Rt*0x101+RO*P2+P1*0x11)%RC_
        for _ in range(3):
            n1=(RE*((RL%0x10000)+P1+0x101)+RL*0x101+RO*(0x11+XV%0x1F)+Rt)%RC_
            n2=(RL*((n1%0x10000)+P2+0x107)+n1*0x81+RO*(0x17+A1)+XV)%RC_
            RE,RL=n1,n2
        RA=(RE%256+(RL%256)*3+(RO%256)*5+((RE-RE%256)//256)%256+((RL-RL%256)//256)%256)%256
        Ry=kA_xor(Ry,RA); R,v=Ry,RW
        s.Rc=kA_xor(rotr8((s.Rc+R+s.Rx+(vU%256))%256,5),v)
        s.RF=rotr8((s.RF*5+v+kA_xor(R,s.Rc))%256,2)
        s.Ru=kA_xor(rotr8((s.Ru+R+v+s.RF+7)%256,5),s.Rx)
        s.Rx=rotr8((s.Rx+v+R+s.Rc+s.Ru+7)%256,1)
        return Ry%M
found=0
for pos0 in range(0,65):
    seed=[DATA[pos0+i] for i in range(4)]
    Rp2,va2,a2,b2,c2,d2=kI(RZ,seed[0],seed[1],seed[2],seed[3])
    k=K(va2,(a2,b2,c2,d2),pos0+4)
    ks=[]
    try:
        while k.pos<len(DATA): ks.append(k.RS())
    except IndexError: pass
    open('ks.bin','wb').write(bytes(ks))
    r=subprocess.run(['./rvscan'],capture_output=True,text=True)
    line=[l for l in r.stdout.splitlines() if 'DONE' in l]
    a=b=None
    if line: 
        import re; m=re.search(r'stageA=(\d+) stageB=(\d+)',line[0]); a,b=int(m.group(1)),int(m.group(2))
    print("pos0=%2d seed=%s va=%10d ks=%6d stageA=%s stageB=%s %s"%(pos0,seed,va2,len(ks),a,b,"*** SURVIVOR ***" if b else ""))
    if b: found+=1
print("\ntotal pos0 offsets with a full-parse survivor:",found)
