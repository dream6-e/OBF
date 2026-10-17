import json
K=json.load(open('/home/user/OBF/analysis/scratch/payload_key.json'))
CC={int(k):v for k,v in K['CC'].items()}
CM=K['CM']
MARK=[('/hga"','#'),('/9Ux0','"'),('/b!k`','$'),('/=KzM','}'),('/9Y<[',"'"),('/t;Cz','%'),('/~4Ha','&'),('/Snx:','!')]
def tokenize(b):
    out=[];R=1;C=len(b);k=1
    while R<=C:
        if b[R-1]=='/':
            if R>k: out.append(b[k-1:R-1])
            f=b[R-1:R+4]
            hit=None
            for m,sym in MARK:
                if f==m: hit=sym;break
            if hit is not None: out.append(hit);R+=5;k=R
            else: out.append(b[R-1]);R+=1;k=R
        else: R+=1
    if k<=C: out.append(b[k-1:])
    return ''.join(out)
# ---- ye!RU key schedule ----
def RU(key):
    Rf=0x10000; RUm=0x7FFFFF01; RM=0x64F16F4B; RL=1674042112; RO=0x2CD9
    RE=0x7973; RQ=0x705; RWx=0xFF; Rz=10481; RP=0x5B15; Rt=30235
    Rj=RM; RR=RL; n=len(key)
    for Rv in range(1,n+1):
        Rb=key[Rv-1]+key[n-Rv]*0x100
        Rk2=(Rj*((RR%Rf)+RE)+RR*Rt+Rv*RO+Rb*RP+RM)%RUm
        Ry2=(RR*((Rk2%Rf)+9841)+Rk2*6749+Rv*RQ+Rb*Rz+RL)%RUm
        Rj=Rk2; RR=Ry2
    Rs=Rj; RyS=RR
    SBOX={}
    for i in range(0,RWx+1): SBOX[i+1]=i
    for Rv in range(RWx,0,-1):
        Ryl=Rv*0x101
        Rbl=(Rj*((RR%Rf)+RE)+RR*Rt+Rv*RO+Ryl*RP+RM)%RUm
        RCl=(RR*((Rbl%Rf)+9841)+Rbl*6749+Rv*RQ+Ryl*Rz+RL)%RUm
        Rj=Rbl; RR=RCl
        Rd=((Rj%Rf)*(RR%Rf)+Rj*3+RR*5+Rv)%(Rv+1)
        SBOX[Rv+1],SBOX[Rd+1]=SBOX[Rd+1],SBOX[Rv+1]
    return SBOX,Rs,RyS
class Stream:
    def __init__(self,key):
        self.SBOX,self.Rs,self.Ry=RU(key); self.RC=0; self.RX=0
    def RW(self,R):
        Rv=0x7FFFFF01; RR=0x100
        Rj=(self.RC+1)%Rv
        Rb=(self.Rs*((self.Ry%0x10000)+0x7973)+self.Ry*30235+Rj*0x2CD9+self.RX*23317+0x64F16F4B)%Rv
        Rf=(self.Ry*((Rb%0x10000)+0x2671)+Rb*0x1A5D+Rj*0x705+self.RX*0x28F1+1674042112)%Rv
        self.Rs=Rb; self.Ry=Rf
        RU=(self.Rs%RR+(self.Ry%RR)*3+(self.RC%RR)*5+self.RX*7)%RR
        Rd=self.SBOX[RU+1]
        self.RC+=1; self.RX=R
        return (R+RR-Rd)%RR
def decode(tok,stream):
    Cy=tok; Cf=len(Cy); R=1; X=[]; out=[]
    def fl(x): return int(x//1)
    while True:
        if len(X)>0:
            d=X.pop(0); out.append(stream.RW(d)); continue
        if R>Cf: break
        f=Cf-R+1
        g=lambda o: CC[ord(Cy[R-1+o])]
        if f>=5:
            v=g(0)*86**4+g(1)*86**3+g(2)*86**2+g(3)*86+g(4)
            L=v%256; U=fl(v/256)%256; j=fl(v/65536)%256; v=fl(v/16777216)
            X=[v,j,U,L]; R+=5
        elif f>=4:
            v=g(0)*86**3+g(1)*86**2+g(2)*86+g(3)
            U=v%256; j=fl(v/256)%256; v=fl(v/65536)
            X=[v,j,U]; R+=4
        elif f>=3:
            v=g(0)*86**2+g(1)*86+g(2); j=v%256; v=fl(v/256)
            X=[v,j]; R+=3
        elif f>=2:
            v=g(0)*86+g(1); X=[v]; R+=2
        else:
            R+=1
    return bytes(out)
blob=open('/home/user/OBF/analysis/scratch/blob.txt').read()
st=Stream(CM)
p1=decode(tokenize(blob[:2501]),st)
print("PART1 len",len(p1))
open('/home/user/OBF/analysis/scratch/part1.txt','wb').write(p1)

st2=Stream(CM)
p2=decode(tokenize(blob[2501:]),st2)
print("\nPART2 len",len(p2))
open('/home/user/OBF/analysis/scratch/part2.lua','wb').write(p2)


import hashlib
print('part1 sha',hashlib.sha256(p1).hexdigest(),len(p1))
print('part2 sha',hashlib.sha256(p2).hexdigest(),len(p2))
