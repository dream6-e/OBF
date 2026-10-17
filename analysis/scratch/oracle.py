import json,math
exec(open('/tmp/an/run.py').read().split("blob=open")[0])
M=1<<32
def xor(a,b): return (a^b)&0xFFFFFFFF
def rotl(v,k): k%=32; return ((v<<k)%M)+(v>>(32-k)) if k else v%M
def rotr8(x,n):
    x&=0xFF; n&=7
    return ((x>>n)|(x<<(8-n)))&0xFF if n else x
def b_xor(K): return lambda a,b:(a^b^K)&0xFFFFFFFF
def b_add(K): return lambda a,b:(a+b-K)&0xFFFFFFFF
OP={(0x35,0x20):b_xor(0x74F4577),(0x35,0x64):b_add(0x7D0E8B9D),(0x60,0x2D):b_xor(0x6C4CE3),
 (0x60,0x27):b_add(0x7FBECC03),(0x26,0x32):b_xor(0x1EDBF73),(0x26,0x33):b_add(0x73E976CB),
 (0x6A,0x52):b_xor(0x559A1A1),(0x6A,0x1B):b_add(0x72903A7F),(0x75,0x4C):b_xor(0x13AC7D1),
 (0x75,0x68):b_add(0x4E85C005),(0x62,0x78):b_xor(0x569D8D9),(0x62,0x64):b_add(0x7436E41F),
 (0x79,0x4C):b_xor(0x6FC84C3),(0x79,0x6B):b_add(0x4D33E13B),(0x6F,0x51):b_xor(0x644F76D),
 (0x6F,0x5E):b_add(0x4B0DACD1),(0x7B,0x21):b_xor(0x6138015),(0x7B,0x63):b_add(0x6B33BDB9),
 (0x1D,0x20):b_xor(0x5EB887B),(0x1D,0x51):b_add(0x5969A577)}
def o(i,j,a,b): return OP[(i,j)](a,b)
# ---- kI ----
def kI(RZ, b0,b1,b2,b3):
    RCa=[o(0x6A,0x1B,3922843976,0x26D26433),o(0x75,0x4C,0x9EB4D866,0x1108A892),o(0x6A,0x1B,0x13B86CD1,0x20C037AD),
         o(0x6F,0x51,0xB2750C21,0x32B6226B),o(0x26,0x32,0x9EF73CD4,1040712794),o(0x79,0x6B,0x3205757E,0x1C26AAC1),
         o(0x35,0x64,0xA64891D1,0x2A7D83D3),o(0x75,0x68,0x524748BB,0x3FBE373F)]
    RXa=[o(0x1D,0x20,2563150964,277228403),o(0x6A,0x52,0xFB5791F7,340768680),o(0x6A,0x52,0x350809FA,361509376),
         o(0x7B,0x63,0x1ED16EC9,0x10FEEBB7),o(0x75,0x68,0xBE7C1AFE,0x36E1A6AC),o(0x6A,0x1B,0xC5B65069,0x29E7076C),
         o(0x6F,0x51,0xB10A0470,422166317),o(0x75,0x68,0x9053EB43,912679284)]
    Rsa=[o(0x6F,0x51,0x191CD804,0x1F582F6A),o(0x1D,0x51,0x37559378,571740672),o(0x35,0x64,0x5CF1384C,538792791),
         o(0x79,0x6B,901970920,393274714),o(0x35,0x64,0x65AFE157,392079950),o(0x62,0x78,0x1F0B0FC1,442685210),
         o(0x26,0x33,873077588,0x3FDF5B7B),o(0x26,0x32,0x2D5FCDDE,0x2CB272A8)]
    Rb={}
    for i in range(8): Rb[Rsa[i]]=((RCa[i]^RXa[i]^0x1EDBF73)+0x243DB52F+0xDBC24AD1)%M
    def Rf(b,k,y):
        RR=xor(b,(o(0x6A,0x1B,0xF8A866FE,404704570)*(k+1))%M)
        RR=xor(rotl(RR,13),rotl(RR,7))
        lo=RR%0x10000; hi=(RR-lo)//0x10000
        Rj=(lo*(0x1F3A5+k*0x9E37)+hi*(0x2C1B3+k*0x4F17)+0x13F7*(k+1))%M
        return xor(Rj,(o(0x60,0x27,0xEA5040AB,458905027)*(y+1))%M)
    k1=o(0x62,0x78,0x1F0B0FC1,0x1A62D71A)
    Ry=Rf(xor(Rb[k1],(RZ*0x7A05+0x2452BA5D)%M), o(0x60,0x2D,0x11415767,0x112D1BDE), o(0x35,0x64,0x696EF5DD,0x139F95C9))
    kk,bb,yy,c4=b0,b1,b2,b3
    kk=xor(kk,Ry%M); bb=xor(bb,(Ry//M)%M); yy=xor(yy,(Ry//0x10000)%M); c4=xor(c4,(Ry//0x1000000)%M)
    k2=o(0x79,0x6B,901970920,393274714)
    va=((Rf(xor(Rb[k2],(RZ*0x4BBD+0x48221848)%M), o(0x60,0x2D,0x11415767,0x112D1BDE), o(0x26,0x33,987394387,0x390F057F))
          + kk*0x10001 + bb*0x101 + yy*0x11 + c4) % o(0x79,0x4C,0x658BE47A,478715719)) + 1
    kidx=o(0x26,0x33,873077588,0x3FDF5B7B)
    RV=Rf(xor(Rb[kidx],(RZ*0x1F33+0xB7D0034E)%M), o(0x62,0x64,0x447C0104,0x2FBAE375), o(0x6A,0x52,0x3848B5A5,0x3D111408))
    return Rb,Rf,va,kk,bb,yy,c4,RV,kidx
# ---- stage2 bytes ----
blob=open('/tmp/an/blob.txt').read()
B2=decode(tokenize(blob[2501:]),Stream(CM))
def build(va_,Rc_,RF_,Ru_,Rx_):
    st={'Rc':Rc_,'RF':RF_,'Ru':Ru_,'Rx':Rx_,'Rm':5,'vU':4}
    XVAL=o(0x26,0x32,0x71479ABB,606349989)
    P1=o(0x79,0x6B,240575207,0x3EDEBA07)%0x10000
    P2=XVAL%0x10000
    def RS():
        RW=B2[st['Rm']-1]; st['Rm']+=1; st['vU']=st['Rm']-1
        vU=st['vU']
        z=RW
        z=(z+256-((st['Rx']+(vU%256)*7)%256))%256      # RR[41]
        z=rotr8(z,3)                                    # RR[48]
        z=(z^st['Ru'])                                  # RR[82]  (xor32, may exceed 255)
        z=(z+256-((st['Rc']+st['RF']+(vU%256)*0xC3)%256))%256   # RR[22]
        Ry=z
        RO=vU%0x7FFFFFFF; Rt=va_%0x7FFFFFFF
        RE=(Rt+RO*P1+(XVAL%0x7FFFFFFF))%0x7FFFFFFF
        RL=(Rt*0x101+RO*P2+P1*0x11)%0x7FFFFFFF
        for _ in range(3):
            n1=(RE*((RL%0x10000)+P1+0x101)+RL*0x101+RO*(0x11+XVAL%0x1F)+Rt)%0x7FFFFFFF
            n2=(RL*((n1%0x10000)+P2+0x107)+n1*0x81+RO*(0x17+o(0x79,0x6B,240575207,1054784007)%0x1D)+XVAL)%0x7FFFFFFF
            RE,RL=n1,n2
        RA=(RE%256+(RL%256)*3+(RO%256)*5+((RE-RE%256)//256)%256+((RL-RL%256)//256)%256)%256
        Ry=(Ry^RA)&0xFFFFFFFF
        Ryb=Ry&0xFF
        st['Rc']=(rotr8((st['Rc']+Ryb+st['Rx']+(vU%256))%256,5)^RW)&0xFF
        st['RF']=rotr8((st['RF']*5+RW+((Ryb^st['Rc'])&0xFF))%256,2)
        st['Ru']=(rotr8((st['Ru']+Ryb+RW+st['RF']+7)%256,5)^st['Rx'])&0xFF
        st['Rx']=rotr8((st['Rx']+RW+Ryb+st['Rc']+st['Ru']+7)%256,1)
        return Ryb
    def Rw():
        a,b,c,d=RS(),RS(),RS(),RS()
        return a+d*16777216+b*256+c*65536
    return RS,Rw,st
def test(RZ,label):
    Rb,Rf,va,kk,bb,yy,c4,RV,kidx=kI(RZ,B2[0],B2[1],B2[2],B2[3])
    RS,Rw,st=build(va,kk,bb,yy,c4)
    w1=Rw(); kE=xor(w1,RV)
    w2=Rw(); kz=xor(w2,xor(rotl(kE,5),rotl(RV,11)))
    w3=Rw(); kP=xor(w3,xor(rotl(kE,13),rotl(RV,19)))
    yE,yt,yl,yQ=RS(),RS(),RS(),RS()
    w4=Rw(); kQ=xor(w4,xor(rotl(kE,11),rotl(RV,7)))
    ok = 0 < kQ < 100000
    print(f"{label:22s} RZ=0x{RZ:08X} va={va:10d} RV=0x{RV:08X} kE=0x{kE:08X} kQ={kQ:11d} {'<<< PLAUSIBLE' if ok else ''}  yE,yt,yl,yQ={yE},{yt},{yl},{yQ}")
    return kQ,ok,(va,RV,kE,kz,kP)
RZ0=3854198969
test(RZ0,"baseline")

print()
print("=== diagnostics ===")
Rb,Rf,va,kk,bb,yy,c4,RV,kidx=kI(RZ0,B2[0],B2[1],B2[2],B2[3])
print("Rb keys:",sorted(Rb.keys()))
print("kidx(RV lookup) =",kidx," in Rb:",kidx in Rb)
print("key1 =",o(0x62,0x78,0x1F0B0FC1,0x1A62D71A)," key2 =",o(0x79,0x6B,901970920,393274714))
print("first 8 stage2 bytes:",list(B2[:8]))
print()
print("=== RZ variant enumeration (kQ must be small) ===")
import itertools
def kF_chain(t1,t3,t4,t7):
    RR=395934548
    RR=(RR*0x6BFD+t1)%M
    RR=(RR*0x8C2D+(0x1B142453%0xA7FF))%M
    RR=(RR*60685+t3)%M
    RR=(RR*0x18BD+t4)%M
    RR=(RR*25445+0x1D88)%M
    RR=(RR*0x20D7+119)%M
    RR=(RR*0xF4B7+t7)%M
    return RR
hits=[]
for t1 in [50,54,55,51,52,53,56,57]:
 for t3 in [13,19,12,14,21]:
  for t4 in [51,50,52]:
   for t7 in [37600,37599,37601]:
    RZ=kF_chain(t1,t3,t4,t7)
    Rb2,_,va2,kk2,bb2,yy2,c42,RV2,ki2=kI(RZ,B2[0],B2[1],B2[2],B2[3])
    if ki2 not in Rb2: continue
    RS2,Rw2,_=build(va2,kk2,bb2,yy2,c42)
    w1=Rw2(); kE2=xor(w1,RV2)
    Rw2();Rw2()
    RS2();RS2();RS2();RS2()
    kQ2=xor(Rw2(),xor(rotl(kE2,11),rotl(RV2,7)))
    if 0<kQ2<200000:
        hits.append((kQ2,t1,t3,t4,t7,RZ,va2))
        print(f"  HIT kQ={kQ2:8d}  t1={t1} t3={t3} t4={t4} t7={t7}  RZ=0x{RZ:08X} va={va2}")
print("total hits:",len(hits))
