import json,re
M32=0xFFFFFFFF
# ---------- kg : string decoder ----------
Rb_mod = 0x7FFFFF01      # Ry (modulus)
RW_    = 0xFF
# constants inside RW
cRb=0x10000; cRy=0x7FFFFF01; cRX=0x7F1E742F; cRs=0x3AC542A2; cRO=0x30E7
cRE=0x5D94; cRQ=0xFCE9; cRz=14067; cRP=0x5F8F; cRt=30072; cRH=30601

RE=[0x16,0x6B,0x79,0x7E,203,0xF0,0xC9,0x60,128,0x48,0xB3,115,0x57,0x6A,0xF3,0x59]

def RW(Rarr):
    Rj={}
    Rk=cRs; RR=cRX
    n=len(Rarr)
    for Rv in range(1,n+1):
        inner = Rarr[Rv-1] + Rarr[n-Rv]*0x100     # R[Rv] + R[#R+1-Rv]*256  (1-based)
        RC=(Rk*((RR%cRb)+cRH)+RR*cRt+Rv*cRz+inner*cRP+cRs)%cRy
        Rf=(RR*((RC%cRb)+cRO)+RC*cRE+Rv*cRQ+inner*0x8BE5+cRX)%cRy
        Rk=RC; RR=Rf
    RU=Rk; Rd=RR
    # shuffle
    for i in range(0,RW_+1): Rj[i+1]=i
    for Rv in range(RW_,0,-1):
        RUl=Rv*0x101
        Rfl=(Rk*((RR%cRb)+cRH)+RR*cRt+Rv*cRz+RUl*cRP+cRs)%cRy
        Rdl=(RR*((Rfl%cRb)+cRO)+Rfl*cRE+Rv*cRQ+RUl*0x8BE5+cRX)%cRy
        Rk=Rfl; RR=Rdl
        RC=((Rk%cRb)*(RR%cRb)+Rk*3+RR*5+Rv)%(Rv+1)
        RM=Rj[Rv+1]; Rj[Rv+1]=Rj[RC+1]; Rj[RC+1]=RM
    return Rj,RU,Rd

SBOX,RU,Rd = RW(RE)
RO_ce = 0xDC4E

# handler-id constants
def dec_bytes(R,v):
    st={'Cn':'','XX':Rd,'XC':0,'CZ':0,'Co':v,'CT':0,'Ce':RO_ce,'Cp':RU,'Xk':0,'Xd':1,'XR':0,'Ch':0,'Cg':R}
    RQ=[0xE5E57BF,0x7A0820F7,0x71053D74,0x7A0820F7,0x7A0820F7,0x7A0820F7,0x7A0820F7,
        0x7A0820F7,0x7A0820F7,0x7A0820F7,0x7BEED2D9,0x7A0820F7,0x31266387,0x6694A568,
        0x1D8AAF76,1709650726,0x43A24719,0x1C96CCB9,1734702167]
    N=len(R)
    guard=0
    while True:
        guard+=1
        if guard>100000: raise RuntimeError("runaway")
        Xd=st['Xd']
        if Xd<1 or Xd>len(RQ): break
        h=RQ[Xd-1]
        if h==0xE5E57BF:      st['CT']=(st['CT']+1)-1
        elif h==0x7A0820F7:   # Xf
            RC=st['Cp']; RR=st['XX']; Rk=st['Co']%cRy; Rbb=st['Ce']
            Rv2=(RC*((RR%0x10000)+0x7789)+RR*30072+Rk*0x36F3+Rbb*24463+0x3AC542A2)%cRy
            RX2=(RR*((Rv2%0x10000)+0x30E7)+Rv2*0x5D94+Rk*0xFCE9+Rbb*35813+0x7F1E742F)%cRy
            st['Cp']=Rv2; st['XX']=RX2
        elif h==0x71053D74:   # Cw init
            st['Co']=1; st['Ce']=0
        elif h==0x7BEED2D9:   # Xj
            st['Co']=st['Ch']+1; st['Ce']=st['Xk']
        elif h==0x31266387:   # Xy
            st['XC']=(st['Cp']%256 + (st['XX']%256)*3 + (st['Ch']%256)*5 + st['Xk']*7)%256
        elif h==0x6694A568:   # Xs
            st['XR']=SBOX[st['XC']+1]
        elif h==0x1D8AAF76:   # Ci emit
            st['Cn']+=chr((st['Cg'][st['Ch']+1-1]+256-st['XR'])%256)
        elif h==1709650726:   # Xv load
            st['Xk']=st['Cg'][st['Ch']+1-1]
        elif h==0x43A24719:   # Xb advance
            st['Ch']=st['Ch']+1
        elif h==0x1C96CCB9:   # Cq
            st['CZ']=(st['CZ']+st['Cp'])%256; st['CT']=(st['CT']+st['Ch'])-st['Ch']
        elif h==1734702167:   # XU
            st['Xd']= 0xA if st['Ch']<N else 63
        else:
            raise RuntimeError("unknown handler %X"%h)
        st['Xd']+=1
    if st['CZ']>256: pass
    return st['Cn']

print("test1:",repr(dec_bytes([(254+8)%256,(0x32+0xE4)%256,0xE7,0x78,(250+221)%256,3],366)))
print("test2:",repr(dec_bytes([(0xFD+68)%256],0x174)))
print("test3:",repr(dec_bytes([0x9F],373)))
print("test4:",repr(dec_bytes([0x21,(221+166)%256,0x6F,0x5B,(0xCC+131)%256,59,0xCD,(189+0x3B)%256],0x17D)))
print("test5:",repr(dec_bytes([0x57,9,0xA,(55+0x8C)%256,(0x91+62)%256,(0xAF+0xFB)%256],389)))
print("test6:",repr(dec_bytes([0xAA],395)))
