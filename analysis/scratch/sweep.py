exec(open('dec.py').read().split("print(\"test1")[0])
V=256
A=[
 ("setmetatable",[230,204,229,(149+0xF)%V,66,(0x3A+0xD1)%V,184,78,0x31,0x80,0x2C,(201+0x5D)%V],420),
 ("__mode",[0xA8,0x67,0x28,(0x72+0x13)%V,82,0x65],752),
 ("k",[0x30],0x2F6),
 ("type",[0x45,207,230,(55+0x78)%V],521),
 ("getfenv",[242,222,121,132,(0xC7+0x4A)%V,(173+82)%V,0x30],413),
 ("bit32",[81,7,(35+0xD5)%V,(186+0xD8)%V,0xDC],432),
 ("bit",[112,(30+188)%V,(0x44+119)%V],437),
 ("string",[70,0x21,(0x4A+166)%V,(220+154)%V,(68+157)%V,0xC6],440),
 ("tostring",[0xE3,0xF5,70,(20+197)%V,0x86,(199+183)%V,(176+0xFC)%V,(0xA2+0x7D)%V],599),
 ("char",[0xE5,0x10,0x82,0xB2],0x2C6),
 ("find",[0xB1,(0xEA+0xAE)%V,0x51,(172+24)%V],607),
 ("rshift_a",[15,(149+209)%V,243,72,14,(0x6C+174)%V],0x2D7),
 ("rshift_b",[208,188,0xC7,219,176,(0x32+228)%V],0x2DD),
 ("band",[0xD9,0x89,(186+0x89)%V,(207+0xCA)%V],535),
 ("bxor",[0x9E,(164+255)%V,(24+128)%V,0x60],0x272),
]
# post-shuffle state
def RWfull(Rarr):
    Rj={};Rk=0x3AC542A2;RR=0x7F1E742F;n=len(Rarr)
    for Rv in range(1,n+1):
        inner=Rarr[Rv-1]+Rarr[n-Rv]*256
        RC=(Rk*((RR%0x10000)+30601)+RR*30072+Rv*14067+inner*0x5F8F+0x3AC542A2)%0x7FFFFF01
        Rf=(RR*((RC%0x10000)+0x30E7)+RC*0x5D94+Rv*0xFCE9+inner*0x8BE5+0x7F1E742F)%0x7FFFFF01
        Rk=RC;RR=Rf
    RU,Rd=Rk,RR
    for i in range(256): Rj[i+1]=i
    for Rv in range(255,0,-1):
        U=Rv*257
        Rf=(Rk*((RR%0x10000)+30601)+RR*30072+Rv*14067+U*0x5F8F+0x3AC542A2)%0x7FFFFF01
        Rd2=(RR*((Rf%0x10000)+0x30E7)+Rf*0x5D94+Rv*0xFCE9+U*0x8BE5+0x7F1E742F)%0x7FFFFF01
        Rk=Rf;RR=Rd2
        RC=((Rk%0x10000)*(RR%0x10000)+Rk*3+RR*5+Rv)%(Rv+1)
        Rj[Rv+1],Rj[RC+1]=Rj[RC+1],Rj[Rv+1]
    return RU,Rd,Rk,RR,Rj
RU0,Rd0,Rk1,RR1,SBOX1=RWfull([0x16,0x6B,0x79,0x7E,203,0xF0,0xC9,0x60,128,0x48,0xB3,115,0x57,0x6A,0xF3,0x59])

def mk(Cp0,XX0,Ce0,npre,npost,xj_before_xf,xy_uses,emit_after_load):
    def trace(R,v):
        Cp,XX,Co,Ce,Ch,Xk=Cp0,XX0,v,Ce0,0,0
        def Xf():
            nonlocal Cp,XX
            a=(Cp*((XX%0x10000)+0x7789)+XX*30072+(Co%0x7FFFFF01)*0x36F3+Ce*24463+0x3AC542A2)%0x7FFFFF01
            b=(XX*((a%0x10000)+0x30E7)+a*0x5D94+(Co%0x7FFFFF01)*0xFCE9+Ce*35813+0x7F1E742F)%0x7FFFFF01
            Cp,XX=a,b
        for _ in range(npre): Xf()
        Co,Ce=1,0
        for _ in range(npost): Xf()
        xs=[]
        for it in range(len(R)):
            if xj_before_xf: Co,Ce=Ch+1,Xk; Xf()
            else: Xf(); Co,Ce=Ch+1,Xk
            c = Ch if xy_uses[0]=='pre' else Ch+1
            xk = Xk if xy_uses[1]=='prev' else R[Ch]
            xs.append((Cp%256+(XX%256)*3+(c%256)*5+xk*7)%256)
            Xk=R[Ch]; Ch+=1
        return xs
    return trace
best=[]
for cpname,(cp0,xx0) in [("RU,Rd",(RU0,Rd0)),("Rd,RU",(Rd0,RU0)),("post",(Rk1,RR1)),("post_rev",(RR1,Rk1))]:
 for Ce0 in [0xDC4E,0,1,0x30E7]:
  for npre in [0,1,2]:
   for npost in [5,6,7,8,9]:
    for xj in [True,False]:
     for ch in ['pre','post']:
      for xk in ['prev','cur']:
        tr=mk(cp0,xx0,Ce0,npre,npost,xj,(ch,xk),False)
        pairs={};bad=0
        for name,arr,seed in A:
            xs=tr(arr,seed)
            for i,c in enumerate(name if name in("k",) else {"setmetatable":"setmetatable","__mode":"__mode","k":"k","type":"type","getfenv":"getfenv","bit32":"bit32","bit":"bit","string":"string","tostring":"tostring","char":"char","find":"find","rshift_a":"rshift","rshift_b":"rshift","band":"band","bxor":"bxor"}[name]):
                xr=(arr[i]+256-ord(c))%256;xc=xs[i]
                if xc in pairs and pairs[xc]!=xr: bad+=1
                pairs[xc]=xr
        best.append((bad,cpname,hex(Ce0),npre,npost,xj,ch,xk))
best.sort()
for b in best[:12]: print(b)
