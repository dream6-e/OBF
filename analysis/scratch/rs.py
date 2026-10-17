import json
exec(open('/tmp/an/vmdec.py').read().split("print(\"Rb keys")[0])
blob=open('/tmp/an/blob.txt').read()
st=Stream(CM); B2=decode(tokenize(blob[2501:]),st)
V={'va':va,'Rc':kk,'RF':bb,'Ru':yy,'Rx':C4}
print("va",V['va'],"key",[V['Rc'],V['RF'],V['Ru'],V['Rx']])
def rotr8(x,n): 
    x&=0xFF; n&=7
    return ((x>>n)|(x<<(8-n)))&0xFF if n else x
Rc,RF,Ru,Rx=V['Rc'],V['RF'],V['Ru'],V['Rx']
va_=V['va']
Rm=5            # 1-based cursor, 4 key bytes consumed
vU=4
def vf():
    global Rm
    b=B2[Rm-1]; Rm+=1; return b
P1=o(0x79,0x6B,240575207,0x3EDEBA07)%0x10000
P2=o(0x26,0x32,0x71479ABB,606349989)%0x10000
P3full=o(0x26,0x32,0x71479ABB,606349989)
P3=P3full%0x7FFFFFFF
P4=o(0x79,0x6B,240575207,1054784007)%0x1D
def RS():
    global Rc,RF,Ru,Rx,vU
    RW=vf(); vU=Rm-1
    Rz=RW
    # RR[41]: (R+256-((Rx+(vU%256)*7)%256))%256
    Rz=(Rz+256-((Rx+(vU%256)*7)%256))%256
    # RR[48]: rotr8(R,3)
    Rz=rotr8(Rz,3)
    # RR[82]: xor(R,Ru)
    Rz=(Rz^Ru)&0xFF
    # RR[22]: (R+256-((Rc+RF+(vU%256)*0xC3)%256))%256
    Rz=(Rz+256-((Rc+RF+(vU%256)*0xC3)%256))%256
    Ry=Rz
    RO=vU%0x7FFFFFFF; Rt=va_%0x7FFFFFFF
    RE=(Rt+RO*P1+P3)%0x7FFFFFFF
    RL=(Rt*0x101+RO*P2+P1*0x11)%0x7FFFFFFF
    for _ in range(3):
        RRn=(RE*((RL%0x10000)+P1+0x101)+RL*0x101+RO*(0x11+P3%0x1F)+Rt)%0x7FFFFFFF
        Rkn=(RL*((RRn%0x10000)+P2+0x107)+RRn*0x81+RO*(0x17+P4)+P3full)%0x7FFFFFFF
        RE,RL=RRn,Rkn
    RA=(RE%256+(RL%256)*3+(RO%256)*5+((RE-RE%256)//256)%256+((RL-RL%256)//256)%256)%256
    Ry=(Ry^RA)&0xFF
    # RR[44]: Rc = xor(rotr8((Rc+R+Rx+(vU%256))%256,5), RW)
    Rc=(rotr8((Rc+Ry+Rx+(vU%256))%256,5)^RW)&0xFF
    # RR[96]: RF = rotr8((RF*5+RW+(Ry+Rc))%256,2)
    RF=rotr8((RF*5+RW+((Ry^Rc)&0xFF))%256,2)
    # RR[12]: Ru = xor(rotr8((Ru+Ry+RW+RF+7)%256,5), Rx)
    Ru=(rotr8((Ru+Ry+RW+RF+7)%256,5)^Rx)&0xFF
    # RR[40]: Rx = rotr8((Rx+RW+Ry+Rc+Ru+7)%256,1)
    Rx=rotr8((Rx+RW+Ry+Rc+Ru+7)%256,1)
    return Ry
def Rwu32():
    a,b,c,d=RS(),RS(),RS(),RS()
    return a + d*16777216 + b*256 + c*65536
out=[RS() for _ in range(96)]
print("first 96 decrypted stream bytes:")
print(out)
print()
print("as u32 LE (Rw):",[hex(Rwu32()) for _ in range(8)])
import collections
print("histogram of 256 bytes:",collections.Counter([RS() for _ in range(256)]).most_common(6))
