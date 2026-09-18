M32=2**32
def lcg(a,b,rounds,libstr):
    # w = debug.info(?, "s") .. LIBSTR ; but debug.info(1,"s") returns chunk name.
    # In t[9080]/t[1283]/t[3328]: w = (q and k(c,"s")) .. m  where q=debuglib, k=dbginfo, c=loadstring, m=LIBSTR
    # dbginfo(loadstring,"s") -> "[C]" for a C function
    w = "[C]" + libstr
    j = ((a*37)+b) % 2147483647
    for _ in range(rounds):
        j = (16807*j) % 2147483647
    x=0
    for ch in w:
        x = ((x + x*256) + ord(ch)) % 2147483647
    return 1 + ((j + x*37) % 2147483646)

LIBSTR = "buffer|bit32|table|freeze|debug|info"
# qt = t[9080](strbyte,3328,1283,...) -> 8 LCG rounds
qt = lcg(3328,1283,8,LIBSTR)
# le = t[1283](strbyte,901,9088,...) -> 3 rounds
le = lcg(901,9088,3,LIBSTR)
# mp = t[3328](strbyte,1910,7594,...) -> 5 rounds
mp = lcg(1910,7594,5,LIBSTR)
# ii = t[8687](ERR, strbyte): from "\127?VS@q<"
s = "\x7f?VS@q<"
vals=[]
for x in range(1,7):
    b=ord(s[x])  # 1-based index x+1 -> python x
    if b==92 or b<35 or b>121: raise SystemExit('bad')
    if b>92: b-=1
    vals.append(b-35)
ii = 1 + ((((vals[0]+vals[1]*87)*31) + ((vals[2]+vals[3]*87)*7) + (vals[4]+vals[5]*87)) % 2147483646)
print('mp(d)=',mp,' le(e)=',le,' qt(p)=',qt,' ii(h)=',ii)

blob=open('blob_full.bin','rb').read()[4:]  # strsub(...,5)
print('blob body len',len(blob))

# t[7015] typeof -> deterministic 2392745008
IS = 2392745008
# t[2902](p=blob, q=mp, m=le, k=qt, d=ii, x=#blob, t=1, c=IS, ...)
def rotl(v,n): return ((v<<n)|(v>>(32-n)))&0xffffffff
def qr(j,a,b,c,d):
    j[a]=(j[a]+j[b])%M32; j[d]=rotl(j[d]^j[a],16)
    j[c]=(j[c]+j[d])%M32; j[b]=rotl(j[b]^j[c],12)
    j[a]=(j[a]+j[b])%M32; j[d]=rotl(j[d]^j[a],8)
    j[c]=(j[c]+j[d])%M32; j[b]=rotl(j[b]^j[c],7)
def chacha(key8, ctr, nonce3):
    w=[1634760805,857760878,2036477234,1797285236]+list(key8)+[ctr]+list(nonce3)
    j=w[:]
    for _ in range(4):
        qr(j,0,4,8,12); qr(j,1,5,9,13); qr(j,2,6,10,14); qr(j,3,7,11,15)
        qr(j,0,5,10,15); qr(j,1,6,11,12); qr(j,2,7,8,13); qr(j,3,4,9,14)
    return [(w[i]+j[i])%M32 for i in range(16)]

def decstr(p, q, m, k, d, x, t, c):
    # p: bytes, q=mp, m=le, k=qt, d=ii, x=len, t=1|2, c=IS
    i=[2131147480,1736413478,546846353,3517700763,1929416932,1091648615,1562964070,1399841576]
    h=[ ((c+q+i[0])%8589934592)%M32,
        ((x+m+i[1])%8589934592)%M32,
        (c+i[2]+k)%M32,
        ((i[3]+d+x)%8589934592)%M32,
        ((q+t+m+i[4])%M32),
        ((k+(x*t)+i[5]+m)%8589934592)%M32,
        ((i[6]+q+k+c+x)%M32),
        ((m+i[7]+c+d+t+q+k)%M32) ]
    e = 394178989 if t==1 else 2000074952
    if t==1:
        n=[((x+2339963232)%8589934592)%M32, (2588098047+c)%M32, ((q+d+418558038+k)%M32)]
    else:
        n=[(3685367549+x)%M32, (304088683+c)%M32, ((q+1871031731+k+d)%M32)]
    j=chacha(h,e,n)
    h=j[0:8]; n=j[8:11]; e=(j[11]+t+e)%M32
    g=bytearray(len(p)); z=0
    for blk in range(0,len(p),64):
        ks=chacha(h,((blk//64)+e)%M32,n)
        lim=min(63,len(p)-blk-1)
        for xx in range(0,lim+1):
            wv=(ks[(xx//4)]>>(8*(xx%4)))&0xff
            tb=p[blk+xx]
            g[blk+xx]=(tb^wv^z)&0xff
            z=tb
    return bytes(g)

out=decstr(blob,mp,le,qt,ii,len(blob),1,IS)
open('decrypted.bin','wb').write(out)
print('decrypted',len(out),'head',out[:48])

# ---- validate t[5189] header checks ----
import struct
j=out
d,e,p,h = mp,le,qt,ii
L=len(j)
assert L>=16 and L%4==0 and L<=16777232, ('len bad',L)
k = 1 + (((d*19)+(e*11)+(p*7)+(h*39)+(L*47)+1965860233) % 2147483646)
c = 1 + (((d*41)+(e*57)+(p*41)+(h*3)+(L*11)+116499707) % 2147483646)
uh = 4098 + (((k+c+48042)%65536)*65536)
u32=lambda off: struct.unpack_from('<I', j, off)[0]
n=u32(0); t=u32(4); o=u32(8); mpv=u32(12)
b=(4-((16+t)%4))%4
print('n=',n,'expected uh=',uh, 'MATCH' if n==uh else 'MISMATCH')
print('t(payload len)=',t,'L check',16+t+b, 'vs', L, 'MATCH' if L==16+t+b else 'MISMATCH')
le_chk = ((t+624818895+((k%65536)*65536)+((c%65536)*17)+(n*257)) % M32)
print('o=',o,'expected',le_chk,'MATCH' if o==le_chk else 'MISMATCH')
m2=(k+1620916158)%65521; f2=(c+624818895)%65521
for x in range(16,16+t):
    bb=j[x]; m2=((m2*257)+bb)%65521; f2=(((f2*263)+bb)+m2)%65521
qtv=(((n*31)+m2+(f2*65521)+(o*17))%4294967296)
print('mp=',mpv,'expected',qtv,'MATCH' if mpv==qtv else 'MISMATCH')
for q_ in range(1,b+1):
    exp=((k+(c*q_)+23394)%256)
    got=j[16+t+q_-1]
    print(' pad',q_,got,exp,'OK' if got==exp else 'BAD')
payload=j[16:16+t]
open('payload.bin','wb').write(payload)
print('payload',len(payload),'head',payload[:32])
