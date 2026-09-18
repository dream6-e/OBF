import struct
exec(open('decrypt.py').read().split('# ---- validate')[0])

payload=open('payload.bin','rb').read()
u32=lambda b,o: struct.unpack_from('<I',b,o)[0]
magic=u32(payload,0)
print('magic',magic, struct.pack('<I',magic))
t_=u32(payload,4)   # uncompressed size
i_=u32(payload,8)   # bit count
a_=u32(payload,12)  # adler32 of output
import math
s_=math.floor((i_+7)/8)
is_=math.floor((t_+8191)/8192)
print('uncompressed',t_,'bits',i_,'adler',a_,'sbytes',s_,'len-16',len(payload)-16)
assert s_==len(payload)-16
uh=((t_*31)+(is_*13)+(a_*7)+(i_*17)+s_)%M32
print('uh(nonce-seed)',uh)
body=payload[16:]
# decrypt with t=2 variant
k=decstr(body,mp,le,qt,ii,uh,2,IS)
open('lzwbits.bin','wb').write(k)
print('bitstream',len(k),'bytes')
m_=(len(k)*8)-i_
print('slack bits',m_)
assert m_<=7
if m_>0:
    assert (k[-1]>>(8-m_))==0, 'tail bits not zero'
print('tail-bit check OK')

# ---- LZW decode ----
class BR:
    def __init__(self,data,nbits):
        self.d=data; self.j=0; self.n=nbits
    def read(self,x):
        if self.j > self.n-x: raise Exception('overrun')
        t=0
        for i in range(x):
            jj=self.j+i
            t += ((self.d[jj//8] >> (jj%8)) & 1) << i
        self.j+=x
        return t
br=BR(k,i_)
out=bytearray()
total=t_
t=0
while t<total:
    m=min(t+8192,total)
    d={}; e=[0]*4096
    i=256; q=None; f=0
    while t<m:
        p=br.read(1)
        if p==1:
            j=br.read(8)
            if j<32: raise Exception('lit<32')
        else:
            p=br.read(1)
            if p==1:
                j=br.read(5)
            else:
                if q is None: raise Exception('no prev')
                cnt=0; ii2=i-256
                while ii2>0:
                    cnt+=1; ii2=ii2//2
                j=256+br.read(cnt)
        if j>i: raise Exception('code>i')
        a=(j==i)
        if a: d[i]=(q*256)+f
        x=0; c=j
        while c>=256:
            jj=d[c]; x+=1; e[x]=jj%256; c=jj//256
        x+=1; e[x]=c
        h=c
        if (not a) and q is not None: d[i]=(q*256)+h
        if q is not None: i+=1
        q=j; f=h
        if t+x>m: raise Exception('overflow chunk')
        for xx in range(x,0,-1):
            t+=1; out.append(e[xx])
print('decompressed',len(out))
# adler32 check
def adler(b):
    a=1;s=0
    for ch in b:
        a=(a+ch)%65521; s=(s+a)%65521
    return a+s*65536
print('adler',adler(out),'expected',a_, 'MATCH' if adler(out)==a_ else 'MISMATCH')
open('bytecode.bin','wb').write(bytes(out))
print('head',bytes(out[:64]))
