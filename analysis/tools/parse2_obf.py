import struct
data=open('bytecode.bin','rb').read()
pos=0
def u8():
    global pos; v=data[pos]; pos+=1; return v
def u16():
    global pos; v=struct.unpack_from('<H',data,pos)[0]; pos+=2; return v
def u32():
    global pos; v=struct.unpack_from('<I',data,pos)[0]; pos+=4; return v
def rd(n):
    global pos; v=data[pos:pos+n]; pos+=n; return v
rd(32)
nproto=18
protos=[]
for idx in range(nproto):
    p=dict(parent=u32(),maxstack=u16(),numparams=u8(),flags=u8(),chain=u16(),
           nupval=u16(),ninstr=u32(),nconst=u32(),size=u32())
    protos.append(p)
print('pos after headers',pos)

# --- upvalue descriptor table: m = sum(nupval) entries, 3x u16 each ---
m=sum(p['nupval'] for p in protos)
print('upvalue records',m)
def perm3(k, addend):
    c=((k*1)+addend)%6
    g=(c-(c%2))//2; z=c%2
    pool=[0,1,2]; r=[g,z,0]; out=[0,0,0]
    for t in range(3):
        w=r[t]; j=0
        for x in range(3):
            if pool[x]>=0:
                if j==w:
                    out[t]=pool[x]; pool[x]=-1; break
                j+=1
    inv=[0,0,0]
    for j in range(3): inv[out[j]]=j+1
    return inv
upvals={}
for k in range(1,m+1):
    f,a,s=u16(),u16(),u16()
    inv=perm3(k,3)
    d=[f,a,s]
    t=((d[inv[0]-1]-(k*17021))-8524)%65536
    assert t<nproto,(k,t)
    q=((d[inv[1]-1]-(t*17021))-k-8524)%65536
    assert q<protos[t]['nupval'],(k,t,q,protos[t])
    h=((d[inv[2]-1]-(q*17021))-t-8524)%65536
    e=h%4; n=(h-e)//4
    assert e<=2 and n<=255
    upvals.setdefault(t,{})[q]=(e,n)
print('upvals parsed',{k:v for k,v in upvals.items()})
print('pos after upvals',pos)


# --- fragment table: interleaved triple + payload ---
frag_n=nproto*2
frags={}
for k in range(1,frag_n+1):
    f,a,s=u16(),u16(),u16()
    inv=perm3(k,2)
    d=[f,a,s]
    t=((d[inv[0]-1]-(k*53011))-34510)%65536
    assert 1<=t<=frag_n,(k,t)
    i=(t-1)//2
    y=((d[inv[1]-1]-(t*53011))-k-34510)%65536
    assert y==i,(k,t,y,i)
    o=(t-1)%2
    l1=protos[i]['size']
    b=((d[inv[2]-1]-(t*53011))-i-34510)%65536
    x=1+((l1-1)*((34510+i*53011)%65536))//65536
    w=x if o==0 else l1-x
    frags[t]=(i,b,rd(w))
print('pos after fragments',pos,'total',len(data))
assert pos==len(data),(pos,len(data))
bodies={}
used={}
for i in range(nproto):
    j=i*2+1
    sb=b''
    for _ in range(2):
        fr=frags[j]
        assert fr[0]==i and j not in used,(i,j)
        used[j]=1
        sb+=fr[2]; j=fr[1]
    assert j==0 and len(sb)==protos[i]['size'],(i,j,len(sb),protos[i]['size'])
    bodies[i]=sb
print('all bodies reassembled OK')
for i in range(nproto): print(i,'body',len(bodies[i]))
import pickle
pickle.dump({'protos':protos,'bodies':bodies,'upvals':upvals},open('protos.pkl','wb'))
