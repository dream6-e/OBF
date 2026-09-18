import pickle,struct
d=pickle.load(open('protos.pkl','rb'))
protos,bodies=d['protos'],d['bodies']
def cl_decode(buf,pos,length,key):
    # local cl = function(i,q,t,k) : i=buf, q=pos(0-based via readu8(i,q+t-2)), t=len, k=key
    out=bytearray(); j=(key+119)%256
    for t in range(1,length+1):
        i2=buf[pos+t-2]
        v=(i2+256-j)%256
        out.append(v)
        j=(j*193+v*109+217)%256
    return bytes(out)
def parse_consts(buf, base, end, count):
    # emulate ia(): pk = base (0-based offset of const area start)
    res=[]; x=0; i=0; a=end-base
    while len(res)<count:
        e=base+x
        p=buf[e]
        if p==0: h=e+1; t=0; q=0
        elif p==3: t=struct.unpack_from('<I',buf,e+1)[0]; h=e+5; q=3
        elif p==1: h=e+1; t=1; q=1
        elif p==4: h=e+1; t=8; q=4
        elif p==2: h=e+1; t=8; q=2
        elif p==5: t=struct.unpack_from('<I',buf,e+1)[0]; h=e+5; q=3
        else: raise Exception('tag %d'%p)
        if q==0: s=None
        elif q==3:
            s=cl_decode(buf,h+1,t,i).decode('latin1')
        elif q==1:
            b=cl_decode(buf,h+1,1,i)[0]; assert b in (0,1); s=(b==1)
        elif q==4:
            xx=cl_decode(buf,h+1,8,i)
            hi=struct.unpack_from('<I',xx,4)[0]; lo=struct.unpack_from('<I',xx,0)[0]
            s=(hi<<32)|lo
            if s>=2**63: s-=2**64
        elif q==2:
            xx=cl_decode(buf,h+1,8,i); s=struct.unpack('<d',xx)[0]
        x=x+(h-e)+t
        i=((i+(t*257)+54108)%(2**32))
        res.append((q,s))
    return res
allc={}
for idx in range(18):
    b=bodies[idx]; h=len(b)-4
    clen=struct.unpack_from('<I',b,h)[0]; g=h-clen
    n=protos[idx]['nconst']
    if n==0: allc[idx]=[]; continue
    try:
        c=parse_consts(b,g,h,n)
        allc[idx]=c
        print(f'--- proto {idx}: {n} constants ---')
        for k,(q,v) in enumerate(c):
            t={0:'nil',1:'bool',2:'number',3:'string',4:'int64'}[q]
            print(f'  [{k}] {t}: {v!r}')
    except Exception as ex:
        print('proto',idx,'FAIL',ex); allc[idx]=None
pickle.dump(allc,open('consts.pkl','wb'))
