import json
exec(open('/tmp/an/run.py').read().split("blob=open")[0])
def lz(B):
    CG=[]; Ck=8; CP=0; i=0; n=len(B)
    while i<n:
        if Ck>7:
            CP=B[i]; i+=1; Ck=0
        if CP&1:
            if i>=n: break
            CG.append(B[i]); i+=1
        else:
            if i+3>n: break
            CB,CY,CK=B[i],B[i+1],B[i+2]; i+=3
            off=CB*256+CY
            Cc=len(CG)-off+1
            if Cc<1: raise ValueError(f"bad backref off={off} len(CG)={len(CG)} at i={i}")
            for t in range(CK+3):
                CG.append(CG[Cc-1+t])
        CP>>=1; Ck+=1
    return bytes(CG),i
blob=open('/tmp/an/blob.txt').read()
st=Stream(CM)
B1=decode(tokenize(blob[:2501]),st)
out,used=lz(B1)
print("part1 raw bytes:",len(B1),"consumed:",used)
print("part1 LZ-decompressed:",len(out))
open('/tmp/an/stage1.txt','wb').write(out)
print(repr(out[:600].decode('latin1')))
print("...")
print(repr(out[-200:].decode('latin1')))
