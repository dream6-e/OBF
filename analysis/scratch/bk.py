import json,re
M=1<<32
# op table from bk
OP={}
def X(i,j,k): OP[(i,j)]=('xor',k)
def A(i,j,k): OP[(i,j)]=('add',k)
OP[(0x6C,0x11)]=('and2',None)
OP[(0x66,0x19)]=('and1',0xFFFFFFFF)
OP[(0x66,122)]=('shr1',1)
X(0x35,0x20,0x74F4577);  A(0x35,0x64,0x7D0E8B9D)
X(0x60,0x2D,0x6C4CE3);   A(0x60,0x27,0x7FBECC03)
X(0x26,0x32,0x1EDBF73);  A(0x26,0x33,0x73E976CB)
X(0x6A,0x52,0x559A1A1);  A(0x6A,0x1B,0x72903A7F)
X(0x75,0x4C,0x13AC7D1);  A(0x75,0x68,0x4E85C005)
X(0x62,0x78,0x569D8D9);  A(0x62,0x64,0x7436E41F)
X(0x79,0x4C,0x6FC84C3);  A(0x79,0x6B,0x4D33E13B)
X(0x6F,0x51,0x644F76D);  A(0x6F,0x5E,0x4B0DACD1)
X(0x7B,0x21,0x6138015);  A(0x7B,0x63,0x6B33BDB9)
X(0x1D,0x20,0x5EB887B);  A(0x1D,0x51,0x5969A577)
def apply(i,j,args):
    t=OP.get((i,j))
    if t is None: return None
    kind,k=t
    if kind=='xor': return (args[0]^args[1]^k)&0xFFFFFFFF
    if kind=='add': return (args[0]+args[1]-k)&0xFFFFFFFF
    if kind=='and2': return (args[0]&args[1])&0xFFFFFFFF
    if kind=='and1': return (args[0]&k)&0xFFFFFFFF
    if kind=='shr1': return (args[0]>>k)&0xFFFFFFFF
    return None
def sgn(v): return v-(1<<32) if v>=0x80000000 else v
toks=json.load(open('/tmp/an/toks.json'))
src=open('/home/user/OBF/V2.7.lua',encoding='utf-8',errors='replace').read()
N=len(toks)
def nv(v): return int(v,16) if v[:2].lower()=='0x' else int(v)
res=[]
for i in range(N-8):
    p,t,v=toks[i]
    if t!='name': continue
    if toks[i+1][2]!='[' or toks[i+2][1]!='num' or toks[i+3][2]!=']': continue
    if toks[i+4][2]!='[' or toks[i+5][1]!='num' or toks[i+6][2]!=']': continue
    if toks[i+7][2]!='(': continue
    a1=toks[i+8]; 
    if a1[1]!='num': continue
    if toks[i+9][2]==')':
        args=[nv(a1[2])]; endx=i+9; raw=src[p:toks[endx][0]+1]
    elif toks[i+9][2]==',' and toks[i+10][1]=='num' and toks[i+11][2]==')':
        args=[nv(a1[2]),nv(toks[i+10][2])]; endx=i+11; raw=src[p:toks[endx][0]+1]
    else: continue
    val=apply(nv(toks[i+2][2]),nv(toks[i+5][2]),args)
    if val is None: continue
    res.append({'pos':p,'end':toks[endx][0]+len(toks[endx][2]),'raw':raw,'i':nv(toks[i+2][2]),'j':nv(toks[i+5][2]),'args':args,'val':val,'ident':v})
print("resolved op-calls:",len(res))
import collections
print("by opcode pair:",collections.Counter((hex(r['i']),hex(r['j'])) for r in res).most_common(8))
json.dump(res,open('/tmp/an/ops.json','w'))
for r in res[:12]: print(f"  {r['raw']:52s} = {r['val']:11d} = 0x{r['val']:08X} (signed {sgn(r['val'])})")
