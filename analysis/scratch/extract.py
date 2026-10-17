import json,re,sys
sys.path.insert(0,'/tmp/an')
exec(open('/tmp/an/dec.py').read().split("print(\"test1")[0])
toks=json.load(open('/tmp/an/toks.json'))
src=open('/home/user/OBF/V2.7.lua',encoding='utf-8',errors='replace').read()
N=len(toks)
def numval(v):
    return int(v,16) if v[:2].lower()=='0x' else (int(v) if re.fullmatch(r'\d+',v) else float(v))
calls=[]
for i in range(N-4):
    p,t,v=toks[i]
    if t!='name': continue
    if toks[i+1][2]!='(' : continue
    if toks[i+2][2]!='{' : continue
    # find matching close brace
    d=0; j=i+2
    ok=True
    while j<N:
        tt=toks[j][1]; vv=toks[j][2]
        if tt=='op' and vv=='{': d+=1
        elif tt=='op' and vv=='}':
            d-=1
            if d==0: break
        elif tt=='name': pass
        elif tt not in ('num','op'): ok=False; break
        elif tt=='op' and vv not in (',','(',')','%','+','-','*'): ok=False; break
        j+=1
    if not ok or j>=N: continue
    # after '}' expect ',' then seed then ')'
    if toks[j+1][2]!=',' or toks[j+2][1]!='num' or toks[j+3][2]!=')': continue
    arr_txt=src[toks[i+2][0]:toks[j][0]+1]
    seed=numval(toks[j+2][2])
    # evaluate array: replace modulus identifiers with 256
    inner=arr_txt[1:-1]
    exprs=[]
    # split at top-level commas
    d=0; cur=''
    for ch in inner:
        if ch=='(': d+=1
        if ch==')': d-=1
        if ch==',' and d==0: exprs.append(cur); cur=''
        else: cur+=ch
    if cur.strip(): exprs.append(cur)
    vals=[]
    good=True
    for e in exprs:
        e2=re.sub(r'(?<![0-9a-fA-FxX])([A-Za-z_][A-Za-z0-9_]*)(?![0-9a-fA-FxX])',
                  lambda m: '256' if len(m.group(1))<=2 and m.group(1) not in ('e','E') else m.group(1), e)
        e2=re.sub(r'0[xX]([0-9a-fA-F]+)',lambda m:str(int(m.group(1),16)),e2)
        try: vals.append(int(eval(e2,{'__builtins__':{}},{})))
        except Exception as ex: good=False; break
    if not good: continue
    calls.append({'name':v,'pos':p,'arr':vals,'seed':seed,'raw':src[p:toks[j+3][0]+1]})
print("decoder calls found:",len(calls))
res={}
bad=0
for c in calls:
    try:
        d=dec_bytes(c['arr'],c['seed'])
    except Exception as e:
        bad+=1; continue
    printable = all(32<=ord(ch)<127 for ch in d)
    c['dec']=d; c['printable']=printable
    res.setdefault(d,[]).append(c['name'])
print("errors:",bad)
print("unique decoded:",len(res))
np=[k for k in res if all(32<=ord(c)<127 for c in k)]
print("printable unique:",len(np))
for k in sorted(np,key=lambda x:-len(res[x])):
    print(f"  {k!r:24} x{len(res[k]):3d}  via {sorted(set(res[k]))}")
print("--- raw calls ---")
for c in calls[:400]:
    print(f"@{c['pos']:7d} {c['raw'][:120]:120s} -> {c.get('dec')!r}")
non=[k for k in res if k not in np]
print("non-printable:",len(non), [repr(x) for x in non[:10]])
json.dump([{k:v for k,v in c.items()} for c in calls],open('/tmp/an/strcalls.json','w'))
