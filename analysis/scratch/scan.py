import json
toks=json.load(open('/tmp/an/toks.json'))
N=len(toks)
# find return ( { 
start=None
for idx,(pos,t,v) in enumerate(toks):
    if t=='kw' and v=='return' and toks[idx+1][2]=='(' and toks[idx+2][2]=='{':
        start=idx+2; break
brace=0; block=0
keys=[]
j=start
endtok=None
OPEN_BLOCK={'function','if','for','while'}
while j<N:
    pos,t,v=toks[j]
    if t=='op' and v=='{': brace+=1
    elif t=='op' and v=='}':
        brace-=1
        if brace==0: endtok=j; break
    elif t=='kw' and v in OPEN_BLOCK: block+=1
    elif t=='kw' and v=='end': block-=1
    elif brace==1 and block==0 and t=='name' and toks[j+1][2]=='=' and toks[j+2][2]!='=' and toks[j-1][2] in ('{',','):
        keys.append((v,pos,j))
    j+=1
print("table:",toks[start][0],"->",toks[endtok][0], "keys:",len(keys))
rows=[]
for kk,(v,pos,j) in enumerate(keys):
    e = keys[kk+1][1] if kk+1<len(keys) else toks[endtok][0]
    rows.append({'key':v,'start':pos,'end':e,'len':e-pos,'tok':j})
for r in rows:
    print(f"{r['key']:8s} start={r['start']:7d} len={r['len']:7d}")
json.dump(rows,open('/tmp/an/keys.json','w'))
