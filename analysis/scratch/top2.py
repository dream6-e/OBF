import json
toks=json.load(open('/tmp/an/toks.json'))
start=None
for idx,(pos,t,v) in enumerate(toks):
    if t=='kw' and v=='return' and toks[idx+1][2]=='(' and toks[idx+2][2]=='{':
        start=idx+2; break
d=0; keys=[]; j=start
while j<len(toks):
    pos,t,v=toks[j]
    if t=='op' and v=='{':
        d+=1
    elif t=='op' and v=='}':
        d-=1
        if d==0:
            tend=j; break
    elif d==1 and t=='name' and toks[j+1][2]=='=' and toks[j-1][2] in ('{',','):
        keys.append((v,pos,j))
    j+=1
print("table chars", toks[start][0], "->", toks[tend][0])
print("num top-level keys:",len(keys))
prev=toks[start][0]
rows=[]
for kk,(v,pos,j) in enumerate(keys):
    end = keys[kk+1][1] if kk+1<len(keys) else toks[tend][0]
    rows.append((v,pos,end-pos,j))
for v,pos,ln,j in rows:
    print(f"{v:8s} start={pos:7d} len={ln:7d} tok={j}")
json.dump(rows,open('/tmp/an/topkeys.json','w'))
