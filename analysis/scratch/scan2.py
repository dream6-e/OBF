import json
toks=json.load(open('/tmp/an/toks.json'))
N=len(toks)
start=None
for idx,(pos,t,v) in enumerate(toks):
    if t=='kw' and v=='return' and toks[idx+1][2]=='(' and toks[idx+2][2]=='{':
        start=idx+2; break
stack=[]   # entries: '{' , 'block' , 'repeat' , '(' 
keys=[]
j=start
endtok=None
pending_do=False
while j<N:
    pos,t,v=toks[j]
    if t=='kw':
        if v=='function': stack.append('block')
        elif v=='if': stack.append('block')
        elif v in('for','while'): stack.append('block'); pending_do=True
        elif v=='do':
            if pending_do: pending_do=False
            else: stack.append('block')
        elif v=='repeat': stack.append('repeat')
        elif v=='until':
            while stack and stack[-1]!='repeat': stack.pop()
            if stack: stack.pop()
        elif v=='end':
            while stack and stack[-1]!='block': stack.pop()
            if stack: stack.pop()
    elif t=='op':
        if v=='{': stack.append('brace')
        elif v=='}':
            k=len(stack)-1
            while k>=0 and stack[k]!='brace': k-=1
            if k<0: endtok=j; break
            del stack[k:]
            if not stack: endtok=j; break
    nblock=sum(1 for x in stack if x=='block')
    nbrace=sum(1 for x in stack if x=='brace')
    if nbrace==1 and nblock==0 and t=='name' and toks[j+1][2]=='=' and toks[j+2][2]!='=' and toks[j-1][2] in ('{',','):
        keys.append((v,pos,j))
    j+=1
print("table:",toks[start][0],"->",toks[endtok][0],"keys:",len(keys))
rows=[]
for kk,(v,pos,j) in enumerate(keys):
    e = keys[kk+1][1] if kk+1<len(keys) else toks[endtok][0]
    rows.append({'key':v,'start':pos,'end':e,'len':e-pos,'tok':j})
for r in rows: print(f"{r['key']:8s} start={r['start']:7d} end={r['end']:7d} len={r['len']:8d}")
json.dump(rows,open('/tmp/an/keys.json','w'))
