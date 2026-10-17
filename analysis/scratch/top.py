import json
toks=json.load(open('/tmp/an/toks.json'))
# find 'return' '(' '{' at top
# track depth of (), {}, and function/end blocks
i=0
# locate first '{' that is the return table
start=None
for idx,(pos,t,v) in enumerate(toks):
    if t=='kw' and v=='return':
        # next should be ( {
        if toks[idx+1][2]=='(' and toks[idx+2][2]=='{':
            start=idx+2
        break
print("table start token idx",start,"at char",toks[start][0])
depth=0; paren=0
keys=[]
cur=None
j=start
pendepth=0
while j<len(toks):
    pos,t,v=toks[j]
    if t=='op' and v=='{':
        pendepth+=1
        if pendepth==1: tblstart=j
    elif t=='op' and v=='}':
        pendepth-=1
        if pendepth==0:
            print("table end at token",j,"char",pos); break
    elif pendepth==1 and t=='name' and toks[j+1][1]=='op' and toks[j+1][2]=='=' :
        keys.append((v,pos,j))
    j+=1
print("num top-level keys:",len(keys))
for kk,(v,pos,j) in enumerate(keys):
    end = keys[kk+1][2] if kk+1<len(keys) else j
    print(f"{v:6s} charpos={pos:7d} tokidx={j:6d} len_chars={ (keys[kk+1][1] if kk+1<len(keys) else pos)-pos }")
