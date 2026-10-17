import json,re
exec(open('/tmp/an/dec.py').read().split("print(\"test1")[0])
ops=json.load(open('/tmp/an/ops.json'))
calls=json.load(open('/tmp/an/strcalls.json'))
src=open('/home/user/OBF/V2.7.lua',encoding='utf-8',errors='replace').read()
def sgn(v): return v-(1<<32) if v>=0x80000000 else v
edits=[]
for r in ops:
    v=r['val']
    txt=f"/*{sgn(v)}|0x{v:08X}*/"
    edits.append((r['pos'],r['end'],txt))
for c in calls:
    d=c.get('dec','')
    if not d: continue
    if all(32<=ord(x)<127 for x in d) and (len(d)>=2 or d in ('k','C','S','#','=')):
        edits.append((c['pos'],c['pos']+len(c['raw']),f'/*STR:{d}*/'+c['raw']))
edits.sort()
out=[];last=0;cnt=0
for a,b,t in edits:
    if a<last: continue
    out.append(src[last:a]); out.append(t); last=b; cnt+=1
out.append(src[last:])
res=''.join(out)
open('/tmp/an/resolved.lua','w').write(res)
print("edits applied:",cnt,"new len:",len(res))
