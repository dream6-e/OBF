import json,os
src=open('/home/user/OBF/V2.7.lua',encoding='utf-8',errors='replace').read()
rows=json.load(open('/tmp/an/keys.json'))
os.makedirs('/tmp/an/fn',exist_ok=True)
for r in rows:
    a=r['start']-len(r['key'])-1
    b=r['end']
    seg=src[a:b].rstrip().rstrip(',')
    open(f"/tmp/an/fn/{r['key']}_{r['start']}.lua",'w').write(seg+"\n")
    print(r['key'], len(seg))
