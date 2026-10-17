import re,sys,json
src=open('/home/user/OBF/V2.7.lua',encoding='utf-8',errors='replace').read()
KEYWORDS={'and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while'}
toks=[]
i=0;n=len(src)
while i<n:
    c=src[i]
    if c in ' \t\r\n':
        i+=1; continue
    if c=='-' and src[i+1:i+2]=='-':
        if src[i+2:i+4]=='[[':
            lvl=src.count('=',src[i+2:i+8])
            j=src.find(']'+'='*src[i+3:i+8].split('[')[0]+']',i) if False else -1
            # simple
            m=re.match(r'--\[(=*)\[',src[i:])
            eq=m.group(1); j=src.find(']'+eq+']',i)
            j=n if j<0 else j+len(eq)+2
        else:
            j=src.find('\n',i); j=n if j<0 else j
        toks.append((i,'comment',src[i:j])); i=j; continue
    m=re.match(r'\[(=*)\[',src[i:])
    if m:
        eq=m.group(1); j=src.find(']'+eq+']',i)
        j=n if j<0 else j+len(eq)+2
        toks.append((i,'lstr',src[i:j])); i=j; continue
    if c=='"' or c=="'":
        q=c;j=i+1
        while j<n:
            if src[j]=='\\': j+=2; continue
            if src[j]==q: j+=1; break
            j+=1
        toks.append((i,'str',src[i:j])); i=j; continue
    m=re.match(r'0[xX][0-9a-fA-F]+',src[i:])
    if m:
        toks.append((i,'num',m.group(0))); i+=len(m.group(0)); continue
    m=re.match(r'\d+\.?\d*([eE][-+]?\d+)?',src[i:])
    if m and (m.group(0)[0].isdigit()):
        toks.append((i,'num',m.group(0))); i+=len(m.group(0)); continue
    m=re.match(r'[A-Za-z_][A-Za-z0-9_]*',src[i:])
    if m:
        w=m.group(0)
        toks.append((i,'kw' if w in KEYWORDS else 'name',w)); i+=len(w); continue
    m=re.match(r'\.\.\.|\.\.|[<>=~]=|::|//|<<|>>|\+|-|\*|/|%|\^|#|~|<|>|=|\(|\)|\{|\}|\[|\]|;|:|,|\.|&|\||!',src[i:])
    if m:
        toks.append((i,'op',m.group(0))); i+=len(m.group(0)); continue
    print("UNPARSED at",i,repr(src[i:i+40])); break
json.dump([(t[0],t[1],t[2]) for t in toks],open('/tmp/an/toks.json','w'))
print("tokens:",len(toks))
