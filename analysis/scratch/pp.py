import sys,re
src=open('V2.7.lua',encoding='utf-8',errors='replace').read()
out=[]
i=0;n=len(src)
depth=0
def iskw(s,i,w):
    if src[i:i+len(w)]!=w: return False
    before = src[i-1] if i>0 else ' '
    after = src[i+len(w)] if i+len(w)<len(src) else ' '
    return not (before.isalnum() or before=='_') and not (after.isalnum() or after=='_')
# tokenizer
toks=[]
while i<n:
    c=src[i]
    if c=='-' and src[i+1:i+2]=='-':
        # comment
        if src[i+2:i+4]=='[[':
            j=src.find(']]',i+4); j=n if j<0 else j+2
        else:
            j=src.find('\n',i); j=n if j<0 else j
        toks.append(('comment',src[i:j])); i=j; continue
    if c=='"' or c=="'":
        q=c; j=i+1
        while j<n:
            if src[j]=='\\': j+=2; continue
            if src[j]==q: j+=1; break
            j+=1
        toks.append(('str',src[i:j])); i=j; continue
    if c=='[' and src[i+1:i+2] in ('[','='):
        j=src.find(']',i)
        toks.append(('lstr',src[i:j+1])); i=j+1; continue
    if c.isalnum() or c=='_':
        j=i
        while j<n and (src[j].isalnum() or src[j]=='_'): j+=1
        # handle hex like 0X123
        toks.append(('name',src[i:j])); i=j; continue
    if src[i:i+2] in ('==','~=','<=','>=','..','::'):
        toks.append(('op',src[i:i+2])); i+=2; continue
    toks.append(('op',c)); i+=1
# now emit with indentation
line=[]
ind=0
res=[]
buf=''
def flush():
    global buf
    if buf.strip(): res.append('  '*ind+buf.strip())
    buf=''
k=0
KW_INC={'function','then','do','else','repeat','{','('}
while k<len(toks):
    t,v=toks[k]
    if t=='comment':
        flush(); res.append('  '*ind+v); k+=1; continue
    w=v
    if iskw(None,0,''): pass
    # detect keywords by name tokens
    if t=='name' and v in ('end','until'):
        ind=max(0,ind-1); buf+=v+';'
        if v=='end': flush()
        k+=1; continue
    if t=='name' and v in ('function',):
        buf+=v; 
        # find matching: increment after we see ')'
        k+=1; continue
    if t=='name' and v in ('then','do'):
        buf+=' '+v; ind+=1; flush(); k+=1; continue
    if t=='name' and v=='else':
        ind=max(0,ind-1); buf+=v; ind+=1; flush(); k+=1; continue
    if t=='name' and v=='elseif':
        ind=max(0,ind-1); buf+=v; k+=1; continue
    if t=='name' and v=='repeat':
        buf+=v; ind+=1; flush(); k+=1; continue
    if t=='op' and v=='}':
        flush(); ind=max(0,ind-1); buf+=v; 
        k+=1; continue
    if t=='op' and v=='{':
        buf+=v; ind+=1; flush(); k+=1; continue
    if t=='op' and v==';':
        buf+=v; flush(); k+=1; continue
    if t=='op' and v==',' and ind>0:
        buf+=v;
        if len(buf)>140: flush()
        k+=1; continue
    buf+=v if t in('str','lstr','name') and not buf.endswith((' ','(','[','.')) else v
    k+=1
flush()
open('/tmp/an/pretty.lua','w').write('\n'.join(res))
print(len(res),"lines")
