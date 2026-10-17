import re,sys
sys.path.insert(0,'.')
import verify
from verify import C, parse, DATA, M
from crack import compute_RZ, kI, compute_RV
RZ=compute_RZ()
Rp,va0,k1,b1,y1,C1=kI(RZ,DATA[0],DATA[1],DATA[2],DATA[3])
RV0=compute_RV(Rp,RZ)
print("baseline state=(%d,%d,%d,%d) RV0=%d"%(k1,b1,y1,C1,RV0))
def run_va(va):
    c=C(va,(k1,b1,y1,C1))
    try: return parse(c,RV0),None
    except (EOFError,ValueError,KeyError) as e: return None,str(e)
vals=[]
for l in open(sys.argv[1] if len(sys.argv)>1 else 'hits_va.txt'):
    m=re.match(r'va=\s*(\d+)\s+kQ=\s*(\d+)',l)
    if m: vals.append((int(m.group(1)),int(m.group(2))))
print("verifying %d va candidates"%len(vals))
surv=[]
for va,kQ in vals:
    info,err=run_va(va)
    if info:
        print("  *** FULL PARSE OK *** va=%d %s"%(va,info)); surv.append((va,info))
print("\n%d / %d survived"%(len(surv),len(vals)))
