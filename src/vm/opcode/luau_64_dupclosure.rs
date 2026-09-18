/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local M=K[i[5]];local id=M.p;local Q=P[id];local cu={};for j=0,Q.u-1 do local d=C[pc];pc=pc+1;if d[1]~=OC then E()end;if d[2]==0 then cu[j]={[1]=rv(d[3])}elseif d[2]==1 then cu[j]=R[d[3]]else cu[j]=ups[d[3]]end end;sv(i[2],mk(id,cu));"
}
