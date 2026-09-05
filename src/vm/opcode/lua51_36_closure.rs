/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local Q=P[F.q[i[5]]];local cu={};for j=0,Q.u-1 do local d=C[pc];pc=pc+1;if d[1]==OM then cu[j]=R[d[3]]elseif d[1]==OU then cu[j]=ups[d[3]]else E()end end;local id=F.q[i[5]];sv(i[2],function(...)return H(id,Z(...),cu,env)end);"
}
