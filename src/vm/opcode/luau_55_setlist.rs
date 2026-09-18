/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=C[pc][7];pc=pc+1;local n=i[4]-1;if n<0 then n=top-i[3]+1 end;local t=rv(i[2]);for j=0,n-1 do t[x+j]=rv(i[3]+j)end;"
}
