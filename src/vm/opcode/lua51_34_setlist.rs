/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local n=i[3];local block=i[4];if n==0 then n=top-i[2]end;if block==0 then local d=C[pc];pc=pc+1;block=d[7]end;local t=rv(i[2]);local last=(block-1)*50+n;for j=n,1,-1 do t[last]=rv(i[2]+j);last=last-1 end;"
}
