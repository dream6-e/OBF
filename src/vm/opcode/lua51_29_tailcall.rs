/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local n=i[3]==0 and(top-i[2])or(i[3]-1);local a={n=n};for j=1,n do a[j]=rv(i[2]+j)end;return rv(i[2])(U(a,1,n));"
}
