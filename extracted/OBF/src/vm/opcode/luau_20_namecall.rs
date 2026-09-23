/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=C[pc][7];pc=pc+1;local v=rv(i[3]);sv(i[2]+1,v);sv(i[2],(F.n and F.n[x])or v[K[x]]);"
}
