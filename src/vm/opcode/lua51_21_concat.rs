/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local v=rv(i[4]);for j=i[4]-1,i[3],-1 do v=rv(j)..v end;sv(i[2],v);"
}
