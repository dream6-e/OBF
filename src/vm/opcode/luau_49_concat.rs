/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=rv(i[4]);for j=i[4]-1,i[3],-1 do x=rv(j)..x end;sv(i[2],x);"
}
