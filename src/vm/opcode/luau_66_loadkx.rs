/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=C[pc][7];pc=pc+1;sv(i[2],K[x]);"
}
