/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=C[pc][7];if rv(i[2])==rv(x)then pc=pc+i[5]else pc=pc+1 end;"
}
