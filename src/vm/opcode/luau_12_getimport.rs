/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "pc=pc+1;sv(i[2],imp(K[i[5]].i));"
}
