/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "if fs(rv(i[2]))then pc=pc+i[5]end;"
}
