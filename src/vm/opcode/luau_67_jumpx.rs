/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "pc=pc+i[6];"
}
