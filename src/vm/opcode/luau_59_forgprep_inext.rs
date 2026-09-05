/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "if type(rv(i[2]))~='function'then E()end;pc=pc+i[5];"
}
