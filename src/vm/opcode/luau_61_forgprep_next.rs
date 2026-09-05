/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "if type(rv(i[2]))~='function'then error('invalid generic for iterator',0)end;pc=pc+i[5];"
}
