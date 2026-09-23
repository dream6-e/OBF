/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "pc=pc+1;call(i[2],i[3],i[4]);"
}
