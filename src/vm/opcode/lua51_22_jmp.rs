/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "if i[2]>0 then close(i[2]-1)end;pc=pc+i[6];"
}
