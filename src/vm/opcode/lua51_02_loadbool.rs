/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "sv(i[2],i[3]~=0);if i[4]~=0 then pc=pc+1 end;"
}
