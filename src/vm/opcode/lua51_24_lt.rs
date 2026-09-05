/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "branch((rk(i[3])<rk(i[4]))==(i[2]~=0));"
}
