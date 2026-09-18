/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "rv(i[2])[rk(i[3])]=rk(i[4]);"
}
