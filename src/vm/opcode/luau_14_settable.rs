/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "rv(i[3])[rv(i[4])]=rv(i[2]);"
}
