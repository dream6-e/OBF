/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "rv(i[3])[i[4]+1]=rv(i[2]);"
}
