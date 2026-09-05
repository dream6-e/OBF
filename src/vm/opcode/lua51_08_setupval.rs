/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "ups[i[3]][1]=rv(i[2]);"
}
