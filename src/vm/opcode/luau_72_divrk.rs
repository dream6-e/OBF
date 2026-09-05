/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "sv(i[2],K[i[3]]/rv(i[4]));"
}
