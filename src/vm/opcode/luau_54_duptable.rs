/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "sv(i[2],clone(K[i[5]]));"
}
