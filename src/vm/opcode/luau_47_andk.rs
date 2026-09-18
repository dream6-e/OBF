/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=rv(i[3]);sv(i[2],sel(fs(x),x,K[i[4]]));"
}
