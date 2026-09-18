/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local v=rv(i[3]);sv(i[2]+1,v);sv(i[2],v[rk(i[4])]);"
}
