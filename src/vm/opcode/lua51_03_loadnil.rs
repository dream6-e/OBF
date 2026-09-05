/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "for j=i[2],i[3] do sv(j,nil)end;"
}
