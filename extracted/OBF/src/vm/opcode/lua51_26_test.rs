/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "branch(falsy(rv(i[2]))~=(i[4]~=0));"
}
