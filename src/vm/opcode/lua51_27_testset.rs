/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local v=rv(i[3]);local ok=falsy(v)~=(i[4]~=0);if ok then sv(i[2],v)end;branch(ok);"
}
