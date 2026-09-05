/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "error('orphan capture instruction',0);"
}
