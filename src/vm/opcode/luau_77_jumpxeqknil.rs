/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=C[pc][7];local ok=(rv(i[2])==nil)~=(x>=2147483648);if ok then pc=pc+i[5]else pc=pc+1 end;"
}
