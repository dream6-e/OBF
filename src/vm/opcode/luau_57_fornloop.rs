/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local l=rv(i[2]);local s=rv(i[2]+1);local x=rv(i[2]+2)+s;sv(i[2]+2,x);if(s>0 and x<=l)or(s<=0 and x>=l)then pc=pc+i[5]end;"
}
