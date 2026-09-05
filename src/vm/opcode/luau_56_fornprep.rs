/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local l=tonumber(rv(i[2]));local s=tonumber(rv(i[2]+1));local x=tonumber(rv(i[2]+2));if not l or not s or not x then error('invalid numeric for values',0)end;sv(i[2],l);sv(i[2]+1,s);sv(i[2]+2,x);if not((s>0 and x<=l)or(s<=0 and x>=l))then pc=pc+i[5]end;"
}
