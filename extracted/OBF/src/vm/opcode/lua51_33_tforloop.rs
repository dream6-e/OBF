/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local z=Z(rv(i[2])(rv(i[2]+1),rv(i[2]+2)));for j=1,i[4] do sv(i[2]+2+j,z[j])end;local ok=z[1]~=nil;if ok then sv(i[2]+2,z[1])end;branch(ok);"
}
