/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local aux=C[pc][7];local n=aux%256;local z=Z(rv(i[2])(rv(i[2]+1),rv(i[2]+2)));for j=1,n do sv(i[2]+2+j,z[j])end;sv(i[2]+2,z[1]);if z[1]==nil then pc=pc+1 else pc=pc+i[5]end;"
}
