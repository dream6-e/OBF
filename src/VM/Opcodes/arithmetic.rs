use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};

pub fn generate(m: &[Vec<u32>], cfg: &OpcodeConfig, rng: &mut OpcodesRng) -> String {
    let mut out = String::new();

    let mut add = OpcodeBuilder::new(m[12].clone(), cfg, rng);
    let add_b = add.rk(3); let add_c = add.rk(4); let add_a = add.raw_inst(2);
    out.push_str(&add.build(&format!("{{STK}}[{}] = {} + {}", add_a, add_b, add_c)));

    let mut sub = OpcodeBuilder::new(m[13].clone(), cfg, rng);
    let sub_b = sub.rk(3); let sub_c = sub.rk(4); let sub_a = sub.raw_inst(2);
    out.push_str(&sub.build(&format!("{{STK}}[{}] = {} - {}", sub_a, sub_b, sub_c)));

    let mut mul = OpcodeBuilder::new(m[14].clone(), cfg, rng);
    let mul_b = mul.rk(3); let mul_c = mul.rk(4); let mul_a = mul.raw_inst(2);
    out.push_str(&mul.build(&format!("{{STK}}[{}] = {} * {}", mul_a, mul_b, mul_c)));

    let mut div = OpcodeBuilder::new(m[15].clone(), cfg, rng);
    let div_b = div.rk(3); let div_c = div.rk(4); let div_a = div.raw_inst(2);
    out.push_str(&div.build(&format!("{{STK}}[{}] = {} / {}", div_a, div_b, div_c)));

    let mut mod_op = OpcodeBuilder::new(m[16].clone(), cfg, rng);
    let mod_b = mod_op.rk(3); let mod_c = mod_op.rk(4); let mod_a = mod_op.raw_inst(2);
    out.push_str(&mod_op.build(&format!("{{STK}}[{}] = {} % {}", mod_a, mod_b, mod_c)));

    let mut pow = OpcodeBuilder::new(m[17].clone(), cfg, rng);
    let pow_b = pow.rk(3); let pow_c = pow.rk(4); let pow_a = pow.raw_inst(2);
    out.push_str(&pow.build(&format!("{{STK}}[{}] = {} ^ {}", pow_a, pow_b, pow_c)));

    let mut unm = OpcodeBuilder::new(m[18].clone(), cfg, rng);
    let unm_b = unm.raw_inst(3); let unm_a = unm.raw_inst(2);
    out.push_str(&unm.build(&format!("{{STK}}[{}] = -{{STK}}[{}]", unm_a, unm_b)));

    let mut not_op = OpcodeBuilder::new(m[19].clone(), cfg, rng);
    let not_b = not_op.raw_inst(3); let not_a = not_op.raw_inst(2);
    out.push_str(&not_op.build(&format!("{{STK}}[{}] = not {{STK}}[{}]", not_a, not_b)));

    let mut len = OpcodeBuilder::new(m[20].clone(), cfg, rng);
    let len_b = len.raw_inst(3); let len_a = len.raw_inst(2);
    out.push_str(&len.build(&format!("{{STK}}[{}] = #{{STK}}[{}]", len_a, len_b)));

    let mut concat = OpcodeBuilder::new(m[21].clone(), cfg, rng);
    let concat_b = concat.raw_inst(3); let concat_c = concat.raw_inst(4); let concat_a = concat.raw_inst(2);
    out.push_str(&concat.build(&format!(
        "local res = {{STK}}[{}]; for j = {} + 1, {} do res = res .. {{STK}}[j] end; {{STK}}[{}] = res;",
        concat_b, concat_b, concat_c, concat_a
    )));

    let mut idiv = OpcodeBuilder::new(m[38].clone(), cfg, rng);
    let idiv_b = idiv.rk(3); let idiv_c = idiv.rk(4); let idiv_a = idiv.raw_inst(2);
    out.push_str(&idiv.build(&format!("{{STK}}[{}] = math.floor({} / {})", idiv_a, idiv_b, idiv_c)));

    let bit_lib = "local bit = bit32 or bit or {band=function() return 0 end, bor=function() return 0 end, bxor=function() return 0 end, lshift=function() return 0 end, rshift=function() return 0 end, bnot=function() return 0 end}; ";

    let mut band = OpcodeBuilder::new(m[39].clone(), cfg, rng);
    let band_b = band.rk(3); let band_c = band.rk(4); let band_a = band.raw_inst(2);
    out.push_str(&band.build(&format!("{} {{STK}}[{}] = bit.band({}, {})", bit_lib, band_a, band_b, band_c)));

    let mut bor = OpcodeBuilder::new(m[40].clone(), cfg, rng);
    let bor_b = bor.rk(3); let bor_c = bor.rk(4); let bor_a = bor.raw_inst(2);
    out.push_str(&bor.build(&format!("{} {{STK}}[{}] = bit.bor({}, {})", bit_lib, bor_a, bor_b, bor_c)));

    let mut bxor = OpcodeBuilder::new(m[41].clone(), cfg, rng);
    let bxor_b = bxor.rk(3); let bxor_c = bxor.rk(4); let bxor_a = bxor.raw_inst(2);
    out.push_str(&bxor.build(&format!("{} {{STK}}[{}] = bit.bxor({}, {})", bit_lib, bxor_a, bxor_b, bxor_c)));

    let mut shl = OpcodeBuilder::new(m[42].clone(), cfg, rng);
    let shl_b = shl.rk(3); let shl_c = shl.rk(4); let shl_a = shl.raw_inst(2);
    out.push_str(&shl.build(&format!("{} {{STK}}[{}] = (bit.lshift or bit.lsh)({}, {})", bit_lib, shl_a, shl_b, shl_c)));

    let mut shr = OpcodeBuilder::new(m[43].clone(), cfg, rng);
    let shr_b = shr.rk(3); let shr_c = shr.rk(4); let shr_a = shr.raw_inst(2);
    out.push_str(&shr.build(&format!("{} {{STK}}[{}] = (bit.rshift or bit.rsh)({}, {})", bit_lib, shr_a, shr_b, shr_c)));

    let mut bnot = OpcodeBuilder::new(m[44].clone(), cfg, rng);
    let bnot_b = bnot.raw_inst(3); let bnot_a = bnot.raw_inst(2);
    out.push_str(&bnot.build(&format!("{} {{STK}}[{}] = bit.bnot({})", bit_lib, bnot_a, bnot_b)));

    let mut addint = OpcodeBuilder::new(m[58].clone(), cfg, rng);
    let addint_b = addint.rk(3); let addint_c = addint.rk(4); let addint_a = addint.raw_inst(2);
    out.push_str(&addint.build(&format!("{{STK}}[{}] = {} + {}", addint_a, addint_b, addint_c)));

    let mut subint = OpcodeBuilder::new(m[59].clone(), cfg, rng);
    let subint_b = subint.rk(3); let subint_c = subint.rk(4); let subint_a = subint.raw_inst(2);
    out.push_str(&subint.build(&format!("{{STK}}[{}] = {} - {}", subint_a, subint_b, subint_c)));

    let mut mulint = OpcodeBuilder::new(m[60].clone(), cfg, rng);
    let mulint_b = mulint.rk(3); let mulint_c = mulint.rk(4); let mulint_a = mulint.raw_inst(2);
    out.push_str(&mulint.build(&format!("{{STK}}[{}] = {} * {}", mulint_a, mulint_b, mulint_c)));

    let mut divint = OpcodeBuilder::new(m[61].clone(), cfg, rng);
    let divint_b = divint.rk(3); let divint_c = divint.rk(4); let divint_a = divint.raw_inst(2);
    out.push_str(&divint.build(&format!("{{STK}}[{}] = {} / {}", divint_a, divint_b, divint_c)));

    let mut modint = OpcodeBuilder::new(m[62].clone(), cfg, rng);
    let modint_b = modint.rk(3); let modint_c = modint.rk(4); let modint_a = modint.raw_inst(2);
    out.push_str(&modint.build(&format!("{{STK}}[{}] = {} % {}", modint_a, modint_b, modint_c)));

    let mut addeq = OpcodeBuilder::new(m[63].clone(), cfg, rng);
    let addeq_b = addeq.rk(3); let addeq_a = addeq.raw_inst(2);
    out.push_str(&addeq.build(&format!("{{STK}}[{}] = {{STK}}[{}] + {}", addeq_a, addeq_a, addeq_b)));

    let mut subeq = OpcodeBuilder::new(m[64].clone(), cfg, rng);
    let subeq_b = subeq.rk(3); let subeq_a = subeq.raw_inst(2);
    out.push_str(&subeq.build(&format!("{{STK}}[{}] = {{STK}}[{}] - {}", subeq_a, subeq_a, subeq_b)));

    let mut muleq = OpcodeBuilder::new(m[65].clone(), cfg, rng);
    let muleq_b = muleq.rk(3); let muleq_a = muleq.raw_inst(2);
    out.push_str(&muleq.build(&format!("{{STK}}[{}] = {{STK}}[{}] * {}", muleq_a, muleq_a, muleq_b)));

    let mut diveq = OpcodeBuilder::new(m[66].clone(), cfg, rng);
    let diveq_b = diveq.rk(3); let diveq_a = diveq.raw_inst(2);
    out.push_str(&diveq.build(&format!("{{STK}}[{}] = {{STK}}[{}] / {}", diveq_a, diveq_a, diveq_b)));

    let mut modeq = OpcodeBuilder::new(m[67].clone(), cfg, rng);
    let modeq_b = modeq.rk(3); let modeq_a = modeq.raw_inst(2);
    out.push_str(&modeq.build(&format!("{{STK}}[{}] = {{STK}}[{}] % {}", modeq_a, modeq_a, modeq_b)));

    let mut poweq = OpcodeBuilder::new(m[68].clone(), cfg, rng);
    let poweq_b = poweq.rk(3); let poweq_a = poweq.raw_inst(2);
    out.push_str(&poweq.build(&format!("{{STK}}[{}] = {{STK}}[{}] ^ {}", poweq_a, poweq_a, poweq_b)));

    out
}