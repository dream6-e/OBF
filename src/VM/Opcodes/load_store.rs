use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};

pub fn generate(m: &[Vec<u32>], cfg: &OpcodeConfig, rng: &mut OpcodesRng) -> String {
    let mut out = String::new();

    let mut mv = OpcodeBuilder::new(m[0].clone(), cfg, rng);
    let mv_b = mv.raw_inst(3);
    let mv_a = mv.raw_inst(2);
    out.push_str(&mv.build(&format!("{{STK}}[{}] = {{STK}}[{}]", mv_a, mv_b)));

    let mut loadk = OpcodeBuilder::new(m[1].clone(), cfg, rng);
    let lk_b = loadk.raw_inst(3);
    let lk_a = loadk.raw_inst(2);
    out.push_str(&loadk.build(&format!("{{STK}}[{}] = {{CONSTS}}[{}+1]", lk_a, lk_b)));

    let mut loadbool = OpcodeBuilder::new(m[2].clone(), cfg, rng);
    let lb_b = loadbool.raw_inst(3);
    let lb_c = loadbool.raw_inst(4);
    let lb_a = loadbool.raw_inst(2);
    out.push_str(&loadbool.build(&format!(
        "{{STK}}[{}] = ({} ~= 0); if {} ~= 0 then {{PC}} = {{PC}} + 1 end",
        lb_a, lb_b, lb_c
    )));

    let mut loadnil = OpcodeBuilder::new(m[3].clone(), cfg, rng);
    let ln_b = loadnil.raw_inst(3);
    let ln_a = loadnil.raw_inst(2);
    out.push_str(&loadnil.build(&format!("for j = {}, {} + {} do {{STK}}[j] = nil end", ln_a, ln_a, ln_b)));

    let mut loadkx = OpcodeBuilder::new(m[45].clone(), cfg, rng);
    let lkx_a = loadkx.raw_inst(2);
    out.push_str(&loadkx.build(&format!(
        "{{STK}}[{}] = {{CONSTS}}[{{INSTS}}[{{PC}}][2] + 1]; {{PC}} = {{PC}} + 1",
        lkx_a
    )));

    let mut extraarg = OpcodeBuilder::new(m[46].clone(), cfg, rng);
    out.push_str(&extraarg.build(""));

    let mut mv1 = OpcodeBuilder::new(m[88].clone(), cfg, rng);
    let mv1_b = mv1.raw_inst(3);
    let mv1_a = mv1.raw_inst(2);
    out.push_str(&mv1.build(&format!("{{STK}}[{}] = {{STK}}[{}]", mv1_a, mv1_b)));

    let mut mv2 = OpcodeBuilder::new(m[89].clone(), cfg, rng);
    let mv2_b = mv2.raw_inst(3);
    let mv2_a = mv2.raw_inst(2);
    out.push_str(&mv2.build(&format!(
        "local mv2_t1, mv2_t2 = {{STK}}[{}], {{STK}}[{}+1]; {{STK}}[{}] = mv2_t1; {{STK}}[{}+1] = mv2_t2",
        mv2_b, mv2_b, mv2_a, mv2_a
    )));

    out
}