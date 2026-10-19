//! 跨函数全局交错常量池 + 标识符罗塞塔表（Rosetta Table）
//!
//! 解决 `混淆改进方案.md` 第一条指出的两个核心弱点：
//! 1. **打散聚簇**：取消原先按每个函数（proto）独立聚簇的局部常量池，将所有原型的常量
//!    与诱饵打散到同一个全局槽位空间中交错排列，并将物理排放批次跨全部原型乱序混排；
//!    即使解出全部常量或挂钩单次原型解码，也无法区分哪些常量属于同一个函数。
//! 2. **罗塞塔表（共享字符串表 + 运行时随机化下标）**：
//!    - 所有原型中的字符串常量（含 `FindFirstChildOfClass`、`CanCollide`、`Died` 等全部
//!      干净属性/方法/键名标识符）不再作为原型常量字面量出现；
//!    - 同一原型内对同一字符串的多次引用（如 `FindFirstChildOfClass ×12`）在进入全局池前
//!      拆分为各自独立的常量槽，每个槽分配独立的随机商 $k_{\text{rand}}$ 与槽位掩码，编码为
//!      8 字节 IEEE-754 浮点数 token（线上 tag 与普通数字常量完全一致，常量池中干净标识符字面量降为 0）；
//!    - 真实字符串与从 `所有api.txt` 抽取的 Roblox/执行器 API 诱饵共同洗牌放入共享罗塞塔表，
//!      运行期通过 ChaCha KDF 派生掩码与模素数逆元动态还原共享表下标后惰性解密。

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use rand::{Rng, rngs::StdRng};
use crate::VM::VM_Backend::CustomIsa::{VmOp, VM_OPCODE_COUNT};
use crate::VM::VM_Backend::Generator_chacha::derive_word;
use crate::VM::VM_Backend::Generator_rewrite::{EncCtx, PayloadReader};

const RAW_API_TXT: &str = include_str!("../../../所有api.txt");

const EXTRA_ROBLOX_IDENTIFIERS: &[&str] = &[
    "FindFirstChildOfClass", "FindFirstChildWhichIsA", "WaitForChild", "GetDescendants",
    "GetChildren", "IsA", "Clone", "Destroy", "Connect", "Disconnect", "CanCollide",
    "Transparency", "Anchored", "PlatformStand", "Velocity", "RotVelocity", "CFrame",
    "Position", "Orientation", "AssemblyLinearVelocity", "AssemblyAngularVelocity",
    "WalkSpeed", "JumpPower", "JumpHeight", "HipHeight", "Health", "MaxHealth",
    "AutoRotate", "CameraSubject", "FieldOfView", "Archivable", "Parent", "Character",
    "Humanoid", "HumanoidRootPart", "Animate", "Disabled", "Died", "Heartbeat",
    "RenderStepped", "Stepped", "Kick", "Notify", "Title", "Content", "Icon",
    "Duration", "Callback", "Options", "HttpGet", "HttpPost",
];

const PRIMES: &[u32] = &[
    2003, 2089, 2203, 2309, 2411, 2503, 2609, 2707, 2801, 2903, 3001,
    3109, 3203, 3301, 3407, 3511, 3607, 3701, 3803, 3907, 4001, 4099,
];

#[derive(Clone, Copy, Debug)]
pub struct RosettaParams {
    pub cmac_key: u32,
    pub p_mul: u32,
    pub p_add: u32,
    pub r_prime: u32,
    pub r_kmul: u32,
    pub r_kinv: u32,
    pub r_kadd: u32,
    pub r_smul: u32,
    pub r_rk: usize,
    pub r_gr: u32,
    pub r_w: u32,
    pub ros_offset: u32,
}

#[derive(Clone, Debug)]
pub struct EmitConstEntry {
    pub slot: u32,
    pub c_type: u8,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ProtoConstPlan {
    pub raw_insts: Vec<(u8, u8, u32, u32)>,
    pub cperm: Vec<u32>,
    pub decoy_slots: Vec<u32>,
    pub all_proto_gslots: Vec<u32>,
    pub emit_batch: Vec<EmitConstEntry>,
    pub pb18: u32,
}

#[derive(Clone, Debug)]
pub struct RosettaPlan {
    pub params: RosettaParams,
    pub protos: Vec<ProtoConstPlan>,
}

struct ParsedProto {
    raw_insts: Vec<(u8, u8, u32, u32)>,
    local_consts: Vec<(u8, Vec<u8>)>,
    decoy_consts: Vec<Vec<u8>>,
}

fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut res = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            res = (res * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1;
    }
    res
}

fn harvest_api_decoys() -> Vec<Vec<u8>> {
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut out: Vec<Vec<u8>> = Vec::new();
    for line in RAW_API_TXT.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('=') {
            continue;
        }
        for tok in trimmed.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if tok.len() >= 3
                && tok.as_bytes()[0].is_ascii_alphabetic()
                && seen.insert(tok.as_bytes().to_vec())
            {
                out.push(tok.as_bytes().to_vec());
            }
        }
    }
    for &extra in EXTRA_ROBLOX_IDENTIFIERS {
        if seen.insert(extra.as_bytes().to_vec()) {
            out.push(extra.as_bytes().to_vec());
        }
    }
    out
}

/// `所有api.txt` 抽取出的真实 API/属性名池（进程内只构建一次）。
///
/// 目标五：哑原型、诱饵条目与诱饵偏移都要能用**真实业务字符串**伪装，
/// 不能再出现"一个字符串都没有"这种一眼可辨的垃圾函数特征。
pub(crate) fn api_decoy_pool() -> &'static [Vec<u8>] {
    static POOL: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    POOL.get_or_init(harvest_api_decoys)
}

fn parse_protos_preorder(
    r: &mut PayloadReader,
    inverse_opcode_map: &[u8; VM_OPCODE_COUNT],
    rng: &mut StdRng,
    out: &mut Vec<ParsedProto>,
) {
    let _ = r.read_string();
    let _ = r.read_u32();
    let _ = r.read_u32();
    let _ = r.read_u8();
    let _ = r.read_u8();
    let _ = r.read_u8();
    let _ = r.read_u8();

    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8();
        let a = r.read_u8();
        let b = r.read_u32();
        let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }

    let const_count = r.read_u32();
    let mut local_consts: Vec<(u8, Vec<u8>)> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push((0, Vec::new())),
            1 => {
                let b = r.read_u8();
                local_consts.push((1, vec![b]));
            }
            2 => {
                let n = r.read_u64();
                local_consts.push((2, n.to_le_bytes().to_vec()));
            }
            3 => {
                let s = r.read_string().to_vec();
                local_consts.push((3, s));
            }
            _ => panic!("未知常量类型: {c_type}"),
        }
    }

    // 拆分同一函数内的重复字符串常量引用（消除如 `FindFirstChildOfClass ×12` 的同槽重复指纹）：
    // 每次重复引用追加一个独立常量槽，后续分配各自的全局打散槽位与独立随机罗塞塔 token。
    const BITRK: u32 = 128;
    let orig_const_count = local_consts.len() as u32;
    let mut seen_str_k: HashSet<u32> = HashSet::new();
    let mut splits_added = 0usize;
    for (op, _a, b, _c) in raw_insts.iter_mut() {
        let canonical = inverse_opcode_map[*op as usize];
        let vop = VmOp::from_global(canonical)
            .unwrap_or_else(|| panic!("非自定义 opcode 落入 VM 载荷：{canonical}"));
        if vop.has_constant_b() && *b < orig_const_count {
            let k = *b as usize;
            if local_consts[k].0 == 3 && !seen_str_k.insert(*b) && splits_added < 96 {
                let cloned = local_consts[k].clone();
                let new_k = local_consts.len() as u32;
                local_consts.push(cloned);
                *b = new_k;
                splits_added += 1;
            }
        } else if vop.has_rk_b() && *b >= BITRK && (*b - BITRK) < orig_const_count {
            let k_u32 = *b - BITRK;
            let k = k_u32 as usize;
            if local_consts[k].0 == 3 && !seen_str_k.insert(k_u32) && splits_added < 96 {
                let cloned = local_consts[k].clone();
                let new_k = local_consts.len() as u32;
                local_consts.push(cloned);
                *b = BITRK + new_k;
                splits_added += 1;
            }
        }
    }

    let eff_const_count = local_consts.len() as u32;
    let decoy_min = if eff_const_count < 4 { 3 } else { 1 };
    let decoy_max = (eff_const_count as usize + 3).clamp(decoy_min, 8);
    let decoy_count = rng.random_range(decoy_min..=decoy_max);
    let decoy_consts: Vec<Vec<u8>> = (0..decoy_count)
        .map(|_| {
            let whole = rng.random_range(10_000u64..=9_999_999u64) as f64;
            let frac = rng.random_range(0u64..=99_999u64) as f64 / 100_000.0;
            (whole + frac).to_le_bytes().to_vec()
        })
        .collect();

    out.push(ParsedProto {
        raw_insts,
        local_consts,
        decoy_consts,
    });

    let p_count = r.read_u32();
    for _ in 0..p_count {
        parse_protos_preorder(r, inverse_opcode_map, rng, out);
    }

    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count {
        let _ = r.read_string();
        let _ = r.read_u32();
        let _ = r.read_u32();
    }
    let upv_count = r.read_u32();
    for _ in 0..upv_count {
        let _ = r.read_string();
    }
}

impl RosettaPlan {
    pub fn build(
        data: &[u8],
        inverse_opcode_map: &[u8; VM_OPCODE_COUNT],
        enc: &EncCtx,
        rng: &mut StdRng,
    ) -> Self {
        let mut reader = PayloadReader { data, pos: 0 };
        let mut parsed: Vec<ParsedProto> = Vec::new();
        parse_protos_preorder(&mut reader, inverse_opcode_map, rng, &mut parsed);

        // 1. 收集所有原型的字符串并混入 `所有api.txt` 的真实 API/属性诱饵，构建共享罗塞塔表
        let mut str_set: HashSet<Vec<u8>> = HashSet::new();
        let mut rosetta_strings: Vec<Vec<u8>> = Vec::new();
        let mut total_str_refs = 0usize;
        let mut total_other_refs = 0usize;

        for p in &parsed {
            for (ct, bytes) in &p.local_consts {
                if *ct == 3 {
                    total_str_refs += 1;
                    if str_set.insert(bytes.clone()) {
                        rosetta_strings.push(bytes.clone());
                    }
                } else {
                    total_other_refs += 1;
                }
            }
            total_other_refs += p.decoy_consts.len();
        }

        let mut api_candidates: Vec<Vec<u8>> = harvest_api_decoys()
            .into_iter()
            .filter(|s| !str_set.contains(s))
            .collect();
        for i in (1..api_candidates.len()).rev() {
            let j = rng.random_range(0..=i);
            api_candidates.swap(i, j);
        }
        let decoy_api_cnt = rng.random_range(36usize..=56usize).min(api_candidates.len());
        for s in api_candidates.into_iter().take(decoy_api_cnt) {
            str_set.insert(s.clone());
            rosetta_strings.push(s);
        }

        // Fisher-Yates 全局洗牌共享罗塞塔表
        for i in (1..rosetta_strings.len()).rev() {
            let j = rng.random_range(0..=i);
            rosetta_strings.swap(i, j);
        }
        let mut str_to_ridx: HashMap<Vec<u8>, u32> = HashMap::with_capacity(rosetta_strings.len());
        for (idx, s) in rosetta_strings.iter().enumerate() {
            str_to_ridx.insert(s.clone(), idx as u32);
        }

        // 2. 生成罗塞塔运行时随机化下标参数与全局奇偶槽位划分
        let min_p = (rosetta_strings.len() as u32 + 128).max(2003);
        let eligible_primes: Vec<u32> = PRIMES.iter().copied().filter(|&p| p > min_p).collect();
        let r_prime = if eligible_primes.is_empty() {
            4099
        } else {
            eligible_primes[rng.random_range(0..eligible_primes.len())]
        };
        let r_kmul = rng.random_range(3u32..r_prime);
        let r_kinv = mod_pow(r_kmul as u64, (r_prime - 2) as u64, r_prime as u64) as u32;
        debug_assert_eq!((r_kmul as u64 * r_kinv as u64) % (r_prime as u64), 1);
        let r_kadd = rng.random_range(1u32..r_prime);
        let r_smul = (rng.random_range(0x101u32..0x1FFFu32) * 2) + 1;
        let r_rk = rng.random_range(0..8usize);
        let r_gr = rng.random_range(0x0400u32..0xFFFFu32);
        let r_w = rng.random_range(0x20u32..0x200u32);
        let r_kbase = derive_word(enc.root[r_rk], r_gr, r_w);

        let p_mul = (rng.random_range(0x101u32..0x1FFFu32) * 2) + 1;
        let p_add = rng.random_range(1u32..0x1FFFu32);
        let cmac_key = rng.random_range(0x10_0000u32..0x7FFF_0000u32);

        let half_cap = (total_str_refs.max(total_other_refs) + 8) as u32;
        let ros_offset = half_cap * 2;
        let mut odd_slots: Vec<u32> = Vec::with_capacity(half_cap as usize);
        let mut even_slots: Vec<u32> = Vec::with_capacity(half_cap as usize);
        for s in 0..ros_offset {
            if ((s * p_mul + p_add) & 1) == 1 {
                odd_slots.push(s);
            } else {
                even_slots.push(s);
            }
        }
        for i in (1..odd_slots.len()).rev() {
            let j = rng.random_range(0..=i);
            odd_slots.swap(i, j);
        }
        for i in (1..even_slots.len()).rev() {
            let j = rng.random_range(0..=i);
            even_slots.swap(i, j);
        }

        // 3. 为每个原型分配跨函数全局打散的槽位，并将字符串引用替换为 8B 浮点罗塞塔 token
        let mut odd_cursor = 0usize;
        let mut even_cursor = 0usize;
        let mut all_emit_entries: Vec<EmitConstEntry> =
            Vec::with_capacity(total_str_refs + total_other_refs + rosetta_strings.len());
        let mut proto_plans: Vec<ProtoConstPlan> = Vec::with_capacity(parsed.len());

        for p in parsed {
            let mut cperm: Vec<u32> = Vec::with_capacity(p.local_consts.len());
            let mut decoy_slots: Vec<u32> = Vec::with_capacity(p.decoy_consts.len());
            let mut all_proto_gslots: Vec<u32> =
                Vec::with_capacity(p.local_consts.len() + p.decoy_consts.len());

            for (ct, bytes) in p.local_consts {
                if ct == 3 {
                    let g_slot = odd_slots[odd_cursor];
                    odd_cursor += 1;
                    let r_idx = *str_to_ridx.get(&bytes).expect("罗塞塔表必须包含全部源字符串");
                    let rem = (r_idx * r_kmul + r_kadd) % r_prime;
                    let k_rand = rng.random_range(64u32..8192u32);
                    let q = rem + k_rand * r_prime;
                    let slot_mask = r_kbase ^ g_slot.wrapping_mul(r_smul);
                    let token: u32 = q ^ slot_mask;
                    let f64_bytes = (token as f64).to_le_bytes().to_vec();
                    cperm.push(g_slot);
                    all_proto_gslots.push(g_slot);
                    all_emit_entries.push(EmitConstEntry {
                        slot: g_slot,
                        c_type: 2,
                        bytes: f64_bytes,
                    });
                } else {
                    let g_slot = even_slots[even_cursor];
                    even_cursor += 1;
                    cperm.push(g_slot);
                    all_proto_gslots.push(g_slot);
                    all_emit_entries.push(EmitConstEntry {
                        slot: g_slot,
                        c_type: ct,
                        bytes,
                    });
                }
            }

            for decoy_bytes in p.decoy_consts {
                let g_slot = even_slots[even_cursor];
                even_cursor += 1;
                decoy_slots.push(g_slot);
                all_proto_gslots.push(g_slot);
                all_emit_entries.push(EmitConstEntry {
                    slot: g_slot,
                    c_type: 2,
                    bytes: decoy_bytes,
                });
            }

            proto_plans.push(ProtoConstPlan {
                raw_insts: p.raw_insts,
                cperm,
                decoy_slots,
                all_proto_gslots,
                emit_batch: Vec::new(),
                pb18: 0,
            });
        }

        // 为全部原型分配非单调乱序且带随机偏移的全局指令基址 pb18（kP）：
        // 打乱分配顺序，使先序遍历下 kP 不再单调递增，且根原型不再位于最低基址。
        let mut alloc_order: Vec<usize> = (0..proto_plans.len()).collect();
        if alloc_order.len() >= 2 {
            for i in (1..alloc_order.len()).rev() {
                let j = rng.random_range(0..=i);
                alloc_order.swap(i, j);
            }
            if alloc_order[0] == 0 {
                let mid = alloc_order.len() / 2;
                alloc_order.swap(0, mid);
            }
        }
        let mut pb18_cursor: u32 = rng.random_range(0x1200u32..0x4800u32);
        for &p_idx in &alloc_order {
            pb18_cursor += rng.random_range(64u32..256u32);
            proto_plans[p_idx].pb18 = pb18_cursor;
            let span = (proto_plans[p_idx].raw_insts.len() as u32)
                + 64
                + rng.random_range(32u32..192u32);
            pb18_cursor += span;
        }

        // 将共享罗塞塔表的底层字符串条目（c_type = 3）一并混入全局排放池
        for (r_idx, str_bytes) in rosetta_strings.into_iter().enumerate() {
            all_emit_entries.push(EmitConstEntry {
                slot: ros_offset + (r_idx as u32),
                c_type: 3,
                bytes: str_bytes,
            });
        }

        // 4. 将全部常量与罗塞塔底层串做全局洗牌，再交错切分到各原型的物理排放批次中
        for i in (1..all_emit_entries.len()).rev() {
            let j = rng.random_range(0..=i);
            all_emit_entries.swap(i, j);
        }

        let n_protos = proto_plans.len();
        if n_protos == 1 {
            proto_plans[0].emit_batch = all_emit_entries;
        } else if n_protos > 1 {
            let total_entries = all_emit_entries.len();
            let weights: Vec<usize> = proto_plans
                .iter()
                .map(|p| p.all_proto_gslots.len().max(3))
                .collect();
            let weight_sum: usize = weights.iter().sum();
            let mut counts: Vec<usize> = vec![1; n_protos];
            let rem_entries = total_entries.saturating_sub(n_protos);
            let mut allocated = n_protos;
            for i in 0..n_protos.saturating_sub(1) {
                let share = (rem_entries * weights[i]) / weight_sum.max(1);
                counts[i] += share;
                allocated += share;
            }
            if total_entries >= allocated {
                counts[n_protos - 1] += total_entries - allocated;
            }
            let mut iter = all_emit_entries.into_iter();
            for (i, plan) in proto_plans.iter_mut().enumerate() {
                plan.emit_batch = iter.by_ref().take(counts[i]).collect();
            }
            for leftover in iter {
                proto_plans[n_protos - 1].emit_batch.push(leftover);
            }
        }

        Self {
            params: RosettaParams {
                cmac_key,
                p_mul,
                p_add,
                r_prime,
                r_kmul,
                r_kinv,
                r_kadd,
                r_smul,
                r_rk,
                r_gr,
                r_w,
                ros_offset,
            },
            protos: proto_plans,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use crate::BytecodeCompiler::virtualizer::deserializer::Deserializer;
    use crate::VM::VM_Backend::Context::VmContext;
    use crate::VM::VM_Backend::Generator_util::GenRng;
    use crate::VM::VM_Backend::Serializer::Serializer;
    use crate::compiler::{codegen, dump};

    #[test]
    fn rosetta_scatters_clusters_splits_duplicates_and_eliminates_proto_string_literals() {
        let src = r#"
            local function f1(x)
                local a = x:FindFirstChildOfClass("Humanoid")
                local b = x:FindFirstChildOfClass("Humanoid")
                local c = x:FindFirstChildOfClass("Humanoid")
                return a, b, c, x.CanCollide, x.Transparency, 42
            end
            local function f2(y)
                return y.Anchored, y.Velocity, y:Kick("bye"), 99
            end
            return f1, f2
        "#;
        let proto = codegen::compile(src.as_bytes(), "@test").expect("compile ok");
        let bytes = dump::dump(&proto, true);
        let chunk = Deserializer::new(bytes).decode_file();
        let ctx = VmContext::new();
        let payload = Serializer::serialize(&chunk, &ctx);
        let mut inv = [0u8; VM_OPCODE_COUNT];
        for (orig, &shuffled) in ctx.opcode_map.iter().enumerate() {
            inv[shuffled as usize] = orig as u8;
        }
        let mut grng = GenRng::new(12345);
        let enc = EncCtx::new(&mut grng, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let mut rrng = StdRng::seed_from_u64(67890);
        let plan = RosettaPlan::build(&payload, &inv, &enc, &mut rrng);

        assert!(plan.protos.len() >= 5, "root and child protos should include dummy protos");
        let p = plan.params;
        let r_kbase = derive_word(enc.root[p.r_rk], p.r_gr, p.r_w);

        // 收集所有物理排放批次中的常量记录
        let mut by_slot: HashMap<u32, EmitConstEntry> = HashMap::new();
        for pr in &plan.protos {
            assert!(!pr.emit_batch.is_empty());
            for e in &pr.emit_batch {
                assert!(by_slot.insert(e.slot, e.clone()).is_none(), "duplicate global slot");
            }
        }

        // 1) 在 0..ros_offset 的全部原型常量槽中，c_type == 3 的明文字符串数量必须为 0；
        //    所有奇数仿射奇偶槽均为 8B 浮点数 token (c_type == 2)，且可精确反解回罗塞塔表字符串。
        let mut odd_tokens: Vec<u32> = Vec::new();
        for (&slot, entry) in &by_slot {
            if slot < p.ros_offset {
                assert_ne!(entry.c_type, 3, "proto constant slot must not hold raw string");
                let parity = (slot.wrapping_mul(p.p_mul).wrapping_add(p.p_add)) & 1;
                if parity == 1 {
                    assert_eq!(entry.c_type, 2);
                    let f = f64::from_le_bytes(entry.bytes[0..8].try_into().unwrap());
                    let vn = f as u32;
                    odd_tokens.push(vn);
                    let vq = vn ^ r_kbase ^ slot.wrapping_mul(p.r_smul);
                    let rem = (vq as u64) % (p.r_prime as u64);
                    let r_idx = (((rem + p.r_prime as u64 - p.r_kadd as u64) * (p.r_kinv as u64))
                        % (p.r_prime as u64)) as u32;
                    let vr = p.ros_offset + r_idx;
                    let ros_entry = by_slot.get(&vr).expect("rosetta slot exists");
                    assert_eq!(ros_entry.c_type, 3);
                    assert!(!ros_entry.bytes.is_empty());
                }
            } else {
                assert_eq!(entry.c_type, 3);
            }
        }
        // f1 中 3 次 FindFirstChildOfClass("Humanoid") 已拆分为不同全局槽与互异随机 token
        assert!(
            plan.protos.iter().any(|pr| pr.cperm.len() >= 9),
            "duplicate string refs in f1 should be split"
        );
        let unique_tokens: HashSet<u32> = odd_tokens.iter().copied().collect();
        assert_eq!(unique_tokens.len(), odd_tokens.len(), "each string ref slot has a unique token");
    }

    #[test]
    fn proto_metadata_noise_non_monotonic_kp_and_dummy_closures_break_call_closure_equality() {
        // 构造一个原本 CLOSURE 次数与 CALL 次数完全相等（各 6 次）的脚本，
        // 同时包含固定形参 + 变参混用函数 `function(a, b, ...)`
        let src = r#"
            local r1 = (function(a, b) return a + b end)(10, 20)
            local r2 = (function(x, y, ...) local p, q = ...; return x + y + (p or 0) + (q or 0) end)(1, 2, 3, 4)
            local r3 = (function(m) return m * 2 end)(7)
            local r4 = (function(k) return k - 3 end)(15)
            local r5 = (function(u, v, w) return u * v + w end)(2, 3, 4)
            local r6 = (function(...) local a, b = ...; return (a or 0) - (b or 0) end)(50, 8)
            return r1 + r2 + r3 + r4 + r5 + r6
        "#;
        let proto = codegen::compile(src.as_bytes(), "@meta").expect("compile ok");
        let bytes = dump::dump(&proto, true);
        let chunk = Deserializer::new(bytes).decode_file();
        assert_eq!(chunk.protos.len(), 6, "original root has 6 child closures");

        let ctx = VmContext::new();
        let payload = Serializer::serialize(&chunk, &ctx);
        let mut inv = [0u8; VM_OPCODE_COUNT];
        for (orig, &shuffled) in ctx.opcode_map.iter().enumerate() {
            inv[shuffled as usize] = orig as u8;
        }
        let mut grng = GenRng::new(54321);
        let enc = EncCtx::new(&mut grng, [0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98]);
        let mut rrng = StdRng::seed_from_u64(98765);
        let plan = RosettaPlan::build(&payload, &inv, &enc, &mut rrng);

        // 1. nChild 填假值：总原型数远大于原始 1 + 6 = 7
        assert!(plan.protos.len() >= 10, "dummy child protos must inflate proto count");

        // 2. kP (pb18) 随机偏移 + 非单调顺序 + 段间严格不重叠
        let pbs: Vec<u32> = plan.protos.iter().map(|p| p.pb18).collect();
        assert!(pbs.iter().all(|&pb| pb >= 0x1200), "all kP (pb18) must include random base offset");
        let min_pb = *pbs.iter().min().unwrap();
        assert_ne!(pbs[0], min_pb, "root proto0 must not sit at the minimum kP");
        let is_monotonic = pbs.windows(2).all(|w| w[0] < w[1]);
        assert!(!is_monotonic, "kP sequence across protos must not be monotonic");

        let mut segments: Vec<(u32, u32)> = plan
            .protos
            .iter()
            .map(|p| (p.pb18, p.pb18 + (p.raw_insts.len() as u32) + 48))
            .collect();
        segments.sort_unstable_by_key(|s| s.0);
        for w in segments.windows(2) {
            assert!(w[0].1 < w[1].0, "proto instruction segments must be strictly disjoint");
        }

        // 3. 根原型 proto0 中 CLOSURE (MakeClosure) 次数严格大于 CALL (CallExecute) 与 SCATTER (CallCollect)
        let root_insts = &plan.protos[0].raw_insts;
        let mut cnt_closure = 0usize;
        let mut cnt_call_exec = 0usize;
        let mut cnt_call_collect = 0usize;
        for &(op, _, _, _) in root_insts {
            let vop = VmOp::from_global(inv[op as usize]).unwrap();
            match vop {
                VmOp::MakeClosure => cnt_closure += 1,
                VmOp::CallExecute => cnt_call_exec += 1,
                VmOp::CallCollect => cnt_call_collect += 1,
                _ => {}
            }
        }
        assert_eq!(cnt_call_exec, 6);
        assert_eq!(cnt_call_collect, 6);
        assert!(
            cnt_closure > cnt_call_exec,
            "dummy closures without CALL must break CLOSURE == CALL == SCATTER (got closure={cnt_closure}, call={cnt_call_exec})"
        );
    }
}
