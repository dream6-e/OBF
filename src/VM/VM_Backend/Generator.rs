use crate::VM::VM_Backend::Context::VmContext;
use crate::VM::VM_Backend::Lua_core;
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use std::collections::HashSet;
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;
use super::AntiTamper;
use super::CustomIsa::{CUSTOM_OPCODE_BASE, VM_OPCODE_COUNT};
use super::Generator_chain;
pub(crate) static DBG_MASK: bool = true;
pub(crate) static DBG_PROXY: bool = true;
pub(crate) static DBG_ARITH: bool = true;

// 底层工具层已拆到 Generator_util.rs（原文件 69 KB 太大）。
// GenRng 继续从这里 re-export，保持 crate 内既有的引用路径不变。
pub use super::Generator_util::{CipherKeys, GenRng};
use super::Generator_util::{
    rename_ident, rewrite_chunk, scan_used_opcodes, uses_ident, write_string, PayloadReader,
};
use super::Generator_integrity::{cold_state_check, emit_state_digest};


pub struct Generator { ctx: VmContext }

/// ㉛ 载荷白化层的专用派生组号/字序号（不与四组常量簇冲突）。
pub(super) const WHITEN_GROUP: usize = 0x5A;
pub(super) const WHITEN_WORD: u32 = 7;
/// ㉛ 项目自定义的位置白化掩码：双残数态交替耦合，seed、绝对位置及
/// 两个逐构建参数都参与每轮；Rust/Lua 中间整数均低于 2^50，可精确表示。
pub(super) fn whiten_byte(seed: u64, pos: u64, mul: u64, add: u64) -> u8 {
    const MOD: u64 = 2_147_483_647;
    let p = pos % MOD;
    let s = seed % MOD;
    let wm = mul % 65_536;
    let wa = add % 65_536;
    let mut a = (s + p * wm + (add % MOD)) % MOD;
    let mut b = (s * 257 + p * wa + wm * 17) % MOD;
    for _ in 0..3 {
        let x = (a * ((b % 65_536) + wm + 257)
            + b * 257 + p * (17 + add % 31) + s) % MOD;
        let y = (b * ((x % 65_536) + wa + 263)
            + x * 129 + p * (23 + mul % 29) + add) % MOD;
        a = x;
        b = y;
    }
    ((a % 256 + (b % 256) * 3 + (p % 256) * 5
        + (a / 256) % 256 + (b / 256) % 256) % 256) as u8
}

/// 整段载荷的滚动可逆变换参数。更新态会同时吸收白化字节和密文字节。
#[derive(Clone, Copy, Debug)]
pub(super) struct RollParams {
    pub add: u8,
    pub rot_in: u32,
    pub add_k1: u8,
    pub mul_k2: u8,
    pub rot_k2: u32,
    pub rot_k4: u32,
}

fn roll_update(state: &mut [u8; 4], pos: u64, plain: u8, cipher: u8, p: RollParams) {
    let [k1, k2, k3, k4] = *state;
    let at = pos as u8;
    let n1 = k1.wrapping_add(plain).wrapping_add(k4).wrapping_add(at)
        .rotate_left(p.rot_in) ^ cipher;
    let n2 = k2.wrapping_mul(p.mul_k2).wrapping_add(cipher)
        .wrapping_add(plain ^ n1).rotate_right(p.rot_k2);
    let n3 = k3.wrapping_add(plain).wrapping_add(cipher).wrapping_add(n2)
        .wrapping_add(p.add_k1).rotate_left(p.rot_in) ^ k4;
    let n4 = k4.wrapping_add(cipher).wrapping_add(plain).wrapping_add(n1)
        .wrapping_add(n3).wrapping_add(p.add_k1).rotate_right(p.rot_k4);
    *state = [n1, n2, n3, n4];
}

/// 把白化后的 payload 字节滚动变换成密文（绝对 1-based 位置）。
pub(super) fn roll_encrypt_byte(state: &mut [u8; 4], pos: u64, plain: u8, p: RollParams) -> u8 {
    let [k1, k2, k3, k4] = *state;
    let at = pos as u8;
    let bias = k1.wrapping_add(k2).wrapping_add(at.wrapping_mul(p.add));
    let mixed = plain.wrapping_add(bias) ^ k3;
    let cipher = mixed.rotate_left(p.rot_in).wrapping_add(k4)
        .wrapping_add(at.wrapping_mul(p.add_k1));
    roll_update(state, pos, plain, cipher, p);
    cipher
}

/// 逆变换；状态更新与写端同式，便于分段/惰性读取时续接。
pub(super) fn roll_decrypt_byte(state: &mut [u8; 4], pos: u64, cipher: u8, p: RollParams) -> u8 {
    let [k1, k2, k3, k4] = *state;
    let at = pos as u8;
    let mixed = cipher.wrapping_sub(k4).wrapping_sub(at.wrapping_mul(p.add_k1))
        .rotate_right(p.rot_in) ^ k3;
    let plain = mixed.wrapping_sub(k1).wrapping_sub(k2)
        .wrapping_sub(at.wrapping_mul(p.add));
    roll_update(state, pos, plain, cipher, p);
    plain
}

impl Generator {
    pub fn new(ctx: VmContext) -> Self { Self { ctx } }

    pub fn build(&self, payload: &[u8]) -> String {
        let mut rng = GenRng::new(self.ctx.seed);
        let var_l = rng.name();

        // 载荷里 Proto 表的字段名、zm(...) 变参表的计数字段名、open_ups 表名
        // 全部逐产物随机化。它们原先以明文出现在产物里（n / ld / lld / nups /
        // numparams / consts / protos / open_ups ...）。压缩器只重命名长度 > 4
        // 的成员名，短名会一路留到产物里，所以在生成端就先换掉。
        let pf_n = rng.name();
        let pf_ld = rng.name();
        let pf_lld = rng.name();
        let pf_nups = rng.name();
        let pf_numparams = rng.name();
        let pf_is_vararg = rng.name();
        let pf_maxstack = rng.name();
        let pf_opcodes = rng.name();
        let pf_cnt18 = rng.name(); // ⑱.3 指令条数（槽偏移后 # 不可靠，扫描用）
        let pf_a_arr = rng.name();
        let pf_b_arr = rng.name();
        let pf_c_arr = rng.name();
        let pf_consts = rng.name();
        let pf_protos = rng.name();
        let pf_open_ups = rng.name();
        let pf_vn = rng.name();
        let pf_builtin_view = rng.name();
        let pf_builtin_mask = rng.name();
        
        let key_seed_var = rng.name();
        // ㉛ 载荷白化层状态名（KDF 耦合的整段掩码；声明在解头，赋值在根派生之后）
        let var_whiten = rng.name();
        let var_whiten_pos = rng.name();
        // ㉒② 焊接缓存：三张缓存表随产物生成，供第二/三阶段各站点发射焊接构造。
        let mut weld = crate::VM::VM_Backend::Generator_kdf::WeldCache::new(&mut rng);
        // ㉓ 统一流：packer 脚本串/探测九件套/守卫散点串共用的一条密钥流（惰性解密）。
        let mut uni = crate::VM::VM_Backend::Generator_util::UniStream::new(&mut rng);
        
        let mut used_ops = HashSet::new();
        { let mut scan_reader = PayloadReader { data: payload, pos: 0 }; scan_used_opcodes(&mut scan_reader, &mut used_ops); }

        let mut inverse_opcode_map = [0u8; VM_OPCODE_COUNT];
        for i in 0..VM_OPCODE_COUNT { inverse_opcode_map[self.ctx.opcode_map[i] as usize] = i as u8; }

        let mut mapped_opcodes: [Vec<u32>; Opcodes::builtins::TOTAL_OPCODES] = std::array::from_fn(|_| Vec::new());
        let mut fused_opcodes: [Vec<u32>; Opcodes::builtins::FUSED_OP_COUNT] = std::array::from_fn(|_| Vec::new());
        let mut transpile_map: [Vec<u32>; VM_OPCODE_COUNT] = std::array::from_fn(|_| Vec::new());
        {
            let mut map_rng = StdRng::seed_from_u64(self.ctx.seed);
            let mut used = std::collections::HashSet::new();
            for i in 0..VM_OPCODE_COUNT {
                let shuffled_val = self.ctx.opcode_map[i];
                // 不再发射旧 Lua opcode handler；自定义指令每种至少保留一个别名，
                // 以覆盖不可达尾段中的 PushRk/Drop/Noop 诱饵处理器。
                let count = if used_ops.contains(&shuffled_val) {
                    map_rng.random_range(3..=6)
                } else if i >= CUSTOM_OPCODE_BASE {
                    1
                } else {
                    0
                };
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); transpile_map[shuffled_val as usize].push(val); break; }
                    }
                }
            }
            for i in VM_OPCODE_COUNT..Opcodes::builtins::TOTAL_OPCODES {
                let count = map_rng.random_range(3..=6);
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); break; }
                    }
                }
            }
            // 融合指令按 slot 分配别名。性能型超级指令只用一个别名，避免为了少量
            // 新 handler 显著扩张每条指令都要走的 opcode 派发树。
            for i in 0..Opcodes::builtins::FUSED_OP_COUNT {
                let count = if i >= Opcodes::builtins::FUSED_SUPER_BASE {
                    1
                } else {
                    map_rng.random_range(3..=6)
                };
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { fused_opcodes[i].push(val); break; }
                    }
                }
            }
        }

        let mut rewritten_chunks = Vec::new();
        let mut reader = PayloadReader { data: payload, pos: 0 };
        let mut rewrite_rng = StdRng::seed_from_u64(self.ctx.seed + 1);
        let mut fused_used: HashSet<usize> = HashSet::new();
        // ⑰ 常量按原型分组内联加密：每组独立 key/salt/nonce 布局/kind；
        // 密文直接写进各原型常量节，中央 gs/gn 密文表废除
        const CG: usize = crate::VM::VM_Backend::Generator_util::CONST_GROUPS;
        // 第 3 项 D：**单根派生**——另起一条原生流（Native Stream）取 32 字节密钥流
        // 折成 K0（8 字），四组密钥/盐/kind 全部由 K0 经 KDF 现算：
        // 产物里不再有「一组 8 个密钥字」的独立材料，只剩这一份 token 化的根，
        // 而推导过程在运行期才发生（静态读者要先复刻 Lua 的异或表/旋转语义）。
        let nat_k0 = crate::VM::VM_Backend::Generator_native::LegacyRootNative::new(&mut rng);
        let k0_seeds: Vec<u8> = (0..16).map(|_| rng.range(0, 256) as u8).collect();
        let k0 = crate::VM::VM_Backend::Generator_chacha::native_root(&nat_k0, &k0_seeds);
        let mut chacha_keys: Vec<[u32; 8]> = Vec::with_capacity(CG);
        let mut chacha_salts: Vec<u32> = Vec::with_capacity(CG);
        let mut kstr: Vec<u32> = Vec::with_capacity(CG);
        let mut knum: Vec<u32> = Vec::with_capacity(CG);
        for g in 0..CG as u32 {
            let gk = crate::VM::VM_Backend::Generator_chacha::group_keys(&k0, g);
            chacha_keys.push(gk.key);
            chacha_salts.push(gk.salt);
            kstr.push(gk.kstr);
            knum.push(gk.knum);
        }
        let mut nonce_layouts: Vec<[usize; 3]> = Vec::with_capacity(CG);
        for _ in 0..CG {
            let mut ly = [0usize, 1, 2];
            for j in (1..3).rev() { let k = rng.range(0, j + 1); ly.swap(j, k); }
            nonce_layouts.push(ly);
        }
        // 第 2 项：逐簇 ChaCha 状态布局（全状态置换 / 轮数 8·10·12 / counter 步进）
        let chacha_layout: Vec<crate::VM::VM_Backend::Generator_chacha::ChaChaLayout> =
            (0..CG).map(|_| crate::VM::VM_Backend::Generator_chacha::ChaChaLayout::new(&mut rng)).collect();
        let enc = crate::VM::VM_Backend::Generator_util::EncCtx { keys: chacha_keys.clone(), salts: chacha_salts.clone(), layouts: nonce_layouts.clone(), kstr, knum, layout: chacha_layout, root: k0 };
        let root_group = rng.range(0, CG);
        // ⑮ 指令格式改版：线上 op 字段不再是 8 万段别名，而是逐别名随机 32 位魔数；
        // 派发树在魔数空间二分（阈值=魔数），与操作类别的数值区间彻底解耦
        let mut op_magic: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        {
            let mut keys_v: Vec<u32> = Vec::new();
            for lst in transpile_map.iter().chain(mapped_opcodes.iter()).chain(fused_opcodes.iter()) { keys_v.extend(lst.iter().copied()); }
            for v in 0..=95u32 { keys_v.push(v); }
            let bob = crate::VM::Opcodes::builtins::BUILTIN_OP_BASE as u32;
            for v in bob..bob + 256u32 { keys_v.push(v); }
            for v in keys_v {
                if op_magic.contains_key(&v) { continue; }
                let m = loop { let x = rng.range(0x0100_0000, 0x7FFF_0000) as u32; if !op_magic.values().any(|&y| y == x) { break x; } };
                op_magic.insert(v, m);
            }
        }
        // ① B/C 场掩码参数：逐产物随机（掩码=值^(mag^ki)^k，mag 链接逐条变化）
        let bc_kb = rng.next(); let bc_kc = rng.next();
        let bc_ki1 = rng.next(); let bc_ki2 = rng.next();
        // ㉚ 指令链式编码：每条指令的四个线上字段叠加「由前一条解码输出推进」的
        // 链偏移（op 偶偏移 EO、A 加偏移 CA、B/C 异或掩码 CB/CC）——单条公式不再
        // 能解全部指令，只能从链种子顺序模拟。种子=(kp18^pb18)*ch_m+ch_k0（每原型
        // 线上槽位推导，写/读两侧同式）。DELTA（偶）全局折进 op 域+派发树常数，
        // 直方图/跨样本统计锚点消失。三参数同时下发扫描读侧与 execute 解码器。
        let (chain_delta, chain_m, chain_k0): (u32, u64, u64) = if std::env::var("OBF_NOCHAIN").is_ok() {
            (0, 0, 0)
        } else {
            (((rng.range(0x10_0000, 0x1FFF_FFFF) as u32) & !1) | 2,
             (rng.range(0x8001, 0xFFFF) as u64) | 1,
             rng.range(0x1000, 0xFFFF_FFFF) as u64)
        };
        // #3 折叠参数：谓词 pv(v)=(rotl32(v,r)^p1)%100<p3、f(pc)=(pc*f1)^f2 —— 逐产物随机，
        // Rust 写侧与 Lua body_consts 扫描两侧同式（静态读产物得不出「哪些 op 参与」）
        let fc18 = crate::VM::VM_Backend::Generator_util::FoldCtx {
            r6b: rng.range(1, 17) as u32, p1b: rng.next(), p3b: rng.range(30, 70) as u32,
            r6c: rng.range(1, 17) as u32, p1c: rng.next(), p3c: rng.range(30, 70) as u32,
            f1: rng.next() | 1, f2: rng.next(),
            m1: rng.next(), m2: rng.next(), m3: rng.range(1, 24) as u32,
            m4: rng.next() | 1, m5: rng.range(1, 24) as u32,
            rs18: rng.next(),
        };
        // ㉓-B 常量 tag 字母表逐 build 随机：[nil/省略, bool, num, str] 四个线上 tag
        // 从 0..59∪251..255 取互不相同值（避开 60..250 诱饵键区）；写侧推送与
        // 读侧 ld/dsp 键两侧同源（修 DF「tag 源/线上不一致」缺陷——线上不再恒为 0..3）
        let mut tag_pool18: Vec<u8> = (0..=59u8).chain(251..=255u8).collect();
        let mut tag_map18 = [0u8; 4];
        for tm in tag_map18.iter_mut() {
            let k18 = rng.range(0, tag_pool18.len());
            *tm = tag_pool18[k18];
            let last18 = tag_pool18.len() - 1;
            tag_pool18.swap(k18, last18);
            tag_pool18.pop();
        }
        // 目标二③（第二部分）：全文件共用指令空间基址游标——根原型从一个小随机基址
        // 起步，每个原型（先序遍历）分到一段互不重叠的记录区间，段间留随机死槽。
        let mut alloc18: u32 = rng.range(4, 64) as u32;
        rewrite_chunk(&mut reader, &mut rewritten_chunks, &transpile_map, &fused_opcodes, &mut fused_used, &inverse_opcode_map, &op_magic, &enc, root_group, &mut rewrite_rng, bc_kb, bc_kc, bc_ki1, bc_ki2, &fc18, &tag_map18, chain_delta, chain_m, chain_k0, &mut alloc18);

        // ⑰ 中央密文池废除：payload = 4 字节滚动密钥 + 各原型常量节（密文内联）
        let mut combined_payload = Vec::new();
        let (k1, k2, k3, k4) = ((rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8);
        combined_payload.push(k1); combined_payload.push(k2); combined_payload.push(k3); combined_payload.push(k4);
        
        combined_payload.extend(rewritten_chunks);

        // 对 4 字节密钥之后的**全部内容**做同一道滚动字节变换 —— 常量池和指令流
        // 共用一条连续的 keystream。指令流此前是明文追加的，固定 10 字节一条
        // 剥掉外层 base86 之后可以直接切片还原；现在和池一样被覆盖。
        // Lua 侧的 chunk 读取器相应改成走 fn_read_dec（见 block_dec_readers）。
        // 自定义滚动层参数逐产物随机；写端与 Lua 逆变换共享这些值。
        let sc_add: u8 = (rng.range(0, 128) * 2 + 1) as u8; // 奇数 1..255
        let sc_rot_in: u32 = rng.range(1, 8) as u32;
        let sc_add_k1: u8 = rng.range(1, 8) as u8;
        let sc_mul_k2: u8 = rng.range(2, 8) as u8;
        let sc_rot_k2: u32 = rng.range(1, 8) as u32;
        let sc_rot_k4: u32 = rng.range(1, 8) as u32;
        // ㉛ 白化种子：kdf(根字, 专用组号, 字序号)——与 Lua 侧同一式（Generator_chain
        // 发射同一取值的 kdf 调用），产物里不落任何白化参数，只有运行期装出的根能重算。
        let whiten_seed: u64 = {
            let w = crate::VM::VM_Backend::Generator_chacha::derive_word(
                enc.root[3], WHITEN_GROUP as u32, WHITEN_WORD) as u64;
            w % 2147483646 + 1
        };
        // 乘法器/加数逐构建随机（奇数乘法器；乘积仍 < 2^45，double 精确）
        let whiten_mul: u64 = (rng.range(0x1001, 0x100000) as u64) | 1;
        let whiten_add: u64 = rng.range(0x1000000, 0x7FFF_FFFF) as u64;
        let roll_params = RollParams { add: sc_add, rot_in: sc_rot_in, add_k1: sc_add_k1,
            mul_k2: sc_mul_k2, rot_k2: sc_rot_k2, rot_k4: sc_rot_k4 };
        let mut roll_state = [k1, k2, k3, k4];
        for (pos4, b) in combined_payload[4..].iter_mut().enumerate() {
            let pos = pos4 + 4; // 0-based payload byte offset
            // 先白化，再把白化字节与绝对位置送入自创的耦合滚动变换。
            *b ^= whiten_byte(whiten_seed, (pos + 1) as u64, whiten_mul, whiten_add);
            let white = *b;
            *b = roll_encrypt_byte(&mut roll_state, (pos + 1) as u64, white, roll_params);
        }
        
        let key_kryvex = String::from("x1"); let p_out: Vec<String> = (0..6).map(|_| rng.name()).collect();
        let var_s = rng.name(); let fn_N_ = rng.name(); let var_fU = rng.name(); let var_L = rng.name(); let var_get_count = rng.name();
        let hex_select_idx = format!("0X{:X}", rng.range(10, 255));
        let var_state_flag = rng.name();
        let wai = rng.name();
        let mut header_block = String::new();
        header_block.push_str(&format!("return ({{ {} = function(agv,aggv,agv,agv,agv,aggv,agv,agv,aggv,aggv,aggv,agggv,agggv,agggv,agggv,aggv,{},{},{},{}, ...)\n", wai, p_out[0], p_out[1], p_out[2], p_out[3]));
        // ㉘D1 头部两行声明换位（互无依赖）：位库 fallback 先、状态旗后
        header_block.push_str(&format!("local {} = {{}}; local {} = bit32 and bit32.rshift or bit and bit.rshift; ", var_s, var_fU));
        header_block.push_str(&format!("local {} = false; ", var_state_flag));
        header_block.push_str(&format!("local {} = function(q, s, M, C) s[{}] = select; end; ", fn_N_, hex_select_idx));
        header_block.push_str(&format!("{}(nil, {}, nil, nil); ", fn_N_, var_s));
        // 冷块状态校验的单向摘要（每产物一次）：产物只留摘要+每块独立 salt。
        let fn_state_digest = rng.name();
        let sbox_state = rng.name();
        let mut sbox_vals: [u32; 256] = [0; 256];
        for v in sbox_vals.iter_mut() {
            *v = rng.range64(0, 0xFFFF_FFFF) as u32;
        }
        header_block.push_str(&emit_state_digest(&sbox_state, &fn_state_digest, &sbox_vals));
        
        // 8 个下标必须互不相同（撞车会让辅助表槽位互相覆盖），见 GenRng
        let idx = rng.distinct(8, 0x10, 0x7F);
        let keys = CipherKeys {
            grp1: idx[0],
            grp2: idx[1],
            key_bx: idx[2],
            key_ba: idx[3],
            key_add: idx[4],
            key_bs: idx[5],
            key_ba2: idx[6],
            key_bs2: idx[7],
            tbl_p: rng.name(),
        };

        let fn_bx = rng.name();
        let fn_ba = rng.name();
        let fn_bs = rng.name();
        // ⑱.4 execute 前置 bxor 别名（与 fn_bxor 同实现）：execute 定义在解码器
        // 函数之前，直接引用 fn_bxor 会捕获成全局 nil——取指/掩码派生专用此别名
        let fn_bxor2 = rng.name();
        let mut block_p_def = String::new();
        // ㉘D2 形式改写：qT4c/qT8c 的两段平铺建表折进一个函数边界（双表以返回值
        // 出界，外层同名局部接住——后续 fn_bx/fn_bxor2 fallback 对 qT8c 的 upvalue
        // 捕获不变）；四个位库局部互无依赖，洗牌后发射
        block_p_def.push_str("local qT4c,qT8c=(function() local qT4c={};for i=0,15 do qT4c[i]={};for j=0,15 do local r,p=0,1;local x,y=i,j;for k=1,4 do local rx,ry=x%2,y%2;if rx~=ry then r=r+p end;x=(x-rx)/2;y=(y-ry)/2;p=p+p end;qT4c[i][j]=r end end;local qT8c={};for i=0,255 do qT8c[i]={};end;for i=0,255 do local qIc=qT8c[i];local qHc=(i-i%16)/16;for j=0,255 do qIc[j]=qT4c[i%16][j%16]+qT4c[qHc][(j-j%16)/16]*16 end end; return qT4c,qT8c end)(); ");
        let mut bit_locals: Vec<String> = vec![
            format!("local {}={}; ", fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b) local r,p=0,1;for k=1,4 do local x,y=a%256,b%256;r=r+qT8c[x][y]*p;a=(a-x)/256;b=(b-y)/256;p=p*256 end;return r end"),
            format!("local {}={}; ", fn_ba, "bit32 and bit32.band or bit and bit.band or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end"),
            format!("local {}={}; ", fn_bs, "bit32 and bit32.rshift or bit and bit.rshift or function(a,n)local d=2^n return (a-a%d)/d end"),
            format!("local {}={}; ", fn_bxor2, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b) local r,p=0,1;for k=1,4 do local x,y=a%256,b%256;r=r+qT8c[x][y]*p;a=(a-x)/256;b=(b-y)/256;p=p*256 end;return r end"),
        ];
        rng.shuffle(&mut bit_locals);
        for bl in &bit_locals { block_p_def.push_str(bl); }
        let tbl_def = format!(
            "local {p}={{}};{p}[{g1}]={{}};{p}[{g1}][{bx}]={fbx};{p}[{g1}][{add}]=function(a,b)return a+b end;{p}[{g1}][{ba}]={fba};{p}[{g2}]={{}};{p}[{g2}][{ba2}]=function(a)return {fba}(a,{max_u32})end;{p}[{g2}][{bs2}]=function(a)return {fbs}(a,{one})end;",
            p = keys.tbl_p,
            g1 = rng.format_num(keys.grp1 as i64),
            g2 = rng.format_num(keys.grp2 as i64),
            bx = rng.format_num(keys.key_bx as i64),
            add = rng.format_num(keys.key_add as i64),
            ba = rng.format_num(keys.key_ba as i64),
            ba2 = rng.format_num(keys.key_ba2 as i64),
            bs2 = rng.format_num(keys.key_bs2 as i64),
            fbx = fn_bx,
            fba = fn_ba,
            fbs = fn_bs,
            max_u32 = rng.format_num(4294967295i64),
            one = rng.format_num(1i64)
        );
        block_p_def.push_str(&tbl_def);

        let block_vm_core = Lua_core::build_vm_core().replace("\n", " ");
        
        let (payload_str, decoder_script, entry_func) = Packer::pack(&combined_payload, &mut rng, &mut uni);
        let var_vc = rng.name(); let var_builtin_reg = rng.name();
        let var_builtin_view = rng.name(); let var_builtin_mask = rng.name(); let var_builtin_i = rng.name(); let var_builtin_xor = rng.name();
        let closure_env_registry = rng.name();
        let native_tonumber = rng.name();
        let native_type = rng.name();
        let native_pairs = rng.name();
        let native_error = rng.name();
        let native_getfenv = rng.name();
        let native_setfenv = rng.name();
        let block_packer_vars = format!("local {}, {}; ", var_vc, var_builtin_reg);

        let fn_execute = "execute";
        // 诱饵投毒旗（外围 upvalue）：守卫失败/诱饵 handler 置位后先经过随机指令窗口，
        // 再渐进污染常量、密钥或路由；探针本身不早退，也不提供固定错误位置。
        let psn_n = rng.name();
        let mut at = AntiTamper::generate_split(true, &key_seed_var, &psn_n);
        let var_pc = rng.name();
        let var_stk = rng.name();
        let var_vstack = rng.name();
        let var_top = rng.name();
        let var_inst = rng.name();
        let var_varargs = rng.name();
        let var_varargs_len = rng.name();
        let var_insts = rng.name();
        let var_opcodes = rng.name();
        let var_a_arr = rng.name();
        let var_b_arr = rng.name();
        let var_c_arr = rng.name();
        // 方法化 / 数据流：
        let var_consts = rng.name();
        let var_protos = rng.name();
        let var_upvals = rng.name();
        let var_env = rng.name();
        let var_current_fn = rng.name();
        let var_parent_frame = rng.name();
        let var_vm = rng.name();      // VM 对象（方法 + 状态槽位都挂在它上面）
        let var_r1 = rng.name();
        let var_r2 = rng.name();
        let var_r3 = rng.name();
        let var_st = rng.name();      // 当前状态号
        let var_md = rng.name();      // 返回载荷模式
        let var_smap = rng.name();    // 操作码 → 状态号 映射表
        let fn_ret0 = rng.name();
        let fn_ret1 = rng.name();
        let fn_ret2 = rng.name();
        let var_methods = rng.name(); // 首个方法分发表
        let method_shard_count = rng.range(3, 6);
        let mut method_shards = vec![var_methods.clone()];
        for _ in 1..method_shard_count { method_shards.push(rng.name()); }
        let var_proto = rng.name();   // 状态对象的元表（__index → 分发表链）
        let ret_shards = [rng.range(0, method_shard_count), rng.range(0, method_shard_count), rng.range(0, method_shard_count)];
        let mut block_execute_def = String::new();
        let (sk, sk_setup) = rng.slot_key_block(28);
        let k_pc = sk[0].clone(); let k_stk = sk[1].clone(); let k_top = sk[2].clone();
        let k_ops = sk[3].clone(); let k_aa = sk[4].clone(); let k_bb = sk[5].clone(); let k_cc = sk[6].clone();
        // ⑱.4 掩码槽键：execute 入口派生后写槽，冷块（CLOSURE 等）中程读自取——
        // 必须走 slot_key_block 池；裸 rng.name() 键不在池里=运行时 nil 键（前车之鉴）
        let k_mk1 = sk[20].clone(); let k_mk2 = sk[21].clone(); let k_mk3 = sk[22].clone();
        let k_dc = sk[23].clone(); // ㉚ DC 缓存表槽位（冷块中程读自取）
        let k_bmask = sk[24].clone(); // 每个原型独立的内建表 XOR 掩码
        let k_vstack = sk[25].clone(); // 每个 VM 帧独立的装箱表达式栈
        // 中危刀1 密钥分驻：kp/pb/cnt 不入 chunk 表也不入 VM 槽（嵌套闭包交错会串），
        // 存弱键注册表 KREG（键=chunk 表）——与被掩码数组异表分驻，重解原型自动回收
        let k_consts = sk[7].clone(); let k_protos = sk[8].clone();
        let k_upv = sk[9].clone(); let k_env = sk[10].clone();
        let k_va = sk[11].clone(); let k_valen = sk[12].clone();
        let k_vc = sk[13].clone(); let k_breg = sk[14].clone();
        let k_state = sk[15].clone(); let k_mode = sk[16].clone();
        let k_retv = sk[17].clone(); let k_retf = sk[18].clone(); let k_rett = sk[19].clone();
        let k_parent = sk[26].clone(); // 虚拟调用栈的父帧
        let k_current_fn = sk[27].clone(); // 当前 Lua 闭包对象（setfenv/getfenv）
        
        // 目标三②：计算式跳转的密钥源——n_kon 是 execute 入口从 KREG 取出的本原型
        // pf_ld 运行期值（热路径处理器可直接引用该局部名）。
        let (n_kon, n_ka) = (rng.name(), rng.name());
        let numeric_for_errors = uni.register_numeric_for_errors(&mut rng);
        let cfg = OpcodeConfig {
            pc: var_pc.clone(),
            stk: var_stk.clone(),
            vstack: var_vstack.clone(),
            consts: var_consts.clone(),
            top: var_top.clone(),
            insts: var_insts.clone(),
            inst: var_inst.clone(),
            upvals: var_upvals.clone(),
            env: var_env.clone(),
            env_ref: format!("self[{}]", k_env),
            protos: var_protos.clone(),
            handlers: String::new(),
            varargs: var_varargs.clone(),
            varargs_len: var_varargs_len.clone(),
            virtual_closures: var_vc.clone(),
            execute: fn_execute.to_string(),
            closure_env_registry: closure_env_registry.clone(),
            frame: "self".to_string(),
            frame_env_key: k_env.clone(),
            frame_parent_key: k_parent.clone(),
            frame_function_key: k_current_fn.clone(),
            native_tonumber: native_tonumber.clone(),
            native_type: native_type.clone(),
            native_pairs: native_pairs.clone(),
            native_error: native_error.clone(),
            numeric_for_errors,
            native_getfenv: native_getfenv.clone(),
            native_setfenv: native_setfenv.clone(),
            builtin_reg: format!("self[{}]", k_breg),
            builtin_mask: format!("self[{}]", k_bmask),
            builtin_bxor: fn_bxor2.clone(),
            ld_key: n_kon.clone(),
            vararg_count: pf_vn.clone(),
            proto_nups: pf_nups.clone(),
            open_ups: pf_open_ups.clone(),
            ret0: format!("{}:{}", var_vm, fn_ret0),
            ret1: format!("{}:{}", var_vm, fn_ret1),
            ret2: format!("{}:{}", var_vm, fn_ret2),
        };
        let mut raw_handlers = Opcodes::generate_handlers(&mapped_opcodes, &fused_opcodes, &fused_used, &cfg, self.ctx.seed).replace("execute(", &format!("{}(", fn_execute));

        
        raw_handlers = raw_handlers.replace(
            &format!("{}[{}][1]", var_insts, var_pc),
            &format!("{}[{}]", var_opcodes, var_pc)
        ).replace(
            &format!("{}[{}][2]", var_insts, var_pc),
            &format!("{}[{}]", var_a_arr, var_pc)
        ).replace(
            &format!("{}[{}][3]", var_insts, var_pc),
            &format!("{}[{}]", var_b_arr, var_pc)
        ).replace(
            &format!("{}[{}][4]", var_insts, var_pc),
            &format!("{}[{}]", var_c_arr, var_pc)
        ).replace(
            &format!("{}[{}]", var_insts, var_pc),
            &format!("({{ {}[{}], {}[{}], {}[{}], {}[{}] }})", var_opcodes, var_pc, var_a_arr, var_pc, var_b_arr, var_pc, var_c_arr, var_pc)
        ).replace(
            &format!("{}[1]", var_inst), "op"
        ).replace(
            &format!("{}[2]", var_inst), "inst_A"
        ).replace(
            &format!("{}[3]", var_inst), "inst_B"
        ).replace(
            &format!("{}[4]", var_inst), "inst_C"
        ).replace(
            &var_inst, "({op, inst_A, inst_B, inst_C})"
        );

        // 返回协议：模板里的 {RET0}/{RET1}/{RET2} 换成 VM 对象上的钩子方法
        // （`:` 调用）。块被提升成方法后，`return` 只能返回给分发器，
        // 载荷放槽位里，由分发器决定真正返回什么。
        raw_handlers = raw_handlers
            .replace("{RET0}", &format!("self:{}", fn_ret0))
            .replace("{RET1}", &format!("self:{}", fn_ret1))
            .replace("{RET2}", &format!("self:{}", fn_ret2));
        // ㉚ 目标②：RET 钩子逐出现轮换别名（每钩 3 池）——统一派发点形态消失，
        // 跨样本对 `:fnX(` 的直方图对齐作废；别名在方法表里等价挂接。
        let mut ret_alias_map: Vec<(String, Vec<String>)> = Vec::new();
        for base in [fn_ret0.clone(), fn_ret1.clone(), fn_ret2.clone()] {
            let pool = vec![base.clone(), rng.name(), rng.name()];
            let token = format!(":{}(", base);
            let parts: Vec<String> = raw_handlers.split(&token).map(|x| x.to_string()).collect();
            let mut out = parts[0].clone();
            for p2 in parts.iter().skip(1) {
                let sel = pool[rng.range(0, pool.len())].clone();
                out.push_str(&format!(":{}(", sel));
                out.push_str(p2);
            }
            raw_handlers = out;
            ret_alias_map.push((base, pool));
        }

        // ⑮ 派发条件换魔数：模板条件是 `elseif op == 别名 then/or`，
        // 把别名 token 整体换成魔数——下游 parsed/tree 全部拿到魔数。
        // ㉚：运行时 op 已是 mag+Δ（DC 条目里链偏移未撤销），树键/伪指令比较
        // 必须同加 Δ，否则二分树按裸魔数导航→错叶崩溃。
        for (alias, mag) in op_magic.iter() {
            let key = mag.wrapping_add(chain_delta);
            raw_handlers = raw_handlers.replace(&format!("op == {} or", alias), &format!("op == {} or", key));
        }
        for (alias, mag) in op_magic.iter() {
            let key = mag.wrapping_add(chain_delta);
            raw_handlers = raw_handlers.replace(&format!("op == {} then", alias), &format!("op == {} then", key));
        }
        // CLOSURE 模板体内还有一层伪指令 op 值比较（uv_inst[1] == 别名），同批换魔数
        // （带 " or"/" then" 尾边界——个位数 fallback key 否则会前缀污染长数字）
        for (alias, mag) in op_magic.iter() {
            let key = mag.wrapping_add(chain_delta);
            raw_handlers = raw_handlers.replace(&format!("uv_inst[1] == {} or", alias), &format!("uv_inst[1] == {} or", key));
            raw_handlers = raw_handlers.replace(&format!("uv_inst[1] == {} then", alias), &format!("uv_inst[1] == {} then", key));
        }
        // ⑮ 三处中程读下一条指令的模板（SETLIST/EXTRAARG/CLOSURE 伪指令）同步解码：
        // ⑱.4 数组存的是掩码值，中程读必须 bx 还原——掩码名在此提前生成：
        // 热块内联用 execute 局部，冷块方法体用同名局部（fetch 前缀从槽位自取）
        let (n_mk1, n_mk2, n_mk3) = (rng.name(), rng.name(), rng.name());
        // ㉚ 目标①：DC 惰性解码缓存表名（热块 execute 局部 / 冷块自槽位取回同名）
        let n_dc = rng.name();
        // ㉚：DC 链状态表名（ds）——execute 局部；换钥块需回写新掩码进 ds，故提升可见域
        let dc_ds = rng.name();
        // （⑮ 魔数替换已在上方完成——树键= mag+Δ；此处曾有裸魔数重复循环，
        //  会把 Δ 撤销成裸魔数导致错叶，已删。）
        {
            let site1 = format!("then c = {}[{}];", var_a_arr, var_pc);
            let site1_new = format!("then c = {}[{}][2];", n_dc, var_pc);
            raw_handlers = raw_handlers.replace(&site1, &site1_new);
            let site3 = format!("[{}[{}] + 1]", var_a_arr, var_pc);
            let site3_new = format!("[{}[{}][2] + 1]", n_dc, var_pc);
            raw_handlers = raw_handlers.replace(&site3, &site3_new);
            let comp_old = format!("local uv_inst = ({{ {}[{}], {}[{}], {}[{}], {}[{}] }})", var_opcodes, var_pc, var_a_arr, var_pc, var_b_arr, var_pc, var_c_arr, var_pc);
            let (cq1, cq2, cq3, cq4) = (rng.name(), rng.name(), rng.name(), rng.name());
            // ㉚：DC 条目已是 {mag+Δ, a, B, C}（奇偶交换在填充时完成）
            let comp_new = format!("local uv_inst = {}[{}]", n_dc, var_pc);
            let _ = (cq1, cq2, cq3, cq4);
            raw_handlers = raw_handlers.replace(&comp_old, &comp_new);
        }

        // handlers 成块：多个 op 共用一个方法（省体积）
        let parsed = crate::VM::VM_Backend::Generator_util::split_dispatch_handlers(&raw_handlers);

        // 去重 + 分配随机方法名 / 随机状态号
        let mut blocks: Vec<(Vec<u32>, String, String, u32, usize)> = Vec::new();
        let mut used_states: Vec<u32> = Vec::new();
        for (ops, code) in parsed {
            if let Some(b) = blocks.iter_mut().find(|b| b.1 == code) { b.0.extend(ops); continue; }
            let name = rng.name();
            let st = loop {
                let v = rng.range(0x0100_0000, 0x7FFF_0000) as u32;
                if !used_states.contains(&v) { used_states.push(v); break v; }
            };
            let shard = rng.range(0, method_shard_count);
            blocks.push((ops, code, name, st, shard));
        }

        // ① 方法化 + ② 数据流打乱
        // 而是按随机槽位号从 VM 对象里取自己的那份状态，出口再写回
        // 每个块的局部别名逐块新取，同一个逻辑变量跨块看到的不是同一个名字
        // ④ 槽位号不再写死在产物里
        // `GenRng::slot_key_block`）。这里拿到的全是**局部名字**，插值进 Lua 源码

        // 表类状态按块取一次（表是引用，不需要写回）
        // 直接把槽位表达式替换进块体 —— 就地读写，不依赖出口写回
        // （Lua 的 `return` 必须是块的最后一条语句，写回语句没法追加在它后面）
        let state_fields: Vec<(String, String, bool)> = vec![
            (var_opcodes.clone(), k_ops.clone(), false),
            (var_a_arr.clone(), k_aa.clone(), false),
            (var_b_arr.clone(), k_bb.clone(), false),
            (var_c_arr.clone(), k_cc.clone(), false),
            (var_stk.clone(), k_stk.clone(), false),
            (var_vstack.clone(), k_vstack.clone(), false),
            (var_consts.clone(), k_consts.clone(), false),
            (var_protos.clone(), k_protos.clone(), false),
            (var_upvals.clone(), k_upv.clone(), false),
            (var_env.clone(), k_env.clone(), false),
            (var_varargs.clone(), k_va.clone(), false),
            (var_varargs_len.clone(), k_valen.clone(), false),
            (var_vc.clone(), k_vc.clone(), false),
            (var_builtin_reg.clone(), k_breg.clone(), false),
        ];
        let mut defs: Vec<String> = Vec::new();
        let mut tree_entries: Vec<(u32, String)> = Vec::new();
        // 热块内联时要用的状态名 → 槽位号（驱动里声明成局部变量）
        let mut hot_locals: Vec<(String, String)> = Vec::new();
        for (ops, code, name, st, method_shard) in blocks.iter() {
            // 预算：热路径（算术/比较/跳转/栈与表存取）保留**内联**，冷路径
            // （调用/返回/闭包/全局/上值/内建）才提升成方法。全量方法化会把每条
            // 指令都变成一次 Lua 函数调用 —— 实测慢 5.6 倍，超出预算
            // n_kon 是 execute 作用域内从 KREG 取出的本原型密钥。引用它的 handler
            // 必须内联在 execute 里；提升成共享方法会把局部名变成未绑定全局（nil），
            // 而把密钥写进 VM 槽又会破坏密钥分驻约束。
            let cold = !uses_ident(code, &n_kon)
                && (uses_ident(code, &var_vc)
                    || uses_ident(code, &var_builtin_reg)
                    || code.contains(&format!("self[{}]", k_breg))
                    || code.contains(&format!("self[{}]", k_bmask))
                    || uses_ident(code, &var_env)
                    || uses_ident(code, &var_protos)
                    || uses_ident(code, &var_varargs)
                    || code.contains(&pf_open_ups)
                    || code.contains("zm(")
                    || code.contains(&format!("{}(", fn_execute)));
            if cold {
                let mut body = code.clone();
                // ── 方法签名逐块随机化：原先每个冷块都是同一条
                // `function(self,op,inst_A,inst_B,inst_C)`（产物里 60+ 处一字不差），
                // 是把「指令处理器」一把 grep 出来的最短路径。这里把首参名与四个
                // 指令参数的名字、以及在实参表里的先后顺序同时打散——签名、方法体、
                // 调用点三处共用同一次抽签结果，语义完全不变。
                let p_self = rng.name();
                let mut p_src: Vec<&str> = vec!["op", "inst_A", "inst_B", "inst_C"];
                rng.shuffle(&mut p_src);
                let p_names: Vec<String> = (0..4).map(|_| rng.name()).collect();
                for (j, src) in p_src.iter().enumerate() {
                    body = rename_ident(&body, src, &p_names[j]);
                }
                body = rename_ident(&body, "self", &p_self);
                // 调用点实参 = 打散后的顺序（与形参位置逐位对应）
                let call_args = p_src.join(",");
                // 标量状态：槽位表达式就地替换（pc/top 的读写直接落在 VM 对象上）
                body = rename_ident(&body, &var_pc, &format!("{}[{}]", p_self, k_pc));
                body = rename_ident(&body, &var_top, &format!("{}[{}]", p_self, k_top));
                // CLOSURE 模板里有字面量 env（内层闭包用），方法表是共享的
                // 必须走槽位拿当前调用的环境，不能捕获第一次调用的 env
                body = rename_ident(&body, "env", &format!("{}[{}]", p_self, k_env));
                // 取指别名对（别名↔槽位绑定不变；抓取顺序与分组随机）
                let mut alias_pairs: Vec<(String, String)> = Vec::new();
                for (old, key, _mutable) in state_fields.iter() {
                    if !uses_ident(&body, old) { continue; }
                    let alias = rng.name();
                    body = rename_ident(&body, old, &alias);
                    alias_pairs.push((alias, format!("{}[{}]", p_self, key)));
                }
                rng.shuffle(&mut alias_pairs);
                // ⑱.4 中程读体需要掩码：从掩码槽自取（execute 入口已派生写入）
                let mut mk_stmt: Option<String> = None;
                if body.contains(&n_mk1) {
                    mk_stmt = Some(format!("local {m1},{m2},{m3}={s}[{k1}],{s}[{k2}],{s}[{k3}];", s = p_self,
                        m1 = n_mk1, m2 = n_mk2, m3 = n_mk3, k1 = k_mk1, k2 = k_mk2, k3 = k_mk3));
                }
                // ㉚：中程读站点改走 DC 缓存——冷块同样自槽位取回同名局部
                if body.contains(&n_dc) {
                    let dc_stmt = format!("local {dc}={s}[{kd}];", dc = n_dc, kd = k_dc, s = p_self);
                    mk_stmt = Some(match mk_stmt.take() { Some(x) => x + &dc_stmt, None => dc_stmt });
                }
                body = body.replace("{STOREBACK}", "");
                // ── 冷块前奏打散：{rk 声明 + 状态投毒采样 + 取指分组} 均先于主体执行，
                // 独立语句仍可洗牌；状态不符只置共享投毒旗，不在固定位置早退。
                let mut pre: Vec<String> = Vec::new();
                pre.push("local rk1,rk2;".to_string());
                // 状态号不符时置共享投毒旗；主体仍按原控制流继续，避免固定早退信号。
                // 校验改单向摘要（改进 1）：产物只留摘要+每块独立 salt，不再发射
                // 可静态读回的期望状态，切断同源代数抵消路径。
                pre.push(cold_state_check(
                    &mut rng, &keys, *st, &sbox_vals, &fn_state_digest, &psn_n, &p_self, &k_state,
                ));
                let mut ai = 0usize;
                while ai < alias_pairs.len() {
                    let rem = alias_pairs.len() - ai;
                    let take = 1 + rng.range(0, rem.min(3));
                    let ns: Vec<String> = alias_pairs[ai..ai + take].iter().map(|(n, _)| n.clone()).collect();
                    let es: Vec<String> = alias_pairs[ai..ai + take].iter().map(|(_, e)| e.clone()).collect();
                    pre.push(format!("local {}={};", ns.join(","), es.join(",")));
                    ai += take;
                }
                if let Some(mk) = mk_stmt { pre.push(mk); }
                rng.shuffle(&mut pre);
                let mut text = pre.concat();
                text.push_str(&body);
                // 必须用 `.名字=function` 注册
                // 成员名统一改名时字符串键不改，两边对不上变 nil。
                defs.push(format!("{}.{}=function({},{},{},{},{}) {} end;", method_shards[*method_shard], name,
                    p_self, p_names[0], p_names[1], p_names[2], p_names[3], text));
                // 冷路径才付同步代价：进出方法前后各存/取一次 pc 与 top
                // 并把本块状态号写进槽位（方法入口自校验）。
                // 同步语句：三连存乱序/分组 + 状态号常数去指纹（原两形态合流）。
                // 初始状态值不留裸明文——它和冷块摘要校验共享同一状态语义。
                let st_o = rng.obfuscate_num(*st as i64, 1, &keys);
                let mut sync: Vec<(String, String)> = vec![
                    (format!("{}[{}]", var_vm, k_pc), var_pc.clone()),
                    (format!("{}[{}]", var_vm, k_top), var_top.clone()),
                    (format!("{}[{}]", var_vm, k_state), st_o),
                ];
                rng.shuffle(&mut sync);
                let mut sync_stmts = String::new();
                let mut si = 0usize;
                while si < sync.len() {
                    let take = 1 + rng.range(0, sync.len() - si);
                    let lhs: Vec<String> = sync[si..si + take].iter().map(|(l, _)| l.clone()).collect();
                    let rhs: Vec<String> = sync[si..si + take].iter().map(|(_, r)| r.clone()).collect();
                    sync_stmts.push_str(&format!("{}={};", lhs.join(","), rhs.join(",")));
                    si += take;
                }
                // ── 调用形态池：此前 240+ 处清一色 `vm:方法(op,inst_A,inst_B,inst_C)`，
                // 是产物里最好 grep 的结构。现在六形随机（0/1 保留冒号调用，约 1/3）：
                // 2/3 走点调用（经原型 __index 同级解析）或先取方法再直调（省掉元表查找，
                // 比冒号还快）。六形语义完全等价——都只是「把接收者与四个已置换的实参
                // 交给同一个方法」，冷块入口的状态自校验与符号同步逻辑一概不变。
                let (rn1, rn2, rn3) = (var_r1.clone(), var_r2.clone(), var_r3.clone());
                let call = match rng.range(0, 6) {
                    0 => format!("{},{},{}={}:{}({});", rn1, rn2, rn3, var_vm, name, call_args),
                    1 => {
                        let vn = rng.name();
                        format!("local {}={};{},{},{}={}:{}({});", vn, var_vm, rn1, rn2, rn3, vn, name, call_args)
                    }
                    2 => format!("{},{},{}={}.{}({},{});", rn1, rn2, rn3, var_vm, name, var_vm, call_args),
                    3 => {
                        let vn = rng.name();
                        format!("local {}={};{},{},{}={}.{}({},{});", vn, var_vm, rn1, rn2, rn3, vn, name, vn, call_args)
                    }
                    4 => {
                        let fnv = rng.name();
                        format!("local {}={}.{};{},{},{}={}({},{});", fnv, method_shards[*method_shard], name, rn1, rn2, rn3, fnv, var_vm, call_args)
                    }
                    _ => {
                        let (vn, fnv) = (rng.name(), rng.name());
                        format!("local {}={};local {}={}.{};{},{},{}={}({},{});", vn, var_vm, fnv, method_shards[*method_shard], name, rn1, rn2, rn3, fnv, vn, call_args)
                    }
                };
                let rs_pc = format!("{}={}[{}];", var_pc, var_vm, k_pc);
                let rs_top = format!("{}={}[{}];", var_top, var_vm, k_top);
                let (ra, rb) = if rng.range(0, 2) == 0 { (rs_pc, rs_top) } else { (rs_top, rs_pc) };
                let leaf = format!("{}{}{}{}", sync_stmts, call, ra, rb);
                for &op in ops.iter() {
                    tree_entries.push((op, leaf.clone()));
                }
            } else {
                // 热块完全内联：pc/top/栈 都是 execute 的局部变量，和基线一样快
                // 冷块调用前后由调用点负责把 pc/top 同步进/出 VM 对象的槽位
                let body = code.replace("{STOREBACK}", "").replace("self:", &format!("{}:", var_vm));
                for (old, key, _mutable) in state_fields.iter() {
                    if uses_ident(&body, old) && !hot_locals.iter().any(|(n, _)| n == old) {
                        hot_locals.push((old.clone(), key.clone()));
                    }
                }
                for &op in ops.iter() {
                    tree_entries.push((op, body.clone()));
                }
            }
        }
        // 诱饵假 handler（用户指示）：2 个永不合法命中的魔数，挂在派发树**之后**
        // 的独立 if（不加深主树——树深影响每指令派发，hash 实测 +13% 的教训）。
        // body 形似真 handler（栈写入+算术）——逆向者分析的是假逻辑；
        // 被字节码补丁/garbage op 撞中：静默压 garbage + 置投毒旗（错误分支）
        // 诱饵假 handler（用户指示）：2 个注册进方法表但**永不路由**的假块——
        // 纯静态蜜罐（逆向者分析的是假逻辑），零运行时开销（树内/树后每指令
        // 评估的形态实测 hash +13%，弃）。garbage op 不命中主树无兜底 else→
        // 自然滑过=静默错误分支；运行时诱饵由守卫投毒+解密诱饵承担
        let decoy_ops: Vec<u32> = {
            let used_ops: Vec<u32> = op_magic.iter().map(|(_, m)| *m).collect();
            let mut v = Vec::new();
            while v.len() < 2 {
                let c = rng.range(0x0100_0000, 0x7FFF_FFFF) as u32;
                if !used_ops.contains(&c) && !v.contains(&c) { v.push(c); }
            }
            v
        };
        // 静态蜜罐注册（永不路由）：形似真 handler 的假块，逆向分析陷阱
        for &dop in decoy_ops.iter() {
            let (dg, skv) = (rng.name(), rng.name());
            // 签名随机化与真块一致（诱饵永不路由，只需语法自洽）
            let (d_self, d_p0, d_p1, d_p2, d_p3) =
                (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let (ha_, hb_) = (rng.range(0x1_0000, 0xFFFF_FFFF) as i64, rng.range(0x1_0000, 0xFFFF_FFFF) as i64);
            let htaut = format!("(0X{:X}-0X{:X}==0X{:X})", ha_, hb_, ha_ - hb_);
            let d_shard = rng.range(0, method_shard_count);
            defs.push(format!(
                "{mv}.{nm}=function({ds},{dp0},{dp1},{dp2},{dp3}) local {dg}={bx2}({dp0},0X{dop:X})%{m32v}; local {skv}={ds}[{ks}]; {skv}[{ds}[{kt}]+0X1]={dg}; {ds}[{kt}]={ds}[{kt}]+0X1; {psn}={psn} or {taut} end;",
                ds = d_self, dp0 = d_p0, dp1 = d_p1, dp2 = d_p2, dp3 = d_p3,
                mv = method_shards[d_shard], nm = rng.name(), dg = dg, bx2 = fn_bxor2.as_str(),
                dop = dop, m32v = crate::VM::VM_Backend::Generator_kdf::kdf_m32(&mut rng),
                skv = skv, ks = k_stk, kt = k_top, psn = psn_n, taut = htaut));
        }
        // ③ 随机代码块分配：注册顺序打乱，分发树按**状态号**（随机大整数）路由
        rng.shuffle(&mut defs);
        tree_entries.sort_by_key(|e| e.0);

        // 这几个哨兵常量在**每次 VM 调用**和**每次 return** 时都要重新求值（下面的
        // execute 前导 + 三个返回钩子 + 返回分派）。按用户要求，一律走 obfuscate_num
        // 的位运算风格（`V[a][b](x,y)`），不为了热路径换成简单表达式。
        let obf0 = rng.obfuscate_num(0i64, 1, &keys);
        let obf1 = rng.obfuscate_num(1i64, 1, &keys);
        let obf2 = rng.obfuscate_num(2i64, 1, &keys);

        // 方法表必须建在 execute **外面**：execute 每次调用都跑一遍，
        // 在里面定义 60 个闭包会让每次函数调用都重建一遍方法表（实测慢 2.5 倍）
        // 状态对象每个调用一个，方法通过 __index 原型共享，调用仍是 `V
        let mut block_methods = String::new();
        block_methods.push_str(&format!("local {}; ", fn_execute));
        block_methods.push_str(&format!(
            "local {to_num}=tonumber;local {err_fn}=error;local {getenv}=getfenv;local {setenv}=setfenv;local {closure_env}=setmetatable({{}},{{__mode='k'}}); ",
            to_num = native_tonumber,
            err_fn = native_error,
            getenv = native_getfenv,
            setenv = native_setfenv,
            closure_env = closure_env_registry,
        ));
        // ㉓ 统一流取用：惰性解密语句+纯数字密文，替换原池调用
        let (hash_stmt, hash_expr) = {
            let id = uni.register("#");
            uni.fetch(&mut rng, id)
        };
        block_methods.push_str(&hash_stmt);
        block_methods.push_str(&format!("local {} = function(...) return {}[{}]({}, ...) end; ", var_get_count, var_s, hex_select_idx, hash_expr));
        block_methods.push_str(&format!("local unpack, zm = unpack or table and table.unpack or function() end, function(...) return {{{}={}(...),...}} end; ", pf_vn, var_get_count));
        let shard_names = method_shards.join(",");
        let shard_tables = vec!["{}"; method_shard_count].join(",");
        block_methods.push_str(&format!("local {}={};local {}={{}};", shard_names, shard_tables, var_proto));
        for d in defs.iter() { block_methods.push_str(d); block_methods.push(' '); }
        let (idx_stmt, idx_expr) = {
            let id = uni.register("__index");
            uni.fetch(&mut rng, id)
        };
        block_methods.push_str(&idx_stmt);
        let mut method_order: Vec<usize> = (0..method_shard_count).collect();
        rng.shuffle(&mut method_order);
        for pair in method_order.windows(2) {
            block_methods.push_str(&format!("setmetatable({},{{[{}]={}}});", method_shards[pair[0]], idx_expr, method_shards[pair[1]]));
        }
        block_methods.push_str(&format!("{}[{}]={};", var_proto, idx_expr, method_shards[method_order[0]]));

        block_execute_def.push_str(&format!(
            "{} = function(chunk, env, upvals, {}, {}, ...) ",
            fn_execute, var_current_fn, var_parent_frame
        ));
        block_execute_def.push_str(&format!("local {} = {}(...); ", var_L, var_get_count));
        block_execute_def.push_str(&format!("local {} = setmetatable({{}}, {}); ", var_vm, var_proto));
        let builtin_count = crate::VM::Opcodes::builtins::BUILTIN_NAMES.len();
        block_execute_def.push_str(&format!("local {bxv}={bx};local {bm}=chunk.{cbm};local {bv}=chunk.{cbv};if not {bv} then {bm}={bxv}({bxv}(chunk.{lld},chunk.{nups}),chunk.{ms})%0X40;{bv}={{}};for {bi}=0,{last} do {bv}[{bxv}({bi},{bm})+1]={src}[{bi}+1] end;chunk.{cbm}={bm};chunk.{cbv}={bv};end;", bxv=var_builtin_xor, bm=var_builtin_mask, bv=var_builtin_view, cbm=pf_builtin_mask, cbv=pf_builtin_view, bx=fn_bxor2, lld=pf_lld, nups=pf_nups, ms=pf_maxstack, bi=var_builtin_i, last=builtin_count-1, src=var_builtin_reg));
        block_execute_def.push_str(&format!("{}[{}]={}.{}+{};{}[{}]={{}};{}[{}]={{}};{}[{}]={};", var_vm, k_pc, "chunk", pf_lld, obf1, var_vm, k_stk, var_vm, k_vstack, var_vm, k_top, obf0));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_ops, pf_opcodes, var_vm, k_aa, pf_a_arr, var_vm, k_bb, pf_b_arr, var_vm, k_cc, pf_c_arr));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_consts, pf_consts, var_vm, k_protos, pf_protos));
        block_execute_def.push_str(&format!(
            "{}[{}]=upvals;{}[{}]=env;{}[{}]={};{}[{}]={};{}[{}]={};{}[{}]={};{}[{}]={};",
            var_vm, k_upv,
            var_vm, k_env,
            var_vm, k_parent, var_parent_frame,
            var_vm, k_current_fn, var_current_fn,
            var_vm, k_vc, var_vc,
            var_vm, k_breg, var_builtin_view,
            var_vm, k_bmask, var_builtin_mask
        ));
        block_execute_def.push_str(&format!("for _=1,chunk.{} do {}[{}][_-1+chunk.{}] = {}[{}](_,...) end; ", pf_numparams, var_vm, k_stk, pf_maxstack, var_s, hex_select_idx));
        block_execute_def.push_str(&format!("local {} = {} - chunk.{}; local {} = {{{}[{}](chunk.{} + 1, ...)}}; ", var_varargs_len, var_L, pf_numparams, var_varargs, var_s, hex_select_idx, pf_numparams));
        block_execute_def.push_str(&format!("{}[{}]={};{}[{}]={};", var_vm, k_va, var_varargs, var_vm, k_valen, var_varargs_len));
        block_execute_def.push_str(&format!("{}[{}]={};{}[{}]={};{}[{}]=nil;{}[{}]={};{}[{}]={};", var_vm, k_state, obf0, var_vm, k_mode, obf0, var_vm, k_retv, var_vm, k_retf, obf0, var_vm, k_rett, obf0));
        // 热块内联时用到的状态
        if !hot_locals.is_empty() {
            // 注意：Lua 里一个 local 只能有一个 `=`，必须写成
            // `local a,b; a,b=V[k1],V[k2];`（不能写 `local a=V[k1],b=V[k2]`）
            let names: Vec<String> = hot_locals.iter().map(|(n, _)| n.clone()).collect();
            let vals: Vec<String> = hot_locals.iter().map(|(_, k)| format!("{}[{}]", var_vm, k)).collect();
            block_execute_def.push_str(&format!("local {};{}={};", names.join(","), names.join(","), vals.join(",")));
        }
        // 返回钩子也是方法（挂在共享方法表上），块里用 `:` 调
        block_methods.push_str(&format!("{}.{}=function(self)self[{}]={};return true end;", method_shards[ret_shards[0]], fn_ret0, k_mode, obf0));
        block_methods.push_str(&format!("{}.{}=function(self,v)self[{}]={};self[{}]=v;return true end;", method_shards[ret_shards[1]], fn_ret1, k_mode, obf1, k_retv));
        block_methods.push_str(&format!("{}.{}=function(self,t,f,l)self[{}]={};self[{}]=t;self[{}]=f;self[{}]=l;return true end;", method_shards[ret_shards[2]], fn_ret2, k_mode, obf2, k_retv, k_retf, k_rett));
        // ㉚：RET 别名等价挂接（方法表同一函数体多入口名）
        for (ret_base, ret_pool) in &ret_alias_map {
            for al in ret_pool.iter().skip(1) {
                let ret_index = if ret_base == &fn_ret0 { 0 } else if ret_base == &fn_ret1 { 1 } else { 2 };
                block_methods.push_str(&format!("{}.{}={}.{};", method_shards[ret_shards[ret_index]], al, method_shards[ret_shards[ret_index]], ret_base));
            }
        }



        let fn_s_byte = rng.name(); let fn_s_sub = rng.name(); let var_raw_p = rng.name(); let var_p = rng.name(); let var_a2 = rng.name(); let fn_a3 = rng.name(); let x = rng.name(); let var__a = rng.name(); let var__b = rng.name(); let fn_read_dec = rng.name(); let fn_bxor = rng.name(); let fn_b_rotr = rng.name(); let fn_a5 = rng.name(); let fn_read_string = rng.name(); let fn_a10 = rng.name(); let fn_decode_chunk = rng.name(); let fn_u32_dec = rng.name(); let l = rng.name(); let s_t = rng.name(); let v = rng.name(); let v_sign = rng.name(); let v_exp = rng.name(); let v_mant = rng.name(); let t = rng.name(); let fn_c = rng.name();
        // 数组槽位只读一次（热路径每指令都读会白花 4 次哈希查找）
        let arrs = format!("{}, {}, {}, {}", var_opcodes, var_a_arr, var_b_arr, var_c_arr);
        block_execute_def.push_str(&format!("local {};{}={}[{}],{}[{}],{}[{}],{}[{}];", arrs, arrs, var_vm, k_ops, var_vm, k_aa, var_vm, k_bb, var_vm, k_cc));
        // pc/top 是**循环外**的局部变量
        // 常量路径态采用 PC 势函数：每步按实际 next-PC 增量推进，合法分支在同一
        // 汇合点、循环回边都归一到同一值；常量代理表只通过随机负键暂存此态。
        let const_path_key = format!("(-0X{:X})", rng.range(0x10000, 0x7FFF_FFFF) as u32);
        let const_path_state = rng.name();
        let const_path_prev_pc = rng.name();
        let const_path_mul = (rng.range(0x1001, 0xFFFF) as u32) | 1;
        let const_path_add = rng.next();
        let const_path_op_mix = (rng.range(0x101, 0xFFFF) as u32) | 1;
        let const_path_a_mix = (rng.range(0x101, 0xFFFF) as u32) | 1;
        let const_path_b_mix = (rng.range(0x101, 0xFFFF) as u32) | 1;
        let const_path_c_mix = (rng.range(0x101, 0xFFFF) as u32) | 1;
        // ㉑ 保守版明文窗口变量：NP(原型数)/MD(=C.pr 别名)/TH(thunk 快照)/tw(回收水位)
        let (np21, md21, th21, tw21) = (rng.name(), rng.name(), rng.name(), rng.name());
        // ⑱.4 驻留收紧：水位步长从 0x8000~0x40000 降到 0x2000~0x8000——
        // proto 明文窗口按 1/4~1/8 频率写回 thunk，dump 窗口随之缩短
        let step21 = rng.range(0x2000, 0x8000);
        // 中危刀1 纪元换钥：每 rn 次水位事件重派生 kp/pb 并原位重掩码三数组
        //（旧钥即弃，跨时刻两份 dump 无法互推；rn 放大换钥摊销成本）
        let rk21 = rng.name();
        let rkey_every = rng.range(4, 16);
        let kreg_n = rng.name();
        let poison_delay_key = rng.range(0x7000_0000, 0x7FFF_FFFF) as u32;
        let poison_delay_expr = format!("{}[0X{:X}]", kreg_n, poison_delay_key);
        // 冷块调用前后由调用点负责与 VM 对象的槽位同步。
        block_execute_def.push_str(&format!("local {},{}={}[{}],{}[{}];", var_pc, var_top, var_vm, k_pc, var_vm, k_top));
        block_execute_def.push_str(&format!(
            "local {state}=({pc}*0X{mul:X}+0X{add:X})%0X100000000;",
            state = const_path_state, pc = var_pc, mul = const_path_mul, add = const_path_add));

        // ⑱.4 数组驻留掩码：body_insts 存的是逐原型掩码值（K 从 kp/pb 派生，同式）。
        // 中危刀1 密钥分驻：pf_ld（仅掩码用）从 chunk 蒸发进弱键注册表 KREG（键=chunk）；
        // pf_lld 是入口 pc 基址（每次入口读）必须留在 chunk——半分量分驻+换钥兜底
        // 数据流打散（本轮）：钥匙派生不再走单一「ka→三元组→升序三存」线性模板——
        // 拓扑池（0=原版保留在池中）× 存储语句乱序（(槽,值) 配对恒定，只换时间序）。
        // 全变体输出恒等：ma=bx(kon,lld)、mb=bx(kon,ma)、mc=bx(lld,ma)。入口一次，跳数无感。
        let bx_s = fn_bxor2.as_str();
        let lld_ref = format!("{}.{}", "chunk", pf_lld);
        let st_ma = format!("{}[{}]={};", var_vm, k_mk1, n_mk1);
        let st_mb = format!("{}[{}]={};", var_vm, k_mk2, n_mk2);
        let st_mc = format!("{}[{}]={};", var_vm, k_mk3, n_mk3);
        let deriv = match rng.range(0, 4) {
            0 => format!(
                "local {ka}={bx}({kon},{lld}); local {ma},{mb},{mc}={ka},{bx}({kon},{ka}),{bx}({lld},{ka}); {s1}{s2}{s3}",
                ka = n_ka, bx = bx_s, kon = n_kon, lld = lld_ref,
                ma = n_mk1, mb = n_mk2, mc = n_mk3, s1 = st_ma, s2 = st_mb, s3 = st_mc),
            1 => {
                // 实参交换 + 逐条派生 + 存储乱序
                let mut ord = vec![st_ma, st_mb, st_mc];
                rng.shuffle(&mut ord);
                format!(
                    "local {ka}={bx}({lld},{kon}); local {mc}={bx}({lld},{ka}); local {mb}={bx}({ka},{kon}); local {ma}={ka}; {o1}{o2}{o3}",
                    ka = n_ka, bx = bx_s, lld = lld_ref, kon = n_kon,
                    ma = n_mk1, mb = n_mk2, mc = n_mk3, o1 = ord[0], o2 = ord[1], o3 = ord[2])
            }
            2 => {
                // ma 链根（无 ka 临时）+ 算完即存；mb/mc 计算序随机（槽时序随计算序）
                let root = format!("local {ma}={bx}({kon},{lld}); {sma}",
                    ma = n_mk1, bx = bx_s, kon = n_kon, lld = lld_ref, sma = st_ma);
                let mb_line = format!("local {mb}={bx}({kon},{ma}); {smb}",
                    mb = n_mk2, bx = bx_s, kon = n_kon, ma = n_mk1, smb = st_mb);
                let mc_line = format!("local {mc}={bx}({lld},{ma}); {smc}",
                    mc = n_mk3, bx = bx_s, lld = lld_ref, ma = n_mk1, smc = st_mc);
                let mut lines = vec![mb_line, mc_line];
                rng.shuffle(&mut lines);
                format!("{} {} {}", root, lines[0], lines[1])
            }
            _ => {
                // 拆条派生 + 存储全乱序（6 排列）
                let mut ord = vec![st_ma, st_mb, st_mc];
                rng.shuffle(&mut ord);
                format!(
                    "local {ka}={bx}({kon},{lld}); local {mb}={bx}({kon},{ka}); local {mc}={bx}({lld},{ka}); local {ma}={ka}; {o1}{o2}{o3}",
                    ka = n_ka, bx = bx_s, kon = n_kon, lld = lld_ref,
                    ma = n_mk1, mb = n_mk2, mc = n_mk3, o1 = ord[0], o2 = ord[1], o3 = ord[2])
            }
        };
        // 目标二③（第二部分）：chunk.{cnt} 不再在读侧入口抹掉——DC 惰性填充用它
        // 与 pf_lld 一起算本原型记录段的上界（越界 pc 不再走进邻接原型的记录）。
        block_execute_def.push_str(&format!(
            "local {kon}={kreg}[{c}]; if not {kon} then {kon}={c}.{ld}; {kreg}[{c}]={kon},{c}.{cnt}; end; {deriv} ",
            kon = n_kon, kreg = kreg_n, c = "chunk", ld = pf_ld, cnt = pf_cnt18, deriv = deriv));
        // 改进项一：指令惰性解码器改为原生 Lua 闭包内联（彻底消除 loadstring/StreamTable 源码级暴露），
        // 状态表 5 个字段名（原 .n/.ch/.m1/.m2/.m3）全量随机化，内层 3 态+1 诱饵态平坦化分发。
        let (ds_n, ds_ch, ds_m1, ds_m2, ds_m3) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        {
            let (factory_prefix, init_dc_stmt) = crate::VM::VM_Backend::Generator_util::build_inst_decoder_lua(
                &mut rng,
                fn_bxor2.as_str(),
                chain_delta,
                chain_m,
                chain_k0,
                var_opcodes.as_str(),
                var_a_arr.as_str(),
                var_b_arr.as_str(),
                var_c_arr.as_str(),
                dc_ds.as_str(),
                n_dc.as_str(),
                pf_lld.as_str(),
                n_kon.as_str(),
                n_mk1.as_str(),
                n_mk2.as_str(),
                n_mk3.as_str(),
                var_vm.as_str(),
                k_dc.as_str(),
                pf_cnt18.as_str(),
                (ds_n.as_str(), ds_ch.as_str(), ds_m1.as_str(), ds_m2.as_str(), ds_m3.as_str()),
            );
            block_execute_def.insert_str(0, &factory_prefix);
            block_execute_def.push_str(&init_dc_stmt);
        }
        let dispatch_state = crate::VM::VM_Backend::Generator_util::build_dispatch_state(&mut rng, &psn_n, &poison_delay_expr);
        if tree_entries.is_empty() {
            // 理论上不会发生（没有任何 handler）；保留原先的一次空转后退出语义。
            let split = crate::VM::VM_Backend::Generator_flow_split::wrap_for_build(
                "", "", false, "chunk", fn_execute, self.ctx.seed, tree_entries.len(),
            );
            block_execute_def.push_str(&split);
            block_execute_def.push_str(" end ");
        } else {
            let mut dispatch_body = String::new();
            dispatch_body.push_str(&format!("{}={};", var_state_flag, "true"));
            dispatch_body.push_str(&dispatch_state.guard);
            dispatch_body.push_str(&format!(
                "local {prev}={pc};",
                prev = const_path_prev_pc, pc = var_pc));

            // ㉚ 目标①：取指改走 DC 缓存（元表前向填充=结构解码；单条公式全解作废）。
            // 条目={mag+Δ, a, B, C}（链偏移撤销+奇偶交换都在填充内完成）；
            // 四字段赋值对洗牌发射（名字↔下标配对恒定，只换书写序——纯外观差异）。
            dispatch_body.push_str(&format!("local inst_t={}[{}];", n_dc, var_pc));
            {
                let mut prs: Vec<(&str, u32)> = vec![("op", 1), ("inst_A", 2), ("inst_B", 3), ("inst_C", 4)];
                rng.shuffle(&mut prs);
                let lhs: Vec<String> = prs.iter().map(|(n, _)| n.to_string()).collect();
                let rhs: Vec<String> = prs.iter().map(|(_, i)| format!("inst_t[{}]", i)).collect();
                dispatch_body.push_str(&format!("local {}={}; ", lhs.join(","), rhs.join(",")));
            }
            // 热路径：pc 就是普通局部变量，推进也用普通字面量
            dispatch_body.push_str(&format!("{}={}+1;", var_pc, var_pc));
            // 同一 PC 上的操作码与三个实际操作数混入本次常量态；分支汇合处因指令
            // 记录固定而自动收敛，路径间不同的执行前缀则通过 PC 势函数统一归一。
            dispatch_body.push_str(&format!(
                "{vm}[{ck}][{key}]=({state}+op*0X{om:X}+inst_A*0X{am:X}+inst_B*0X{bm:X}+inst_C*0X{cm:X})%0X100000000;",
                vm = var_vm, ck = k_consts, key = const_path_key, state = const_path_state,
                om = const_path_op_mix, am = const_path_a_mix, bm = const_path_b_mix, cm = const_path_c_mix));
            dispatch_body.push_str(&format!("local {}=op+{};", dispatch_state.route_op, dispatch_state.bias));

            dispatch_body.push_str(&format!("local rk1,rk2;local {},{},{};", var_r1, var_r2, var_r3));
            dispatch_body.push_str(&crate::VM::VM_Backend::Generator_flow_split::build_relay_dispatch(&tree_entries, &var_pc, &var_top, &var_r1, &var_r2, &var_r3, &dispatch_state.route_op, &dispatch_state.bias, fn_execute, self.ctx.seed));
            dispatch_body.push_str(&format!(
                "{state}=({state}+({pc}-{prev})*0X{mul:X})%0X100000000;",
                state = const_path_state, pc = var_pc, prev = const_path_prev_pc, mul = const_path_mul));
            dispatch_body.push_str(&dispatch_state.update);
            dispatch_body.push_str(&format!("if {} then local {}={}[{}]; if {}=={} then return {}[{}] elseif {}=={} then return unpack({}[{}],{}[{}],{}[{}]) end; return end;", var_r1, var_md, var_vm, k_mode, var_md, obf1, var_vm, k_retv, var_md, obf2, var_vm, k_retv, var_vm, k_retf, var_vm, k_rett));
            // ㉑ 周期性明文回收：pc 水位过阈值→全部原型槽写回 thunk（密文）；
            // 活跃闭包持有明文引用不受影响；未来 CLOSURE 经 type(p)=='function' 重解
            // 换钥高频路径零新增调用：嵌套双 bx 拆平（5 次→3 次）+ 声明序/实参对/存储乱序
            let (lv_n, nk1_n, na_n, nb_n, nc_n, d1_n, d2_n, d3_n, ri_n) =
                (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let bx_s2 = fn_bxor2.as_str();
            let nn_seg = {
                let na_e = format!("{}({},{})", bx_s2, nk1_n, lv_n);
                let (nb_a, nb_b) = if rng.range(0, 2) == 0 { (nk1_n.clone(), na_n.clone()) } else { (na_n.clone(), nk1_n.clone()) };
                let (nc_a, nc_b) = if rng.range(0, 2) == 0 { (lv_n.clone(), na_n.clone()) } else { (na_n.clone(), lv_n.clone()) };
                let nb_e = format!("{}({},{})", bx_s2, nb_a, nb_b);
                let nc_e = format!("{}({},{})", bx_s2, nc_a, nc_b);
                if rng.range(0, 2) == 0 {
                    format!("local {a}={nae}; local {b}={nbe}; local {c}={nce};", a=na_n, b=nb_n, c=nc_n, nae=na_e, nbe=nb_e, nce=nc_e)
                } else {
                    format!("local {a}={nae}; local {c}={nce}; local {b}={nbe};", a=na_n, b=nb_n, c=nc_n, nae=na_e, nbe=nb_e, nce=nc_e)
                }
            };
            let dline_seg = {
                let mut parts = Vec::new();
                for trio in [(&d1_n, &n_mk1, &na_n), (&d2_n, &n_mk2, &nb_n), (&d3_n, &n_mk3, &nc_n)] {
                    let (dn, mn, xn) = trio;
                    let e = if rng.range(0, 2) == 0 {
                        format!("{}({},{})", bx_s2, mn, xn)
                    } else {
                        format!("{}({},{})", bx_s2, xn, mn)
                    };
                    parts.push(format!("local {}={};", dn, e));
                }
                parts.join(" ")
            };
            let rk_tail_seg = {
                let mut stmts = vec![
                    format!("{}[{}]={};", var_vm, k_mk1, na_n),
                    format!("{}[{}]={};", var_vm, k_mk2, nb_n),
                    format!("{}[{}]={};", var_vm, k_mk3, nc_n),
                ];
                rng.shuffle(&mut stmts);
                // ㉚：DC 填充从状态表读掩码——换钥后把新钥同步进 ds（使用随机化字段名），
                // 否则后续填充用旧钥解新掩码数组→垃圾条目。
                format!("{}[{}][1]={}; {}{}{} {},{},{}={},{},{}; {}.{}={}; {}.{}={}; {}.{}={}; ",
                    kreg_n, "chunk", nk1_n, stmts[0], stmts[1], stmts[2],
                    n_mk1, n_mk2, n_mk3, na_n, nb_n, nc_n,
                    dc_ds, ds_m1, na_n, dc_ds, ds_m2, nb_n, dc_ds, ds_m3, nc_n)
            };
            // ㉒② 焊接 2^32 模数（execute 换钥分支每次重走——第二次起逻辑无分支）；
            // ㉒① thunk 回写环、寄存器键轮换环 → 动态分段数值游标机
            // （execute 作用域内 P 表已建，状态常数走 obfuscate_num 的运行时查表表示）。
            let w2_dst = weld.dst();
            let w2_mv = crate::VM::VM_Backend::Generator_kdf::kdf_m32(&mut rng);
            let w2_stmt = format!("local {};", w2_dst) + &weld.weld(&mut rng, &w2_dst, &w2_mv);
            let md_walk = {
                let (md2, th2) = (md21.clone(), th21.clone());
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("if {nt}({md}[{iv}])=='table' then {md}[{iv}]={th}[{iv}] end; ", nt = native_type, md = md2, th = th2, iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_dyn(&mut rng, Some(&keys), off, &format!("#{}", md21), 2, 3, &unit)
            };
            let rot_walk = {
                let (aa2, bb2, cc2, d12, d22, d32, bx2) = (var_a_arr.clone(), var_b_arr.clone(), var_c_arr.clone(), d1_n.clone(), d2_n.clone(), d3_n.clone(), fn_bxor2.clone());
                let off = rng.range(0, 100);
                let nexp = format!("{}[chunk][2]", kreg_n);
                let unit = |iv: &str| format!("{aa}[{iv}]={bx}({aa}[{iv}],{d1}); {bb}[{iv}]={bx}({bb}[{iv}],{d2}); {cc}[{iv}]={bx}({cc}[{iv}],{d3}); ", aa = aa2, bb = bb2, cc = cc2, bx = bx2, d1 = d12, d2 = d22, d3 = d32, iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_dyn(&mut rng, Some(&keys), off, &nexp, 3, 3, &unit)
            };
            dispatch_body.push_str(&format!(
                "if {flg} and {pc}>{tw} then {tw}={pc}+0X{sx:X}; {mdw} \
                 {rk}={rk}+0X1; if {rk}>={rn} then {rk}=0X0; \
                   local {kmt}=getmetatable({kreg}); local {kold}={kreg}; {kreg}=setmetatable({{}},{{}}); setmetatable({kreg},{kmt}); for {kc1},{kv1} in {pairs_fn}({kold}) do {kreg}[{kc1}]={kv1} end; \
                   local {lv}={c}.{lld}; {w2} local {nk1}={bx}({kon},{pc}%{m32})%{m32}; {nn} \
                   {dline} \
                   {rotw} \
                   {rk_tail} \
                 end end; ",
                flg = format!("({}) and true", var_state_flag), pc = var_pc, tw = tw21, sx = step21,
                mdw = md_walk,
                rk = rk21, rn = rng.format_num(rkey_every as i64),
                bx = fn_bxor2.as_str(),
                lld = pf_lld, kon = n_kon,
                w2 = w2_stmt, m32 = w2_dst,
                nk1 = nk1_n, lv = lv_n,
                nn = nn_seg, dline = dline_seg, rk_tail = rk_tail_seg,
                kreg = kreg_n, c = "chunk", rotw = rot_walk, pairs_fn = native_pairs,
                kmt = rng.name(), kold = rng.name(), kc1 = rng.name(), kv1 = rng.name()));
            dispatch_body.push_str(&format!("{}={};", var_state_flag, "false"));
            let split = crate::VM::VM_Backend::Generator_flow_split::wrap_for_build(
                &dispatch_state.setup, &dispatch_body, true, "chunk",
                fn_execute, self.ctx.seed, tree_entries.len(),
            );
            block_execute_def.push_str(&split);
            block_execute_def.push_str(" end ");
            // ① 热区常量折叠（派发环里参数全为字面量的键表调用；语义逐位等价）
            block_execute_def = crate::VM::VM_Backend::Generator_util::fold_const_keycalls(&block_execute_def, &keys);
        }

        let block_decoder_script = decoder_script.replace("\n", " ");
        
        let var_boot_env = rng.name();

        let fn_qr = rng.name();
        let fn_xor32 = rng.name();
        let fn_rotl32 = rng.name();
        let xor_tbl_var = rng.name();

        // ChaCha 的 4 个 sigma 常量（"expand 32-byte k"）不以字面量出现在产物里；
        // ⑯ 每组独立派生：sigma_i=(d_i+K_g[idx_i])%2^32，idx 是每组自己的 [1..8] 洗牌排列
        let sigma: [u32; 4] = crate::VM::VM_Backend::Generator_chacha::SIGMA;


        // phase 2 已原样搬至 Generator_chain.rs（README 单文件 ≤ 80 KB 规则）。
        Generator_chain::build_chain(Generator_chain::ChainIn {
            rng, at, keys, enc, sigma,
            var_whiten,
            var_whiten_pos,
            whiten_mul,
            whiten_add,
            fn_a3, fn_bxor, fn_c, fn_decode_chunk, fn_s_byte, fn_s_sub, pf_a_arr, pf_b_arr, pf_c_arr, pf_is_vararg,
            pf_ld, pf_lld, pf_maxstack, pf_n, pf_numparams, pf_nups, pf_opcodes, pf_protos, psn_n, poison_delay_key, var_a2,
            var_builtin_reg, var_p, var_raw_p, var_vc, native_type, native_pairs, np21,
            md21, th21, tw21, rk21, kreg_n,
            fn_execute, bc_kb, bc_kc, bc_ki1, bc_ki2, chain_delta, chain_m, chain_k0, sc_add, sc_add_k1, sc_mul_k2, sc_rot_in, sc_rot_k2, sc_rot_k4, tag_map18, fc18, block_decoder_script, block_execute_def, block_methods, block_p_def, block_packer_vars, block_vm_core, entry_func, fn_a10, fn_a5, fn_b_rotr, fn_qr, fn_read_dec, fn_read_string, fn_rotl32, fn_u32_dec, fn_xor32, header_block, key_seed_var, payload_str, pf_cnt18, pf_consts, const_path_key, sk_setup, t, x, var_boot_env, var_l, var_state_flag, wai, xor_tbl_var,
            weld,
            uni,
        })
    }
}


#[cfg(test)]
mod payload_crypto_tests {
    use super::{roll_decrypt_byte, roll_encrypt_byte, whiten_byte, RollParams};

    #[test]
    fn whitening_and_rolling_layers_round_trip_with_state_continuity() {
        let params = RollParams { add: 0xA5, rot_in: 3, add_k1: 5, mul_k2: 7, rot_k2: 2, rot_k4: 6 };
        let input: Vec<u8> = (0..=255).chain((0..=127).rev()).collect();
        let (mul, add, seed) = (0x1_2345, 0x1234_5678, 0x6543_210);
        let mut enc_state = [0x12, 0xA7, 0x5C, 0xE1];
        let mut cipher = Vec::with_capacity(input.len());
        for (idx, &plain) in input.iter().enumerate() {
            let pos = idx as u64 + 5;
            let white = plain ^ whiten_byte(seed, pos, mul, add);
            cipher.push(roll_encrypt_byte(&mut enc_state, pos, white, params));
        }

        let mut dec_state = [0x12, 0xA7, 0x5C, 0xE1];
        let mut recovered = Vec::with_capacity(input.len());
        for (idx, &byte) in cipher.iter().enumerate() {
            let pos = idx as u64 + 5;
            let white = roll_decrypt_byte(&mut dec_state, pos, byte, params);
            recovered.push(white ^ whiten_byte(seed, pos, mul, add));
        }
        assert_eq!(recovered, input);
        assert_eq!(dec_state, enc_state);
        assert_ne!(cipher, input);
    }
}
