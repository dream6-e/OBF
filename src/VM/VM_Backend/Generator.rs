use crate::VM::VM_Backend::Context::VmContext;
use crate::VM::VM_Backend::Lua_core;
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use crate::compiler::instructions::{OpCode, OpMode, OpArgMask};
use std::collections::HashSet;
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;
use super::AntiTamper;
use super::Generator_chain;
pub(crate) static DBG_MASK: bool = true;
pub(crate) static DBG_PROXY: bool = true;
pub(crate) static DBG_ARITH: bool = true;

// 底层工具层已拆到 Generator_util.rs（原文件 69 KB 太大）。
// GenRng 继续从这里 re-export，保持 crate 内既有的引用路径不变。
pub use super::Generator_util::{CipherKeys, GenRng};
use super::Generator_util::{
    build_opcode_tree, chacha8_xor, rename_ident, rewrite_chunk, scan_max_stack,
    scan_setglobal_targets, scan_used_opcodes, uses_ident, write_string, PayloadReader,
};


pub struct Generator { ctx: VmContext }

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
        
        let key_seed_var = rng.name();
        // ㉒② 焊接缓存：三张缓存表随产物生成，供第二/三阶段各站点发射焊接构造。
        let mut weld = crate::VM::VM_Backend::Generator_util::WeldCache::new(&mut rng);
        // ㉓ 统一流：packer 脚本串/探测九件套/守卫散点串共用的一条密钥流（惰性解密）。
        let mut uni = crate::VM::VM_Backend::Generator_util::UniStream::new(&mut rng);
        let mut at = AntiTamper::generate_split(true, &key_seed_var);
        
        let mut used_ops = HashSet::new();
        { let mut scan_reader = PayloadReader { data: payload, pos: 0 }; scan_used_opcodes(&mut scan_reader, &mut used_ops); }

        let mut setglobal_targets: HashSet<Vec<u8>> = HashSet::new();
        let setglobal_op = self.ctx.opcode_map[7];
        let getglobal_op = self.ctx.opcode_map[5];
        let getglobalstr_op = self.ctx.opcode_map[56];
        let mut inverse_opcode_map = [0u8; 90];
        for i in 0..90 { inverse_opcode_map[self.ctx.opcode_map[i] as usize] = i as u8; }
        let builtin_slot_perm = Opcodes::builtins::slot_permutation(self.ctx.seed);
        { let mut sg_reader = PayloadReader { data: payload, pos: 0 }; scan_setglobal_targets(&mut sg_reader, &mut setglobal_targets, setglobal_op); }

        let mut mapped_opcodes: [Vec<u32>; Opcodes::builtins::TOTAL_OPCODES] = std::array::from_fn(|_| Vec::new());
        let mut fused_opcodes: [Vec<u32>; Opcodes::builtins::FUSED_OP_COUNT] = std::array::from_fn(|_| Vec::new());
        let mut transpile_map: [Vec<u32>; 90] = std::array::from_fn(|_| Vec::new());
        {
            let mut map_rng = StdRng::seed_from_u64(self.ctx.seed);
            let mut used = std::collections::HashSet::new();
            for i in 0..90 {
                let shuffled_val = self.ctx.opcode_map[i];
                let count = if used_ops.contains(&shuffled_val) { map_rng.random_range(3..=6) } else { 1 };
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); transpile_map[shuffled_val as usize].push(val); break; }
                    }
                }
            }
            for i in 90..Opcodes::builtins::TOTAL_OPCODES {
                let count = map_rng.random_range(3..=6);
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); break; }
                    }
                }
            }
            // 融合指令（SuperOperator）也各分一组别名，和 builtin-load 一样按 slot 索引
            for i in 0..Opcodes::builtins::FUSED_OP_COUNT {
                let count = map_rng.random_range(3..=6);
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
        // 反混淆判据③修复（寄存器平移）：所有原型寄存器统一平移 G。G 的上限由
        // 全原型最大 maxstack 钉死（平移后寄存器必须仍 <128，否则撞 RK 常量域）；
        // execute 入口的实参落位同步 +G（见 block_execute_def）。
        let gshift: u8 = {
            let mut max_stack_all = 0u8;
            let mut scan_reader = PayloadReader { data: payload, pos: 0 };
            scan_max_stack(&mut scan_reader, &mut max_stack_all);
            if max_stack_all < 127 {
                let cap = (127u8 - max_stack_all).min(48);
                rewrite_rng.random_range(1u8..=cap.max(1))
            } else { 0 }
        };
        let mut fused_used: HashSet<usize> = HashSet::new();
        // ⑰ 常量按原型分组内联加密：每组独立 key/salt/nonce 布局/kind；
        // 密文直接写进各原型常量节，中央 gs/gn 密文表废除
        const CG: usize = crate::VM::VM_Backend::Generator_util::CONST_GROUPS;
        let mut chacha_keys: Vec<[u32; 8]> = Vec::with_capacity(CG);
        for _ in 0..CG { let mut row = [0u32; 8]; for v in row.iter_mut() { *v = rng.next(); } chacha_keys.push(row); }
        let mut chacha_salts: Vec<u32> = Vec::with_capacity(CG);
        for _ in 0..CG { chacha_salts.push(rng.next()); }
        let mut nonce_layouts: Vec<[usize; 3]> = Vec::with_capacity(CG);
        for _ in 0..CG {
            let mut ly = [0usize, 1, 2];
            for j in (1..3).rev() { let k = rng.range(0, j + 1); ly.swap(j, k); }
            nonce_layouts.push(ly);
        }
        let mut kstr: Vec<u32> = Vec::with_capacity(CG);
        let mut knum: Vec<u32> = Vec::with_capacity(CG);
        for _ in 0..CG { kstr.push(rng.next()); knum.push(rng.next()); }
        let enc = crate::VM::VM_Backend::Generator_util::EncCtx { keys: chacha_keys.clone(), salts: chacha_salts.clone(), layouts: nonce_layouts.clone(), kstr, knum };
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
        // #3 折叠参数：谓词 pv(v)=(rotl32(v,r)^p1)%100<p3、f(pc)=(pc*f1)^f2 —— 逐产物随机，
        // Rust 写侧与 Lua body_consts 扫描两侧同式（静态读产物得不出「哪些 op 参与」）
        let fc18 = crate::VM::VM_Backend::Generator_util::FoldCtx {
            r6b: rng.range(1, 17) as u32, p1b: rng.next(), p3b: rng.range(30, 70) as u32,
            r6c: rng.range(1, 17) as u32, p1c: rng.next(), p3c: rng.range(30, 70) as u32,
            f1: rng.next() | 1, f2: rng.next(),
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
        let mut proto_sites_root: Vec<(usize, u32)> = rewrite_chunk(&mut reader, &mut rewritten_chunks, &transpile_map, &mapped_opcodes, &fused_opcodes, &mut fused_used, &setglobal_targets, getglobal_op, getglobalstr_op, &inverse_opcode_map, &builtin_slot_perm, &op_magic, &enc, root_group, &mut rewrite_rng, bc_kb, bc_kc, bc_ki1, bc_ki2, &fc18, &tag_map18, gshift);

        // ⑰ 中央密文池废除：payload = 4 字节滚动密钥 + 各原型常量节（密文内联）
        let mut combined_payload = Vec::new();
        let (mut k1, mut k2, mut k3, mut k4) = ((rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8);
        combined_payload.push(k1); combined_payload.push(k2); combined_payload.push(k3); combined_payload.push(k4);
        
        combined_payload.extend(rewritten_chunks);

        // 对 4 字节密钥之后的**全部内容**做同一道滚动字节变换 —— 常量池和指令流
        // 共用一条连续的 keystream。指令流此前是明文追加的，固定 10 字节一条
        // 剥掉外层 base86 之后可以直接切片还原；现在和池一样被覆盖。
        // Lua 侧的 chunk 读取器相应改成走 fn_read_dec（见 block_dec_readers）。
        // ⑤ 滚动层常数逐产物随机（正向这五个数在 Rust 侧，逆向在 Lua 读取器里
        // 两边由下面这组变量同时生成 —— 抓产物的人看到的是另一组数）
        let sc_add: u8 = (rng.range(0, 128) * 2 + 1) as u8; // 奇数 1..255
        let sc_rot_in: u32 = rng.range(1, 8) as u32;
        let sc_add_k1: u8 = rng.range(1, 8) as u8;
        let sc_mul_k2: u8 = rng.range(2, 8) as u8;
        let sc_rot_k2: u32 = rng.range(1, 8) as u32;
        let sc_rot_k4: u32 = rng.range(1, 8) as u32;
        // ⑱.2 尺寸前缀掩码：ln=child_len ^ f(站点密钥状态, 层内序号)。站点=(payload
        // 偏移(+4 种子), 层内 1-based 序号)；掩码在本循环里在线取站点首字节前的
        // k1..k4 计算（与 Lua body_protos 读 ln 前快照同一状态），4 字节就地异或后
        // 再走正常滚动变换——orig 取异或后的值，与 Lua 解出字节一致。
        let (pm_r0, pm_r1, pm_r2, pm_r3) = (rng.range(1, 8) as u32, rng.range(1, 8) as u32, rng.range(1, 8) as u32, rng.range(1, 8) as u32);
        let pm_s: [u64; 8] = [rng.range(1, 255) as u64, rng.range(0, 255) as u64, rng.range(1, 255) as u64, rng.range(0, 255) as u64, rng.range(1, 255) as u64, rng.range(0, 255) as u64, rng.range(1, 255) as u64, rng.range(0, 255) as u64];
        for (off, _) in proto_sites_root.iter_mut() { *off += 4; }
        proto_sites_root.sort_by_key(|e| e.0);
        let pm_g = |x: u8, y: u8, r: u32, sv: u8| (x ^ y).rotate_left(r).wrapping_add(sv);
        let pm_sb = |i: u64, j: usize| -> u8 { (i.wrapping_mul(pm_s[j * 2]).wrapping_add(pm_s[j * 2 + 1]) & 0xFF) as u8 };
        let mut pm_cur: Option<(usize, [u8; 4])> = None;
        let mut pm_i = 0usize;
        for (pos4, b) in combined_payload[4..].iter_mut().enumerate() {
            let pos = pos4 + 4;
            if pm_cur.map_or(false, |(sp, _)| pos >= sp + 4) { pm_cur = None; }
            if pm_i < proto_sites_root.len() && proto_sites_root[pm_i].0 == pos {
                let idx18 = proto_sites_root[pm_i].1 as u64;
                let sv = [pm_sb(idx18, 0), pm_sb(idx18, 1), pm_sb(idx18, 2), pm_sb(idx18, 3)];
                pm_cur = Some((pos, [pm_g(k1, k4, pm_r0, sv[0]), pm_g(k2, k1, pm_r1, sv[1]), pm_g(k3, k2, pm_r2, sv[2]), pm_g(k4, k3, pm_r3, sv[3])]));
                pm_i += 1;
            }
            if let Some((sp, mb)) = pm_cur { if pos < sp + 4 { *b ^= mb[pos - sp]; } }
            let orig = *b;
            *b = orig ^ k1; *b = b.wrapping_sub(k2); *b = b.rotate_left((k3 % 8) as u32); *b = *b ^ k4; *b = b.wrapping_add(sc_add);
            k1 = k1.wrapping_add(orig).rotate_left(sc_rot_in).wrapping_add(sc_add_k1);
            k2 = k2.wrapping_mul(sc_mul_k2).wrapping_add(*b).rotate_right(sc_rot_k2);
            k3 = k3 ^ k1.wrapping_sub(k4);
            k4 = k4.wrapping_add(k2).rotate_left(sc_rot_k4);
        }
        
        let key_kryvex = String::from("x1"); let p_out: Vec<String> = (0..6).map(|_| rng.name()).collect();
        let var_s = rng.name(); let fn_N_ = rng.name(); let var_fU = rng.name(); let var_L = rng.name(); let var_get_count = rng.name();
        let hex_select_idx = format!("0X{:X}", rng.range(10, 255));
        let var_state_flag = rng.name();
        let wai = rng.name();
        let mut header_block = String::new();
        // ㉓ 外壳由 build_chain 统一包（return((function() 前导 return({ ... })end)()):fu()），
        // 这里只产「字段表体」——前导落在 IIFE 内、return({}) 壳表达式内。
        header_block.push_str(&format!("{{ {} = function(agv,aggv,agv,agv,agv,aggv,agv,agv,aggv,aggv,aggv,agggv,agggv,agggv,agggv,aggv,{},{},{},{}, ...)\n", wai, p_out[0], p_out[1], p_out[2], p_out[3]));
        header_block.push_str(&format!("local {} = {{}}; local {} = false; ", var_s, var_state_flag));
        header_block.push_str(&format!("local {} = bit32 and bit32.rshift or bit and bit.rshift; ", var_fU));
        header_block.push_str(&format!("local {} = function(q, s, M, C) s[{}] = select; end; ", fn_N_, hex_select_idx));
        header_block.push_str(&format!("{}(nil, {}, nil, nil); ", fn_N_, var_s));
        
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
        block_p_def.push_str(&format!("local qT4c={{}};for i=0,15 do qT4c[i]={{}};for j=0,15 do local r,p=0,1;local x,y=i,j;for k=1,4 do local rx,ry=x%2,y%2;if rx~=ry then r=r+p end;x=(x-rx)/2;y=(y-ry)/2;p=p+p end;qT4c[i][j]=r end end;local qT8c={{}};for i=0,255 do qT8c[i]={{}};end;for i=0,255 do local qIc=qT8c[i];local qHc=(i-i%16)/16;for j=0,255 do qIc[j]=qT4c[i%16][j%16]+qT4c[qHc][(j-j%16)/16]*16 end end; local {}={}; local {}={}; local {}={}; local {}={}; ",
            fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b) local r,p=0,1;for k=1,4 do local x,y=a%256,b%256;r=r+qT8c[x][y]*p;a=(a-x)/256;b=(b-y)/256;p=p*256 end;return r end",
            fn_ba, "bit32 and bit32.band or bit and bit.band or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end",
            fn_bs, "bit32 and bit32.rshift or bit and bit.rshift or function(a,n)local d=2^n return (a-a%d)/d end",
            fn_bxor2, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b) local r,p=0,1;for k=1,4 do local x,y=a%256,b%256;r=r+qT8c[x][y]*p;a=(a-x)/256;b=(b-y)/256;p=p*256 end;return r end"
        ));
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
        let var_junk = rng.name(); let var_vc = rng.name(); let var_builtin_reg = rng.name();
        let block_packer_vars = format!("local {}, {}, {}; ", var_junk, var_vc, var_builtin_reg);

        let fn_execute = "execute";
        // 诱饵投毒旗（prelude 局部）：守卫失败/诱饵 handler 置位 → 后续常量解码
        // 全部 type-preserving 扰乱——程序继续跑、不报错、输出乱码（用户指示）
        let psn_n = rng.name();
        let var_pc = rng.name();
        let var_stk = rng.name();
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
        let var_methods = rng.name(); // 共享方法表（所有调用共用一个）
        let var_proto = rng.name();   // 状态对象的元表（__index → 方法表）
        let mut block_execute_def = String::new();
        
        let cfg = OpcodeConfig { pc: var_pc.clone(), stk: var_stk.clone(), consts: var_consts.clone(), top: var_top.clone(), insts: var_insts.clone(), inst: var_inst.clone(), upvals: var_upvals.clone(), env: var_env.clone(), protos: var_protos.clone(), handlers: String::new(), varargs: var_varargs.clone(), varargs_len: var_varargs_len.clone(), virtual_closures: var_vc.clone(), builtin_reg: var_builtin_reg.clone(), vararg_count: pf_vn.clone(), proto_nups: pf_nups.clone(), open_ups: pf_open_ups.clone(), ret0: format!("{}:{}", var_vm, fn_ret0), ret1: format!("{}:{}", var_vm, fn_ret1), ret2: format!("{}:{}", var_vm, fn_ret2) };
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

        // ⑮ 派发条件换魔数：模板条件是 `elseif op == 别名 then/or`，
        // 把别名 token 整体换成魔数——下游 parsed/tree 全部拿到魔数
        for (alias, mag) in op_magic.iter() {
            raw_handlers = raw_handlers.replace(&format!("op == {} or", alias), &format!("op == {} or", mag));
        }
        for (alias, mag) in op_magic.iter() {
            raw_handlers = raw_handlers.replace(&format!("op == {} then", alias), &format!("op == {} then", mag));
        }
        // CLOSURE 模板体内还有一层伪指令 op 值比较（uv_inst[1] == 别名），同批换魔数
        // （带 " or"/" then" 尾边界——个位数 fallback key 否则会前缀污染长数字）
        for (alias, mag) in op_magic.iter() {
            raw_handlers = raw_handlers.replace(&format!("uv_inst[1] == {} or", alias), &format!("uv_inst[1] == {} or", mag));
            raw_handlers = raw_handlers.replace(&format!("uv_inst[1] == {} then", alias), &format!("uv_inst[1] == {} then", mag));
        }
        // ⑮ 三处中程读下一条指令的模板（SETLIST/EXTRAARG/CLOSURE 伪指令）同步解码：
        // ⑱.4 数组存的是掩码值，中程读必须 bx 还原——掩码名在此提前生成：
        // 热块内联用 execute 局部，冷块方法体用同名局部（fetch 前缀从槽位自取）
        let (n_mk1, n_mk2, n_mk3) = (rng.name(), rng.name(), rng.name());
        for (alias, mag) in op_magic.iter() {
            raw_handlers = raw_handlers.replace(&format!("op == {} or", alias), &format!("op == {} or", mag));
            raw_handlers = raw_handlers.replace(&format!("op == {} then", alias), &format!("op == {} then", mag));
        }
        {
            let site1 = format!("then c = {}[{}];", var_a_arr, var_pc);
            let site1_new = format!("then c = ({}({}[{}],{})-{}[{}]);", fn_bxor2, var_a_arr, var_pc, n_mk1, var_opcodes, var_pc);
            raw_handlers = raw_handlers.replace(&site1, &site1_new);
            let site3 = format!("[{}[{}] + 1]", var_a_arr, var_pc);
            let site3_new = format!("[({}({}[{}],{})-{}[{}]) + 1]", fn_bxor2, var_a_arr, var_pc, n_mk1, var_opcodes, var_pc);
            raw_handlers = raw_handlers.replace(&site3, &site3_new);
            let comp_old = format!("local uv_inst = ({{ {}[{}], {}[{}], {}[{}], {}[{}] }})", var_opcodes, var_pc, var_a_arr, var_pc, var_b_arr, var_pc, var_c_arr, var_pc);
            let (cq1, cq2, cq3, cq4) = (rng.name(), rng.name(), rng.name(), rng.name());
            let comp_new = format!("local {q1}={ops}[{p}]; local {q2}=({bx}({a}[{p}],{m1})-{ops}[{p}]); local {q3}={bx}({b}[{p}],{m2}); if {q3}>=0X80000000 then {q3}={q3}-4294967296 end; local {q4}={bx}({c}[{p}],{m3}); if {q4}>=0X80000000 then {q4}={q4}-4294967296 end; local uv_inst=({{ {q1}, {q2}, {q1}%2~=0 and {q4} or {q3}, {q1}%2~=0 and {q3} or {q4} }})",
                ops = var_opcodes, p = var_pc,
                bx = fn_bxor2, a = var_a_arr, m1 = n_mk1,
                b = var_b_arr, m2 = n_mk2,
                c = var_c_arr, m3 = n_mk3,
                q1 = cq1, q2 = cq2, q3 = cq3, q4 = cq4);
            raw_handlers = raw_handlers.replace(&comp_old, &comp_new);
        }

        if raw_handlers.trim_start().starts_with("if op") { raw_handlers = raw_handlers.replacen("if op", "elseif op", 1); }

        // handlers 成块：多个 op 共用一个方法（省体积）
        let mut parsed: Vec<(Vec<u32>, String)> = Vec::new();
        let mut remaining = raw_handlers.as_str();
        let mut current_ops: Vec<u32> = Vec::new(); let mut current_code = String::new();
        while let Some(idx) = remaining.find("elseif op") {
            let before = &remaining[..idx];
            if !current_ops.is_empty() {
                current_code.push_str(before); let code_str = current_code.trim().to_string();
                parsed.push((current_ops.clone(), code_str));
                current_code.clear();
            }
            remaining = &remaining[idx + 9..];
            if let Some(then_idx) = remaining.find("then") {
                let ops: Vec<u32> = remaining[..then_idx].split(|c: char| !c.is_numeric()).filter_map(|s| s.parse::<u32>().ok()).collect();
                if !ops.is_empty() { current_ops = ops; remaining = &remaining[then_idx + 4..]; } else { current_code.push_str("elseif op"); current_code.push_str(&remaining[..then_idx]); current_code.push_str("then"); remaining = &remaining[then_idx + 4..]; }
            }
        }
        if !current_ops.is_empty() {
            current_code.push_str(remaining); let code_str = current_code.trim().to_string();
            parsed.push((current_ops.clone(), code_str));
        }

        // 去重 + 分配随机方法名 / 随机状态号
        let mut blocks: Vec<(Vec<u32>, String, String, u32)> = Vec::new();
        let mut used_states: Vec<u32> = Vec::new();
        for (ops, code) in parsed {
            if let Some(b) = blocks.iter_mut().find(|b| b.1 == code) { b.0.extend(ops); continue; }
            let name = rng.name();
            let st = loop {
                let v = rng.range(0x0100_0000, 0x7FFF_0000) as u32;
                if !used_states.contains(&v) { used_states.push(v); break v; }
            };
            blocks.push((ops, code, name, st));
        }

        // ① 方法化 + ② 数据流打乱
        // 而是按随机槽位号从 VM 对象里取自己的那份状态，出口再写回
        // 每个块的局部别名逐块新取，同一个逻辑变量跨块看到的不是同一个名字
        // ④ 槽位号不再写死在产物里
        // `GenRng::slot_key_block`）。这里拿到的全是**局部名字**，插值进 Lua 源码
        let (sk, sk_setup) = rng.slot_key_block(23);
        let k_pc = sk[0].clone(); let k_stk = sk[1].clone(); let k_top = sk[2].clone();
        let k_ops = sk[3].clone(); let k_aa = sk[4].clone(); let k_bb = sk[5].clone(); let k_cc = sk[6].clone();
        // ⑱.4 掩码槽键：execute 入口派生后写槽，冷块（CLOSURE 等）中程读自取——
        // 必须走 slot_key_block 池；裸 rng.name() 键不在池里=运行时 nil 键（前车之鉴）
        let k_mk1 = sk[20].clone(); let k_mk2 = sk[21].clone(); let k_mk3 = sk[22].clone();
        // 中危刀1 密钥分驻：kp/pb/cnt 不入 chunk 表也不入 VM 槽（嵌套闭包交错会串），
        // 存弱键注册表 KREG（键=chunk 表）——与被掩码数组异表分驻，重解原型自动回收
        let k_consts = sk[7].clone(); let k_protos = sk[8].clone();
        let k_upv = sk[9].clone(); let k_env = sk[10].clone();
        let k_va = sk[11].clone(); let k_valen = sk[12].clone();
        let k_vc = sk[13].clone(); let k_breg = sk[14].clone();
        let k_state = sk[15].clone(); let k_mode = sk[16].clone();
        let k_retv = sk[17].clone(); let k_retf = sk[18].clone(); let k_rett = sk[19].clone();

        // 表类状态按块取一次（表是引用，不需要写回）
        // 直接把槽位表达式替换进块体 —— 就地读写，不依赖出口写回
        // （Lua 的 `return` 必须是块的最后一条语句，写回语句没法追加在它后面）
        let state_fields: Vec<(String, String, bool)> = vec![
            (var_opcodes.clone(), k_ops.clone(), false),
            (var_a_arr.clone(), k_aa.clone(), false),
            (var_b_arr.clone(), k_bb.clone(), false),
            (var_c_arr.clone(), k_cc.clone(), false),
            (var_stk.clone(), k_stk.clone(), false),
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
        for (ops, code, name, st) in blocks.iter() {
            let st_lua = rng.format_num(*st as i64);
            // 预算：热路径（算术/比较/跳转/栈与表存取）保留**内联**，冷路径
            // （调用/返回/闭包/全局/上值/内建）才提升成方法。全量方法化会把每条
            // 指令都变成一次 Lua 函数调用 —— 实测慢 5.6 倍，超出预算
            let cold = uses_ident(code, &var_vc)
                || uses_ident(code, &var_builtin_reg)
                || uses_ident(code, &var_env)
                || uses_ident(code, &var_protos)
                || uses_ident(code, &var_varargs)
                || code.contains(&pf_open_ups)
                || code.contains("zm(")
                || code.contains(&format!("{}(", fn_execute));
            if cold {
                let mut body = code.clone();
                // 标量状态：槽位表达式就地替换（pc/top 的读写直接落在 VM 对象上）
                body = rename_ident(&body, &var_pc, &format!("self[{}]", k_pc));
                body = rename_ident(&body, &var_top, &format!("self[{}]", k_top));
                // CLOSURE 模板里有字面量 env（内层闭包用），方法表是共享的
                // 必须走槽位拿当前调用的环境，不能捕获第一次调用的 env
                body = rename_ident(&body, "env", &format!("self[{}]", k_env));
                // 取指别名对（别名↔槽位绑定不变；抓取顺序与分组随机）
                let mut alias_pairs: Vec<(String, String)> = Vec::new();
                for (old, key, _mutable) in state_fields.iter() {
                    if !uses_ident(&body, old) { continue; }
                    let alias = rng.name();
                    body = rename_ident(&body, old, &alias);
                    alias_pairs.push((alias, format!("self[{}]", key)));
                }
                rng.shuffle(&mut alias_pairs);
                // ⑱.4 中程读体需要掩码：从掩码槽自取（execute 入口已派生写入）
                let mut mk_stmt: Option<String> = None;
                if body.contains(&n_mk1) {
                    mk_stmt = Some(format!("local {m1},{m2},{m3}=self[{k1}],self[{k2}],self[{k3}];",
                        m1 = n_mk1, m2 = n_mk2, m3 = n_mk3, k1 = k_mk1, k2 = k_mk2, k3 = k_mk3));
                }
                body = body.replace("{STOREBACK}", "");
                // ── 冷块前奏打散：{rk 声明 + 状态自校验 + 取指分组} 全是独立纯读/声明，
                // 任意线性化等价 → 语句池洗牌，"校验必居首 + 取指两连"的指纹消失；
                // 校验恒先于任何写（体在后），跳错块照旧拒绝。常数经 obfuscate 去指纹。
                let mut pre: Vec<String> = Vec::new();
                pre.push("local rk1,rk2;".to_string());
                // 状态号自校验：分发器刚把本块的状态号写进槽位，对不上说明跳错了块
                // 常数混淆固定 depth=1：差式嵌套 depth≥2 会造出 ≥2^32 中间值，
                // 32 位 bxor（bit32/回退实现）高位丢失 → 校验值错（obf0/1/2 用 1 从未暴露）
                let st_obf = rng.obfuscate_num(*st as i64, 1, &keys);
                match rng.range(0, 4) {
                    0 => pre.push(format!("if self[{}]~={} then return end;", k_state, st_obf)),
                    1 => pre.push(format!("if self[{}]-{}~=0 then return end;", k_state, st_obf)),
                    2 => pre.push(format!("if self[{}]=={} then else return end;", k_state, st_obf)),
                    _ => pre.push(format!("if not(self[{}]=={}) then return end;", k_state, st_obf)),
                }
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
                defs.push(format!("{}.{}=function(self,op,inst_A,inst_B,inst_C) {} end;", var_methods, name, text));
                // 冷路径才付同步代价：进出方法前后各存/取一次 pc 与 top
                // 并把本块状态号写进槽位（方法入口自校验）。
                // 叶子打散：三连存乱序/分组 + 状态号常数去指纹 + 调用别名/恢复序随机（0=原版保留）
                let leaf = if rng.range(0, 4) == 0 {
                    format!(
                        "{}[{}]={};{}[{}]={};{}[{}]={};{},{},{}={}:{}(op,inst_A,inst_B,inst_C);{}={}[{}];{}={}[{}]",
                        var_vm, k_pc, var_pc, var_vm, k_top, var_top, var_vm, k_state, st_lua,
                        var_r1, var_r2, var_r3, var_vm, name,
                        var_pc, var_vm, k_pc, var_top, var_vm, k_top
                    )
                } else {
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
                    // 方法经 __index 解析（裸索引 vm[name]=nil）→ 别名臂只能别 self
                    let call = if rng.range(0, 2) == 0 {
                        format!("{},{},{}={}:{}(op,inst_A,inst_B,inst_C);", var_r1, var_r2, var_r3, var_vm, name)
                    } else {
                        let vname = rng.name();
                        format!("local {}={};{},{},{}={}:{}(op,inst_A,inst_B,inst_C);", vname, var_vm, var_r1, var_r2, var_r3, vname, name)
                    };
                    let rs_pc = format!("{}={}[{}];", var_pc, var_vm, k_pc);
                    let rs_top = format!("{}={}[{}];", var_top, var_vm, k_top);
                    let (ra, rb) = if rng.range(0, 2) == 0 { (rs_pc, rs_top) } else { (rs_top, rs_pc) };
                    format!("{}{}{}{}", sync_stmts, call, ra, rb)
                };
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
            let (ha_, hb_) = (rng.range(0x1_0000, 0xFFFF_FFFF) as i64, rng.range(0x1_0000, 0xFFFF_FFFF) as i64);
            let htaut = format!("(0X{:X}-0X{:X}==0X{:X})", ha_, hb_, ha_ - hb_);
            defs.push(format!(
                "{mv}.{nm}=function(self,op,inst_A,inst_B,inst_C) local {dg}={bx2}(op,0X{dop:X})%4294967296; local {skv}=self[{ks}]; {skv}[self[{kt}]+0X1]={dg}; self[{kt}]=self[{kt}]+0X1; {psn}={psn} or {taut} end;",
                mv = var_methods, nm = rng.name(), dg = dg, bx2 = fn_bxor2.as_str(),
                dop = dop, skv = skv, ks = k_stk, kt = k_top, psn = psn_n, taut = htaut));
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
        // ㉓ 统一流取用：惰性解密语句+纯数字密文，替换原池调用
        let (hash_stmt, hash_expr) = {
            let id = uni.register("#");
            uni.fetch(&mut rng, id)
        };
        block_methods.push_str(&hash_stmt);
        block_methods.push_str(&format!("local {} = function(...) return {}[{}]({}, ...) end; ", var_get_count, var_s, hex_select_idx, hash_expr));
        block_methods.push_str(&format!("local unpack, zm = unpack or table and table.unpack or function() end, function(...) return {{{}={}(...),...}} end; ", pf_vn, var_get_count));
        block_methods.push_str(&format!("local {}={{}};local {}={{}};", var_methods, var_proto));
        for d in defs.iter() { block_methods.push_str(d); block_methods.push(' '); }
        let (idx_stmt, idx_expr) = {
            let id = uni.register("__index");
            uni.fetch(&mut rng, id)
        };
        block_methods.push_str(&idx_stmt);
        block_methods.push_str(&format!("{}[{}]={};", var_proto, idx_expr, var_methods));

        block_execute_def.push_str(&format!("{} = function(chunk, env, upvals, ...) ", fn_execute));
        block_execute_def.push_str(&format!("local {} = {}(...); ", var_L, var_get_count));
        block_execute_def.push_str(&format!("local {} = setmetatable({{}}, {}); ", var_vm, var_proto));
        block_execute_def.push_str(&format!("{}[{}]={}.{}+{};{}[{}]={{}};{}[{}]={};", var_vm, k_pc, "chunk", pf_lld, obf1, var_vm, k_stk, var_vm, k_top, obf0));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_ops, pf_opcodes, var_vm, k_aa, pf_a_arr, var_vm, k_bb, pf_b_arr, var_vm, k_cc, pf_c_arr));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_consts, pf_consts, var_vm, k_protos, pf_protos));
        block_execute_def.push_str(&format!("{}[{}]=upvals;{}[{}]=env;{}[{}]={};{}[{}]={};", var_vm, k_upv, var_vm, k_env, var_vm, k_vc, var_vc, var_vm, k_breg, var_builtin_reg));
        block_execute_def.push_str(&format!("for _=1,chunk.{} do {}[{}][_-1+{}] = {}[{}](_,...) end; ", pf_numparams, var_vm, k_stk, rng.format_num(gshift as i64), var_s, hex_select_idx));
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
        block_methods.push_str(&format!("{}.{}=function(self)self[{}]={};return true end;", var_methods, fn_ret0, k_mode, obf0));
        block_methods.push_str(&format!("{}.{}=function(self,v)self[{}]={};self[{}]=v;return true end;", var_methods, fn_ret1, k_mode, obf1, k_retv));
        block_methods.push_str(&format!("{}.{}=function(self,t,f,l)self[{}]={};self[{}]=t;self[{}]=f;self[{}]=l;return true end;", var_methods, fn_ret2, k_mode, obf2, k_retv, k_retf, k_rett));



        let var_idx = rng.name(); let var_b = rng.name(); let var_tamper = rng.name(); let fn_s_byte = rng.name(); let fn_s_sub = rng.name(); let var_raw_p = rng.name(); let var_chk = rng.name(); let var_p = rng.name(); let var_a2 = rng.name(); let fn_a3 = rng.name(); let x = rng.name(); let var__a = rng.name(); let var__b = rng.name(); let fn_read_dec = rng.name(); let fn_bxor = rng.name(); let fn_b_rotr = rng.name(); let fn_a5 = rng.name(); let fn_read_string = rng.name(); let fn_a10 = rng.name(); let fn_decode_chunk = rng.name(); let fn_u32_dec = rng.name(); let l = rng.name(); let s_t = rng.name(); let v = rng.name(); let v_sign = rng.name(); let v_exp = rng.name(); let v_mant = rng.name(); let t = rng.name(); let fn_c = rng.name();
        // 数组槽位只读一次（热路径每指令都读会白花 4 次哈希查找）
        let arrs = format!("{}, {}, {}, {}", var_opcodes, var_a_arr, var_b_arr, var_c_arr);
        block_execute_def.push_str(&format!("local {};{}={}[{}],{}[{}],{}[{}],{}[{}];", arrs, arrs, var_vm, k_ops, var_vm, k_aa, var_vm, k_bb, var_vm, k_cc));
        // pc/top 是**循环外**的局部变量
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
        // 冷块调用前后由调用点负责与 VM 对象的槽位同步。
        block_execute_def.push_str(&format!("local {},{}={}[{}],{}[{}];", var_pc, var_top, var_vm, k_pc, var_vm, k_top));

        // ⑱.4 数组驻留掩码：body_insts 存的是逐原型掩码值（K 从 kp/pb 派生，同式）。
        // 中危刀1 密钥分驻：pf_ld（仅掩码用）从 chunk 蒸发进弱键注册表 KREG（键=chunk）；
        // pf_lld 是入口 pc 基址（每次入口读）必须留在 chunk——半分量分驻+换钥兜底
        let (n_kon, n_ka) = (rng.name(), rng.name());
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
        block_execute_def.push_str(&format!(
            "local {kon}={kreg}[{c}]; if not {kon} then {kon}={c}.{ld}; {kreg}[{c}]={kon},{c}.{cnt}; {c}.{cnt}=nil end; {deriv} ",
            kon = n_kon, kreg = kreg_n, c = "chunk", ld = pf_ld, cnt = pf_cnt18, deriv = deriv));
        if tree_entries.is_empty() {
            // 理论上不会发生（没有任何 handler）
            block_execute_def.push_str("while true do break end end ");
        } else {
            block_execute_def.push_str("while true do ");
            block_execute_def.push_str(&format!("{}={};", var_state_flag, "true"));

            block_execute_def.push_str(&format!("local op={}[{}];", var_opcodes, var_pc));
            // ⑮ 指令解码：A=存值-魔数；魔数奇偶决定 (B,C) 交换还原
            // ⑱.4 取指单点还原：数组存掩码值，这里 bx 解出语义值（内存 dump 得不到明文指令）
            block_execute_def.push_str(&format!("local inst_A={bx}({}[{}],{})-op;", var_a_arr, var_pc, n_mk1, bx = fn_bxor2.as_str()));
            block_execute_def.push_str(&format!("local inst_B={bx}({}[{}],{}); if inst_B>=0X80000000 then inst_B=inst_B-4294967296 end;", var_b_arr, var_pc, n_mk2, bx = fn_bxor2.as_str()));
            block_execute_def.push_str(&format!("local inst_C={bx}({}[{}],{}); if inst_C>=0X80000000 then inst_C=inst_C-4294967296 end; ", var_c_arr, var_pc, n_mk3, bx = fn_bxor2.as_str()));
            block_execute_def.push_str("if op%2~=0 then inst_B,inst_C=inst_C,inst_B end; ");
            // 热路径：pc 就是普通局部变量，推进也用普通字面量
            block_execute_def.push_str(&format!("{}={}+1;", var_pc, var_pc));

            block_execute_def.push_str(&format!("local rk1,rk2;local {},{},{};", var_r1, var_r2, var_r3));
            block_execute_def.push_str(&build_opcode_tree(&tree_entries, 0, tree_entries.len() - 1, "op", &keys, &mut rng));
            block_execute_def.push_str(&format!("if {} then local {}={}[{}]; if {}=={} then return {}[{}] elseif {}=={} then return unpack({}[{}],{}[{}],{}[{}]) end; return end;", var_r1, var_md, var_vm, k_mode, var_md, obf1, var_vm, k_retv, var_md, obf2, var_vm, k_retv, var_vm, k_retf, var_vm, k_rett));
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
                format!("{}[{}][1]={}; {}{}{} {},{},{}={},{},{}; ",
                    kreg_n, "chunk", nk1_n, stmts[0], stmts[1], stmts[2],
                    n_mk1, n_mk2, n_mk3, na_n, nb_n, nc_n)
            };
            // ㉒② 焊接 2^32 模数（execute 换钥分支每次重走——第二次起逻辑无分支）；
            // ㉒① thunk 回写环、寄存器键轮换环 → 动态分段数值游标机
            // （execute 作用域内 P 表已建，状态常数走 obfuscate_num 算式化出边）。
            let w2_dst = weld.dst();
            let w2_stmt = format!("local {};", w2_dst) + &weld.weld(&mut rng, &w2_dst, "4294967296");
            let md_walk = {
                let (md2, th2) = (md21.clone(), th21.clone());
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("if type({md}[{iv}])=='table' then {md}[{iv}]={th}[{iv}] end; ", md = md2, th = th2, iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_dyn(&mut rng, Some(&keys), off, &format!("#{}", md21), 2, 3, &unit)
            };
            let rot_walk = {
                let (aa2, bb2, cc2, d12, d22, d32, bx2) = (var_a_arr.clone(), var_b_arr.clone(), var_c_arr.clone(), d1_n.clone(), d2_n.clone(), d3_n.clone(), fn_bxor2.clone());
                let off = rng.range(0, 100);
                let nexp = format!("{}[chunk][2]", kreg_n);
                let unit = |iv: &str| format!("{aa}[{iv}]={bx}({aa}[{iv}],{d1}); {bb}[{iv}]={bx}({bb}[{iv}],{d2}); {cc}[{iv}]={bx}({cc}[{iv}],{d3}); ", aa = aa2, bb = bb2, cc = cc2, bx = bx2, d1 = d12, d2 = d22, d3 = d32, iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_dyn(&mut rng, Some(&keys), off, &nexp, 3, 3, &unit)
            };
            block_execute_def.push_str(&format!(
                "if {flg} and {pc}>{tw} then {tw}={pc}+0X{sx:X}; {mdw} \
                 {rk}={rk}+0X1; if {rk}>={rn} then {rk}=0X0; \
                   local {kmt}=getmetatable({kreg}); local {kold}={kreg}; {kreg}=setmetatable({{}},{{}}); setmetatable({kreg},{kmt}); for {kc1},{kv1} in pairs({kold}) do {kreg}[{kc1}]={kv1} end; \
                   local {lv}={c}.{lld}; {w2} local {nk1}={bx}({kon},{pc}%{m32})%{m32}; {nn} \
                   {dline} \
                   {rotw} \
                   {rk_tail} \
                 end end; ",
                flg = var_state_flag, pc = var_pc, tw = tw21, sx = step21,
                mdw = md_walk,
                rk = rk21, rn = rng.format_num(rkey_every as i64),
                bx = fn_bxor2.as_str(),
                lld = pf_lld, kon = n_kon,
                w2 = w2_stmt, m32 = w2_dst,
                nk1 = nk1_n, lv = lv_n,
                nn = nn_seg, dline = dline_seg, rk_tail = rk_tail_seg,
                kreg = kreg_n, c = "chunk", rotw = rot_walk,
                kmt = rng.name(), kold = rng.name(), kc1 = rng.name(), kv1 = rng.name()));
            block_execute_def.push_str(&format!("{}={};", var_state_flag, "false"));
            block_execute_def.push_str("end end ");
        }

        let block_decoder_script = decoder_script.replace("\n", " ");
        
        let var_boot_env = rng.name(); let var_bname = rng.name();

        let fn_qr = rng.name();
        let fn_xor32 = rng.name();
        let fn_rotl32 = rng.name();
        let xor_tbl_var = rng.name();

        // ChaCha 的 4 个 sigma 常量（"expand 32-byte k"）不以字面量出现在产物里；
        // ⑯ 每组独立派生：sigma_i=(d_i+K_g[idx_i])%2^32，idx 是每组自己的 [1..8] 洗牌排列
        let sigma: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];


        // phase 2 已原样搬至 Generator_chain.rs（README 单文件 ≤ 80 KB 规则）。
        Generator_chain::build_chain(Generator_chain::ChainIn {
            rng, at, keys, enc, builtin_slot_perm, sigma,
            fn_a3, fn_bxor, fn_c, fn_decode_chunk, fn_s_byte, fn_s_sub, pf_a_arr, pf_b_arr, pf_c_arr, pf_is_vararg,
            pf_ld, pf_lld, pf_maxstack, pf_n, pf_numparams, pf_nups, pf_opcodes, pf_protos, psn_n, var_a2,
            var_b, var_builtin_reg, var_chk, var_idx, var_junk, var_p, var_raw_p, var_tamper, var_vc, np21,
            md21, th21, tw21, rk21, kreg_n,
            fn_execute, bc_kb, bc_kc, bc_ki1, bc_ki2, pm_r0, pm_r1, pm_r2, pm_r3, sc_add, sc_add_k1, sc_mul_k2, sc_rot_in, sc_rot_k2, sc_rot_k4, pm_s, tag_map18, fc18, block_decoder_script, block_execute_def, block_methods, block_p_def, block_packer_vars, block_vm_core, entry_func, fn_a10, fn_a5, fn_b_rotr, fn_qr, fn_read_dec, fn_read_string, fn_rotl32, fn_u32_dec, fn_xor32, header_block, key_seed_var, payload_str, pf_cnt18, pf_consts, sk_setup, t, x, var_bname, var_boot_env, var_l, var_state_flag, wai, xor_tbl_var,
            weld,
            uni,
        })
    }
}

