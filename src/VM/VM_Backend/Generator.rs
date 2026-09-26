use crate::VM::VM_Backend::Context::VmContext;
use crate::VM::VM_Backend::Lua_core;
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use crate::compiler::instructions::{OpCode, OpMode, OpArgMask};
use std::collections::HashSet;
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;
use super::AntiTamper;

// 底层工具层已拆到 Generator_util.rs（原文件 69 KB 太大）。
// GenRng 继续从这里 re-export，保持 crate 内既有的引用路径不变。
pub use super::Generator_util::{CipherKeys, GenRng};
use super::Generator_util::{
    build_opcode_tree, chacha8_xor, rename_ident, rewrite_chunk, scan_setglobal_targets,
    scan_used_opcodes, uses_ident, write_string, PayloadReader,
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
        let mut proto_sites_root: Vec<(usize, u32)> = rewrite_chunk(&mut reader, &mut rewritten_chunks, &transpile_map, &mapped_opcodes, &fused_opcodes, &mut fused_used, &setglobal_targets, getglobal_op, getglobalstr_op, &inverse_opcode_map, &builtin_slot_perm, &op_magic, &enc, root_group, &mut rewrite_rng, bc_kb, bc_kc, bc_ki1, bc_ki2, &fc18, &tag_map18);

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
        header_block.push_str(&format!("return ({{ {} = function(agv,aggv,agv,agv,agv,aggv,agv,agv,aggv,aggv,aggv,agggv,agggv,agggv,agggv,aggv,{},{},{},{}, ...)\n", wai, p_out[0], p_out[1], p_out[2], p_out[3]));
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
        let mut block_p_def = String::new();
        block_p_def.push_str(&format!("local {}={}; local {}={}; local {}={}; ", 
            fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b)local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra~=rb then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end",
            fn_ba, "bit32 and bit32.band or bit and bit.band or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end",
            fn_bs, "bit32 and bit32.rshift or bit and bit.rshift or function(a,n)local d=2^n return (a-a%d)/d end"
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
        
        let (payload_str, decoder_script, entry_func) = Packer::pack(&combined_payload, &mut rng);
        let var_junk = rng.name(); let var_vc = rng.name(); let var_builtin_reg = rng.name();
        let block_packer_vars = format!("local {}, {}, {}; ", var_junk, var_vc, var_builtin_reg);

        let fn_execute = "execute";
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
        // ⑮ 三处中程读下一条指令的模板（SETLIST/VARARG/CLOSURE 伪指令）同步解码：
        // 裸 A 读=存值-魔数；复合 inst 的 B/C 按魔数奇偶还原。先改裸读、后改复合体。
        for (alias, mag) in op_magic.iter() {
            raw_handlers = raw_handlers.replace(&format!("op == {} or", alias), &format!("op == {} or", mag));
            raw_handlers = raw_handlers.replace(&format!("op == {} then", alias), &format!("op == {} then", mag));
        }
        {
            let site1 = format!("then c = {}[{}];", var_a_arr, var_pc);
            let site1_new = format!("then c = ({}[{}]-{}[{}]);", var_a_arr, var_pc, var_opcodes, var_pc);
            raw_handlers = raw_handlers.replace(&site1, &site1_new);
            let site3 = format!("[{}[{}] + 1]", var_a_arr, var_pc);
            let site3_new = format!("[({}[{}]-{}[{}]) + 1]", var_a_arr, var_pc, var_opcodes, var_pc);
            raw_handlers = raw_handlers.replace(&site3, &site3_new);
            let comp_old = format!("({{ {}[{}], {}[{}], {}[{}], {}[{}] }})", var_opcodes, var_pc, var_a_arr, var_pc, var_b_arr, var_pc, var_c_arr, var_pc);
            let comp_new = format!("({{ {}[{}], {}[{}]-{}[{}], {}[{}]%2~=0 and {}[{}] or {}[{}], {}[{}]%2~=0 and {}[{}] or {}[{}] }})",
                var_opcodes, var_pc,
                var_a_arr, var_pc, var_opcodes, var_pc,
                var_opcodes, var_pc, var_c_arr, var_pc, var_b_arr, var_pc,
                var_opcodes, var_pc, var_b_arr, var_pc, var_c_arr, var_pc);
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
        let (sk, sk_setup) = rng.slot_key_block(20);
        let k_pc = sk[0].clone(); let k_stk = sk[1].clone(); let k_top = sk[2].clone();
        let k_ops = sk[3].clone(); let k_aa = sk[4].clone(); let k_bb = sk[5].clone(); let k_cc = sk[6].clone();
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
                let mut fetch = String::new();
                for (old, key, _mutable) in state_fields.iter() {
                    if !uses_ident(&body, old) { continue; }
                    let alias = rng.name();
                    body = rename_ident(&body, old, &alias);
                    fetch.push_str(&format!("local {}={}[{}];", alias, "self", key));
                }
                body = body.replace("{STOREBACK}", "");
                let mut text = String::from("local rk1,rk2;");
                // 状态号自校验：分发器刚把本块的状态号写进槽位，对不上说明跳错了块
                text.push_str(&format!("if self[{}]~={} then return end;", k_state, st_lua));
                text.push_str(&fetch);
                text.push_str(&body);
                // 必须用 `.名字=function` 注册
                // 成员名统一改名时字符串键不改，两边对不上变 nil。
                defs.push(format!("{}.{}=function(self,op,inst_A,inst_B,inst_C) {} end;", var_methods, name, text));
                // 冷路径才付同步代价：进出方法前后各存/取一次 pc 与 top
                // 并把本块状态号写进槽位（方法入口自校验）。
                let leaf = format!(
                    "{}[{}]={};{}[{}]={};{}[{}]={};{},{},{}={}:{}(op,inst_A,inst_B,inst_C);{}={}[{}];{}={}[{}]",
                    var_vm, k_pc, var_pc, var_vm, k_top, var_top, var_vm, k_state, st_lua,
                    var_r1, var_r2, var_r3, var_vm, name,
                    var_pc, var_vm, k_pc, var_top, var_vm, k_top
                );
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
        let (h0, h1) = crate::VM::VM_Backend::Generator_util::stream_key("#", &mut rng);
        let sc_hash = at.st.call("#", h0, h1);
        block_methods.push_str(&format!("local {} = function(...) return {}[{}]({}, ...) end; ", var_get_count, var_s, hex_select_idx, sc_hash));
        block_methods.push_str(&format!("local unpack, zm = unpack or table and table.unpack or function() end, function(...) return {{{}={}(...),...}} end; ", pf_vn, var_get_count));
        block_methods.push_str(&format!("local {}={{}};local {}={{}};", var_methods, var_proto));
        for d in defs.iter() { block_methods.push_str(d); block_methods.push(' '); }
        let (ix0, ix1) = crate::VM::VM_Backend::Generator_util::stream_key("__index", &mut rng);
        let sc_index = at.st.call("__index", ix0, ix1);
        block_methods.push_str(&format!("{}[{}]={};", var_proto, sc_index, var_methods));

        block_execute_def.push_str(&format!("{} = function(chunk, env, upvals, ...) ", fn_execute));
        block_execute_def.push_str(&format!("local {} = {}(...); ", var_L, var_get_count));
        block_execute_def.push_str(&format!("local {} = setmetatable({{}}, {}); ", var_vm, var_proto));
        block_execute_def.push_str(&format!("{}[{}]={}.{}+{};{}[{}]={{}};{}[{}]={};", var_vm, k_pc, "chunk", pf_lld, obf1, var_vm, k_stk, var_vm, k_top, obf0));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_ops, pf_opcodes, var_vm, k_aa, pf_a_arr, var_vm, k_bb, pf_b_arr, var_vm, k_cc, pf_c_arr));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_consts, pf_consts, var_vm, k_protos, pf_protos));
        block_execute_def.push_str(&format!("{}[{}]=upvals;{}[{}]=env;{}[{}]={};{}[{}]={};", var_vm, k_upv, var_vm, k_env, var_vm, k_vc, var_vc, var_vm, k_breg, var_builtin_reg));
        block_execute_def.push_str(&format!("for _=1,chunk.{} do {}[{}][_-1] = {}[{}](_,...) end; ", pf_numparams, var_vm, k_stk, var_s, hex_select_idx));
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



        // 数组槽位只读一次（热路径每指令都读会白花 4 次哈希查找）
        let arrs = format!("{}, {}, {}, {}", var_opcodes, var_a_arr, var_b_arr, var_c_arr);
        block_execute_def.push_str(&format!("local {};{}={}[{}],{}[{}],{}[{}],{}[{}];", arrs, arrs, var_vm, k_ops, var_vm, k_aa, var_vm, k_bb, var_vm, k_cc));
        // pc/top 是**循环外**的局部变量
        // ㉑ 保守版明文窗口变量：NP(原型数)/MD(=C.pr 别名)/TH(thunk 快照)/tw(回收水位)
        let (np21, md21, th21, tw21) = (rng.name(), rng.name(), rng.name(), rng.name());
        let step21 = rng.range(0x8000, 0x40000);
        // 冷块调用前后由调用点负责与 VM 对象的槽位同步。
        block_execute_def.push_str(&format!("local {},{}={}[{}],{}[{}];", var_pc, var_top, var_vm, k_pc, var_vm, k_top));

        if tree_entries.is_empty() {
            // 理论上不会发生（没有任何 handler）
            block_execute_def.push_str("while true do break end end ");
        } else {
            block_execute_def.push_str("while true do ");
            block_execute_def.push_str(&format!("{}={};", var_state_flag, "true"));

            block_execute_def.push_str(&format!("local op={}[{}];", var_opcodes, var_pc));
            // ⑮ 指令解码：A=存值-魔数；魔数奇偶决定 (B,C) 交换还原
            block_execute_def.push_str(&format!("local inst_A={}[{}]-op;", var_a_arr, var_pc));
            block_execute_def.push_str(&format!("local inst_B={}[{}];", var_b_arr, var_pc));
            block_execute_def.push_str(&format!("local inst_C={}[{}];", var_c_arr, var_pc));
            block_execute_def.push_str("if op%2~=0 then inst_B,inst_C=inst_C,inst_B end; ");
            // 热路径：pc 就是普通局部变量，推进也用普通字面量
            block_execute_def.push_str(&format!("{}={}+1;", var_pc, var_pc));

            block_execute_def.push_str(&format!("local rk1,rk2;local {},{},{};", var_r1, var_r2, var_r3));
            block_execute_def.push_str(&build_opcode_tree(&tree_entries, 0, tree_entries.len() - 1, "op", &keys, &mut rng));
            block_execute_def.push_str(&format!("if {} then local {}={}[{}]; if {}=={} then return {}[{}] elseif {}=={} then return unpack({}[{}],{}[{}],{}[{}]) end; return end;", var_r1, var_md, var_vm, k_mode, var_md, obf1, var_vm, k_retv, var_md, obf2, var_vm, k_retv, var_vm, k_retf, var_vm, k_rett));
            // ㉑ 周期性明文回收：pc 水位过阈值→全部原型槽写回 thunk（密文）；
            // 活跃闭包持有明文引用不受影响；未来 CLOSURE 经 type(p)=='function' 重解
            block_execute_def.push_str(&format!(
                "if {flg} and {pc}>{tw} then {tw}={pc}+0X{sx:X}; for {j}=1,#{md} do if type({md}[{j}])=='table' then {md}[{j}]={th}[{j}] end end end; ",
                flg = var_state_flag, pc = var_pc, tw = tw21, sx = step21,
                j = rng.name(), md = md21, th = th21));
            block_execute_def.push_str(&format!("{}={};", var_state_flag, "false"));
            block_execute_def.push_str("end end ");
        }

        let block_decoder_script = decoder_script.replace("\n", " ");
        
        let var_idx = rng.name(); let var_b = rng.name(); let var_tamper = rng.name(); let fn_s_byte = rng.name(); let fn_s_sub = rng.name(); let var_raw_p = rng.name(); let var_chk = rng.name(); let var_p = rng.name(); let var_a2 = rng.name(); let fn_a3 = rng.name(); let x = rng.name(); let var__a = rng.name(); let var__b = rng.name(); let fn_read_dec = rng.name(); let fn_bxor = rng.name(); let fn_b_rotr = rng.name(); let fn_a5 = rng.name(); let fn_read_string = rng.name(); let fn_a10 = rng.name(); let fn_decode_chunk = rng.name(); let fn_u32_dec = rng.name(); let l = rng.name(); let s_t = rng.name(); let v = rng.name(); let v_sign = rng.name(); let v_exp = rng.name(); let v_mant = rng.name(); let t = rng.name(); let fn_c = rng.name();
        let var_boot_env = rng.name(); let var_bname = rng.name();

        let fn_qr = rng.name();
        let fn_xor32 = rng.name();
        let fn_rotl32 = rng.name();
        let xor_tbl_var = rng.name();

        // ChaCha 的 4 个 sigma 常量（"expand 32-byte k"）不以字面量出现在产物里；
        // ⑯ 每组独立派生：sigma_i=(d_i+K_g[idx_i])%2^32，idx 是每组自己的 [1..8] 洗牌排列
        let sigma: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

        let mut block_chacha_setup = String::new();
        block_chacha_setup.push_str(&format!(
            "local {xt}={{}}; for a=0,255 do local row={{}}; for b=0,255 do local x,y,r,p=a,b,0,1; while x>0 or y>0 do local rx,ry=x%2,y%2; if rx~=ry then r=r+p end; x,y,p=math_floor(x/2),math_floor(y/2),p*2 end; row[b]=r end; {xt}[a]=row end; ",
            xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {xor32}(a,b) local a1,a2,a3,a4=a%256,math_floor(a/256)%256,math_floor(a/65536)%256,math_floor(a/16777216)%256; local b1,b2,b3,b4=b%256,math_floor(b/256)%256,math_floor(b/65536)%256,math_floor(b/16777216)%256; return {xt}[a1][b1]+{xt}[a2][b2]*256+{xt}[a3][b3]*65536+{xt}[a4][b4]*16777216 end; ",
            xor32 = fn_xor32, xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {rotl32}(x,n) local m=2^n; return ((x*m)%4294967296)+math_floor(x/(4294967296/m)) end; ",
            rotl32 = fn_rotl32
        ));
        block_chacha_setup.push_str(&format!(
            "local function {qr}(s,a,b,c,d) s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],16); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],12); s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],8); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],7) end; ",
            qr = fn_qr, xor32 = fn_xor32, rotl32 = fn_rotl32
        ));
        // ⑰ 每组一个自包含簇：K/salt/sigma 排列/cblock/cstream + 专属 dec_str/dec_num
        // （无统一路由入口——四个簇打散插到产物不同位置，各原型按组直连本簇解码器）
        let mut clusters: Vec<String> = Vec::with_capacity(CG);
        let mut ds_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut dn_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut salt_names: [String; CG] = std::array::from_fn(|_| String::new());
        for g in 0..CG {
            let mut cl = String::new();
            let kname = rng.name();
            let slname = rng.name();
            let sname = rng.name();
            let cbname = rng.name();
            let key_lua = (0..8).map(|i| rng.obfuscate_num(enc.keys[g][i] as i64, 1, &keys)).collect::<Vec<_>>().join(",");
            let salt_lua = rng.obfuscate_num(enc.salts[g] as i64, 1, &keys);
            let mut idxs: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7, 8];
            for j in (1..idxs.len()).rev() { let k = rng.range(0, j + 1); idxs.swap(j, k); }
            let sig_idx = [idxs[0], idxs[1], idxs[2], idxs[3]];
            let sigma_lua = (0..4)
                .map(|i| {
                    let d = sigma[i].wrapping_sub(enc.keys[g][sig_idx[i] - 1]);
                    format!("(({}+K[{}])%4294967296)", rng.obfuscate_num(d as i64, 1, &keys), sig_idx[i])
                })
                .collect::<Vec<_>>()
                .join(",");
            cl.push_str(&format!(
                "local {kn}={{{key_lua}}}; local {sl}={salt_lua}; ",
                kn = kname, key_lua = key_lua, sl = slname, salt_lua = salt_lua));
            cl.push_str(&format!(
                "local function {cb}(n1,n2,n3,ctr) local K={kn}; local s={{{sig},K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],ctr,n1,n2,n3}}; local o={{}}; for i=1,16 do o[i]=s[i] end; for _=1,4 do {qr}(s,1,5,9,13); {qr}(s,2,6,10,14); {qr}(s,3,7,11,15); {qr}(s,4,8,12,16); {qr}(s,1,6,11,16); {qr}(s,2,7,12,13); {qr}(s,3,8,9,14); {qr}(s,4,5,10,15) end; local out={{}}; for i=1,16 do local w=(s[i]+o[i])%4294967296; out[(i-1)*4+1]=w%256; out[(i-1)*4+2]=math_floor(w/256)%256; out[(i-1)*4+3]=math_floor(w/65536)%256; out[(i-1)*4+4]=math_floor(w/16777216)%256 end; return out end; ",
                cb = cbname, kn = kname, qr = fn_qr, sig = sigma_lua));
            // ㉓-A sm 换公式：nonce=[盐^roll^fold, r7^(槽*6+kind), 盐^rotl7(r7)]——
            // layouts 直传退役；roll/fold 由 body_consts 扫描重算后经 dsp 透传
            let salt_v18 = slname.as_str();
            cl.push_str(&format!(
                "local function {sm}(pool_idx,kind,n,fold,rl) local out={{}}; local ctr=0; local pos=1; local {r7v}={rot}(rl or 0X0,0X7); while pos<=n do local blk={cb}({bx}({bx}({sl},rl or 0X0),fold or 0X0), {bx}({r7v},pool_idx*0X6+kind), {bx}({sl},{rot}({r7v},0X7)), ctr); for i=1,64 do if pos>n then break end; out[pos]=blk[i]; pos=pos+1 end; ctr=ctr+1 end; return out end; ",
                sm = sname, cb = cbname, sl = salt_v18, bx = fn_bxor.as_str(), rot = fn_rotl32.as_str(), r7v = rng.name()));
            // 组专属解码器：kind 常量内嵌（每组不同随机值），下标参数=节内槽位号
            let (vb, vs, ve, vm) = (rng.name(), rng.name(), rng.name(), rng.name());
            let mut f64_parts = vec![format!("({vb}[7]%16)*2^48", vb = vb), format!("({vb}[6]*2^40)", vb = vb), format!("({vb}[5]*2^32)", vb = vb), format!("({vb}[4]*2^24)", vb = vb), format!("({vb}[3]*2^16)", vb = vb), format!("({vb}[2]*2^8)", vb = vb), format!("{vb}[1]", vb = vb)];
            rng.shuffle(&mut f64_parts);
            let (v_num_i, v_num_g, v_num_ks) = (rng.name(), rng.name(), rng.name());
            let dname = rng.name();
            let fd18n = rng.name();
            let rl18n = rng.name();
            cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decnum(
                dname.as_str(), sname.as_str(), rng.obfuscate_num(enc.knum[g] as i64, 1, &keys).as_str(), vb.as_str(),
                xor_tbl_var.as_str(), vs.as_str(), ve.as_str(), vm.as_str(), f64_parts.join("+"),
                v_num_ks.as_str(), v_num_i.as_str(), v_num_g.as_str(), fd18n.as_str(), rl18n.as_str()));
            salt_names[g] = slname.clone();
            dn_names[g] = dname;
            let (v_str_i, v_str_g, v_str_ks, v_str_s) = (rng.name(), rng.name(), rng.name(), rng.name());
            let sname_d = rng.name();
            let fd18s = rng.name();
            let rl18s = rng.name();
            let kstr_lit = rng.obfuscate_num(enc.kstr[g] as i64, 1, &keys);
            cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decstr(
                &mut rng, sname_d.as_str(), sname.as_str(), kstr_lit.as_str(),
                xor_tbl_var.as_str(), fn_s_byte.as_str(), v_str_ks.as_str(), v_str_s.as_str(),
                v_str_i.as_str(), v_str_g.as_str(), fd18s.as_str(), rl18s.as_str()));
            ds_names[g] = sname_d;
            clusters.push(cl);
        }
        // 簇落位洗牌：1 个进 chacha_setup 尾部，其余 3 个作为独立 parts 插在
        // chacha_setup 之后、decode_chunk 之前（词法作用域先行，落位随机）
        let mut cluster_order: Vec<usize> = (0..CG).collect();
        rng.shuffle(&mut cluster_order);
        block_chacha_setup.push_str(&clusters[cluster_order[0]]);
        let cluster_parts: Vec<String> = vec![
            clusters[cluster_order[1]].clone(),
            clusters[cluster_order[2]].clone(),
            clusters[cluster_order[3]].clone(),
        ];
        
        let (fh0, fh1) = crate::VM::VM_Backend::Generator_util::stream_key("function", &mut rng);
        let sc_fn_hdr = at.st.call("function", fh0, fh1);
        let (md0, md1) = crate::VM::VM_Backend::Generator_util::stream_key("__mode", &mut rng);
        let sc_mode = at.st.call("__mode", md0, md1);
        let (mk0, mk1) = crate::VM::VM_Backend::Generator_util::stream_key("k", &mut rng);
        let sc_k = at.st.call("k", mk0, mk1);
        let block_dec_header = crate::VM::VM_Backend::Generator_flow::build_header(
            &mut rng, &keys, fn_s_byte.as_str(), fn_s_sub.as_str(), var_raw_p.as_str(), payload_str.as_str(),
            var_chk.as_str(), var_idx.as_str(), var_junk.as_str(), var_b.as_str(), var_tamper.as_str(),
            var_vc.as_str(), var_p.as_str(), var_a2.as_str(), entry_func.as_str(), fn_a3.as_str(), x.as_str(),
            sc_fn_hdr.as_str(), sc_mode.as_str(), sc_k.as_str());
        // ── 解码链（第 6 项：解密逻辑打乱）──
        // 冷路径一次性函数，放心打乱形态。
        let (v_bx_a, v_bx_b, v_bx_r, v_bx_w, v_bx_g, v_bx_s) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rt_x, v_rt_n, v_rt_d, v_rt_g, v_rt_t) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rd_o, v_rd_g, v_rd_e) = (rng.name(), rng.name(), rng.name());
        let (v_rd_c1, v_rd_c2, v_rd_c3, v_rd_c4, v_rd_c5) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());

        // 注意：产物里的 k1..k4 是固定局部名，模板里只能写裸标识符 k1 —— 写成 {k1}
        // 会被 format! 隐式捕获抓走同名生成器变量（产物语法错）；
        // 同理 Lua 的空表要写 {{}}，裸 {} 是位置参数占位符。
        // 原形态：逐位比较累权重、n==0早返回右移、滚动密钥顺序赋值
        // 现在：位异或写成 (xa+xb)%2 乘权重、右移用 256/2^n 代 2^(8-n) 去早返回
        // 解密链拆 5 个中间变量、密钥演化换等价变形（-229 代 +27、
        // (v-v%d)/d 代 floor、k2*2+k2 代 k2*3，包单次循环+影子计数器。
        let block_dec_helpers = format!(
            "local function {bx}({a},{b}) local {r},{w},{g},{s}=0,1,0,0; \
             while {g}<({r}-{r})+1 do \
             if {a}<=0 and {b}<=0 then {g}={g}+1 else \
             {s}=(({a}%2)+({b}%2))%2; {r}={r}+{s}*{w}; \
             {a}=({a}-({a}%2))/2; {b}=({b}-({b}%2))/2; {w}={w}+{w}; end end; \
             return {r} end; \
             local function {rt}({x},{n}) local {d},{g},{t}=2^{n},0,0; \
             while {g}<({t}-{t})+1 do \
             {t}=(({x}*(256/{d}))%256)+(({x}-({x}%{d}))/{d}); {g}={g}+1; end; \
             return {t} end; \
             {rd_scatter} ",
            bx = fn_bxor, a = v_bx_a, b = v_bx_b, r = v_bx_r, w = v_bx_w, g = v_bx_g, s = v_bx_s,
            rt = fn_b_rotr, x = v_rt_x, n = v_rt_n, d = v_rt_d, t = v_rt_t,
rd_scatter = crate::VM::VM_Backend::Generator_flow::build_scatter(
                &mut rng, fn_bxor.as_str(), fn_b_rotr.as_str(), fn_read_dec.as_str(), fn_a3.as_str(),
                &v_bx_a, &v_bx_b, &v_bx_r, &v_bx_w, &v_bx_g, &v_bx_s,
                &v_rt_x, &v_rt_n, &v_rt_d, &v_rt_g, &v_rt_t,
                &v_rd_o, &v_rd_g, &v_rd_e, &v_rd_c1, &v_rd_c2, &v_rd_c3, &v_rd_c4, &v_rd_c5,
                sc_add, sc_rot_in, sc_add_k1, sc_mul_k2, sc_rot_k2, sc_rot_k4)
        );
        let (kt_name, pj_name) = (rng.name(), rng.name());
        let kc = crate::VM::VM_Backend::Generator_flow::build_k(&mut rng, kt_name.as_str());
        let (v_u32_t, v_u32_n, v_u32_i, v_u32_v) = (rng.name(), rng.name(), rng.name(), rng.name());
        let (v_a5_t, v_a5_n, v_a5_i) = (rng.name(), rng.name(), rng.name());
        let (v_rs_l, v_rs_t, v_rs_i) = (rng.name(), rng.name(), rng.name());
        let (v_a10_v, v_a10_h) = (rng.name(), rng.name());

        // 原形态：for 循环按 1..4 读、再按固定顺序累加、权重全是十进制常量
        // 现在：while + 显式自增下标、累加项顺序打乱（整数加法精确，顺序无影响）
        // 权重换 2^8/2^16/2^24 与自减零初值、零长度短路、有符号转换改形
        let block_dec_readers = format!(
            "{u32_family} ",
u32_family = crate::VM::VM_Backend::Generator_flow::build_readers(
                &mut rng, &keys, &kc, kt_name.as_str(), pj_name.as_str(), fn_bxor.as_str(),
                fn_u32_dec.as_str(), fn_a5.as_str(), fn_read_string.as_str(), fn_read_dec.as_str(), fn_a10.as_str(),
                &v_u32_t, &v_u32_n, &v_u32_i, &v_u32_v, &v_rs_l, &v_a10_v, &v_a10_h)
        );
        
        // ⑰ 旧统一 dec_num/dec_str 已由四组簇内专属解码器取代。

// ⑰ 中央字符串/数值池初始化块废除（池不存在了）。⑦ 的 while/repeat
        // 抽签壳保留在 body_ret/body_debug；池壳随池一起退役。
        let var_enc_c = rng.name();
        let var_tbl = rng.name();
        let var_idx_chunk = rng.name();
        let var_e = rng.name();
        let var_cache = rng.name();

        let var_state = rng.name();
        let s_init = rng.range(0x100, 0xFFF) as i64;
        let s_insts = rng.range(0x1000, 0x1FFF) as i64;
        let s_consts = rng.range(0x2000, 0x2FFF) as i64;
        let s_protos = rng.range(0x3000, 0x3FFF) as i64;
        let s_debug = rng.range(0x4000, 0x4FFF) as i64;
        let s_ret = rng.range(0x5000, 0x5FFF) as i64;

        let obf_s_init = rng.format_num(s_init);
        let obf_s_insts = rng.format_num(s_insts);
        let obf_s_consts = rng.format_num(s_consts);
        let obf_s_protos = rng.format_num(s_protos);
        let obf_s_debug = rng.format_num(s_debug);
        let obf_s_ret = rng.format_num(s_ret);
        
        // ── 状态机（第 6 项：解密逻辑打乱）──
        // 原形态：if state==A then <体>
        // 状态推进总在体尾，一眼就是「顺序状态机」。现在：
        //   ① 六个状态体各自构造后 **shuffle**（分支条件互相排斥，顺序无关）
        //   ② 状态推进提到体首（体内不读 state，等价）；
        //   ③ 所有 for 循环换成 while + 显式自增下标 + 独立局部下标；
        //   ④ 结尾统一 return（不再是分支内 return），并带一个恒假谓词与影子守卫
        // 注意：体内的**读流顺序**一个字都不能动 —— 那些字节是按顺序读进来的
        let (v_ch_g, v_ch_out, v_ch_i, v_ch_n) = (rng.name(), rng.name(), rng.name(), rng.name());

        // ⑧ 常数提供者：连常数 1 都要过一次形参重名函数
        let cpp = rng.name();
        let cpq = rng.name();
        let body_init = format!(
            "local function {cpp}({cpq},{cpq}) {cpq}=0X1; return {cpq} end; {st}={nxt}; {c}.{pf_n}={rs}(); {c}.{pf_ld}={a5}(); {c}.{pf_lld}={a5}(); {c}.{pf_nups}={rd}(); \
             {c}.{pf_numparams}={rd}(); {c}.{pf_is_vararg}={rd}(); {c}.{pf_maxstack}={rd}(); if {i} > {cpp}({cpq},{cpq}) then {i} = {i} - {cpp}({cpq},{cpq}) end; ",
            st = var_state, nxt = obf_s_insts, c = fn_c, rs = fn_read_string, a5 = fn_a5, rd = fn_read_dec,
            pf_n = pf_n, pf_ld = pf_ld, pf_lld = pf_lld, pf_nups = pf_nups,
            pf_numparams = pf_numparams, pf_is_vararg = pf_is_vararg, pf_maxstack = pf_maxstack, i = v_ch_i,
            cpp = cpp, cpq = cpq
        );
        // ⑨ 区间二分树诱饵：not(x<=k) 双重否定嵌套（恒空转，美化后深度剧增）
        let it9 = |rng: &mut GenRng, st: &str| format!(
            "if not({st}<=0X{:X}) then if not({st}<=0X{:X}) then else end else end; ",
            rng.range(0x1000, 0xFFFF), rng.range(0x10000, 0xFFFFF));
        // ① B/C 解掩码：线上=值^(mag^ki)^k（k/ki 逐产物、mag 逐条别名魔数）。
        // a10 返回带符号值：先回 2^32 域异或，再按 2^31 还原符号——与旧 a10 语义逐位一致
        let (kb_x, kc_x, ki1_x, ki2_x) = (
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_kb as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_kc as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_ki1 as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_ki2 as i64),
        );
        let body_insts = format!(
            "{st}={nxt}; {tree9} {c}.{pf_opcodes}={{}}; {c}.{pf_a_arr}={{}}; {c}.{pf_b_arr}={{}}; {c}.{pf_c_arr}={{}}; \
             local function {dcb}({w},{m},{k},{q}) if {w}<0X0 then {w}={w}+0X100000000 end {w}={bx}({bx}({w},{k}),{bx}({m},{q})) if {w}>=0X80000000 then {w}={w}-0X100000000 end return {w} end; \
             local {i}=0; local {n}={a5}(); {c}.{cnt18}={n}; local {kp}={c}.{pf_ld}; local {pb}={c}.{pf_lld}; \
             while {i} < {n} do {i} = {i} + 1; \
             local {mv}={a5}() local {g18}={bx}({mv},{kp}) {c}.{pf_opcodes}[{i}+{pb}]={g18} {c}.{pf_a_arr}[{i}+{pb}]={a10}() {c}.{pf_b_arr}[{i}+{pb}]={dcb}({a10}(),{g18},{kbx},{k1x}) {c}.{pf_c_arr}[{i}+{pb}]={dcb}({a10}(),{g18},{kcx},{k2x}) end; ",
            tree9 = it9(&mut rng, var_state.as_str()),
            st = var_state, nxt = obf_s_consts, c = fn_c, a5 = fn_a5, a10 = fn_a10,
            pf_opcodes = pf_opcodes, pf_a_arr = pf_a_arr, pf_b_arr = pf_b_arr, pf_c_arr = pf_c_arr,
            i = v_ch_i, n = v_ch_n, cnt18 = pf_cnt18, kp = rng.name(), g18 = rng.name(),
            pb = rng.name(),
            pf_ld = pf_ld, pf_lld = pf_lld,
            dcb = rng.name(), w = rng.name(), m = rng.name(), k = rng.name(), q = rng.name(),
            bx = fn_bxor.as_str(), mv = rng.name(), kbx = kb_x, kcx = kc_x, k1x = ki1_x, k2x = ki2_x
        );
        let (bi0, bi1) = crate::VM::VM_Backend::Generator_util::stream_key("__index", &mut rng);
        let sc_index2 = at.st.call("__index", bi0, bi1);
        let (ko0, ko1) = crate::VM::VM_Backend::Generator_util::stream_key("KryvexObf_", &mut rng);
        let sc_kobf = at.st.call("KryvexObf_", ko0, ko1);
        let body_consts = format!(
            "{st}={nxt}; {bc_scatter} ",
            st = var_state, nxt = obf_s_protos,
bc_scatter = crate::VM::VM_Backend::Generator_flow::build_consts(
                &mut rng, &keys, &kc, pj_name.as_str(), fn_bxor.as_str(),
                sc_index2.as_str(), sc_kobf.as_str(), var_state_flag.as_str(), var_idx_chunk.as_str(),
                var_tbl.as_str(), var_e.as_str(), &ds_names, &dn_names, fn_read_string.as_str(),
                fn_a5.as_str(), fn_read_dec.as_str(), var_enc_c.as_str(), var_cache.as_str(),
                fn_c.as_str(), pf_consts.as_str(),
                &v_ch_i, &v_ch_n, &t,
                pf_opcodes.as_str(), pf_a_arr.as_str(), pf_b_arr.as_str(), pf_c_arr.as_str(), fn_rotl32.as_str(), &fc18,
                &tag_map18, &salt_names, pf_lld.as_str(), pf_cnt18.as_str())
        );
        let pkx1 = { let v = rng.range(0x10000, 0xFFFFF) as i64; crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), v) };
        // ⑱ 惰性原型：读取游标是 var_a2（fn_a3 读载荷子串 P[A2]），read_dec 是
        // 滚动密钥流（k1..k4 随消费演化）——跳读须逐字节喂 rd() 推进外层密钥；
        // 快照取在 len 之后（=子块首字节前的 A2 与滚动密钥），thunk 换入快照解码、
        // 换出恢复；防篡改旗彼时为 false，同样保存/置位/恢复
        let (ln18, p18, s1a, b1a, sv18, svf18, rr18) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        // ⑱.2 读侧掩码还原：ln=u32d() 后与 f(u32d 前快照的 k1..k4, 层内序号) 异或。
        // 公式与写侧 pm_g/pm_sb 同源：mask 字节=(rotl8(ka^kb)+盐)%256，
        // rotl8(r)=fn_b_rotr 的 rotr8(8-r)；盐=(i*A+B)%256，A/B 逐产物随机（pm_s）。
        let (qa18, qb18, qc18, qd18) = (rng.name(), rng.name(), rng.name(), rng.name());
        let pm_lua = |x: &str, y: &str, r: u32, j: usize| -> String {
            format!("({rt}({bx}({x},{y}),8-0X{r:X})+({i}*0X{a:X}+0X{b:X})%256)%256",
                rt = fn_b_rotr, bx = fn_bxor, i = v_ch_i,
                a = pm_s[j * 2], b = pm_s[j * 2 + 1], r = r)
        };
        let m18_0 = pm_lua(&qa18, &qd18, pm_r0, 0);
        let m18_1 = pm_lua(&qb18, &qa18, pm_r1, 1);
        let m18_2 = pm_lua(&qc18, &qb18, pm_r2, 2);
        let m18_3 = pm_lua(&qd18, &qc18, pm_r3, 3);
        let body_protos = format!(
            "{st}={nxt}; {tree9} {c}.{pf_protos}={{}}; local {i}=0; local {n}={a5}(); {md18}={c}.{pf_protos}; {np18}={n}; \
             if not {pj}[({pkx1})] then while {i} < {n} do {i} = {i} + 1; local {qa},{qb},{qc},{qd}=k1,k2,k3,k4; local {ln}={bx}({u32d}(),{m0}+{m1}*256+{m2}*65536+{m3}*16777216); \
               local {p0}={a2}; local {s1},k2s,k3s,k4s=k1,k2,k3,k4; for _=0X1,{ln} do {rd}() end; \
               {c}.{pf_protos}[{i}]=function() local {sv}={a2}; local {svf}={flg}; local {b1},k2b,k3b,k4b=k1,k2,k3,k4; \
                 {a2}={p0}; k1,k2,k3,k4={s1},k2s,k3s,k4s; {flg}=true; local {rr}={dc}(); \
                 {a2}={sv}; k1,k2,k3,k4={b1},k2b,k3b,k4b; {flg}={svf}; return {rr} end end else {i}={n}; {n}=0X0; end; ",
            st = var_state, nxt = obf_s_debug, c = fn_c, pf_protos = pf_protos, a5 = fn_a5,
            dc = fn_decode_chunk, i = v_ch_i, n = v_ch_n, pj = pj_name, pkx1 = pkx1,
            u32d = fn_u32_dec, md18 = md21, np18 = np21,
            a2 = var_a2, flg = var_state_flag, rd = fn_read_dec,
            bx = fn_bxor, qa = qa18, qb = qb18, qc = qc18, qd = qd18,
            m0 = m18_0, m1 = m18_1, m2 = m18_2, m3 = m18_3,
            ln = ln18, p0 = p18, s1 = s1a, b1 = b1a, sv = sv18, svf = svf18, rr = rr18,
            tree9 = it9(&mut rng, var_state.as_str())
        );
        // ⑭ 九元联合 nil 声明 + ⑦ repeat…until false 换皮 + ⑨ 区间树
        let d14: Vec<String> = (0..9).map(|_| rng.name()).collect();
        let body_debug = format!(
            "{st}={nxt}; {tree9} repeat \
             local {d0},{d1},{d2},{d3},{d4},{d5},{d6},{d7},{d8}; \
             local {i}=0; local {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {a5}() end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}(); {a5}(); {a5}() end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}() end; break; until false; ",
            st = var_state, nxt = obf_s_ret, a5 = fn_a5, rs = fn_read_string, i = v_ch_i, n = v_ch_n,
            d0 = d14[0], d1 = d14[1], d2 = d14[2], d3 = d14[3], d4 = d14[4],
            d5 = d14[5], d6 = d14[6], d7 = d14[7], d8 = d14[8],
            tree9 = it9(&mut rng, var_state.as_str())
        );
        // ⑦ while true 壳 + ⑭ return nil 兜底（ret 态跑完显式出）
        // ⑦ while true 壳 + ⑭ return nil 兜底（藏在恒假守卫内，真死代码）
        let r14 = rng.name();
        let body_ret = format!("while true do if not(not {pj}[({pkx1})]) then {g}={g}+1; else {out}={c}; {g}={g}+1; end; local {r14}=nil; if {r14} then return nil end; break; end; ",
            out = v_ch_out, c = fn_c, g = v_ch_g, pj = pj_name, pkx1 = pkx1, r14 = r14);

        // ⑳ 行完整性守卫（用户 2026-09-25 指示，推翻早前"放弃行数守卫/反美化 fail-open"）：
        // 产物只许 1 行注释 + 1 行整体逻辑；采样点用 pcall 触发真实索引错误，
        // 从解释器位置前缀取行号（gmatch 取最后一个 :N:，防 chunkname 内含 :N: 干扰），
        // 行号≠期望值时触发同型索引错误自然崩溃——文案为解释器原生，无 error()、无自造报错。
        // 已知边界：最后一个采样点之后的拆行不在守卫范围内。
        // ⑳.2 守卫伪装化：不再提取行号（gmatch/tonumber/行号变量全删）——
        // 形态是「自检函数 + pcall 验证 + 错误消息内容断言」：探针每构建从
        // 索引/调用/算术/连接四族随机取型；期望行以 ":"..(r1-r2)..":" 针式内嵌
        // 于 find（消息里找不到该前缀才触发同型自然错误）；定义式/内联两形态随机
        // ⑳.3 守卫去线性化：逻辑拆进挂表的多个 function、全部以 : 方法调用
        // 驱动，数据流折进参数树（t:dz(t:cx(e))），定义顺序洗牌+诱饵方法埋伏；
        // 链路：驱动→m1(pcall 自派发)→m2(探针错误族随机)→m3(find 针式)→
        // m4(触发族随机：h and 容纳值 or nil 折叠，nil 时自然崩溃)
        let line_guard = |rng: &mut GenRng| -> String {
            let tbl = rng.name();
            let probe_body = |rng: &mut GenRng| -> String {
                let v = rng.name();
                match rng.range(0, 4) {
                    0 => format!("local {v};return {v}.{f}", v = v, f = rng.name()),
                    1 => format!("local {v};return {v}()", v = v),
                    2 => format!("local {v};return {v}+0X1", v = v),
                    _ => format!("local {v};return {v}..\"\"", v = v),
                }
            };
            let trig_stmt = |rng: &mut GenRng, u: &str| -> (String, String) {
                match rng.range(0, 3) {
                    0 => (format!("{u}.{f}=0X1", u = u, f = rng.name()), "{}".to_string()),
                    1 => (format!("{u}()", u = u), "function()end".to_string()),
                    _ => (format!("{u}={u}..\"\"", u = u), "\"\"".to_string()),
                }
            };
            let (m_drv, m_pcall, m_probe, m_chk, m_hit) =
                (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let (p_err, p_hit, p_u, p_self) = (rng.name(), rng.name(), rng.name(), rng.name());
            let d = rng.range(0x1000, 0xFFFF);
            // ⑧ 针式去冒号字面量：":"..N..":" 是错误消息行号嗅探指纹——
            // 冒号改 string.char(0X3A)（或差式）运行期构造，数值本身不变
            let sc = rng.name();
            let c58 = if rng.range(0, 2) == 0 { "0X3A".to_string() } else { format!("0X{:X}-0X{:X}", 0x1000 + 58, 0x1000) };
            let needle = format!("{s}({c})..(0X{:X}-0X{:X})..{s}({c})", d + 2, d, s = sc, c = c58);
            let pb = probe_body(rng);
            let (ts, tolerant) = trig_stmt(rng, &p_u);
            // ⑦ m_hit 去空壳：原来 local u=h and tol or nil; ts 一眼即知是桩。
            // 先捕获 type(u)，再洗牌插 1~2 句对 ""/function/nil 全安全的填充语，
            // 触发语句按随机形态收尾（直尾 / if not u 尾）——触发语义不变：
            // u=nil 时 ts 仍抛同型自然错误
            let (f1, f2) = (rng.name(), rng.name());
            let mut ht_body = format!("local {u}={h} and {tol} or nil; local {f1}=type({u}); ",
                u = p_u, h = p_hit, tol = tolerant, f1 = f1);
            let mut hopts = vec![
                format!("if {u}~={u} then {u}={u} end; ", u = p_u),
                format!("if {f1}==\"function\"then {u}={u} end; ", f1 = f1, u = p_u),
                format!("if {f1}==\"string\"and #{u}>0X0 then {u}={u} end; ", f1 = f1, u = p_u),
                format!("for {f2}=0X1,0X{} do if {u} then break end end; ", rng.range(2, 6), f2 = f2, u = p_u),
                format!("local {f2}=({u})and 0X1 or 0X0; ", f2 = f2, u = p_u),
            ];
            rng.shuffle(&mut hopts);
            let hn = 1 + rng.range(0, 2);
            for i in 0..hn { ht_body.push_str(&hopts[i]); }
            if rng.range(0, 2) == 0 {
                ht_body.push_str(&ts);
            } else {
                ht_body.push_str(&format!("if not {u} then {ts} end; ", u = p_u, ts = ts));
            }
            let mut ms = vec![
                format!("{t}.{drv}=function({s})local {o},{e}={s}:{pc}() {s}:{ht}({s}:{ck}({e}))end; ",
                    t = tbl, drv = m_drv, s = p_self, o = rng.name(), e = p_err,
                    pc = m_pcall, ht = m_hit, ck = m_chk),
                format!("{t}.{pc}=function({s})return pcall({s}.{pb},{s})end; ",
                    t = tbl, pc = m_pcall, s = p_self, pb = m_probe),
                format!("{t}.{pb}=function({s}){body} end; ",
                    t = tbl, pb = m_probe, s = p_self, body = pb),
                format!("{t}.{ck}=function({s},{e})local {sc}=string.char;return type({e})==\"string\"and {e}:find({ndl})end; ",
                    t = tbl, ck = m_chk, s = p_self, e = p_err, sc = sc, ndl = needle),
                format!("{t}.{ht}=function({s},{h}){hb} end; ",
                    t = tbl, ht = m_hit, s = p_self, h = p_hit, hb = ht_body),
                format!("{t}.{d1}=function({s},{q})return {q} end; ",
                    t = tbl, d1 = rng.name(), s = p_self, q = rng.name()),
            ];
            if rng.range(0, 2) == 1 {
                ms.push(format!("{t}.{d2}=function({s},{q})return {q} end; ",
                    t = tbl, d2 = rng.name(), s = p_self, q = rng.name()));
            }
            rng.shuffle(&mut ms);
            format!("local {t}={{}} {ms} {t}:{drv}() ",
                t = tbl, ms = ms.concat(), drv = m_drv)
        };
        let mut ch_pairs: Vec<(String, String)> = vec![
            (obf_s_init.clone(), body_init),
            (obf_s_insts.clone(), body_insts),
            (obf_s_consts.clone(), body_consts),
            (obf_s_protos.clone(), body_protos),
            (obf_s_debug.clone(), body_debug),
            (obf_s_ret.clone(), body_ret),
        ];
        rng.shuffle(&mut ch_pairs);
        let mut chain = String::new();
        for (idx, (val, body)) in ch_pairs.iter().enumerate() {
            let kw = if idx == 0 { "if" } else { "elseif" };
            chain.push_str(&format!("{} {} == {} then {} ", kw, var_state, val, body));
        }
        chain.push_str(&format!("else {} = {} + 1; end; ", v_ch_g, v_ch_g));

        let block_dec_chunk = format!(
            "local function {fn_dec_chunk}() local {fn_c}, {t}, {var_state} = {{}}, nil, {obf_s_init}; \
             local {g}, {out}, {i}, {n} = 0, nil, 0, 0; \
             while {g} < 1 do {chain} end; \
             return {out} end; ",
            fn_dec_chunk = fn_decode_chunk, fn_c = fn_c, t = t, var_state = var_state,
            obf_s_init = obf_s_init, g = v_ch_g, out = v_ch_out, i = v_ch_i, n = v_ch_n,
            chain = chain
        );

        let mut parts = vec![
            block_p_def,
            block_methods,
            block_vm_core,
            block_packer_vars,
            block_execute_def,
            block_decoder_script,
            block_dec_header,
            block_dec_helpers,
            block_dec_readers,
            block_chacha_setup,
            cluster_parts[0].clone(),
            cluster_parts[1].clone(),
            cluster_parts[2].clone(),
            block_dec_chunk,
        ];

        {
            let lg20 = line_guard(&mut rng);
            let gap20 = rng.range(0, parts.len() + 1);
            parts.insert(gap20, lg20);
        }

        let mut shuffled_guards = at.guards.clone();
        rng.shuffle(&mut shuffled_guards);

        for guard in shuffled_guards {
            let gap_idx = rng.range(0, parts.len() + 1);
            parts.insert(gap_idx, guard);
        }

        let mut out = String::new();
        out.push_str(&format!("local {} = ...;\n", var_l));
        out.push_str(&header_block);
        // ㉑ 保守版明文窗口：NP(原型数)/MD(=C.pr 别名)/TH(thunk 快照)/tw(回收水位)
        // 必须在 execute 定义（parts）之前声明，execute 内才能捕获为 upvalue
        out.push_str(&format!("local {np},{md},{th},{tw}=0,{{}},{{}},0X0; ", np = np21, md = md21, th = th21, tw = tw21));
        // ⑳.4 守卫必须在 return 壳内（用户指示）：三处采样全部作为壳方法体的
        // 开头/缝隙语句，行 2 头部只留 local L=... 和 return({——壳外零检测代码
        out.push_str(&line_guard(&mut rng));
        // ④ 槽位键的运行期推导块必须在所有用键代码之前；
        // finish_setup 把状态链种子/陷阱门等收尾语句并进 setup（在全部注册后调用）
        out.push_str(&sk_setup);
        at.finish_setup();
        out.push_str(&at.setup);
        out.push_str(&format!(" local {} = 0; ", key_seed_var));
        out.push_str(" ");
        // A 解码器前奏打散：五件套不再「库-函数」对齐并列（math.floor,string.char,... 教科书
        // 解码器开场）。先落随机键库表，五个 local 按洗牌序逐个经表取用，.m/["m"] 访问混用；
        // 后续模板仍引用同名局部（math_floor/string_char/...），语义不变
        {
            let pt = rng.name();
            let kf = |v: usize| -> String {
                if v % 2 == 0 { format!("0X{:X}", v) } else { format!("(0X{:X}-7)", v + 7) }
            };
            let (km, ks, kt) = (rng.range(0x1000, 0xFFFFF), rng.range(0x1000, 0xFFFFF), rng.range(0x1000, 0xFFFFF));
            let mut members = vec![
                (km, "math_floor", "floor"),
                (ks, "string_char", "char"),
                (ks, "string_sub", "sub"),
                (ks, "string_byte", "byte"),
                (kt, "table_concat", "concat"),
            ];
            rng.shuffle(&mut members);
            let mut frag = format!("local {}={{[{}]=math,[{}]=string,[{}]=table}}; ", pt, kf(km), kf(ks), kf(kt));
            for (k, loc, m) in &members {
                let acc = if rng.range(0, 2) == 0 { format!(".{}", m) } else { format!("[\"{}\"]", m) };
                frag.push_str(&format!("local {}={}[{}]{}; ", loc, pt, kf(*k), acc));
            }
            out.push_str(&frag);
        }

        for part in parts {
            out.push_str(&part);
            out.push_str(" ");
        }

        out.push_str(&line_guard(&mut rng));
        out.push_str(&format!("local main_chunk={}(); ", fn_decode_chunk));
        out.push_str(&at.trigger);
        out.push_str(&format!(" {} = {{}}; local {} = (getfenv and getfenv() or _ENV or _G); local {}; ", var_builtin_reg, var_boot_env, var_bname));
        // ⑰ 内建名专用簇：独立 key/salt/kind，密文以混合转义字面量内嵌，
        // 与四组常量簇完全分离——导出任何常量簇参数都拿不到内建名
        {
            let bkey: [u32; 8] = std::array::from_fn(|_| rng.next());
            let bsalt: u32 = rng.next();
            let bkind: u32 = rng.next();
            let mut boot_lits: Vec<String> = Vec::with_capacity(Opcodes::builtins::BUILTIN_NAMES.len());
            for (i, name) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
                let blob = crate::VM::VM_Backend::Generator_util::chacha8_xor(&bkey, [bsalt, i as u32, bkind], name.as_bytes());
                boot_lits.push(format!("\"{}\"", crate::VM::VM_Backend::Generator_util::lua_mixed(&blob)));
            }
            let (bk, bs, bcb, bsm, bdec, bpt) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let key_lua = (0..8).map(|i| rng.obfuscate_num(bkey[i] as i64, 1, &keys)).collect::<Vec<_>>().join(",");
            let salt_lua = rng.obfuscate_num(bsalt as i64, 1, &keys);
            let mut idxs: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7, 8];
            for j in (1..idxs.len()).rev() { let k = rng.range(0, j + 1); idxs.swap(j, k); }
            let sig_idx = [idxs[0], idxs[1], idxs[2], idxs[3]];
            let sigma_lua = (0..4)
                .map(|i| {
                    let d = sigma[i].wrapping_sub(bkey[sig_idx[i] - 1]);
                    format!("(({}+K[{}])%4294967296)", rng.obfuscate_num(d as i64, 1, &keys), sig_idx[i])
                })
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!(
                "local {bp}={{{lits}}}; local {kn}={{{key_lua}}}; local {sl}={salt_lua}; ",
                bp = bpt, lits = boot_lits.join(","), kn = bk, key_lua = key_lua, sl = bs, salt_lua = salt_lua));
            out.push_str(&format!(
                "local function {cb}(n1,n2,n3,ctr) local K={kn}; local s={{{sig},K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],ctr,n1,n2,n3}}; local o={{}}; for i=1,16 do o[i]=s[i] end; for _=1,4 do {qr}(s,1,5,9,13); {qr}(s,2,6,10,14); {qr}(s,3,7,11,15); {qr}(s,4,8,12,16); {qr}(s,1,6,11,16); {qr}(s,2,7,12,13); {qr}(s,3,8,9,14); {qr}(s,4,5,10,15) end; local out={{}}; for i=1,16 do local w=(s[i]+o[i])%4294967296; out[(i-1)*4+1]=w%256; out[(i-1)*4+2]=math_floor(w/256)%256; out[(i-1)*4+3]=math_floor(w/65536)%256; out[(i-1)*4+4]=math_floor(w/16777216)%256 end; return out end; ",
                cb = bcb, kn = bk, qr = fn_qr, sig = sigma_lua));
            out.push_str(&format!(
                "local function {sm}(pool_idx,kind,n) local out={{}}; local ctr=0; local pos=1; while pos<=n do local blk={cb}({sl},pool_idx,kind,ctr); for i=1,64 do if pos>n then break end; out[pos]=blk[i]; pos=pos+1 end; ctr=ctr+1 end; return out end; ",
                sm = bsm, cb = bcb, sl = bs));
            let (v_str_i, v_str_g, v_str_ks, v_str_s) = (rng.name(), rng.name(), rng.name(), rng.name());
            let fd18b = rng.name(); // 哑形参：boot 域 bsm 是 3 参，fold/rl 实参多余即弃
            let rl18b = rng.name();
            let bkind_lit = rng.obfuscate_num(bkind as i64, 1, &keys);
            out.push_str(&crate::VM::VM_Backend::Generator_flow::build_decstr(
                &mut rng, bdec.as_str(), bsm.as_str(), bkind_lit.as_str(),
                xor_tbl_var.as_str(), fn_s_byte.as_str(), v_str_ks.as_str(), v_str_s.as_str(),
                v_str_i.as_str(), v_str_g.as_str(), fd18b.as_str(), rl18b.as_str()));
            for (i, _) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
                let slot = builtin_slot_perm[i];
                out.push_str(&format!(
                    "{bname}={bdec}({bp}[{lidx}],{ridx}); {reg}[{slot}]={benv}[{bname}]; if {reg}[{slot}]==nil and getgenv then {reg}[{slot}]=getgenv()[{bname}] end; ",
                    bname = var_bname, bdec = bdec, bp = bpt, lidx = i + 1, ridx = i,
                    reg = var_builtin_reg, slot = slot + 1, benv = var_boot_env
                ));
            }
            // ⑱ 用毕销毁（⑳.1 伪装化）：连续 X=nil 运行是指纹——每个变量换一种
            // "取值赋值" 形态消化，nil 全部来自合法表达式的自然缺失：
            // 槽位表取未用键 / 未命中补取(恒执行) / 空表取键 / or 链 /
            // 条件式恒 nil / 间接索引，混入常见池取图案，无 =nil 字面赋值
            let (g1, g2, g3) = (rng.name(), rng.name(), rng.name());
            let h1 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h2 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h3 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h4 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h5 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h6 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            out.push_str(&format!(
                "local {g1}={reg}[{h1}]; {bk}={g1}; if not {g1} then {bs}={reg}[{h2}] end; \
                 local {g2}=({{}})[{h3}]; {bcb}={g2}; {bsm}={reg}[{h4}] or ({{}})[{h5}]; \
                 {bdec}={bdec} and nil or {bdec}; local {g3}={reg}; {bpt}={g3}[({{}})[{h6}]]; ",
                reg = var_builtin_reg, g1 = g1, g2 = g2, g3 = g3,
                bk = bk, bs = bs, bcb = bcb, bsm = bsm, bdec = bdec, bpt = bpt,
                h1 = h1, h2 = h2, h3 = h3, h4 = h4, h5 = h5, h6 = h6));
        }
        // ㉑ thunk 快照：密文 thunk 常驻，明文可随时写回回收
        out.push_str(&format!("for {j}=1,{np} do {th}[{j}]={md}[{j}] end; ",
            j = rng.name(), np = np21, th = th21, md = md21));
        let fu = rng.name();
        
        out.push_str(" ");
        out.push_str(&format!("return {}(main_chunk, {}, {{}}, {}) end,{}=function(x) x:{}() end", fn_execute, var_boot_env, var_l, fu, wai));
        out.push_str(&format!(" }}):{}()", fu));
        out
    }
}
