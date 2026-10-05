use std::time::SystemTime;
use rand::{rngs::StdRng, Rng, SeedableRng, random};

use crate::VM::Control_Flow::Control_flow::ControlFlowBuilder;
use crate::VM::VM_Backend::Generator::GenRng;
use crate::VM::VM_Backend::Sandbox::generate_sandbox;

struct SimpleRng {
    rng: StdRng,
}

impl SimpleRng {
    fn new(seed: u32) -> Self {
        let seed_val = if seed == 0 {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        } else {
            let t = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            t ^ (seed as u64)
        };
        
        Self {
            rng: StdRng::seed_from_u64(seed_val),
        }
    }

    fn next(&mut self) -> u32 {
        self.rng.random()
    }

    fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max { return min; }
        self.rng.random_range(min..max)
    }
}

#[derive(Clone, Copy)]
enum Step {
    Raw,
    Link { stride: u16, span: u16 },
}

pub struct Packer;

impl Packer {
    pub fn pack(input: &[u8], vm_rng: &mut GenRng, uni: &mut crate::VM::VM_Backend::Generator_util::UniStream) -> (String, String, String) {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0xDEADBEEF);
        let mut rng = SimpleRng::new(seed);
        let mut keys = Vec::new();
        for _ in 0..16 {
            keys.push((rng.next() & 0xFF) as u8);
        }
        let (alpha_str, alpha_perm) = Self::generate_alphabet();

        // 原生流（Native Stream）：16 字节种子只在运行期参与「折叠 + S-box 现场构造」，
        // 密钥流 = 双 LCG 状态 + 位置 + 前一密文字节 混合后查运行期 S-box。
        // 每段各自起一条流（位置从 0 起），周期不再固定 16 字节。
        let nat = crate::VM::VM_Backend::Generator_native::Native::new(vm_rng);
        let n_sbox = nat.sbox(&keys);

        let sandbox = generate_sandbox("kryvex");
        let compressed_sb = Self::encode_stream(sandbox.payload.as_bytes());
        let (encrypted_sb, _) = nat.encrypt(&keys, &n_sbox, &compressed_sb);
        let b86_sb = Self::base86_encode_with_alpha(&encrypted_sb, &alpha_str, &alpha_perm);

        // 第二段单起一条流：解码器 stage2 会重放内核初始化——若续用第一段的收尾
        // 状态，两段之间任一字节的偏差都会让后续整条流错位（第一段未必吃满字节）。
        // 主载荷自适应选择：对原样字节与 LZ 流都走相同的 Native Stream / base86，
        // 最后按 token 替换后的真实字符数择小。高熵主载荷不再承担 LZ 原始 token 的
        // 每 8 字节标志位开销；压缩确有收益时仍沿用原解码路径。
        let b86_compressed_main = {
            let compressed_main = Self::encode_stream(input);
            let (encrypted_main, _) = nat.encrypt(&keys, &n_sbox, &compressed_main);
            Self::base86_encode_with_alpha(&encrypted_main, &alpha_str, &alpha_perm)
        };
        let b86_raw_main = {
            let (encrypted_main, _) = nat.encrypt(&keys, &n_sbox, input);
            Self::base86_encode_with_alpha(&encrypted_main, &alpha_str, &alpha_perm)
        };

        // 用字母表中未参与 0..85 编码的诱饵字符作逐产物随机转义前缀；原密文里
        // 不可能自然出现此前缀。定长 5 字符码字避免歧义，且不生成 ']' 以保留 `[=[...]=]`。
        let (symbol_marker, symbol_map) = Self::generate_symbol_codebook(&alpha_str, &alpha_perm, vm_rng);
        let escaped_sb = Self::replace_symbols(&b86_sb, &symbol_map);
        let escaped_compressed_main = Self::replace_symbols(&b86_compressed_main, &symbol_map);
        let escaped_raw_main = Self::replace_symbols(&b86_raw_main, &symbol_map);
        let (escaped_main, main_is_raw) = if escaped_raw_main.len() <= escaped_compressed_main.len() {
            (escaped_raw_main, true)
        } else {
            (escaped_compressed_main, false)
        };

        // 判据①修复：'~' 分隔符废除——载荷是连续一段，sb/main 边界由
        // 解码器按字符运行点切分。split_pos 必须是 token 替换后的 sandbox 字符数。
        let split_pos = escaped_sb.len();
        let lua_payload = format!("{}{}", escaped_sb, escaped_main);

        let (decoder_script, entry_func) = Self::build_decoder(
            &keys, &nat, &alpha_str, &alpha_perm, split_pos,
            symbol_marker, &symbol_map, main_is_raw, vm_rng, uni,
        );
        (lua_payload, decoder_script, entry_func)
    }

    fn encode_stream(input: &[u8]) -> Vec<u8> {
        let len = input.len();
        if len == 0 {
            return Vec::new();
        }

        let mut costs = vec![u32::MAX; len + 1];
        let mut links = vec![Step::Raw; len + 1];
        costs[0] = 0;

        for i in 0..len {
            if costs[i] == u32::MAX {
                continue;
            }

            let cost_raw = costs[i] + 9;
            if cost_raw < costs[i + 1] {
                costs[i + 1] = cost_raw;
                links[i + 1] = Step::Raw;
            }

            let max_search = if i > 65535 { i - 65535 } else { 0 };
            let max_span = std::cmp::min(258, len - i);

            let mut optimal_strides = vec![0u16; max_span + 1];
            let mut peak_span = 0;

            for start in max_search..i {
                if peak_span < max_span && input[start + peak_span] == input[i + peak_span] {
                    let mut current_span = 0;
                    while current_span < max_span && input[start + current_span] == input[i + current_span] {
                        current_span += 1;
                    }
                    if current_span > peak_span {
                        for l in (peak_span + 1)..=current_span {
                            optimal_strides[l] = (i - start) as u16;
                        }
                        peak_span = current_span;
                    }
                }
            }

            for span_l in 3..=peak_span {
                let cost_link = costs[i] + 25;
                let next_pos = i + span_l;
                if cost_link < costs[next_pos] {
                    costs[next_pos] = cost_link;
                    links[next_pos] = Step::Link {
                        stride: optimal_strides[span_l],
                        span: span_l as u16,
                    };
                }
            }
        }

        let mut route = Vec::new();
        let mut cursor = len;
        while cursor > 0 {
            match links[cursor] {
                Step::Raw => {
                    route.push(Step::Raw);
                    cursor -= 1;
                }
                Step::Link { stride, span } => {
                    route.push(Step::Link { stride, span });
                    cursor -= span as usize;
                }
            }
        }
        route.reverse();

        let mut output = Vec::new();
        let mut route_head = 0;
        let route_len = route.len();
        let mut read_head = 0;

        while route_head < route_len {
            let mut header = 0u8;
            let mut payload_part = Vec::new();

            for bit in 0..8 {
                if route_head >= route_len {
                    break;
                }

                match route[route_head] {
                    Step::Raw => {
                        header |= 1 << bit;
                        payload_part.push(input[read_head]);
                        read_head += 1;
                    }
                    Step::Link { stride, span } => {
                        let b1 = (stride >> 8) as u8;
                        let b2 = (stride & 0xFF) as u8;
                        let b3 = (span - 3) as u8;
                        payload_part.push(b1);
                        payload_part.push(b2);
                        payload_part.push(b3);
                        read_head += span as usize;
                    }
                }
                route_head += 1;
            }

            output.push(header);
            output.extend_from_slice(&payload_part);
        }

        output
    }

    /// 反混淆判据①修复：旧字母表 86 字符，载荷字符集 = 86 + 分隔符 '~' = 恰好 87
    /// （「87 差 1」），一次集合比对就锁定编码与字母表。现在：
    /// - 91 个安全可见字符（剔除 [ ] ~ ：长字符串定界 `]=]` 相关字符不用）取 86+K（K=3..5）；
    /// - 数字 0..85 随机注入其中 86 个槽位（返回的 perm：数字 → 字母表位置），
    ///   其余 K 个是永不入载荷的诱饵；
    /// - 分隔符 '~' 废除（sb/main 边界改按运行期长度切分，见 build_decoder）。
    /// 集合比对结果 = K + 未命中字符数，逐产物浮动，不再是干净的「差 1」。
    fn generate_alphabet() -> (String, Vec<usize>) {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0x56781234);
        let mut rng = SimpleRng::new(seed);

        let mut pool: Vec<char> = (33u8..=126u8)
            .filter(|&c| c != b'[' && c != b']' && c != b'~')
            .map(|c| c as char)
            .collect();
        let n = pool.len();
        for i in (1..n).rev() {
            let j = rng.next_range(0, i + 1);
            pool.swap(i, j);
        }
        let extra = rng.next_range(3, 6);
        let alphabet: Vec<char> = pool[..86 + extra].to_vec();
        let mut slots: Vec<usize> = (0..alphabet.len()).collect();
        for i in (1..slots.len()).rev() {
            let j = rng.next_range(0, i + 1);
            slots.swap(i, j);
        }
        let perm: Vec<usize> = slots[..86].to_vec();
        (alphabet.iter().collect(), perm)
    }

    fn base86_encode_with_alpha(input: &[u8], alphabet_str: &str, perm: &[usize]) -> String {
        let base_chars: Vec<char> = alphabet_str.chars().collect();
        let mut encoded = String::new();
        let len = input.len();
        let chunks = len / 4;
        for i in 0..chunks {
            let val = ((input[i * 4] as usize) << 24)
                | ((input[i * 4 + 1] as usize) << 16)
                | ((input[i * 4 + 2] as usize) << 8)
                | (input[i * 4 + 3] as usize);
            let c1 = val / 54700816;
            let r1 = val % 54700816;
            let c2 = r1 / 636056;
            let r2 = r1 % 636056;
            let c3 = r2 / 7396;
            let r3 = r2 % 7396;
            let c4 = r3 / 86;
            let c5 = r3 % 86;
            encoded.push(base_chars[perm[c1 as usize]]);
            encoded.push(base_chars[perm[c2 as usize]]);
            encoded.push(base_chars[perm[c3 as usize]]);
            encoded.push(base_chars[perm[c4 as usize]]);
            encoded.push(base_chars[perm[c5 as usize]]);
        }
        let rem = len % 4;
        if rem == 3 {
            let val = ((input[len - 3] as usize) << 16)
                | ((input[len - 2] as usize) << 8)
                | (input[len - 1] as usize);
            let c1 = val / 636056;
            let r1 = val % 636056;
            let c2 = r1 / 7396;
            let r2 = r1 % 7396;
            let c3 = r2 / 86;
            let c4 = r2 % 86;
            encoded.push(base_chars[perm[c1 as usize]]);
            encoded.push(base_chars[perm[c2 as usize]]);
            encoded.push(base_chars[perm[c3 as usize]]);
            encoded.push(base_chars[perm[c4 as usize]]);
        } else if rem == 2 {
            let val = ((input[len - 2] as usize) << 8) | (input[len - 1] as usize);
            let c1 = val / 7396;
            let r1 = val % 7396;
            let c2 = r1 / 86;
            let c3 = r1 % 86;
            encoded.push(base_chars[perm[c1 as usize]]);
            encoded.push(base_chars[perm[c2 as usize]]);
            encoded.push(base_chars[perm[c3 as usize]]);
        } else if rem == 1 {
            let val = input[len - 1] as usize;
            let c1 = val / 86;
            let c2 = val % 86;
            encoded.push(base_chars[perm[c1 as usize]]);
            encoded.push(base_chars[perm[c2 as usize]]);
        }
        encoded
    }

    /// 为用户给出的特殊符号集合逐产物生成可逆码本。marker 取自字母表诱饵位，
    /// 因而不可能自然出现在 base86 密文中；所有码字等长，解码无需模式匹配转义。
    fn generate_symbol_codebook(alphabet: &str, perm: &[usize], rng: &mut GenRng) -> (u8, Vec<(u8, String)>) {
        const TARGET_SYMBOLS: &[u8] = b"\"'%$!~#}& ";
        let alphabet_bytes = alphabet.as_bytes();
        let decoy_positions: Vec<usize> = (0..alphabet_bytes.len())
            .filter(|position| !perm.contains(position))
            .collect();

        let mut marker_candidates: Vec<u8> = decoy_positions.iter()
            .map(|&position| alphabet_bytes[position])
            .filter(|symbol| !TARGET_SYMBOLS.contains(symbol))
            .collect();
        if marker_candidates.is_empty() {
            marker_candidates = decoy_positions.iter()
                .map(|&position| alphabet_bytes[position])
                .collect();
        }
        let marker = marker_candidates[rng.range(0, marker_candidates.len())];

        let used_symbols: Vec<u8> = perm.iter().map(|&position| alphabet_bytes[position]).collect();
        let mut symbols: Vec<u8> = TARGET_SYMBOLS.iter().copied()
            .filter(|symbol| *symbol != marker && used_symbols.contains(symbol))
            .collect();
        rng.shuffle(&mut symbols);

        // 不含 ']'，避免替换结果关闭外层 Lua 长字符串；其余可见字符允许参与随机码字。
        let token_chars: Vec<u8> = (33u8..=126u8)
            .filter(|&byte| byte != b']' && byte != marker)
            .collect();
        let mut used_codes: Vec<String> = Vec::with_capacity(symbols.len());
        let mut mapping = Vec::with_capacity(symbols.len());
        for symbol in symbols {
            loop {
                let mut token = String::with_capacity(5);
                token.push(marker as char);
                for _ in 0..4 {
                    token.push(token_chars[rng.range(0, token_chars.len())] as char);
                }
                if !used_codes.contains(&token) {
                    used_codes.push(token.clone());
                    mapping.push((symbol, token));
                    break;
                }
            }
        }
        (marker, mapping)
    }

    fn replace_symbols(input: &str, mapping: &[(u8, String)]) -> String {
        let mut lookup: [Option<&str>; 256] = [None; 256];
        for (symbol, token) in mapping {
            lookup[*symbol as usize] = Some(token.as_str());
        }
        let mut output = String::with_capacity(input.len());
        for byte in input.bytes() {
            if let Some(token) = lookup[byte as usize] {
                output.push_str(token);
            } else {
                output.push(byte as char);
            }
        }
        output
    }

    fn build_decoder(
        keys: &[u8],
        nat: &crate::VM::VM_Backend::Generator_native::Native,
        alphabet: &str,
        perm: &[usize],
        split_pos: usize,
        symbol_marker: u8,
        symbol_map: &[(u8, String)],
        main_is_raw: bool,
        rng: &mut GenRng,
        uni: &mut crate::VM::VM_Backend::Generator_util::UniStream,
    ) -> (String, String) {
        // 原生流（Native Stream）解密内核：运行期指纹 + 现场构造 S-box + 每字节步进，
        // 闭包按 upvalue 捕获状态——密钥材料不以数据形态出现在产物里。
        let kern = crate::VM::VM_Backend::Generator_native::emit_decrypt_kernel(rng, nat, "pack");
        let kern_decl = kern.decl.clone();
        let kern_init_fn = kern.init_fn.clone();
        let kern_step = kern.step.clone();
        let f_entry = rng.name();
        let v_data = rng.name();
        // 只用原生 loadstring：执行器/沙盒常把 loadstring 换成 Lua 钩子，
        // 这里在调用前探测一次，优先挑原生（C）实现，见 loadstring_probe_lua。
        let f_isnat = rng.name();
        let f_getls = rng.name();
        let v_pload = rng.name();

        let m_next = rng.name();
        let m_init_map = rng.name();
        let m_init_insts = rng.name();
        let m_init_handlers = rng.name();
        let m_run = rng.name();
        let m_main = rng.name();

        let op_state0 = rng.range(100, 200);
        let op_state1 = rng.range(201, 300);
        let op_state2 = rng.range(301, 400);
        let op_state3 = rng.range(401, 500);
        let op_state4 = rng.range(501, 600);
        let op_state5 = rng.range(601, 700);
        let op_state6 = rng.range(701, 800);
        let op_state7 = rng.range(801, 900);
        let op_state8 = rng.range(901, 1000);
        let op_state9 = rng.range(1001, 1100);

        // ㉕ pc 状态号运行时耦合：值域保持 1..10 的稠密排列（路由器用
        // #s.insts 做越界哨兵、取指后还有 pc+1 快推）；表槽直接写入数值字面量，
        // 发射顺序洗牌，引用走状态表/委托两形态。
        let mut pcs: Vec<usize> = (0..10).collect();
        for i in (1..10).rev() {
            let j = rng.range(0, i + 1);
            pcs.swap(i, j);
        }

        let tamper_val = rng.range(10, 50);

        // ㉕ pc 状态表基建：在解码脚本所有方法之前声明，被各闭包按 upvalue 捕获。
        // 槽位与值直接用数值字面量写入；状态仍经表访问，稠密 1..10 保持 #s.insts 语义。
        let (pct, pcdv) = (rng.name(), rng.name());
        let mut pc_fills: Vec<String> = Vec::new();
        for n in 0..10 {
            pc_fills.push(format!("{}[{}]={};", pct,
                ControlFlowBuilder::obf_num((n + 1) as i64, rng),
                ControlFlowBuilder::obf_num((pcs[n] + 1) as i64, rng)));
        }
        rng.shuffle(&mut pc_fills);
        let pc_infra = format!("local {}={{}};{}local {}=function(w,u) local z=w%0X2 return u+(z-z) end;",
            pct, pc_fills.join(""), pcdv);
        // pc 值引用形态：②状态表引用 / ④委托调用（数值本身永不直出）
        let pc_ref = |rng: &mut GenRng, n: usize| -> String {
            let idx = ControlFlowBuilder::obf_num((n + 1) as i64, rng);
            if rng.range(0, 3) == 0 {
                format!("{}({},{}[{}])", pcdv, ControlFlowBuilder::obf_num(rng.range64(0x100, 0xFFFF), rng), pct, idx)
            } else {
                format!("{}[{}]", pct, idx)
            }
        };

        // 状态表字段名逐产物随机化：这些字段名原先直接以明文出现在产物里
        // （data / pc / kidx / memo / ...）。压缩器只重命名长度 > 4 的成员名，
        // 所以短名会原样留下；而 char/byte/floor/concat/... 又因为与库函数同名，
        // 被压缩器的保护名单挡住。这里在生成端统一换成随机短名。
        let p_data = rng.name(); let p_pc = rng.name(); let p_insts = rng.name(); let p_tamper = rng.name();
        let p_handlers = rng.name(); let p_r_flg = rng.name(); let p_r_vals = rng.name(); let p_r_len = rng.name();
        let p_tail_flg = rng.name(); let p_raw = rng.name(); let p_map = rng.name(); let p_idx = rng.name(); let p_len = rng.name();
        let p_k = rng.name(); let p_kidx = rng.name(); let p_buf = rng.name(); let p_memo = rng.name();
        let raw_flag_num = ControlFlowBuilder::obf_num(255, rng);
        let p_unpack = rng.name(); let p_char = rng.name(); let p_byte = rng.name(); let p_floor = rng.name();
        let p_insert = rng.name(); let p_concat = rng.name(); let p_remove = rng.name(); let p_reverse = rng.name();
        let p_bc = rng.name(); let p_res = rng.name(); let p_f = rng.name(); let p_p1 = rng.name();
        let p_p2 = rng.name(); let p_w = rng.name(); let p_u = rng.name(); let p_ptr = rng.name();
        // ㉙② 句柄键基/步长字段（运行时推导，防句柄静态计数）
        let p_hk = rng.name(); let p_hs = rng.name();

        let mut insts_init = Vec::new();
        // ㉕ pc 键走状态表引用；op 值直接写为数值字面量，运行期仍与句柄注册键 op+tamper 对齐。
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 0), ControlFlowBuilder::obf_num(op_state0 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 1), ControlFlowBuilder::obf_num(op_state1 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 2), ControlFlowBuilder::obf_num(op_state2 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 3), ControlFlowBuilder::obf_num(op_state3 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 4), ControlFlowBuilder::obf_num(op_state4 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 5), ControlFlowBuilder::obf_num(op_state5 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 6), ControlFlowBuilder::obf_num(op_state6 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 7), ControlFlowBuilder::obf_num(op_state7 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 8), ControlFlowBuilder::obf_num(op_state8 as i64, rng)));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_ref(rng, 9), ControlFlowBuilder::obf_num(op_state9 as i64, rng)));

        // ㉕ 初始化状态机运行时耦合化：状态号（原 1..N 洗牌裸字面量）改为
        // 运行期等差数列填表，比较/转移/初值经状态表/惰性槽/委托三形态流动
        let kseed_i = format!("(#s.data)+(s.k[{}])", ControlFlowBuilder::obf_num(1, rng));
        let (insts_decl, init_insts_loop_body) =
            ControlFlowBuilder::build_router_machine(&insts_init, "while not(false or false) do ", "st", &kseed_i, rng);
        let init_insts_loop = format!("{}{}", insts_decl, init_insts_loop_body);

        let mut handlers_init = Vec::new();
        // ㉙③ 句柄体去平坦：每个句柄改成「加载期语句闭包表 + 运行期游走」——
        // 语句组变闭包（定义洗牌发射），真实执行序编进混淆键序列 S；组返回
        // false 立即停走（早退语义与原 return end 一致）。闭包表在建句柄时一次
        // 建成，热路径每步只多一次表查+微调用。
        let scramble_handler = |groups: Vec<String>, rng: &mut GenRng| -> String {
            let tn = rng.name();
            let sn = rng.name();
            let mut def_keys: Vec<String> = Vec::new();
            let mut defs: Vec<String> = Vec::new();
            for g in &groups {
                let k = ControlFlowBuilder::obf_num(rng.range64(0x100, 0xFFFFF), rng);
                def_keys.push(k.clone());
                defs.push(format!("{}[{}]=function() {} end;", tn, k, g));
            }
            rng.shuffle(&mut defs);
            let jn = rng.name();
            let gj = rng.name();
            format!("(function() local {}={{}};{}local {}={{{}}};return function(inst) local {}={};while {}<={} do local {}={}[{}[{}]];if not {}() then break end;{}={}+{} end end end)()",
                tn, defs.join(""), sn, def_keys.join(","),
                jn, ControlFlowBuilder::obf_num(1, rng),
                jn, ControlFlowBuilder::obf_num(groups.len() as i64, rng),
                gj, tn, sn, jn, gj, jn, jn, ControlFlowBuilder::obf_num(1, rng))
        };
        // ㉙② 注册键运行时化：键 = 键基 + (指令码+篡改常量)*步长；键基/步长在
        // m_main 里由密钥字节运行时推导（见模板），静态求值拿不到键集合
        let reg_key = |op: usize, rng: &mut GenRng| format!("s.hk+(({})+({}))*s.hs",
            ControlFlowBuilder::obf_num(op as i64, rng), ControlFlowBuilder::obf_num(tamper_val as i64, rng));
        let fail_g = |fld: &str, rng: &mut GenRng| format!(
            "if not s.{} then s.r_flg=true;s.r_vals={{s.concat(s.res)}};s.r_len={};return false end;",
            fld, ControlFlowBuilder::obf_num(1, rng));

        // H0：复位位计数/结果表 → 落 pc1
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state0, rng),
            scramble_handler(vec![
                format!("s.bc={};s.res={{}};return true", ControlFlowBuilder::obf_num(8, rng)),
                format!("s.pc={};return true", pc_ref(rng, 1)),
            ], rng)));
        // H1：位计数分流（and/or 选择式替代显式 if）
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state1, rng),
            scramble_handler(vec![
                format!("s.bc=s.bc+{};return true", ControlFlowBuilder::obf_num(0, rng)),
                format!("s.pc=(s.bc>{} and ({}) or ({}));return true",
                    ControlFlowBuilder::obf_num(7, rng), pc_ref(rng, 2), pc_ref(rng, 3)),
            ], rng)));
        // H2：读标志字节（失败早退）→ 位计数清零 → 落 pc3
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state2, rng),
            scramble_handler(vec![
                format!("s.f=q:{}(s);{}s.bc={};return true", m_next, fail_g("f", rng), ControlFlowBuilder::obf_num(0, rng)),
                format!("s.pc={};return true", pc_ref(rng, 3)),
            ], rng)));
        // H3：标志位分流（模二选择式）
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state3, rng),
            scramble_handler(vec![
                format!("s.bc=s.bc+{};return true", ControlFlowBuilder::obf_num(0, rng)),
                format!("s.pc=((s.f%{})=={} and ({}) or ({}));return true",
                    ControlFlowBuilder::obf_num(2, rng), ControlFlowBuilder::obf_num(1, rng), pc_ref(rng, 4), pc_ref(rng, 5)),
            ], rng)));
        // H4：读一字节入结果表（失败早退）→ 落 pc9
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state4, rng),
            scramble_handler(vec![
                format!("s.u=q:{}(s);{}s.res[#s.res+{}]=s.char(s.u);return true",
                    m_next, fail_g("u", rng), ControlFlowBuilder::obf_num(1, rng)),
                format!("s.pc={};return true", pc_ref(rng, 9)),
            ], rng)));
        // H5/H6/H7：读参数（失败早退）→ 落各自下一态
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state5, rng),
            scramble_handler(vec![
                format!("s.p1=q:{}(s);{}return true", m_next, fail_g("p1", rng)),
                format!("s.pc={};return true", pc_ref(rng, 6)),
            ], rng)));
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state6, rng),
            scramble_handler(vec![
                format!("s.p2=q:{}(s);{}return true", m_next, fail_g("p2", rng)),
                format!("s.pc={};return true", pc_ref(rng, 7)),
            ], rng)));
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state7, rng),
            scramble_handler(vec![
                format!("s.w=q:{}(s);{}return true", m_next, fail_g("w", rng)),
                format!("s.pc={};return true", pc_ref(rng, 8)),
            ], rng)));
        // 字节拼装权重直接使用 0X100，不再包成加减乘除恒等式。
        let w256 = "s.p1*0X100+s.p2".to_string();
        // H8：回引复制（循环体整组装进一个组，局部迭代器替代原形参）→ 落 pc9
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state8, rng),
            scramble_handler(vec![
                {
                    let it = rng.name();
                    format!("s.ptr=#s.res-({})+{};local {}={};while true do if {}>=s.w+{} then break end;s.res[#s.res+{}]=s.res[s.ptr+{}];{}={}+{} end;return true",
                        w256, ControlFlowBuilder::obf_num(1, rng), it, ControlFlowBuilder::obf_num(0, rng),
                        it, ControlFlowBuilder::obf_num(3, rng), ControlFlowBuilder::obf_num(1, rng), it, it, it, ControlFlowBuilder::obf_num(1, rng))
                },
                format!("s.pc={};return true", pc_ref(rng, 9)),
            ], rng)));
        // H9：位计数推进（三组语句三闭包）→ 落 pc1
        handlers_init.push(format!("s.handlers[{}] = {};", reg_key(op_state9, rng),
            scramble_handler(vec![
                format!("s.f=s.floor(s.f/{});return true", ControlFlowBuilder::obf_num(2, rng)),
                format!("s.bc=s.bc+{};return true", ControlFlowBuilder::obf_num(1, rng)),
                format!("s.pc={};return true", pc_ref(rng, 1)),
            ], rng)));
        // ㉙② 诱饵句柄：键域远离真实键系数带（指令码+篡改 ≤ 1150），永不命中；
        // 键集枚举/计数看到的不再是「恰好 10 个连续可推键」
        for _ in 0..3 {
            let dk = rng.range(2000, 9000);
            handlers_init.push(format!("s.handlers[s.hk+({})*s.hs] = function(inst) end;",
                ControlFlowBuilder::obf_num(dk as i64, rng)));
        }

        // ㉕ 句柄注册状态机同样运行时耦合化（原 1..N 洗牌裸字面量）
        let kseed = format!("(#s.data)+(s.k[{}])", ControlFlowBuilder::obf_num(1, rng));
        let (handlers_decl, init_handlers_loop_body) =
            ControlFlowBuilder::build_router_machine(&handlers_init, "while true do ", "st", &kseed, rng);
        let init_handlers_loop = format!("{}{}", handlers_decl, init_handlers_loop_body);

        let router_code = ControlFlowBuilder::build_fast_router(
            "s.pc", "s.insts", "inst", "s.handlers", "s.r_flg", "s.r_vals", "s.r_len", "s.tamper", "s.tail_flg",
            &kseed, "s.hk", "s.hs", rng
        );

        let num_key_parts = rng.range(3, 7);
        let mut key_boundaries = Vec::new();
        for _ in 0..num_key_parts.saturating_sub(1) {
            key_boundaries.push(rng.range(1, keys.len()));
        }
        key_boundaries.sort_unstable();
        key_boundaries.dedup();
        let mut kb = vec![0];
        kb.extend(key_boundaries);
        if *kb.last().unwrap() != keys.len() {
            kb.push(keys.len());
        }

        // ㉓.7 密钥分片/字母表/数字表**不再以字节表落盘**（原来 1/3 概率发
        // `s.char(49,50,…)`、其余发 \\ddd 转义字面量）：整片登记进统一流，
        // 落盘只有密文数字，取用点是惰性解密表达式（首访解密、其后缓存直通）。
        // 语句收集到 map_fetch_stmts，统一落在 m_init_map 的方法体开头（语句位置）。
        let mut map_fetch_stmts = String::new();
        let mut mk_part = |rng: &mut GenRng,
                           uni: &mut crate::VM::VM_Backend::Generator_util::UniStream,
                           plain: &[u8]|
         -> String {
            // 1/3 概率倒序存放：取用点用 s.reverse 还原，形态不齐整
            let rev = rng.range(0, 3) == 0;
            let mut b = plain.to_vec();
            if rev {
                b.reverse();
            }
            let id = uni.register_bytes(&b);
            let (st, ex) = uni.fetch(rng, id);
            map_fetch_stmts.push_str(&st);
            if rev {
                format!("s.reverse({})", ex)
            } else {
                ex
            }
        };
        let mut key_parts_exprs = Vec::new();
        let num_actual_key_parts = kb.len() - 1;
        for i in 0..num_actual_key_parts {
            let start = kb[i];
            let end = kb[i + 1];
            let part_bytes = &keys[start..end];
            key_parts_exprs.push(mk_part(rng, uni, part_bytes));
        }
        let combined_key_expr = key_parts_exprs.join(",");

        let chars: Vec<char> = alphabet.chars().collect();
        // 判据①修复：数字串与字母表位置一一对应（byte=数字+1；诱饵位=255，
        // 永不查表）。解码端按「字符→数字串同位字节-1」建表，不再用位置序号，
        // 所以诱饵可以插在字母表任意位置。
        let mut dig_bytes: Vec<u8> = vec![255u8; chars.len()];
        for (d, &pos) in perm.iter().enumerate() { dig_bytes[pos] = (d + 1) as u8; }
        let num_parts = rng.range(6, 12);
        let mut part_boundaries = Vec::new();
        for _ in 0..num_parts - 1 {
            part_boundaries.push(rng.range(1, chars.len()));
        }
        part_boundaries.sort_unstable();
        part_boundaries.dedup();
        let mut boundaries = vec![0];
        boundaries.extend(part_boundaries);
        if *boundaries.last().unwrap() != chars.len() {
            boundaries.push(chars.len());
        }

        let mut parts_exprs = Vec::new();
        let mut digs_exprs = Vec::new();
        let num_actual_parts = boundaries.len() - 1;

        for i in 0..num_actual_parts {
            let start = boundaries[i];
            let end = boundaries[i + 1];
            let part_chars = &chars[start..end];
            let part_digs = &dig_bytes[start..end];
            let cb: Vec<u8> = part_chars.iter().map(|&c| c as u8).collect();
            parts_exprs.push(mk_part(rng, uni, &cb));
            digs_exprs.push(mk_part(rng, uni, part_digs));
        }
        
        let combined_alpha_expr = parts_exprs.join(",");
        let combined_digs_expr = digs_exprs.join(",");

        // ㉓ 统一流加密（UniStream）："return " 前缀、chunk 名、probe 九件套、
        // 守卫散点串全并入同一条 LCG 密钥流——惰性解密+缓存，密文只以数字落盘，
        // 解码脚本作用域里零 "" 字面量。
        let id_ret = uni.register("return ");
        let id_chunk = uni.register("kryvex");
        let (ret_stmt, ret_expr) = uni.fetch(rng, id_ret);
        let (chunk_stmt, chunk_expr) = uni.fetch(rng, id_chunk);
        let probe = crate::VM::VM_Backend::Generator_util::loadstring_probe_lua(&f_isnat, &f_getls, &v_pload, uni, rng);
        // ── 第 2 项：这层解码器也不再是「初始化 → 拆分 → 解码 → 执行」的清晰骨架 ──
        // 状态表构造里 32 个键值对彼此独立，顺序打乱；stage2 里 16 条初始化赋值同样打乱
        // （data/len 那一对有先后依赖，单独保持原序）；gmatch 的 for-in 拆成显式迭代器 + 影子守卫。
        let mut pk_pairs: Vec<String> = vec![
            format!("{} = data", p_data),
            format!("{} = {}", p_pc, pc_ref(rng, 0)),
            format!("{} = {{}}", p_insts),
            format!("{} = {}", p_tamper, ControlFlowBuilder::obf_num(tamper_val as i64, rng)),
            format!("{} = {{}}", p_handlers),
            format!("{} = false", p_r_flg),
            format!("{} = {{}}", p_r_vals),
            format!("{} = 0", p_r_len),
            format!("{} = false", p_tail_flg),
            format!("{} = false", p_raw),
            format!("{} = {{}}", p_map),
            format!("{} = 1", p_idx),
            format!("{} = #data", p_len),
            format!("{} = {{}}", p_k),
            format!("{} = 0", p_kidx),
            format!("{} = {{}}", p_buf),
            format!("{} = {{}}", p_memo),
            format!("{} = unpack", p_unpack),
            format!("{} = char", p_char),
            format!("{} = byte", p_byte),
            format!("{} = floor", p_floor),
            format!("{} = insert", p_insert),
            format!("{} = concat", p_concat),
            format!("{} = remove", p_remove),
            format!("{} = reverse", p_reverse),
            format!("{} = 0", p_bc),
            format!("{} = {{}}", p_res),
            format!("{} = 0", p_f),
            format!("{} = 0", p_p1),
            format!("{} = 0", p_p2),
            format!("{} = 0", p_w),
            format!("{} = 0", p_u),
            format!("{} = 0", p_ptr),
        ];
        rng.shuffle(&mut pk_pairs);
        let pk_init_table = pk_pairs.join(", ");

        let token_map_name = rng.name();
        let token_decode_name = rng.name();
        let (token_text, token_out, token_i, token_len, token_from, token_key, token_value) = (
            rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
        );
        let token_entries = symbol_map.iter()
            .map(|(symbol, token)| format!(
                "[{}]={}",
                lua_string_literal(token),
                lua_string_literal(&(*symbol as char).to_string()),
            ))
            .collect::<Vec<_>>()
            .join(",");
        let token_marker_num = ControlFlowBuilder::obf_num(symbol_marker as i64, rng);
        let symbol_decoder_lua = format!(
            "local {map}={{{entries}}};local {decode}=function({text},{out},{i},{len},{from},{key},{value}) {out}={{}};{i}=1;{len}=#{text};{from}=1;while {i}<={len} do if byte({text},{i})=={marker} then if {i}>{from} then {out}[#{out}+1]=sub({text},{from},{i}-1) end;{key}=sub({text},{i},{i}+4);{value}={map}[{key}];if {value} then {out}[#{out}+1]={value};{i}={i}+5;{from}={i} else {out}[#{out}+1]=sub({text},{i},{i});{i}={i}+1;{from}={i} end else {i}={i}+1 end end;if {from}<={len} then {out}[#{out}+1]=sub({text},{from}) end;return concat({out}) end;",
            map = token_map_name,
            entries = token_entries,
            decode = token_decode_name,
            text = token_text,
            out = token_out,
            i = token_i,
            len = token_len,
            from = token_from,
            key = token_key,
            value = token_value,
            marker = token_marker_num,
        );
        let main_stage_run = if main_is_raw {
            // 保留同一 VM LZ/反篡改状态机：m_next 在 raw 模式按需合成 0XFF 标志字节，
            // 真实 Native Stream 字节仍逐个经原 handler 路由为 literal，不绕过校验状态。
            format!("s.raw=true;return q:{}(s);", m_run)
        } else {
            format!("return q:{}(s);", m_run)
        };

        // 注意：这里必须写源字段名（s.idx 等），重命名由后面的
        // rename_state_fields 统一处理（它按 "s." + 源名匹配），
        // 直接写最终随机名会导致该处字段漏改、运行时对不上。
        let mut pk_s2: Vec<String> = vec![
            "s.idx = 1".to_string(),
            "s.buf = {}".to_string(),
            "s.res = {}".to_string(),
            format!("s.pc = {}", pc_ref(rng, 0)),
            "s.bc = 0".to_string(),
            "s.f = 0".to_string(),
            "s.p1 = 0".to_string(),
            "s.p2 = 0".to_string(),
            "s.w = 0".to_string(),
            "s.u = 0".to_string(),
            "s.ptr = 0".to_string(),
            "s.r_flg = false".to_string(),
            "s.r_vals = {}".to_string(),
            "s.r_len = 0".to_string(),
            "s.tail_flg = false".to_string(),
            "s.raw = false".to_string(),
            format!("{}(s.k)", kern_init_fn), // 第二段从头起流（第一段未必吃满字节）
        ];
        rng.shuffle(&mut pk_s2);
        let pk_s2_assigns = pk_s2.join(" ");
        let (pk_fet, pk_code, pk_env, pk_maker) = (rng.name(), rng.name(), rng.name(), rng.name());
        // 判据①修复：载荷切分点（sb 段字符数）以混淆数字拼写下发，'~' 不再出现
        let split_lit = rng.format_num(split_pos as i64);
        // ㉙② 句柄键基/步长运行时推导：取密钥前 3 字节混合（init_map 之后 s.k
        // 已就位），值域 <0XFFFFF；步长恒奇。注册/查表两侧共用 → 键集合不落文本
        let hk_derive = format!(
            "s.hk=(s.k[{}]*{}+s.k[{}]*{}+s.k[{}]*{})%0XFFFFF;s.hs=((s.hk%{})*0X2)+{};",
            ControlFlowBuilder::obf_num(1, rng), ControlFlowBuilder::obf_num(rng.range64(100, 999), rng),
            ControlFlowBuilder::obf_num(2, rng), ControlFlowBuilder::obf_num(rng.range64(100, 999), rng),
            ControlFlowBuilder::obf_num(3, rng), ControlFlowBuilder::obf_num(rng.range64(100, 999), rng),
            ControlFlowBuilder::obf_num(rng.range64(7, 61), rng), ControlFlowBuilder::obf_num(1, rng));

        // ⑤ 字节权/base86 权重逐构建派生（隐式捕获进模板）
        let (p2, p3) = (rng.name(), rng.name());
        let (p2v, p3v) = (crate::VM::VM_Backend::Generator_kdf::kdf_pow2(rng, 16), crate::VM::VM_Backend::Generator_kdf::kdf_pow2(rng, 24));
        let (w1, w2, w3, w4) = (rng.name(), rng.name(), rng.name(), rng.name());
        let script = format!("
local function {f_entry}({v_data})
    {probe}
    {pc_infra}
    {kern_decl}
    return ({{
        {m_next} = function(q, s, r, c, e, v, x, y, z, i, d, m, b, k, B, F)
    B, F = s.byte, s.floor;
    if s.raw and s.bc > 7 then return {raw_flag_num} end;
    local {p2}={p2v}; local {p3}={p3v}; local {w1}=86; local {w2}={w1}*86; local {w3}={w2}*86; local {w4}={w3}*86;
    i, d, m, b, k = s.idx, s.data, s.map, s.buf, s.kidx;
    if #b > 0 then
        r = s.remove(b, 1);
        c = {kern_step}(r);
        return c;
    end;
    if i > s.len then return nil end;
    e = s.len - i + 1;
    if e >= 5 then
        v = m[B(d, i)] * {w4} + m[B(d, i+1)] * {w3} + m[B(d, i+2)] * {w2} + m[B(d, i+3)] * {w1} + m[B(d, i+4)];
        z, y, x = v % 256, F(v / 256) % 256, F(v / {p2}) % 256;
        v = F(v / {p3});
        b[1], b[2], b[3], b[4] = v, x, y, z;
        i = i + 5;
    elseif e >= 4 then
        v = m[B(d, i)] * {w3} + m[B(d, i+1)] * {w2} + m[B(d, i+2)] * {w1} + m[B(d, i+3)];
        y, x = v % 256, F(v / 256) % 256;
        v = F(v / {p2});
        b[1], b[2], b[3] = v, x, y;
        i = i + 4;
    elseif e >= 3 then
        v = m[B(d, i)] * {w2} + m[B(d, i+1)] * {w1} + m[B(d, i+2)];
        x = v % 256;
        v = F(v / 256);
        b[1], b[2] = v, x;
        i = i + 3;
    elseif e >= 2 then
        v = m[B(d, i)] * 86 + m[B(d, i+1)];
        b[1] = v;
        i = i + 2;
    else
        i = i + 1;
    end;
    s.idx = i;
    return q:{m_next}(s);
end,
        {m_init_map} = function(q, s, parts, alpha, i, kparts, kstr, dparts, digs)
            {map_fetch_stmts}
            parts = {{{combined_alpha_expr}}};
            alpha = \"\";
            i = 0;
            while i < {num_actual_parts} do i = i + 1; alpha = alpha .. parts[i]; end;
            dparts = {{{combined_digs_expr}}};
            digs = \"\";
            i = 0;
            while i < {num_actual_parts} do i = i + 1; digs = digs .. dparts[i]; end;
            i = 0;
            while i < #alpha do i = i + 1; s.map[s.byte(alpha, i)] = s.byte(digs, i) - 1; end;
            kparts = {{{combined_key_expr}}};
            kstr = \"\";
            i = 0;
            while i < {num_actual_key_parts} do i = i + 1; kstr = kstr .. kparts[i]; end;
            i = 0;
            while i < #kstr do i = i + 1; s.k[i] = s.byte(kstr, i); end;
            {kern_init_fn}(s.k);
        end,
        {m_init_insts} = function(q, s, st)
            {init_insts_loop}
        end,
        {m_init_handlers} = function(q, s, st)
            {init_handlers_loop}
        end,
        {m_run} = function(q, s)
            {router_code}
        end,
        {m_main} = function(q, data, split_at, unpack, char, byte, floor, insert, concat, remove, reverse, sub, load_func)
            {symbol_decoder_lua}
            return (function(s)
                q:{m_init_map}(s);
                {hk_derive}
                q:{m_init_insts}(s);
                q:{m_init_handlers}(s);
                
                s.data = {token_decode_name}(sub(data, 1, {split_lit}));
                s.len = #s.data;
                local sb_expr = q:{m_run}(s);
                
                {ret_stmt}local {pk_fet} = load_func({ret_expr} .. sb_expr);
                local {pk_code} = {pk_fet} and {pk_fet}() or string.char();
                {chunk_stmt}local {pk_env} = load_func({pk_code}, {chunk_expr});
                
                local stage2 = function()
                    {pk_s2_assigns}
                    s.data = {token_decode_name}(sub(data, {split_lit} + 1));
                    s.len = #s.data;
                    {main_stage_run}
                end
                
                local {pk_maker} = {pk_env} and {pk_env}(stage2) or stage2;
                return {pk_maker}();
            end)({{
                {pk_init_table}
            }});
        end
    }}):{m_main}({v_data}, {split_lit}, unpack or table.unpack, string.char, string.byte, math.floor, table.insert, table.concat, table.remove, string.reverse, string.sub, {v_pload});
end
");
        // 脚本里所有 s.<字段> 的访问统一换成随机名（router / init_insts_loop /
        // init_handlers_loop 都已嵌进 script，所以这里是最后一处，覆盖全部引用）
        let script = rename_state_fields(
            &script,
            &[
                ("data", p_data),
                ("pc", p_pc),
                ("insts", p_insts),
                ("tamper", p_tamper),
                ("handlers", p_handlers),
                ("r_flg", p_r_flg),
                ("r_vals", p_r_vals),
                ("r_len", p_r_len),
                ("tail_flg", p_tail_flg),
                ("raw", p_raw),
                ("map", p_map),
                ("idx", p_idx),
                ("len", p_len),
                ("k", p_k),
                ("kidx", p_kidx),
                ("buf", p_buf),
                ("memo", p_memo),
                ("unpack", p_unpack),
                ("char", p_char),
                ("byte", p_byte),
                ("floor", p_floor),
                ("insert", p_insert),
                ("concat", p_concat),
                ("remove", p_remove),
                ("reverse", p_reverse),
                ("bc", p_bc),
                ("res", p_res),
                ("f", p_f),
                ("p1", p_p1),
                ("p2", p_p2),
                ("w", p_w),
                ("u", p_u),
                ("ptr", p_ptr),
                ("hk", p_hk),
                ("hs", p_hs),
            ],
        );
        (script, f_entry)
    }
}

/// 生成可安全嵌入 Lua 双引号字符串的 ASCII 字面量（码本只使用可打印 ASCII）。
fn lua_string_literal(value: &str) -> String {
    let mut literal = String::with_capacity(value.len() + 2);
    literal.push('"');
    for byte in value.bytes() {
        match byte {
            b'"' => literal.push_str("\\\""),
            b'\\' => literal.push_str("\\\\"),
            b'\n' => literal.push_str("\\n"),
            b'\r' => literal.push_str("\\r"),
            b'\t' => literal.push_str("\\t"),
            0..=31 | 127 => literal.push_str(&format!("\\{:03}", byte)),
            _ => literal.push(byte as char),
        }
    }
    literal.push('"');
    literal
}

/// 把脚本里 `s.<旧名>` 形式的状态表字段访问换成随机名。
/// 只认字面量 `s.` 前缀并做整词匹配：不会误伤 `s.k` / `s.kidx` 这种前缀关系，
/// 也不会碰 `math.floor`、`table.concat` 这类库访问。
fn rename_state_fields(script: &str, pairs: &[(&str, String)]) -> String {
    let src = script.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    let mut i = 0usize;
    while i < src.len() {
        if src[i] == b's'
            && i + 1 < src.len()
            && src[i + 1] == b'.'
            && (i == 0 || !(src[i - 1] == b'_' || src[i - 1].is_ascii_alphanumeric()))
        {
            let start = i + 2;
            let mut end = start;
            while end < src.len() && (src[end] == b'_' || src[end].is_ascii_alphanumeric()) {
                end += 1;
            }
            let word = &script[start..end];
            if let Some((_, new)) = pairs.iter().find(|(old, _)| *old == word) {
                out.extend_from_slice(b"s.");
                out.extend_from_slice(new.as_bytes());
                i = end;
                continue;
            }
        }
        out.push(src[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| script.to_string())
}

#[cfg(test)]
mod tests {
    use super::Packer;
    use crate::VM::VM_Backend::Generator::GenRng;

    fn restore_symbol_codes(input: &str, marker: u8, mapping: &[(u8, String)]) -> Option<String> {
        let bytes = input.as_bytes();
        let mut output = Vec::with_capacity(bytes.len());
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            if bytes[cursor] == marker {
                let end = cursor.checked_add(5)?;
                let token = std::str::from_utf8(bytes.get(cursor..end)?).ok()?;
                let (symbol, _) = mapping.iter().find(|(_, code)| code == token)?;
                output.push(*symbol);
                cursor = end;
            } else {
                output.push(bytes[cursor]);
                cursor += 1;
            }
        }
        String::from_utf8(output).ok()
    }

    #[test]
    fn generated_symbol_codebook_is_unambiguous_and_reversible() {
        let alphabet: String = (33u8..=126u8)
            .filter(|&byte| byte != b'[' && byte != b']' && byte != b'~')
            .map(char::from)
            .collect();
        let perm: Vec<usize> = (0..86).collect();
        let mut rng = GenRng::new(0);
        let (marker, mapping) = Packer::generate_symbol_codebook(&alphabet, &perm, &mut rng);

        assert!(!perm.iter().any(|&position| alphabet.as_bytes()[position] == marker));
        assert!(!mapping.is_empty());
        assert!(mapping.iter().all(|(_, token)| {
            token.len() == 5 && token.as_bytes()[0] == marker && !token.as_bytes().contains(&b']')
        }));

        let mut source = vec![alphabet.as_bytes()[perm[0]], alphabet.as_bytes()[perm[1]]];
        source.extend(mapping.iter().map(|(symbol, _)| *symbol));
        source.extend_from_slice(&[alphabet.as_bytes()[perm[2]], alphabet.as_bytes()[perm[3]]]);
        let source = String::from_utf8(source).unwrap();
        let encoded = Packer::replace_symbols(&source, &mapping);
        assert_eq!(restore_symbol_codes(&encoded, marker, &mapping).as_deref(), Some(source.as_str()));
        assert!(!encoded.contains("]=]"));
    }

    #[test]
    fn main_stream_can_choose_raw_for_high_entropy_and_lz_for_repetition() {
        let mut state = 2_654_435_769u32;
        let noisy: Vec<u8> = (0..2048)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        assert!(Packer::encode_stream(&noisy).len() >= noisy.len());

        let repeated = vec![90u8; 2048];
        assert!(Packer::encode_stream(&repeated).len() < repeated.len());
    }

}
