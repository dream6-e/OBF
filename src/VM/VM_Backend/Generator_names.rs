//! ㉜ API 名保险库（NameVault，产物侧局部名 NB）：把 VM 自身在产物里留下的
//! 明文全局 API 标识符（pcall/tostring/setmetatable/string.byte/bit32.bxor/…）
//! 全部收进一张运行期解析表——名字复用统一流（UniStream）以**数字密文**落盘，
//! boot 时一次性解码并从环境表取值装槽；所有发射点只引用 `NB[0X槽号]`。
//!
//! 装配位置（词法顺序，见 Generator_chain_tail）：
//! `uni prelude → ㉑ 预声明（kreg 改普通 {}）→ NB 建表 IIFE → 毒化延迟写 →
//!  头部捕获（select/bit 位库）→ type/pairs 捕获 → ……→ parts`
//! NB 建表时顺带用解出的 setmetatable 给 kreg 补 `__mode='k'` 弱键元表
//! （kreg 声明因此必须前移成普通 `{}`）。
//!
//! 环境根三态覆盖：`local e0=_ENV or _G; local gf=e0["getfenv"(密文)];
//! local e=(gf and gf()) or e0` —— 标准 5.1（_G）、Luau（_ENV、无 getfenv）、
//! 被 setfenv 过的宿主（getfenv() 拿到真环境）三种形态同一式命中。
//!
//! 保留边界（不入库，见 项目交接总结.md）：
//! - `_ENV` / `_G` 根标识符（引导必需，且本身不指向任何库/函数名）；
//! - fu 壳守卫的 `local X=type`（fu 在 wai 之前执行，NB 尚不存在，自足形态）；
//! - sandbox 载荷串与 line_guard 的 `string.char()` 自足拼装（独立 chunk / 早于 NB）；
//! - uni prelude 自身的解码原语（NB 依赖 uni，不能反向依赖）。

use super::Generator::GenRng;
use super::Generator_unistream::UniStream;
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
enum Slot {
    /// e[name]
    Global(String),
    /// (e[lib] and e[lib][mem])——库缺失时为 nil，与旧 `lib and lib.mem` 同语义
    Member(String, String),
    /// (bit32 and bit32[mem]) or (bit and bit[mem])——双库回退链
    Bit(String),
    /// e["unpack"] or (table and table["unpack"])
    Unpack,
    /// 环境根本体 e
    Root,
    /// kreg 的 `__mode='k'` 弱键元表本体（建表时构造，kreg 轮换重建时复用）
    KregMt,
    /// 纯字符串常量值（如 "function"/"string"/"number"/"table"/"boolean"/"__index" 等）
    Lit(String),
}

#[derive(Clone)]
pub struct NameVault {
    local: String,
    entries: Vec<(u32, Slot)>,
    index: HashMap<String, usize>,
    used_keys: HashSet<u32>,
    built: bool,
}

fn key_lit(k: u32) -> String {
    format!("0X{:X}", k)
}

impl NameVault {
    pub fn new(rng: &mut GenRng) -> Self {
        NameVault {
            local: rng.name(),
            entries: Vec::new(),
            index: HashMap::new(),
            used_keys: HashSet::new(),
            built: false,
        }
    }
    /// 绑定到既有表名（如 kreg_n）：一切请求都走该表槽，零新增壳层 local。
    pub fn bind_local(&mut self, name: &str) {
        assert!(self.entries.is_empty(), "bind_local must precede requests");
        self.local = name.to_string();
    }
    /// NB 的产物侧局部名（chain_tail 装配处引用）。
    pub fn local_name(&self) -> &str {
        &self.local
    }
    /// 槽键抽签：范围与 uni 缓存键同域；单实例内 HashSet 保证互异
    /// （撞键会让两个名字互相覆盖，产物直接坏掉）。
    fn draw_key(&mut self) -> u32 {
        use rand::Rng;
        loop {
            let k = rand::thread_rng().gen_range(0x0200_0000u32..0x7FFF_FFFF);
            if self.used_keys.insert(k) {
                return k;
            }
        }
    }
    fn request(&mut self, idx_key: &str, slot: Slot) -> String {
        // 建表后再登记的槽永远不会被装配（产物侧拿到恒 nil 的槽）——直接炸掉构建
        assert!(!self.built, "NameVault: request `{}` after build()", idx_key);
        if let Some(&i) = self.index.get(idx_key) {
            return format!("{}[{}]", self.local, key_lit(self.entries[i].0));
        }
        let k = self.draw_key();
        self.index.insert(idx_key.to_string(), self.entries.len());
        self.entries.push((k, slot));
        format!("{}[{}]", self.local, key_lit(k))
    }
    /// 全局函数/表名（pcall、tostring、setmetatable、math、string、debug、
    /// typeof、raknet、newproxy、collectgarbage、print、getfenv、setfenv、…）。
    pub fn global(&mut self, name: &str) -> String {
        let slot = Slot::Global(name.to_string());
        self.request(name, slot)
    }
    /// 库成员（math.floor、string.byte、table.concat、string.reverse、…）。
    pub fn member(&mut self, lib: &str, mem: &str) -> String {
        let key = format!("{}.{}", lib, mem);
        let slot = Slot::Member(lib.to_string(), mem.to_string());
        self.request(&key, slot)
    }
    /// 位运算双库回退（bxor/band/rshift）：bit32 优先、bit 次之、
    /// 两者皆缺时槽值 nil——调用侧 `NB[k] or function…end` 接纯算术兜底，
    /// 与旧 `bit32 and bit32.m or bit and bit.m or function…end` 逐位同语义。
    pub fn bitop(&mut self, mem: &str) -> String {
        let key = format!("bit:{}", mem);
        let slot = Slot::Bit(mem.to_string());
        self.request(&key, slot)
    }
    /// unpack or table.unpack
    pub fn unpack(&mut self) -> String {
        self.request("unpack|table.unpack", Slot::Unpack)
    }
    /// 环境根：(getfenv and getfenv()) or _ENV or _G —— NB boot 时的 e 本体。
    pub fn root(&mut self) -> String {
        self.request("@root", Slot::Root)
    }
    /// kreg 弱键元表本体（同一张 mt 表；kreg 定期轮换重建时 `sm({},mt)` 复用，
    /// 免去 getmetatable 明文）。
    pub fn kreg_mt(&mut self) -> String {
        self.request("@kreg_mt", Slot::KregMt)
    }
    /// 纯字符串常量槽（如类型名 "function"/"string"/"number"/"table"/"boolean"、
    /// 元方法键 "__index"/"__newindex"、字段名 "what" 等）：复用 UniStream 数字密文
    /// 在 NB 建表时一次性解码入槽，运行期直接读槽，零明文残留且零热路径解码开销。
    pub fn lit(&mut self, s: &str) -> String {
        let key = format!("@lit:{}", s);
        let slot = Slot::Lit(s.to_string());
        self.request(&key, slot)
    }
    /// 独立去重标签的全局槽：同一全局名在 `UniStream` 中分配独立偏移密文与独立 `kreg_n` 键，防跨处同槽关联。
    pub fn global_fresh(&mut self, tag: usize, name: &str) -> String {
        let key = format!("@glob#{}:{}", tag, name);
        let slot = Slot::Global(name.to_string());
        self.request(&key, slot)
    }
    /// 独立去重标签的字符串常量槽：同一字面量在 `UniStream` 中分配独立偏移密文与独立 `kreg_n` 键。
    pub fn lit_fresh(&mut self, tag: usize, s: &str) -> String {
        let key = format!("@lit#{}:{}", tag, s);
        let slot = Slot::Lit(s.to_string());
        self.request(&key, slot)
    }

    /// 发射 NB 建表 IIFE（一次 boot 开销；热路径零改动）。
    /// `kreg` 给定时顺带补 `__mode='k'` 弱键元表（kreg 声明侧已改普通 `{}`）。
    pub fn build(&mut self, rng: &mut GenRng, uni: &mut UniStream, kreg: Option<&str>) -> String {
        self.built = true;
        // ── 引导区：e0 → getfenv → e → setmetatable → t ──
        let id_gf = uni.register("getfenv");
        let (st_gf, ex_gf) = uni.fetch(rng, id_gf);
        let id_sm = uni.register("setmetatable");
        let (st_sm, ex_sm) = uni.fetch(rng, id_sm);
        let (v_e0, v_gf, v_e, v_sm, v_t) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let mut body = format!(
            "local {e0}=(getfenv and getfenv()) or _ENV or _G; {stg}local {gf}={e0}[{exg}]; local {e}=({gf} and {gf}()) or {e0}; {sts}local {sm}={e}[{exs}]; local {t}={{}}; ",
            e0 = v_e0, stg = st_gf, gf = v_gf, exg = ex_gf,
            e = v_e, sts = st_sm, sm = v_sm, exs = ex_sm, t = v_t);

        // ── 库表局部（math/string/table/bit32/bit，按需去重） ──
        let mut libs: Vec<String> = Vec::new();
        {
            let mut add = |libs: &mut Vec<String>, l: &str| {
                if !libs.iter().any(|x| x == l) {
                    libs.push(l.to_string());
                }
            };
            for (_, slot) in self.entries.iter() {
                match slot {
                    Slot::Member(lib, _) => add(&mut libs, lib),
                    Slot::Bit(_) => { add(&mut libs, "bit32"); add(&mut libs, "bit"); }
                    Slot::Unpack => add(&mut libs, "table"),
                    _ => {}
                }
            }
        }
        let mut lib_local: HashMap<String, String> = HashMap::new();
        for lib in libs.iter() {
            let id = uni.register(lib);
            let (st, ex) = uni.fetch(rng, id);
            let l = rng.name();
            body.push_str(&format!("{}local {}={}[{}]; ", st, l, v_e, ex));
            lib_local.insert(lib.clone(), l);
        }

        // ── 槽位装配（条目互不依赖，发射序洗牌） ──
        let mut order: Vec<usize> = (0..self.entries.len()).collect();
        rng.shuffle(&mut order);
        for i in order {
            let (key, slot) = &self.entries[i];
            let kl = key_lit(*key);
            match slot {
                Slot::Global(n) => {
                    let id = uni.register(n);
                    let (st, ex) = uni.fetch(rng, id);
                    body.push_str(&format!("{}{}[{}]={}[{}]; ", st, v_t, kl, v_e, ex));
                }
                Slot::Member(lib, mem) => {
                    let id = uni.register(mem);
                    let (st, ex) = uni.fetch(rng, id);
                    let l = &lib_local[lib];
                    body.push_str(&format!(
                        "{}{}[{}]=({} and {}[{}]); ", st, v_t, kl, l, l, ex));
                }
                Slot::Bit(mem) => {
                    // 同一成员名对两条库各解一次（两个独立缓存键，形态不齐整）
                    let id1 = uni.register(mem);
                    let (st1, ex1) = uni.fetch(rng, id1);
                    let id2 = uni.register(mem);
                    let (st2, ex2) = uni.fetch(rng, id2);
                    let b32 = &lib_local["bit32"];
                    let bl = &lib_local["bit"];
                    body.push_str(&format!(
                        "{}{}{}[{}]=({} and {}[{}]) or ({} and {}[{}]); ",
                        st1, st2, v_t, kl, b32, b32, ex1, bl, bl, ex2));
                }
                Slot::Unpack => {
                    let id1 = uni.register("unpack");
                    let (st1, ex1) = uni.fetch(rng, id1);
                    let id2 = uni.register("unpack");
                    let (st2, ex2) = uni.fetch(rng, id2);
                    let tb = &lib_local["table"];
                    body.push_str(&format!(
                        "{}{}{}[{}]={}[{}] or ({} and {}[{}]); ",
                        st1, st2, v_t, kl, v_e, ex1, tb, tb, ex2));
                }
                Slot::Root => {
                    body.push_str(&format!("{}[{}]={}; ", v_t, kl, v_e));
                }
                Slot::KregMt => {} // 在下方弱表分支统一装配
                Slot::Lit(s) => {
                    let id = uni.register(s);
                    let (st, ex) = uni.fetch(rng, id);
                    body.push_str(&format!("{}{}[{}]={}; ", st, v_t, kl, ex));
                }
            }
        }

        // ── kreg 弱键元表（原 ㉑ 预声明处的 setmetatable({},{__mode='k'}) 移到这里）──
        // mt 本体可入槽（KregMt）：kreg 定期轮换重建时 `sm({},mt)` 直接复用，
        // 免掉 getmetatable 明文。
        let mt_slot = self
            .entries
            .iter()
            .find(|(_, s)| matches!(s, Slot::KregMt))
            .map(|(k, _)| key_lit(*k));
        if kreg.is_some() || mt_slot.is_some() {
            let id_m = uni.register("__mode");
            let (st_m, ex_m) = uni.fetch(rng, id_m);
            let id_k = uni.register("k");
            let (st_k, ex_k) = uni.fetch(rng, id_k);
            let v_mt = rng.name();
            body.push_str(&format!(
                "{stm}{stk}local {mt}={{[{exm}]={exk}}}; ",
                stm = st_m, stk = st_k, mt = v_mt, exm = ex_m, exk = ex_k));
            if let Some(kl) = mt_slot {
                body.push_str(&format!("{}[{}]={}; ", v_t, kl, v_mt));
            }
            if let Some(kreg) = kreg {
                body.push_str(&format!("if {sm} then {sm}({kreg},{mt}); end; ", sm = v_sm, kreg = kreg, mt = v_mt));
            }
        }

        // 若与 kreg 同名（零局部模式），条目直接装进该表（无新 local，弱键元表数字键不回收）；
        // 否则（单测独立跑）落新 local。
        if kreg == Some(self.local.as_str()) {
            let body_inplace = body.replace(&format!("local {}={{}}; ", v_t), "")
                .replace(&format!("{}[", v_t), &format!("{}[", self.local));
            // `do (function()...end)() end;`：不能以裸 `(` 开头，否则压缩器剥掉
            // 前一条语句末尾 `;`（尤其 rk21=`(0X…%0X…)` 抽在末尾时）会被 Lua
            // 解析成对前值做函数调用（attempt to call a number/table value）。
            format!("do (function() {}end)() end; ", body_inplace)
        } else {
            format!("local {}=(function() {}return {} end)(); ", self.local, body, v_t)
        }
    }
}

/// 位库四局部（bxor/band/rshift/bxor2）：NB 槽 + 纯算术兜底。
/// `(bit32 and bit32.m) or (bit and bit.m)` 在建表时解析成单槽，两库皆缺时
/// 槽值 nil，`or function…end` 兜底与旧三连 or 逐位同语义（and/or 左结合）。
/// 返回未洗牌的发射体（调用侧照旧 `rng.shuffle`）。
pub fn emit_bit_locals(
    vault: &mut NameVault, fn_bx: &str, fn_ba: &str, fn_bs: &str, fn_bxor2: &str,
) -> Vec<String> {
    let (slot_bxor, slot_band, slot_rshift) =
        (vault.bitop("bxor"), vault.bitop("band"), vault.bitop("rshift"));
    let fb = "function(a,b) local r,p=0,1;for k=1,4 do local x,y=a%256,b%256;r=r+qT8c[x][y]*p;a=(a-x)/256;b=(b-y)/256;p=p*256 end;return r end";
    vec![
        format!("local {}={} or {}; ", fn_bx, slot_bxor, fb),
        format!("local {}={} or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end; ", fn_ba, slot_band),
        format!("local {}={} or function(a,n)local d=2^n return (a-a%d)/d end; ", fn_bs, slot_rshift),
        format!("local {}={} or {}; ", fn_bxor2, slot_bxor, fb),
    ]
}

/// vm_core 解码内核模板的四个库访问点收进 NB 槽（模板固定串，逐一替换）。
pub fn vaultify_vm_core(vault: &mut NameVault, raw: String) -> String {
    let mut vc = raw.replace("local A, B, C, D = ...;", "local A, B, C, D;");
    for (plain, slot) in [
        ("string.byte(", vault.member("string", "byte")),
        ("string.char(", vault.member("string", "char")),
        ("table.concat(", vault.member("table", "concat")),
        ("math.random(", vault.member("math", "random")),
    ] {
        vc = vc.replace(plain, &format!("{}(", slot));
    }
    vc
}

/// block_methods 开头的原生捕获语句组：tonumber/error/getfenv/setfenv/
/// setmetatable(+kreg 弱元表本体) 全走 NB 槽；弱表键 "__mode"/"k" 走统一流。
pub fn emit_natives_capture(
    rng: &mut GenRng,
    uni: &mut UniStream,
    vault: &mut NameVault,
    to_num: &str,
    err_fn: &str,
    getenv: &str,
    setenv: &str,
    closure_env: &str,
) -> String {
    let (mode_stmt, mode_expr) = {
        let id = uni.register("__mode");
        uni.fetch(rng, id)
    };
    let (mk_stmt, mk_expr) = {
        let id = uni.register("k");
        uni.fetch(rng, id)
    };
    format!(
        "{mst}{kst}local {to_num}={tn};local {err_fn}={er};local {getenv}={gf};local {setenv}={sf};local {closure_env}={sm}({{}},{{[{mk}]={kv}}}); ",
        mst = mode_stmt,
        kst = mk_stmt,
        to_num = to_num,
        err_fn = err_fn,
        getenv = getenv,
        setenv = setenv,
        closure_env = closure_env,
        tn = vault.global("tonumber"),
        er = vault.global("error"),
        gf = vault.global("getfenv"),
        sf = vault.global("setfenv"),
        sm = vault.global("setmetatable"),
        mk = mode_expr,
        kv = mk_expr,
    )
}

/// 最外层大 `return({...})` 表壳的兄弟方法注册器。
///
/// 按 `README.md` 约定：多出来的步骤以及逼近/超过 Lua 5.1 单函数 200 `local`
/// 上限的步骤，统一拆成最外层 `return({wai=function(...) end, xx=function(a,b,c) end, ...})`
/// 表壳里的多个兄弟方法。每个兄弟方法拥有独立的局部寄存器帧与常量池，
/// 压缩器会自动将方法名压成 2 字母、形参压成单字母 `(a,b,c,...)`。
pub struct ShellMethods {
    pub self_var: String,
    /// `(method_name, self_param, params_without_self, body)`
    entries: Vec<(String, String, Vec<String>, String)>,
}

impl ShellMethods {
    pub fn new(rng: &mut GenRng) -> Self {
        Self {
            self_var: rng.name(),
            entries: Vec::new(),
        }
    }

    /// 注册一个不直接引用自身 `self` 的外层兄弟方法 `m = function(s, p1, p2, ...) body end`。
    pub fn add(&mut self, rng: &mut GenRng, params: &[&str], body: String) -> String {
        let s = rng.name();
        self.add_self(rng, &s, params, body)
    }

    /// 注册一个显式指定 `self_param` 的外层兄弟方法（供方法体内继续调 `s:other(...)`）。
    pub fn add_self(
        &mut self,
        rng: &mut GenRng,
        self_param: &str,
        params: &[&str],
        body: String,
    ) -> String {
        let m = rng.name();
        let mut ps: Vec<String> = params.iter().map(|p| (*p).to_string()).collect();
        while ps.len() < 2 {
            ps.push(rng.name());
        }
        self.entries.push((m.clone(), self_param.to_string(), ps, body));
        m
    }

    /// 生成 `self_var:m(arg1, arg2, ...)` 调用表达式。
    pub fn call(&self, m: &str, args: &[&str]) -> String {
        format!("{}:{}({})", self.self_var, m, args.join(","))
    }

    /// 批量重写所有已登记兄弟方法的方法体（例如把元表状态生成器的明文 API / 元方法名统一替换为 NB 槽引用）。
    pub fn map_bodies<F: FnMut(String) -> String>(&mut self, mut f: F) {
        for (_, _, _, body) in self.entries.iter_mut() {
            let old = std::mem::take(body);
            *body = f(old);
        }
    }

    /// 把巨型方法体切成"碎函数 + 单次调用树"（见 `Generator_fragment`）。
    /// 只改结构：新碎片作为兄弟方法登记进来，原方法体换成微状态机 + 单次调用。
    pub fn fragment_all(&mut self, rng: &mut GenRng) -> super::Generator_fragment::FragStats {
        super::Generator_fragment::fragment(&mut self.entries, rng)
    }

    /// 对已登记方法中的闭包体做 upvalue 保守分析，安全片段提升为外层兄弟方法。
    pub fn fragment_nested_body(&mut self, body: &mut String, rng: &mut GenRng, budget: usize) -> usize {
        let mut added: Vec<super::Generator_fragment::Entry> = Vec::new();
        let self_var = self.self_var.clone();
        let count = super::Generator_fragment::fragment_nested_body(
            body, &self_var, &mut added, rng, budget,
        );
        self.entries.extend(added);
        count
    }

    /// 对**尚未登记**的方法体（例如最终的 `wai` 装配体）做碎片化，碎片直接登记为兄弟方法。
    pub fn fragment_body(&mut self, body: &mut String, rng: &mut GenRng) -> (usize, usize) {
        let mut added: Vec<super::Generator_fragment::Entry> = Vec::new();
        let self_var = self.self_var.clone();
        let r = super::Generator_fragment::frag_body(body, &self_var, &[], &mut added, rng);
        self.entries.extend(added);
        r
    }

    /// 导出外层表壳的 `xx=function(s,a,b,...) ... end` 字段列表。
    pub fn into_fields(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(m, s, ps, body)| {
                let mut all = Vec::with_capacity(ps.len() + 1);
                all.push(s.clone());
                all.extend(ps.iter().cloned());
                format!("{}=function({}) {} end", m, all.join(","), body)
            })
            .collect()
    }

    /// 将 `wai_field`（内含最大加密密文 payload `[=[...]=]`）置于外层 `return({...})` 表中央，
    /// 并将剩余所有兄弟方法按压缩后体积均衡分配到密文上下两部分，使密文前后的功能性代码大小基本一致。
    pub fn into_balanced_fields(
        &self,
        rng: &mut GenRng,
        wai_field: String,
        fu_field: String,
    ) -> Vec<String> {
        let mut other_fields = self.into_fields();
        other_fields.push(fu_field);
        rng.shuffle(&mut other_fields);

        let (mut upper_len, mut lower_len) = if let Some(open_pos) = wai_field.find("[=[") {
            let close_pos = wai_field[open_pos..]
                .find("]=]")
                .map(|p| open_pos + p + 3)
                .unwrap_or(open_pos);
            let u = est_compressed_len(&wai_field[..open_pos]);
            let l = est_compressed_len(&wai_field[close_pos..]);
            // 补偿 wai 上半段（execute 派发表）常量提升带来的额外压缩量与下半段 RadixSieve 进制转换增量
            let adjust = (u + l) / 48;
            (u, l + adjust)
        } else {
            let half = est_compressed_len(&wai_field) / 2;
            (half, half)
        };

        let weights: Vec<usize> = other_fields.iter().map(|f| est_compressed_len(f) + 1).collect();
        let mut order: Vec<usize> = (0..other_fields.len()).collect();
        order.sort_by(|&a, &b| weights[b].cmp(&weights[a]).then(a.cmp(&b)));

        let mut in_upper = vec![false; other_fields.len()];
        for idx in order {
            if upper_len <= lower_len {
                in_upper[idx] = true;
                upper_len += weights[idx];
            } else {
                lower_len += weights[idx];
            }
        }

        // 1-flip / 1-swap 局部搜索微调，进一步收窄上下两部分体积差
        loop {
            let cur_diff = upper_len.abs_diff(lower_len);
            let mut best_diff = cur_diff;
            let mut best_flip: Option<usize> = None;
            let mut best_swap: Option<(usize, usize)> = None;

            for i in 0..weights.len() {
                let (nu, nl) = if in_upper[i] {
                    (upper_len - weights[i], lower_len + weights[i])
                } else {
                    (upper_len + weights[i], lower_len - weights[i])
                };
                let d = nu.abs_diff(nl);
                if d < best_diff {
                    best_diff = d;
                    best_flip = Some(i);
                    best_swap = None;
                }
            }
            for i in 0..weights.len() {
                if !in_upper[i] {
                    continue;
                }
                for j in 0..weights.len() {
                    if in_upper[j] {
                        continue;
                    }
                    let nu = upper_len + weights[j] - weights[i];
                    let nl = lower_len + weights[i] - weights[j];
                    let d = nu.abs_diff(nl);
                    if d < best_diff {
                        best_diff = d;
                        best_flip = None;
                        best_swap = Some((i, j));
                    }
                }
            }
            if let Some(i) = best_flip {
                if in_upper[i] {
                    upper_len -= weights[i];
                    lower_len += weights[i];
                } else {
                    upper_len += weights[i];
                    lower_len -= weights[i];
                }
                in_upper[i] = !in_upper[i];
            } else if let Some((i, j)) = best_swap {
                upper_len = upper_len + weights[j] - weights[i];
                lower_len = lower_len + weights[i] - weights[j];
                in_upper[i] = false;
                in_upper[j] = true;
            } else {
                break;
            }
        }

        let mut out = Vec::with_capacity(other_fields.len() + 1);
        let mut lower = Vec::new();
        for (idx, field) in other_fields.into_iter().enumerate() {
            if in_upper[idx] {
                out.push(field);
            } else {
                lower.push(field);
            }
        }
        out.push(wai_field);
        out.extend(lower);
        out
    }
}

/// 估算一段生成期 Lua 代码经 `Compressor` 改名与去空白后的字节长度。
fn est_compressed_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut total = 0usize;
    let mut prev_alnum = false;
    let mut after_fn = false;
    let mut in_param_list = false;

    while i < n {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let cur_alnum = b.is_ascii_alphanumeric() || b == b'_';
        if prev_alnum && cur_alnum {
            total += 1;
        }
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let word = &s[start..i];
            let is_kw = matches!(
                word,
                "and" | "break" | "do" | "else" | "elseif" | "end" | "false" | "for"
                    | "function" | "if" | "in" | "local" | "nil" | "not" | "or"
                    | "repeat" | "return" | "then" | "true" | "until" | "while"
            );
            if is_kw {
                total += word.len();
                after_fn = word == "function";
            } else if in_param_list {
                total += 1;
                after_fn = false;
            } else {
                total += 2;
                after_fn = false;
            }
            prev_alnum = true;
        } else if b.is_ascii_digit() {
            let start = i;
            i += 1;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.') {
                i += 1;
            }
            let num = &s[start..i];
            if (num.starts_with("0X") || num.starts_with("0x"))
                && u64::from_str_radix(&num[2..], 16).map_or(false, |v| v <= 1)
            {
                total += 1;
            } else {
                total += num.len();
            }
            after_fn = false;
            prev_alnum = true;
        } else {
            if b == b'(' && after_fn {
                in_param_list = true;
                after_fn = false;
            } else if b == b')' && in_param_list {
                in_param_list = false;
            } else {
                after_fn = false;
            }
            total += 1;
            prev_alnum = false;
            i += 1;
        }
    }
    total
}

/// 生成 `block_methods` 中 `#`/`unpack`/分片元表链的装配代码（将 `hash_expr` 与 `idx_expr`
/// 收敛在 `do ... end` 块内，为 `wai` 省 2 个顶层局部槽，同时为 `Generator.rs` 减重）。
#[allow(clippy::too_many_arguments)]
pub fn emit_methods_wire(
    rng: &mut GenRng,
    uni: &mut UniStream,
    vault: &mut NameVault,
    var_get_count: &str,
    var_s: &str,
    hex_select_idx: &str,
    pf_vn: &str,
    var_unpack: &str,
    method_shards: &[String],
    var_proto: &str,
    defs: &[String],
    native_smeta: &str,
    rename_fn: impl Fn(&str, &str, &str) -> String,
) -> String {
    let mut out = String::new();
    let (hash_stmt, hash_expr) = {
        let id = uni.register("#");
        uni.fetch(rng, id)
    };
    out.push_str(&format!(
        "local {gc}; do {hs}{gc} = function(...) return {vs}[{hsi}]({he}, ...) end end; ",
        gc = var_get_count,
        hs = hash_stmt,
        vs = var_s,
        hsi = hex_select_idx,
        he = hash_expr
    ));
    out.push_str(&format!(
        "local {up}, zm = {vup} or function() end, function(...) return {{{vn}={gc}(...),...}} end; ",
        up = var_unpack,
        vup = vault.unpack(),
        vn = pf_vn,
        gc = var_get_count
    ));
    let shard_names = method_shards.join(",");
    let shard_tables = vec!["{}"; method_shards.len()].join(",");
    out.push_str(&format!(
        "local {}={};local {}={{}};",
        shard_names, shard_tables, var_proto
    ));
    for d in defs.iter() {
        out.push_str(&rename_fn(d, "unpack", &var_unpack));
        out.push(' ');
    }
    let (idx_stmt, idx_expr) = {
        let id = uni.register("__index");
        uni.fetch(rng, id)
    };
    let mut method_order: Vec<usize> = (0..method_shards.len()).collect();
    rng.shuffle(&mut method_order);
    out.push_str(&format!("do {}", idx_stmt));
    for pair in method_order.windows(2) {
        out.push_str(&format!(
            "{}({},{{[{}]={}}});",
            native_smeta, method_shards[pair[0]], idx_expr, method_shards[pair[1]]
        ));
    }
    out.push_str(&format!(
        "{}[{}]={} end;",
        var_proto, idx_expr, method_shards[method_order[0]]
    ));
    out
}

/// 抗静态代换折叠的多槽非同构元表状态机参数。
/// 由 `(mt_var, base)` 经 SplitMix64 确定性派生，使声明端 `emit_mt_state_decl`
/// 与任意引用端 `emit_mt_state_expr` 共享同一套逐实例唯一的槽排列与非标准元方法公式。
struct MtStateParams {
    slots: [i64; 4],
    init_slots: [i64; 4],
    c_init: i64,
    p1: usize,
    p2: usize,
    p3: usize,
    var_add: u8,
    var_sub: u8,
    var_mul: u8,
    c_add: i64,
    w_add: i64,
    c_sub: i64,
    w_sub: i64,
    c_mul: i64,
    m_mul: i64,
}

impl MtStateParams {
    fn from_seed(mt_var: &str, base: i64) -> Self {
        let mut z = (base as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
        for &b in mt_var.as_bytes() {
            z = (z ^ (b as u64)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z ^= z >> 29;
        }
        let mut next = || -> u64 {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^ (x >> 31)
        };
        let mut perm = [1usize, 2, 3, 4];
        for i in (1..4).rev() {
            let j = (next() as usize) % (i + 1);
            perm.swap(i, j);
        }
        let (p1, p2, p3) = (perm[0], perm[1], perm[2]);
        let init_slots = [
            ((next() % 0x3_F000) + 0x1000) as i64,
            ((next() % 0x3_F000) + 0x1000) as i64,
            ((next() % 0x3_F000) + 0x1000) as i64,
            ((next() % 0x3_F000) + 0x1000) as i64,
        ];
        let c_init = ((next() % 0x7E00) + 0x100) as i64;
        let mut slots = init_slots;
        // 运行期经 `M[p3] = M[p1] * #M + M[p2] - c_init` 动态覆写（#M == 4）
        slots[p3 - 1] = slots[p1 - 1] * 4 + slots[p2 - 1] - c_init;
        Self {
            slots,
            init_slots,
            c_init,
            p1,
            p2,
            p3,
            var_add: (next() % 3) as u8,
            var_sub: (next() % 3) as u8,
            var_mul: (next() % 3) as u8,
            c_add: ((next() % 17) + 3) as i64,
            w_add: ((next() % 13) + 2) as i64,
            c_sub: ((next() % 17) + 3) as i64,
            w_sub: ((next() % 13) + 2) as i64,
            c_mul: ((next() % 17) + 3) as i64,
            m_mul: ((next() % 79) + 17) as i64,
        }
    }

    fn eval_add(&self, b: i64) -> i64 {
        let (v1, v2, v3) = (self.slots[self.p1 - 1], self.slots[self.p2 - 1], self.slots[self.p3 - 1]);
        match self.var_add {
            0 => (v1 - b) * self.c_add + v2 - v3,
            1 => v3 * self.c_add - (b * self.w_add) + v1,
            _ => (v2 + b * self.w_add) * self.c_add - v1 + v3,
        }
    }

    fn eval_sub(&self, b: i64) -> i64 {
        let (v1, v2, v3) = (self.slots[self.p1 - 1], self.slots[self.p2 - 1], self.slots[self.p3 - 1]);
        match self.var_sub {
            0 => v2 + (b * self.c_sub) - v1 * self.w_sub + v3,
            1 => (v3 + b) * self.c_sub + v2 - v1,
            _ => v1 * self.c_sub + (b * self.w_sub) - v3,
        }
    }

    fn eval_mul(&self, b: i64) -> i64 {
        let (v1, v2, v3) = (self.slots[self.p1 - 1], self.slots[self.p2 - 1], self.slots[self.p3 - 1]);
        let rem = b.rem_euclid(self.m_mul);
        match self.var_mul {
            0 => (v1 + v3) * rem + v2 * self.c_mul - b,
            1 => v2 * rem - v3 + b * self.c_mul + v1,
            _ => (v3 - v1) * rem + v2 - b * self.c_mul,
        }
    }
}

/// 元表状态生成器声明：
/// 1. 载体表含 4 个打乱槽位，初值经算术拆和构造，并在建表后利用运行期表长 `#M` 动态变异 `M[p3]`；
/// 2. `__add`、`__sub`、`__mul` 各自采用非同构、符号反置的跨槽线性/取模公式（`M+b` 不等于加、`M-b` 不等于减、`M*b` 不等于乘），彻底阻断将 `M` 当成常数代入 `eval()` 的静态折叠；
/// 3. 三个元方法条目在元表构造器中随机洗牌发射，静态分析无法凭位置或函数体运算符区分哪个槽对应哪个元方法。
pub fn emit_mt_state_decl(rng: &mut GenRng, mt_var: &str, base: i64) -> String {
    let p = MtStateParams::from_seed(mt_var, base);
    let slot_exprs: Vec<String> = p.init_slots.iter().map(|&sv| {
        let mask = rng.range64(0x200, 0x9FFF);
        if rng.range(0, 2) == 0 {
            format!("(0X{:X}-0X{:X})", sv + mask, mask)
        } else {
            let d = sv - mask;
            if d >= 0 { format!("(0X{:X}+0X{:X})", mask, d) } else { format!("(0X{:X}-0X{:X})", mask, -d) }
        }
    }).collect();
    let fn_add = match p.var_add {
        0 => format!("__add=function(a,b)return(a[{}]-b)*0X{:X}+a[{}]-a[{}] end", p.p1, p.c_add, p.p2, p.p3),
        1 => format!("__add=function(a,b)return a[{}]*0X{:X}-(b*0X{:X})+a[{}] end", p.p3, p.c_add, p.w_add, p.p1),
        _ => format!("__add=function(a,b)return(a[{}]+b*0X{:X})*0X{:X}-a[{}]+a[{}] end", p.p2, p.w_add, p.c_add, p.p1, p.p3),
    };
    let fn_sub = match p.var_sub {
        0 => format!("__sub=function(a,b)return a[{}]+(b*0X{:X})-a[{}]*0X{:X}+a[{}] end", p.p2, p.c_sub, p.p1, p.w_sub, p.p3),
        1 => format!("__sub=function(a,b)return(a[{}]+b)*0X{:X}+a[{}]-a[{}] end", p.p3, p.c_sub, p.p2, p.p1),
        _ => format!("__sub=function(a,b)return a[{}]*0X{:X}+(b*0X{:X})-a[{}] end", p.p1, p.c_sub, p.w_sub, p.p3),
    };
    let fn_mul = match p.var_mul {
        0 => format!("__mul=function(a,b)return(a[{}]+a[{}])*(b%0X{:X})+a[{}]*0X{:X}-b end", p.p1, p.p3, p.m_mul, p.p2, p.c_mul),
        1 => format!("__mul=function(a,b)return a[{}]*(b%0X{:X})-a[{}]+b*0X{:X}+a[{}] end", p.p2, p.m_mul, p.p3, p.c_mul, p.p1),
        _ => format!("__mul=function(a,b)return(a[{}]-a[{}])*(b%0X{:X})+a[{}]-b*0X{:X} end", p.p3, p.p1, p.m_mul, p.p2, p.c_mul),
    };
    let mut mms = vec![fn_add, fn_sub, fn_mul];
    rng.shuffle(&mut mms);
    format!(
        "local {m}=setmetatable({{{s}}},{{{mm}}});{m}[{p3}]={m}[{p1}]*#{m}+{m}[{p2}]-0X{ci:X};",
        m = mt_var,
        s = slot_exprs.join(","),
        mm = mms.join(","),
        p1 = p.p1,
        p2 = p.p2,
        p3 = p.p3,
        ci = p.c_init,
    )
}

/// 生成通过非同构元表元方法在运行期动态还原为 `target` 的多态代数式（8 种异构 AST 拓扑随机切换）。
pub fn emit_mt_state_expr(rng: &mut GenRng, mt_var: &str, base: i64, target: i64) -> String {
    let p = MtStateParams::from_seed(mt_var, base);
    let with_offset = |inner: String, val: i64, target: i64| -> String {
        let d = target - val;
        if d >= 0 {
            format!("({}+0X{:X})", inner, d)
        } else {
            format!("({}-0X{:X})", inner, -d)
        }
    };
    match rng.range(0, 8) {
        0 => {
            // 形态 0：外层常数反减 + 内层复合加法实参 `d - (M + (x1 + x2))`
            let x1 = rng.range64(0x100, 0x1_FFFF);
            let x2 = rng.range64(0x100, 0x1_FFFF);
            let v = p.eval_add(x1 + x2);
            let d = target + v;
            if d >= 0 {
                format!("(0X{d:X}-({m}+(0X{x1:X}+0X{x2:X})))", m = mt_var)
            } else {
                format!("(-0X{nd:X}-({m}+(0X{x1:X}+0X{x2:X})))", nd = -d, m = mt_var)
            }
        }
        1 => {
            // 形态 1：外层交换律前置常数 + 内层复合减法实参 `d + (M - (x1 - x2))`
            let x2 = rng.range64(0x100, 0x0FFF);
            let b = rng.range64(0x100, 0x2_FFFF);
            let x1 = b + x2;
            let v = p.eval_sub(b);
            let d = target - v;
            if d >= 0 {
                format!("(0X{d:X}+({m}-(0X{x1:X}-0X{x2:X})))", m = mt_var)
            } else {
                format!("(({m}-(0X{x1:X}-0X{x2:X}))-0X{nd:X})", m = mt_var, nd = -d)
            }
        }
        2 => {
            // 形态 2：双元方法级联 `((M + b1) - (M - b2)) ± d`（单表达式同时触发 __add 与 __sub）
            let b1 = rng.range64(0x100, 0x2_FFFF);
            let b2 = rng.range64(0x100, 0x2_FFFF);
            let v = p.eval_add(b1) - p.eval_sub(b2);
            with_offset(format!("(({m}+0X{b1:X})-({m}-0X{b2:X}))", m = mt_var), v, target)
        }
        3 => {
            // 形态 3：双元方法级联 `((M * b1) + (M + b2)) ± d`（单表达式同时触发 __mul 与 __add）
            let b1 = rng.range64(0x100, 0x2_FFFF);
            let b2 = rng.range64(0x100, 0x2_FFFF);
            let v = p.eval_mul(b1) + p.eval_add(b2);
            with_offset(format!("(({m}*0X{b1:X})+({m}+0X{b2:X}))", m = mt_var), v, target)
        }
        4 => {
            // 形态 4：双元方法级联 `((M * b1) - (M - b2)) ± d`（单表达式同时触发 __mul 与 __sub）
            let b1 = rng.range64(0x100, 0x2_FFFF);
            let b2 = rng.range64(0x100, 0x2_FFFF);
            let v = p.eval_mul(b1) - p.eval_sub(b2);
            with_offset(format!("(({m}*0X{b1:X})-({m}-0X{b2:X}))", m = mt_var), v, target)
        }
        5 => {
            // 形态 5：外层倍率缩放 `(w * (M - b)) ± d`
            let w = rng.range64(2, 9);
            let b = rng.range64(0x100, 0x2_FFFF);
            let v = w * p.eval_sub(b);
            with_offset(format!("(0X{w:X}*({m}-0X{b:X}))", m = mt_var), v, target)
        }
        6 => {
            // 形态 6：外层非线性取模包裹 `(((M * b) + bias) % md) ± d`
            let b = rng.range64(0x100, 0x2_FFFF);
            let bias: i64 = 0x4000_0000;
            let md = rng.range64(0x4000, 0x0FFF_FFFF);
            let v = (p.eval_mul(b) + bias).rem_euclid(md);
            with_offset(format!("((({m}*0X{b:X})+0X{bias:X})%0X{md:X})", m = mt_var), v, target)
        }
        _ => {
            // 形态 7：外层右乘缩放 `((M + b) * w) ± d`
            let w = rng.range64(2, 9);
            let b = rng.range64(0x100, 0x2_FFFF);
            let v = p.eval_add(b) * w;
            with_offset(format!("(({m}+0X{b:X})*0X{w:X})", m = mt_var), v, target)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_dedups_and_builds_guarded_slots() {
        let mut rng = GenRng::new(0x1234_5678);
        let mut uni = UniStream::new(&mut rng);
        let mut v = NameVault::new(&mut rng);
        let a = v.global("pcall");
        let b = v.global("pcall");
        assert_eq!(a, b, "同名请求必须命中同一槽");
        let m = v.member("string", "byte");
        assert_ne!(a, m);
        let bx = v.bitop("bxor");
        let up = v.unpack();
        let rt = v.root();
        let l1 = v.lit("function");
        let l2 = v.lit("function");
        assert_eq!(l1, l2, "同字面量请求必须命中同一槽");
        assert_ne!(l1, a);
        let src = v.build(&mut rng, &mut uni, Some("KrEg"));
        // 引导三态式 + 弱表补齐 + 各槽装配都在
        assert!(src.contains("_ENV or _G"));
        assert!(src.contains("__mode") || src.contains("KrEg"));
        assert!(src.contains("KrEg"));
        for e in [&a, &m, &bx, &up, &rt, &l1] {
            let kl = e.split('[').nth(1).unwrap().trim_end_matches(']');
            assert!(src.contains(kl), "槽 {} 必须被装配", kl);
        }
        // 产物侧不得出现任何明文 API 名或类型串字面量（引导根 getfenv/_ENV/_G 除外）
        for bad in ["pcall", "string", "byte", "bxor", "unpack", "bit32", "setmetatable", "__mode", "\"k\"", "'k'", "\"function\"", "'function'"] {
            assert!(!src.contains(bad), "NB 建表泄漏明文: {}", bad);
        }
    }

    #[test]
    fn vault_bound_to_kreg_runs_in_lua51_and_resolves_slots() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let mut rng = GenRng::new(0xA91_BA5E);
        let mut uni = UniStream::new(&mut rng);
        let mut v = NameVault::new(&mut rng);
        v.bind_local("Kr");
        let s_pc = v.global("pcall");
        let s_ts = v.global("tostring");
        let s_sb = v.member("string", "byte");
        let s_mf = v.member("math", "floor");
        let s_bx = v.bitop("bxor");
        let s_up = v.unpack();
        let s_mt = v.kreg_mt();
        let s_lfn = v.lit("function");
        let s_lnum = v.lit("number");
        let s_idx = v.lit("__index");
        let nb_src = v.build(&mut rng, &mut uni, Some("Kr"));
        assert!(nb_src.starts_with("do (function()"), "必须 do..end 包裹防括号首语句歧义");
        assert!(!nb_src.contains("local Kr="), "bind_local 模式不得另起 local");
        let prelude = uni.emit_prelude(&mut rng);
        let script = format!(
            "{prelude} local Kr={{}}; {nb_src}              assert({s_pc}==pcall); assert({s_ts}==tostring);              assert({s_sb}('AB',2)==66); assert({s_mf}(3.9)==3);              assert({s_up}({{7,8,9}},2,3)==8);              assert(getmetatable(Kr)=={s_mt} and {s_mt}.__mode=='k');              assert({s_lfn}=='function' and {s_lnum}=='number' and {s_idx}=='__index');              local _ = {s_bx}; print('VAULT_LUA_OK')"
        );
        let out = std::process::Command::new(lua)
            .arg("-e").arg(&script).output().expect("run lua5.1");
        assert!(out.status.success(), "Lua failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("VAULT_LUA_OK"));
    }

    #[test]
    fn shell_methods_shuffle_and_dispatch_in_lua51() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let mut rng = GenRng::new(0x5E11_B0D5);
        let mut shell = ShellMethods::new(&mut rng);
        let m1 = shell.add(&mut rng, &["x"], "return x + 0X20".to_string());
        let s2 = rng.name();
        let m2 = shell.add_self(
            &mut rng,
            &s2,
            &["u", "v"],
            format!("return {}:{}({}) + v", s2, m1, "u"),
        );
        let call_expr = shell.call(&m2, &["0X10", "0X5"]);
        let wai = rng.name();
        let fu = rng.name();
        let mut fields = shell.into_fields();
        assert_eq!(fields.len(), 2);
        fields.push(format!("{}=function({}) return {} end", wai, shell.self_var, call_expr));
        fields.push(format!("{}=function(z) return z:{}() end", fu, wai));
        rng.shuffle(&mut fields);
        let script = format!(
            "local r = (function() return ({{ {} }}):{}() end)(); assert(r == 0X35); print('SHELL_OK')",
            fields.join(", "),
            fu
        );
        let out = std::process::Command::new(lua)
            .arg("-e")
            .arg(&script)
            .output()
            .expect("run lua5.1");
        assert!(out.status.success(), "Lua failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("SHELL_OK"));
    }

    #[test]
    fn into_balanced_fields_centers_payload_between_functional_halves() {
        let mut rng = GenRng::new(0xC3A7_E501);
        let mut shell = ShellMethods::new(&mut rng);
        for k in 0..10 {
            let body = "local a=0X10; a=a+0X20; ".repeat(20 + k * 5) + "return a";
            shell.add(&mut rng, &["x"], body);
        }
        let wai = rng.name();
        let fu = rng.name();
        let wai_pre = "local u=0X1; ".repeat(60);
        let payload = "P".repeat(4000);
        let wai_post = "local v=0X2; ".repeat(60);
        let wai_field = format!(
            "{}=function({}) {} local raw=([=[{}]=]); {} return #raw end",
            wai, shell.self_var, wai_pre, payload, wai_post
        );
        let fu_field = format!("{}=function(z) return z:{}() end", fu, wai);
        let balanced = shell.into_balanced_fields(&mut rng, wai_field, fu_field);
        let joined = format!("return ({{ {} }}):{}()", balanced.join(", "), fu);
        let open = joined.find("[=[").expect("must contain payload open");
        let close = joined[open..].find("]=]").map(|p| open + p + 3).unwrap();
        let upper_est = est_compressed_len(&joined[..open]);
        let lower_est = est_compressed_len(&joined[close..]);
        let ratio = upper_est as f64 / (upper_est + lower_est) as f64;
        assert!(
            (0.42..=0.58).contains(&ratio),
            "upper/lower functional code should be balanced around payload: upper={} lower={} ratio={:.3}",
            upper_est,
            lower_est,
            ratio
        );
    }

    #[test]
    fn non_isomorphic_mt_state_decl_and_all_expr_shapes_roundtrip_in_lua51() {
        let lua = std::path::Path::new("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let mut rng = GenRng::new(0x5EED_91A3);
        let mut script = String::new();
        for idx in 0..24 {
            let mt_var = format!("m_{}", idx);
            let base = rng.range64(0x10_0000, 0x01FF_FFFF);
            script.push_str(&emit_mt_state_decl(&mut rng, &mt_var, base));
            for _ in 0..16 {
                let target = rng.range64(0, 0x0FFF_FFFF);
                let expr = emit_mt_state_expr(&mut rng, &mt_var, base, target);
                script.push_str(&format!("assert({}==0X{:X});", expr, target));
                // 验证将 mt_var 替换为标量 base 时无法静态代换还原 target
                let naive_fold = expr.replace(&mt_var, &format!("0X{:X}", base));
                script.push_str(&format!("assert(({})~=0X{:X});", naive_fold, target));
            }
        }
        script.push_str("print('MT_NON_ISO_OK')");
        let out = std::process::Command::new(lua)
            .arg("-e")
            .arg(&script)
            .output()
            .expect("run lua5.1");
        assert!(out.status.success(), "Lua failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("MT_NON_ISO_OK"));
    }
}
