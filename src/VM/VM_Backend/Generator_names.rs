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
            "local {e0}=_ENV or _G; {stg}local {gf}={e0}[{exg}]; local {e}=({gf} and {gf}()) or {e0}; {sts}local {sm}={e}[{exs}]; local {t}={{}}; ",
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
        // 产物侧不得出现任何明文 API 名或类型串字面量
        for bad in ["pcall", "string", "byte", "bxor", "unpack", "bit32", "getfenv", "setmetatable", "__mode", "\"k\"", "'k'", "\"function\"", "'function'"] {
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
}
