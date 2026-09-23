//! M2 batch: additional opaque-predicate families requested by the user,
//! mixed into the existing composition layer with per-site random draws.
//! `src/random.rs` is at the 80 KiB ceiling, so the helpers live in their own
//! module and the toolbox (`opaque_literal*`, the condition shapers and
//! `opaque_guard`) calls in from there.
//!
//! Families (all exact under both targets' semantics; the all-ones masking
//! variant additionally requires a bit name in scope, which the callers
//! signal with the same `bits` opt-in as M1):
//!
//! * **自反 guard tables**: already covered by `opaque_guard` — extended here
//!   only by the type-check forms (`type(x)~="table"`, `type(x)=="number"`,
//!   both tautologically true for the numeric condition variables).
//! * **自减 zero-dwarf arms**: `(v+(A-A)+(Q-Q))` — the value survives the two
//!   self-cancelling groups; Luraph's noise-injection style.
//! * **位与全 1**: `(BA(arm,0xFFFFFFFF))` — bit32 identity over any exact arm;
//!   folding requires resolving the capture and recognising the mask.
//! * **布尔异或 / 布尔等价 wrappers**: `(not(C)~=(N~=0))` ≡ C,
//!   `(not(C)==((A-A)~=0))` ≡ C — Luraph's boolean-composition conditions.
//! * **循环移位伪装 dispatch keys**: `((o*2^S)%2^32)+floor(o/2^(32-S))==rol(k,S)`
//!   — a rotate spelt by plain arithmetic (or Luau `//`); folding it needs the
//!   multiplication-wide semantics, not an identity rewrite. Lua 5.1 spells
//!   floor as `(o-o%D)/D`, which is exact for the guaranteed operand range
//!   (variables are u16 lane values at every call site).

use crate::random::Prng;

impl Prng {
    /// A random non-audit-nice, non-zero operand for the noise/dwarf groups.
    /// Small enough to stay readable, large enough to not look like a special
    /// constant.
    fn dwarf_operand(&mut self, forbidden: u64) -> u64 {
        for _ in 0..16 {
            let value = 17 + self.index(2028) as u64;
            if !Self::audit_nice(value) && value != forbidden {
                return value;
            }
        }
        if forbidden == 1337 {
            1973
        } else {
            1337
        }
    }

    /// 自减 zero-dwarf wrapper: exact identity under both targets.
    pub(crate) fn zero_dwarf_arm(&mut self, arm: String, forbidden: u64) -> String {
        let a = self.dwarf_operand(forbidden);
        let q = self.dwarf_operand(forbidden);
        if self.index(2) == 0 {
            format!("({arm}+({a}-{a})+({q}-{q}))")
        } else {
            format!("({arm}+({a}-{a}))-({q}-{q})")
        }
    }

    /// 位与全 1: an all-ones bit32 AND around an exact arm. `bits` scope only;
    /// the mask's spelling rides the same mixed-radix lane as the anchors.
    pub(crate) fn all_ones_bit_arm(&mut self, arm: String, luau: bool) -> String {
        let _ = luau; // spelling stays decimal so the crate evaluator folds it
        format!("(BA({arm},4294967295))")
    }

    /// 布尔异或 / 布尔等价: wrap an exact condition in one of Luraph's
    /// boolean-composition forms. Both are exact identities:
    /// `(not C) ~= (N~=0)` ≡ C for any nonzero N (N~=0 ⇔ true),
    /// `(not C) == ((A-A)~=0)` ≡ C ((A-A)~=0 ⇔ false).
    pub(crate) fn bool_wrap(&mut self, condition: &str, forbid: &[u64]) -> String {
        let operand = |this: &mut Self| {
            for _ in 0..16 {
                let value = 17 + this.index(2028) as u64;
                if !Self::audit_nice(value) && !forbid.contains(&value) {
                    return value;
                }
            }
            1337
        };
        match self.index(2) {
            0 => {
                let n = operand(self);
                format!("(not({condition})~=({n}~=0))")
            }
            _ => {
                let a = operand(self);
                format!("(not({condition})==(({a}-{a})~=0))")
            }
        }
    }

    /// 循环移位伪装: spell `rol(variable, S) == K` with K = rol(value, S).
    /// Arity-safe on both targets: multiplication stays under 2^53 for every
    /// call-site operand (u16 lanes), division is exact floor semantics —
    /// Luau uses `//`, Lua 5.1 uses `(v - v%D)/D`.
    pub(crate) fn rol_dispatch_condition(
        &mut self,
        variable: &str,
        value: u16,
        luau: bool,
    ) -> String {
        debug_assert!(variable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
        // Reject rotates whose key would literally print the bound's digits --
        // the whole point is that a bound never literally appears beside its
        // own comparison. A few retries almost surely land; otherwise fall
        // back to a shift of 1 with the same rejection window.
        let mut s = 1;
        for _ in 0..6 {
            let candidate = 1 + self.index(21) as u32;
            let key = u64::from((value as u32).rotate_left(candidate));
            if !Self::spells_value(u64::from(value), &key.to_string()) {
                s = candidate;
                break;
            }
        }
        let dividend = 1u64 << s;
        let divisor = 1u64 << (32 - s);
        let mask = 1u64 << 32;
        let key = u64::from((value as u32).rotate_left(s));
        let rotated = if luau {
            format!("((({variable}*{dividend})%{mask})+({variable}//{divisor}))")
        } else {
            format!(
                "((({variable}*{dividend})%{mask})+((({variable}-({variable}%{divisor}))/{divisor})))"
            )
        };
        match self.index(3) {
            0 => format!("{rotated}=={key}"),
            1 => format!("{key}=={rotated}"),
            _ => format!("not({rotated}~={key})"),
        }
    }
}
