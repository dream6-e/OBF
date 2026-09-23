//! M1 batch: Luau bit-composed constant spellings for the opaque-predicate
//! toolbox (`Prng::opaque_literal`'s opt-in `bits` pool). Kept in its own file
//! because `src/random.rs` sits at the 80 KiB source-file ceiling.
//!
//! Every family written here is exact under Luau's u32 bit semantics (pinned
//! by `tests/opaque_bits.rs`), but no plain constant folder can recover the
//! value: folding requires resolving the hidden-name capture indirection
//! (BX/BA/LR are destructured validator parameters bound to bit32 functions)
//! *and* implementing bit32, and the operand roles differ per family, per
//! site, and per seed -- the numeric-interval analogue for constants.

use crate::random::Prng;

impl Prng {
    /// A fresh u32 operand for the bit-composed families: two 16-bit draws so
    /// the whole 32-bit lane really is reachable (a pair of `/ 65536` halves
    /// never is). Audit-nice values are retried so the census cannot start
    /// pointing inside the composed text.
    fn rand_operand32(&mut self) -> Option<u32> {
        for _ in 0..12 {
            let high = self.index(65536) as u32;
            let low = self.index(65536) as u32;
            let value = (high << 16) | low;
            if value != 0 && !Self::audit_nice(u64::from(value)) {
                return Some(value);
            }
        }
        None
    }

    /// M1 batch, Luau-only: further constant-composition families spelled with
    /// the *captured low-level names* (`BX=bit32.bxor`, `BA=bit32.band`,
    /// `LR=bit32.lrotate`). Every family is exact under Luau's u32 bit
    /// semantics -- the details the surrounding tests pin -- but no plain
    /// constant folder recovers the value: folding requires resolving the
    /// hidden-name capture indirection *and* implementing bit32, and the
    /// operand roles differ per family, per site and per seed (the number
    /// intervalic analogue of K21's dispatch-respelling for constants).
    ///
    /// Families (each producing zero or one candidate arm; the arithmetic
    /// families stay in the pool beside these, so a site's pool mixes both):
    ///
    /// * **(f) xor split** `BX(A,B)` -- `A` fresh, `B = A ^ v`.
    /// * **(g) rotated xor** `LR(BX(A,B),r)` -- protects against evaluators
    ///   that implement bxor but shortcut rotate counts.
    /// * **(h) mask window** `BA(C,M)` -- `M` masks exactly the value's bit
    ///   length, `C = v | noise<<bits`; the intervalic member of the set.
    /// * **(i) xor under mask** `BA(BX(A,B),M)` -- the chain form.
    ///
    /// As with the arithmetic families every operand is redrawn per site, is
    /// never the value, differs per seed, and never is an audit-nice literal.
    pub(crate) fn opaque_bit_arms(&mut self, value: u64) -> Vec<String> {
        let value32 = value as u32;
        let mut arms: Vec<String> = Vec::new();
        // (f) xor split.
        if let Some(a) = self.rand_operand32() {
            let b = a ^ value32;
            if b != value32 && b != 0 && !Self::audit_nice(u64::from(b)) {
                arms.push(format!("(BX({a},{b}))"));
            }
        }
        // (g) rotated xor.
        if let Some(a) = self.rand_operand32() {
            let r = 1 + self.index(31) as u32;
            let x = value32.rotate_right(r);
            let b = a ^ x;
            if x != value32 && b != value32 && b != 0 && !Self::audit_nice(u64::from(b)) {
                arms.push(format!("(LR(BX({a},{b}),{r}))"));
            }
        }
        // (h) mask window. `value < 2^31` guarantees bitlen <= 31, so an
        // off-value noise bit always exists above it.
        let bits = 32 - value32.leading_zeros();
        let bits = if bits == 0 { 1 } else { bits };
        let noise_max = (1u32 << (32 - bits)) - 1;
        debug_assert!(noise_max >= 1);
        let noise = 1 + self.index(noise_max.min(4095) as usize) as u32;
        let mask = if bits == 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        };
        let windowed = value32 | (noise << bits);
        if windowed != value32 && !Self::audit_nice(u64::from(windowed)) {
            arms.push(format!("(BA({windowed},{mask}))"));
            // (i) xor under mask shares the window construction.
            if let Some(a) = self.rand_operand32() {
                let x = value32 | (noise << bits);
                let b = a ^ x;
                if b != value32 && b != 0 && !Self::audit_nice(u64::from(b)) {
                    arms.push(format!("(BA(BX({a},{b}),{mask}))"));
                }
            }
        }
        arms
    }
}
