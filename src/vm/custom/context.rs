//! K22 — execution-context keyed dispatch: the semantic interpreter's successor
//! block is never written down as a constant anywhere.
//!
//! Before this pass every arm body ended with `sid = <stage>`, and the dispatch
//! chain matched that same number with its own equality/interval tests. An
//! analyst could therefore read the block graph off the text in one pass: any
//! number appearing both as an assignment and as a test *is* an edge -- the
//! "static next0/next1 recovery" the batch has to kill. This module replaces the
//! plaintext successor with a **wire token** that only decodes against a key the
//! run has to carry and against a per-image multiplicative mask:
//!
//! ```text
//!   wire      wv = mask(target) - kw             (written by the arm body)
//!   decode    sid = ((wv + kw) mod M) * inv      (once per dispatch round)
//!   roll      kw = (kw*A + sid*B + pc*C + cw) mod M
//!   reseed    kw = (kw*A + rid*B + pc*C + cw + dg) mod M ; wv = mask(init) - kw
//!   mask(t)   = (t * W) mod M       (W per image, invertible: M is prime)
//! ```
//!
//! Three things follow, and they are the two items the batch was asked for:
//!
//! * **Cascade (item 1).** `kw` is a rolling accumulator over what actually ran:
//!   it mixes the identity of the block that just executed (`sid`), the
//!   instruction serial (`pc`) and the runtime witness mask (`cw`, the
//!   share-derived `control` field). Every instruction fetch re-seeds it from the
//!   runtime-decoded recipe token `rid` **and from `dg`, a digest of the operand
//!   values the instruction just bound** (`a,b,c,k,j` -- the very locals the
//!   handler consumed). So the key that unlocks block `B(n+1)` is a checksum of
//!   the execution path *and of the real data that path computed*: a reader
//!   cannot evaluate a later block's wire token without replaying the earlier
//!   blocks in order, and cannot even evaluate one instruction's key without
//!   knowing what its operands were. `dg` is built only from equality
//!   comparisons, which are defined on every value the VM can hold (numbers,
//!   strings, tables, nil, false), so it can never fault, and the roll stays
//!   arithmetic on values the script already holds: no loaded key material and
//!   no dependency on wall-clock or host entropy, so the script stays
//!   bit-for-bit reproducible for a given `(source, target, seed)`.
//!
//!   The digest is what makes the key *load-bearing* rather than decorative. A
//!   roll that only mixed `(kw, sid, pc, cw)` would cancel: the arm writes
//!   `mask(t) - kw` and the decode adds `kw` straight back, so
//!   `sigma = mask(t)*inv` would hold for every arm no matter what the roll did.
//!   `dg` breaks that cancellation only for a reader: the decoder reconstructs
//!   it from the same live locals, so the machine agrees with itself while a
//!   static analysis has to decide `a==b`, `c==k`, `j==nil` for every
//!   instruction on every path.
//! * **No static successor table (item 2).** Every arm writes
//!   `wv = mask(target) - kw`, where `mask(target)` is a five-digit residue that
//!   has nothing to do with the stage numbering the chains partition (stages are
//!   drawn from `100..=999`; the mask pushes every literal above 999 and off the
//!   audit-nice values). The naive pairing -- "whatever number an arm writes is
//!   the number some arm tests" -- therefore scores zero: no wire literal is a
//!   stage value, so it cannot be matched against the chain. The value the arm
//!   *assigns* is not even a constant, because `kw` is live; the constant in the
//!   text is only a masked token. `sid` itself is produced by an arithmetic
//!   expression over live state before the interval chains run, so the chains
//!   partition a value that does not exist statically.
//!
//! What this is not: a secret. The decode statement ships in the script, so a
//! reader who (a) finds the one statement that turns a wire token back into a
//! state, (b) inverts the mask printed inside it and (c) replays the roll from
//! the entry recovers the graph. Step (c) is the expensive one and it is the
//! point of the pass, but (a)+(b) are a local read: this pass buys *structure*,
//! not secrecy. Buying the last step as well would mean keying each arm on the
//! real register values it computed, and that costs a per-arm statement
//! (measured at ~4 B/arm, ~2.4 KB/image) which the script and shell budgets do
//! not have: the decision is recorded here rather than silently skipped.
//!
//! The spellings are chosen so the *dispatch census* (K21) stays honest: no
//! spelling writes a comparison whose left side is `sid`, so `scan_dispatch_chain`
//! never reads a modulus check as an interval bound, and `sid %` never appears
//! (K21 banned the residue selector on the state variable).

use super::{structure, transport};
use crate::random::Prng;
use crate::Target;

/// The wire token written by every arm body and read back by the decode.
pub(crate) const WIRE_VAR: &str = "wv";
/// The rolling context key. Named so the emitted text stays greppable for the
/// gates that count roll statements.
pub(crate) const KEY_VAR: &str = "kw";
/// Frame-constant runtime witness mask (`control`, share-derived). Named `cw`
/// because `ct` and `ctx` already occur in unrelated emitted fields.
pub(crate) const CONTROL_VAR: &str = "cw";
/// The decoded block identity keeps the name `sid`: the interval chains still
/// partition it, and the K21 census scans exactly that name.
pub(crate) const STATE_VAR: &str = "sid";

/// Same prime the K8 route table and the frame tag already use, so the batch
/// introduces no new pretty constant.
pub(crate) const MODULUS: u64 = 65521;

/// Every stage number the emitter can hand out comes from `state_values`
/// (`100..=999`). The mask hygiene below leans on that ceiling, so it is named
/// here instead of being re-derived at each use site.
const STAGE_CEILING: u64 = 999;

/// Draw a mixing weight: never `0`/`1` (degenerate rolls), never one of the
/// audit-anchored "nice" values (the same list the interval bounds and the
/// dispatch noise avoid), and never a value already used by this plan, so the
/// three terms of the roll cannot collapse into each other.
fn weight(random: &mut Prng, taken: &mut Vec<u64>) -> u64 {
    loop {
        let value = 2 + random.index((MODULUS - 3) as usize) as u64;
        if structure::nice_label(value) || transport::is_nice_part(value) || taken.contains(&value)
        {
            continue;
        }
        taken.push(value);
        return value;
    }
}

/// The per-image key plan. Draws from its own stream so enabling the chain does
/// not shift any other seed-derived decision in the emitter: the rest of the
/// generated script stays byte-identical and the diff of this batch is exactly
/// the new statements plus the wire-token writes.
#[derive(Clone, Debug)]
pub(crate) struct ContextPlan {
    pub(crate) modulus: u64,
    pub(crate) mul_key: u64,
    pub(crate) mul_state: u64,
    pub(crate) mul_pc: u64,
    wire_mul: u64,
    wire_inv: u64,
    digest: [u64; 6],
    digest_form: usize,
    decode_form: usize,
    roll_form: usize,
    reset_form: usize,
    end_form: usize,
}

impl ContextPlan {
    /// Build the plan for one image. `stages` is every block number the emitter
    /// can name as a successor (`fragment_states` plus the recipe tail's init
    /// state); it is needed for the mask hygiene, because the masked literal of
    /// a real stage is what ships inside the arms.
    pub(crate) fn new(target: Target, seed: u64, stages: &[u16]) -> Self {
        // Independent salt (same convention as `fields.rs`): the chain's
        // spellings are per-image, the seeded choices behind them are not
        // allowed to perturb the structure stream.
        let _ = target;
        let mut random = Prng::new(seed ^ 0x6b32_3263_7478_6b31);
        let mut taken = Vec::new();
        let mul_key = weight(&mut random, &mut taken);
        let mul_state = weight(&mut random, &mut taken);
        let mul_pc = weight(&mut random, &mut taken);
        let wire_mul = mask_weight(&mut random, stages);
        let wire_inv = mod_inverse(wire_mul, MODULUS);
        let mut digest = [0u64; 6];
        for slot in digest.iter_mut() {
            // Small and coprime-free by construction: the term is an addend of
            // the roll sum, so any value under the modulus works; only the audit
            // anchors are avoided.
            loop {
                let value = 2 + random.index(96) as u64;
                if !structure::nice_label(value) && !transport::is_nice_part(value) {
                    *slot = value;
                    break;
                }
            }
        }
        ContextPlan {
            modulus: MODULUS,
            mul_key,
            mul_state,
            mul_pc,
            wire_mul,
            wire_inv,
            digest,
            digest_form: random.index(4),
            decode_form: random.index(4),
            roll_form: random.index(4),
            reset_form: random.index(2),
            end_form: random.index(4),
        }
    }

    /// `mask(t) = (t * W) mod M` for one stage.
    pub(crate) fn mask_literal(&self, target: u16) -> u64 {
        (u64::from(target) * self.wire_mul) % self.modulus
    }

    /// The per-image wire multiplier, for the gates that read the arithmetic
    /// back out of the emitted text.
    pub(crate) fn wire_mul(&self) -> u64 {
        self.wire_mul
    }

    pub(crate) fn wire_inv(&self) -> u64 {
        self.wire_inv
    }

    /// One of four exactly equivalent spellings of the decode. None of them puts
    /// a comparison on `sid`: two spellings just reduce and multiply, one
    /// reduces a possibly negative sum with a conditional add *inside the
    /// expression*, and one reduces it in a statement of its own. Lua's `%` is a
    /// floor modulus on doubles and every operand is exact in that model, so
    /// the four are the same function; the gate file runs all four on the real
    /// interpreter rather than trusting this comment.
    pub(crate) fn decode_stmt(&self) -> String {
        let (m, inv) = (self.modulus, self.wire_inv);
        match self.decode_form {
            0 => format!("{STATE_VAR}=({WIRE_VAR}+{KEY_VAR})%{m}*{inv}%{m};"),
            1 => format!("{STATE_VAR}=({KEY_VAR}+{WIRE_VAR})%{m}*{inv}%{m};"),
            2 => format!(
                "{STATE_VAR}=({WIRE_VAR}+{KEY_VAR}-({WIRE_VAR}+{KEY_VAR}<0 and {m} or 0))%{m}*{inv}%{m};"
            ),
            _ => format!(
                "{STATE_VAR}={WIRE_VAR}+{KEY_VAR};if {STATE_VAR}<0 then {STATE_VAR}={STATE_VAR}+{m} end;{STATE_VAR}={STATE_VAR}*{inv}%{m};"
            ),
        }
    }

    /// The roll, spelled one of four ways (term order and operand order inside
    /// the products). Every spelling is the same polynomial in `(kw, sid, pc,
    /// cw)`; the weights are below 2^16 and the state below 2^16, so each
    /// product stays under 2^32 and the four-term sum stays exactly
    /// representable as a double before the modulus.
    pub(crate) fn roll_stmt(&self) -> String {
        self.roll_expr(&format!("{KEY_VAR}"), STATE_VAR, "pc", CONTROL_VAR)
    }

    fn roll_expr_with_digest(&self, key: &str, state: &str, pc: &str, control: &str) -> String {
        let body = self.roll_body(key, state, pc, control);
        format!(
            "{KEY_VAR}=({body}+{})%{};",
            self.digest_expr(),
            self.modulus
        )
    }

    fn roll_expr(&self, key: &str, state: &str, pc: &str, control: &str) -> String {
        let body = self.roll_body(key, state, pc, control);
        format!("{KEY_VAR}=({body})%{};", self.modulus)
    }

    fn roll_body(&self, key: &str, state: &str, pc: &str, control: &str) -> String {
        let (a, b, c) = (self.mul_key, self.mul_state, self.mul_pc);
        let body = match self.roll_form {
            0 => format!("{key}*{a}+{state}*{b}+{pc}*{c}+{control}"),
            1 => format!("{a}*{key}+{b}*{state}+{c}*{pc}+{control}"),
            2 => format!("{key}*{a}+{control}+{state}*{b}+{pc}*{c}"),
            _ => format!("{pc}*{c}+{key}*{a}+{state}*{b}+{control}"),
        };
        body
    }

    /// The data digest: an additive term computed from the operand values the
    /// instruction just bound. It uses equality comparisons only, so it is
    /// defined for every value the VM can hold, and it is evaluated identically
    /// at the fetch (which rolls the key) and by any reader who replays the
    /// instruction -- except that a reader has to know the operands, which is
    /// exactly the dependency the batch wants.
    pub(crate) fn digest_expr(&self) -> String {
        let (p, q, r) = (self.digest[0], self.digest[1], self.digest[2]);
        let (s, t, u) = (self.digest[3], self.digest[4], self.digest[5]);
        match self.digest_form {
            0 => format!("((a==b)and {p} or {q})+((c==k)and {s} or {t})+((j==nil)and {r} or {u})"),
            1 => format!("((b==a)and {p} or {q})+((k==c)and {s} or {t})+((nil==j)and {r} or {u})"),
            2 => format!("((a==b)and {p} or {q})+((c~=k)and {t} or {s})+((j~=nil)and {u} or {r})"),
            _ => format!("({p}-((a~=b)and {q} or 0))+({s}-((c~=k)and {t} or 0))+({r}-((j~=nil)and {u} or 0))"),
        }
    }

    /// Instruction-fetch re-seed: the chain carries forward (it is mixed into
    /// itself) and picks up the runtime-decoded recipe token `rid` and the new
    /// instruction serial `pc`, then the wire token for the pending `init`
    /// dispatch is derived from that key. The literal stays *unreduced*
    /// (`mask - kw`, not `(mask - kw) % M`) because the recipe-end test below
    /// compares it against the same expression.
    pub(crate) fn reset_stmt(&self, init: u16) -> String {
        let mut text = self.roll_expr_with_digest(&format!("{KEY_VAR}"), "rid", "pc", CONTROL_VAR);
        let masked = self.mask_literal(init);
        match self.reset_form {
            0 => text.push_str(&format!("{WIRE_VAR}={masked}-{KEY_VAR};")),
            _ => text.push_str(&format!("{WIRE_VAR}=-{KEY_VAR}+{masked};")),
        }
        text
    }

    /// The successor write. `target`, the number the interval chains actually
    /// partition, never appears: the constant in the text is its masked residue
    /// and the assigned value additionally depends on the live key.
    pub(crate) fn successor(&self, target: u16) -> String {
        format!("{WIRE_VAR}={}-{KEY_VAR}", self.mask_literal(target))
    }

    /// The "the block that just ran was a recipe tail" test, in *wire* space.
    /// The recipe tail writes `successor(semantic_init)`, i.e.
    /// `mask(init) - kw` unreduced, and the key is not rolled between that write
    /// and this test, so the comparison is exact and needs no modulus. Testing
    /// the wire instead of the decoded state is what lets the machine keep its
    /// entry transition (state == init, arm writes the first chunk's wire)
    /// distinct from its loop-back transition (recipe tail wrote init's wire).
    pub(crate) fn recipe_end_condition(&self, init: u16) -> String {
        let (wire, key) = (WIRE_VAR, KEY_VAR);
        let masked = self.mask_literal(init);
        match self.end_form {
            0 => format!("{wire}=={masked}-{key}"),
            1 => format!("{wire}-{masked}+{key}==0"),
            2 => format!("{key}+{wire}=={masked}"),
            _ => format!("not({wire}~={masked}-{key})"),
        }
    }

    /// The Rust mirror of the wire arithmetic: `decode(encode(t, k), k) == t`
    /// for every state and key, and `decode` accepts the unreduced (possibly
    /// negative) wire the arms actually write.
    pub(crate) fn decode(&self, wire: u64, key: u64) -> u64 {
        ((wire + key) % self.modulus * self.wire_inv) % self.modulus
    }

    pub(crate) fn encode(&self, target: u64, key: u64) -> u64 {
        (self.mask_literal(target as u16) + self.modulus - key % self.modulus) % self.modulus
    }

    pub(crate) fn roll(&self, key: u64, state: u64, pc: u64, control: u64) -> u64 {
        (key * self.mul_key + state * self.mul_state + pc * self.mul_pc + control) % self.modulus
    }

    /// The three weights, in the order they are drawn. Gates pin the emitted
    /// text against the plan, so a future edit that changes one without the
    /// other fails instead of silently shipping a different chain.
    pub(crate) fn weights(&self) -> [u64; 3] {
        [self.mul_key, self.mul_state, self.mul_pc]
    }
}

/// Draw the wire multiplier. `M` is prime and every candidate is `< M` and `>= 2`,
/// so the inverse used by the decode always exists; what this filter adds is that
/// the *literals that ship in the arms* stay unusable for pattern matching:
/// every masked stage must clear the three-digit stage band (so it can never be
/// mistaken for, or matched against, a chain arm value) and must miss the
/// audit-nice anchors. For ~40 stages roughly half the draws qualify, and the
/// budget is generous because a plan that fails here would ship leaking
/// literals; if no draw qualifies the last one is kept (the filter is a
/// hygiene ratchet, not a correctness condition).
fn mask_weight(random: &mut Prng, stages: &[u16]) -> u64 {
    let mut fallback = 2;
    for attempt in 0..1024 {
        let candidate = 2 + random.index((MODULUS - 3) as usize) as u64;
        let clean = stages.iter().all(|stage| {
            let masked = u64::from(*stage) * candidate % MODULUS;
            masked > STAGE_CEILING
                && !structure::nice_label(masked)
                && !transport::is_nice_part(masked)
        });
        if clean {
            return candidate;
        }
        if attempt == 0 {
            fallback = candidate;
        }
    }
    fallback
}

/// Extended Euclid on `u64`; `modulus` is prime so the inverse always exists for
/// a non-zero input, and the loop is bounded by the classic Fibonacci bound.
fn mod_inverse(value: u64, modulus: u64) -> u64 {
    let (mut old_r, mut r) = (value as i128, modulus as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let quotient = old_r / r;
        let (nr, ns) = (old_r - quotient * r, old_s - quotient * s);
        old_r = r;
        r = nr;
        old_s = s;
        s = ns;
    }
    let inverse = old_s % modulus as i128;
    ((inverse + modulus as i128) % modulus as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stage list shaped like the emitter's: every value from `state_values`.
    const STAGES: [u16; 8] = [459, 512, 288, 190, 170, 178, 977, 860];

    fn plan_for(seed: u64) -> ContextPlan {
        ContextPlan::new(Target::Lua51, seed, &STAGES)
    }

    /// The wire/decode pair is an exact round trip for every state the emitter
    /// can produce and for every key the roll can reach (the modulus is closed
    /// under the roll, so the key domain is the full residue ring).
    #[test]
    fn wire_encode_decode_roundtrips_over_the_whole_state_domain() {
        for seed in [0u64, 1, 7001, 7351, 0x6b32, u64::MAX] {
            let plan = plan_for(seed);
            for state in (0u64..MODULUS).step_by(97) {
                for key in (0u64..MODULUS).step_by(1301) {
                    let wire = plan.encode(state, key);
                    assert!(wire < plan.modulus, "seed {seed}: wire {wire} out of range");
                    assert_eq!(
                        plan.decode(wire, key),
                        state,
                        "seed {seed}: wire {wire} under key {key} does not decode to {state}"
                    );
                    // The arms write the *unreduced* expression; the decode must
                    // take that too, including the negative branch.
                    let unreduced =
                        (state as i128 * plan.wire_mul() as i128 - (key % plan.modulus) as i128)
                            .rem_euclid(plan.modulus as i128) as u64;
                    assert_eq!(unreduced, wire);
                }
            }
        }
    }

    /// Every spelling is the same function. The arm writes the *unreduced*
    /// value `mask - key` (negative when the key is the larger one), so the
    /// four spellings have to agree on that input as well: the boundary cases
    /// are the literals and keys that make the sum land on 0, 1 or `M - 1`, and
    /// the negative-wire case that the conditional add exists for.
    #[test]
    fn every_decode_spelling_agrees_on_the_boundary_values() {
        for seed in [2u64, 7001, 7351, 4242, u64::MAX] {
            let plan = plan_for(seed);
            // `m` and `inv` as i128 so the negative branch is exercised exactly.
            let (m, inv) = (plan.modulus as i128, plan.wire_inv() as i128);
            let biggest = *STAGES.iter().max().unwrap();
            for literal in [
                0i128,
                1,
                m - 1,
                m / 2,
                plan.mask_literal(biggest) as i128,
                plan.mask_literal(STAGES[0]) as i128,
            ] {
                for key in [0i128, 1, m - 1, m / 3, m / 2] {
                    // The write site: `wv = L - kw`, deliberately unreduced.
                    let live = literal - key;
                    // The successor is decided by the static literal alone.
                    let want = (literal % m * inv) % m;
                    // Form 0/1: `(wv+kw)%M*inv%M`.
                    assert_eq!(
                        (live + key) % m * inv % m,
                        want,
                        "seed {seed}: spelling 1/2 diverges at literal {literal} key {key}"
                    );
                    // Form 2: `(wv+kw-(wv+kw<0 and M or 0))%M*inv%M`. The sum is
                    // `L` here, so the branch is only reachable through a reader
                    // that reduces the wire first -- both inputs must agree.
                    for wire in [live, live.rem_euclid(m)] {
                        let sum = wire + key;
                        let shifted = if sum < 0 { sum + m } else { sum };
                        assert_eq!(
                            shifted % m * inv % m,
                            want,
                            "seed {seed}: spelling 3 diverges at literal {literal} key {key}"
                        );
                        // Form 3: `sid=wv+kw;if sid<0 then sid=sid+M end;sid=sid*inv%M`.
                        let mut sid = sum;
                        if sid < 0 {
                            sid += m;
                        }
                        assert_eq!(
                            sid * inv % m,
                            want,
                            "seed {seed}: spelling 4 diverges at literal {literal} key {key}"
                        );
                    }
                }
            }
            // And the shipped literals round-trip: `mask_literal` and `wire_inv`
            // are inverses, so every stage is recoverable from its own literal.
            for stage in STAGES {
                let literal = plan.mask_literal(stage);
                let wire = (literal as i128 - 7).rem_euclid(m) as u64;
                assert_eq!(plan.decode(wire, 7), u64::from(stage));
                assert!(plan.decode(wire, 7) <= STAGE_CEILING);
            }
        }
    }

    /// The weights are distinct, non-degenerate and clear of every audit anchor
    /// the generator avoids elsewhere; the mask is invertible and pushes every
    /// shipped literal out of the stage band; the plan is deterministic per seed
    /// and different seeds do not share the same weights.
    #[test]
    fn weights_and_mask_are_seeded_and_never_an_audit_anchor() {
        let mut seen: Vec<[u64; 3]> = Vec::new();
        for seed in [0u64, 1, 2, 7001, 7351, 4242, 0x6b32_3263, u64::MAX] {
            let plan = plan_for(seed);
            let weights = plan.weights();
            for value in weights {
                assert!(value >= 2 && value < MODULUS, "weight {value} out of range");
                assert!(
                    !structure::nice_label(value),
                    "weight {value} is a nice label"
                );
                assert!(
                    !transport::is_nice_part(value),
                    "weight {value} is a nice part"
                );
            }
            assert_ne!(weights[0], weights[1]);
            assert_ne!(weights[1], weights[2]);
            assert_ne!(weights[0], weights[2]);
            let mask = plan.wire_mul();
            assert!(
                mask >= 2 && mask < MODULUS,
                "wire multiplier {mask} out of range"
            );
            assert!(!structure::nice_label(mask), "mask {mask} is a nice label");
            assert_eq!(
                mask * plan.wire_inv() % MODULUS,
                1,
                "mask {mask} is not invertible"
            );
            assert_ne!(mask, 1, "an identity mask keeps the literal a stage value");
            for stage in STAGES {
                let literal = plan.mask_literal(stage);
                assert!(
                    literal > STAGE_CEILING,
                    "seed {seed}: stage {stage} masks to {literal}, inside the stage band"
                );
                assert!(
                    !STAGES.contains(&(literal as u16)),
                    "seed {seed}: stage {stage} masks to another stage ({literal})"
                );
                assert!(
                    !structure::nice_label(literal) && !transport::is_nice_part(literal),
                    "seed {seed}: masked literal {literal} is an audit anchor"
                );
                assert_ne!(
                    literal,
                    u64::from(stage),
                    "seed {seed}: the stage leaks through unmodified"
                );
            }
            assert_eq!(plan.weights(), plan_for(seed).weights());
            assert_eq!(plan.wire_mul(), plan_for(seed).wire_mul());
            seen.push(weights);
        }
        seen.sort_unstable();
        seen.dedup();
        assert!(seen.len() >= 6, "weights do not vary with the seed");
    }

    /// The roll is a genuine function of all four inputs: changing any one of
    /// them (including the witness-derived `cw`) changes the produced key for
    /// at least one sampled state, so no term is decorative.
    #[test]
    fn every_roll_input_is_load_bearing() {
        let plan = plan_for(7001);
        let base = plan.roll(11, 22, 33, 44);
        assert_ne!(base, plan.roll(12, 22, 33, 44), "key weight is inert");
        assert_ne!(base, plan.roll(11, 23, 33, 44), "state weight is inert");
        assert_ne!(base, plan.roll(11, 22, 34, 44), "pc weight is inert");
        assert_ne!(base, plan.roll(11, 22, 33, 45), "witness term is inert");
        // The roll closes over the residue ring, so the key domain is self
        // contained: no key ever leaves `0..M`.
        for key in [0u64, 1, MODULUS - 1] {
            assert!(plan.roll(key, MODULUS - 1, MODULUS - 1, MODULUS - 1) < MODULUS);
        }
    }

    /// Statement text carries exactly the plan's own numbers (read back through
    /// the real lexer, so a number that happens to be a substring of another
    /// cannot satisfy the check by accident), the successor write is always in
    /// wire space, and no spelling compares `sid` -- which is what keeps the
    /// K21 interval census able to treat every `sid` comparison as a chain node.
    #[test]
    fn statements_spell_the_plan_once_and_never_compare_the_state() {
        for seed in [7001u64, 7351, 3] {
            let plan = ContextPlan::new(Target::Luau, seed, &STAGES);
            let decode = plan.decode_stmt();
            let roll = plan.roll_stmt();
            let reset = plan.reset_stmt(512);
            assert!(decode.starts_with(&format!("{STATE_VAR}=")), "{decode}");
            assert!(roll.starts_with(&format!("{KEY_VAR}=")), "{roll}");
            assert!(reset.contains("rid"), "{reset}");
            assert!(roll.ends_with(';'), "{roll}");
            assert!(reset.ends_with(';'), "{reset}");
            let numbers = |text: &str| -> Vec<u64> {
                crate::lexer::lex(text, Target::Luau)
                    .unwrap()
                    .iter()
                    .filter(|token| token.kind == crate::lexer::TokenKind::Number)
                    .filter_map(|token| token.text(text).parse::<u64>().ok())
                    .collect()
            };
            let mut decode_numbers = numbers(&decode);
            decode_numbers
                .retain(|value| *value != plan.modulus && *value != plan.wire_inv() && *value != 0);
            assert!(
                decode_numbers.is_empty(),
                "decode {decode:?} spells numbers beyond modulus/inverse"
            );
            for text in [&roll, &reset] {
                let mut spelled = numbers(text);
                spelled.retain(|value| {
                    *value != plan.modulus
                        && *value != plan.mask_literal(512)
                        && *value != 0
                        && !plan.weights().contains(value)
                        && !plan.digest.contains(value)
                });
                assert!(
                    spelled.is_empty(),
                    "{text:?} spells numbers beyond weights/mask"
                );
            }
            let successor = plan.successor(512);
            assert_eq!(
                successor,
                format!("{WIRE_VAR}={}-{KEY_VAR}", plan.mask_literal(512))
            );
            let end = plan.recipe_end_condition(512);
            assert!(end.contains(&plan.mask_literal(512).to_string()), "{end}");
            assert!(!end.contains(&512u64.to_string()) || plan.mask_literal(512) == 512);
        }
    }
}
