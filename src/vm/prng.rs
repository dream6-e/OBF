use std::collections::BTreeSet;
use std::fmt::Write;

/// Small deterministic generator used only for layout randomization.
///
/// This is deliberately not presented as a cryptographic primitive. Data
/// encryption and key derivation belong to a later milestone.
pub struct Prng {
    state: u64,
}

impl Prng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.state = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn index(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            0
        } else {
            (self.next_u64() % upper as u64) as usize
        }
    }

    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = self.index(index + 1);
            values.swap(index, other);
        }
    }

    pub fn unique_opcodes(&mut self, count: usize) -> Vec<u16> {
        let mut used = BTreeSet::new();
        let mut result = Vec::with_capacity(count);
        while result.len() < count {
            let candidate = 257 + (self.next_u64() % 65_000) as u16;
            if used.insert(candidate) {
                result.push(candidate);
            }
        }
        result
    }

    /// Spell an exact non-negative integer using only forms accepted by the
    /// selected output target. Lua 5.1 receives decimal/hexadecimal forms;
    /// Luau may additionally receive binary digits and separators.
    pub fn integer_literal(&mut self, value: u64, luau: bool) -> String {
        match self.index(if luau { 3 } else { 2 }) {
            0 => value.to_string(),
            1 => format!("0x{value:x}"),
            2 => {
                let digits = format!("{value:b}");
                let first = {
                    let remainder = digits.len() % 4;
                    if remainder == 0 {
                        4
                    } else {
                        remainder
                    }
                };
                let mut result = String::from("0b");
                result.push_str(&digits[..first]);
                for chunk in digits.as_bytes()[first..].chunks(4) {
                    result.push('_');
                    result.push_str(std::str::from_utf8(chunk).expect("binary digits are UTF-8"));
                }
                result
            }
            _ => unreachable!(),
        }
    }

    /// Emit one of several side-effect-free dispatcher comparisons. Only the
    /// opcode comparison changes; handler evaluation order stays unchanged.
    pub fn dispatch_condition(&mut self, opcode: u16, luau: bool) -> String {
        let literal = self.integer_literal(u64::from(opcode), luau);
        let mut result = String::new();
        match self.index(4) {
            0 => write!(result, "o=={literal}").unwrap(),
            1 => write!(result, "{literal}==o").unwrap(),
            2 => write!(result, "not(o~={literal})").unwrap(),
            3 => write!(result, "o-{literal}==0").unwrap(),
            _ => unreachable!(),
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::Prng;

    #[test]
    fn deterministic_and_unique() {
        let left = Prng::new(42).unique_opcodes(128);
        let right = Prng::new(42).unique_opcodes(128);
        assert_eq!(left, right);
        let mut sorted = left.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 128);
    }

    #[test]
    fn numeric_spelling_is_target_aware() {
        let mut lua = Prng::new(7);
        for _ in 0..64 {
            let literal = lua.integer_literal(0x1234, false);
            assert!(!literal.starts_with("0b"));
            assert!(!literal.contains('_'));
        }

        let mut luau = Prng::new(7);
        let literals: Vec<_> = (0..64)
            .map(|_| luau.integer_literal(0x1234, true))
            .collect();
        assert!(literals.iter().any(|literal| literal.starts_with("0b")));
        assert!(literals.iter().any(|literal| literal.contains('_')));
    }
}
