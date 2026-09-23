// Boundary-partition gate, relocated out of `src/random.rs` (80 KiB ceiling)
// during the M2 batch and adapted 先测后录 for the new boolean-composition
// wrappers: the renderer now wraps one condition in three in
// `(not(C)~=(N~=0))` (boolean-xor form) or `(not(C)==((A-A)~=0))`
// (boolean-equivalence form) -- both exact identities on the inner C. The gate
// unwraps exactly these two documented shapes and then checks the partition
// semantics on the inner spelling, keeping the coverage census airtight:
// anything else that changes the condition surface still panics here.

/// Strip the two M2 boolean wrappers; everything else passes through.
fn unwrap_bool(mut text: &str) -> &str {
    while let Some(rest) = text
        .strip_prefix("(not(")
        .and_then(|t| t.strip_suffix("~=0))"))
    {
        if let Some((captured, _)) = rest.rsplit_once(")==((") {
            // `(not(C)==((A-A)~=0))`
            text = captured;
            continue;
        }
        if let Some((captured, _)) = rest.rsplit_once(")~=(") {
            // `(not(C)~=(N~=0))`
            text = captured;
            continue;
        }
        panic!("undocumented wrapper spelling {text:?}");
    }
    text
}

fn boundary_label(text: &str) -> &'static str {
    let trimmed = unwrap_bool(text.trim());
    if let Some(inner) = trimmed
        .strip_prefix("not(")
        .and_then(|body| body.strip_suffix(')'))
    {
        return if inner.contains(">=") { "not>=" } else { "not<" };
    }
    if let Some(rest) = trimmed.strip_prefix("o-") {
        return if rest.ends_with("<0") {
            "o-K<0"
        } else {
            "o-K>=0"
        };
    }
    if trimmed.starts_with("o<") {
        "o<"
    } else if trimmed.starts_with("o>=") {
        "o>="
    } else if trimmed.ends_with(">o") {
        "K>o"
    } else if trimmed.ends_with("<=o") {
        "K<=o"
    } else if trimmed.ends_with(">0") {
        "K-o>0"
    } else {
        panic!("unexpected boundary spelling {trimmed:?}")
    }
}

/// `boundary_condition` is what the validator's search tree partitions on,
/// so every spelling it can emit must be an exact `<` / `>=` complement over
/// the whole byte range: one wrong spelling would route records to the wrong
/// arm (or past every arm) while still looking like a plain dispatch chain.
/// The parser below accepts exactly the nine inner forms the renderer can
/// produce (after wrapper unwrapping) and panics on anything else, so new
/// spellings cannot go uncovered. M2 also requires both wrapper forms to show
/// up under the sweep -- a silent revert of the wrapper draw would halve the
/// boolean surface on the shipped conditions.
#[test]
fn boundary_conditions_partition_the_byte_range_exactly() {
    fn literal(token: &str) -> i64 {
        if let Some(hex) = token.strip_prefix("0x") {
            i64::from_str_radix(hex, 16).expect("hex literal")
        } else if let Some(bits) = token.strip_prefix("0b") {
            i64::from_str_radix(&bits.replace('_', ""), 2).expect("binary literal")
        } else {
            token.parse::<i64>().expect("decimal literal")
        }
    }
    fn side(token: &str, value: i64) -> i64 {
        let token = token.trim();
        if token == "o" {
            return value;
        }
        if let Some(rest) = token.strip_prefix("o-") {
            return value - literal(rest.trim());
        }
        if let Some(pos) = token.find("-o") {
            return literal(&token[..pos]) - value;
        }
        literal(token)
    }
    fn holds(text: &str, value: i64) -> bool {
        let trimmed = unwrap_bool(text.trim());
        if let Some(inner) = trimmed
            .strip_prefix("not(")
            .and_then(|body| body.strip_suffix(')'))
        {
            return !holds(inner, value);
        }
        // `<` and `>` are checked after their inclusive siblings so a
        // leading `<=` is never split into `<` plus a stray `=`.
        for op in ["<=", ">=", "<", ">"] {
            if let Some((left, right)) = trimmed.split_once(op) {
                let (a, b) = (side(left, value), side(right, value));
                return match op {
                    "<=" => a <= b,
                    ">=" => a >= b,
                    "<" => a < b,
                    _ => a > b,
                };
            }
        }
        panic!("unparsable boundary condition {trimmed:?}");
    }

    for luau in [false, true] {
        let mut rng = Prng::new(0xb01d_2024);
        let mut seen = std::collections::BTreeSet::new();
        let mut wrapped = 0usize;
        for bound in 0..=255u16 {
            for below in [true, false] {
                let text = rng.boundary_condition("o", bound, below, luau);
                if unwrap_bool(&text).len() != text.len() {
                    wrapped += 1;
                }
                // The bound in the text must be the requested one, and the
                // two families must be exact complements at every value.
                for value in [0i64, 1, 63, 64, 127, 128, 254, 255, 256] {
                    let below_holds = holds(&text, value)
                        == (if below { value < i64::from(bound) } else { value >= i64::from(bound) });
                    assert!(below_holds, "{text} at o={value} against {bound}");
                }
                seen.insert(boundary_label(&text));
            }
        }
        // Every inner spelling the renderer owns must actually show up,
        // otherwise the partition check above quietly covers a subset.
        assert_eq!(
            seen.len(),
            9,
            "{target} boundary spellings: {seen:?}",
            target = if luau { "luau" } else { "lua51" }
        );
        assert_eq!(
            wrapped, 0,
            "raw boundary funnel picked up an M2 wrapper without a bits scope"
        );
    }

    // The licensed scope: opaque boundary conditions with bits=true may carry
    // the boolean wrappers; the partition semantics must still be exact. The
    // crate evaluator (u32-exact, wrapper-capable) reads the compound text
    // directly -- an exactness check, not a shape census.
    fn unwrap_is_wrapper(text: &str) -> bool {
        unwrap_bool(text).len() != text.len()
    }
    {
        let mut rng = Prng::new(0xb02d_20b1_7f0a_1145);
        let mut wrapped = 0usize;
        for bound in [1u16, 3, 17, 86, 255, 256, 512, 4096, 65_535] {
            for below in [true, false] {
                for _ in 0..64 {
                    let text = crate::random::Prng::boundary_condition_opaque(
                        &mut rng, "X", bound, below, true, true, "X",
                    );
                    if unwrap_is_wrapper(&text) {
                        wrapped += 1;
                    }
                    for probe in [0i64, 1, i64::from(bound) - 1, i64::from(bound), i64::from(bound) + 1, 101_013] {
                        let expected = if below { probe < i64::from(bound) } else { probe >= i64::from(bound) };
                        assert_eq!(
                            crate::random::tests::OvParser::truthy(&text, probe),
                            expected,
                            "{text} at X={probe} vs bound {bound} below={below}"
                        );
                    }
                }
            }
        }
        assert!(wrapped > 64, "M2 boolean wraps faded away: {wrapped}");
    }
}
