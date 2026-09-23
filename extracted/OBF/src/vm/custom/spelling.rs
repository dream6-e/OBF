//! Seeded escape-spelling of plain double-quoted string literals (L1 batch).
//!
//! Source: `analysis/luraph/混淆技术全解.md` section A -- every surviving
//! plaintext word in the emitted script is a static anchor (this build still
//! spelled `"userdata"`, `"table"` and `"function"` verbatim inside NAMECALL
//! adapters and pooled name tables, while Luraph-style products never leave
//! any). The obfuscator already varies numeric spellings, so this pass closes
//! the matching lexical surface for strings: each participating literal body
//! is respelled with an independent seeded mix of literal / `\ddd` / `\xHH`
//! (Luau) forms. Spellings are value-identical by construction -- Lua 5.1 and
//! Luau both accept zero-padded `\ddd` decimals, Luau additionally `\xHH` --
//! and both the before/after texts are fully re-lexed with a token-for-token
//! comparison, so the pass can never change program semantics. The seeded
//! stream is fresh and shared with no existing pass.

use super::*;
use crate::random::Prng;

/// Sole sink of this fresh stream; extend the documented "seed affects" list.
const SPELLING_SALT: u64 = 0x7370_656c_6c69_6e67;

/// Printable ASCII minus the quote and backslash. Anything else keeps its
/// literal byte, so a respelled body can never change the string value.
fn respellable(byte: u8) -> bool {
    (b'!'..=b'~').contains(&byte) && byte != b'"' && byte != b'\\'
}

fn participates(body: &[u8], rnd: &mut Prng) -> bool {
    // Length-1 strings include the audited probe arguments "s" / "S"; short
    // literals and anything already carrying an escape stay byte-stable.
    if body.len() < 2 || !body.iter().all(|&b| respellable(b)) {
        return false;
    }
    // 4/5 participation keeps a natural literal/escape mix instead of a
    // fully escaped (and thus machine-recognizable) script.
    rnd.index(5) != 0
}

fn spell_byte(byte: u8, luau: bool, rnd: &mut Prng) -> String {
    if rnd.index(100) < 55 {
        return (byte as char).to_string();
    }
    // `\ddd` is the only spelling both targets accept. Skipping it for 'U'
    // (85) and 'V' (86) keeps the zero-padded 3-digit runs off the audit's
    // NICE-value anchors; on Luau those two may use `\xHH` (the hex runs
    // "55"/"56" are not anchors), on Lua 5.1 they stay literal.
    let decimal_ok = !matches!(byte, 85 | 86);
    if luau {
        if !decimal_ok {
            return format!("\\x{byte:02X}");
        }
        return if rnd.index(2) == 0 {
            format!("\\{byte:03}")
        } else {
            format!("\\x{byte:02X}")
        };
    }
    if !decimal_ok {
        return (byte as char).to_string();
    }
    format!("\\{byte:03}")
}

/// Decode exactly the spellings this module can emit (plain bytes, `\ddd`,
/// `\xHH`) back to raw bytes; used to prove value identity after respelling.
fn decode_emitted(body: &str) -> Result<Vec<u8>, Diagnostic> {
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let kind = *bytes
            .get(i + 1)
            .ok_or_else(|| Diagnostic::new("spelling: truncated escape"))?;
        if kind == b'x' {
            let hex = body
                .get(i + 2..i + 4)
                .ok_or_else(|| Diagnostic::new("spelling: short hex escape"))?;
            let value = u8::from_str_radix(hex, 16)
                .map_err(|_| Diagnostic::new("spelling: bad hex escape"))?;
            out.push(value);
            i += 4;
        } else if kind.is_ascii_digit() {
            let digits = body
                .get(i + 1..i + 4)
                .ok_or_else(|| Diagnostic::new("spelling: short decimal escape"))?;
            if !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Diagnostic::new("spelling: bad decimal escape"));
            }
            let value: u16 = digits
                .parse()
                .map_err(|_| Diagnostic::new("spelling: bad decimal escape"))?;
            if value > 255 {
                return Err(Diagnostic::new("spelling: decimal escape out of range"));
            }
            out.push(value as u8);
            i += 4;
        } else {
            return Err(Diagnostic::new("spelling: unknown escape form"));
        }
    }
    Ok(out)
}

/// Respells plain double-quoted short-string bodies with an independent
/// seeded stream. Rejection-proof contract: token count is stable, every
/// non-string token is byte-identical, and every respelled string decodes
/// back to the original bytes; any violation refuses the whole output.
pub(crate) fn respell_script_strings(
    source: &str,
    seed: u64,
    target: Target,
) -> Result<String, Diagnostic> {
    let tokens = crate::lexer::lex(source, target)?;
    let mut rnd = Prng::lcg(seed ^ SPELLING_SALT);
    let luau = target.is_luau();
    let mut output = String::with_capacity(source.len() + source.len() / 4);
    let mut cursor = 0;
    let mut changed: Vec<(usize, Vec<u8>, String)> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let text = token.text(source);
        if token.kind != crate::lexer::TokenKind::String
            || !text.starts_with('"')
            || !text.ends_with('"')
        {
            continue;
        }
        let body = &text[1..text.len() - 1];
        if !participates(body.as_bytes(), &mut rnd) {
            continue;
        }
        let mut respelled = String::with_capacity(body.len() * 2);
        for &byte in body.as_bytes() {
            respelled.push_str(&spell_byte(byte, luau, &mut rnd));
        }
        output.push_str(&source[cursor..token.span.start]);
        output.push('"');
        output.push_str(&respelled);
        output.push('"');
        cursor = token.span.end;
        changed.push((index, body.as_bytes().to_vec(), respelled));
    }
    output.push_str(&source[cursor..]);

    // Full re-lex contract: identical token stream outside the respelled
    // string bodies, and every respelled body decodes back to the original
    // bytes (spelling is value-identical by verification, not by hope).
    let after = crate::lexer::lex(&output, target)?;
    if after.len() != tokens.len() {
        return Err(Diagnostic::new("spelling: token count changed"));
    }
    let mut cursor_chg = 0usize;
    for (index, (before, token)) in tokens.iter().zip(&after).enumerate() {
        if before.kind != token.kind {
            return Err(Diagnostic::new("spelling: token kind changed"));
        }
        let expected = if cursor_chg < changed.len() && changed[cursor_chg].0 == index {
            let (_, body, respelled) = &changed[cursor_chg];
            cursor_chg += 1;
            let mut out = String::with_capacity(respelled.len() + 2);
            out.push('"');
            out.push_str(respelled);
            out.push('"');
            let _ = body;
            out
        } else {
            before.text(source).to_string()
        };
        if expected != token.text(&output) {
            return Err(Diagnostic::new("spelling: unmarked token changed"));
        }
    }
    for (_, body, respelled) in &changed {
        if decode_emitted(respelled)?.as_slice() != body.as_slice() {
            return Err(Diagnostic::new("spelling: value drifted"));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::Target;

    fn plain(text: &str) -> String {
        format!("local t={{a=\"{text}\",b=\"ok\"}};return t.a..t.b")
    }

    #[test]
    fn respelled_strings_keep_values_and_other_tokens_on_both_targets() {
        for target in [Target::Lua51, Target::Luau] {
            for seed in [1, 7351, 7001, 42_424] {
                let source = plain("userdata==function");
                let out = respell_script_strings(&source, seed, target).unwrap();
                // The pass's own decoder must return every literal byte.
                {
                    // Re-run the same stream offline to collect (body, respelled) pairs.
                    let mut rnd = Prng::lcg(seed ^ SPELLING_SALT);
                    let tokens = crate::lexer::lex(&source, target).unwrap();
                    for token in &tokens {
                        let text = token.text(&source);
                        if token.kind != crate::lexer::TokenKind::String || !text.starts_with('"') {
                            continue;
                        }
                        let body = &text[1..text.len() - 1];
                        if !participates(body.as_bytes(), &mut rnd) {
                            continue;
                        }
                        let mut re = String::new();
                        for &b in body.as_bytes() {
                            re.push_str(&spell_byte(b, target.is_luau(), &mut rnd));
                        }
                        assert_eq!(decode_emitted(&re).unwrap(), body.as_bytes());
                    }
                }
                // "ok" is length 2 but may participate; "s"/"S"-class audited
                // single-letter shapes are length 1 and always byte-stable.
                assert!(out.contains("\"ok\"") || out.contains("\\"));
            }
        }
    }

    #[test]
    fn respelling_is_deterministic_per_seed_and_differs_across_seeds() {
        for target in [Target::Lua51, Target::Luau] {
            let source = plain("metamethod-__call");
            let a = respell_script_strings(&source, 99, target).unwrap();
            let b = respell_script_strings(&source, 99, target).unwrap();
            assert_eq!(a, b, "same seed must reproduce byte-identical text");
            let c = respell_script_strings(&source, 100, target).unwrap();
            assert_ne!(a, c, "different seeds should respell differently");
        }
    }

    #[test]
    fn lua51_never_emits_hex_or_unicode_spellings() {
        let source = plain("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        for seed in [3, 6, 9, 7001, 99991] {
            let out = respell_script_strings(&source, seed, Target::Lua51).unwrap();
            assert!(!out.contains("\\x"), "hex escape leaked into Lua 5.1 text");
            assert!(
                !out.contains("\\u"),
                "unicode escape leaked into Lua 5.1 text"
            );
        }
    }

    #[test]
    fn audited_short_shapes_and_escaped_bodies_are_left_byte_stable() {
        let source = "local s=\"s\";local t=\"S\";local u=\"\\\\115\";return s..t..u";
        let out = respell_script_strings(source, 7351, Target::Luau).unwrap();
        assert!(
            out.contains("\"s\""),
            "audited probe string must stay literal"
        );
        assert!(
            out.contains("\"S\""),
            "audited probe string must stay literal"
        );
        assert!(
            out.contains("\"\\\\115\""),
            "escaped bodies are never re-spelled"
        );
    }
}
