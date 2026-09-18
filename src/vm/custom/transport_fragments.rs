use super::*;
use std::collections::BTreeMap;

/// Goal 7: split one encoded transport segment into a shuffled table of
/// independently quoted fragments. Byte zero of every fragment is its ordinal
/// in this segment's private alphabet; the runtime removes it before joining.
/// No individual string token is a complete base86 stream anymore.
pub(crate) fn fragment_segment_literal(
    text: &str,
    alphabet: &[u8; 86],
    rng: &mut crate::random::Prng,
) -> String {
    let count = 8 + rng.index(9);
    assert!(
        text.len() >= count * 12,
        "transport segment is too short to fragment"
    );
    let mut fragments = Vec::with_capacity(count);
    for ordinal in 1..=count {
        let start = text.len() * (ordinal - 1) / count;
        let end = text.len() * ordinal / count;
        let mut bytes = Vec::with_capacity(end - start + 1);
        bytes.push(alphabet[ordinal]);
        bytes.extend_from_slice(&text.as_bytes()[start..end]);
        fragments.push(lua_escape_string(&bytes));
    }
    rng.shuffle(&mut fragments);
    let mut literal = String::from("{");
    for (index, fragment) in fragments.iter().enumerate() {
        if index != 0 {
            literal.push(',');
        }
        literal.push('"');
        literal.push_str(fragment);
        literal.push('"');
    }
    literal.push('}');
    literal
}

fn generated_function_spans(
    source: &str,
    target: Target,
) -> Result<Vec<(usize, usize)>, Diagnostic> {
    let tokens = crate::lexer::lex(source, target)?;
    let mut stack: Vec<(&str, usize)> = Vec::new();
    let mut functions = Vec::new();
    for token in tokens
        .iter()
        .filter(|token| token.kind == crate::lexer::TokenKind::Keyword)
    {
        match token.text(source) {
            "do" => {
                if !matches!(
                    stack.last().map(|(word, _)| *word),
                    Some("for") | Some("while")
                ) {
                    stack.push(("do", token.span.start));
                }
            }
            "function" | "for" | "if" | "while" | "repeat" => {
                stack.push((token.text(source), token.span.start));
            }
            "end" | "until" => {
                let (opener, start) = stack
                    .pop()
                    .ok_or_else(|| Diagnostic::new("generated VM has an unbalanced closer"))?;
                let closer = token.text(source);
                if !((closer == "end" && opener != "repeat")
                    || (closer == "until" && opener == "repeat"))
                {
                    return Err(Diagnostic::new(
                        "generated VM has mismatched block delimiters",
                    ));
                }
                if opener == "function" {
                    functions.push((start, token.span.end));
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(Diagnostic::new("generated VM has unclosed blocks"));
    }
    Ok(functions)
}

/// Recover the three encoded streams from their Goal-7 fragment tables. The
/// grouping is lexical (innermost generated function); ordering comes from the
/// private alphabet marker carried by each fragment, not from source order.
/// This remains a static audit path, but deliberately requires structure and
/// per-segment alphabet recovery instead of selecting the three longest tokens.
pub(crate) fn segment_literals(
    source: &str,
    target: Target,
    seed: u64,
) -> Result<Vec<Vec<u8>>, Diagnostic> {
    let alphabets = base86_segment_alphabets(seed);
    let mut union = [false; 256];
    for alphabet in &alphabets {
        for &byte in alphabet {
            union[byte as usize] = true;
        }
    }
    let functions = generated_function_spans(source, target)?;
    let mut groups: BTreeMap<(usize, usize), Vec<Vec<u8>>> = BTreeMap::new();
    for token in crate::lexer::lex(source, target)? {
        if token.kind != crate::lexer::TokenKind::String {
            continue;
        }
        let value = crate::minify::literal_bytes(token.text(source), target)
            .map_err(|error| Diagnostic::new(format!("generated VM fragment: {error}")))?;
        if value.len() < 12 || !value.iter().all(|byte| union[*byte as usize]) {
            continue;
        }
        let owner = functions
            .iter()
            .filter(|(start, end)| *start < token.span.start && token.span.end < *end)
            .max_by_key(|(start, _)| *start);
        if let Some(&span) = owner {
            groups.entry(span).or_default().push(value);
        }
    }

    let mut segments = Vec::new();
    for fragments in groups.values().filter(|fragments| fragments.len() >= 2) {
        for alphabet in &alphabets {
            if fragments
                .iter()
                .any(|fragment| fragment.iter().any(|byte| !alphabet.contains(byte)))
            {
                continue;
            }
            let count = fragments.len();
            if count >= alphabet.len() {
                continue;
            }
            let mut ordered = vec![None; count];
            let mut valid = true;
            for fragment in fragments {
                let Some(ordinal) = alphabet.iter().position(|byte| *byte == fragment[0]) else {
                    valid = false;
                    break;
                };
                if ordinal == 0 || ordinal > count || ordered[ordinal - 1].is_some() {
                    valid = false;
                    break;
                }
                ordered[ordinal - 1] = Some(&fragment[1..]);
            }
            if valid && ordered.iter().all(Option::is_some) {
                segments.push(
                    ordered
                        .into_iter()
                        .flat_map(|fragment| fragment.unwrap().iter().copied())
                        .collect(),
                );
            }
        }
    }
    segments.sort();
    segments.dedup();
    if segments.len() != 3 {
        return Err(Diagnostic::new(format!(
            "generated VM has {} recoverable transport fragment chains, expected 3",
            segments.len()
        )));
    }
    Ok(segments)
}
