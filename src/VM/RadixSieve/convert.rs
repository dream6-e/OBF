use rand::Rng;
use rand::seq::SliceRandom;
use rand::thread_rng;
use regex::Regex;

fn convert_number_complex(num_str: &str, num_type: usize, rng: &mut impl Rng) -> String {
    let num: i64 = match num_str.parse() {
        Ok(n) => n,
        Err(_) => return num_str.to_string(),
    };
    match num_type {
        0 => {
            let zeros = "0".repeat(rng.gen_range(1..3));
            format!("0x{}{:X}", zeros, num)
        }
        1 => {
            format!("0x{:X}", num)
        }
        2 => {
            let zeros = "0".repeat(rng.gen_range(3..5));
            format!("0x{}{:X}", zeros, num)
        }
        _ => num_str.to_string(),
    }
}

fn find_string_and_comment_ranges(code: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let bytes = code.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if i + 1 < len && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            let start = i;
            i += 2;

            let mut is_long_comment = false;
            if i < len && bytes[i] == b'[' {
                let mut eq_count = 0;
                let mut j = i + 1;
                while j < len && bytes[j] == b'=' {
                    eq_count += 1;
                    j += 1;
                }
                if j < len && bytes[j] == b'[' {
                    is_long_comment = true;
                    i = j + 1;
                    let mut closed = false;
                    while i < len {
                        if bytes[i] == b']' {
                            let mut k = i + 1;
                            let mut close_eq = 0;
                            while k < len && bytes[k] == b'=' {
                                close_eq += 1;
                                k += 1;
                            }
                            if k < len && bytes[k] == b']' && close_eq == eq_count {
                                ranges.push((start, k + 1));
                                i = k + 1;
                                closed = true;
                                break;
                            }
                        }
                        i += 1;
                    }
                    if !closed {
                        ranges.push((start, len));
                        i = len;
                    }
                }
            }

            if !is_long_comment {
                while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                    i += 1;
                }
                ranges.push((start, i));
            }
            continue;
        }

        if bytes[i] == b'[' {
            let start = i;
            let mut eq_count = 0;
            let mut j = i + 1;
            while j < len && bytes[j] == b'=' {
                eq_count += 1;
                j += 1;
            }
            if j < len && bytes[j] == b'[' {
                i = j + 1;
                let mut closed = false;
                while i < len {
                    if bytes[i] == b']' {
                        let mut k = i + 1;
                        let mut close_eq = 0;
                        while k < len && bytes[k] == b'=' {
                            close_eq += 1;
                            k += 1;
                        }
                        if k < len && bytes[k] == b']' && close_eq == eq_count {
                            ranges.push((start, k + 1));
                            i = k + 1;
                            closed = true;
                            break;
                        }
                    }
                    i += 1;
                }
                if !closed {
                    ranges.push((start, len));
                    i = len;
                }
                continue;
            }
        }

        let c = bytes[i];
        if c == b'\'' || c == b'"' {
            let quote = c;
            let start = i;
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == quote {
                    ranges.push((start, i + 1));
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }
    ranges
}

fn is_in_ranges(pos: usize, ranges: &[(usize, usize)]) -> bool {
    for &(start, end) in ranges {
        if pos >= start && pos < end {
            return true;
        }
    }
    false
}

pub fn apply_radix_sieve(code: &str, _version: Option<super::detect::LuaVersion>) -> Result<String, String> {
    let ignored_ranges = find_string_and_comment_ranges(code);
    let re = Regex::new(r"\b\d+\b").map_err(|e| e.to_string())?;
    
    let matches: Vec<_> = re.find_iter(code)
        .filter(|mat| {
            let start = mat.start();
            let end = mat.end();

            if is_in_ranges(start, &ignored_ranges) || is_in_ranges(end - 1, &ignored_ranges) {
                return false;
            }

            let bytes = code.as_bytes();
            let prev_ok = if start == 0 {
                true
            } else {
                let prev = bytes[start - 1];
                if prev == b'-' || prev == b'+' {
                    if start > 1 {
                        let prev2 = bytes[start - 2];
                        if prev2 == b'e' || prev2 == b'E' {
                            return false;
                        }
                    }
                    prev != b'.' && prev != b'_' && !prev.is_ascii_alphanumeric()
                } else {
                    prev != b'.' && prev != b'_' && !prev.is_ascii_alphanumeric()
                }
            };

            let next_ok = if end == bytes.len() {
                true
            } else {
                let next = bytes[end];
                next != b'.' && next != b'_' && !next.is_ascii_alphanumeric()
            };

            prev_ok && next_ok
        })
        .collect();

    if matches.is_empty() {
        return Ok(code.to_string());
    }

    let total = matches.len();
    let mut rng = thread_rng();

    let mut indices: Vec<usize> = (0..total).collect();
    indices.shuffle(&mut rng);

    let mut type_assignments = vec![None; total];
    let sample_size = (total as f64 * 0.40) as usize;

    for (i, &idx) in indices.iter().take(sample_size).enumerate() {
        type_assignments[idx] = Some(i % 3);
    }

    let mut replacements = Vec::new();

    for (idx, mat) in matches.iter().enumerate() {
        if let Some(num_type) = type_assignments[idx] {
            let new_str = convert_number_complex(mat.as_str(), num_type, &mut rng);
            replacements.push((mat.start(), mat.end(), new_str));
        }
    }

    replacements.sort_by_key(|(start, _, _)| *start);
    replacements.reverse();

    let mut result = code.to_string();
    for (start, end, new_str) in replacements {
        result.replace_range(start..end, &new_str);
    }
    Ok(result)
}
