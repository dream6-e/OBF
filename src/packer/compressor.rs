#[derive(Clone, Copy)]
pub enum Step {
    Raw,
    Link { stride: u16, span: u32 },
}

pub struct Compressor;

const MAX_SPAN: usize = 4096;

fn length_bytes(base: u32) -> u32 {
    base / 255 + 1
}

impl Compressor {
    pub fn compress(input: &[u8]) -> Vec<u8> {
        let len = input.len();
        if len == 0 {
            return Vec::new();
        }

        let mut costs = vec![u32::MAX; len + 1];
        let mut links = vec![Step::Raw; len + 1];
        costs[0] = 0;

        for i in 0..len {
            if costs[i] == u32::MAX {
                continue;
            }

            let cost_raw = costs[i] + 9;
            if cost_raw < costs[i + 1] {
                costs[i + 1] = cost_raw;
                links[i + 1] = Step::Raw;
            }

            let max_search = if i > 65535 { i - 65535 } else { 0 };
            let max_span = std::cmp::min(MAX_SPAN, len - i);

            let mut optimal_strides = vec![0u16; max_span + 1];
            let mut peak_span = 0;

            for start in max_search..i {
                if peak_span < max_span && input[start + peak_span] == input[i + peak_span] {
                    let mut current_span = 0;
                    while current_span < max_span && input[start + current_span] == input[i + current_span] {
                        current_span += 1;
                    }
                    if current_span > peak_span {
                        for l in (peak_span + 1)..=current_span {
                            optimal_strides[l] = (i - start) as u16;
                        }
                        peak_span = current_span;
                    }
                }
            }

            for span_l in 3..=peak_span {
                let base = (span_l - 3) as u32;
                let cost_link = costs[i] + 17 + 8 * length_bytes(base);
                let next_pos = i + span_l;
                if cost_link < costs[next_pos] {
                    costs[next_pos] = cost_link;
                    links[next_pos] = Step::Link {
                        stride: optimal_strides[span_l],
                        span: span_l as u32,
                    };
                }
            }
        }

        let mut route = Vec::new();
        let mut cursor = len;
        while cursor > 0 {
            match links[cursor] {
                Step::Raw => {
                    route.push(Step::Raw);
                    cursor -= 1;
                }
                Step::Link { stride, span } => {
                    route.push(Step::Link { stride, span });
                    cursor -= span as usize;
                }
            }
        }
        route.reverse();

        let mut output = Vec::new();
        let mut route_head = 0;
        let route_len = route.len();
        let mut read_head = 0;

        while route_head < route_len {
            let mut header = 0u8;
            let mut payload_part = Vec::new();

            for bit in 0..8 {
                if route_head >= route_len {
                    break;
                }

                match route[route_head] {
                    Step::Raw => {
                        header |= 1 << bit;
                        payload_part.push(input[read_head]);
                        read_head += 1;
                    }
                    Step::Link { stride, span } => {
                        let b1 = (stride >> 8) as u8;
                        let b2 = (stride & 0xFF) as u8;
                        payload_part.push(b1);
                        payload_part.push(b2);
                        let mut base = span - 3;
                        while base >= 255 {
                            payload_part.push(255);
                            base -= 255;
                        }
                        payload_part.push(base as u8);
                        read_head += span as usize;
                    }
                }
                route_head += 1;
            }

            output.push(header);
            output.extend_from_slice(&payload_part);
        }

        output
    }
}
