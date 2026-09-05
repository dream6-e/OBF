pub struct Point3D {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

struct CoinPoint {
    pos: Point3D,
    ch: char,
    is_text: bool,
}

pub fn rotate_x(p: &Point3D, angle: f32) -> Point3D {
    let cos = angle.cos();
    let sin = angle.sin();
    Point3D {
        x: p.x,
        y: p.y * cos - p.z * sin,
        z: p.y * sin + p.z * cos,
    }
}

pub fn rotate_y(p: &Point3D, angle: f32) -> Point3D {
    let cos = angle.cos();
    let sin = angle.sin();
    Point3D {
        x: p.x * cos + p.z * sin,
        y: p.y,
        z: -p.x * sin + p.z * cos,
    }
}

pub fn rotate_z(p: &Point3D, angle: f32) -> Point3D {
    let cos = angle.cos();
    let sin = angle.sin();
    Point3D {
        x: p.x * cos - p.y * sin,
        y: p.x * sin + p.y * cos,
        z: p.z,
    }
}

pub fn project(p: &Point3D, width: usize, height: usize) -> (i32, i32) {
    let distance = 3.5;
    let base_scale = width as f32 * 0.40;
    let scale_x = base_scale;
    let scale_y = base_scale * 0.45;
    let z_depth = p.z + distance;
    let clamped_z = if z_depth < 0.1 { 0.1 } else { z_depth };

    let projected_x = (p.x / clamped_z) * scale_x + (width as f32 / 2.0);
    let projected_y = (p.y / clamped_z) * scale_y + (height as f32 / 2.0);

    (projected_x as i32, projected_y as i32)
}

fn is_pixel_on(row: usize, col: usize) -> bool {
    if row >= 5 || col >= 35 { return false; }
    let letter_idx = col / 6;
    let col_in_letter = col % 6;
    if col_in_letter == 5 { return false; }

    let mask = match letter_idx {
        0 => [0b10001, 0b10010, 0b11100, 0b10010, 0b10001][row],
        1 => [0b11110, 0b10001, 0b11110, 0b10010, 0b10001][row],
        2 => [0b10001, 0b01010, 0b00100, 0b00100, 0b00100][row],
        3 => [0b10001, 0b10001, 0b01010, 0b01010, 0b00100][row],
        4 => [0b11111, 0b10000, 0b11110, 0b10000, 0b11111][row],
        5 => [0b10001, 0b01010, 0b00100, 0b01010, 0b10001][row],
        _ => 0,
    };
    let bit_pos = 4 - col_in_letter;
    ((mask >> bit_pos) & 1) == 1
}

fn is_pixel_on_back(row: usize, col: usize) -> bool {
    if row >= 5 || col >= 11 { return false; }
    let letter_idx = col / 6;
    let col_in_letter = col % 6;
    if col_in_letter == 5 { return false; }

    let mask = match letter_idx {
        0 => [0b01110, 0b10001, 0b10001, 0b10001, 0b01110][row],
        1 => [0b11110, 0b10001, 0b11110, 0b10001, 0b11110][row],
        _ => 0,
    };
    let bit_pos = 4 - col_in_letter;
    ((mask >> bit_pos) & 1) == 1
}

pub struct Coin3D {
    points: Vec<CoinPoint>,
}

impl Coin3D {
    pub fn new() -> Self {
        let mut points = Vec::new();
        let radius = 1.1;
        let thickness = 0.18;
        let radial_steps = 18;

        for r_step in 1..=radial_steps {
            let r = (r_step as f32 / radial_steps as f32) * radius;
            let segments = (r * 110.0) as usize;
            for s in 0..segments {
                let theta = (s as f32 / segments as f32) * 2.0 * std::f32::consts::PI;
                let x = r * theta.cos();
                let y = r * theta.sin();

                let mut is_text = false;
                let mut ch = if r_step == radial_steps {
                    '#'
                } else if r_step == radial_steps - 1 {
                    '*'
                } else {
                    '.'
                };

                let x_min = -0.75;
                let x_max = 0.75;
                let y_min = -0.16;
                let y_max = 0.16;
                if x >= x_min && x <= x_max && y >= y_min && y <= y_max {
                    let u = (x - x_min) / (x_max - x_min);
                    let v = (y - y_min) / (y_max - y_min);
                    let col_idx = ((u * 35.0) as usize).min(34);
                    let row_idx = ((v * 5.0) as usize).min(4);
                    if is_pixel_on(row_idx, col_idx) {
                        let text_str = "KRYVEX";
                        let letter_idx = col_idx / 6;
                        if letter_idx < text_str.len() {
                            ch = text_str.chars().nth(letter_idx).unwrap();
                            is_text = true;
                        }
                    }
                }

                points.push(CoinPoint {
                    pos: Point3D { x, y, z: -thickness / 2.0 },
                    ch,
                    is_text,
                });
            }
        }

        for r_step in 1..=radial_steps {
            let r = (r_step as f32 / radial_steps as f32) * radius;
            let segments = (r * 110.0) as usize;
            for s in 0..segments {
                let theta = (s as f32 / segments as f32) * 2.0 * std::f32::consts::PI;
                let x = r * theta.cos();
                let y = r * theta.sin();

                let mut is_text = false;
                let mut ch = if r_step == radial_steps {
                    '#'
                } else if r_step == radial_steps - 1 {
                    '*'
                } else {
                    '+'
                };

                let x_min = -0.35;
                let x_max = 0.35;
                let y_min = -0.16;
                let y_max = 0.16;
                if x >= x_min && x <= x_max && y >= y_min && y <= y_max {
                    let u = (x - x_min) / (x_max - x_min);
                    let v = (y - y_min) / (y_max - y_min);
                    let col_idx = ((u * 11.0) as usize).min(10);
                    let row_idx = ((v * 5.0) as usize).min(4);
                    if is_pixel_on_back(row_idx, col_idx) {
                        let text_str = "OB";
                        let letter_idx = col_idx / 6;
                        if letter_idx < text_str.len() {
                            ch = text_str.chars().nth(letter_idx).unwrap();
                            is_text = true;
                        }
                    }
                }

                points.push(CoinPoint {
                    pos: Point3D { x, y, z: thickness / 2.0 },
                    ch,
                    is_text,
                });
            }
        }

        let edge_steps = 144;
        let thickness_slices = 4;
        for s in 0..edge_steps {
            let theta = (s as f32 / edge_steps as f32) * 2.0 * std::f32::consts::PI;
            let x = radius * theta.cos();
            let y = radius * theta.sin();

            let edge_ch = if s % 2 == 0 { '|' } else { '=' };

            for t_slice in 0..thickness_slices {
                let t_frac = t_slice as f32 / (thickness_slices - 1) as f32;
                let z = -thickness / 2.0 + t_frac * thickness;
                points.push(CoinPoint {
                    pos: Point3D { x, y, z },
                    ch: edge_ch,
                    is_text: false,
                });
            }
        }

        Coin3D { points }
    }

    pub fn render_frame(&self, angle_x: f32, angle_y: f32, angle_z: f32, width: usize, height: usize) -> String {
        let mut buffer = vec![vec![(" ".to_string(), 99.0); width]; height];

        for cp in &self.points {
            let rx = rotate_x(&cp.pos, angle_x);
            let ry = rotate_y(&rx, angle_y);
            let rz = rotate_z(&ry, angle_z);

            let (px, py) = project(&rz, width, height);
            if px >= 0 && px < width as i32 && py >= 0 && py < height as i32 {
                let current_depth = buffer[py as usize][px as usize].1;
                if rz.z < current_depth {
                    let styled_ch = if cp.is_text {
                        format!("\x1b[1;31m{}\x1b[0m", cp.ch)
                    } else if rz.z < -0.3 {
                        format!("\x1b[1;36m{}\x1b[0m", cp.ch)
                    } else if rz.z <= 0.3 {
                        format!("\x1b[0;36m{}\x1b[0m", cp.ch)
                    } else {
                        format!("\x1b[90m{}\x1b[0m", cp.ch)
                    };
                    buffer[py as usize][px as usize] = (styled_ch, rz.z);
                }
            }
        }

        let mut frame_data = String::new();
        for row in &buffer {
            let mut line = String::new();
            for cell in row {
                line.push_str(&cell.0);
            }
            frame_data.push_str(&format!("      {}\x1b[K\r\n", line));
        }
        frame_data
    }
}