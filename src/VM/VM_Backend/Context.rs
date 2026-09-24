use rand::Rng;
use rand::seq::SliceRandom;

pub struct VmContext {
    pub seed: u64,
    pub lcg_a: u64,
    pub lcg_c: u64,
    pub lcg_m: u64,
    pub opcode_map: [u8; 90],
    pub state_sequence: Vec<usize>,
    pub xor_keys: [u8; 4],
}

impl VmContext {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let seed: u64 = rng.random();

        let lcg_a = rng.random_range(10000..60000);
        let lcg_c = rng.random_range(10000..110000);
        let lcg_m = rng.random_range(100000000..1100000000);

        let mut opcode_map = [0u8; 90];
        for i in 0..90 {
            opcode_map[i] = i as u8;
        }

        (&mut opcode_map[..]).shuffle(&mut rng);

        let mut state_sequence = Vec::new();
        for _ in 0..20 {
            state_sequence.push(rng.random_range(0..10000));
        }

        let xor_keys: [u8; 4] = rng.random();

        Self {
            seed,
            lcg_a,
            lcg_c,
            lcg_m,
            opcode_map,
            state_sequence,
            xor_keys,
        }
    }
}