use std::collections::HashSet;
use std::time::SystemTime;
use rand::{rngs::StdRng, SeedableRng, Rng};

pub struct SimpleRng {
    rng: StdRng,
}

impl SimpleRng {
    pub fn new(seed: u32) -> Self {
        let seed_val = if seed == 0 {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        } else {
            let t = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            t ^ (seed as u64)
        };
        
        Self {
            rng: StdRng::seed_from_u64(seed_val),
        }
    }

    pub fn next(&mut self) -> u32 {
        self.rng.random()
    }

    pub fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max { return min; }
        self.rng.random_range(min..max)
    }
}

pub struct NamePool {
    rng: SimpleRng,
    used: HashSet<String>,
}

impl NamePool {
    pub fn new(seed: u32) -> Self {
        Self {
            rng: SimpleRng::new(seed),
            used: HashSet::new(),
        }
    }

    pub fn get(&mut self) -> String {
        let chars = ['I', 'l', '1'];
        loop {
            let len = self.rng.next_range(4, 9);
            let mut s = String::new();
            s.push(if self.rng.next() % 2 == 0 { 'I' } else { 'l' });
            for _ in 1..len {
                s.push(chars[self.rng.next_range(0, 3)]);
            }
            if self.used.insert(s.clone()) {
                return s;
            }
        }
    }

    pub fn rng_mut(&mut self) -> &mut SimpleRng {
        &mut self.rng
    }
}