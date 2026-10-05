use std::time::SystemTime;
use super::utils::SimpleRng;
use rand::Rng;

pub struct Encryptor;

impl Encryptor {
    /// Legacy stub stream: a project-specific two-state byte transform.
    /// The 16-byte material is expanded by the Lua stub into the same state,
    /// then each output byte feeds the following transition.
    pub fn custom_stream(input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        const MOD: u64 = 65_536;
        // Key material is sampled independently of the clock-seeded RNG used only
        // for the base122 alphabet below; encryption uses the custom state transform.
        let mut rng = rand::rng();
        let mut keys = Vec::with_capacity(16);
        for _ in 0..16 {
            keys.push(rng.random::<u8>());
        }

        let (mut a, mut b) = Self::initial_state(&keys);
        let mut prev = 0u64;
        let mut output = Vec::with_capacity(input.len());
        for (idx, &plain) in input.iter().enumerate() {
            let pos = idx as u64 + 1;
            let k1 = keys[idx % 16] as u64;
            let k2 = keys[(idx + 7) % 16] as u64;
            let p = pos % 256;
            let mask = (a % 256 + (b % 256) * 3 + p * 5 + prev * 7
                + k1 * 11 + k2 * 13 + ((a / 256) % 256) * 17
                + ((b / 256) % 256) * 19) % 256;
            let cipher = (plain as u64 + mask) % 256;
            let next_a = (a * (257 + k1) + b * 17 + pos * 1021
                + plain as u64 * 31 + cipher * 43 + k2 * 59 + prev * 73) % MOD;
            let next_b = (b * (263 + k2) + next_a * 19 + pos * 1237
                + cipher * 37 + plain as u64 * 47 + k1 * 61 + prev * 89) % MOD;
            output.push(cipher as u8);
            a = next_a;
            b = next_b;
            prev = cipher;
        }
        (output, keys)
    }

    fn initial_state(keys: &[u8]) -> (u64, u64) {
        let mut a = 0x4C31u64;
        let mut b = 0xA7D3u64;
        for i in 0..16 {
            let x = keys[i] as u64;
            let y = keys[15 - i] as u64;
            let pos = i as u64 + 1;
            a = (a * 257 + x + y * 3 + pos * 1237 + b * 5) % 65_536;
            b = (b * 263 + y + a * 7 + pos * 1321 + x * 11) % 65_536;
        }
        (a, b)
    }

    pub fn base122_encode(input: &[u8]) -> (String, [char; 85]) {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0x56781234);
        let mut rng = SimpleRng::new(seed);

        let mut alphabet_vec: Vec<char> = "!#$()*+,-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|"
            .chars()
            .collect();
        
        for i in (1..85).rev() {
            let j = rng.next_range(0, i + 1);
            alphabet_vec.swap(i, j);
        }

        let mut alphabet = ['\0'; 85];
        alphabet.copy_from_slice(&alphabet_vec);

        let mut padded = input.to_vec();
        while padded.len() % 4 != 0 {
            padded.push(0);
        }

        let mut out = String::with_capacity((padded.len() / 4) * 5);
        let mut i = 0;
        while i < padded.len() {
            let mut v = (padded[i] as u32)
                      | ((padded[i + 1] as u32) << 8)
                      | ((padded[i + 2] as u32) << 16)
                      | ((padded[i + 3] as u32) << 24);
            for _ in 0..5 {
                out.push(alphabet[(v % 85) as usize]);
                v /= 85;
            }
            i += 4;
        }
        (out, alphabet)
    }
}

#[cfg(test)]
mod custom_stream_tests {
    use super::Encryptor;

    #[test]
    fn byte_transform_round_trips() {
        const MOD: u64 = 65_536;
        let plain: Vec<u8> = (0..=255).chain(0..=255).collect();
        let (cipher, keys) = Encryptor::custom_stream(&plain);
        let (mut a, mut b) = Encryptor::initial_state(&keys);
        let mut prev = 0u64;
        let mut decoded = Vec::with_capacity(cipher.len());
        for (idx, &c) in cipher.iter().enumerate() {
            let pos = idx as u64 + 1;
            let k1 = keys[idx % 16] as u64;
            let k2 = keys[(idx + 7) % 16] as u64;
            let p = pos % 256;
            let mask = (a % 256 + (b % 256) * 3 + p * 5 + prev * 7
                + k1 * 11 + k2 * 13 + ((a / 256) % 256) * 17
                + ((b / 256) % 256) * 19) % 256;
            let plain = (c as u64 + 256 - mask) % 256;
            let next_a = (a * (257 + k1) + b * 17 + pos * 1021
                + plain * 31 + c as u64 * 43 + k2 * 59 + prev * 73) % MOD;
            let next_b = (b * (263 + k2) + next_a * 19 + pos * 1237
                + c as u64 * 37 + plain * 47 + k1 * 61 + prev * 89) % MOD;
            decoded.push(plain as u8);
            a = next_a;
            b = next_b;
            prev = c as u64;
        }
        assert_eq!(decoded, plain);
        assert_ne!(cipher, plain);
    }
}
