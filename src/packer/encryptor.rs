use std::time::SystemTime;
use super::utils::SimpleRng;

pub struct Encryptor;

impl Encryptor {
    pub fn xor_stream(input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0xDEADBEEF);
        let mut rng = SimpleRng::new(seed);
        let mut keys = Vec::new();
        for _ in 0..16 {
            keys.push((rng.next() & 0xFF) as u8);
        }
        let mut output = Vec::new();
        for (i, &b) in input.iter().enumerate() {
            output.push(b ^ keys[i % 16]);
        }
        (output, keys)
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