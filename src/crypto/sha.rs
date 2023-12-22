pub enum ShaType {
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

pub fn sha(message: &str, sha_type: ShaType) -> String {
    let mut message_padding: Vec<u8> = Vec::from(message);

    let hash224_init_values = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];

    let hash256_init_values = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let hash384_init_values = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];

    let hash512_init_values = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let k_224_256: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let k_384_512: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    padding(&mut message_padding, &sha_type);
    let mut hash_str = String::new();
    match sha_type {
        ShaType::SHA224 => {
            let hash: [u32; 8] = iteration_64(&message_padding, &hash224_init_values, &k_224_256);
            for word in hash.into_iter().take(7) {
                hash_str.push_str(&format!("{:08x}", word))
            }
        }
        ShaType::SHA256 => {
            let hash: [u32; 8] = iteration_64(&message_padding, &hash256_init_values, &k_224_256);
            for word in hash {
                hash_str.push_str(&format!("{:08x}", word))
            }
        }
        ShaType::SHA384 => {
            let hash: [u64; 8] = iteration_80(&message_padding, &hash384_init_values, &k_384_512);
            for word in hash.into_iter().take(6) {
                hash_str.push_str(&format!("{:016x}", word))
            }
        }
        ShaType::SHA512 => {
            let hash: [u64; 8] = iteration_80(&message_padding, &hash512_init_values, &k_384_512);
            for word in hash {
                hash_str.push_str(&format!("{:016x}", word))
            }
        }
    };

    hash_str
}

fn padding(message: &mut Vec<u8>, sha_type: &ShaType) {
    let alignment: u32;
    let remainer_expect: u32;
    let message_bits = (message.len() as u32) * u8::BITS;
    let mut message_length: Vec<u8>;
    match sha_type {
        ShaType::SHA224 | ShaType::SHA256 => {
            alignment = 512;
            remainer_expect = 448;
            message_length = Vec::from((message_bits as u64).to_be_bytes());
        }
        ShaType::SHA384 | ShaType::SHA512 => {
            alignment = 1024;
            remainer_expect = 896;
            message_length = Vec::from((message_bits as u128).to_be_bytes());
        }
    };
    let remainer = message_bits % alignment;
    let bits_padding = if remainer == remainer_expect {
        alignment
    } else {
        if remainer > remainer_expect {
            alignment + remainer_expect - remainer
        } else {
            remainer_expect - remainer
        }
    };
    message.push(0x80);
    for _ in 1..(bits_padding as u32) / u8::BITS {
        message.push(0x00);
    }
    message.append(&mut message_length);
}

fn iteration_64(message_padding: &Vec<u8>, hash_init_values: &[u32; 8], k: &[u32; 64]) -> [u32; 8] {
    let mut w: [u32; 64] = [0; 64];
    let mut m: Vec<u32> = Vec::new();
    let mut hash = hash_init_values.clone();

    for chunk in message_padding.chunks(32 / 8) {
        m.push(u32::from_be_bytes(chunk.try_into().unwrap()));
    }

    // main loop
    for mi in 0..((m.len() * 32) / 512) {
        for i in 0..16 {
            w[i] = m[(mi * 16)..(mi * 16 + 16)][i];
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = s1 + w[i - 7] + s0 + w[i - 16];
        }

        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];

        for i in 0..64 {
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h + s1 + ch + k[i] + w[i];
            let t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
    hash
}

fn iteration_80(message_padding: &Vec<u8>, hash_init_values: &[u64; 8], k: &[u64; 80]) -> [u64; 8] {
    let mut w: [u64; 80] = [0; 80];
    let mut m: Vec<u64> = Vec::new();
    let mut hash = hash_init_values.clone();

    for chunk in message_padding.chunks(64 / 8) {
        m.push(u64::from_be_bytes(chunk.try_into().unwrap()));
    }

    // main loop
    for mi in 0..((m.len() * 64) / 1024) {
        for i in 0..16 {
            w[i] = m[(mi * 16)..(mi * 16 + 16)][i];
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = s1 + w[i - 16] + s0 + w[i - 7];
        }

        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];

        for i in 0..80 {
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h + s1 + ch + k[i] + w[i];
            let t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
    hash
}
#[cfg(test)]
mod hash_test {
    use super::{sha, ShaType};
    use std::{env, fs};
    #[test]
    fn hash() {
        let args: Vec<String> = env::args().collect();

        //let query = &args[2];
        let query = &String::from("sha256");
        //let file_path = &args[3];
        let file_path = &String::from("sunyue");

        let sha_type = match query.as_str() {
            "sha224" => ShaType::SHA224,
            "sha256" => ShaType::SHA256,
            "sha384" => ShaType::SHA384,
            "sha512" => ShaType::SHA512,
            _ => ShaType::SHA256,
        };
        let mut message =
            fs::read_to_string(file_path).expect("Should have been able to read the file");
        message.pop();
        assert_eq!(
            sha(&message, sha_type),
            String::from("9e83b875af66e8931e38b1edd29e51c8e4ed549b4fe1947f97daea138d5eb116")
        );
    }
}
