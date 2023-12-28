pub enum AesType {
    AES128,
    AES192,
    AES256,
}

#[cfg(test)]
mod aes_test {
    use super::{aes, AesType};
    #[test]
    fn aes128_test() {
        let plain_text: String = String::from("SUNYSUNYSUNYSUNY");
        let aes_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
            0x03, 0x04,
        ];
        //let aes_type = AesType::AES128;
        print!("{:?}", aes(&plain_text, &aes_key, AesType::AES128));
        // assert_eq!(
        //     aes(&plain_text, &aes_key, aes_type),
        //     String::from("U2FsdGVkX19VH7uYOh64K8U3bovtKCbdKTy/Cpgo6V2nCiEEwAAE39WiKnVldrMB")
        // );
    }
}

pub fn aes(message: &str, key: &[u8], aes_type: AesType) -> String {
    let mut message_blocks: Vec<Vec<u8>> = Vec::new();

    for chunk in message.as_bytes().chunks(16) {
        message_blocks.push(chunk.to_vec());
    }

    let mut res: String = String::new();

    let key_bytes: Vec<u8> = Vec::from(key);

    let expanded_key: Vec<u32> = key_expansion(&key_bytes);

    for mut state in message_blocks {
        cipher(&mut state, &expanded_key, &aes_type);
        for byte in state {
            res.push_str(&format!("{:02x}", byte))
        }
    }

    res
}

//fn round(state: 

fn cipher(state: &mut [u8], expanded_key: &[u32], aes_type: &AesType) {
    let loop_num: usize = match aes_type {
        AesType::AES128 => 10,
        AesType::AES192 => 12,
        AesType::AES256 => 14,
    };

    add_round_key(state, &expanded_key[0..4]);

    // from 1 to 9
    for round in 1..loop_num {

        let round_key: &[u32] = &expanded_key[4*round..(4*round+4)];

        byte_sub(state);
        shift_rows(state);
        mix_cols(state);
        add_round_key(state, round_key);

    }

    // tenth
    byte_sub(state);
    shift_rows(state);
    add_round_key(state, &expanded_key[40..44]);

}

fn byte_sub(state: &mut [u8]) {
    let s_box: [[u8; 16]; 16] = [
        [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ],
        [
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
            0x72, 0xc0,
        ],
        [
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8,
            0x31, 0x15,
        ],
        [
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27,
            0xb2, 0x75,
        ],
        [
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
            0x2f, 0x84,
        ],
        [
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c,
            0x58, 0xcf,
        ],
        [
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8,
        ],
        [
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2,
        ],
        [
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d,
            0x19, 0x73,
        ],
        [
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e,
            0x0b, 0xdb,
        ],
        [
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95,
            0xe4, 0x79,
        ],
        [
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
            0xae, 0x08,
        ],
        [
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd,
            0x8b, 0x8a,
        ],
        [
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1,
            0x1d, 0x9e,
        ],
        [
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
            0x28, 0xdf,
        ],
        [
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54,
            0xbb, 0x16,
        ],
        ];
        for byte in state {
            *byte = s_box[((*byte & 0xF0) >> 4) as usize][(*byte & 0x0F) as usize];
        }
}

fn t(word: u32, round: u8) -> u32 {
    let rcon: [u32; 10] = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1B000000, 0x36000000,
    ];

    //byte cycle
    let w = word.rotate_left(8);

    let mut bytes = w.to_be_bytes();

    //byte sub
    byte_sub(&mut bytes);

    u32::from_be_bytes(bytes) ^ rcon[round as usize]
}

fn key_expansion(key_bytes: &[u8]) -> Vec<u32> {
    let mut expanded_key: Vec<u32> =  Vec::new();

    // convert key to u32 array
    for chunk in key_bytes.chunks(4) {
        expanded_key.push(u32::from_be_bytes(chunk.try_into().unwrap()));
    }

    let mut round: u8 = 0;

    // compute rest of keys
    for i in 4..44 {
        if i % 4 != 0 {
            // if not a multiple of 4
            expanded_key.push(expanded_key[i - 4] ^ expanded_key[i - 1]);
        } else {
            // if is a multiple of 4
            expanded_key.push(expanded_key[i - 4] ^ t(expanded_key[i - 1], round));
            round += 1;
        }
    }
    expanded_key
}

fn add_round_key(state: &mut [u8], expanded_key: &[u32]) {
    for i in 0..4 {
        let key_bytes = expanded_key[i].to_be_bytes();

        let row = 4*i;

        // xor byte one by one
        state[row..(row+4)][0] ^= key_bytes[0];
        state[row..(row+4)][1] ^= key_bytes[1];
        state[row..(row+4)][2] ^= key_bytes[2];
        state[row..(row+4)][3] ^= key_bytes[3];

    }
}


fn shift_row(arr: &mut [u8]) {
    // left shift
    let byte: u8 = arr[0];
    arr[0] = arr[1];
    arr[1] = arr[2];
    arr[2] = arr[3];
    arr[3] = byte;
}

fn shift_rows(state: &mut [u8]) {
    for i in 0..4 {
        for _ in 0..i {
            shift_row(&mut state[4*i..(4*i+4)]);
        }
    }
}

fn gf_mul(n1: u8, n2: u8) -> u8 {
    let gf: &dyn Fn(u8) -> u8 = &|mut byte| {
        if (byte & 0x80) == 0 {
            byte << 1
        } else {
            byte <<= 1;
            byte ^ 0x1B
        }
    };
    match n1 {
        1 => n2,
        2 => gf(n2),
        3 => gf(n2) ^ n2,
        _ => 0,
    }
}

fn mix_cols(state: &mut [u8]) {
    let mix_cols_matrix: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    let state_old: Vec<u8> = state.to_vec();
    for i in 0..4 {
        for j in 0..4 {
            state[4*i..(4*i+4)][j] = gf_mul(mix_cols_matrix[i][0], state_old[0..4][j])
                ^ gf_mul(mix_cols_matrix[i][1], state_old[4..8][j])
                ^ gf_mul(mix_cols_matrix[i][2], state_old[8..12][j])
                ^ gf_mul(mix_cols_matrix[i][3], state_old[12..16][j]);
        }
    }
}
