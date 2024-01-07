pub enum AesType {
    AES128,
    AES192,
    AES256,
}

mod aes_cfg;
use aes_cfg::*;

#[cfg(test)]
mod aes_tests {
    use super::*;
    #[test]
    fn aes_ecb_test() {
        let plain_text: String = String::from("SUNYSUNYSUNYSUNY");
        let aes_key = String::from("abcdabcdabcdabcd").into_bytes();

        let ciphered_bytes: Vec<u8> = aes_ecb_enc(&plain_text, &aes_key, AesType::AES128);

        let mut ciphered_hex_str: String = String::new();

        for byte in ciphered_bytes.clone() {
            ciphered_hex_str.push_str(&format!("{:02x}", byte))
        }

        assert_eq!(
            ciphered_hex_str,
            String::from("30e1afaf9c36e4814f2abfd05c76cf12")
        );

        let deciphered_bytes: Vec<u8> = aes_ecb_dec(&ciphered_bytes, &aes_key, AesType::AES128);

        let mut deciphered_str: String = String::new();

        println!("{:?}", deciphered_bytes);
        for byte in deciphered_bytes {
            deciphered_str.push(char::from(byte));
        }

        assert_eq!(deciphered_str, plain_text);
    }
    #[test]
    fn aes_cbc_test() {
        let plain_text: String = String::from("SUNYSUNYSUNYSUNY");
        let aes_key = String::from("abcdabcdabcdabcd").into_bytes();
        let iv = String::from("abcdabcdabcdabcd").into_bytes();
        print!(
            "{:?}",
            aes_cbc_enc(&plain_text, &aes_key, &iv, AesType::AES128)
        );
        assert_eq!(
            aes_cbc_enc(&plain_text, &aes_key, &iv, AesType::AES128),
            String::from("8131ea8c4597cfcfdc096a878e65d35b")
        );
    }
}

pub fn aes_ecb_enc(message: &str, key: &[u8], aes_type: AesType) -> Vec<u8> {
    let mut message_blocks: Vec<Vec<u8>> = Vec::new();

    let mut res: Vec<u8> = Vec::new();

    for chunk in message.as_bytes().chunks(16) {
        message_blocks.push(chunk.to_vec());
    }

    let expanded_key: Vec<u32> = key_expansion(key);

    for mut state in message_blocks {
        cipher(&mut state, &expanded_key, &aes_type);
        res.append(&mut state);
    }

    res
}

pub fn aes_ecb_dec(ciphered_bytes: &[u8], key: &[u8], aes_type: AesType) -> Vec<u8> {
    let mut blocks: Vec<Vec<u8>> = Vec::new();

    let mut res: Vec<u8> = Vec::new();

    for chunk in ciphered_bytes.chunks(16) {
        blocks.push(chunk.to_vec());
    }

    let expanded_key: Vec<u32> = key_expansion(key);

    for mut state in blocks {
        decipher(&mut state, &expanded_key, &aes_type);
        res.append(&mut state);
    }

    res
}

pub fn aes_cbc_enc(message: &str, key: &[u8], iv: &[u8], aes_type: AesType) -> String {
    let mut message_blocks: Vec<Vec<u8>> = Vec::new();

    for chunk in message.as_bytes().chunks(16) {
        message_blocks.push(chunk.to_vec());
    }

    let mut res: String = String::new();

    let mut blocks_iter = message_blocks.iter_mut();

    let mut state_first = blocks_iter.next().unwrap();
    for (i, byte) in iv.iter().enumerate() {
        state_first[i] ^= byte;
    }

    let key_bytes: Vec<u8> = Vec::from(key);

    let expanded_key: Vec<u32> = key_expansion(&key_bytes);

    cipher(&mut state_first, &expanded_key, &aes_type);

    for mut state in blocks_iter {
        cipher(&mut state, &expanded_key, &aes_type);
    }

    for state in message_blocks {
        for byte in state {
            res.push_str(&format!("{:02x}", byte))
        }
    }

    res
}

fn cipher(state: &mut [u8], expanded_key: &[u32], aes_type: &AesType) {
    let loop_num: usize = match aes_type {
        AesType::AES128 => 10,
        AesType::AES192 => 12,
        AesType::AES256 => 14,
    };

    add_round_key(state, &expanded_key[0..4]);

    // round
    for round in 1..loop_num {
        let round_key: &[u32] = &expanded_key[4 * round..(4 * round + 4)];

        byte_sub(state, &S_BOX);
        shift_rows(state);
        mix_cols(state, &MIX_COLS_MATRIX);
        add_round_key(state, round_key);
    }

    // final round
    byte_sub(state, &S_BOX);
    shift_rows(state);
    add_round_key(state, &expanded_key[40..44]);
}

fn decipher(state: &mut [u8], expanded_key: &[u32], aes_type: &AesType) {
    let round_num: usize = match aes_type {
        AesType::AES128 => 10,
        AesType::AES192 => 12,
        AesType::AES256 => 14,
    };

    add_round_key(state, &expanded_key[40..44]);

    let mut round = 0;
    // round
    while round < round_num - 1 {
        let round_key_group = round_num - 1 - round;
        let round_key: &[u32] = &expanded_key[(4 * round_key_group)..(4 * round_key_group + 4)];

        inv_shift_rows(state);
        byte_sub(state, &INV_S_BOX);
        add_round_key(state, round_key);
        mix_cols(state, &INV_MIX_COLS_MATRIX);

        round += 1;
    }

    // final round
    inv_shift_rows(state);
    byte_sub(state, &INV_S_BOX);
    add_round_key(state, &expanded_key[0..4]);
}

fn byte_sub(state: &mut [u8], s_box: &[u8]) {
    for byte in state {
        let row = (((*byte & 0xF0) >> 4) * 16) as usize;
        let col = (*byte & 0x0F) as usize;

        *byte = s_box[row..row + 16][col];
    }
}

fn t(word: u32, round: u8) -> u32 {
    let mut bytes = word.to_be_bytes();

    //byte cycle
    bytes.rotate_left(1);

    //byte sub
    byte_sub(&mut bytes, &S_BOX);

    u32::from_be_bytes(bytes) ^ RCON[round as usize]
}

fn key_expansion(key_bytes: &[u8]) -> Vec<u32> {
    let mut expanded_key: Vec<u32> = Vec::new();

    // convert key to u32
    for chunk in key_bytes.chunks(4) {
        expanded_key.push(u32::from_be_bytes(
            chunk.try_into().expect("Convert chunk to u32 failed!"),
        ));
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

        let row = 4 * i;

        // xor byte one by one
        state[row..(row + 4)][0] ^= key_bytes[0];
        state[row..(row + 4)][1] ^= key_bytes[1];
        state[row..(row + 4)][2] ^= key_bytes[2];
        state[row..(row + 4)][3] ^= key_bytes[3];
    }
}

fn shift_row_left(arr: &mut [u8]) {
    // left shift
    let first: u8 = arr[0];
    let iter = vec![0, 4, 8].into_iter();

    for col in iter {
        arr[col] = arr[col + 4];
    }

    arr[12] = first;
}

fn shift_row_right(arr: &mut [u8]) {
    // right shift
    let last: u8 = arr[12];
    let iter = vec![8, 4, 0].into_iter();

    for col in iter {
        arr[col + 4] = arr[col];
    }
    arr[0] = last;
}

fn shift_rows(state: &mut [u8]) {
    for row in 0..4 {
        for _ in 0..row {
            shift_row_left(&mut state[row..]);
        }
    }
}

fn inv_shift_rows(state: &mut [u8]) {
    for row in 0..4 {
        for _ in 0..row {
            shift_row_right(&mut state[row..]);
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
        0x01 => n2,
        0x02 => gf(n2),
        0x03 => gf(n2) ^ n2,
        0x09 => gf(gf(gf(n2))) ^ n2,
        0x0b => (gf(gf(gf(n2))) ^ n2) ^ gf(n2),
        0x0d => (gf(gf(gf(n2))) ^ gf(gf(n2))) ^ n2,
        0x0e => (gf(gf(gf(n2))) ^ gf(gf(n2))) ^ gf(n2),
        _ => 0,
    }
}

fn mix_cols(state: &mut [u8], mix_cols_matrix: &[[u8; 4]; 4]) {
    let state_old: Vec<u8> = state.to_vec();

    for i in 0..4 {
        for j in 0..4 {
            let col = 4 * j;

            state[col..(col + 4)][i] = gf_mul(mix_cols_matrix[i][0], state_old[col..(col + 4)][0])
                ^ gf_mul(mix_cols_matrix[i][1], state_old[col..(col + 4)][1])
                ^ gf_mul(mix_cols_matrix[i][2], state_old[col..(col + 4)][2])
                ^ gf_mul(mix_cols_matrix[i][3], state_old[col..(col + 4)][3]);
        }
    }
}
