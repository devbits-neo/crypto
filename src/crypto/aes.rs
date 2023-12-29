pub enum AesType {
    AES128,
    AES192,
    AES256,
}

mod aes_cfg;
use aes_cfg::*;

#[cfg(test)]
mod aes_ecb_test {
    use super::*;
    #[test]
    fn aes128_test() {
        let plain_text: String = String::from("SUNYSUNYSUNYSUNY");
        let aes_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
            0x03, 0x04,
        ];
        //let aes_type = AesType::AES128;
        print!("{:?}", aes_ecb(&plain_text, &aes_key, AesType::AES128));
        // assert_eq!(
        //     aes(&plain_text, &aes_key, aes_type),
        //     String::from("U2FsdGVkX19VH7uYOh64K8U3bovtKCbdKTy/Cpgo6V2nCiEEwAAE39WiKnVldrMB")
        // );
    }
}

pub fn aes_ecb(message: &str, key: &[u8], aes_type: AesType) -> String {
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
    for byte in state {
        *byte = S_BOX[((*byte & 0xF0) >> 4) as usize][(*byte & 0x0F) as usize];
    }
}

fn t(word: u32, round: u8) -> u32 {
    //byte cycle
    let w = word.rotate_left(8);

    let mut bytes = w.to_be_bytes();

    //byte sub
    byte_sub(&mut bytes);

    u32::from_be_bytes(bytes) ^ RCON[round as usize]
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
            let row = 4*i;
            shift_row(&mut state[row..(row+4)]);
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
    let state_old: Vec<u8> = state.to_vec();
    for i in 0..4 {
        for j in 0..4 {

            let row = 4*i;

            state[row..(row+4)][j] = gf_mul(MIX_COLS_MATRIX[i][0], state_old[0..4][j])
                ^ gf_mul(MIX_COLS_MATRIX[i][1], state_old[4..8][j])
                ^ gf_mul(MIX_COLS_MATRIX[i][2], state_old[8..12][j])
                ^ gf_mul(MIX_COLS_MATRIX[i][3], state_old[12..16][j]);
        }
    }
}
