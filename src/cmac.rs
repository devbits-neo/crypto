use crate::aes::{aes_ecb_enc, AesType};

#[cfg(test)]
mod cmac_tests {
    use super::*;
    #[test]
    fn cmac_aes_ecb_128_test() {
        // let plaintext: Vec<u8> = String::from("SUNYSUNYSUNYSUNYJILQJILQJILQJILQ").into_bytes();
        let plaintext: Vec<u8> = String::from("SUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNY").into_bytes();
        // let plaintext: Vec<u8> = String::from("SUNYSUNYSUNYSUNY").into_bytes();
        // let plaintext: Vec<u8> = String::from("SUNY").into_bytes();
        // let plaintext: Vec<u8> = String::from("SUNYSUNYSUNYSUNYJILQ").into_bytes();
        let key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
            0x03, 0x04,
        ];
        let aes_type: AesType = AesType::AES128;

        let cmac_bytes: Vec<u8> = cmac(&plaintext, &key, &aes_type);

        let mut cmac_str: String = String::new();

        for byte in cmac_bytes.clone() {
            cmac_str.push_str(&format!("{:02x}", byte))
        }

        assert_eq!(cmac_str, String::from("a0ec1cca5c501df17cc71ce05cac82c6"));
    }
}

fn bytes_xor(arr1: &[u8], arr2: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = arr1.to_vec();
    for i in 0..arr1.len() {
        output[i] = arr1[i] ^ arr2[i];
    }
    output
}

fn bytes_left_shfit(input: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = input.to_vec();
    let mut overflow: u8 = 0;
    let mut _temp: u8 = 0;

    for i in (0..input.len()).rev() {
        _temp = input[i] << 1;
        _temp |= overflow;
        overflow = if input[i] & 0x80 == 0x80 { 0x01 } else { 0x00 };
        output[i] = _temp;
    }
    output
}

pub fn cmac(plaintext: &[u8], key: &[u8], aes_type: &AesType) -> Vec<u8> {
    let l: Vec<u8> = aes_ecb_enc(&[0; 16], key, aes_type);

    let const_rb: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x87,
    ];

    let _k1: Vec<u8> = if l[0] & 0x80 == 0x00 {
        bytes_left_shfit(&l)
    } else {
        bytes_xor(&bytes_left_shfit(&l), &const_rb)
    };

    let _k2: Vec<u8> = if l[0] & 0x80 == 0x00 {
        bytes_left_shfit(&_k1)
    } else {
        bytes_xor(&bytes_left_shfit(&_k1), &const_rb)
    };

    let mut ciphered_block: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let mut mac: Vec<u8> = Vec::new();
    let blocks = plaintext.chunks(16);
    let blocks_num: usize = blocks.len();
    let bytes_num: usize = match aes_type {
        AesType::AES128 => 16, // 128 bits
        AesType::AES192 => 24, // 192 bits
        AesType::AES256 => 32, // 256 bits
    };

    for (i, block) in blocks.into_iter().enumerate() {
        let mut _m: Vec<u8> = Vec::new();
        if i < blocks_num - 1 {
            _m = bytes_xor(&ciphered_block, block);
            ciphered_block = aes_ecb_enc(&_m, key, aes_type);
        } else {
            let mut last_block: Vec<u8> = block.to_vec();

            if block.len() < 16 {
                //in case that it's not a complete block (128 bits)
                let bytes_to_pad: usize = bytes_num - block.len();
                last_block.push(0x80);
                for _ in 0..(bytes_to_pad - 1) {
                    last_block.push(0x00);
                }
                _m = bytes_xor(&bytes_xor(&_k2, &last_block), &ciphered_block);
            } else {
                println!("ciphered_block: {:?}", &ciphered_block);
                //in case that it's a complete block (128 bits)
                _m = bytes_xor(&bytes_xor(&_k1, &last_block), &ciphered_block);
            }
            mac = aes_ecb_enc(&_m, key, aes_type);
        }
    }
    mac
}
