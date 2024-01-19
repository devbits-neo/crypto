use crate::aes::{aes_ecb_enc, AesType};

#[cfg(test)]
mod cmac_tests {
    use super::*;
    #[test]
    fn cmac_aes_ecb_128_test() {
        let plaintext: Vec<u8> = String::from("SUNYSUNYSUNYSUNYJILQJILQJILQJILQ").into_bytes();
        // let plaintext: Vec<u8> = String::from("SUNYSUNYSUNYSUNY").into_bytes();
        // let plaintext: Vec<u8> = String::from("SUNY").into_bytes();
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

pub fn cmac(plaintext: &[u8], key: &[u8], aes_type: &AesType) -> Vec<u8> {
    let l: Vec<u8> = aes_ecb_enc(&[0; 16], key, aes_type);

    let l_u128: u128 = u128::from_be_bytes(l.try_into().unwrap());

    let k1: u128;

    if l_u128 & 0x80000000000000000000000000000000 == 0 {
        k1 = l_u128 << 1;
    } else {
        k1 = (l_u128 << 1) ^ 0x0000000000000000000087;
    }

    let k2: u128;
    if k1 & 0x80000000000000000000000000000000 == 0 {
        k2 = k1 << 1;
    } else {
        k2 = (k1 << 1) ^ 0x0000000000000000000087;
    }

    let mut ciphered_block: u128 = 0;
    let mut res: Vec<u8> = Vec::new();

    let blocks = plaintext.chunks(16);
    let blocks_num: usize = blocks.len();
    let bytes_num: usize = match aes_type {
        AesType::AES128 => 16, // 128 bits
        AesType::AES192 => 24, // 192 bits
        AesType::AES256 => 32, // 256 bits
    };

    for (i, block) in blocks.into_iter().enumerate() {
        if i < blocks_num - 1 {
            let m: u128;

            m = ciphered_block ^ u128::from_be_bytes(block.try_into().unwrap());

            ciphered_block = u128::from_be_bytes(
                aes_ecb_enc(&m.to_be_bytes().to_vec(), key, aes_type)
                    .try_into()
                    .unwrap(),
            );
        } else {
            let mut last_block: Vec<u8> = block.to_vec();
            let m: u128;

            if block.len() < 16 {
                //in case that it's not a complete block (128 bits)
                let bytes_to_pad: usize = bytes_num - block.len();
                last_block.push(0x80);
                for _ in 0..(bytes_to_pad - 1) {
                    last_block.push(0x00);
                }
                m = ciphered_block ^ u128::from_be_bytes(last_block.try_into().unwrap()) ^ k2;
            } else {
                //in case that it's a complete block (128 bits)
                m = ciphered_block ^ u128::from_be_bytes(last_block.try_into().unwrap()) ^ k1;
            }

            res = aes_ecb_enc(&m.to_be_bytes().to_vec(), key, aes_type);
        }
    }
    res
}
