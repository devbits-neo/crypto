use crate::crypto::aes::{aes_ecb_enc, AesType};
#[cfg(test)]
mod cmac_tests {
    use super::*;
    #[test]
    fn cmac_aes_ecb_128_test() {
        let plaintext: Vec<u8> = String::from("SUNYSUNYSUNYSUNY").into_bytes();
        let key: [u8; 16] = 
            [ 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,0x01, 0x02, 0x03, 0x04];

        let cmac_bytes: Vec<u8> = cmac(&plaintext, &key, AesType::AES128);

        let mut cmac_str: String = String::new();

        for byte in cmac_bytes.clone() {
            cmac_str.push_str(&format!("{:02x}", byte))
        }


        assert_eq!(cmac_str, String::from("d8280d163fd468f32b293915e7bcc102"));
    }
}

fn cmac(plaintext: &[u8], key: &[u8], aes_type: AesType) -> Vec<u8> {
    let zero_128: [u8; 16] = [0; 16];
    let l: Vec<u8> = aes_ecb_enc(&zero_128, &key, aes_type);

    let l_u128: u128 = u128::from_be_bytes(l.try_into().unwrap());
    let k1: u128;
    if l_u128 & 0x80000000000000000000000000000000 == 0 {
        k1 = l_u128 << 1;
    } else {
        k1 = (l_u128 << 1) ^ 0x0000000000000000000087;
    }

    let _k2: u128;
    if k1 & 0x80000000000000000000000000000000 == 0 {
        _k2 = k1 << 1;
    } else {
        _k2 = (k1 << 1) ^ 0x0000000000000000000087;
    }

    let mut pre_block: u128 = 0;
    let mut res: Vec<u8> = Vec::new();

    let chunks = plaintext.chunks(16);
    let blocks_num = chunks.len();
    for (i, block) in chunks.into_iter().enumerate() {
        if block.len() == 16 {
            let m: u128;
            if i > 0 && i < blocks_num - 1 {
                m = pre_block ^ u128::from_be_bytes(block.try_into().unwrap());
            } else {
                m = pre_block ^ u128::from_be_bytes(block.try_into().unwrap()) ^ k1;
            }
            pre_block = u128::from_be_bytes(
                aes_ecb_enc(&m.to_be_bytes().to_vec(), &key, AesType::AES128)
                    .try_into()
                    .unwrap(),
            );

            res.append(&mut pre_block.to_be_bytes().to_vec());
        } else {
            //TODO: last block is not a complete block
        }
    }
    res
}
