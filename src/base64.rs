mod base64_cfg;

use crate::base64::base64_cfg::{BASE64_CONV_TABLE, PADDING_BYTE};
use std::collections::HashMap;

fn base64_enc(plain_text: &[u8]) -> Vec<u8> {
    let mut ciphered_text: Vec<u8> = Vec::new();

    for block in plain_text.chunks(3) {
        match block.len() {
            1 => {
                let first_index: usize = (block[0] >> 2) as usize;
                let second_index: usize = ((block[0] & 0x03) << 4) as usize;

                ciphered_text.push(BASE64_CONV_TABLE[first_index]);
                ciphered_text.push(BASE64_CONV_TABLE[second_index]);
                ciphered_text.push(PADDING_BYTE);
                ciphered_text.push(PADDING_BYTE);
            }

            2 => {
                let first_index: usize = (block[0] >> 2) as usize;
                let second_index: usize =
                    ((block[0] & 0x03) << 4 | (block[1] & 0xF0) >> 4) as usize;
                let third_index: usize = ((block[1] & 0x0F) << 4) as usize;

                ciphered_text.push(BASE64_CONV_TABLE[first_index]);
                ciphered_text.push(BASE64_CONV_TABLE[second_index]);
                ciphered_text.push(BASE64_CONV_TABLE[third_index]);
                ciphered_text.push(PADDING_BYTE);
            }

            _ => {
                let first_index: usize = (block[0] >> 2) as usize;
                let second_index: usize =
                    (((block[0] & 0x03) << 4) | (block[1] & 0xF0) >> 4) as usize;
                let third_index: usize =
                    (((block[1] & 0x0F) << 2) | (block[2] & 0xC0) >> 6) as usize;
                let fourth_index: usize = (block[2] & 0x3F) as usize;

                ciphered_text.push(BASE64_CONV_TABLE[first_index]);
                ciphered_text.push(BASE64_CONV_TABLE[second_index]);
                ciphered_text.push(BASE64_CONV_TABLE[third_index]);
                ciphered_text.push(BASE64_CONV_TABLE[fourth_index]);
            }
        }
    }

    ciphered_text
}

fn base64_dec(ciphered_text: &[u8]) -> Vec<u8> {
    let mut plain_text: Vec<u8> = Vec::new();
    let mut base64_rev_table: HashMap<u8, u8> = HashMap::new();
    for (i, byte) in BASE64_CONV_TABLE.iter().enumerate() {
        base64_rev_table.insert(*byte, i as u8);
    }

    for block in ciphered_text.chunks(4) {
        let mut bits_arr: Vec<u8> = Vec::new();
        for byte in block {
            if let Some(six_bits) = base64_rev_table.get(byte) {
                bits_arr.push(*six_bits);
            }
        }
        //6+2
        plain_text.push((bits_arr[0] << 2) | (bits_arr[1] >> 4));

        if block[2] == '=' as u8 {
            continue;
        }
        //4+4
        plain_text.push((bits_arr[1] << 4) | (bits_arr[2] >> 2));

        if block[3] == '=' as u8 {
            continue;
        }
        plain_text.push((bits_arr[2] << 6) | (bits_arr[3]));
    }
    plain_text
}

#[cfg(test)]
mod base64_tests {
    use super::*;
    #[test]
    fn base64_test() {
        let plain_text: String = String::from(
            "A language empowering everyone to build reliable and efficient software.",
        );
        let plain_text2: String = String::from(
            "A language empowering everyone to build reliable and efficient software. ",
        );
        let plain_text3: String = String::from(
            "A language empowering everyone to build reliable and efficient software.  ",
        );
        let cipered_text = base64_enc(plain_text.as_bytes());
        let cipered_text2 = base64_enc(plain_text2.as_bytes());
        let cipered_text3 = base64_enc(plain_text3.as_bytes());
        let mut base64_str: String = String::new();
        let mut base64_str2: String = String::new();
        let mut base64_str3: String = String::new();

        for byte in cipered_text.clone() {
            base64_str.push(char::from(byte));
        }
        for byte in cipered_text.clone() {
            base64_str2.push(char::from(byte));
        }
        for byte in cipered_text.clone() {
            base64_str3.push(char::from(byte));
        }
        assert_eq!(base64_str, String::from("QSBsYW5ndWFnZSBlbXBvd2VyaW5nIGV2ZXJ5b25lIHRvIGJ1aWxkIHJlbGlhYmxlIGFuZCBlZmZpY2llbnQgc29mdHdhcmUu"));
        assert_eq!(base64_str2, String::from("QSBsYW5ndWFnZSBlbXBvd2VyaW5nIGV2ZXJ5b25lIHRvIGJ1aWxkIHJlbGlhYmxlIGFuZCBlZmZpY2llbnQgc29mdHdhcmUu"));
        assert_eq!(base64_str3, String::from("QSBsYW5ndWFnZSBlbXBvd2VyaW5nIGV2ZXJ5b25lIHRvIGJ1aWxkIHJlbGlhYmxlIGFuZCBlZmZpY2llbnQgc29mdHdhcmUu"));

        let text_dec: Vec<u8> = base64_dec(&cipered_text);
        let text_dec2: Vec<u8> = base64_dec(&cipered_text2);
        let text_dec3: Vec<u8> = base64_dec(&cipered_text3);

        let mut str_dec: String = String::new();
        let mut str_dec2: String = String::new();
        let mut str_dec3: String = String::new();
        for byte in text_dec {
            str_dec.push(char::from(byte));
        }
        for byte in text_dec2 {
            str_dec2.push(char::from(byte));
        }
        for byte in text_dec3 {
            str_dec3.push(char::from(byte));
        }
        assert_eq!(str_dec, plain_text);
        assert_eq!(str_dec2, plain_text2);
        assert_eq!(str_dec3, plain_text3);
    }
}
