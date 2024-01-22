use std::usize;

use rand::random;

#[cfg(test)]
mod padding_tests {
    use super::*;
    #[test]
    fn asnix923_test() {
        let plaintext: [u8; 13] = [
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01,
        ];
        let paded_plaintext: Vec<u8> = standard_padding(&plaintext, 16, &PaddingMode::ASNIX923);
        assert_eq!(
            paded_plaintext,
            [
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x00,
                0x00, 0x03
            ]
        );
    }
    #[test]
    fn pkcs5_test() {
        let plaintext: [u8; 13] = [
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01,
        ];
        let paded_plaintext: Vec<u8> = standard_padding(&plaintext, 16, &PaddingMode::PKCS5);
        assert_eq!(
            paded_plaintext,
            [
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x03,
                0x03, 0x03
            ]
        );
    }
    #[test]
    fn isoiec7816_4_test() {
        let plaintext: [u8; 13] = [
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01,
        ];
        let paded_plaintext: Vec<u8> = standard_padding(&plaintext, 16, &PaddingMode::ISOIEC7816_4);
        assert_eq!(
            paded_plaintext,
            [
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x80,
                0x00, 0x00
            ]
        );
    }
    #[test]
    fn zeropadding_test() {
        let plaintext: [u8; 13] = [
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01,
        ];
        let paded_plaintext: Vec<u8> = standard_padding(&plaintext, 16, &PaddingMode::ZeroPadding);
        assert_eq!(
            paded_plaintext,
            [
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x00,
                0x00, 0x00
            ]
        );
    }
}

pub enum PaddingMode {
    NoPadding,
    ASNIX923,
    ISO10126,
    PKCS5,
    PKCS7,
    ISOIEC7816_4,
    ZeroPadding,
}

pub fn standard_padding(
    plaintext: &[u8],
    expected_len: usize,
    padding_mode: &PaddingMode,
) -> Vec<u8> {
    let mut paded_plaintext: Vec<u8> = plaintext.to_vec();
    let bytes_rem: usize = paded_plaintext.len() % expected_len;
    let bytes_to_pad: usize = if bytes_rem != 0 {
        expected_len - bytes_rem
    } else {
        0
    };

    match padding_mode {
        PaddingMode::NoPadding => {}
        PaddingMode::ASNIX923 => {
            for _ in 1..bytes_to_pad {
                paded_plaintext.push(0x00);
            }
            paded_plaintext.push(bytes_to_pad as u8);
        }
        PaddingMode::ISO10126 => {
            for _ in 1..bytes_to_pad {
                paded_plaintext.push(random::<u8>());
            }
            paded_plaintext.push(bytes_to_pad as u8);
        }
        PaddingMode::PKCS5 | PaddingMode::PKCS7 => {
            for _ in 0..bytes_to_pad {
                paded_plaintext.push(bytes_to_pad as u8);
            }
        }
        PaddingMode::ISOIEC7816_4 => {
            paded_plaintext.push(0x80);
            for _ in 1..bytes_to_pad {
                paded_plaintext.push(0x00);
            }
        }
        PaddingMode::ZeroPadding => {
            for _ in 0..bytes_to_pad {
                paded_plaintext.push(0x00);
            }
        }
    }
    paded_plaintext
}
