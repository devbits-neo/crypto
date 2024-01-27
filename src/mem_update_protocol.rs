use crate::aes::{aes_cbc_enc, AesType};
use crate::aes_mp::mp_compression;
use crate::cfg::mem_update_cfg::{KEY_UPDATE_ENC_C, KEY_UPDATE_MAC_C};
use crate::cmac::cmac;

#[derive(Debug, Clone, Copy)]
pub enum KeyFlag {
    WriteProtection = 0x10,
    BootProtection = 0x08,
    DebuggerProtection = 0x04,
    KeyUsage = 0x02,
    Wildcard = 0x01,
    FlagUnset = 0x00,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MemUpdate {
    k1: [u8; 16],
    k2: [u8; 16],
    k3: [u8; 16],
    k4: [u8; 16],
    m1: [u8; 16],
    m2: [u8; 32],
    m3: [u8; 16],
    m4: [u8; 32],
    m5: [u8; 16],
}

impl MemUpdate {
    pub fn new(
        key_auth: &[u8; 16],
        key_new: &[u8; 16],
        counter: u32,
        she_id: u8,
        auth_id: u8,
        uid: &[u8],
        key_flags: &[KeyFlag],
    ) -> Self {
        let k1: [u8; 16] = kdf(key_auth, &KEY_UPDATE_ENC_C[0..6]);
        let k2: [u8; 16] = kdf(key_auth, &KEY_UPDATE_MAC_C[0..6]);
        let k3: [u8; 16] = [0; 16];
        let k4: [u8; 16] = [0; 16];
        let mut m1: [u8; 16] = [0; 16];
        let iv: [u8; 16] = [0; 16];
        let mut m2_raw: [u8; 32] = [0; 32];

        for (i, byte) in uid.iter().enumerate() {
            m1[i] = *byte;
        }

        m1[15] = (she_id << 4) | (auth_id & 0x0F);

        let counter_bytes: [u8; 4] = (counter << 4).to_be_bytes();

        for (i, byte) in counter_bytes.iter().enumerate() {
            m2_raw[i] = *byte;
        }
        let mut flag_byte: u8 = 0x00;

        for flag in key_flags {
            flag_byte |= *flag as u8;
        }

        m2_raw[3] |= flag_byte >> 1;

        // last bit in key_flag and seven bits "0"
        m2_raw[4] = flag_byte << 7;

        // rest of 88 bits (95-7) "0" already been filled

        for (i, byte) in key_new.iter().enumerate() {
            m2_raw[i + 16] = *byte;
        }

        let m2: [u8; 32] = aes_cbc_enc(&m2_raw, &k1, &iv, &AesType::AES128)
            .try_into()
            .unwrap();
        let mut m3_raw: Vec<u8> = m1.to_vec();
        m3_raw.append(&mut m2.to_vec());
        let m3: [u8; 16] = cmac(&m3_raw, &k2, &AesType::AES128).try_into().unwrap();
        let m4: [u8; 32] = [0; 32];
        let m5: [u8; 16] = [0; 16];

        MemUpdate {
            k1,
            k2,
            k3,
            k4,
            m1,
            m2,
            m3,
            m4,
            m5,
        }
    }
}

fn kdf(k: &[u8], c: &[u8]) -> [u8; 16] {
    let mut msg: Vec<u8> = k.to_vec();
    msg.append(&mut c.to_vec());
    mp_compression(&msg)
}

#[cfg(test)]
mod mem_update_tests {
    use super::*;
    #[test]
    fn mem_update_test() {
        let key_new: [u8; 16] = [
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x01, 0x00,
        ];

        // let key_new: [u8; 16] = [
        //     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        //     0x0e, 0x0f,
        // ];
        let key_auth: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let uid: [u8; 15] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01,
        ];
        let she_id: u8 = 4;

        let auth_id: u8 = 1;
        let counter: u32 = 1;
        let key_flags: Vec<KeyFlag> = vec![KeyFlag::FlagUnset];

        let mem_update: MemUpdate = MemUpdate::new(
            &key_auth, &key_new, counter, she_id, auth_id, &uid, &key_flags,
        );
        println!("{:?}", &mem_update);

        dbg!(&mem_update);
    }
}
