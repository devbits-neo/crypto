use num_bigint::{BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_integer::Integer;

#[cfg(test)]
mod rsa_tests {
    use super::*;
    #[test]
    fn rsa_test() {
        let r = Rsa::new();
        let msg = String::from("SUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNY");
        println!(
            "plaintext: {:?}\nlength: {}",
            msg.as_bytes(),
            msg.as_bytes().len()
        );
        let ciphertext = r.enc(&msg.as_bytes());
        let plaintext = r.dec(&ciphertext);

        println!("ciphertext: {:?}\nlength: {}", ciphertext, ciphertext.len());
        assert_eq!(msg.as_bytes(), plaintext,);
    }
}

#[derive(Debug)]
struct Key(BigUint, BigUint);

#[derive(Debug)]
pub struct Rsa {
    pri_key: Key,
    pub_key: Key,
}

impl Rsa {
    fn gen_prime_num() -> BigUint {
        let mut rng = rand::thread_rng();
        let mut big_uint: BigUint;
        loop {
            big_uint = rng.gen_biguint(32);

            if big_uint.clone() % 6.to_biguint().unwrap() != 1.to_biguint().unwrap()
                && big_uint.clone() % 6.to_biguint().unwrap() != 5.to_biguint().unwrap()
            {
                println!("inside");
                continue;
            }

            if big_uint.is_even() {
                println!("inside2");
                continue;
            }
            let root: BigUint = big_uint.sqrt();
            let mut factor: BigUint = 5.to_biguint().unwrap();
            let mut is_prime: bool = true;

            println!("big_uint: {:?}\nroot: {:?}\n\n", big_uint, root);
            loop {
                if (root.clone() % factor.clone()) == 0.to_biguint().unwrap()
                    || (root.clone() % (factor.clone() + 2u8).clone()) == 0.to_biguint().unwrap()
                {
                    is_prime = false;
                    break;
                } else {
                    factor += 6u8;
                }

                // println!("{:?}", factor);
                if factor > root {
                    break;
                }
            }

            if is_prime {
                break;
            }
        }
        big_uint
    }

    fn gen_key() -> (Key, Key) {
        let p: BigUint = Self::gen_prime_num();
        let q: BigUint = Self::gen_prime_num();
        let e: BigUint = BigUint::parse_bytes(b"5", 16).unwrap();

        let n = p.clone() * q.clone();
        let fi = (p.clone() - 1 as u8) * (q.clone() - 1 as u8);

        let res_gcd_ext = e
            .to_bigint()
            .expect("covert to bigint fail!")
            .extended_gcd(&fi.to_bigint().expect("covert to bigint fail!"));

        let mut d = res_gcd_ext.x;
        if d < 0.to_bigint().unwrap() {
            d = d + fi.to_bigint().unwrap();
        }
        (Key(d.to_biguint().unwrap(), n.clone()), Key(e, n))
    }

    pub fn new() -> Self {
        let (pri_key, pub_key) = Self::gen_key();
        Self { pri_key, pub_key }
    }
    pub fn enc(&self, msg: &[u8]) -> Vec<u8> {
        let mut cipher_text: Vec<u8> = Vec::new();
        let mut msg_blocks: Vec<Vec<u8>> = Vec::new();

        for chunk in msg.chunks(8) {
            msg_blocks.push(chunk.to_vec());
        }
        for block in msg_blocks {
            println!("{:?}", &block);
            let temp = BigUint::from_bytes_be(&block);

            let a = temp.modpow(&self.pri_key.0, &self.pri_key.1);
            cipher_text.append(&mut a.to_bytes_be());
        }
        cipher_text
    }
    pub fn dec(&self, cipher_text: &[u8]) -> Vec<u8> {
        let mut plain_text: Vec<u8> = Vec::new();
        let mut ctext_blocks: Vec<Vec<u8>> = Vec::new();

        for chunk in cipher_text.chunks(8) {
            ctext_blocks.push(chunk.to_vec());
        }
        for block in ctext_blocks {
            let temp = BigUint::from_bytes_be(&block);

            let a = temp.modpow(&self.pub_key.0, &self.pub_key.1);
            plain_text.append(&mut a.to_bytes_be());
        }
        plain_text
    }
}
