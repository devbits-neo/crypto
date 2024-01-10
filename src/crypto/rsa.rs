use num_bigint::{BigUint, ToBigInt};
use num_integer::Integer;
use num_primes::{BigUint as BigPrime, Generator, Verification};

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
    fn gen_prime() -> BigUint {
        let mut num: BigPrime;
        loop {
            num = Generator::safe_prime(256);
            if Verification::is_prime(&num) {
                break;
            }
        }
        BigUint::from_bytes_be(&num.to_bytes_be())
    }
    fn gen_key() -> (Key, Key) {
        let p: BigUint = Self::gen_prime();
        println!("{:?}", &p);
        let q: BigUint = Self::gen_prime();
        println!("{:?}", &q);
        let e: BigUint = BigUint::parse_bytes(b"10001", 16).unwrap();

        let n = p.clone() * q.clone();
        let fi = (p.clone() - 1 as u8) * (q.clone() - 1 as u8);

        let res_gcd_ext = e
            .to_bigint()
            .expect("covert to bigint failed!")
            .extended_gcd(&fi.to_bigint().expect("covert to bigint failed!"));

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

        for chunk in msg.chunks(64) {
            let temp = BigUint::from_bytes_be(&chunk.to_vec());

            let a = temp.modpow(&self.pri_key.0, &self.pri_key.1);
            cipher_text.append(&mut a.to_bytes_be());
        }
        cipher_text
    }
    pub fn dec(&self, cipher_text: &[u8]) -> Vec<u8> {
        let mut plain_text: Vec<u8> = Vec::new();

        for chunk in cipher_text.chunks(64) {
            let temp = BigUint::from_bytes_be(&chunk.to_vec());

            let a = temp.modpow(&self.pub_key.0, &self.pub_key.1);
            plain_text.append(&mut a.to_bytes_be());
        }
        plain_text
    }
}
