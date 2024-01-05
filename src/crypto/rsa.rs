use num_bigint::{BigUint, ToBigInt};
use num_integer::Integer;

#[cfg(test)]
mod rsa_tests {
    use super::*;
    #[test]
    fn rsa_test() {
        let r = Rsa::new();
        let msg = String::from("SUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNYSUNY");
        println!("plaintext: {:?}\n", msg.as_bytes());
        let ciphertext = r.enc(&msg.as_bytes());
        let plaintext = r.dec(&ciphertext);

        assert_eq!(
             msg.as_bytes(),
             plaintext,
        );
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

    //fn gen_key(p: BigNum, q: BigNum) -> Rsa {

    //}

    pub fn new() -> Rsa{
        let p: BigUint = BigUint::parse_bytes(b"106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169", 10).unwrap();
        let q: BigUint = BigUint::parse_bytes(b"144819424465842307806353672547344125290716753535239658417883828941232509622838692761917211806963011168822281666033695157426515864265527046213326145174398018859056439431422867957079149967592078894410082695714160599647180947207504108618794637872261572262805565517756922288320779308895819726074229154002310375209", 10).unwrap();
        let e: BigUint = BigUint::parse_bytes(b"10001", 16).unwrap();

        let n = p.clone() * q.clone();
        let fi = (p.clone() - 1 as u8)*(q.clone() - 1 as u8); 

        let res_gcd_ext = e.to_bigint().expect("covert to bigint fail!").extended_gcd(&fi.to_bigint().expect("covert to bigint fail!"));

        let mut d = res_gcd_ext.x;
        if d < 0.to_bigint().unwrap() {
            d = d + fi.to_bigint().unwrap();
        }
        Rsa {
            pri_key: Key(d.to_biguint().unwrap(), n.clone()),
            pub_key: Key(e, n)
        }

    }
    pub fn enc(&self, msg: &[u8]) -> Vec<u8> {
        let mut cipher_text: Vec<u8> = Vec::new();
        let mut msg_blocks: Vec<Vec<u8>> = Vec::new();

        for chunk in msg.chunks(256) {
            msg_blocks.push(chunk.to_vec());
        }
        for block in msg_blocks {
            let temp = BigUint::from_bytes_be(&block);
            
            let a = temp.modpow(&self.pri_key.0, &self.pri_key.1);
            cipher_text.append(&mut a.to_bytes_be());
        }
        cipher_text
    }
    pub fn dec(&self, cipher_text: &[u8]) -> Vec<u8> {
        let mut plain_text: Vec<u8> = Vec::new();
        let mut ctext_blocks: Vec<Vec<u8>> = Vec::new();

        for chunk in cipher_text.chunks(256) {
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

