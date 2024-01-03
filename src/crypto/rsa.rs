use num_bigint::{BigUint, BigInt};

#[cfg(test)]
mod rsa_tests {
    use super::*;
    #[test]
    fn rsa_test() {
        //let plain_text: String = String::from("SUNYSUNYSUNYSUNY");
        //let rsa_key = String::from("abcdabcdabcdabcd").into_bytes();
        //let n1 = BigNum::new(String::from("106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169"));
        //let n2 = BigNum::new(String::from("144819424465842307806353672547344125290716753535239658417883828941232509622838692761917211806963011168822281666033695157426515864265527046213326145174398018859056439431422867957079149967592078894410082695714160599647180947207504108618794637872261572262805565517756922288320779308895819726074229154002310375209"));

        //let r = Rsa::new(n1 ,n2);
        //println!("Rsa: {:?}", r);


        //assert_eq!(
        //     rsa_enc(&plain_text, &aes_key, AesType::AES128),
        //     String::from("30e1afaf9c36e4814f2abfd05c76cf12")
        //);
    }
}

#[derive(Debug)]
struct Key(String, String);


#[derive(Debug)]
pub struct Rsa {
    pri_key: Key,
    pub_key: Key,
}


impl Rsa {

    //fn gen_key(p: BigNum, q: BigNum) -> Rsa {

   //}

    //pub fn new(p: BigNum, q: BigNum) -> Rsa{
    //}
   // fn enc(byte: u8, e: &[u8], n: u32) -> u8 {
   // }
}

//fn gcd_ext(a: BigNum, b: BigNum, x: &mut BigNum, y: &mut BigNum) ->  BigNum {
//}

fn rem_fast(plaintext: u8, e: u32, n: BigUint) -> u32 {

    let mut d: u8 = 1;



    let mut shift = 0x80000000;
    while shift > 0 {
        d = (d*d)%n;
        if shift&byte != 0 {
            d = (d*plaintext)%n;
        }
        shift >>= 1;
        println!("{}, {}, {}", d, shift, shift&byte );
    }    

    d
}

