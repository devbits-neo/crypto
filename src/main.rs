use crypto_lib::crypto::rsa::{BigNum, Rsa};

fn main() {
        let n1 = BigNum::new(String::from("1"));
        //let n2 = BigNum::new(String::from("11"));

        println!("n1: {:?}", n1-BigNum::new(String::from("987654321")));
        //let r = Rsa::new(n1 ,n2);
        //println!("Rsa: {:?}", r);

}
