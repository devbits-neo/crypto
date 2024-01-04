use crypto_lib::crypto::rsa::Rsa;
use num_bigint::{BigUint, BigInt, RandBigInt};
fn main() {
        let r = Rsa::new();
        println!("r: {:?}", r);
        let msg = vec![11,21,31,41];
        let ctext = r.enc(&msg);
        println!("r: {:?}", ctext);

}
