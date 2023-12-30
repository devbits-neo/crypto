use std::ops::{Add, Sub, Mul, Div};


#[cfg(test)]
mod rsa_tests {
    use super::*;
    #[test]
    fn rsa_test() {
        //let plain_text: String = String::from("SUNYSUNYSUNYSUNY");
        //let rsa_key = String::from("abcdabcdabcdabcd").into_bytes();
        let n1 = BigNum(String::from("ab"));
        let n2 = BigNum(String::from("cc"));

        let n3 = n1*n2;
        println!("{:?}", n3);

        //assert_eq!(
        //     rsa_enc(&plain_text, &aes_key, AesType::AES128),
        //     String::from("30e1afaf9c36e4814f2abfd05c76cf12")
        //);
    }
}

//struct Key(String, String)
#[derive(Debug, Clone)]
struct BigNum(String);

impl BigNum {
    fn is_zero(&self) -> bool {
        let mut iter = self.0.chars();
        let mut is_zero: bool = true;
        while let Some(c) = iter.next() {
            
                println!("c: {c}");
            if let Some(n) = c.to_digit(16) {
                if n!= 0 {
                    is_zero = false;
                    break;
                }
            }
        }
        is_zero
    }
}

impl Add for BigNum {

    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let mut res: String = String::new();

        let mut iter_lhs = self.0.chars();
        let mut iter_rhs = rhs.0.chars();

        let mut digits_lhs: Vec<u32> = Vec::new();
        let mut digits_rhs: Vec<u32> = Vec::new();
        let mut digits_sum: Vec<u32> = Vec::new();

        while let Some(c) = iter_lhs.next() {
            if let Some(n) = c.to_digit(16) {
                digits_lhs.push(n);         
            }
        }
        while let Some(c) = iter_rhs.next() {
            if let Some(n) = c.to_digit(16) {
                digits_rhs.push(n);         
            }
        }

        let mut carry = 0;

        loop {
            let mut n1 = 0;
            let mut n2 = 0;

            if let Some(x) = digits_lhs.pop() {
                n1 = x; 
            }
            if let Some(x) = digits_rhs.pop() {
                n2 = x;
            }

            let mut sum = n1 * n2 + carry;

            if sum > 15 {
                carry = sum / 16;
                sum %= 16;
            } else {
                carry = 0;
            }

            digits_sum.push(sum);

            if digits_lhs.is_empty() && digits_rhs.is_empty() && carry == 0 {
                break;
            }
        }

        for n in digits_sum.into_iter().rev() {
            if let Some(hex) =  char::from_digit(n, 16) {
                res.push(hex);
            }
        }
        BigNum(res)
    }
} 
impl Sub for BigNum {

    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let mut res: String = String::new();

        let mut iter_lhs = self.0.chars();
        let mut iter_rhs = rhs.0.chars();

        let mut digits_lhs: Vec<u32> = Vec::new();
        let mut digits_rhs: Vec<u32> = Vec::new();
        let mut digits_sum: Vec<u32> = Vec::new();

        while let Some(c) = iter_lhs.next() {
            if let Some(n) = c.to_digit(16) {
                digits_lhs.push(n);         
            }
        }
        while let Some(c) = iter_rhs.next() {
            if let Some(n) = c.to_digit(16) {
                digits_rhs.push(n);         
            }
        }

        let mut borrow = 0;

        loop {
            let mut n1 = 0;
            let mut n2 = 0;

            if let Some(x) = digits_lhs.pop() {
                n1 = x; 
            }
            if let Some(x) = digits_rhs.pop() {
                n2 = x;
            }

            let mut sum: i32 = n1 as i32 - n2 as i32 - borrow;

            if sum > 0 {
                borrow = 0;
                                
            } else {
                sum = sum.abs();
                borrow = 1;
            }

            digits_sum.push(sum as u32);

            if digits_lhs.is_empty() && digits_rhs.is_empty() {
                break;
            }
        }

        for n in digits_sum.into_iter().rev() {
            if let Some(hex) =  char::from_digit(n, 16) {
                res.push(hex);
            }
        }
        BigNum(res)
    }
} 



impl Mul for BigNum {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        
        let mut product = self.clone(); 
        let mut multiplier = rhs.clone();
        //while !multiplier.is_zero() {
            //product = product.clone() + product;
            println!("{:?}", multiplier);
            multiplier = multiplier - BigNum(String::from("cc"));
            println!("{:?}", multiplier);
        //}
        product 
    }
}
//struct Rsa {
//    pri_key: Key,
//    pub_key: Key,
//}


//impl Rsa {
//    pub fn gen_key(&self) {

//    }

//    fn enc(byte: u8, e: &[u8], n: u32) -> u8 {
//        let d: usize = 1;

//        for b in e {
//            let mut shift = 0x80;

//            while shift > 0 {
//                d = (d*d)%n;
//                if shift&b == 1 {
//                    d = (d*a)%n;
//                }
//                shift >>= 1;
//            }
//        }
//        d
//    }
//}


