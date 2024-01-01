use std::ops::{Add, Sub, Mul, Div, Rem};


#[cfg(test)]
mod rsa_tests {
    use super::*;
    #[test]
    fn rsa_test() {
        //let plain_text: String = String::from("SUNYSUNYSUNYSUNY");
        //let rsa_key = String::from("abcdabcdabcdabcd").into_bytes();
        let n1 = BigNum(String::from("07"));
        let n2 = BigNum(String::from("11"));

        let r = Rsa::new(n1 ,n2);
        println!("Rsa: {:?}", r);


        //assert_eq!(
        //     rsa_enc(&plain_text, &aes_key, AesType::AES128),
        //     String::from("30e1afaf9c36e4814f2abfd05c76cf12")
        //);
    }
}

#[derive(Debug)]
struct Key(BigNum, BigNum);
#[derive(Debug, Clone)]
struct BigNum(String);

impl BigNum {
    fn is_zero(&self) -> bool {
        let mut iter = self.0.chars();
        let mut is_zero: bool = true;
        while let Some(c) = iter.next() {

            if let Some(n) = c.to_digit(16) {
                if n!= 0 {
                    is_zero = false;
                    break;
                }
            }
        }
        is_zero
    }
    fn greater_than(&self, rhs: &BigNum) -> bool {

        let mut res: bool = true;
        let mut iter_lhs = self.0.chars().rev();
        let mut iter_rhs = rhs.0.chars().rev();

        let mut digits_lhs: Vec<u32> = Vec::new();
        let mut digits_rhs: Vec<u32> = Vec::new();

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
        println!("{:?}, {:?}", &digits_lhs, &digits_rhs);
        loop {
            let mut n1 = 0;
            let mut n2 = 0;

            if let Some(x) = digits_lhs.pop() {
                n1 = x; 
            }
            if let Some(x) = digits_rhs.pop() {
                n2 = x;
            }
        println!("{:?}, {:?}", n1, n2);
            if n1 > n2 {
                res = true;
                break;
            }
            else if n1 < n2 {
                res = false;
                break;
            }
            else if n1 == n2 {
                continue;
            }

            if digits_lhs.is_empty() && digits_rhs.is_empty() {
                break;
            }
        }
        res
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

            let mut sum = n1 + n2 + carry;

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

            if sum >= 0 {
                borrow = 0;
                                
            } else {
                sum += 16;
                borrow = 1;
            }

            digits_sum.push(sum as u32);

            //TODO: end the loop depends on bits of operand
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
        
        let mut product = BigNum(String::from("0")); 
        let mut multiplier = rhs.clone();
        while !multiplier.is_zero() {
            product = product.clone() + self.clone();
            multiplier = multiplier - BigNum(String::from("1"));
        }
        product 
    }
}

impl Rem for BigNum {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        
        let mut rem = self.clone(); 
        let mut subtrahend = rhs.clone();
        while rem.greater_than(&rhs) {
            rem = rem.clone() - subtrahend.clone();
            println!("{:?}", &rem);
        }
        rem
    }
}
impl Div for BigNum {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        
        let mut rem = self.clone(); 
        let mut divier = rhs.clone();
        let mut quotient = BigNum(String::from("0"));
        while rem.greater_than(&rhs) {
            rem = rem.clone() - divier.clone();
            quotient = quotient + BigNum(String::from("1"));
        }
        quotient
    }
}
#[derive(Debug)]
struct Rsa {
    pri_key: Key,
    pub_key: Key,
}


impl Rsa {

    fn gen_key(p: BigNum, q: BigNum) -> Rsa {
        let n: BigNum = p.clone() * q.clone();
        let fi: BigNum = (p - BigNum(String::from("1"))) * (q - BigNum(String::from("1")));
       // let e: BigNum = BigNum(String::from("10001"));//65537
        let e: BigNum = BigNum(String::from("7"));//65537
        let d: BigNum = BigNum(String::from("3"));//65537
        println!("fi: {:?}, n: {:?}", &fi, &n);
        //let (r, d, y) = gcd_ext(e.clone(), fi.clone());

        Rsa {
            pri_key: Key(d, n.clone()),
            pub_key: Key(e, n)
        }
        

   }

    pub fn new(p: BigNum, q: BigNum) -> Rsa{
        Self::gen_key(p, q)
    }
   // fn enc(byte: u8, e: &[u8], n: u32) -> u8 {
   // }
}

fn gcd_ext(a: BigNum, b: BigNum) -> (BigNum, BigNum, BigNum){

    println!("{:?}, {:?}", &a, &b);
    if b.is_zero(){
        let r = a;
        let x = BigNum(String::from("1"));
        let y = BigNum(String::from("0"));
        (r, x, y)
    }
    else{
        let rem = a.clone() % b.clone();
        let (r, x, y1) = gcd_ext(b.clone(), rem);
        let y = x.clone() - a / b * y1;
        (r, x, y)
    }
}

fn rem_fast(byte: u32, e: u32, n: u32) -> u32 {
    let mut d: u32 = 1;

    let mut shift = 0x80000000;

    while shift > 0 {
        d = (d*d)%n;
        if shift&e != 0 {
            d = (d*byte)%n;
        }
        shift >>= 1;
        println!("{}, {}, {}", d, shift, shift&byte );
    }
    d
}

