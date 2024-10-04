# cryptolib

This algorithm lib supplies you a set of simple interface to achieve your encryption requirements

## Usage

Add this to your `Cargo.toml`

```toml
[dependencies]
cryptolib = "<version>"
```

## Supported Features

- SHA Family
  
- AES Family
  
- CMAC
  
- AES-MP
  
- Base64
  
- Memory Update Protocol
  
- Padding
  
- RSA(planned)
  

## Examples

### SHA

```rust
use cryptolib::sha::{sha, ShaType};
fn main() {
    let msg: String = String::from("It is cryptolib");
    let hash_text: Vec<u8> = sha(&msg, ShaType::SHA256);
    println!("{:?}", hash_text); //[110, 61, 35, 228, 69, 228, 253, 91, 91, 79, 229, 196, 34, 253, 109, 35, 46, 241, 255, 188, 82, 162, 166, 25, 181, 96, 140, 196, 94, 203, 100, 177]
}
```

Note:

Add the this to `Cargo.toml` to avoid overflow warning

```toml
[profile.dev]
overflow-checks = false
```

## AES

```rust
use cryptolib::aes::{aes_ecb_enc, AesType};
fn main() {
    let msg: String = String::from("It is cryptolib");
    let aes_key: String = String::from("0123456789ABCDEF");
    let enc_text: Vec<u8> = aes_ecb_enc(&msg.into_bytes(), &aes_key.into_bytes(), &AesType::AES128);
    println!("{:?}", enc_text); //[20, 223, 131, 141, 80, 131, 81, 224, 163, 90, 211, 211, 249, 186, 21, 60]
}
```
