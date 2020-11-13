#![no_std]

extern crate alloc;

/// AES engine for single block en/decryption
pub mod aes;

/// CBC mode for AES
pub mod cbc;

/// ECB mode for AES
pub mod ecb;

/// PKCS#7 padding for AES block size
pub mod pkcs7;

#[cfg(test)]
mod tests {}
