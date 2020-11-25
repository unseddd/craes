#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// AES engine for single block en/decryption
pub mod aes;

/// CBC mode for AES
pub mod cbc;

/// CTR mode for AES
pub mod ctr;

/// ECB mode for AES
pub mod ecb;

/// PKCS#7 padding for AES block size
pub mod pkcs7;

#[derive(Debug)]
pub enum Error {
    InvalidLength,
}

/// Perform bitwise XOR on equal length byte slices
pub fn xor(left: &[u8], right: &[u8]) -> Result<Vec<u8>, Error> {
    let len = left.len();

    if len != right.len() {
        return Err(Error::InvalidLength);
    }

    let mut res = Vec::with_capacity(len);

    for (el, ar) in left.iter().zip(right.iter()) {
        res.push(el ^ ar);
    }

    Ok(res)
}

/// Perform bitwise XOR on equal length byte slices
///
/// Assigns result into the left byte slice
pub fn xor_equals(left: &mut [u8], right: &[u8]) -> Result<(), Error> {
    if left.len() != right.len() {
        return Err(Error::InvalidLength);
    }

    for (el, ar) in left.iter_mut().zip(right.iter()) {
        *el ^= *ar;
    }

    Ok(())
}

#[cfg(test)]
mod tests {}
