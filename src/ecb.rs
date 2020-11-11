use alloc::vec::Vec;
use core::convert::TryInto;

use crate::aes;

#[derive(Debug)]
pub enum Error {
    InvalidLength,
}

pub fn aes_128_ecb(plaintext: &[u8], key: &[u8; aes::KEY_LEN_128]) -> Result<Vec<u8>, Error> {
    let len = plaintext.len();
    if len % aes::BLOCK_LEN != 0 {
        return Err(Error::InvalidLength)
    }

    let mut res = Vec::with_capacity(len);
    for block in plaintext.chunks_exact(aes::BLOCK_LEN) {
        res.extend_from_slice(&aes::aes_128(block.try_into().unwrap(), &key)[..]);
    }

    Ok(res)
}

pub fn aes_inv_128_ecb(plaintext: &[u8], key: &[u8; aes::KEY_LEN_128]) -> Result<Vec<u8>, Error> {
    let len = plaintext.len();
    if len % aes::BLOCK_LEN != 0 {
        return Err(Error::InvalidLength)
    }

    let mut res = Vec::with_capacity(len);
    for block in plaintext.chunks_exact(aes::BLOCK_LEN) {
        res.extend_from_slice(&aes::aes_inv_128(block.try_into().unwrap(), &key)[..]);
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_aes_128_ecb() {
        let txt = b"This block good! This block good";
        let key = b"YELLOW SUBMARINE";

        assert!(aes_128_ecb(&txt[..], &key).is_ok());

        // use an invalid length plaintext, ensure error is returned
        assert!(aes_128_ecb(&txt[1..], &key).is_err());
    }

    #[test]
    fn check_aes_inv_128_ecb() {
        let txt = b"This block good! This block good";
        let key = b"YELLOW SUBMARINE";

        let cipher = aes_128_ecb(&txt[..], &key);
        assert!(cipher.is_ok());

        let pt = aes_inv_128_ecb(&cipher.unwrap(), &key);
        assert!(pt.is_ok());
        assert_eq!(pt.unwrap()[..], txt[..]);
    }
}
