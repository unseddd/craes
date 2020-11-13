use alloc::vec::Vec;
use core::convert::TryInto;

use crate::aes;

/// Initialization vector length for AES-128-CBC
pub const IV_LEN: usize = 16_usize;

#[derive(Debug)]
pub enum Error {
    InvalidLength,
}

fn xor(left: &[u8], right: &[u8]) -> Result<Vec<u8>, Error> {
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

/// Encrypt a message in CBC mode
///
/// Message must be a multiple of the AES block length (16)
pub fn encrypt(
    msg: &[u8],
    key: &[u8; aes::KEY_LEN_128],
    iv: &[u8; IV_LEN],
) -> Result<Vec<u8>, Error> {
    let len = msg.len();
    if len % aes::BLOCK_LEN != 0 {
        return Err(Error::InvalidLength);
    }

    let mut res = Vec::with_capacity(len);

    for (i, block) in msg.chunks_exact(aes::BLOCK_LEN).enumerate() {
        if i == 0 {
            // next cipher block:       AES-128( block_i ^ IV , key )
            res.extend_from_slice(&aes::aes_128(
                &xor(&block, iv.as_ref())?.as_slice().try_into().unwrap(),
                &key,
            ));
        } else {
            // next cipher block:       AES-128( block_i ^ cipher_block[i-1] , key )
            res.extend_from_slice(&aes::aes_128(
                &xor(&block, &res[aes::BLOCK_LEN * (i - 1)..aes::BLOCK_LEN * i])?
                    .as_slice()
                    .try_into()
                    .unwrap(),
                &key,
            ));
        }
    }

    Ok(res)
}

/// Decrypt a message in CBC mode
///
/// Message must be a multiple of the AES block length (16)
pub fn decrypt(
    cipher: &[u8],
    key: &[u8; aes::KEY_LEN_128],
    iv: &[u8; IV_LEN],
) -> Result<Vec<u8>, Error> {
    let len = cipher.len();
    if len % aes::BLOCK_LEN != 0 {
        return Err(Error::InvalidLength);
    }

    let mut res = Vec::with_capacity(len);

    for (i, block) in cipher.chunks_exact(aes::BLOCK_LEN).enumerate() {
        if i == 0 {
            // next cipher block:       AES-INV-128( block_i ^ IV , key )
            res.extend_from_slice(&aes::aes_inv_128(
                &xor(&block, iv.as_ref())?.as_slice().try_into().unwrap(),
                &key,
            ));
        } else {
            // next cipher block:       AES-INV-128( block_i , key ) ^ cipher_block[i-1]
            res.extend_from_slice(&xor(
                &aes::aes_inv_128(&block.try_into().unwrap(), key),
                &cipher[aes::BLOCK_LEN * (i - 1)..aes::BLOCK_LEN * i],
            )?);
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_aes_128_cbc() {
        let txt = b"This block good! This block good";
        let key = b"YELLOW SUBMARINE";
        let iv = [0_u8; IV_LEN];

        assert!(encrypt(&txt[..], &key, &iv).is_ok());

        // use an invalid length plaintext, ensure error is returned
        assert!(encrypt(&txt[1..], &key, &iv).is_err());
    }

    #[test]
    fn check_aes_inv_128_cbc() {
        let txt = b"This block good! This block good";
        let key = b"YELLOW SUBMARINE";
        let iv = [0_u8; IV_LEN];

        let cipher = encrypt(&txt[..], &key, &iv);
        assert!(cipher.is_ok());

        let pt = decrypt(&cipher.unwrap(), &key, &iv);
        assert!(pt.is_ok());
        assert_eq!(pt.unwrap()[..], txt[..]);
    }
}
