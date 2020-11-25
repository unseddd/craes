use alloc::vec::Vec;
use core::convert::TryInto;

use crate::{aes, xor};
use crate::Error;

/// Initialization vector length for AES-128-CBC
pub const IV_LEN: usize = 16_usize;

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
            // next plaintext block:       AES-INV-128( block_i , key ) ^ IV 
            res.extend_from_slice(&xor(
                &aes::aes_inv_128(&block.try_into().unwrap(), key),
                iv.as_ref(),
            )?);
        } else {
            // next plaintext block:       AES-INV-128( block_i , key ) ^ cipher_block[i-1]
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
    fn check_cbc_encrypt() {
        let txt = b"This block good! This block good";
        let key = b"YELLOW SUBMARINE";
        let iv = [0_u8; IV_LEN];

        assert!(encrypt(txt.as_ref(), &key, &iv).is_ok());

        // use an invalid length plaintext, ensure error is returned
        assert!(encrypt(&txt[1..], &key, &iv).is_err());
    }

    #[test]
    fn check_cbc_decrypt() {
        let txt = b"This block good! This block good";
        let key = b"YELLOW SUBMARINE";
        let iv = [0_u8; IV_LEN];

        let cipher = encrypt(txt.as_ref(), &key, &iv);
        assert!(cipher.is_ok());

        let pt = decrypt(&cipher.unwrap(), &key, &iv);
        assert!(pt.is_ok());
        assert_eq!(pt.unwrap()[..], txt[..]);
    }

    // NIST test vectors from RFC 3602: https://tools.ietf.org/html/rfc3602
    #[test]
    fn nist_test_vector_case_one() {
        let key = [
            0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b, 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12,
            0x00, 0x06,
        ];
        let iv = [
            0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f,
            0xac, 0x41,
        ];
        let msg = b"Single block msg";
        let exp_cipher = [
            0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8, 0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77,
            0x18, 0x1a,
        ];

        let cipher = encrypt(msg.as_ref(), &key, &iv).unwrap();
        assert_eq!(cipher.as_slice(), exp_cipher.as_ref());

        let plaintext = decrypt(&cipher, &key, &iv).unwrap();
        assert_eq!(plaintext.as_slice(), msg.as_ref());
    }

    // NIST test vectors from RFC 3602: https://tools.ietf.org/html/rfc3602
    #[test]
    fn nist_test_vector_case_two() {
        let key = [
            0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0, 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25,
            0xa4, 0x5a,
        ];
        let iv = [
            0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e,
            0x6f, 0x58,
        ];
        let msg = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let exp_cipher = [
            0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a, 0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1,
            0xdc, 0x0a, 0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9, 0x1b, 0x82, 0x66, 0xbe,
            0xa6, 0xd6, 0x1a, 0xb1,
        ];

        let cipher = encrypt(msg.as_ref(), &key, &iv).unwrap();
        assert_eq!(cipher.as_slice(), exp_cipher.as_ref());

        let plaintext = decrypt(&cipher, &key, &iv).unwrap();
        assert_eq!(plaintext.as_slice(), msg.as_ref());
    }

    // NIST test vectors from RFC 3602: https://tools.ietf.org/html/rfc3602
    #[test]
    fn nist_test_vector_case_three() {
        let key = [
            0x6c, 0x3e, 0xa0, 0x47, 0x76, 0x30, 0xce, 0x21, 0xa2, 0xce, 0x33, 0x4a, 0xa7, 0x46,
            0xc2, 0xcd,
        ];
        let iv = [
            0xc7, 0x82, 0xdc, 0x4c, 0x09, 0x8c, 0x66, 0xcb, 0xd9, 0xcd, 0x27, 0xd8, 0x25, 0x68,
            0x2c, 0x81,
        ];
        let msg = b"This is a 48-byte message (exactly 3 AES blocks)";
        let exp_cipher = [
            0xd0, 0xa0, 0x2b, 0x38, 0x36, 0x45, 0x17, 0x53, 0xd4, 0x93, 0x66, 0x5d, 0x33, 0xf0,
            0xe8, 0x86, 0x2d, 0xea, 0x54, 0xcd, 0xb2, 0x93, 0xab, 0xc7, 0x50, 0x69, 0x39, 0x27,
            0x67, 0x72, 0xf8, 0xd5, 0x02, 0x1c, 0x19, 0x21, 0x6b, 0xad, 0x52, 0x5c, 0x85, 0x79,
            0x69, 0x5d, 0x83, 0xba, 0x26, 0x84,
        ];

        let cipher = encrypt(msg.as_ref(), &key, &iv).unwrap();
        assert_eq!(cipher.as_slice(), exp_cipher.as_ref());

        let plaintext = decrypt(&cipher, &key, &iv).unwrap();
        assert_eq!(plaintext.as_slice(), msg.as_ref());
    }

    // NIST test vectors from RFC 3602: https://tools.ietf.org/html/rfc3602
    #[test]
    fn nist_test_vector_case_four() {
        let key = [
            0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74, 0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29,
            0x03, 0x49,
        ];
        let iv = [
            0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c, 0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51,
            0xb7, 0xd9,
        ];
        let msg = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
            0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
            0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
            0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        ];
        let exp_cipher = [
            0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e, 0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f,
            0x71, 0xaa, 0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6, 0x84, 0xdb, 0x20, 0x7e,
            0xb0, 0xef, 0x8e, 0x4e, 0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf, 0x86, 0x8b,
            0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad, 0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d,
            0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55,
        ];

        let cipher = encrypt(msg.as_ref(), &key, &iv).unwrap();
        assert_eq!(cipher.as_slice(), exp_cipher.as_ref());

        let plaintext = decrypt(&cipher, &key, &iv).unwrap();
        assert_eq!(plaintext.as_slice(), msg.as_ref());
    }
}
