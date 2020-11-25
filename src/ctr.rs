use alloc::vec::Vec;

use crate::{aes, xor};

// Nonce length for key stream input
const NONCE_LEN: usize = 8;

// Counter length for key stream input
const COUNT_LEN: usize = 8;

/// Endianess for interpreting nonce and counter values
#[derive(Debug, PartialEq)]
pub enum Endian {
    Big,
    Little,
}

/// Encrypt a given plaintext using AES-128-CTR
/// Supply the nonce and initial count for encryption
/// The mode determines the Endian interpretation of the nonce and counter
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; aes::KEY_LEN_128],
    nonce: u64,
    count: &mut u64,
    mode: &Endian,
    ) -> Vec<u8> {
    ctr_inner(&plaintext, &key, nonce, count, &mode)
}

/// Decrypt a given ciphertext using AES-128-CTR
/// Supply the nonce and initial count for decryption
/// The mode determines the Endian interpretation of the nonce and counter
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; aes::KEY_LEN_128],
    nonce: u64,
    count: &mut u64,
    mode: &Endian,
    ) -> Vec<u8> {
    ctr_inner(&ciphertext, &key, nonce, count, &mode)
}

fn ctr_inner(
    text: &[u8],
    key: &[u8; aes::KEY_LEN_128],
    nonce: u64,
    count: &mut u64,
    mode: &Endian,
    ) -> Vec<u8> {
    let len = text.len();

    let mut res: Vec<u8> = Vec::with_capacity(len);

    let nonce_bytes = match mode {
        Endian::Big => nonce.to_be_bytes(),
        Endian::Little => nonce.to_le_bytes(),
    };

    let mut input = [0_u8; aes::BLOCK_LEN];
    input[..NONCE_LEN].copy_from_slice(&nonce_bytes);

    for block in text.chunks(aes::BLOCK_LEN) {
        let stream = ctr_inner_cipher(&mut input, &key, *count, &mode);
        // block and stream guaranteed to be the same length, safe to just unwrap here
        let output = xor(block, &stream[..block.len()]).unwrap();
        res.extend_from_slice(&output);
        *count += 1;
    }

    res
}

// Get the next block of the keystream
// NOTE: separated into own function to help debugging
fn ctr_inner_cipher(
    input: &mut [u8; aes::BLOCK_LEN],
    key: &[u8; aes::KEY_LEN_128],
    count: u64,
    mode: &Endian) -> [u8; aes::BLOCK_LEN] {
    let count_bytes = match mode {
        Endian::Big => count.to_be_bytes(),
        Endian::Little => count.to_le_bytes(),
    };

    input[COUNT_LEN..].copy_from_slice(&count_bytes);

    aes::aes_128(&input, &key)
}

// Get the number of blocks of key stream needed for a give text length
// Useful for debugging purposes
#[allow(dead_code)]
fn get_block_count(len: usize) -> u64 {
    ((len / aes::BLOCK_LEN) + ((len % aes::BLOCK_LEN) != 0) as usize) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_encryption_test_vectors() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let nonce = u64::from_be_bytes([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]); 
        let mut init_count = u64::from_be_bytes([0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]);
        let mut count = init_count;

        let in_block_1 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];
        let out_block_1 = [0xec, 0x8c, 0xdf, 0x73, 0x98, 0x60, 0x7c, 0xb0, 0xf2, 0xd2, 0x16, 0x75, 0xea, 0x9e, 0xa1, 0xe4];
        let plaintext_1 = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
        let ciphertext_1 = [0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce];

        let mut input = [0_u8; aes::BLOCK_LEN];
        input[..NONCE_LEN].copy_from_slice(&nonce.to_be_bytes());

        let mut output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_1, input);
        assert_eq!(out_block_1, output);

        let mut ciphertext = encrypt(&plaintext_1, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(ciphertext_1, ciphertext[..]);
        assert_eq!(count, init_count + get_block_count(plaintext_1.len()));

        let in_block_2 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x00];
        let out_block_2 = [0x36, 0x2b, 0x7c, 0x3c, 0x67, 0x73, 0x51, 0x63, 0x18, 0xa0, 0x77, 0xd7, 0xfc, 0x50, 0x73, 0xae];
        let plaintext_2 = [0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51];
        let ciphertext_2 = [0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff];

        output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_2, input);
        assert_eq!(out_block_2, output);

        init_count = count;
        ciphertext = encrypt(&plaintext_2, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(ciphertext_2, ciphertext[..]);
        assert_eq!(count, init_count + get_block_count(plaintext_2.len()));

        let in_block_3 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x01];
        let out_block_3 = [0x6a, 0x2c, 0xc3, 0x78, 0x78, 0x89, 0x37, 0x4f, 0xbe, 0xb4, 0xc8, 0x1b, 0x17, 0xba, 0x6c, 0x44];
        let plaintext_3 = [0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef];
        let ciphertext_3 = [0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab];

        output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_3, input);
        assert_eq!(out_block_3, output);

        init_count = count;
        ciphertext = encrypt(&plaintext_3, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(ciphertext_3, ciphertext[..]);
        assert_eq!(count, init_count + get_block_count(plaintext_3.len()));

        let in_block_4 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x02];
        let out_block_4 = [0xe8, 0x9c, 0x39, 0x9f, 0xf0, 0xf1, 0x98, 0xc6, 0xd4, 0x0a, 0x31, 0xdb, 0x15, 0x6c, 0xab, 0xfe];
        let plaintext_4 = [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10];
        let ciphertext_4 = [0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee];

        output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_4, input);
        assert_eq!(out_block_4, output);

        init_count = count;
        ciphertext = encrypt(&plaintext_4, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(ciphertext_4, ciphertext[..]);
        assert_eq!(count, init_count + get_block_count(plaintext_4.len()));
    }

    #[test]
    fn nist_decryption_test_vectors() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let nonce = u64::from_be_bytes([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]); 
        let mut init_count = u64::from_be_bytes([0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]);
        let mut count = init_count;

        let in_block_1 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];
        let out_block_1 = [0xec, 0x8c, 0xdf, 0x73, 0x98, 0x60, 0x7c, 0xb0, 0xf2, 0xd2, 0x16, 0x75, 0xea, 0x9e, 0xa1, 0xe4];
        let plaintext_1 = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
        let ciphertext_1 = [0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce];

        let mut input = [0_u8; aes::BLOCK_LEN];
        input[..NONCE_LEN].copy_from_slice(&nonce.to_be_bytes());

        let mut output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_1, input);
        assert_eq!(out_block_1, output);

        let mut plaintext = decrypt(&ciphertext_1, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(plaintext_1, plaintext[..]);
        assert_eq!(count, init_count + get_block_count(ciphertext_1.len()));

        let in_block_2 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x00];
        let out_block_2 = [0x36, 0x2b, 0x7c, 0x3c, 0x67, 0x73, 0x51, 0x63, 0x18, 0xa0, 0x77, 0xd7, 0xfc, 0x50, 0x73, 0xae];
        let plaintext_2 = [0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51];
        let ciphertext_2 = [0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff];

        output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_2, input);
        assert_eq!(out_block_2, output);

        init_count = count;
        plaintext = decrypt(&ciphertext_2, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(plaintext_2, plaintext[..]);
        assert_eq!(count, init_count + get_block_count(ciphertext_2.len()));

        let in_block_3 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x01];
        let out_block_3 = [0x6a, 0x2c, 0xc3, 0x78, 0x78, 0x89, 0x37, 0x4f, 0xbe, 0xb4, 0xc8, 0x1b, 0x17, 0xba, 0x6c, 0x44];
        let plaintext_3 = [0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef];
        let ciphertext_3 = [0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab];

        output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_3, input);
        assert_eq!(out_block_3, output);

        init_count = count;
        plaintext = decrypt(&ciphertext_3, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(plaintext_3, plaintext[..]);
        assert_eq!(count, init_count + get_block_count(ciphertext_3.len()));

        let in_block_4 = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x02];
        let out_block_4 = [0xe8, 0x9c, 0x39, 0x9f, 0xf0, 0xf1, 0x98, 0xc6, 0xd4, 0x0a, 0x31, 0xdb, 0x15, 0x6c, 0xab, 0xfe];
        let plaintext_4 = [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10];
        let ciphertext_4 = [0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee];

        output = ctr_inner_cipher(&mut input, &key, count, &Endian::Big);
        assert_eq!(in_block_4, input);
        assert_eq!(out_block_4, output);

        init_count = count;
        plaintext = decrypt(&ciphertext_4, &key, nonce, &mut count, &Endian::Big);

        assert_eq!(plaintext_4, plaintext[..]);
        assert_eq!(count, init_count + get_block_count(ciphertext_4.len()));
    }
}
