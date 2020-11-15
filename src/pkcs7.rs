use crate::aes;
use alloc::vec::Vec;

/// PKCS#7 padding errors
#[derive(Debug)]
pub enum Error {
    InvalidLength,
    InvalidPadding,
}

/// Pads a buffer to the next multiple of AES block-size with PKCS#7 specified bytes
///
/// Examples:
///
/// [42]     => [42, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15]
/// [42, 69] => [42, 69, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14]
pub fn pad(buf: &[u8]) -> Vec<u8> {
    match buf.len() % aes::BLOCK_LEN {
        15 => [buf, &[1_u8; 1]].concat(),
        14 => [buf, &[2_u8; 2]].concat(),
        13 => [buf, &[3_u8; 3]].concat(),
        12 => [buf, &[4_u8; 4]].concat(),
        11 => [buf, &[5_u8; 5]].concat(),
        10 => [buf, &[6_u8; 6]].concat(),
        9 => [buf, &[7_u8; 7]].concat(),
        8 => [buf, &[8_u8; 8]].concat(),
        7 => [buf, &[9_u8; 9]].concat(),
        6 => [buf, &[10_u8; 10]].concat(),
        5 => [buf, &[11_u8; 11]].concat(),
        4 => [buf, &[12_u8; 12]].concat(),
        3 => [buf, &[13_u8; 13]].concat(),
        2 => [buf, &[14_u8; 14]].concat(),
        1 => [buf, &[15_u8; 15]].concat(),
        0 => buf.to_vec(),
        _ => unreachable!("n mod 16 can only be in range 0..=15"),
    }
}

/// Remove PKCS#7 padding from provided buffer
pub fn unpad(buf: &[u8]) -> Result<Vec<u8>, Error> {
    let buf_len = buf.len();

    if buf_len < aes::BLOCK_LEN || buf_len % aes::BLOCK_LEN != 0 {
        return Err(Error::InvalidLength);
    }

    let padded_block = &buf[buf_len - aes::BLOCK_LEN..];

    if padded_block == &[16_u8; 16] {
        Ok(Vec::new())
    } else if &padded_block[1..] == &[15_u8; 15] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 1].to_vec())
    } else if &padded_block[2..] == &[14_u8; 14] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 2].to_vec())
    } else if &padded_block[3..] == &[13_u8; 13] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 3].to_vec())
    } else if &padded_block[4..] == &[12_u8; 12] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 4].to_vec())
    } else if &padded_block[5..] == &[11_u8; 11] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 5].to_vec())
    } else if &padded_block[6..] == &[10_u8; 10] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 6].to_vec())
    } else if &padded_block[7..] == &[9_u8; 9] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 7].to_vec())
    } else if &padded_block[8..] == &[8_u8; 8] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 8].to_vec())
    } else if &padded_block[9..] == &[7_u8; 7] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 9].to_vec())
    } else if &padded_block[10..] == &[6_u8; 6] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 10].to_vec())
    } else if &padded_block[11..] == &[5_u8; 5] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 11].to_vec())
    } else if &padded_block[12..] == &[4_u8; 4] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 12].to_vec())
    } else if &padded_block[13..] == &[3_u8; 3] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 13].to_vec())
    } else if &padded_block[14..] == &[2_u8; 2] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 14].to_vec())
    } else if &padded_block[15..] == &[1_u8; 1] {
        Ok(buf[..buf_len - aes::BLOCK_LEN + 15].to_vec())
    } else {
        // filter any padding bytes from the final block
        // FIXME: in the general case, what if a protocol uses PKCS#7 bytes?
        let test_pad: Vec<u8> = padded_block
            .iter()
            .filter(|&&b| {
                b != 1
                    && b != 2
                    && b != 3
                    && b != 4
                    && b != 5
                    && b != 6
                    && b != 7
                    && b != 8
                    && b != 9
                    && b != 10
                    && b != 11
                    && b != 12
                    && b != 13
                    && b != 14
                    && b != 15
            })
            .map(|&b| b)
            .collect();

        if &test_pad == &padded_block {
            // unpadded buffer
            Ok(buf.to_vec())
        } else {
            // padding block has invalid bytes
            Err(Error::InvalidPadding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_pad() {
        let mut msg = b"Y".to_vec();

        let mut padded = pad(&msg);

        // check when 15 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[1..], [15_u8; 15][..]);

        msg.extend_from_slice(&b"E"[..]);
        padded = pad(&msg);

        // check when 14 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[2..], [14_u8; 14][..]);

        msg.extend_from_slice(&b"L"[..]);
        padded = pad(&msg);

        // check when 13 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[3..], [13_u8; 13][..]);

        msg.extend_from_slice(&b"L"[..]);
        padded = pad(&msg);

        // check when 12 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[4..], [12_u8; 12][..]);

        msg.extend_from_slice(&b"O"[..]);
        padded = pad(&msg);

        // check when 11 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[5..], [11_u8; 11][..]);

        msg.extend_from_slice(&b"W"[..]);
        padded = pad(&msg);

        // check when 10 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[6..], [10_u8; 10][..]);

        msg.extend_from_slice(&b" "[..]);
        padded = pad(&msg);

        // check when 9 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[7..], [9_u8; 9][..]);

        msg.extend_from_slice(&b"S"[..]);
        padded = pad(&msg);

        // check when 8 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[8..], [8_u8; 8][..]);

        msg.extend_from_slice(&b"U"[..]);
        padded = pad(&msg);

        // check when 7 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[9..], [7_u8; 7][..]);

        msg.extend_from_slice(&b"B"[..]);
        padded = pad(&msg);

        // check when 6 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[10..], [6_u8; 6][..]);

        msg.extend_from_slice(&b"M"[..]);
        padded = pad(&msg);

        // check when 5 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[11..], [5_u8; 5][..]);

        msg.extend_from_slice(&b"A"[..]);
        padded = pad(&msg);

        // check when 4 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[12..], [4_u8; 4][..]);

        msg.extend_from_slice(&b"R"[..]);
        padded = pad(&msg);

        // check when 3 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[13..], [3_u8; 3][..]);

        msg.extend_from_slice(&b"I"[..]);
        padded = pad(&msg);

        // check when 2 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[14..], [2_u8; 2][..]);

        msg.extend_from_slice(&b"N"[..]);
        padded = pad(&msg);

        // check when 1 padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded[15..], [1_u8; 1][..]);

        msg.extend_from_slice(&b"E"[..]);
        padded = pad(&msg);

        // check when no padding bytes needed
        assert_eq!(padded.len(), aes::BLOCK_LEN);
        assert_eq!(padded, msg);

        // check padding multiple blocks
        msg.extend_from_slice(&b"!"[..]);
        padded = pad(&msg);

        // 15 padding bytes needed to fill next block
        assert_eq!(padded.len(), 2 * aes::BLOCK_LEN);
        assert_eq!(padded[aes::BLOCK_LEN + 1..], [15_u8; 15]);
    }

    #[test]
    fn check_unpad() {
        let mut block = [0_u8; aes::BLOCK_LEN];

        for i in 0..aes::BLOCK_LEN {
            let last_bytes = aes::BLOCK_LEN - i - 1;

            for j in last_bytes..aes::BLOCK_LEN {
                block[j] = (i + 1) as u8;
            }

            assert_eq!(unpad(block.as_ref()).unwrap()[..], block[..last_bytes]);
        }
    }
}
