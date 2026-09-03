// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL siphash24.c – SipHash-2-4 (from libsodium)

/// SipHash-2-4: produce an 8-byte hash.
///
/// `k` must be exactly 16 bytes (the key).
/// `in` is the input data.
/// Returns the 8-byte hash as a `[u8; 8]`.
pub fn siphash24(input: &[u8], key: &[u8; 16]) -> [u8; 8] {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

    let mut v0: u64 = 0x736f6d6570736575;
    let mut v1: u64 = 0x646f72616e646f6d;
    let mut v2: u64 = 0x6c7967656e657261;
    let mut v3: u64 = 0x7465646279746573;

    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    let inlen = input.len();
    let end = inlen - (inlen % 8);

    // Process 8-byte blocks
    let mut i = 0;
    while i < end {
        let m = u64::from_le_bytes(input[i..i + 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 8;
    }

    // Build trailing block b (length in top byte + remaining bytes)
    let mut b: u64 = (inlen as u64) << 56;
    let left = inlen & 7;
    if left >= 1 {
        b |= input[end] as u64;
    }
    if left >= 2 {
        b |= (input[end + 1] as u64) << 8;
    }
    if left >= 3 {
        b |= (input[end + 2] as u64) << 16;
    }
    if left >= 4 {
        b |= (input[end + 3] as u64) << 24;
    }
    if left >= 5 {
        b |= (input[end + 4] as u64) << 32;
    }
    if left >= 6 {
        b |= (input[end + 5] as u64) << 40;
    }
    if left >= 7 {
        b |= (input[end + 6] as u64) << 48;
    }

    v3 ^= b;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    let result = v0 ^ v1 ^ v2 ^ v3;
    result.to_le_bytes()
}

#[inline]
fn rotl64(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotl64(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl64(*v0, 32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = rotl64(*v3, 16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = rotl64(*v3, 21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = rotl64(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl64(*v2, 32);
}

/// Derive a 16-byte SipHash key from two u64 values (little-endian encoded).
pub fn sipkey(a: u64, b: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0..8].copy_from_slice(&a.to_le_bytes());
    key[8..16].copy_from_slice(&b.to_le_bytes());
    key
}

/// Truncate a 64-bit hash to u16 (lower 16 bits, as used by AWDL channel sequence).
pub fn siphash_truncate(hash: [u8; 8]) -> u16 {
    u16::from_le_bytes([hash[0], hash[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siphash_empty() {
        let key = [0u8; 16];
        let hash = siphash24(&[], &key);
        // Known SipHash-2-4 of empty input with a zero key.
        assert_eq!(hash, [0xd7, 0x00, 0x77, 0x73, 0x9d, 0x4b, 0x92, 0x1e]);
    }

    #[test]
    fn test_siphash_single_byte() {
        let key = [0u8; 16];
        let hash = siphash24(&[0x00], &key);
        // Known SipHash-2-4 of a single 0x00 byte with a zero key.
        assert_eq!(hash, [0x8d, 0xc5, 0xfb, 0x49, 0xaa, 0x0b, 0x5a, 0x8b]);
    }
}
