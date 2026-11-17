//! Small encoders for the testnet transactions: hex, bech32/bech32m, base58,
//! base64, DER, a CBOR subset, Bitcoin CompactSize and RLP.
#![allow(dead_code)]

use sha2::{Digest, Sha256};

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    Ripemd160::digest(Sha256::digest(data)).into()
}
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    use blake2::{digest::consts::U32, Blake2b};
    Blake2b::<U32>::digest(data).into()
}
pub fn blake2b224(data: &[u8]) -> [u8; 28] {
    use blake2::{digest::consts::U28, Blake2b};
    Blake2b::<U28>::digest(data).into()
}

// ---- bech32 / bech32m (BIP173, BIP350) ----

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Bech32,
    Bech32m,
}
impl Variant {
    fn constant(self) -> u32 {
        match self {
            Self::Bech32 => 1,
            Self::Bech32m => 0x2bc8_30a3,
        }
    }
}
fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk = 1u32;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|b| b & 31));
    v
}
pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for value in data {
        let v = u32::from(*value);
        if v >> from != 0 {
            return None;
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}
pub fn bech32_encode(hrp: &str, data5: &[u8], variant: Variant) -> String {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data5);
    values.extend([0; 6]);
    let pm = polymod(&values) ^ variant.constant();
    let mut out = format!("{hrp}1");
    for d in data5 {
        out.push(CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}
/// Returns (hrp, 5-bit data, variant). Rejects mixed case and bad checksums.
pub fn bech32_decode(s: &str) -> Option<(String, Vec<u8>, Variant)> {
    let lower = s.to_lowercase();
    if lower != s && s.to_uppercase() != s {
        return None;
    }
    let pos = lower.rfind('1')?;
    if pos < 1 || pos + 7 > lower.len() || lower.len() > 1023 {
        return None;
    }
    let hrp = &lower[..pos];
    if hrp.bytes().any(|b| !(33..=126).contains(&b)) {
        return None;
    }
    let data: Option<Vec<u8>> = lower[pos + 1..]
        .bytes()
        .map(|c| CHARSET.iter().position(|x| *x == c).map(|p| p as u8))
        .collect();
    let data = data?;
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    let variant = match polymod(&values) {
        1 => Variant::Bech32,
        0x2bc8_30a3 => Variant::Bech32m,
        _ => return None,
    };
    Some((hrp.to_string(), data[..data.len() - 6].to_vec(), variant))
}
/// Plain bech32 over 8-bit data (Cardano, Midnight), no length limit of 90.
pub fn bech32_bytes(hrp: &str, data: &[u8], variant: Variant) -> String {
    bech32_encode(hrp, &convert_bits(data, 8, 5, true).unwrap(), variant)
}
pub fn bech32_bytes_decode(s: &str) -> Option<(String, Vec<u8>, Variant)> {
    let (hrp, d5, v) = bech32_decode(s)?;
    Some((hrp, convert_bits(&d5, 5, 8, false)?, v))
}
pub fn segwit_encode(hrp: &str, version: u8, program: &[u8]) -> String {
    let mut d = vec![version];
    d.extend(convert_bits(program, 8, 5, true).unwrap());
    let variant = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    bech32_encode(hrp, &d, variant)
}
/// Returns (version, program) after the BIP173/BIP350 validity rules.
pub fn segwit_decode(hrp: &str, addr: &str) -> Option<(u8, Vec<u8>)> {
    if addr.len() > 90 {
        return None;
    }
    let (h, d, variant) = bech32_decode(addr)?;
    if h != hrp || d.is_empty() || d[0] > 16 {
        return None;
    }
    let program = convert_bits(&d[1..], 5, 8, false)?;
    if program.len() < 2 || program.len() > 40 {
        return None;
    }
    if d[0] == 0 && program.len() != 20 && program.len() != 32 {
        return None;
    }
    let expected = if d[0] == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    (variant == expected).then_some((d[0], program))
}
/// scriptPubKey for a segwit program.
pub fn segwit_script(version: u8, program: &[u8]) -> Vec<u8> {
    let mut s = vec![
        if version == 0 { 0 } else { 0x50 + version },
        program.len() as u8,
    ];
    s.extend_from_slice(program);
    s
}

// ---- base58 (Bitcoin alphabet; Solana addresses) ----

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
pub fn base58(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for byte in &data[zeros..] {
        let mut carry = u32::from(*byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|d| B58[*d as usize] as char));
    out
}
pub fn unbase58(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|c| *c == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes().skip(zeros) {
        let mut carry = B58.iter().position(|x| *x == c)? as u32;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

// ---- base64 (RFC 4648 standard alphabet) ----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
pub fn unbase64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let clean: Vec<u8> = s.bytes().filter(|c| *c != b'=').collect();
    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= (B64.iter().position(|x| x == c)? as u32) << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

// ---- DER for a low-s ECDSA signature (BIP66 strict encoding) ----

fn der_int(v: &[u8; 32], out: &mut Vec<u8>) {
    let start = v.iter().position(|b| *b != 0).unwrap_or(31);
    let mut body = v[start..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    out.push(0x02);
    out.push(body.len() as u8);
    out.extend(body);
}
pub fn der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::new();
    der_int(r, &mut body);
    der_int(s, &mut body);
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

// ---- Bitcoin CompactSize ----

pub fn compact(n: usize, out: &mut Vec<u8>) {
    match n {
        0..=252 => out.push(n as u8),
        253..=0xffff => {
            out.push(253);
            out.extend((n as u16).to_le_bytes());
        }
        _ => {
            out.push(254);
            out.extend((n as u32).to_le_bytes());
        }
    }
}

// ---- RLP ----

fn rlp_len(len: usize, short: u8, long: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let b = len.to_be_bytes();
        let start = b.iter().position(|x| *x != 0).unwrap();
        out.push(long + (b.len() - start) as u8);
        out.extend(&b[start..]);
    }
}
pub fn rlp_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_len(bytes.len(), 0x80, 0xb7, out);
        out.extend(bytes);
    }
}
/// Big-endian integer without leading zeros (zero is the empty string).
pub fn rlp_uint(bytes: &[u8], out: &mut Vec<u8>) {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    rlp_bytes(&bytes[start..], out);
}
pub fn rlp_list(items: &[u8], out: &mut Vec<u8>) {
    rlp_len(items.len(), 0xc0, 0xf7, out);
    out.extend(items);
}

// ---- CBOR subset (RFC 8949 major types 0, 2, 4, 5, 7) ----

pub fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend(n.to_be_bytes());
        }
    }
}
pub fn cbor_uint(n: u64, out: &mut Vec<u8>) {
    cbor_head(0, n, out);
}
pub fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}
pub fn cbor_array(n: usize, out: &mut Vec<u8>) {
    cbor_head(4, n as u64, out);
}
pub fn cbor_map(n: usize, out: &mut Vec<u8>) {
    cbor_head(5, n as u64, out);
}
pub const CBOR_TRUE: u8 = 0xf5;
pub const CBOR_NULL: u8 = 0xf6;

/// Byte length of the CBOR item at `i` (definite and indefinite lengths, tags).
/// Used to cut the exact body bytes out of a chain transaction.
pub fn cbor_skip(b: &[u8], i: usize) -> usize {
    let ib = b[i];
    let (major, ai) = (ib >> 5, ib & 31);
    let mut j = i + 1;
    let n: Option<u64> = match ai {
        0..=23 => Some(u64::from(ai)),
        24 => {
            j += 1;
            Some(u64::from(b[i + 1]))
        }
        25 => {
            j += 2;
            Some(u64::from(u16::from_be_bytes([b[i + 1], b[i + 2]])))
        }
        26 => {
            j += 4;
            Some(u64::from(u32::from_be_bytes(
                b[i + 1..i + 5].try_into().unwrap(),
            )))
        }
        27 => {
            j += 8;
            Some(u64::from_be_bytes(b[i + 1..i + 9].try_into().unwrap()))
        }
        31 => None,
        _ => panic!("reserved CBOR additional info"),
    };
    match (major, n) {
        (0 | 1 | 7, _) => j,
        (2 | 3, Some(n)) => j + n as usize,
        (6, _) => cbor_skip(b, j),
        (4, Some(n)) => (0..n).fold(j, |k, _| cbor_skip(b, k)),
        (5, Some(n)) => (0..2 * n).fold(j, |k, _| cbor_skip(b, k)),
        (2..=5, None) => {
            while b[j] != 0xff {
                j = cbor_skip(b, j);
            }
            j + 1
        }
        _ => unreachable!(),
    }
}
