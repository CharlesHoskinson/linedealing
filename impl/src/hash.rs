use crate::{algebra::reduce, Error, Result};
use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    ProjectivePoint, Scalar, Secp256k1,
};
use sha2::{Digest, Sha256, Sha512};

pub fn h(tag: &str, message: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    let mut hash = Sha256::new();
    hash.update(t);
    hash.update(t);
    hash.update(message);
    hash.finalize().into()
}

/// SHA-256 tag hashes, SHA-512 outer hash, then reduction modulo q (§3.1).
pub fn hq(tag: &str, message: &[u8]) -> Scalar {
    let t = Sha256::digest(tag.as_bytes());
    let mut hash = Sha512::new();
    hash.update(t);
    hash.update(t);
    hash.update(message);
    reduce(&hash.finalize())
}

/// RFC 9380 secp256k1_XMD:SHA-256_SSWU_RO_, with the protocol label as DST.
pub fn hg(tag: &str, message: &[u8]) -> Result<ProjectivePoint> {
    Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[message], &[tag.as_bytes()])
        .map_err(|_| Error::Point)
}

pub fn ciphertext_digest(ct: &[u8], domain: Option<ReshareDomain>) -> [u8; 32] {
    let mut data = domain.map_or_else(Vec::new, |d| d.prefix());
    data.extend_from_slice(ct);
    h(
        if domain.is_some() {
            "LD1/rs-ct"
        } else {
            "LD1/ct"
        },
        &data,
    )
}

pub(crate) fn proof_prefix(hd: &[u8; 32], ct: &[u8], domain: Option<ReshareDomain>) -> Vec<u8> {
    let mut data = domain.map_or_else(Vec::new, |d| d.prefix());
    data.extend_from_slice(hd);
    data.extend_from_slice(&ciphertext_digest(ct, domain));
    data
}

pub fn length_prefixed(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| Error::Encoding)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

pub fn dealing_digest(header: &[u8], deal: &[u8]) -> Result<[u8; 32]> {
    let mut input = Vec::new();
    length_prefixed(&mut input, header)?;
    length_prefixed(&mut input, deal)?;
    Ok(h("LD1/hd", &input))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotLabel([u8; 8]);

impl SlotLabel {
    pub fn new(mode: u8, component: u8, generation: u16, input: u16) -> Result<Self> {
        let valid = match (mode, component) {
            (1, 1) | (2, 2 | 3 | 5 | 6) => generation > 0 && input > 0,
            (2, 4) => generation == 0 && input == 0,
            _ => false,
        };
        if !valid {
            return Err(Error::Parameters);
        }
        let [a, b] = generation.to_be_bytes();
        let [c, d] = input.to_be_bytes();
        Ok(Self([mode, component, a, b, c, d, 0, 0]))
    }
    pub fn bytes(self) -> [u8; 8] {
        self.0
    }
}

pub fn binding_factor(hd: &[u8; 32], g: u16, input: u16, digest: &[u8; 32]) -> Scalar {
    hq(
        "LD1/bind",
        &[
            hd.as_slice(),
            &g.to_be_bytes(),
            &input.to_be_bytes(),
            digest,
        ]
        .concat(),
    )
}

/// BIP340 uses its own SHA-256 challenge, never LD1's Hq.
pub fn bip340_challenge(rx: &[u8; 32], x: &[u8; 32], message: &[u8; 32]) -> Scalar {
    reduce(&h(
        "BIP0340/challenge",
        &[rx.as_slice(), x, message].concat(),
    ))
}

#[derive(Clone, Copy)]
pub struct ReshareDomain {
    pub rid: [u8; 32],
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub dealer: u16,
}

impl ReshareDomain {
    pub fn prefix(self) -> Vec<u8> {
        [
            &self.rid[..],
            &self.old_epoch.to_be_bytes(),
            &self.new_epoch.to_be_bytes(),
            &self.dealer.to_be_bytes(),
        ]
        .concat()
    }
    pub fn digest(self, header: &[u8], deal: &[u8]) -> Result<[u8; 32]> {
        let mut data = self.prefix();
        length_prefixed(&mut data, header)?;
        length_prefixed(&mut data, deal)?;
        Ok(h("LD1/rs-hd", &data))
    }
}
