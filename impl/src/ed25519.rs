//! Suite 3 signature-level line dealing. This module does not implement a Solana
//! transaction builder or a board lock/ledger. The caller must enforce both.
//!
//! Protocol scalars are big-endian; Ed25519 challenges and signature scalars use
//! RFC 8032 little-endian encoding. All transmitted points must be nonidentity
//! members of the prime-order subgroup. Commitments and header/proof points use
//! `0x00 || compressed Edwards Y`; sealed signature nonces use 32 bytes.
use crate::{
    hash::{dealing_digest, h, proof_prefix, ReshareDomain, SlotLabel},
    message::CommitteeState,
    wire::{Intent, Output},
    Error, Result,
};
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_COMPRESSED, ED25519_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use ed25519_dalek::{Signature, VerifyingKey};
use k256::elliptic_curve::rand_core::CryptoRngCore;
use sha2::{Digest, Sha256, Sha512};
use std::{borrow::Cow, collections::BTreeSet, sync::Arc};
const G: EdwardsPoint = ED25519_BASEPOINT_POINT;
// Header prefix: six one-byte fields and five 32-byte hashes.
const KEY_OFFSET: usize = 6 + 5 * 32;
const EPHEMERAL_OFFSET: usize = KEY_OFFSET + 33;
const HEADER_POINTS_END: usize = EPHEMERAL_OFFSET + 33;

// Dispatch only on the public base. Both scalar-multiplication paths are constant time.
fn mul_public_base(base: EdwardsPoint, scalar: &Scalar) -> EdwardsPoint {
    if base == G {
        EdwardsPoint::mul_base(scalar)
    } else {
        base * scalar
    }
}

/// Expand an Ed25519 seed exactly as RFC 8032, reducing the clamped scalar mod l.
pub fn secret_from_seed(seed: &[u8; 32]) -> Scalar {
    let digest = Sha512::digest(seed);
    let mut bytes: [u8; 32] = digest[..32].try_into().expect("fixed digest");
    bytes[0] &= 248;
    bytes[31] &= 63;
    bytes[31] |= 64;
    Scalar::from_bytes_mod_order(bytes)
}

/// Strict decoding includes canonical y, sign bit, subgroup, and identity checks.
pub fn decode_compressed(bytes: &[u8; 32]) -> Result<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(Error::Point)?;
    if point.compress().to_bytes() != *bytes || point.is_identity() || !point.is_torsion_free() {
        return Err(Error::Point);
    }
    Ok(point)
}
pub fn encode_point(point: EdwardsPoint) -> Result<[u8; 33]> {
    if point.is_identity() || !point.is_torsion_free() {
        return Err(Error::Point);
    }
    Ok(encode_checked_point(point))
}
// Only for points whose subgroup and nonidentity checks already succeeded.
fn encode_checked_point(point: EdwardsPoint) -> [u8; 33] {
    let mut bytes = [0; 33];
    bytes[1..].copy_from_slice(&point.compress().to_bytes());
    bytes
}
pub fn decode_point(bytes: &[u8]) -> Result<EdwardsPoint> {
    if bytes.len() != 33 || bytes[0] != 0 {
        return Err(Error::Encoding);
    }
    decode_compressed(bytes[1..].try_into().map_err(|_| Error::Encoding)?)
}
pub fn encode_scalar(scalar: Scalar) -> [u8; 32] {
    let mut bytes = scalar.to_bytes();
    bytes.reverse();
    bytes
}
pub fn decode_scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    let mut little = *bytes;
    little.reverse();
    Option::<Scalar>::from(Scalar::from_canonical_bytes(little)).ok_or(Error::Scalar)
}
/// LD1 Hq reads the SHA-512 digest as a big-endian integer.
pub fn hq(tag: &str, message: &[u8]) -> Scalar {
    let t = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha512::new();
    hasher.update(t);
    hasher.update(t);
    hasher.update(message);
    reduce(&hasher.finalize())
}
/// Read an arbitrary-length big-endian integer modulo the subgroup order.
pub fn reduce(bytes: &[u8]) -> Scalar {
    let limb_scalar = |limb: &[u8]| {
        let mut wide = [0; 64];
        for (out, byte) in wide.iter_mut().zip(limb.iter().rev()) {
            *out = *byte;
        }
        Scalar::from_bytes_mod_order_wide(&wide)
    };
    // First reduce at most 64 bytes; subsequent 32-byte limbs fit in 512 bits.
    let first = bytes.len().min(64);
    let mut value = limb_scalar(&bytes[..first]);
    if bytes.len() == first {
        return value;
    }
    let mut radix = [0; 64];
    radix[32] = 1;
    let radix = Scalar::from_bytes_mod_order_wide(&radix);
    for limb in bytes[first..].chunks(32) {
        let factor = if limb.len() == 32 {
            radix
        } else {
            let mut power = [0; 64];
            power[limb.len()] = 1;
            Scalar::from_bytes_mod_order_wide(&power)
        };
        value = value * factor + limb_scalar(limb);
    }
    value
}
/// Prototype map: labelled SHA-256(message || counter_be32), canonical decode,
/// cofactor clearing, and rejection of the identity. Counter starts at zero.
pub fn hg(tag: &str, message: &[u8]) -> Result<EdwardsPoint> {
    for counter in 0..=u32::MAX {
        let bytes = h(tag, &[message, &counter.to_be_bytes()].concat());
        if let Some(point) = CompressedEdwardsY(bytes).decompress() {
            if point.compress().to_bytes() == bytes {
                let point = point.mul_by_cofactor();
                if !point.is_identity() {
                    return Ok(point);
                }
            }
        }
    }
    Err(Error::Point)
}

/// RFC 8032 challenge: SHA512(R || A || M) interpreted little-endian.
pub fn challenge(nonce: EdwardsPoint, key: EdwardsPoint, message: &[u8]) -> Scalar {
    challenge_bytes(
        nonce.compress().as_bytes(),
        key.compress().as_bytes(),
        message,
    )
}
fn challenge_bytes(nonce: &[u8], key: &[u8], message: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(nonce);
    hasher.update(key);
    hasher.update(message);
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}
pub fn binding_factor(hd: &[u8; 32], generation: u16, input: u16, digest: &[u8; 32]) -> Scalar {
    hq(
        "LD1/bind",
        &[
            hd.as_slice(),
            &generation.to_be_bytes(),
            &input.to_be_bytes(),
            digest,
        ]
        .concat(),
    )
}
pub fn random_nonzero(rng: &mut impl CryptoRngCore) -> Scalar {
    loop {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub suite: u8,
    pub mode: u8,
    pub addr_type: u8,
    pub on_rotation: u8,
    pub late_inputs: u8,
    pub chain_id: [u8; 32],
    pub board_id: [u8; 32],
    pub owner_nonce: [u8; 32],
    pub keylist_hash: [u8; 32],
    pub builder_hash: [u8; 32],
    pub public_key: EdwardsPoint,
    pub ephemeral: EdwardsPoint,
    pub address: Vec<u8>,
    pub epoch: u64,
    pub not_before: u64,
    pub expires: u64,
    pub n: u16,
    pub threshold: u16,
    pub f: u16,
    pub variants: u16,
    pub inputs: u16,
    pub generations: u16,
    pub trigger_id: u16,
    pub trigger_params: [u8; 32],
    pub intent: Intent,
}

fn padded(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if value.len() > 35 {
        return Err(Error::Encoding);
    }
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out.resize(out.len() + 35 - value.len(), 0);
    Ok(())
}

impl Header {
    pub fn validate(&self) -> Result<()> {
        self.validate_fields()?;
        encode_point(self.public_key)?;
        encode_point(self.ephemeral)?;
        Ok(())
    }
    fn validate_fields(&self) -> Result<()> {
        if self.version != 1
            || self.suite != 3
            || !matches!(self.mode, 1 | 2)
            || !matches!(self.on_rotation, 1..=3)
            || self.late_inputs > 1
            || (self.n as u32) < 3 * self.f as u32 + 1
            || self.threshold == 0
            || (self.threshold != self.f + 1 && self.threshold != self.n - self.f)
            || (self.on_rotation == 2 && self.threshold != self.f + 1)
            || self.inputs == 0
            || self.not_before > self.expires
            || (self.mode == 1 && self.variants == 0)
            || (self.mode == 2 && self.generations == 0)
        {
            return Err(Error::Parameters);
        }
        if self.addr_type != 6 || self.intent.pin[0] != 3 {
            return Err(Error::Parameters);
        }
        let intent = &self.intent;
        if !(1..=2).contains(&intent.outputs.len())
            || intent.allowed.len() > 7
            || intent
                .outputs
                .iter()
                .filter(|o| o.amount == u128::MAX)
                .count()
                > 1
            || intent.grid_ratio[1] == 0
        {
            return Err(Error::Parameters);
        }
        let used = match intent.pin[0] {
            1 => 45,
            2 => 9,
            3 => 65,
            _ => return Err(Error::Encoding),
        };
        if intent.pin[used..].iter().any(|b| *b != 0) {
            return Err(Error::Encoding);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = vec![
            self.version,
            self.suite,
            self.mode,
            self.addr_type,
            self.on_rotation,
            self.late_inputs,
        ];
        for field in [
            &self.chain_id,
            &self.board_id,
            &self.owner_nonce,
            &self.keylist_hash,
            &self.builder_hash,
        ] {
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&encode_checked_point(self.public_key));
        out.extend_from_slice(&encode_checked_point(self.ephemeral));
        padded(&mut out, &self.address)?;
        for value in [self.epoch, self.not_before, self.expires] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.n,
            self.threshold,
            self.f,
            self.variants,
            self.inputs,
            self.generations,
            self.trigger_id,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.trigger_params);
        out.push(self.intent.outputs.len() as u8);
        for output in &self.intent.outputs {
            padded(&mut out, &output.script)?;
            out.extend_from_slice(&output.amount.to_be_bytes());
        }
        padded(&mut out, &self.intent.change_to)?;
        out.extend_from_slice(&self.intent.pin);
        out.push(self.intent.allowed.len() as u8);
        for allowed in &self.intent.allowed {
            out.extend_from_slice(allowed);
        }
        out.extend_from_slice(&self.intent.fee_ceiling.to_be_bytes());
        for value in [self.intent.fee_rule, self.intent.bump_delay] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.intent.grid_ratio);
        out.extend_from_slice(&self.intent.min_conf.to_be_bytes());
        Ok(out)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.byte()?;
        let suite = r.byte()?;
        let mode = r.byte()?;
        let addr_type = r.byte()?;
        let on_rotation = r.byte()?;
        let late_inputs = r.byte()?;
        let chain_id = r.array()?;
        let board_id = r.array()?;
        let owner_nonce = r.array()?;
        let keylist_hash = r.array()?;
        let builder_hash = r.array()?;
        let public_key = r.point()?;
        let ephemeral = r.point()?;
        let address = r.padded()?;
        let epoch = r.u64()?;
        let not_before = r.u64()?;
        let expires = r.u64()?;
        let n = r.u16()?;
        let threshold = r.u16()?;
        let f = r.u16()?;
        let variants = r.u16()?;
        let inputs = r.u16()?;
        let generations = r.u16()?;
        let trigger_id = r.u16()?;
        let trigger_params = r.array()?;
        let n_out = r.byte()?;
        if !(1..=2).contains(&n_out) {
            return Err(Error::Encoding);
        }
        let mut outputs = Vec::new();
        for _ in 0..n_out {
            outputs.push(Output {
                script: r.padded()?,
                amount: u128::from_be_bytes(r.array()?),
            });
        }
        let change_to = r.padded()?;
        let pin = r.array()?;
        let n_allowed = r.byte()?;
        if n_allowed > 7 {
            return Err(Error::Encoding);
        }
        let mut allowed = Vec::new();
        for _ in 0..n_allowed {
            allowed.push(r.array()?);
        }
        let intent = Intent {
            outputs,
            change_to,
            pin,
            allowed,
            fee_ceiling: u128::from_be_bytes(r.array()?),
            fee_rule: r.u16()?,
            bump_delay: r.u16()?,
            grid_ratio: r.array()?,
            min_conf: r.u16()?,
        };
        let header = Self {
            version,
            suite,
            mode,
            addr_type,
            on_rotation,
            late_inputs,
            chain_id,
            board_id,
            owner_nonce,
            keylist_hash,
            builder_hash,
            public_key,
            ephemeral,
            address,
            epoch,
            not_before,
            expires,
            n,
            threshold,
            f,
            variants,
            inputs,
            generations,
            trigger_id,
            trigger_params,
            intent,
        };
        header.validate_fields()?;
        Ok(header)
    }

    pub fn check_address(&self) -> Result<()> {
        let expected = encode_point(self.public_key)?[1..].to_vec();
        if self.address != expected {
            return Err(Error::Context);
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Encoding)?;
        let value = self.bytes.get(self.pos..end).ok_or(Error::Encoding)?;
        self.pos = end;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn point(&mut self) -> Result<EdwardsPoint> {
        decode_point(self.take(33)?)
    }
    pub fn scalar(&mut self) -> Result<Scalar> {
        decode_scalar(&self.array()?)
    }
    pub fn padded(&mut self) -> Result<Vec<u8>> {
        let len = self.byte()? as usize;
        let value = self.take(35)?;
        if len > 35 || value[len..].iter().any(|b| *b != 0) {
            return Err(Error::Encoding);
        }
        Ok(value[..len].to_vec())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub constant: EdwardsPoint,
    pub coefficients: Vec<EdwardsPoint>,
}
impl Commitment {
    pub fn evaluate(&self, node: u16) -> Result<EdwardsPoint> {
        if node == 0 {
            return Err(Error::Parameters);
        }
        let sum = self
            .coefficients
            .iter()
            .rev()
            .fold(EdwardsPoint::identity(), |sum, c| mul_node(sum + c, node));
        Ok(sum + self.constant)
    }
    pub fn verify(&self, node: u16, share: Scalar) -> bool {
        self.evaluate(node)
            .is_ok_and(|value| EdwardsPoint::mul_base(&share) == value)
    }
}
struct Polynomial(Vec<Scalar>);
impl Polynomial {
    fn random(constant: Scalar, threshold: u16, rng: &mut impl CryptoRngCore) -> Result<Self> {
        if threshold == 0 {
            return Err(Error::Threshold);
        }
        let mut coefficients = vec![constant];
        coefficients.extend((1..threshold).map(|_| random_nonzero(rng)));
        Ok(Self(coefficients))
    }
    fn evaluate(&self, node: u16) -> Scalar {
        let x = Scalar::from(node as u64);
        self.0.iter().rev().fold(Scalar::ZERO, |sum, c| sum * x + c)
    }
    fn commitments(&self) -> Vec<EdwardsPoint> {
        self.0[1..].iter().map(EdwardsPoint::mul_base).collect()
    }
}
// The branch and iteration count depend only on the public node index.
fn mul_node(point: EdwardsPoint, mut node: u16) -> EdwardsPoint {
    let mut sum = EdwardsPoint::identity();
    let mut multiple = point;
    while node != 0 {
        if node & 1 != 0 {
            sum += multiple;
        }
        multiple += multiple;
        node >>= 1;
    }
    sum
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrSlot {
    pub d: EdwardsPoint,
    pub e: EdwardsPoint,
    pub d_commitments: Vec<EdwardsPoint>,
    pub e_commitments: Vec<EdwardsPoint>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPoint {
    pub nonce: EdwardsPoint,
    pub commitments: Vec<EdwardsPoint>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deal {
    Open {
        x: Vec<EdwardsPoint>,
        slots: Vec<SchnorrSlot>,
    },
    Sealed(Vec<SealedPoint>),
}
impl Deal {
    pub fn encode(&self, header: &Header) -> Result<Vec<u8>> {
        header.validate()?;
        let count = header.inputs as usize
            * if header.mode == 1 {
                header.variants
            } else {
                header.generations
            } as usize;
        let mut bytes = Vec::new();
        let append = |cs: &[EdwardsPoint], bytes: &mut Vec<u8>| -> Result<()> {
            if cs.len() + 1 != header.threshold as usize {
                return Err(Error::Parameters);
            }
            for c in cs {
                bytes.extend_from_slice(&encode_point(*c)?);
            }
            Ok(())
        };
        match self {
            Self::Open { x, slots } if header.mode == 2 && slots.len() == count => {
                append(x, &mut bytes)?;
                for slot in slots {
                    bytes.extend_from_slice(&encode_point(slot.d)?);
                    bytes.extend_from_slice(&encode_point(slot.e)?);
                    append(&slot.d_commitments, &mut bytes)?;
                    append(&slot.e_commitments, &mut bytes)?;
                }
            }
            Self::Sealed(slots) if header.mode == 1 && slots.len() == count => {
                for slot in slots {
                    bytes.extend_from_slice(&encode_point(slot.nonce)?[1..]);
                    append(&slot.commitments, &mut bytes)?;
                }
            }
            _ => return Err(Error::Parameters),
        }
        Ok(bytes)
    }
    fn read(reader: &mut Reader<'_>, header: &Header) -> Result<Self> {
        let count = header.inputs as usize
            * if header.mode == 1 {
                header.variants
            } else {
                header.generations
            } as usize;
        if count > reader.remaining() / 32 {
            return Err(Error::Encoding);
        }
        let read_cs = |r: &mut Reader<'_>| -> Result<Vec<EdwardsPoint>> {
            let t = header.threshold as usize - 1;
            if t > r.remaining() / 33 {
                return Err(Error::Encoding);
            }
            (0..t).map(|_| r.point()).collect()
        };
        if header.mode == 1 {
            Ok(Self::Sealed(
                (0..count)
                    .map(|_| {
                        Ok(SealedPoint {
                            nonce: decode_compressed(&reader.array()?)?,
                            commitments: read_cs(reader)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            ))
        } else {
            Ok(Self::Open {
                x: read_cs(reader)?,
                slots: (0..count)
                    .map(|_| {
                        Ok(SchnorrSlot {
                            d: reader.point()?,
                            e: reader.point()?,
                            d_commitments: read_cs(reader)?,
                            e_commitments: read_cs(reader)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            })
        }
    }
    pub fn labels(&self, header: &Header) -> Result<Vec<SlotLabel>> {
        let mut labels = Vec::new();
        if header.mode == 2 {
            labels.push(SlotLabel::new(2, 4, 0, 0)?);
        }
        let count = if header.mode == 1 {
            header.variants
        } else {
            header.generations
        };
        for g in 1..=count {
            for input in 1..=header.inputs {
                if header.mode == 1 {
                    labels.push(SlotLabel::new(1, 1, g, input)?);
                } else {
                    labels.extend([
                        SlotLabel::new(2, 5, g, input)?,
                        SlotLabel::new(2, 6, g, input)?,
                    ]);
                }
            }
        }
        Ok(labels)
    }
    pub fn public_polynomials(
        &self,
        header: &Header,
        messages: &[Vec<u8>],
    ) -> Result<Vec<Commitment>> {
        let wire = self.encode(header)?;
        self.public_polynomials_wire(
            header,
            messages,
            &wire,
            &header.public_key.compress().to_bytes(),
        )
    }
    fn public_polynomials_wire(
        &self,
        header: &Header,
        messages: &[Vec<u8>],
        wire: &[u8],
        key: &[u8],
    ) -> Result<Vec<Commitment>> {
        let mut polynomials = Vec::new();
        let mut seen = BTreeSet::new();
        let mut unique = |bytes: &[u8]| -> Result<()> {
            // For Edwards points, equal x means equal y or opposite y. The
            // second choice differs by an order-2 point after negation, and
            // cannot occur between two prime-order points. Thus canonical
            // point equality detects x collisions in the checked subgroup.
            if !seen.insert(bytes.to_vec()) {
                return Err(Error::Nonce);
            }
            Ok(())
        };
        match self {
            Self::Open { x, slots } => {
                polynomials.push(Commitment {
                    constant: header.public_key,
                    coefficients: x.clone(),
                });
                let mut offset = x.len() * 33;
                for slot in slots {
                    unique(&wire[offset + 1..offset + 33])?;
                    unique(&wire[offset + 34..offset + 66])?;
                    offset += 66 + 33 * (slot.d_commitments.len() + slot.e_commitments.len());
                    polynomials.push(Commitment {
                        constant: slot.d,
                        coefficients: slot.d_commitments.clone(),
                    });
                    polynomials.push(Commitment {
                        constant: slot.e,
                        coefficients: slot.e_commitments.clone(),
                    });
                }
            }
            Self::Sealed(slots) => {
                if messages.len() != slots.len() {
                    return Err(Error::Context);
                }
                let mut offset = 0;
                for (slot, message) in slots.iter().zip(messages) {
                    let nonce = &wire[offset..offset + 32];
                    unique(nonce)?;
                    offset += 32 + 33 * slot.commitments.len();
                    let constant =
                        slot.nonce + header.public_key * challenge_bytes(nonce, key, message);
                    if constant.is_identity() {
                        return Err(Error::Point);
                    }
                    polynomials.push(Commitment {
                        constant,
                        coefficients: slot.commitments.clone(),
                    });
                }
            }
        }
        Ok(polynomials)
    }
}
pub fn share_pad(
    hd: &[u8; 32],
    node: u16,
    key: EdwardsPoint,
    dh: EdwardsPoint,
    label: SlotLabel,
) -> Result<Scalar> {
    if node == 0 {
        return Err(Error::Parameters);
    }
    Ok(share_pad_wire(
        hd,
        node,
        &encode_point(key)?,
        &encode_point(dh)?,
        label,
    ))
}
fn share_pad_wire(hd: &[u8; 32], node: u16, key: &[u8], dh: &[u8], label: SlotLabel) -> Scalar {
    hq(
        "LD1/enc",
        &[hd.as_slice(), &node.to_be_bytes(), key, dh, &label.bytes()].concat(),
    )
}
fn ciphertext_bytes(ciphertexts: &[Vec<Scalar>]) -> Vec<u8> {
    ciphertexts
        .iter()
        .flatten()
        .flat_map(|s| encode_scalar(*s))
        .collect()
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthProof {
    pub e_prime: EdwardsPoint,
    pub t_1: EdwardsPoint,
    pub t_2: EdwardsPoint,
    pub z_e: Scalar,
    pub t_a: EdwardsPoint,
    pub z_a: Scalar,
}

impl AuthProof {
    fn eph_input(
        hd: &[u8; 32],
        ct: &[u8],
        ephemeral: EdwardsPoint,
        domain: Option<ReshareDomain>,
    ) -> Result<Vec<u8>> {
        let mut data = proof_prefix(hd, ct, domain);
        data.extend_from_slice(&encode_point(ephemeral)?);
        Ok(data)
    }
    fn eph_challenge(&self, mut data: Vec<u8>, domain: Option<ReshareDomain>) -> Result<Scalar> {
        data.extend_from_slice(&encode_point(self.e_prime)?);
        data.extend_from_slice(&encode_point(self.t_1)?);
        data.extend_from_slice(&encode_point(self.t_2)?);
        Ok(hq(
            if domain.is_some() {
                "LD1/rs-ephpok"
            } else {
                "LD1/ephpok"
            },
            &data,
        ))
    }
    fn auth_challenge(
        &self,
        hd: &[u8; 32],
        ct: &[u8],
        domain: Option<ReshareDomain>,
    ) -> Result<Scalar> {
        let mut data = proof_prefix(hd, ct, domain);
        data.extend_from_slice(&encode_point(self.e_prime)?);
        data.extend_from_slice(&encode_point(self.t_1)?);
        data.extend_from_slice(&encode_point(self.t_2)?);
        data.extend_from_slice(&encode_scalar(self.z_e));
        data.extend_from_slice(&encode_point(self.t_a)?);
        Ok(hq(
            if domain.is_some() {
                "LD1/rs-auth"
            } else {
                "LD1/auth"
            },
            &data,
        ))
    }
    pub fn create(
        hd: &[u8; 32],
        ct: &[u8],
        ephemeral: Scalar,
        witness: Scalar,
        base: EdwardsPoint,
        domain: Option<ReshareDomain>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let input = Self::eph_input(hd, ct, EdwardsPoint::mul_base(&ephemeral), domain)?;
        let g_prime = hg(
            if domain.is_some() {
                "LD1/rs-eph"
            } else {
                "LD1/eph"
            },
            &input,
        )?;
        let a = random_nonzero(rng);
        let b = random_nonzero(rng);
        let mut proof = Self {
            e_prime: g_prime * ephemeral,
            t_1: EdwardsPoint::mul_base(&a),
            t_2: g_prime * a,
            z_e: Scalar::ZERO,
            t_a: mul_public_base(base, &b),
            z_a: Scalar::ZERO,
        };
        proof.z_e = a + proof.eph_challenge(input, domain)? * ephemeral;
        proof.z_a = b + proof.auth_challenge(hd, ct, domain)? * witness;
        Ok(proof)
    }
    pub fn verify(
        &self,
        hd: &[u8; 32],
        ct: &[u8],
        ephemeral: EdwardsPoint,
        base: EdwardsPoint,
        constant: EdwardsPoint,
        domain: Option<ReshareDomain>,
    ) -> Result<()> {
        encode_point(base)?;
        // Zero old shares imply an identity constant; this point is not sent.
        if domain.is_none() {
            encode_point(constant)?;
        }
        if domain.is_some() && !constant.is_torsion_free() {
            return Err(Error::Point);
        }
        let ephemeral_wire = encode_point(ephemeral)?;
        let proof_wire = self.encode()?;
        self.verify_wire(
            hd,
            ct,
            ephemeral,
            base,
            constant,
            domain,
            &ephemeral_wire,
            &proof_wire,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn verify_wire(
        &self,
        hd: &[u8; 32],
        ct: &[u8],
        ephemeral: EdwardsPoint,
        base: EdwardsPoint,
        constant: EdwardsPoint,
        domain: Option<ReshareDomain>,
        ephemeral_wire: &[u8],
        proof_wire: &[u8],
    ) -> Result<()> {
        let mut input = proof_prefix(hd, ct, domain);
        input.extend_from_slice(ephemeral_wire);
        let g_prime = hg(
            if domain.is_some() {
                "LD1/rs-eph"
            } else {
                "LD1/eph"
            },
            &input,
        )?;
        input.extend_from_slice(&proof_wire[..99]);
        let c_e = hq(
            if domain.is_some() {
                "LD1/rs-ephpok"
            } else {
                "LD1/ephpok"
            },
            &input,
        );
        let mut auth = proof_prefix(hd, ct, domain);
        auth.extend_from_slice(&proof_wire[..164]);
        let c_a = hq(
            if domain.is_some() {
                "LD1/rs-auth"
            } else {
                "LD1/auth"
            },
            &auth,
        );
        if EdwardsPoint::mul_base(&self.z_e) != self.t_1 + ephemeral * c_e
            || g_prime * self.z_e != self.t_2 + self.e_prime * c_e
            || mul_public_base(base, &self.z_a) != self.t_a + constant * c_a
        {
            return Err(Error::Proof);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok([
            &encode_point(self.e_prime)?[..],
            &encode_point(self.t_1)?,
            &encode_point(self.t_2)?,
            &encode_scalar(self.z_e),
            &encode_point(self.t_a)?,
            &encode_scalar(self.z_a),
        ]
        .concat())
    }
}

#[derive(Clone, Debug)]
pub struct OwnerMessage {
    pub header: Header,
    pub deal: Deal,
    pub ciphertexts: Vec<Vec<Scalar>>,
    pub proof: AuthProof,
    wire: Option<Arc<DecodedWire>>,
}
#[derive(Clone, Debug)]
struct DecodedWire {
    snapshot: OwnerMessage,
    bytes: Vec<u8>,
    header_end: usize,
    deal_end: usize,
}
impl PartialEq for OwnerMessage {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.deal == other.deal
            && self.ciphertexts == other.ciphertexts
            && self.proof == other.proof
    }
}
impl Eq for OwnerMessage {}
impl OwnerMessage {
    /// Build a mutable message; encoding and acceptance validate all public points.
    pub fn new(
        header: Header,
        deal: Deal,
        ciphertexts: Vec<Vec<Scalar>>,
        proof: AuthProof,
    ) -> Self {
        Self {
            header,
            deal,
            ciphertexts,
            proof,
            wire: None,
        }
    }
    fn decoded_wire(&self) -> Option<&DecodedWire> {
        self.wire.as_deref().filter(|wire| self == &wire.snapshot)
    }
    fn wire_bytes(&self) -> Result<Cow<'_, [u8]>> {
        match self.decoded_wire() {
            Some(wire) => Ok(Cow::Borrowed(&wire.bytes)),
            None => Ok(Cow::Owned(self.encode()?)),
        }
    }
    pub fn hd(&self) -> Result<[u8; 32]> {
        if let Some(wire) = self.decoded_wire() {
            return dealing_digest(
                &wire.bytes[..wire.header_end],
                &wire.bytes[wire.header_end..wire.deal_end],
            );
        }
        dealing_digest(&self.header.encode()?, &self.deal.encode(&self.header)?)
    }
    pub fn rid(&self) -> Result<[u8; 32]> {
        let key = match self.decoded_wire() {
            Some(wire) => wire.bytes[KEY_OFFSET..EPHEMERAL_OFFSET]
                .try_into()
                .expect("header point"),
            None => encode_point(self.header.public_key)?,
        };
        let tie = if self.header.mode == 1 {
            self.hd()?
        } else {
            [0; 32]
        };
        Ok(h(
            "LD1/rid",
            &[
                self.header.chain_id.as_slice(),
                &self.header.board_id,
                &key,
                &self.header.owner_nonce,
                &tie,
            ]
            .concat(),
        ))
    }
    pub fn mid(&self) -> Result<[u8; 32]> {
        Ok(h("LD1/mid", &self.wire_bytes()?))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if let Some(wire) = self.decoded_wire() {
            return Ok(wire.bytes.clone());
        }
        let mut bytes = self.header.encode()?;
        bytes.extend(self.deal.encode(&self.header)?);
        let count = self.deal.labels(&self.header)?.len();
        if self.ciphertexts.len() != self.header.n as usize
            || self.ciphertexts.iter().any(|row| row.len() != count)
        {
            return Err(Error::Encoding);
        }
        bytes.extend(ciphertext_bytes(&self.ciphertexts));
        bytes.extend(self.proof.encode()?);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let header = Header::read(&mut reader)?;
        let header_end = bytes.len() - reader.remaining();
        let deal = Deal::read(&mut reader, &header)?;
        let deal_end = bytes.len() - reader.remaining();
        let count = deal.labels(&header)?.len();
        let size = (header.n as usize)
            .checked_mul(count)
            .and_then(|n| n.checked_mul(32))
            .and_then(|n| n.checked_add(196))
            .ok_or(Error::Encoding)?;
        if reader.remaining() != size {
            return Err(Error::Encoding);
        }
        let ciphertexts = (0..header.n)
            .map(|_| {
                (0..count)
                    .map(|_| reader.scalar())
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<_>>()?;
        let proof = AuthProof {
            e_prime: reader.point()?,
            t_1: reader.point()?,
            t_2: reader.point()?,
            z_e: reader.scalar()?,
            t_a: reader.point()?,
            z_a: reader.scalar()?,
        };
        if reader.remaining() != 0 {
            return Err(Error::Encoding);
        }
        let mut message = Self::new(header, deal, ciphertexts, proof);
        message.wire = Some(Arc::new(DecodedWire {
            snapshot: message.clone(),
            bytes: bytes.to_vec(),
            header_end,
            deal_end,
        }));
        Ok(message)
    }
    pub fn step_a(&self, context: &impl AcceptanceContext) -> Result<Accepted> {
        let bytes = self.wire_bytes()?;
        // Obtain validated wire spans even for a mutable, locally built message.
        let checked;
        let wire = match self.decoded_wire() {
            Some(wire) => wire,
            None => {
                checked = Self::decode(&bytes)?;
                checked.decoded_wire().expect("just decoded")
            }
        };
        if self.header.address != wire.bytes[KEY_OFFSET + 1..EPHEMERAL_OFFSET] {
            return Err(Error::Context);
        }
        let h = &self.header;
        let hd = dealing_digest(
            &wire.bytes[..wire.header_end],
            &wire.bytes[wire.header_end..wire.deal_end],
        )?;
        let current = context.committee();
        if h.chain_id != current.chain_id
            || h.board_id != current.board_id
            || h.epoch != current.epoch
            || h.keylist_hash != current.keylist_hash
            || h.n != current.n
            || h.f != current.f
            || current.board_height > h.expires
            || (h.on_rotation == 1 && h.expires > current.grace_end)
        {
            return Err(Error::Context);
        }
        context.check_header(h)?;
        let tie = if h.mode == 1 { hd } else { [0; 32] };
        let rid = crate::hash::h(
            "LD1/rid",
            &[
                h.chain_id.as_slice(),
                &h.board_id,
                &wire.bytes[KEY_OFFSET..EPHEMERAL_OFFSET],
                &h.owner_nonce,
                &tie,
            ]
            .concat(),
        );
        if context.is_bound_or_tombstoned(&rid) {
            return Err(Error::Context);
        }
        let messages = if h.mode == 1 {
            context.sealed_messages(h)?
        } else {
            Vec::new()
        };
        let polynomials = self.deal.public_polynomials_wire(
            h,
            &messages,
            &wire.bytes[wire.header_end..wire.deal_end],
            &wire.bytes[KEY_OFFSET + 1..EPHEMERAL_OFFSET],
        )?;
        let constant = if h.mode == 1 {
            polynomials[0].constant
        } else {
            h.public_key
        };
        self.proof.verify_wire(
            &hd,
            &wire.bytes[wire.deal_end..wire.bytes.len() - 196],
            h.ephemeral,
            G,
            constant,
            None,
            &wire.bytes[EPHEMERAL_OFFSET..HEADER_POINTS_END],
            &wire.bytes[wire.bytes.len() - 196..],
        )?;
        let keys = context.node_keys();
        if keys.len() != h.n as usize {
            return Err(Error::Context);
        }
        for key in keys {
            encode_point(*key)?;
        }
        Ok(Accepted {
            message: {
                let mut message = self.clone();
                message.wire = Some(Arc::new(wire.clone()));
                message
            },
            polynomials,
            sealed_messages: messages,
            keys: keys.to_vec(),
        })
    }
}
/// The caller supplies current registry and board state, validates its builder,
/// and recomputes sealed messages from intent. No chain adapter is supplied here.
pub trait AcceptanceContext {
    fn committee(&self) -> CommitteeState;
    fn check_header(&self, header: &Header) -> Result<()>;
    fn is_bound_or_tombstoned(&self, rid: &[u8; 32]) -> bool;
    fn sealed_messages(&self, header: &Header) -> Result<Vec<Vec<u8>>>;
    fn node_keys(&self) -> &[EdwardsPoint];
}
#[derive(Clone)]
pub struct Accepted {
    message: OwnerMessage,
    polynomials: Vec<Commitment>,
    sealed_messages: Vec<Vec<u8>>,
    keys: Vec<EdwardsPoint>,
}
#[derive(Clone)]
pub struct NodeShares {
    node: u16,
    values: Vec<Scalar>,
    hd: [u8; 32],
}
impl NodeShares {
    pub fn node(&self) -> u16 {
        self.node
    }
    pub fn values(&self) -> &[Scalar] {
        &self.values
    }
}
impl Accepted {
    pub fn message(&self) -> &OwnerMessage {
        &self.message
    }
    pub fn polynomials(&self) -> &[Commitment] {
        &self.polynomials
    }
    pub fn decrypt(&self, node: u16, secret: Scalar) -> Result<NodeShares> {
        if node == 0 || node > self.message.header.n {
            return Err(Error::Parameters);
        }
        let key = self.keys[node as usize - 1];
        if EdwardsPoint::mul_base(&secret) != key {
            return Err(Error::Share);
        }
        let hd = self.message.hd()?;
        let dh = self.message.header.ephemeral * secret;
        let key_wire = encode_checked_point(key);
        let dh_wire = encode_checked_point(dh);
        let labels = self.message.deal.labels(&self.message.header)?;
        let mut values = Vec::new();
        for ((ct, label), polynomial) in self.message.ciphertexts[node as usize - 1]
            .iter()
            .zip(labels)
            .zip(&self.polynomials)
        {
            let share = ct - share_pad_wire(&hd, node, &key_wire, &dh_wire, label);
            if !polynomial.verify(node, share) {
                return Err(Error::Share);
            }
            values.push(share);
        }
        Ok(NodeShares { node, values, hd })
    }
}

pub struct Owner {
    header: Header,
    deal: Deal,
    polynomials: Vec<Polynomial>,
    witness: Scalar,
}
impl Owner {
    pub fn open(
        mut header: Header,
        seed: [u8; 32],
        nonces: &[(Scalar, Scalar)],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if header.mode != 2 || header.suite != 3 {
            return Err(Error::Parameters);
        }
        let secret = secret_from_seed(&seed);
        header.public_key = EdwardsPoint::mul_base(&secret);
        header.validate()?;
        let x = Polynomial::random(secret, header.threshold, rng)?;
        let x_commitments = x.commitments();
        let mut polynomials = vec![x];
        let mut slots = Vec::new();
        for (d, e) in nonces {
            let pd = Polynomial::random(*d, header.threshold, rng)?;
            let pe = Polynomial::random(*e, header.threshold, rng)?;
            slots.push(SchnorrSlot {
                d: EdwardsPoint::mul_base(d),
                e: EdwardsPoint::mul_base(e),
                d_commitments: pd.commitments(),
                e_commitments: pe.commitments(),
            });
            polynomials.extend([pd, pe]);
        }
        let deal = Deal::Open {
            x: x_commitments,
            slots,
        };
        deal.public_polynomials(&header, &[])?;
        Ok(Self {
            header,
            deal,
            polynomials,
            witness: secret,
        })
    }
    /// Deal existing standard Ed25519 signatures, without importing the key.
    pub fn sealed(
        header: Header,
        signatures: &[(Vec<u8>, Signature)],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if header.mode != 1 || header.suite != 3 {
            return Err(Error::Parameters);
        }
        header.validate()?;
        let key = VerifyingKey::from_bytes(&header.public_key.compress().to_bytes())
            .map_err(|_| Error::Point)?;
        let mut polynomials = Vec::new();
        let mut slots = Vec::new();
        let mut messages = Vec::new();
        for (message, signature) in signatures {
            key.verify_strict(message, signature)
                .map_err(|_| Error::Signature)?;
            let bytes = signature.to_bytes();
            let nonce = decode_compressed(bytes[..32].try_into().map_err(|_| Error::Encoding)?)?;
            let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(
                bytes[32..].try_into().map_err(|_| Error::Encoding)?,
            ))
            .ok_or(Error::Scalar)?;
            let p = Polynomial::random(scalar, header.threshold, rng)?;
            slots.push(SealedPoint {
                nonce,
                commitments: p.commitments(),
            });
            polynomials.push(p);
            messages.push(message.clone());
        }
        let deal = Deal::Sealed(slots);
        deal.public_polynomials(&header, &messages)?;
        let witness = polynomials.first().ok_or(Error::Parameters)?.0[0];
        Ok(Self {
            header,
            deal,
            polynomials,
            witness,
        })
    }
    pub fn encrypt(
        mut self,
        ephemeral: Scalar,
        keys: &[EdwardsPoint],
        rng: &mut impl CryptoRngCore,
    ) -> Result<OwnerMessage> {
        self.header.ephemeral = EdwardsPoint::mul_base(&ephemeral);
        self.header.check_address()?;
        if keys.len() != self.header.n as usize {
            return Err(Error::Parameters);
        }
        let hd = dealing_digest(&self.header.encode()?, &self.deal.encode(&self.header)?)?;
        let labels = self.deal.labels(&self.header)?;
        let mut ciphertexts = Vec::new();
        for (offset, key) in keys.iter().enumerate() {
            let node = offset as u16 + 1;
            let dh = key * ephemeral;
            ciphertexts.push(
                self.polynomials
                    .iter()
                    .zip(&labels)
                    .map(
                        |(p, label)| Ok(p.evaluate(node) + share_pad(&hd, node, *key, dh, *label)?),
                    )
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        let proof = AuthProof::create(
            &hd,
            &ciphertext_bytes(&ciphertexts),
            ephemeral,
            self.witness,
            G,
            None,
            rng,
        )?;
        Ok(OwnerMessage {
            header: self.header,
            deal: self.deal,
            ciphertexts,
            proof,
            wire: None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partial {
    pub node: u16,
    pub value: Scalar,
}
pub struct Combined(pub Signature);
impl Combined {
    pub fn verify(&self, key: EdwardsPoint, message: &[u8]) -> Result<()> {
        encode_point(key)?;
        decode_compressed(self.0.r_bytes())?;
        VerifyingKey::from_bytes(&key.compress().to_bytes())
            .map_err(|_| Error::Point)?
            .verify_strict(message, &self.0)
            .map_err(|_| Error::Signature)
    }
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}
#[derive(Clone)]
pub struct SigningPackage {
    hd: [u8; 32],
    threshold: usize,
    n: u16,
    public_key: EdwardsPoint,
    message: Vec<u8>,
    nonce: EdwardsPoint,
    terms: Vec<(usize, Scalar, Commitment)>,
}
impl Accepted {
    /// Cryptographic operations for a caller-established lock or sealed release.
    /// The caller must prevent signing two digests with the same nonce shares.
    pub fn signing_package(
        &self,
        generation: u16,
        input: u16,
        message: &[u8],
        digest: [u8; 32],
    ) -> Result<SigningPackage> {
        let header = &self.message.header;
        let count = if header.mode == 1 {
            header.variants
        } else {
            header.generations
        };
        if generation == 0 || generation > count || input == 0 || input > header.inputs {
            return Err(Error::Parameters);
        }
        let index = (generation as usize - 1) * header.inputs as usize + input as usize - 1;
        let hd = self.message.hd()?;
        let mut terms = Vec::new();
        let mut add =
            |index: usize, factor| terms.push((index, factor, self.polynomials[index].clone()));
        let nonce = match &self.message.deal {
            Deal::Open { slots, .. } => {
                let slot = &slots[index];
                let rho = binding_factor(&hd, generation, input, &digest);
                let nonce = slot.d + slot.e * rho;
                if nonce.is_identity() {
                    return Err(Error::Point);
                }
                let key_wire = &self.message.decoded_wire().expect("accepted wire").bytes
                    [KEY_OFFSET + 1..EPHEMERAL_OFFSET];
                add(
                    0,
                    challenge_bytes(nonce.compress().as_bytes(), key_wire, message),
                );
                add(1 + 2 * index, Scalar::ONE);
                add(2 + 2 * index, rho);
                nonce
            }
            Deal::Sealed(slots) => {
                if message != self.sealed_messages[index] {
                    return Err(Error::Context);
                }
                add(index, Scalar::ONE);
                slots[index].nonce
            }
        };
        Ok(SigningPackage {
            hd,
            threshold: header.threshold as usize,
            n: header.n,
            public_key: header.public_key,
            message: message.to_vec(),
            nonce,
            terms,
        })
    }
}
impl SigningPackage {
    pub fn nonce(&self) -> EdwardsPoint {
        self.nonce
    }
    pub fn partial(&self, shares: &NodeShares) -> Result<Partial> {
        if shares.hd != self.hd || shares.node == 0 || shares.node > self.n {
            return Err(Error::Share);
        }
        let mut value = Scalar::ZERO;
        for (index, factor, _) in &self.terms {
            value += factor * shares.values.get(*index).ok_or(Error::Share)?;
        }
        let partial = Partial {
            node: shares.node,
            value,
        };
        if !self.verify_partial(&partial) {
            return Err(Error::Share);
        }
        Ok(partial)
    }
    pub fn verify_partial(&self, partial: &Partial) -> bool {
        if partial.node == 0 || partial.node > self.n {
            return false;
        }
        let expected =
            self.terms
                .iter()
                .try_fold(EdwardsPoint::identity(), |sum, (_, factor, commitment)| {
                    Ok::<_, Error>(sum + commitment.evaluate(partial.node)? * factor)
                });
        expected.is_ok_and(|point| EdwardsPoint::mul_base(&partial.value) == point)
    }
    /// Optimistic interpolation, followed by independent strict Ed25519 verification.
    pub fn combine(&self, partials: &[Partial]) -> Result<Combined> {
        self.combine_with_faults(partials)
            .map(|(combined, _)| combined)
    }
    /// Return the signature and every bad node found after a failed interpolation.
    pub fn combine_with_faults(&self, partials: &[Partial]) -> Result<(Combined, Vec<u16>)> {
        if partials.len() < self.threshold {
            return Err(Error::Threshold);
        }
        if partials.iter().any(|p| p.node == 0 || p.node > self.n) {
            return Err(Error::Share);
        }
        let mut unique = BTreeSet::new();
        if partials.iter().any(|p| !unique.insert(p.node)) {
            return Err(Error::Threshold);
        }
        if let Ok(signature) = self.interpolate(partials) {
            return Ok((signature, Vec::new()));
        }
        let mut faults = Vec::new();
        let good: Vec<_> = partials
            .iter()
            .copied()
            .filter(|partial| {
                if self.verify_partial(partial) {
                    true
                } else {
                    faults.push(partial.node);
                    false
                }
            })
            .collect();
        if faults.is_empty() {
            return Err(Error::Signature);
        }
        if good.len() < self.threshold {
            return Err(Error::BadPartial(faults[0]));
        }
        Ok((self.interpolate(&good)?, faults))
    }
    fn interpolate(&self, partials: &[Partial]) -> Result<Combined> {
        let mut s = Scalar::ZERO;
        for p in partials {
            let i = Scalar::from(p.node as u64);
            let mut numerator = Scalar::ONE;
            let mut denominator = Scalar::ONE;
            for other in partials {
                if other.node != p.node {
                    let j = Scalar::from(other.node as u64);
                    numerator *= -j;
                    denominator *= i - j;
                }
            }
            s += p.value * numerator * denominator.invert();
        }
        if s == Scalar::ZERO {
            return Err(Error::Signature);
        }
        let signature = Signature::from_components(self.nonce.compress().to_bytes(), s.to_bytes());
        let combined = Combined(signature);
        combined.verify(self.public_key, &self.message)?;
        Ok(combined)
    }
}

/// Public DH proof. Construct only after Step A (or transfer verification).
#[derive(Clone, Debug)]
pub struct DhProof {
    pub key: EdwardsPoint,
    pub t_1: EdwardsPoint,
    pub t_2: EdwardsPoint,
    pub z: Scalar,
    wire: Option<Arc<DecodedDhWire>>,
}
#[derive(Clone, Debug)]
struct DecodedDhWire {
    key: EdwardsPoint,
    t_1: EdwardsPoint,
    t_2: EdwardsPoint,
    z: Scalar,
    bytes: [u8; 131],
}
impl DhProof {
    /// Build a mutable proof; encoding and verification validate its public points.
    pub fn new(key: EdwardsPoint, t_1: EdwardsPoint, t_2: EdwardsPoint, z: Scalar) -> Self {
        Self {
            key,
            t_1,
            t_2,
            z,
            wire: None,
        }
    }
    fn wire_bytes(&self) -> Result<Cow<'_, [u8]>> {
        if let Some(wire) = &self.wire {
            if self.key == wire.key
                && self.t_1 == wire.t_1
                && self.t_2 == wire.t_2
                && self.z == wire.z
            {
                return Ok(Cow::Borrowed(&wire.bytes));
            }
        }
        Ok(Cow::Owned(self.encode_points()?))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.wire_bytes()?.into_owned())
    }
    fn encode_points(&self) -> Result<Vec<u8>> {
        Ok([
            encode_point(self.key)?.as_slice(),
            &encode_point(self.t_1)?,
            &encode_point(self.t_2)?,
            &encode_scalar(self.z),
        ]
        .concat())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 131 {
            return Err(Error::Encoding);
        }
        let mut reader = Reader::new(bytes);
        let mut proof = Self::new(
            reader.point()?,
            reader.point()?,
            reader.point()?,
            reader.scalar()?,
        );
        proof.wire = Some(Arc::new(DecodedDhWire {
            key: proof.key,
            t_1: proof.t_1,
            t_2: proof.t_2,
            z: proof.z,
            bytes: bytes.try_into().expect("checked proof size"),
        }));
        Ok(proof)
    }

    pub fn create(
        mid: &[u8; 32],
        pk: EdwardsPoint,
        ephemeral: EdwardsPoint,
        secret: Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        encode_point(pk)?;
        encode_point(ephemeral)?;
        if EdwardsPoint::mul_base(&secret) != pk {
            return Err(Error::Share);
        }
        let a = random_nonzero(rng);
        let mut proof = Self {
            key: ephemeral * secret,
            t_1: EdwardsPoint::mul_base(&a),
            t_2: ephemeral * a,
            z: Scalar::ZERO,
            wire: None,
        };
        proof.z = a + proof.challenge(mid, pk, ephemeral)? * secret;
        Ok(proof)
    }
    fn challenge(
        &self,
        mid: &[u8; 32],
        pk: EdwardsPoint,
        ephemeral: EdwardsPoint,
    ) -> Result<Scalar> {
        let wire = self.wire_bytes()?;
        let mut generator = [0; 33];
        generator[1..].copy_from_slice(ED25519_BASEPOINT_COMPRESSED.as_bytes());
        Ok(hq(
            "LD1/dleq",
            &[
                generator.as_slice(),
                &encode_point(pk)?,
                &encode_point(ephemeral)?,
                &wire[..99],
                mid,
            ]
            .concat(),
        ))
    }
    pub fn verify(&self, mid: &[u8; 32], pk: EdwardsPoint, ephemeral: EdwardsPoint) -> Result<()> {
        let c = self.challenge(mid, pk, ephemeral)?;
        if EdwardsPoint::mul_base(&self.z) != self.t_1 + pk * c
            || ephemeral * self.z != self.t_2 + self.key * c
        {
            return Err(Error::Proof);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Complaint {
    pub node: u16,
    pub proof: DhProof,
}
impl Accepted {
    /// A DH value is revealed only for an authenticated dealing with bad delivery.
    pub fn complain(
        &self,
        node: u16,
        secret: Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Complaint> {
        if node == 0 || usize::from(node) > self.keys.len() {
            return Err(Error::Parameters);
        }
        let proof = DhProof::create(
            &self.message.mid()?,
            self.keys[usize::from(node) - 1],
            self.message.header.ephemeral,
            secret,
            rng,
        )?;
        let complaint = Complaint { node, proof };
        self.verify_complaint(&complaint)?;
        Ok(complaint)
    }
    pub fn verify_complaint(&self, complaint: &Complaint) -> Result<()> {
        let node = complaint.node;
        if node == 0 || usize::from(node) > self.keys.len() {
            return Err(Error::Parameters);
        }
        let pk = self.keys[usize::from(node) - 1];
        complaint
            .proof
            .verify(&self.message.mid()?, pk, self.message.header.ephemeral)?;
        let hd = self.message.hd()?;
        let labels = self.message.deal.labels(&self.message.header)?;
        for ((ct, label), polynomial) in self.message.ciphertexts[usize::from(node) - 1]
            .iter()
            .zip(labels)
            .zip(&self.polynomials)
        {
            let share = *ct - share_pad(&hd, node, pk, complaint.proof.key, label)?;
            if !polynomial.verify(node, share) {
                return Ok(());
            }
        }
        Err(Error::Share)
    }
}

#[path = "ed25519_reshare.rs"]
pub mod reshare;
