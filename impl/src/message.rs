use crate::{
    algebra::*,
    hash::*,
    wire::{Header, Reader},
    Error, Result,
};
use k256::{elliptic_curve::rand_core::CryptoRngCore, ProjectivePoint, Scalar};
use std::{borrow::Cow, collections::BTreeSet, sync::Arc};

const G: ProjectivePoint = ProjectivePoint::GENERATOR;
const KEY_OFFSET: usize = 6 + 5 * 32;
const EPHEMERAL_OFFSET: usize = KEY_OFFSET + 33;
const HEADER_POINTS_END: usize = EPHEMERAL_OFFSET + 33;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaSlot {
    pub nonce: ProjectivePoint,
    pub w: Vec<ProjectivePoint>,
    pub mu: Vec<ProjectivePoint>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrSlot {
    pub d: ProjectivePoint,
    pub e: ProjectivePoint,
    pub d_commitments: Vec<ProjectivePoint>,
    pub e_commitments: Vec<ProjectivePoint>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPoint {
    pub nonce: ProjectivePoint,
    pub commitments: Vec<ProjectivePoint>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deal {
    OpenEcdsa(Vec<EcdsaSlot>),
    OpenBip340 {
        x: Vec<ProjectivePoint>,
        slots: Vec<SchnorrSlot>,
    },
    Sealed(Vec<SealedPoint>),
}

impl Deal {
    pub fn encode(&self, header: &Header) -> Result<Vec<u8>> {
        header.validate()?;
        let t = header.threshold as usize - 1;
        let mut points = Vec::new();
        let commitments = |cs: &[ProjectivePoint], points: &mut Vec<_>| -> Result<()> {
            if cs.len() != t {
                return Err(Error::Parameters);
            }
            points.extend_from_slice(cs);
            Ok(())
        };
        let slots = header.inputs as usize
            * if header.mode == 1 {
                header.variants
            } else {
                header.generations
            } as usize;
        match self {
            Self::OpenEcdsa(values)
                if header.mode == 2 && header.suite == 1 && values.len() == slots =>
            {
                for s in values {
                    points.push(s.nonce);
                    commitments(&s.w, &mut points)?;
                    commitments(&s.mu, &mut points)?;
                }
            }
            Self::OpenBip340 { x, slots: values }
                if header.mode == 2 && header.suite == 2 && values.len() == slots =>
            {
                commitments(x, &mut points)?;
                for s in values {
                    points.push(s.d);
                    points.push(s.e);
                    commitments(&s.d_commitments, &mut points)?;
                    commitments(&s.e_commitments, &mut points)?;
                }
            }
            Self::Sealed(values) if header.mode == 1 && values.len() == slots => {
                for s in values {
                    points.push(s.nonce);
                    commitments(&s.commitments, &mut points)?;
                }
            }
            _ => return Err(Error::Parameters),
        }
        let mut out = Vec::new();
        for (index, encoded) in encode_points(&points)?.iter().enumerate() {
            if header.mode == 1 && header.suite == 2 && index % (t + 1) == 0 {
                if encoded[0] == 3 {
                    return Err(Error::Nonce);
                }
                out.extend_from_slice(&encoded[1..]);
            } else {
                out.extend_from_slice(encoded);
            }
        }
        Ok(out)
    }

    fn read(r: &mut Reader<'_>, header: &Header) -> Result<Self> {
        let count = header.inputs as usize
            * if header.mode == 1 {
                header.variants
            } else {
                header.generations
            } as usize;
        let t = header.threshold as usize - 1;
        let read_cs = |r: &mut Reader<'_>| -> Result<Vec<ProjectivePoint>> {
            if t > r.remaining() / 33 {
                return Err(Error::Encoding);
            }
            (0..t).map(|_| r.point()).collect()
        };
        if count > r.remaining() / 32 {
            return Err(Error::Encoding);
        }
        Ok(match (header.mode, header.suite) {
            (1, suite) => Self::Sealed(
                (0..count)
                    .map(|_| {
                        Ok(SealedPoint {
                            nonce: if suite == 2 {
                                lift_x(&r.array()?)?
                            } else {
                                r.point()?
                            },
                            commitments: read_cs(r)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            ),
            (2, 1) => Self::OpenEcdsa(
                (0..count)
                    .map(|_| {
                        Ok(EcdsaSlot {
                            nonce: r.point()?,
                            w: read_cs(r)?,
                            mu: read_cs(r)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            ),
            (2, 2) => Self::OpenBip340 {
                x: read_cs(r)?,
                slots: (0..count)
                    .map(|_| {
                        Ok(SchnorrSlot {
                            d: r.point()?,
                            e: r.point()?,
                            d_commitments: read_cs(r)?,
                            e_commitments: read_cs(r)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            },
            _ => return Err(Error::Parameters),
        })
    }

    pub fn labels(&self, header: &Header) -> Result<Vec<SlotLabel>> {
        let mut labels = Vec::new();
        if matches!(self, Self::OpenBip340 { .. }) {
            labels.push(SlotLabel::new(2, 4, 0, 0)?);
        }
        let count = if header.mode == 1 {
            header.variants
        } else {
            header.generations
        };
        for g in 1..=count {
            for input in 1..=header.inputs {
                let components: &[u8] = match self {
                    Self::Sealed(_) => &[1],
                    Self::OpenEcdsa(_) => &[2, 3],
                    Self::OpenBip340 { .. } => &[5, 6],
                };
                for component in components {
                    labels.push(SlotLabel::new(header.mode, *component, g, input)?);
                }
            }
        }
        Ok(labels)
    }

    /// Compute all constant terms locally, never from transmitted commitments.
    pub fn public_polynomials(
        &self,
        header: &Header,
        messages: &[[u8; 32]],
    ) -> Result<Vec<Commitment>> {
        let wire = self.encode(header)?;
        let key = encode_point(header.public_key)?;
        self.public_polynomials_wire(
            header,
            messages,
            &wire,
            key[1..].try_into().expect("point width"),
        )
    }

    fn public_polynomials_wire(
        &self,
        header: &Header,
        messages: &[[u8; 32]],
        wire: &[u8],
        key_x: &[u8; 32],
    ) -> Result<Vec<Commitment>> {
        let mut result = Vec::new();
        let mut nonces = BTreeSet::new();
        let mut nonce = |x: &[u8]| -> Result<()> {
            if !nonces.insert(x.to_vec()) {
                return Err(Error::Nonce);
            }
            Ok(())
        };
        let commitment = |base, constant, coefficients: &Vec<_>| Commitment {
            base,
            constant,
            coefficients: coefficients.clone(),
        };
        match self {
            Self::OpenEcdsa(slots) => {
                let mut offset = 0;
                for slot in slots {
                    let x = wire[offset + 1..offset + 33]
                        .try_into()
                        .expect("point width");
                    ecdsa_r_x(x)?;
                    nonce(x)?;
                    offset += 33 * (1 + slot.w.len() + slot.mu.len());
                    result.push(commitment(slot.nonce, G, &slot.w));
                    result.push(commitment(slot.nonce, header.public_key, &slot.mu));
                }
            }
            Self::OpenBip340 { x, slots } => {
                result.push(commitment(G, header.public_key, x));
                let mut offset = 33 * x.len();
                for slot in slots {
                    nonce(&wire[offset + 1..offset + 33])?;
                    nonce(&wire[offset + 34..offset + 66])?;
                    offset += 33 * (2 + slot.d_commitments.len() + slot.e_commitments.len());
                    result.push(commitment(G, slot.d, &slot.d_commitments));
                    result.push(commitment(G, slot.e, &slot.e_commitments));
                }
            }
            Self::Sealed(slots) => {
                if messages.len() != slots.len() {
                    return Err(Error::Parameters);
                }
                let mut offset = 0;
                for (slot, message) in slots.iter().zip(messages) {
                    let width = if header.suite == 1 { 33 } else { 32 };
                    let x: &[u8; 32] = wire[offset + width - 32..offset + width]
                        .try_into()
                        .expect("point width");
                    nonce(x)?;
                    offset += width + 33 * slot.commitments.len();
                    let (base, constant) = if header.suite == 1 {
                        (
                            slot.nonce,
                            mul_generator(reduce(message)) + header.public_key * ecdsa_r_x(x)?,
                        )
                    } else {
                        (
                            G,
                            slot.nonce + header.public_key * bip340_challenge(x, key_x, message),
                        )
                    };
                    if constant == ProjectivePoint::IDENTITY {
                        return Err(Error::Point);
                    }
                    result.push(commitment(base, constant, &slot.commitments));
                }
            }
        }
        Ok(result)
    }
}

/// Step A requires x(R) < q as well as r != 0, excluding recovery overflow.
pub fn ecdsa_r(nonce: ProjectivePoint) -> Result<Scalar> {
    ecdsa_r_x(&x_bytes(nonce)?)
}

fn ecdsa_r_x(x: &[u8; 32]) -> Result<Scalar> {
    let r = decode_scalar(x).map_err(|_| Error::Nonce)?;
    if r == Scalar::ZERO {
        return Err(Error::Nonce);
    }
    Ok(r)
}

pub fn share_pad(
    hd: &[u8; 32],
    node: u16,
    public_key: ProjectivePoint,
    dh: ProjectivePoint,
    label: SlotLabel,
    domain: Option<ReshareDomain>,
) -> Result<Scalar> {
    if node == 0 {
        return Err(Error::Parameters);
    }
    let points = encode_points(&[public_key, dh])?;
    Ok(share_pad_wire(
        hd, node, &points[0], &points[1], label, domain,
    ))
}

fn share_pad_wire(
    hd: &[u8; 32],
    node: u16,
    public_key: &[u8],
    dh: &[u8],
    label: SlotLabel,
    domain: Option<ReshareDomain>,
) -> Scalar {
    let mut data = domain.map_or_else(Vec::new, |d| d.prefix());
    data.extend_from_slice(hd);
    data.extend_from_slice(&node.to_be_bytes());
    data.extend_from_slice(public_key);
    data.extend_from_slice(dh);
    data.extend_from_slice(&label.bytes());
    hq(
        if domain.is_some() {
            "LD1/rs-enc"
        } else {
            "LD1/enc"
        },
        &data,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthProof {
    pub e_prime: ProjectivePoint,
    pub t_1: ProjectivePoint,
    pub t_2: ProjectivePoint,
    pub z_e: Scalar,
    pub t_a: ProjectivePoint,
    pub z_a: Scalar,
}

impl AuthProof {
    fn eph_input(
        hd: &[u8; 32],
        ct: &[u8],
        ephemeral: ProjectivePoint,
        domain: Option<ReshareDomain>,
    ) -> Result<Vec<u8>> {
        let mut data = proof_prefix(hd, ct, domain);
        data.extend_from_slice(&encode_point(ephemeral)?);
        Ok(data)
    }
    fn eph_challenge(&self, mut data: Vec<u8>, domain: Option<ReshareDomain>) -> Result<Scalar> {
        for point in encode_points(&[self.e_prime, self.t_1, self.t_2])? {
            data.extend_from_slice(&point);
        }
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
        let points = encode_points(&[self.e_prime, self.t_1, self.t_2, self.t_a])?;
        for point in &points[..3] {
            data.extend_from_slice(point);
        }
        data.extend_from_slice(&self.z_e.to_bytes());
        data.extend_from_slice(&points[3]);
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
        base: ProjectivePoint,
        domain: Option<ReshareDomain>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let input = Self::eph_input(hd, ct, mul_generator(ephemeral), domain)?;
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
            t_1: mul_generator(a),
            t_2: g_prime * a,
            z_e: Scalar::ZERO,
            t_a: mul_base(base, b),
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
        ephemeral: ProjectivePoint,
        base: ProjectivePoint,
        constant: ProjectivePoint,
        domain: Option<ReshareDomain>,
    ) -> Result<()> {
        encode_point(base)?;
        // Zero old shares imply an identity constant; this point is not sent.
        if domain.is_none() {
            encode_point(constant)?;
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
        ephemeral: ProjectivePoint,
        base: ProjectivePoint,
        constant: ProjectivePoint,
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
        if mul_generator(self.z_e) != self.t_1 + ephemeral * c_e
            || g_prime * self.z_e != self.t_2 + self.e_prime * c_e
            || mul_base(base, self.z_a) != self.t_a + constant * c_a
        {
            return Err(Error::Proof);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let points = encode_points(&[self.e_prime, self.t_1, self.t_2, self.t_a])?;
        Ok([
            &points[0][..],
            &points[1],
            &points[2],
            &self.z_e.to_bytes(),
            &points[3],
            &self.z_a.to_bytes(),
        ]
        .concat())
    }
}

#[derive(Clone, Debug)]
pub struct OwnerMessage {
    pub header: Header,
    pub deal: Deal,
    /// Node-major, followed by the polynomial order in deal.
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

pub(crate) fn ciphertext_bytes(ct: &[Vec<Scalar>]) -> Vec<u8> {
    ct.iter().flatten().flat_map(|s| s.to_bytes()).collect()
}

impl OwnerMessage {
    /// Build a mutable message. Encoding and acceptance validate its public fields.
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

    fn public_key_wire(&self) -> Result<[u8; 33]> {
        match self.decoded_wire() {
            Some(wire) => Ok(wire.bytes[KEY_OFFSET..EPHEMERAL_OFFSET]
                .try_into()
                .expect("header point")),
            None => encode_point(self.header.public_key),
        }
    }

    pub(crate) fn public_key_x(&self) -> Result<[u8; 32]> {
        Ok(self.public_key_wire()?[1..]
            .try_into()
            .expect("point width"))
    }

    fn ephemeral_wire(&self) -> Result<[u8; 33]> {
        match self.decoded_wire() {
            Some(wire) => Ok(wire.bytes[EPHEMERAL_OFFSET..HEADER_POINTS_END]
                .try_into()
                .expect("header point")),
            None => encode_point(self.header.ephemeral),
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
        let tie = if self.header.mode == 1 {
            self.hd()?
        } else {
            [0; 32]
        };
        Ok(h(
            "LD1/rid",
            &[
                &self.header.chain_id[..],
                &self.header.board_id,
                &self.public_key_wire()?,
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
        bytes.extend_from_slice(&self.deal.encode(&self.header)?);
        let count = self.deal.labels(&self.header)?.len();
        if self.ciphertexts.len() != self.header.n as usize
            || self.ciphertexts.iter().any(|v| v.len() != count)
        {
            return Err(Error::Encoding);
        }
        bytes.extend_from_slice(&ciphertext_bytes(&self.ciphertexts));
        bytes.extend_from_slice(&self.proof.encode()?);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let header = Header::read(&mut r)?;
        let header_end = bytes.len() - r.remaining();
        let deal = Deal::read(&mut r, &header)?;
        let deal_end = bytes.len() - r.remaining();
        let count = deal.labels(&header)?.len();
        let ct_len = (header.n as usize)
            .checked_mul(count)
            .and_then(|n| n.checked_mul(32))
            .ok_or(Error::Encoding)?;
        if r.remaining() != ct_len + 196 {
            return Err(Error::Encoding);
        }
        let ciphertexts = (0..header.n)
            .map(|_| (0..count).map(|_| r.scalar()).collect::<Result<Vec<_>>>())
            .collect::<Result<Vec<_>>>()?;
        let proof = AuthProof {
            e_prime: r.point()?,
            t_1: r.point()?,
            t_2: r.point()?,
            z_e: r.scalar()?,
            t_a: r.point()?,
            z_a: r.scalar()?,
        };
        if r.remaining() != 0 {
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

    pub fn step_a<C: AcceptanceContext>(&self, context: &C) -> Result<Accepted> {
        let bytes = self.wire_bytes()?;
        // Mutable local values pass through the same strict decode before raw
        // spans can be trusted. A matching decoded snapshot needs no encoding.
        let checked;
        let wire = match self.decoded_wire() {
            Some(wire) => wire,
            None => {
                checked = Self::decode(&bytes)?;
                checked.decoded_wire().expect("just decoded")
            }
        };
        self.header
            .check_address_wire(&wire.bytes[KEY_OFFSET..EPHEMERAL_OFFSET])?;
        context.committee().check_header(&self.header)?;
        context.check_header(&self.header)?;
        let hd = dealing_digest(
            &wire.bytes[..wire.header_end],
            &wire.bytes[wire.header_end..wire.deal_end],
        )?;
        let tie = if self.header.mode == 1 { hd } else { [0; 32] };
        let rid = h(
            "LD1/rid",
            &[
                self.header.chain_id.as_slice(),
                &self.header.board_id,
                &wire.bytes[KEY_OFFSET..EPHEMERAL_OFFSET],
                &self.header.owner_nonce,
                &tie,
            ]
            .concat(),
        );
        if context.is_bound_or_tombstoned(&rid) {
            return Err(Error::Context);
        }
        let messages = if self.header.mode == 1 {
            context.sealed_sighashes(&self.header)?
        } else {
            Vec::new()
        };
        let polynomials = self.deal.public_polynomials_wire(
            &self.header,
            &messages,
            &wire.bytes[wire.header_end..wire.deal_end],
            wire.bytes[KEY_OFFSET + 1..EPHEMERAL_OFFSET]
                .try_into()
                .expect("header point"),
        )?;
        let (base, constant) = if self.header.mode == 1 {
            (polynomials[0].base, polynomials[0].constant)
        } else {
            (G, self.header.public_key)
        };
        self.proof.verify_wire(
            &hd,
            &wire.bytes[wire.deal_end..wire.bytes.len() - 196],
            self.header.ephemeral,
            base,
            constant,
            None,
            &wire.bytes[EPHEMERAL_OFFSET..HEADER_POINTS_END],
            &wire.bytes[wire.bytes.len() - 196..],
        )?;
        let keys = context.node_keys();
        if keys.len() != self.header.n as usize {
            return Err(Error::Context);
        }
        let key_wires = encode_points(keys)?;
        Ok(Accepted {
            message: {
                let mut message = self.clone();
                message.wire = Some(Arc::new(wire.clone()));
                message
            },
            polynomials,
            sealed_messages: messages,
            keys: keys.to_vec(),
            key_wires,
        })
    }
}

/// Implementations must check current chain/board/epoch/keylist, n/f, expiry and
/// grace, and recompute sealed transactions from intent (including the pin,
/// outputs, fees, and replacement increments). No default accepts those checks.
#[derive(Clone, Copy)]
pub struct CommitteeState {
    pub chain_id: [u8; 32],
    pub board_id: [u8; 32],
    pub epoch: u64,
    pub keylist_hash: [u8; 32],
    pub n: u16,
    pub f: u16,
    pub board_height: u64,
    pub grace_end: u64,
}

impl CommitteeState {
    pub fn check_header(&self, header: &Header) -> Result<()> {
        if header.chain_id != self.chain_id
            || header.board_id != self.board_id
            || header.epoch != self.epoch
            || header.keylist_hash != self.keylist_hash
            || header.n != self.n
            || header.f != self.f
            || self.board_height > header.expires
            || (header.on_rotation == 1 && header.expires > self.grace_end)
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}

pub trait AcceptanceContext {
    fn committee(&self) -> CommitteeState;
    /// Additional chain/builder-specific header validation.
    fn check_header(&self, header: &Header) -> Result<()>;
    fn is_bound_or_tombstoned(&self, rid: &[u8; 32]) -> bool;
    fn sealed_sighashes(&self, header: &Header) -> Result<Vec<[u8; 32]>>;
    fn node_keys(&self) -> &[ProjectivePoint];
}

#[derive(Clone)]
pub struct Accepted {
    pub(crate) message: OwnerMessage,
    pub(crate) polynomials: Vec<Commitment>,
    pub(crate) sealed_messages: Vec<[u8; 32]>,
    keys: Vec<ProjectivePoint>,
    key_wires: Vec<[u8; 33]>,
}

impl Accepted {
    pub fn message(&self) -> &OwnerMessage {
        &self.message
    }
    pub fn polynomials(&self) -> &[Commitment] {
        &self.polynomials
    }
    pub fn decrypt(&self, node: u16, secret_key: Scalar) -> Result<NodeShares> {
        if node == 0 || node > self.message.header.n {
            return Err(Error::Parameters);
        }
        let pk = self.keys[node as usize - 1];
        if mul_generator(secret_key) != pk {
            return Err(Error::Share);
        }
        let hd = self.message.hd()?;
        let dh = encode_point(self.message.header.ephemeral * secret_key)?;
        let labels = self.message.deal.labels(&self.message.header)?;
        let mut values = Vec::new();
        for ((ct, label), polynomial) in self.message.ciphertexts[node as usize - 1]
            .iter()
            .zip(labels)
            .zip(&self.polynomials)
        {
            let share = *ct
                - share_pad_wire(
                    &hd,
                    node,
                    &self.key_wires[node as usize - 1],
                    &dh,
                    label,
                    None,
                );
            if !polynomial.verify(node, share) {
                return Err(Error::Share);
            }
            values.push(share);
        }
        Ok(NodeShares { node, values, hd })
    }
}

#[derive(Clone)]
pub struct NodeShares {
    pub(crate) node: u16,
    pub(crate) values: Vec<Scalar>,
    pub(crate) hd: [u8; 32],
}
impl NodeShares {
    pub fn node(&self) -> u16 {
        self.node
    }
    pub fn values(&self) -> &[Scalar] {
        &self.values
    }
}

pub struct Owner {
    header: Header,
    deal: Deal,
    polynomials: Vec<Polynomial>,
    witness: Scalar,
    auth_base: ProjectivePoint,
}

impl Owner {
    pub fn open_ecdsa(
        mut header: Header,
        secret: Scalar,
        nonces: &[Scalar],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if header.mode != 2 || header.suite != 1 {
            return Err(Error::Parameters);
        }
        header.public_key = mul_generator(secret);
        let mut slots = Vec::new();
        let mut polynomials = Vec::new();
        for k in nonces {
            let nonce = mul_generator(*k);
            ecdsa_r(nonce)?;
            let w = Polynomial::random(inverse(*k)?, header.threshold, rng)?;
            let mu = Polynomial::random(inverse(*k)? * secret, header.threshold, rng)?;
            slots.push(EcdsaSlot {
                nonce,
                w: w.commit(nonce)?.coefficients,
                mu: mu.commit(nonce)?.coefficients,
            });
            polynomials.extend([w, mu]);
        }
        let deal = Deal::OpenEcdsa(slots);
        deal.public_polynomials(&header, &[])?;
        Ok(Self {
            header,
            deal,
            polynomials,
            witness: secret,
            auth_base: G,
        })
    }

    pub fn open_bip340(
        mut header: Header,
        secret: Scalar,
        nonces: &[(Scalar, Scalar)],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if header.mode != 2 || header.suite != 2 {
            return Err(Error::Parameters);
        }
        let secret = if is_odd(mul_generator(secret))? {
            -secret
        } else {
            secret
        };
        header.public_key = mul_generator(secret);
        let x = Polynomial::random(secret, header.threshold, rng)?;
        let x_commit = x.commit(G)?.coefficients;
        let mut polynomials = vec![x];
        let mut slots = Vec::new();
        for (d, e) in nonces {
            let pd = Polynomial::random(*d, header.threshold, rng)?;
            let pe = Polynomial::random(*e, header.threshold, rng)?;
            slots.push(SchnorrSlot {
                d: mul_generator(*d),
                e: mul_generator(*e),
                d_commitments: pd.commit(G)?.coefficients,
                e_commitments: pe.commit(G)?.coefficients,
            });
            polynomials.extend([pd, pe]);
        }
        let deal = Deal::OpenBip340 { x: x_commit, slots };
        deal.public_polynomials(&header, &[])?;
        Ok(Self {
            header,
            deal,
            polynomials,
            witness: secret,
            auth_base: G,
        })
    }

    /// Import wallet signatures without access to the address secret key.
    pub fn sealed_ecdsa(
        header: Header,
        signatures: &[([u8; 32], k256::ecdsa::Signature)],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        if header.mode != 1 || header.suite != 1 {
            return Err(Error::Parameters);
        }
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&encode_point(header.public_key)?)
            .map_err(|_| Error::Point)?;
        let mut slots = Vec::new();
        let mut polynomials = Vec::new();
        let mut messages = Vec::new();
        for (message, signature) in signatures {
            let normalized = signature.normalize_s().unwrap_or(*signature);
            key.verify_prehash(message, &normalized)
                .map_err(|_| Error::Signature)?;
            let r = *signature.r();
            let s = *signature.s();
            let nonce = (mul_generator(reduce(message)) + header.public_key * r) * inverse(s)?;
            if ecdsa_r(nonce)? != r {
                return Err(Error::Signature);
            }
            let p = Polynomial::random(s, header.threshold, rng)?;
            slots.push(SealedPoint {
                nonce,
                commitments: p.commit(nonce)?.coefficients,
            });
            polynomials.push(p);
            messages.push(*message);
        }
        Self::sealed(header, slots, polynomials, messages)
    }

    pub fn sealed_bip340(
        header: Header,
        signatures: &[([u8; 32], k256::schnorr::Signature)],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if header.mode != 1 || header.suite != 2 {
            return Err(Error::Parameters);
        }
        let key = k256::schnorr::VerifyingKey::from_bytes(&x_bytes(header.public_key)?)
            .map_err(|_| Error::Point)?;
        let mut slots = Vec::new();
        let mut polynomials = Vec::new();
        let mut messages = Vec::new();
        for (message, signature) in signatures {
            key.verify_raw(message, signature)
                .map_err(|_| Error::Signature)?;
            let bytes = signature.to_bytes();
            let nonce = lift_x(bytes[..32].try_into().expect("signature width"))?;
            let s = decode_scalar(bytes[32..].try_into().expect("signature width"))?;
            let p = Polynomial::random(s, header.threshold, rng)?;
            slots.push(SealedPoint {
                nonce,
                commitments: p.commit(G)?.coefficients,
            });
            polynomials.push(p);
            messages.push(*message);
        }
        Self::sealed(header, slots, polynomials, messages)
    }

    fn sealed(
        header: Header,
        slots: Vec<SealedPoint>,
        polynomials: Vec<Polynomial>,
        messages: Vec<[u8; 32]>,
    ) -> Result<Self> {
        let deal = Deal::Sealed(slots);
        let public = deal.public_polynomials(&header, &messages)?;
        let first = public.first().ok_or(Error::Parameters)?;
        Ok(Self {
            header,
            deal,
            witness: polynomials[0].constant(),
            auth_base: first.base,
            polynomials,
        })
    }

    pub fn encrypt(
        mut self,
        ephemeral: Scalar,
        keys: &[ProjectivePoint],
        rng: &mut impl CryptoRngCore,
    ) -> Result<OwnerMessage> {
        self.header.ephemeral = mul_generator(ephemeral);
        self.header.check_address()?;
        if keys.len() != self.header.n as usize {
            return Err(Error::Parameters);
        }
        let hd = dealing_digest(&self.header.encode()?, &self.deal.encode(&self.header)?)?;
        let labels = self.deal.labels(&self.header)?;
        let mut ciphertexts = Vec::new();
        for (offset, key) in keys.iter().enumerate() {
            let node = offset as u16 + 1;
            let dh = *key * ephemeral;
            let row = self
                .polynomials
                .iter()
                .zip(&labels)
                .map(|(p, label)| {
                    Ok(p.evaluate(node)? + share_pad(&hd, node, *key, dh, *label, None)?)
                })
                .collect::<Result<_>>()?;
            ciphertexts.push(row);
        }
        let proof = AuthProof::create(
            &hd,
            &ciphertext_bytes(&ciphertexts),
            ephemeral,
            self.witness,
            self.auth_base,
            None,
            rng,
        )?;
        Ok(OwnerMessage::new(
            self.header,
            self.deal,
            ciphertexts,
            proof,
        ))
    }
}

/// Public DH proof. Construct only after Step A (or transfer verification).
#[derive(Clone, Debug)]
pub struct DhProof {
    pub key: ProjectivePoint,
    pub t_1: ProjectivePoint,
    pub t_2: ProjectivePoint,
    pub z: Scalar,
    wire: Option<Arc<DecodedDhWire>>,
}

#[derive(Clone, Debug)]
struct DecodedDhWire {
    points: [ProjectivePoint; 3],
    z: Scalar,
    bytes: [u8; 131],
}
impl DhProof {
    /// Build a mutable proof. Encoding and verification validate its points.
    pub fn new(
        key: ProjectivePoint,
        t_1: ProjectivePoint,
        t_2: ProjectivePoint,
        z: Scalar,
    ) -> Self {
        Self {
            key,
            t_1,
            t_2,
            z,
            wire: None,
        }
    }

    fn decoded_wire(&self) -> Option<&DecodedDhWire> {
        self.wire
            .as_deref()
            .filter(|wire| wire.points == [self.key, self.t_1, self.t_2] && wire.z == self.z)
    }

    fn wire_bytes(&self) -> Result<Cow<'_, [u8]>> {
        match self.decoded_wire() {
            Some(wire) => Ok(Cow::Borrowed(&wire.bytes)),
            None => Ok(Cow::Owned(self.encode()?)),
        }
    }

    fn key_wire(&self) -> Result<[u8; 33]> {
        match self.decoded_wire() {
            Some(wire) => Ok(wire.bytes[..33].try_into().expect("proof point")),
            None => encode_point(self.key),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if let Some(wire) = self.decoded_wire() {
            return Ok(wire.bytes.to_vec());
        }
        let points = encode_points(&[self.key, self.t_1, self.t_2])?;
        Ok([
            points[0].as_slice(),
            &points[1],
            &points[2],
            &self.z.to_bytes(),
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
            points: [proof.key, proof.t_1, proof.t_2],
            z: proof.z,
            bytes: bytes.try_into().expect("proof width"),
        }));
        Ok(proof)
    }

    pub fn create(
        mid: &[u8; 32],
        pk: ProjectivePoint,
        ephemeral: ProjectivePoint,
        secret: Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        encode_point(pk)?;
        encode_point(ephemeral)?;
        if mul_generator(secret) != pk {
            return Err(Error::Share);
        }
        let a = random_nonzero(rng);
        let mut proof = Self::new(
            ephemeral * secret,
            mul_generator(a),
            ephemeral * a,
            Scalar::ZERO,
        );
        proof.z = a + proof.challenge(mid, pk, ephemeral)? * secret;
        Ok(proof)
    }
    fn challenge(
        &self,
        mid: &[u8; 32],
        pk: ProjectivePoint,
        ephemeral: ProjectivePoint,
    ) -> Result<Scalar> {
        let points = encode_points(&[pk, ephemeral])?;
        self.challenge_wire(mid, &points[0], &points[1])
    }

    fn challenge_wire(&self, mid: &[u8; 32], pk: &[u8], ephemeral: &[u8]) -> Result<Scalar> {
        let proof = self.wire_bytes()?;
        let mut data = [encode_point(G)?.as_slice(), pk, ephemeral, &proof[..99]].concat();
        data.extend_from_slice(mid);
        Ok(hq("LD1/dleq", &data))
    }
    pub fn verify(
        &self,
        mid: &[u8; 32],
        pk: ProjectivePoint,
        ephemeral: ProjectivePoint,
    ) -> Result<()> {
        let points = encode_points(&[pk, ephemeral])?;
        self.verify_wire(mid, pk, ephemeral, &points[0], &points[1])
    }

    fn verify_wire(
        &self,
        mid: &[u8; 32],
        pk: ProjectivePoint,
        ephemeral: ProjectivePoint,
        pk_wire: &[u8],
        ephemeral_wire: &[u8],
    ) -> Result<()> {
        let c = self.challenge_wire(mid, pk_wire, ephemeral_wire)?;
        if mul_generator(self.z) != self.t_1 + pk * c
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
        complaint.proof.verify_wire(
            &self.message.mid()?,
            pk,
            self.message.header.ephemeral,
            &self.key_wires[usize::from(node) - 1],
            &self.message.ephemeral_wire()?,
        )?;
        let hd = self.message.hd()?;
        let dh = complaint.proof.key_wire()?;
        let labels = self.message.deal.labels(&self.message.header)?;
        for ((ct, label), polynomial) in self.message.ciphertexts[usize::from(node) - 1]
            .iter()
            .zip(labels)
            .zip(&self.polynomials)
        {
            let share = *ct
                - share_pad_wire(
                    &hd,
                    node,
                    &self.key_wires[usize::from(node) - 1],
                    &dh,
                    label,
                    None,
                );
            if !polynomial.verify(node, share) {
                return Ok(());
            }
        }
        Err(Error::Share)
    }
}
