//! Canonical 16 KiB envelopes. All integers are big endian.
//!
//! A fixed authenticated layout locates each encrypted region. No public length
//! or type field leaks the private layout.
use super::{
    contribution::SealedContribution,
    hpke,
    prf::{self, Label, OneShotKey, Partial},
};
use crate::{
    algebra::{encode_points, mul_generator, random_nonzero, Commitment},
    hash::{h, SlotLabel},
    message::{share_pad, AuthProof, Complaint, DhProof},
    wire::Reader,
    Error, Result,
};
use k256::{elliptic_curve::rand_core::CryptoRngCore, ProjectivePoint, Scalar};
use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

pub const FRAME_SIZE: usize = 16_384;
pub const PUBLIC_SIZE: usize = 96;
pub const PROOF_SIZE: usize = 196;
pub const K_MAX: usize = 8;
const BODY_MAX: usize = 2 * K_MAX - 1;
const LAYOUT_FIELDS: usize = 1 + BODY_MAX + K_MAX;
/// Twenty-four u16 lengths plus one AEAD tag, identical for every frame kind.
pub const LAYOUT_SIZE: usize = 2 * LAYOUT_FIELDS + 16;
/// HPKE encapsulation/tag + header/layout keys + position/token + eight keys.
pub const ACTOR_CAPSULE_SIZE: usize = 48 + 64 + 1 + 16 + 32 * K_MAX;
const G: ProjectivePoint = ProjectivePoint::GENERATOR;
const HEADER_FIXED: usize = 214;
const CONTRIB_FIXED: usize = 150;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub epoch: u32,
    pub keylist_hash: [u8; 32],
    pub exp: u64,
    pub auth_ref: [u8; 32],
    pub reserved: [u8; 18],
}
impl Public {
    pub fn new(epoch: u32, keylist_hash: [u8; 32], exp: u64) -> Self {
        Self {
            epoch,
            keylist_hash,
            exp,
            auth_ref: [0; 32],
            reserved: [0; 18],
        }
    }
    pub fn encode(&self) -> [u8; PUBLIC_SIZE] {
        let mut out = [0; PUBLIC_SIZE];
        out[0] = 1;
        out[1..5].copy_from_slice(&self.epoch.to_be_bytes());
        out[5..37].copy_from_slice(&self.keylist_hash);
        out[37..45].copy_from_slice(&self.exp.to_be_bytes());
        out[46..78].copy_from_slice(&self.auth_ref);
        out[78..].copy_from_slice(&self.reserved);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_SIZE || bytes[0] != 1 || bytes[45] != 0 {
            return Err(Error::Encoding);
        }
        let mut r = Reader::new(bytes);
        r.byte()?;
        let epoch = u32::from_be_bytes(r.array()?);
        let keylist_hash = r.array()?;
        let exp = r.u64()?;
        r.byte()?;
        Ok(Self {
            epoch,
            keylist_hash,
            exp,
            auth_ref: r.array()?,
            reserved: r.array()?,
        })
    }
    fn masked(&self) -> [u8; PUBLIC_SIZE] {
        let mut b = self.encode();
        b[46..78].fill(0);
        b
    }
}

pub fn keylist_hash(keys: &[ProjectivePoint]) -> Result<[u8; 32]> {
    let mut bytes = Vec::with_capacity(keys.len() * 33);
    for key in encode_points(keys)? {
        bytes.extend_from_slice(&key)
    }
    Ok(h("SL1/keylist", &bytes))
}

/// These values complete the two assigned wire tags (BIRTH=1, CONTRIB=6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestType {
    Birth = 1,
    Spend = 2,
    SlotRefill = 3,
    Exit = 4,
    P0Spend = 5,
    Contrib = 6,
}
impl TryFrom<u8> for RequestType {
    type Error = Error;
    fn try_from(x: u8) -> Result<Self> {
        match x {
            1 => Ok(Self::Birth),
            2 => Ok(Self::Spend),
            3 => Ok(Self::SlotRefill),
            4 => Ok(Self::Exit),
            5 => Ok(Self::P0Spend),
            6 => Ok(Self::Contrib),
            _ => Err(Error::Encoding),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedContribution {
    pub token: [u8; 16],
    pub sealed: Vec<SealedContribution>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorSlot {
    pub position: u8,
    pub token_hash: [u8; 32],
    pub party_index: Option<u16>,
    pub embedded: Option<EmbeddedContribution>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeActor {
    pub weighted_point: Vec<u8>,
    pub pair_ids: Vec<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeFields {
    pub intent: Vec<u8>,
    pub public_key: Vec<u8>,
    pub leaf_root: [u8; 32],
    pub r_ic: [u8; 32],
    pub salts: Vec<[u8; 32]>,
    pub actors: Vec<TeeActor>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionPayload {
    pub target_hd: [u8; 32],
    pub position: u8,
    pub token: [u8; 16],
    pub sealed: Vec<SealedContribution>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: RequestType,
    pub suite: u8,
    pub k: u8,
    pub l: u8,
    pub g: u8,
    pub slots: Vec<u32>,
    pub tickets: Vec<Vec<u8>>,
    pub actors: Vec<ActorSlot>,
    pub delta_c: u64,
    pub ic: [u8; 32],
    pub r_tkc: [u8; 32],
    pub contribution_keys: Vec<ProjectivePoint>,
    /// Fee ladder order is ticket order; selection is the first adequate fee, else last.
    pub tee: Option<TeeFields>,
    /// Request-specific birth/refill/exit/P0 payload, interpreted by the owning lane.
    pub extension: Vec<u8>,
    pub contribution: Option<ContributionPayload>,
    capsule_lengths: Vec<u16>,
}
impl Header {
    pub fn request(kind: RequestType, suite: u8, k: u8, l: u8) -> Result<Self> {
        if !(1..=3).contains(&suite)
            || !(1..=8).contains(&k)
            || !(1..=2).contains(&l)
            || kind == RequestType::Contrib
        {
            return Err(Error::Parameters);
        }
        Ok(Self {
            kind,
            suite,
            k,
            l,
            g: if suite == 1 { 0 } else { k.min(2) },
            slots: vec![],
            tickets: vec![],
            actors: vec![],
            delta_c: 0,
            ic: [0; 32],
            r_tkc: [0; 32],
            contribution_keys: vec![],
            tee: None,
            extension: vec![],
            contribution: None,
            capsule_lengths: vec![0; k as usize],
        })
    }
    pub fn contribution(target: &Header, payload: ContributionPayload) -> Result<Self> {
        let mut out = Self::request(RequestType::Spend, target.suite, target.k, target.l)?;
        out.kind = RequestType::Contrib;
        out.contribution = Some(payload);
        out.capsule_lengths.clear();
        out.validate()?;
        Ok(out)
    }
    pub fn labels(&self) -> Vec<(u8, u8)> {
        (1..=self.k)
            .flat_map(|v| {
                if self.suite == 1 {
                    vec![(v, 0)]
                } else {
                    (1..=v.min(self.g)).map(|g| (v, g)).collect()
                }
            })
            .collect()
    }
    pub fn slot_count(&self) -> usize {
        if self.suite == 1 {
            self.k as usize * self.l as usize
        } else {
            self.g as usize * self.l as usize
        }
    }
    pub fn ticket_len(&self) -> usize {
        if self.suite == 1 {
            36
        } else {
            149
        }
    }
    pub fn half_count(&self) -> usize {
        self.labels().len() * self.l as usize
    }
    pub fn actor_capsule_count(&self) -> usize {
        self.actors.iter().filter(|a| a.embedded.is_none()).count()
    }
    pub fn capsule_lengths(&self) -> &[u16] {
        &self.capsule_lengths
    }
    pub fn validate(&self) -> Result<()> {
        if !(1..=3).contains(&self.suite)
            || !(1..=8).contains(&self.k)
            || !(1..=2).contains(&self.l)
            || self.g != if self.suite == 1 { 0 } else { self.k.min(2) }
        {
            return Err(Error::Parameters);
        }
        if self.kind == RequestType::Contrib {
            let c = self.contribution.as_ref().ok_or(Error::Encoding)?;
            if c.position == 0
                || c.sealed.len() != self.labels().len()
                || !self.slots.is_empty()
                || !self.tickets.is_empty()
                || !self.actors.is_empty()
                || !self.contribution_keys.is_empty()
                || !self.extension.is_empty()
                || self.tee.is_some()
                || !self.capsule_lengths.is_empty()
            {
                return Err(Error::Encoding);
            }
            for s in &c.sealed {
                s.validate_inputs(self.l as usize)?;
            }
            return Ok(());
        }
        if self.contribution.is_some()
            || self.slots.len() != self.slot_count()
            || self.slots.iter().copied().collect::<BTreeSet<_>>().len() != self.slots.len()
            || self.tickets.len() != self.half_count()
            || self.capsule_lengths.len() != self.k as usize
            || self.actors.len() > 255
            || self.extension.len() > FRAME_SIZE
        {
            return Err(Error::Encoding);
        }
        let mut idx = 0;
        for (v, g) in self.labels() {
            for j in 0..self.l as usize {
                let t = &self.tickets[idx];
                idx += 1;
                let slot = if self.suite == 1 {
                    (v as usize - 1) * self.l as usize + j
                } else {
                    (g as usize - 1) * self.l as usize + j
                };
                if t.len() != self.ticket_len() || t[..4] != self.slots[slot].to_be_bytes() {
                    return Err(Error::Encoding);
                }
            }
        }
        if self.contribution_keys.len()
            != if self.actors.is_empty() {
                0
            } else {
                self.labels().len()
            }
        {
            return Err(Error::Encoding);
        }
        let mut embedded_started = false;
        for (i, a) in self.actors.iter().enumerate() {
            if a.position as usize != i + 1
                || a.party_index.is_some() != (self.suite == 1)
                || a.party_index == Some(0)
            {
                return Err(Error::Encoding);
            }
            if let Some(e) = &a.embedded {
                embedded_started = true;
                if token_hash(&e.token) != a.token_hash || e.sealed.len() != self.labels().len() {
                    return Err(Error::Context);
                }
                for s in &e.sealed {
                    s.validate_inputs(self.l as usize)?;
                }
            } else if embedded_started {
                return Err(Error::Encoding);
            }
        }
        if let Some(t) = &self.tee {
            validate_suite_point(self.suite, &t.public_key)?;
            if t.intent.len() > FRAME_SIZE
                || t.public_key.len() != point_len(self.suite)
                || t.salts.len() != self.k as usize
                || t.actors.len() != self.actors.len()
            {
                return Err(Error::Encoding);
            }
            for a in &t.actors {
                validate_suite_point(self.suite, &a.weighted_point)?;
                if a.weighted_point.len() != point_len(self.suite)
                    || a.pair_ids.len()
                        != if self.suite == 1 {
                            0
                        } else {
                            self.half_count()
                        }
                {
                    return Err(Error::Encoding);
                }
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut b = Zeroizing::new(vec![self.kind as u8, self.suite, self.k, self.l, self.g]);
        if let Some(c) = &self.contribution {
            b.resize(CONTRIB_FIXED, 0);
            b.extend_from_slice(&c.target_hd);
            b.push(c.position);
            b.extend_from_slice(&c.token);
            for s in &c.sealed {
                b.extend_from_slice(&s.encode())
            }
            return Ok(core::mem::take(&mut *b));
        }
        b.push(u8::from(self.tee.is_some()));
        b.push(self.actors.len() as u8);
        b.push(0);
        b.extend_from_slice(&self.delta_c.to_be_bytes());
        b.extend_from_slice(&self.ic);
        b.extend_from_slice(&self.r_tkc);
        push_len(&mut b, self.extension.len())?;
        push_len(&mut b, self.tee.as_ref().map_or(0, |t| t.intent.len()))?;
        let mut bitmap = [0u8; 32];
        for (i, a) in self.actors.iter().enumerate() {
            if a.embedded.is_some() {
                bitmap[i / 8] |= 1 << (i % 8)
            }
        }
        b.extend_from_slice(&bitmap);
        for i in 0..8 {
            b.extend_from_slice(
                &self
                    .capsule_lengths
                    .get(i)
                    .copied()
                    .unwrap_or(0)
                    .to_be_bytes(),
            )
        }
        for slot in &self.slots {
            b.extend_from_slice(&slot.to_be_bytes())
        }
        b.resize(HEADER_FIXED, 0);
        for ticket in &self.tickets {
            b.extend_from_slice(ticket)
        }
        for actor in &self.actors {
            b.push(actor.position);
            b.extend_from_slice(&actor.token_hash);
            if let Some(i) = actor.party_index {
                b.extend_from_slice(&i.to_be_bytes())
            }
        }
        for p in encode_points(&self.contribution_keys)? {
            b.extend_from_slice(&p)
        }
        for a in &self.actors {
            if let Some(e) = &a.embedded {
                b.extend_from_slice(&e.token);
                for s in &e.sealed {
                    b.extend_from_slice(&s.encode())
                }
            }
        }
        b.extend_from_slice(&self.extension);
        if let Some(t) = &self.tee {
            b.extend_from_slice(&t.intent);
            b.extend_from_slice(&t.public_key);
            b.extend_from_slice(&t.leaf_root);
            b.extend_from_slice(&t.r_ic);
            for s in &t.salts {
                b.extend_from_slice(s)
            }
            for a in &t.actors {
                b.extend_from_slice(&a.weighted_point);
                for id in &a.pair_ids {
                    b.extend_from_slice(&id.to_be_bytes())
                }
            }
        }
        if b.len() > FRAME_SIZE {
            return Err(Error::Encoding);
        }
        Ok(core::mem::take(&mut *b))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FRAME_SIZE {
            return Err(Error::Encoding);
        }
        let mut r = Reader::new(bytes);
        let kind = RequestType::try_from(r.byte()?)?;
        let suite = r.byte()?;
        let k = r.byte()?;
        let l = r.byte()?;
        let g = r.byte()?;
        let mut out = Self::request(RequestType::Spend, suite, k, l)?;
        out.kind = kind;
        if out.g != g {
            return Err(Error::Encoding);
        }
        if kind == RequestType::Contrib {
            require_zero(r.take(CONTRIB_FIXED - 5)?)?;
            let target_hd = r.array()?;
            let position = r.byte()?;
            let token = Zeroizing::new(r.array()?);
            let mut sealed = vec![];
            for _ in out.labels() {
                sealed.push(SealedContribution::decode(
                    r.take(49 + 32 * l as usize)?,
                    l as usize,
                )?)
            }
            out.contribution = Some(ContributionPayload {
                target_hd,
                position,
                token: *token,
                sealed,
            });
            out.capsule_lengths.clear();
        } else {
            let tee = match r.byte()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Encoding),
            };
            let count = r.byte()? as usize;
            if r.byte()? != 0 {
                return Err(Error::Encoding);
            }
            out.delta_c = r.u64()?;
            out.ic = r.array()?;
            out.r_tkc = r.array()?;
            let extlen = r.u16()? as usize;
            let intentlen = r.u16()? as usize;
            let bitmap: [u8; 32] = r.array()?;
            for i in count..256 {
                if bitmap[i / 8] & (1 << (i % 8)) != 0 {
                    return Err(Error::Encoding);
                }
            }
            out.capsule_lengths.clear();
            for i in 0..8 {
                let len = r.u16()?;
                if i < k {
                    out.capsule_lengths.push(len)
                } else if len != 0 {
                    return Err(Error::Encoding);
                }
            }
            for _ in 0..out.slot_count() {
                out.slots.push(u32::from_be_bytes(r.array()?))
            }
            require_zero(r.take(HEADER_FIXED - 132 - 4 * out.slot_count())?)?;
            for _ in 0..out.half_count() {
                out.tickets.push(r.take(out.ticket_len())?.to_vec())
            }
            for _ in 0..count {
                out.actors.push(ActorSlot {
                    position: r.byte()?,
                    token_hash: r.array()?,
                    party_index: if suite == 1 { Some(r.u16()?) } else { None },
                    embedded: None,
                })
            }
            if count > 0 {
                for _ in out.labels() {
                    out.contribution_keys.push(r.point()?)
                }
            }
            let bodies = out.labels().len();
            for (i, a) in out.actors.iter_mut().enumerate() {
                if bitmap[i / 8] & (1 << (i % 8)) != 0 {
                    let token = Zeroizing::new(r.array()?);
                    let mut sealed = vec![];
                    for _ in 0..bodies {
                        sealed.push(SealedContribution::decode(
                            r.take(49 + 32 * l as usize)?,
                            l as usize,
                        )?)
                    }
                    a.embedded = Some(EmbeddedContribution {
                        token: *token,
                        sealed,
                    });
                }
            }
            out.extension = r.take(extlen)?.to_vec();
            if tee {
                let mut intent = Zeroizing::new(r.take(intentlen)?.to_vec());
                let mut public_key = Zeroizing::new(r.take(point_len(suite))?.to_vec());
                let leaf_root = Zeroizing::new(r.array()?);
                let r_ic = Zeroizing::new(r.array()?);
                let mut salts = Zeroizing::new(vec![]);
                for _ in 0..k {
                    salts.push(r.array()?)
                }
                let mut actors = vec![];
                for _ in 0..count {
                    let mut weighted_point = Zeroizing::new(r.take(point_len(suite))?.to_vec());
                    let mut pair_ids = Zeroizing::new(vec![]);
                    if suite != 1 {
                        for _ in 0..out.half_count() {
                            pair_ids.push(u32::from_be_bytes(r.array()?))
                        }
                    }
                    actors.push(TeeActor {
                        weighted_point: core::mem::take(&mut *weighted_point),
                        pair_ids: core::mem::take(&mut *pair_ids),
                    })
                }
                out.tee = Some(TeeFields {
                    intent: core::mem::take(&mut *intent),
                    public_key: core::mem::take(&mut *public_key),
                    leaf_root: *leaf_root,
                    r_ic: *r_ic,
                    salts: core::mem::take(&mut *salts),
                    actors,
                });
            } else if intentlen != 0 {
                return Err(Error::Encoding);
            }
        }
        if r.remaining() != 0 {
            return Err(Error::Encoding);
        }
        out.validate()?;
        Ok(out)
    }
    pub fn validate_contribution(
        &self,
        hd: &[u8; 32],
        payload: &ContributionPayload,
    ) -> Result<()> {
        if payload.target_hd != *hd {
            return Err(Error::Context);
        }
        let actor = self
            .actors
            .iter()
            .find(|a| a.position == payload.position)
            .ok_or(Error::Context)?;
        if token_hash(&payload.token) != actor.token_hash
            || payload.sealed.len() != self.labels().len()
        {
            return Err(Error::Context);
        }
        for s in &payload.sealed {
            s.validate_inputs(self.l as usize)?;
        }
        Ok(())
    }
}
fn point_len(_suite: u8) -> usize {
    33
}
fn validate_suite_point(suite: u8, bytes: &[u8]) -> Result<()> {
    match suite {
        1 | 2 => {
            crate::algebra::decode_point(bytes)?;
        }
        3 => {
            crate::ed25519::decode_point(bytes)?;
        }
        _ => return Err(Error::Parameters),
    }
    Ok(())
}
fn push_len(b: &mut Vec<u8>, n: usize) -> Result<()> {
    b.extend_from_slice(&u16::try_from(n).map_err(|_| Error::Encoding)?.to_be_bytes());
    Ok(())
}
fn require_zero(b: &[u8]) -> Result<()> {
    if b.iter().any(|b| *b != 0) {
        Err(Error::Encoding)
    } else {
        Ok(())
    }
}
pub fn token_hash(token: &[u8; 16]) -> [u8; 32] {
    h("SL1/token", token)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsuleActor {
    pub leaf: u16,
    pub pool_id: Option<u32>,
    pub pair_indices: Vec<u16>,
    pub weighted_point: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capsule {
    pub transaction: Vec<u8>,
    pub prevouts: Vec<u8>,
    pub destination: Vec<u8>,
    pub nonces: Vec<Vec<u8>>,
    pub salt: [u8; 32],
    pub initiator_term: Vec<u8>,
    pub initiator: u16,
    pub signing_set: Vec<u16>,
    pub actors: Vec<CapsuleActor>,
}
impl Capsule {
    fn validate(&self, suite: u8, halves: usize) -> Result<()> {
        validate_suite_point(suite, &self.initiator_term)?;
        for p in &self.nonces {
            validate_suite_point(suite, p)?;
        }
        for a in &self.actors {
            validate_suite_point(suite, &a.weighted_point)?;
        }
        if self.nonces.len() != halves
            || self.nonces.iter().any(|p| p.len() != point_len(suite))
            || self.initiator_term.len() != point_len(suite)
            || self.signing_set.len() != self.actors.len() + 1
            || self.signing_set.len() > 256
            || !self.signing_set.contains(&self.initiator)
            || self.signing_set.contains(&0)
            || self
                .signing_set
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != self.signing_set.len()
        {
            return Err(Error::Encoding);
        }
        let expected: BTreeSet<_> = self
            .signing_set
            .iter()
            .copied()
            .filter(|id| *id != self.initiator)
            .collect();
        if self.actors.iter().map(|a| a.leaf).collect::<BTreeSet<_>>() != expected
            || self.actors.iter().any(|a| {
                a.weighted_point.len() != point_len(suite)
                    || a.pool_id.is_some() != (suite != 1)
                    || a.pair_indices.len() != if suite == 1 { 0 } else { halves }
            })
        {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    pub fn encode(&self, suite: u8, halves: usize) -> Result<Vec<u8>> {
        self.validate(suite, halves)?;
        let mut b = Zeroizing::new(vec![]);
        for field in [&self.transaction, &self.prevouts, &self.destination] {
            push_len(&mut b, field.len())?;
            b.extend_from_slice(field)
        }
        for nonce in &self.nonces {
            b.extend_from_slice(nonce)
        }
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&self.initiator_term);
        b.extend_from_slice(&self.initiator.to_be_bytes());
        push_len(&mut b, self.signing_set.len())?;
        for id in &self.signing_set {
            b.extend_from_slice(&id.to_be_bytes())
        }
        for leaf in self.signing_set.iter().filter(|id| **id != self.initiator) {
            let a = self
                .actors
                .iter()
                .find(|a| a.leaf == *leaf)
                .ok_or(Error::Encoding)?;
            if let Some(id) = a.pool_id {
                b.extend_from_slice(&id.to_be_bytes())
            }
            for id in &a.pair_indices {
                b.extend_from_slice(&id.to_be_bytes())
            }
            b.extend_from_slice(&a.weighted_point)
        }
        if b.len() > FRAME_SIZE {
            return Err(Error::Encoding);
        }
        Ok(core::mem::take(&mut *b))
    }
    pub fn decode(bytes: &[u8], suite: u8, halves: usize) -> Result<Self> {
        if !(1..=3).contains(&suite) || halves > 4 || bytes.len() > FRAME_SIZE {
            return Err(Error::Encoding);
        }
        let mut r = Reader::new(bytes);
        let n = r.u16()? as usize;
        let mut transaction = Zeroizing::new(r.take(n)?.to_vec());
        let n = r.u16()? as usize;
        let mut prevouts = Zeroizing::new(r.take(n)?.to_vec());
        let n = r.u16()? as usize;
        let mut destination = Zeroizing::new(r.take(n)?.to_vec());
        let mut nonces = Zeroizing::new(vec![]);
        for _ in 0..halves {
            nonces.push(r.take(point_len(suite))?.to_vec())
        }
        let salt = Zeroizing::new(r.array()?);
        let mut initiator_term = Zeroizing::new(r.take(point_len(suite))?.to_vec());
        let initiator = r.u16()?;
        let n = r.u16()? as usize;
        if n == 0 || n > 256 {
            return Err(Error::Encoding);
        }
        let mut signing_set = Zeroizing::new(vec![]);
        for _ in 0..n {
            signing_set.push(r.u16()?)
        }
        let mut actors = vec![];
        for leaf in signing_set.iter().copied().filter(|id| *id != initiator) {
            let pool_id = if suite != 1 {
                Some(u32::from_be_bytes(r.array()?))
            } else {
                None
            };
            let mut pair_indices = Zeroizing::new(vec![]);
            if suite != 1 {
                for _ in 0..halves {
                    pair_indices.push(r.u16()?)
                }
            }
            let weighted_point = r.take(point_len(suite))?.to_vec();
            actors.push(CapsuleActor {
                leaf,
                pool_id,
                pair_indices: core::mem::take(&mut *pair_indices),
                weighted_point,
            })
        }
        if r.remaining() != 0 {
            return Err(Error::Encoding);
        }
        let out = Self {
            transaction: core::mem::take(&mut *transaction),
            prevouts: core::mem::take(&mut *prevouts),
            destination: core::mem::take(&mut *destination),
            nonces: core::mem::take(&mut *nonces),
            salt: *salt,
            initiator_term: core::mem::take(&mut *initiator_term),
            initiator,
            signing_set: core::mem::take(&mut *signing_set),
            actors,
        };
        out.validate(suite, halves)?;
        Ok(out)
    }
}

/// Byte lengths of the serialized regions in an authenticated envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireSizes {
    pub public: usize,
    pub outer: usize,
    pub proof: usize,
    pub layout: usize,
    pub header: usize,
    pub bodies: usize,
    pub capsules: usize,
    pub actor_capsules: usize,
}
impl WireSizes {
    pub fn used(&self) -> usize {
        self.public
            + self.outer
            + self.proof
            + self.layout
            + self.header
            + self.bodies
            + self.capsules
            + self.actor_capsules
    }
}

/// Public dealing material with the exact serialized bytes retained for hashes.
#[derive(Clone, Debug)]
struct Outer {
    commitment: Commitment,
    ciphertexts: Vec<Scalar>,
    ephemeral: ProjectivePoint,
    wire: Vec<u8>,
}
impl Outer {
    fn decode(bytes: &[u8], n: usize, t: usize) -> Result<Self> {
        if t == 0 || t > n || n > u16::MAX as usize || bytes.len() != t * 33 + n * 32 + 33 {
            return Err(Error::Encoding);
        }
        let mut r = Reader::new(bytes);
        let constant = r.point()?;
        let mut coefficients = vec![];
        for _ in 1..t {
            coefficients.push(r.point()?)
        }
        let mut ciphertexts = vec![];
        for _ in 0..n {
            ciphertexts.push(r.scalar()?)
        }
        let ephemeral = r.point()?;
        Ok(Self {
            commitment: Commitment {
                base: G,
                constant,
                coefficients,
            },
            ciphertexts,
            ephemeral,
            wire: bytes.to_vec(),
        })
    }
    fn encryption_context(&self, public: &Public) -> [u8; 32] {
        let t = self.commitment.coefficients.len() + 1;
        h(
            "SL1/outer",
            &[
                public.masked().as_slice(),
                &self.wire[..t * 33],
                &self.wire[self.wire.len() - 33..],
            ]
            .concat(),
        )
    }
    fn ciphertext_bytes(&self) -> &[u8] {
        let t = self.commitment.coefficients.len() + 1;
        &self.wire[t * 33..self.wire.len() - 33]
    }
}
fn pad_label() -> SlotLabel {
    SlotLabel::new(2, 4, 0, 0).expect("fixed valid label")
}
fn eval_small(c: &Commitment, i: u16) -> Result<ProjectivePoint> {
    if i == 0 {
        return Err(Error::Parameters);
    }
    fn mul(mut p: ProjectivePoint, mut i: u16) -> ProjectivePoint {
        let mut acc = ProjectivePoint::IDENTITY;
        while i > 0 {
            if i & 1 != 0 {
                acc += p
            }
            p = p.double();
            i >>= 1;
        }
        acc
    }
    Ok(c.coefficients
        .iter()
        .rev()
        .fold(ProjectivePoint::IDENTITY, |a, p| mul(a + *p, i))
        + c.constant)
}

/// Wallet preparation fixes dd before collecting embedded contributions.
pub struct PreparedEnvelope {
    public: Public,
    outer: Outer,
    secret: Scalar,
    ephemeral: Scalar,
    dd: [u8; 32],
}
impl Drop for PreparedEnvelope {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.ephemeral.zeroize();
    }
}
impl PreparedEnvelope {
    pub fn new(
        public: Public,
        keys: &[ProjectivePoint],
        threshold: u16,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if threshold == 0
            || threshold as usize > keys.len()
            || keys.len() > u16::MAX as usize
            || PUBLIC_SIZE
                + threshold as usize * 33
                + keys.len() * 32
                + 33
                + PROOF_SIZE
                + LAYOUT_SIZE
                + HEADER_FIXED
                + 16
                > FRAME_SIZE
            || public.keylist_hash != keylist_hash(keys)?
        {
            return Err(Error::Parameters);
        }
        let secret = Zeroizing::new(random_nonzero(rng));
        let ephemeral = Zeroizing::new(random_nonzero(rng));
        let mut coefficients = Zeroizing::new(Vec::with_capacity(threshold as usize));
        coefficients.push(*secret);
        coefficients.extend((1..threshold).map(|_| random_nonzero(rng)));
        let commitment = Commitment {
            base: G,
            constant: mul_generator(*secret),
            coefficients: coefficients
                .iter()
                .skip(1)
                .map(|coefficient| mul_generator(*coefficient))
                .collect(),
        };
        let ephemeral_point = mul_generator(*ephemeral);
        let points: Vec<_> = std::iter::once(commitment.constant)
            .chain(commitment.coefficients.iter().copied())
            .chain(std::iter::once(ephemeral_point))
            .collect();
        let encoded = encode_points(&points)?;
        let ephemeral_bytes = encoded.last().ok_or(Error::Parameters)?;
        let mut wire = vec![];
        for point in &encoded[..encoded.len() - 1] {
            wire.extend_from_slice(point);
        }
        let context = h(
            "SL1/outer",
            &[public.masked().as_slice(), wire.as_slice(), ephemeral_bytes].concat(),
        );
        let mut ciphertexts = vec![];
        for (i, pk) in keys.iter().enumerate() {
            let node = (i + 1) as u16;
            let index = Scalar::from(node as u64);
            let share = Zeroizing::new(
                coefficients
                    .iter()
                    .rev()
                    .fold(Scalar::ZERO, |value, coefficient| {
                        value * index + coefficient
                    }),
            );
            let ct = *share + share_pad(&context, node, *pk, *pk * *ephemeral, pad_label(), None)?;
            wire.extend_from_slice(&ct.to_bytes());
            ciphertexts.push(ct)
        }
        wire.extend_from_slice(ephemeral_bytes);
        let dd = h(
            "SL1/dd",
            &[public.masked().as_slice(), wire.as_slice()].concat(),
        );
        Ok(Self {
            public,
            outer: Outer {
                commitment,
                ciphertexts,
                ephemeral: ephemeral_point,
                wire,
            },
            secret: *secret,
            ephemeral: *ephemeral,
            dd,
        })
    }
    pub fn dd(&self) -> [u8; 32] {
        self.dd
    }
    pub fn outer_bytes(&self) -> &[u8] {
        &self.outer.wire
    }
    pub fn contribution_public(&self, variant: u8, generation: u8) -> Result<ProjectivePoint> {
        let (secret, public) = prf::contribution_key(prf::evaluate(
            self.secret,
            &self.dd,
            Label::Body {
                variant: variant as u16,
                generation: generation as u16,
            },
        )?)?;
        let _secret = Zeroizing::new(secret);
        Ok(public)
    }
    pub fn build(
        self,
        mut header: Header,
        bodies: Vec<Vec<Scalar>>,
        capsules: Vec<Capsule>,
        actors: Vec<ActorRecipient>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PendingEnvelope> {
        let bodies = Zeroizing::new(bodies);
        let mut frame = vec![0; FRAME_SIZE];
        rng.fill_bytes(&mut frame);
        frame[..PUBLIC_SIZE].copy_from_slice(&self.public.encode());
        let layout_start = PUBLIC_SIZE + self.outer.wire.len();
        let proof_start = layout_start + LAYOUT_SIZE;
        frame[PUBLIC_SIZE..layout_start].copy_from_slice(&self.outer.wire);
        frame[proof_start..proof_start + PROOF_SIZE].fill(0);
        let (header_key, layout_key) =
            prf::header_keys(prf::evaluate(self.secret, &self.dd, Label::Hdr)?)?;
        let header_bytes = Zeroizing::new(header_key.export_bytes());
        let layout_bytes = Zeroizing::new(layout_key.export_bytes());
        let mut encrypted_bodies = vec![];
        let mut encrypted_caps = vec![];
        let mut capkeys: Vec<Zeroizing<[u8; 32]>> = vec![];
        if header.kind != RequestType::Contrib {
            if bodies.len() != header.labels().len() || capsules.len() != header.k as usize {
                return Err(Error::Parameters);
            }
            for (v, cap) in capsules.iter().enumerate() {
                let halves = if header.suite == 1 {
                    header.l as usize
                } else {
                    (v + 1).min(header.g as usize) * header.l as usize
                };
                if cap.actors.len() != header.actors.len() {
                    return Err(Error::Encoding);
                }
                let mut ck = Zeroizing::new([0; 32]);
                rng.fill_bytes(ck.as_mut());
                let bytes = Zeroizing::new(cap.encode(header.suite, halves)?);
                encrypted_caps.push(OneShotKey::from_bytes(*ck).encrypt(&bytes, &self.dd)?);
                capkeys.push(ck);
            }
            header.capsule_lengths = encrypted_caps
                .iter()
                .map(|c| u16::try_from(c.len()).map_err(|_| Error::Encoding))
                .collect::<Result<_>>()?;
            let mut public_keys = vec![];
            for ((v, g), scalars) in header.labels().iter().copied().zip(bodies.iter()) {
                if scalars.len() != header.l as usize {
                    return Err(Error::Encoding);
                }
                let z = prf::evaluate(
                    self.secret,
                    &self.dd,
                    Label::Body {
                        variant: v as u16,
                        generation: g as u16,
                    },
                )?;
                if !header.actors.is_empty() {
                    let (secret, public) = prf::contribution_key(z)?;
                    let _secret = Zeroizing::new(secret);
                    public_keys.push(public);
                }
                let mut b = Zeroizing::new(Vec::new());
                for s in scalars {
                    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(s.to_bytes().into());
                    if header.suite == 3 {
                        let _scalar = Zeroizing::new(crate::ed25519::decode_scalar(&bytes)?);
                    }
                    b.extend_from_slice(bytes.as_ref());
                }
                b.extend_from_slice(capkeys[v as usize - 1].as_ref());
                encrypted_bodies.push(prf::body_key(z)?.encrypt(&b, &self.dd)?);
            }
            if !header.contribution_keys.is_empty() && header.contribution_keys != public_keys {
                return Err(Error::Context);
            }
            header.contribution_keys = public_keys;
        } else if !bodies.is_empty() || !capsules.is_empty() || !actors.is_empty() {
            return Err(Error::Parameters);
        }
        header.validate()?;
        if actors.len() != header.actor_capsule_count() {
            return Err(Error::Parameters);
        }
        let actor_size = ACTOR_CAPSULE_SIZE;
        let tail_start = FRAME_SIZE
            .checked_sub(actors.len() * actor_size)
            .ok_or(Error::Encoding)?;
        for (i, actor) in actors.iter().enumerate() {
            let slot = &header.actors[i];
            if actor.position != slot.position || token_hash(&actor.token) != slot.token_hash {
                return Err(Error::Context);
            }
            let mut b = Zeroizing::new(Vec::new());
            b.extend_from_slice(header_bytes.as_ref());
            b.extend_from_slice(layout_bytes.as_ref());
            b.push(actor.position);
            b.extend_from_slice(&actor.token);
            for ck in &capkeys {
                b.extend_from_slice(ck.as_ref())
            }
            b.resize(64 + 1 + 16 + 32 * K_MAX, 0);
            let ciphertext = hpke::seal(&actor.public_key, &b, rng)?;
            if ciphertext.len() != actor_size {
                return Err(Error::Encoding);
            }
            let start = FRAME_SIZE - (i + 1) * actor_size;
            frame[start..start + actor_size].copy_from_slice(&ciphertext);
        }
        let plaintext = Zeroizing::new(header.encode()?);
        let encrypted_header = header_key.encrypt(&plaintext, &self.dd)?;
        let mut lengths = Zeroizing::new([0u16; LAYOUT_FIELDS]);
        lengths[0] = u16::try_from(encrypted_header.len()).map_err(|_| Error::Encoding)?;
        for (i, body) in encrypted_bodies.iter().enumerate() {
            lengths[1 + i] = u16::try_from(body.len()).map_err(|_| Error::Encoding)?;
        }
        for (i, capsule) in encrypted_caps.iter().enumerate() {
            lengths[1 + BODY_MAX + i] =
                u16::try_from(capsule.len()).map_err(|_| Error::Encoding)?;
        }
        let mut layout = Zeroizing::new(Vec::with_capacity(2 * LAYOUT_FIELDS));
        for length in lengths.iter() {
            layout.extend_from_slice(&length.to_be_bytes());
        }
        let encrypted_layout = layout_key.encrypt(&layout, &self.dd)?;
        frame[layout_start..proof_start].copy_from_slice(&encrypted_layout);
        let mut offset = proof_start + PROOF_SIZE;
        for part in std::iter::once(&encrypted_header)
            .chain(encrypted_bodies.iter())
            .chain(encrypted_caps.iter())
        {
            let end = offset.checked_add(part.len()).ok_or(Error::Encoding)?;
            if end > tail_start {
                return Err(Error::Encoding);
            }
            frame[offset..end].copy_from_slice(part);
            offset = end;
        }
        let used = offset + actors.len() * actor_size;
        let hd = hash_frame(&frame, proof_start, "SL1/hd");
        Ok(PendingEnvelope {
            frame,
            public: self.public.clone(),
            outer: self.outer.clone(),
            secret: self.secret,
            ephemeral: self.ephemeral,
            hd,
            used,
            contrib: header.kind == RequestType::Contrib,
        })
    }
}
#[derive(Clone, Debug)]
pub struct ActorRecipient {
    pub position: u8,
    pub token: [u8; 16],
    pub public_key: [u8; 32],
}
/// Authorization can commit to hd before the eid-bound proof exists.
pub struct PendingEnvelope {
    frame: Vec<u8>,
    public: Public,
    outer: Outer,
    secret: Scalar,
    ephemeral: Scalar,
    hd: [u8; 32],
    used: usize,
    /// A CONTRIB frame has no authorization and takes random `auth_ref` bytes.
    contrib: bool,
}
impl Drop for PendingEnvelope {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.ephemeral.zeroize();
    }
}
impl PendingEnvelope {
    pub fn hd(&self) -> [u8; 32] {
        self.hd
    }
    pub fn used_bytes(&self) -> usize {
        self.used
    }
    pub fn authorize(
        mut self,
        auth_ref: Option<[u8; 32]>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Envelope> {
        // DESIGN §4.6, DECISIONS 54(2): every envelope without an authorization,
        // CONTRIB frames included, carries 32 random bytes in `auth_ref`.
        if self.contrib && auth_ref.is_some() {
            return Err(Error::Parameters);
        }
        self.public.auth_ref = auth_ref.unwrap_or_else(|| {
            let mut b = [0; 32];
            rng.fill_bytes(&mut b);
            b
        });
        self.frame[..PUBLIC_SIZE].copy_from_slice(&self.public.encode());
        let eid = h(
            "SL1/eid",
            &[self.hd.as_slice(), &self.public.auth_ref].concat(),
        );
        let proof = AuthProof::create(
            &eid,
            self.outer.ciphertext_bytes(),
            self.ephemeral,
            self.secret,
            G,
            None,
            rng,
        )?;
        let start = PUBLIC_SIZE + self.outer.wire.len() + LAYOUT_SIZE;
        self.frame[start..start + PROOF_SIZE].copy_from_slice(&proof.encode()?);
        Envelope::decode(
            &self.frame,
            self.outer.ciphertexts.len(),
            self.outer.commitment.coefficients.len() + 1,
        )
    }
}
fn hash_frame(frame: &[u8], proof_start: usize, tag: &str) -> [u8; 32] {
    let mut b = frame.to_vec();
    b[46..78].fill(0);
    b.drain(proof_start..proof_start + PROOF_SIZE);
    h(tag, &b)
}

#[derive(Clone, Debug)]
pub struct Envelope {
    frame: Vec<u8>,
    public: Public,
    outer: Outer,
    proof: AuthProof,
    dd: [u8; 32],
    hd: [u8; 32],
    eid: [u8; 32],
}
impl Envelope {
    pub fn decode(bytes: &[u8], n: usize, t: usize) -> Result<Self> {
        if bytes.len() != FRAME_SIZE || t == 0 || t > n || n > u16::MAX as usize {
            return Err(Error::Encoding);
        }
        let outer_len = t * 33 + n * 32 + 33;
        let layout_start = PUBLIC_SIZE + outer_len;
        let proof_start = layout_start + LAYOUT_SIZE;
        if proof_start + PROOF_SIZE >= FRAME_SIZE {
            return Err(Error::Encoding);
        }
        let public = Public::decode(&bytes[..PUBLIC_SIZE])?;
        let outer = Outer::decode(&bytes[PUBLIC_SIZE..layout_start], n, t)?;
        let mut r = Reader::new(&bytes[proof_start..proof_start + PROOF_SIZE]);
        let proof = AuthProof {
            e_prime: r.point()?,
            t_1: r.point()?,
            t_2: r.point()?,
            z_e: r.scalar()?,
            t_a: r.point()?,
            z_a: r.scalar()?,
        };
        let dd = h(
            "SL1/dd",
            &[public.masked().as_slice(), outer.wire.as_slice()].concat(),
        );
        let hd = hash_frame(bytes, proof_start, "SL1/hd");
        let eid = h("SL1/eid", &[hd.as_slice(), &public.auth_ref].concat());
        Ok(Self {
            frame: bytes.to_vec(),
            public,
            outer,
            proof,
            dd,
            hd,
            eid,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.frame
    }
    /// Account for authenticated wire regions, excluding random frame padding.
    pub fn wire_sizes(&self, opened: &OpenedHeader) -> Result<WireSizes> {
        let (bodies, capsules) = self.layout(opened)?;
        let header_start = self.body_start();
        let header = self.frame[header_start..header_start + opened.header_ciphertext_len].len();
        let bodies = bodies.iter().map(|r| self.frame[r.clone()].len()).sum();
        let capsules = capsules.iter().map(|r| self.frame[r.clone()].len()).sum();
        let actor_width = ACTOR_CAPSULE_SIZE;
        let actor_capsules = (0..opened.header.actor_capsule_count())
            .map(|i| {
                let end = FRAME_SIZE - i * actor_width;
                self.frame[end - actor_width..end].len()
            })
            .sum();
        Ok(WireSizes {
            public: self.frame[..PUBLIC_SIZE].len(),
            outer: self.outer.wire.len(),
            proof: PROOF_SIZE,
            layout: LAYOUT_SIZE,
            header,
            bodies,
            capsules,
            actor_capsules,
        })
    }
    pub fn public(&self) -> &Public {
        &self.public
    }
    pub fn dd(&self) -> [u8; 32] {
        self.dd
    }
    pub fn hd(&self) -> [u8; 32] {
        self.hd
    }
    pub fn eid(&self) -> [u8; 32] {
        self.eid
    }
    pub fn commitment(&self) -> &Commitment {
        &self.outer.commitment
    }
    pub fn threshold(&self) -> usize {
        self.outer.commitment.coefficients.len() + 1
    }
    pub fn verify_public(
        &self,
        keys: &[ProjectivePoint],
        threshold: usize,
        epoch: u32,
        height: u64,
    ) -> Result<()> {
        if keys.len() != self.outer.ciphertexts.len()
            || threshold != self.threshold()
            || epoch != self.public.epoch
            || self.public.exp <= height
            || keylist_hash(keys)? != self.public.keylist_hash
        {
            return Err(Error::Context);
        }
        self.proof.verify(
            &self.eid,
            self.outer.ciphertext_bytes(),
            self.outer.ephemeral,
            G,
            self.outer.commitment.constant,
            None,
        )
    }
    /// Authenticate the dealing before secret-key arithmetic. The board adapter
    /// must additionally enforce epoch/expiry, uniqueness and the ordering QC.
    pub fn decrypt_share(
        &self,
        node: u16,
        secret: Scalar,
        keys: &[ProjectivePoint],
    ) -> Result<Scalar> {
        self.verify_crypto(keys)?;
        let i = node.checked_sub(1).ok_or(Error::Parameters)? as usize;
        let pk = *keys.get(i).ok_or(Error::Parameters)?;
        if mul_generator(secret) != pk {
            return Err(Error::Share);
        }
        let ct = *self.outer.ciphertexts.get(i).ok_or(Error::Parameters)?;
        let share = ct
            - share_pad(
                &self.outer.encryption_context(&self.public),
                node,
                pk,
                self.outer.ephemeral * secret,
                pad_label(),
                None,
            )?;
        if mul_generator(share) != eval_small(&self.outer.commitment, node)? {
            return Err(Error::Share);
        }
        Ok(share)
    }
    pub fn complain(
        &self,
        node: u16,
        secret: Scalar,
        keys: &[ProjectivePoint],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Complaint> {
        self.verify_crypto(keys)?;
        let pk = *keys
            .get(node.checked_sub(1).ok_or(Error::Parameters)? as usize)
            .ok_or(Error::Parameters)?;
        let complaint = Complaint {
            node,
            proof: DhProof::create(&self.eid, pk, self.outer.ephemeral, secret, rng)?,
        };
        self.verify_complaint(&complaint, keys)?;
        Ok(complaint)
    }
    pub fn verify_complaint(&self, c: &Complaint, keys: &[ProjectivePoint]) -> Result<()> {
        self.verify_crypto(keys)?;
        let i = c.node.checked_sub(1).ok_or(Error::Parameters)? as usize;
        let pk = *keys.get(i).ok_or(Error::Parameters)?;
        let ct = *self.outer.ciphertexts.get(i).ok_or(Error::Parameters)?;
        c.proof.verify(&self.eid, pk, self.outer.ephemeral)?;
        let share = ct
            - share_pad(
                &self.outer.encryption_context(&self.public),
                c.node,
                pk,
                c.proof.key,
                pad_label(),
                None,
            )?;
        if mul_generator(share) == eval_small(&self.outer.commitment, c.node)? {
            return Err(Error::Share);
        }
        Ok(())
    }
    fn verify_crypto(&self, keys: &[ProjectivePoint]) -> Result<()> {
        if keys.len() != self.outer.ciphertexts.len()
            || keylist_hash(keys)? != self.public.keylist_hash
        {
            return Err(Error::Context);
        }
        self.proof.verify(
            &self.eid,
            self.outer.ciphertext_bytes(),
            self.outer.ephemeral,
            G,
            self.outer.commitment.constant,
            None,
        )
    }
    fn body_start(&self) -> usize {
        PUBLIC_SIZE + self.outer.wire.len() + LAYOUT_SIZE + PROOF_SIZE
    }
    pub fn open_header(&self, partials: &[Partial]) -> Result<OpenedHeader> {
        let z = prf::combine(partials, self.threshold())?;
        let (key, layout_key) = prf::header_keys(z)?;
        self.open_with_header_keys(&key, &layout_key)
    }
    pub fn open_header_with_fallback(
        &self,
        partials: &[Partial],
        request_proof: impl FnMut(&Partial) -> Option<prf::Proof>,
    ) -> Result<prf::OpenOutcome<OpenedHeader>> {
        prf::combine_with_fallback(
            &self.outer.commitment,
            &self.dd,
            Label::Hdr,
            partials,
            |z| {
                let (key, layout_key) = prf::header_keys(z)?;
                self.open_with_header_keys(&key, &layout_key)
            },
            request_proof,
        )
    }
    pub fn open_with_header_keys(
        &self,
        key: &OneShotKey,
        layout_key: &OneShotKey,
    ) -> Result<OpenedHeader> {
        let layout_start = PUBLIC_SIZE + self.outer.wire.len();
        let plaintext = Zeroizing::new(layout_key.decrypt(
            &self.frame[layout_start..layout_start + LAYOUT_SIZE],
            &self.dd,
        )?);
        let mut reader = Reader::new(&plaintext);
        let mut lengths = [0u16; LAYOUT_FIELDS];
        for length in &mut lengths {
            *length = reader.u16()?;
        }
        if reader.remaining() != 0 {
            return Err(Error::Encoding);
        }
        let start = self.body_start();
        let length = usize::from(lengths[0]);
        if length < 16 || length > FRAME_SIZE - start {
            return Err(Error::Encoding);
        }
        let plaintext = Zeroizing::new(key.decrypt(&self.frame[start..start + length], &self.dd)?);
        let opened = OpenedHeader {
            header: Header::decode(&plaintext)?,
            header_ciphertext_len: length,
            lengths,
            eid: self.eid,
        };
        self.layout(&opened)?;
        Ok(opened)
    }
    fn layout(&self, opened: &OpenedHeader) -> Result<FrameLayout> {
        if opened.eid != self.eid {
            return Err(Error::Context);
        }
        let h = &opened.header;
        let mut offset = self.body_start() + opened.header_ciphertext_len;
        let mut bodies = vec![];
        let mut caps = vec![];
        let body_count = if h.kind == RequestType::Contrib {
            0
        } else {
            h.labels().len()
        };
        let cap_count = if h.kind == RequestType::Contrib {
            0
        } else {
            h.k as usize
        };
        if opened.lengths[0] as usize != opened.header_ciphertext_len
            || opened.lengths[1 + body_count..1 + BODY_MAX]
                .iter()
                .any(|length| *length != 0)
            || opened.lengths[1 + BODY_MAX + cap_count..]
                .iter()
                .any(|length| *length != 0)
        {
            return Err(Error::Encoding);
        }
        if h.kind != RequestType::Contrib {
            for length in &opened.lengths[1..1 + body_count] {
                if usize::from(*length) != 32 * h.l as usize + 48 {
                    return Err(Error::Encoding);
                }
                let end = offset + usize::from(*length);
                bodies.push(offset..end);
                offset = end;
            }
            for (i, len) in h.capsule_lengths.iter().enumerate() {
                if *len < 16 || *len != opened.lengths[1 + BODY_MAX + i] {
                    return Err(Error::Encoding);
                }
                let end = offset + *len as usize;
                caps.push(offset..end);
                offset = end;
            }
        }
        if offset > FRAME_SIZE.saturating_sub(h.actor_capsule_count() * ACTOR_CAPSULE_SIZE) {
            return Err(Error::Encoding);
        }
        Ok((bodies, caps))
    }
    pub fn open_selected(
        &self,
        opened: &OpenedHeader,
        variant: u8,
        generation: u8,
        partials: &[Partial],
    ) -> Result<OpenedVariant> {
        self.open_selected_point(
            opened,
            variant,
            generation,
            prf::combine(partials, self.threshold())?,
        )
    }
    /// A proved body that still fails names this envelope's initiator as dealer.
    pub fn open_selected_with_fallback(
        &self,
        opened: &OpenedHeader,
        variant: u8,
        generation: u8,
        partials: &[Partial],
        request_proof: impl FnMut(&Partial) -> Option<prf::Proof>,
    ) -> Result<prf::OpenOutcome<OpenedVariant>> {
        self.layout(opened)?;
        if !opened.header.labels().contains(&(variant, generation)) {
            return Err(Error::Parameters);
        }
        prf::combine_with_fallback(
            &self.outer.commitment,
            &self.dd,
            Label::Body {
                variant: variant as u16,
                generation: generation as u16,
            },
            partials,
            |z| self.open_selected_point(opened, variant, generation, z),
            request_proof,
        )
    }
    fn open_selected_point(
        &self,
        opened: &OpenedHeader,
        variant: u8,
        generation: u8,
        z: ProjectivePoint,
    ) -> Result<OpenedVariant> {
        let labels = opened.header.labels();
        let index = labels
            .iter()
            .position(|x| *x == (variant, generation))
            .ok_or(Error::Parameters)?;
        let (bodies, caps) = self.layout(opened)?;
        let range = bodies.get(index).ok_or(Error::Parameters)?;
        let plaintext =
            Zeroizing::new(prf::body_key(z)?.decrypt(&self.frame[range.clone()], &self.dd)?);
        let mut r = Reader::new(&plaintext);
        let mut scalars = Zeroizing::new(vec![]);
        for _ in 0..opened.header.l {
            let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(r.array()?);
            if opened.header.suite == 3 {
                let _scalar = Zeroizing::new(crate::ed25519::decode_scalar(&bytes)?);
            }
            scalars.push(crate::algebra::decode_scalar(&bytes)?);
        }
        let ck = OneShotKey::from_bytes(r.array()?);
        if r.remaining() != 0 {
            return Err(Error::Encoding);
        }
        let capsule = self.open_capsule(opened, variant, &ck, &caps)?;
        let (contribution_secret, contribution_public) = prf::contribution_key(z)?;
        let contribution_secret = Zeroizing::new(contribution_secret);
        if !opened.header.actors.is_empty()
            && opened.header.contribution_keys[index] != contribution_public
        {
            return Err(Error::Context);
        }
        Ok(OpenedVariant {
            scalars: core::mem::take(&mut *scalars),
            capsule,
            contribution_secret: *contribution_secret,
        })
    }
    fn open_capsule(
        &self,
        opened: &OpenedHeader,
        variant: u8,
        key: &OneShotKey,
        caps: &[std::ops::Range<usize>],
    ) -> Result<Capsule> {
        let range = caps
            .get(variant.checked_sub(1).ok_or(Error::Parameters)? as usize)
            .ok_or(Error::Parameters)?;
        let plaintext = Zeroizing::new(key.decrypt(&self.frame[range.clone()], &self.dd)?);
        let h = &opened.header;
        let halves = if h.suite == 1 {
            h.l as usize
        } else {
            variant.min(h.g) as usize * h.l as usize
        };
        let capsule = Capsule::decode(&plaintext, h.suite, halves)?;
        if capsule.actors.len() != h.actors.len() {
            return Err(Error::Encoding);
        }
        Ok(capsule)
    }
    pub fn open_actor(&self, secret: &[u8; 32], position: u8) -> Result<ActorView> {
        if position == 0 {
            return Err(Error::Parameters);
        }
        let size = ACTOR_CAPSULE_SIZE;
        let start = FRAME_SIZE
            .checked_sub(position as usize * size)
            .ok_or(Error::Encoding)?;
        if start < self.body_start() {
            return Err(Error::Encoding);
        }
        {
            let plaintext = hpke::open(secret, &self.frame[start..start + size])?;
            let plaintext = Zeroizing::new(plaintext);
            let mut r = Reader::new(&plaintext);
            let key = OneShotKey::from_bytes(r.array()?);
            let layout_key = OneShotKey::from_bytes(r.array()?);
            if r.byte()? != position {
                return Err(Error::Context);
            }
            let token = Zeroizing::new(r.array()?);
            let mut keys = vec![];
            for _ in 0..K_MAX {
                keys.push(OneShotKey::from_bytes(r.array()?))
            }
            if r.remaining() != 0 {
                return Err(Error::Encoding);
            }
            let opened = self.open_with_header_keys(&key, &layout_key)?;
            let k = opened.header.k as usize;
            if position as usize > opened.header.actor_capsule_count() {
                return Err(Error::Context);
            }
            // Padding is encrypted and canonical. No unused key has a purpose.
            for key in &keys[k..] {
                let unused = Zeroizing::new(key.export_bytes());
                require_zero(unused.as_ref())?;
            }
            let actor = &opened.header.actors[position as usize - 1];
            if actor.position != position || actor.token_hash != token_hash(&token) {
                return Err(Error::Context);
            }
            let (_, ranges) = self.layout(&opened)?;
            let mut capsules = vec![];
            for (i, key) in keys[..k].iter().enumerate() {
                capsules.push(self.open_capsule(&opened, (i + 1) as u8, key, &ranges)?)
            }
            Ok(ActorView {
                opened,
                capsules,
                position,
                token: *token,
            })
        }
    }
}
#[derive(Clone, Debug)]
pub struct OpenedHeader {
    header: Header,
    header_ciphertext_len: usize,
    lengths: [u16; LAYOUT_FIELDS],
    eid: [u8; 32],
}
impl OpenedHeader {
    pub fn header(&self) -> &Header {
        &self.header
    }
}
type FrameLayout = (Vec<std::ops::Range<usize>>, Vec<std::ops::Range<usize>>);
pub struct OpenedVariant {
    pub scalars: Vec<Scalar>,
    pub capsule: Capsule,
    pub contribution_secret: Scalar,
}
impl Drop for OpenedVariant {
    fn drop(&mut self) {
        self.scalars.zeroize();
        self.contribution_secret.zeroize();
    }
}
pub struct ActorView {
    pub opened: OpenedHeader,
    pub capsules: Vec<Capsule>,
    pub position: u8,
    pub token: [u8; 16],
}
impl Zeroize for Header {
    fn zeroize(&mut self) {
        self.kind = RequestType::Birth;
        self.suite.zeroize();
        self.k.zeroize();
        self.l.zeroize();
        self.g.zeroize();
        self.slots.zeroize();
        self.tickets.zeroize();
        self.actors.zeroize();
        self.delta_c.zeroize();
        self.ic.zeroize();
        self.r_tkc.zeroize();
        self.contribution_keys.clear();
        self.tee.zeroize();
        self.extension.zeroize();
        self.contribution.zeroize();
        self.capsule_lengths.zeroize();
    }
}
impl Drop for Header {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for Capsule {
    fn zeroize(&mut self) {
        self.transaction.zeroize();
        self.prevouts.zeroize();
        self.destination.zeroize();
        self.nonces.zeroize();
        self.salt.zeroize();
        self.initiator_term.zeroize();
        self.initiator.zeroize();
        self.signing_set.zeroize();
        self.actors.zeroize();
    }
}
impl Drop for Capsule {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for CapsuleActor {
    fn zeroize(&mut self) {
        self.leaf.zeroize();
        self.pool_id.zeroize();
        self.pair_indices.zeroize();
        self.weighted_point.zeroize();
    }
}
impl Drop for CapsuleActor {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for TeeFields {
    fn zeroize(&mut self) {
        self.intent.zeroize();
        self.public_key.zeroize();
        self.leaf_root.zeroize();
        self.r_ic.zeroize();
        self.salts.zeroize();
        self.actors.zeroize();
    }
}
impl Drop for TeeFields {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for TeeActor {
    fn zeroize(&mut self) {
        self.weighted_point.zeroize();
        self.pair_ids.zeroize();
    }
}
impl Drop for TeeActor {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ActorSlot {
    fn zeroize(&mut self) {
        self.position.zeroize();
        self.token_hash.zeroize();
        self.party_index.zeroize();
        self.embedded.zeroize();
    }
}
impl Drop for ActorSlot {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for EmbeddedContribution {
    fn zeroize(&mut self) {
        self.token.zeroize();
        self.sealed.clear();
    }
}
impl Drop for EmbeddedContribution {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ContributionPayload {
    fn zeroize(&mut self) {
        self.target_hd.zeroize();
        self.position.zeroize();
        self.token.zeroize();
        self.sealed.clear();
    }
}
impl Drop for ContributionPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ActorRecipient {
    fn zeroize(&mut self) {
        self.position.zeroize();
        self.token.zeroize();
        self.public_key.zeroize();
    }
}
impl Drop for ActorRecipient {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ActorView {
    fn zeroize(&mut self) {
        self.opened.header.zeroize();
        self.capsules.zeroize();
        self.position.zeroize();
        self.token.zeroize();
    }
}
impl Drop for ActorView {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Epoch-scoped uniqueness check; callers insert only after public verification.
#[derive(Default)]
pub struct SeenDealings {
    seen: BTreeSet<(u32, [u8; 32])>,
}
impl SeenDealings {
    pub fn accept(&mut self, envelope: &Envelope) -> Result<()> {
        if self.seen.insert((envelope.public.epoch, envelope.dd)) {
            Ok(())
        } else {
            Err(Error::Context)
        }
    }
    pub fn forget_epoch(&mut self, epoch: u32) {
        self.seen.retain(|(e, _)| *e != epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::encode_point;
    use crate::experiment::SeededRng;

    #[test]
    fn plaintext_owners_clear_sensitive_fields() {
        let (mut header, _, mut capsules) = request_parts(17);
        header.ic = [4; 32];
        header.r_tkc = [5; 32];
        header.extension = vec![6; 16];
        header.actors.push(ActorSlot {
            position: 1,
            token_hash: [7; 32],
            party_index: None,
            embedded: Some(EmbeddedContribution {
                token: [8; 16],
                sealed: vec![],
            }),
        });
        header.zeroize();
        assert!(header.tickets.is_empty());
        assert!(header.actors.is_empty());
        assert!(header.extension.is_empty());
        assert_eq!(header.ic, [0; 32]);
        assert_eq!(header.r_tkc, [0; 32]);
        let capsule = &mut capsules[0];
        capsule.zeroize();
        assert!(capsule.transaction.is_empty());
        assert!(capsule.prevouts.is_empty());
        assert!(capsule.destination.is_empty());
        assert!(capsule.nonces.is_empty());
        assert!(capsule.initiator_term.is_empty());
        assert!(capsule.signing_set.is_empty());
        assert_eq!(capsule.salt, [0; 32]);

        let mut tee = TeeFields {
            intent: vec![1; 8],
            public_key: vec![2; 33],
            leaf_root: [3; 32],
            r_ic: [4; 32],
            salts: vec![[5; 32]],
            actors: vec![TeeActor {
                weighted_point: vec![6; 33],
                pair_ids: vec![7],
            }],
        };
        tee.zeroize();
        assert!(tee.intent.is_empty());
        assert!(tee.public_key.is_empty());
        assert_eq!(tee.leaf_root, [0; 32]);
        assert_eq!(tee.r_ic, [0; 32]);
        assert!(tee.salts.is_empty());
        assert!(tee.actors.is_empty());
    }

    #[test]
    fn actor_token_owners_clear_tokens_and_opened_plaintext() {
        let mut recipient = ActorRecipient {
            position: 1,
            token: [3; 16],
            public_key: [4; 32],
        };
        recipient.zeroize();
        assert_eq!(recipient.token, [0; 16]);
        let (mut header, _, capsules) = request_parts(17);
        header.r_tkc = [7; 32];
        let mut view = ActorView {
            opened: OpenedHeader {
                header,
                header_ciphertext_len: 0,
                lengths: [0; LAYOUT_FIELDS],
                eid: [8; 32],
            },
            capsules,
            position: 1,
            token: [9; 16],
        };
        view.zeroize();
        assert_eq!(view.token, [0; 16]);
        assert_eq!(view.opened.header.r_tkc, [0; 32]);
        assert!(view.capsules.is_empty());
    }

    #[test]
    fn selected_ed25519_body_rejects_scalar_at_group_order() {
        let (secrets, keys) = committee();
        let mut rng = SeededRng::new(403);
        let maximum = crate::algebra::decode_scalar(&crate::ed25519::encode_scalar(
            -curve25519_dalek::scalar::Scalar::ONE,
        ))
        .unwrap();
        for scalar in [maximum, maximum + Scalar::ONE] {
            let public = Public::new(7, keylist_hash(&keys).unwrap(), 100);
            let prepared = PreparedEnvelope::new(public, &keys, 2, &mut rng).unwrap();
            let (mut header, mut bodies, mut capsules) = request_parts(17);
            header.suite = 3;
            bodies[0][0] = maximum;
            let point =
                crate::ed25519::encode_point(curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
                    .unwrap()
                    .to_vec();
            capsules[0].nonces[0] = point.clone();
            capsules[0].initiator_term = point;
            let body_start = PUBLIC_SIZE
                + prepared.outer.wire.len()
                + PROOF_SIZE
                + LAYOUT_SIZE
                + header.encode().unwrap().len()
                + 16;
            let z = prf::evaluate(
                prepared.secret,
                &prepared.dd,
                Label::Body {
                    variant: 1,
                    generation: 1,
                },
            )
            .unwrap();
            let mut pending = prepared
                .build(header, bodies, capsules, vec![], &mut rng)
                .unwrap();
            if scalar != maximum {
                // A malicious dealer can authenticate a noncanonical body scalar.
                let dd = h(
                    "SL1/dd",
                    &[
                        pending.public.masked().as_slice(),
                        pending.outer.wire.as_slice(),
                    ]
                    .concat(),
                );
                let mut plaintext = Zeroizing::new(
                    prf::body_key(z)
                        .unwrap()
                        .decrypt(&pending.frame[body_start..body_start + 80], &dd)
                        .unwrap(),
                );
                plaintext[..32].copy_from_slice(&scalar.to_bytes());
                let ciphertext = prf::body_key(z).unwrap().encrypt(&plaintext, &dd).unwrap();
                pending.frame[body_start..body_start + 80].copy_from_slice(&ciphertext);
                pending.hd = hash_frame(
                    &pending.frame,
                    PUBLIC_SIZE + pending.outer.wire.len() + LAYOUT_SIZE,
                    "SL1/hd",
                );
            }
            let envelope = pending.authorize(Some([42; 32]), &mut rng).unwrap();
            envelope.verify_public(&keys, 2, 7, 99).unwrap();
            let partials = |label| {
                (1..=2)
                    .map(|i| {
                        let share = envelope
                            .decrypt_share(i, secrets[i as usize - 1], &keys)
                            .unwrap();
                        prf::partial(share, i, &envelope.dd(), label).unwrap()
                    })
                    .collect::<Vec<_>>()
            };
            let header = envelope.open_header(&partials(Label::Hdr)).unwrap();
            let result = envelope.open_selected(
                &header,
                1,
                1,
                &partials(Label::Body {
                    variant: 1,
                    generation: 1,
                }),
            );
            if scalar == maximum {
                assert_eq!(result.unwrap().scalars, vec![scalar]);
            } else {
                assert!(matches!(result, Err(Error::Scalar)));
            }
        }
    }

    fn committee() -> (Vec<Scalar>, Vec<ProjectivePoint>) {
        let secrets: Vec<_> = (11u64..=13).map(Scalar::from).collect();
        let keys = secrets.iter().map(|secret| G * secret).collect();
        (secrets, keys)
    }

    fn request_parts(marker: u64) -> (Header, Vec<Vec<Scalar>>, Vec<Capsule>) {
        let mut header = Header::request(RequestType::Spend, 2, 1, 1).unwrap();
        header.slots.push(1);
        let mut ticket = vec![0; header.ticket_len()];
        ticket[..4].copy_from_slice(&1u32.to_be_bytes());
        header.tickets.push(ticket);
        let point = encode_point(G).unwrap().to_vec();
        let capsule = Capsule {
            transaction: marker.to_be_bytes().to_vec(),
            prevouts: vec![1; 8],
            destination: vec![2; 8],
            nonces: vec![point.clone()],
            salt: [3; 32],
            initiator_term: point,
            initiator: 1,
            signing_set: vec![1],
            actors: vec![],
        };
        (header, vec![vec![Scalar::from(marker)]], vec![capsule])
    }

    #[test]
    fn authenticated_bad_dealer_ciphertext_has_a_publicly_valid_complaint() {
        let (secrets, keys) = committee();
        let mut rng = SeededRng::new(401);
        let public = Public::new(7, keylist_hash(&keys).unwrap(), 100);
        let mut prepared = PreparedEnvelope::new(public, &keys, 2, &mut rng).unwrap();
        let faulty = 1;
        prepared.outer.ciphertexts[faulty] += Scalar::ONE;
        let start = 2 * 33 + faulty * 32;
        prepared.outer.wire[start..start + 32]
            .copy_from_slice(&prepared.outer.ciphertexts[faulty].to_bytes());
        prepared.dd = h(
            "SL1/dd",
            &[
                prepared.public.masked().as_slice(),
                prepared.outer.wire.as_slice(),
            ]
            .concat(),
        );
        let (header, bodies, capsules) = request_parts(17);
        let envelope = prepared
            .build(header, bodies, capsules, vec![], &mut rng)
            .unwrap()
            .authorize(Some([42; 32]), &mut rng)
            .unwrap();
        envelope.verify_public(&keys, 2, 7, 99).unwrap();
        envelope.decrypt_share(1, secrets[0], &keys).unwrap();
        envelope.decrypt_share(3, secrets[2], &keys).unwrap();
        assert_eq!(
            envelope.decrypt_share(2, secrets[1], &keys),
            Err(Error::Share)
        );
        assert!(envelope.complain(1, secrets[0], &keys, &mut rng).is_err());

        let complaint = envelope.complain(2, secrets[1], &keys, &mut rng).unwrap();
        envelope.verify_complaint(&complaint, &keys).unwrap();
        let decoded = Envelope::decode(envelope.as_bytes(), 3, 2).unwrap();
        decoded.verify_complaint(&complaint, &keys).unwrap();
        let mut wrong_node = complaint.clone();
        wrong_node.node = 1;
        assert!(decoded.verify_complaint(&wrong_node, &keys).is_err());
        let mut forged_proof = complaint;
        forged_proof.proof.z += Scalar::ONE;
        assert!(decoded.verify_complaint(&forged_proof, &keys).is_err());
    }

    #[test]
    fn copied_outer_with_new_bodies_and_valid_eid_proof_is_rejected_by_dd() {
        let (secrets, keys) = committee();
        let mut rng = SeededRng::new(402);
        let public = Public::new(7, keylist_hash(&keys).unwrap(), 100);
        let prepared = PreparedEnvelope::new(public, &keys, 2, &mut rng).unwrap();
        // A malicious dealer retains its secrets and copies the outer dealing.
        let copied = PreparedEnvelope {
            public: prepared.public.clone(),
            outer: prepared.outer.clone(),
            secret: prepared.secret,
            ephemeral: prepared.ephemeral,
            dd: prepared.dd,
        };
        let (header, bodies, capsules) = request_parts(17);
        let original = prepared
            .build(header, bodies, capsules, vec![], &mut rng)
            .unwrap()
            .authorize(Some([42; 32]), &mut rng)
            .unwrap();
        let (header, bodies, capsules) = request_parts(19);
        let changed = copied
            .build(header, bodies, capsules, vec![], &mut rng)
            .unwrap()
            .authorize(Some([42; 32]), &mut rng)
            .unwrap();
        original.verify_public(&keys, 2, 7, 99).unwrap();
        changed.verify_public(&keys, 2, 7, 99).unwrap();
        assert_eq!(original.outer.wire, changed.outer.wire);
        assert_eq!(original.dd(), changed.dd());
        assert_ne!(original.hd(), changed.hd());
        assert_ne!(original.eid(), changed.eid());
        assert!(original
            .proof
            .verify(
                &changed.eid(),
                changed.outer.ciphertext_bytes(),
                changed.outer.ephemeral,
                G,
                changed.outer.commitment.constant,
                None,
            )
            .is_err());

        for (envelope, expected) in [(&original, 17), (&changed, 19)] {
            let shares: Vec<_> = (1..=2)
                .map(|i| {
                    envelope
                        .decrypt_share(i, secrets[i as usize - 1], &keys)
                        .unwrap()
                })
                .collect();
            let partials = |label| {
                shares
                    .iter()
                    .enumerate()
                    .map(|(i, share)| {
                        prf::partial(*share, (i + 1) as u16, &envelope.dd(), label).unwrap()
                    })
                    .collect::<Vec<_>>()
            };
            let opened = envelope.open_header(&partials(Label::Hdr)).unwrap();
            let body = envelope
                .open_selected(
                    &opened,
                    1,
                    1,
                    &partials(Label::Body {
                        variant: 1,
                        generation: 1,
                    }),
                )
                .unwrap();
            assert_eq!(body.scalars, vec![Scalar::from(expected as u64)]);
        }
        let mut seen = SeenDealings::default();
        seen.accept(&original).unwrap();
        assert_eq!(seen.accept(&changed), Err(Error::Context));
    }
}
