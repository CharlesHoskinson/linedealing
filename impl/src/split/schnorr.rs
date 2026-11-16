//! BIP340 and Ed25519 split signing (DESIGN §§4.1–4.3, 4.7, 5.6).
//!
//! Requests contain public inputs. Each actor derives its own transcript before
//! consuming a nonce. Nodes consume a slot only after checking its ticket.
//! These in-memory guards require the board/witness persistence of §5.6 in a
//! deployment. Transaction parsing and actor policy run above this algebra API.
use super::{
    access::{Gate, LeafId},
    birth::{ActorShares, Committee},
    group::{lagrange, Edwards, Secp, Suite},
    slots::NonceSlot,
};
use crate::{Error, Result};
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::elliptic_curve::zeroize::Zeroize;
use std::collections::{BTreeMap, BTreeSet};

pub const G_MAX: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Half {
    pub variant: u16,
    pub generation: u16,
    pub input: u16,
}

pub fn halves(variants: u16, inputs: u16) -> Result<Vec<Half>> {
    if variants == 0 || inputs == 0 {
        return Err(Error::Parameters);
    }
    Ok((1..=variants)
        .flat_map(|variant| {
            (1..=variant.min(G_MAX)).flat_map(move |generation| {
                (0..inputs).map(move |input| Half {
                    variant,
                    generation,
                    input,
                })
            })
        })
        .collect())
}

/// Standard signature operations, distinct from protocol hash-to-scalar.
pub type OutputKey<S> = (
    <S as Suite>::Point,
    <S as Suite>::Scalar,
    <S as Suite>::Scalar,
    <S as Suite>::Scalar,
);
pub trait SchnorrSuite: Suite {
    fn output_key(x: Self::Point, root: &[u8]) -> Result<OutputKey<Self>>;
    fn nonce_sign(r: Self::Point) -> Result<Self::Scalar>;
    fn signature_point(p: Self::Point) -> Result<[u8; 32]>;
    fn challenge(r: Self::Point, q: Self::Point, message: &[u8]) -> Result<Self::Scalar>;
    fn signature(r: Self::Point, s: Self::Scalar) -> Result<[u8; 64]>;
    fn verify(q: Self::Point, message: &[u8], signature: &[u8; 64]) -> Result<()>;
}

impl SchnorrSuite for Secp {
    fn output_key(
        x: Self::Point,
        root: &[u8],
    ) -> Result<(Self::Point, Self::Scalar, Self::Scalar, Self::Scalar)> {
        if !root.is_empty() && root.len() != 32 {
            return Err(Error::Parameters);
        }
        let encoded = Self::encode_point(x)?;
        // Parity is public. Normalize its sign without a scalar multiplication.
        let (gp, p) = if encoded[0] == 3 {
            (-Self::scalar_one(), -x)
        } else {
            (Self::scalar_one(), x)
        };
        let mut input = encoded[1..].to_vec();
        input.extend_from_slice(root);
        // BIP341 rejects out-of-range tweaks rather than reducing them.
        let tap = crate::algebra::decode_scalar(&crate::hash::h("TapTweak", &input))?;
        let q = p + Self::generator_mul(tap);
        let gq = Self::nonce_sign(q)?;
        Ok((q, gp, gq, tap))
    }
    fn nonce_sign(r: Self::Point) -> Result<Self::Scalar> {
        Ok(if crate::algebra::is_odd(r)? {
            -Self::scalar_one()
        } else {
            Self::scalar_one()
        })
    }
    fn signature_point(p: Self::Point) -> Result<[u8; 32]> {
        crate::algebra::x_bytes(p)
    }
    fn challenge(r: Self::Point, q: Self::Point, message: &[u8]) -> Result<Self::Scalar> {
        if message.len() != 32 {
            return Err(Error::Parameters);
        }
        let encoded = Self::encode_points(&[r, q])?;
        let bytes = [&encoded[0][1..], &encoded[1][1..], message].concat();
        Ok(crate::algebra::reduce(&crate::hash::h(
            "BIP0340/challenge",
            &bytes,
        )))
    }
    fn signature(r: Self::Point, s: Self::Scalar) -> Result<[u8; 64]> {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&Self::signature_point(r)?);
        bytes[32..].copy_from_slice(&Self::encode_scalar(s));
        Ok(bytes)
    }
    fn verify(q: Self::Point, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let key = k256::schnorr::VerifyingKey::from_bytes(&Self::signature_point(q)?)
            .map_err(|_| Error::Point)?;
        let sig = k256::schnorr::Signature::try_from(signature.as_slice())
            .map_err(|_| Error::Signature)?;
        key.verify_raw(message, &sig).map_err(|_| Error::Signature)
    }
}
impl SchnorrSuite for Edwards {
    fn output_key(
        x: Self::Point,
        root: &[u8],
    ) -> Result<(Self::Point, Self::Scalar, Self::Scalar, Self::Scalar)> {
        if !root.is_empty() {
            return Err(Error::Parameters);
        }
        if x == Self::identity() {
            return Err(Error::Point);
        }
        Ok((
            x,
            Self::scalar_one(),
            Self::scalar_one(),
            Self::scalar_zero(),
        ))
    }
    fn nonce_sign(r: Self::Point) -> Result<Self::Scalar> {
        if r == Self::identity() {
            return Err(Error::Point);
        }
        Ok(Self::scalar_one())
    }
    fn signature_point(p: Self::Point) -> Result<[u8; 32]> {
        if p == Self::identity() {
            return Err(Error::Point);
        }
        Ok(p.compress().to_bytes())
    }
    fn challenge(r: Self::Point, q: Self::Point, message: &[u8]) -> Result<Self::Scalar> {
        Ok(crate::ed25519::challenge(r, q, message))
    }
    fn signature(r: Self::Point, s: Self::Scalar) -> Result<[u8; 64]> {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&Self::signature_point(r)?);
        bytes[32..].copy_from_slice(&s.to_bytes());
        Ok(bytes)
    }
    fn verify(q: Self::Point, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&Self::signature_point(q)?)
            .map_err(|_| Error::Point)?;
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| Error::Signature)
    }
}

#[derive(Clone, Debug)]
pub struct SigningKey<S: SchnorrSuite> {
    pub gate: Gate,
    pub initiators: Vec<LeafId>,
    pub leaves: BTreeMap<LeafId, S::Point>,
    pub committee: S::Point,
    pub tweak: S::Scalar,
    pub root: Vec<u8>,
    pub x: S::Point,
}
impl<S: SchnorrSuite> SigningKey<S> {
    pub fn new(
        committee: S::Point,
        actors: &ActorShares<S>,
        tweak: S::Scalar,
        root: Vec<u8>,
        initiators: Vec<LeafId>,
    ) -> Result<Self> {
        S::validate_point(committee)?;
        S::validate_point(actors.public)?;
        for point in actors.points.values() {
            S::validate_point(*point)?;
        }
        let x = committee + actors.public + S::generator_mul(tweak);
        S::output_key(x, &root)?;
        if initiators.is_empty() || initiators.iter().any(|id| !actors.points.contains_key(id)) {
            return Err(Error::Parameters);
        }
        Ok(Self {
            gate: actors.gate.clone(),
            initiators,
            leaves: actors.points.clone(),
            committee,
            tweak,
            root,
            x,
        })
    }
    pub fn output(&self) -> Result<S::Point> {
        Ok(S::output_key(self.x, &self.root)?.0)
    }
    fn validate_points(&self) -> Result<()> {
        for point in [self.committee, self.x] {
            S::validate_point(point)?;
        }
        for point in self.leaves.values() {
            S::validate_point(*point)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolCommitment<S: Suite> {
    pub pool_id: [u8; 32],
    pub index: u32,
    pub d: S::Point,
    pub e: S::Point,
}
#[derive(Clone, Debug)]
pub struct Request<S: SchnorrSuite> {
    pub epoch: u64,
    pub slot: u64,
    pub half: Half,
    pub initiator: LeafId,
    pub signers: Vec<LeafId>,
    pub r0: S::Point,
    pub pairs: BTreeMap<LeafId, PoolCommitment<S>>,
    pub d: S::Point,
    pub e: S::Point,
    pub message: Vec<u8>,
    pub salt_v: [u8; 32],
    pub fee_rate: u64,
    pub not_before: u64,
    pub exp_c: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket<S: Suite> {
    pub slot: u64,
    pub actor_nonce: S::Point,
    pub pm: [u8; 32],
    pub challenge: S::Scalar,
    pub nonce: [u8; 32],
    pub fee_rate: u64,
    pub not_before: u64,
}
#[derive(Clone, Debug)]
pub struct Transcript<S: SchnorrSuite> {
    pub output_key: S::Point,
    pub ticket: Ticket<S>,
    pub weights: BTreeMap<LeafId, S::Scalar>,
    pub actor_bindings: BTreeMap<LeafId, S::Scalar>,
    pub committee_binding: S::Scalar,
    pub nonce: S::Point,
    pub sigma: S::Scalar,
    pub challenge: S::Scalar,
    pub tweak_term: S::Scalar,
    pub parity: (S::Scalar, S::Scalar, S::Scalar),
}
fn committee_binding<S: Suite>(epoch: u64, ticket: &Ticket<S>) -> Result<S::Scalar> {
    let mut bytes = vec![S::SUITE_ID];
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&ticket.slot.to_be_bytes());
    bytes.extend_from_slice(&S::encode_point(ticket.actor_nonce)?);
    bytes.extend_from_slice(&ticket.pm);
    Ok(S::hash_to_scalar("SL1/bind", &bytes))
}
impl<S: SchnorrSuite> Request<S> {
    /// Compare the ticket supplied by the initiator with the actor's own result.
    pub fn check_ticket(&self, key: &SigningKey<S>, ticket: &Ticket<S>) -> Result<()> {
        if self.transcript(key)?.ticket != *ticket {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// Derive everything from the capsule and registered public keys.
    pub fn transcript(&self, key: &SigningKey<S>) -> Result<Transcript<S>> {
        key.validate_points()?;
        self.transcript_with_validated_key(key)
    }
    fn transcript_with_validated_key(&self, key: &SigningKey<S>) -> Result<Transcript<S>> {
        // This API also accepts typed points, so decoding provenance cannot be
        // assumed. Validate at acceptance; hash encodings below do not recheck.
        for point in [self.r0, self.d, self.e] {
            S::validate_point(point)?;
        }
        for pair in self.pairs.values() {
            S::validate_point(pair.d)?;
            S::validate_point(pair.e)?;
        }
        if self.half.variant == 0
            || self.half.generation == 0
            || self.half.generation > self.half.variant.min(G_MAX)
        {
            return Err(Error::Parameters);
        }
        key.gate
            .check_initiator(&self.signers, &self.initiator, &key.initiators)?;
        let weights = key.gate.weights::<S>(&self.signers)?;
        if self.pairs.len() + 1 != weights.len()
            || self.pairs.contains_key(&self.initiator)
            || self.pairs.keys().any(|id| !weights.contains_key(id))
        {
            return Err(Error::Context);
        }
        let mut recomputed = key.committee + S::generator_mul(key.tweak);
        for (id, w) in &weights {
            recomputed = recomputed + S::mul(*key.leaves.get(id).ok_or(Error::Context)?, *w);
        }
        if recomputed != key.x {
            return Err(Error::Context);
        }
        let (q, gp, gq, tap) = S::output_key(recomputed, &key.root)?;
        let salt = crate::hash::h(
            "SL1/salt",
            &[
                self.salt_v.as_slice(),
                &self.half.generation.to_be_bytes(),
                &self.half.input.to_be_bytes(),
            ]
            .concat(),
        );
        let pm = crate::hash::h(
            "SL1/pm",
            &[S::signature_point(q)?.as_slice(), &self.message, &salt].concat(),
        );
        // One affine batch for the entire commitment list. Hash these bytes
        // directly instead of encoding a point once per actor binding.
        let mut cl_points = vec![self.r0];
        for pair in self.pairs.values() {
            cl_points.extend([pair.d, pair.e]);
        }
        cl_points.extend([self.d, self.e]);
        let encoded = S::encode_points(&cl_points)?;
        let mut encoded = encoded.into_iter();
        let mut cl = encoded.next().ok_or(Error::Point)?;
        let mut distinct = BTreeSet::new();
        for (id, pair) in &self.pairs {
            if !distinct.insert((pair.pool_id, pair.index)) {
                return Err(Error::Nonce);
            }
            cl.extend_from_slice(&id.encode());
            cl.extend_from_slice(&pair.pool_id);
            cl.extend_from_slice(&pair.index.to_be_bytes());
            cl.extend_from_slice(&encoded.next().ok_or(Error::Point)?);
            cl.extend_from_slice(&encoded.next().ok_or(Error::Point)?);
        }
        cl.extend_from_slice(&self.slot.to_be_bytes());
        cl.extend_from_slice(&encoded.next().ok_or(Error::Point)?);
        cl.extend_from_slice(&encoded.next().ok_or(Error::Point)?);
        let mut actor_bindings = BTreeMap::new();
        let mut actor_nonce = self.r0;
        for (id, pair) in &self.pairs {
            let bytes = [
                &[S::SUITE_ID],
                self.epoch.to_be_bytes().as_slice(),
                &id.encode(),
                &cl,
                &pm,
            ]
            .concat();
            let rho = S::hash_to_scalar("SL1/bind-act", &bytes);
            actor_bindings.insert(id.clone(), rho);
            actor_nonce = actor_nonce + pair.d + S::mul(pair.e, rho);
        }
        let mut ticket = Ticket {
            slot: self.slot,
            actor_nonce,
            pm,
            challenge: S::scalar_zero(),
            nonce: [0; 32],
            fee_rate: self.fee_rate,
            not_before: self.not_before,
        };
        let rho = committee_binding::<S>(self.epoch, &ticket)?;
        let nonce = actor_nonce + self.d + S::mul(self.e, rho);
        let sigma = S::nonce_sign(nonce)?;
        let challenge = S::challenge(nonce, q, &self.message)?;
        ticket.challenge = gp * gq * challenge;
        ticket.nonce = S::signature_point(nonce)?;
        Ok(Transcript {
            output_key: q,
            tweak_term: ticket.challenge * key.tweak + challenge * gq * tap,
            ticket,
            weights,
            actor_bindings,
            committee_binding: rho,
            nonce,
            sigma,
            challenge,
            parity: (gp, gq, sigma),
        })
    }
}

/// Validate the relations between halves before any actor spends a pool pair.
pub fn validate_halves<S: SchnorrSuite>(
    key: &SigningKey<S>,
    requests: &[Request<S>],
) -> Result<Vec<Transcript<S>>> {
    if requests.is_empty() {
        return Err(Error::Parameters);
    }
    // The same immutable key applies to every half in this batch.
    key.validate_points()?;
    let mut halves_seen = BTreeSet::new();
    let mut nonce_seen = BTreeSet::new();
    let mut pairs_seen = BTreeSet::new();
    let mut by_generation = BTreeMap::new();
    let mut by_slot = BTreeMap::new();
    let mut slot_points = BTreeMap::new();
    let mut result = Vec::new();
    for r in requests {
        let first = &requests[0];
        if r.epoch != first.epoch
            || r.signers != first.signers
            || r.initiator != first.initiator
            || r.exp_c != first.exp_c
            || !halves_seen.insert(r.half)
        {
            return Err(Error::Context);
        }
        let coordinate = (r.half.generation, r.half.input);
        if by_generation
            .insert(coordinate, r.slot)
            .is_some_and(|old| old != r.slot)
            || by_slot
                .insert(r.slot, coordinate)
                .is_some_and(|old| old != coordinate)
            || slot_points
                .insert(r.slot, (r.d, r.e))
                .is_some_and(|old| old != (r.d, r.e))
        {
            return Err(Error::Nonce);
        }
        for (leaf, pair) in &r.pairs {
            if !pairs_seen.insert((leaf.clone(), pair.pool_id, pair.index)) {
                return Err(Error::Nonce);
            }
        }
        let tr = r.transcript_with_validated_key(key)?;
        if !nonce_seen.insert(S::encode_point(tr.ticket.actor_nonce)?) {
            return Err(Error::Nonce);
        }
        result.push(tr);
    }
    Ok(result)
}

/// Check the complete fee grid as well as nonce and slot uniqueness.
pub fn validate_schedule<S: SchnorrSuite>(
    key: &SigningKey<S>,
    requests: &[Request<S>],
    variants: u16,
    inputs: u16,
) -> Result<()> {
    let expected: BTreeSet<_> = halves(variants, inputs)?.into_iter().collect();
    let actual: BTreeSet<_> = requests.iter().map(|r| r.half).collect();
    if expected != actual || expected.len() != requests.len() {
        return Err(Error::Parameters);
    }
    validate_halves(key, requests)?;
    Ok(())
}

/// Non-cloneable local pool. Consumed pair storage is zeroized before release.
pub struct ActorPool<S: SchnorrSuite> {
    leaf: LeafId,
    secret: S::Scalar,
    public: Vec<PoolCommitment<S>>,
    secrets: Vec<Option<(S::Scalar, S::Scalar)>>,
}
impl<S: SchnorrSuite> ActorPool<S> {
    pub fn new(
        leaf: LeafId,
        pool_id: [u8; 32],
        secret: S::Scalar,
        tweak: S::Scalar,
        count: u32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if count == 0 {
            return Err(Error::Parameters);
        }
        let mut public = Vec::new();
        let mut secrets = Vec::new();
        for index in 0..count {
            let mut context = [
                S::encode_scalar(secret).as_slice(),
                &S::encode_scalar(tweak),
                &pool_id,
                &index.to_be_bytes(),
            ]
            .concat();
            let mut ds = Vec::new();
            for label in [0u8, 1] {
                let mut bytes = context.clone();
                bytes.push(label);
                bytes.extend_from_slice(&S::encode_scalar(S::random(rng)));
                let s = S::hash_to_scalar("SL1/actor-nonce", &bytes);
                bytes.zeroize();
                if s == S::scalar_zero() {
                    return Err(Error::Nonce);
                }
                ds.push(s);
            }
            public.push(PoolCommitment {
                pool_id,
                index,
                d: S::generator_mul(ds[0]),
                e: S::generator_mul(ds[1]),
            });
            secrets.push(Some((ds[0], ds[1])));
            ds.zeroize();
            context.zeroize();
        }
        Ok(Self {
            leaf,
            secret,
            public,
            secrets,
        })
    }
    /// Actor identity bound to this local nonce pool.
    pub fn leaf(&self) -> &LeafId {
        &self.leaf
    }
    pub fn commitment(&self, index: u32) -> Result<PoolCommitment<S>> {
        self.public.get(index as usize).cloned().ok_or(Error::Nonce)
    }
    pub fn unused(&self) -> usize {
        self.secrets.iter().filter(|s| s.is_some()).count()
    }
    pub fn contribute(
        &mut self,
        key: &SigningKey<S>,
        request: &Request<S>,
        now: u64,
    ) -> Result<S::Scalar> {
        Ok(self
            .contribute_batch(key, std::slice::from_ref(request), now)?
            .remove(0))
    }
    /// Validate the entire request before consuming any pair; reject pair reuse
    /// across different halves even when those halves share a committee slot.
    pub fn contribute_batch(
        &mut self,
        key: &SigningKey<S>,
        requests: &[Request<S>],
        now: u64,
    ) -> Result<Vec<S::Scalar>> {
        if requests.is_empty() {
            return Err(Error::Context);
        }
        let transcripts = validate_halves(key, requests)?;
        self.contribute_batch_with_transcripts(key, requests, &transcripts, now)
    }
    /// Internal reuse after `validate_halves` on these exact requests and key.
    /// The caller must not mutate either input after transcript derivation.
    pub(crate) fn contribute_batch_with_transcripts(
        &mut self,
        key: &SigningKey<S>,
        requests: &[Request<S>],
        transcripts: &[Transcript<S>],
        now: u64,
    ) -> Result<Vec<S::Scalar>> {
        if requests.len() != transcripts.len() {
            return Err(Error::Context);
        }
        if requests.is_empty() || key.leaves.get(&self.leaf) != Some(&S::generator_mul(self.secret))
        {
            return Err(Error::Context);
        }
        let mut work = Vec::new();
        let mut seen = BTreeSet::new();
        for (request, transcript) in requests.iter().zip(transcripts) {
            if now > request.exp_c {
                return Err(Error::Nonce);
            }
            let pair = request.pairs.get(&self.leaf).ok_or(Error::Context)?;
            if self.public.get(pair.index as usize) != Some(pair)
                || !seen.insert(pair.index)
                || self
                    .secrets
                    .get(pair.index as usize)
                    .is_none_or(|p| p.is_none())
            {
                return Err(Error::Nonce);
            }
            work.push((pair.index, transcript));
        }
        let mut result = Vec::new();
        for (index, tr) in work {
            let pair = self.secrets[index as usize].as_mut().ok_or(Error::Nonce)?;
            let (mut d, mut e) = *pair;
            pair.zeroize();
            self.secrets[index as usize] = None;
            result.push(
                tr.sigma * (d + tr.actor_bindings[&self.leaf] * e)
                    + tr.ticket.challenge * tr.weights[&self.leaf] * self.secret,
            );
            d.zeroize();
            e.zeroize();
        }
        Ok(result)
    }
}

impl<S: SchnorrSuite> Drop for ActorPool<S> {
    fn drop(&mut self) {
        self.secret.zeroize();
        for pair in self.secrets.iter_mut().flatten() {
            pair.zeroize();
        }
    }
}

pub struct InitiatorNonce<S: SchnorrSuite> {
    leaf: LeafId,
    secret: S::Scalar,
    nonce: S::Scalar,
    slot: u64,
    message: Vec<u8>,
}
impl<S: SchnorrSuite> Drop for InitiatorNonce<S> {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.secret.zeroize();
    }
}
impl<S: SchnorrSuite> InitiatorNonce<S> {
    pub fn new(
        leaf: LeafId,
        secret: S::Scalar,
        key: &SigningKey<S>,
        slot: u64,
        message: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if key.leaves.get(&leaf) != Some(&S::generator_mul(secret)) {
            return Err(Error::Context);
        }
        let mut bytes = [
            S::encode_scalar(secret).as_slice(),
            &S::encode_scalar(key.tweak),
            &slot.to_be_bytes(),
            message,
            &S::encode_scalar(S::random(rng)),
        ]
        .concat();
        let nonce = S::hash_to_scalar("SL1/init-nonce", &bytes);
        bytes.zeroize();
        if nonce == S::scalar_zero() {
            return Err(Error::Nonce);
        }
        Ok(Self {
            leaf,
            secret,
            nonce,
            slot,
            message: message.to_vec(),
        })
    }
    pub fn point(&self) -> S::Point {
        S::generator_mul(self.nonce)
    }
    pub fn contribute(
        self,
        key: &SigningKey<S>,
        request: &Request<S>,
        now: u64,
    ) -> Result<S::Scalar> {
        Ok(self.contribute_with_transcript(key, request, now)?.0)
    }
    /// Return the checked transcript with the contribution for wallet reuse.
    pub(crate) fn contribute_with_transcript(
        self,
        key: &SigningKey<S>,
        request: &Request<S>,
        now: u64,
    ) -> Result<(S::Scalar, Transcript<S>)> {
        if request.initiator != self.leaf
            || request.r0 != self.point()
            || request.slot != self.slot
            || request.message != self.message
            || now > request.exp_c
        {
            return Err(Error::Nonce);
        }
        let tr = request.transcript(key)?;
        let value = tr.sigma * self.nonce
            + tr.ticket.challenge * tr.weights[&self.leaf] * self.secret
            + tr.tweak_term;
        Ok((value, tr))
    }
}

#[derive(Clone, Debug)]
pub struct Partial<S: Suite> {
    pub node: u16,
    pub value: S::Scalar,
}
/// One node's release guard. No Clone implementation: duplicated signing state
/// requires the external rollback/witness model, not a second local object.
pub struct Node<S: SchnorrSuite> {
    pub id: u16,
    pub epoch: u64,
    root_share: S::Scalar,
    slots: BTreeMap<u64, NodeSlot<S>>,
    burned: BTreeSet<u64>,
}
struct NodeSlot<S: Suite> {
    d: S::Scalar,
    e: S::Scalar,
    dp: S::Point,
    ep: S::Point,
}
impl<S: Suite> Drop for NodeSlot<S> {
    fn drop(&mut self) {
        self.d.zeroize();
        self.e.zeroize();
    }
}
impl<S: SchnorrSuite> Drop for Node<S> {
    fn drop(&mut self) {
        self.root_share.zeroize();
    }
}
impl<S: SchnorrSuite> Node<S> {
    pub fn new(id: u16, epoch: u64, root_share: S::Scalar) -> Result<Self> {
        if id == 0 {
            return Err(Error::Parameters);
        }
        Ok(Self {
            id,
            epoch,
            root_share,
            slots: BTreeMap::new(),
            burned: BTreeSet::new(),
        })
    }
    pub fn install(&mut self, id: u64, slot: &NonceSlot<S>) -> Result<()> {
        S::validate_point(slot.d)?;
        S::validate_point(slot.e)?;
        if self.slots.contains_key(&id) || self.burned.contains(&id) {
            return Err(Error::Nonce);
        }
        let (d, e) = *slot.shares.get(&self.id).ok_or(Error::Share)?;
        self.slots.insert(
            id,
            NodeSlot {
                d,
                e,
                dp: slot.d,
                ep: slot.e,
            },
        );
        Ok(())
    }
    /// Check this node's installed slot without consuming its nonce shares.
    pub fn check_release(&self, ticket: &Ticket<S>) -> Result<()> {
        self.release_values(ticket).map(|_| ())
    }
    fn release_values(&self, ticket: &Ticket<S>) -> Result<(S::Scalar, S::Scalar)> {
        S::validate_point(ticket.actor_nonce)?;
        let slot = self.slots.get(&ticket.slot).ok_or(Error::Nonce)?;
        let rho = committee_binding::<S>(self.epoch, ticket)?;
        let nonce = ticket.actor_nonce + slot.dp + S::mul(slot.ep, rho);
        if S::signature_point(nonce)? != ticket.nonce {
            return Err(Error::Nonce);
        }
        let sigma = S::nonce_sign(nonce)?;
        Ok((rho, sigma))
    }
    pub fn release(&mut self, ticket: &Ticket<S>) -> Result<Partial<S>> {
        let (rho, sigma) = self.release_values(ticket)?;
        let slot = self.slots.get(&ticket.slot).ok_or(Error::Nonce)?;
        let value = signature_partial_value::<S>(
            self.root_share,
            slot.d,
            slot.e,
            rho,
            sigma,
            ticket.challenge,
        );
        self.slots.remove(&ticket.slot);
        self.burned.insert(ticket.slot);
        Ok(Partial {
            node: self.id,
            value,
        })
    }
    pub fn burn(&mut self, slot: u64) {
        self.slots.remove(&slot);
        self.burned.insert(slot);
    }
}

/// Field arithmetic after the public ticket checks. Slot consumption and release
/// authorization remain the caller's responsibility through `Node::release`.
pub fn signature_partial_value<S: Suite>(
    root_share: S::Scalar,
    d: S::Scalar,
    e: S::Scalar,
    rho: S::Scalar,
    sigma: S::Scalar,
    challenge: S::Scalar,
) -> S::Scalar {
    sigma * (d + rho * e) + challenge * root_share
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CombineFailure {
    Invalid(Error),
    BadPartials(Vec<u16>),
    BadContributions(Vec<LeafId>),
    Signature,
}
#[derive(Clone, Debug)]
pub struct Combined {
    pub signature: [u8; 64],
    pub rejected_partials: Vec<u16>,
}

fn combine_values<S: SchnorrSuite>(
    threshold: usize,
    tr: &Transcript<S>,
    partials: &[Partial<S>],
    contributions: &BTreeMap<LeafId, S::Scalar>,
) -> Result<[u8; 64]> {
    if partials.len() < threshold || threshold == 0 {
        return Err(Error::Threshold);
    }
    let ids: Vec<_> = partials[..threshold].iter().map(|p| p.node).collect();
    let weights = lagrange::<S>(&ids)?;
    let sf = partials[..threshold]
        .iter()
        .zip(weights)
        .fold(S::scalar_zero(), |a, (p, w)| a + p.value * w);
    let sum = contributions.values().fold(sf, |a, s| a + *s);
    S::signature(tr.nonce, sum)
}

/// Interpolate and verify first. Only failure evaluates lazy slot commitments
/// or checks individual public contribution equations (DESIGN §5.6 step 6).
pub fn combine<S: SchnorrSuite>(
    key: &SigningKey<S>,
    request: &Request<S>,
    committee: &Committee<S>,
    slot: &mut NonceSlot<S>,
    partials: &[Partial<S>],
    contributions: &BTreeMap<LeafId, S::Scalar>,
) -> core::result::Result<Combined, CombineFailure> {
    let tr = request.transcript(key).map_err(CombineFailure::Invalid)?;
    combine_with_transcript(key, request, &tr, committee, slot, partials, contributions)
}

/// Internal reuse of a transcript derived from these exact request/key inputs.
/// The caller must not mutate either input after transcript derivation.
pub(crate) fn combine_with_transcript<S: SchnorrSuite>(
    key: &SigningKey<S>,
    request: &Request<S>,
    tr: &Transcript<S>,
    committee: &Committee<S>,
    slot: &mut NonceSlot<S>,
    partials: &[Partial<S>],
    contributions: &BTreeMap<LeafId, S::Scalar>,
) -> core::result::Result<Combined, CombineFailure> {
    let invalid = CombineFailure::Invalid;
    if committee.public != key.committee
        || slot.d != request.d
        || slot.e != request.e
        || contributions.keys().ne(tr.weights.keys())
    {
        return Err(invalid(Error::Context));
    }
    let ids: BTreeSet<_> = partials.iter().map(|p| p.node).collect();
    if ids.len() != partials.len() || ids.iter().any(|i| *i == 0 || *i > committee.n) {
        return Err(invalid(Error::Threshold));
    }
    let q = tr.output_key;
    let signature =
        combine_values::<S>(committee.threshold, tr, partials, contributions).map_err(invalid)?;
    if S::verify(q, &request.message, &signature).is_ok() {
        return Ok(Combined {
            signature,
            rejected_partials: vec![],
        });
    }
    let mut bad_actors = Vec::new();
    for (leaf, s) in contributions {
        let mut expected = S::mul(key.leaves[leaf], tr.ticket.challenge * tr.weights[leaf]);
        if leaf == &request.initiator {
            expected = expected + S::mul(request.r0, tr.sigma) + S::generator_mul(tr.tweak_term);
        } else {
            let pair = &request.pairs[leaf];
            expected =
                expected + S::mul(pair.d + S::mul(pair.e, tr.actor_bindings[leaf]), tr.sigma);
        }
        if S::generator_mul(*s) != expected {
            bad_actors.push(leaf.clone());
        }
    }
    if !bad_actors.is_empty() {
        return Err(CombineFailure::BadContributions(bad_actors));
    }
    let mut bad = Vec::new();
    let mut good = Vec::new();
    for partial in partials {
        let (d, e) = slot.evaluate(partial.node).map_err(invalid)?;
        let expected = S::mul(d + S::mul(e, tr.committee_binding), tr.sigma)
            + S::mul(
                committee.share_points[partial.node as usize - 1],
                tr.ticket.challenge,
            );
        if S::generator_mul(partial.value) == expected {
            good.push(partial.clone());
        } else {
            bad.push(partial.node);
        }
    }
    if good.len() < committee.threshold {
        return Err(CombineFailure::BadPartials(bad));
    }
    let signature =
        combine_values::<S>(committee.threshold, tr, &good, contributions).map_err(invalid)?;
    S::verify(q, &request.message, &signature).map_err(|_| CombineFailure::Signature)?;
    Ok(Combined {
        signature,
        rejected_partials: bad,
    })
}
