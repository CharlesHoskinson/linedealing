//! End-to-end split request adapters. Setup is an in-process birth/slot simulator.
//! Host authorization, chain observations and board authentication are supplied
//! separately through `board`; cryptographic checks are performed on wire data.
pub mod board;
pub mod ecdsa;

use super::{
    access::{Gate, LeafId},
    birth::{ActorShares, Birth, BirthContext, Committee},
    contribution::{ContributionContext, SealedContribution},
    envelope::{
        self, ActorRecipient, ActorSlot, Capsule, CapsuleActor, ContributionPayload,
        EmbeddedContribution, Envelope, Header, OpenedHeader, PreparedEnvelope, Public,
        RequestType,
    },
    group::Suite,
    prf,
    schnorr::{
        self, ActorPool, Half, InitiatorNonce, Node, PoolCommitment, SchnorrSuite, SigningKey,
    },
    slots::CommitteeSlots,
};
use crate::{Error, Result};
use k256::{elliptic_curve::rand_core::CryptoRngCore, ProjectivePoint, Scalar};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

// Test-only spans keep diagnostics out of production request processing.
macro_rules! profile_span {
    ($guard:ident, $name:literal) => {
        #[cfg(test)]
        let $guard = profiling::Span::new($name);
    };
}
macro_rules! profile_end {
    ($guard:ident) => {
        #[cfg(test)]
        drop($guard);
    };
}

/// The 149-byte committee ticket uses a u32 slot and u64 fee and height fields.
pub fn encode_ticket<S: Suite>(t: &schnorr::Ticket<S>) -> Result<Vec<u8>> {
    let mut b = u32::try_from(t.slot)
        .map_err(|_| Error::Encoding)?
        .to_be_bytes()
        .to_vec();
    b.extend(S::encode_point(t.actor_nonce)?);
    b.extend(t.pm);
    b.extend(S::encode_scalar(t.challenge));
    b.extend(t.nonce);
    b.extend(t.fee_rate.to_be_bytes());
    b.extend(t.not_before.to_be_bytes());
    if b.len() != 149 {
        return Err(Error::Encoding);
    }
    Ok(b)
}
pub fn decode_ticket<S: Suite>(b: &[u8]) -> Result<schnorr::Ticket<S>> {
    if b.len() != 149 {
        return Err(Error::Encoding);
    }
    Ok(schnorr::Ticket {
        slot: u32::from_be_bytes(b[..4].try_into().unwrap()) as u64,
        actor_nonce: S::decode_point(&b[4..37])?,
        pm: b[37..69].try_into().unwrap(),
        challenge: S::decode_scalar(b[69..101].try_into().unwrap())?,
        nonce: b[101..133].try_into().unwrap(),
        fee_rate: u64::from_be_bytes(b[133..141].try_into().unwrap()),
        not_before: u64::from_be_bytes(b[141..149].try_into().unwrap()),
    })
}

/// Canonical Bitcoin transaction and prevout codec, or an Ed25519 host message.
#[derive(Clone, Debug)]
pub struct SpendVariant {
    pub transaction: Vec<u8>,
    pub prevouts: Vec<u8>,
    pub destination: Vec<u8>,
}
/// Prototype hiding commitment to the complete finite spend intent. All inputs,
/// outputs and the maximum fee are fixed by this grid. The authorization circuit
/// must use its native commitment primitive in a deployed implementation.
pub fn intent_commitment(variants: &[SpendVariant], opening: &[u8; 32]) -> Result<[u8; 32]> {
    if variants.is_empty() || variants.len() > 8 {
        return Err(Error::Parameters);
    }
    let mut bytes = Zeroizing::new(opening.to_vec());
    bytes.push(variants.len() as u8);
    for variant in variants {
        for field in [
            &variant.transaction,
            &variant.prevouts,
            &variant.destination,
        ] {
            bytes.extend_from_slice(
                &u32::try_from(field.len())
                    .map_err(|_| Error::Encoding)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(field);
        }
    }
    Ok(crate::hash::h("SL1/intent", &bytes))
}
impl SpendVariant {
    pub fn bitcoin(tx: &crate::builder::UtxoTransaction) -> Result<Self> {
        let mut prevouts = Vec::new();
        for u in &tx.inputs {
            prevouts.extend(u.value.to_le_bytes());
            prevouts.extend(
                u16::try_from(u.script_pubkey.len())
                    .map_err(|_| Error::Encoding)?
                    .to_le_bytes(),
            );
            prevouts.extend(&u.script_pubkey);
        }
        Ok(Self {
            transaction: tx.unsigned_bytes().map_err(|_| Error::Encoding)?,
            prevouts,
            destination: tx.outputs.first().ok_or(Error::Parameters)?.script.clone(),
        })
    }
    pub fn messages(&self, suite: u8, inputs: u8) -> Result<Vec<Vec<u8>>> {
        if suite == 3 {
            if inputs != 1 || self.transaction.is_empty() || !self.prevouts.is_empty() {
                return Err(Error::Parameters);
            }
            return Ok(vec![self.transaction.clone()]);
        }
        let tx = decode_bitcoin(&self.transaction, &self.prevouts, suite)?;
        self.bitcoin_messages(&tx, inputs)
    }
    fn bitcoin_messages(
        &self,
        tx: &crate::builder::UtxoTransaction,
        inputs: u8,
    ) -> Result<Vec<Vec<u8>>> {
        if tx.inputs.len() != inputs as usize
            || tx.outputs.first().map(|o| &o.script) != Some(&self.destination)
        {
            return Err(Error::Context);
        }
        Ok(tx
            .sighashes()
            .map_err(|_| Error::Encoding)?
            .into_iter()
            .map(|h| h.to_vec())
            .collect())
    }
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.0.len() < n {
            return Err(Error::Encoding);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn compact(&mut self) -> Result<usize> {
        match self.array::<1>()?[0] {
            v @ 0..=252 => Ok(v as usize),
            253 => {
                let n = u16::from_le_bytes(self.array()?);
                if n < 253 {
                    Err(Error::Encoding)
                } else {
                    Ok(n as usize)
                }
            }
            _ => Err(Error::Encoding),
        }
    }
}
/// Parse the unsigned version-2 RBF transaction subset emitted by the builder.
pub fn decode_bitcoin(
    bytes: &[u8],
    prevouts: &[u8],
    suite: u8,
) -> Result<crate::builder::UtxoTransaction> {
    use crate::builder::{OutPoint, SpendKind, Utxo, UtxoTransaction, RBF_SEQUENCE};
    let mut r = Reader(bytes);
    let mut p = Reader(prevouts);
    if u32::from_le_bytes(r.array()?) != 2 {
        return Err(Error::Encoding);
    }
    let n = r.compact()?;
    if n == 0 || n > 2 {
        return Err(Error::Parameters);
    }
    let mut inputs = Vec::new();
    for _ in 0..n {
        let mut txid = r.array::<32>()?;
        txid.reverse();
        let vout = u32::from_le_bytes(r.array()?);
        if r.compact()? != 0 || u32::from_le_bytes(r.array()?) != RBF_SEQUENCE {
            return Err(Error::Encoding);
        }
        let value = u64::from_le_bytes(p.array()?);
        let len = u16::from_le_bytes(p.array()?) as usize;
        inputs.push(Utxo {
            outpoint: OutPoint { txid, vout },
            value,
            script_pubkey: p.take(len)?.to_vec(),
            confirmations: 1,
        });
    }
    let m = r.compact()?;
    if m == 0 || m > 256 {
        return Err(Error::Parameters);
    }
    let mut outputs = Vec::new();
    for _ in 0..m {
        let amount = u64::from_le_bytes(r.array()?) as u128;
        let len = r.compact()?;
        outputs.push(crate::wire::Output {
            amount,
            script: r.take(len)?.to_vec(),
        });
    }
    let lock_time = u32::from_le_bytes(r.array()?);
    if !r.0.is_empty() || !p.0.is_empty() {
        return Err(Error::Encoding);
    }
    let spend_kind = match suite {
        1 => SpendKind::P2wpkh,
        2 => SpendKind::P2tr,
        _ => return Err(Error::Parameters),
    };
    let paid = outputs.iter().try_fold(0u128, |a, o| {
        a.checked_add(o.amount).ok_or(Error::Parameters)
    })?;
    let available = inputs.iter().map(|u| u.value as u128).sum::<u128>();
    let fee = u64::try_from(available.checked_sub(paid).ok_or(Error::Parameters)?)
        .map_err(|_| Error::Parameters)?;
    Ok(UtxoTransaction {
        inputs,
        outputs,
        fee,
        vsize: 0,
        signed_vsize: None,
        anchor_height: 0,
        lock_time,
        spend_kind,
    })
}

type ReconstructedHalves<S> = (Vec<schnorr::Request<S>>, Vec<schnorr::Transcript<S>>);

#[derive(Clone, Debug)]
pub struct RequestContext<S: SchnorrSuite> {
    pub key: SigningKey<S>,
    pub slots: BTreeMap<u64, (S::Point, S::Point)>,
    pub pairs: BTreeMap<(LeafId, u32), PoolCommitment<S>>,
    pub pool_ids: BTreeMap<LeafId, u32>,
}
impl<S: SchnorrSuite> RequestContext<S> {
    pub fn leaf(&self, id: u16) -> Result<LeafId> {
        self.key
            .gate
            .leaves()?
            .get(id.checked_sub(1).ok_or(Error::Context)? as usize)
            .cloned()
            .ok_or(Error::Context)
    }
    pub fn leaf_id(&self, id: &LeafId) -> Result<u16> {
        u16::try_from(
            self.key
                .gate
                .leaves()?
                .iter()
                .position(|x| x == id)
                .ok_or(Error::Context)?
                + 1,
        )
        .map_err(|_| Error::Encoding)
    }
    /// Recompute every sighash, weight, binding and ticket from authenticated capsules.
    pub fn reconstruct(
        &self,
        h: &Header,
        caps: &[Capsule],
        epoch: u64,
    ) -> Result<Vec<schnorr::Request<S>>> {
        Ok(self.reconstruct_inner(h, caps, epoch, None, u64::MAX)?.0)
    }
    pub fn reconstruct_body(
        &self,
        h: &Header,
        cap: &Capsule,
        epoch: u64,
        v: u8,
        g: u8,
    ) -> Result<Vec<schnorr::Request<S>>> {
        Ok(self
            .reconstruct_inner(h, std::slice::from_ref(cap), epoch, Some((v, g)), u64::MAX)?
            .0)
    }
    fn check_actor_position(
        &self,
        position: u8,
        pool: &ActorPool<S>,
        caps: &[Capsule],
    ) -> Result<()> {
        let at = position.checked_sub(1).ok_or(Error::Context)? as usize;
        if caps.is_empty() {
            return Err(Error::Context);
        }
        for cap in caps {
            let actor = cap.actors.get(at).ok_or(Error::Context)?;
            if self.leaf(actor.leaf)? != *pool.leaf() {
                return Err(Error::Context);
            }
        }
        Ok(())
    }
    fn reconstruct_inner(
        &self,
        h: &Header,
        caps: &[Capsule],
        epoch: u64,
        selected: Option<(u8, u8)>,
        collection_deadline: u64,
    ) -> Result<ReconstructedHalves<S>> {
        if h.suite != S::SUITE_ID || caps.len() != if selected.is_some() { 1 } else { h.k as usize }
        {
            return Err(Error::Context);
        }
        h.validate()?;
        if h.kind == RequestType::Contrib || h.slots.contains(&0) {
            return Err(Error::Parameters);
        }
        let mut requests = Vec::new();
        let mut tickets = Vec::new();
        let labels = h.labels();
        let expected_script = if S::SUITE_ID == 2 {
            let mut script = vec![0x51, 32];
            script.extend(S::signature_point(self.key.output()?)?);
            Some(script)
        } else {
            None
        };
        // A capsule is shared by its generations and inputs. Validate its host
        // transaction and weighted public terms once before constructing halves.
        for (cap_index, cap) in caps.iter().enumerate() {
            let v = selected.map_or(cap_index as u8 + 1, |label| label.0);
            let _encoded =
                Zeroizing::new(cap.encode(S::SUITE_ID, v.min(h.g) as usize * h.l as usize)?);
            let signers = cap
                .signing_set
                .iter()
                .map(|id| self.leaf(*id))
                .collect::<Result<Vec<_>>>()?;
            let initiator = self.leaf(cap.initiator)?;
            let weights = self.key.gate.weights::<S>(&signers)?;
            let term = S::mul(
                *self.key.leaves.get(&initiator).ok_or(Error::Context)?,
                *weights.get(&initiator).ok_or(Error::Context)?,
            ) + S::generator_mul(self.key.tweak);
            if S::decode_point(&cap.initiator_term)? != term {
                return Err(Error::Context);
            }
            let host = SpendVariant {
                transaction: cap.transaction.clone(),
                prevouts: cap.prevouts.clone(),
                destination: cap.destination.clone(),
            };
            let messages = if let Some(script) = &expected_script {
                let tx = decode_bitcoin(&host.transaction, &host.prevouts, 2)?;
                if tx.inputs.iter().any(|u| &u.script_pubkey != script) {
                    return Err(Error::Context);
                }
                host.bitcoin_messages(&tx, h.l)?
            } else {
                host.messages(S::SUITE_ID, h.l)?
            };
            let actor_leaves = cap
                .actors
                .iter()
                .map(|actor| {
                    let leaf = self.leaf(actor.leaf)?;
                    if actor.pool_id != self.pool_ids.get(&leaf).copied()
                        || S::decode_point(&actor.weighted_point)?
                            != S::mul(
                                *self.key.leaves.get(&leaf).ok_or(Error::Context)?,
                                *weights.get(&leaf).ok_or(Error::Context)?,
                            )
                    {
                        return Err(Error::Context);
                    }
                    Ok(leaf)
                })
                .collect::<Result<Vec<_>>>()?;
            for (label_index, &(_, g)) in labels.iter().enumerate().filter(|(_, label)| {
                label.0 == v && selected.is_none_or(|selected| selected == **label)
            }) {
                let ti = label_index * h.l as usize;
                for j in 0..h.l {
                    let hi = (g as usize - 1) * h.l as usize + j as usize;
                    let ticket = decode_ticket::<S>(&h.tickets[ti + j as usize])?;
                    let mut pairs = BTreeMap::new();
                    for (actor, leaf) in cap.actors.iter().zip(&actor_leaves) {
                        let index = *actor.pair_indices.get(hi).ok_or(Error::Context)? as u32;
                        pairs.insert(
                            leaf.clone(),
                            self.pairs
                                .get(&(leaf.clone(), index))
                                .ok_or(Error::Context)?
                                .clone(),
                        );
                    }
                    let (d, e) = *self.slots.get(&ticket.slot).ok_or(Error::Context)?;
                    if ticket.slot != h.slots[(g as usize - 1) * h.l as usize + j as usize] as u64 {
                        return Err(Error::Context);
                    }
                    let request = schnorr::Request {
                        epoch,
                        slot: ticket.slot,
                        half: Half {
                            variant: v as u16,
                            generation: g as u16,
                            input: j as u16,
                        },
                        initiator: initiator.clone(),
                        signers: signers.clone(),
                        r0: S::decode_point(cap.nonces.get(hi).ok_or(Error::Context)?)?,
                        pairs,
                        d,
                        e,
                        message: messages[j as usize].clone(),
                        salt_v: cap.salt,
                        fee_rate: ticket.fee_rate,
                        not_before: ticket.not_before,
                        exp_c: collection_deadline,
                    };
                    tickets.push(ticket);
                    requests.push(request);
                }
            }
        }
        if selected.is_none() {
            let expected = schnorr::halves(h.k as u16, h.l as u16)?;
            if requests.iter().map(|r| r.half).collect::<BTreeSet<_>>()
                != expected.iter().copied().collect::<BTreeSet<_>>()
                || requests.len() != expected.len()
            {
                return Err(Error::Parameters);
            }
        }
        let transcripts = schnorr::validate_halves(&self.key, &requests)?;
        for (transcript, ticket) in transcripts.iter().zip(tickets) {
            if transcript.ticket != ticket {
                return Err(Error::Context);
            }
        }
        Ok((requests, transcripts))
    }
}

/// Simulator fixtures hold independent parties' secrets. Production callers
/// must keep these in separate stores; request and capsule objects hold none.
pub struct SchnorrSetup<S: SchnorrSuite> {
    pub committee: Committee<S>,
    pub actors: ActorShares<S>,
    pub birth: Birth<S>,
    pub key: SigningKey<S>,
    pub slots: CommitteeSlots<S>,
    pub transport_keys: Vec<ProjectivePoint>,
    pub transport_secrets: Vec<Scalar>,
    pub pools: BTreeMap<LeafId, ActorPool<S>>,
    pub actor_secrets: BTreeMap<u8, [u8; 32]>,
    pub context: RequestContext<S>,
    pub variants: Vec<SpendVariant>,
    pub set: Vec<LeafId>,
    pub k: u8,
    pub l: u8,
}
impl<S: SchnorrSuite> SchnorrSetup<S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        n: u16,
        t: usize,
        k: u8,
        l: u8,
        gate: Gate,
        set: Vec<LeafId>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        Self::new_with_rngs(n, t, k, l, gate, set, rng, None)
    }
    /// As `new`, with optional separate randomness for nonce material.
    /// Key draws (committee, actor shares, birth seed) come from `key_rng`.
    /// Slots, transport keys, actor pools and actor secrets come from
    /// `nonce_rng` when given, so a persisted key seed never fixes a nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_rngs(
        n: u16,
        t: usize,
        k: u8,
        l: u8,
        gate: Gate,
        set: Vec<LeafId>,
        key_rng: &mut impl CryptoRngCore,
        nonce_rng: Option<&mut dyn CryptoRngCore>,
    ) -> Result<Self> {
        let rng = key_rng;
        let halves = schnorr::halves(k as u16, l as u16)?;
        if k > 8 || l > 2 || set.is_empty() {
            return Err(Error::Parameters);
        }
        let committee = Committee::<S>::generate(n, t, rng)?;
        let bc = BirthContext {
            committee: committee.public,
            charter_id: [11; 32],
            chain_id: [S::SUITE_ID; 32],
        };
        let actors = ActorShares::generate(gate, &bc, rng)?;
        actors.gate.weights::<S>(&set)?;
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let birth = Birth::create(bc, &actors, seed, None, 1, [31; 32])?;
        let key = SigningKey::new(
            committee.public,
            &actors,
            birth.tweak,
            vec![],
            vec![set[0].clone()],
        )?;
        let mut nonce: &mut dyn CryptoRngCore = match nonce_rng {
            Some(r) => r,
            None => rng,
        };
        let rng = &mut nonce;
        let slots = CommitteeSlots::generate(
            n,
            u16::try_from(t).map_err(|_| Error::Parameters)?,
            &(1..=k.min(2) as u64 * l as u64).collect::<Vec<_>>(),
            1,
            rng,
        )?;
        let transport_secrets = (0..n)
            .map(|_| crate::algebra::random_nonzero(rng))
            .collect::<Vec<_>>();
        let transport_keys = transport_secrets
            .iter()
            .map(|s| ProjectivePoint::GENERATOR * *s)
            .collect();
        let mut pools = BTreeMap::new();
        let mut pairs = BTreeMap::new();
        let mut pool_ids = BTreeMap::new();
        let mut actor_secrets = BTreeMap::new();
        for (i, leaf) in set.iter().skip(1).enumerate() {
            let mut pool_id = [0; 32];
            rng.fill_bytes(&mut pool_id);
            let pool = ActorPool::new(
                leaf.clone(),
                pool_id,
                actors.shares[leaf],
                key.tweak,
                halves.len() as u32,
                rng,
            )?;
            for index in 0..halves.len() as u32 {
                pairs.insert((leaf.clone(), index), pool.commitment(index)?);
            }
            pool_ids.insert(leaf.clone(), i as u32 + 1);
            pools.insert(leaf.clone(), pool);
            let mut secret = [0; 32];
            rng.fill_bytes(&mut secret);
            actor_secrets.insert(i as u8 + 1, secret);
        }
        let context = RequestContext {
            key: key.clone(),
            slots: slots
                .slots
                .iter()
                .map(|(id, s)| (*id, (s.d, s.e)))
                .collect(),
            pairs,
            pool_ids,
        };
        let variants = fixture_variants::<S>(&key, k, l)?;
        Ok(Self {
            committee,
            actors,
            birth,
            key,
            slots,
            transport_keys,
            transport_secrets,
            pools,
            actor_secrets,
            context,
            variants,
            set,
            k,
            l,
        })
    }
    pub fn build(&self, rng: &mut impl CryptoRngCore) -> Result<SchnorrDraft<S>> {
        profile_span!(_build, "wallet.total_build");
        profile_span!(host, "wallet.host_parse");
        if self.variants.len() != self.k as usize {
            return Err(Error::Parameters);
        }
        let mut first_inputs = None;
        let messages = self
            .variants
            .iter()
            .map(|host| {
                if S::SUITE_ID == 2 {
                    let tx = decode_bitcoin(&host.transaction, &host.prevouts, 2)?;
                    if first_inputs
                        .as_ref()
                        .is_some_and(|inputs| inputs != &tx.inputs)
                    {
                        return Err(Error::Context);
                    }
                    let messages = host.bitcoin_messages(&tx, self.l)?;
                    if first_inputs.is_none() {
                        first_inputs = Some(tx.inputs);
                    }
                    Ok(messages)
                } else {
                    host.messages(S::SUITE_ID, self.l)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        profile_end!(host);
        profile_span!(prepare, "wallet.outer_prepare");
        let public = Public::new(1, envelope::keylist_hash(&self.transport_keys)?, 100);
        let prepared = PreparedEnvelope::new(
            public,
            &self.transport_keys,
            self.committee.threshold as u16,
            rng,
        )?;
        profile_end!(prepare);
        profile_span!(header_profile, "wallet.header_and_recipients");
        let mut header = Header::request(RequestType::Spend, S::SUITE_ID, self.k, self.l)?;
        header.slots = self
            .slots
            .slots
            .keys()
            .map(|id| u32::try_from(*id).map_err(|_| Error::Encoding))
            .collect::<Result<_>>()?;
        header.delta_c = 20;
        let mut intent_opening = Zeroizing::new([0; 32]);
        rng.fill_bytes(intent_opening.as_mut());
        header.ic = intent_commitment(&self.variants, &intent_opening)?;
        rng.fill_bytes(&mut header.r_tkc);
        let weights = self.key.gate.weights::<S>(&self.set)?;
        let mut recipients = Vec::new();
        for (i, _) in self.set.iter().skip(1).enumerate() {
            let position = i as u8 + 1;
            let mut token = [0; 16];
            rng.fill_bytes(&mut token);
            header.actors.push(ActorSlot {
                position,
                token_hash: envelope::token_hash(&token),
                party_index: None,
                embedded: None,
            });
            recipients.push(ActorRecipient {
                position,
                token,
                public_key: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                    self.actor_secrets[&position],
                ))
                .to_bytes(),
            });
        }
        profile_end!(header_profile);
        profile_span!(halves, "wallet.capsules_and_halves");
        let mut capsules = Vec::new();
        let mut bodies = Vec::new();
        let mut index = 0u32;
        let initiator_term = S::encode_point(
            S::mul(self.key.leaves[&self.set[0]], weights[&self.set[0]])
                + S::generator_mul(self.key.tweak),
        )?;
        let initiator = self.context.leaf_id(&self.set[0])?;
        let signing_set = self
            .set
            .iter()
            .map(|id| self.context.leaf_id(id))
            .collect::<Result<Vec<_>>>()?;
        let actors = self
            .set
            .iter()
            .skip(1)
            .map(|id| {
                Ok(CapsuleActor {
                    leaf: self.context.leaf_id(id)?,
                    pool_id: Some(self.context.pool_ids[id]),
                    pair_indices: vec![],
                    weighted_point: S::encode_point(S::mul(self.key.leaves[id], weights[id]))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        for (v, host) in self.variants.iter().enumerate() {
            let messages = &messages[v];
            let v = v as u8 + 1;
            let mut salt = [0; 32];
            rng.fill_bytes(&mut salt);
            let mut cap = Capsule {
                transaction: host.transaction.clone(),
                prevouts: host.prevouts.clone(),
                destination: host.destination.clone(),
                nonces: vec![],
                salt,
                initiator_term: initiator_term.clone(),
                initiator,
                signing_set: signing_set.clone(),
                actors: actors.clone(),
            };
            for g in 1..=v.min(2) {
                let mut scalars = Vec::new();
                for j in 0..self.l {
                    let slot = header.slots[(g as usize - 1) * self.l as usize + j as usize] as u64;
                    let nonce = InitiatorNonce::new(
                        self.set[0].clone(),
                        self.actors.shares[&self.set[0]],
                        &self.key,
                        slot,
                        &messages[j as usize],
                        rng,
                    )?;
                    let pairs = self
                        .set
                        .iter()
                        .skip(1)
                        .map(|id| (id.clone(), self.context.pairs[&(id.clone(), index)].clone()))
                        .collect();
                    for actor in &mut cap.actors {
                        actor.pair_indices.push(index as u16);
                    }
                    let (d, e) = self.context.slots[&slot];
                    let request = schnorr::Request {
                        epoch: 1,
                        slot,
                        half: Half {
                            variant: v as u16,
                            generation: g as u16,
                            input: j as u16,
                        },
                        initiator: self.set[0].clone(),
                        signers: self.set.clone(),
                        r0: nonce.point(),
                        pairs,
                        d,
                        e,
                        message: messages[j as usize].clone(),
                        salt_v: salt,
                        fee_rate: v as u64,
                        not_before: 0,
                        exp_c: u64::MAX,
                    };
                    cap.nonces.push(S::encode_point(request.r0)?);
                    let (value, transcript) =
                        nonce.contribute_with_transcript(&self.key, &request, 0)?;
                    let value = Zeroizing::new(value);
                    header.tickets.push(encode_ticket(&transcript.ticket)?);
                    scalars.push(crate::algebra::decode_scalar(&S::encode_scalar(*value))?);
                    index += 1;
                }
                bodies.push(scalars);
            }
            capsules.push(cap);
        }
        profile_end!(halves);
        profile_span!(_keys, "wallet.contribution_keys");
        if !header.actors.is_empty() {
            header.contribution_keys = header
                .labels()
                .iter()
                .map(|(v, g)| prepared.contribution_public(*v, *g))
                .collect::<Result<_>>()?;
        }
        Ok(SchnorrDraft {
            intent_opening,
            prepared: Some(prepared),
            header,
            capsules,
            bodies,
            recipients,
            context: self.context.clone(),
        })
    }
    pub fn node(&self, id: u16) -> Result<Node<S>> {
        let mut node = Node::new(
            id,
            1,
            *self
                .committee
                .shares
                .get(id.checked_sub(1).ok_or(Error::Parameters)? as usize)
                .ok_or(Error::Parameters)?,
        )?;
        for (id, slot) in &self.slots.slots {
            node.install(*id, slot)?;
        }
        Ok(node)
    }
}

pub fn fixture_variants<S: SchnorrSuite>(
    key: &SigningKey<S>,
    k: u8,
    l: u8,
) -> Result<Vec<SpendVariant>> {
    if S::SUITE_ID == 3 {
        return (1..=k)
            .map(|v| {
                Ok(SpendVariant {
                    transaction: vec![v; 128],
                    prevouts: vec![],
                    destination: vec![42; 32],
                })
            })
            .collect();
    }
    use crate::builder::{OutPoint, SpendKind, Utxo, UtxoTransaction};
    let mut script = vec![0x51, 32];
    script.extend(S::signature_point(key.output()?)?);
    (1..=k)
        .map(|v| {
            SpendVariant::bitcoin(&UtxoTransaction {
                inputs: (0..l)
                    .map(|j| Utxo {
                        outpoint: OutPoint {
                            txid: [17; 32],
                            vout: j as u32,
                        },
                        value: 100_000,
                        script_pubkey: script.clone(),
                        confirmations: 6,
                    })
                    .collect(),
                outputs: vec![
                    crate::wire::Output {
                        amount: 50_000,
                        script: script.clone(),
                    },
                    crate::wire::Output {
                        amount: l as u128 * 100_000 - 50_000 - v as u128 * 1000,
                        script: script.clone(),
                    },
                ],
                fee: v as u64 * 1000,
                vsize: 200,
                signed_vsize: None,
                anchor_height: 100,
                lock_time: 0,
                spend_kind: SpendKind::P2tr,
            })
        })
        .collect()
}

pub struct SchnorrDraft<S: SchnorrSuite> {
    /// Wallet-only opening for the external authorization adapter.
    pub intent_opening: Zeroizing<[u8; 32]>,
    pub prepared: Option<PreparedEnvelope>,
    pub header: Header,
    pub capsules: Vec<Capsule>,
    pub bodies: Vec<Vec<Scalar>>,
    pub recipients: Vec<ActorRecipient>,
    pub context: RequestContext<S>,
}
impl<S: SchnorrSuite> Drop for SchnorrDraft<S> {
    fn drop(&mut self) {
        self.bodies.zeroize();
    }
}
impl<S: SchnorrSuite> SchnorrDraft<S> {
    /// Embedded actors receive these capsules directly before the post. Only
    /// trailing positions can embed: C reserves the leading physical HPKE slots.
    /// The actor must approve its own transaction policy over `self.capsules`
    /// before calling this method. This method checks cryptographic consistency.
    pub fn embed(
        &mut self,
        position: u8,
        pool: &mut ActorPool<S>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let at = position.checked_sub(1).ok_or(Error::Parameters)? as usize;
        if at >= self.header.actors.len()
            || self.header.actors[at].embedded.is_some()
            || self.header.actors[at + 1..]
                .iter()
                .any(|a| a.embedded.is_none())
        {
            return Err(Error::Parameters);
        }
        let recipient = self
            .recipients
            .iter()
            .find(|a| a.position == position)
            .ok_or(Error::Context)?;
        self.context
            .check_actor_position(position, pool, &self.capsules)?;
        let (requests, transcripts) =
            self.context
                .reconstruct_inner(&self.header, &self.capsules, 1, None, u64::MAX)?;
        let values = Zeroizing::new(pool.contribute_batch_with_transcripts(
            &self.context.key,
            &requests,
            &transcripts,
            0,
        )?);
        let sealed = seal_contributions::<S>(
            &self.header,
            self.prepared.as_ref().ok_or(Error::Context)?.dd(),
            position,
            &values,
            rng,
        )?;
        self.header.actors[at].embedded = Some(EmbeddedContribution {
            token: recipient.token,
            sealed,
        });
        self.recipients.retain(|a| a.position != position);
        Ok(())
    }
    pub fn finish(mut self, rng: &mut impl CryptoRngCore) -> Result<SchnorrRequest<S>> {
        // Move the one-use outer dealing without cloning its secret.
        let header = self.header.clone();
        let capsules = std::mem::take(&mut self.capsules);
        let bodies = std::mem::take(&mut self.bodies);
        let recipients = std::mem::take(&mut self.recipients);
        let context = self.context.clone();
        let prepared = self.prepared.take().ok_or(Error::Context)?;
        let pending = prepared.build(header, bodies, capsules, recipients, rng)?;
        let used_bytes = pending.used_bytes();
        Ok(SchnorrRequest {
            envelope: pending.authorize(None, rng)?,
            used_bytes,
            context,
        })
    }
}

pub fn seal_contributions<S: SchnorrSuite>(
    h: &Header,
    dd: [u8; 32],
    position: u8,
    values: &[S::Scalar],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<SealedContribution>> {
    if values.len() != h.half_count() || h.contribution_keys.len() != h.labels().len() {
        return Err(Error::Parameters);
    }
    h.labels()
        .into_iter()
        .enumerate()
        .map(|(i, (variant, generation))| {
            let scalars = Zeroizing::new(
                values[i * h.l as usize..(i + 1) * h.l as usize]
                    .iter()
                    .map(|s| crate::algebra::decode_scalar(&S::encode_scalar(*s)))
                    .collect::<Result<Vec<_>>>()?,
            );
            SealedContribution::seal_for_suite(
                S::SUITE_ID,
                h.contribution_keys[i],
                &ContributionContext {
                    dd,
                    position,
                    variant,
                    generation,
                },
                &scalars,
                rng,
            )
        })
        .collect()
}

pub struct SchnorrRequest<S: SchnorrSuite> {
    pub envelope: Envelope,
    pub used_bytes: usize,
    pub context: RequestContext<S>,
}
#[derive(Debug)]
pub enum CombineError {
    Invalid(Error),
    Initiator(LeafId),
    Actor(LeafId),
    Algebra(schnorr::CombineFailure),
}
impl From<Error> for CombineError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}
impl<S: SchnorrSuite> SchnorrRequest<S> {
    pub fn header_partial(
        &self,
        node: u16,
        secret: Scalar,
        keys: &[ProjectivePoint],
    ) -> Result<prf::Partial> {
        self.partial(node, secret, keys, prf::Label::Hdr)
    }
    pub fn partial(
        &self,
        node: u16,
        secret: Scalar,
        keys: &[ProjectivePoint],
        label: prf::Label,
    ) -> Result<prf::Partial> {
        prf::partial(
            self.envelope.decrypt_share(node, secret, keys)?,
            node,
            &self.envelope.dd(),
            label,
        )
    }
    /// Simulator convenience that accepts every cryptographically valid host transaction.
    /// Actors with transaction policy must use `actor_contribute_with_policy`.
    pub fn actor_contribute(
        &self,
        position: u8,
        secret: &[u8; 32],
        pool: &mut ActorPool<S>,
        now: u64,
        collection_deadline: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ContributionPayload> {
        self.actor_contribute_with_policy(
            position,
            secret,
            pool,
            now,
            collection_deadline,
            rng,
            |_| Ok(()),
        )
    }
    /// Apply the actor's policy to all authenticated variants before consuming a nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn actor_contribute_with_policy(
        &self,
        position: u8,
        secret: &[u8; 32],
        pool: &mut ActorPool<S>,
        now: u64,
        collection_deadline: u64,
        rng: &mut impl CryptoRngCore,
        policy: impl FnOnce(&[Capsule]) -> Result<()>,
    ) -> Result<ContributionPayload> {
        if now > collection_deadline || now > self.envelope.public().exp {
            return Err(Error::Nonce);
        }
        profile_span!(_actor, "actor.total");
        profile_span!(open, "actor.open_capsules");
        let view = self.envelope.open_actor(secret, position)?;
        profile_end!(open);
        profile_span!(reconstruct, "actor.reconstruct");
        self.context
            .check_actor_position(position, pool, &view.capsules)?;
        let (requests, transcripts) = self.context.reconstruct_inner(
            view.opened.header(),
            &view.capsules,
            self.envelope.public().epoch as u64,
            None,
            collection_deadline,
        )?;
        profile_end!(reconstruct);
        policy(&view.capsules)?;
        profile_span!(consume, "actor.consume");
        let values = Zeroizing::new(pool.contribute_batch_with_transcripts(
            &self.context.key,
            &requests,
            &transcripts,
            now,
        )?);
        profile_end!(consume);
        profile_span!(_seal, "actor.seal");
        Ok(ContributionPayload {
            target_hd: self.envelope.hd(),
            position,
            token: view.token,
            sealed: seal_contributions::<S>(
                view.opened.header(),
                self.envelope.dd(),
                position,
                &values,
                rng,
            )?,
        })
    }
    /// Attribute a malformed body/key only after threshold valid PRF proofs.
    pub fn open_selected_with_proofs(
        &self,
        opened: &OpenedHeader,
        v: u8,
        g: u8,
        partials: &[prf::Partial],
        proof: impl FnMut(&prf::Partial) -> Option<prf::Proof>,
    ) -> core::result::Result<envelope::OpenedVariant, CombineError> {
        match self
            .envelope
            .open_selected_with_fallback(opened, v, g, partials, proof)?
        {
            prf::OpenOutcome::Opened { plaintext, .. } => Ok(plaintext),
            prf::OpenOutcome::InsufficientValid { .. } => {
                Err(CombineError::Invalid(Error::Threshold))
            }
            prf::OpenOutcome::DealerFault { .. } => Err(CombineError::Initiator(
                self.context
                    .key
                    .initiators
                    .first()
                    .ok_or(Error::Context)?
                    .clone(),
            )),
        }
    }
    pub fn signature_partials(
        &self,
        h: &OpenedHeader,
        v: u8,
        g: u8,
        node: &mut Node<S>,
    ) -> Result<Vec<schnorr::Partial<S>>> {
        self.envelope.wire_sizes(h)?;
        if h.header().suite != S::SUITE_ID || node.epoch != u64::from(self.envelope.public().epoch)
        {
            return Err(Error::Context);
        }
        let index = h
            .header()
            .labels()
            .iter()
            .position(|x| *x == (v, g))
            .ok_or(Error::Parameters)?;
        let tickets = h.header().tickets
            [index * h.header().l as usize..(index + 1) * h.header().l as usize]
            .iter()
            .map(|b| decode_ticket::<S>(b))
            .collect::<Result<Vec<_>>>()?;
        // Validate the whole batch before consuming any slot.
        check_release_tickets::<S>(node.epoch, &tickets, &self.context.slots)?;
        for ticket in &tickets {
            node.check_release(ticket)?;
        }
        tickets.iter().map(|t| node.release(t)).collect()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn combine_admitted(
        &self,
        board: &board::BoardAdapter,
        opened: &OpenedHeader,
        v: u8,
        g: u8,
        body_partials: &[prf::Partial],
        signature_partials: &[Vec<schnorr::Partial<S>>],
        committee: &Committee<S>,
        slots: &mut CommitteeSlots<S>,
    ) -> core::result::Result<Vec<schnorr::Combined>, CombineError> {
        let admitted = board
            .board()
            .request(&self.envelope.eid())
            .map_err(|_| Error::Context)?;
        if !admitted.admitted || admitted.envelope.hd != self.envelope.hd() {
            return Err(Error::Context.into());
        }
        for node in body_partials
            .iter()
            .map(|p| p.index)
            .chain(signature_partials.iter().flatten().map(|p| p.node))
        {
            if admitted.releases.get(&(u16::from(g), node)) != Some(&u16::from(v)) {
                return Err(Error::Context.into());
            }
        }
        let payloads = board
            .accepted_contributions(self.envelope.eid())
            .map_err(|_| Error::Context)?;
        self.combine(
            opened,
            v,
            g,
            body_partials,
            signature_partials,
            &payloads,
            committee,
            slots,
        )
    }

    /// Cryptographic combiner primitive. Callers must supply the contributions
    /// selected by the board. `combine_admitted` performs that selection and
    /// verifies that every supplied sender has a committed release.
    #[allow(clippy::too_many_arguments)]
    pub fn combine(
        &self,
        opened: &OpenedHeader,
        v: u8,
        g: u8,
        body_partials: &[prf::Partial],
        signature_partials: &[Vec<schnorr::Partial<S>>],
        payloads: &[ContributionPayload],
        committee: &Committee<S>,
        slots: &mut CommitteeSlots<S>,
    ) -> core::result::Result<Vec<schnorr::Combined>, CombineError> {
        let h = opened.header();
        let index = h
            .labels()
            .iter()
            .position(|x| *x == (v, g))
            .ok_or(Error::Parameters)?;
        let initiator = self
            .context
            .key
            .initiators
            .first()
            .ok_or(Error::Context)?
            .clone();
        profile_span!(_combine, "combine.total");
        profile_span!(open, "combine.open_selected");
        let selected = self
            .envelope
            .open_selected(opened, v, g, body_partials)
            .map_err(CombineError::Invalid)?;
        profile_end!(open);
        profile_span!(reconstruct, "combine.reconstruct");
        let (requests, transcripts) = self.context.reconstruct_inner(
            h,
            std::slice::from_ref(&selected.capsule),
            self.envelope.public().epoch as u64,
            Some((v, g)),
            u64::MAX,
        )?;
        profile_end!(reconstruct);
        profile_span!(contributions_profile, "combine.open_contributions");
        if signature_partials.len() != h.l as usize {
            return Err(Error::Parameters.into());
        }
        let mut contributions = (0..h.l)
            .map(|j| {
                Ok(BTreeMap::from([(
                    initiator.clone(),
                    S::decode_scalar(&selected.scalars[j as usize].to_bytes().into())?,
                )]))
            })
            .collect::<Result<Vec<_>>>()?;
        for actor in &h.actors {
            let ai = actor.position.checked_sub(1).ok_or(Error::Context)? as usize;
            let leaf = self
                .context
                .leaf(selected.capsule.actors.get(ai).ok_or(Error::Context)?.leaf)?;
            let sealed = if let Some(e) = &actor.embedded {
                &e.sealed
            } else {
                let mut matches = payloads.iter().filter(|p| p.position == actor.position);
                let p = matches.next().ok_or(Error::Context)?;
                if matches.next().is_some() {
                    return Err(Error::Context.into());
                }
                h.validate_contribution(&self.envelope.hd(), p)?;
                &p.sealed
            };
            let values = Zeroizing::new(
                sealed
                    .get(index)
                    .ok_or(Error::Context)?
                    .open_for_suite(
                        S::SUITE_ID,
                        selected.contribution_secret,
                        h.contribution_keys[index],
                        &ContributionContext {
                            dd: self.envelope.dd(),
                            position: actor.position,
                            variant: v,
                            generation: g,
                        },
                        h.l as usize,
                    )
                    .map_err(|_| CombineError::Actor(leaf.clone()))?,
            );
            for (j, value) in values.iter().enumerate() {
                contributions[j].insert(leaf.clone(), S::decode_scalar(&value.to_bytes().into())?);
            }
        }
        profile_end!(contributions_profile);
        profile_span!(_signatures, "combine.signatures");
        let mut results = Vec::new();
        for (j, (r, transcript)) in requests.iter().zip(&transcripts).enumerate() {
            let result = schnorr::combine_with_transcript(
                &self.context.key,
                r,
                transcript,
                committee,
                slots.slots.get_mut(&r.slot).ok_or(Error::Context)?,
                &signature_partials[j],
                &contributions[j],
            );
            for value in contributions[j].values_mut() {
                value.zeroize();
            }
            results.push(result.map_err(|e| match e {
                schnorr::CombineFailure::BadContributions(ref ids) if ids.contains(&initiator) => {
                    CombineError::Initiator(initiator.clone())
                }
                schnorr::CombineFailure::BadContributions(ref ids) => {
                    CombineError::Actor(ids[0].clone())
                }
                other => CombineError::Algebra(other),
            })?);
        }
        Ok(results)
    }
}

/// Node's public release check: no address, capsule or actor registry is needed.
pub fn check_release_tickets<S: SchnorrSuite>(
    epoch: u64,
    tickets: &[schnorr::Ticket<S>],
    slots: &BTreeMap<u64, (S::Point, S::Point)>,
) -> Result<()> {
    if tickets.is_empty()
        || tickets.iter().any(|t| t.slot == 0)
        || tickets
            .iter()
            .map(|t| t.slot)
            .collect::<BTreeSet<_>>()
            .len()
            != tickets.len()
    {
        return Err(Error::Nonce);
    }
    for t in tickets {
        let (d, e) = slots.get(&t.slot).ok_or(Error::Nonce)?;
        S::validate_point(t.actor_nonce)?;
        let bytes = [
            &[S::SUITE_ID][..],
            epoch.to_be_bytes().as_slice(),
            t.slot.to_be_bytes().as_slice(),
            &S::encode_point(t.actor_nonce)?,
            &t.pm,
        ]
        .concat();
        let rho = S::hash_to_scalar("SL1/bind", &bytes);
        let nonce = t.actor_nonce + *d + S::mul(*e, rho);
        let _ = S::nonce_sign(nonce)?;
        if S::signature_point(nonce)? != t.nonce {
            return Err(Error::Nonce);
        }
    }
    Ok(())
}
pub fn contribution_frame(
    target: &Header,
    payload: ContributionPayload,
    keys: &[ProjectivePoint],
    threshold: usize,
    epoch: u32,
    exp: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<(Envelope, usize)> {
    let p = PreparedEnvelope::new(
        Public::new(epoch, envelope::keylist_hash(keys)?, exp),
        keys,
        u16::try_from(threshold).map_err(|_| Error::Parameters)?,
        rng,
    )?;
    let pending = p.build(
        Header::contribution(target, payload)?,
        vec![],
        vec![],
        vec![],
        rng,
    )?;
    let used = pending.used_bytes();
    Ok((pending.authorize(None, rng)?, used))
}

#[cfg(test)]
mod profiling {
    use super::*;
    use crate::{
        experiment::SeededRng,
        split::group::{Edwards, Secp},
    };
    use std::{
        cell::RefCell,
        time::{Duration, Instant},
    };

    thread_local! {
        static SPANS: RefCell<Option<BTreeMap<&'static str, Duration>>> = const { RefCell::new(None) };
    }
    pub(super) struct Span(&'static str, Option<Instant>);
    impl Span {
        pub(super) fn new(name: &'static str) -> Self {
            Self(
                name,
                SPANS.with(|s| s.borrow().is_some().then(Instant::now)),
            )
        }
    }
    impl Drop for Span {
        fn drop(&mut self) {
            if let Some(start) = self.1 {
                SPANS.with(|s| {
                    if let Some(entries) = s.borrow_mut().as_mut() {
                        *entries.entry(self.0).or_default() += start.elapsed();
                    }
                });
            }
        }
    }
    fn fixture<S: SchnorrSuite>(n: u16, l: u8, rng: &mut SeededRng) -> SchnorrSetup<S> {
        let leaves = (1..=3)
            .map(|id| LeafId::new(id, vec![], 1))
            .collect::<Vec<_>>();
        let gate = Gate::And(leaves.iter().cloned().map(Gate::Leaf).collect());
        SchnorrSetup::new(n, if n == 9 { 7 } else { 12 }, 3, l, gate, leaves, rng).unwrap()
    }
    fn profile<S: SchnorrSuite>(n: u16, l: u8) {
        let mut rng = SeededRng::new(250);
        let mut setup = fixture::<S>(n, l, &mut rng);
        SPANS.with(|s| *s.borrow_mut() = Some(BTreeMap::new()));
        let draft = setup.build(&mut rng).unwrap();
        let finish = Span::new("wallet.finish");
        let request = draft.finish(&mut rng).unwrap();
        drop(finish);
        let first = request
            .actor_contribute(
                1,
                &setup.actor_secrets[&1],
                setup.pools.get_mut(&setup.set[1]).unwrap(),
                1,
                50,
                &mut rng,
            )
            .unwrap();
        // Prepare releases and the second actor outside measured spans.
        let spans = SPANS.with(|s| s.borrow_mut().take());
        let second = request
            .actor_contribute(
                2,
                &setup.actor_secrets[&2],
                setup.pools.get_mut(&setup.set[2]).unwrap(),
                1,
                50,
                &mut rng,
            )
            .unwrap();
        let header_partials = (1..=setup.committee.threshold as u16)
            .map(|node| {
                request
                    .header_partial(
                        node,
                        setup.transport_secrets[node as usize - 1],
                        &setup.transport_keys,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let opened = request.envelope.open_header(&header_partials).unwrap();
        let body_partials = (1..=setup.committee.threshold as u16)
            .map(|node| {
                request
                    .partial(
                        node,
                        setup.transport_secrets[node as usize - 1],
                        &setup.transport_keys,
                        prf::Label::Body {
                            variant: 3,
                            generation: 2,
                        },
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut signature_partials = vec![Vec::new(); l as usize];
        for id in 1..=setup.committee.threshold as u16 {
            let mut node = setup.node(id).unwrap();
            for (j, partial) in request
                .signature_partials(&opened, 3, 2, &mut node)
                .unwrap()
                .into_iter()
                .enumerate()
            {
                signature_partials[j].push(partial);
            }
        }
        SPANS.with(|s| *s.borrow_mut() = spans);
        request
            .combine(
                &opened,
                3,
                2,
                &body_partials,
                &signature_partials,
                &[first, second],
                &setup.committee,
                &mut setup.slots,
            )
            .unwrap();
        for (name, elapsed) in SPANS.with(|s| s.borrow_mut().take().unwrap()) {
            eprintln!(
                "request-profile suite={} n={n} {name}={}us",
                S::SUITE_ID,
                elapsed.as_micros()
            );
        }
    }
    #[test]
    #[ignore = "single-shot diagnostics; run without concurrent benchmarks"]
    fn request_stage_profile() {
        for n in [9, 17] {
            profile::<Secp>(n, 2);
            profile::<Edwards>(n, 1);
        }
    }
    fn reconstruction_checks<S: SchnorrSuite>(l: u8) {
        let mut rng = SeededRng::new(251);
        let setup = fixture::<S>(9, l, &mut rng);
        let draft = setup.build(&mut rng).unwrap();
        let requests = draft
            .context
            .reconstruct(&draft.header, &draft.capsules, 1)
            .unwrap();
        assert_eq!(requests.len(), 5 * l as usize);
        for (index, (v, g)) in draft.header.labels().into_iter().enumerate() {
            let selected = draft
                .context
                .reconstruct_body(&draft.header, &draft.capsules[v as usize - 1], 1, v, g)
                .unwrap();
            for (j, r) in selected.iter().enumerate() {
                assert_eq!(
                    r.transcript(&draft.context.key).unwrap().ticket,
                    requests[index * l as usize + j]
                        .transcript(&draft.context.key)
                        .unwrap()
                        .ticket
                );
            }
        }
        let mut header = draft.header.clone();
        // A changed challenge in generation two must be compared with its own transcript.
        header.tickets[2 * l as usize][100] ^= 1;
        assert!(draft
            .context
            .reconstruct(&header, &draft.capsules, 1)
            .is_err());
        for mutation in 0..5 {
            let mut caps = draft.capsules.clone();
            let cap = &mut caps[1];
            match mutation {
                0 => cap.actors[0].weighted_point = cap.initiator_term.clone(),
                1 => cap.actors[0].pool_id = Some(u32::MAX),
                2 => cap.actors[0].pair_indices[l as usize] = u16::MAX,
                3 => cap.nonces[l as usize] = cap.nonces[0].clone(),
                _ => cap.signing_set.push(cap.initiator),
            }
            assert!(
                draft.context.reconstruct(&draft.header, &caps, 1).is_err(),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn reconstruction_preserves_all_halves_and_actor_checks() {
        reconstruction_checks::<Secp>(2);
        reconstruction_checks::<Edwards>(1);
    }
    #[test]
    fn wallet_parsing_preserves_destination_and_common_prevout_checks() {
        let mut rng = SeededRng::new(252);
        let mut setup = fixture::<Secp>(9, 2, &mut rng);
        let original = setup.variants[1].clone();
        setup.variants[1].destination.push(0);
        assert!(setup.build(&mut rng).is_err());
        setup.variants[1] = original.clone();
        setup.variants[1].prevouts[0] ^= 1;
        assert!(setup.build(&mut rng).is_err());
        setup.variants[1] = original;
        let draft = setup.build(&mut rng).unwrap();
        let mut caps = draft.capsules.clone();
        caps[1].destination.push(0);
        assert!(draft.context.reconstruct(&draft.header, &caps, 1).is_err());
        assert!(draft
            .context
            .reconstruct(&draft.header, &draft.capsules, 1)
            .is_ok());
    }
}
