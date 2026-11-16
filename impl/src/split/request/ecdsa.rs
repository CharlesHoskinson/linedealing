//! ECDSA request envelopes backed by the ideal presignature sessions.
//!
//! Input prehashes are recomputed from the encoded P2WPKH transaction and
//! prevouts. Board release authorization is supplied by the caller.
//! Slots are consumed in variant/input order; ECDSA uses generation zero.

use crate::algebra::encode_point;
use crate::split::access::LeafId;
use crate::split::birth::{ActorShares, Committee};
use crate::split::contribution::{ContributionContext, SealedContribution};
use crate::split::ecdsa::{self, Contribution, Slot, SlotRecord, Ticket};
use crate::split::envelope::{
    self, ActorSlot, Capsule, CapsuleActor, EmbeddedContribution, Envelope, Header, OpenedHeader,
    OpenedVariant, PreparedEnvelope, Public, RequestType,
};
use crate::split::group::{Secp, Suite};
use crate::split::prf::{self, Label};
use crate::{Error, Result};
use k256::{elliptic_curve::rand_core::CryptoRngCore, ProjectivePoint, Scalar};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// One fee variant and its host-computed input signature hashes.
#[derive(Clone, Debug)]
pub struct EcdsaVariant {
    pub transaction: Vec<u8>,
    pub prevouts: Vec<u8>,
    pub destination: Vec<u8>,
    pub hashes: Vec<[u8; 32]>,
}

impl EcdsaVariant {
    pub fn bitcoin(transaction: &crate::builder::UtxoTransaction) -> Result<Self> {
        if transaction.spend_kind != crate::builder::SpendKind::P2wpkh {
            return Err(Error::Parameters);
        }
        let host = super::SpendVariant::bitcoin(transaction)?;
        let inputs = u8::try_from(transaction.inputs.len()).map_err(|_| Error::Parameters)?;
        let hashes = host
            .messages(1, inputs)?
            .into_iter()
            .map(|hash| hash.try_into().map_err(|_| Error::Encoding))
            .collect::<Result<_>>()?;
        Ok(Self {
            transaction: host.transaction,
            prevouts: host.prevouts,
            destination: host.destination,
            hashes,
        })
    }

    fn recompute(&self, inputs: u8) -> Result<Vec<[u8; 32]>> {
        super::SpendVariant {
            transaction: self.transaction.clone(),
            prevouts: self.prevouts.clone(),
            destination: self.destination.clone(),
        }
        .messages(1, inputs)?
        .into_iter()
        .map(|hash| hash.try_into().map_err(|_| Error::Encoding))
        .collect()
    }
}

/// Actual serialized sizes. Ciphertext sizes include their AEAD tags.
#[derive(Clone, Debug)]
pub struct EcdsaSizes {
    pub used: usize,
    pub outer: usize,
    pub header: usize,
    pub bodies: usize,
    pub capsules: usize,
    pub embedded_contributions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcdsaCombineError {
    Invalid(Error),
    Initiator { input: usize, leaf: LeafId },
    Actor { input: usize, leaf: LeafId },
    Node { input: usize, node: u16 },
}

impl From<Error> for EcdsaCombineError {
    fn from(error: Error) -> Self {
        Self::Invalid(error)
    }
}

/// In-process wallet, actor and node fixture. Slot holders retain their one-use
/// guards. Public release methods must be called only after board authorization.
pub struct EcdsaRequest {
    /// Wallet-only opening, retained by this in-process request fixture.
    pub intent_opening: Zeroizing<[u8; 32]>,
    pub envelope: Envelope,
    pub sizes: EcdsaSizes,
    pub public_key: ProjectivePoint,
    pub k: u8,
    pub l: u8,
    slots: Vec<Slot>,
    tickets: Vec<Ticket>,
    signing_set: Vec<LeafId>,
    wire_ids: Vec<u16>,
    weighted_points: Vec<ProjectivePoint>,
    variants: Vec<EcdsaVariant>,
    transport_keys: Vec<ProjectivePoint>,
    bound_eid: [u8; 32],
}

impl EcdsaRequest {
    /// The first signing leaf is the initiator. Additional actors' contributions
    /// are sealed and embedded before posting. Capsule leaf numbers are the
    /// one-based positions in the charter's sorted canonical leaf list.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        committee: &Committee<Secp>,
        actors: &ActorShares<Secp>,
        signing_set: &[LeafId],
        tweak: Scalar,
        mut slots: Vec<Slot>,
        variants: Vec<EcdsaVariant>,
        transport_keys: &[ProjectivePoint],
        public: Public,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let k = u8::try_from(variants.len()).map_err(|_| Error::Parameters)?;
        let l = u8::try_from(variants.first().ok_or(Error::Parameters)?.hashes.len())
            .map_err(|_| Error::Parameters)?;
        let mut header = Header::request(RequestType::Spend, 1, k, l)?;
        header.delta_c = 20;
        if variants.iter().any(|v| v.hashes.len() != l as usize)
            || slots.len() != k as usize * l as usize
            || transport_keys.len() != committee.n as usize
            || signing_set.is_empty()
            || signing_set.len() > 256
        {
            return Err(Error::Parameters);
        }
        let weights = actors.gate.weights::<Secp>(signing_set)?;
        if signing_set
            .iter()
            .any(|leaf| !actors.points.contains_key(leaf))
        {
            return Err(Error::Share);
        }
        let weighted_points: Vec<_> = signing_set
            .iter()
            .enumerate()
            .map(|(index, leaf)| {
                actors.points[leaf] * weights[leaf]
                    + if index == 0 {
                        Secp::generator_mul(tweak)
                    } else {
                        ProjectivePoint::IDENTITY
                    }
            })
            .collect();
        let all_leaves = actors.gate.leaves()?;
        let wire_ids: Vec<_> = signing_set
            .iter()
            .map(|leaf| {
                let index = all_leaves.binary_search(leaf).map_err(|_| Error::Context)?;
                u16::try_from(index + 1).map_err(|_| Error::Parameters)
            })
            .collect::<Result<_>>()?;
        let binding = ecdsa::leaf_set_hash(signing_set)?;
        let public_key = committee.public + actors.public + Secp::generator_mul(tweak);
        encode_point(public_key)?;
        let mut owner_script = vec![0, 20];
        owner_script.extend(crate::wire::address_for(3, public_key)?);
        for variant in &variants {
            if variant.recompute(l)? != variant.hashes
                || super::decode_bitcoin(&variant.transaction, &variant.prevouts, 1)?
                    .inputs
                    .iter()
                    .any(|input| input.script_pubkey != owner_script)
            {
                return Err(Error::Context);
            }
        }
        let mut slot_ids = BTreeSet::new();
        for slot in &slots {
            let record = &slot.record;
            let id = u32::try_from(record.slot).map_err(|_| Error::Parameters)?;
            if !slot_ids.insert(id)
                || record.public != public_key
                || record.committee_public != committee.public
                || record.leaf_set_hash != binding
                || record.threshold != committee.threshold
                || record.n != committee.n
                || record.gate != actors.gate
            {
                return Err(Error::Context);
            }
            slot.verify_setup()?;
            header.slots.push(id);
        }
        let prepared = PreparedEnvelope::new(
            public,
            transport_keys,
            u16::try_from(committee.threshold).map_err(|_| Error::Threshold)?,
            rng,
        )?;
        let outer = prepared.outer_bytes().len();
        let dd = prepared.dd();
        let mut tickets = Vec::with_capacity(slots.len());
        let mut bodies = Zeroizing::new(Vec::new());
        let mut actor_values =
            Zeroizing::new(vec![vec![Vec::new(); k as usize]; signing_set.len() - 1]);
        let mut capsules = Vec::with_capacity(k as usize);
        let mut capsule_bytes = 0;
        for (variant_index, variant) in variants.iter().enumerate() {
            let mut values = Zeroizing::new(Vec::with_capacity(l as usize));
            let mut nonces = Vec::with_capacity(l as usize);
            for (input, hash) in variant.hashes.iter().enumerate() {
                let slot = &mut slots[variant_index * l as usize + input];
                let ticket = Ticket {
                    slot: slot.record.slot,
                    hash: *hash,
                };
                let mut bytes = (ticket.slot as u32).to_be_bytes().to_vec();
                bytes.extend_from_slice(&ticket.hash);
                header.tickets.push(bytes);
                values.push(
                    slot.contribute(&signing_set[0], signing_set, &ticket)?
                        .value,
                );
                for (actor_index, leaf) in signing_set.iter().skip(1).enumerate() {
                    actor_values[actor_index][variant_index]
                        .push(slot.contribute(leaf, signing_set, &ticket)?.value);
                }
                nonces.push(encode_point(slot.record.nonce)?.to_vec());
                tickets.push(ticket);
            }
            bodies.push(core::mem::take(&mut *values));
            let mut salt = [0; 32];
            rng.fill_bytes(&mut salt);
            let capsule = Capsule {
                transaction: variant.transaction.clone(),
                prevouts: variant.prevouts.clone(),
                destination: variant.destination.clone(),
                nonces,
                salt,
                initiator_term: encode_point(weighted_points[0])?.to_vec(),
                initiator: wire_ids[0],
                signing_set: wire_ids.clone(),
                actors: signing_set
                    .iter()
                    .enumerate()
                    .skip(1)
                    .map(|(index, _leaf)| {
                        Ok(CapsuleActor {
                            leaf: wire_ids[index],
                            pool_id: None,
                            pair_indices: vec![],
                            weighted_point: encode_point(weighted_points[index])?.to_vec(),
                        })
                    })
                    .collect::<Result<_>>()?,
            };
            capsule_bytes += capsule.encode(1, l as usize)?.len() + 16;
            capsules.push(capsule);
        }
        let mut intent_opening = Zeroizing::new([0; 32]);
        rng.fill_bytes(intent_opening.as_mut());
        let intent = variants
            .iter()
            .map(|v| super::SpendVariant {
                transaction: v.transaction.clone(),
                prevouts: v.prevouts.clone(),
                destination: v.destination.clone(),
            })
            .collect::<Vec<_>>();
        header.ic = super::intent_commitment(&intent, &intent_opening)?;
        rng.fill_bytes(&mut header.r_tkc);
        let mut embedded_bytes = 0;
        if signing_set.len() > 1 {
            for variant in 1..=k {
                header
                    .contribution_keys
                    .push(prepared.contribution_public(variant, 0)?);
            }
            for (actor_index, values) in actor_values.iter().enumerate() {
                let position = u8::try_from(actor_index + 1).map_err(|_| Error::Parameters)?;
                let mut token = [0; 16];
                rng.fill_bytes(&mut token);
                let sealed = values
                    .iter()
                    .enumerate()
                    .map(|(v, scalars)| {
                        SealedContribution::seal(
                            header.contribution_keys[v],
                            &ContributionContext {
                                dd,
                                position,
                                variant: (v + 1) as u8,
                                generation: 0,
                            },
                            scalars,
                            rng,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                embedded_bytes += 16 + sealed.iter().map(|s| s.encode().len()).sum::<usize>();
                header.actors.push(ActorSlot {
                    position,
                    token_hash: envelope::token_hash(&token),
                    party_index: Some(wire_ids[actor_index + 1]),
                    embedded: Some(EmbeddedContribution { token, sealed }),
                });
            }
        }
        let header_bytes = header.encode()?.len() + 16;
        let pending =
            prepared.build(header, core::mem::take(&mut *bodies), capsules, vec![], rng)?;
        // Measure the body region from the serialized frame after subtracting
        // its other serialized regions. Embedded actors add no tail capsules.
        let body_bytes = pending.used_bytes()
            - envelope::PUBLIC_SIZE
            - envelope::PROOF_SIZE
            - envelope::LAYOUT_SIZE
            - outer
            - header_bytes
            - capsule_bytes;
        let sizes = EcdsaSizes {
            used: pending.used_bytes(),
            outer,
            header: header_bytes,
            bodies: body_bytes,
            capsules: capsule_bytes,
            embedded_contributions: embedded_bytes,
        };
        let envelope = pending.authorize(None, rng)?;
        let bound_eid = envelope.eid();
        Ok(Self {
            intent_opening,
            envelope,
            sizes,
            public_key,
            k,
            l,
            slots,
            tickets,
            signing_set: signing_set.to_vec(),
            wire_ids,
            weighted_points,
            variants,
            transport_keys: transport_keys.to_vec(),
            bound_eid,
        })
    }

    fn index(&self, variant: u8, input: usize) -> Result<usize> {
        self.check_binding()?;
        if variant == 0 || variant > self.k || input >= self.l as usize {
            return Err(Error::Parameters);
        }
        Ok((variant as usize - 1) * self.l as usize + input)
    }

    fn check_binding(&self) -> Result<()> {
        if self.envelope.eid() != self.bound_eid
            || self.k as usize != self.variants.len()
            || self
                .variants
                .iter()
                .any(|v| v.hashes.len() != self.l as usize)
            || self.slots.len() != self.k as usize * self.l as usize
        {
            return Err(Error::Context);
        }
        Ok(())
    }

    pub fn ticket(&self, variant: u8, input: usize) -> Result<&Ticket> {
        Ok(&self.tickets[self.index(variant, input)?])
    }

    pub fn slot_record(&self, variant: u8, input: usize) -> Result<&SlotRecord> {
        Ok(&self.slots[self.index(variant, input)?].record)
    }

    pub fn header_partial(&self, node: u16, transport_secret: Scalar) -> Result<prf::Partial> {
        self.check_binding()?;
        let share = Zeroizing::new(self.envelope.decrypt_share(
            node,
            transport_secret,
            &self.transport_keys,
        )?);
        prf::partial(*share, node, &self.envelope.dd(), Label::Hdr)
    }

    pub fn open_header(&self, partials: &[prf::Partial]) -> Result<OpenedHeader> {
        self.check_binding()?;
        self.envelope.open_header(partials)
    }

    pub fn body_partial(
        &self,
        node: u16,
        transport_secret: Scalar,
        variant: u8,
    ) -> Result<prf::Partial> {
        self.index(variant, 0)?;
        let share = Zeroizing::new(self.envelope.decrypt_share(
            node,
            transport_secret,
            &self.transport_keys,
        )?);
        prf::partial(
            *share,
            node,
            &self.envelope.dd(),
            Label::Body {
                variant: variant as u16,
                generation: 0,
            },
        )
    }

    /// Produce this node's L signing partials. Every slot holder is one-use.
    pub fn signature_partials(&mut self, variant: u8, node: u16) -> Result<Vec<ecdsa::Partial>> {
        self.index(variant, 0)?;
        (0..self.l as usize)
            .map(|input| {
                let index = self.index(variant, input)?;
                self.slots[index].partial(node, &self.signing_set, &self.tickets[index])
            })
            .collect()
    }

    /// `partials[input]` contains the committee replies for that input.
    pub fn combine(
        &self,
        opened: &OpenedHeader,
        variant: u8,
        body_partials: &[prf::Partial],
        partials: &[Vec<ecdsa::Partial>],
    ) -> core::result::Result<Vec<ecdsa::Signature>, EcdsaCombineError> {
        self.index(variant, 0)?;
        self.envelope.wire_sizes(opened)?;
        let body = self
            .envelope
            .open_selected(opened, variant, 0, body_partials)?;
        self.combine_opened(opened.header(), variant, &body, partials)
    }

    /// Internal equation checks after authenticated opening. Keeping raw header
    /// and body values private prevents callers from bypassing envelope binding.
    fn combine_opened(
        &self,
        header: &Header,
        variant: u8,
        body: &OpenedVariant,
        partials: &[Vec<ecdsa::Partial>],
    ) -> core::result::Result<Vec<ecdsa::Signature>, EcdsaCombineError> {
        self.index(variant, 0)?;
        header.validate()?;
        if header.kind != RequestType::Spend
            || header.suite != 1
            || header.k != self.k
            || header.l != self.l
            || body.scalars.len() != self.l as usize
            || partials.len() != self.l as usize
            || header.actors.len() + 1 != self.signing_set.len()
        {
            return Err(Error::Context.into());
        }
        let source = &self.variants[variant as usize - 1];
        if body.capsule.transaction != source.transaction
            || body.capsule.prevouts != source.prevouts
            || body.capsule.destination != source.destination
            || body.capsule.signing_set != self.wire_ids
            || body.capsule.initiator != self.wire_ids[0]
            || body.capsule.initiator_term != encode_point(self.weighted_points[0])?
            || body.capsule.nonces.len() != self.l as usize
            || body.capsule.actors.len() + 1 != self.signing_set.len()
        {
            return Err(Error::Context.into());
        }
        let host_hashes = EcdsaVariant {
            transaction: body.capsule.transaction.clone(),
            prevouts: body.capsule.prevouts.clone(),
            destination: body.capsule.destination.clone(),
            hashes: vec![],
        }
        .recompute(self.l)?;
        let mut contributions = vec![Vec::new(); self.l as usize];
        for (input, row) in contributions.iter_mut().enumerate() {
            row.push(Contribution {
                leaf: self.signing_set[0].clone(),
                value: body.scalars[input],
            });
        }
        for (actor_index, actor) in header.actors.iter().enumerate() {
            let capsule_actor = &body.capsule.actors[actor_index];
            if capsule_actor.leaf != self.wire_ids[actor_index + 1]
                || capsule_actor.pool_id.is_some()
                || !capsule_actor.pair_indices.is_empty()
                || capsule_actor.weighted_point
                    != encode_point(self.weighted_points[actor_index + 1])?
            {
                return Err(Error::Context.into());
            }
            let key = header.contribution_keys[variant as usize - 1];
            if Secp::generator_mul(body.contribution_secret) != key {
                return Err(EcdsaCombineError::Initiator {
                    input: 0,
                    leaf: self.signing_set[0].clone(),
                });
            }
            if actor.party_index != Some(self.wire_ids[actor_index + 1]) {
                return Err(Error::Context.into());
            }
            let sealed =
                &actor.embedded.as_ref().ok_or(Error::Threshold)?.sealed[variant as usize - 1];
            let values = Zeroizing::new(
                sealed
                    .open(
                        body.contribution_secret,
                        key,
                        &ContributionContext {
                            dd: self.envelope.dd(),
                            position: actor.position,
                            variant,
                            generation: 0,
                        },
                        self.l as usize,
                    )
                    .map_err(|_| EcdsaCombineError::Actor {
                        input: 0,
                        leaf: self.signing_set[actor_index + 1].clone(),
                    })?,
            );
            for (input, row) in contributions.iter_mut().enumerate() {
                row.push(Contribution {
                    leaf: self.signing_set[actor_index + 1].clone(),
                    value: values[input],
                });
            }
        }
        (0..self.l as usize)
            .map(|input| {
                let index = self.index(variant, input)?;
                let ticket = &self.tickets[index];
                let wire = &header.tickets[index];
                if wire[..4] != (ticket.slot as u32).to_be_bytes()
                    || wire[4..] != ticket.hash
                    || host_hashes[input] != ticket.hash
                    || body.capsule.nonces[input] != encode_point(self.slots[index].record.nonce)?
                {
                    return Err(Error::Context.into());
                }
                self.slots[index]
                    .combine_diagnosed(
                        &self.signing_set,
                        ticket,
                        &contributions[input],
                        &partials[input],
                    )
                    .map_err(|error| match error {
                        ecdsa::CombineFailure::Invalid(error) => EcdsaCombineError::Invalid(error),
                        ecdsa::CombineFailure::BadPartial(node) => {
                            EcdsaCombineError::Node { input, node }
                        }
                        ecdsa::CombineFailure::BadContribution(leaf)
                            if leaf == self.signing_set[0] =>
                        {
                            EcdsaCombineError::Initiator { input, leaf }
                        }
                        ecdsa::CombineFailure::BadContribution(leaf) => {
                            EcdsaCombineError::Actor { input, leaf }
                        }
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::SeededRng;
    use crate::split::access::Gate;
    use crate::split::birth::BirthContext;

    fn fixture(actors_count: u16) -> (EcdsaRequest, Vec<Scalar>) {
        fixture_with_seed(actors_count, 914)
    }

    fn fixture_with_seed(actors_count: u16, seed: u64) -> (EcdsaRequest, Vec<Scalar>) {
        let mut rng = SeededRng::new(seed);
        let committee = Committee::<Secp>::generate(4, 3, &mut rng).unwrap();
        let set: Vec<_> = (1..=actors_count)
            .map(|i| LeafId::new(i, vec![], 1))
            .collect();
        let gate = Gate::And(set.iter().cloned().map(Gate::Leaf).collect());
        let actors = ActorShares::<Secp>::generate(
            gate,
            &BirthContext {
                committee: committee.public,
                charter_id: [4; 32],
                chain_id: [5; 32],
            },
            &mut rng,
        )
        .unwrap();
        let tweak = Scalar::from(7u64);
        let slots = (1..=6)
            .map(|id| Slot::ideal(id, &committee, &actors, tweak, &set, &mut rng).unwrap())
            .collect();
        let mut owner_script = vec![0, 20];
        owner_script.extend(
            crate::wire::address_for(
                3,
                committee.public + actors.public + Secp::generator_mul(tweak),
            )
            .unwrap(),
        );
        let variants = (1..=3)
            .map(|v| {
                use crate::builder::{OutPoint, SpendKind, Utxo, UtxoTransaction};
                EcdsaVariant::bitcoin(&UtxoTransaction {
                    inputs: (0..2)
                        .map(|input| Utxo {
                            outpoint: OutPoint {
                                txid: [17; 32],
                                vout: input,
                            },
                            value: 100_000,
                            script_pubkey: owner_script.clone(),
                            confirmations: 6,
                        })
                        .collect(),
                    outputs: vec![crate::wire::Output {
                        amount: 200_000 - v as u128 * 1000,
                        script: owner_script.clone(),
                    }],
                    fee: v * 1000,
                    vsize: 200,
                    signed_vsize: None,
                    anchor_height: 100,
                    lock_time: 0,
                    spend_kind: SpendKind::P2wpkh,
                })
                .unwrap()
            })
            .collect();
        let secrets: Vec<_> = (1..=4).map(|i| Scalar::from(i + 100u64)).collect();
        let keys: Vec<_> = secrets.iter().map(|s| Secp::generator_mul(*s)).collect();
        let public = Public::new(1, envelope::keylist_hash(&keys).unwrap(), 100);
        (
            EcdsaRequest::build(
                &committee, &actors, &set, tweak, slots, variants, &keys, public, &mut rng,
            )
            .unwrap(),
            secrets,
        )
    }

    fn replies(
        request: &mut EcdsaRequest,
        secrets: &[Scalar],
        variant: u8,
    ) -> (OpenedHeader, Vec<prf::Partial>, Vec<Vec<ecdsa::Partial>>) {
        let hdr: Vec<_> = (1..=3)
            .map(|node| {
                request
                    .header_partial(node, secrets[node as usize - 1])
                    .unwrap()
            })
            .collect();
        let opened = request.open_header(&hdr).unwrap();
        let body: Vec<_> = (1..=3)
            .map(|node| {
                request
                    .body_partial(node, secrets[node as usize - 1], variant)
                    .unwrap()
            })
            .collect();
        let mut signatures = vec![vec![], vec![]];
        for node in 1..=3 {
            for (input, partial) in request
                .signature_partials(variant, node)
                .unwrap()
                .into_iter()
                .enumerate()
            {
                signatures[input].push(partial);
            }
        }
        (opened, body, signatures)
    }

    #[test]
    fn k3_l2_single_user_roundtrip() {
        let (mut request, secrets) = fixture(1);
        let (opened, body, partials) = replies(&mut request, &secrets, 2);
        assert!(opened
            .header()
            .tickets
            .iter()
            .all(|ticket| ticket.len() == 36));
        assert_eq!(opened.header().labels(), vec![(1, 0), (2, 0), (3, 0)]);
        assert!(request
            .envelope
            .open_selected(&opened, 1, 0, &body)
            .is_err());
        let signatures = request.combine(&opened, 2, &body, &partials).unwrap();
        for (input, signature) in signatures.iter().enumerate() {
            signature
                .verify(request.public_key, &request.ticket(2, input).unwrap().hash)
                .unwrap();
        }
        assert!(request.signature_partials(2, 1).is_err());
        assert_eq!(
            request.sizes.used,
            envelope::PUBLIC_SIZE
                + envelope::PROOF_SIZE
                + envelope::LAYOUT_SIZE
                + request.sizes.outer
                + request.sizes.header
                + request.sizes.bodies
                + request.sizes.capsules
        );
    }

    #[test]
    fn invalid_scalar_names_initiator() {
        let (mut request, secrets) = fixture(1);
        let (opened, body_partials, partials) = replies(&mut request, &secrets, 2);
        let mut body = request
            .envelope
            .open_selected(&opened, 2, 0, &body_partials)
            .unwrap();
        body.scalars[1] += Scalar::ONE;
        assert_eq!(
            request
                .combine_opened(opened.header(), 2, &body, &partials)
                .unwrap_err(),
            EcdsaCombineError::Initiator {
                input: 1,
                leaf: request.signing_set[0].clone()
            }
        );
    }

    #[test]
    fn embedded_actors_roundtrip_and_key_attribution() {
        let (mut request, secrets) = fixture(3);
        let (opened, body_partials, partials) = replies(&mut request, &secrets, 3);
        assert_eq!(
            request
                .combine(&opened, 3, &body_partials, &partials)
                .unwrap()
                .len(),
            2
        );
        let body = request
            .envelope
            .open_selected(&opened, 3, 0, &body_partials)
            .unwrap();
        let mut header = opened.header().clone();
        header.contribution_keys[2] += ProjectivePoint::GENERATOR;
        assert_eq!(
            request
                .combine_opened(&header, 3, &body, &partials)
                .unwrap_err(),
            EcdsaCombineError::Initiator {
                input: 0,
                leaf: request.signing_set[0].clone()
            }
        );
    }

    #[test]
    fn foreign_envelope_and_malformed_dimensions_are_rejected_before_release() {
        let (mut request, _) = fixture(1);
        let (mut other, secrets) = fixture_with_seed(1, 915);
        let hdr = (1..=3)
            .map(|node| {
                other
                    .header_partial(node, secrets[node as usize - 1])
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let opened = other.open_header(&hdr).unwrap();
        assert!(matches!(
            request.combine(&opened, 2, &[], &[]),
            Err(EcdsaCombineError::Invalid(Error::Context))
        ));
        core::mem::swap(&mut request.envelope, &mut other.envelope);
        assert!(matches!(
            request.signature_partials(2, 1),
            Err(Error::Context)
        ));
        core::mem::swap(&mut request.envelope, &mut other.envelope);
        request.k = u8::MAX;
        assert!(matches!(request.ticket(u8::MAX, 0), Err(Error::Context)));
        request.k = 3;
        request.l = 0;
        assert!(matches!(
            request.signature_partials(2, 1),
            Err(Error::Context)
        ));
        request.l = 2;
        assert_eq!(request.signature_partials(2, 1).unwrap().len(), 2);
    }
}
