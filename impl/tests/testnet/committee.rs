//! The split-line committee as a signer for the testnet transactions.
//!
//! Every signature comes from the split prototype: a 9-node committee with
//! threshold 7 plus one actor leaf. Bitcoin, Solana and Cardano go through the
//! full request flow (envelope, board, release, combine). Ethereum and Midnight
//! sign a 32-byte hash one layer lower with the same committee and slots: the
//! envelope's host parser accepts only Bitcoin transactions (lead decision,
//! marked for owner confirmation).
//!
//! Key draws come from a seeded stream, so a persisted seed gives the same
//! address on every run. Nonce material (slots, presignatures, transport keys,
//! initiator nonces) always comes from the caller's fresh RNG.
#![allow(dead_code)]

use k256::elliptic_curve::rand_core::{CryptoRng, CryptoRngCore, Error as RngError, RngCore};
use k256::{ProjectivePoint, Scalar};
use line_dealing::split::{
    access::{Gate, LeafId},
    birth::{ActorShares, BirthContext, Committee},
    ecdsa::{self, Slot, Ticket},
    envelope::{self, Public},
    group::{Edwards, Secp, Suite},
    prf::Label,
    request::{
        board::{AuthorizationEvidence, BoardAdapter, HeaderPolicy, ReleaseEvidence},
        check_release_tickets, decode_ticket,
        ecdsa::{EcdsaRequest, EcdsaVariant},
        SchnorrSetup, SpendVariant,
    },
    schnorr::{self, Half, InitiatorNonce, SchnorrSuite},
    state::{Event, Observation, PoolCheckpoint, PoolId, State},
};
use line_dealing::Error;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const N: u16 = 9;
pub const T: usize = 7;

/// Deterministic key stream: SHA-256(tag || seed || counter) blocks.
pub struct KeyRng {
    seed: [u8; 32],
    counter: u64,
}
impl KeyRng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}
impl CryptoRng for KeyRng {}
impl RngCore for KeyRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_be_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.counter += 1;
            let block = Sha256::new()
                .chain_update(b"testnet/key")
                .chain_update(self.seed)
                .chain_update(self.counter.to_be_bytes())
                .finalize();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn single() -> (Gate, Vec<LeafId>) {
    let id = LeafId::new(1, vec![], 1);
    (Gate::Leaf(id.clone()), vec![id])
}

fn checkpoint(board: &mut BoardAdapter) {
    board
        .apply(
            0,
            Event::Checkpoint {
                pools: [
                    line_dealing::split::state::Suite::Bip340,
                    line_dealing::split::state::Suite::Ed25519,
                ]
                .into_iter()
                .map(|suite| {
                    (
                        PoolId { suite, epoch: 1 },
                        PoolCheckpoint {
                            h: 0,
                            pending_min: 1,
                            pending_root: [0; 32],
                            pending_count: 0,
                            pending: BTreeMap::new(),
                            pending_verified: true,
                        },
                    )
                })
                .collect(),
            },
        )
        .unwrap();
}

/// BIP340 or Ed25519 committee for one signing round (one fresh slot).
pub struct SchnorrCommittee<S: SchnorrSuite> {
    pub setup: SchnorrSetup<S>,
}
impl<S: SchnorrSuite> SchnorrCommittee<S> {
    pub fn new(seed: [u8; 32], nonce_rng: &mut dyn CryptoRngCore) -> Self {
        let (gate, set) = single();
        let setup = SchnorrSetup::<S>::new_with_rngs(
            N,
            T,
            1,
            1,
            gate,
            set,
            &mut KeyRng::new(seed),
            Some(nonce_rng),
        )
        .unwrap();
        Self { setup }
    }
    /// The key the chain sees: BIP341-tweaked for Secp, plain for Ed25519.
    pub fn output_key(&self) -> S::Point {
        self.setup.key.output().unwrap()
    }

    /// Full split request flow for one host variant with one input.
    /// Returns the signature and the message the committee signed.
    pub fn sign_variant(
        &mut self,
        variant: SpendVariant,
        rng: &mut dyn CryptoRngCore,
    ) -> ([u8; 64], Vec<u8>) {
        let mut rng = rng;
        let setup = &mut self.setup;
        setup.variants = vec![variant];
        let req = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let eid = req.envelope.eid();
        let n = setup.committee.n;
        let f = n - setup.committee.threshold as u16;
        let quorum = (n + f + 1).div_ceil(2);
        let mut board = BoardAdapter::new(
            line_dealing::board::Committee { n, f },
            1,
            20,
            256,
            false,
            false,
            setup.transport_keys.clone(),
        )
        .unwrap();
        checkpoint(&mut board);
        board.post(1, &req.envelope).unwrap();
        board.order(2, eid, true).unwrap();
        let keys: Vec<_> = setup
            .transport_secrets
            .iter()
            .enumerate()
            .map(|(i, s)| (i as u16 + 1, *s))
            .collect();
        let opened = board
            .open_header(
                3,
                &req.envelope,
                &keys,
                HeaderPolicy::simulator_owner([1; 32], [2; 32], [3; 32]),
            )
            .unwrap();
        board
            .authorize(
                3,
                eid,
                AuthorizationEvidence {
                    statement_verified: true,
                    inclusion_verified: true,
                    midnight_height: 10,
                },
            )
            .unwrap();
        for node in 1..=quorum {
            board
                .admit(
                    4,
                    eid,
                    node,
                    Observation {
                        host_height: 100,
                        midnight_height: 10,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            board.board().request(&eid).unwrap().state,
            State::Anchored(1)
        );
        let (v, g) = (1u8, 1u8);
        let index = opened
            .header()
            .labels()
            .iter()
            .position(|p| *p == (v, g))
            .unwrap();
        let tickets = opened.header().tickets[index..index + 1]
            .iter()
            .map(|b| decode_ticket::<S>(b).unwrap())
            .collect::<Vec<_>>();
        let mut nodes = (1..=n).map(|i| setup.node(i).unwrap()).collect::<Vec<_>>();
        let mut body = Vec::new();
        let mut parts = vec![Vec::new()];
        for node in &mut nodes {
            board
                .release(
                    5,
                    eid,
                    node.id,
                    u16::from(g),
                    u16::from(v),
                    ReleaseEvidence {
                        selection_verified: true,
                        midnight_height: 11,
                        not_revoked_verified: true,
                    },
                    || check_release_tickets::<S>(1, &tickets, &setup.context.slots),
                )
                .unwrap();
            body.push(
                req.partial(
                    node.id,
                    setup.transport_secrets[node.id as usize - 1],
                    &setup.transport_keys,
                    Label::Body {
                        variant: u16::from(v),
                        generation: u16::from(g),
                    },
                )
                .unwrap(),
            );
            for (j, p) in req
                .signature_partials(&opened, v, g, node)
                .unwrap()
                .into_iter()
                .enumerate()
            {
                parts[j].push(p);
            }
        }
        assert_eq!(
            board.board().request(&eid).unwrap().state,
            State::Released {
                generation: 1,
                variant: 1
            }
        );
        let combined = req
            .combine_admitted(
                &board,
                &opened,
                v,
                g,
                &body,
                &parts,
                &setup.committee,
                &mut setup.slots,
            )
            .unwrap();
        // The message is what the opened capsule says, not what the caller holds.
        let selected = req.envelope.open_selected(&opened, v, g, &body).unwrap();
        let message = SpendVariant {
            transaction: selected.capsule.transaction.clone(),
            prevouts: selected.capsule.prevouts.clone(),
            destination: selected.capsule.destination.clone(),
        }
        .messages(S::SUITE_ID, 1)
        .unwrap()
        .remove(0);
        board.board().check_invariants().unwrap();
        board.board().check_release_invariants().unwrap();
        (combined[0].signature, message)
    }

    /// Sign one message through the split Schnorr algebra without the envelope:
    /// initiator nonce, committee slot, node releases and verified combine.
    pub fn sign_message(&mut self, message: &[u8], rng: &mut dyn CryptoRngCore) -> [u8; 64] {
        let mut rng = rng;
        let setup = &mut self.setup;
        let leaf = setup.set[0].clone();
        let slot = *setup.slots.slots.keys().next().unwrap();
        let init = InitiatorNonce::new(
            leaf.clone(),
            setup.actors.shares[&leaf],
            &setup.key,
            slot,
            message,
            &mut rng,
        )
        .unwrap();
        let (d, e) = setup.context.slots[&slot];
        let mut salt = [0; 32];
        rng.fill_bytes(&mut salt);
        let request = schnorr::Request {
            epoch: 1,
            slot,
            half: Half {
                variant: 1,
                generation: 1,
                input: 0,
            },
            initiator: leaf.clone(),
            signers: setup.set.clone(),
            r0: init.point(),
            pairs: BTreeMap::new(),
            d,
            e,
            message: message.to_vec(),
            salt_v: salt,
            fee_rate: 0,
            not_before: 0,
            exp_c: u64::MAX,
        };
        let value = init.contribute(&setup.key, &request, 0).unwrap();
        let transcript = request.transcript(&setup.key).unwrap();
        let partials = (1..=setup.committee.n)
            .map(|i| setup.node(i).unwrap().release(&transcript.ticket).unwrap())
            .collect::<Vec<_>>();
        let contributions = BTreeMap::from([(leaf, value)]);
        let combined = schnorr::combine(
            &setup.key,
            &request,
            &setup.committee,
            setup.slots.slots.get_mut(&slot).unwrap(),
            &partials,
            &contributions,
        )
        .unwrap();
        S::verify(self.output_key(), message, &combined.signature).unwrap();
        combined.signature
    }
}

pub type Bip340Committee = SchnorrCommittee<Secp>;
pub type Ed25519Committee = SchnorrCommittee<Edwards>;

/// Split ECDSA committee key; each signing round draws fresh presignatures.
pub struct EcdsaCommittee {
    pub committee: Committee<Secp>,
    pub actors: ActorShares<Secp>,
    pub set: Vec<LeafId>,
    pub tweak: Scalar,
}
impl EcdsaCommittee {
    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = KeyRng::new(seed);
        let committee = Committee::<Secp>::generate(N, T, &mut rng).unwrap();
        let (gate, set) = single();
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
        let tweak = Secp::random(&mut rng);
        Self {
            committee,
            actors,
            set,
            tweak,
        }
    }
    pub fn public_key(&self) -> ProjectivePoint {
        self.committee.public + self.actors.public + Secp::generator_mul(self.tweak)
    }
    fn slot(&self, id: u64, rng: &mut dyn CryptoRngCore) -> Slot {
        let mut rng = rng;
        let slot = Slot::ideal(
            id,
            &self.committee,
            &self.actors,
            self.tweak,
            &self.set,
            &mut rng,
        )
        .unwrap();
        assert_eq!(slot.record.public, self.public_key());
        slot
    }

    /// Sign a 32-byte hash with the split ECDSA slot algebra (no envelope).
    pub fn sign_hash(&self, hash: [u8; 32], rng: &mut dyn CryptoRngCore) -> ecdsa::Signature {
        let mut slot = self.slot(1, rng);
        let ticket = Ticket { slot: 1, hash };
        let contributions = self
            .set
            .iter()
            .map(|leaf| slot.contribute(leaf, &self.set, &ticket).unwrap())
            .collect::<Vec<_>>();
        let partials = (1..=T as u16)
            .map(|node| slot.partial(node, &self.set, &ticket).unwrap())
            .collect::<Vec<_>>();
        let sig = slot
            .combine(&self.set, &ticket, &contributions, &partials)
            .unwrap();
        sig.verify(self.public_key(), &hash).unwrap();
        sig
    }

    /// Full split ECDSA request flow for one P2WPKH transaction.
    pub fn sign_p2wpkh(
        &self,
        tx: &line_dealing::builder::UtxoTransaction,
        rng: &mut dyn CryptoRngCore,
    ) -> Vec<ecdsa::Signature> {
        let mut rng = rng;
        let l = tx.inputs.len();
        let slots = (1..=l as u64)
            .map(|id| self.slot(id, &mut rng))
            .collect::<Vec<_>>();
        let variant = EcdsaVariant::bitcoin(tx).unwrap();
        let hashes = variant.hashes.clone();
        let secrets: Vec<Scalar> = (0..N).map(|_| Secp::random(&mut rng)).collect();
        let keys: Vec<_> = secrets.iter().map(|s| Secp::generator_mul(*s)).collect();
        let public = Public::new(1, envelope::keylist_hash(&keys).unwrap(), 100);
        let mut request = EcdsaRequest::build(
            &self.committee,
            &self.actors,
            &self.set,
            self.tweak,
            slots,
            vec![variant],
            &keys,
            public,
            &mut rng,
        )
        .unwrap();
        let node_keys: Vec<_> = secrets
            .iter()
            .take(T)
            .enumerate()
            .map(|(i, s)| (i as u16 + 1, *s))
            .collect();
        let eid = request.envelope.eid();
        let f = N - T as u16;
        let mut board = BoardAdapter::new(
            line_dealing::board::Committee { n: N, f },
            1,
            20,
            256,
            false,
            false,
            keys,
        )
        .unwrap();
        board.post(1, &request.envelope).unwrap();
        board.order(2, eid, true).unwrap();
        let mut policy = HeaderPolicy::simulator_owner([71; 32], [72; 32], [73; 32]);
        let installed: Vec<_> = (0..l)
            .map(|input| request.slot_record(1, input).unwrap().slot)
            .collect();
        policy.ticket_membership = (0..l)
            .map(|input| installed.contains(&request.ticket(1, input).unwrap().slot))
            .collect();
        let opened = board
            .open_header(3, &request.envelope, &node_keys, policy)
            .unwrap();
        board
            .authorize(
                3,
                eid,
                AuthorizationEvidence {
                    statement_verified: true,
                    inclusion_verified: true,
                    midnight_height: 10,
                },
            )
            .unwrap();
        for node in 1..=(N + f + 1).div_ceil(2) {
            board
                .admit(
                    4,
                    eid,
                    node,
                    Observation {
                        host_height: 100,
                        midnight_height: 10,
                    },
                )
                .unwrap();
        }
        let mut body = Vec::new();
        let mut partials = vec![Vec::new(); l];
        for (node, secret) in &node_keys {
            board
                .release(
                    5,
                    eid,
                    *node,
                    1,
                    1,
                    ReleaseEvidence {
                        selection_verified: true,
                        midnight_height: 11,
                        not_revoked_verified: true,
                    },
                    || {
                        for input in 0..l {
                            let ticket = request.ticket(1, input)?;
                            let wire = &opened.header().tickets[input];
                            if wire[..4] != (ticket.slot as u32).to_be_bytes()
                                || wire[4..] != ticket.hash
                            {
                                return Err(Error::Context);
                            }
                        }
                        Ok(())
                    },
                )
                .unwrap();
            body.push(request.body_partial(*node, *secret, 1).unwrap());
            for (input, p) in request
                .signature_partials(1, *node)
                .unwrap()
                .into_iter()
                .enumerate()
            {
                partials[input].push(p);
            }
        }
        let signatures = request.combine(&opened, 1, &body, &partials).unwrap();
        for (sig, hash) in signatures.iter().zip(&hashes) {
            sig.verify(self.public_key(), hash).unwrap();
        }
        signatures
    }
}

/// `OsRng` for nonce material.
pub fn fresh() -> k256::elliptic_curve::rand_core::OsRng {
    k256::elliptic_curve::rand_core::OsRng
}
