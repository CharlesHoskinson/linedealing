//! E9 (DECISIONS 78): a ticket whose `c̃` is not the challenge of an admitted transaction.
//!
//! A committee that answers challenges which nothing binds to a message signs for an
//! attacker: the bitcoin-dev thread "Blinded 2-party Musig2" (July 2023) gets `K + 1`
//! signatures from `K` sessions with a Wagner attack on such a signer. The node of this
//! design is blind and takes `c̃` from the ticket (DESIGN §4.2), so the ticket check is the
//! only rule that ties `c̃` to a transaction.
//!
//! The first test shows what one unchecked ticket gives: a signature on a transaction
//! outside the request. The second test puts the same forged ticket in a real request header
//! and checks that the recomputation of the tickets from the capsules refuses it. The
//! wallet, the actor (rule 1 of §4.2) and the combiner run that recomputation. It is what
//! the prototype has of the ticket check. The node side has none: the ticket circuit of O4
//! is not built, and the reducer takes the TEE intent check of §5.3 as the flag
//! `Header.valid`. Both take the same vector when they are built.
mod common;
use common::TestRng;
use line_dealing::split::{
    access::{Gate, LeafId},
    birth::{ActorShares, BirthContext, Committee},
    group::{lagrange, Edwards, Secp},
    request::{check_release_tickets, decode_ticket, encode_ticket, SchnorrSetup},
    schnorr::{ActorPool, Half, InitiatorNonce, Node, Request, SchnorrSuite, SigningKey, Ticket},
    slots::CommitteeSlots,
};
use std::collections::BTreeMap;

fn and_of_three() -> (Gate, Vec<LeafId>) {
    let leaves: Vec<_> = (1..=3).map(|i| LeafId::new(i, vec![], 1)).collect();
    (
        Gate::And(leaves.iter().cloned().map(Gate::Leaf).collect()),
        leaves,
    )
}

/// The ticket of `request` with `c̃` replaced by the challenge of `other` on the same `R`.
fn forged<S: SchnorrSuite>(key: &SigningKey<S>, request: &Request<S>, other: &[u8]) -> Ticket<S> {
    let tr = request.transcript(key).unwrap();
    let (gp, gq, _) = tr.parity;
    let mut ticket = tr.ticket.clone();
    ticket.challenge = gp * gq * S::challenge(tr.nonce, tr.output_key, other).unwrap();
    assert_ne!(ticket.challenge, tr.ticket.challenge);
    ticket
}

/// Without the ticket check the committee signs a transaction that no request holds.
fn unchecked_ticket_signs_another_message<S: SchnorrSuite>() {
    let mut rng = TestRng::new();
    let committee = Committee::<S>::generate(9, 7, &mut rng).unwrap();
    let slots = CommitteeSlots::<S>::generate(9, 7, &[7], 9, &mut rng).unwrap();
    let slot = &slots.slots[&7];
    let (gate, set) = and_of_three();
    let actors = ActorShares::<S>::generate(
        gate,
        &BirthContext {
            committee: committee.public,
            charter_id: [11; 32],
            chain_id: [12; 32],
        },
        &mut rng,
    )
    .unwrap();
    let key = SigningKey::new(
        committee.public,
        &actors,
        S::scalar_from_u64(79),
        vec![],
        set.clone(),
    )
    .unwrap();

    // An honest request for the admitted message, with every actor's contribution.
    let admitted = vec![42; 32];
    let mut pools = BTreeMap::new();
    let mut pairs = BTreeMap::new();
    for (i, id) in set.iter().enumerate().skip(1) {
        let pool = ActorPool::new(
            id.clone(),
            [i as u8; 32],
            actors.shares[id],
            key.tweak,
            1,
            &mut rng,
        )
        .unwrap();
        pairs.insert(id.clone(), pool.commitment(0).unwrap());
        pools.insert(id.clone(), pool);
    }
    let init = InitiatorNonce::new(
        set[0].clone(),
        actors.shares[&set[0]],
        &key,
        7,
        &admitted,
        &mut rng,
    )
    .unwrap();
    let request = Request {
        epoch: 9,
        slot: 7,
        half: Half {
            variant: 1,
            generation: 1,
            input: 0,
        },
        initiator: set[0].clone(),
        signers: set.clone(),
        r0: init.point(),
        pairs,
        d: slot.d,
        e: slot.e,
        message: admitted,
        salt_v: [13; 32],
        fee_rate: 10,
        not_before: 0,
        exp_c: 100,
    };
    let tr = request.transcript(&key).unwrap();
    let mut actor_sum = init.contribute(&key, &request, 0).unwrap();
    for pool in pools.values_mut() {
        actor_sum = actor_sum + pool.contribute(&key, &request, 0).unwrap();
    }

    // The attacker holds every actor and wants a signature on another message.
    let other = vec![43; 32];
    let ticket = forged(&key, &request, &other);
    // The actor's own check refuses the ticket.
    assert!(request.check_ticket(&key, &ticket).is_err());
    // The node's release check passes it: `R` follows from `R_A`, the slot and `pm`, and
    // the node cannot tell whose challenge `c̃` is.
    check_release_tickets::<S>(
        9,
        std::slice::from_ref(&ticket),
        &BTreeMap::from([(7, (slot.d, slot.e))]),
    )
    .unwrap();
    let ids: Vec<u16> = (1..=7).collect();
    let mut committee_half = S::scalar_zero();
    for (id, weight) in ids.iter().zip(lagrange::<S>(&ids).unwrap()) {
        let mut node = Node::<S>::new(*id, 9, committee.shares[*id as usize - 1]).unwrap();
        node.install(7, slot).unwrap();
        committee_half = committee_half + weight * node.release(&ticket).unwrap().value;
    }
    // The actors' sum moves from the admitted challenge to the forged one with values the
    // attacker holds: s_A' = s_A + (c̃' − c̃)·(Σ λ_a·x_a + tw) + (c' − c)·g_Q·t_tap.
    let (_, gp, _, tap) = S::output_key(key.x, &key.root).unwrap();
    let mut secret = key.tweak;
    for id in &set {
        secret = secret + tr.weights[id] * actors.shares[id];
    }
    let shift = (ticket.challenge - tr.ticket.challenge) * (secret + gp * tap);
    let signature = S::signature(tr.nonce, actor_sum + shift + committee_half).unwrap();
    S::verify(tr.output_key, &other, &signature).unwrap();
    assert!(S::verify(tr.output_key, &request.message, &signature).is_err());
}

/// The ticket check: every ticket of a header is recomputed from the capsules, and a
/// ticket with another challenge is refused at every position.
fn forged_ticket_is_refused<S: SchnorrSuite>(l: u8) {
    let mut rng = TestRng::new();
    let (gate, set) = and_of_three();
    let setup = SchnorrSetup::<S>::new(9, 7, 3, l, gate, set, &mut rng).unwrap();
    let draft = setup.build(&mut rng).unwrap();
    let requests = draft
        .context
        .reconstruct(&draft.header, &draft.capsules, 1)
        .unwrap();
    assert_eq!(requests.len(), draft.header.tickets.len());
    for (i, request) in requests.iter().enumerate() {
        let honest = decode_ticket::<S>(&draft.header.tickets[i]).unwrap();
        assert_eq!(
            honest,
            request.transcript(&draft.context.key).unwrap().ticket
        );
        let ticket = forged(&draft.context.key, request, &[0xE9; 32]);
        // Only `c̃` differs, so the node's release check still passes.
        check_release_tickets::<S>(1, std::slice::from_ref(&ticket), &draft.context.slots).unwrap();
        let mut header = draft.header.clone();
        header.tickets[i] = encode_ticket(&ticket).unwrap();
        assert!(
            draft
                .context
                .reconstruct(&header, &draft.capsules, 1)
                .is_err(),
            "ticket {i} with an unbound challenge was accepted"
        );
    }
}

#[test]
fn e9_bip340_unchecked_ticket_signs_another_message() {
    unchecked_ticket_signs_another_message::<Secp>();
}
#[test]
fn e9_ed25519_unchecked_ticket_signs_another_message() {
    unchecked_ticket_signs_another_message::<Edwards>();
}
#[test]
fn e9_bip340_wagner_unbound_challenge_ticket_is_refused() {
    forged_ticket_is_refused::<Secp>(2);
}
#[test]
fn e9_ed25519_wagner_unbound_challenge_ticket_is_refused() {
    forged_ticket_is_refused::<Edwards>(1);
}
