use line_dealing::split::schnorr::{halves, G_MAX};

#[test]
fn half_schedule_matches_reference() {
    assert_eq!(G_MAX, 2);
    assert_eq!(halves(8, 2).unwrap().len(), 30);
    assert_eq!(halves(8, 1).unwrap().len(), 15);
    assert_eq!(halves(3, 2).unwrap().len(), 10);
    assert_eq!(halves(1, 1).unwrap().len(), 1);
    assert!(halves(0, 2).is_err());
    assert!(halves(2, 0).is_err());
}

mod common;
use common::TestRng;
use line_dealing::split::{
    access::{Gate, LeafId},
    birth::{ActorShares, BirthContext, Committee},
    group::{Edwards, Secp, Suite},
    schnorr::{
        self, ActorPool, CombineFailure, Half, InitiatorNonce, Node, Partial, Request,
        SchnorrSuite, SigningKey,
    },
    slots::{CommitteeSlots, NonceSlot},
};
use std::collections::{BTreeMap, BTreeSet};

fn leaf(slot: u16, path: &[u16], member: u16) -> Gate {
    Gate::Leaf(LeafId::new(slot, path.to_vec(), member))
}
fn and_gate(count: u16) -> Gate {
    Gate::And((1..=count).map(|i| leaf(i, &[], 1)).collect())
}
fn group(slot: u16, path: &[u16], k: usize, n: u16) -> Gate {
    Gate::Threshold {
        k,
        children: (1..=n).map(|i| leaf(slot, path, i)).collect(),
    }
}
fn actors<S: Suite>(gate: Gate, committee: &Committee<S>, rng: &mut TestRng) -> ActorShares<S> {
    ActorShares::generate(
        gate,
        &BirthContext {
            committee: committee.public,
            charter_id: [11; 32],
            chain_id: [12; 32],
        },
        rng,
    )
    .unwrap()
}

// Each invocation is a separate process simulation with independent local nonce state.
fn prepared<S: SchnorrSuite>(
    key: &SigningKey<S>,
    actors: &ActorShares<S>,
    set: &[LeafId],
    slot_id: u64,
    slot: &NonceSlot<S>,
    rng: &mut TestRng,
) -> (Request<S>, BTreeMap<LeafId, S::Scalar>) {
    let first = set[0].clone();
    let mut pools = BTreeMap::new();
    let mut pairs = BTreeMap::new();
    for (i, id) in set.iter().enumerate().skip(1) {
        let pool = ActorPool::new(
            id.clone(),
            [i as u8; 32],
            actors.shares[id],
            key.tweak,
            1,
            rng,
        )
        .unwrap();
        pairs.insert(id.clone(), pool.commitment(0).unwrap());
        pools.insert(id.clone(), pool);
    }
    let message = vec![42; 32];
    let init = InitiatorNonce::new(
        first.clone(),
        actors.shares[&first],
        key,
        slot_id,
        &message,
        rng,
    )
    .unwrap();
    let request = Request {
        epoch: 9,
        slot: slot_id,
        half: Half {
            variant: 1,
            generation: 1,
            input: 0,
        },
        initiator: first.clone(),
        signers: set.to_vec(),
        r0: init.point(),
        pairs,
        d: slot.d,
        e: slot.e,
        message,
        salt_v: [13; 32],
        fee_rate: 10,
        not_before: 0,
        exp_c: 100,
    };
    let mut contributions = BTreeMap::new();
    contributions.insert(first, init.contribute(key, &request, 0).unwrap());
    for (id, pool) in &mut pools {
        contributions.insert(id.clone(), pool.contribute(key, &request, 0).unwrap());
        assert!(pool.contribute(key, &request, 0).is_err());
        assert_eq!(pool.unused(), 0);
    }
    (request, contributions)
}
fn partials<S: SchnorrSuite>(
    committee: &Committee<S>,
    slot_id: u64,
    slot: &NonceSlot<S>,
    request: &Request<S>,
    key: &SigningKey<S>,
) -> Vec<Partial<S>> {
    let ticket = request.transcript(key).unwrap().ticket;
    request.check_ticket(key, &ticket).unwrap();
    let mut altered = ticket.clone();
    altered.challenge = altered.challenge + S::scalar_one();
    assert!(request.check_ticket(key, &altered).is_err());
    (1..=committee.n)
        .map(|i| {
            let mut node = Node::<S>::new(i, 9, committee.shares[i as usize - 1]).unwrap();
            node.install(slot_id, slot).unwrap();
            let mut bad = ticket.clone();
            bad.nonce[0] ^= 1;
            assert!(node.release(&bad).is_err());
            let partial = node.release(&ticket).unwrap();
            assert!(node.release(&ticket).is_err());
            assert!(node.install(slot_id, slot).is_err());
            partial
        })
        .collect()
}
fn sign<S: SchnorrSuite>(
    committee: &Committee<S>,
    actors: &ActorShares<S>,
    set: &[LeafId],
    slot: &mut NonceSlot<S>,
    root: Vec<u8>,
    rng: &mut TestRng,
) {
    let key = SigningKey::new(
        committee.public,
        actors,
        S::scalar_from_u64(79),
        root,
        actors.gate.leaves().unwrap(),
    )
    .unwrap();
    let (request, contributions) = prepared(&key, actors, set, 7, slot, rng);
    let parts = partials(committee, 7, slot, &request, &key);
    let combined =
        schnorr::combine(&key, &request, committee, slot, &parts, &contributions).unwrap();
    S::verify(key.output().unwrap(), &request.message, &combined.signature).unwrap();
    assert_eq!(slot.cached_nodes(), 0);
}
fn access_matrix<S: SchnorrSuite>() {
    let mut rng = TestRng::new();
    let committee = Committee::<S>::generate(9, 7, &mut rng).unwrap();
    let mut slots = CommitteeSlots::<S>::generate(9, 7, &[7], 9, &mut rng).unwrap();
    for n in 1..=5 {
        let a = actors(and_gate(n), &committee, &mut rng);
        let set = a.gate.leaves().unwrap();
        sign(
            &committee,
            &a,
            &set,
            slots.slots.get_mut(&7).unwrap(),
            vec![],
            &mut rng,
        );
    }
    let a = actors(group(1, &[], 2, 3), &committee, &mut rng);
    let ids = a.gate.leaves().unwrap();
    for subset in [[0, 1], [0, 2], [1, 2]] {
        let set = subset.map(|i| ids[i].clone());
        sign(
            &committee,
            &a,
            &set,
            slots.slots.get_mut(&7).unwrap(),
            vec![],
            &mut rng,
        );
    }
    let escrow = Gate::Or(vec![leaf(1, &[1], 1), group(1, &[2], 3, 5)]);
    let a = actors(escrow, &committee, &mut rng);
    let ids = a.gate.leaves().unwrap();
    sign(
        &committee,
        &a,
        &ids[..1],
        slots.slots.get_mut(&7).unwrap(),
        vec![],
        &mut rng,
    );
    for i in 1..=3 {
        for j in i + 1..=4 {
            for k in j + 1..=5 {
                let set = vec![ids[i].clone(), ids[j].clone(), ids[k].clone()];
                sign(
                    &committee,
                    &a,
                    &set,
                    slots.slots.get_mut(&7).unwrap(),
                    vec![],
                    &mut rng,
                );
            }
        }
    }
}
#[test]
fn bip340_and_threshold_and_escrow_matrix() {
    access_matrix::<Secp>();
}
#[test]
fn ed25519_and_threshold_and_escrow_matrix() {
    access_matrix::<Edwards>();
}

#[test]
fn bip340_nested_threshold_all_seven_subsets() {
    let mut rng = TestRng::new();
    let committee = Committee::<Secp>::generate(9, 7, &mut rng).unwrap();
    let gate = Gate::Threshold {
        k: 2,
        children: vec![leaf(1, &[], 1), leaf(1, &[], 2), group(1, &[3], 2, 3)],
    };
    let a = actors(gate, &committee, &mut rng);
    let ids = a.gate.leaves().unwrap();
    let mut slots = CommitteeSlots::<Secp>::generate(9, 7, &[7], 9, &mut rng).unwrap();
    sign(
        &committee,
        &a,
        &ids[..2],
        slots.slots.get_mut(&7).unwrap(),
        vec![],
        &mut rng,
    );
    for outer in 0..2 {
        for pair in [[2, 3], [2, 4], [3, 4]] {
            let set = vec![
                ids[outer].clone(),
                ids[pair[0]].clone(),
                ids[pair[1]].clone(),
            ];
            sign(
                &committee,
                &a,
                &set,
                slots.slots.get_mut(&7).unwrap(),
                vec![],
                &mut rng,
            );
        }
    }
}

#[test]
fn all_eight_bip340_parities_with_and_without_script_root() {
    let mut rng = TestRng::new();
    let committee = Committee::<Secp>::generate(9, 7, &mut rng).unwrap();
    let mut slots = CommitteeSlots::<Secp>::generate(9, 7, &[7], 9, &mut rng).unwrap();
    for root in [vec![], vec![99; 32]] {
        let mut seen = BTreeSet::new();
        for _ in 0..256 {
            let a = actors(and_gate(2), &committee, &mut rng);
            let set = a.gate.leaves().unwrap();
            let key = SigningKey::new(
                committee.public,
                &a,
                Secp::scalar_from_u64(79),
                root.clone(),
                set.clone(),
            )
            .unwrap();
            let slot = slots.slots.get_mut(&7).unwrap();
            let (request, c) = prepared(&key, &a, &set, 7, slot, &mut rng);
            let tr = request.transcript(&key).unwrap();
            seen.insert((
                tr.parity.0 == Secp::scalar_one(),
                tr.parity.1 == Secp::scalar_one(),
                tr.parity.2 == Secp::scalar_one(),
            ));
            let parts = partials(&committee, 7, slot, &request, &key);
            schnorr::combine(&key, &request, &committee, slot, &parts, &c).unwrap();
            if seen.len() == 8 {
                break;
            }
        }
        assert_eq!(seen.len(), 8);
    }
}

fn blame<S: SchnorrSuite>(n: u16, t: usize) {
    let mut rng = TestRng::new();
    let committee = Committee::<S>::generate(n, t, &mut rng).unwrap();
    let a = actors(and_gate(2), &committee, &mut rng);
    let set = a.gate.leaves().unwrap();
    let key = SigningKey::new(
        committee.public,
        &a,
        S::scalar_from_u64(79),
        vec![],
        set.clone(),
    )
    .unwrap();
    let mut slots = CommitteeSlots::<S>::generate(n, t as u16, &[7], 9, &mut rng).unwrap();
    let slot = slots.slots.get_mut(&7).unwrap();
    let (request, c) = prepared(&key, &a, &set, 7, slot, &mut rng);
    let parts = partials(&committee, 7, slot, &request, &key);
    schnorr::combine(&key, &request, &committee, slot, &parts, &c).unwrap();
    assert_eq!(slot.cached_nodes(), 0);
    let mut bad = parts.clone();
    bad[0].value = bad[0].value + S::scalar_one();
    let recovered = schnorr::combine(&key, &request, &committee, slot, &bad, &c).unwrap();
    assert_eq!(recovered.rejected_partials, vec![1]);
    assert_eq!(slot.cached_nodes(), n as usize);
    assert_eq!(
        schnorr::combine(&key, &request, &committee, slot, &bad[..t], &c).unwrap_err(),
        CombineFailure::BadPartials(vec![1])
    );
    let mut twice = c.clone();
    twice.insert(
        set[1].clone(),
        c[&set[1]] + request.transcript(&key).unwrap().tweak_term,
    );
    assert_eq!(
        schnorr::combine(&key, &request, &committee, slot, &parts, &twice).unwrap_err(),
        CombineFailure::BadContributions(vec![set[1].clone()])
    );
    let mut bad_init = c.clone();
    bad_init.insert(set[0].clone(), c[&set[0]] + S::scalar_one());
    assert_eq!(
        schnorr::combine(&key, &request, &committee, slot, &parts, &bad_init).unwrap_err(),
        CombineFailure::BadContributions(vec![set[0].clone()])
    );
    let mut missing = request.clone();
    missing.signers.pop();
    assert!(missing.transcript(&key).is_err());
    let mut duplicate = request.clone();
    duplicate.signers.push(set[0].clone());
    assert!(duplicate.transcript(&key).is_err());
    let mut denied = key.clone();
    denied.initiators = vec![set[1].clone()];
    assert!(request.transcript(&denied).is_err());
}
#[test]
fn schnorr_optimistic_blame_and_recovery() {
    blame::<Secp>(9, 7);
    blame::<Edwards>(9, 7);
    blame::<Secp>(17, 12);
    blame::<Edwards>(17, 12);
}

// Diagnostic parts only; fixtures and nonce consumption are outside measurements.
// Run explicitly under an exclusive timing slot for comparable performance data.
#[test]
#[ignore = "diagnostic arithmetic breakdown; not a benchmark assertion"]
fn arithmetic_breakdown() {
    fn measure<S: SchnorrSuite>(n: u16, threshold: usize) {
        use std::{hint::black_box, time::Instant};
        let mut rng = TestRng::new();
        let committee = Committee::<S>::generate(n, threshold, &mut rng).unwrap();
        let a = actors(and_gate(3), &committee, &mut rng);
        let set = a.gate.leaves().unwrap();
        let key = SigningKey::new(
            committee.public,
            &a,
            S::scalar_from_u64(79),
            vec![],
            set.clone(),
        )
        .unwrap();
        let mut slots =
            CommitteeSlots::<S>::generate(n, threshold as u16, &[7], 9, &mut rng).unwrap();
        let slot = slots.slots.get_mut(&7).unwrap();
        let (request, c) = prepared(&key, &a, &set, 7, slot, &mut rng);
        let parts = partials(&committee, 7, slot, &request, &key);
        let tr = request.transcript(&key).unwrap();
        let combined = schnorr::combine(&key, &request, &committee, slot, &parts, &c).unwrap();
        let q = key.output().unwrap();
        const REPEATS: u32 = 20;
        let time = |label: &str, work: &mut dyn FnMut()| {
            let start = Instant::now();
            for _ in 0..REPEATS {
                work();
            }
            eprintln!(
                "{}/{n} {label}: {:?}/call",
                S::NAME,
                start.elapsed() / REPEATS
            );
        };
        time("point_validation", &mut || {
            for p in [key.committee, key.x, request.r0, request.d, request.e] {
                S::validate_point(black_box(p)).unwrap();
            }
            for p in key.leaves.values() {
                S::validate_point(black_box(*p)).unwrap();
            }
            for pair in request.pairs.values() {
                S::validate_point(black_box(pair.d)).unwrap();
                S::validate_point(black_box(pair.e)).unwrap();
            }
        });
        time("output_key", &mut || {
            black_box(key.output().unwrap());
        });
        time("transcript", &mut || {
            black_box(request.transcript(&key).unwrap());
        });
        time("interpolation", &mut || {
            let ids: Vec<_> = parts[..threshold].iter().map(|p| p.node).collect();
            let weights = line_dealing::split::group::lagrange::<S>(&ids).unwrap();
            let sf = parts[..threshold]
                .iter()
                .zip(weights)
                .fold(S::scalar_zero(), |acc, (p, w)| acc + p.value * w);
            let sum = c.values().fold(sf, |acc, value| acc + *value);
            black_box(S::signature(tr.nonce, sum).unwrap());
        });
        time("final_verify", &mut || {
            S::verify(q, &request.message, &combined.signature).unwrap();
        });
        time("full_combine", &mut || {
            black_box(schnorr::combine(&key, &request, &committee, slot, &parts, &c).unwrap());
        });
        assert_eq!(slot.cached_nodes(), 0);
    }
    measure::<Secp>(9, 7);
    measure::<Secp>(17, 12);
    measure::<Edwards>(9, 7);
    measure::<Edwards>(17, 12);
}

fn shared_slots<S: SchnorrSuite>() {
    let mut rng = TestRng::new();
    let committee = Committee::<S>::generate(9, 7, &mut rng).unwrap();
    let a = actors(and_gate(2), &committee, &mut rng);
    let set = a.gate.leaves().unwrap();
    let key = SigningKey::new(
        committee.public,
        &a,
        S::scalar_from_u64(79),
        vec![],
        set.clone(),
    )
    .unwrap();
    let mut slots = CommitteeSlots::<S>::generate(9, 7, &[10, 11, 20, 21], 9, &mut rng).unwrap();
    let mut pool = ActorPool::new(
        set[1].clone(),
        [4; 32],
        a.shares[&set[1]],
        key.tweak,
        30,
        &mut rng,
    )
    .unwrap();
    let mut requests = Vec::new();
    let mut contributions = Vec::new();
    let mut unique = BTreeSet::new();
    for (index, half) in halves(8, 2).unwrap().into_iter().enumerate() {
        let slot_id = half.generation as u64 * 10 + half.input as u64;
        let slot = &slots.slots[&slot_id];
        let message = vec![half.variant as u8; 32];
        let init = InitiatorNonce::new(
            set[0].clone(),
            a.shares[&set[0]],
            &key,
            slot_id,
            &message,
            &mut rng,
        )
        .unwrap();
        let r = Request {
            epoch: 9,
            slot: slot_id,
            half,
            initiator: set[0].clone(),
            signers: set.clone(),
            r0: init.point(),
            pairs: BTreeMap::from([(set[1].clone(), pool.commitment(index as u32).unwrap())]),
            d: slot.d,
            e: slot.e,
            message,
            salt_v: [half.variant as u8; 32],
            fee_rate: half.variant as u64,
            not_before: 0,
            exp_c: 100,
        };
        assert!(unique.insert(r.transcript(&key).unwrap().ticket.nonce));
        contributions.push(BTreeMap::from([(
            set[0].clone(),
            init.contribute(&key, &r, 0).unwrap(),
        )]));
        requests.push(r);
    }
    schnorr::validate_schedule(&key, &requests, 8, 2).unwrap();
    assert!(schnorr::validate_schedule(&key, &requests[..29], 8, 2).is_err());
    let mut bad_schedule = requests.clone();
    bad_schedule[1].slot = bad_schedule[0].slot;
    assert!(schnorr::validate_halves(&key, &bad_schedule).is_err());
    let mut bad_points = requests.clone();
    bad_points[2].d = bad_points[2].d + S::generator_mul(S::scalar_one());
    assert!(schnorr::validate_halves(&key, &bad_points).is_err());
    let mut mixed_epoch = requests.clone();
    mixed_epoch[1].epoch += 1;
    assert!(schnorr::validate_halves(&key, &mixed_epoch).is_err());
    let mut duplicate = requests.clone();
    duplicate[1].pairs = duplicate[0].pairs.clone();
    assert!(pool.contribute_batch(&key, &duplicate, 0).is_err());
    assert_eq!(pool.unused(), 30);
    assert!(pool.contribute_batch(&key, &requests, 101).is_err());
    assert_eq!(pool.unused(), 30);
    let actor = pool.contribute_batch(&key, &requests, 100).unwrap();
    assert_eq!(pool.unused(), 0);
    for (c, s) in contributions.iter_mut().zip(actor) {
        c.insert(set[1].clone(), s);
    }
    let mut nodes: Vec<_> = (1..=9)
        .map(|i| Node::<S>::new(i, 9, committee.shares[i as usize - 1]).unwrap())
        .collect();
    for node in &mut nodes {
        for (id, slot) in &slots.slots {
            node.install(*id, slot).unwrap();
        }
    }
    let mut completed = 0;
    for (index, r) in requests.iter().enumerate() {
        if !((r.half.generation == 1 && r.half.variant == 3)
            || (r.half.generation == 2 && r.half.variant == 7))
        {
            continue;
        }
        let ticket = r.transcript(&key).unwrap().ticket;
        let parts: Vec<_> = nodes
            .iter_mut()
            .map(|node| node.release(&ticket).unwrap())
            .collect();
        schnorr::combine(
            &key,
            r,
            &committee,
            slots.slots.get_mut(&r.slot).unwrap(),
            &parts,
            &contributions[index],
        )
        .unwrap();
        completed += 1;
    }
    assert_eq!(completed, 4);
    for r in requests {
        let ticket = r.transcript(&key).unwrap().ticket;
        for node in &mut nodes {
            assert!(node.release(&ticket).is_err());
        }
    }
}
#[test]
fn bip340_thirty_halves_four_slots() {
    shared_slots::<Secp>();
}
#[test]
fn ed25519_thirty_halves_four_slots() {
    shared_slots::<Edwards>();
}

#[test]
fn insufficient_coalition_cannot_reconstruct_or_complete() {
    let mut rng = TestRng::new();
    let committee = Committee::<Secp>::generate(9, 7, &mut rng).unwrap();
    let a = actors(group(1, &[], 2, 3), &committee, &mut rng);
    let set = a.gate.leaves().unwrap();
    assert!(!a.gate.satisfies(&set[..1]));
    assert!(a.reconstruct(&set[..1]).is_err());
    let weight = a.gate.weights::<Secp>(&set[..2]).unwrap()[&set[0]];
    assert_ne!(Secp::generator_mul(weight * a.shares[&set[0]]), a.public);
    let key = SigningKey::new(
        committee.public,
        &a,
        Secp::scalar_from_u64(79),
        vec![],
        set.clone(),
    )
    .unwrap();
    let mut slots = CommitteeSlots::<Secp>::generate(9, 7, &[7], 9, &mut rng).unwrap();
    let slot = slots.slots.get_mut(&7).unwrap();
    let (request, mut contributions) = prepared(&key, &a, &set[..2], 7, slot, &mut rng);
    let parts = partials(&committee, 7, slot, &request, &key);
    contributions.remove(&set[1]);
    assert!(schnorr::combine(&key, &request, &committee, slot, &parts, &contributions).is_err());
}

#[test]
fn schnorr_typed_edwards_torsion_is_rejected_before_consumption() {
    let mut rng = TestRng::new();
    let committee = Committee::<Edwards>::generate(9, 7, &mut rng).unwrap();
    let a = actors(and_gate(2), &committee, &mut rng);
    let set = a.gate.leaves().unwrap();
    let key = SigningKey::new(
        committee.public,
        &a,
        Edwards::scalar_from_u64(79),
        vec![],
        set.clone(),
    )
    .unwrap();
    let slots = CommitteeSlots::<Edwards>::generate(9, 7, &[7], 9, &mut rng).unwrap();
    let slot = &slots.slots[&7];
    let (request, _) = prepared(&key, &a, &set, 7, slot, &mut rng);
    let torsion = curve25519_dalek::constants::EIGHT_TORSION[1];
    let mut bad = request.clone();
    bad.r0 += torsion;
    assert!(bad.transcript(&key).is_err());
    assert!(schnorr::validate_halves(&key, &[bad]).is_err());
    let mut bad = request.clone();
    bad.pairs.get_mut(&set[1]).unwrap().d += torsion;
    assert!(bad.transcript(&key).is_err());
    assert!(schnorr::validate_halves(&key, &[bad]).is_err());
    let mut bad_key = key.clone();
    *bad_key.leaves.get_mut(&set[1]).unwrap() += torsion;
    assert!(request.transcript(&bad_key).is_err());
    assert!(schnorr::validate_halves(&bad_key, std::slice::from_ref(&request)).is_err());
    let mut node = Node::<Edwards>::new(1, 9, committee.shares[0]).unwrap();
    node.install(7, slot).unwrap();
    let ticket = request.transcript(&key).unwrap().ticket;
    let mut bad = ticket.clone();
    bad.actor_nonce += torsion;
    assert!(node.release(&bad).is_err());
    assert!(node.release(&ticket).is_ok());
}
