use k256::Scalar;
use line_dealing::split::access::{Gate, LeafId};
use line_dealing::{
    experiment::SeededRng,
    split::{
        birth::{ActorShares, BirthContext, Committee},
        ecdsa::Slot,
        envelope::{self, Public},
        group::{Secp, Suite},
        request::{ecdsa::EcdsaRequest, SchnorrSetup},
        schnorr::{self, ActorPool, SchnorrSuite},
    },
};

pub fn actors(other_actors: u16) -> (Gate, Vec<LeafId>) {
    let leaves: Vec<_> = (1..=other_actors + 1)
        .map(|slot| LeafId::new(slot, vec![], 1))
        .collect();
    let gate = if leaves.len() == 1 {
        Gate::Leaf(leaves[0].clone())
    } else {
        Gate::And(leaves.iter().cloned().map(Gate::Leaf).collect())
    };
    (gate, leaves)
}

pub fn schnorr<S: SchnorrSuite>(n: u16, k: u8, l: u8, other_actors: u16) -> SchnorrSetup<S> {
    let (gate, set) = actors(other_actors);
    let mut setup = SchnorrSetup::new(
        n,
        usize::from(threshold(n)),
        k,
        l,
        gate,
        set,
        &mut SeededRng::new(73),
    )
    .unwrap();
    // These public fixture seeds let iter_batched prepare a fresh actor state
    // with the exact commitments already committed by the request.
    for position in 1..=other_actors as u8 {
        let pool = fresh_pool(&setup, position);
        let leaf = setup.set[usize::from(position)].clone();
        for index in 0..schnorr::halves(u16::from(k), u16::from(l)).unwrap().len() as u32 {
            setup
                .context
                .pairs
                .insert((leaf.clone(), index), pool.commitment(index).unwrap());
        }
        setup.pools.insert(leaf, pool);
    }
    setup
}

pub fn fresh_pool<S: SchnorrSuite>(setup: &SchnorrSetup<S>, position: u8) -> ActorPool<S> {
    let leaf = setup.set[usize::from(position)].clone();
    ActorPool::new(
        leaf.clone(),
        [position; 32],
        setup.actors.shares[&leaf],
        setup.key.tweak,
        schnorr::halves(u16::from(setup.k), u16::from(setup.l))
            .unwrap()
            .len() as u32,
        &mut SeededRng::new(1000 + u64::from(position)),
    )
    .unwrap()
}

/// Fault bound f = floor((n - 1) / 3) and threshold t = n - f: 9 -> 7, 17 -> 12,
/// 5 -> 4, 33 -> 23.
pub fn faults(n: u16) -> u16 {
    assert!(n >= 4, "unsupported committee size");
    (n - 1) / 3
}
pub fn threshold(n: u16) -> u16 {
    n - faults(n)
}

pub fn ecdsa(n: u16, other_actors: u16) -> (EcdsaRequest, Vec<Scalar>) {
    let mut rng = SeededRng::new(94);
    let committee = Committee::<Secp>::generate(n, usize::from(threshold(n)), &mut rng).unwrap();
    let (gate, set) = actors(other_actors);
    let shares = ActorShares::<Secp>::generate(
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
        .map(|id| Slot::ideal(id, &committee, &shares, tweak, &set, &mut rng).unwrap())
        .collect();
    let mut script = vec![0, 20];
    script.extend(
        line_dealing::wire::address_for(
            3,
            committee.public + shares.public + Secp::generator_mul(tweak),
        )
        .unwrap(),
    );
    let variants = line_dealing::split::request::ecdsa::fixture_variants(&script, 3, 2).unwrap();
    let secrets: Vec<_> = (1..=n).map(|i| Scalar::from(u64::from(i) + 100)).collect();
    let keys: Vec<_> = secrets.iter().map(|s| Secp::generator_mul(*s)).collect();
    let public = Public::new(1, envelope::keylist_hash(&keys).unwrap(), 100);
    (
        EcdsaRequest::build(
            &committee, &shares, &set, tweak, slots, variants, &keys, public, &mut rng,
        )
        .unwrap(),
        secrets,
    )
}
