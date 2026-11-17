// Counterexample of finding E1 (research/literature-2026-11/ENHANCEMENTS.md) on the prototype.
//
// DESIGN §4.2 item 3 built the commitment list CL from R_0, the pool pairs of the actors of
// S' = S \ {a_0} and the committee slot. The initiator's leaf id was not in it. In a 2-of-3
// group the weight of member 1 is 2 beside member 2 and 3/2 beside member 3. Two requests
// that differ only in the initiator (member 2 or member 3) therefore have one CL and one pm,
// so member 1 gets one binding factor, one R and one c under two weights.
//
// The tests run the real `Request::transcript`, `ActorPool` and the public contribution
// equation of §4.2, for BIP340 and Ed25519.
//
// History: on commit 1ece835 (before the fix) the two `counterexample` tests asserted the
// finding and passed: one binding factor, one ticket, and the leaf secret of member 1 from
// the answers of one pool and of a copy of it. The two `regression` tests failed there
// (`e1_before_fix.txt`). DECISIONS 72 puts the initiator's leaf id first in CL. The asserts
// of the `counterexample` tests are inverted and check the fixed rule.
//
// The last test replays the scripted traces of formal/quint/splitline_binding.qnt on the
// same code (traces in `binding/`): `dt_design__*Holds` step by step, and `dt_no_initiator__*Broken`, whose
// violation the fixed code does not follow.
//
// Run: cd impl && cargo test --release --test e1_initiator_leaf_counterexample
// (impl/tests/e1_initiator_leaf_counterexample.rs includes this file with #[path]).
use super::common::TestRng;
use line_dealing::split::{
    access::{Gate, LeafId},
    birth::{ActorShares, BirthContext, Committee},
    group::{Edwards, Secp},
    schnorr::{ActorPool, Half, Request, SchnorrSuite, SigningKey, Transcript},
    slots::CommitteeSlots,
};
use line_dealing::Error;
use serde_json::Value;
use std::collections::BTreeMap;

struct Scene<S: SchnorrSuite> {
    key: SigningKey<S>,
    actors: ActorShares<S>,
    members: Vec<LeafId>,
    slot: (S::Point, S::Point),
}
impl<S: SchnorrSuite> Scene<S> {
    /// A request of the adversary, which holds members 2 and 3: pair `pair` (from 1) of
    /// member 1, member `initiator` as the initiator, and its choice of R_0 and message.
    fn request(&self, pair: u32, initiator: usize, r0: u64, msg: u8) -> Request<S> {
        let pool = pool_of_member_1(&self.key, &self.actors);
        Request {
            epoch: 9,
            slot: 7,
            half: Half {
                variant: 1,
                generation: 1,
                input: 0,
            },
            initiator: self.members[initiator - 1].clone(),
            signers: vec![self.members[0].clone(), self.members[initiator - 1].clone()],
            r0: S::generator_mul(S::scalar_from_u64(4 + r0)),
            pairs: BTreeMap::from([(self.members[0].clone(), pool.commitment(pair - 1).unwrap())]),
            d: self.slot.0,
            e: self.slot.1,
            message: vec![41 + msg; 32],
            salt_v: [13; 32],
            fee_rate: 10,
            not_before: 0,
            exp_c: 100,
        }
    }
}

/// The pool of member 1. Two calls give the same pairs: the second pool is a copy of the
/// first from before any answer (a restored backup or a rolled-back disk).
fn pool_of_member_1<S: SchnorrSuite>(key: &SigningKey<S>, actors: &ActorShares<S>) -> ActorPool<S> {
    let id = actors.gate.leaves().unwrap()[0].clone();
    ActorPool::new(
        id.clone(),
        [1; 32],
        actors.shares[&id],
        key.tweak,
        2,
        &mut TestRng::new(),
    )
    .unwrap()
}

fn scene<S: SchnorrSuite>() -> Scene<S> {
    let mut rng = TestRng::new();
    let committee = Committee::<S>::generate(9, 7, &mut rng).unwrap();
    let slots = CommitteeSlots::<S>::generate(9, 7, &[7], 9, &mut rng).unwrap();
    let slot = &slots.slots[&7];
    let gate = Gate::Threshold {
        k: 2,
        children: (1..=3)
            .map(|i| Gate::Leaf(LeafId::new(1, vec![], i)))
            .collect(),
    };
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
    let members = actors.gate.leaves().unwrap();
    // Every member may initiate.
    let key = SigningKey::new(
        committee.public,
        &actors,
        S::scalar_from_u64(79),
        vec![],
        members.clone(),
    )
    .unwrap();
    Scene {
        slot: (slot.d, slot.e),
        key,
        actors,
        members,
    }
}

/// The public contribution equation of §4.2: s_a·G = σ·(D + ρ_a·E) + c̃·λ_a·X_a.
fn verifies<S: SchnorrSuite>(
    s: &Scene<S>,
    r: &Request<S>,
    tr: &Transcript<S>,
    value: S::Scalar,
) -> bool {
    let id = &s.members[0];
    let pair = &r.pairs[id];
    S::generator_mul(value)
        == S::mul(pair.d + S::mul(pair.e, tr.actor_bindings[id]), tr.sigma)
            + S::mul(s.key.leaves[id], tr.ticket.challenge * tr.weights[id])
}

fn weights_differ<S: SchnorrSuite>(s: &Scene<S>, ta: &Transcript<S>, tb: &Transcript<S>) {
    let id = &s.members[0];
    let two = S::scalar_from_u64(2);
    assert_eq!(ta.weights[id], two, "weight of member 1 beside member 2");
    assert_eq!(
        tb.weights[id] * two,
        S::scalar_from_u64(3),
        "weight of member 1 beside member 3"
    );
}

/// The schedule of the counterexample on the fixed code. Before the fix the three
/// `assert_ne!` lines were `assert_eq!`, and the last one recovered the leaf secret
/// (`e1_before_fix.txt`, commit 1ece835).
fn one_binding_two_weights<S: SchnorrSuite>() {
    let s = scene::<S>();
    let id = &s.members[0];
    // One pair, one R_0 and one message, with member 2 and with member 3 as the initiator.
    let (a, b) = (s.request(1, 2, 1, 1), s.request(1, 3, 1, 1));
    let ta = a.transcript(&s.key).unwrap();
    let tb = b.transcript(&s.key).unwrap();
    weights_differ(&s, &ta, &tb);
    // The two lists differ in the initiator's leaf id, and so does every value below them.
    assert_ne!(ta.actor_bindings[id], tb.actor_bindings[id]);
    assert_ne!(ta.ticket, tb.ticket);

    // One pool answers a pair once, as before.
    let mut pool = pool_of_member_1(&s.key, &s.actors);
    let sa = pool.contribute(&s.key, &a, 0).unwrap();
    assert_eq!(pool.contribute(&s.key, &b, 0), Err(Error::Nonce));

    // A copy of the pool from before the answer gives a second answer. Both answers
    // verify, each under its own weight and not under the other.
    let sb = pool_of_member_1(&s.key, &s.actors)
        .contribute(&s.key, &b, 0)
        .unwrap();
    assert!(verifies(&s, &a, &ta, sa) && verifies(&s, &b, &tb, sb));
    assert!(!verifies(&s, &a, &ta, sb) && !verifies(&s, &b, &tb, sa));

    // The two answers now stand on two nonces, d + ρ_a·e and d + ρ_a'·e. The difference
    // that gave the leaf secret before the fix does not give it.
    let x1 =
        (sa - sb) * S::invert(ta.ticket.challenge * (ta.weights[id] - tb.weights[id])).unwrap();
    assert_ne!(x1, s.actors.shares[id]);
}

/// The regression test of the fix (DECISIONS 72). It fails on the code before the fix.
fn initiator_leaf_separates_the_binding<S: SchnorrSuite>() {
    let s = scene::<S>();
    let id = &s.members[0];
    // One pair, one R_0 and one message, with member 2 and with member 3 as the initiator.
    let (a, b) = (s.request(1, 2, 1, 1), s.request(1, 3, 1, 1));
    let ta = a.transcript(&s.key).unwrap();
    let tb = b.transcript(&s.key).unwrap();
    weights_differ(&s, &ta, &tb);
    assert_ne!(
        ta.actor_bindings[id], tb.actor_bindings[id],
        "one binding factor for member 1 under two weights"
    );
    assert_ne!(ta.ticket, tb.ticket, "one ticket under two weights");
}

#[test]
fn e1_bip340_two_weights_two_bindings_counterexample() {
    one_binding_two_weights::<Secp>();
}
#[test]
fn e1_ed25519_two_weights_two_bindings_counterexample() {
    one_binding_two_weights::<Edwards>();
}
#[test]
fn e1_bip340_initiator_leaf_separates_the_binding_regression() {
    initiator_leaf_separates_the_binding::<Secp>();
}
#[test]
fn e1_ed25519_initiator_leaf_separates_the_binding_regression() {
    initiator_leaf_separates_the_binding::<Edwards>();
}

/// One request of the model: (pair, initiator, r0, msg).
type ModelRequest = (u32, usize, u64, u8);

fn int(v: &Value) -> u64 {
    v["#bigint"].as_str().unwrap().parse().unwrap()
}
fn model_request(v: &Value) -> ModelRequest {
    (
        int(&v["pair"]) as u32,
        int(&v["initiator"]) as usize,
        int(&v["r0"]),
        int(&v["msg"]) as u8,
    )
}
fn set(v: &Value) -> &[Value] {
    v["#set"].as_array().map_or(&[], Vec::as_slice)
}

/// Replays one scripted trace of `splitline_binding.qnt`. Every answer of the trace is given
/// by the real pool of member 1, a rollback of the model restores the pool from a copy,
/// each answer verifies under the weight that the model records, and the pool refuses the
/// step that the model refuses. Returns the posted
/// requests and whether the trace holds two answers on one pair with one model key and two
/// weights.
fn replay<S: SchnorrSuite>(s: &Scene<S>, name: &str) -> (Vec<ModelRequest>, bool) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/quint-regressions/splitline/binding")
        .join(name);
    let trace: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let id = &s.members[0];
    let mut pool = pool_of_member_1(&s.key, &s.actors);
    let mut answered = 0;
    let mut last = Value::Null;
    for state in trace["states"].as_array().unwrap() {
        let d = &state["binding_scenarios::splitline_binding::d"];
        if d.is_null() {
            // A step that the model refuses leaves an empty state: a second answer on a
            // used pair. The pool refuses every posted request on such a pair.
            for r in set(&last["posted"]).iter().map(model_request) {
                if set(&last["used"]).iter().any(|p| int(p) == r.0 as u64) {
                    let request = s.request(r.0, r.1, r.2, r.3);
                    assert_eq!(pool.contribute(&s.key, &request, 0), Err(Error::Nonce));
                }
            }
            continue;
        }
        match d["lastAction"].as_str().unwrap() {
            "rollback" => pool = pool_of_member_1(&s.key, &s.actors),
            "answer" => {
                // the request whose answer this step adds
                let answers = set(&d["answers"]);
                assert_eq!(answers.len(), answered + 1, "{name}: one answer per step");
                let new = answers
                    .iter()
                    .find(|a| !set(&last["answers"]).contains(a))
                    .unwrap();
                let (pair, initiator, r0, msg) = set(&d["posted"])
                    .iter()
                    .map(model_request)
                    .find(|r| {
                        r.0 as u64 == int(&new["pair"])
                            && r.2 == int(&new["key"]["r0"])
                            && r.3 as u64 == int(&new["key"]["pm"])
                            && (if r.1 == 2 { 4 } else { 3 }) == int(&new["weight2"])
                    })
                    .unwrap();
                let request = s.request(pair, initiator, r0, msg);
                let tr = request.transcript(&s.key).unwrap();
                assert_eq!(
                    tr.weights[id] * S::scalar_from_u64(2),
                    S::scalar_from_u64(int(&new["weight2"])),
                    "{name}: the weight of the model"
                );
                let value = pool.contribute(&s.key, &request, 0).unwrap();
                assert!(
                    verifies(s, &request, &tr, value),
                    "{name}: the answer verifies"
                );
                answered += 1;
            }
            _ => {}
        }
        last = d.clone();
    }
    let answers = set(&last["answers"]);
    let one_key_two_weights = answers.iter().any(|a| {
        answers
            .iter()
            .any(|b| a["pair"] == b["pair"] && a["key"] == b["key"] && a["weight2"] != b["weight2"])
    });
    (
        set(&last["posted"]).iter().map(model_request).collect(),
        one_key_two_weights,
    )
}

/// The binding factors of the real code are equal exactly when the requests are equal.
fn real_bindings_separate<S: SchnorrSuite>(s: &Scene<S>, posted: &[ModelRequest]) {
    let rho = |r: &ModelRequest| {
        s.request(r.0, r.1, r.2, r.3)
            .transcript(&s.key)
            .unwrap()
            .actor_bindings[&s.members[0]]
    };
    for a in posted {
        for b in posted {
            assert_eq!(rho(a) == rho(b), a == b, "{a:?} and {b:?}");
        }
    }
}

fn quint_traces_replay<S: SchnorrSuite>() {
    let s = scene::<S>();
    // Design traces: the prototype follows every step, and no trace holds one key under
    // two weights.
    for name in [
        "dt_design__twoInitiatorsHolds.itf.json",
        "dt_design__secondAnswerRefusedHolds.itf.json",
        "dt_design__restoredPoolHolds.itf.json",
    ] {
        let (posted, one_key_two_weights) = replay(&s, name);
        assert_eq!(posted.len(), 2, "{name}");
        assert!(!one_key_two_weights, "{name}");
        real_bindings_separate(&s, &posted);
    }
    // Mutant traces (CL without the initiator's leaf id): the model holds two answers on
    // one key under two weights. The prototype gives the same two requests two binding
    // factors, so it does not follow the mutant.
    let (posted, _) = replay(&s, "dt_no_initiator__twoInitiatorsBroken.itf.json");
    real_bindings_separate(&s, &posted);
    let (posted, one_key_two_weights) = replay(&s, "dt_no_initiator__restoredPoolBroken.itf.json");
    assert!(one_key_two_weights);
    real_bindings_separate(&s, &posted);
}

#[test]
fn e1_bip340_quint_binding_traces_replay() {
    quint_traces_replay::<Secp>();
}
#[test]
fn e1_ed25519_quint_binding_traces_replay() {
    quint_traces_replay::<Edwards>();
}
