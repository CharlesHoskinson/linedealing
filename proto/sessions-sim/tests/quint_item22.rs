//! Item 22: counterexamples of the Quint model schedules in
//! veritee wt-sessions specs/quint/sessions_test.qnt, built on this prototype.
//! Each test is one model schedule. n = 4, f = 1 unless the test says otherwise,
//! with B = 2. Seat 0 is the owner; Schnorr is the sequential pool "p" and ECDSA
//! is the account pool "a". `Sim::new` already syncs every seat, opens both pools
//! and posts cp1 (seq 1, h 0, pending_min 1), which is the model's first postCp.
use sessions_sim::{board::pending_root, ledger::Refusal, oracle::Event, *};
use std::collections::BTreeSet;

const P: Purpose = Purpose::Schnorr;
const A: Purpose = Purpose::Ecdsa;

fn params(n: usize, f: usize) -> Params {
    let mut p = Params::new(n, f);
    p.b = 2; // model constant B = 2
    p
}

fn sim(n: usize, f: usize) -> Sim {
    let s = Sim::new(params(n, f), 2201);
    let cp = s.ledger.cp.as_ref().unwrap();
    assert_eq!((cp.seq, cp.h, cp.pending_min, cp.restart_seq), (1, 0, 1, 0));
    s
}

fn d1() -> Digest {
    hash(b"d1")
}
fn d2() -> Digest {
    hash(b"d2")
}

fn g2g3(s: &Sim) -> bool {
    s.oracle.violations.iter().any(|v| v.contains("G2/G3"))
}

fn set(seats: &[usize]) -> Option<BTreeSet<usize>> {
    Some(seats.iter().copied().collect())
}

/// Shared prefix of schedules 1 and 2: open p (done by `Sim::new`), put slot 1,
/// checkpoint v1 with slot 1 free, snapshot every disk, bind d1, release d1,
/// roll back every disk.
fn seq_prefix(s: &mut Sim) {
    s.slot_put(0, P, 1, vec![1]).unwrap();
    assert_eq!(s.checkpoint(0, P), Ok(1));
    let snap = s.snapshot();
    assert_eq!(s.slot_bind(0, P, 1, d1()), Ok(2));
    assert!(s.release(0, P, 1, d1()));
    s.inject(Fault::CoordinatedRollback(snap));
}

/// g3SeqRestartBurnTest. Whole restart: every seat syncs against cp1, so seat 0
/// classifies whole_restart and SS-068 burns [pending_min, h + B] = [1, 2].
#[test]
fn g3_restart_burn() {
    let mut s = sim(4, 1);
    seq_prefix(&mut s);
    for j in [1, 2, 3, 0] {
        s.sync(j).unwrap();
    }
    assert_eq!(s.nodes[0].ram.whole_restart, Some(true));
    assert_eq!(s.nodes[0].ram.cp_boot.as_ref().unwrap().seq, 1);
    // Restore of v1 (slot 1 free), then the SS-068 burn.
    assert_eq!(s.open(0, P), Ok(vec![1, 2]));
    assert!(s.trace.iter().any(|e| matches!(
        e,
        Event::Opened {
            seat: 0,
            purpose: Purpose::Schnorr,
            source: 1,
            ..
        }
    )));
    assert_eq!(s.slot_put(0, P, 1, vec![1]), Err(Error::SlotBurned));
    assert_eq!(s.slot_bind(0, P, 1, d2()), Err(Error::SlotBurned));
    assert!(!s.release(0, P, 1, d2()));
    assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 1);
    assert!(s.oracle.violations.is_empty(), "{:?}", s.oracle.violations);
    // The rollback is outside the bound, so the G1 restart loss is a Limits event.
    assert_eq!(s.oracle.classify(s.params.c(), s.params.f), "OUT-OF-BOUND");
}

/// g3LateBootStaleTest and g3NoJumpRefusedTest. Seats 1..3 sync and post
/// RestoreDone; the contract refuses cp2 without the SS-104 jump and accepts
/// h = 2, pending_min = 3. Seat 0 then sees w + 1 continuous seats, does not
/// classify a whole restart, restores v1 with slot 1 free and gets slot_stale.
fn late_boot_seq(s: &mut Sim) {
    seq_prefix(s);
    for j in [1, 2, 3] {
        s.sync(j).unwrap();
    }
    // g3NoJumpRefusedTest: cp2 with h = 0, pending_min = 1 is refused (SS-104).
    let old = s.ledger.cp.clone().unwrap();
    let (batches, restores) = s.board.batches(&s.ledger).unwrap();
    let mut next = old.clone();
    next.seq = old.seq + 1;
    next.restart_seq = next.seq; // seats 1..3 posted whole_restart statements
    next.boot_counters = s.ledger.latest_done(&restores);
    assert_eq!(next.boot_counters, vec![1, 2, 2, 2]);
    next.batch_root = batches;
    next.restores = restores;
    next.h = 0;
    next.pending_min = 1;
    next.pending_root = pending_root(&BTreeSet::new());
    next.pending_count = 0;
    assert_eq!(s.ledger.validate(&next, &s.params), Err(Refusal::Restart));
    // The driver's cp2 takes the jump.
    s.post_checkpoint().unwrap();
    let cp2 = s.ledger.cp.clone().unwrap();
    assert_eq!((cp2.seq, cp2.h, cp2.pending_min), (2, 2, 3));
    s.sync(0).unwrap();
    assert_eq!(s.ledger.continuous(&cp2), s.params.w + 1);
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    assert_eq!(s.open(0, P), Ok(vec![]));
    assert_eq!(
        s.session(0, P).work.slots.get(&1),
        Some(&Slot::Free(vec![1]))
    );
}

#[test]
fn g3_late_boot() {
    let mut s = sim(4, 1);
    late_boot_seq(&mut s);
    assert_eq!(s.slot_bind(0, P, 1, d2()), Err(Error::SlotStale));
    assert!(!s.release(0, P, 1, d2()));
    assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 1);
    assert!(s.oracle.violations.is_empty(), "{:?}", s.oracle.violations);
}

/// mNoStaleTest: with the SS-064 lower bound removed the late seat releases d2.
/// There is no knob for the SS-104 jump (Ledger::validate has no mutation branch).
#[test]
fn g3_late_boot_mutant_no_slot_stale() {
    let mut s = sim(4, 1);
    s.oracle.observe_only = true;
    late_boot_seq(&mut s);
    s.knobs.no_slot_stale = true;
    assert_eq!(s.slot_bind(0, P, 1, d2()), Ok(3));
    assert!(s.release(0, P, 1, d2()));
    assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 2);
    assert!(g2g3(&s));
}

/// g3AcctLateBurnTest. Account pool: the put entry is covered by cp2, v1 holds
/// the free slot, seats 1..3 sync, cp3 is the restart checkpoint, seat 0 syncs
/// late without a whole restart and SS-123 burns slot 1 at its open.
#[test]
fn g3_acct_late_burn() {
    let mut s = sim(4, 1);
    s.slot_put(0, A, 1, vec![1; 64]).unwrap();
    s.post_checkpoint().unwrap(); // cp2 covers the put entry
    assert_eq!(s.checkpoint(0, A), Ok(1));
    let snap = s.snapshot();
    s.slot_bind(0, A, 1, d1()).unwrap();
    assert!(s.release(0, A, 1, d1()));
    s.inject(Fault::CoordinatedRollback(snap));
    for j in [1, 2, 3] {
        s.sync(j).unwrap();
    }
    s.post_checkpoint().unwrap(); // cp3
    let cp3 = s.ledger.cp.clone().unwrap();
    assert_eq!((cp3.seq, cp3.restart_seq), (3, 3));
    s.sync(0).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    assert_eq!(s.open(0, A), Ok(vec![1]));
    assert_eq!(s.session(0, A).work.restart_mark, cp3.restart_seq);
    assert_eq!(s.slot_bind(0, A, 1, d2()), Err(Error::SlotBurned));
    assert!(!s.release(0, A, 1, d2()));
    assert_eq!(s.oracle.share_releases[&((0, A, 1), vec![1; 64])].len(), 1);
    assert!(s.oracle.violations.is_empty(), "{:?}", s.oracle.violations);
}

/// g3RePutTest. Snapshot before the slot exists (no record on any disk), put
/// share s at slot 1, cp2 covers the put entry, bind d1, release, roll back every
/// disk, all seats sync, open a, restart checkpoint, re-put s at slot 2.
#[test]
fn g3_reput() {
    let mut s = sim(4, 1);
    let snap = s.snapshot();
    assert!(snap.0.iter().all(|(_, disk)| disk.local.is_empty()));
    s.slot_put(0, A, 1, vec![7; 64]).unwrap();
    s.post_checkpoint().unwrap(); // cp2
    s.slot_bind(0, A, 1, d1()).unwrap();
    assert!(s.release(0, A, 1, d1()));
    s.inject(Fault::CoordinatedRollback(snap));
    for j in [1, 2, 3, 0] {
        s.sync(j).unwrap();
    }
    assert_eq!(s.nodes[0].ram.whole_restart, Some(true));
    assert_eq!(s.open(0, A), Ok(vec![]));
    s.post_checkpoint().unwrap(); // restart checkpoint
    assert_eq!(s.ledger.cp.as_ref().unwrap().restart_seq, 3);
    assert_eq!(s.slot_put(0, A, 2, vec![7; 64]), Err(Error::SlotUsed));
    assert_eq!(s.slot_put(0, A, 1, vec![7; 64]), Err(Error::SlotUsed));
    assert!(!s.release(0, A, 2, d2()));
    assert_eq!(s.oracle.share_releases[&((0, A, 1), vec![7; 64])].len(), 1);
    assert!(s.oracle.violations.is_empty(), "{:?}", s.oracle.violations);
}

/// Shared prefix of schedules 5 and 6: put slot 1, checkpoint v1 to every seat,
/// snapshot, bind d1 with slot acks and the bound seal sent only to `bind_acks`,
/// release d1.
fn owner_prefix(s: &mut Sim, bind_acks: &[usize]) -> Snapshot {
    s.slot_put(0, P, 1, vec![1]).unwrap();
    assert_eq!(s.checkpoint(0, P), Ok(1));
    let snap = s.snapshot();
    s.witness_peers = set(bind_acks);
    assert_eq!(s.slot_bind(0, P, 1, d1()), Ok(2));
    assert!(s.release(0, P, 1, d1()));
    s.witness_peers = None;
    snap
}

/// q003N7DoubleReleaseTest with the prototype's own Byzantine peer
/// (Fault::ByzantinePeer from the start). The v1 restore needs t = 5 partials:
/// 3 and 4 refuse by the SS-016 fence (they hold v2), 5 and 6 refuse because
/// the prototype's Byzantine peer never serves a partial. Only 0, 1, 2 remain.
#[test]
fn q003_n7() {
    let mut s = sim(7, 2);
    s.oracle.observe_only = true;
    assert_eq!((s.params.w, s.params.t, s.params.c()), (4, 5, 2));
    s.inject(Fault::ByzantinePeer(5));
    s.inject(Fault::ByzantinePeer(6));
    let snap = owner_prefix(&mut s, &[3, 4, 5, 6]);
    s.inject(Fault::RollbackSeat(0, snap));
    s.sync_peers = set(&[1, 2, 5, 6]);
    s.witness_peers = set(&[1, 2, 5, 6]);
    s.sync(0).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    // The prototype's Byzantine answer puts a conflicting entry in seat 0's log.
    assert_ne!(s.nodes[0].tier0.slots.get(&(0, P, 1)), None);
    assert!(s.oracle.byzantine_fired[0] > 0);
    assert_eq!(s.open(0, P), Err(Error::GroupUnavailable));
    assert!(s.oracle.byzantine_fired[3] > 0); // refused Byzantine partials
    assert_eq!(s.slot_bind(0, P, 1, d2()), Err(Error::NotOpen));
    assert!(!s.release(0, P, 1, d2()));
    assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 1);
    assert!(!g2g3(&s));
    // CONCURRENT: Byzantine 5, 6 and the owner rollback count 3 > c = 2.
    assert_eq!(s.oracle.peak_lost, 3);
    assert_eq!(s.oracle.max_down, 3);
    assert_eq!(s.oracle.classify(s.params.c(), s.params.f), "OUT-OF-BOUND");
}

/// Model adversary for q003: the model's BYZ seats ack every witness, serve every
/// partial and (with byzSlot = 0) report nothing at sync. The test emulates that
/// with seats 5 and 6 left unflagged: they ack the d1 bind, then answer from
/// their pre-bind disks. The loss is counted by hand.
#[test]
fn q003_n7_model_adversary() {
    let mut s = sim(7, 2);
    s.oracle.observe_only = true;
    for j in [5, 6] {
        s.oracle.lost_permanently(j);
    }
    let snap = owner_prefix(&mut s, &[3, 4, 5, 6]);
    for j in [5, 6] {
        s.nodes[j].tier0 = snap.0[j].0.clone();
        s.nodes[j].disk = snap.0[j].1.clone();
    }
    s.inject(Fault::RollbackSeat(0, snap));
    s.sync_peers = set(&[1, 2, 5, 6]);
    s.witness_peers = set(&[1, 2, 5, 6]);
    s.sync(0).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    assert_eq!(s.open(0, P), Ok(vec![]));
    assert_eq!(
        s.session(0, P).work.slots.get(&1),
        Some(&Slot::Free(vec![1]))
    );
    s.slot_bind(0, P, 1, d2()).unwrap();
    assert!(s.release(0, P, 1, d2()));
    assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 2);
    // The prototype scores the second release as a violation, not a Limits event,
    // although the run is out of bound (3 > c = 2), as in the model (peak > BUDGET).
    assert!(g2g3(&s));
    assert!(!s.oracle.expected.iter().any(|e| e.contains("G2/G3")));
    assert_eq!(s.oracle.peak_lost, 3);
    assert_eq!(s.oracle.classify(s.params.c(), s.params.f), "OUT-OF-BOUND");
}

/// q015RogueDoubleReleaseTest with the prototype's own Byzantine peers. Seats 7
/// and 8 are Byzantine from the start. Seat 1 (rogue boot) is flagged Byzantine
/// after the d1 release: flagging it earlier leaves 6 honest shares against
/// t = 7 and the v1 checkpoint already fails.
#[test]
fn q015_rogue() {
    let mut s = sim(9, 2);
    s.oracle.observe_only = true;
    assert_eq!((s.params.w, s.params.t, s.params.c()), (6, 7, 4));
    s.inject(Fault::ByzantinePeer(7));
    s.inject(Fault::ByzantinePeer(8));
    let snap = owner_prefix(&mut s, &[1, 2, 3, 4, 7, 8]);
    s.inject(Fault::ByzantinePeer(1));
    s.inject(Fault::RollbackSeat(2, snap.clone()));
    s.inject(Fault::RollbackSeat(0, snap));
    s.sync_peers = set(&[1, 2, 5, 6, 7, 8]);
    s.witness_peers = set(&[1, 2, 5, 6, 7, 8]);
    s.sync(0).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    // Partials: 0, 2, 5, 6 serve v1; 3, 4 refuse (SS-016); 1, 7, 8 refuse (Byzantine).
    assert_eq!(s.open(0, P), Err(Error::GroupUnavailable));
    assert_eq!(s.slot_bind(0, P, 1, d2()), Err(Error::NotOpen));
    assert!(!s.release(0, P, 1, d2()));
    assert!(!g2g3(&s));
    // The rogue seat is counted: {0, 1, 2, 7, 8} = 5 > c = 4.
    assert_eq!(s.oracle.peak_lost, 5);
    assert_eq!(s.oracle.classify(s.params.c(), s.params.f), "OUT-OF-BOUND");
}

/// Model adversary for q015: seats 1, 7 and 8 ack the d1 bind, then answer from
/// their pre-bind disks and serve partials. Nothing in the prototype marks seat 1:
/// it holds a valid ticket and `valid()` checks only the ticket. With the rogue
/// seat left out of the count (the model's reading) the run is in bound and the
/// oracle records an in-bound G2/G3 violation. Counting it makes the run out of bound.
#[test]
fn q015_rogue_model_adversary() {
    let mut s = sim(9, 2);
    s.oracle.observe_only = true;
    for j in [7, 8] {
        s.oracle.lost_permanently(j);
    }
    let snap = owner_prefix(&mut s, &[1, 2, 3, 4, 7, 8]);
    for j in [1, 7, 8] {
        s.nodes[j].tier0 = snap.0[j].0.clone();
        s.nodes[j].disk = snap.0[j].1.clone();
    }
    s.inject(Fault::RollbackSeat(2, snap.clone()));
    s.inject(Fault::RollbackSeat(0, snap));
    s.sync_peers = set(&[1, 2, 5, 6, 7, 8]);
    s.witness_peers = set(&[1, 2, 5, 6, 7, 8]);
    s.sync(0).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    assert_eq!(s.open(0, P), Ok(vec![]));
    s.slot_bind(0, P, 1, d2()).unwrap();
    assert!(s.release(0, P, 1, d2()));
    assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 2);
    assert!(g2g3(&s));
    // Rogue not counted: {0, 2, 7, 8} = 4 = c, max_down 1 <= f.
    assert_eq!(s.oracle.peak_lost, 4);
    assert_eq!(s.oracle.max_down, 1);
    assert!(s.in_bound());
    assert_eq!(s.oracle.classify(s.params.c(), s.params.f), "IN-BOUND");
    // Rogue counted: 5 > c.
    s.oracle.lost_permanently(1);
    assert_eq!(s.oracle.classify(s.params.c(), s.params.f), "OUT-OF-BOUND");
}

/// S-01 (share rollback across install_prf_share of epoch 2) is not buildable:
/// the prototype is single-epoch. Every seal writes epoch 1, the share is one
/// abstract bool per seat, and there is no rekey or share-install operation.
#[test]
fn s01_share_rollback_not_buildable() {
    let mut s = sim(4, 1);
    s.slot_put(0, P, 1, vec![1]).unwrap();
    s.checkpoint(0, P).unwrap();
    s.run(8);
    for node in &s.nodes {
        let _: bool = node.tier0.share; // no per-epoch share material
        assert!(node
            .disk
            .local
            .values()
            .flatten()
            .chain(node.disk.replicas.values())
            .all(|r| r.epoch == 1));
        assert!(node.tier0.peers.values().all(|e| e.pe == 1));
    }
    assert!(Purpose::ALL.iter().all(|&p| s.session(0, p).epoch <= 1));
}
