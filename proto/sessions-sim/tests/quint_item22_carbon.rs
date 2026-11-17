//! Item 22, Carbon Quint QA findings C-01 and C-02 (veritee wt-sessions
//! specs/quint/qa-carbon/carbon_test.qnt, module c_n4g), built on this prototype.
//! n = 4, f = 1, w = 2, B = 2, slot_anchor off. Seat 0 is the owner of the
//! sequential pool "p" (Schnorr). `Sim::new` posts cp1 (seq 1, h 0, pending_min 1).
//!
//! Without the feature `d039` the contract is the one of spec.md before D-039
//! (SS-103, SS-104 over the boot counters only, SS-142) and each schedule
//! releases slot 1 for two digests. With `d039` the contract also refuses a
//! checkpoint that lowers `pending_min` (SS-146) and requires the SS-104 jump on
//! each checkpoint that advances `restart_seq` (SS-147); the same schedules end
//! with the forged checkpoint refused or with `slot_stale`.
use sessions_sim::{board::pending_root, ledger::Refusal, *};
use std::collections::BTreeSet;

const P: Purpose = Purpose::Schnorr;
const FIXED: bool = cfg!(feature = "d039");

fn sim() -> Sim {
    let mut p = Params::new(4, 1);
    p.b = 2;
    let s = Sim::new(p, 2201);
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

/// A checkpoint that the committee application writes by hand: the next seq,
/// the restart marker the contract demands (SS-121, SS-122), the boot counters
/// of the RestoreDone statements on the board (SS-117), and the given floor,
/// pending floor and pending set. Returns the contract's answer; on success the
/// board takes the pending set as landed.
fn forge(s: &mut Sim, h: u64, pending_min: u64, pending: &[u64]) -> Result<(), Refusal> {
    let old = s.ledger.cp.clone().unwrap();
    let (batches, restores) = s.board.batches(&s.ledger).unwrap();
    let mut next = old.clone();
    next.seq = old.seq + 1;
    next.restart_seq = if s.ledger.restart_pending(&old, &restores) {
        next.seq
    } else {
        old.restart_seq
    };
    next.boot_counters = s.ledger.latest_done(&restores);
    next.batch_root = batches;
    next.restores = restores;
    next.h = h;
    next.pending_min = pending_min;
    let set: BTreeSet<u64> = pending.iter().copied().collect();
    next.pending_root = pending_root(&set);
    next.pending_count = set.len() as u32;
    s.ledger.post(next.clone(), &s.params)?;
    let landed = s.ledger.cp.clone().unwrap();
    s.board.landed(&landed, set);
    Ok(())
}

/// seqPre of carbon_test.qnt: put slot 1, checkpoint v1 (slot 1 free), snapshot
/// every disk, bind d1, release d1. The caller rolls back.
fn prefix(s: &mut Sim) -> Snapshot {
    s.oracle.observe_only = true;
    s.slot_put(0, P, 1, vec![1]).unwrap();
    assert_eq!(s.checkpoint(0, P), Ok(1));
    let snap = s.snapshot();
    assert_eq!(s.slot_bind(0, P, 1, d1()), Ok(2));
    assert!(s.release(0, P, 1, d1()));
    snap
}

/// c01PendingFloorDropsLateBootTest. Seats 1..3 sync after the rollback and
/// classify the restart; cp2 takes the SS-104 jump (h 2, pending_min 3). cp3
/// keeps every boot counter of cp2, so SS-104 does not apply, and names slot 1
/// pending again with pending_min 1 <= h + 1 (SS-142 holds). Seat 0 boots late,
/// sees w + 1 continuous seats, burns nothing and binds slot 1 with a proof.
#[test]
fn c01_pending_floor_drops_late_boot() {
    let mut s = sim();
    let snap = prefix(&mut s);
    s.inject(Fault::CoordinatedRollback(snap));
    for j in [1, 2, 3] {
        s.sync(j).unwrap();
    }
    s.post_checkpoint().unwrap();
    let cp2 = s.ledger.cp.clone().unwrap();
    assert_eq!(
        (cp2.seq, cp2.h, cp2.pending_min, cp2.restart_seq),
        (2, 2, 3, 2)
    );
    let r = forge(&mut s, 2, 1, &[1]);
    if FIXED {
        // SS-146: pending_min 1 below cp2.pending_min 3.
        assert_eq!(r, Err(Refusal::PendingFloor));
    } else {
        assert_eq!(r, Ok(()));
    }
    s.sync(0).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    assert_eq!(s.open(0, P), Ok(vec![]));
    assert_eq!(
        s.session(0, P).work.slots.get(&1),
        Some(&Slot::Free(vec![1]))
    );
    if FIXED {
        assert_eq!(s.slot_bind(0, P, 1, d2()), Err(Error::SlotStale));
        assert!(!s.release(0, P, 1, d2()));
        assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 1);
        assert!(!g2g3(&s));
    } else {
        assert!(s.slot_bind(0, P, 1, d2()).is_ok());
        assert!(s.release(0, P, 1, d2()));
        assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 2);
        assert!(g2g3(&s));
    }
}

/// c01PendingFloorDropsNoLateBootTest. cp2 (h 1, pending_min 2, slot 1 done)
/// lands before the rollback. Seats 0 and 1 classify the restart against cp2;
/// seat 0 burns [2, 3] and slot 1 stays free below pending_min. cp3 takes the
/// jump (h 3, pending_min 4). cp4 keeps every boot counter of cp3 and names
/// slot 1 pending with pending_min 1. Seat 0 binds slot 1 for d2.
#[test]
fn c01_pending_floor_drops_no_late_boot() {
    let mut s = sim();
    let snap = prefix(&mut s);
    forge(&mut s, 1, 2, &[]).unwrap();
    s.inject(Fault::CoordinatedRollback(snap));
    for j in [1, 0] {
        s.sync(j).unwrap();
    }
    assert_eq!(s.nodes[0].ram.whole_restart, Some(true));
    assert_eq!(s.open(0, P), Ok(vec![2, 3]));
    assert_eq!(
        s.session(0, P).work.slots.get(&1),
        Some(&Slot::Free(vec![1]))
    );
    s.post_checkpoint().unwrap();
    let cp3 = s.ledger.cp.clone().unwrap();
    assert_eq!(
        (cp3.seq, cp3.h, cp3.pending_min, cp3.restart_seq),
        (3, 3, 4, 3)
    );
    let r = forge(&mut s, 3, 1, &[1]);
    if FIXED {
        assert_eq!(r, Err(Refusal::PendingFloor));
        assert_eq!(s.slot_bind(0, P, 1, d2()), Err(Error::SlotStale));
        assert!(!s.release(0, P, 1, d2()));
        assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 1);
        assert!(!g2g3(&s));
    } else {
        assert_eq!(r, Ok(()));
        assert!(s.slot_bind(0, P, 1, d2()).is_ok());
        assert!(s.release(0, P, 1, d2()));
        assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 2);
        assert!(g2g3(&s));
    }
}

/// c02StaggeredSyncBypassesJumpTest. After the rollback the seats sync one at a
/// time and the committee posts a checkpoint after each RestoreDone (the cadence
/// of design.md, "Parameters"). Each checkpoint changes one boot counter, so
/// w + 1 = 3 seats keep their counter between neighbours and SS-104 never
/// applies, although seats 1, 2 and 3 each classified a whole-committee restart
/// and each checkpoint advances restart_seq (SS-121). Seat 0 syncs last, sees
/// w + 1 continuous seats, burns nothing and binds slot 1 above h = 0.
#[test]
fn c02_staggered_sync_bypasses_jump() {
    let mut s = sim();
    let snap = prefix(&mut s);
    s.inject(Fault::CoordinatedRollback(snap));
    let mut seen = vec![];
    for j in [1, 2, 3] {
        s.sync(j).unwrap();
        assert_eq!(s.nodes[j].ram.whole_restart, Some(true));
        s.post_checkpoint().unwrap();
        let cp = s.ledger.cp.clone().unwrap();
        assert_eq!(cp.restart_seq, cp.seq);
        seen.push((cp.seq, cp.h, cp.pending_min));
    }
    if FIXED {
        // SS-147: each checkpoint that advances restart_seq takes the jump.
        assert_eq!(seen, vec![(2, 2, 3), (3, 4, 5), (4, 6, 7)]);
    } else {
        assert_eq!(seen, vec![(2, 0, 1), (3, 0, 1), (4, 0, 1)]);
    }
    s.sync(0).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
    assert_eq!(s.open(0, P), Ok(vec![]));
    assert_eq!(
        s.session(0, P).work.slots.get(&1),
        Some(&Slot::Free(vec![1]))
    );
    if FIXED {
        assert_eq!(s.slot_bind(0, P, 1, d2()), Err(Error::SlotStale));
        assert!(!s.release(0, P, 1, d2()));
        assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 1);
        assert!(!g2g3(&s));
    } else {
        assert!(s.slot_bind(0, P, 1, d2()).is_ok());
        assert!(s.release(0, P, 1, d2()));
        assert_eq!(s.oracle.releases[&(0, P, 1)].len(), 2);
        assert!(g2g3(&s));
    }
}

/// The same pairwise rule refuses the C-02 checkpoint without the jump once the
/// fix is on: cp2 after seat 1's RestoreDone(whole_restart = true) with h = 0.
#[test]
fn c02_no_jump_checkpoint_refused() {
    let mut s = sim();
    let snap = prefix(&mut s);
    s.inject(Fault::CoordinatedRollback(snap));
    s.sync(1).unwrap();
    let r = forge(&mut s, 0, 1, &[]);
    if FIXED {
        assert_eq!(r, Err(Refusal::Restart));
    } else {
        assert_eq!(r, Ok(()));
        assert_eq!(s.ledger.cp.as_ref().unwrap().restart_seq, 2);
    }
}
