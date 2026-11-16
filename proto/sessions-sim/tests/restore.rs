use sessions_sim::ledger::{Checkpoint, Refusal};
use sessions_sim::oracle::Event;
use sessions_sim::*;

#[test]
fn split_version_committed_record_is_tried_first_qi04() {
    for (n, f) in [(4, 1), (7, 2)] {
        let mut s = Sim::new(Params::new(n, f), 100);
        let p = Purpose::Schnorr;
        s.put(0, p, "base", vec![1]).unwrap();
        s.checkpoint(0, p).unwrap();
        let snap = s.snapshot();
        s.put(0, p, "uncommitted", vec![2]).unwrap();
        s.crash_point = Some(CrashPoint::AfterWitnessAcks { peers: vec![1] });
        assert_eq!(s.checkpoint(0, p), Err(Error::Crashed));
        s.inject(Fault::RollbackSeat(0, snap));
        s.sync_peers = Some((2..n).collect());
        s.open(0, p).unwrap();
        // Peer 1 has uncommitted v2 A, all other peers have committed v2 B.
        assert_eq!(s.session(0, p).v, 2);
        let committed = s.nodes[2].tier0.peers[&(0, sid(0, p))].pd;
        assert_ne!(s.nodes[1].tier0.peers[&(0, sid(0, p))].pd, committed);
        s.sync_peers = None;
        s.inject(Fault::VmReboot(0));
        let offset = s.trace.len();
        s.open(0, p).unwrap();
        assert!(
            matches!(s.trace[offset..].iter().find(|e|matches!(e,Event::Candidate {..})),Some(Event::Candidate {v:2,digest,..}) if *digest==committed)
        );
        assert_eq!(s.get(0, p, "uncommitted"), Err(Error::NotFound));
        assert!(s.oracle.violations.is_empty());
    }
}

#[test]
fn corrupted_unwitnessed_candidate_sends_no_witness() {
    let mut s = Sim::new(Params::new(4, 1), 90);
    let p = Purpose::Schnorr;
    s.put(0, p, "k", vec![4]).unwrap();
    s.crash_point = Some(CrashPoint::AfterFsync);
    assert_eq!(s.checkpoint(0, p), Err(Error::Crashed));
    s.nodes[0].disk.local.get_mut(&sid(0, p)).unwrap()[0].tag[0] ^= 1;
    let offset = s.trace.len();
    assert_eq!(s.open(0, p), Err(Error::Corrupt));
    assert!(!s.session(0, p).open);
    assert!(!s.trace[offset..]
        .iter()
        .any(|e| matches!(e, Event::Witness { seat: 0, .. })));
}
#[test]
fn candidate_error_record_unavailable() {
    let mut s = Sim::new(Params::new(4, 1), 90);
    let p = Purpose::Schnorr;
    s.checkpoint(0, p).unwrap();
    for node in &mut s.nodes {
        node.disk.local.clear();
        node.disk.replicas.clear();
    }
    s.inject(Fault::VmReboot(0));
    assert_eq!(s.open(0, p), Err(Error::RecordUnavailable));
}
#[test]
fn candidate_error_group_unavailable() {
    let mut s = Sim::new(Params::new(4, 1), 90);
    let p = Purpose::Schnorr;
    s.checkpoint(0, p).unwrap();
    for node in &mut s.nodes {
        node.tier0.share = false;
    }
    s.inject(Fault::VmReboot(0));
    assert_eq!(s.open(0, p), Err(Error::GroupUnavailable));
}
#[test]
fn witness_conflict_reack_and_forgery() {
    let mut s = Sim::new(Params::new(4, 1), 90);
    let p = Purpose::Schnorr;
    s.checkpoint(0, p).unwrap();
    let r = s.nodes[0].disk.local[&sid(0, p)][0].clone();
    let st = Statement::signed(&r, 1);
    s.nodes[1].disk.replicas.clear();
    s.witness(1, 0, &r, &st).unwrap();
    assert_eq!(s.nodes[1].disk.replicas[&(0, r.sid)], r);
    let mut wrong = r.clone();
    wrong.nonce[0] ^= 1;
    let wrong_st = Statement::signed(&wrong, 1);
    assert_eq!(s.witness(1, 0, &wrong, &wrong_st), Err(Error::Conflict));
    let mut forged = st.clone();
    forged.valid = false;
    assert_eq!(s.witness(1, 0, &r, &forged), Err(Error::NotCurrent));
    s.ledger.reboot(1);
    assert_eq!(s.partial(1, 0, r.sid, 1), Err(Error::Fenced));
    s.ledger.reboot(0);
    assert_eq!(s.partial(2, 0, r.sid, 1), Err(Error::NotCurrent));
}
#[test]
fn contract_rejects_all_three_rules() {
    let mut s = Sim::new(Params::new(4, 1), 3);
    s.h_next = 5;
    s.post_checkpoint().unwrap();
    let old = s.ledger.cp.clone().unwrap();
    let mut cp = old.clone();
    cp.seq += 1;
    cp.h = 4;
    assert_eq!(s.ledger.post(cp, &s.params), Err(Refusal::Floor));
    s.inject(Fault::VmReboot(0));
    let mut cp = old.clone();
    cp.seq += 1;
    cp.boot_counters[0] = 2;
    assert_eq!(s.ledger.post(cp, &s.params), Err(Refusal::RestoreDone));
    s.inject(Fault::WholeCommitteeRestart);
    s.recover_all();
    let cp = Checkpoint {
        seq: old.seq + 1,
        restart_seq: old.seq + 1,
        h: old.h,
        boot_counters: s.ledger.latest_done(&s.board.batches(&s.ledger).unwrap().1),
        batch_root: s.board.batches(&s.ledger).unwrap().0,
        restores: s.board.batches(&s.ledger).unwrap().1,
        ..old.clone()
    };
    assert_eq!(s.ledger.post(cp, &s.params), Err(Refusal::Restart));
    assert_eq!(s.ledger.refusals.len(), 3);
    s.post_checkpoint().unwrap();
    assert_eq!(s.ledger.cp.as_ref().unwrap().h, old.h + s.params.b);
}
#[test]
fn burn_destroy_retries_and_same_digest_rebind() {
    let mut s = Sim::new(Params::new(4, 1), 3);
    let p = Purpose::Schnorr;
    s.put(0, p, "key", vec![2]).unwrap();
    s.slot_put(0, p, 1, vec![1]).unwrap();
    s.checkpoint(0, p).unwrap();
    s.witness_peers = Some([1].into());
    assert_eq!(s.destroy(0, p, "key"), Err(Error::NoQuorum));
    assert!(s.session(0, p).dirty);
    s.witness_peers = None;
    s.destroy(0, p, "key").unwrap();
    let d = hash(b"ticket");
    s.slot_bind(0, p, 1, d).unwrap();
    let v = s.session(0, p).v;
    assert_eq!(s.slot_bind(0, p, 1, d), Ok(v));
    s.witness_peers = Some([1].into());
    assert_eq!(s.slot_burn(0, p, 1), Err(Error::NoQuorum));
    assert!(!s.release(0, p, 1, d));
    s.witness_peers = None;
    s.slot_burn(0, p, 1).unwrap();
    let v = s.session(0, p).v;
    assert_eq!(s.slot_burn(0, p, 1), Ok(v));
    s.inject(Fault::VmReboot(0));
    s.recover_all();
    assert!(s.oracle.violations.is_empty());
}
#[test]
fn latest_window_refusal_order_and_covered_deletion() {
    let mut s = Sim::new(Params::new(4, 1), 3);
    let p = Purpose::Schnorr;
    let d = hash(b"ticket");
    s.slot_put(0, p, 100, vec![1]).unwrap();
    assert_eq!(s.slot_bind(0, p, 100, d), Err(Error::WindowExceeded));
    s.h_next = 100;
    s.post_checkpoint().unwrap();
    assert_eq!(s.slot_bind(0, p, 100, d), Err(Error::SlotStale));
    s.slot_burn(0, p, 100).unwrap();
    assert_eq!(s.slot_bind(0, p, 100, d), Err(Error::SlotBurned));
    s.slot_put(0, p, 101, vec![1]).unwrap();
    s.slot_bind(0, p, 101, d).unwrap();
    s.h_next = 101;
    s.post_checkpoint().unwrap();
    assert!(!s.nodes[1].tier0.slots.contains_key(&(0, p, 101)));
    assert!(s.nodes[0].tier0.slots.contains_key(&(0, p, 101)));
    s.slot_burn(0, p, 101).unwrap();
    s.collect_covered();
    assert!(!s.nodes[0].tier0.slots.contains_key(&(0, p, 101)));
    s.ledger.cp = None;
    s.slot_put(0, Purpose::Ecdsa, 1, vec![]).unwrap();
    assert_eq!(
        s.slot_bind(0, Purpose::Ecdsa, 1, d),
        Err(Error::NoCheckpoint)
    );
}
#[test]
fn ledger_restart_pending_must_be_voided() {
    let mut s = Sim::new(Params::new(7, 2), 2);
    s.request(Purpose::Schnorr).unwrap();
    s.post_checkpoint().unwrap();
    let old = s.ledger.cp.clone().unwrap();
    s.inject(Fault::WholeCommitteeRestart);
    s.recover_all();
    let cp = Checkpoint {
        seq: old.seq + 1,
        restart_seq: old.seq + 1,
        h: old.h + s.params.b,
        boot_counters: s.ledger.latest_done(&s.board.batches(&s.ledger).unwrap().1),
        batch_root: s.board.batches(&s.ledger).unwrap().0,
        restores: s.board.batches(&s.ledger).unwrap().1,
        ..old.clone()
    };
    assert_eq!(s.ledger.post(cp, &s.params), Err(Refusal::Restart));
    s.post_checkpoint().unwrap();
    assert!(s.requests.is_empty());
    assert_eq!(s.ledger.cp.as_ref().unwrap().pending_count, 0);
}

#[test]
fn restore_no_quorum_stays_closed() {
    let mut s = Sim::new(Params::new(4, 1), 17);
    let p = Purpose::Schnorr;
    s.checkpoint(0, p).unwrap();
    s.inject(Fault::VmReboot(0));
    s.witness_peers = Some([1].into());
    assert_eq!(s.open(0, p), Err(Error::NoQuorum));
    assert!(!s.session(0, p).open);
    s.witness_peers = None;
    s.open(0, p).unwrap();
    assert!(s.session(0, p).open);
}
#[test]
fn blank_fetch_blocks_partials_and_witness() {
    let mut s = Sim::new(Params::new(4, 1), 17);
    let p = Purpose::Schnorr;
    s.checkpoint(0, p).unwrap();
    let r = s.nodes[0].disk.local[&sid(0, p)][0].clone();
    let st = Statement::signed(&r, 1);
    s.inject(Fault::ReplaceSlot(1));
    assert_eq!(s.partial(1, 0, r.sid, r.v), Err(Error::Unavailable));
    assert_eq!(s.witness(1, 0, &r, &st), Err(Error::Unavailable));
    s.sync(1).unwrap();
    assert_eq!(s.nodes[1].tier0.peers[&(0, r.sid)].pv, r.v);
}
#[test]
fn nonce_and_authentication_bind_header_and_body() {
    let mut rng = Rng(45);
    let key = hash(b"abstract-key");
    let body = Body::default();
    let a = Record::seal(0, Purpose::Ecdsa, 1, body.clone(), rng.nonce(), key);
    let b = Record::seal(0, Purpose::Ecdsa, 1, body, rng.nonce(), key);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.digest(), b.digest());
    assert!(a.authenticates(key));
    let mut bad = a.clone();
    bad.v += 1;
    assert!(!bad.authenticates(key));
    let mut bad = a;
    bad.body.entries.insert("changed".into(), vec![1]);
    assert!(!bad.authenticates(key));
}
#[test]
fn failed_bind_retains_free_slot_and_own_conflict() {
    let mut s = Sim::new(Params::new(4, 1), 17);
    let p = Purpose::Schnorr;
    s.slot_put(0, p, 1, vec![3]).unwrap();
    s.witness_peers = Some([1].into());
    assert_eq!(s.slot_bind(0, p, 1, hash(b"one")), Err(Error::NoQuorum));
    assert!(matches!(s.session(0, p).work.slots[&1], Slot::Free(_)));
    assert_eq!(s.slot_bind(0, p, 1, hash(b"two")), Err(Error::Conflict));
    assert!(!s.slot_release_ok(0, p, 1, hash(b"one")));
}

#[test]
fn running_restart_failure_cannot_leave_account_pool_releasable() {
    for (n, f) in [(4, 1), (7, 2)] {
        let mut s = Sim::new(Params::new(n, f), 12);
        let p = Purpose::Ecdsa;
        let d = hash(b"pending");
        s.slot_put(0, p, 1, vec![4]).unwrap();
        s.post_checkpoint().unwrap();
        s.slot_bind(0, p, 1, d).unwrap();
        for j in 1..=f + 1 {
            s.inject(Fault::VmReboot(j));
        }
        s.witness_peers = Some([1].into());
        assert_eq!(s.observe_ledger(0), Err(Error::NoQuorum));
        assert!(
            !s.slot_release_ok(0, p, 1, d),
            "SS-113 must apply to both pools even if the first burn cannot seal"
        );
        s.witness_peers = None;
        s.recover_all();
        assert_eq!(s.session(0, p).work.slots[&1], Slot::Burned);
        assert!(s.oracle.violations.is_empty());
    }
}

#[test]
fn crash_at_quorum_records_ghost_commit() {
    let mut s = Sim::new(Params::new(4, 1), 18);
    let p = Purpose::Schnorr;
    s.put(0, p, "key", vec![1]).unwrap();
    s.checkpoint(0, p).unwrap();
    s.crash_point = Some(CrashPoint::AfterWitnessAcks { peers: vec![1, 2] });
    assert_eq!(s.destroy(0, p, "key"), Err(Error::Crashed));
    assert_eq!(s.oracle.committed[&(0, sid(0, p))].v, 2);
    assert!(s.oracle.erased[&(0, sid(0, p))].names.contains("key"));
    s.recover_all();
    assert_eq!(s.get(0, p, "key"), Err(Error::NotFound));
}

#[test]
fn restart_marker_contract_and_running_statement_ss120_to_ss122() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    assert_eq!(s.ledger.cp.as_ref().unwrap().restart_seq, 0);
    let boot = s.nodes[0].ram.boot_counter;
    for j in [1, 2] {
        s.inject(Fault::VmReboot(j));
        s.sync(j).unwrap();
    }
    s.observe_ledger(0).unwrap();
    let old = s.ledger.cp.clone().unwrap();
    assert!(s.board.logs[0].iter().any(|e| matches!(e.entry,
        sessions_sim::board::Entry::Restore { boot: b, seq, whole_restart: true } if b == boot && seq == old.seq)));
    let mut next = old.clone();
    next.seq += 1;
    next.h += s.params.b;
    let (batches, restores) = s.board.batches(&s.ledger).unwrap();
    next.boot_counters = s.ledger.latest_done(&restores);
    next.batch_root = batches;
    next.restores = restores;
    next.pending_min = next.h + 1;
    assert_eq!(
        s.ledger.validate(&next, &s.params),
        Err(Refusal::RestartMarker)
    );
    next.restart_seq = next.seq;
    s.ledger.post(next.clone(), &s.params).unwrap();
    let mut later = next.clone();
    later.restores.clear();
    later.seq += 1;
    later.restart_seq = later.seq;
    // SS-122: old true statements below restart_seq cannot start another generation.
    assert_eq!(
        s.ledger.validate(&later, &s.params),
        Err(Refusal::RestartMarker)
    );
    later.restart_seq = next.restart_seq;
    s.ledger.post(later, &s.params).unwrap();
}

#[test]
fn blank_fetch_waits_for_w_plus_one_and_ignores_owner_ss102() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let p = Purpose::Schnorr;
    s.checkpoint(0, p).unwrap();
    let r = s.nodes[0].disk.local[&sid(0, p)][0].clone();
    // SS-102: even a valid signed self-report must not enter another peer's fence.
    let mut owner_report = s.nodes[1].tier0.peers[&(0, r.sid)].clone();
    owner_report.pv = 999;
    owner_report.statement.v = 999;
    s.nodes[0].tier0.peers.insert((0, r.sid), owner_report);
    s.inject(Fault::ReplaceSlot(1));
    s.inject(Fault::Down(3));
    s.sync_peers = Some([0, 2].into());
    assert_eq!(s.sync(1), Err(Error::NoQuorum));
    assert!(s.nodes[1].ram.fetching);
    assert_eq!(s.partial(1, 0, r.sid, 1), Err(Error::Unavailable));
    assert_eq!(
        s.witness(1, 0, &r, &Statement::signed(&r, 1)),
        Err(Error::Unavailable)
    );
    s.inject(Fault::Up(3));
    s.sync(1).unwrap(); // source 3 is added in ascending seat order
    let entry = &s.nodes[1].tier0.peers[&(0, r.sid)];
    assert_eq!(entry.pv, 1);
    assert_eq!(s.nodes[1].disk.replicas[&(0, r.sid)].digest(), entry.pd);
}

#[test]
fn missing_replica_keeps_entry_and_completes_ss127() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    s.checkpoint(0, Purpose::Schnorr).unwrap();
    let id = sid(0, Purpose::Schnorr);
    for n in &mut s.nodes {
        n.disk.replicas.clear();
    }
    s.inject(Fault::ReplaceSlot(1));
    s.sync(1).unwrap();
    assert!(!s.nodes[1].ram.fetching);
    assert_eq!(s.nodes[1].tier0.peers[&(0, id)].pv, 1);
    assert!(!s.nodes[1].disk.replicas.contains_key(&(0, id)));
}

#[test]
fn late_empty_account_open_commits_marker_and_digest_ss123_ss125() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    s.inject(Fault::WholeCommitteeRestart);
    for j in 1..4 {
        s.sync(j).unwrap();
    }
    s.post_checkpoint().unwrap();
    let marker = s.ledger.cp.as_ref().unwrap().restart_seq;
    assert!(marker > 0);
    s.open(0, Purpose::Ecdsa).unwrap();
    assert_eq!(s.session(0, Purpose::Ecdsa).v, 1);
    let body = &s.session(0, Purpose::Ecdsa).work;
    assert_eq!(body.restart_mark, marker);
    let mut other = body.clone();
    other.restart_mark = 0;
    assert_ne!(other.digest(Purpose::Ecdsa), body.digest(Purpose::Ecdsa));
    // SS-125 independently raises a burned session's marker at seal start.
    s.knobs.old_no_restart_rearm = true;
    s.open(1, Purpose::Ecdsa).unwrap();
    s.checkpoint(1, Purpose::Ecdsa).unwrap();
    assert_eq!(s.session(1, Purpose::Ecdsa).work.restart_mark, marker);
}
