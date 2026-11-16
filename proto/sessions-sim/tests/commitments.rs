use sessions_sim::{
    board::{batch_root, pending_root, seat_root, Entry},
    ledger::Refusal,
    *,
};
use std::collections::BTreeSet;

#[test]
fn q11_lost_tail_covered_put_not_rebound() {
    for (n, f) in [(4, 1), (7, 2)] {
        let mut s = Sim::new(Params::new(n, f), 731);
        let p = Purpose::Ecdsa;
        let snap = s.snapshot();
        s.slot_put(0, p, 1, vec![7; 64]).unwrap();
        s.post_checkpoint().unwrap();
        s.slot_bind(0, p, 1, hash(b"first")).unwrap();
        assert!(s.release(0, p, 1, hash(b"first")));
        s.inject(Fault::CoordinatedRollback(snap));
        s.inject(Fault::LoseTail);
        s.recover_all();
        for i in [1, 2] {
            assert_eq!(s.slot_put(0, p, i, vec![7; 64]), Err(Error::SlotUsed));
            assert!(!s.release(0, p, i, hash(b"second")));
        }
        s.post_checkpoint().unwrap();
        assert_eq!(s.slot_put(0, p, 1, vec![7; 64]), Err(Error::SlotUsed));
        assert_eq!(s.oracle.share_releases[&((0, p, 1), vec![7; 64])].len(), 1);
    }
}

#[test]
fn withheld_log_refuses_bind_never_releases() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let p = Purpose::Ecdsa;
    let snap = s.snapshot();
    s.slot_put(0, p, 1, vec![7; 64]).unwrap();
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 1, hash(b"first")).unwrap();
    assert!(s.release(0, p, 1, hash(b"first")));
    s.inject(Fault::CoordinatedRollback(snap));
    s.inject(Fault::Withhold(0));
    s.recover_all();
    let before = s.session(0, p).work.clone();
    let tx = s.ledger.midnight.tx();
    assert_eq!(s.slot_put(0, p, 1, vec![7; 64]), Err(Error::LogUnavailable));
    assert_eq!(s.slot_put(0, p, 2, vec![8; 64]), Err(Error::LogUnavailable));
    assert_eq!(
        s.slot_bind(0, p, 1, hash(b"second")),
        Err(Error::LogUnavailable)
    );
    assert!(!s.release(0, p, 1, hash(b"second")));
    assert_eq!(s.session(0, p).work, before);
    assert_eq!(s.post_checkpoint(), Err(Refusal::LogUnavailable));
    assert_eq!(s.ledger.midnight.tx(), tx);
    s.inject(Fault::ServeLog(0));
    assert_eq!(s.slot_put(0, p, 1, vec![7; 64]), Err(Error::SlotUsed));
    s.post_checkpoint().unwrap();
    assert_eq!(s.oracle.share_releases[&((0, p, 1), vec![7; 64])].len(), 1);
}

#[test]
fn rollback_across_checkpoint_boundary() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let p = Purpose::Ecdsa;
    let snap = s.snapshot(); // before k-1
    s.post_checkpoint().unwrap(); // k-1
    s.slot_put(0, p, 1, vec![7; 64]).unwrap();
    let position = s.board.logs[0].last().unwrap().position;
    s.post_checkpoint().unwrap(); // k
    assert!(position <= s.board.covered_position());
    s.slot_put(0, p, 2, vec![8; 64]).unwrap();
    assert_eq!(s.slot_bind(0, p, 2, hash(b"tail")), Err(Error::PutPending));
    assert!(!s.release(0, p, 2, hash(b"tail")));
    s.inject(Fault::CoordinatedRollback(snap));
    s.inject(Fault::LoseTail);
    s.recover_all();
    assert_eq!(s.slot_put(0, p, 1, vec![7; 64]), Err(Error::SlotUsed));
    assert!(!s.oracle.releases.contains_key(&(0, p, 2)));
    s.post_checkpoint().unwrap();
    s.slot_put(0, p, 2, vec![8; 64]).unwrap();
    assert_eq!(
        s.slot_bind(0, p, 2, hash(b"new tail")),
        Err(Error::PutPending)
    );
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 2, hash(b"new tail")).unwrap();
    assert!(s.release(0, p, 2, hash(b"new tail")));
}

#[test]
fn lost_covered_entries_stall_checkpoint_and_fail_closed() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let p = Purpose::Ecdsa;
    s.slot_put(0, p, 1, vec![7]).unwrap();
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 1, hash(b"first")).unwrap();
    assert!(s.release(0, p, 1, hash(b"first")));
    s.inject(Fault::LoseCovered(0));
    let cp = s.ledger.cp.clone();
    let tx = s.ledger.midnight.clone();
    for _ in 0..3 {
        assert_eq!(s.post_checkpoint(), Err(Refusal::LogUnavailable));
        assert_eq!(s.slot_put(0, p, 2, vec![7]), Err(Error::LogUnavailable));
        assert_eq!(
            s.slot_bind(0, p, 1, hash(b"first")),
            Err(Error::LogUnavailable)
        );
        assert!(!s.release(0, p, 1, hash(b"first")));
    }
    assert_eq!(s.ledger.cp, cp);
    assert_eq!(s.ledger.midnight, tx);
}

#[test]
fn lost_tail_resubmits_once_and_needs_coverage() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let p = Purpose::Ecdsa;
    s.slot_put(0, p, 1, vec![7]).unwrap();
    let tag = s.session(0, p).work.put_tags[&1];
    s.board.lose_tail();
    let count = s.board.logs[0].len();
    for _ in 0..3 {
        assert_eq!(s.slot_bind(0, p, 1, hash(b"first")), Err(Error::PutPending));
        assert_eq!(s.board.logs[0].len(), count + 1);
        assert_eq!(s.session(0, p).work.put_tags[&1], tag);
    }
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 1, hash(b"first")).unwrap();
}

#[test]
fn roots_chain_empty_batches_and_detect_changed_bytes() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let old = s.ledger.cp.clone().unwrap();
    s.post_checkpoint().unwrap();
    let cp = s.ledger.cp.as_ref().unwrap();
    assert!(cp.batch_root.is_empty()); // ledger retains chained roots only
    for j in 0..4 {
        assert_eq!(
            cp.seat_root[j],
            seat_root(old.seat_root[j], batch_root(&[]))
        );
        assert!(s.board.verified(j, &s.ledger).is_some());
    }
    s.slot_put(0, Purpose::Ecdsa, 1, vec![7]).unwrap();
    s.post_checkpoint().unwrap();
    if let Entry::Put { ref mut tag, .. } = s.board.logs[0].last_mut().unwrap().entry {
        tag[0] ^= 1;
    } else {
        panic!("expected put");
    }
    assert!(s.board.verified(0, &s.ledger).is_none());
    assert_eq!(s.post_checkpoint(), Err(Refusal::LogUnavailable));
}

#[test]
fn pending_min_restart_jump_refused_and_accepted() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    s.request(Purpose::Schnorr).unwrap();
    s.post_checkpoint().unwrap();
    let old = s.ledger.cp.clone().unwrap();
    s.inject(Fault::WholeCommitteeRestart);
    s.recover_all();
    let mut next = old.clone();
    next.seq += 1;
    next.restart_seq = next.seq;
    let (batches, restores) = s.board.batches(&s.ledger).unwrap();
    next.batch_root = batches;
    next.boot_counters = s.ledger.latest_done(&restores);
    next.restores = restores;
    let end = old.h + s.params.b;
    next.h = end;
    next.pending_min = end;
    assert_eq!(s.ledger.validate(&next, &s.params), Err(Refusal::Restart));
    next.pending_min = end + 1;
    next.h = end - 1;
    assert_eq!(s.ledger.validate(&next, &s.params), Err(Refusal::Restart));
    next.h = end;
    next.pending_root = pending_root(&BTreeSet::new());
    next.pending_count = 0;
    s.ledger.post(next, &s.params).unwrap();
}

#[test]
fn sequential_pending_membership_requires_matching_root() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    for _ in 0..3 {
        s.request(Purpose::Schnorr).unwrap();
    }
    s.requests.retain(|r| r.index != 2);
    s.post_checkpoint().unwrap();
    let cp = s.ledger.cp.clone().unwrap();
    assert_eq!((cp.pending_min, cp.pending_count, cp.h), (1, 2, 3));
    for i in 0..=3 {
        s.slot_put(0, Purpose::Schnorr, i, vec![7]).unwrap();
    }
    assert_eq!(
        s.slot_bind(0, Purpose::Schnorr, 0, hash(b"d")),
        Err(Error::SlotStale)
    );
    assert_eq!(
        s.slot_bind(0, Purpose::Schnorr, 2, hash(b"d")),
        Err(Error::SlotStale)
    );
    s.board.pending.insert(2); // membership alone cannot authorize a forged set
    assert_eq!(
        s.slot_bind(0, Purpose::Schnorr, 2, hash(b"d")),
        Err(Error::SlotStale)
    );
    assert_eq!(
        s.slot_bind(0, Purpose::Schnorr, 1, hash(b"d")),
        Err(Error::SlotStale)
    );
    s.board.pending.remove(&2);
    s.slot_bind(0, Purpose::Schnorr, 1, hash(b"d")).unwrap();
    s.slot_bind(0, Purpose::Schnorr, 3, hash(b"d")).unwrap();
}

#[test]
fn restart_burn_is_one_run_including_pending_holes() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    for _ in 0..4 {
        s.request(Purpose::Schnorr).unwrap();
    }
    s.requests.retain(|r| r.index == 2 || r.index == 4);
    s.post_checkpoint().unwrap();
    s.inject(Fault::WholeCommitteeRestart);
    assert_eq!(
        s.open(0, Purpose::Schnorr).unwrap(),
        (2..=12).collect::<Vec<_>>()
    );
}

#[test]
fn fixed_midnight_writes_only_checkpoints_and_boot_tickets() {
    for (n, f) in [(4, 1), (7, 2)] {
        let mut fixed = Sim::new(Params::new(n, f), 731);
        let mut old = Sim::new_with_knobs(
            Params::new(n, f),
            731,
            Knobs {
                old_per_event_ledger: true,
                ..Knobs::default()
            },
        );
        for s in [&mut fixed, &mut old] {
            let initial = s.ledger.midnight.clone();
            s.slot_put(0, Purpose::Ecdsa, 100, vec![99]).unwrap();
            if !s.knobs.old_per_event_ledger {
                assert_eq!(s.ledger.midnight, initial);
            }
            s.run(12);
            s.inject(Fault::WholeCommitteeRestart);
            s.recover_all();
            s.post_checkpoint().unwrap();
            assert!(s.oracle.violations.is_empty());
        }
        let m = &fixed.ledger.midnight;
        assert_eq!(m.tx(), m.checkpoints + m.boot_tickets);
        assert_eq!((m.put_records, m.restore_transactions), (0, 0));
        assert_eq!(m.boot_tickets, 2 * n as u64);
        assert_eq!(m.checkpoints, fixed.ledger.history.len() as u64);
        let q = (n + f + 1).div_ceil(2);
        let expected = 150 * m.boot_tickets
            + (88 + 52 + 8 * n + 8 + 32 * n + 64 * q) as u64 * m.checkpoints
            + 115 * fixed.ledger.statements().count() as u64;
        assert_eq!(m.bytes, expected);
        assert_eq!(old.trace, fixed.trace);
        assert!(old.ledger.midnight.tx() > m.tx());
        assert!(old.ledger.midnight.bytes > m.bytes);
        assert_eq!(
            old.ledger.midnight.bytes - m.bytes,
            146 * old.ledger.midnight.put_records
        );
        assert_eq!(old.ledger.midnight.restore_transactions, 2 * n as u64);
    }
}

#[test]
fn rejected_contract_submission_counts_but_builder_stall_does_not() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let mut next = s.ledger.cp.clone().unwrap();
    next.batch_root = vec![batch_root(&[]); 4];
    next.restores.clear();
    let before = s.ledger.midnight.clone();
    assert_eq!(s.ledger.post(next, &s.params), Err(Refusal::Sequence));
    assert_eq!(s.ledger.midnight.tx(), before.tx() + 1);
    assert_eq!(s.ledger.midnight.bytes, before.bytes + 500);
    let submitted = s.ledger.midnight.clone();
    s.board.withhold(0);
    assert_eq!(s.post_checkpoint(), Err(Refusal::LogUnavailable));
    assert_eq!(s.ledger.midnight, submitted);
}

#[test]
fn restore_lost_after_recovery_is_reposted_before_checkpoint() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    s.inject(Fault::WholeCommitteeRestart);
    s.recover_all();
    s.board.lose_tail();
    s.recover_all();
    let logs = s.board.logs.clone();
    s.recover_all();
    assert_eq!(s.board.logs, logs); // retries do not duplicate a visible statement
    s.post_checkpoint().unwrap();
    assert_eq!(s.ledger.cp.as_ref().unwrap().boot_counters, s.ledger.boots);
    assert!(s.ledger.cp.as_ref().unwrap().restart_seq > 0);
    s.slot_put(0, Purpose::Ecdsa, 1, vec![7]).unwrap();
    s.post_checkpoint().unwrap();
    s.slot_bind(0, Purpose::Ecdsa, 1, hash(b"after recovery"))
        .unwrap();
    assert!(s.release(0, Purpose::Ecdsa, 1, hash(b"after recovery")));
}
