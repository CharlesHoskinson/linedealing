use sessions_sim::{experiments::*, oracle::LossReading, *};

// SS-102/126: every finding uses the original seed and protocol trace.
fn safety(s: &Sim) -> Vec<&str> {
    s.oracle
        .violations
        .iter()
        .chain(&s.oracle.expected)
        .filter(|v| v.contains("G2/G3") || v.contains("G4"))
        .map(String::as_str)
        .collect()
}

fn fixed_series(kind: SeriesKind) {
    for (n, f) in SERIES_PARAMS {
        let old = replacement_series(
            Params::new(n, f),
            731,
            kind,
            Knobs {
                old_fetch_w_sources: true,
                old_no_replica_fetch: true,
                ..Knobs::default()
            },
            LossReading::Concurrent,
        );
        let reproduces = n - 2 - f <= f;
        assert_eq!(!safety(&old.sim).is_empty(), reproduces, "{n}/{f}");
        assert_eq!(old.resurrected || old.second_release, reproduces);
        if reproduces {
            assert!(old.sim.trace.iter().any(|e| matches!(
                e,
                sessions_sim::oracle::Event::Opened {
                    seat: 0,
                    source: 1,
                    ..
                }
            )));
            if kind != SeriesKind::Fence {
                assert!(old.second_release);
                assert!(safety(&old.sim).iter().any(|v| v.contains("G2/G3")));
            }
        } else {
            assert_eq!(old.open_result, Err(Error::GroupUnavailable));
        }
        let r = replacement_series(Params::new(n, f), 731, kind, false, LossReading::Concurrent);
        assert!(safety(&r.sim).is_empty(), "{n}/{f}: {:?}", safety(&r.sim));
        assert!(r.open_result.is_ok(), "{n}/{f}: {:?}", r.open_result);
        assert!(!r.resurrected && !r.second_release);
        assert!(r.sim.oracle.violations.is_empty());
        let p = if kind == SeriesKind::Account {
            Purpose::Ecdsa
        } else {
            Purpose::Schnorr
        };
        assert!(r.sim.session(0, p).open);
        if kind == SeriesKind::Fence {
            assert_eq!(r.sim.get(0, p, "erased"), Err(Error::NotFound));
        } else {
            assert_eq!(r.bind_result, Some(Err(Error::SlotBoundOther)));
        }
    }
}

#[test]
fn q01_fence_series_owner_rollback() {
    fixed_series(SeriesKind::Fence);
}
#[test]
fn q02_sequential_series_owner_rollback() {
    fixed_series(SeriesKind::Sequential);
}
#[test]
fn q03_account_series_owner_rollback() {
    fixed_series(SeriesKind::Account);
}

#[test]
fn q05_series_replicas_rebuilt() {
    for (n, f) in SERIES_PARAMS {
        for kind in SeriesKind::ALL {
            for old in [true, false] {
                let r = replacement_series(
                    Params::new(n, f),
                    731,
                    kind,
                    Knobs {
                        old_no_replica_fetch: old,
                        ..Knobs::default()
                    },
                    LossReading::Concurrent,
                );
                assert!(safety(&r.sim).is_empty());
                if old {
                    assert_eq!(r.open_result, Err(Error::GroupUnavailable));
                    assert!(r.sim.oracle.violations.iter().any(|v| v.starts_with("G1:")));
                } else {
                    assert!(r.open_result.is_ok());
                    assert!(r.sim.oracle.violations.is_empty());
                    // SS-126: the owner authenticates the latest pre-rollback record.
                    assert!(r.sim.trace.iter().any(|e| matches!(
                        e,
                        sessions_sim::oracle::Event::Opened {
                            seat: 0,
                            source: 2,
                            ..
                        }
                    )));
                }
            }
        }
    }
}

#[test]
fn q06_late_boot_account_burns_via_marker() {
    for (n, f) in [(4, 1), (7, 2)] {
        for old in [true, false] {
            let mut s = Sim::new(Params::new(n, f), 731);
            s.oracle.observe_only = true;
            s.knobs.old_no_restart_marker = old;
            let p = Purpose::Ecdsa;
            for j in 0..n {
                s.slot_put(j, p, 1, vec![j as u8]).unwrap();
                s.checkpoint(j, p).unwrap();
            }
            let snap = s.snapshot();
            s.post_checkpoint().unwrap();
            for j in 0..n {
                s.slot_bind(j, p, 1, hash(b"first")).unwrap();
                assert!(s.release(j, p, 1, hash(b"first")));
            }
            s.inject(Fault::CoordinatedRollback(snap));
            // SS-112: leave seat 0 unsynchronized until the recovery checkpoint.
            for j in 1..n {
                s.sync(j).unwrap();
                for pool in Purpose::ALL {
                    s.open(j, pool).unwrap();
                }
            }
            s.post_checkpoint().unwrap();
            let burned = s.open(0, p).unwrap();
            assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
            let bind = s.slot_bind(0, p, 1, hash(b"second"));
            let released = s.release(0, p, 1, hash(b"second"));
            assert_eq!(released, old);
            assert_eq!(safety(&s).iter().any(|v| v.contains("G2/G3")), old);
            if !old {
                assert_eq!(burned, vec![1]);
                assert_eq!(bind, Err(Error::SlotBurned));
                assert_eq!(
                    s.session(0, p).work.restart_mark,
                    s.ledger.cp.as_ref().unwrap().restart_seq
                );
            }
        }
    }
}

#[test]
fn q09_second_continuity_loss_rearms_ss113() {
    for old in [true, false] {
        let mut s = Sim::new(Params::new(4, 1), 731);
        s.knobs.old_no_restart_rearm = old;
        for j in [1, 2] {
            s.inject(Fault::VmReboot(j));
            s.sync(j).unwrap();
        }
        s.observe_ledger(0).unwrap();
        assert_eq!(s.nodes[0].ram.whole_restart, Some(true));
        s.post_checkpoint().unwrap();
        let boot = s.nodes[0].ram.cp_boot.clone();
        s.slot_put(0, Purpose::Ecdsa, 1, vec![7; 64]).unwrap();
        s.post_checkpoint().unwrap();
        s.slot_bind(0, Purpose::Ecdsa, 1, hash(b"new")).unwrap();
        assert_eq!(s.nodes[0].ram.whole_restart, Some(old));
        for j in [1, 2] {
            s.inject(Fault::VmReboot(j));
            s.sync(j).unwrap();
        }
        s.observe_ledger(0).unwrap();
        assert_eq!(s.nodes[0].ram.cp_boot == boot, old);
        assert_eq!(s.slot_release_ok(0, Purpose::Ecdsa, 1, hash(b"new")), old);
        if !old {
            assert_eq!(
                s.slot_bind(0, Purpose::Ecdsa, 1, hash(b"new")),
                Err(Error::SlotBurned)
            );
        }
        // Q-09 detects a missing burn, not a second digest in this original trace.
        assert!(safety(&s).is_empty());
    }
}

#[test]
fn q11_absent_account_slot_after_whole_rollback() {
    for (n, f) in [(4, 1), (7, 2)] {
        for (old, legacy) in [(true, true), (true, false), (false, false)] {
            let mut s = Sim::new(Params::new(n, f), 731);
            s.knobs = if legacy {
                Knobs::old_rules()
            } else {
                Knobs {
                    old_no_put_record: old,
                    ..Knobs::default()
                }
            };
            s.oracle.observe_only = true;
            let p = Purpose::Ecdsa;
            let snap = s.snapshot();
            s.slot_put(0, p, 1, vec![7; 64]).unwrap();
            s.post_checkpoint().unwrap();
            s.slot_bind(0, p, 1, hash(b"d1")).unwrap();
            assert!(s.release(0, p, 1, hash(b"d1")));
            s.inject(Fault::CoordinatedRollback(snap));
            s.recover_all();
            assert_eq!(s.nodes[0].ram.whole_restart, Some(true));
            let put = s.slot_put(0, p, 1, vec![7; 64]);
            if old {
                put.unwrap();
                if legacy {
                    // SS-128..132: all old rules reproduce the exact original Q-11 tail.
                    s.slot_bind(0, p, 1, hash(b"d2")).unwrap();
                } else {
                    // SS-124 blocks the original tail even with put records disabled.
                    // Land its checkpoint to isolate SS-128..132 without weakening it.
                    assert_eq!(s.slot_bind(0, p, 1, hash(b"d2")), Err(Error::NoCheckpoint));
                    s.post_checkpoint().unwrap();
                    s.slot_bind(0, p, 1, hash(b"d2")).unwrap();
                }
                assert!(s.release(0, p, 1, hash(b"d2")));
                assert_eq!(s.oracle.share_releases[&((0, p, 1), vec![7; 64])].len(), 2);
            } else {
                assert_eq!(put, Err(Error::SlotUsed));
                assert_eq!(s.slot_put(0, p, 2, vec![7; 64]), Err(Error::SlotUsed));
                s.post_checkpoint().unwrap();
                assert_eq!(s.slot_put(0, p, 1, vec![7; 64]), Err(Error::SlotUsed));
                assert!(!s.release(0, p, 1, hash(b"d2")));
                assert_eq!(s.oracle.share_releases[&((0, p, 1), vec![7; 64])].len(), 1);
            }
            assert_eq!(safety(&s).iter().any(|v| v.contains("G2/G3")), old);
        }
    }
}

#[test]
fn q11_put_pending_then_bind() {
    for old in [false, true] {
        let mut s = Sim::new(Params::new(4, 1), 731);
        s.knobs.old_no_put_record = old;
        s.oracle.observe_only = true;
        let p = Purpose::Ecdsa;
        let snap = s.snapshot();
        s.slot_put(0, p, 1, vec![7; 64]).unwrap();
        let body = s.session(0, p).work.clone();
        let log = s.board.logs[0].clone();
        let refusals = s
            .trace
            .iter()
            .filter(|e| matches!(e, oracle::Event::BindRefused { .. }))
            .count();
        let first = s.slot_bind(0, p, 1, hash(b"d1"));
        if old {
            first.unwrap();
            assert!(s.release(0, p, 1, hash(b"d1")));
        } else {
            assert_eq!(first, Err(Error::PutPending));
            assert_eq!(s.session(0, p).work, body);
            assert_eq!(s.board.logs[0], log); // no duplicate while the tail holds it
            assert_eq!(
                s.trace
                    .iter()
                    .filter(|e| matches!(e, oracle::Event::BindRefused { .. }))
                    .count(),
                refusals
            );
            assert!(!s.release(0, p, 1, hash(b"d1")));
        }
        s.post_checkpoint().unwrap();
        s.slot_bind(0, p, 1, hash(b"d1")).unwrap();
        assert!(s.release(0, p, 1, hash(b"d1")));
        s.inject(Fault::CoordinatedRollback(snap));
        s.board.lose_tail();
        s.recover_all();
        s.post_checkpoint().unwrap();
        let put = s.slot_put(0, p, 1, vec![7; 64]);
        if old {
            put.unwrap();
            s.slot_bind(0, p, 1, hash(b"d2")).unwrap();
            assert!(s.release(0, p, 1, hash(b"d2")));
        } else {
            assert_eq!(put, Err(Error::SlotUsed));
            assert!(!s.release(0, p, 1, hash(b"d2")));
        }
        assert_eq!(safety(&s).iter().any(|v| v.contains("G2/G3")), old);
        assert_eq!(
            s.oracle.share_releases[&((0, p, 1), vec![7; 64])].len(),
            if old { 2 } else { 1 }
        );
    }
}

#[test]
fn uncovered_put_cannot_bind() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    let p = Purpose::Ecdsa;
    let d = hash(b"uncovered");
    let writes = s.ledger.midnight.clone();
    s.slot_put(0, p, 1, vec![7; 64]).unwrap();
    assert_eq!(s.slot_put(0, p, 2, vec![7; 64]), Err(Error::SlotUsed));
    assert_eq!(s.slot_bind(0, p, 1, d), Err(Error::PutPending));
    assert!(!s.release(0, p, 1, d));
    assert_eq!(s.ledger.midnight, writes);
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 1, d).unwrap();
    assert!(s.release(0, p, 1, d));
}
