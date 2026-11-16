use sessions_sim::*;
fn sim() -> Sim {
    Sim::new(Params::new(4, 1), 0xdecaf)
}
fn free_snapshot(s: &mut Sim, p: Purpose) -> Snapshot {
    for j in 0..s.params.n {
        s.slot_put(j, p, 1, vec![j as u8]).unwrap();
        s.checkpoint(j, p).unwrap();
    }
    s.snapshot()
}
fn first_release(s: &mut Sim, p: Purpose) {
    s.post_checkpoint().unwrap();
    for j in 0..s.params.n {
        s.slot_bind(j, p, 1, hash(b"first")).unwrap();
        assert!(s.release(j, p, 1, hash(b"first")));
    }
}
fn fired(s: &Sim, label: &str) {
    assert!(
        s.oracle.violations.iter().any(|x| x.contains(label)),
        "oracle did not fire: {:?}",
        s.trace
    );
}

#[test]
fn mutant_no_restart_burn_fires() {
    for mutant in [false, true] {
        let mut s = sim();
        let p = Purpose::Schnorr;
        let snap = free_snapshot(&mut s, p);
        first_release(&mut s, p);
        s.knobs.no_restart_burn = mutant;
        s.inject(Fault::CoordinatedRollback(snap));
        s.recover_all();
        let _ = s.slot_bind(0, p, 1, hash(b"second"));
        s.release(0, p, 1, hash(b"second"));
        control(&s, mutant, "G2/G3");
    }
}
#[test]
fn mutant_no_account_burn_fires() {
    for mutant in [false, true] {
        let mut s = sim();
        let p = Purpose::Ecdsa;
        let snap = free_snapshot(&mut s, p);
        first_release(&mut s, p);
        s.knobs.no_account_burn = mutant;
        s.inject(Fault::CoordinatedRollback(snap));
        s.recover_all();
        s.post_checkpoint().unwrap();
        let _ = s.slot_bind(0, p, 1, hash(b"second"));
        s.release(0, p, 1, hash(b"second"));
        control(&s, mutant, "G2/G3");
    }
}
#[test]
fn mutant_no_version_fence_fires() {
    for mutant in [false, true] {
        let mut s = sim();
        let p = Purpose::Schnorr;
        s.put(0, p, "secret", vec![1]).unwrap();
        let v = s.checkpoint(0, p).unwrap();
        s.destroy(0, p, "secret").unwrap();
        s.knobs.no_version_fence = mutant;
        assert_eq!(
            s.derive(0, sid(0, p), v),
            Err(if mutant {
                Error::OracleViolation
            } else {
                Error::GroupUnavailable
            })
        );
        control(&s, mutant, "G4");
    }
}

fn control(s: &Sim, mutant: bool, label: &str) {
    if mutant {
        fired(s, label);
    } else {
        assert!(
            s.oracle.violations.is_empty(),
            "OFF: {:?}",
            s.oracle.violations
        );
    }
}

fn late_boot(s: &mut Sim, p: Purpose) {
    let snap = free_snapshot(s, p);
    first_release(s, p);
    s.inject(Fault::CoordinatedRollback(snap));
    // RestoreDone can precede session_open. Leave seat 0 unsynced until cp2.
    for j in 1..s.params.n {
        s.sync(j).unwrap();
        for pool in Purpose::ALL {
            s.open(j, pool).unwrap();
        }
    }
    s.post_checkpoint().unwrap();
    s.open(0, p).unwrap();
    assert_eq!(s.nodes[0].ram.whole_restart, Some(false));
}
#[test]
fn late_boot_sequential_refuses_after_cp2() {
    for (n, f) in [(4, 1), (7, 2)] {
        let mut s = Sim::new(Params::new(n, f), 89);
        let p = Purpose::Schnorr;
        late_boot(&mut s, p);
        assert_eq!(s.slot_bind(0, p, 1, hash(b"second")), Err(Error::SlotStale));
        assert!(!s.release(0, p, 1, hash(b"second")));
        assert!(s.oracle.violations.is_empty());
    }
}
#[test]
fn mutant_no_slot_stale_fires() {
    for mutant in [false, true] {
        let mut s = sim();
        let p = Purpose::Schnorr;
        late_boot(&mut s, p);
        s.knobs.no_slot_stale = mutant;
        let _ = s.slot_bind(0, p, 1, hash(b"second"));
        s.release(0, p, 1, hash(b"second"));
        control(&s, mutant, "G2/G3");
    }
}
#[test]
fn mutant_no_blank_fetch_fires() {
    for mutant in [false, true] {
        let mut s = sim();
        s.oracle.observe_only = true; // SS-102: CONCURRENT sees G4 before the release probe.
        let p = Purpose::Schnorr;
        let snap = free_snapshot(&mut s, p);
        first_release(&mut s, p);
        s.knobs.no_blank_fetch = mutant;
        // Serial forgetful peers, each with a checkpoint and repaired share.
        // The hostile app leaves h unchanged so the slot remains in the window.
        for peer in 1..s.params.n {
            s.inject(Fault::ReplaceSlot(peer));
            s.recover_all();
            s.post_checkpoint().unwrap();
        }
        s.inject(Fault::RollbackSeat(0, snap));
        s.recover_all();
        let _ = s.slot_bind(0, p, 1, hash(b"second"));
        s.release(0, p, 1, hash(b"second"));
        if mutant {
            fired(&s, "G2/G3");
        } else {
            assert!(s.oracle.violations.is_empty());
        }
    }
}

#[test]
fn mutant_no_witness_before_bind_fires() {
    for mutant in [false, true] {
        let mut s = sim();
        let p = Purpose::Schnorr;
        free_snapshot(&mut s, p);
        s.knobs.no_witness_before_bind = mutant;
        // Capture a real snapshot after the slot round, before the bound seal.
        // Replacement erases the owner's log; honest peers retain the slot entry.
        s.crash_point = Some(CrashPoint::AfterSlotAcks);
        assert_eq!(s.slot_bind(0, p, 1, hash(b"first")), Err(Error::Crashed));
        s.inject(Fault::ReplaceSlot(0));
        let snap = s.snapshot();
        s.recover_all();
        s.slot_bind(0, p, 1, hash(b"first")).unwrap();
        assert!(s.release(0, p, 1, hash(b"first")));
        s.post_checkpoint().unwrap();
        // Roll peers back first, then the owner. Checkpoints between waves
        // preserve continuity; hostile application leaves h=0, as contract allows.
        for j in [1, 2, 3, 0] {
            s.inject(Fault::RollbackSeat(j, snap.clone()));
            s.sync(j).unwrap();
            s.post_checkpoint().unwrap();
        }
        s.open(0, p).unwrap();
        let _ = s.slot_bind(0, p, 1, hash(b"second"));
        s.release(0, p, 1, hash(b"second"));
        if mutant {
            fired(&s, "G2/G3");
        } else {
            assert!(s.oracle.violations.is_empty());
        }
    }
}
