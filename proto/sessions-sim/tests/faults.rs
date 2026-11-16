use sessions_sim::oracle::Event;
use sessions_sim::*;

fn each(mut f: impl FnMut(Sim)) {
    for (n, b) in [(4, 1), (7, 2)] {
        f(Sim::new(Params::new(n, b), 123));
    }
}
fn clean(s: &Sim) {
    assert!(
        s.oracle.violations.is_empty(),
        "{:?}\n{:?}",
        s.oracle.violations,
        s.trace
    );
}
fn committed(s: &mut Sim) {
    for j in 0..s.params.n {
        s.put(j, Purpose::Schnorr, "keyshare", vec![j as u8])
            .unwrap();
        s.checkpoint(j, Purpose::Schnorr).unwrap();
    }
}

#[test]
fn seald_crash_both_profiles() {
    each(|mut s| {
        committed(&mut s);
        s.inject(Fault::SealdCrash(0));
        s.recover_all();
        clean(&s);
        assert_eq!(s.get(0, Purpose::Schnorr, "keyshare").unwrap(), vec![0]);
    });
}
#[test]
fn vm_reboot_both_profiles() {
    each(|mut s| {
        committed(&mut s);
        s.inject(Fault::VmReboot(0));
        s.recover_all();
        clean(&s);
        assert_eq!(s.nodes[0].ram.boot_counter, 2);
    });
}
#[test]
fn replace_slot_both_profiles() {
    each(|mut s| {
        committed(&mut s);
        s.inject(Fault::ReplaceSlot(0));
        assert!(s.nodes[0].ram.fetching);
        assert!(s.nodes[0].disk.local.is_empty());
        s.recover_all();
        clean(&s);
        assert_eq!(s.get(0, Purpose::Schnorr, "keyshare").unwrap(), vec![0]);
    });
}
#[test]
fn whole_committee_restart_both_profiles() {
    each(|mut s| {
        committed(&mut s);
        s.inject(Fault::WholeCommitteeRestart);
        s.recover_all();
        clean(&s);
        for j in 0..s.params.n {
            assert_eq!(s.nodes[j].ram.whole_restart, Some(true));
            assert_eq!(
                s.get(j, Purpose::Schnorr, "keyshare").unwrap(),
                vec![j as u8]
            );
            assert_eq!(s.session(j, Purpose::Schnorr).work.slots[&1], Slot::Burned);
        }
    });
}
#[test]
fn byzantine_peer_both_profiles() {
    each(|mut s| {
        committed(&mut s);
        let p = Purpose::Schnorr;
        let d = hash(b"one");
        s.slot_put(0, p, 1, vec![1]).unwrap();
        s.slot_bind(0, p, 1, d).unwrap();
        s.inject(Fault::ByzantinePeer(1));
        s.put(0, p, "fresh", vec![2]).unwrap();
        s.checkpoint(0, p).unwrap();
        s.inject(Fault::VmReboot(0));
        s.recover_all();
        assert!(s.nodes[0].tier0.conflicted.contains(&(0, p, 1)));
        assert!(!s.slot_release_ok(0, p, 1, d));
        assert!(s.trace.iter().any(|e| matches!(e, Event::IgnoredReport(1))));
        assert!(s.session(0, p).v_max < 100);
        clean(&s);
    });
}
#[test]
fn ledger_read_failure_stays_not_ready_both_profiles() {
    each(|mut s| {
        committed(&mut s);
        s.inject(Fault::VmReboot(0));
        s.inject(Fault::LedgerReadFailure(0));
        assert_eq!(s.open(0, Purpose::Schnorr), Err(Error::NotReady));
        assert_eq!(s.nodes[0].ram.whole_restart, None);
        assert!(!s.ledger.statements().any(|d| d.seat == 0 && d.boot == 2));
        assert!(!s.board.logs[0]
            .iter()
            .any(|e| matches!(e.entry, sessions_sim::board::Entry::Restore { boot: 2, .. })));
        assert_eq!(
            s.put(0, Purpose::Schnorr, "bad", vec![]),
            Err(Error::NotReady)
        );
        s.inject(Fault::LedgerReadRecovered(0));
        s.recover_all();
        clean(&s);
    });
}

fn rollback_case(mut s: Sim, p: Purpose) {
    let d1 = hash(b"ticket-one");
    let d2 = hash(b"ticket-two");
    for j in 0..s.params.n {
        s.slot_put(j, p, 1, vec![j as u8]).unwrap();
        s.checkpoint(j, p).unwrap();
    }
    let snapshot = s.snapshot();
    s.post_checkpoint().unwrap();
    for j in 0..s.params.n {
        s.slot_bind(j, p, 1, d1).unwrap();
        assert!(s.release(j, p, 1, d1));
    }
    s.inject(Fault::CoordinatedRollback(snapshot));
    // Inspect the raw rollback record BEFORE mandatory restart steps. A restored
    // open session must already be burned under SS-036/068/114.
    for j in 0..s.params.n {
        assert!(matches!(
            s.nodes[j].disk.local[&sid(j, p)][0].body.slots[&1],
            Slot::Free(_)
        ));
    }
    s.inject(Fault::WholeCommitteeRestart);
    s.recover_all();
    for j in 0..s.params.n {
        assert_eq!(s.slot_bind(j, p, 1, d2), Err(Error::SlotBurned));
        assert!(!s.release(j, p, 1, d2));
        assert_eq!(s.oracle.releases[&(j, p, 1)].len(), 1);
    }
    assert!(!s.in_bound());
    assert!(!s.oracle.expected.is_empty());
    clean(&s);
}
#[test]
fn coordinated_rollback_no_double_release() {
    each(|s| rollback_case(s, Purpose::Schnorr));
}
#[test]
fn coordinated_rollback_account_no_double_release() {
    each(|s| rollback_case(s, Purpose::Ecdsa));
}

#[test]
fn crash_after_partial_witness_both_profiles() {
    each(|mut s| {
        let p = Purpose::Schnorr;
        s.put(0, p, "old", vec![1]).unwrap();
        s.checkpoint(0, p).unwrap();
        s.put(0, p, "new", vec![2]).unwrap();
        s.crash_point = Some(CrashPoint::AfterWitnessAcks {
            peers: (1..s.params.w).collect(),
        });
        assert_eq!(s.checkpoint(0, p), Err(Error::Crashed));
        let offset = s.trace.len();
        s.recover_all();
        clean(&s);
        // SS-031/094: higher uncommitted local v2 precedes committed v1.
        assert!(matches!(
            s.trace[offset..]
                .iter()
                .find(|e| matches!(e, Event::Candidate { .. })),
            Some(Event::Candidate { v: 2, .. })
        ));
        assert_eq!(s.get(0, p, "new").unwrap(), vec![2]);
    });
}
#[test]
fn crash_between_slot_acks_and_seal_both_profiles() {
    each(|mut s| {
        let p = Purpose::Schnorr;
        s.slot_put(0, p, 1, vec![1]).unwrap();
        s.checkpoint(0, p).unwrap();
        s.crash_point = Some(CrashPoint::AfterSlotAcks);
        assert_eq!(s.slot_bind(0, p, 1, hash(b"one")), Err(Error::Crashed));
        s.recover_all();
        assert_eq!(s.slot_bind(0, p, 1, hash(b"two")), Err(Error::Conflict));
        clean(&s);
    });
}
#[test]
fn crash_during_restore_both_profiles() {
    each(|mut s| {
        committed(&mut s);
        s.inject(Fault::VmReboot(0));
        s.crash_point = Some(CrashPoint::DuringRestore);
        assert_eq!(s.open(0, Purpose::Schnorr), Err(Error::Crashed));
        assert!(s.nodes[0].ram.sessions.is_empty());
        s.recover_all();
        clean(&s);
    });
}
#[test]
fn blank_tier0_series_never_lowers_fence() {
    each(|mut s| {
        let p = Purpose::Schnorr;
        s.slot_put(0, p, 1, vec![1]).unwrap();
        s.slot_bind(0, p, 1, hash(b"one")).unwrap();
        let id = sid(0, p);
        let v = s.session(0, p).v;
        for peer in 1..s.params.n {
            s.inject(Fault::ReplaceSlot(peer));
            s.recover_all();
            s.post_checkpoint().unwrap();
            assert!(s.nodes[peer].tier0.peers[&(0, id)].pv >= v);
            assert_eq!(s.partial(peer, 0, id, v - 1), Err(Error::StaleVersion));
            assert_eq!(s.nodes[peer].tier0.slots[&(0, p, 1)], hash(b"one"));
            clean(&s);
        }
    });
}
#[test]
fn staggered_reboots_faster_than_checkpoint_cadence() {
    each(|mut s| {
        committed(&mut s);
        for j in 0..=s.params.f {
            s.inject(Fault::VmReboot(j));
            s.recover_all();
            clean(&s);
        }
        assert!(s.nodes.iter().all(|n| n.ram.whole_restart == Some(true)));
        s.post_checkpoint().unwrap();
        assert!(s.ledger.cp.as_ref().unwrap().h >= s.params.b);
    });
}
