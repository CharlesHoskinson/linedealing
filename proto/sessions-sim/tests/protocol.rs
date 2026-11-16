use sessions_sim::{hash, CrashPoint, Error, Fault, Params, Purpose, Sim, Slot};

#[test]
fn deterministic_demo() {
    let mut a = Sim::new(Params::new(4, 1), 19);
    let mut b = Sim::new(Params::new(4, 1), 19);
    a.run(8);
    b.run(8);
    assert_eq!(a.trace, b.trace);
    assert!(a.oracle.violations.is_empty(), "{:?}", a.oracle.violations);
}

#[test]
fn durable_before_witness_and_restore() {
    for (n, f) in [(4, 1), (7, 2)] {
        let mut s = Sim::new(Params::new(n, f), 7);
        s.put(0, Purpose::Schnorr, "key", b"secret".to_vec())
            .unwrap();
        s.crash_point = Some(CrashPoint::AfterFsync);
        assert_eq!(s.checkpoint(0, Purpose::Schnorr), Err(Error::Crashed));
        assert!(!s.nodes[0].disk.local.is_empty());
        s.recover_all();
        assert_eq!(
            s.session(0, Purpose::Schnorr).work.entries["key"],
            b"secret"
        );
        assert!(s.oracle.violations.is_empty());
    }
}

#[test]
fn basic_slot_rules() {
    let mut s = Sim::new(Params::new(4, 1), 3);
    let p = Purpose::Schnorr;
    s.slot_put(0, p, 1, vec![7]).unwrap();
    let d = hash(b"ticket");
    assert!(!s.release(0, p, 1, d));
    s.slot_bind(0, p, 1, d).unwrap();
    assert!(s.release(0, p, 1, d));
    assert_eq!(
        s.slot_bind(0, p, 1, hash(b"other")),
        Err(Error::SlotBoundOther)
    );
    s.slot_burn(0, p, 1).unwrap();
    assert_eq!(s.session(0, p).work.slots[&1], Slot::Burned);
    assert_eq!(s.slot_bind(0, p, 1, d), Err(Error::SlotBurned));
    s.inject(Fault::VmReboot(0));
    s.recover_all();
    assert!(!s.release(0, p, 1, d));
    assert!(s.oracle.violations.is_empty());
}

#[test]
fn first_covered_tag_wins_and_seats_are_independent() {
    use sessions_sim::{board::Entry, node::put_digest};
    let mut s = Sim::new(Params::new(4, 1), 731);
    let p = Purpose::Ecdsa;
    let share = vec![7; 64];
    s.slot_put(0, p, 1, share.clone()).unwrap();
    s.slot_put(1, p, 2, share.clone()).unwrap();
    let first = s.session(0, p).work.put_tags[&1];
    let other = s.session(1, p).work.put_tags[&2];
    assert_ne!(first, other);
    // Low-level adversarial log fixture: another tag later in board order.
    s.board.post(
        0,
        Entry::Put {
            digest: put_digest(&share),
            tag: other,
        },
    );
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 1, hash(b"d")).unwrap();
    s.slot_bind(1, p, 2, hash(b"d")).unwrap();
    assert!(s.release(0, p, 1, hash(b"d")));
    assert!(s.release(1, p, 2, hash(b"d")));
    // An old body with a different tag cannot claim this seat's first covered put.
    s.nodes[0]
        .ram
        .sessions
        .get_mut(&p)
        .unwrap()
        .work
        .slots
        .insert(3, Slot::Free(share.clone()));
    s.nodes[0]
        .ram
        .sessions
        .get_mut(&p)
        .unwrap()
        .work
        .put_tags
        .insert(3, other);
    s.nodes[0].tier0.conflicted.insert((0, p, 3));
    let before = s.session(0, p).work.clone();
    let log = s.board.logs[0].clone();
    assert_eq!(s.slot_bind(0, p, 3, hash(b"d2")), Err(Error::SlotUsed));
    assert_eq!(s.session(0, p).work, before);
    assert_eq!(s.board.logs[0], log);
    assert_eq!(s.slot_put(0, p, 1, share.clone()), Err(Error::SlotExists));
    s.slot_burn(0, p, 1).unwrap();
    assert_eq!(s.slot_put(0, p, 1, share.clone()), Err(Error::SlotBurned));
    assert_eq!(s.slot_bind(0, p, 1, hash(b"d")), Err(Error::SlotBurned));
    assert_eq!(s.slot_put(0, p, 4, share), Err(Error::SlotUsed));
}

#[test]
fn driver_covers_pending_puts_at_scheduled_checkpoint() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    s.run(4);
    assert!(s
        .oracle
        .releases
        .keys()
        .any(|(_, p, _)| *p == Purpose::Ecdsa));
    assert!(s.oracle.violations.is_empty());
}
