// Regression tests of Quint finding G5 (item 26, DECISIONS 54, O38) on the prototype.
//
// History: these two tests were the prototype counterexample of G5. On wt-proto 7953331
// (old rule) the seizure's admit vote returned Err(SlotTaken), and the lapse of the
// unauthorized envelope left the guardian slot Burned. Item 11 adopted DECISIONS 54 in
// impl/ (merge 0a7900a); the asserts are inverted and check the fixed rule: an ECDSA slot
// takes precedence only from an authorization in force, and it burns only when the
// request that reserved it ends.
//
// Run: cd impl && cargo test --release --test g5_prototype_counterexample
// (impl/tests/g5_prototype_counterexample.rs includes this file with #[path]).
use line_dealing::board::Committee;
use line_dealing::split::profile::*;
use line_dealing::split::state::*;
use std::collections::BTreeMap;

fn d(n: u8) -> Digest {
    [n; 32]
}
fn apply(b: &mut SplitBoard, h: u64, e: Event) -> Result<(), SplitError> {
    let result = b.apply(h, e);
    b.check_invariants().unwrap();
    result
}
fn board() -> SplitBoard {
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 256, false, false).unwrap();
    let pool = PoolCheckpoint {
        h: 0,
        pending_min: 1,
        pending_root: d(0),
        pending_count: 0,
        pending: BTreeMap::new(),
        pending_verified: true,
    };
    let pools = BTreeMap::from([(
        PoolId {
            suite: Suite::Bip340,
            epoch: 1,
        },
        pool,
    )]);
    apply(&mut b, 0, Event::Checkpoint { pools }).unwrap();
    b
}
fn p2() -> Charter {
    Charter {
        profile: Profile::P2 {
            exit: d(90),
            registry: d(91),
            delta_hold: 2,
            owner_checks: OwnerChecks::default(),
        },
        board_first: false,
    }
}
const GUARDIAN_SLOTS: [SlotId; 2] = [
    SlotId::Ecdsa { record: [210; 32] },
    SlotId::Ecdsa { record: [211; 32] },
];
// The ECDSA header of the G5 counterexample: a P2 record, two variants on the
// guardian slots, with the user (owner) or the guardians (seizure) as source.
fn g5_header(id: u8, source: Source) -> Header {
    let slots = GUARDIAN_SLOTS.to_vec();
    Header {
        hash: d(id + 80),
        selection_rule: d(250),
        charter: p2(),
        source,
        record: d(id + 100),
        nf: d(id + 120),
        pin: d(id + 140),
        outputs: vec![match source {
            Source::Seizure => d(91),
            _ => d(99),
        }],
        checks: SourceEvidence::verified(),
        suite: Suite::Ecdsa,
        variants: 2,
        inputs: 1,
        tickets: (1..=2)
            .map(|v| Ticket {
                variant: v,
                generation: 0,
                input: 1,
                slot: slots[usize::from(v - 1)],
                digest: d(200 + v as u8),
                in_source_root: true,
            })
            .collect(),
        slots,
        actors: vec![],
        embedded: vec![],
        valid: true,
    }
}
fn opened(b: &mut SplitBoard, id: u8, header: Header) {
    let height = b.height.max(1);
    let envelope = Envelope {
        eid: d(id),
        hd: d(id + 20),
        dd: d(id + 40),
        auth_ref: d(id + 60),
        epoch: 1,
        exp: height + 99,
        checks: PublicChecks::verified(),
    };
    apply(b, height, Event::Post { envelope }).unwrap();
    let eid = d(id);
    apply(
        b,
        height,
        Event::Order {
            eid,
            qc_verified: true,
        },
    )
    .unwrap();
    for node in 1..=3 {
        let e = Event::HeaderPartial {
            eid,
            node,
            share_verified: true,
        };
        apply(b, height, e).unwrap();
    }
    let header = Box::new(header);
    apply(b, height, Event::SeeHeader { eid, header }).unwrap();
}
fn auth(b: &mut SplitBoard, id: u8) {
    let height = b.height.max(1);
    let eid = d(id);
    apply(
        b,
        height,
        Event::Authorize {
            eid,
            verified: true,
        },
    )
    .unwrap();
    let e = Event::AuthFinal {
        eid,
        midnight_height: 10,
        verified: true,
    };
    apply(b, height, e).unwrap();
}
fn admit_vote(b: &mut SplitBoard, id: u8, node: u16) -> Result<(), SplitError> {
    let e = Event::VoteAdmit {
        eid: d(id),
        node,
        header_hash: d(id + 80),
        obs: Observation {
            host_height: 101,
            midnight_height: 10,
        },
    };
    apply(b, 2, e)
}

// Old rule: the seizure's admit vote returned Err(SlotTaken). Fixed rule: the
// user's envelope (ordered first, never authorized) takes no precedence; the
// seizure request takes the slots and is admitted.
#[test]
fn g5_unauthorized_namer_does_not_void_the_seizure() {
    let mut b = board();
    opened(&mut b, 2, g5_header(2, Source::Owner));
    opened(&mut b, 1, g5_header(1, Source::Seizure));
    auth(&mut b, 1);
    for slot in GUARDIAN_SLOTS {
        assert_eq!(b.slot(&slot), SlotState::Named(d(1)));
    }
    for node in 1..=3 {
        assert_eq!(admit_vote(&mut b, 1, node), Ok(()));
    }
    assert!(b.request(&d(1)).unwrap().admitted);
    for slot in GUARDIAN_SLOTS {
        assert_eq!(b.slot(&slot), SlotState::Claimed(d(1)));
    }
}

// Old rule: after the lapse the guardian slot was Burned. Fixed rule: the lapse
// of an envelope with no authorization in force burns no ECDSA slot.
#[test]
fn g5_unauthorized_namer_burns_no_guardian_slot() {
    let mut b = board();
    opened(&mut b, 2, g5_header(2, Source::Owner));
    apply(&mut b, 11, Event::Lapse { eid: d(2) }).unwrap();
    assert!(b.request(&d(2)).unwrap().lapsed);
    for slot in GUARDIAN_SLOTS {
        assert_eq!(b.slot(&slot), SlotState::Free);
    }
}
