use line_dealing::board::Committee;
use line_dealing::split::profile::*;
use line_dealing::split::state::*;

fn d(n: u8) -> Digest {
    [n; 32]
}
fn charter() -> Charter {
    Charter {
        profile: Profile::P1 {
            exit: d(90),
            owner_checks: OwnerChecks::default(),
        },
        board_first: false,
    }
}
fn board() -> SplitBoard {
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 256, false, false).unwrap();
    apply(&mut b, 0, checkpoint()).unwrap();
    b
}
fn checkpoint() -> Event {
    Event::Checkpoint {
        pools: std::collections::BTreeMap::from([(
            PoolId {
                suite: Suite::Bip340,
                epoch: 1,
            },
            PoolCheckpoint {
                h: 0,
                pending_min: 1,
                pending_root: d(0),
                pending_count: 0,
                pending: std::collections::BTreeMap::new(),
                pending_verified: true,
            },
        )]),
    }
}
fn envelope(id: u8) -> Envelope {
    Envelope {
        eid: d(id),
        hd: d(id + 20),
        dd: d(id + 40),
        auth_ref: d(id + 60),
        epoch: 1,
        exp: 100,
        checks: PublicChecks::verified(),
    }
}
fn header(id: u8, slots: Vec<SlotId>) -> Header {
    Header {
        hash: d(id + 80),
        selection_rule: d(250),
        charter: charter(),
        source: Source::Owner,
        record: d(id + 100),
        nf: d(id + 120),
        pin: d(id + 140),
        outputs: vec![d(99)],
        checks: SourceEvidence::verified(),
        suite: Suite::Bip340,
        variants: 2,
        inputs: 1,
        slots,
        tickets: vec![
            Ticket {
                variant: 1,
                generation: 1,
                input: 1,
                slot: SlotId::Schnorr {
                    suite: Suite::Bip340,
                    epoch: 1,
                    index: u64::from(id),
                },
                digest: d(201),
                in_source_root: true,
            },
            Ticket {
                variant: 2,
                generation: 1,
                input: 1,
                slot: SlotId::Schnorr {
                    suite: Suite::Bip340,
                    epoch: 1,
                    index: u64::from(id),
                },
                digest: d(202),
                in_source_root: true,
            },
            Ticket {
                variant: 2,
                generation: 2,
                input: 1,
                slot: SlotId::Schnorr {
                    suite: Suite::Bip340,
                    epoch: 1,
                    index: u64::from(id + 10),
                },
                digest: d(203),
                in_source_root: true,
            },
        ],
        actors: vec![],
        embedded: vec![],
        valid: true,
    }
}
fn slots(id: u8) -> Vec<SlotId> {
    [id, id + 10]
        .into_iter()
        .map(|x| SlotId::Schnorr {
            suite: Suite::Bip340,
            epoch: 1,
            index: u64::from(x),
        })
        .collect()
}
fn apply(b: &mut SplitBoard, h: u64, e: Event) -> Result<(), SplitError> {
    let result = b.apply(h, e);
    b.check_invariants().unwrap();
    result
}
fn opened(b: &mut SplitBoard, id: u8, header: Header) {
    let height = b.height.max(1);
    let mut e = envelope(id);
    e.exp = height + 99;
    apply(b, height, Event::Post { envelope: e }).unwrap();
    apply(
        b,
        height,
        Event::Order {
            eid: d(id),
            qc_verified: true,
        },
    )
    .unwrap();
    for node in 1..=3 {
        apply(
            b,
            height,
            Event::HeaderPartial {
                eid: d(id),
                node,
                share_verified: true,
            },
        )
        .unwrap();
    }
    apply(
        b,
        height,
        Event::SeeHeader {
            eid: d(id),
            header: Box::new(header),
        },
    )
    .unwrap();
}
fn auth(b: &mut SplitBoard, id: u8) {
    let height = b.height.max(1);
    apply(
        b,
        height,
        Event::Authorize {
            eid: d(id),
            verified: true,
        },
    )
    .unwrap();
    apply(
        b,
        height,
        Event::AuthFinal {
            eid: d(id),
            midnight_height: 10,
            verified: true,
        },
    )
    .unwrap();
}
fn admit(b: &mut SplitBoard, id: u8, height: u64) {
    for node in 1..=3 {
        apply(
            b,
            height,
            Event::VoteAdmit {
                eid: d(id),
                node,
                header_hash: d(id + 80),
                obs: Observation {
                    host_height: 100 + u64::from(node),
                    midnight_height: 10,
                },
            },
        )
        .unwrap();
    }
}
fn release(b: &mut SplitBoard, id: u8, node: u16, h: u64) {
    apply(
        b,
        h,
        Event::Release {
            eid: d(id),
            node,
            generation: 1,
            variant: 1,
            tickets: vec![d(201)],
            selection_verified: true,
            checks_verified: true,
            midnight_height: 12,
            not_revoked_verified: true,
        },
    )
    .unwrap();
}
#[test]
fn single_user_two_commits_and_final() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    assert_eq!(b.request(&d(1)).unwrap().anchors[&1].host_height, 102);
    for node in 1..=3 {
        release(&mut b, 1, node, 2);
    }
    assert_eq!(
        b.request(&d(1)).unwrap().state,
        State::Released {
            generation: 1,
            variant: 1
        }
    );
    for node in 1..=3 {
        apply(
            &mut b,
            3,
            Event::Final {
                eid: d(1),
                epoch: 1,
                node,
                ciphertext: d(240),
            },
        )
        .unwrap();
    }
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::Successor(d(240)))
    );
    assert_eq!(b.erasures().len(), 1);
}
#[test]
fn copied_slots_cannot_win_by_authorizing_first() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    let mut copy = header(2, slots(1));
    copy.tickets = header(1, slots(1)).tickets;
    opened(&mut b, 2, copy);
    auth(&mut b, 2);
    assert_eq!(
        apply(
            &mut b,
            2,
            Event::VoteAdmit {
                eid: d(2),
                node: 1,
                header_hash: d(82),
                obs: Observation {
                    host_height: 100,
                    midnight_height: 10
                }
            }
        ),
        Err(SplitError::SlotTaken)
    );
    for node in 1..=2 {
        apply(
            &mut b,
            2,
            Event::Void {
                eid: d(2),
                epoch: 1,
                node,
                reason: VoidReason::SlotTaken,
            },
        )
        .unwrap();
    }
    assert_eq!(b.slot(&slots(1)[0]), SlotState::Named(d(1)));
}
#[test]
fn profile_recovery_and_seizure_rules() {
    let mut c = charter();
    assert!(c
        .check(Source::Recovery, &[d(90)], SourceEvidence::default())
        .is_ok());
    assert_eq!(
        c.check(Source::Seizure, &[d(91)], SourceEvidence::verified()),
        Err(ProfileError::Source)
    );
    c.profile = Profile::P2 {
        exit: d(90),
        registry: d(91),
        delta_hold: 2,
        owner_checks: OwnerChecks::default(),
    };
    assert!(c
        .check(Source::Seizure, &[d(91)], SourceEvidence::verified())
        .is_ok());
    assert_eq!(
        c.check(Source::Seizure, &[d(91), d(92)], SourceEvidence::verified()),
        Err(ProfileError::Destination)
    );
    c.board_first = true;
    assert_eq!(c.validate(), Err(ProfileError::BoardFirst));
}

fn admit_vote(id: u8, node: u16) -> Event {
    Event::VoteAdmit {
        eid: d(id),
        node,
        header_hash: d(id + 80),
        obs: Observation {
            host_height: 100 + u64::from(node),
            midnight_height: 10,
        },
    }
}
fn bf(id: u8, valid: bool) -> Event {
    Event::BoardFirstCall {
        eid: d(id),
        proof_verified: valid,
        finalized_root: true,
        unused_nf: true,
        root_height: 10,
        midnight_height: 12,
        max_root_age: 5,
        relay_margin: 2,
    }
}
fn contribution(frame: u8, actor: u16) -> Event {
    Event::Contribute {
        contribution: Contribution {
            frame: d(frame),
            epoch: 1,
            dd: d(frame),
            target_hd: d(21),
            actor,
            digest: d(frame),
            verified: true,
        },
    }
}
fn void(b: &mut SplitBoard, id: u8, reason: VoidReason, height: u64) {
    for node in 1..=2 {
        apply(
            b,
            height,
            Event::Void {
                eid: d(id),
                epoch: 1,
                node,
                reason,
            },
        )
        .unwrap();
    }
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

#[test]
fn collection_holds_early_frames_and_waits_for_opened_quorum() {
    let mut b = board();
    apply(&mut b, 0, contribution(180, 1)).unwrap();
    let mut h = header(1, slots(1));
    h.actors = vec![1, 2];
    opened(&mut b, 1, h);
    assert_eq!(b.request(&d(1)).unwrap().contributions[&1], d(180));
    auth(&mut b, 1);
    assert_eq!(
        apply(&mut b, 2, admit_vote(1, 1)),
        Err(SplitError::Collection)
    );
    for node in 1..=3 {
        apply(
            &mut b,
            2,
            Event::VoteOpened {
                eid: d(1),
                node,
                header_hash: d(81),
            },
        )
        .unwrap();
    }
    assert_eq!(b.slot(&slots(1)[0]), SlotState::Reserved(d(1)));
    apply(&mut b, 3, contribution(181, 2)).unwrap();
    apply(&mut b, 3, contribution(182, 2)).unwrap();
    assert_eq!(b.request(&d(1)).unwrap().contributions[&2], d(181));
    admit(&mut b, 1, 4);
    assert_eq!(b.slot(&slots(1)[0]), SlotState::Claimed(d(1)));
}
#[test]
fn complained_frame_detaches_and_late_frames_are_ignored() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.actors = vec![1, 2];
    opened(&mut b, 1, h);
    auth(&mut b, 1);
    apply(&mut b, 2, contribution(180, 1)).unwrap();
    apply(
        &mut b,
        2,
        Event::ContributionComplaint {
            frame: d(180),
            verified: true,
        },
    )
    .unwrap();
    assert!(b.request(&d(1)).unwrap().contributions.is_empty());
    apply(&mut b, 3, contribution(181, 1)).unwrap();
    assert_eq!(b.request(&d(1)).unwrap().contributions[&1], d(181));
    apply(&mut b, 12, contribution(182, 2)).unwrap();
    assert!(!b.request(&d(1)).unwrap().contributions.contains_key(&2));
    assert!(b.request(&d(1)).unwrap().stalled);
}
#[test]
fn embedded_contributions_use_two_commit_path() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.actors = vec![1, 2];
    h.embedded = vec![1, 2];
    opened(&mut b, 1, h);
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    assert!(b.request(&d(1)).unwrap().opened_votes.is_empty());
    assert!(b.request(&d(1)).unwrap().admitted);
}
#[test]
fn board_first_verifies_before_claiming_nullifier_and_checkpoints_pending() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.charter.board_first = true;
    opened(&mut b, 1, h);
    assert_eq!(apply(&mut b, 1, bf(1, false)), Err(SplitError::Evidence));
    assert!(b.pending().is_empty());
    let mut h = header(2, slots(2));
    h.charter.board_first = true;
    h.nf = d(121);
    opened(&mut b, 2, h);
    apply(&mut b, 1, bf(2, true)).unwrap();
    assert_eq!(apply(&mut b, 1, bf(1, true)), Err(SplitError::Nullifier));
    apply(&mut b, 1, checkpoint()).unwrap();
    assert_eq!(b.checkpoint.as_ref().unwrap().pending[&d(121)], d(2));
    admit(&mut b, 2, 2);
    release(&mut b, 2, 1, 2);
    assert!(b.request(&d(2)).unwrap().auth_final.is_none());
    apply(
        &mut b,
        2,
        Event::Rotate {
            epoch: 2,
            committee: Committee { n: 7, f: 2 },
        },
    )
    .unwrap();
    assert_eq!(b.pending()[&d(121)], d(2));
}
#[test]
fn board_first_rejects_stale_roots_direct_calls_and_stateful_charters() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.charter.board_first = true;
    opened(&mut b, 1, h);
    apply(
        &mut b,
        1,
        Event::Authorize {
            eid: d(1),
            verified: true,
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::AuthFinal {
                eid: d(1),
                midnight_height: 10,
                verified: true
            }
        ),
        Err(SplitError::Authorization)
    );
    let stale = Event::BoardFirstCall {
        eid: d(1),
        proof_verified: true,
        finalized_root: true,
        unused_nf: true,
        root_height: 1,
        midnight_height: 10,
        max_root_age: 10,
        relay_margin: 2,
    };
    assert_eq!(apply(&mut b, 1, stale), Err(SplitError::Evidence));
    let c = Charter {
        profile: Profile::P1 {
            exit: d(90),
            owner_checks: OwnerChecks {
                stateful: true,
                ..OwnerChecks::default()
            },
        },
        board_first: true,
    };
    assert_eq!(c.validate(), Err(ProfileError::BoardFirst));
}
#[test]
fn lapse_burns_named_unreserved_slots_permanently() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    apply(&mut b, 11, Event::Lapse { eid: d(1) }).unwrap();
    for slot in slots(1) {
        assert_eq!(b.slot(&slot), SlotState::Burned);
    }
    assert_eq!(
        apply(
            &mut b,
            11,
            Event::Authorize {
                eid: d(1),
                verified: true
            }
        ),
        Ok(())
    );
    assert_eq!(
        apply(
            &mut b,
            11,
            Event::AuthFinal {
                eid: d(1),
                midnight_height: 10,
                verified: true
            }
        ),
        Err(SplitError::Window)
    );
    void(&mut b, 1, VoidReason::AuthorizationRefused, 11);
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::UnspentFreshNullifier)
    );
}
#[test]
fn stalled_is_committed_quorum_predicate_even_with_all_contributions() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.actors = vec![1];
    opened(&mut b, 1, h);
    auth(&mut b, 1);
    for node in 1..=3 {
        apply(
            &mut b,
            2,
            Event::VoteOpened {
                eid: d(1),
                node,
                header_hash: d(81),
            },
        )
        .unwrap();
    }
    apply(&mut b, 2, contribution(180, 1)).unwrap();
    for node in 1..=2 {
        apply(&mut b, 10, admit_vote(1, node)).unwrap();
    }
    apply(&mut b, 11, Event::Stall { eid: d(1) }).unwrap();
    assert_eq!(apply(&mut b, 11, admit_vote(1, 3)), Err(SplitError::Window));
    void(&mut b, 1, VoidReason::Stalled, 11);
    assert_eq!(b.slot(&slots(1)[0]), SlotState::Burned);
    let old_record = d(101);
    let mut h = header(2, slots(2));
    h.record = old_record;
    opened(&mut b, 2, h);
    auth(&mut b, 2);
    admit(&mut b, 2, 12);
    assert!(b.request(&d(2)).unwrap().admitted);
}
#[test]
fn complaint_before_first_admit_blocks_admission_and_voids_by_posts() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    apply(
        &mut b,
        2,
        Event::Complaint {
            eid: d(1),
            verified: true,
        },
    )
    .unwrap();
    assert_eq!(
        apply(&mut b, 2, admit_vote(1, 1)),
        Err(SplitError::Evidence)
    );
    void(&mut b, 1, VoidReason::ShareComplaint, 2);
    assert_eq!(
        b.request(&d(1)).unwrap().state,
        State::Void(VoidReason::ShareComplaint)
    );
}
#[test]
fn complaint_after_first_admit_only_records_dealer_fault() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    apply(&mut b, 2, admit_vote(1, 1)).unwrap();
    apply(
        &mut b,
        2,
        Event::Complaint {
            eid: d(1),
            verified: true,
        },
    )
    .unwrap();
    void(&mut b, 1, VoidReason::ShareComplaint, 2);
    for node in 2..=3 {
        apply(&mut b, 2, admit_vote(1, node)).unwrap();
    }
    assert!(b.request(&d(1)).unwrap().admitted);
    assert!(!b.request(&d(1)).unwrap().dealer_faults.is_empty());
}
#[test]
fn release_then_void_or_expiry_keeps_record_pin_even_across_retry() {
    for expire in [false, true] {
        let mut b = board();
        opened(&mut b, 1, header(1, slots(1)));
        auth(&mut b, 1);
        admit(&mut b, 1, 2);
        release(&mut b, 1, 1, 2);
        if expire {
            apply(&mut b, 100, Event::Expire { eid: d(1) }).unwrap();
        } else {
            void(&mut b, 1, VoidReason::FailedContribution, 3);
        }
        assert_eq!(
            b.request(&d(1)).unwrap().settlement,
            Some(Settlement::Released { pin: d(141) })
        );
        let mut wrong = header(2, slots(2));
        wrong.record = d(101);
        opened(&mut b, 2, wrong);
        assert_eq!(
            apply(
                &mut b,
                b_height(expire, 3),
                Event::Authorize {
                    eid: d(2),
                    verified: true
                }
            ),
            Err(SplitError::Pin)
        );
        let mut good = header(3, slots(3));
        good.record = d(101);
        good.pin = d(141);
        opened(&mut b, 3, good);
        auth(&mut b, 3);
        void(
            &mut b,
            3,
            VoidReason::AuthorizationRefused,
            b_height(expire, 3),
        );
        assert_eq!(
            b.request(&d(3)).unwrap().settlement,
            Some(Settlement::Released { pin: d(141) })
        );
    }
}
fn b_height(expired: bool, otherwise: u64) -> u64 {
    if expired {
        100
    } else {
        otherwise
    }
}
#[test]
fn p2_hold_window_and_obs_use_midnight_heights() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.charter = p2();
    opened(&mut b, 1, h);
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    let rel = |height| Event::Release {
        eid: d(1),
        node: 1,
        generation: 1,
        variant: 1,
        tickets: vec![d(201)],
        selection_verified: true,
        checks_verified: true,
        midnight_height: height,
        not_revoked_verified: true,
    };
    assert_eq!(apply(&mut b, 8, rel(11)), Err(SplitError::Hold));
    apply(
        &mut b,
        8,
        Event::SetHold {
            record: d(101),
            midnight_height: 11,
            held: true,
            verified: true,
        },
    )
    .unwrap();
    apply(
        &mut b,
        8,
        Event::Revoke {
            eid: d(1),
            midnight_height: 11,
            verified: true,
        },
    )
    .unwrap();
    assert_eq!(apply(&mut b, 8, rel(12)), Err(SplitError::Revoked));
    void(&mut b, 1, VoidReason::Revoked, 8);
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::UnspentFreshNullifier)
    );
}
#[test]
fn p2_no_release_on_held_record_and_seizure_still_allowed() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.charter = p2();
    opened(&mut b, 1, h);
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    apply(
        &mut b,
        2,
        Event::SetHold {
            record: d(101),
            midnight_height: 12,
            held: true,
            verified: true,
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut b,
            2,
            Event::Release {
                eid: d(1),
                node: 1,
                generation: 1,
                variant: 1,
                tickets: vec![d(201)],
                selection_verified: true,
                checks_verified: true,
                midnight_height: 12,
                not_revoked_verified: true
            }
        ),
        Err(SplitError::Hold)
    );
    let c = p2();
    let mut evidence = SourceEvidence::verified();
    evidence.hold_clear = false;
    assert_eq!(
        c.check(Source::Recovery, &[d(90)], evidence),
        Err(ProfileError::Hold)
    );
    assert!(c.check(Source::Seizure, &[d(91)], evidence).is_ok());
}
#[test]
fn gen_two_is_bounded_and_requires_newer_anchor_and_higher_variant() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    release(&mut b, 1, 1, 2);
    for node in 1..=3 {
        apply(
            &mut b,
            3,
            Event::AnchorGen {
                eid: d(1),
                generation: 2,
                node,
                obs: Observation {
                    host_height: 200,
                    midnight_height: 20,
                },
                deadline_verified: true,
            },
        )
        .unwrap();
    }
    let rel = |g, v, tk| Event::Release {
        eid: d(1),
        node: 1,
        generation: g,
        variant: v,
        tickets: vec![d(tk)],
        selection_verified: true,
        checks_verified: true,
        midnight_height: 20,
        not_revoked_verified: true,
    };
    assert_eq!(apply(&mut b, 3, rel(2, 1, 201)), Err(SplitError::Selection));
    apply(&mut b, 3, rel(2, 2, 203)).unwrap();
    assert_eq!(
        apply(&mut b, 3, rel(3, 2, 203)),
        Err(SplitError::Generation)
    );
    assert_eq!(apply(&mut b, 3, rel(1, 2, 202)), Err(SplitError::Selection));
}
#[test]
fn final_and_void_posts_count_per_epoch_without_chain_view_filters() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    apply(
        &mut b,
        2,
        Event::Final {
            eid: d(1),
            epoch: 1,
            node: 1,
            ciphertext: d(200),
        },
    )
    .unwrap();
    apply(
        &mut b,
        2,
        Event::Rotate {
            epoch: 2,
            committee: Committee { n: 7, f: 2 },
        },
    )
    .unwrap();
    for node in 1..=4 {
        apply(
            &mut b,
            2,
            Event::Final {
                eid: d(1),
                epoch: 2,
                node,
                ciphertext: d(200),
            },
        )
        .unwrap();
    }
    assert!(!b.request(&d(1)).unwrap().state.terminal());
    for node in 2..=3 {
        apply(
            &mut b,
            2,
            Event::Final {
                eid: d(1),
                epoch: 1,
                node,
                ciphertext: d(200),
            },
        )
        .unwrap();
    }
    assert_eq!(b.request(&d(1)).unwrap().state, State::Final(d(200)));
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    apply(
        &mut b,
        2,
        Event::Void {
            eid: d(1),
            epoch: 1,
            node: 1,
            reason: VoidReason::AuthorizationRefused,
        },
    )
    .unwrap();
    apply(
        &mut b,
        2,
        Event::Rotate {
            epoch: 2,
            committee: Committee { n: 7, f: 2 },
        },
    )
    .unwrap();
    for node in 1..=2 {
        apply(
            &mut b,
            2,
            Event::Void {
                eid: d(1),
                epoch: 2,
                node,
                reason: VoidReason::AuthorizationRefused,
            },
        )
        .unwrap();
    }
    assert!(!b.request(&d(1)).unwrap().state.terminal());
    apply(
        &mut b,
        2,
        Event::Void {
            eid: d(1),
            epoch: 1,
            node: 2,
            reason: VoidReason::AuthorizationRefused,
        },
    )
    .unwrap();
    assert!(b.request(&d(1)).unwrap().state.terminal());
}
#[test]
fn public_checks_bind_auth_ref_and_deduplicate_ordered_dealings() {
    for i in 0..6 {
        let mut b = board();
        let mut e = envelope(1);
        match i {
            0 => e.checks.frame = false,
            1 => e.checks.version = false,
            2 => e.checks.epoch = false,
            3 => e.checks.keylist = false,
            4 => e.checks.expiry = false,
            _ => {
                e.auth_ref = d(199);
                e.eid = d(199);
                e.checks.pi_binds_eid = false;
            }
        }
        assert_eq!(
            apply(&mut b, 1, Event::Post { envelope: e }),
            Err(SplitError::PublicChecks)
        );
    }
    let mut b = board();
    let e = envelope(1);
    let mut copy = envelope(2);
    copy.dd = e.dd;
    apply(&mut b, 1, Event::Post { envelope: e }).unwrap();
    apply(
        &mut b,
        1,
        Event::Post {
            envelope: copy.clone(),
        },
    )
    .unwrap();
    apply(
        &mut b,
        1,
        Event::Order {
            eid: d(1),
            qc_verified: true,
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::Order {
                eid: d(2),
                qc_verified: true
            }
        ),
        Err(SplitError::DuplicateDealing)
    );
    copy.eid = d(3);
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::Post {
                envelope: copy.clone()
            }
        ),
        Err(SplitError::DuplicateDealing)
    );
    apply(
        &mut b,
        1,
        Event::Rotate {
            epoch: 2,
            committee: Committee { n: 4, f: 1 },
        },
    )
    .unwrap();
    copy.epoch = 2;
    apply(&mut b, 1, Event::Post { envelope: copy }).unwrap();
    apply(
        &mut b,
        1,
        Event::Order {
            eid: d(3),
            qc_verified: true,
        },
    )
    .unwrap();
}
#[test]
fn admission_requires_finality_matching_hash_and_q_distinct_votes() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    apply(
        &mut b,
        1,
        Event::Authorize {
            eid: d(1),
            verified: true,
        },
    )
    .unwrap();
    assert_eq!(
        apply(&mut b, 1, admit_vote(1, 1)),
        Err(SplitError::Authorization)
    );
    auth(&mut b, 1);
    assert_eq!(
        apply(
            &mut b,
            2,
            Event::VoteAdmit {
                eid: d(1),
                node: 1,
                header_hash: d(200),
                obs: Observation {
                    host_height: 1000,
                    midnight_height: 999
                }
            }
        ),
        Err(SplitError::HeaderHash)
    );
    apply(&mut b, 2, admit_vote(1, 1)).unwrap();
    assert_eq!(
        apply(&mut b, 2, admit_vote(1, 1)),
        Err(SplitError::AlreadyVoted)
    );
    assert!(b.request(&d(1)).unwrap().anchors.is_empty());
    for node in 2..=3 {
        apply(&mut b, 2, admit_vote(1, node)).unwrap();
    }
    assert_eq!(b.request(&d(1)).unwrap().anchors[&1].midnight_height, 10);
}

#[test]
fn later_header_cannot_burn_slots_while_earlier_header_is_unresolved() {
    let mut b = board();
    for id in [1, 2] {
        apply(
            &mut b,
            1,
            Event::Post {
                envelope: envelope(id),
            },
        )
        .unwrap();
        apply(
            &mut b,
            1,
            Event::Order {
                eid: d(id),
                qc_verified: true,
            },
        )
        .unwrap();
        for node in 1..=3 {
            apply(
                &mut b,
                1,
                Event::HeaderPartial {
                    eid: d(id),
                    node,
                    share_verified: true,
                },
            )
            .unwrap();
        }
    }
    let mut copy = header(2, slots(1));
    copy.tickets = header(1, slots(1)).tickets;
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::SeeHeader {
                eid: d(2),
                header: Box::new(copy.clone())
            }
        ),
        Err(SplitError::EarlierHeader)
    );
    apply(
        &mut b,
        1,
        Event::SeeHeader {
            eid: d(1),
            header: Box::new(header(1, slots(1))),
        },
    )
    .unwrap();
    apply(
        &mut b,
        1,
        Event::SeeHeader {
            eid: d(2),
            header: Box::new(copy),
        },
    )
    .unwrap();
    void(&mut b, 2, VoidReason::SlotTaken, 2);
    assert_eq!(b.slot(&slots(1)[0]), SlotState::Named(d(1)));
}
#[test]
fn lapsed_unopened_request_cannot_claim_slots_later() {
    let mut b = board();
    apply(
        &mut b,
        1,
        Event::Post {
            envelope: envelope(1),
        },
    )
    .unwrap();
    apply(
        &mut b,
        1,
        Event::Order {
            eid: d(1),
            qc_verified: true,
        },
    )
    .unwrap();
    for node in 1..=3 {
        apply(
            &mut b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node,
                share_verified: true,
            },
        )
        .unwrap();
    }
    apply(&mut b, 11, Event::Lapse { eid: d(1) }).unwrap();
    assert_eq!(
        apply(
            &mut b,
            11,
            Event::SeeHeader {
                eid: d(1),
                header: Box::new(header(1, slots(1)))
            }
        ),
        Err(SplitError::Window)
    );
}

fn tee_opened(b: &mut SplitBoard, h: Header) {
    apply(
        b,
        1,
        Event::Post {
            envelope: envelope(1),
        },
    )
    .unwrap();
    // A proposal without a QC must not permanently pin the open witness.
    apply(
        b,
        1,
        Event::WitnessOpen {
            eid: d(1),
            node: 1,
            position: 999,
            committed: false,
            peers: vec![2, 3],
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node: 1,
                share_verified: true
            }
        ),
        Err(SplitError::NotOrdered)
    );
    apply(
        b,
        1,
        Event::Order {
            eid: d(1),
            qc_verified: true,
        },
    )
    .unwrap();
    let position = b.request(&d(1)).unwrap().order_position.unwrap();
    assert_eq!(
        apply(
            b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node: 1,
                share_verified: true
            }
        ),
        Err(SplitError::Witness)
    );
    for node in 1..=3 {
        let peers = (1..=4).filter(|p| *p != node).take(2).collect();
        apply(
            b,
            1,
            Event::WitnessOpen {
                eid: d(1),
                node,
                position,
                committed: true,
                peers,
            },
        )
        .unwrap();
        apply(
            b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node,
                share_verified: true,
            },
        )
        .unwrap();
    }
    apply(
        b,
        1,
        Event::SeeHeader {
            eid: d(1),
            header: Box::new(h),
        },
    )
    .unwrap();
}
fn witness(midnight_height: u64) -> Event {
    Event::WitnessRelease {
        eid: d(1),
        node: 1,
        generation: 1,
        variant: 1,
        tickets: vec![d(201)],
        peers: vec![2, 3],
        selection_verified: true,
        checks_verified: true,
        midnight_height,
        not_revoked_verified: true,
    }
}
#[test]
fn tee_witness_is_after_anchor_with_distinct_peers_and_one_ticket() {
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 256, true, false).unwrap();
    apply(&mut b, 0, checkpoint()).unwrap();
    tee_opened(&mut b, header(1, slots(1)));
    auth(&mut b, 1);
    assert_eq!(apply(&mut b, 1, witness(12)), Err(SplitError::NoAnchor));
    admit(&mut b, 1, 2);
    assert_eq!(
        apply(
            &mut b,
            2,
            Event::Release {
                eid: d(1),
                node: 1,
                generation: 1,
                variant: 1,
                tickets: vec![d(201)],
                selection_verified: true,
                checks_verified: true,
                midnight_height: 12,
                not_revoked_verified: true
            }
        ),
        Err(SplitError::Witness)
    );
    let mut bad = witness(12);
    if let Event::WitnessRelease { peers, .. } = &mut bad {
        *peers = vec![2, 2];
    }
    assert_eq!(apply(&mut b, 2, bad), Err(SplitError::Witness));
    apply(&mut b, 2, witness(12)).unwrap();
    let mut conflict = witness(12);
    if let Event::WitnessRelease {
        variant, tickets, ..
    } = &mut conflict
    {
        *variant = 2;
        *tickets = vec![d(202)];
    }
    assert_eq!(apply(&mut b, 2, conflict), Err(SplitError::Selection));
    let anchor_pos = b.request(&d(1)).unwrap().anchors[&1].position;
    for (key, entry) in b.witnesses() {
        if matches!(key, WitnessKey::Release { .. } | WitnessKey::Slot { .. }) {
            assert!(entry.position > anchor_pos);
        }
    }
    release(&mut b, 1, 1, 2);
    assert_eq!(
        apply(
            &mut b,
            2,
            Event::WitnessOpen {
                eid: d(1),
                node: 1,
                position: 999,
                committed: false,
                peers: vec![2, 3]
            }
        ),
        Err(SplitError::Witness)
    );
}
#[test]
fn p2_witness_cannot_bypass_hold_window_or_prevent_revocation_void() {
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 256, true, false).unwrap();
    apply(&mut b, 0, checkpoint()).unwrap();
    let mut h = header(1, slots(1));
    h.charter = p2();
    tee_opened(&mut b, h);
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    assert_eq!(apply(&mut b, 2, witness(11)), Err(SplitError::Hold));
    assert!(!b
        .witnesses()
        .keys()
        .any(|k| matches!(k, WitnessKey::Release { .. })));
    apply(
        &mut b,
        2,
        Event::Revoke {
            eid: d(1),
            midnight_height: 11,
            verified: true,
        },
    )
    .unwrap();
    void(&mut b, 1, VoidReason::Revoked, 2);
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::UnspentFreshNullifier)
    );
}
#[test]
fn witnessed_release_without_release_post_locks_settlement() {
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 256, true, false).unwrap();
    apply(&mut b, 0, checkpoint()).unwrap();
    tee_opened(&mut b, header(1, slots(1)));
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    apply(&mut b, 2, witness(12)).unwrap();
    apply(&mut b, 100, Event::Expire { eid: d(1) }).unwrap();
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::Released { pin: d(141) })
    );
}
#[test]
fn slot_anchor_option_requires_matching_final_entry() {
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 256, false, true).unwrap();
    apply(&mut b, 0, checkpoint()).unwrap();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    let release = Event::Release {
        eid: d(1),
        node: 1,
        generation: 1,
        variant: 1,
        tickets: vec![d(201)],
        selection_verified: true,
        checks_verified: true,
        midnight_height: 12,
        not_revoked_verified: true,
    };
    assert_eq!(apply(&mut b, 2, release.clone()), Err(SplitError::Witness));
    apply(
        &mut b,
        2,
        Event::SlotAnchor {
            eid: d(1),
            generation: 1,
            variant: 1,
            tickets: vec![d(201)],
            verified: true,
        },
    )
    .unwrap();
    apply(&mut b, 2, release).unwrap();
}
#[test]
fn ecdsa_ticket_roots_and_variant_slots_are_checked() {
    for source in [Source::Owner, Source::Recovery, Source::Seizure] {
        for in_root in [false, true] {
            let mut b = board();
            let mut h = header(
                1,
                vec![
                    SlotId::Ecdsa { record: d(210) },
                    SlotId::Ecdsa { record: d(211) },
                ],
            );
            h.suite = Suite::Ecdsa;
            h.charter = p2();
            h.source = source;
            h.outputs = vec![match source {
                Source::Owner => d(99),
                Source::Recovery => d(90),
                Source::Seizure => d(91),
            }];
            h.tickets = (1..=2)
                .map(|v| Ticket {
                    variant: v,
                    generation: 0,
                    input: 1,
                    slot: h.slots[usize::from(v - 1)],
                    digest: d(200 + v as u8),
                    in_source_root: in_root,
                })
                .collect();
            opened(&mut b, 1, h);
            let result = apply(
                &mut b,
                1,
                Event::Authorize {
                    eid: d(1),
                    verified: true,
                },
            );
            if in_root {
                result.unwrap();
                auth(&mut b, 1);
                admit(&mut b, 1, 2);
                release(&mut b, 1, 1, 2);
            } else {
                assert_eq!(result, Err(SplitError::Ticket));
            }
        }
    }
}
#[test]
fn failed_release_check_and_verified_combiner_failure_end_requests_safely() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    apply(
        &mut b,
        2,
        Event::Release {
            eid: d(1),
            node: 1,
            generation: 1,
            variant: 1,
            tickets: vec![d(201)],
            selection_verified: true,
            checks_verified: false,
            midnight_height: 12,
            not_revoked_verified: true,
        },
    )
    .unwrap();
    assert!(b.request(&d(1)).unwrap().releases.is_empty());
    void(&mut b, 1, VoidReason::FailedReleaseCheck, 2);
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::UnspentFreshNullifier)
    );
    for reason in [VoidReason::DealerFault, VoidReason::FailedContribution] {
        let mut b = board();
        opened(&mut b, 1, header(1, slots(1)));
        auth(&mut b, 1);
        admit(&mut b, 1, 2);
        release(&mut b, 1, 1, 2);
        assert_eq!(
            apply(
                &mut b,
                2,
                Event::CombinerFailure {
                    eid: d(1),
                    reason,
                    verified: false
                }
            ),
            Err(SplitError::Evidence)
        );
        apply(
            &mut b,
            2,
            Event::CombinerFailure {
                eid: d(1),
                reason,
                verified: true,
            },
        )
        .unwrap();
        assert_eq!(
            b.request(&d(1)).unwrap().settlement,
            Some(Settlement::Released { pin: d(141) })
        );
    }
}
#[test]
fn malformed_slots_and_header_partials_are_rejected() {
    let mut b = board();
    apply(
        &mut b,
        1,
        Event::Post {
            envelope: envelope(1),
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node: 1,
                share_verified: true
            }
        ),
        Err(SplitError::NotOrdered)
    );
    apply(
        &mut b,
        1,
        Event::Order {
            eid: d(1),
            qc_verified: true,
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node: 1,
                share_verified: false
            }
        ),
        Err(SplitError::Evidence)
    );
    for node in 1..=2 {
        apply(
            &mut b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node,
                share_verified: true,
            },
        )
        .unwrap();
    }
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::SeeHeader {
                eid: d(1),
                header: Box::new(header(1, slots(1)))
            }
        ),
        Err(SplitError::Threshold)
    );
    apply(
        &mut b,
        1,
        Event::HeaderPartial {
            eid: d(1),
            node: 3,
            share_verified: true,
        },
    )
    .unwrap();
    let mut h = header(1, slots(1));
    h.slots[1] = h.slots[0];
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::SeeHeader {
                eid: d(1),
                header: Box::new(h)
            }
        ),
        Err(SplitError::Header)
    );
}
#[test]
fn final_needs_one_ciphertext_but_void_posts_can_have_different_reasons() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    for node in 1..=3 {
        apply(
            &mut b,
            2,
            Event::Final {
                eid: d(1),
                epoch: 1,
                node,
                ciphertext: d(node as u8),
            },
        )
        .unwrap();
    }
    assert!(!b.request(&d(1)).unwrap().state.terminal());
    for (node, reason) in [
        (1, VoidReason::Stalled),
        (2, VoidReason::AuthorizationRefused),
    ] {
        apply(
            &mut b,
            2,
            Event::Void {
                eid: d(1),
                epoch: 1,
                node,
                reason,
            },
        )
        .unwrap();
    }
    assert_eq!(
        b.request(&d(1)).unwrap().state,
        State::Void(VoidReason::AuthorizationRefused)
    );
}
fn random(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
#[test]
fn randomized_schedules_replay_and_preserve_invariants() {
    let mut admitted = 0;
    let mut released = 0;
    let mut ended = 0;
    for seed in 1..=400 {
        let mut rng = seed;
        let mut b = board();
        let mut h = header(1, slots(1));
        if seed % 2 == 0 {
            h.actors = vec![1, 2];
        }
        opened(&mut b, 1, h);
        let initial = b.clone();
        let mut log = vec![];
        let mut slots_ever_nonfree = std::collections::BTreeSet::new();
        let mut released_pin = None;
        for step in 0..160 {
            let node = (random(&mut rng) % 5 + 1) as u16;
            let obs = Observation {
                host_height: 100 + random(&mut rng) % 30,
                midnight_height: random(&mut rng) % 20,
            };
            let event = match random(&mut rng) % 20 {
                0 => Event::Authorize {
                    eid: d(1),
                    verified: !random(&mut rng).is_multiple_of(4),
                },
                1 | 2 => Event::AuthFinal {
                    eid: d(1),
                    midnight_height: 10,
                    verified: true,
                },
                3 => Event::VoteOpened {
                    eid: d(1),
                    node,
                    header_hash: d(81),
                },
                4 | 5 => Event::Contribute {
                    contribution: Contribution {
                        frame: d(180 + (step % 40) as u8),
                        epoch: 1,
                        dd: d(180 + (step % 40) as u8),
                        target_hd: d(21),
                        actor: random(&mut rng) as u16 % 2 + 1,
                        digest: d(200),
                        verified: true,
                    },
                },
                6..=8 => Event::VoteAdmit {
                    eid: d(1),
                    node,
                    header_hash: if step % 9 == 0 { d(200) } else { d(81) },
                    obs,
                },
                9..=11 => Event::Release {
                    eid: d(1),
                    node,
                    generation: 1,
                    variant: 1,
                    tickets: vec![d(201)],
                    selection_verified: true,
                    checks_verified: true,
                    midnight_height: 12,
                    not_revoked_verified: true,
                },
                12 if step > 110 => Event::Complaint {
                    eid: d(1),
                    verified: true,
                },
                13 if step > 110 => Event::Void {
                    eid: d(1),
                    epoch: if step % 2 == 0 { 1 } else { 2 },
                    node,
                    reason: VoidReason::Stalled,
                },
                14 if step > 100 => Event::Final {
                    eid: d(1),
                    epoch: 1,
                    node,
                    ciphertext: d(230),
                },
                15 if step > 100 => Event::Rotate {
                    epoch: 2,
                    committee: Committee { n: 7, f: 2 },
                },
                16 => checkpoint(),
                17 => Event::ContributionComplaint {
                    frame: d(180 + (step % 40) as u8),
                    verified: true,
                },
                _ => Event::Tick,
            };
            let height = if step >= 155 {
                100
            } else if step >= 120 {
                11
            } else {
                1 + step / 20
            };
            log.push((height, event.clone()));
            let _ = apply(&mut b, height, event);
            for slot in slots(1) {
                if b.slot(&slot) != SlotState::Free {
                    slots_ever_nonfree.insert(slot);
                }
                if slots_ever_nonfree.contains(&slot) {
                    assert_ne!(b.slot(&slot), SlotState::Free);
                }
            }
            let r = b.request(&d(1)).unwrap();
            if !r.releases.is_empty() {
                released_pin = Some(d(141));
            }
            if let Some(pin) = released_pin {
                assert_ne!(r.settlement, Some(Settlement::UnspentFreshNullifier));
                if r.state == State::Expired || matches!(r.state, State::Void(_)) {
                    assert_eq!(r.settlement, Some(Settlement::Released { pin }));
                }
            }
        }
        let r = b.request(&d(1)).unwrap();
        admitted += usize::from(r.admitted);
        released += usize::from(!r.releases.is_empty());
        ended += usize::from(r.state.terminal());
        let mut replay = initial;
        for (height, event) in log {
            let _ = apply(&mut replay, height, event);
        }
        assert_eq!(replay, b, "seed {seed}");
    }
    assert!(admitted > 0 && released > 0);
    assert_eq!(ended, 400);
}

#[test]
fn final_before_local_header_opening_still_settles_as_successor() {
    let mut b = board();
    apply(
        &mut b,
        1,
        Event::Post {
            envelope: envelope(1),
        },
    )
    .unwrap();
    apply(
        &mut b,
        1,
        Event::Order {
            eid: d(1),
            qc_verified: true,
        },
    )
    .unwrap();
    for node in 1..=3 {
        apply(
            &mut b,
            2,
            Event::Final {
                eid: d(1),
                epoch: 1,
                node,
                ciphertext: d(240),
            },
        )
        .unwrap();
    }
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::Successor(d(240)))
    );
}

#[test]
fn deterministic_selection_evidence_is_required_before_witness_or_release() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    admit(&mut b, 1, 2);
    // Variant 2 is in range, but the trusted builder selected variant 1.
    let wrong = Event::Release {
        eid: d(1),
        node: 1,
        generation: 1,
        variant: 2,
        tickets: vec![d(202)],
        selection_verified: false,
        checks_verified: true,
        midnight_height: 12,
        not_revoked_verified: true,
    };
    assert_eq!(apply(&mut b, 2, wrong), Err(SplitError::Selection));
    let mut wrong_witness = witness(12);
    if let Event::WitnessRelease {
        selection_verified, ..
    } = &mut wrong_witness
    {
        *selection_verified = false;
    }
    assert_eq!(apply(&mut b, 2, wrong_witness), Err(SplitError::Selection));
    assert!(b.release_audits().is_empty());
    release(&mut b, 1, 1, 2);
}
#[test]
fn contribution_frames_share_the_epoch_dealing_deduplication_ledger() {
    let mut b = board();
    opened(&mut b, 1, header(1, slots(1)));
    let mut copy = contribution(180, 1);
    if let Event::Contribute { contribution } = &mut copy {
        contribution.dd = d(41);
    }
    assert_eq!(apply(&mut b, 1, copy), Err(SplitError::DuplicateDealing));
    apply(&mut b, 1, contribution(181, 1)).unwrap();
    let mut e = envelope(2);
    e.dd = d(181);
    assert_eq!(
        apply(&mut b, 1, Event::Post { envelope: e }),
        Err(SplitError::DuplicateDealing)
    );
}
#[test]
fn p2_fresh_revocation_view_must_cover_every_obs_midnight_height() {
    let mut b = board();
    let mut h = header(1, slots(1));
    h.charter = p2();
    opened(&mut b, 1, h);
    auth(&mut b, 1);
    for node in 1..=3 {
        apply(
            &mut b,
            2,
            Event::VoteAdmit {
                eid: d(1),
                node,
                header_hash: d(81),
                obs: Observation {
                    host_height: 100,
                    midnight_height: 20 + u64::from(node),
                },
            },
        )
        .unwrap();
    }
    let rel = |midnight_height| Event::Release {
        eid: d(1),
        node: 1,
        generation: 1,
        variant: 1,
        tickets: vec![d(201)],
        selection_verified: true,
        checks_verified: true,
        midnight_height,
        not_revoked_verified: true,
    };
    assert_eq!(apply(&mut b, 2, rel(22)), Err(SplitError::Hold));
    apply(&mut b, 2, rel(23)).unwrap();
    assert_eq!(b.release_audits()[0].required_midnight_height, 23);
    apply(
        &mut b,
        2,
        Event::Revoke {
            eid: d(1),
            midnight_height: 24,
            verified: true,
        },
    )
    .unwrap();
    void(&mut b, 1, VoidReason::Revoked, 2);
    assert!(!b.request(&d(1)).unwrap().state.terminal());
    assert_eq!(
        apply(
            &mut b,
            2,
            Event::AnchorGen {
                eid: d(1),
                generation: 2,
                node: 1,
                obs: Observation {
                    host_height: 200,
                    midnight_height: 24
                },
                deadline_verified: true
            }
        ),
        Err(SplitError::Revoked)
    );
    apply(&mut b, 100, Event::Expire { eid: d(1) }).unwrap();
    assert_eq!(
        b.request(&d(1)).unwrap().settlement,
        Some(Settlement::Released { pin: d(141) })
    );
}
#[test]
fn launch_thresholds_keep_q_six_and_t_seven_separate() {
    let mut b = SplitBoard::new(Committee { n: 9, f: 2 }, 1, 10, 256, false, false).unwrap();
    apply(&mut b, 0, checkpoint()).unwrap();
    apply(
        &mut b,
        1,
        Event::Post {
            envelope: envelope(1),
        },
    )
    .unwrap();
    apply(
        &mut b,
        1,
        Event::Order {
            eid: d(1),
            qc_verified: true,
        },
    )
    .unwrap();
    for node in 1..=6 {
        apply(
            &mut b,
            1,
            Event::HeaderPartial {
                eid: d(1),
                node,
                share_verified: true,
            },
        )
        .unwrap();
    }
    assert_eq!(
        apply(
            &mut b,
            1,
            Event::SeeHeader {
                eid: d(1),
                header: Box::new(header(1, slots(1)))
            }
        ),
        Err(SplitError::Threshold)
    );
    apply(
        &mut b,
        1,
        Event::HeaderPartial {
            eid: d(1),
            node: 7,
            share_verified: true,
        },
    )
    .unwrap();
    apply(
        &mut b,
        1,
        Event::SeeHeader {
            eid: d(1),
            header: Box::new(header(1, slots(1))),
        },
    )
    .unwrap();
    auth(&mut b, 1);
    for node in 1..=6 {
        apply(&mut b, 2, admit_vote(1, node)).unwrap();
    }
    assert!(b.request(&d(1)).unwrap().admitted);
    for node in 1..=6 {
        release(&mut b, 1, node, 2);
    }
    assert_eq!(b.request(&d(1)).unwrap().state, State::Anchored(1));
    release(&mut b, 1, 7, 2);
    assert_eq!(
        b.request(&d(1)).unwrap().state,
        State::Released {
            generation: 1,
            variant: 1
        }
    );
}
#[test]
fn seventeen_node_witness_requires_eleven_distinct_peers_not_q_twelve() {
    let mut b = SplitBoard::new(Committee { n: 17, f: 5 }, 1, 10, 256, true, false).unwrap();
    apply(
        &mut b,
        1,
        Event::Post {
            envelope: envelope(1),
        },
    )
    .unwrap();
    let w = |peers| Event::WitnessOpen {
        eid: d(1),
        node: 1,
        position: 1,
        committed: false,
        peers,
    };
    assert_eq!(
        apply(&mut b, 1, w((2..=11).collect())),
        Err(SplitError::Witness)
    );
    apply(&mut b, 1, w((2..=12).collect())).unwrap();
    assert_eq!(b.witnesses().values().next().unwrap().peers.len(), 11);
}
#[test]
fn p0_and_p1_have_no_hold_checks() {
    for profile in [Profile::P0, charter().profile] {
        let mut b = board();
        let mut h = header(1, slots(1));
        h.charter.profile = profile;
        opened(&mut b, 1, h);
        auth(&mut b, 1);
        admit(&mut b, 1, 2);
        apply(
            &mut b,
            2,
            Event::SetHold {
                record: d(101),
                midnight_height: 999,
                held: true,
                verified: true,
            },
        )
        .unwrap();
        assert_eq!(
            apply(
                &mut b,
                2,
                Event::Revoke {
                    eid: d(1),
                    midnight_height: 999,
                    verified: true
                }
            ),
            Err(SplitError::Profile(ProfileError::Source))
        );
        apply(
            &mut b,
            2,
            Event::Release {
                eid: d(1),
                node: 1,
                generation: 1,
                variant: 1,
                tickets: vec![d(201)],
                selection_verified: true,
                checks_verified: true,
                midnight_height: 0,
                not_revoked_verified: false,
            },
        )
        .unwrap();
    }
}

fn pool_checkpoint(h: u64, pending: &[(u64, u8)]) -> Event {
    let pending: std::collections::BTreeMap<u64, Eid> =
        pending.iter().map(|(index, id)| (*index, d(*id))).collect();
    Event::Checkpoint {
        pools: std::collections::BTreeMap::from([(
            PoolId {
                suite: Suite::Bip340,
                epoch: 1,
            },
            PoolCheckpoint {
                h,
                pending_min: pending.keys().next().copied().unwrap_or(h + 1),
                pending_root: d(0),
                pending_count: pending.len() as u32,
                pending,
                pending_verified: true,
            },
        )]),
    }
}
fn try_admit_vote(b: &mut SplitBoard, id: u8) -> Result<(), SplitError> {
    apply(
        b,
        b.height.max(1),
        Event::VoteAdmit {
            eid: d(id),
            node: 1,
            header_hash: d(id + 80),
            obs: Observation {
                host_height: 101,
                midnight_height: 10,
            },
        },
    )
}
#[test]
fn reservation_window_at_the_vote() {
    // Own pending indices at or below h are votable; foreign ones are taken.
    let mut b = board();
    apply(&mut b, 1, pool_checkpoint(20, &[(1, 1), (11, 1)])).unwrap();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    assert_eq!(try_admit_vote(&mut b, 1), Ok(()));
    opened(&mut b, 2, header(2, slots(2)));
    auth(&mut b, 2);
    assert_eq!(try_admit_vote(&mut b, 2), Err(SplitError::SlotTaken));
    assert!(b.request(&d(2)).unwrap().admit_votes.is_empty());

    // Below pending_min: taken, even when the index looks free.
    let mut b = board();
    apply(&mut b, 1, pool_checkpoint(20, &[(11, 9)])).unwrap();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    assert_eq!(try_admit_vote(&mut b, 1), Err(SplitError::SlotTaken));

    // Above h + B: wait, no vote and no VOID, until a checkpoint moves h.
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 5, false, false).unwrap();
    opened(&mut b, 1, header(1, slots(1)));
    auth(&mut b, 1);
    assert_eq!(try_admit_vote(&mut b, 1), Err(SplitError::Window)); // no checkpoint lists the pool
    apply(&mut b, 1, pool_checkpoint(0, &[])).unwrap();
    assert_eq!(try_admit_vote(&mut b, 1), Err(SplitError::Window)); // index 11 > 0 + 5
    assert!(!b.request(&d(1)).unwrap().state.terminal());
    apply(&mut b, 1, pool_checkpoint(6, &[(1, 1)])).unwrap();
    assert_eq!(try_admit_vote(&mut b, 1), Ok(()));
}
#[test]
fn reservation_window_pools_are_per_suite() {
    // A checkpoint of the BIP340 pool says nothing about the Ed25519 pool.
    let ed = |id: u8| {
        let mut h = header(id, slots(id));
        h.suite = Suite::Ed25519;
        for slot in h
            .slots
            .iter_mut()
            .chain(h.tickets.iter_mut().map(|t| &mut t.slot))
        {
            if let SlotId::Schnorr { suite, .. } = slot {
                *suite = Suite::Ed25519;
            }
        }
        h
    };
    let mut b = board();
    apply(&mut b, 1, pool_checkpoint(30, &[])).unwrap();
    opened(&mut b, 1, ed(1));
    auth(&mut b, 1);
    // The BIP340 floor is 31; the Ed25519 pool has no checkpoint yet: wait.
    assert_eq!(try_admit_vote(&mut b, 1), Err(SplitError::Window));
    let mut pools = match pool_checkpoint(30, &[]) {
        Event::Checkpoint { pools } => pools,
        _ => unreachable!(),
    };
    let mut ed_cp = pools.values().next().unwrap().clone();
    ed_cp.h = 0;
    ed_cp.pending_min = 1;
    pools.insert(
        PoolId {
            suite: Suite::Ed25519,
            epoch: 1,
        },
        ed_cp,
    );
    apply(&mut b, 1, Event::Checkpoint { pools }).unwrap();
    // Indices 1 and 11 are above the Ed25519 floor 0, so they are free.
    assert_eq!(try_admit_vote(&mut b, 1), Ok(()));
}
