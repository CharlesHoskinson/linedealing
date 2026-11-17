//! Item 11: replay of the item 26 split-line traces
//! (`tests/quint-regressions/splitline/`) on the `SplitBoard` reducer.
//!
//! The adapters in `itf_split/proto.rs` (request machine, `splitline.qnt`) and
//! `itf_split/pools.rs` (pools and restarts, `splitline_pools.qnt`) state the
//! projection rules. Each test names one trace and lists every refusal and
//! divergence of its replay:
//! - a design trace (`*Holds`, `sampled/`) replays with no divergence, except
//!   where a comment states why the reducer refuses earlier than the model;
//! - a mutant trace (`*Broken`, `m_*`) must be refused, or the test shows that
//!   the mutated effect is absent from the reducer. Mutant traces of the
//!   request machine replay in mutant mode: the projection compares requests
//!   and admission only, so the replay reaches the step that the mutant
//!   changes.
//!
//! The per-view replay of the forked board of S1 is in
//! `quint_split_conformance.rs`. `every_trace_is_replayed_or_excused` lists the
//! traces that the reducer cannot express, with the reason for each.

mod itf_split;

use itf_split::pools::{self, Pools};
use itf_split::proto::{self, ecdsa_slot, record, Params, Proto, Refusal, N4};
use itf_split::{digest, slot};
use line_dealing::split::profile::ProfileError;
use line_dealing::split::state::*;

type Want<'a> = &'a [(usize, &'a str, Refusal)];

fn same(got: &[proto::Step], want: Want) {
    let got: Vec<_> = got
        .iter()
        .map(|s| (s.index, s.action.as_str(), s.refusal.clone()))
        .collect();
    assert_eq!(got, want.to_vec());
}
fn design(name: &str, p: Params, want: Want) -> Proto {
    let x = proto::replay(name, p);
    same(&x.refusals, want);
    x
}
fn mutant(name: &str, p: Params, want: Want) -> Proto {
    let x = proto::replay_mutant(name, p);
    same(&x.refusals, want);
    x
}
fn pool(name: &str, want: Want) -> Pools {
    let x = pools::replay(name);
    same(&x.refusals, want);
    x
}
fn e(n: u64) -> Eid {
    digest(n)
}
fn split(err: SplitError) -> Refusal {
    Refusal::Split(err)
}
fn taken() -> Refusal {
    Refusal::Split(SplitError::SlotTaken)
}
fn diverged(s: &str) -> Refusal {
    Refusal::Diverged(s.into())
}
fn no_quorum() -> Refusal {
    Refusal::NoEvidence("no quorum of accepted votes")
}
fn vote(x: &Pools, r: u64) -> Event {
    Event::VoteAdmit {
        eid: e(r),
        node: 1,
        header_hash: digest(1000 + r),
        obs: Observation {
            host_height: x.height,
            midnight_height: 0,
        },
    }
}

// ---------------------------------------------------------------- G5 (DECISIONS 54)

// The user's envelope opens but its authorization never comes into force, so
// no honest node runs its admission checks (DECISIONS 68). It lapses.
#[test]
fn gt_design_g5_void_holds() {
    let x = design("gt_design__g5VoidHolds.itf.json", N4, &[]);
    assert_eq!(x.b.slot(&ecdsa_slot(13)), SlotState::Claimed(e(1)));
    assert!(x.b.request(&e(2)).unwrap().lapsed);
}

// ---------------------------------------------------------------- PG1 (DECISIONS 68)

// Request 2 opens before its authorization is final. Precedence is an admission
// check, so SLOT_TAKEN follows only once the authorization is in force.
#[test]
fn pg1_design_open_void_holds() {
    let x = design("pg1_design__pg1OpenVoidHolds.itf.json", N4, &[]);
    assert!(x.b.request(&e(2)).unwrap().in_force());
    assert_eq!(
        x.b.request(&e(2)).unwrap().state,
        State::Void(VoidReason::SlotTaken)
    );
}

// Old reading of §4.7: SLOT_TAKEN at opening, before the authorization. The
// honest node in the reducer has no evidence: the authorization is not in force.
#[test]
fn pg1_m_open_void_broken_is_refused() {
    let x = mutant(
        "pg1_m_open__pg1OpenVoidBroken.itf.json",
        N4,
        &[
            (
                7,
                "voidSlotTaken",
                Refusal::NoEvidence("the authorization is not in force"),
            ),
            (
                7,
                "voidSlotTaken",
                diverged("r2 model Void SLOT_TAKEN, reducer Opened"),
            ),
        ],
    );
    assert!(!x.b.request(&e(2)).unwrap().state.terminal());
}

#[test]
fn gt_design_g5_burn_holds() {
    let x = design("gt_design__g5BurnHolds.itf.json", N4, &[]);
    assert!(x.b.request(&e(2)).unwrap().lapsed);
    assert_eq!(x.b.slot(&ecdsa_slot(13)), SlotState::Claimed(e(1)));
}

// Old rule: the unauthorized namer voids the seizure. No honest node holds
// SLOT_TAKEN evidence: the seizure request has precedence on both slots.
#[test]
fn gt_m_g5_void_broken_is_refused() {
    let x = mutant(
        "gt_m_g5__g5VoidBroken.itf.json",
        N4,
        &[
            (
                9,
                "voidSlotTaken",
                Refusal::NoEvidence("every named slot is free or held by the request"),
            ),
            (
                9,
                "voidSlotTaken",
                diverged("r1 model Void SLOT_TAKEN, reducer Opened"),
            ),
        ],
    );
    assert_eq!(x.b.slot(&ecdsa_slot(13)), SlotState::Named(e(1)));
}

// Old rule: the lapse of the unauthorized envelope burns the guardian slots.
// The reducer lapses it and burns nothing.
#[test]
fn gt_m_g5_burn_broken_burns_nothing() {
    let x = mutant("gt_m_g5__g5BurnBroken.itf.json", N4, &[]);
    assert!(x.b.request(&e(2)).unwrap().lapsed);
    for l in [13, 14] {
        assert_eq!(x.b.slot(&ecdsa_slot(l)), SlotState::Free);
    }
}

// Sampled G5 mutant run. Request 2 names a slot outside its source root, so
// the reducer refuses its authorization (DESIGN §5.3 item 4), and no ECDSA slot
// takes precedence before an authorization is in force.
#[test]
fn g5_m_g5_sampled_names_no_ecdsa_slot_before_authorization() {
    let x = mutant(
        "g5_m_g5_sampled.itf.json",
        N4,
        &[
            (13, "deferred", split(SplitError::Ticket)),
            (13, "deferred", split(SplitError::Evidence)),
        ],
    );
    for l in 11..=16 {
        assert_eq!(x.b.slot(&ecdsa_slot(l)), SlotState::Free);
    }
}

// ---------------------------------------------------------------- QA fixes, hold, revocation, QA-8

#[test]
fn fix_c7_boundary_holds() {
    let x = design("fix__c7BoundaryHolds.itf.json", N4, &[]);
    assert!(x.b.request(&e(1)).unwrap().revoked);
    assert_eq!(x.b.release_audits().len(), 1);
}

#[test]
fn fix_c7_early_hold_stops_holds() {
    let mut x = design("fix__c7EarlyHoldStopsHolds.itf.json", N4, &[]);
    // The model's last step, doRelease(1, 1, 1, 1), fails after the hold.
    let r = x.b.apply(
        x.height,
        Event::Release {
            eid: e(1),
            node: 1,
            generation: 1,
            variant: 1,
            tickets: vec![digest(111)],
            selection_verified: true,
            checks_verified: true,
            midnight_height: x.mid,
            not_revoked_verified: false,
        },
    );
    assert_eq!(r, Err(SplitError::Revoked));
}

#[test]
fn fix_ec_revoke_frees_holds() {
    let x = design("fix__ecRevokeFreesHolds.itf.json", N4, &[]);
    assert_eq!(x.b.slot(&ecdsa_slot(11)), SlotState::Free);
}

#[test]
fn fix_ec_expire_reissue_holds() {
    let x = design("fix__ecExpireReissueHolds.itf.json", N4, &[]);
    assert_eq!(x.b.slot(&ecdsa_slot(11)), SlotState::Claimed(e(3)));
}

// Regression of the restart range burn: before the fix the cold start left
// committee slots 1 to 3 free where the model burns them (step 14).
#[test]
fn fix_cold_final_settles_final_holds() {
    let x = design("fix__coldFinalSettlesFinalHolds.itf.json", N4, &[]);
    assert_eq!(x.b.request(&e(1)).unwrap().state, State::Final(digest(241)));
    assert_eq!(x.b.record_lock(&record(1)), None);
}

#[test]
fn fix_released_repost_holds() {
    let x = design("fix__releasedRepostHolds.itf.json", N4, &[]);
    assert_eq!(x.b.record_lock(&record(1)), Some(digest(7001)));
    assert!(x.b.request(&e(3)).unwrap().in_force());
}

#[test]
fn fix_gen2_after_release_holds() {
    let mut x = design("fix__gen2AfterReleaseHolds.itf.json", N4, &[]);
    // doAnchorGen(1, 2, 2) fails: no partial of generation 1 left.
    let r = x.b.apply(
        x.height,
        Event::AnchorGen {
            eid: e(1),
            generation: 2,
            node: 1,
            obs: Observation {
                host_height: x.height,
                midnight_height: x.mid,
            },
            deadline_verified: true,
        },
    );
    assert_eq!(r, Err(SplitError::Generation));
}

#[test]
fn fix_gen2_anchors_holds() {
    let x = design("fix__gen2AnchorsHolds.itf.json", N4, &[]);
    assert!(x.b.request(&e(1)).unwrap().anchors.contains_key(&2));
}

#[test]
fn fix_p1_guardian_refused_holds() {
    let mut x = design("fix__p1GuardianRefusedHolds.itf.json", N4, &[]);
    // doAuthorize(1) fails: a P1 record has no seizure source.
    let r = x.b.apply(
        x.height,
        Event::Authorize {
            eid: e(1),
            verified: true,
        },
    );
    assert_eq!(r, Err(SplitError::Profile(ProfileError::Source)));
}

// QA-6: the reducer refuses the authorization of a header that names slots of
// another record (DESIGN §5.3 item 4); the model refuses the vote.
#[test]
fn rt_design_slot_root_holds() {
    let mut x = design(
        "rt_design__slotRootHolds.itf.json",
        N4,
        &[
            (3, "authorize", split(SplitError::Ticket)),
            (4, "authFinal", split(SplitError::Evidence)),
        ],
    );
    let r = x.b.apply(
        x.height,
        Event::VoteAdmit {
            eid: e(1),
            node: 1,
            header_hash: digest(1001),
            obs: Observation {
                host_height: x.height,
                midnight_height: x.mid,
            },
        },
    );
    assert_eq!(r, Err(SplitError::Ticket));
}

#[test]
fn rt_m_slot_root_broken_is_refused() {
    let x = mutant(
        "rt_m_slot_root__slotRootBroken.itf.json",
        N4,
        &[
            (3, "authorize", split(SplitError::Ticket)),
            (4, "authFinal", split(SplitError::Evidence)),
            (7, "voteAdmit", split(SplitError::Ticket)),
            (8, "voteAdmit", split(SplitError::Ticket)),
            (9, "voteAdmit", split(SplitError::Ticket)),
            (9, "voteAdmit", diverged("r1 admitted differs")),
        ],
    );
    assert!(x.b.release_audits().is_empty());
}

// QA-7 design run: the owner's contribution on its own leaf set. The model's
// refused second contribution is an actor rule (see the excused list).
#[test]
fn rt_design_leaf_set_holds() {
    design("rt_design__leafSetHolds.itf.json", N4, &[]);
}

// ---------------------------------------------------------------- mutants mt_m_*

#[test]
fn mt_m_burn_broken_is_refused() {
    let x = mutant(
        "mt_m_burn__burnBroken.itf.json",
        N4,
        &[
            (20, "voteAdmit", taken()),
            (21, "voteAdmit", taken()),
            (22, "voteAdmit", taken()),
            (22, "voteAdmit", diverged("r3 admitted differs")),
        ],
    );
    assert_eq!(x.b.slot(&slot(2)), SlotState::Burned);
}

#[test]
fn mt_m_precedence_broken_is_refused() {
    mutant(
        "mt_m_precedence__precedenceBroken.itf.json",
        N4,
        &[
            (9, "voteAdmit", taken()),
            (10, "voteAdmit", taken()),
            (11, "voteAdmit", taken()),
            (11, "voteAdmit", diverged("r2 admitted differs")),
        ],
    );
}

#[test]
fn mt_m_distinct_broken_is_refused() {
    mutant(
        "mt_m_distinct__distinctBroken.itf.json",
        N4,
        &[
            (2, "order", split(SplitError::Header)),
            (7, "voteAdmit", split(SplitError::NotOpened)),
            (8, "voteAdmit", split(SplitError::NotOpened)),
            (9, "voteAdmit", split(SplitError::NotOpened)),
            (9, "voteAdmit", diverged("r1 admitted differs")),
        ],
    );
}

#[test]
fn mt_m_bf_p2_broken_is_refused() {
    mutant(
        "mt_m_bf_p2__bfP2Broken.itf.json",
        N4,
        &[
            (
                2,
                "order",
                split(SplitError::Profile(ProfileError::BoardFirst)),
            ),
            (6, "voteAdmit", split(SplitError::NotOpened)),
            (7, "voteAdmit", split(SplitError::NotOpened)),
            (8, "voteAdmit", split(SplitError::NotOpened)),
            (8, "voteAdmit", diverged("r1 admitted differs")),
        ],
    );
}

#[test]
fn mt_m_inclusion_broken_is_refused() {
    mutant(
        "mt_m_inclusion__inclusionBroken.itf.json",
        N4,
        &[
            (6, "voteAdmit", split(SplitError::Authorization)),
            (7, "voteAdmit", split(SplitError::Authorization)),
            (8, "voteAdmit", split(SplitError::Authorization)),
            (8, "voteAdmit", diverged("r1 admitted differs")),
        ],
    );
}

#[test]
fn mt_m_no_collect_broken_is_refused() {
    mutant(
        "mt_m_no_collect__noCollectBroken.itf.json",
        N4,
        &[
            (10, "voteAdmit", split(SplitError::Collection)),
            (11, "voteAdmit", split(SplitError::Collection)),
            (12, "voteAdmit", split(SplitError::Collection)),
            (12, "voteAdmit", diverged("r1 admitted differs")),
        ],
    );
}

// The cold start burns the claimed slot 11 and blocks account-pool
// reservations until the next checkpoint; the reissue is never admitted.
#[test]
fn mt_m_cold_old_broken_is_refused() {
    let x = mutant(
        "mt_m_cold_old__coldOldBroken.itf.json",
        N4,
        &[
            (21, "voteAdmit", split(SplitError::Window)),
            (22, "voteAdmit", split(SplitError::Window)),
            (23, "voteAdmit", split(SplitError::Window)),
            (23, "voteAdmit", diverged("r3 admitted differs")),
        ],
    );
    assert_eq!(x.b.slot(&ecdsa_slot(11)), SlotState::Burned);
}

// The reducer's P2 charter has Δ_hold = 2 and refuses Δ_hold = 0.
#[test]
fn mt_m_hold0_broken_is_refused() {
    mutant(
        "mt_m_hold0__hold0Broken.itf.json",
        N4,
        &[(10, "release", split(SplitError::Hold))],
    );
}

// S4 (DECISIONS 53): the old rule settles the lost request VOID with the input
// unspent. The reducer settles it RELEASED and keeps the record locked.
#[test]
fn s4_cold_void_settles_released() {
    let x = mutant("s4_cold_void_m_cold_void.itf.json", N4, &[]);
    let r = x.b.request(&e(1)).unwrap();
    assert_eq!(r.state, State::Void(VoidReason::Restart));
    assert_eq!(
        r.settlement,
        Some(Settlement::Released { pin: digest(7001) })
    );
    assert_eq!(x.b.record_lock(&record(1)), Some(digest(7001)));
}

// ---------------------------------------------------------------- S1 forks on one board

// One reducer is one honest board view: the second variant on slot 1 is
// refused. The two forked views are replayed in quint_split_conformance.rs.
#[test]
fn q1_fork_sl_n4_b2_one_view_refuses_the_second_variant() {
    design(
        "q1_fork_sl_n4_b2.itf.json",
        Params {
            n: 4,
            f: 1,
            nbyz: 2,
        },
        &[(3, "release", split(SplitError::Selection))],
    );
}

// |C| = 3 > f = 2 and |C| = 5: outside the non-TEE adversary of DECISIONS 42.
// On one board view the second variant is refused. The corrupt node's ADMIT
// vote after admission (step 14 at n = 7) is refused and changes nothing.
#[test]
fn q1_n7_b3_one_view_refuses_the_second_variant() {
    design(
        "q1_n7_b3__q1ForkBroken.itf.json",
        Params {
            n: 7,
            f: 2,
            nbyz: 3,
        },
        &[
            (14, "byzVoteAdmit", split(SplitError::AlreadyVoted)),
            (17, "release", split(SplitError::Selection)),
            (18, "release", split(SplitError::Selection)),
        ],
    );
}

#[test]
fn q1_n9_b5_one_view_refuses_the_second_variant() {
    design(
        "q1_n9_b5__q1ForkBroken.itf.json",
        Params {
            n: 9,
            f: 2,
            nbyz: 5,
        },
        &[
            (17, "release", split(SplitError::Selection)),
            (18, "release", split(SplitError::Selection)),
        ],
    );
}

// ---------------------------------------------------------------- sampled design runs

// Request 2 names a slot outside its source root: the reducer refuses its
// authorization (DESIGN §5.3 item 4); the model never lets it vote.
#[test]
fn sampled_sl_n4_armed() {
    let refused: Want = &[
        (15, "deferred", Refusal::Split(SplitError::Ticket)),
        (17, "authFinal", Refusal::Split(SplitError::Evidence)),
    ];
    for (name, want) in [
        ("sampled/sl_n4_armedEcdsa_0.itf.json", refused),
        ("sampled/sl_n4_armedEcdsa_1.itf.json", &[]),
        ("sampled/sl_n4_armedEcdsa_2.itf.json", &[]),
        ("sampled/sl_n4_armedEcdsa_3.itf.json", &[]),
        ("sampled/sl_n4_armedEcdsa_4.itf.json", &[]),
        ("sampled/sl_n4_armedSchnorr_0.itf.json", refused),
        ("sampled/sl_n4_armedSchnorr_1.itf.json", &[]),
        ("sampled/sl_n4_armedSchnorr_3.itf.json", &[]),
        ("sampled/sl_n4_armedSchnorr_4.itf.json", &[]),
    ] {
        design(name, N4, want);
    }
}

// Model artifact MA1 (COUNTEREXAMPLES.md): doAuthorize omits DESIGN §5.3 item 4,
// so the model gives request 2 precedence on slot 15, the one slot of its
// header inside its record's root. Midnight refuses that authorization, and so
// does the reducer; no slot is named.
#[test]
fn sampled_sl_n4_armed_schnorr_2_model_names_a_slot_of_an_unopenable_request() {
    let x = design(
        "sampled/sl_n4_armedSchnorr_2.itf.json",
        N4,
        &[
            (17, "deferred", split(SplitError::Ticket)),
            (
                17,
                "order",
                diverged("slot 15: model Named(2), reducer Free"),
            ),
        ],
    );
    assert!(!x.b.request(&e(2)).unwrap().in_force());
}

// ---------------------------------------------------------------- pools and restarts

// W1 regression (restart range burn) and QA-5: before the fix the restart left
// index 1 free and the vote went through.
#[test]
fn pt_design_burned_index_vote_refused_holds() {
    let mut x = pool("pt_design__burnedIndexVoteRefusedHolds.itf.json", &[]);
    assert_eq!(x.b.slot(&pools::pool_slot(1, 1)), SlotState::Burned);
    let v = vote(&x, 1);
    assert_eq!(x.b.apply(x.height, v), Err(SplitError::SlotTaken));
}

#[test]
fn pt_design_burned_index_void_holds() {
    pool("pt_design__burnedIndexVoidHolds.itf.json", &[]);
}

#[test]
fn pt_design_restart_ends_ordered_holds() {
    pool("pt_design__restartEndsOrderedHolds.itf.json", &[]);
}

#[test]
fn pt_design_pending_burn_holds() {
    let x = pool("pt_design__pendingBurnHolds.itf.json", &[]);
    // doAnchor(1, 2) fails: the restart ended request 1.
    assert!(x.b.request(&e(1)).unwrap().state.terminal());
}

#[test]
fn pt_design_window_vote_holds() {
    let mut x = pool("pt_design__windowVoteHolds.itf.json", &[]);
    let v = vote(&x, 1);
    assert_eq!(x.b.apply(x.height, v), Err(SplitError::Window));
}

// QA-14: the votes of request 1 land before checkpoint 2 raises h past index 1.
// The reducer checks the admitting vote against checkpoint 2 and refuses it;
// the model admits request 1 and seald refuses the bind. Neither lets a
// partial leave on index 1.
#[test]
fn pt_design_window_bind_holds() {
    pool(
        "pt_design__windowBindHolds.itf.json",
        &[
            (12, "admit", taken()),
            (12, "admit", diverged("r1 model A , reducer Opened")),
        ],
    );
}

#[test]
fn pt_window_bind_broken_is_refused() {
    pool(
        "pt_window_bind__windowBindBroken.itf.json",
        &[
            (12, "admit", taken()),
            (12, "admit", diverged("r1 model A , reducer Opened")),
        ],
    );
}

// QA-4: account precedence by board order. The reducer refuses the later
// request's votes (precedence holder r1); the model refuses its admission.
#[test]
fn pt_design_acct_earliest_holds() {
    pool(
        "pt_design__acctEarliestHolds.itf.json",
        &[(5, "vote", taken()), (6, "vote", taken())],
    );
}

#[test]
fn pt_design_acct_earliest_admits_holds() {
    let x = pool(
        "pt_design__acctEarliestAdmitsHolds.itf.json",
        &[(5, "vote", taken()), (6, "vote", taken())],
    );
    assert_eq!(x.b.slot(&pools::pool_slot(3, 1)), SlotState::Claimed(e(1)));
}

#[test]
fn pt_acct_race_broken_is_refused() {
    pool(
        "pt_acct_race__acctEarliestBroken.itf.json",
        &[
            (5, "vote", taken()),
            (6, "vote", taken()),
            (7, "admit", no_quorum()),
            (7, "admit", diverged("r2 model A , reducer Opened")),
        ],
    );
}

// W1, W3, W4 mutants and the seald-only design runs (voteStale off): the
// reducer refuses the reuse at the vote, before the model's bind.
#[test]
fn pt_restart_reuse_is_refused_at_the_vote() {
    let reuse = |v: usize, err: SplitError, who: &str| -> Vec<(usize, &str, Refusal)> {
        vec![
            (v, "vote", split(err.clone())),
            (v + 1, "vote", split(err)),
            (v + 2, "admit", no_quorum()),
            (
                v + 2,
                "admit",
                diverged(&format!("{who} model A , reducer Opened")),
            ),
        ]
    };
    for (name, want) in [
        (
            "pt_no_window_burn__windowBurnBroken.itf.json",
            reuse(15, SplitError::SlotTaken, "r2"),
        ),
        (
            "pt_seald__windowBurnHolds.itf.json",
            reuse(15, SplitError::SlotTaken, "r2"),
        ),
        (
            "pt_no_account_burn__accountBurnBroken.itf.json",
            reuse(16, SplitError::SlotTaken, "r2"),
        ),
        (
            "pt_seald__accountBurnHolds.itf.json",
            reuse(16, SplitError::SlotTaken, "r2"),
        ),
        (
            "pt_seald__accountMarkerHolds.itf.json",
            reuse(5, SplitError::Window, "r2"),
        ),
        (
            "pt_window__windowVoteBroken.itf.json",
            reuse(4, SplitError::Window, "r1"),
        ),
    ] {
        pool(name, &want);
    }
}

// W2 mutant: the model restores request 1 as admitted after the restart and
// anchors another variant. The reducer ended request 1 at the restart.
#[test]
fn pt_no_pending_burn_broken_is_refused() {
    let x = pool(
        "pt_no_pending_burn__pendingBurnBroken.itf.json",
        &[(
            11,
            "wholeRestart",
            diverged("r1 model A , reducer Void(Restart)"),
        )],
    );
    assert_eq!(x.b.slot(&pools::pool_slot(1, 1)), SlotState::Burned);
}

// Sampled design runs with a restart. Before the fix they diverged at the
// restart: index 1 free (runs 1, 2) and a posted envelope ended (runs 0, 3, 4).
#[test]
fn sampled_pl_design_restart() {
    for i in 0..5 {
        pool(&format!("sampled/pl_design_restart_{i}.itf.json"), &[]);
    }
}

// QA-10: the witness of DESIGN §7.7 needs n - 1 - f = 6 peers at n = 9; the
// five acks of the WACK = 5 mutant are refused.
#[test]
fn w5_five_acks_are_refused_at_n9() {
    let mut b = SplitBoard::new(
        line_dealing::board::Committee { n: 9, f: 2 },
        1,
        10,
        256,
        true,
        false,
    )
    .unwrap();
    b.apply(
        1,
        Event::Post {
            envelope: Envelope {
                eid: e(1),
                hd: digest(1001),
                dd: digest(1),
                auth_ref: digest(2001),
                epoch: 1,
                exp: 100,
                checks: PublicChecks::verified(),
            },
        },
    )
    .unwrap();
    let open = |peers: Vec<u16>| Event::WitnessOpen {
        eid: e(1),
        node: 1,
        position: 1,
        committed: false,
        peers,
    };
    assert_eq!(
        b.apply(1, open(vec![4, 5, 7, 8, 9])),
        Err(SplitError::Witness)
    );
    b.apply(1, open(vec![2, 4, 5, 7, 8, 9])).unwrap();
}

// ---------------------------------------------------------------- coverage

const EXCUSED: &[(&str, &str)] = &[
    (
        "pt_anchor__reshareCoveredHolds.itf.json",
        "recovery through E and seald seat logs (DESIGN §5.8, §7.11 item 2); the reducer has no recovery transition",
    ),
    (
        "pt_design__reshareNoAnchorHolds.itf.json",
        "recovery through E (DESIGN §5.8, §7.11 item 2); the reducer has no recovery transition",
    ),
    (
        "pt_reshare_all__reshareCoveredBroken.itf.json",
        "recovery through E with seat logs; the reducer has no recovery transition",
    ),
    (
        "pt_reshare_no_anchor__reshareNoAnchorBroken.itf.json",
        "recovery through E; the reducer has no recovery transition",
    ),
    (
        "rt_m_leafset__leafSetBroken.itf.json",
        "an actor rule: a group member answers only for the slot record's leaf set; ecdsa.rs binds each half to leaf_set_hash (test ecdsa_attack_d_recovers_group_line_and_key_but_binding_refuses), and the reducer holds no member answers",
    ),
    (
        "w5_mutant__w5Broken.itf.json",
        "TEE rollback and readmission of one node; the reducer has no node disks. The witness quorum is w5_five_acks_are_refused_at_n9",
    ),
    (
        "wk_design__witkeyReleaseHolds.itf.json",
        "TEE witness keys; WK1 GUARD HOLDS is tested in split_state.rs with the full WitnessKey::Slot key",
    ),
];

const REPLAYED: &[&str] = &[
    "fix__c7BoundaryHolds.itf.json",
    "fix__c7EarlyHoldStopsHolds.itf.json",
    "fix__coldFinalSettlesFinalHolds.itf.json",
    "fix__ecExpireReissueHolds.itf.json",
    "fix__ecRevokeFreesHolds.itf.json",
    "fix__gen2AfterReleaseHolds.itf.json",
    "fix__gen2AnchorsHolds.itf.json",
    "fix__p1GuardianRefusedHolds.itf.json",
    "fix__releasedRepostHolds.itf.json",
    "g5_m_g5_sampled.itf.json",
    "gt_design__g5BurnHolds.itf.json",
    "gt_design__g5VoidHolds.itf.json",
    "gt_m_g5__g5BurnBroken.itf.json",
    "gt_m_g5__g5VoidBroken.itf.json",
    "mt_m_bf_p2__bfP2Broken.itf.json",
    "mt_m_burn__burnBroken.itf.json",
    "mt_m_cold_old__coldOldBroken.itf.json",
    "mt_m_distinct__distinctBroken.itf.json",
    "mt_m_hold0__hold0Broken.itf.json",
    "mt_m_inclusion__inclusionBroken.itf.json",
    "mt_m_no_collect__noCollectBroken.itf.json",
    "mt_m_precedence__precedenceBroken.itf.json",
    "pg1_design__pg1OpenVoidHolds.itf.json",
    "pg1_m_open__pg1OpenVoidBroken.itf.json",
    "pt_acct_race__acctEarliestBroken.itf.json",
    "pt_design__acctEarliestAdmitsHolds.itf.json",
    "pt_design__acctEarliestHolds.itf.json",
    "pt_design__burnedIndexVoidHolds.itf.json",
    "pt_design__burnedIndexVoteRefusedHolds.itf.json",
    "pt_design__pendingBurnHolds.itf.json",
    "pt_design__restartEndsOrderedHolds.itf.json",
    "pt_design__windowBindHolds.itf.json",
    "pt_design__windowVoteHolds.itf.json",
    "pt_no_account_burn__accountBurnBroken.itf.json",
    "pt_no_pending_burn__pendingBurnBroken.itf.json",
    "pt_no_window_burn__windowBurnBroken.itf.json",
    "pt_seald__accountBurnHolds.itf.json",
    "pt_seald__accountMarkerHolds.itf.json",
    "pt_seald__windowBurnHolds.itf.json",
    "pt_window__windowVoteBroken.itf.json",
    "pt_window_bind__windowBindBroken.itf.json",
    "q1_fork_sl_n4_b2.itf.json",
    "q1_n7_b3__q1ForkBroken.itf.json",
    "q1_n9_b5__q1ForkBroken.itf.json",
    "rt_design__leafSetHolds.itf.json",
    "rt_design__slotRootHolds.itf.json",
    "rt_m_slot_root__slotRootBroken.itf.json",
    "s4_cold_void_m_cold_void.itf.json",
    "sampled/pl_design_restart_0.itf.json",
    "sampled/pl_design_restart_1.itf.json",
    "sampled/pl_design_restart_2.itf.json",
    "sampled/pl_design_restart_3.itf.json",
    "sampled/pl_design_restart_4.itf.json",
    "sampled/sl_n4_armedEcdsa_0.itf.json",
    "sampled/sl_n4_armedEcdsa_1.itf.json",
    "sampled/sl_n4_armedEcdsa_2.itf.json",
    "sampled/sl_n4_armedEcdsa_3.itf.json",
    "sampled/sl_n4_armedEcdsa_4.itf.json",
    "sampled/sl_n4_armedSchnorr_0.itf.json",
    "sampled/sl_n4_armedSchnorr_1.itf.json",
    "sampled/sl_n4_armedSchnorr_2.itf.json",
    "sampled/sl_n4_armedSchnorr_3.itf.json",
    "sampled/sl_n4_armedSchnorr_4.itf.json",
];

#[test]
fn every_trace_is_replayed_or_excused() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/quint-regressions/splitline");
    let mut names = vec![];
    for (sub, prefix) in [("", ""), ("sampled", "sampled/")] {
        for entry in std::fs::read_dir(dir.join(sub)).unwrap() {
            let n = entry.unwrap().file_name().into_string().unwrap();
            if n.ends_with(".itf.json") {
                names.push(format!("{prefix}{n}"));
            }
        }
    }
    names.sort();
    let mut known: Vec<String> = REPLAYED
        .iter()
        .chain(EXCUSED.iter().map(|(n, _)| n))
        .map(|n| n.to_string())
        .collect();
    known.sort();
    assert_eq!(names, known);
    assert!(EXCUSED.iter().all(|(_, why)| !why.is_empty()));
}
