//! Pass F: replay the supported projection of the item 26 split-line traces.
//!
//! S1 uses a reducer per honest view. The model abstracts fork certificates and
//! selection checks; Byzantine members 3 and 4 supply votes to both histories.
//! The armed initial state is expanded into public events. Its two honest header
//! partials alone cannot open the Rust header (which needs three).
//!
//! State 2's premature generation-2 anchor is explicitly tested as a mismatch,
//! then omitted from the generation-1 projection. No failed transition is silently
//! accepted. Pool tests below are missing-rule probes, not full pool replays.
//! See lanes/F-report.md for all unsupported traces and adapter assumptions.

mod itf_split;

use itf_split::*;
use line_dealing::split::state::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const S1: &str = "q1_fork_sl_n4_b2.itf.json";

fn bootstrap(initial: &Value, honest: u16, anchored: bool) -> SplitBoard {
    let r = &initial["reqs"]["1"];
    assert_eq!(r["hdr"]["suite"]["tag"], "Schnorr");
    assert_eq!(r["auth"]["tag"], "AFinal");
    assert_eq!(r["admitted"], true);
    assert_eq!(r["hdrPartials"], serde_json::json!([1, 2]));
    assert_eq!(r["admitVotes"], serde_json::json!([1, 2, 3]));
    assert_eq!(r["anchors"]["1"], 1);
    let slots = (1..=2)
        .map(|g| slot(integer(&r["hdr"]["sch"][g.to_string()])))
        .collect();
    let mut b = board(anchored);
    post(&mut b, 1, integer(&r["hdr"]["dd"]));
    // Existential certificate expansion of the forked-board abstraction. Only
    // this view's honest node votes; the two corrupt nodes vote on both forks.
    let voters = [honest, 3, 4];
    open_authorize(&mut b, 1, header(1, slots, 3), &voters);
    for node in voters {
        apply(&mut b, vote(1, node, 1)).unwrap();
    }
    b
}

fn project(views: &BTreeMap<u16, SplitBoard>, model: &Value, refused: &BTreeSet<u16>) {
    let mut actual = BTreeSet::new();
    for (&honest, b) in views {
        b.check_invariants().unwrap();
        let r = b.request(&digest(1)).unwrap();
        assert_eq!(
            r.admitted,
            model["reqs"]["1"]["admitted"].as_bool().unwrap()
        );
        assert!(r.in_force());
        assert_eq!(r.anchors.len(), 1, "generation 2 is the recorded mismatch");
        assert_eq!(r.anchors[&1].host_height, 1);
        assert_eq!(
            r.admit_votes
                .iter()
                .map(|(n, _)| *n)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([honest, 3, 4])
        );
        for t in &r.header.as_ref().unwrap().tickets {
            assert_eq!(b.slot(&t.slot), SlotState::Claimed(digest(1)));
        }
        for ((generation, node), variant) in &r.releases {
            assert_eq!(
                *node, honest,
                "another honest history leaked into this view"
            );
            let h = r.header.as_ref().unwrap();
            let t = h
                .tickets
                .iter()
                .find(|t| t.generation == *generation && t.variant == *variant)
                .unwrap();
            let SlotId::Schnorr { index: slot_id, .. } = t.slot else {
                panic!("Schnorr trace")
            };
            let tk = u64::from_be_bytes(t.digest[24..].try_into().unwrap());
            actual.insert((*node, slot_id, tk));
            assert_eq!(
                integer(&model["nodes"][node.to_string()]["slotTk"][slot_id.to_string()]),
                tk
            );
            assert_eq!(
                integer(&model["nodes"][node.to_string()]["relGen"][(10 + generation).to_string()]),
                u64::from(*variant)
            );
        }
        assert_eq!(b.release_audits().len(), r.releases.len());
        for rid in 2..=3 {
            match model["reqs"][rid.to_string()]["st"]["tag"]
                .as_str()
                .unwrap()
            {
                "Unposted" => assert_eq!(b.request(&digest(rid)), Err(SplitError::UnknownRequest)),
                "Posted" => assert_eq!(b.request(&digest(rid)).unwrap().state, State::Posted),
                st => panic!("unhandled request state {st}"),
            }
        }
    }
    let expected: BTreeSet<_> = model["sigPartials"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| {
            let node = integer(&s["node"]) as u16;
            (!refused.contains(&node)).then(|| (node, integer(&s["slot"]), integer(&s["tk"])))
        })
        .collect();
    assert_eq!(actual, expected, "signature-partial projection");
}

fn replay(anchored: bool) -> (BTreeMap<u16, SplitBoard>, Vec<Release>) {
    let states = trace(S1);
    assert_eq!(states.len(), 5);
    let mut views: BTreeMap<_, _> = (1..=2)
        .map(|n| (n, bootstrap(&states[0], n, anchored)))
        .collect();
    let mut refused = BTreeSet::new();
    let mut releases = Vec::new();
    let mut mismatches = Vec::new();
    project(&views, &states[0], &refused);
    for (i, pair) in states.windows(2).enumerate() {
        let (before, after) = (&pair[0], &pair[1]);
        let mut fields = changed(before, after);
        fields.remove("lastAction"); // Diagnostic label never selects the action.
        if fields == BTreeSet::from(["reqs".into()]) {
            let rids = changed(&before["reqs"], &after["reqs"]);
            assert_eq!(rids.len(), 1);
            let rid = rids.first().unwrap();
            let b = &before["reqs"][rid];
            let a = &after["reqs"][rid];
            match changed(b, a)
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                ["st"] => {
                    assert_eq!(b["st"]["tag"], "Unposted");
                    assert_eq!(a["st"]["tag"], "Posted");
                    for view in views.values_mut() {
                        post(view, rid.parse().unwrap(), integer(&a["hdr"]["dd"]));
                    }
                }
                ["anchors"] => {
                    let gens = changed(&b["anchors"], &a["anchors"]);
                    assert_eq!(gens, BTreeSet::from(["2".into()]));
                    assert_eq!(b["anchors"]["2"], 0);
                    assert_eq!(a["anchors"]["2"], 3);
                    for (&honest, view) in &mut views {
                        let event = Event::AnchorGen {
                            eid: digest(rid.parse().unwrap()),
                            generation: 2,
                            node: honest,
                            obs: Observation {
                                host_height: 2,
                                midnight_height: 0,
                            },
                            deadline_verified: true,
                        };
                        assert_eq!(apply(view, event), Err(SplitError::Generation));
                        assert!(!view.request(&digest(1)).unwrap().anchors.contains_key(&2));
                    }
                    mismatches.push(i + 1);
                }
                delta => panic!("unhandled request delta at state {}: {delta:?}", i + 1),
            }
        } else {
            assert_eq!(
                fields,
                BTreeSet::from([
                    "nodes".into(),
                    "prfPartials".into(),
                    "relEvents".into(),
                    "sigPartials".into()
                ])
            );
            let release = Release::from_diff(before, after);
            assert_eq!(release.generation, 1);
            assert_eq!(release.slot, 3);
            assert_eq!(
                changed(&before["nodes"], &after["nodes"]),
                BTreeSet::from([release.node.to_string()])
            );
            assert_eq!(
                additions(&before["prfPartials"], &after["prfPartials"]),
                vec![&serde_json::json!([release.node, release.ticket])]
            );
            if anchored && releases.is_empty() {
                for view in views.values_mut() {
                    // The flag gates even the first release, until finality evidence arrives.
                    assert_eq!(apply(view, release.event()), Err(SplitError::Witness));
                    assert_eq!(
                        apply(view, release.anchor(false)),
                        Err(SplitError::Evidence)
                    );
                    apply(view, release.anchor(true)).unwrap();
                }
            }
            if anchored && !releases.is_empty() {
                // Every honest view receives the SAME finalized entry (ticket 131).
                // The reducer consumes trusted evidence; it does not prove finality.
                for (&honest, view) in &mut views {
                    let prior_release = !view.request(&digest(1)).unwrap().releases.is_empty();
                    assert_eq!(
                        apply(view, release.anchor(true)),
                        Err(if prior_release {
                            SplitError::Selection
                        } else {
                            SplitError::Ticket
                        })
                    );
                    let mut local = release.clone();
                    local.node = honest;
                    assert_eq!(
                        apply(view, local.event()),
                        Err(if prior_release {
                            SplitError::Selection
                        } else {
                            SplitError::Witness
                        })
                    );
                }
                refused.insert(release.node);
            } else {
                apply(views.get_mut(&release.node).unwrap(), release.event()).unwrap();
            }
            releases.push(release);
        }
        project(&views, after, &refused);
    }
    assert_eq!(mismatches, vec![2]);
    assert_eq!(
        releases
            .iter()
            .map(|r| (r.node, r.ticket))
            .collect::<Vec<_>>(),
        vec![(2, 131), (1, 111)]
    );
    assert_eq!(
        refused,
        if anchored {
            BTreeSet::from([1])
        } else {
            BTreeSet::new()
        }
    );
    (views, releases)
}

#[test]
fn s1_fork_confirms_two_honest_tickets_without_slot_anchor() {
    let (views, _) = replay(false);
    assert_eq!(views[&1].request(&digest(1)).unwrap().releases[&(1, 1)], 1);
    assert_eq!(views[&2].request(&digest(1)).unwrap().releases[&(1, 2)], 3);
}

#[test]
fn s1_slot_anchor_refuses_second_ticket_on_every_honest_view() {
    let (views, _) = replay(true);
    assert!(views[&1].request(&digest(1)).unwrap().releases.is_empty());
    assert_eq!(views[&2].request(&digest(1)).unwrap().releases.len(), 1);
}

#[test]
fn s1_one_shared_view_refuses_conflicting_selection() {
    let (mut views, releases) = replay(false);
    assert_eq!(
        apply(views.get_mut(&2).unwrap(), releases[1].event()),
        Err(SplitError::Selection)
    );
}

#[test]
fn s1_armed_header_needs_a_third_partial_in_the_prototype() {
    let initial = &trace(S1)[0];
    let r = &initial["reqs"]["1"];
    let mut b = board(false);
    post(&mut b, 1, integer(&r["hdr"]["dd"]));
    apply(
        &mut b,
        Event::Order {
            eid: digest(1),
            qc_verified: true,
        },
    )
    .unwrap();
    for node in r["hdrPartials"].as_array().unwrap() {
        apply(
            &mut b,
            Event::HeaderPartial {
                eid: digest(1),
                node: integer(node) as u16,
                share_verified: true,
            },
        )
        .unwrap();
    }
    let slots = (1..=2)
        .map(|g| slot(integer(&r["hdr"]["sch"][g.to_string()])))
        .collect();
    assert_eq!(
        apply(
            &mut b,
            Event::SeeHeader {
                eid: digest(1),
                header: Box::new(header(1, slots, 3))
            }
        ),
        Err(SplitError::Threshold)
    );
}

#[test]
fn w3_window_vote_regression() {
    for name in [
        "pt_design__windowVoteHolds.itf.json",
        "pt_window__windowVoteBroken.itf.json",
    ] {
        let states = trace(name);
        // State 3 is the common prefix before doVote(1, 1). Holds ends in
        // .fail(), whose metadata-only terminal state is not an accepted vote.
        let p = &states[3];
        let r = &p["reqs"]["1"];
        assert_eq!(r["st"], "O");
        assert_eq!(r["suite"], 1);
        let index = integer(&r["idx"]);
        let floor = integer(&p["cp"]["h"]["1"]);
        assert_eq!((floor, index), (0, 3));
        assert!(index > floor + 2); // B = 2 in pools_scenarios.
        let mut b = SplitBoard::new(
            line_dealing::board::Committee { n: 4, f: 1 },
            1,
            10,
            2,
            false,
            false,
        )
        .unwrap();
        apply(
            &mut b,
            Event::Checkpoint {
                pools: BTreeMap::from([(
                    PoolId {
                        suite: Suite::Bip340,
                        epoch: 1,
                    },
                    PoolCheckpoint {
                        h: floor,
                        pending_min: floor + 1,
                        pending_root: digest(0),
                        pending_count: 0,
                        pending: BTreeMap::new(),
                        pending_verified: true,
                    },
                )]),
            },
        )
        .unwrap();
        post(&mut b, 1, 1);
        open_authorize(&mut b, 1, header(1, vec![slot(index)], 1), &[1, 2, 3]);
        assert_eq!(apply(&mut b, vote(1, 1, 1)), Err(SplitError::Window));
        assert!(b.request(&digest(1)).unwrap().admit_votes.is_empty());
        assert!(!b.request(&digest(1)).unwrap().state.terminal());
        if name.contains("Broken") {
            assert_eq!(
                additions(
                    &states[3]["reqs"]["1"]["votes"],
                    &states[4]["reqs"]["1"]["votes"]
                ),
                vec![&serde_json::json!(1)]
            );
        } else {
            assert_eq!(states.len(), 4);
        }
    }
}
