//! Adapter from `formal/quint/splitline_pools.qnt` to the `SplitBoard` reducer.
//!
//! Projection rules (abstractions of the model, not findings):
//! - Committee. The model has `NN = 3` honest seats and `QQ = 2` votes; the
//!   reducer runs `n = 3`, `f = 0`, quorum 2, window `B = 2`.
//! - Requests. A request names one slot: index `idx` of the Schnorr pool
//!   (suite 1, BIP340), of the Ed25519 pool (suite 2), or slot `idx` of one
//!   ECDSA account pool (suite 3). Every request of the model is authorized,
//!   so the adapter opens the header and makes the authorization final at
//!   ORDER. Each request has its own record and one variant.
//! - Admission. The model admits in its own `admit` step after the votes; the
//!   reducer admits on the vote that reaches the quorum. The adapter holds
//!   back that vote until the model's `admit`, so the reducer checks it at the
//!   board state of the admission. A vote the reducer refuses is recorded and
//!   dropped.
//! - Seald. `log`, `bindBatch`, `burnEnd` and `succCheckpoint` are seald and
//!   seat-log steps of a TEE node; the reducer has no slot_bind, so these
//!   steps apply no event. The reducer's own checks (vote window, slot owner,
//!   restart burns) stand in for them, and a refusal there comes earlier than
//!   the model's refusal at the bind.
//! - Restart. The model loses the board tail and restores the checkpoint
//!   snapshot; the reducer keeps its log and ends every live request
//!   (`WholeCommitteeRestart`). A request the model restores as live and the
//!   reducer ended is a divergence, reported as such.
use super::proto::{Refusal, Step, EXP};
use super::{digest, trace};
use line_dealing::board::Committee;
use line_dealing::split::profile::{Charter, OwnerChecks, Profile, Source, SourceEvidence};
use line_dealing::split::state::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const B: u64 = 2;

fn int(v: &Value) -> i64 {
    v.as_i64().expect("model integer")
}
fn eid(r: i64) -> Eid {
    digest(r as u64)
}
fn pool_id(pl: i64) -> PoolId {
    PoolId {
        suite: if pl == 1 {
            Suite::Bip340
        } else {
            Suite::Ed25519
        },
        epoch: 1,
    }
}
pub fn pool_slot(pl: i64, idx: i64) -> SlotId {
    if pl == 3 {
        SlotId::Ecdsa {
            record: digest(300 + idx as u64),
        }
    } else {
        SlotId::Schnorr {
            suite: pool_id(pl).suite,
            epoch: 1,
            index: idx as u64,
        }
    }
}

pub struct Pools {
    pub b: SplitBoard,
    pub height: u64,
    held_votes: BTreeMap<i64, Vec<u16>>,
    named: BTreeSet<SlotId>,
    /// Account-pool slots that a header named before the restart.
    named_at_restart: BTreeSet<SlotId>,
    pub refusals: Vec<Step>,
    step: usize,
}

impl Pools {
    pub fn new() -> Self {
        let mut b = SplitBoard::new(Committee { n: 3, f: 0 }, 1, 1000, B, false, false).unwrap();
        b.apply(
            0,
            Event::Checkpoint {
                pools: [1, 2]
                    .into_iter()
                    .map(|pl| (pool_id(pl), pool_cp(0, &BTreeMap::new())))
                    .collect(),
            },
        )
        .unwrap();
        Self {
            b,
            height: 0,
            held_votes: BTreeMap::new(),
            named: BTreeSet::new(),
            named_at_restart: BTreeSet::new(),
            refusals: vec![],
            step: 0,
        }
    }
    fn refuse(&mut self, action: &str, refusal: Refusal) {
        self.refusals.push(Step {
            index: self.step,
            action: action.into(),
            refusal,
        });
    }
    pub fn ev(&mut self, action: &str, e: Event) -> bool {
        let r = self.b.apply(self.height, e);
        self.b.check_invariants().unwrap();
        match r {
            Ok(()) => true,
            Err(err) => {
                self.refuse(action, err.into());
                false
            }
        }
    }
    fn header(r: i64, q: &Value) -> Header {
        let pl = int(&q["pool"]);
        let s = pool_slot(pl, int(&q["idx"]));
        let suite = match int(&q["suite"]) {
            1 => Suite::Bip340,
            2 => Suite::Ed25519,
            _ => Suite::Ecdsa,
        };
        Header {
            hash: digest(1000 + r as u64),
            selection_rule: digest(3000),
            charter: Charter {
                profile: Profile::P1 {
                    exit: digest(4000),
                    owner_checks: OwnerChecks::default(),
                },
                board_first: false,
            },
            source: Source::Owner,
            record: digest(5000 + r as u64),
            nf: digest(6000 + r as u64),
            pin: digest(7000 + r as u64),
            outputs: vec![digest(8000)],
            checks: SourceEvidence::verified(),
            suite,
            variants: 1,
            inputs: 1,
            slots: vec![s],
            tickets: vec![Ticket {
                variant: 1,
                generation: if suite == Suite::Ecdsa { 0 } else { 1 },
                input: 1,
                slot: s,
                digest: digest((r * 10 + 1) as u64),
                in_source_root: true,
            }],
            actors: vec![],
            embedded: vec![],
            valid: true,
        }
    }
    fn vote_event(&self, r: i64, node: u16) -> Event {
        Event::VoteAdmit {
            eid: eid(r),
            node,
            header_hash: digest(1000 + r as u64),
            obs: Observation {
                host_height: self.height,
                midnight_height: 0,
            },
        }
    }
    fn slot_taken_evidence(&self, r: i64) -> bool {
        self.b.request(&eid(r)).is_ok_and(|q| {
            q.header.as_ref().is_some_and(|h| {
                h.slots.iter().any(|s| match self.b.slot(s) {
                    SlotState::Free => false,
                    SlotState::Burned => true,
                    SlotState::Named(e) | SlotState::Reserved(e) | SlotState::Claimed(e) => {
                        e != eid(r)
                    }
                })
            })
        })
    }
    fn void_slot_taken(&mut self, r: i64, action: &str, evidence: bool) {
        if evidence {
            self.ev(
                action,
                Event::Void {
                    eid: eid(r),
                    epoch: 1,
                    node: 1,
                    reason: VoidReason::SlotTaken,
                },
            );
        } else {
            self.refuse(action, Refusal::NoEvidence("no honest SLOT_TAKEN evidence"));
        }
    }

    /// Applies one model step; false when the projection diverges.
    pub fn step(&mut self, index: usize, before: &Value, after: &Value) -> bool {
        self.step = index;
        self.height += 1;
        self.b.apply(self.height, Event::Tick).unwrap();
        let action = after["lastAction"].as_str().unwrap().to_string();
        let changed: Vec<i64> = (1..=4)
            .filter(|r| before["reqs"][r.to_string()] != after["reqs"][r.to_string()])
            .collect();
        let one = || {
            assert_eq!(changed.len(), 1, "{action}: one request changes");
            changed[0]
        };
        match action.as_str() {
            "idle" | "height" | "log" | "bindBatch" | "burnEnd" | "succCheckpoint" => {}
            "post" => {
                let r = one();
                self.ev(
                    "post",
                    Event::Post {
                        envelope: Envelope {
                            eid: eid(r),
                            hd: digest(1000 + r as u64),
                            dd: digest(100 + r as u64),
                            auth_ref: digest(2000 + r as u64),
                            epoch: 1,
                            exp: self.height + EXP,
                            checks: PublicChecks::verified(),
                        },
                    },
                );
            }
            "order" => {
                let r = one();
                let q = &after["reqs"][r.to_string()];
                let e = eid(r);
                if self.ev(
                    "order",
                    Event::Order {
                        eid: e,
                        qc_verified: true,
                    },
                ) {
                    for node in 1..=3 {
                        self.ev(
                            "order",
                            Event::HeaderPartial {
                                eid: e,
                                node,
                                share_verified: true,
                            },
                        );
                    }
                    let h = Self::header(r, q);
                    self.named.extend(h.slots.iter().copied());
                    self.ev(
                        "order",
                        Event::SeeHeader {
                            eid: e,
                            header: Box::new(h),
                        },
                    );
                    self.ev(
                        "order",
                        Event::Authorize {
                            eid: e,
                            verified: true,
                        },
                    );
                    self.ev(
                        "order",
                        Event::AuthFinal {
                            eid: e,
                            midnight_height: 0,
                            verified: true,
                        },
                    );
                }
                if q["st"] == "V" {
                    let ev = self.slot_taken_evidence(r);
                    self.void_slot_taken(r, "order", ev);
                }
            }
            "vote" => {
                let r = one();
                let before_votes: BTreeSet<_> = before["reqs"][r.to_string()]["votes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(int)
                    .collect();
                let node = after["reqs"][r.to_string()]["votes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(int)
                    .find(|n| !before_votes.contains(n))
                    .unwrap() as u16;
                let accepted = self.b.request(&eid(r)).map_or(0, |q| q.admit_votes.len());
                if accepted + 1 >= 2 {
                    self.held_votes.entry(r).or_default().push(node);
                } else {
                    let e = self.vote_event(r, node);
                    self.ev("vote", e);
                }
            }
            "admit" => {
                let r = one();
                let mut admitted = false;
                for node in self.held_votes.remove(&r).unwrap_or_default() {
                    let e = self.vote_event(r, node);
                    self.ev("admit", e);
                    admitted = self.b.request(&eid(r)).unwrap().admitted;
                    if admitted {
                        break;
                    }
                }
                if !admitted && !self.refusals.iter().any(|s| s.index == index) {
                    self.refuse("admit", Refusal::NoEvidence("no quorum of accepted votes"));
                }
            }
            "anchor" => {
                let r = one();
                let q = self.b.request(&eid(r)).unwrap();
                if q.state.terminal() {
                    self.refuse("anchor", Refusal::Split(SplitError::Terminal));
                } else if !q.admitted {
                    self.refuse("anchor", Refusal::Split(SplitError::NoAnchor));
                }
            }
            "release" => {
                let p0 = before["partials"].as_array().unwrap();
                let added: Vec<_> = after["partials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|x| !p0.contains(x))
                    .collect();
                assert_eq!(added.len(), 1);
                let x = added[0].as_array().unwrap();
                let (node, tk) = (int(&x[0]) as u16, int(&x[3]));
                let (r, v) = (tk / 10, tk % 10);
                let ecdsa = int(&after["reqs"][r.to_string()]["pool"]) == 3;
                self.ev(
                    "release",
                    Event::Release {
                        eid: eid(r),
                        node,
                        generation: 1,
                        variant: v as u16,
                        tickets: vec![digest(tk as u64)],
                        selection_verified: true,
                        checks_verified: true,
                        midnight_height: 0,
                        not_revoked_verified: true,
                    },
                );
                let _ = ecdsa;
            }
            "final" => {
                let r = one();
                if self.b.request(&eid(r)).is_ok_and(|q| q.releases.len() >= 2) {
                    for node in 1..=2 {
                        self.ev(
                            "final",
                            Event::Final {
                                eid: eid(r),
                                epoch: 1,
                                node,
                                ciphertext: digest(240 + r as u64),
                            },
                        );
                    }
                } else {
                    self.refuse("final", Refusal::NoEvidence("fewer than QQ partials"));
                }
            }
            "checkpoint" => {
                let cp = &after["cp"];
                let pools = [1, 2]
                    .into_iter()
                    .map(|pl| {
                        let pending: BTreeMap<u64, Eid> = cp["pending"][pl.to_string()]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|e| (int(&e[0]) as u64, eid(int(&e[1]))))
                            .collect();
                        (
                            pool_id(pl),
                            pool_cp(int(&cp["h"][pl.to_string()]) as u64, &pending),
                        )
                    })
                    .collect();
                self.ev("checkpoint", Event::Checkpoint { pools });
            }
            "wholeRestart" => {
                self.named_at_restart = self.named.clone();
                self.ev(
                    "wholeRestart",
                    Event::WholeCommitteeRestart {
                        host_final: BTreeMap::new(),
                    },
                );
            }
            "voidBelowFloor" => {
                let r = one();
                let mut probe = self.b.clone();
                let e = self.vote_event(r, 1);
                let ev = probe.apply(self.height, e) == Err(SplitError::SlotTaken);
                self.void_slot_taken(r, "voidBelowFloor", ev);
            }
            "voidBurned" => {
                let r = one();
                let ev = self.b.request(&eid(r)).is_ok_and(|q| {
                    q.header.as_ref().is_some_and(|h| {
                        h.slots.iter().all(|s| self.b.slot(s) == SlotState::Burned)
                    })
                });
                self.void_slot_taken(r, "voidBurned", ev);
            }
            "voidAcctTaken" => {
                let r = one();
                let ev = self.slot_taken_evidence(r);
                self.void_slot_taken(r, "voidAcctTaken", ev);
            }
            a => panic!("unmapped pools action {a}"),
        }
        if let Err(d) = self.project(after) {
            self.refuse(&action, Refusal::Diverged(d));
            return false;
        }
        true
    }

    pub fn project(&self, m: &Value) -> Result<(), String> {
        for r in 1..=4i64 {
            let q = &m["reqs"][r.to_string()];
            let st = q["st"].as_str().unwrap();
            if st == "U" {
                continue;
            }
            let Ok(x) = self.b.request(&eid(r)) else {
                return Err(format!("r{r} {st}: unknown to the reducer"));
            };
            let reason = q["reason"].as_str().unwrap();
            let ok = match st {
                "P" => x.state == State::Posted,
                "O" => !x.state.terminal() && !x.admitted,
                "A" | "K" => !x.state.terminal() && x.admitted,
                "F" => matches!(x.state, State::Final(_)),
                "V" => match reason {
                    "SLOT_TAKEN" => x.state == State::Void(VoidReason::SlotTaken),
                    "BURNED" => matches!(
                        x.state,
                        State::Void(VoidReason::SlotTaken | VoidReason::Restart)
                    ),
                    _ => false,
                },
                "L" => x.state.terminal(),
                _ => false,
            };
            if !ok {
                return Err(format!("r{r} model {st} {reason}, reducer {:?}", x.state));
            }
        }
        for e in m["burnedAtRestart"].as_array().unwrap() {
            let (pl, i) = (int(&e[0]), int(&e[1]));
            let s = pool_slot(pl, i);
            let got = self.b.slot(&s);
            let unknown_account = pl == 3 && !self.named_at_restart.contains(&s);
            if got != SlotState::Burned && !unknown_account {
                return Err(format!(
                    "({pl}, {i}) burned at the restart, reducer {}",
                    super::proto::show(got)
                ));
            }
        }
        Ok(())
    }
}

impl Default for Pools {
    fn default() -> Self {
        Self::new()
    }
}

pub fn pool_cp(h: u64, pending: &BTreeMap<u64, Eid>) -> PoolCheckpoint {
    PoolCheckpoint {
        h,
        pending_min: pending.keys().next().copied().unwrap_or(h + 1),
        pending_root: digest(0),
        pending_count: pending.len() as u32,
        pending: pending.clone(),
        pending_verified: true,
    }
}

pub fn replay(name: &str) -> Pools {
    let states = trace(name);
    let mut x = Pools::new();
    assert_eq!(states[0]["lastAction"], "init");
    for (i, pair) in states.windows(2).enumerate() {
        if !x.step(i + 1, &pair[0], &pair[1]) {
            break;
        }
    }
    x
}
