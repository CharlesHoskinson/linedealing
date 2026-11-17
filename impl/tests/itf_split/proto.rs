//! Adapter from the request machine of `formal/quint/splitline.qnt` to the
//! `SplitBoard` reducer.
//!
//! The adapter reads `lastAction` and the state difference of each model step
//! and applies the public board events of that step. After each step it
//! compares the projection of the model state (request states, admission, slot
//! states, record locks) with the reducer. Refused events are recorded with
//! their step; the replay goes on, so a test states every refusal of a trace.
//!
//! Projection rules. These are abstractions of the model, not findings:
//! - Header. The model knows each header from `init` and names committee slots
//!   at ORDER. Honest nodes post the header partial of every ordered envelope
//!   (DESIGN §5.2 item 2), so the adapter opens the reducer header at ORDER,
//!   with the corrupt nodes and the lowest honest nodes as the `n - f`
//!   partials. A later model `headerPartial` checks that the partial is there
//!   or adds it.
//! - Authorization. The reducer checks an authorization against the opened
//!   header (`policy`), so `authorize`, `authFinal`, `boardFirstCall`, `relay`
//!   and the revoke of `hold` wait until the header is open.
//! - Board time. Each model step is one board height. `expc` advances the board
//!   to the request's `exp_c`; `expire` advances it to the envelope's `exp`.
//!   The reducer lapses a request at `exp_c` (a lapse is not terminal in the
//!   reducer, the model ends it VOID LAPSED).
//! - VOID posts. The reducer counts VOID posts without evidence, so the
//!   adapter posts VOID only when an honest node holds the evidence in the
//!   reducer: another holder or a burn on a named slot (SLOT_TAKEN), the
//!   revoke (REVOKED), the stall flag (STALLED).
//! - Cold start. The model loses the board tail and settles each lost request
//!   in `settleLost`; the reducer keeps its log, and `WholeCommitteeRestart`
//!   ends and settles every live request at once. Its `host_final` lists the
//!   requests that the model settles FINAL.
//! - ECDSA slots after a restart. The reducer holds an account-pool slot only
//!   once a header names it. A slot that no header named before the restart is
//!   `Free` in the reducer where the model shows it `Burned`; the projection
//!   accepts that, and the reducer refuses every account-pool reservation
//!   until the post-restart checkpoint lands (DESIGN §7.11 marker rule).
use super::{digest, slot, trace};
use line_dealing::board::Committee;
use line_dealing::split::profile::{Charter, OwnerChecks, Profile, Source, SourceEvidence};
use line_dealing::split::state::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const DELTA_C: u64 = 100;
pub const EXP: u64 = 5000;

pub fn int(v: &Value) -> i64 {
    v.as_i64().expect("model integer")
}
fn ints(v: &Value) -> BTreeSet<i64> {
    v.as_array().unwrap().iter().map(int).collect()
}
fn tag(v: &Value) -> &str {
    v["tag"].as_str().unwrap()
}
fn eid(r: i64) -> Eid {
    digest(r as u64)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The reducer refuses the event.
    Split(SplitError),
    /// No honest node holds the evidence that the model step posts.
    NoEvidence(&'static str),
    /// The model state after the step differs from the reducer.
    Diverged(String),
}
impl From<SplitError> for Refusal {
    fn from(e: SplitError) -> Self {
        Self::Split(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub index: usize,
    pub action: String,
    pub refusal: Refusal,
}

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub n: u16,
    pub f: u16,
    pub nbyz: u16,
}
pub const N4: Params = Params {
    n: 4,
    f: 1,
    nbyz: 1,
};

pub fn ecdsa_slot(l: i64) -> SlotId {
    SlotId::Ecdsa {
        record: digest(10_000 + l as u64),
    }
}
pub fn model_slot(l: i64) -> SlotId {
    if l < 10 {
        slot(l as u64)
    } else {
        ecdsa_slot(l)
    }
}
pub fn record(rec: i64) -> Digest {
    digest(5000 + rec as u64)
}

pub struct Proto {
    pub b: SplitBoard,
    pub p: Params,
    pub height: u64,
    pub mid: u64,
    deferred: BTreeMap<i64, Vec<Event>>,
    named: BTreeSet<SlotId>,
    /// Account-pool slots that a header named before the restart, if any.
    restarted: Option<BTreeSet<SlotId>>,
    /// Mutant traces: the projection compares request states and admission
    /// only, so the replay reaches the step that the mutant changes.
    pub mutant: bool,
    pub refusals: Vec<Step>,
    step: usize,
}

impl Proto {
    pub fn new(p: Params) -> Self {
        let mut b =
            SplitBoard::new(Committee { n: p.n, f: p.f }, 1, DELTA_C, 256, false, false).unwrap();
        b.apply(0, checkpoint()).unwrap();
        Self {
            b,
            p,
            height: 0,
            mid: 0,
            deferred: BTreeMap::new(),
            named: BTreeSet::new(),
            restarted: None,
            mutant: false,
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
    /// Applies one event at the current height; a refusal is recorded.
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
    fn opened(&self, r: i64) -> bool {
        self.b.request(&eid(r)).is_ok_and(|q| q.header.is_some())
    }
    fn honest(&self) -> impl Iterator<Item = u16> {
        1..=self.p.n - self.p.nbyz
    }
    fn byz(&self) -> impl Iterator<Item = u16> {
        self.p.n - self.p.nbyz + 1..=self.p.n
    }

    pub fn header(m: &Value, r: i64) -> Header {
        let q = &m["reqs"][r.to_string()];
        let h = &q["hdr"];
        let rec = int(&h["rec"]);
        let ch = &m["charters"][rec.to_string()];
        let profile = match tag(&ch["profile"]) {
            "P1" => Profile::P1 {
                exit: digest(4000),
                owner_checks: OwnerChecks::default(),
            },
            _ => Profile::P2 {
                exit: digest(4000),
                registry: digest(4001),
                delta_hold: 2,
                owner_checks: OwnerChecks::default(),
            },
        };
        let ecdsa = tag(&h["suite"]) == "Ecdsa";
        let ls = int(&h["ls"]);
        let source = if ecdsa && ls == 2 {
            Source::Seizure
        } else {
            Source::Owner
        };
        let nfv = int(&q["nfv"]);
        let nf = if nfv >= 0 {
            nfv
        } else {
            int(&m["mid"]["recNf"][rec.to_string()])
        };
        let (suite, variants, slots, tickets) = if ecdsa {
            let slots: Vec<_> = (1..=2).map(|v| int(&h["ec"][v.to_string()])).collect();
            // splitline.qnt srcOpens: the record's slot root and the leaf set.
            let root = |l: i64| {
                (if rec == 1 { 11..=14 } else { 15..=16 }).contains(&l)
                    && (if (13..=14).contains(&l) { 2 } else { 1 }) == ls
            };
            let tickets = (1..=2u16)
                .map(|v| Ticket {
                    variant: v,
                    generation: 0,
                    input: 1,
                    slot: ecdsa_slot(slots[usize::from(v - 1)]),
                    digest: digest((r * 100 + i64::from(v) * 10) as u64),
                    in_source_root: root(slots[usize::from(v - 1)]),
                })
                .collect();
            (
                Suite::Ecdsa,
                2,
                slots.iter().map(|l| ecdsa_slot(*l)).collect(),
                tickets,
            )
        } else {
            let slots: Vec<_> = (1..=2)
                .map(|g| slot(int(&h["sch"][g.to_string()]) as u64))
                .collect();
            let tickets = (1..=3u16)
                .flat_map(|v| (1..=v.min(2)).map(move |g| (v, g)))
                .map(|(v, g)| Ticket {
                    variant: v,
                    generation: g,
                    input: 1,
                    slot: slots[usize::from(g - 1)],
                    digest: digest((r * 100 + i64::from(v) * 10 + i64::from(g)) as u64),
                    in_source_root: true,
                })
                .collect();
            (Suite::Bip340, 3, slots, tickets)
        };
        let collecting = h["collecting"].as_bool().unwrap();
        Header {
            hash: digest(1000 + r as u64),
            selection_rule: digest(3000),
            charter: Charter {
                profile,
                board_first: ch["bf"].as_bool().unwrap(),
            },
            source,
            record: record(rec),
            nf: digest(6000 + (rec * 10 + nf) as u64),
            pin: digest(7000 + rec as u64),
            outputs: vec![if source == Source::Seizure {
                digest(4001)
            } else {
                digest(8000)
            }],
            checks: SourceEvidence::verified(),
            suite,
            variants,
            inputs: 1,
            slots,
            tickets,
            actors: if collecting { vec![1] } else { vec![] },
            embedded: vec![],
            valid: true,
        }
    }

    fn post(&mut self, m: &Value, r: i64) {
        let dd = int(&m["reqs"][r.to_string()]["hdr"]["dd"]) as u64;
        self.ev(
            "post",
            Event::Post {
                envelope: Envelope {
                    eid: eid(r),
                    hd: digest(1000 + r as u64),
                    dd: digest(dd),
                    auth_ref: digest(2000 + r as u64),
                    epoch: 1,
                    exp: self.height + EXP,
                    checks: PublicChecks::verified(),
                },
            },
        );
    }

    fn order(&mut self, m: &Value, r: i64) {
        if !self.ev(
            "order",
            Event::Order {
                eid: eid(r),
                qc_verified: true,
            },
        ) {
            return;
        }
        let have = self.b.request(&eid(r)).unwrap().header_partials.clone();
        let need = usize::from(self.p.n - self.p.f);
        let openers: Vec<u16> = self.byz().chain(self.honest()).take(need).collect();
        for node in openers {
            if !have.contains(&node) {
                self.ev(
                    "order",
                    Event::HeaderPartial {
                        eid: eid(r),
                        node,
                        share_verified: true,
                    },
                );
            }
        }
        let h = Self::header(m, r);
        let slots = h.slots.clone();
        if self.ev(
            "order",
            Event::SeeHeader {
                eid: eid(r),
                header: Box::new(h),
            },
        ) {
            self.named.extend(slots);
            for e in self.deferred.remove(&r).unwrap_or_default() {
                self.ev("deferred", e);
            }
        }
    }

    fn after_open(&mut self, r: i64, action: &str, e: Event) {
        if self.opened(r) {
            self.ev(action, e);
        } else {
            self.deferred.entry(r).or_default().push(e);
        }
    }

    fn vote(&mut self, r: i64, node: u16, action: &str) {
        let e = Event::VoteAdmit {
            eid: eid(r),
            node,
            header_hash: digest(1000 + r as u64),
            obs: Observation {
                host_height: self.height,
                midnight_height: self.mid,
            },
        };
        self.ev(action, e);
    }

    fn void(&mut self, r: i64, reason: VoidReason, action: &str) {
        for node in 1..=self.p.f + 1 {
            self.ev(
                action,
                Event::Void {
                    eid: eid(r),
                    epoch: 1,
                    node,
                    reason,
                },
            );
        }
    }

    /// splitline.qnt doVoidSlotTaken, as an honest node sees it in the reducer:
    /// a named slot is held by another request or burned.
    fn slot_taken_evidence(&self, r: i64) -> bool {
        let Ok(q) = self.b.request(&eid(r)) else {
            return false;
        };
        q.header.as_ref().is_some_and(|h| {
            h.slots.iter().any(|s| match self.b.slot(s) {
                SlotState::Free => false,
                SlotState::Burned => true,
                SlotState::Named(e) | SlotState::Reserved(e) | SlotState::Claimed(e) => e != eid(r),
            })
        })
    }

    fn signed(&self, m: &Value, r: i64) -> bool {
        // splitline.qnt reqSigned on the reducer: honest releases plus the corrupt
        // nodes reach n - f on one generation.
        let Ok(q) = self.b.request(&eid(r)) else {
            return false;
        };
        let _ = m;
        (1..=G_MAX).any(|g| {
            q.releases.keys().filter(|(gg, _)| *gg == g).count() + usize::from(self.p.nbyz)
                >= usize::from(self.p.n - self.p.f)
        })
    }

    /// Expands `initArmed`: request 1 posted, ordered, authorized and admitted.
    fn armed(&mut self, m: &Value) {
        let r = 1;
        self.post(m, r);
        self.order(m, r);
        self.ev(
            "initArmed",
            Event::Authorize {
                eid: eid(r),
                verified: true,
            },
        );
        self.ev(
            "initArmed",
            Event::AuthFinal {
                eid: eid(r),
                midnight_height: 0,
                verified: true,
            },
        );
        for node in ints(&m["reqs"]["1"]["admitVotes"]) {
            self.vote(r, node as u16, "initArmed");
        }
    }

    /// Applies one model step; false when the projection diverges.
    pub fn step(&mut self, index: usize, before: &Value, after: &Value) -> bool {
        self.step = index;
        self.height += 1;
        self.b.apply(self.height, Event::Tick).unwrap();
        let action = after["lastAction"].as_str().unwrap().to_string();
        let changed: Vec<i64> = (1..=3)
            .filter(|r| before["reqs"][r.to_string()] != after["reqs"][r.to_string()])
            .collect();
        let one = || {
            assert_eq!(changed.len(), 1, "{action}: one request changes");
            changed[0]
        };
        let rq = |r: i64| &after["reqs"][r.to_string()];
        match action.as_str() {
            "idle" | "midTick" => {
                self.mid = int(&after["mid"]["h"]) as u64;
            }
            "post" => self.post(after, one()),
            "order" => self.order(after, one()),
            "authorize" => {
                let r = one();
                self.after_open(
                    r,
                    "authorize",
                    Event::Authorize {
                        eid: eid(r),
                        verified: true,
                    },
                );
            }
            "authFinal" | "relay" => {
                let r = one();
                let midnight_height = int(&rq(r)["authAt"]).max(0) as u64;
                self.after_open(
                    r,
                    &action,
                    Event::AuthFinal {
                        eid: eid(r),
                        midnight_height,
                        verified: true,
                    },
                );
            }
            "boardFirstCall" => {
                let r = one();
                let ok = rq(r)["bfInForce"].as_bool().unwrap();
                // A call that the model refuses (nullifier used or pending, hold)
                // puts nothing in force; it changes no reducer state either.
                if !ok {
                    return self.finish(&action, after);
                }
                self.after_open(
                    r,
                    "boardFirstCall",
                    Event::BoardFirstCall {
                        eid: eid(r),
                        proof_verified: true,
                        finalized_root: true,
                        unused_nf: ok,
                        root_height: self.mid,
                        midnight_height: self.mid,
                        max_root_age: 10,
                        relay_margin: 1,
                    },
                );
            }
            "headerPartial" => {
                let r = one();
                let added: Vec<_> = ints(&rq(r)["hdrPartials"])
                    .difference(&ints(&before["reqs"][r.to_string()]["hdrPartials"]))
                    .copied()
                    .collect();
                for node in added {
                    let have = self
                        .b
                        .request(&eid(r))
                        .is_ok_and(|q| q.header_partials.contains(&(node as u16)));
                    if !have {
                        self.ev(
                            "headerPartial",
                            Event::HeaderPartial {
                                eid: eid(r),
                                node: node as u16,
                                share_verified: true,
                            },
                        );
                    }
                }
            }
            "voteAdmit" | "byzVoteAdmit" | "voteOpened" | "byzVoteOpened" => {
                let r = one();
                let field = if action.contains("Opened") {
                    "openedVotes"
                } else {
                    "admitVotes"
                };
                let added: Vec<_> = ints(&rq(r)[field])
                    .difference(&ints(&before["reqs"][r.to_string()][field]))
                    .copied()
                    .collect();
                assert_eq!(added.len(), 1);
                let node = added[0] as u16;
                if field == "admitVotes" {
                    self.vote(r, node, &action);
                } else {
                    self.ev(
                        &action,
                        Event::VoteOpened {
                            eid: eid(r),
                            node,
                            header_hash: digest(1000 + r as u64),
                        },
                    );
                }
            }
            "contribute" => {
                let r = one();
                self.ev(
                    "contribute",
                    Event::Contribute {
                        contribution: Contribution {
                            frame: digest(9000 + r as u64),
                            epoch: 1,
                            dd: digest(9500 + r as u64),
                            target_hd: digest(1000 + r as u64),
                            actor: 1,
                            digest: digest(9900 + r as u64),
                            verified: true,
                        },
                    },
                );
            }
            "seeContrib" => {
                let r = one();
                self.ev("seeContrib", Event::SeeContrib { eid: eid(r) });
            }
            "hold" => {
                let rec = (1..=2)
                    .find(|x| {
                        before["mid"]["hold"][x.to_string()] != after["mid"]["hold"][x.to_string()]
                    })
                    .unwrap();
                self.ev(
                    "hold",
                    Event::SetHold {
                        record: record(rec),
                        midnight_height: self.mid,
                        held: true,
                        verified: true,
                    },
                );
                for r in changed.clone() {
                    if tag(&rq(r)["auth"]) == "ARevoked" {
                        let e = Event::Revoke {
                            eid: eid(r),
                            midnight_height: self.mid,
                            verified: true,
                        };
                        self.after_open(r, "hold", e);
                    }
                }
            }
            "voidRevoked" => {
                let r = one();
                if self.b.request(&eid(r)).is_ok_and(|q| q.revoked) || !self.opened(r) {
                    self.void(r, VoidReason::Revoked, "voidRevoked");
                } else {
                    self.refuse(
                        "voidRevoked",
                        Refusal::NoEvidence("no revoke in the reducer"),
                    );
                }
            }
            "voidSlotTaken" => {
                let r = one();
                if !self.b.request(&eid(r)).is_ok_and(|q| q.in_force()) {
                    // DESIGN §4.7, §5.4 (DECISIONS 68): precedence is an admission
                    // check; an honest node runs it once the authorization is in force.
                    self.refuse(
                        "voidSlotTaken",
                        Refusal::NoEvidence("the authorization is not in force"),
                    );
                } else if self.slot_taken_evidence(r) {
                    self.void(r, VoidReason::SlotTaken, "voidSlotTaken");
                } else {
                    self.refuse(
                        "voidSlotTaken",
                        Refusal::NoEvidence("every named slot is free or held by the request"),
                    );
                }
            }
            "expc" => {
                let r = one();
                let to = self.b.request(&eid(r)).unwrap().exp_c.unwrap();
                self.height = self.height.max(to);
                self.b.apply(self.height, Event::Tick).unwrap();
            }
            "lapse" => {
                let r = one();
                self.ev("lapse", Event::Lapse { eid: eid(r) });
            }
            "stall" => {
                let r = one();
                if self.ev("stall", Event::Stall { eid: eid(r) }) {
                    self.void(r, VoidReason::Stalled, "stall");
                }
            }
            "expire" => {
                let r = one();
                let to = self.b.request(&eid(r)).unwrap().envelope.exp;
                self.height = self.height.max(to);
                self.b.apply(self.height, Event::Tick).unwrap();
                self.ev("expire", Event::Expire { eid: eid(r) });
            }
            "anchorGen" => {
                let r = one();
                let g = (2..=3)
                    .find(|g| {
                        before["reqs"][r.to_string()]["anchors"][g.to_string()]
                            != rq(r)["anchors"][g.to_string()]
                    })
                    .unwrap() as u16;
                let q = Committee {
                    n: self.p.n,
                    f: self.p.f,
                }
                .quorum() as u16;
                for node in 1..=q {
                    if !self.ev(
                        "anchorGen",
                        Event::AnchorGen {
                            eid: eid(r),
                            generation: g,
                            node,
                            obs: Observation {
                                host_height: self.height,
                                midnight_height: self.mid,
                            },
                            deadline_verified: true,
                        },
                    ) {
                        break;
                    }
                }
            }
            "release" => {
                let es: Vec<_> = after["relEvents"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|e| !before["relEvents"].as_array().unwrap().contains(e))
                    .collect();
                // A repeated release of the same partial changes no model state.
                let Some(e) = es.first() else {
                    return self.finish(&action, after);
                };
                assert_eq!(es.len(), 1);
                let (r, node, g, v) = (int(&e["rid"]), int(&e["node"]), int(&e["g"]), int(&e["v"]));
                // The model records a repeat of a node's own partial at a later
                // Midnight height as a new event; the reducer keeps the first.
                let repeat = before["relEvents"].as_array().unwrap().iter().any(|x| {
                    x["rid"] == e["rid"]
                        && x["node"] == e["node"]
                        && x["g"] == e["g"]
                        && x["v"] == e["v"]
                });
                if repeat {
                    return self.finish(&action, after);
                }
                let ecdsa = e["suite"]["tag"] == "Ecdsa";
                let tk = if ecdsa {
                    r * 100 + v * 10
                } else {
                    r * 100 + v * 10 + g
                };
                let revoked = tag(&before["reqs"][r.to_string()]["auth"]) == "ARevoked";
                self.ev(
                    "release",
                    Event::Release {
                        eid: eid(r),
                        node: node as u16,
                        generation: g as u16,
                        variant: v as u16,
                        tickets: vec![digest(tk as u64)],
                        selection_verified: true,
                        checks_verified: true,
                        midnight_height: int(&e["midH"]) as u64,
                        not_revoked_verified: !revoked,
                    },
                );
            }
            "final" => {
                let r = one();
                if self.signed(after, r) {
                    let q = Committee {
                        n: self.p.n,
                        f: self.p.f,
                    }
                    .quorum() as u16;
                    for node in 1..=q {
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
                    self.refuse("final", Refusal::NoEvidence("no t-partial signature"));
                }
            }
            "checkpoint" => {
                self.ev("checkpoint", checkpoint());
            }
            "coldStartE" => {
                // Requests that settleLost settles FINAL: the host shows their
                // transaction (the record is spent and the request signed).
                let host_final = (1..=3)
                    .filter(|r| {
                        let rec = int(&rq(*r)["hdr"]["rec"]);
                        tag(&rq(*r)["st"]) == "Lost"
                            && after["mid"]["recSpent"][rec.to_string()] == true
                            && self.signed(after, *r)
                    })
                    .map(|r| (eid(r), digest(240 + r as u64)))
                    .collect();
                self.restarted = Some(self.named.clone());
                self.ev("coldStartE", Event::WholeCommitteeRestart { host_final });
            }
            "settleLost" => {}
            a => panic!("unmapped model action {a}"),
        }
        self.finish(&action, after)
    }

    fn finish(&mut self, action: &str, after: &Value) -> bool {
        self.mid = int(&after["mid"]["h"]) as u64;
        if let Err(d) = self.project(after) {
            self.refuse(action, Refusal::Diverged(d));
            return false;
        }
        true
    }

    pub fn project(&self, m: &Value) -> Result<(), String> {
        for r in 1..=3i64 {
            let q = &m["reqs"][r.to_string()];
            let st = tag(&q["st"]);
            if st == "Unposted" {
                continue;
            }
            let Ok(x) = self.b.request(&eid(r)) else {
                return Err(format!("r{r} {st}: unknown to the reducer"));
            };
            let reason = q["reason"].as_str().unwrap();
            let ok = match st {
                "Posted" => x.state == State::Posted,
                "Ordered" => {
                    !x.state.terminal()
                        && x.order_position.is_some()
                        && (!x.lapsed || (q["expc"] == true && q["everInForce"] == false))
                }
                "Void" => match reason {
                    "LAPSED" => x.lapsed && !x.state.terminal(),
                    "SLOT_TAKEN" => x.state == State::Void(VoidReason::SlotTaken),
                    "REVOKED" => x.state == State::Void(VoidReason::Revoked),
                    "STALLED" => x.state == State::Void(VoidReason::Stalled),
                    "COLD_SETTLED" => x.state == State::Void(VoidReason::Restart),
                    _ => false,
                },
                "Final" => matches!(x.state, State::Final(_)),
                "Expired" => x.state == State::Expired,
                "Lost" => x.state.terminal(),
                _ => false,
            };
            if !ok {
                return Err(format!("r{r} model {st} {reason}, reducer {:?}", x.state));
            }
            if q["admitted"].as_bool().unwrap() != x.admitted {
                return Err(format!("r{r} admitted differs"));
            }
        }
        if self.mutant {
            return Ok(());
        }
        for (key, v) in m["slots"].as_object().unwrap() {
            let l: i64 = key.parse().unwrap();
            let s = model_slot(l);
            let r = || eid(int(&v["value"]));
            let want = match tag(v) {
                "Free" => SlotState::Free,
                "Named" => SlotState::Named(r()),
                "Reserved" => SlotState::Reserved(r()),
                "Claimed" => SlotState::Claimed(r()),
                _ => SlotState::Burned,
            };
            let got = self.b.slot(&s);
            let unknown_account = l >= 10
                && self
                    .restarted
                    .as_ref()
                    .is_some_and(|known| !known.contains(&s));
            if got != want && !(want == SlotState::Burned && unknown_account) {
                return Err(format!(
                    "slot {l}: model {}, reducer {}",
                    show(want),
                    show(got)
                ));
            }
        }
        for rec in 1..=2i64 {
            // The model locks a record when a request with a release ends
            // (RELEASED); the reducer locks it at the first release, which
            // fixes the same pin earlier (`lock_record`).
            let locked = m["mid"]["recLocked"][rec.to_string()] == true;
            let released_live = m["relEvents"].as_array().unwrap().iter().any(|e| {
                let q = &m["reqs"][int(&e["rid"]).to_string()];
                int(&q["hdr"]["rec"]) == rec && tag(&q["st"]) == "Ordered"
            });
            let got = self.b.record_lock(&record(rec)).is_some();
            if locked != got && !(got && released_live) {
                return Err(format!("record {rec}: model locked {locked}"));
            }
        }
        Ok(())
    }
}

pub fn checkpoint() -> Event {
    Event::Checkpoint {
        pools: BTreeMap::from([(
            PoolId {
                suite: Suite::Bip340,
                epoch: 1,
            },
            PoolCheckpoint {
                h: 0,
                pending_min: 1,
                pending_root: digest(0),
                pending_count: 0,
                pending: BTreeMap::new(),
                pending_verified: true,
            },
        )]),
    }
}

/// Replays a splitline.qnt trace and returns the adapter with its refusals.
pub fn replay(name: &str, p: Params) -> Proto {
    replay_as(name, p, false)
}

/// Replays a mutant trace: slots and locks are not compared.
pub fn replay_mutant(name: &str, p: Params) -> Proto {
    replay_as(name, p, true)
}

fn replay_as(name: &str, p: Params, mutant: bool) -> Proto {
    let states = trace(name);
    let mut x = Proto::new(p);
    x.mutant = mutant;
    let init = &states[0];
    match init["lastAction"].as_str().unwrap() {
        "init" => {}
        "initArmed" => x.armed(init),
        a => panic!("unknown initial action {a}"),
    }
    if let Err(d) = x.project(init) {
        x.refuse("init", Refusal::Diverged(d));
        return x;
    }
    for (i, pair) in states.windows(2).enumerate() {
        if !x.step(i + 1, &pair[0], &pair[1]) {
            break;
        }
    }
    x
}

/// A slot state with the request number in place of the digest.
pub fn show(s: SlotState) -> String {
    let n = |e: Eid| u64::from_be_bytes(e[24..].try_into().unwrap());
    match s {
        SlotState::Named(e) => format!("Named({})", n(e)),
        SlotState::Reserved(e) => format!("Reserved({})", n(e)),
        SlotState::Claimed(e) => format!("Claimed({})", n(e)),
        s => format!("{s:?}"),
    }
}
