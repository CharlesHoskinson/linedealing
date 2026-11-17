//! Small ITF reader and public-event fixtures for the split-line projection.
#![allow(dead_code)]
pub mod pools;
pub mod proto;
use line_dealing::board::Committee;
use line_dealing::split::profile::{Charter, OwnerChecks, Profile, Source, SourceEvidence};
use line_dealing::split::state::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub fn integer(v: &Value) -> u64 {
    v.as_u64().expect("nonnegative model integer")
}

fn normalize(v: Value) -> Value {
    match v {
        Value::Array(xs) => Value::Array(xs.into_iter().map(normalize).collect()),
        Value::Object(mut m) => {
            if let Some(n) = m.remove("#bigint") {
                return n.as_str().unwrap().parse::<i64>().unwrap().into();
            }
            if let Some(entries) = m.remove("#map") {
                return Value::Object(
                    entries
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|entry| {
                            let key = normalize(entry[0].clone()).to_string();
                            (key, normalize(entry[1].clone()))
                        })
                        .collect(),
                );
            }
            if let Some(xs) = m.remove("#set").or_else(|| m.remove("#tup")) {
                return normalize(xs);
            }
            Value::Object(m.into_iter().map(|(k, v)| (k, normalize(v))).collect())
        }
        v => v,
    }
}

pub fn trace(name: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/quint-regressions/splitline")
        .join(name);
    let raw: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let var = raw["vars"][0].as_str().unwrap();
    let states = raw["states"].as_array().unwrap();
    states
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            assert_eq!(s["#meta"]["index"].as_u64(), Some(i as u64));
            if let Some(value) = s.get(var) {
                Some(normalize(value.clone()))
            } else {
                // Quint .fail() writes a final metadata-only state, not a transition.
                assert_eq!(i + 1, states.len(), "missing nonterminal state");
                assert_eq!(s.as_object().unwrap().len(), 1);
                None
            }
        })
        .collect()
}

pub fn additions<'a>(before: &'a Value, after: &'a Value) -> Vec<&'a Value> {
    let before = before.as_array().unwrap();
    let after = after.as_array().unwrap();
    assert!(before.iter().all(|v| after.contains(v)), "set shrank");
    after.iter().filter(|v| !before.contains(v)).collect()
}

pub fn changed(before: &Value, after: &Value) -> BTreeSet<String> {
    let b = before.as_object().unwrap();
    let a = after.as_object().unwrap();
    assert_eq!(b.keys().collect::<Vec<_>>(), a.keys().collect::<Vec<_>>());
    a.iter()
        .filter(|(k, v)| b[*k] != **v)
        .map(|(k, _)| k.clone())
        .collect()
}

pub fn digest(n: u64) -> Digest {
    let mut d = [0; 32];
    d[24..].copy_from_slice(&n.to_be_bytes());
    d
}

pub fn slot(n: u64) -> SlotId {
    SlotId::Schnorr {
        suite: Suite::Bip340,
        epoch: 1,
        index: n,
    }
}

pub fn board(anchor: bool) -> SplitBoard {
    let mut b = SplitBoard::new(Committee { n: 4, f: 1 }, 1, 10, 256, false, anchor).unwrap();
    apply(
        &mut b,
        Event::Checkpoint {
            pools: std::collections::BTreeMap::from([(
                PoolId {
                    suite: Suite::Bip340,
                    epoch: 1,
                },
                PoolCheckpoint {
                    h: 0,
                    pending_min: 1,
                    pending_root: digest(0),
                    pending_count: 0,
                    pending: std::collections::BTreeMap::new(),
                    pending_verified: true,
                },
            )]),
        },
    )
    .unwrap();
    b
}

pub fn apply(b: &mut SplitBoard, e: Event) -> Result<(), SplitError> {
    let result = b.apply(1, e);
    b.check_invariants().unwrap();
    result
}

pub fn post(b: &mut SplitBoard, rid: u64, dd: u64) {
    apply(
        b,
        Event::Post {
            envelope: Envelope {
                eid: digest(rid),
                hd: digest(1000 + rid),
                dd: digest(dd),
                auth_ref: digest(2000 + rid),
                epoch: 1,
                exp: 100,
                checks: PublicChecks::verified(),
            },
        },
    )
    .unwrap();
}

pub fn header(rid: u64, slots: Vec<SlotId>, variants: u16) -> Header {
    let tickets = (1..=variants)
        .flat_map(|v| {
            let slots = &slots;
            (1..=v.min(G_MAX)).map(move |g| Ticket {
                variant: v,
                generation: g,
                input: 1,
                slot: slots[usize::from(g - 1)],
                // splitline.qnt ticketOf, encoded injectively as a test digest.
                digest: digest(rid * 100 + u64::from(v) * 10 + u64::from(g)),
                in_source_root: true,
            })
        })
        .collect();
    Header {
        hash: digest(1000 + rid),
        selection_rule: digest(3000),
        charter: Charter {
            profile: Profile::P1 {
                exit: digest(4000),
                owner_checks: OwnerChecks::default(),
            },
            board_first: false,
        },
        source: Source::Owner,
        record: digest(5000 + rid),
        nf: digest(6000 + rid),
        pin: digest(7000 + rid),
        outputs: vec![digest(8000)],
        checks: SourceEvidence::verified(),
        suite: Suite::Bip340,
        variants,
        inputs: 1,
        slots,
        tickets,
        actors: vec![],
        embedded: vec![],
        valid: true,
    }
}

pub fn open_authorize(b: &mut SplitBoard, rid: u64, h: Header, voters: &[u16]) {
    let eid = digest(rid);
    apply(
        b,
        Event::Order {
            eid,
            qc_verified: true,
        },
    )
    .unwrap();
    for &node in voters {
        apply(
            b,
            Event::HeaderPartial {
                eid,
                node,
                share_verified: true,
            },
        )
        .unwrap();
    }
    apply(
        b,
        Event::SeeHeader {
            eid,
            header: Box::new(h),
        },
    )
    .unwrap();
    apply(
        b,
        Event::Authorize {
            eid,
            verified: true,
        },
    )
    .unwrap();
    apply(
        b,
        Event::AuthFinal {
            eid,
            midnight_height: 0,
            verified: true,
        },
    )
    .unwrap();
}

pub fn vote(rid: u64, node: u16, host_height: u64) -> Event {
    Event::VoteAdmit {
        eid: digest(rid),
        node,
        header_hash: digest(1000 + rid),
        obs: Observation {
            host_height,
            midnight_height: 0,
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub rid: u64,
    pub node: u16,
    pub generation: u16,
    pub variant: u16,
    pub slot: u64,
    pub ticket: u64,
    pub midnight_height: u64,
}

impl Release {
    pub fn from_diff(before: &Value, after: &Value) -> Self {
        let events = additions(&before["relEvents"], &after["relEvents"]);
        assert_eq!(events.len(), 1);
        let e = events[0];
        let sigs = additions(&before["sigPartials"], &after["sigPartials"]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0]["node"], e["node"]);
        assert_eq!(sigs[0]["slot"], e["slot"]);
        let release = Self {
            rid: integer(&e["rid"]),
            node: integer(&e["node"]).try_into().unwrap(),
            generation: integer(&e["g"]).try_into().unwrap(),
            variant: integer(&e["v"]).try_into().unwrap(),
            slot: integer(&e["slot"]),
            ticket: integer(&sigs[0]["tk"]),
            midnight_height: integer(&e["midH"]),
        };
        assert_eq!(
            release.ticket,
            release.rid * 100 + u64::from(release.variant) * 10 + u64::from(release.generation)
        );
        release
    }

    pub fn event(&self) -> Event {
        Event::Release {
            eid: digest(self.rid),
            node: self.node,
            generation: self.generation,
            variant: self.variant,
            tickets: vec![digest(self.ticket)],
            selection_verified: true,
            checks_verified: true,
            midnight_height: self.midnight_height,
            not_revoked_verified: true,
        }
    }

    pub fn anchor(&self, verified: bool) -> Event {
        Event::SlotAnchor {
            eid: digest(self.rid),
            generation: self.generation,
            variant: self.variant,
            tickets: vec![digest(self.ticket)],
            verified,
        }
    }
}
