//! Ghost state: no protocol decision reads this module and no fault changes it.
use crate::{node::SlotKey, Body, Digest, Purpose, Sid, Slot};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BindRefused {
        reason: crate::Error,
    },
    Burned {
        seat: usize,
        purpose: Purpose,
        indices: Vec<u64>,
    },
    Fault(String),
    CrashCut {
        seat: usize,
        step: u64,
        point: crate::CrashPoint,
    },
    Sync(usize),
    IgnoredReport(usize),
    Derived {
        seat: usize,
        sid: Sid,
        v: u64,
        partials: Vec<usize>,
    },
    Fsync {
        seat: usize,
        v: u64,
    },
    Witness {
        seat: usize,
        peer: usize,
        v: u64,
    },
    Candidate {
        seat: usize,
        v: u64,
        digest: Digest,
        reports: usize,
    },
    Authenticated {
        seat: usize,
        v: u64,
    },
    Committed {
        seat: usize,
        v: u64,
        digest: Digest,
    },
    Opened {
        seat: usize,
        purpose: Purpose,
        source: u64,
        burned: Vec<u64>,
    },
    SlotAck {
        seat: usize,
        peer: usize,
        index: u64,
    },
    Release {
        seat: usize,
        purpose: Purpose,
        index: u64,
        digest: Digest,
        share: Vec<u8>,
    },
    Checkpoint {
        seq: u64,
        h: u64,
    },
    End {
        index: u64,
        void: bool,
    },
    Expected(String),
    Violation(String),
}
#[derive(Clone, Debug)]
pub struct Commit {
    pub v: u64,
    pub digest: Digest,
    pub body: Body,
}
#[derive(Clone, Debug, Default)]
pub struct Erased {
    pub names: BTreeSet<String>,
    pub slots: BTreeSet<u64>,
}
#[derive(Clone, Debug, Default)]
pub struct Oracle {
    pub reading: LossReading,
    /// Observe complete counterexample traces without changing protocol decisions.
    pub observe_only: bool,
    pub active_lost: BTreeSet<usize>,
    pub permanent_lost: BTreeSet<usize>,
    pub peak_lost: usize,
    pub releases: BTreeMap<SlotKey, BTreeSet<Digest>>,
    /// App/board history outside node state and the rollback domain (SS-048).
    pub first_shares: BTreeMap<SlotKey, Vec<u8>>,
    /// Exact share bytes, not just the slot index, identify nonce reuse.
    pub share_releases: BTreeMap<(SlotKey, Vec<u8>), BTreeSet<Digest>>,
    /// Actual Byzantine responses: conflicting slots, forged reports, stale
    /// replicas returned, refused partials. Counters never drive protocol state.
    pub byzantine_fired: [usize; 4],
    pub committed: BTreeMap<(usize, Sid), Commit>,
    pub erased: BTreeMap<(usize, Sid), Erased>,
    pub violations: Vec<String>,
    pub expected: Vec<String>,
    pub lost_seats: BTreeSet<usize>,
    pub max_down: usize,
    pub planned_out_of_bound: bool,
}
/// Design G2 / SS-102: whether a completed replacement retires its loss count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LossReading {
    Literal,
    #[default]
    Concurrent,
}
impl Oracle {
    pub fn halted(&self) -> bool {
        !self.observe_only && !self.violations.is_empty()
    }
    pub fn lost(&mut self, seat: usize) {
        self.lost_seats.insert(seat);
        self.active_lost.insert(seat);
        self.peak_lost = self.peak_lost.max(self.active_lost.len());
    }
    pub fn lost_permanently(&mut self, seat: usize) {
        self.permanent_lost.insert(seat);
        self.lost(seat);
    }
    pub fn in_bound(&self, c: usize, f: usize) -> bool {
        let losses = match self.reading {
            LossReading::Literal => self.lost_seats.len(),
            LossReading::Concurrent => self.peak_lost,
        };
        !self.planned_out_of_bound && losses <= c && self.max_down <= f
    }
    pub fn classify(&self, c: usize, f: usize) -> &'static str {
        if self.in_bound(c, f) {
            "IN-BOUND"
        } else {
            "OUT-OF-BOUND"
        }
    }
    pub fn problem(&mut self, msg: String, expected: bool, trace: &mut Vec<Event>) {
        if expected {
            let msg = format!("expected per Limits: {msg}");
            self.expected.push(msg.clone());
            trace.push(Event::Expected(msg));
        } else {
            self.violations.push(msg.clone());
            trace.push(Event::Violation(msg));
        }
    }
    pub fn derive(&mut self, j: usize, sid: Sid, v: u64, in_bound: bool, trace: &mut Vec<Event>) {
        if self.committed.get(&(j, sid)).is_some_and(|c| v < c.v) {
            self.problem(
                format!("G4: seat {j} derived version {v} below committed fence"),
                !in_bound,
                trace,
            );
        }
    }
    pub fn commit(&mut self, j: usize, sid: Sid, p: Purpose, v: u64, body: &Body) {
        // Ghost maximum never rolls back, including in OUT-OF-BOUND runs.
        let key = (j, sid);
        let erased = self.erased.entry(key).or_default();
        if let Some(old) = self.committed.get(&key) {
            erased.names.extend(
                old.body
                    .entries
                    .keys()
                    .filter(|k| !body.entries.contains_key(*k))
                    .cloned(),
            );
        }
        erased.slots.extend(
            body.slots
                .iter()
                .filter_map(|(i, s)| (*s == Slot::Burned).then_some(*i)),
        );
        // A later deliberate put is a new value, not resurrection by restore.
        for name in body.entries.keys() {
            erased.names.remove(name);
        }
        if self.committed.get(&key).is_none_or(|old| v >= old.v) {
            self.committed.insert(
                key,
                Commit {
                    v,
                    digest: body.digest(p),
                    body: body.clone(),
                },
            );
        }
    }
    pub fn restored(
        &mut self,
        session: (usize, Sid),
        p: Purpose,
        v: u64,
        body: &Body,
        in_bound: bool,
        trace: &mut Vec<Event>,
    ) {
        let (j, sid) = session;
        if let Some(c) = self.committed.get(&(j, sid)) {
            if v < c.v || (v == c.v && body.digest(p) != c.digest) {
                self.problem(
                    format!("G1/G4: seat {j} restored older or split committed content at {v}"),
                    !in_bound,
                    trace,
                );
            }
        }
        if let Some(e) = self.erased.get(&(j, sid)) {
            if e.names.iter().any(|k| body.entries.contains_key(k))
                || e.slots
                    .iter()
                    .any(|i| matches!(body.slots.get(i), Some(Slot::Free(_) | Slot::Bound(..))))
            {
                self.problem(
                    format!("G4: seat {j} restored erased material"),
                    !in_bound,
                    trace,
                );
            }
        }
    }
    pub fn release(&mut self, key: SlotKey, d: Digest, share: Vec<u8>, trace: &mut Vec<Event>) {
        let (j, p, i) = key;
        trace.push(Event::Release {
            seat: j,
            purpose: p,
            index: i,
            digest: d,
            share: share.clone(),
        });
        self.share_releases
            .entry((key, share))
            .or_default()
            .insert(d);
        let set = self.releases.entry((j, p, i)).or_default();
        set.insert(d);
        // SS-055 / G2/G3: second releases are scored even outside the bound.
        if set.len() > 1 {
            self.problem(
                format!("G2/G3: seat {j} {p:?} slot {i} released two digests"),
                false,
                trace,
            );
        }
    }
}
