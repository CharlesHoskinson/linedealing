use crate::{hash, ledger::Checkpoint, sid, Digest, Purpose, Sid};
use std::collections::{BTreeMap, BTreeSet};
// SS-128: purpose and index deliberately do not enter this seat-log digest.
pub fn put_digest(share: &[u8]) -> Digest {
    let mut bytes = b"VT1/slot-put".to_vec();
    bytes.extend(share);
    hash(&bytes)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    OracleViolation,
    NotReady,
    Fenced,
    NotOpen,
    NotFound,
    SlotBurned,
    SlotExists,
    SlotUsed,
    PutPending,
    LogUnavailable,
    SlotBoundOther,
    NoCheckpoint,
    WindowExceeded,
    SlotStale,
    Conflict,
    GroupUnavailable,
    NoQuorum,
    RecordUnavailable,
    Corrupt,
    Crashed,
    StaleVersion,
    Unavailable,
    NotCurrent,
    BadRecord,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    Free(Vec<u8>),
    Bound(Vec<u8>, Digest),
    Burned,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Body {
    pub restart_mark: u64,
    pub entries: BTreeMap<String, Vec<u8>>,
    pub slots: BTreeMap<u64, Slot>,
    // SS-128/134: tags belong to live account slots and roll back with the body.
    pub put_tags: BTreeMap<u64, [u8; 16]>,
}
fn short_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend(
        u16::try_from(bytes.len())
            .expect("SS-134 u16 length")
            .to_be_bytes(),
    );
    out.extend(bytes);
}
impl Body {
    pub fn bytes(&self, p: Purpose) -> Vec<u8> {
        self.encode(p, p.name(), false)
    }
    // SS-134/135: shared canonical body encoder; measurement names are explicit.
    pub fn encode(&self, p: Purpose, purpose: &str, accounted: bool) -> Vec<u8> {
        let mut out = vec![];
        short_blob(&mut out, purpose.as_bytes());
        out.extend(self.restart_mark.to_be_bytes());
        out.extend((self.entries.len() as u32).to_be_bytes());
        for (k, v) in &self.entries {
            short_blob(&mut out, k.as_bytes());
            out.extend((v.len() as u32).to_be_bytes());
            out.extend(v);
        }
        out.extend(
            (self.slots.values().filter(|s| **s != Slot::Burned).count() as u32).to_be_bytes(),
        );
        let mut runs: Vec<(u64, u64)> = vec![];
        for (&i, slot) in &self.slots {
            match slot {
                Slot::Free(share) | Slot::Bound(share, _) => {
                    out.extend(i.to_be_bytes());
                    out.push(if accounted || matches!(slot, Slot::Bound(..)) {
                        2
                    } else {
                        1
                    });
                    short_blob(&mut out, share);
                    if !p.sequential() {
                        // Old-rule bodies have no tag; keep their encoding deterministic.
                        out.extend(self.put_tags.get(&i).unwrap_or(&[0; 16]));
                    }
                    if let Slot::Bound(_, d) = slot {
                        out.extend(d);
                    } else if accounted {
                        out.extend([0; 32]);
                    }
                }
                Slot::Burned => {
                    if let Some(last) = runs.last_mut().filter(|r| r.1.checked_add(1) == Some(i)) {
                        last.1 = i;
                    } else {
                        runs.push((i, i));
                    }
                }
            }
        }
        out.extend((runs.len() as u32).to_be_bytes());
        for (first, last) in runs {
            out.extend(first.to_be_bytes());
            out.extend(last.to_be_bytes());
        }
        out
    }
    pub fn digest(&self, p: Purpose) -> Digest {
        hash(&self.bytes(p))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub sid: Sid,
    pub v: u64,
    pub node: usize,
    pub epoch: u64,
    pub nonce: [u8; 24],
    pub purpose: Purpose,
    pub body: Body,
    pub tag: Digest,
}
impl Record {
    // SS-008: header || 24-byte nonce || body || authentication tag.
    fn authenticated_bytes(&self) -> Vec<u8> {
        let mut b = self.sid.to_vec();
        b.extend(self.v.to_be_bytes());
        b.extend((self.node as u32).to_be_bytes());
        b.extend(self.epoch.to_be_bytes());
        b.extend(self.nonce);
        b.extend(self.body.bytes(self.purpose));
        b
    }
    pub fn seal(node: usize, p: Purpose, v: u64, body: Body, nonce: [u8; 24], key: Digest) -> Self {
        let mut r = Self {
            sid: sid(node, p),
            v,
            node,
            epoch: 1,
            nonce,
            purpose: p,
            body,
            tag: [0; 32],
        };
        r.tag = r.mac(key);
        r
    }
    fn mac(&self, key: Digest) -> Digest {
        let mut b = key.to_vec();
        b.extend(self.authenticated_bytes());
        hash(&b)
    }
    pub fn authenticates(&self, key: Digest) -> bool {
        self.tag == self.mac(key)
    }
    pub fn digest(&self) -> Digest {
        let mut b = self.authenticated_bytes();
        b.extend(self.tag);
        hash(&b)
    }
}
// SS-111: an abstract signature binds the ENTIRE statement to a real historical
// boot key. `valid` is the abstract signature verification bit, not peer trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub seat: usize,
    pub boot: u64,
    pub sid: Sid,
    pub v: u64,
    pub epoch: u64,
    pub digest: Digest,
    pub valid: bool,
}
impl Statement {
    pub fn signed(r: &Record, boot: u64) -> Self {
        Self {
            seat: r.node,
            boot,
            sid: r.sid,
            v: r.v,
            epoch: r.epoch,
            digest: r.digest(),
            valid: true,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEntry {
    pub pv: u64,
    pub pe: u64,
    pub pd: Digest,
    pub statement: Statement,
}
pub type SlotKey = (usize, Purpose, u64);
// SS-003/074/075: tier 0 survives reboot, but not replacement or rollback.
#[derive(Clone, Debug, Default)]
pub struct Tier0 {
    pub log_initialized: bool,
    pub share: bool,
    pub peers: BTreeMap<(usize, Sid), PeerEntry>,
    pub slots: BTreeMap<SlotKey, Digest>,
    pub conflicted: BTreeSet<SlotKey>,
}
#[derive(Clone, Debug, Default)]
pub struct Persist {
    pub local: BTreeMap<Sid, Vec<Record>>,
    pub replicas: BTreeMap<(usize, Sid), Record>,
}
// SS-001/002: all mutable working session state is RAM only.
#[derive(Clone, Debug)]
pub struct Session {
    pub sid: Sid,
    pub purpose: Purpose,
    pub open: bool,
    pub v: u64,
    pub v_max: u64,
    pub epoch: u64,
    pub work: Body,
    pub unsealed: BTreeSet<u64>,
    pub dirty: bool,
}
impl Session {
    pub fn new(j: usize, p: Purpose) -> Self {
        Self {
            sid: sid(j, p),
            purpose: p,
            open: false,
            v: 0,
            v_max: 0,
            epoch: 1,
            work: Body::default(),
            unsealed: BTreeSet::new(),
            dirty: false,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Ram {
    pub sessions: BTreeMap<Purpose, Session>,
    pub whole_restart: Option<bool>,
    pub cp_boot: Option<Checkpoint>,
    pub boot_counter: u64,
    pub synced: bool,
    /// Current recovery statement, retained for board-tail retransmission.
    pub restore_statement: Option<crate::board::Entry>,
    pub fetching: bool,
    pub account_burned: BTreeSet<Purpose>,
}
#[derive(Clone, Debug)]
pub struct Node {
    pub tier0: Tier0,
    pub disk: Persist,
    pub ram: Ram,
    pub up: bool,
    pub byzantine: bool,
    pub ledger_read_failure: bool,
}
impl Node {
    pub fn new() -> Self {
        Self {
            tier0: Tier0 {
                log_initialized: true,
                share: true,
                ..Tier0::default()
            },
            disk: Persist::default(),
            ram: Ram {
                boot_counter: 1,
                ..Ram::default()
            },
            up: true,
            byzantine: false,
            ledger_read_failure: false,
        }
    }
}
impl Default for Node {
    fn default() -> Self {
        Self::new()
    }
}
