//! Board storage is independent of every node disk. Positions never roll back.
use crate::{
    hash,
    ledger::{Checkpoint, Ledger, RestoreDone},
    Digest,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Put {
        digest: Digest,
        tag: [u8; 16],
    },
    Restore {
        boot: u64,
        seq: u64,
        whole_restart: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posted {
    pub position: u64,
    pub entry: Entry,
}
#[derive(Clone, Debug)]
pub struct Board {
    pub logs: Vec<Vec<Posted>>,
    withheld: BTreeSet<usize>,
    position: u64,
    /// Only landed checkpoints create batch boundaries.
    boundaries: BTreeMap<u64, u64>,
    pub pending: BTreeSet<u64>,
}

pub fn pending_root(pending: &BTreeSet<u64>) -> Digest {
    let mut bytes = b"VT1/pending".to_vec();
    for i in pending {
        bytes.extend(i.to_be_bytes());
    }
    hash(&bytes)
}
pub fn batch_root(entries: &[Posted]) -> Digest {
    let mut bytes = b"VT1/seat-batch".to_vec();
    for posted in entries {
        bytes.extend(posted.position.to_be_bytes());
        match &posted.entry {
            Entry::Put { digest, tag } => {
                bytes.push(0);
                bytes.extend(digest);
                bytes.extend(tag);
            }
            Entry::Restore {
                boot,
                seq,
                whole_restart,
            } => {
                bytes.push(1);
                bytes.extend(boot.to_be_bytes());
                bytes.extend(seq.to_be_bytes());
                bytes.push(u8::from(*whole_restart));
            }
        }
    }
    hash(&bytes)
}
pub fn seat_root(previous: Digest, batch: Digest) -> Digest {
    let mut bytes = b"VT1/seat-log".to_vec();
    bytes.extend(previous);
    bytes.extend(batch);
    hash(&bytes)
}
impl Board {
    pub fn new(n: usize) -> Self {
        Self {
            logs: vec![vec![]; n],
            withheld: BTreeSet::new(),
            position: 0,
            boundaries: BTreeMap::new(),
            pending: BTreeSet::new(),
        }
    }
    pub fn post(&mut self, seat: usize, entry: Entry) {
        self.position += 1;
        self.logs[seat].push(Posted {
            position: self.position,
            entry,
        });
    }
    pub fn withhold(&mut self, seat: usize) {
        self.withheld.insert(seat);
    }
    pub fn serve(&mut self, seat: usize) {
        self.withheld.remove(&seat);
    }
    pub fn covered_position(&self) -> u64 {
        self.boundaries.last_key_value().map_or(0, |(_, end)| *end)
    }
    pub fn lose_tail(&mut self) {
        let end = self.covered_position();
        for log in &mut self.logs {
            log.retain(|e| e.position <= end);
        }
    }
    pub fn lose_covered(&mut self, seat: usize) {
        let end = self.covered_position();
        self.logs[seat].retain(|e| e.position > end);
    }
    /// Replay bytes, not cached hashes. Missing or changed covered data fails closed.
    pub fn verified<'a>(&'a self, seat: usize, ledger: &Ledger) -> Option<&'a [Posted]> {
        if self.withheld.contains(&seat) {
            return None;
        }
        let mut root = [0; 32];
        let mut start = 0;
        for cp in &ledger.history {
            let end = *self.boundaries.get(&cp.seq)?;
            let entries: Vec<_> = self.logs[seat]
                .iter()
                .filter(|e| e.position > start && e.position <= end)
                .cloned()
                .collect();
            root = seat_root(root, batch_root(&entries));
            if cp.seat_root.get(seat) != Some(&root) {
                return None;
            }
            start = end;
        }
        if let Some(cp) = &ledger.cp {
            if cp.seat_root.get(seat) != Some(&root) {
                return None;
            }
        }
        Some(&self.logs[seat])
    }
    pub fn batches(&self, ledger: &Ledger) -> Option<(Vec<Digest>, Vec<RestoreDone>)> {
        let mut roots = vec![];
        let mut restores = vec![];
        for seat in 0..self.logs.len() {
            let entries: Vec<_> = self
                .verified(seat, ledger)?
                .iter()
                .filter(|e| e.position > self.covered_position())
                .cloned()
                .collect();
            roots.push(batch_root(&entries));
            for e in entries {
                if let Entry::Restore {
                    boot,
                    seq,
                    whole_restart,
                } = e.entry
                {
                    restores.push(RestoreDone {
                        seat,
                        boot,
                        seq,
                        whole_restart,
                    });
                }
            }
        }
        Some((roots, restores))
    }
    pub fn landed(&mut self, cp: &Checkpoint, pending: BTreeSet<u64>) {
        self.boundaries.insert(cp.seq, self.position);
        self.pending = pending;
    }
}
