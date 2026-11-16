use crate::{board::seat_root, Digest, Params};
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub seq: u64,
    pub restart_seq: u64,
    pub h: u64,
    pub pending_min: u64,
    pub pending_root: Digest,
    pub pending_count: u32,
    pub boot_counters: Vec<u64>,
    /// Submission input only: consumed by the contract, never retained in history.
    pub batch_root: Vec<Digest>,
    pub seat_root: Vec<Digest>,
    pub restores: Vec<RestoreDone>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Floor,
    Restart,
    RestoreDone,
    Sequence,
    RestartMarker,
    LogUnavailable,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreDone {
    pub seat: usize,
    pub boot: u64,
    pub seq: u64,
    pub whole_restart: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Midnight {
    pub checkpoints: u64,
    pub boot_tickets: u64,
    pub put_records: u64,
    pub restore_transactions: u64,
    pub bytes: u64,
}
impl Midnight {
    pub fn tx(&self) -> u64 {
        self.checkpoints + self.boot_tickets + self.put_records + self.restore_transactions
    }
}
#[derive(Clone, Debug)]
pub struct Ledger {
    pub boots: Vec<u64>,
    pub tickets: BTreeSet<(usize, u64)>,
    pub cp: Option<Checkpoint>,
    pub history: Vec<Checkpoint>,
    pub refusals: Vec<Refusal>,
    pub midnight: Midnight,
    /// Accounting comparison only; protocol decisions still use checkpoints.
    pub old_per_event_ledger: bool,
}
impl Ledger {
    pub fn new(n: usize) -> Self {
        Self {
            boots: vec![1; n],
            tickets: (0..n).map(|j| (j, 1)).collect(),
            cp: None,
            history: vec![],
            refusals: vec![],
            midnight: Midnight {
                boot_tickets: n as u64,
                bytes: 150 * n as u64,
                ..Midnight::default()
            },
            old_per_event_ledger: false,
        }
    }
    pub fn reboot(&mut self, seat: usize) -> u64 {
        self.boots[seat] += 1;
        self.tickets.insert((seat, self.boots[seat]));
        self.midnight.boot_tickets += 1;
        self.midnight.bytes += 150;
        self.boots[seat]
    }
    pub fn statements(&self) -> impl Iterator<Item = &RestoreDone> {
        self.history.iter().flat_map(|cp| &cp.restores)
    }
    pub fn restart_pending(&self, old: &Checkpoint, current: &[RestoreDone]) -> bool {
        self.statements()
            .chain(current)
            .any(|d| d.whole_restart && d.seq >= old.restart_seq)
    }
    pub fn latest_done(&self, current: &[RestoreDone]) -> Vec<u64> {
        (0..self.boots.len())
            .map(|j| {
                self.statements()
                    .chain(current)
                    .filter(|d| d.seat == j)
                    .map(|d| d.boot)
                    .max()
                    .unwrap_or(0)
            })
            .collect()
    }
    pub fn continuous(&self, cp: &Checkpoint) -> usize {
        self.boots
            .iter()
            .zip(&cp.boot_counters)
            .filter(|(a, b)| a == b)
            .count()
    }
    pub fn validate(&self, next: &Checkpoint, p: &Params) -> Result<(), Refusal> {
        if next.boot_counters.len() != p.n
            || next
                .restores
                .iter()
                .any(|d| !self.tickets.contains(&(d.seat, d.boot)))
            || next.boot_counters.iter().enumerate().any(|(j, b)| {
                !self
                    .statements()
                    .chain(&next.restores)
                    .any(|d| d.seat == j && d.boot == *b)
            })
        {
            return Err(Refusal::RestoreDone);
        }
        if let Some(old) = &self.cp {
            if next.seq <= old.seq {
                return Err(Refusal::Sequence);
            }
            if next.h < old.h {
                return Err(Refusal::Floor);
            }
            let marker = if self.restart_pending(old, &next.restores) {
                next.seq
            } else {
                old.restart_seq
            };
            if next.restart_seq != marker {
                return Err(Refusal::RestartMarker);
            }
            let same = old
                .boot_counters
                .iter()
                .zip(&next.boot_counters)
                .filter(|(a, b)| a == b)
                .count();
            if same < p.w + 1
                && (next.h < old.h.saturating_add(p.b)
                    || next.pending_min <= old.h.saturating_add(p.b))
            {
                return Err(Refusal::Restart);
            }
        } else if next.restart_seq != 0 {
            return Err(Refusal::RestartMarker);
        }
        if next.batch_root.len() != p.n {
            return Err(Refusal::LogUnavailable);
        }
        Ok(())
    }
    pub fn post(&mut self, mut next: Checkpoint, p: &Params) -> Result<(), Refusal> {
        // A submitted transaction counts even if the contract refuses it.
        self.midnight.checkpoints += 1;
        let q = (p.n + p.f + 1).div_ceil(2);
        self.midnight.bytes += (88
            + 52
            + 8 * p.n
            + 8
            + 32 * p.n
            + 64 * q
            + if self.old_per_event_ledger {
                0
            } else {
                115 * next.restores.len()
            }) as u64;
        if let Err(e) = self.validate(&next, p) {
            self.refusals.push(e);
            return Err(e);
        }
        next.seat_root = next
            .batch_root
            .iter()
            .enumerate()
            .map(|(j, b)| seat_root(self.cp.as_ref().map_or([0; 32], |cp| cp.seat_root[j]), *b))
            .collect();
        next.batch_root.clear();
        self.history.push(next.clone());
        self.cp = Some(next);
        Ok(())
    }
}
