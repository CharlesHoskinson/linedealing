use crate::node::{Persist, Tier0};
#[derive(Clone, Debug)]
pub enum Fault {
    SealdCrash(usize),
    VmReboot(usize),
    ReplaceSlot(usize),
    WholeCommitteeRestart,
    CoordinatedRollback(Snapshot),
    RollbackSeat(usize, Snapshot),
    ByzantinePeer(usize),
    LedgerReadFailure(usize),
    LedgerReadRecovered(usize),
    Withhold(usize),
    ServeLog(usize),
    LoseTail,
    LoseCovered(usize),
    Down(usize),
    Up(usize),
}
/// Only disk classes are snapshotted; the board, ledger, RNG and oracle never roll back.
#[derive(Clone, Debug)]
pub struct Snapshot(pub Vec<(Tier0, Persist)>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    AfterFsync,
    AfterWitnessAcks { peers: Vec<usize> },
    AfterSlotAcks,
    DuringRestore,
}
