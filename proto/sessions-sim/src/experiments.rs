//! Reachable app/restore schedules for SS-102, QI-01 and QI-02.
use crate::{oracle::LossReading, *};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeriesKind {
    Fence,
    Sequential,
    Account,
}
impl SeriesKind {
    pub const ALL: [Self; 3] = [Self::Fence, Self::Sequential, Self::Account];
}
pub struct SeriesResult {
    pub sim: Sim,
    pub resurrected: bool,
    pub second_release: bool,
    pub open_result: Result<Vec<u64>, Error>,
    pub bind_result: Option<Result<u64, Error>>,
}
pub const SERIES_PARAMS: [(usize, usize); 5] = [(4, 1), (7, 2), (5, 1), (6, 2), (9, 2)];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeriesTail {
    Rollback,
    CheckpointThenRollback,
    ReplaceOwner,
}
/// SS-102/016/050/055/064: all protocol requests originate in app calls or restore.
/// For n=7, w=4 exceeds owner + non-holders (3), so one retained holder is required.
/// A shuffled holder order and a checkpoint between each replacement exercise the
/// schedule family without injecting a stale PRF request or editing node state.
pub fn replacement_series(
    params: Params,
    seed: u64,
    kind: SeriesKind,
    knobs: impl Into<Knobs>,
    reading: LossReading,
) -> SeriesResult {
    replacement_series_tail(params, seed, kind, knobs, reading, SeriesTail::Rollback)
}

pub fn replacement_series_tail(
    params: Params,
    seed: u64,
    kind: SeriesKind,
    knobs: impl Into<Knobs>,
    reading: LossReading,
    tail: SeriesTail,
) -> SeriesResult {
    let mut s = Sim::new_with_knobs(params, seed, knobs.into());
    s.oracle.reading = reading;
    s.oracle.observe_only = true;
    let p = if kind == SeriesKind::Account {
        Purpose::Ecdsa
    } else {
        Purpose::Schnorr
    };
    let request = if kind != SeriesKind::Fence {
        let r = s.request(p).unwrap();
        s.post_checkpoint().unwrap(); // SS-064: index 1 remains pending throughout.
        s.slot_put(0, p, r.index, vec![9; 64]).unwrap();
        s.post_checkpoint().unwrap();
        Some(r)
    } else {
        s.put(0, p, "erased", vec![9]).unwrap();
        None
    };
    assert_eq!(s.checkpoint(0, p), Ok(1));
    let snapshot = s.snapshot();
    let mut holders: Vec<_> = (1..s.params.n).collect();
    let mut rng = Rng(seed ^ 0xa102);
    for i in (1..holders.len()).rev() {
        let other = rng.next_u64() as usize % (i + 1);
        holders.swap(i, other);
    }
    holders.truncate(s.params.w);
    s.witness_peers = Some(holders.iter().copied().collect());
    if let Some(r) = &request {
        assert_eq!(s.slot_bind(0, p, r.index, r.digest), Ok(2));
        assert!(s.release(0, p, r.index, r.digest));
    } else {
        assert_eq!(s.destroy(0, p, "erased"), Ok(2));
    }
    s.witness_peers = None;
    let mut clean: BTreeSet<_> = (1..s.params.n).filter(|j| !holders.contains(j)).collect();
    for &j in &holders {
        s.inject(Fault::ReplaceSlot(j));
        let mut sources = BTreeSet::from([0]);
        sources.extend(clean.iter().copied().take(s.params.w - 1));
        // SS-102: if w-1 > f, a w-answer fetch needs an informed holder.
        for &k in &holders {
            if sources.len() == s.params.w {
                break;
            }
            if k != j {
                sources.insert(k);
            }
        }
        assert_eq!(sources.len(), s.params.w);
        assert!(!sources.contains(&j));
        s.sync_peers = Some(sources);
        s.sync(j).unwrap();
        assert!(!s.nodes[j].ram.fetching);
        s.sync_peers = None;
        // Repairs the new share from t live shares, then restores its own sessions.
        // The owner stays running and never asks for its old version.
        s.recover_all();
        clean.insert(j);
        s.step += 1;
        // Preserve continuity and the pending request between replacements.
        s.post_checkpoint().unwrap();
    }
    if tail == SeriesTail::CheckpointThenRollback {
        // SS-023/045: a new session checkpoint replenishes records and fences.
        assert!(s.checkpoint(0, p).is_ok());
    }
    if tail == SeriesTail::ReplaceOwner {
        s.inject(Fault::ReplaceSlot(0));
    } else {
        s.inject(Fault::RollbackSeat(0, snapshot));
    }
    let open_result = s.open(0, p);
    let resurrected = s.get(0, p, "erased") == Ok(vec![9]);
    let mut second_release = false;
    let mut bind_result = None;
    if let Some(r) = request {
        if p.sequential() {
            assert!(s.board.pending.contains(&r.index));
        }
        let d2 = hash(b"second ticket");
        bind_result = Some(s.slot_bind(0, p, r.index, d2));
        second_release = s.release(0, p, r.index, d2);
    }
    s.check_recovery();
    SeriesResult {
        sim: s,
        resurrected,
        second_release,
        open_result,
        bind_result,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    SealdCrash,
    VmReboot,
    ReplaceSlot,
    WholeCommitteeRestart,
    CoordinatedRollback,
    ByzantinePeer,
    LedgerReadFailure,
    ReplaceSeriesThenRollback,
    Mixed,
}
impl FailureKind {
    pub const ALL: [Self; 9] = [
        Self::SealdCrash,
        Self::VmReboot,
        Self::ReplaceSlot,
        Self::WholeCommitteeRestart,
        Self::CoordinatedRollback,
        Self::ByzantinePeer,
        Self::LedgerReadFailure,
        Self::ReplaceSeriesThenRollback,
        Self::Mixed,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::SealdCrash => "seald_crash",
            Self::VmReboot => "vm_reboot",
            Self::ReplaceSlot => "replace_slot",
            Self::WholeCommitteeRestart => "whole_committee_restart",
            Self::CoordinatedRollback => "coordinated_rollback",
            Self::ByzantinePeer => "byzantine_peer",
            Self::LedgerReadFailure => "ledger_read_failure",
            Self::ReplaceSeriesThenRollback => "replace_series_then_rollback",
            Self::Mixed => "mixed",
        }
    }
}
pub struct RunResult {
    pub sim: Sim,
    pub a_counterexample: bool,
    pub series: bool,
    pub absent_account_keys: BTreeSet<(usize, Purpose, u64)>,
    /// Recovery rounds after the last injected fault. None is right-censored.
    pub recovery_steps: Option<u64>,
}
fn all_open(s: &Sim) -> bool {
    s.nodes.iter().filter(|n| !n.byzantine).all(|n| {
        n.up && Purpose::ALL
            .iter()
            .all(|p| n.ram.sessions.get(p).is_some_and(|x| x.open))
    })
}
/// SS-030/036: one recovery step is one complete sync/repair/open sweep.
fn recover(s: &mut Sim) -> Option<u64> {
    for step in 1..=3 {
        s.recover_all();
        if all_open(s) {
            return Some(step);
        }
    }
    None
}
/// SS-102 series schedules are part of the random mixed distribution (1 in 4).
/// Other mixed runs use three seeded fault kinds and seats. RNG has no OS input.
pub fn run_case(
    params: Params,
    seed: u64,
    kind: FailureKind,
    knobs: impl Into<Knobs>,
    reading: LossReading,
) -> RunResult {
    let knobs = knobs.into();
    // Independent reproducible streams prevent different fault rows from
    // receiving identical schedules merely because they use the same seed range.
    let mut rng = Rng(seed ^ 0xb002 ^ (kind as u64).wrapping_mul(0x9e3779b97f4a7c15));
    if kind == FailureKind::ReplaceSeriesThenRollback
        || (kind == FailureKind::Mixed && rng.next_u64().is_multiple_of(4))
    {
        let which = SeriesKind::ALL[(rng.next_u64() % 3) as usize];
        let result = replacement_series(params, seed, which, knobs, reading);
        let mut s = result.sim;
        let recovery_steps = recover(&mut s);
        return RunResult {
            sim: s,
            a_counterexample: result.resurrected || result.second_release,
            series: true,
            absent_account_keys: BTreeSet::new(),
            recovery_steps,
        };
    }
    let mut s = Sim::new_with_knobs(params, seed, knobs);
    s.oracle.reading = reading;
    s.oracle.observe_only = true;
    s.run(1 + rng.next_u64() % 2);
    let snapshot = s.snapshot();
    let count = if kind == FailureKind::Mixed { 3 } else { 1 };
    // Declare the schedule so early observations use the complete run's bounds.
    let schedule: Vec<_> = (0..count)
        .map(|_| {
            let k = if kind == FailureKind::Mixed {
                FailureKind::ALL[(rng.next_u64() % 7) as usize]
            } else {
                kind
            };
            (
                k,
                rng.next_u64() as usize % s.params.n,
                1 + rng.next_u64() % 6,
                rng.next_u64() % 5,
            )
        })
        .collect();
    let mut losses = BTreeSet::new();
    for &(k, j, _, _) in &schedule {
        if matches!(
            k,
            FailureKind::WholeCommitteeRestart | FailureKind::CoordinatedRollback
        ) {
            s.oracle.planned_out_of_bound = true;
        }
        if k == FailureKind::ByzantinePeer
            || (k == FailureKind::ReplaceSlot && reading == LossReading::Literal)
        {
            losses.insert(j);
        }
    }
    s.oracle.planned_out_of_bound |= losses.len() > s.params.c();
    let mut recovery_steps = None;
    let mut absent_account_keys = BTreeSet::new();
    for (k, j, steps, point) in schedule {
        s.run(steps);
        // SS-021/024/050/051/036: seed the seat, app step and interruption.
        // A cut crashes seald at the operation boundary, then applies the row's
        // named disk/availability fault before recovery. DuringRestore cuts the
        // first open after that fault. None leaves the operation uninterrupted.
        let victim = if k == FailureKind::ByzantinePeer {
            (j + 1 + rng.next_u64() as usize % (s.params.n - 1)) % s.params.n
        } else {
            j
        };
        let p = Purpose::Ecdsa;
        let request = s.request(p).unwrap();
        let _ = s.slot_put(
            victim,
            p,
            request.index,
            vec![victim as u8, request.index as u8],
        );
        let _ = s.checkpoint(victim, p);
        // Explicit experiment boundary: cover the put before arming bind crash cuts.
        let _ = s.post_checkpoint();
        let mut peers: Vec<_> = (0..s.params.n).filter(|k| *k != victim).collect();
        for i in (1..peers.len()).rev() {
            let other = rng.next_u64() as usize % (i + 1);
            peers.swap(i, other);
        }
        peers.truncate(rng.next_u64() as usize % s.params.w);
        s.crash_point = match point {
            1 => Some(CrashPoint::AfterFsync),
            2 => Some(CrashPoint::AfterWitnessAcks { peers }),
            3 => Some(CrashPoint::AfterSlotAcks),
            _ => None,
        };
        let _ = s.slot_bind(victim, p, request.index, request.digest);
        s.release(victim, p, request.index, request.digest);
        // A previous mixed fault can leave this session closed; never let an
        // unconsumed cut migrate silently into an unrelated recovery operation.
        s.crash_point = None;
        match k {
            FailureKind::SealdCrash => s.inject(Fault::SealdCrash(j)),
            FailureKind::VmReboot => s.inject(Fault::VmReboot(j)),
            FailureKind::ReplaceSlot => s.inject(Fault::ReplaceSlot(j)),
            FailureKind::WholeCommitteeRestart => s.inject(Fault::WholeCommitteeRestart),
            FailureKind::CoordinatedRollback => {
                // SS-114 burns present slots only. Retain exact ghost evidence
                // for the separately documented absent-account counterexample.
                for &(owner, p, i) in s.oracle.releases.keys() {
                    if !p.sequential()
                        && snapshot.0[owner]
                            .1
                            .local
                            .get(&sid(owner, p))
                            .is_none_or(|rs| rs.iter().all(|r| !r.body.slots.contains_key(&i)))
                    {
                        absent_account_keys.insert((owner, p, i));
                    }
                }
                s.inject(Fault::CoordinatedRollback(snapshot.clone()));
            }
            FailureKind::ByzantinePeer => {
                // SS-111/116: leave a real signed record and slot entry at the
                // adversary, then advance the owner while its replica is stale.
                recover(&mut s);
                s.inject(Fault::ByzantinePeer(j));
                let _ = s.put(victim, p, "fresh-after-byzantine", vec![1]);
                let _ = s.checkpoint(victim, p);
                s.first_sync_peer = Some(j); // seeded first response, not trust
                if rng.next_u64().is_multiple_of(2) {
                    s.inject(Fault::ReplaceSlot(victim));
                } else {
                    s.inject(Fault::VmReboot(victim));
                }
            }
            FailureKind::LedgerReadFailure => {
                s.inject(Fault::VmReboot(j));
                s.inject(Fault::LedgerReadFailure(j));
                assert_eq!(s.open(j, Purpose::Schnorr), Err(Error::NotReady));
                s.inject(Fault::LedgerReadRecovered(j));
            }
            _ => unreachable!(),
        }
        if point == 4 {
            s.crash_point = Some(CrashPoint::DuringRestore);
            let _ = s.open(victim, p);
            s.crash_point = None;
        }
        recovery_steps = recover(&mut s);
        // SS-050/055: app probes only indices that really released before the fault.
        let released: Vec<_> = s.oracle.releases.keys().copied().collect();
        for (owner, p, i) in released {
            let d2 = hash(&rng.next_u64().to_be_bytes());
            // SS-048/114, Q-11 (formerly Q-13): model board re-delivery of the
            // ORIGINAL dealt share, retained only in ghost application history.
            let share = s.oracle.first_shares[&(owner, p, i)].clone();
            let _ = s.slot_put(owner, p, i, share);
            let _ = s.slot_bind(owner, p, i, d2);
            s.release(owner, p, i, d2);
        }
        s.run(1);
    }
    RunResult {
        sim: s,
        a_counterexample: false,
        series: false,
        absent_account_keys,
        recovery_steps,
    }
}

#[derive(Default, Debug)]
pub struct Totals {
    pub runs: usize,
    pub bounds: [usize; 2],
    pub violations: [[usize; 2]; 3],
    pub same_share: [usize; 2],
    pub byzantine_fired: [usize; 4],
    /// Per-run reported outcomes, excluding seeds, seat labels and random bytes.
    pub outcomes: BTreeSet<Vec<u64>>,
    pub expected: usize,
    pub a_class: usize,
    /// Runs with a second release on an account slot absent from the rollback snapshot (QUESTIONS Q-11).
    pub q13_class: usize,
    pub reopened: usize,
    pub sessions: usize,
    pub releases: usize,
    pub refusals: [usize; 4],
    pub voided: usize,
    pub burned: usize,
    pub recovery_sum: u64,
    pub recovered_runs: usize,
    pub midnight_tx: u64,
    pub midnight_bytes: u64,
}
impl Totals {
    pub fn add(&mut self, r: &RunResult) {
        let mut row = Self::default();
        row.accumulate(r);
        let mut outcome = vec![
            row.expected as u64,
            row.a_class as u64,
            row.q13_class as u64,
            row.reopened as u64,
            row.sessions as u64,
            row.releases as u64,
            row.voided as u64,
            row.burned as u64,
            row.recovery_sum,
            row.recovered_runs as u64,
            row.midnight_tx,
            row.midnight_bytes,
        ];
        outcome.extend(row.bounds.map(|v| v as u64));
        outcome.extend(row.violations.into_iter().flatten().map(|v| v as u64));
        outcome.extend(row.same_share.map(|v| v as u64));
        outcome.extend(row.refusals.map(|v| v as u64));
        outcome.extend(row.byzantine_fired.map(|v| v as u64));
        self.outcomes.insert(outcome);
        self.accumulate(r);
    }
    fn accumulate(&mut self, r: &RunResult) {
        use crate::oracle::Event;
        self.runs += 1;
        let s = &r.sim;
        self.midnight_tx += s.ledger.midnight.tx();
        self.midnight_bytes += s.ledger.midnight.bytes;
        let bound = usize::from(!s.in_bound());
        self.bounds[bound] += 1;
        self.same_share[bound] +=
            usize::from(s.oracle.share_releases.values().any(|ds| ds.len() > 1));
        for (sum, count) in self
            .byzantine_fired
            .iter_mut()
            .zip(s.oracle.byzantine_fired)
        {
            *sum += count;
        }
        for (i, label) in ["G2/G3", "G4", "G1"].iter().enumerate() {
            if s.oracle.violations.iter().any(|v| v.contains(label)) {
                self.violations[i][bound] += 1;
            }
        }
        self.expected += s.oracle.expected.len();
        self.a_class += usize::from(r.a_counterexample);
        self.q13_class += usize::from(
            r.absent_account_keys
                .iter()
                .any(|k| r.sim.oracle.releases.get(k).is_some_and(|d| d.len() > 1)),
        );
        for n in s.nodes.iter().filter(|n| !n.byzantine) {
            for p in Purpose::ALL {
                self.sessions += 1;
                self.reopened +=
                    usize::from(n.up && n.ram.sessions.get(&p).is_some_and(|x| x.open));
            }
        }
        self.releases += s.oracle.releases.values().map(|v| v.len()).sum::<usize>();
        // Count burn transitions, including absent indices in restart windows.
        for e in &s.trace {
            match e {
                Event::BindRefused { reason } => {
                    let i = match reason {
                        Error::WindowExceeded => Some(0),
                        Error::SlotStale => Some(1),
                        Error::NoCheckpoint => Some(2),
                        Error::Conflict | Error::SlotBoundOther => Some(3),
                        _ => None,
                    };
                    if let Some(i) = i {
                        self.refusals[i] += 1;
                    }
                }
                Event::End { void: true, .. } => self.voided += 1,
                Event::Burned { indices, .. } => self.burned += indices.len(),
                _ => (),
            }
        }
        if let Some(steps) = r.recovery_steps {
            self.recovery_sum += steps;
            self.recovered_runs += 1;
        }
    }
}
