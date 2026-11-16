//! SS-008/134/135: canonical body sizes, 52-byte header, nonce24 and AEAD tag16.
//! Free slots count as bound for S_max. Base64 includes LF but no RPC envelope.
//! The protocol model uses an abstract 32-byte SHA-256 MAC instead of AEAD.
use crate::*;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug)]
pub enum PoolState {
    Free,
    Bound,
    Burned,
    Alternating,
    Restart,
}
impl PoolState {
    pub const ALL: [Self; 5] = [
        Self::Free,
        Self::Bound,
        Self::Burned,
        Self::Alternating,
        Self::Restart,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Free => "all_free",
            Self::Bound => "all_bound",
            Self::Burned => "all_burned",
            Self::Alternating => "alternating_burned_free",
            Self::Restart => "after_restart_burn_B",
        }
    }
}
pub struct SizeMeasurement {
    pub body: usize,
    pub accounted_body: usize,
    pub record: usize,
    pub line: usize,
    pub accounted_record: usize,
    pub accounted_line: usize,
}
/// SS-134/135: exact design encoding, with the measurement-only Schnorr name.
pub fn encode_body(body: &Body, p: Purpose, accounted: bool) -> Vec<u8> {
    body.encode(
        p,
        if p == Purpose::Schnorr {
            "schnorr-slots"
        } else {
            p.name()
        },
        accounted,
    )
}
pub fn pool_measurement(n: usize, state: PoolState, b: u64) -> SizeMeasurement {
    let mut body = Body::default();
    for i in 1..=n as u64 {
        let slot = match state {
            PoolState::Bound => Slot::Bound(vec![7; 64], hash(b"digest")),
            PoolState::Burned => Slot::Burned,
            PoolState::Alternating if i % 2 == 1 => Slot::Burned,
            PoolState::Restart if i <= b => Slot::Burned,
            _ => Slot::Free(vec![7; 64]),
        };
        body.slots.insert(i, slot);
    }
    let actual = encode_body(&body, Purpose::Schnorr, false).len();
    let accounted = encode_body(&body, Purpose::Schnorr, true).len();
    let record = actual + 92;
    let accounted_record = accounted + 92;
    SizeMeasurement {
        body: actual,
        accounted_body: accounted,
        record,
        line: 4 * record.div_ceil(3) + 1,
        accounted_record,
        accounted_line: 4 * accounted_record.div_ceil(3) + 1,
    }
}

pub struct RestartMeasurement {
    pub sequential: u64,
    pub account: u64,
    pub voided: u64,
    pub union: u64,
}
fn restart_setup(b: u64) -> Sim {
    let mut params = Params::new(4, 1);
    params.b = b;
    let mut s = Sim::new(params, 42);
    // SS-068: pending index 1 lies below the new window (h=1).
    s.request(Purpose::Schnorr).unwrap();
    s.post_checkpoint().unwrap();
    for j in 0..4 {
        s.slot_put(j, Purpose::Schnorr, 1, vec![7; 64]).unwrap();
        s.checkpoint(j, Purpose::Schnorr).unwrap();
        for i in 1..=16 {
            s.slot_put(j, Purpose::Ecdsa, i, vec![j as u8, i as u8])
                .unwrap();
        }
        s.checkpoint(j, Purpose::Ecdsa).unwrap();
    }
    s.inject(Fault::WholeCommitteeRestart);
    s
}
pub fn restart_measurement(b: u64) -> RestartMeasurement {
    let mut s = restart_setup(b);
    s.recover_all();
    let sequential = s
        .session(0, Purpose::Schnorr)
        .work
        .slots
        .values()
        .filter(|x| **x == Slot::Burned)
        .count() as u64;
    let account = s
        .session(0, Purpose::Ecdsa)
        .work
        .slots
        .values()
        .filter(|x| **x == Slot::Burned)
        .count() as u64;
    s.post_checkpoint().unwrap();
    let voided = s
        .trace
        .iter()
        .filter(|e| matches!(e, oracle::Event::End { void: true, .. }))
        .count() as u64;
    // SS-067/104/112: two RestoreDone statements let cp2 advance h by B,
    // but only two seats are continuous, so seat 1 classifies another burn.
    let mut split = restart_setup(b);
    for j in [0, 2] {
        split.sync(j).unwrap();
    }
    let first = split.open(0, Purpose::Schnorr).unwrap();
    split.post_checkpoint().unwrap();
    let second = split.open(1, Purpose::Schnorr).unwrap();
    assert_ne!(
        split.nodes[0].ram.cp_boot.as_ref().unwrap().seq,
        split.nodes[1].ram.cp_boot.as_ref().unwrap().seq
    );
    let union = first
        .into_iter()
        .chain(second)
        .collect::<BTreeSet<_>>()
        .len() as u64;
    RestartMeasurement {
        sequential,
        account,
        voided,
        union,
    }
}
/// SS-063: Sixteen complete checkpoint intervals, normalized per 1,000 binds. The application
/// reserves unique indices even when a bind is refused and checkpoints each interval.
/// No normal-driver request() clipping is used: refused attempts must be measured.
pub fn window_refusals(b: u64, rate: u64) -> f64 {
    let mut params = Params::new(4, 1);
    params.b = b;
    let mut s = Sim::new(params, 42);
    let mut refused = 0;
    for i in 1..=16 * rate {
        if (i - 1) % rate == 0 {
            s.post_checkpoint().unwrap();
        }
        s.h_next = i;
        s.slot_put(0, Purpose::Schnorr, i, vec![7; 64]).unwrap();
        // Bound bodies would grow quadratically across successful binds.
        // Burn/compact after each successful bind to measure the window only.
        let result = s.slot_bind(0, Purpose::Schnorr, i, hash(&i.to_be_bytes()));
        if result == Err(Error::WindowExceeded) {
            refused += 1;
        } else {
            result.unwrap();
        }
        s.slot_burn(0, Purpose::Schnorr, i).unwrap();
    }
    1000.0 * refused as f64 / (16 * rate) as f64
}

/// Identical workload for the fixed checkpoint model and the per-event accounting knob.
pub fn midnight_measurement(n: usize, f: usize, old: bool) -> crate::ledger::Midnight {
    let mut s = Sim::new_with_knobs(
        Params::new(n, f),
        731,
        Knobs {
            old_per_event_ledger: old,
            ..Knobs::default()
        },
    );
    s.run(12);
    s.inject(Fault::WholeCommitteeRestart);
    s.recover_all();
    s.post_checkpoint().unwrap();
    assert!(s.oracle.violations.is_empty());
    s.ledger.midnight
}
