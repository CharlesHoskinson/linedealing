use crate::{hash, Sid};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    Schnorr,
    Ecdsa,
}
impl Purpose {
    pub const ALL: [Self; 2] = [Self::Schnorr, Self::Ecdsa];
    pub fn name(self) -> &'static str {
        match self {
            Self::Schnorr => "schnorr",
            Self::Ecdsa => "ecdsa",
        }
    }
    pub fn sequential(self) -> bool {
        self == Self::Schnorr
    }
}
#[derive(Clone, Debug)]
pub struct Params {
    pub n: usize,
    pub f: usize,
    pub t: usize,
    pub w: usize,
    pub b: u64,
    pub cp_every: u64,
}
impl Params {
    // SS-004: one sequential pool, one account pool; anchors always false.
    pub fn new(n: usize, f: usize) -> Self {
        assert!(n > 2 * f + 1);
        Self {
            n,
            f,
            t: n - f,
            w: n - 1 - f,
            b: 8,
            cp_every: 4,
        }
    }
    pub fn c(&self) -> usize {
        self.n - 1 - 2 * self.f
    }
}
// SS-006: fixed committee bytes and big-endian u32 seat.
pub fn sid(seat: usize, p: Purpose) -> Sid {
    let mut bytes = b"VT1/session-id".to_vec();
    bytes.extend(b"discovery-committee");
    bytes.extend((seat as u32).to_be_bytes());
    bytes.extend(p.name().as_bytes());
    hash(&bytes)
}
/// Experimental test mutations. Each flag has exactly one rule branch in the model.
#[derive(Clone, Debug, Default)]
pub struct Knobs {
    /// SS-120..125: omit restart statements, marker handling and bind barrier.
    pub old_no_restart_marker: bool,
    /// SS-102: use w sources as supplied, with source-relative projection.
    pub old_fetch_w_sources: bool,
    /// SS-126/127: retain entries without fetching their ciphertexts.
    pub old_no_replica_fetch: bool,
    /// SS-128..132: omit account put records and their checks.
    pub old_no_put_record: bool,
    /// SS-133: keep whole_restart set until reboot.
    pub old_no_restart_rearm: bool,
    /// Count the former per-event Midnight transactions (accounting only).
    pub old_per_event_ledger: bool,
    /// Candidate SS-102 change: sources include their own latest signed record
    /// statement and their own slot entries, in addition to other seats' entries.
    pub fetch_owner_statement: bool,
    pub no_restart_burn: bool,
    pub no_slot_stale: bool,
    pub no_version_fence: bool,
    pub no_blank_fetch: bool,
    pub no_account_burn: bool,
    pub no_witness_before_bind: bool,
}

impl Knobs {
    pub fn old_rules() -> Self {
        Self {
            old_per_event_ledger: true,
            old_no_restart_marker: true,
            old_fetch_w_sources: true,
            old_no_replica_fetch: true,
            old_no_put_record: true,
            old_no_restart_rearm: true,
            ..Self::default()
        }
    }
}

impl From<bool> for Knobs {
    fn from(fetch_owner_statement: bool) -> Self {
        Self {
            fetch_owner_statement,
            ..Self::default()
        }
    }
}
