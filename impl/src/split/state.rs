//! Pure committee reducer for DESIGN §§4.1, 4.7, 5 and 7.7.
//!
//! `apply` consumes an authenticated, totally ordered log. Verification flags
//! come from trusted proof, chain, and decoding adapters. This module checks no
//! cryptography and stores no secrets. FINAL and VOID posts count independently
//! of the evaluator's chain view, with separate thresholds for each epoch.
//! Witness acks model durable peer storage. Production adapters must persist
//! them before sending partials and execute the returned erasure obligations.

use super::profile::{Charter, ProfileError, Source, SourceEvidence};
use crate::board::Committee;
use std::collections::{BTreeMap, BTreeSet};

pub type Digest = [u8; 32];
pub type Eid = Digest;
pub type NodeId = u16;
pub type Epoch = u64;
pub const G_MAX: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Suite {
    Bip340,
    Ed25519,
    Ecdsa,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlotId {
    Schnorr {
        suite: Suite,
        epoch: Epoch,
        index: u64,
    },
    Ecdsa {
        record: Digest,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Free,
    Named(Eid),
    Reserved(Eid),
    Claimed(Eid),
    Burned,
}
impl SlotState {
    fn owner(self) -> Option<Eid> {
        match self {
            Self::Named(e) | Self::Reserved(e) | Self::Claimed(e) => Some(e),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VoidReason {
    ShareComplaint,
    AuthorizationRefused,
    Revoked,
    FailedReleaseCheck,
    FailedContribution,
    SlotTaken,
    Stalled,
    DealerFault,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Posted,
    Ordered,
    Opened,
    Collecting,
    Admitted,
    Anchored(u16),
    Released { generation: u16, variant: u16 },
    Final(Digest),
    Void(VoidReason),
    Expired,
}
impl State {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Final(_) | Self::Void(_) | Self::Expired)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    Successor(Digest),
    /// The adapter creates a fresh nullifier. The old one remains consumed.
    UnspentFreshNullifier,
    Released {
        pin: Digest,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicChecks {
    pub frame: bool,
    pub version: bool,
    pub epoch: bool,
    pub keylist: bool,
    pub expiry: bool,
    pub pi_binds_eid: bool,
}
impl PublicChecks {
    pub fn verified() -> Self {
        Self {
            frame: true,
            version: true,
            epoch: true,
            keylist: true,
            expiry: true,
            pi_binds_eid: true,
        }
    }
    fn valid(self) -> bool {
        self.frame && self.version && self.epoch && self.keylist && self.expiry && self.pi_binds_eid
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub eid: Eid,
    pub hd: Digest,
    pub dd: Digest,
    pub auth_ref: Digest,
    pub epoch: Epoch,
    pub exp: u64,
    pub checks: PublicChecks,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub variant: u16,
    pub generation: u16,
    pub input: u16,
    pub slot: SlotId,
    pub digest: Digest,
    /// Membership under slr_own for owner/recovery, slr_G for seizure.
    pub in_source_root: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub hash: Digest,
    /// Opaque rule commitment checked by the deterministic selection adapter.
    pub selection_rule: Digest,
    pub charter: Charter,
    pub source: Source,
    pub record: Digest,
    pub nf: Digest,
    pub pin: Digest,
    pub outputs: Vec<Digest>,
    pub checks: SourceEvidence,
    pub suite: Suite,
    pub variants: u16,
    pub inputs: u16,
    /// Schnorr: generation-major. ECDSA: variant-major.
    pub slots: Vec<SlotId>,
    pub tickets: Vec<Ticket>,
    pub actors: Vec<u16>,
    pub embedded: Vec<u16>,
    /// AEAD, point distinctness, actor pairs, lengths, and TEE intent checks.
    pub valid: bool,
}
impl Header {
    pub fn generations(&self) -> u16 {
        self.variants.min(G_MAX)
    }
    fn collecting(&self) -> bool {
        self.actors.iter().any(|a| !self.embedded.contains(a))
    }
    fn validate(&self, epoch: Epoch) -> Result<(), SplitError> {
        self.charter.validate()?;
        if !self.valid
            || self.variants == 0
            || self.variants > 8
            || self.inputs == 0
            || self.inputs > 2
        {
            return Err(SplitError::Header);
        }
        let count = if self.suite == Suite::Ecdsa {
            self.variants
        } else {
            self.generations()
        };
        if self.slots.len() != usize::from(count * self.inputs)
            || self.slots.iter().collect::<BTreeSet<_>>().len() != self.slots.len()
        {
            return Err(SplitError::Header);
        }
        for slot in &self.slots {
            match slot {
                SlotId::Schnorr {
                    suite, epoch: e, ..
                } if *suite == self.suite && *suite != Suite::Ecdsa && *e == epoch => {}
                SlotId::Ecdsa { .. } if self.suite == Suite::Ecdsa => {}
                _ => return Err(SplitError::Header),
            }
        }
        let mut expected = BTreeSet::new();
        for v in 1..=self.variants {
            if self.suite == Suite::Ecdsa {
                for i in 1..=self.inputs {
                    expected.insert((v, 0, i));
                }
            } else {
                for g in 1..=v.min(G_MAX) {
                    for i in 1..=self.inputs {
                        expected.insert((v, g, i));
                    }
                }
            }
        }
        let keys: BTreeSet<_> = self
            .tickets
            .iter()
            .map(|t| (t.variant, t.generation, t.input))
            .collect();
        if keys != expected || keys.len() != self.tickets.len() {
            return Err(SplitError::Header);
        }
        for t in &self.tickets {
            let index = if self.suite == Suite::Ecdsa {
                t.variant
            } else {
                t.generation
            };
            if t.slot != self.slots[usize::from((index - 1) * self.inputs + t.input - 1)] {
                return Err(SplitError::Header);
            }
        }
        if self.actors.iter().collect::<BTreeSet<_>>().len() != self.actors.len()
            || self.embedded.iter().collect::<BTreeSet<_>>().len() != self.embedded.len()
            || self.embedded.iter().any(|a| !self.actors.contains(a))
        {
            return Err(SplitError::Header);
        }
        Ok(())
    }
    fn selected(&self, generation: u16, variant: u16) -> Vec<&Ticket> {
        let g = if self.suite == Suite::Ecdsa {
            0
        } else {
            generation
        };
        let mut tickets: Vec<_> = self
            .tickets
            .iter()
            .filter(|t| t.generation == g && t.variant == variant)
            .collect();
        tickets.sort_by_key(|t| t.input);
        tickets
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub host_height: u64,
    pub midnight_height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub host_height: u64,
    pub midnight_height: u64,
    pub position: u64,
    pub reports: Vec<(NodeId, Observation)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    pub frame: Eid,
    pub epoch: Epoch,
    pub dd: Digest,
    pub target_hd: Digest,
    pub actor: u16,
    pub digest: Digest,
    /// Includes public envelope checks, its QC, opening, token and body lengths.
    pub verified: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Frame {
    value: Contribution,
    height: u64,
    position: u64,
    complained: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub envelope: Envelope,
    pub state: State,
    pub header: Option<Header>,
    pub order_position: Option<u64>,
    pub order_height: Option<u64>,
    pub exp_c: Option<u64>,
    pub header_partials: BTreeSet<NodeId>,
    pub opened_votes: BTreeSet<NodeId>,
    pub admit_votes: Vec<(NodeId, Observation)>,
    pub admitted: bool,
    pub auth_verified: bool,
    pub auth_final: Option<u64>,
    pub board_first: bool,
    pub revoked: bool,
    pub lapsed: bool,
    pub stalled: bool,
    pub contributions: BTreeMap<u16, Eid>,
    pub anchors: BTreeMap<u16, Anchor>,
    pub releases: BTreeMap<(u16, NodeId), u16>,
    pub settlement: Option<Settlement>,
    pub dealer_faults: Vec<VoidReason>,
    pub failures: BTreeSet<VoidReason>,
    final_posts: BTreeMap<(Epoch, Digest), BTreeSet<NodeId>>,
    void_posts: BTreeMap<Epoch, BTreeMap<NodeId, VoidReason>>,
    obs: BTreeMap<u16, Vec<(NodeId, Observation)>>,
    selections: BTreeMap<u16, (u16, Vec<Digest>)>,
}
impl Request {
    pub fn in_force(&self) -> bool {
        self.auth_final.is_some() || self.board_first
    }
    fn live(&self) -> Result<(), SplitError> {
        if self.state.terminal() {
            Err(SplitError::Terminal)
        } else {
            Ok(())
        }
    }
    fn header(&self) -> Result<&Header, SplitError> {
        self.header.as_ref().ok_or(SplitError::NotOpened)
    }
    fn complete(&self) -> bool {
        self.header.as_ref().is_some_and(|h| {
            h.actors
                .iter()
                .all(|a| h.embedded.contains(a) || self.contributions.contains_key(a))
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WitnessKey {
    Open {
        epoch: Epoch,
        node: NodeId,
        eid: Eid,
    },
    Release {
        epoch: Epoch,
        node: NodeId,
        eid: Eid,
        generation: u16,
    },
    Slot {
        node: NodeId,
        slot: SlotId,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessValue {
    Open { position: u64, committed: bool },
    Release { variant: u16, tickets: Vec<Digest> },
    Slot(Digest),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessEntry {
    pub value: WitnessValue,
    pub peers: BTreeSet<NodeId>,
    pub position: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erase {
    SlotShares,
    OuterShare,
    PrfPointsAndKeys,
    ContributionShares,
    OpenedScalars,
    Header,
    Capsules,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erasure {
    pub eid: Eid,
    pub position: u64,
    pub items: Vec<Erase>,
}
/// Facts at the instant a release or its durable witness is accepted.
/// A later hold does not retroactively invalidate an earlier release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAudit {
    pub eid: Eid,
    pub node: NodeId,
    pub generation: u16,
    pub position: u64,
    pub admitted: bool,
    pub in_force: bool,
    pub held: bool,
    pub midnight_height: u64,
    pub required_midnight_height: u64,
}
/// Committee pools have independent index spaces for each suite and epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PoolId {
    pub suite: Suite,
    pub epoch: Epoch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolCheckpoint {
    pub h: u64,
    pub pending_min: u64,
    pub pending_root: Digest,
    pub pending_count: u32,
    /// Sorted board-side index list with its request attribution.
    pub pending: BTreeMap<u64, Eid>,
    /// Trusted adapter verified this exact list under pending_root and its
    /// request attribution under the board root of the same checkpoint.
    pub pending_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub position: u64,
    pub pending: BTreeMap<Digest, Eid>,
    pub slots: BTreeMap<SlotId, SlotState>,
    pub pools: BTreeMap<PoolId, PoolCheckpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Post {
        envelope: Envelope,
    },
    Order {
        eid: Eid,
        qc_verified: bool,
    },
    HeaderPartial {
        eid: Eid,
        node: NodeId,
        share_verified: bool,
    },
    SeeHeader {
        eid: Eid,
        header: Box<Header>,
    },
    Authorize {
        eid: Eid,
        /// Full DESIGN §5.3 statement, including auth_ref -> hd/tkc binding,
        /// record identity, pin, source signature and birth/registration proof.
        verified: bool,
    },
    AuthFinal {
        eid: Eid,
        midnight_height: u64,
        /// Final inclusion of this request's verified authorization, not mempool
        /// acceptance or inclusion without finality.
        verified: bool,
    },
    BoardFirstCall {
        eid: Eid,
        /// Same complete statement and envelope binding as Authorize. The
        /// remaining fields describe the checked finalized root and relay bound.
        proof_verified: bool,
        finalized_root: bool,
        unused_nf: bool,
        root_height: u64,
        midnight_height: u64,
        max_root_age: u64,
        relay_margin: u64,
    },
    VoteOpened {
        eid: Eid,
        node: NodeId,
        header_hash: Digest,
    },
    Contribute {
        contribution: Contribution,
    },
    SeeContrib {
        eid: Eid,
    },
    ContributionComplaint {
        frame: Eid,
        verified: bool,
    },
    VoteAdmit {
        eid: Eid,
        node: NodeId,
        header_hash: Digest,
        obs: Observation,
    },
    AnchorGen {
        eid: Eid,
        generation: u16,
        node: NodeId,
        obs: Observation,
        deadline_verified: bool,
    },
    WitnessOpen {
        eid: Eid,
        node: NodeId,
        position: u64,
        committed: bool,
        peers: Vec<NodeId>,
    },
    WitnessRelease {
        eid: Eid,
        node: NodeId,
        generation: u16,
        variant: u16,
        tickets: Vec<Digest>,
        peers: Vec<NodeId>,
        /// The header's rule selects this variant at this committed anchor.
        selection_verified: bool,
        checks_verified: bool,
        midnight_height: u64,
        not_revoked_verified: bool,
    },
    SlotAnchor {
        eid: Eid,
        generation: u16,
        variant: u16,
        tickets: Vec<Digest>,
        verified: bool,
    },
    Release {
        eid: Eid,
        node: NodeId,
        generation: u16,
        variant: u16,
        tickets: Vec<Digest>,
        /// The header's rule selects this variant at this committed anchor.
        selection_verified: bool,
        /// DESIGN §4.7 item 7, for every selected ticket.
        checks_verified: bool,
        midnight_height: u64,
        not_revoked_verified: bool,
    },
    Complaint {
        eid: Eid,
        verified: bool,
    },
    CombinerFailure {
        eid: Eid,
        reason: VoidReason,
        verified: bool,
    },
    Revoke {
        eid: Eid,
        midnight_height: u64,
        verified: bool,
    },
    SetHold {
        record: Digest,
        midnight_height: u64,
        held: bool,
        verified: bool,
    },
    Final {
        eid: Eid,
        epoch: Epoch,
        node: NodeId,
        ciphertext: Digest,
    },
    Void {
        eid: Eid,
        epoch: Epoch,
        node: NodeId,
        reason: VoidReason,
    },
    Lapse {
        eid: Eid,
    },
    ExpC {
        eid: Eid,
    },
    Stall {
        eid: Eid,
    },
    Expire {
        eid: Eid,
    },
    Rotate {
        epoch: Epoch,
        committee: Committee,
    },
    Checkpoint {
        pools: BTreeMap<PoolId, PoolCheckpoint>,
    },
    Tick,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitError {
    Parameters,
    Height,
    Epoch,
    Member,
    Duplicate,
    UnknownRequest,
    PublicChecks,
    DuplicateDealing,
    Evidence,
    Header,
    NotOrdered,
    NotOpened,
    Threshold,
    Terminal,
    Authorization,
    Profile(ProfileError),
    SlotTaken,
    EarlierHeader,
    Window,
    Collection,
    HeaderHash,
    AlreadyVoted,
    Generation,
    NoAnchor,
    Selection,
    Witness,
    Ticket,
    Revoked,
    Hold,
    Pin,
    Nullifier,
    Invariant(&'static str),
}
impl From<ProfileError> for SplitError {
    fn from(e: ProfileError) -> Self {
        Self::Profile(e)
    }
}
impl std::fmt::Display for SplitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "split board: {self:?}")
    }
}
impl std::error::Error for SplitError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitBoard {
    pub height: u64,
    pub position: u64,
    pub epoch: Epoch,
    delta_c: u64,
    reservation_window: u64,
    tee: bool,
    slot_anchor: bool,
    committees: BTreeMap<Epoch, Committee>,
    requests: BTreeMap<Eid, Request>,
    dealings: BTreeMap<(Epoch, Digest), Eid>,
    slots: BTreeMap<SlotId, SlotState>,
    named: BTreeSet<SlotId>,
    frames: BTreeMap<Eid, Frame>,
    pending: BTreeMap<Digest, Eid>,
    used_nf: BTreeMap<Digest, Eid>,
    active_records: BTreeMap<Digest, Eid>,
    record_locks: BTreeMap<Digest, Digest>,
    spent_records: BTreeSet<Digest>,
    holds: BTreeMap<Digest, (u64, bool)>,
    witnesses: BTreeMap<WitnessKey, WitnessEntry>,
    signed_slots: BTreeMap<(NodeId, SlotId), Digest>,
    anchored_slots: BTreeMap<SlotId, Digest>,
    erasures: Vec<Erasure>,
    release_audits: Vec<ReleaseAudit>,
    pub checkpoint: Option<Checkpoint>,
}
impl SplitBoard {
    pub fn new(
        committee: Committee,
        epoch: Epoch,
        delta_c: u64,
        reservation_window: u64,
        tee: bool,
        slot_anchor: bool,
    ) -> Result<Self, SplitError> {
        committee.validate().map_err(|_| SplitError::Parameters)?;
        if delta_c == 0 || reservation_window == 0 {
            return Err(SplitError::Parameters);
        }
        Ok(Self {
            height: 0,
            position: 0,
            epoch,
            delta_c,
            reservation_window,
            tee,
            slot_anchor,
            committees: BTreeMap::from([(epoch, committee)]),
            requests: BTreeMap::new(),
            dealings: BTreeMap::new(),
            slots: BTreeMap::new(),
            named: BTreeSet::new(),
            frames: BTreeMap::new(),
            pending: BTreeMap::new(),
            used_nf: BTreeMap::new(),
            active_records: BTreeMap::new(),
            record_locks: BTreeMap::new(),
            spent_records: BTreeSet::new(),
            holds: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            signed_slots: BTreeMap::new(),
            anchored_slots: BTreeMap::new(),
            erasures: vec![],
            release_audits: vec![],
            checkpoint: None,
        })
    }
    pub fn request(&self, eid: &Eid) -> Result<&Request, SplitError> {
        self.requests.get(eid).ok_or(SplitError::UnknownRequest)
    }
    pub fn slot(&self, slot: &SlotId) -> SlotState {
        self.slots.get(slot).copied().unwrap_or(SlotState::Free)
    }
    pub fn erasures(&self) -> &[Erasure] {
        &self.erasures
    }
    pub fn release_audits(&self) -> &[ReleaseAudit] {
        &self.release_audits
    }
    pub fn witnesses(&self) -> &BTreeMap<WitnessKey, WitnessEntry> {
        &self.witnesses
    }
    pub fn pending(&self) -> &BTreeMap<Digest, Eid> {
        &self.pending
    }
    fn req_mut(&mut self, eid: Eid) -> &mut Request {
        self.requests.get_mut(&eid).expect("validated request")
    }
    fn committee(&self, epoch: Epoch) -> Result<Committee, SplitError> {
        self.committees
            .get(&epoch)
            .copied()
            .ok_or(SplitError::Epoch)
    }
    fn member(&self, epoch: Epoch, node: NodeId) -> Result<Committee, SplitError> {
        let c = self.committee(epoch)?;
        if node == 0 || node > c.n {
            return Err(SplitError::Member);
        }
        Ok(c)
    }
    /// Bad posts consume a log position. Deadline transitions still apply.
    /// The event itself is atomic, including witness and nullifier updates.
    pub fn apply(&mut self, height: u64, event: Event) -> Result<(), SplitError> {
        if height < self.height {
            return Err(SplitError::Height);
        }
        self.height = height;
        self.position = self.position.checked_add(1).ok_or(SplitError::Height)?;
        self.deadlines();
        let mut next = self.clone();
        next.transition(event)?;
        *self = next;
        Ok(())
    }
    fn deadlines(&mut self) {
        let ids: Vec<_> = self.requests.keys().copied().collect();
        for eid in ids {
            let r = &self.requests[&eid];
            if r.state.terminal() {
                continue;
            }
            if self.height >= r.envelope.exp {
                self.finish(eid, State::Expired);
                continue;
            }
            if r.exp_c.is_some_and(|h| self.height >= h) {
                let lapse = !r.in_force();
                if !r.admitted {
                    self.req_mut(eid).stalled = true;
                }
                if lapse {
                    self.req_mut(eid).lapsed = true;
                    self.burn(eid);
                }
            }
        }
    }
    fn burn(&mut self, eid: Eid) {
        for state in self.slots.values_mut() {
            if state.owner() == Some(eid) {
                *state = SlotState::Burned;
            }
        }
    }
    fn finish(&mut self, eid: Eid, state: State) {
        self.burn(eid);
        let h = self.requests[&eid].header.clone();
        let settlement = if let Some(h) = h {
            if self.active_records.get(&h.record) == Some(&eid) {
                self.active_records.remove(&h.record);
            }
            if self.pending.get(&h.nf) == Some(&eid) {
                self.pending.remove(&h.nf);
            }
            match state {
                State::Final(ciphertext) => {
                    self.spent_records.insert(h.record);
                    Settlement::Successor(ciphertext)
                }
                _ => match self.record_locks.get(&h.record) {
                    Some(pin) => Settlement::Released { pin: *pin },
                    None => Settlement::UnspentFreshNullifier,
                },
            }
        } else {
            match state {
                State::Final(ciphertext) => Settlement::Successor(ciphertext),
                _ => Settlement::UnspentFreshNullifier,
            }
        };
        let r = self.req_mut(eid);
        r.state = state;
        r.settlement = Some(settlement);
        self.erasures.push(Erasure {
            eid,
            position: self.position,
            items: vec![
                Erase::SlotShares,
                Erase::OuterShare,
                Erase::PrfPointsAndKeys,
                Erase::ContributionShares,
                Erase::OpenedScalars,
                Erase::Header,
                Erase::Capsules,
            ],
        });
    }
    fn policy(&self, eid: Eid) -> Result<(), SplitError> {
        let r = self.request(&eid)?;
        r.live()?;
        let h = r.header()?;
        h.charter.check(h.source, &h.outputs, h.checks)?;
        if h.source == Source::Recovery && !h.checks.recovery_transition {
            return Err(SplitError::Profile(ProfileError::Recovery));
        }
        if h.suite == Suite::Ecdsa && h.tickets.iter().any(|t| !t.in_source_root) {
            return Err(SplitError::Ticket);
        }
        if r.revoked {
            return Err(SplitError::Revoked);
        }
        if self.held(h) {
            return Err(SplitError::Hold);
        }
        if self.spent_records.contains(&h.record)
            || self
                .record_locks
                .get(&h.record)
                .is_some_and(|pin| *pin != h.pin)
        {
            return Err(SplitError::Pin);
        }
        Ok(())
    }
    fn held(&self, h: &Header) -> bool {
        h.charter.regulated()
            && h.source != Source::Seizure
            && self.holds.get(&h.record).is_some_and(|(_, held)| *held)
    }
    fn force(&mut self, eid: Eid) -> Result<(), SplitError> {
        self.policy(eid)?;
        let r = self.request(&eid)?;
        if r.lapsed {
            return Err(SplitError::Window);
        }
        let h = r.header()?;
        if self.used_nf.get(&h.nf).is_some_and(|e| *e != eid)
            || self.pending.get(&h.nf).is_some_and(|e| *e != eid)
            || self
                .active_records
                .get(&h.record)
                .is_some_and(|e| *e != eid)
        {
            return Err(SplitError::Nullifier);
        }
        let (nf, record) = (h.nf, h.record);
        self.used_nf.insert(nf, eid);
        self.active_records.insert(record, eid);
        Ok(())
    }
    fn precedence(&self, eid: Eid) -> Result<(), SplitError> {
        let r = self.request(&eid)?;
        if r.lapsed {
            return Err(SplitError::Window);
        }
        if r.header()?
            .slots
            .iter()
            .any(|s| self.slot(s).owner() != Some(eid))
        {
            return Err(SplitError::SlotTaken);
        }
        // An earlier unopened envelope may still name these slots. Its header
        // must be resolved before a later request reserves or releases them.
        if self.requests.values().any(|p| {
            !p.state.terminal()
                && !p.lapsed
                && p.order_position.is_some()
                && p.order_position < r.order_position
                && p.header.is_none()
        }) {
            return Err(SplitError::EarlierHeader);
        }
        Ok(())
    }
    fn vote_ready(&self, eid: Eid, node: NodeId, hash: Digest) -> Result<Committee, SplitError> {
        self.policy(eid)?;
        let r = self.request(&eid)?;
        let c = self.member(r.envelope.epoch, node)?;
        if !r.in_force() {
            return Err(SplitError::Authorization);
        }
        if r.stalled || r.exp_c.is_some_and(|h| self.height >= h) {
            return Err(SplitError::Window);
        }
        if r.header()?.hash != hash {
            return Err(SplitError::HeaderHash);
        }
        if r.failures.contains(&VoidReason::ShareComplaint) {
            return Err(SplitError::Evidence);
        }
        self.reservation_ready(eid)?;
        self.precedence(eid)?;
        Ok(c)
    }
    fn reservation_ready(&self, eid: Eid) -> Result<(), SplitError> {
        let mut wait = false;
        for slot in &self.request(&eid)?.header()?.slots {
            // ECDSA account pools use opaque records, not committee indices.
            let SlotId::Schnorr {
                suite,
                epoch,
                index,
            } = slot
            else {
                continue;
            };
            let pool = PoolId {
                suite: *suite,
                epoch: *epoch,
            };
            let Some(cp) = self.checkpoint.as_ref().and_then(|cp| cp.pools.get(&pool)) else {
                wait = true;
                continue;
            };
            if *index < cp.pending_min || (*index <= cp.h && cp.pending.get(index) != Some(&eid)) {
                return Err(SplitError::SlotTaken);
            }
            // Subtract only above h, so the window cannot wrap at u64::MAX.
            if *index > cp.h && *index - cp.h > self.reservation_window {
                wait = true;
            }
        }
        if wait {
            Err(SplitError::Window)
        } else {
            Ok(())
        }
    }
    fn attach(&mut self, eid: Eid) -> Result<(), SplitError> {
        let r = self.request(&eid)?;
        if r.state.terminal() || r.admitted {
            return Ok(());
        }
        let h = r.header()?;
        let mut frames: Vec<_> = self
            .frames
            .values()
            .filter(|f| {
                !f.complained
                    && f.value.target_hd == r.envelope.hd
                    && f.height <= r.exp_c.unwrap_or(0)
            })
            .collect();
        frames.sort_by_key(|f| f.position);
        let mut attached = BTreeMap::new();
        for f in frames {
            if h.actors.contains(&f.value.actor) && !h.embedded.contains(&f.value.actor) {
                attached.entry(f.value.actor).or_insert(f.value.frame);
            }
        }
        self.req_mut(eid).contributions = attached;
        Ok(())
    }
    fn make_anchor(&self, reports: Vec<(NodeId, Observation)>, c: Committee) -> Anchor {
        let mut heights: Vec<_> = reports.iter().map(|(_, o)| o.host_height).collect();
        heights.sort_unstable_by(|a, b| b.cmp(a));
        Anchor {
            host_height: heights[usize::from(c.f)],
            midnight_height: reports
                .iter()
                .map(|(_, o)| o.midnight_height)
                .max()
                .unwrap_or(0),
            position: self.position,
            reports,
        }
    }
    fn transition(&mut self, event: Event) -> Result<(), SplitError> {
        match event {
            Event::Post { envelope } => {
                if !envelope.checks.valid() || envelope.exp <= self.height {
                    return Err(SplitError::PublicChecks);
                }
                if envelope.epoch != self.epoch {
                    return Err(SplitError::Epoch);
                }
                if self.requests.contains_key(&envelope.eid) {
                    return Err(SplitError::Duplicate);
                }
                if self.dealings.contains_key(&(envelope.epoch, envelope.dd)) {
                    return Err(SplitError::DuplicateDealing);
                }
                self.requests.insert(
                    envelope.eid,
                    Request {
                        envelope,
                        state: State::Posted,
                        header: None,
                        order_position: None,
                        order_height: None,
                        exp_c: None,
                        header_partials: BTreeSet::new(),
                        opened_votes: BTreeSet::new(),
                        admit_votes: vec![],
                        admitted: false,
                        auth_verified: false,
                        auth_final: None,
                        board_first: false,
                        revoked: false,
                        lapsed: false,
                        stalled: false,
                        contributions: BTreeMap::new(),
                        anchors: BTreeMap::new(),
                        releases: BTreeMap::new(),
                        settlement: None,
                        dealer_faults: vec![],
                        failures: BTreeSet::new(),
                        final_posts: BTreeMap::new(),
                        void_posts: BTreeMap::new(),
                        obs: BTreeMap::new(),
                        selections: BTreeMap::new(),
                    },
                );
            }
            Event::Order { eid, qc_verified } => {
                let r = self.request(&eid)?;
                r.live()?;
                if !qc_verified {
                    return Err(SplitError::Evidence);
                }
                if r.state != State::Posted {
                    return Err(SplitError::NotOrdered);
                }
                if r.envelope.epoch != self.epoch {
                    return Err(SplitError::Epoch);
                }
                if self
                    .dealings
                    .contains_key(&(r.envelope.epoch, r.envelope.dd))
                {
                    return Err(SplitError::DuplicateDealing);
                }
                let exp_c = self
                    .height
                    .checked_add(self.delta_c)
                    .ok_or(SplitError::Parameters)?;
                if exp_c >= r.envelope.exp {
                    return Err(SplitError::Window);
                }
                self.dealings.insert((r.envelope.epoch, r.envelope.dd), eid);
                let (position, height) = (self.position, self.height);
                let r = self.req_mut(eid);
                r.state = State::Ordered;
                r.order_position = Some(position);
                r.order_height = Some(height);
                r.exp_c = Some(exp_c);
            }
            Event::HeaderPartial {
                eid,
                node,
                share_verified,
            } => {
                let r = self.request(&eid)?;
                r.live()?;
                self.member(r.envelope.epoch, node)?;
                let position = r.order_position.ok_or(SplitError::NotOrdered)?;
                if !share_verified {
                    return Err(SplitError::Evidence);
                }
                if self.tee {
                    self.require_witness(
                        r.envelope.epoch,
                        node,
                        &WitnessKey::Open {
                            epoch: r.envelope.epoch,
                            node,
                            eid,
                        },
                        &WitnessValue::Open {
                            position,
                            committed: true,
                        },
                    )?;
                }
                if !self.req_mut(eid).header_partials.insert(node) {
                    return Err(SplitError::AlreadyVoted);
                }
            }
            Event::SeeHeader { eid, header } => {
                let header = *header;
                let r = self.request(&eid)?;
                r.live()?;
                let position = r.order_position.ok_or(SplitError::NotOrdered)?;
                if r.header.is_some() {
                    return Err(SplitError::Duplicate);
                }
                if r.lapsed {
                    return Err(SplitError::Window);
                }
                // Resolve names in envelope order. Otherwise a later header
                // could burn a slot before the earlier header reveals its claim.
                if self.requests.values().any(|p| {
                    !p.state.terminal()
                        && !p.lapsed
                        && p.order_position.is_some()
                        && p.order_position < Some(position)
                        && p.header.is_none()
                }) {
                    return Err(SplitError::EarlierHeader);
                }
                let c = self.committee(r.envelope.epoch)?;
                if r.header_partials.len() < usize::from(c.n - c.f) {
                    return Err(SplitError::Threshold);
                }
                header.validate(r.envelope.epoch)?;
                for slot in &header.slots {
                    let previous = self.slot(slot);
                    if previous == SlotState::Free {
                        self.slots.insert(*slot, SlotState::Named(eid));
                    }
                    self.named.insert(*slot);
                }
                let r = self.req_mut(eid);
                r.header = Some(header);
                r.state = State::Opened;
                self.attach(eid)?;
            }
            Event::Authorize { eid, verified } => {
                if !verified {
                    return Err(SplitError::Evidence);
                }
                self.policy(eid)?;
                self.req_mut(eid).auth_verified = true;
            }
            Event::AuthFinal {
                eid,
                midnight_height,
                verified,
            } => {
                let r = self.request(&eid)?;
                if !verified || !r.auth_verified {
                    return Err(SplitError::Evidence);
                }
                if r.header()?.charter.board_first && !r.board_first {
                    return Err(SplitError::Authorization);
                }
                if let Some(old) = r.auth_final {
                    return if old == midnight_height {
                        Ok(())
                    } else {
                        Err(SplitError::Evidence)
                    };
                }
                self.force(eid)?;
                self.req_mut(eid).auth_final = Some(midnight_height);
            }
            Event::BoardFirstCall {
                eid,
                proof_verified,
                finalized_root,
                unused_nf,
                root_height,
                midnight_height,
                max_root_age,
                relay_margin,
            } => {
                // Invalid copies never enter pending, including copies of nf.
                if !proof_verified || !finalized_root || !unused_nf {
                    return Err(SplitError::Evidence);
                }
                let age = midnight_height
                    .checked_sub(root_height)
                    .ok_or(SplitError::Evidence)?;
                let bound = max_root_age
                    .checked_sub(relay_margin)
                    .ok_or(SplitError::Evidence)?;
                if age > bound {
                    return Err(SplitError::Evidence);
                }
                let r = self.request(&eid)?;
                if !r.header()?.charter.board_first {
                    return Err(SplitError::Authorization);
                }
                self.force(eid)?;
                let nf = self.request(&eid)?.header()?.nf;
                self.pending.insert(nf, eid);
                let r = self.req_mut(eid);
                r.auth_verified = true;
                r.board_first = true;
            }
            Event::VoteOpened {
                eid,
                node,
                header_hash,
            } => {
                let c = self.vote_ready(eid, node, header_hash)?;
                let r = self.request(&eid)?;
                if !r.header()?.collecting() || r.admitted {
                    return Err(SplitError::Collection);
                }
                let r = self.req_mut(eid);
                if !r.opened_votes.insert(node) {
                    return Err(SplitError::AlreadyVoted);
                }
                if r.opened_votes.len() == c.quorum() {
                    r.state = State::Collecting;
                    for slot in r.header()?.slots.clone() {
                        self.slots.insert(slot, SlotState::Reserved(eid));
                    }
                }
            }
            Event::Contribute { contribution } => {
                if !contribution.verified {
                    return Err(SplitError::Evidence);
                }
                if contribution.epoch != self.epoch {
                    return Err(SplitError::Epoch);
                }
                if self.frames.contains_key(&contribution.frame) {
                    return Err(SplitError::Duplicate);
                }
                if self.requests.contains_key(&contribution.frame) {
                    return Err(SplitError::Duplicate);
                }
                if self
                    .dealings
                    .contains_key(&(contribution.epoch, contribution.dd))
                {
                    return Err(SplitError::DuplicateDealing);
                }
                // Even ignored frames consume their ordered outer dealing.
                self.dealings
                    .insert((contribution.epoch, contribution.dd), contribution.frame);
                let target = self
                    .requests
                    .iter()
                    .find(|(_, r)| r.envelope.hd == contribution.target_hd)
                    .map(|(e, _)| *e);
                if let Some(eid) = target {
                    let r = self.request(&eid)?;
                    if r.state.terminal() || r.admitted || r.exp_c.is_some_and(|h| self.height > h)
                    {
                        return Ok(());
                    }
                }
                self.frames.insert(
                    contribution.frame,
                    Frame {
                        value: contribution,
                        height: self.height,
                        position: self.position,
                        complained: false,
                    },
                );
                if let Some(eid) = target {
                    if self.request(&eid)?.header.is_some() {
                        self.attach(eid)?;
                    }
                }
            }
            Event::SeeContrib { eid } => {
                self.attach(eid)?;
            }
            Event::ContributionComplaint { frame, verified } => {
                if !verified {
                    return Err(SplitError::Evidence);
                }
                let f = self
                    .frames
                    .get_mut(&frame)
                    .ok_or(SplitError::UnknownRequest)?;
                f.complained = true;
                let hd = f.value.target_hd;
                let ids: Vec<_> = self
                    .requests
                    .iter()
                    .filter(|(_, r)| r.envelope.hd == hd)
                    .map(|(eid, _)| *eid)
                    .collect();
                for eid in ids {
                    let r = self.req_mut(eid);
                    r.contributions.retain(|_, f| *f != frame);
                    r.dealer_faults.push(VoidReason::ShareComplaint);
                    // No replacement after admission. A late complaint cannot
                    // undo the committed ADMIT certificate (DECISIONS 47).
                    if !r.admitted && r.header.is_some() {
                        self.attach(eid)?;
                    }
                }
            }
            Event::VoteAdmit {
                eid,
                node,
                header_hash,
                obs,
            } => {
                let c = self.vote_ready(eid, node, header_hash)?;
                let r = self.request(&eid)?;
                if r.admitted {
                    return Err(SplitError::AlreadyVoted);
                }
                if !r.complete() || (r.header()?.collecting() && r.opened_votes.len() < c.quorum())
                {
                    return Err(SplitError::Collection);
                }
                if r.admit_votes.iter().any(|(n, _)| *n == node) {
                    return Err(SplitError::AlreadyVoted);
                }
                self.req_mut(eid).admit_votes.push((node, obs));
                let r = self.request(&eid)?;
                if r.admit_votes.len() == c.quorum() {
                    let anchor = self.make_anchor(r.admit_votes.clone(), c);
                    for slot in r.header()?.slots.clone() {
                        self.slots.insert(slot, SlotState::Claimed(eid));
                    }
                    let r = self.req_mut(eid);
                    r.admitted = true;
                    r.state = State::Admitted;
                    r.anchors.insert(1, anchor);
                    r.state = State::Anchored(1);
                }
            }
            Event::AnchorGen {
                eid,
                generation,
                node,
                obs,
                deadline_verified,
            } => {
                self.policy(eid)?;
                let r = self.request(&eid)?;
                let c = self.member(r.envelope.epoch, node)?;
                if !r.admitted || generation != 2 || generation > r.header()?.generations() {
                    return Err(SplitError::Generation);
                }
                if !deadline_verified {
                    return Err(SplitError::Evidence);
                }
                if !r.releases.keys().any(|(g, _)| *g == 1) {
                    return Err(SplitError::Generation);
                }
                if r.anchors.contains_key(&generation) {
                    return Err(SplitError::AlreadyVoted);
                }
                let reports = self.req_mut(eid).obs.entry(generation).or_default();
                if reports.iter().any(|(n, _)| *n == node) {
                    return Err(SplitError::AlreadyVoted);
                }
                reports.push((node, obs));
                if reports.len() == c.quorum() {
                    let reports = reports.clone();
                    let anchor = self.make_anchor(reports, c);
                    if anchor.host_height <= self.requests[&eid].anchors[&1].host_height {
                        return Err(SplitError::Generation);
                    }
                    let r = self.req_mut(eid);
                    r.anchors.insert(generation, anchor);
                    r.state = State::Anchored(generation);
                }
            }
            Event::WitnessOpen {
                eid,
                node,
                position,
                committed,
                peers,
            } => {
                let r = self.request(&eid)?;
                r.live()?;
                let epoch = r.envelope.epoch;
                if committed && r.order_position != Some(position) {
                    return Err(SplitError::NotOrdered);
                }
                self.put_witness(
                    epoch,
                    node,
                    WitnessKey::Open { epoch, node, eid },
                    WitnessValue::Open {
                        position,
                        committed,
                    },
                    peers,
                )?;
            }
            Event::WitnessRelease {
                eid,
                node,
                generation,
                variant,
                tickets,
                peers,
                selection_verified,
                checks_verified,
                midnight_height,
                not_revoked_verified,
            } => {
                if !selection_verified {
                    return Err(SplitError::Selection);
                }
                self.selection(eid, generation, variant, &tickets)?;
                self.release_policy(eid, generation, midnight_height, not_revoked_verified)?;
                if !checks_verified {
                    return Err(SplitError::Evidence);
                }
                let r = self.request(&eid)?;
                let epoch = r.envelope.epoch;
                let chosen: Vec<_> = r
                    .header()?
                    .selected(generation, variant)
                    .iter()
                    .map(|t| (t.slot, t.digest))
                    .collect();
                self.put_witness(
                    epoch,
                    node,
                    WitnessKey::Release {
                        epoch,
                        node,
                        eid,
                        generation,
                    },
                    WitnessValue::Release {
                        variant,
                        tickets: tickets.clone(),
                    },
                    peers.clone(),
                )?;
                for (slot, digest) in chosen {
                    self.put_witness(
                        epoch,
                        node,
                        WitnessKey::Slot { node, slot },
                        WitnessValue::Slot(digest),
                        peers.clone(),
                    )?;
                }
                // A witnessed release already locks settlement, even if the
                // process crashes before its committed RELEASE post.
                self.lock_record(eid)?;
                self.audit_release(eid, node, generation, midnight_height)?;
                self.req_mut(eid)
                    .selections
                    .entry(generation)
                    .or_insert((variant, tickets));
            }
            Event::SlotAnchor {
                eid,
                generation,
                variant,
                tickets,
                verified,
            } => {
                if !verified {
                    return Err(SplitError::Evidence);
                }
                self.selection(eid, generation, variant, &tickets)?;
                let chosen: Vec<_> = self
                    .request(&eid)?
                    .header()?
                    .selected(generation, variant)
                    .iter()
                    .map(|t| (t.slot, t.digest))
                    .collect();
                for (slot, digest) in chosen {
                    if self
                        .anchored_slots
                        .get(&slot)
                        .is_some_and(|old| *old != digest)
                    {
                        return Err(SplitError::Ticket);
                    }
                    self.anchored_slots.insert(slot, digest);
                }
            }
            Event::Release {
                eid,
                node,
                generation,
                variant,
                tickets,
                selection_verified,
                checks_verified,
                midnight_height,
                not_revoked_verified,
            } => {
                if !selection_verified {
                    return Err(SplitError::Selection);
                }
                self.selection(eid, generation, variant, &tickets)?;
                self.release_policy(eid, generation, midnight_height, not_revoked_verified)?;
                let r = self.request(&eid)?;
                let c = self.member(r.envelope.epoch, node)?;
                if !checks_verified {
                    self.req_mut(eid)
                        .failures
                        .insert(VoidReason::FailedReleaseCheck);
                    return Ok(());
                }
                let chosen: Vec<_> = r
                    .header()?
                    .selected(generation, variant)
                    .iter()
                    .map(|t| (t.slot, t.digest))
                    .collect();
                if self.tee {
                    self.require_witness(
                        r.envelope.epoch,
                        node,
                        &WitnessKey::Release {
                            epoch: r.envelope.epoch,
                            node,
                            eid,
                            generation,
                        },
                        &WitnessValue::Release {
                            variant,
                            tickets: tickets.clone(),
                        },
                    )?;
                }
                for (slot, digest) in &chosen {
                    if self.slot_anchor && self.anchored_slots.get(slot) != Some(digest) {
                        return Err(SplitError::Witness);
                    }
                    if self.tee {
                        self.require_witness(
                            r.envelope.epoch,
                            node,
                            &WitnessKey::Slot { node, slot: *slot },
                            &WitnessValue::Slot(*digest),
                        )?;
                    }
                    if self
                        .signed_slots
                        .get(&(node, *slot))
                        .is_some_and(|d| d != digest)
                    {
                        return Err(SplitError::Ticket);
                    }
                }
                if r.releases.contains_key(&(generation, node)) {
                    return Err(SplitError::AlreadyVoted);
                }
                for (slot, digest) in chosen {
                    self.signed_slots.insert((node, slot), digest);
                }
                self.lock_record(eid)?;
                self.audit_release(eid, node, generation, midnight_height)?;
                let r = self.req_mut(eid);
                r.selections.entry(generation).or_insert((variant, tickets));
                r.releases.insert((generation, node), variant);
                if r.releases.keys().filter(|(g, _)| *g == generation).count()
                    >= usize::from(c.n - c.f)
                {
                    r.state = State::Released {
                        generation,
                        variant,
                    };
                }
            }
            Event::Complaint { eid, verified } => {
                if !verified {
                    return Err(SplitError::Evidence);
                }
                let r = self.request(&eid)?;
                if r.order_position.is_none() {
                    return Err(SplitError::NotOrdered);
                }
                let r = self.req_mut(eid);
                r.dealer_faults.push(VoidReason::ShareComplaint);
                if r.admit_votes.is_empty() && !r.state.terminal() {
                    r.failures.insert(VoidReason::ShareComplaint);
                }
            }
            Event::CombinerFailure {
                eid,
                reason,
                verified,
            } => {
                if !verified
                    || !matches!(
                        reason,
                        VoidReason::FailedContribution
                            | VoidReason::FailedReleaseCheck
                            | VoidReason::DealerFault
                    )
                {
                    return Err(SplitError::Evidence);
                }
                self.request(&eid)?.live()?;
                self.req_mut(eid).dealer_faults.push(reason);
                self.finish(eid, State::Void(reason));
            }
            Event::Revoke {
                eid,
                midnight_height: _,
                verified,
            } => {
                if !verified {
                    return Err(SplitError::Evidence);
                }
                self.request(&eid)?.live()?;
                if !self.request(&eid)?.header()?.charter.regulated() {
                    return Err(SplitError::Profile(ProfileError::Source));
                }
                self.req_mut(eid).revoked = true;
            }
            Event::SetHold {
                record,
                midnight_height,
                held,
                verified,
            } => {
                if !verified
                    || self
                        .holds
                        .get(&record)
                        .is_some_and(|(h, _)| *h > midnight_height)
                {
                    return Err(SplitError::Evidence);
                }
                self.holds.insert(record, (midnight_height, held));
            }
            Event::Final {
                eid,
                epoch,
                node,
                ciphertext,
            } => {
                let c = self.member(epoch, node)?;
                let r = self.request(&eid)?;
                r.live()?;
                if r.order_position.is_none() {
                    return Err(SplitError::NotOrdered);
                }
                let posts = self
                    .req_mut(eid)
                    .final_posts
                    .entry((epoch, ciphertext))
                    .or_default();
                posts.insert(node);
                if posts.len() >= c.quorum() {
                    self.finish(eid, State::Final(ciphertext));
                }
            }
            Event::Void {
                eid,
                epoch,
                node,
                reason,
            } => {
                let c = self.member(epoch, node)?;
                let r = self.request(&eid)?;
                r.live()?;
                if r.order_position.is_none() {
                    return Err(SplitError::NotOrdered);
                }
                // No local evidence test: authenticated posters validate their
                // own evidence. Only protocol-wide exceptions suppress posts.
                if reason == VoidReason::ShareComplaint && !r.admit_votes.is_empty() {
                    self.req_mut(eid).dealer_faults.push(reason);
                    return Ok(());
                }
                if reason == VoidReason::Revoked && self.any_release(eid) {
                    return Ok(());
                }
                let posts = self.req_mut(eid).void_posts.entry(epoch).or_default();
                posts.entry(node).or_insert(reason);
                if posts.len() > usize::from(c.f) {
                    self.finish(eid, State::Void(reason));
                }
            }
            Event::Lapse { eid } => {
                if !self.request(&eid)?.lapsed {
                    return Err(SplitError::Window);
                }
            }
            Event::ExpC { eid } | Event::Stall { eid } => {
                if !self.request(&eid)?.stalled {
                    return Err(SplitError::Window);
                }
            }
            Event::Expire { eid } => {
                if self.request(&eid)?.state != State::Expired {
                    return Err(SplitError::Window);
                }
            }
            Event::Rotate { epoch, committee } => {
                committee.validate().map_err(|_| SplitError::Parameters)?;
                if epoch <= self.epoch {
                    return Err(SplitError::Epoch);
                }
                self.committees.insert(epoch, committee);
                self.epoch = epoch;
            }
            Event::Checkpoint { pools } => {
                for (pool, cp) in &pools {
                    if pool.suite == Suite::Ecdsa
                        || !cp.pending_verified
                        || usize::try_from(cp.pending_count).ok() != Some(cp.pending.len())
                        || cp.h.checked_add(self.reservation_window).is_none()
                        || cp.pending_min != cp.pending.keys().next().copied().unwrap_or(cp.h + 1)
                        || cp.pending.keys().any(|index| *index == 0 || *index > cp.h)
                    {
                        return Err(SplitError::Evidence);
                    }
                    self.committee(pool.epoch)?;
                }
                if let Some(previous) = &self.checkpoint {
                    for (pool, old) in &previous.pools {
                        if pools.get(pool).is_none_or(|cp| cp.h < old.h) {
                            return Err(SplitError::Evidence);
                        }
                    }
                }
                self.checkpoint = Some(Checkpoint {
                    position: self.position,
                    pending: self.pending.clone(),
                    slots: self.slots.clone(),
                    pools,
                });
            }
            Event::Tick => {}
        }
        Ok(())
    }
    fn selection(
        &self,
        eid: Eid,
        generation: u16,
        variant: u16,
        tickets: &[Digest],
    ) -> Result<(), SplitError> {
        self.policy(eid)?;
        let r = self.request(&eid)?;
        if !r.in_force() {
            return Err(SplitError::Authorization);
        }
        if !r.admitted {
            return Err(SplitError::NoAnchor);
        }
        self.precedence(eid)?;
        let h = r.header()?;
        if generation == 0 || generation > h.generations() {
            return Err(SplitError::Generation);
        }
        let anchor = r.anchors.get(&generation).ok_or(SplitError::NoAnchor)?;
        if self.position <= anchor.position {
            return Err(SplitError::NoAnchor);
        }
        if variant < generation || variant > h.variants {
            return Err(SplitError::Selection);
        }
        if generation > 1
            && r.selections
                .get(&(generation - 1))
                .is_none_or(|(v, _)| variant <= *v)
        {
            return Err(SplitError::Selection);
        }
        let expected: Vec<_> = h
            .selected(generation, variant)
            .iter()
            .map(|t| t.digest)
            .collect();
        if expected != tickets {
            return Err(SplitError::Ticket);
        }
        if r.selections
            .get(&generation)
            .is_some_and(|s| s.0 != variant || s.1 != tickets)
        {
            return Err(SplitError::Selection);
        }
        if r.failures.contains(&VoidReason::FailedReleaseCheck) {
            return Err(SplitError::Evidence);
        }
        Ok(())
    }
    fn release_policy(
        &self,
        eid: Eid,
        generation: u16,
        midnight_height: u64,
        not_revoked_verified: bool,
    ) -> Result<(), SplitError> {
        let r = self.request(&eid)?;
        if r.header()?.charter.regulated() {
            if !not_revoked_verified {
                return Err(SplitError::Revoked);
            }
            if midnight_height < r.anchors[&generation].midnight_height {
                return Err(SplitError::Hold);
            }
            if generation == 1
                && midnight_height
                    < r.auth_final
                        .ok_or(SplitError::Authorization)?
                        .checked_add(r.header()?.charter.delta_hold())
                        .ok_or(SplitError::Parameters)?
            {
                return Err(SplitError::Hold);
            }
            if self
                .holds
                .get(&r.header()?.record)
                .is_some_and(|(h, _)| midnight_height < *h)
            {
                return Err(SplitError::Hold);
            }
        }
        Ok(())
    }
    fn any_release(&self, eid: Eid) -> bool {
        !self.requests[&eid].releases.is_empty()
            || self
                .witnesses
                .keys()
                .any(|k| matches!(k, WitnessKey::Release { eid: e, .. } if *e == eid))
    }
    fn audit_release(
        &mut self,
        eid: Eid,
        node: NodeId,
        generation: u16,
        midnight_height: u64,
    ) -> Result<(), SplitError> {
        let r = self.request(&eid)?;
        let h = r.header()?;
        let required_midnight_height = if h.charter.regulated() {
            let hold_end = if generation == 1 {
                r.auth_final
                    .ok_or(SplitError::Authorization)?
                    .checked_add(h.charter.delta_hold())
                    .ok_or(SplitError::Parameters)?
            } else {
                0
            };
            r.anchors[&generation].midnight_height.max(hold_end)
        } else {
            0
        };
        self.release_audits.push(ReleaseAudit {
            eid,
            node,
            generation,
            position: self.position,
            admitted: r.admitted,
            in_force: r.in_force(),
            held: self.held(h),
            midnight_height,
            required_midnight_height,
        });
        Ok(())
    }
    fn lock_record(&mut self, eid: Eid) -> Result<(), SplitError> {
        let h = self.request(&eid)?.header()?;
        if self
            .record_locks
            .get(&h.record)
            .is_some_and(|pin| *pin != h.pin)
        {
            return Err(SplitError::Pin);
        }
        self.record_locks.insert(h.record, h.pin);
        Ok(())
    }
    fn put_witness(
        &mut self,
        epoch: Epoch,
        node: NodeId,
        key: WitnessKey,
        value: WitnessValue,
        peers: Vec<NodeId>,
    ) -> Result<(), SplitError> {
        let c = self.member(epoch, node)?;
        let peers: BTreeSet<_> = peers.into_iter().collect();
        for peer in &peers {
            self.member(epoch, *peer)?;
            if *peer == node {
                return Err(SplitError::Witness);
            }
        }
        if peers.len() < usize::from(c.n - 1 - c.f) {
            return Err(SplitError::Witness);
        }
        if let Some(old) = self.witnesses.get(&key) {
            if old.value == value {
                return Ok(());
            }
            if !matches!(
                old.value,
                WitnessValue::Open {
                    committed: false,
                    ..
                }
            ) {
                return Err(SplitError::Witness);
            }
        }
        self.witnesses.insert(
            key,
            WitnessEntry {
                value,
                peers,
                position: self.position,
            },
        );
        Ok(())
    }
    fn require_witness(
        &self,
        epoch: Epoch,
        node: NodeId,
        key: &WitnessKey,
        value: &WitnessValue,
    ) -> Result<(), SplitError> {
        let c = self.member(epoch, node)?;
        let entry = self.witnesses.get(key).ok_or(SplitError::Witness)?;
        if &entry.value != value || entry.peers.len() < usize::from(c.n - 1 - c.f) {
            return Err(SplitError::Witness);
        }
        Ok(())
    }
    /// Structural invariants. Tests also compare consecutive snapshots to check
    /// temporal facts, including monotone slot burns and settlement pin locks.
    pub fn check_invariants(&self) -> Result<(), SplitError> {
        let fail = SplitError::Invariant;
        self.check_release_invariants()?;
        for slot in &self.named {
            if self.slot(slot) == SlotState::Free {
                return Err(fail("named slot returned to free"));
            }
        }
        for (slot, state) in &self.slots {
            if let Some(eid) = state.owner() {
                let r = self.request(&eid)?;
                if r.state.terminal() || r.lapsed || !r.header()?.slots.contains(slot) {
                    return Err(fail("invalid slot owner"));
                }
            }
        }
        let mut dd = BTreeSet::new();
        for (eid, r) in &self.requests {
            if r.order_position.is_some() && !dd.insert((r.envelope.epoch, r.envelope.dd)) {
                return Err(fail("duplicate ordered dd"));
            }
            if !r.releases.is_empty() && (!r.admitted || !r.in_force()) {
                return Err(fail("release before admission or authorization"));
            }
            if self.any_release(*eid) {
                let h = r.header()?;
                if self.record_locks.get(&h.record) != Some(&h.pin) {
                    return Err(fail("lost released pin"));
                }
                if r.settlement == Some(Settlement::UnspentFreshNullifier) {
                    return Err(fail("released record became unspent"));
                }
            }
            for ((g, node), v) in &r.releases {
                if !r.anchors.contains_key(g) || *g > G_MAX {
                    return Err(fail("release without bounded anchor"));
                }
                for t in r.header()?.selected(*g, *v) {
                    if self.signed_slots.get(&(*node, t.slot)) != Some(&t.digest) {
                        return Err(fail("two tickets on a slot"));
                    }
                }
            }
            if r.admitted && !r.anchors.contains_key(&1) {
                return Err(fail("admission without OBS anchor"));
            }
            if r.admitted
                && !r.state.terminal()
                && r.header()?
                    .slots
                    .iter()
                    .any(|slot| self.slot(slot) != SlotState::Claimed(*eid))
            {
                return Err(fail("admitted requests share a slot"));
            }
            if let State::Final(ciphertext) = r.state {
                if r.settlement != Some(Settlement::Successor(ciphertext)) {
                    return Err(fail("FINAL did not settle as successor"));
                }
            }
        }
        for frame in self.frames.values() {
            if !dd.insert((frame.value.epoch, frame.value.dd)) {
                return Err(fail("contribution repeats ordered dd"));
            }
        }
        Ok(())
    }
    pub fn check_release_invariants(&self) -> Result<(), SplitError> {
        for audit in &self.release_audits {
            if !audit.admitted || !audit.in_force || audit.held {
                return Err(SplitError::Invariant("unauthorized or held release"));
            }
            if audit.midnight_height < audit.required_midnight_height {
                return Err(SplitError::Invariant(
                    "release before Midnight hold window or OBS",
                ));
            }
            if self
                .request(&audit.eid)?
                .anchors
                .get(&audit.generation)
                .is_none_or(|anchor| anchor.position >= audit.position)
            {
                return Err(SplitError::Invariant("release before committed anchor"));
            }
        }
        Ok(())
    }
}
