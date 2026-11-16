//! Deterministic board state and signer policy (SCHEME §§3.5–3.9, 5).
//!
//! TRUST BOUNDARY: `apply` consumes an already authenticated, totally ordered log.
//! `Bind.valid`, `Complaint.valid`, `Partial.valid`, dealer verification and finality
//! evidence are results of the cryptographic/chain adapters, not claims to trust
//! from a network packet. OBS heights and PREVOTE digests remain adversarial.
//! `LocalBuild` must come from the node's own finalized chain and deterministic
//! builder, including eligibility and recursive reconstruction of `Anchor.previous`.
//! Never construct it from another node's transaction or supplied sighash.
//!
//! Quorums are ceil((n+f+1)/2) for n >= 3f+1: n=9, f=2 gives q=6.
//! OBS uses the first q distinct reports and entry f+1 in descending order.
//!
//! `NodeState::new` and snapshots model durable storage for simulations. For disk
//! use `NodeState::open`: writes fsync a temporary file, rename it, and fsync the
//! directory BEFORE an outgoing event is returned. A storage error must stop the
//! signer. Replay after restart blocks slots with own board posts but no ledger
//! entry. A node restored behind both storage and the board is Byzantine and must
//! count toward f. This module contains no networking, post signatures, chain
//! verifier, share storage/erasure, or cryptographic resharing implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub type Digest = [u8; 32];
pub type RequestId = Digest;
pub type Pin = Digest;
pub type NodeId = u16;
pub type Epoch = u64;
pub type GenerationId = u16;
pub type BoardResult<T> = Result<T, BoardError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardError {
    Parameters,
    Height,
    UnknownRequest,
    Bound,
    Tombstone,
    Epoch,
    Member,
    NotArmed,
    Window,
    Attempt,
    Frozen,
    NoAnchor,
    NoLock,
    Digest,
    AlreadyVoted,
    ReplayAbstention,
    ReplayIncomplete,
    InvalidEvidence,
    Handover,
    Persistence(String),
}
impl std::fmt::Display for BoardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "board: {self:?}")
    }
}
impl std::error::Error for BoardError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committee {
    pub n: u16,
    pub f: u16,
}
impl Committee {
    pub fn validate(self) -> BoardResult<()> {
        if self.n == 0 || u32::from(self.n) < 3 * u32::from(self.f) + 1 {
            Err(BoardError::Parameters)
        } else {
            Ok(())
        }
    }
    pub fn quorum(self) -> usize {
        (usize::from(self.n) + usize::from(self.f) + 1).div_ceil(2)
    }
    fn member(self, node: NodeId) -> BoardResult<()> {
        if node > 0 && node <= self.n {
            Ok(())
        } else {
            Err(BoardError::Member)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Open,
    Sealed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotation {
    Finish,
    Reshare,
    Void,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tombstone {
    Final(Digest),
    Void,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSpec {
    pub rid: RequestId,
    pub mid: Digest,
    pub pin: Pin,
    pub epoch: Epoch,
    pub mode: Mode,
    pub threshold: u16,
    pub not_before: u64,
    pub expires: u64,
    pub generations: u16,
    pub variants: u16,
    pub rotation: Rotation,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Candidate {
    pub attempt: u32,
    pub block_hash: Digest,
    pub digest: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorAnchor {
    pub generation: GenerationId,
    pub epoch: Epoch,
    pub attempt: u32,
    pub height: u64,
    pub candidate: Option<Candidate>,
    pub variant: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub height: u64,
    pub cut: u64,
    pub previous: Vec<PriorAnchor>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockCertificate {
    pub epoch: Epoch,
    pub candidate: Candidate,
    pub voters: BTreeSet<NodeId>,
    pub position: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub candidate: Candidate,
    pub variant: u16,
    pub position: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub reports: Vec<(NodeId, u64)>,
    pub anchor: Option<Anchor>,
    pub nacks: BTreeSet<NodeId>,
    pub failed: bool,
    pub votes: BTreeMap<Candidate, BTreeSet<NodeId>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generation {
    pub epoch: Epoch,
    pub threshold: u16,
    pub attempts: BTreeMap<u32, Attempt>,
    pub lock: Option<LockCertificate>,
    pub release: Option<Release>,
    pub partials: BTreeSet<NodeId>,
    pub transferred: bool,
}
impl Generation {
    fn new(epoch: Epoch, threshold: u16) -> Self {
        Self {
            epoch,
            threshold,
            attempts: BTreeMap::new(),
            lock: None,
            release: None,
            partials: BTreeSet::new(),
            transferred: false,
        }
    }
    pub fn in_flight(&self) -> bool {
        self.lock.is_some() || self.release.is_some()
    }
    pub fn anchor(&self) -> Option<(u32, &Anchor)> {
        let fixed = self
            .lock
            .as_ref()
            .map(|l| l.candidate.attempt)
            .or_else(|| self.release.as_ref().map(|r| r.candidate.attempt));
        if let Some(a) = fixed {
            return self
                .attempts
                .get(&a)
                .and_then(|v| v.anchor.as_ref().map(|h| (a, h)));
        }
        self.attempts.iter().rev().find_map(|(a, v)| {
            if v.failed {
                None
            } else {
                v.anchor.as_ref().map(|h| (*a, h))
            }
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Freeze {
    pub position: u64,
    pub old_epoch: Epoch,
    pub new_epoch: Epoch,
    pub in_flight: BTreeSet<GenerationId>,
    pub handed_over: bool,
    pub dealers: Vec<NodeId>,
    pub complained: BTreeSet<NodeId>,
    pub ready: BTreeMap<Vec<NodeId>, BTreeSet<NodeId>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub spec: RequestSpec,
    pub epoch: Epoch,
    pub threshold: u16,
    pub acks: BTreeSet<NodeId>,
    pub armed: bool,
    pub generations: BTreeMap<GenerationId, Generation>,
    pub freeze: Option<Freeze>,
    pub tombstone: Option<Tombstone>,
    served_epochs: BTreeSet<Epoch>,
    final_votes: BTreeMap<Digest, BTreeSet<(Epoch, NodeId)>>,
    void_votes: BTreeSet<(Epoch, NodeId)>,
}
impl Request {
    fn live(&self) -> BoardResult<()> {
        if self.tombstone.is_some() {
            Err(BoardError::Tombstone)
        } else {
            Ok(())
        }
    }
    fn prior(&self, generation: GenerationId) -> BoardResult<Vec<PriorAnchor>> {
        (1..generation)
            .map(|g| {
                let generation = &self.generations[&g];
                let (attempt, anchor) = generation.anchor().ok_or(BoardError::NoAnchor)?;
                Ok(PriorAnchor {
                    generation: g,
                    epoch: generation.epoch,
                    attempt,
                    height: anchor.height,
                    candidate: generation
                        .lock
                        .as_ref()
                        .map(|l| l.candidate.clone())
                        .or_else(|| generation.release.as_ref().map(|r| r.candidate.clone())),
                    variant: generation.release.as_ref().map(|r| r.variant),
                })
            })
            .collect()
    }
    pub fn signed(&self, g: GenerationId) -> bool {
        self.generations
            .get(&g)
            .is_some_and(|v| v.partials.len() >= usize::from(v.threshold))
    }
}

/// Every node field is the identity verified by the post-signature adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Bind {
        spec: RequestSpec,
        valid: bool,
    },
    Ack {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        mid: Digest,
    },
    Complaint {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        mid: Digest,
        valid: bool,
    },
    Obs {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        generation: GenerationId,
        attempt: u32,
        target_height: u64,
    },
    Nack {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        generation: GenerationId,
        attempt: u32,
    },
    Prevote {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        generation: GenerationId,
        candidate: Candidate,
    },
    Partial {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        generation: GenerationId,
        candidate: Candidate,
        variant: Option<u16>,
        valid: bool,
    },
    Final {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        txid: Digest,
        valid: bool,
    },
    ForeignSpend {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        txid: Digest,
        valid: bool,
    },
    Rotate {
        new_epoch: Epoch,
        committee: Committee,
    },
    Dealer {
        rid: RequestId,
        epoch: Epoch,
        dealer: NodeId,
        valid: bool,
    },
    DealerComplaint {
        rid: RequestId,
        epoch: Epoch,
        dealer: NodeId,
        valid: bool,
    },
    Ready {
        rid: RequestId,
        epoch: Epoch,
        node: NodeId,
        dealers: Vec<NodeId>,
    },
    Tick,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnPost {
    epoch: Epoch,
    node: NodeId,
    rid: RequestId,
    generation: GenerationId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Board {
    pub height: u64,
    pub position: u64,
    pub epoch: Epoch,
    committees: BTreeMap<Epoch, Committee>,
    requests: BTreeMap<RequestId, Request>,
    own_posts: Vec<OwnPost>,
}
impl Board {
    pub fn new(committee: Committee, epoch: Epoch) -> BoardResult<Self> {
        committee.validate()?;
        Ok(Self {
            height: 0,
            position: 0,
            epoch,
            committees: BTreeMap::from([(epoch, committee)]),
            requests: BTreeMap::new(),
            own_posts: Vec::new(),
        })
    }
    pub fn request(&self, rid: &RequestId) -> BoardResult<&Request> {
        self.requests.get(rid).ok_or(BoardError::UnknownRequest)
    }
    pub fn committee(&self, epoch: Epoch) -> BoardResult<Committee> {
        self.committees
            .get(&epoch)
            .copied()
            .ok_or(BoardError::Epoch)
    }
    fn member(&self, epoch: Epoch, node: NodeId) -> BoardResult<Committee> {
        let c = self.committee(epoch)?;
        c.member(node)?;
        Ok(c)
    }
    /// Invalid posts still occupy a log position and are retained for restart replay.
    /// Only the post's transition is ignored; monotone board time can expire requests.
    pub fn apply(&mut self, height: u64, event: Event) -> BoardResult<()> {
        if height < self.height {
            return Err(BoardError::Height);
        }
        self.height = height;
        self.position += 1;
        for r in self.requests.values_mut() {
            if r.tombstone.is_none()
                && height > r.spec.expires
                && !r.generations.values().any(Generation::in_flight)
            {
                r.tombstone = Some(Tombstone::Expired);
            }
        }
        match &event {
            Event::Prevote {
                rid,
                epoch,
                node,
                generation,
                ..
            }
            | Event::Partial {
                rid,
                epoch,
                node,
                generation,
                ..
            } => {
                self.member(*epoch, *node)?;
                self.own_posts.push(OwnPost {
                    epoch: *epoch,
                    node: *node,
                    rid: *rid,
                    generation: *generation,
                });
            }
            _ => {}
        }
        match event {
            Event::Tick => Ok(()),
            Event::Bind { spec, valid } => self.bind(spec, valid),
            Event::Rotate {
                new_epoch,
                committee,
            } => self.rotate(new_epoch, committee),
            other => {
                let rid = match &other {
                    Event::Ack { rid, .. }
                    | Event::Complaint { rid, .. }
                    | Event::Obs { rid, .. }
                    | Event::Nack { rid, .. }
                    | Event::Prevote { rid, .. }
                    | Event::Partial { rid, .. }
                    | Event::Final { rid, .. }
                    | Event::ForeignSpend { rid, .. }
                    | Event::Dealer { rid, .. }
                    | Event::DealerComplaint { rid, .. }
                    | Event::Ready { rid, .. } => *rid,
                    _ => unreachable!(),
                };
                let mut r = self
                    .requests
                    .remove(&rid)
                    .ok_or(BoardError::UnknownRequest)?;
                let result = self.transition(&mut r, other);
                self.requests.insert(rid, r);
                result
            }
        }
    }
    fn bind(&mut self, spec: RequestSpec, valid: bool) -> BoardResult<()> {
        if !valid {
            return Err(BoardError::InvalidEvidence);
        }
        if self.requests.contains_key(&spec.rid) {
            return Err(BoardError::Bound);
        }
        let c = self.committee(spec.epoch)?;
        if spec.epoch != self.epoch {
            return Err(BoardError::Epoch);
        }
        if spec.not_before > spec.expires
            || self.height > spec.expires
            || spec.generations == 0
            || (spec.threshold != c.f + 1 && spec.threshold != c.n - c.f)
            || (spec.rotation == Rotation::Reshare && spec.threshold != c.f + 1)
            || (spec.mode == Mode::Sealed
                && (spec.variants == 0 || spec.generations > spec.variants))
        {
            return Err(BoardError::Parameters);
        }
        let generations = (1..=spec.generations)
            .map(|g| (g, Generation::new(spec.epoch, spec.threshold)))
            .collect();
        self.requests.insert(
            spec.rid,
            Request {
                epoch: spec.epoch,
                threshold: spec.threshold,
                served_epochs: BTreeSet::from([spec.epoch]),
                spec,
                acks: BTreeSet::new(),
                armed: false,
                generations,
                freeze: None,
                tombstone: None,
                final_votes: BTreeMap::new(),
                void_votes: BTreeSet::new(),
            },
        );
        Ok(())
    }
    fn rotate(&mut self, new_epoch: Epoch, committee: Committee) -> BoardResult<()> {
        committee.validate()?;
        if self.epoch.checked_add(1) != Some(new_epoch) {
            return Err(BoardError::Epoch);
        }
        self.committees.insert(new_epoch, committee);
        self.epoch = new_epoch;
        for r in self.requests.values_mut().filter(|r| r.tombstone.is_none()) {
            // A registered successor counts from ROTATE, before HANDOVER.
            r.served_epochs.insert(new_epoch);
            match r.spec.rotation {
                Rotation::Finish => {}
                Rotation::Void => r.tombstone = Some(Tombstone::Void),
                Rotation::Reshare => {
                    // An unfinished transfer cannot silently skip its destination epoch.
                    if r.freeze.as_ref().is_some_and(|f| !f.handed_over) {
                        r.tombstone = Some(Tombstone::Void);
                        continue;
                    }
                    r.freeze = Some(Freeze {
                        position: self.position,
                        old_epoch: r.epoch,
                        new_epoch,
                        in_flight: r
                            .generations
                            .iter()
                            .filter(|(_, g)| g.in_flight())
                            .map(|(g, _)| *g)
                            .collect(),
                        handed_over: false,
                        dealers: Vec::new(),
                        complained: BTreeSet::new(),
                        ready: BTreeMap::new(),
                    });
                }
            }
        }
        Ok(())
    }
    fn check_generation<'a>(
        &self,
        r: &'a Request,
        epoch: Epoch,
        node: NodeId,
        g: GenerationId,
        starting: bool,
    ) -> BoardResult<&'a Generation> {
        r.live()?;
        self.member(epoch, node)?;
        if !r.armed {
            return Err(BoardError::NotArmed);
        }
        let generation = r.generations.get(&g).ok_or(BoardError::Parameters)?;
        if generation.epoch != epoch {
            return Err(BoardError::Epoch);
        }
        if r.freeze
            .as_ref()
            .is_some_and(|f| !f.handed_over && !f.in_flight.contains(&g))
        {
            return Err(BoardError::Frozen);
        }
        if starting && (self.height < r.spec.not_before || self.height > r.spec.expires) {
            return Err(BoardError::Window);
        }
        Ok(generation)
    }
    fn transition(&self, r: &mut Request, event: Event) -> BoardResult<()> {
        r.live()?;
        match event {
            Event::Ack {
                epoch, node, mid, ..
            }
            | Event::Complaint {
                epoch,
                node,
                mid,
                valid: false,
                ..
            } => {
                let c = self.member(epoch, node)?;
                if epoch != r.epoch || mid != r.spec.mid {
                    return Err(BoardError::Epoch);
                }
                if matches!(event, Event::Complaint { .. }) {
                    return Err(BoardError::InvalidEvidence);
                }
                r.acks.insert(node);
                r.armed |= r.acks.len() >= c.quorum();
                Ok(())
            }
            Event::Complaint {
                epoch,
                node,
                mid,
                valid: true,
                ..
            } => {
                self.member(epoch, node)?;
                if epoch != r.epoch || mid != r.spec.mid {
                    return Err(BoardError::Epoch);
                }
                r.tombstone = Some(Tombstone::Void);
                Ok(())
            }
            Event::Obs {
                epoch,
                node,
                generation: g,
                attempt: a,
                target_height,
                ..
            } => {
                let generation = self.check_generation(r, epoch, node, g, true)?;
                if generation.in_flight() || a == 0 {
                    return Err(BoardError::Attempt);
                }
                if !generation.attempts.contains_key(&a) {
                    let expected = generation
                        .attempts
                        .last_key_value()
                        .map_or(1, |(a, _)| a.saturating_add(1));
                    if a != expected
                        || generation
                            .attempts
                            .last_key_value()
                            .is_some_and(|(_, v)| !v.failed)
                    {
                        return Err(BoardError::Attempt);
                    }
                }
                let previous = r.prior(g)?;
                let c = self.committee(epoch)?;
                let attempt = r
                    .generations
                    .get_mut(&g)
                    .unwrap()
                    .attempts
                    .entry(a)
                    .or_default();
                if attempt.failed || attempt.anchor.is_some() {
                    return Err(BoardError::Attempt);
                }
                if attempt.reports.iter().any(|(i, _)| *i == node) {
                    return Ok(());
                }
                attempt.reports.push((node, target_height));
                if attempt.reports.len() == c.quorum() {
                    let mut heights: Vec<_> = attempt.reports.iter().map(|(_, h)| *h).collect();
                    heights.sort_unstable_by(|a, b| b.cmp(a));
                    attempt.anchor = Some(Anchor {
                        height: heights[usize::from(c.f)],
                        cut: self.position,
                        previous,
                    });
                }
                Ok(())
            }
            Event::Nack {
                epoch,
                node,
                generation: g,
                attempt: a,
                ..
            } => {
                let generation = self.check_generation(r, epoch, node, g, true)?;
                if generation.in_flight() {
                    return Err(BoardError::Attempt);
                }
                let attempt = r
                    .generations
                    .get_mut(&g)
                    .unwrap()
                    .attempts
                    .get_mut(&a)
                    .ok_or(BoardError::Attempt)?;
                if attempt.anchor.is_none() || attempt.failed {
                    return Err(BoardError::NoAnchor);
                }
                attempt.nacks.insert(node);
                if attempt.nacks.len() > usize::from(self.committee(epoch)?.f) {
                    attempt.failed = true;
                }
                Ok(())
            }
            Event::Prevote {
                epoch,
                node,
                generation: g,
                candidate,
                ..
            } => {
                let generation = self.check_generation(r, epoch, node, g, true)?;
                if r.spec.mode != Mode::Open || generation.in_flight() {
                    return Err(BoardError::Attempt);
                }
                let c = self.committee(epoch)?;
                let attempt = r
                    .generations
                    .get_mut(&g)
                    .unwrap()
                    .attempts
                    .get_mut(&candidate.attempt)
                    .ok_or(BoardError::Attempt)?;
                if attempt.failed || attempt.anchor.is_none() {
                    return Err(BoardError::NoAnchor);
                }
                let votes = attempt.votes.entry(candidate.clone()).or_default();
                votes.insert(node);
                if votes.len() >= c.quorum() {
                    let cert = LockCertificate {
                        epoch,
                        candidate,
                        voters: votes.clone(),
                        position: self.position,
                    };
                    r.generations.get_mut(&g).unwrap().lock = Some(cert);
                }
                Ok(())
            }
            Event::Partial {
                epoch,
                node,
                generation: g,
                candidate,
                variant,
                valid,
                ..
            } => {
                if !valid {
                    return Err(BoardError::InvalidEvidence);
                }
                let generation = self.check_generation(r, epoch, node, g, false)?;
                let attempt = generation
                    .attempts
                    .get(&candidate.attempt)
                    .ok_or(BoardError::Attempt)?;
                if attempt.failed || attempt.anchor.is_none() {
                    return Err(BoardError::NoAnchor);
                }
                match r.spec.mode {
                    Mode::Open => {
                        let lock = generation.lock.as_ref().ok_or(BoardError::NoLock)?;
                        if lock.candidate != candidate || variant.is_some() {
                            return Err(BoardError::Digest);
                        }
                    }
                    Mode::Sealed => {
                        if let Some(release) = &generation.release {
                            if release.candidate != candidate || Some(release.variant) != variant {
                                return Err(BoardError::Digest);
                            }
                        } else {
                            if self.height > r.spec.expires {
                                return Err(BoardError::Window);
                            }
                            let j = variant.ok_or(BoardError::Parameters)?;
                            let prior = attempt
                                .anchor
                                .as_ref()
                                .unwrap()
                                .previous
                                .last()
                                .and_then(|p| p.variant)
                                .unwrap_or(0);
                            if j == 0 || j > r.spec.variants || j <= prior {
                                return Err(BoardError::Parameters);
                            }
                            r.generations.get_mut(&g).unwrap().release = Some(Release {
                                candidate,
                                variant: j,
                                position: self.position,
                            });
                        }
                    }
                }
                r.generations.get_mut(&g).unwrap().partials.insert(node);
                Ok(())
            }
            Event::Final {
                epoch, node, txid, ..
            }
            | Event::ForeignSpend {
                epoch, node, txid, ..
            } => {
                // Evidence is checked by an honest poster in its own chain view.
                // The board records authenticated posts at their arrival position.
                let c = self.member(epoch, node)?;
                if !r.served_epochs.contains(&epoch) {
                    return Err(BoardError::Epoch);
                }
                let is_final = matches!(event, Event::Final { .. });
                let voters = if is_final {
                    r.final_votes.entry(txid).or_default()
                } else {
                    &mut r.void_votes
                };
                voters.insert((epoch, node));
                // Count an individual epoch's f+1, never mix memberships across epochs.
                if voters.iter().filter(|(e, _)| *e == epoch).count() > usize::from(c.f) {
                    r.tombstone = Some(if is_final {
                        Tombstone::Final(txid)
                    } else {
                        Tombstone::Void
                    });
                }
                Ok(())
            }
            Event::Dealer {
                epoch,
                dealer,
                valid,
                ..
            }
            | Event::DealerComplaint {
                epoch,
                dealer,
                valid,
                ..
            } => {
                if !valid {
                    return Err(BoardError::InvalidEvidence);
                }
                let freeze = r.freeze.as_mut().ok_or(BoardError::Handover)?;
                if freeze.handed_over || epoch != freeze.old_epoch || self.height > r.spec.expires {
                    return Err(BoardError::Handover);
                }
                self.member(epoch, dealer)?;
                if matches!(event, Event::DealerComplaint { .. }) {
                    freeze.complained.insert(dealer);
                } else if !freeze.dealers.contains(&dealer) {
                    freeze.dealers.push(dealer);
                }
                Ok(())
            }
            Event::Ready {
                epoch,
                node,
                dealers,
                ..
            } => {
                let c = self.member(epoch, node)?;
                let freeze = r.freeze.as_mut().ok_or(BoardError::Handover)?;
                if freeze.handed_over || epoch != freeze.new_epoch || self.height > r.spec.expires {
                    return Err(BoardError::Handover);
                }
                let q: Vec<_> = freeze
                    .dealers
                    .iter()
                    .filter(|d| !freeze.complained.contains(d))
                    .take(usize::from(r.threshold))
                    .copied()
                    .collect();
                if q.len() != usize::from(r.threshold) || dealers != q {
                    return Err(BoardError::Handover);
                }
                let voters = freeze.ready.entry(q).or_default();
                voters.insert(node);
                if voters.len() >= c.quorum() {
                    freeze.handed_over = true;
                    r.epoch = epoch;
                    r.served_epochs.insert(epoch);
                    r.threshold = c.f + 1;
                    r.armed = true;
                    for (g, v) in &mut r.generations {
                        if !freeze.in_flight.contains(g) {
                            v.epoch = epoch;
                            v.threshold = c.f + 1;
                            v.transferred = true;
                            for a in v.attempts.values_mut() {
                                a.failed = true;
                            }
                        }
                    }
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }
}

/// Output of the trusted LOCAL builder and finalized-chain adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalBuild {
    pub rid: RequestId,
    pub epoch: Epoch,
    pub generation: GenerationId,
    pub candidate: Candidate,
    pub pin: Pin,
    pub txid: Digest,
    pub variant: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Slot {
    digest: Digest,
    voted: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PersistedNodeState {
    processed_position: u64,
    slots: BTreeMap<(RequestId, GenerationId), Slot>,
}
#[derive(Clone, Debug)]
pub struct NodeState {
    pub node: NodeId,
    pub epoch: Epoch,
    durable: PersistedNodeState,
    abstain: BTreeSet<(RequestId, GenerationId)>,
    file: Option<PathBuf>,
    poisoned: bool,
    replay_target: Option<u64>,
    replay_pending: bool,
}
impl NodeState {
    pub fn new(node: NodeId, epoch: Epoch) -> Self {
        Self {
            node,
            epoch,
            durable: PersistedNodeState::default(),
            abstain: BTreeSet::new(),
            file: None,
            poisoned: false,
            replay_target: Some(0),
            replay_pending: false,
        }
    }
    pub fn snapshot(&self) -> PersistedNodeState {
        self.durable.clone()
    }
    /// `earlier_position` comes from a rollback-resistant record, or authenticated
    /// recovery answers on a consistent board. None keeps every post disabled.
    pub fn restart(
        node: NodeId,
        epoch: Epoch,
        durable: PersistedNodeState,
        earlier_position: Option<u64>,
    ) -> Self {
        let replay_target = earlier_position.map(|p| p.max(durable.processed_position));
        Self {
            node,
            epoch,
            durable,
            abstain: BTreeSet::new(),
            file: None,
            poisoned: false,
            replay_target,
            replay_pending: true,
        }
    }
    /// Answers must be authenticated, distinct, and from a consistent board.
    pub fn recover_position(
        &mut self,
        committee: Committee,
        answers: &BTreeMap<NodeId, u64>,
    ) -> BoardResult<()> {
        committee.validate()?;
        for node in answers.keys() {
            committee.member(*node)?;
        }
        if answers.len() < 2 * usize::from(committee.f) + 1 {
            return Err(BoardError::ReplayIncomplete);
        }
        let position = *answers.values().max().ok_or(BoardError::ReplayIncomplete)?;
        self.replay_target = Some(
            position
                .max(self.durable.processed_position)
                .max(self.replay_target.unwrap_or(0)),
        );
        self.replay_pending = true;
        Ok(())
    }
    /// Replay a verified board prefix. The callback must erase storage before it
    /// returns success: None means the whole request, Some(g) one generation.
    /// Call this for each processed prefix, including during normal operation.
    pub fn replay(
        &mut self,
        board: &Board,
        mut erase: impl FnMut(RequestId, Option<GenerationId>) -> BoardResult<()>,
    ) -> BoardResult<()> {
        self.replay_pending = true;
        for post in &board.own_posts {
            if post.node == self.node
                && post.epoch == self.epoch
                && !self
                    .durable
                    .slots
                    .contains_key(&(post.rid, post.generation))
            {
                self.abstain.insert((post.rid, post.generation));
            }
        }
        for (rid, request) in &board.requests {
            if matches!(
                request.tombstone,
                Some(Tombstone::Final(_) | Tombstone::Void)
            ) {
                erase(*rid, None)?;
                continue;
            }
            for (g, generation) in &request.generations {
                if (board.height > request.spec.expires && !generation.in_flight())
                    || (generation.transferred && generation.epoch != self.epoch)
                {
                    erase(*rid, Some(*g))?;
                }
            }
        }
        let mut next = self.durable.clone();
        next.processed_position = next.processed_position.max(board.position);
        self.save(next)?;
        if self
            .replay_target
            .is_none_or(|target| board.position < target)
        {
            return Err(BoardError::ReplayIncomplete);
        }
        self.replay_pending = false;
        Ok(())
    }
    /// Apply this gate to ACK, OBS, READY, and every other local board post too.
    pub fn ensure_can_post(&self, board: &Board) -> BoardResult<()> {
        if self.poisoned {
            return Err(BoardError::Persistence(
                "storage failed; restart required".into(),
            ));
        }
        if self.replay_pending
            || self.replay_target.is_none_or(|p| board.position < p)
            || board.position < self.durable.processed_position
        {
            return Err(BoardError::ReplayIncomplete);
        }
        Ok(())
    }

    /// The chain adapter supplies evidence from this node's view at confirmation
    /// depth. A false evidence flag must never produce an honest FINAL post.
    pub fn final_post(
        &self,
        board: &Board,
        rid: RequestId,
        txid: Digest,
        valid: bool,
    ) -> BoardResult<Event> {
        self.ensure_can_post(board)?;
        if !valid {
            return Err(BoardError::InvalidEvidence);
        }
        Ok(Event::Final {
            rid,
            epoch: self.epoch,
            node: self.node,
            txid,
            valid,
        })
    }

    /// The chain adapter supplies evidence of a foreign spend of the pin.
    pub fn foreign_spend(
        &self,
        board: &Board,
        rid: RequestId,
        txid: Digest,
        valid: bool,
    ) -> BoardResult<Event> {
        self.ensure_can_post(board)?;
        if !valid {
            return Err(BoardError::InvalidEvidence);
        }
        Ok(Event::ForeignSpend {
            rid,
            epoch: self.epoch,
            node: self.node,
            txid,
            valid,
        })
    }
    /// One process must exclusively own this path. Call replay with the share
    /// erasure adapter before posting. Supply the independently retained position.
    pub fn open(
        node: NodeId,
        epoch: Epoch,
        path: impl AsRef<Path>,
        earlier_position: Option<u64>,
    ) -> BoardResult<Self> {
        let path = path.as_ref();
        let durable = match File::open(path) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).map_err(io_error)?;
                decode_ledger(&bytes, node, epoch)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PersistedNodeState::default(),
            Err(e) => return Err(io_error(e)),
        };
        // Before rename, no event has been returned, so an orphan temporary file
        // is uncommitted. After rename, the authoritative final file already
        // contains the record. Under this API's exclusive-path requirement it is
        // safe to remove the orphan on restart, including a truncated one.
        match fs::remove_file(pending_path(path)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
        let mut state = Self::restart(node, epoch, durable, earlier_position);
        state.file = Some(path.to_owned());
        Ok(state)
    }
    pub fn abstains(&self, rid: RequestId, g: GenerationId) -> bool {
        self.abstain.contains(&(rid, g))
    }
    /// Read-only view of the durable slot ledger: the digest consumed for `(rid, g)`.
    pub fn slot_digest(&self, rid: RequestId, g: GenerationId) -> Option<Digest> {
        self.durable.slots.get(&(rid, g)).map(|s| s.digest)
    }
    fn validate(&self, board: &Board, build: &LocalBuild, voting: bool) -> BoardResult<()> {
        self.ensure_can_post(board)?;
        if build.epoch != self.epoch {
            return Err(BoardError::Epoch);
        }
        let r = board.request(&build.rid)?;
        let g = board.check_generation(r, self.epoch, self.node, build.generation, voting)?;
        if build.pin != r.spec.pin {
            return Err(BoardError::Digest);
        }
        if self.abstains(build.rid, build.generation) {
            return Err(BoardError::ReplayAbstention);
        }
        let a = g
            .attempts
            .get(&build.candidate.attempt)
            .ok_or(BoardError::Attempt)?;
        if a.failed || a.anchor.is_none() {
            return Err(BoardError::NoAnchor);
        }
        if self
            .durable
            .slots
            .get(&(build.rid, build.generation))
            .is_some_and(|s| s.digest != build.candidate.digest)
        {
            return Err(BoardError::Digest);
        }
        Ok(())
    }
    fn persist(
        &mut self,
        key: (RequestId, GenerationId),
        digest: Digest,
        vote: bool,
        position: u64,
    ) -> BoardResult<()> {
        let mut next = self.durable.clone();
        let slot = next.slots.entry(key).or_insert(Slot {
            digest,
            voted: false,
        });
        if slot.digest != digest {
            return Err(BoardError::Digest);
        }
        slot.voted |= vote;
        next.processed_position = next.processed_position.max(position);
        self.save(next)
    }
    fn save(&mut self, next: PersistedNodeState) -> BoardResult<()> {
        if let Some(path) = &self.file {
            if let Err(error) = write_ledger(path, self.node, self.epoch, &next) {
                self.poisoned = true;
                return Err(error);
            }
        }
        self.durable = next;
        Ok(())
    }
    pub fn prevote(&mut self, board: &Board, build: &LocalBuild) -> BoardResult<Event> {
        self.validate(board, build, true)?;
        if board.request(&build.rid)?.spec.mode != Mode::Open {
            return Err(BoardError::Parameters);
        }
        let key = (build.rid, build.generation);
        if self.durable.slots.get(&key).is_some_and(|s| s.voted) {
            return Err(BoardError::AlreadyVoted);
        }
        self.persist(key, build.candidate.digest, true, board.position)?;
        Ok(Event::Prevote {
            rid: build.rid,
            epoch: self.epoch,
            node: self.node,
            generation: build.generation,
            candidate: build.candidate.clone(),
        })
    }
    /// Authorizes cryptographic partial calculation only after durable consumption.
    /// Retransmission is allowed: the cryptographic partial is deterministic.
    pub fn partial(&mut self, board: &Board, build: &LocalBuild) -> BoardResult<Event> {
        self.validate(board, build, false)?;
        let r = board.request(&build.rid)?;
        let g = &r.generations[&build.generation];
        if r.spec.mode == Mode::Open {
            let lock = g.lock.as_ref().ok_or(BoardError::NoLock)?;
            if lock.candidate != build.candidate || build.variant.is_some() {
                return Err(BoardError::Digest);
            }
        } else {
            if g.release.is_none() && board.height > r.spec.expires {
                return Err(BoardError::Window);
            }
            let variant = build.variant.ok_or(BoardError::Parameters)?;
            let prior = g.attempts[&build.candidate.attempt]
                .anchor
                .as_ref()
                .unwrap()
                .previous
                .last()
                .and_then(|p| p.variant)
                .unwrap_or(0);
            if variant == 0 || variant > r.spec.variants || variant <= prior {
                return Err(BoardError::Parameters);
            }
            if g.release
                .as_ref()
                .is_some_and(|v| v.candidate != build.candidate || v.variant != variant)
            {
                return Err(BoardError::Digest);
            }
        }
        self.persist(
            (build.rid, build.generation),
            build.candidate.digest,
            false,
            board.position,
        )?;
        Ok(Event::Partial {
            rid: build.rid,
            epoch: self.epoch,
            node: self.node,
            generation: build.generation,
            candidate: build.candidate.clone(),
            variant: build.variant,
            valid: true,
        })
    }
}
fn io_error(e: std::io::Error) -> BoardError {
    BoardError::Persistence(e.to_string())
}
fn pending_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".pending");
    PathBuf::from(name)
}
fn write_ledger(
    path: &Path,
    node: NodeId,
    epoch: Epoch,
    state: &PersistedNodeState,
) -> BoardResult<()> {
    let mut bytes = b"LDLEDGER2".to_vec();
    bytes.extend(node.to_be_bytes());
    bytes.extend(epoch.to_be_bytes());
    bytes.extend(state.processed_position.to_be_bytes());
    for ((rid, g), slot) in &state.slots {
        bytes.extend(rid);
        bytes.extend(g.to_be_bytes());
        bytes.extend(slot.digest);
        bytes.push(u8::from(slot.voted));
    }
    let temp = pending_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(io_error)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(io_error)
}
fn decode_ledger(bytes: &[u8], node: NodeId, epoch: Epoch) -> BoardResult<PersistedNodeState> {
    let invalid = || BoardError::Persistence("invalid or mismatched ledger".into());
    if bytes.len() < 27
        || &bytes[..9] != b"LDLEDGER2"
        || bytes[9..11] != node.to_be_bytes()
        || bytes[11..19] != epoch.to_be_bytes()
        || !(bytes.len() - 27).is_multiple_of(67)
    {
        return Err(invalid());
    }
    let mut state = PersistedNodeState {
        processed_position: u64::from_be_bytes(bytes[19..27].try_into().unwrap()),
        ..Default::default()
    };
    for record in bytes[27..].as_chunks::<67>().0 {
        let rid = record[..32].try_into().unwrap();
        let g = u16::from_be_bytes(record[32..34].try_into().unwrap());
        if g == 0 || record[66] > 1 {
            return Err(invalid());
        }
        let slot = Slot {
            digest: record[34..66].try_into().unwrap(),
            voted: record[66] == 1,
        };
        if state.slots.insert((rid, g), slot).is_some() {
            return Err(invalid());
        }
    }
    Ok(state)
}

/// Small chain-conflict model for simulation. Real execution must be supplied by
/// a chain adapter that verifies every transaction spends its request's pin.
#[derive(Clone, Debug, Default)]
pub struct PinLedger {
    spent: BTreeMap<Pin, Digest>,
}
impl PinLedger {
    pub fn execute(&mut self, pin: Pin, txid: Digest) -> bool {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.spent.entry(pin) {
            entry.insert(txid);
            true
        } else {
            false
        }
    }
    pub fn transaction(&self, pin: &Pin) -> Option<Digest> {
        self.spent.get(pin).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const RID: Digest = [1; 32];
    const MID: Digest = [2; 32];
    const PIN: Digest = [3; 32];
    fn spec(mode: Mode, rotation: Rotation) -> RequestSpec {
        RequestSpec {
            rid: RID,
            mid: MID,
            pin: PIN,
            epoch: 1,
            mode,
            threshold: 2,
            not_before: 10,
            expires: 100,
            generations: 3,
            variants: 3,
            rotation,
        }
    }
    fn board(mode: Mode, rotation: Rotation) -> Board {
        let mut b = Board::new(Committee { n: 4, f: 1 }, 1).unwrap();
        b.apply(
            1,
            Event::Bind {
                spec: spec(mode, rotation),
                valid: true,
            },
        )
        .unwrap();
        for node in 1..=3 {
            b.apply(
                2,
                Event::Ack {
                    rid: RID,
                    epoch: 1,
                    node,
                    mid: MID,
                },
            )
            .unwrap();
        }
        b
    }
    fn observe(b: &mut Board, epoch: Epoch, g: u16, a: u32, heights: &[u64]) {
        for (i, h) in heights.iter().enumerate() {
            b.apply(
                10,
                Event::Obs {
                    rid: RID,
                    epoch,
                    node: i as u16 + 1,
                    generation: g,
                    attempt: a,
                    target_height: *h,
                },
            )
            .unwrap();
        }
    }
    fn build(epoch: Epoch, g: u16, a: u32, d: u8) -> LocalBuild {
        LocalBuild {
            rid: RID,
            epoch,
            generation: g,
            candidate: Candidate {
                attempt: a,
                block_hash: [a as u8; 32],
                digest: [d; 32],
            },
            pin: PIN,
            txid: [d; 32],
            variant: None,
        }
    }
    fn vote(b: &mut Board, node: u16, v: &LocalBuild) -> BoardResult<()> {
        b.apply(
            b.height,
            Event::Prevote {
                rid: RID,
                epoch: v.epoch,
                node,
                generation: v.generation,
                candidate: v.candidate.clone(),
            },
        )
    }
    fn lock(b: &mut Board, v: &LocalBuild) {
        for node in 1..=3 {
            vote(b, node, v).unwrap();
        }
    }
    fn generation(b: &Board, g: u16) -> &Generation {
        &b.request(&RID).unwrap().generations[&g]
    }
    fn nack(b: &mut Board, node: u16, g: u16, a: u32) -> BoardResult<()> {
        b.apply(
            b.height,
            Event::Nack {
                rid: RID,
                epoch: 1,
                node,
                generation: g,
                attempt: a,
            },
        )
    }
    fn restarted(
        node: NodeId,
        epoch: Epoch,
        durable: PersistedNodeState,
        board: &Board,
    ) -> NodeState {
        let mut state = NodeState::restart(node, epoch, durable, Some(board.position));
        state.replay(board, |_, _| Ok(())).unwrap();
        state
    }
    fn opened(
        node: NodeId,
        epoch: Epoch,
        path: impl AsRef<Path>,
        board: &Board,
    ) -> BoardResult<NodeState> {
        let path = path.as_ref().to_owned();
        let mut state = NodeState::open(node, epoch, &path, Some(board.position))?;
        // An empty store needs no erasures. Avoid an initial write here so the
        // persistence-failure tests still exercise the posting path.
        state.file = None;
        state.replay(board, |_, _| Ok(()))?;
        state.file = Some(path);
        Ok(state)
    }
    #[test]
    fn nine_nodes_need_six_votes() {
        assert_eq!(Committee { n: 9, f: 2 }.quorum(), 6);
        assert!(Board::new(Committee { n: 6, f: 2 }, 1).is_err());
        let mut b = Board::new(Committee { n: 9, f: 2 }, 1).unwrap();
        let mut s = spec(Mode::Open, Rotation::Finish);
        s.threshold = 3;
        b.apply(
            1,
            Event::Bind {
                spec: s,
                valid: true,
            },
        )
        .unwrap();
        for node in 1..=6 {
            b.apply(
                2,
                Event::Ack {
                    rid: RID,
                    epoch: 1,
                    node,
                    mid: MID,
                },
            )
            .unwrap();
            assert_eq!(b.request(&RID).unwrap().armed, node == 6);
        }
        observe(&mut b, 1, 1, 1, &[1000, 1000, 100, 101, 102, 103]);
        assert_eq!(generation(&b, 1).anchor().unwrap().1.height, 103);
        let fixed = generation(&b, 1).anchor().unwrap().1.height;
        assert_eq!(
            b.apply(
                b.height,
                Event::Obs {
                    rid: RID,
                    epoch: 1,
                    node: 7,
                    generation: 1,
                    attempt: 1,
                    target_height: 9000,
                },
            ),
            Err(BoardError::Attempt)
        );
        assert_eq!(generation(&b, 1).anchor().unwrap().1.height, fixed);
        let v = build(1, 1, 1, 9);
        for node in 1..=5 {
            vote(&mut b, node, &v).unwrap();
        }
        assert!(generation(&b, 1).lock.is_none());
        vote(&mut b, 6, &v).unwrap();
        assert_eq!(generation(&b, 1).lock.as_ref().unwrap().voters.len(), 6);
    }
    #[test]
    fn first_valid_binding_ack_quorum_and_validated_complaint() {
        let mut b = Board::new(Committee { n: 4, f: 1 }, 1).unwrap();
        assert_eq!(
            b.apply(
                1,
                Event::Bind {
                    spec: spec(Mode::Open, Rotation::Finish),
                    valid: false
                }
            ),
            Err(BoardError::InvalidEvidence)
        );
        b.apply(
            1,
            Event::Bind {
                spec: spec(Mode::Open, Rotation::Finish),
                valid: true,
            },
        )
        .unwrap();
        for _ in 0..4 {
            b.apply(
                2,
                Event::Ack {
                    rid: RID,
                    epoch: 1,
                    node: 1,
                    mid: MID,
                },
            )
            .unwrap();
        }
        assert!(!b.request(&RID).unwrap().armed);
        assert!(b
            .apply(
                2,
                Event::Ack {
                    rid: RID,
                    epoch: 1,
                    node: 2,
                    mid: [0; 32]
                }
            )
            .is_err());
        assert!(b
            .apply(
                2,
                Event::Complaint {
                    rid: RID,
                    epoch: 1,
                    node: 4,
                    mid: MID,
                    valid: false
                }
            )
            .is_err());
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        b.apply(
            2,
            Event::Complaint {
                rid: RID,
                epoch: 1,
                node: 4,
                mid: MID,
                valid: true,
            },
        )
        .unwrap();
        assert_eq!(b.request(&RID).unwrap().tombstone, Some(Tombstone::Void));
        assert_eq!(
            b.apply(
                3,
                Event::Bind {
                    spec: spec(Mode::Open, Rotation::Finish),
                    valid: true
                }
            ),
            Err(BoardError::Bound)
        );
    }
    #[test]
    fn first_distinct_reports_anchor_and_nack_retry_consume_no_slot() {
        let mut b = board(Mode::Open, Rotation::Finish);
        for (node, h) in [(1, 100), (1, 10000), (2, 101), (3, 102)] {
            b.apply(
                10,
                Event::Obs {
                    rid: RID,
                    epoch: 1,
                    node,
                    generation: 1,
                    attempt: 1,
                    target_height: h,
                },
            )
            .unwrap();
        }
        assert_eq!(generation(&b, 1).anchor().unwrap().1.height, 101);
        assert!(b
            .apply(
                10,
                Event::Obs {
                    rid: RID,
                    epoch: 1,
                    node: 4,
                    generation: 1,
                    attempt: 1,
                    target_height: 999
                }
            )
            .is_err());
        nack(&mut b, 4, 1, 1).unwrap();
        assert!(!generation(&b, 1).attempts[&1].failed);
        nack(&mut b, 4, 1, 1).unwrap();
        assert!(!generation(&b, 1).attempts[&1].failed);
        nack(&mut b, 2, 1, 1).unwrap();
        assert!(generation(&b, 1).attempts[&1].failed);
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        observe(&mut b, 1, 1, 2, &[105, 106, 107]);
        let mut node = NodeState::new(1, 1);
        let v = build(1, 1, 2, 10);
        let event = node.prevote(&b, &v).unwrap();
        b.apply(10, event).unwrap();
        assert_eq!(node.prevote(&b, &v), Err(BoardError::AlreadyVoted));
    }
    #[test]
    fn own_digest_lock_before_partial_and_no_late_prevote() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[100, 100, 100]);
        let v = build(1, 1, 1, 10);
        let mut node = NodeState::new(4, 1);
        assert_eq!(node.partial(&b, &v), Err(BoardError::NoLock));
        assert!(node.snapshot().slots.is_empty());
        lock(&mut b, &v);
        assert_eq!(
            node.partial(&b, &build(1, 1, 1, 11)),
            Err(BoardError::Digest)
        );
        let first = node.partial(&b, &v).unwrap();
        let resend = node.partial(&b, &v).unwrap();
        assert_eq!(first, resend);
        b.apply(10, first).unwrap();
        b.apply(101, Event::Tick).unwrap();
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        assert_eq!(
            NodeState::new(2, 1).prevote(&b, &v),
            Err(BoardError::Window)
        );
        assert!(node.partial(&b, &v).is_ok());
        assert!(NodeState::new(1, 1)
            .partial(
                &b,
                &LocalBuild {
                    pin: [9; 32],
                    ..v.clone()
                }
            )
            .is_err());
    }
    #[test]
    fn restart_replays_votes_and_partials_even_if_post_rejected() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[1, 2, 3]);
        let v = build(1, 1, 1, 10);
        let mut node = NodeState::new(1, 1);
        let event = node.prevote(&b, &v).unwrap();
        let snapshot = node.snapshot();
        b.apply(10, event).unwrap();
        assert_eq!(
            restarted(1, 1, snapshot, &b).prevote(&b, &v),
            Err(BoardError::AlreadyVoted)
        );
        let mut rolled = restarted(1, 1, PersistedNodeState::default(), &b);
        assert!(rolled.abstains(RID, 1));
        assert_eq!(rolled.prevote(&b, &v), Err(BoardError::ReplayAbstention));
        assert!(b
            .apply(
                10,
                Event::Partial {
                    rid: RID,
                    epoch: 1,
                    node: 4,
                    generation: 1,
                    candidate: v.candidate.clone(),
                    variant: None,
                    valid: false
                }
            )
            .is_err());
        assert!(restarted(4, 1, PersistedNodeState::default(), &b).abstains(RID, 1));
    }
    #[test]
    fn file_ledger_is_durable_before_outgoing_vote() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[10, 10, 10]);
        let v = build(1, 1, 1, 10);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("ld-board-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger");
        let _ = fs::remove_file(&path);
        let mut node = opened(1, 1, &path, &b).unwrap();
        let event = node.prevote(&b, &v).unwrap();
        // Crash BEFORE posting: the durable record still prevents a second vote.
        drop(node);
        assert_eq!(
            opened(1, 1, &path, &b).unwrap().prevote(&b, &v),
            Err(BoardError::AlreadyVoted)
        );
        b.apply(10, event).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(opened(1, 1, &path, &b).unwrap().abstains(RID, 1));
        fs::write(&path, b"LDLEDGER1corrupt").unwrap();
        assert!(opened(1, 1, &path, &b).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn board_cut_keeps_previous_anchor_despite_later_failure_and_retry() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[100, 101, 102]);
        observe(&mut b, 1, 2, 1, &[110, 111, 112]);
        let cut = generation(&b, 2).anchor().unwrap().1.clone();
        assert_eq!(cut.previous[0].height, 101);
        assert_eq!(cut.previous[0].attempt, 1);
        nack(&mut b, 1, 1, 1).unwrap();
        nack(&mut b, 2, 1, 1).unwrap();
        observe(&mut b, 1, 1, 2, &[120, 121, 122]);
        assert_eq!(generation(&b, 2).anchor().unwrap().1, &cut);
        observe(&mut b, 1, 3, 1, &[130, 131, 132]);
        let prior = &generation(&b, 3).anchor().unwrap().1.previous;
        assert_eq!(prior[0].height, 121);
        assert_eq!(prior[1].height, 111);
    }
    #[test]
    fn freeze_keeps_only_certificates_and_handover_moves_the_rest() {
        let mut b = board(Mode::Open, Rotation::Reshare);
        observe(&mut b, 1, 1, 1, &[100, 100, 100]);
        let locked = build(1, 1, 1, 10);
        lock(&mut b, &locked);
        observe(&mut b, 1, 2, 1, &[110, 110, 110]);
        let stray = build(1, 2, 1, 11);
        vote(&mut b, 4, &stray).unwrap();
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 4, f: 1 },
            },
        )
        .unwrap();
        assert_eq!(vote(&mut b, 1, &stray), Err(BoardError::Frozen));
        let event = NodeState::new(1, 1).partial(&b, &locked).unwrap();
        b.apply(10, event).unwrap();
        for dealer in [4, 1, 2] {
            b.apply(
                10,
                Event::Dealer {
                    rid: RID,
                    epoch: 1,
                    dealer,
                    valid: true,
                },
            )
            .unwrap();
        }
        b.apply(
            10,
            Event::DealerComplaint {
                rid: RID,
                epoch: 1,
                dealer: 4,
                valid: true,
            },
        )
        .unwrap();
        assert_eq!(
            b.apply(
                10,
                Event::Ready {
                    rid: RID,
                    epoch: 2,
                    node: 1,
                    dealers: vec![4, 1]
                }
            ),
            Err(BoardError::Handover)
        );
        for node in 1..=3 {
            b.apply(
                10,
                Event::Ready {
                    rid: RID,
                    epoch: 2,
                    node,
                    dealers: vec![1, 2],
                },
            )
            .unwrap();
        }
        assert_eq!(generation(&b, 1).epoch, 1);
        assert!(!generation(&b, 1).transferred);
        assert_eq!(generation(&b, 2).epoch, 2);
        assert!(generation(&b, 2).transferred);
        assert!(vote(&mut b, 2, &stray).is_err());
        observe(&mut b, 2, 2, 2, &[120, 120, 120]);
        let replacement = build(2, 2, 2, 12);
        lock(&mut b, &replacement);
        assert!(NodeState::new(1, 2).partial(&b, &replacement).is_ok());
        assert!(NodeState::new(1, 1).partial(&b, &locked).is_ok());
        let f = b.request(&RID).unwrap().freeze.as_ref().unwrap();
        for g in &f.in_flight {
            assert!(!generation(&b, *g).transferred);
        }
    }
    #[test]
    fn sealed_release_is_in_flight_and_variants_increase() {
        let mut b = board(Mode::Sealed, Rotation::Reshare);
        observe(&mut b, 1, 1, 1, &[10, 10, 10]);
        let v = LocalBuild {
            variant: Some(1),
            ..build(1, 1, 1, 10)
        };
        let event = NodeState::new(1, 1).partial(&b, &v).unwrap();
        b.apply(10, event).unwrap();
        observe(&mut b, 1, 2, 1, &[20, 20, 20]);
        let wrong = LocalBuild {
            variant: Some(1),
            ..build(1, 2, 1, 11)
        };
        assert!(NodeState::new(1, 1).partial(&b, &wrong).is_err());
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 4, f: 1 },
            },
        )
        .unwrap();
        assert_eq!(
            b.request(&RID).unwrap().freeze.as_ref().unwrap().in_flight,
            BTreeSet::from([1])
        );
        assert!(NodeState::new(2, 1).partial(&b, &v).is_ok());
        assert_eq!(
            NodeState::new(2, 1).partial(
                &b,
                &LocalBuild {
                    variant: Some(2),
                    ..wrong
                }
            ),
            Err(BoardError::Frozen)
        );
    }
    #[test]
    fn only_terminal_events_tombstone_and_every_generation_conflicts_on_pin() {
        let mut b = board(Mode::Open, Rotation::Finish);
        assert_eq!(
            b.apply(
                2,
                Event::Obs {
                    rid: RID,
                    epoch: 1,
                    node: 1,
                    generation: 1,
                    attempt: 1,
                    target_height: 1
                }
            ),
            Err(BoardError::Window)
        );
        for a in 1..=8 {
            observe(&mut b, 1, 1, a, &[10, 10, 10]);
            nack(&mut b, 1, 1, a).unwrap();
            nack(&mut b, 2, 1, a).unwrap();
            assert!(b.request(&RID).unwrap().tombstone.is_none());
        }
        b.apply(101, Event::Tick).unwrap();
        assert_eq!(b.request(&RID).unwrap().tombstone, Some(Tombstone::Expired));
        let mut b = board(Mode::Open, Rotation::Finish);
        for node in [1, 1] {
            b.apply(
                10,
                Event::Final {
                    rid: RID,
                    epoch: 1,
                    node,
                    txid: [9; 32],
                    valid: true,
                },
            )
            .unwrap();
        }
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        b.apply(
            10,
            Event::Final {
                rid: RID,
                epoch: 1,
                node: 2,
                txid: [9; 32],
                valid: true,
            },
        )
        .unwrap();
        assert_eq!(
            b.request(&RID).unwrap().tombstone,
            Some(Tombstone::Final([9; 32]))
        );
        b.apply(200, Event::Tick).unwrap();
        assert_eq!(
            b.request(&RID).unwrap().tombstone,
            Some(Tombstone::Final([9; 32]))
        );
        let mut chain = PinLedger::default();
        assert!(chain.execute(PIN, [1; 32]));
        for g in 2..=100 {
            assert!(!chain.execute(PIN, [g; 32]));
        }
    }
    #[test]
    fn void_rotation_foreign_spend_and_failed_handover() {
        let mut b = board(Mode::Open, Rotation::Void);
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 4, f: 1 },
            },
        )
        .unwrap();
        assert_eq!(b.request(&RID).unwrap().tombstone, Some(Tombstone::Void));
        let mut b = board(Mode::Open, Rotation::Finish);
        for node in 1..=2 {
            b.apply(
                10,
                Event::ForeignSpend {
                    rid: RID,
                    epoch: 1,
                    node,
                    txid: [8; 32],
                    valid: true,
                },
            )
            .unwrap();
        }
        assert_eq!(b.request(&RID).unwrap().tombstone, Some(Tombstone::Void));
        let mut b = board(Mode::Open, Rotation::Reshare);
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 4, f: 1 },
            },
        )
        .unwrap();
        b.apply(101, Event::Tick).unwrap();
        assert_eq!(b.request(&RID).unwrap().tombstone, Some(Tombstone::Expired));
        let mut s = spec(Mode::Open, Rotation::Reshare);
        s.threshold = 3;
        let mut b = Board::new(Committee { n: 4, f: 1 }, 1).unwrap();
        assert_eq!(
            b.apply(
                1,
                Event::Bind {
                    spec: s,
                    valid: true
                }
            ),
            Err(BoardError::Parameters)
        );
    }

    #[test]
    fn repeated_rotation_preserves_each_in_flight_epoch_threshold() {
        let mut b = board(Mode::Open, Rotation::Reshare);
        observe(&mut b, 1, 1, 1, &[10, 10, 10]);
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 7, f: 2 },
            },
        )
        .unwrap();
        for dealer in 1..=2 {
            b.apply(
                10,
                Event::Dealer {
                    rid: RID,
                    epoch: 1,
                    dealer,
                    valid: true,
                },
            )
            .unwrap();
        }
        for node in 1..=5 {
            b.apply(
                10,
                Event::Ready {
                    rid: RID,
                    epoch: 2,
                    node,
                    dealers: vec![1, 2],
                },
            )
            .unwrap();
        }
        observe(&mut b, 2, 1, 2, &[20, 20, 20, 20, 20]);
        let v = build(2, 1, 2, 12);
        for node in 1..=5 {
            vote(&mut b, node, &v).unwrap();
        }
        for node in 1..=2 {
            let event = NodeState::new(node, 2).partial(&b, &v).unwrap();
            b.apply(10, event).unwrap();
        }
        assert!(!b.request(&RID).unwrap().signed(1));
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 3,
                committee: Committee { n: 4, f: 1 },
            },
        )
        .unwrap();
        for dealer in 1..=3 {
            b.apply(
                10,
                Event::Dealer {
                    rid: RID,
                    epoch: 2,
                    dealer,
                    valid: true,
                },
            )
            .unwrap();
        }
        for node in 1..=3 {
            b.apply(
                10,
                Event::Ready {
                    rid: RID,
                    epoch: 3,
                    node,
                    dealers: vec![1, 2, 3],
                },
            )
            .unwrap();
        }
        assert_eq!(generation(&b, 1).threshold, 3);
        assert_eq!(generation(&b, 2).threshold, 2);
        assert!(!b.request(&RID).unwrap().signed(1));
        let event = NodeState::new(3, 2).partial(&b, &v).unwrap();
        b.apply(10, event).unwrap();
        assert!(b.request(&RID).unwrap().signed(1));
    }

    #[test]
    fn orphan_temporary_ledger_recovers_after_crash() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[10, 10, 10]);
        let v = build(1, 1, 1, 10);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("ld-board-orphan-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger");
        let _ = fs::remove_file(&path);
        fs::write(pending_path(&path), b"interrupted initial write").unwrap();
        let mut node = opened(1, 1, &path, &b).unwrap();
        assert!(!pending_path(&path).exists());
        let event = node.prevote(&b, &v).unwrap();
        b.apply(10, event).unwrap();
        drop(node);
        // A later crashed write must not replace the committed vote.
        fs::write(pending_path(&path), b"interrupted later write").unwrap();
        let mut node = opened(1, 1, &path, &b).unwrap();
        assert_eq!(node.prevote(&b, &v), Err(BoardError::AlreadyVoted));
        assert_eq!(
            node.prevote(&b, &build(1, 1, 1, 11)),
            Err(BoardError::Digest)
        );
        assert!(!pending_path(&path).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn storage_error_poisoning_requires_restart_before_any_signature() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[10, 10, 10]);
        let v = build(1, 1, 1, 10);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("ld-board-missing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("ledger");
        let mut node = opened(1, 1, &path, &b).unwrap();
        assert!(matches!(
            node.prevote(&b, &v),
            Err(BoardError::Persistence(_))
        ));
        fs::create_dir_all(&dir).unwrap();
        assert!(matches!(
            node.prevote(&b, &v),
            Err(BoardError::Persistence(_))
        ));
        assert!(opened(1, 1, &path, &b).unwrap().prevote(&b, &v).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn three_signed_generations_execute_at_most_once() {
        let mut b = board(Mode::Open, Rotation::Finish);
        let mut chain = PinLedger::default();
        let mut nodes = [
            NodeState::new(1, 1),
            NodeState::new(2, 1),
            NodeState::new(3, 1),
        ];
        let mut executions = 0;
        for g in 1..=3 {
            observe(
                &mut b,
                1,
                g,
                1,
                &[10 * g as u64, 10 * g as u64, 10 * g as u64],
            );
            let v = build(1, g, 1, g as u8);
            for node in &mut nodes {
                let e = node.prevote(&b, &v).unwrap();
                b.apply(10, e).unwrap();
            }
            for node in &mut nodes {
                let e = node.partial(&b, &v).unwrap();
                b.apply(10, e).unwrap();
            }
            assert!(b.request(&RID).unwrap().signed(g));
            executions += usize::from(chain.execute(v.pin, v.txid));
        }
        assert_eq!(executions, 1);
    }

    fn random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }
    fn shuffle<T>(items: &mut [T], seed: &mut u64) {
        for i in (1..items.len()).rev() {
            let j = random(seed) as usize % (i + 1);
            items.swap(i, j);
        }
    }
    #[test]
    fn randomized_equivocation_rollback_and_divergent_builders_cannot_double_certify() {
        // 600 seeds x two independent board views x 7 nodes. Nodes 6 and 7 are
        // the entire f=2 faulty set: 6 equivocates and 7 loses persistent state.
        // The rollback is counted WITHIN f, never added to f Byzantine nodes.
        // Distinct views ensure this tests quorum intersection rather than just
        // the reducer's rule of remembering its first certificate.
        let mut certified = 0;
        let mut stalled = 0;
        for seed in 1..=600u64 {
            let mut rng = seed;
            let mut b = Board::new(Committee { n: 7, f: 2 }, 1).unwrap();
            let mut s = spec(Mode::Open, Rotation::Finish);
            s.threshold = 3;
            b.apply(
                1,
                Event::Bind {
                    spec: s,
                    valid: true,
                },
            )
            .unwrap();
            for node in 1..=5 {
                b.apply(
                    2,
                    Event::Ack {
                        rid: RID,
                        epoch: 1,
                        node,
                        mid: MID,
                    },
                )
                .unwrap();
            }
            observe(&mut b, 1, 1, 1, &[100, 100, 100, 0, u64::MAX]);
            let mut left = b.clone();
            let mut right = b.clone();
            let a = build(1, 1, 1, 10);
            let z = build(1, 1, 1, 11);
            let mut posts = Vec::new();
            let mut honest_states = Vec::new();
            for node in 1..=5 {
                let mut state = NodeState::new(node, 1);
                let chosen = if random(&mut rng).is_multiple_of(2) {
                    &a
                } else {
                    &z
                };
                let first = state.prevote(&b, chosen).unwrap();
                // Persisted restart does not reset the one-vote rule.
                let mut restarted = restarted(node, 1, state.snapshot(), &b);
                assert!(restarted
                    .prevote(&b, if chosen == &a { &z } else { &a })
                    .is_err());
                posts.push(first);
                honest_states.push(state);
            }
            for v in [&a, &z] {
                posts.push(Event::Prevote {
                    rid: RID,
                    epoch: 1,
                    node: 6,
                    generation: 1,
                    candidate: v.candidate.clone(),
                });
            }
            let mut rolled = NodeState::new(7, 1);
            posts.push(rolled.prevote(&b, &a).unwrap());
            // Restoring BOTH the ledger and board prefix is a Byzantine rollback.
            let mut rolled = restarted(7, 1, PersistedNodeState::default(), &b);
            posts.push(rolled.prevote(&b, &z).unwrap());
            let mut other = posts.clone();
            shuffle(&mut posts, &mut rng);
            shuffle(&mut other, &mut rng);
            for event in posts {
                if !random(&mut rng).is_multiple_of(5) {
                    let _ = left.apply(10, event);
                }
            }
            for event in other {
                if !random(&mut rng).is_multiple_of(5) {
                    let _ = right.apply(10, event);
                }
            }
            let l = generation(&left, 1).lock.as_ref();
            let r = generation(&right, 1).lock.as_ref();
            if l.is_some() || r.is_some() {
                certified += 1;
            } else {
                stalled += 1;
            }
            if let (Some(l), Some(r)) = (l, r) {
                assert_eq!(l.candidate.digest, r.candidate.digest, "seed {seed}");
            }
            for view in [&left, &right] {
                assert!(view.request(&RID).unwrap().tombstone.is_none());
                for state in &honest_states {
                    let mut honest = state.clone();
                    for v in [&a, &z] {
                        if let Ok(partial) = honest.partial(view, v) {
                            let lock = generation(view, 1).lock.as_ref().unwrap();
                            assert_eq!(lock.candidate, v.candidate);
                            let mut after = view.clone();
                            after.apply(10, partial).unwrap();
                        }
                    }
                }
            }
        }
        assert!(certified > 0 && stalled > 0);
    }
    #[test]
    fn randomized_schedules_replay_identically_and_preserve_lifecycle_invariants() {
        // Many interleavings of retries, votes, duplicates, stale epochs, rotation,
        // complaints, expiry, and restoration. Invalid inputs are adversarial posts.
        for seed in 1..=200u64 {
            let mut rng = seed + 900;
            let mut b = board(Mode::Open, Rotation::Reshare);
            let initial = b.clone();
            let mut log = Vec::new();
            let mut nodes: Vec<_> = (1..=3).map(|i| NodeState::new(i, 1)).collect();
            let mut honest_digests: BTreeMap<(u16, u16), Digest> = BTreeMap::new();
            for step in 0..120 {
                let g = (random(&mut rng) % 3 + 1) as u16;
                let node = (random(&mut rng) % 4 + 1) as u16;
                let a = generation(&b, g)
                    .attempts
                    .last_key_value()
                    .map_or(1, |(a, v)| if v.failed { a + 1 } else { *a });
                let v = build(1, g, a, 10 + g as u8);
                let event = match random(&mut rng) % 10 {
                    0..=2 => Event::Obs {
                        rid: RID,
                        epoch: 1,
                        node,
                        generation: g,
                        attempt: a,
                        target_height: 100 + step,
                    },
                    3 => Event::Nack {
                        rid: RID,
                        epoch: 1,
                        node,
                        generation: g,
                        attempt: a,
                    },
                    4 if node <= 3 => match nodes[usize::from(node - 1)].prevote(&b, &v) {
                        Ok(e) => e,
                        Err(_) => Event::Tick,
                    },
                    5 if node <= 3 => match nodes[usize::from(node - 1)].partial(&b, &v) {
                        Ok(e) => {
                            let key = (node, g);
                            if let Some(old) = honest_digests.insert(key, v.candidate.digest) {
                                assert_eq!(old, v.candidate.digest);
                            }
                            assert!(generation(&b, g).lock.is_some());
                            e
                        }
                        Err(_) => Event::Tick,
                    },
                    6 => Event::Prevote {
                        rid: RID,
                        epoch: 1,
                        node: 4,
                        generation: g,
                        candidate: build(1, g, a, 99).candidate,
                    },
                    7 if step > 70 => Event::Rotate {
                        new_epoch: 2,
                        committee: Committee { n: 4, f: 1 },
                    },
                    8 => {
                        let i = (random(&mut rng) % 3) as usize;
                        nodes[i] = restarted(i as u16 + 1, 1, nodes[i].snapshot(), &b);
                        Event::Tick
                    }
                    _ => Event::Complaint {
                        rid: RID,
                        epoch: 1,
                        node: 4,
                        mid: MID,
                        valid: false,
                    },
                };
                let h = if step > 110 { 101 } else { 10 };
                log.push((h, event.clone()));
                let _ = b.apply(h, event);
                let r = b.request(&RID).unwrap();
                if let Some(f) = &r.freeze {
                    for g in &f.in_flight {
                        assert!(r.generations[g].in_flight());
                        assert!(!r.generations[g].transferred);
                    }
                }
                for generation in r.generations.values() {
                    if !generation.partials.is_empty() {
                        assert!(generation.lock.is_some());
                    }
                }
                if h <= 100 {
                    assert!(r.tombstone.is_none());
                }
            }
            let mut replay = initial;
            for (h, e) in log {
                let _ = replay.apply(h, e);
            }
            assert_eq!(replay, b, "seed {seed}");
        }
    }
    #[test]
    fn restored_node_posts_nothing_until_prior_position_and_erasure_replay() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[10, 10, 10]);
        let prefix = b.clone();
        let build = build(1, 1, 1, 10);
        let mut original = NodeState::new(1, 1);
        let old_snapshot = original.snapshot();
        let event = original.prevote(&b, &build).unwrap();
        b.apply(10, event).unwrap();
        let earlier_position = b.position;
        let mut restored = NodeState::restart(1, 1, old_snapshot, Some(earlier_position));
        assert_eq!(
            restored.ensure_can_post(&b),
            Err(BoardError::ReplayIncomplete)
        );
        assert_eq!(
            restored.replay(&prefix, |_, _| Ok(())),
            Err(BoardError::ReplayIncomplete)
        );
        assert_eq!(
            restored.prevote(&prefix, &build),
            Err(BoardError::ReplayIncomplete)
        );
        assert_eq!(
            restored.partial(&prefix, &build),
            Err(BoardError::ReplayIncomplete)
        );
        assert_eq!(
            restored.ensure_can_post(&prefix),
            Err(BoardError::ReplayIncomplete)
        );
        restored.replay(&b, |_, _| Ok(())).unwrap();
        assert_eq!(
            restored.prevote(&b, &build),
            Err(BoardError::ReplayAbstention)
        );
        assert!(restored.abstains(RID, 1));
        assert_eq!(
            restored.ensure_can_post(&prefix),
            Err(BoardError::ReplayIncomplete)
        );

        // Replay a tombstone with secret storage restored from an old snapshot.
        for node in 1..=2 {
            b.apply(
                10,
                Event::ForeignSpend {
                    rid: RID,
                    epoch: 1,
                    node,
                    txid: [99; 32],
                    valid: true,
                },
            )
            .unwrap();
        }
        let mut secrets = BTreeMap::from([((RID, 1), vec![42u8; 32]), ((RID, 2), vec![43u8; 32])]);
        let mut restored =
            NodeState::restart(1, 1, PersistedNodeState::default(), Some(b.position));
        assert_eq!(
            restored.replay(&b, |_, _| Err(BoardError::Persistence(
                "erase failed".into()
            ))),
            Err(BoardError::Persistence("erase failed".into()))
        );
        assert_eq!(
            restored.ensure_can_post(&b),
            Err(BoardError::ReplayIncomplete)
        );
        restored
            .replay(&b, |rid, g| {
                secrets.retain(|(r, k), _| *r != rid || g.is_some_and(|g| g != *k));
                Ok(())
            })
            .unwrap();
        assert!(secrets.is_empty());
        assert!(restored.ensure_can_post(&b).is_ok());
    }

    #[test]
    fn recovery_without_position_needs_authenticated_answers_and_expiry_erasure() {
        let mut b = board(Mode::Open, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[10, 10, 10]);
        let v = build(1, 1, 1, 10);
        lock(&mut b, &v);
        let mut state = NodeState::restart(4, 1, PersistedNodeState::default(), None);
        assert_eq!(
            state.replay(&b, |_, _| Ok(())),
            Err(BoardError::ReplayIncomplete)
        );
        let committee = Committee { n: 4, f: 1 };
        assert_eq!(
            state.recover_position(
                committee,
                &BTreeMap::from([(1, b.position), (2, b.position)])
            ),
            Err(BoardError::ReplayIncomplete)
        );
        let previous = b.clone();
        b.apply(1001, Event::Tick).unwrap();
        state
            .recover_position(
                committee,
                &BTreeMap::from([
                    (1, previous.position),
                    (2, b.position),
                    (3, previous.position),
                ]),
            )
            .unwrap();
        assert_eq!(
            state.replay(&previous, |_, _| Ok(())),
            Err(BoardError::ReplayIncomplete)
        );
        let mut erased = Vec::new();
        state
            .replay(&b, |rid, g| {
                erased.push((rid, g));
                Ok(())
            })
            .unwrap();
        assert!(!erased.contains(&(RID, Some(1)))); // Locked generation remains.
        assert!(erased.contains(&(RID, Some(2))));
        assert!(state.ensure_can_post(&b).is_ok());
    }

    #[test]
    fn nine_node_ready_handover_needs_six_and_keeps_t2_separate() {
        let mut b = board(Mode::Open, Rotation::Reshare);
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 9, f: 2 },
            },
        )
        .unwrap();
        for dealer in 1..=2 {
            b.apply(
                10,
                Event::Dealer {
                    rid: RID,
                    epoch: 1,
                    dealer,
                    valid: true,
                },
            )
            .unwrap();
        }
        for node in 1..=5 {
            b.apply(
                10,
                Event::Ready {
                    rid: RID,
                    epoch: 2,
                    node,
                    dealers: vec![1, 2],
                },
            )
            .unwrap();
        }
        assert!(
            !b.request(&RID)
                .unwrap()
                .freeze
                .as_ref()
                .unwrap()
                .handed_over
        );
        b.apply(
            10,
            Event::Ready {
                rid: RID,
                epoch: 2,
                node: 6,
                dealers: vec![1, 2],
            },
        )
        .unwrap();
        assert!(
            b.request(&RID)
                .unwrap()
                .freeze
                .as_ref()
                .unwrap()
                .handed_over
        );
        let mut old = NodeState::restart(1, 1, PersistedNodeState::default(), Some(b.position));
        let mut erased = Vec::new();
        old.replay(&b, |rid, g| {
            erased.push((rid, g));
            Ok(())
        })
        .unwrap();
        assert!(erased.contains(&(RID, Some(1))));
        let mut b = Board::new(Committee { n: 9, f: 2 }, 1).unwrap();
        let mut s = spec(Mode::Open, Rotation::Finish);
        s.threshold = 7;
        b.apply(
            1,
            Event::Bind {
                spec: s,
                valid: true,
            },
        )
        .unwrap();
        assert_eq!(b.request(&RID).unwrap().threshold, 7);
    }

    // Counterexamples of the Quint conformance findings (tests/quint-regressions/COUNTEREXAMPLES.md).

    /// E1: the board does not check generation eligibility. An OBS quorum for
    /// generation 2 at the anchor height of generation 1 (less than any delta above
    /// it) anchors. Eligibility is checked by each node before it posts OBS.
    #[test]
    fn counterexample_e1_board_does_not_check_generation_delay() {
        let mut b = board(Mode::Sealed, Rotation::Finish);
        observe(&mut b, 1, 1, 1, &[100, 100, 100]);
        observe(&mut b, 1, 2, 1, &[100, 100, 100]);
        let (_, a) = generation(&b, 2).anchor().unwrap();
        assert_eq!(a.height, 100);
        assert_eq!(a.previous[0].height, 100);
    }

    /// Evidence gates the honest poster, not an evaluator's board count.
    #[test]
    fn g1_final_counted_without_evaluator_chain_view() {
        let mut b = board(Mode::Open, Rotation::Finish);
        let fin = |node, valid| Event::Final {
            rid: RID,
            epoch: 1,
            node,
            txid: [9; 32],
            valid,
        };
        b.apply(10, fin(4, false)).unwrap();
        b.apply(10, fin(4, false)).unwrap();
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        b.apply(11, fin(1, true)).unwrap();
        assert_eq!(
            b.request(&RID).unwrap().tombstone,
            Some(Tombstone::Final([9; 32]))
        );
    }

    /// Each served epoch retains its own quorum after handover.
    #[test]
    fn g2_old_committee_final_counts_after_handover() {
        let mut b = board(Mode::Open, Rotation::Reshare);
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 4, f: 1 },
            },
        )
        .unwrap();
        for dealer in [1, 2] {
            b.apply(
                10,
                Event::Dealer {
                    rid: RID,
                    epoch: 1,
                    dealer,
                    valid: true,
                },
            )
            .unwrap();
        }
        for node in 1..=3 {
            b.apply(
                10,
                Event::Ready {
                    rid: RID,
                    epoch: 2,
                    node,
                    dealers: vec![1, 2],
                },
            )
            .unwrap();
        }
        assert!(
            b.request(&RID)
                .unwrap()
                .freeze
                .as_ref()
                .unwrap()
                .handed_over
        );
        let fin = |epoch, node| Event::Final {
            rid: RID,
            epoch,
            node,
            txid: [9; 32],
            valid: true,
        };
        b.apply(11, fin(1, 1)).unwrap();
        b.apply(11, fin(2, 2)).unwrap();
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        b.apply(11, fin(1, 2)).unwrap();
        assert_eq!(
            b.request(&RID).unwrap().tombstone,
            Some(Tombstone::Final([9; 32]))
        );
    }

    #[test]
    fn a2_successor_posts_count_from_rotate_with_own_threshold() {
        let mut b = board(Mode::Open, Rotation::Reshare);
        let fin = |epoch, node| Event::Final {
            rid: RID,
            epoch,
            node,
            txid: [9; 32],
            valid: false,
        };
        assert_eq!(b.apply(10, fin(2, 1)), Err(BoardError::Epoch));
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 7, f: 2 },
            },
        )
        .unwrap();
        b.apply(10, fin(1, 1)).unwrap();
        b.apply(10, fin(2, 2)).unwrap();
        b.apply(10, fin(2, 3)).unwrap();
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        b.apply(10, fin(2, 4)).unwrap();
        assert_eq!(
            b.request(&RID).unwrap().tombstone,
            Some(Tombstone::Final([9; 32]))
        );
    }

    #[test]
    fn a2_void_counts_distinct_members_not_txids() {
        let mut b = board(Mode::Open, Rotation::Reshare);
        let void = |node, txid| Event::ForeignSpend {
            rid: RID,
            epoch: 1,
            node,
            txid: [txid; 32],
            valid: false,
        };
        b.apply(10, void(1, 8)).unwrap();
        b.apply(10, void(1, 9)).unwrap();
        assert!(b.request(&RID).unwrap().tombstone.is_none());
        b.apply(10, void(2, 10)).unwrap();
        assert_eq!(b.request(&RID).unwrap().tombstone, Some(Tombstone::Void));
        assert_eq!(
            b.apply(
                10,
                Event::Final {
                    rid: RID,
                    epoch: 1,
                    node: 3,
                    txid: [9; 32],
                    valid: true
                }
            ),
            Err(BoardError::Tombstone)
        );
    }

    #[test]
    fn a2_honest_tombstone_posts_require_evidence() {
        let b = board(Mode::Open, Rotation::Finish);
        let node = NodeState::new(1, 1);
        assert_eq!(
            node.final_post(&b, RID, [9; 32], false),
            Err(BoardError::InvalidEvidence)
        );
        assert_eq!(
            node.foreign_spend(&b, RID, [9; 32], false),
            Err(BoardError::InvalidEvidence)
        );
        assert!(matches!(
            node.final_post(&b, RID, [9; 32], true).unwrap(),
            Event::Final {
                node: 1,
                epoch: 1,
                valid: true,
                ..
            }
        ));
        assert!(matches!(
            node.foreign_spend(&b, RID, [9; 32], true).unwrap(),
            Event::ForeignSpend {
                node: 1,
                epoch: 1,
                valid: true,
                ..
            }
        ));
        let restarted = NodeState::restart(1, 1, node.snapshot(), None);
        assert_eq!(
            restarted.final_post(&b, RID, [9; 32], true),
            Err(BoardError::ReplayIncomplete)
        );
        assert_eq!(
            restarted.foreign_spend(&b, RID, [9; 32], true),
            Err(BoardError::ReplayIncomplete)
        );
    }

    #[test]
    fn a2_registered_epoch_must_belong_to_request_and_final_txids_must_match() {
        let mut b = board(Mode::Open, Rotation::Finish);
        b.apply(
            10,
            Event::Rotate {
                new_epoch: 2,
                committee: Committee { n: 4, f: 1 },
            },
        )
        .unwrap();
        let mut spec = b.request(&RID).unwrap().spec.clone();
        spec.epoch = 2;
        spec.rid = [7; 32];
        b.apply(10, Event::Bind { spec, valid: true }).unwrap();
        let fin = |epoch, node, txid| Event::Final {
            rid: [7; 32],
            epoch,
            node,
            txid: [txid; 32],
            valid: false,
        };
        assert_eq!(b.apply(10, fin(1, 1, 9)), Err(BoardError::Epoch));
        b.apply(10, fin(2, 1, 8)).unwrap();
        b.apply(10, fin(2, 2, 9)).unwrap();
        assert!(b.request(&[7; 32]).unwrap().tombstone.is_none());
        b.apply(10, fin(2, 3, 9)).unwrap();
        assert_eq!(
            b.request(&[7; 32]).unwrap().tombstone,
            Some(Tombstone::Final([9; 32]))
        );
    }
}
