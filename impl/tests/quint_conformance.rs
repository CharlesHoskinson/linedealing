//! Model-based conformance test: replays Quint ITF traces of
//! `formal/quint/conformance/linedealing_mbt.qnt` (a projection wrapper around
//! `formal/quint/linedealing.qnt`) on the Rust board and signer policy.
//!
//! For every trace step the harness derives the transition from the state diff
//! (one new board post, one new chain block, one board-height tick, or one node
//! record change), drives the Rust code with it and then compares:
//!
//! * the derived board state (binding, status, ACK quorum, ROTATE, HANDOVER, the
//!   reshare set Q, and per generation the active epoch, the freeze decision,
//!   lock or release, the lock digest, each attempt's anchor height and failure)
//!   with the model's projection of the same state, and
//! * every honest node's slot ledger, abstentions and erasures with the model's
//!   node records.
//!
//! Honest PREVOTE and PARTIAL posts go only through `NodeState::prevote` and
//! `NodeState::partial`; every other honest post passes `ensure_can_post`.
//! Byzantine posts go straight to `Board::apply`. Evidence flags come from trace
//! ground truth (ciphertext validity in the MSG, chain contents) or from the Rust
//! board's own state, never from the model projection.
//!
//! The Rust side also checks the five model invariants on its own state after
//! every step. Traces of the two broken model instances must be refused by the
//! Rust signer policy at an honest PREVOTE or PARTIAL before the violation.
//!
//! Traces live in `formal/quint/conformance/traces/<instance>/`; set
//! `QUINT_TRACES` to replay another corpus with the same layout.

mod itf;

use itf::{Block, Int, ModelNode, Post, Proj, State, Trace};
use line_dealing::board::{
    Board, BoardError, Candidate, Committee, Digest, Epoch, Event, GenerationId, LocalBuild, Mode,
    NodeId, NodeState, PersistedNodeState, PinLedger, RequestSpec, Rotation, Tombstone,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const GENS: [GenerationId; 2] = [1, 2];
const RID: Int = 4242;
const PIN: Int = 31337;
const FOREIGN_TX: Int = 999;
const SEALED_DIGEST_BASE: Int = 800_000;
const FEE_CEILING: Int = 25;
const DELTA: Int = 1;

const LABEL_DEAL_AFTER_HANDOVER: &str = "RS_DEAL after HANDOVER";
const M2: &str = "M2 post by an epoch before its ROTATE (model does not check key registration)";

fn enc(x: Int) -> Digest {
    let mut d = [0u8; 32];
    d[24..].copy_from_slice(&x.to_be_bytes());
    d
}

fn dec(d: &Digest) -> Int {
    Int::from_be_bytes(d[24..].try_into().unwrap())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Broken {
    None,
    Prevote,
    Rule4,
}

#[derive(Clone, Copy, Debug)]
struct Instance {
    name: &'static str,
    n: u16,
    f: u16,
    broken: Broken,
}

const INSTANCES: [Instance; 4] = [
    Instance {
        name: "n4",
        n: 4,
        f: 1,
        broken: Broken::None,
    },
    Instance {
        name: "n7",
        n: 7,
        f: 2,
        broken: Broken::None,
    },
    Instance {
        name: "broken_prevote",
        n: 4,
        f: 1,
        broken: Broken::Prevote,
    },
    Instance {
        name: "broken_rule4",
        n: 4,
        f: 1,
        broken: Broken::Rule4,
    },
];

/// Sealed Select of the model's builder (selectSealedVariant): the chain adapter
/// stand-in that decides whether a Byzantine sealed PARTIAL is for the selected
/// variant at its anchor. Honest posts carry the variant their builder chose.
fn select_variant(chain: &[Block], h: Int, g: Int, prev_h: Int, prev_v: Int) -> Int {
    if h < 1 || h > chain.len() as Int {
        return 0;
    }
    let blk = &chain[(h - 1) as usize];
    let delta_ok = g == 1 || (prev_h >= 1 && h >= prev_h + DELTA);
    let spent = chain[..h as usize].iter().any(|b| b.tx_kind != "TxNone");
    if !blk.trigger_ok || spent || !delta_ok {
        0
    } else if prev_v < 1 && 15 >= blk.market_fee {
        1
    } else if prev_v < 2 && FEE_CEILING >= blk.market_fee {
        2
    } else {
        0
    }
}

/// How a trace ended.
#[derive(Debug)]
#[allow(dead_code)] // fields are read through Debug in failure reports
enum Outcome {
    /// Every step replayed and matched.
    Conformed,
    ModelArtifact {
        step: usize,
        detail: String,
    },
    /// The Rust signer policy refused an honest model step.
    Refused {
        step: usize,
        action: String,
        error: BoardError,
    },
    /// The Rust state diverged from the model.
    Mismatch {
        step: usize,
        action: String,
        detail: String,
    },
}

#[derive(Default)]
struct Stats {
    traces: usize,
    conformed: usize,
    m1_traces: usize,
    steps: usize,
    actions: BTreeMap<String, usize>,
    reached: BTreeMap<&'static str, usize>,
    erase_beyond_model: BTreeMap<String, usize>,
    probes: usize,
    projections: usize,
    ignored: BTreeMap<&'static str, usize>,
}

struct Replay {
    inst: Instance,
    rid: Digest,
    pin: Digest,
    board: Board,
    nodes: BTreeMap<(Epoch, NodeId), NodeState>,
    erased: BTreeMap<(Epoch, NodeId), BTreeSet<GenerationId>>,
    pins: PinLedger,
    executions: usize,
    bound: Option<Post>,
    valid_complaint: bool,
    /// Epoch-2 attempt number offset per generation (Rust keeps the failed
    /// epoch-1 attempts of a transferred generation; the model restarts at 1).
    offset: BTreeMap<GenerationId, u32>,
    /// Honest partials accepted by the board: (epoch, node, g) -> digest or variant.
    honest_partials: BTreeMap<(Epoch, NodeId, GenerationId), Int>,
    reached: BTreeSet<&'static str>,
    step_no: usize,
    ignored: BTreeMap<&'static str, usize>,
    /// Regression replays of traces from the pre-fix model (finding M1) set this:
    /// the old model let an old node deal after HANDOVER.
    old_model_deal_after_handover: bool,
    /// Model board positions refused because no epoch key existed at arrival.
    unregistered_posts: BTreeSet<usize>,
}

type StepResult = Result<(), (Option<BoardError>, String)>;

fn mismatch<T>(detail: String) -> Result<T, (Option<BoardError>, String)> {
    Err((None, detail))
}

impl Replay {
    fn new(inst: Instance) -> Self {
        let committee = Committee {
            n: inst.n,
            f: inst.f,
        };
        let mut nodes = BTreeMap::new();
        for e in [1u64, 2] {
            for i in 1..=inst.n {
                nodes.insert((e, i), NodeState::new(i, e));
            }
        }
        Self {
            inst,
            rid: enc(RID),
            pin: enc(PIN),
            board: Board::new(committee, 1).unwrap(),
            nodes,
            erased: BTreeMap::new(),
            pins: PinLedger::default(),
            executions: 0,
            bound: None,
            valid_complaint: false,
            offset: BTreeMap::new(),
            honest_partials: BTreeMap::new(),
            reached: BTreeSet::new(),
            step_no: 0,
            ignored: BTreeMap::new(),
            old_model_deal_after_handover: false,
            unregistered_posts: BTreeSet::new(),
        }
    }

    fn committee(&self) -> Committee {
        Committee {
            n: self.inst.n,
            f: self.inst.f,
        }
    }

    fn is_byz(s: &State, e: Int, i: Int) -> bool {
        match e {
            1 => s.byz1.contains(&i),
            2 => s.byz2.contains(&i),
            _ => false,
        }
    }

    /// Rust attempt number of the model's attempt `a` of epoch `e`.
    fn ra(&self, e: Int, g: GenerationId, a: Int) -> u32 {
        let base = if e == 2 {
            self.offset.get(&g).copied().unwrap_or(0)
        } else {
            0
        };
        (a.max(0) as u32) + base
    }

    fn gate(&self, e: Int, i: Int) -> StepResult {
        let node = &self.nodes[&(e as u64, i as u16)];
        node.ensure_can_post(&self.board)
            .or_else(|err| mismatch(format!("honest node ({e},{i}) cannot post: {err:?}")))
    }

    /// Applies an honest post. The board may ignore (Err) an honest post only when the
    /// post is redundant in the model too: a PREVOTE after the generation is locked or
    /// released, or a READY or resharing complaint after HANDOVER. Such cases are
    /// counted; the projection comparison then checks that ignoring it changed nothing.
    fn apply_honest(&mut self, height: u64, event: Event, what: &str) -> StepResult {
        let g = match &event {
            Event::Prevote { generation, .. } => Some(*generation),
            _ => None,
        };
        let in_flight = g.is_some_and(|g| {
            self.board
                .request(&self.rid)
                .is_ok_and(|r| r.generations.get(&g).is_some_and(|v| v.in_flight()))
        });
        let handed_over = self.handed_over();
        match self.board.apply(height, event) {
            Ok(()) => Ok(()),
            Err(err) => {
                let benign = match (what, &err) {
                    ("P_PREVOTE", BoardError::Attempt) if in_flight => {
                        Some("PREVOTE after lock or release")
                    }
                    ("READY", BoardError::Handover) if handed_over => Some("READY after HANDOVER"),
                    ("RS_COMPLAINT", BoardError::Handover) if handed_over => {
                        Some("resharing complaint after HANDOVER")
                    }
                    ("RS_DEAL", BoardError::Handover)
                        if handed_over && self.old_model_deal_after_handover =>
                    {
                        Some(LABEL_DEAL_AFTER_HANDOVER)
                    }
                    _ => None,
                };
                match benign {
                    Some(label) => {
                        *self.ignored.entry(label).or_default() += 1;
                        Ok(())
                    }
                    None => mismatch(format!("board rejected honest {what}: {err:?}")),
                }
            }
        }
    }

    fn spec(&self, p: &Post) -> RequestSpec {
        let c = self.committee();
        RequestSpec {
            rid: self.rid,
            mid: enc(p.mid),
            pin: self.pin,
            epoch: self.board.epoch,
            mode: if p.mode == "OpenMode" {
                Mode::Open
            } else {
                Mode::Sealed
            },
            threshold: if p.t_profile == "ProfileT1" {
                c.f + 1
            } else {
                c.n - c.f
            },
            not_before: p.nb as u64,
            expires: p.exp as u64,
            generations: 2,
            variants: 2,
            rotation: match p.rot_policy.as_str() {
                "RotFinish" => Rotation::Finish,
                "RotReshare" => Rotation::Reshare,
                _ => Rotation::Void,
            },
        }
    }

    fn mode(&self) -> Option<Mode> {
        self.board.request(&self.rid).ok().map(|r| r.spec.mode)
    }

    /// Order the model's set Q as the Rust board lists its dealers, as an honest
    /// node computing Q from the board would.
    fn ordered_dealers(&self, set: &BTreeSet<Int>) -> Vec<NodeId> {
        let mut out = Vec::new();
        if let Some(fr) = self
            .board
            .request(&self.rid)
            .ok()
            .and_then(|r| r.freeze.as_ref())
        {
            for d in &fr.dealers {
                if set.contains(&Int::from(*d)) {
                    out.push(*d);
                }
            }
        }
        for d in set {
            if !out.contains(&(*d as u16)) {
                out.push(*d as u16);
            }
        }
        out
    }

    fn post(&mut self, before: &State, after: &State, p: &Post) -> StepResult {
        let honest = !Self::is_byz(after, p.epoch, p.node) && p.node >= 1;
        let height = p.bheight as u64;
        let rid = self.rid;
        let g = p.g.clamp(0, 1000) as u16;
        match p.kind.as_str() {
            "P_MSG" => {
                let spec = self.spec(p);
                if self
                    .board
                    .apply(height, Event::Bind { spec, valid: true })
                    .is_ok()
                {
                    self.bound = Some(p.clone());
                }
                Ok(())
            }
            "P_ACK" | "P_COMPLAINT" => {
                let ev = if p.kind == "P_ACK" {
                    Event::Ack {
                        rid,
                        epoch: p.epoch as u64,
                        node: p.node as u16,
                        mid: enc(p.mid),
                    }
                } else {
                    let valid = self
                        .bound
                        .as_ref()
                        .is_some_and(|m| m.mid == p.mid && m.bad_nodes.contains(&p.node));
                    Event::Complaint {
                        rid,
                        epoch: p.epoch as u64,
                        node: p.node as u16,
                        mid: enc(p.mid),
                        valid,
                    }
                };
                if honest {
                    self.gate(p.epoch, p.node)?;
                    self.apply_honest(height, ev, &p.kind)?;
                    if p.kind == "P_COMPLAINT" {
                        self.valid_complaint = true;
                    }
                } else if self.board.apply(height, ev.clone()).is_ok()
                    && matches!(ev, Event::Complaint { valid: true, .. })
                {
                    self.valid_complaint = true;
                }
                Ok(())
            }
            "P_OBS" | "P_NACK" => {
                let attempt = self.ra(p.epoch, g, p.a);
                let ev = if p.kind == "P_OBS" {
                    Event::Obs {
                        rid,
                        epoch: p.epoch as u64,
                        node: p.node as u16,
                        generation: g,
                        attempt,
                        target_height: p.h.max(0) as u64,
                    }
                } else {
                    Event::Nack {
                        rid,
                        epoch: p.epoch as u64,
                        node: p.node as u16,
                        generation: g,
                        attempt,
                    }
                };
                if honest {
                    self.gate(p.epoch, p.node)?;
                    self.apply_honest(height, ev, &p.kind)
                } else {
                    let _ = self.board.apply(height, ev);
                    Ok(())
                }
            }
            "P_PREVOTE" | "P_PARTIAL" | "P_SEALED_PARTIAL" => self.signing_post(after, p, honest),
            "P_ROTATE" => {
                let committee = self.committee();
                self.board
                    .apply(
                        height,
                        Event::Rotate {
                            new_epoch: 2,
                            committee,
                        },
                    )
                    .or_else(|err| mismatch(format!("ROTATE rejected: {err:?}")))
            }
            "P_RS_DEAL" => {
                let expected: BTreeSet<Int> = match self
                    .board
                    .request(&rid)
                    .ok()
                    .and_then(|r| r.freeze.as_ref())
                {
                    Some(fr) => GENS
                        .iter()
                        .filter(|x| !fr.in_flight.contains(x))
                        .map(|x| Int::from(*x))
                        .collect(),
                    None => GENS.iter().map(|x| Int::from(*x)).collect(),
                };
                let ev = Event::Dealer {
                    rid,
                    epoch: p.epoch as u64,
                    dealer: p.node as u16,
                    valid: p.gens == expected,
                };
                if honest {
                    self.gate(p.epoch, p.node)?;
                    self.apply_honest(height, ev, "RS_DEAL")
                } else {
                    let _ = self.board.apply(height, ev);
                    Ok(())
                }
            }
            "P_RS_COMPLAINT" => {
                // Ground truth: the target dealer's first deal after ROTATE gave this node a bad sub-share.
                let r_idx = before.board.iter().position(|x| x.kind == "P_ROTATE");
                let valid = r_idx.is_some_and(|ri| {
                    before.board[ri + 1..]
                        .iter()
                        .find(|x| {
                            x.kind == "P_RS_DEAL" && x.epoch == 1 && x.node == p.target_dealer
                        })
                        .is_some_and(|d| d.bad_nodes.contains(&p.node))
                });
                let ev = Event::DealerComplaint {
                    rid,
                    epoch: 1,
                    dealer: p.target_dealer as u16,
                    valid,
                };
                if honest {
                    self.gate(p.epoch, p.node)?;
                    self.apply_honest(height, ev, "RS_COMPLAINT")
                } else {
                    let _ = self.board.apply(height, ev);
                    Ok(())
                }
            }
            "P_READY" => {
                let was = self.handed_over();
                let ev = Event::Ready {
                    rid,
                    epoch: p.epoch as u64,
                    node: p.node as u16,
                    dealers: self.ordered_dealers(&p.dealers),
                };
                if honest {
                    self.gate(p.epoch, p.node)?;
                    self.apply_honest(height, ev, "READY")?;
                } else {
                    let _ = self.board.apply(height, ev);
                }
                if !was && self.handed_over() {
                    let r = self.board.request(&rid).unwrap();
                    for (g, v) in &r.generations {
                        if v.transferred {
                            let last = v.attempts.keys().next_back().copied().unwrap_or(0);
                            self.offset.insert(*g, last);
                        }
                    }
                }
                Ok(())
            }
            "P_FINAL" | "P_VOID" => {
                let unregistered = self.board.committee(p.epoch as u64).is_err();
                let tip = if honest {
                    let ns = if p.epoch == 1 {
                        &after.nodes1
                    } else {
                        &after.nodes2
                    };
                    ns[&p.node].chain_tip
                } else {
                    after.chain.len() as Int
                };
                let ev = if p.kind == "P_FINAL" {
                    let valid = after
                        .chain
                        .iter()
                        .any(|b| b.height <= tip && b.tx_kind == "TxReq" && b.tx_val == p.dg);
                    if honest {
                        self.nodes[&(p.epoch as u64, p.node as u16)]
                            .final_post(&self.board, rid, enc(p.dg), valid)
                            .map_err(|e| (None, format!("honest FINAL evidence gate: {e:?}")))?
                    } else {
                        Event::Final {
                            rid,
                            epoch: p.epoch as u64,
                            node: p.node as u16,
                            txid: enc(p.dg),
                            valid,
                        }
                    }
                } else {
                    let valid = after
                        .chain
                        .iter()
                        .any(|b| b.height <= tip && b.tx_kind == "TxForeign");
                    if honest {
                        self.nodes[&(p.epoch as u64, p.node as u16)]
                            .foreign_spend(&self.board, rid, enc(FOREIGN_TX), valid)
                            .map_err(|e| (None, format!("honest VOID evidence gate: {e:?}")))?
                    } else {
                        Event::ForeignSpend {
                            rid,
                            epoch: p.epoch as u64,
                            node: p.node as u16,
                            txid: enc(FOREIGN_TX),
                            valid,
                        }
                    }
                };
                if honest {
                    self.gate(p.epoch, p.node)?;
                }
                match self.board.apply(height, ev) {
                    Ok(()) => Ok(()),
                    Err(BoardError::Epoch)
                        if unregistered
                            && self.bound.is_some()
                            && [1, 2].contains(&p.epoch)
                            && (1..=Int::from(self.inst.n)).contains(&p.node)
                            && (p.kind == "P_VOID" || p.dg > 0) =>
                    {
                        self.unregistered_posts.insert(before.board.len());
                        Ok(())
                    }
                    Err(err) if honest => {
                        mismatch(format!("board rejected honest {}: {err:?}", p.kind))
                    }
                    Err(_) => Ok(()),
                }
            }
            other => mismatch(format!("unknown post kind {other}")),
        }
    }

    fn handed_over(&self) -> bool {
        self.board
            .request(&self.rid)
            .ok()
            .and_then(|r| r.freeze.as_ref())
            .is_some_and(|f| f.handed_over)
    }

    /// Require the first model FINAL/VOID quorum to depend on a refused post.
    /// A mere earlier unregistered post cannot excuse another mismatch.
    fn m1_causes_tombstone(&self, s: &State, detail: &str) -> bool {
        if !(detail.starts_with("status:") || detail.starts_with("model erased ("))
            || self.unregistered_posts.is_empty()
            || !self
                .board
                .request(&self.rid)
                .is_ok_and(|r| matches!(r.tombstone, None | Some(Tombstone::Expired)))
        {
            return false;
        }
        let Some(start) = s.board.iter().position(|p| Some(p) == self.bound.as_ref()) else {
            return false;
        };
        let mut all: BTreeMap<(&str, Int, Int), BTreeSet<Int>> = BTreeMap::new();
        let mut registered: BTreeMap<(&str, Int, Int), BTreeSet<Int>> = BTreeMap::new();
        let mut first_status = None;
        for (pos, p) in s.board.iter().enumerate().skip(start + 1) {
            if ![1, 2].contains(&p.epoch)
                || !(1..=Int::from(self.inst.n)).contains(&p.node)
                || !(p.kind == "P_VOID" || (p.kind == "P_FINAL" && p.dg > 0))
            {
                continue;
            }
            let key = (
                p.kind.as_str(),
                p.epoch,
                if p.kind == "P_FINAL" { p.dg } else { 0 },
            );
            all.entry(key).or_default().insert(p.node);
            if !self.unregistered_posts.contains(&pos) {
                registered.entry(key).or_default().insert(p.node);
            }
            // A later authenticated quorum must end the Rust request too.
            if registered.get(&key).map_or(0, BTreeSet::len) > usize::from(self.inst.f) {
                return false;
            }
            if all[&key].len() > usize::from(self.inst.f) {
                let status = if p.kind == "P_FINAL" {
                    "StFinal"
                } else {
                    "StVoid"
                };
                first_status.get_or_insert(status);
            }
        }
        first_status.is_some_and(|status| {
            !detail.starts_with("status:")
                || detail.starts_with(&format!("status: model {status} "))
        })
    }

    fn signing_post(&mut self, after: &State, p: &Post, honest: bool) -> StepResult {
        let rid = self.rid;
        let height = p.bheight as u64;
        let e = p.epoch;
        let g = p.g.clamp(0, 1000) as u16;
        let sealed = p.kind == "P_SEALED_PARTIAL";
        // Candidate of the post. A Byzantine sealed PARTIAL in the model carries
        // only (g, variant); it is a share for the variant at the current anchor.
        let (candidate, variant, valid) = if sealed && !honest {
            let anchor = self
                .board
                .request(&rid)
                .ok()
                .and_then(|r| r.generations.get(&g))
                .and_then(|v| v.anchor().map(|(a, an)| (a, an.clone())));
            match anchor {
                None => (
                    Candidate {
                        attempt: 0,
                        block_hash: enc(0),
                        digest: enc(SEALED_DIGEST_BASE + p.variant),
                    },
                    Some(p.variant as u16),
                    false,
                ),
                Some((a, an)) => {
                    let (prev_h, prev_v) = match an.previous.last() {
                        None => (0, 0),
                        Some(pr) => {
                            let ph = pr.height as Int;
                            (ph, select_variant(&after.chain, ph, 1, 0, 0))
                        }
                    };
                    let sel = select_variant(&after.chain, an.height as Int, p.g, prev_h, prev_v);
                    (
                        Candidate {
                            attempt: a,
                            block_hash: enc(an.height as Int),
                            digest: enc(SEALED_DIGEST_BASE + p.variant),
                        },
                        Some(p.variant as u16),
                        sel == p.variant,
                    )
                }
            }
        } else if sealed {
            (
                Candidate {
                    attempt: self.ra(e, g, p.a),
                    block_hash: enc(p.h),
                    digest: enc(SEALED_DIGEST_BASE + p.variant),
                },
                Some(p.variant as u16),
                true,
            )
        } else {
            (
                Candidate {
                    attempt: self.ra(e, g, p.a),
                    block_hash: enc(p.h),
                    digest: enc(p.dg),
                },
                None,
                true,
            )
        };
        if !honest {
            let ev = if p.kind == "P_PREVOTE" {
                Event::Prevote {
                    rid,
                    epoch: e as u64,
                    node: p.node as u16,
                    generation: g,
                    candidate,
                }
            } else {
                Event::Partial {
                    rid,
                    epoch: e as u64,
                    node: p.node as u16,
                    generation: g,
                    candidate,
                    variant,
                    valid,
                }
            };
            let _ = self.board.apply(height, ev);
            return Ok(());
        }
        let build = LocalBuild {
            rid,
            epoch: e as u64,
            generation: g,
            candidate: candidate.clone(),
            pin: self.pin,
            txid: candidate.digest,
            variant,
        };
        let key = (e as u64, p.node as u16);
        let lock_before = self
            .board
            .request(&rid)
            .ok()
            .and_then(|r| r.generations.get(&g))
            .and_then(|v| v.lock.clone());
        let node = self.nodes.get_mut(&key).unwrap();
        let result = if p.kind == "P_PREVOTE" {
            node.prevote(&self.board, &build)
        } else {
            node.partial(&self.board, &build)
        };
        let event = match result {
            Ok(ev) => ev,
            Err(err) => {
                return Err((
                    Some(err.clone()),
                    format!(
                        "signer refused honest {} of ({e},{}) g={g}: {err:?}",
                        p.kind, p.node
                    ),
                ))
            }
        };
        if p.kind == "P_PARTIAL" {
            // LockBeforeShare on the Rust side: the board already holds a lock for this candidate.
            if lock_before.as_ref().map(|l| &l.candidate) != Some(&candidate) {
                return mismatch(format!(
                    "Rust authorized open PARTIAL g={g} without a lock on the board"
                ));
            }
        }
        self.apply_honest(height, event, &p.kind)?;
        if p.kind != "P_PREVOTE" {
            let val = if sealed { p.variant } else { p.dg };
            self.honest_partials
                .insert((e as u64, p.node as u16, g), val);
            self.reached.insert(if sealed {
                "honest sealed partial"
            } else {
                "honest open partial"
            });
            if g == 2 {
                self.reached.insert("generation-2 partial");
            }
            if e == 2 {
                self.reached.insert("epoch-2 partial");
            }
        }
        Ok(())
    }

    fn chain_block(&mut self, b: &Block) -> StepResult {
        match b.tx_kind.as_str() {
            "TxReq" => {
                let g = b.tx_gen as u16;
                let r = match self.board.request(&self.rid) {
                    Ok(r) => r,
                    Err(_) => return mismatch("spend of an unbound request".into()),
                };
                let gen = &r.generations[&g];
                let authorized = match r.spec.mode {
                    Mode::Open => gen
                        .lock
                        .as_ref()
                        .is_some_and(|l| dec(&l.candidate.digest) == b.tx_val),
                    Mode::Sealed => gen
                        .release
                        .as_ref()
                        .is_some_and(|x| Int::from(x.variant) == b.tx_val),
                };
                let honest_share = self
                    .honest_partials
                    .iter()
                    .any(|((_, _, pg), v)| *pg == g && *v == b.tx_val);
                if !authorized || !honest_share {
                    return mismatch(format!(
                        "model executed g={g} value {} that the Rust board did not lock/release with an honest partial",
                        b.tx_val
                    ));
                }
                if !self.pins.execute(self.pin, enc(b.tx_val)) {
                    return mismatch("pin already spent in the Rust pin ledger".into());
                }
                self.executions += 1;
                self.reached.insert("spend executed");
                if g == 2 {
                    self.reached.insert("generation-2 spend");
                }
                Ok(())
            }
            "TxForeign" => {
                if !self.pins.execute(self.pin, enc(FOREIGN_TX)) {
                    return mismatch("foreign spend of a spent pin".into());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn node_change(&mut self, e: Int, i: Int, old: &ModelNode, new: &ModelNode) -> StepResult {
        if old.ledger == new.ledger && old.builder_impl == new.builder_impl {
            return Ok(()); // tip sync: chain adapter only
        }
        let key = (e as u64, i as u16);
        let wiped = new.ledger.values().all(|d| *d == 0) && old.ledger.values().any(|d| *d != 0);
        let durable = if wiped {
            let had_partial = self.honest_partials.contains_key(&(key.0, key.1, 1))
                || self.honest_partials.contains_key(&(key.0, key.1, 2));
            if had_partial {
                self.reached.insert("rollback after own partial");
            }
            self.reached.insert("disk rollback");
            PersistedNodeState::default()
        } else {
            self.reached.insert("restart keeping ledger");
            self.nodes[&key].snapshot()
        };
        let node = NodeState::restart(key.1, key.0, durable, Some(self.board.position));
        self.nodes.insert(key, node);
        Ok(())
    }

    /// Every honest node processes the board (rule 4 replay and section 3.10 erasure).
    fn replay_all(&mut self, s: &State) -> StepResult {
        for ((e, i), node) in self.nodes.iter_mut() {
            if Self::is_byz(s, *e as Int, Int::from(*i)) {
                continue;
            }
            let rec = self.erased.entry((*e, *i)).or_default();
            let rid = self.rid;
            node.replay(&self.board, |r, g| {
                assert_eq!(r, rid);
                match g {
                    None => rec.extend(GENS),
                    Some(g) => {
                        rec.insert(g);
                    }
                }
                Ok(())
            })
            .or_else(|err| mismatch(format!("replay failed for ({e},{i}): {err:?}")))?;
        }
        Ok(())
    }

    fn step(&mut self, before: &State, after: &State) -> StepResult {
        if after.board.len() == before.board.len() + 1 {
            let p = after.board.last().unwrap().clone();
            self.post(before, after, &p)?;
        } else if after.board.len() != before.board.len() {
            return mismatch("board changed by more than one post".into());
        }
        if after.chain.len() == before.chain.len() + 1 {
            self.chain_block(after.chain.last().unwrap())?;
        }
        if after.board_height == before.board_height + 1 {
            self.board
                .apply(after.board_height as u64, Event::Tick)
                .or_else(|err| mismatch(format!("tick rejected: {err:?}")))?;
        }
        if after.board.len() == before.board.len() {
            for (e, olds, news) in [
                (1, &before.nodes1, &after.nodes1),
                (2, &before.nodes2, &after.nodes2),
            ] {
                for (i, new) in news {
                    if Self::is_byz(after, e, *i) {
                        continue;
                    }
                    self.node_change(e, *i, &olds[i], new)?;
                }
            }
        }
        self.replay_all(after)
    }

    /// Replays the initial board of an armed init post by post.
    fn initial(&mut self, s0: &State) -> StepResult {
        let mut prefix = State {
            board: Vec::new(),
            ..s0.clone()
        };
        for p in &s0.board {
            let mut next = prefix.clone();
            next.board.push(p.clone());
            self.post(&prefix, &next, p)?;
            prefix = next;
        }
        self.replay_all(s0)
    }

    fn compare(
        &self,
        s: &State,
        proj: Option<&Proj>,
        stats: &mut Stats,
        artifact: &mut Option<String>,
    ) -> Result<(), String> {
        let rid = self.rid;
        let r = self.board.request(&rid).ok();
        let mode = self.mode();
        // Node records (every state).
        for (e, ns) in [(1u64, &s.nodes1), (2u64, &s.nodes2)] {
            for (i, mn) in ns {
                if Self::is_byz(s, e as Int, *i) {
                    continue;
                }
                let node = &self.nodes[&(e, *i as u16)];
                for g in GENS {
                    let model_dg = mn.ledger.get(&Int::from(g)).copied().unwrap_or(0);
                    let rust_dg = node.slot_digest(rid, g).map(|d| dec(&d)).unwrap_or(0);
                    if mode == Some(Mode::Open) && model_dg != rust_dg {
                        return Err(format!(
                            "ledger ({e},{i}) g={g}: model {model_dg} rust {rust_dg}"
                        ));
                    }
                    let m_abs = mn.abstained.contains(&Int::from(g));
                    // The rule-4 mutant skips the replay abstention that Rust always makes;
                    // the replay continues to the honest post that Rust then refuses.
                    let mutant_gap = self.inst.broken == Broken::Rule4 && !m_abs;
                    if m_abs != node.abstains(rid, g) && !mutant_gap {
                        return Err(format!(
                            "abstain ({e},{i}) g={g}: model {m_abs} rust {}",
                            !m_abs
                        ));
                    }
                    let r_er = self
                        .erased
                        .get(&(e, *i as u16))
                        .is_some_and(|x| x.contains(&g));
                    let m_er = mn.erased.contains(&Int::from(g));
                    let own_partial = self.honest_partials.contains_key(&(e, *i as u16, g));
                    if m_er && !r_er && !own_partial {
                        let detail = format!("model erased ({e},{i}) g={g}, Rust kept the share");
                        if self.m1_causes_tombstone(s, &detail) {
                            artifact.get_or_insert(detail);
                        } else {
                            return Err(detail);
                        }
                    }
                    if r_er && !m_er {
                        let why = match r.and_then(|r| r.tombstone.as_ref()) {
                            Some(Tombstone::Void) => "VOID tombstone",
                            Some(Tombstone::Final(_)) => "FINAL tombstone",
                            Some(Tombstone::Expired) => "EXPIRED",
                            None => "other",
                        };
                        *stats
                            .erase_beyond_model
                            .entry(format!("epoch {e}, {why}"))
                            .or_default() += 1;
                    }
                }
            }
        }
        let Some(proj) = proj else { return Ok(()) };
        stats.projections += 1;
        if proj.bound != r.is_some() {
            return Err(format!("bound: model {} rust {}", proj.bound, r.is_some()));
        }
        let Some(r) = r else { return Ok(()) };
        let status = match &r.tombstone {
            Some(Tombstone::Final(_)) => "StFinal",
            Some(Tombstone::Void) => "StVoid",
            Some(Tombstone::Expired) => "StExpired",
            None if r.armed => "StArmed",
            None => "StBound",
        };
        if proj.status != status {
            let detail = format!("status: model {} rust {status}", proj.status);
            if self.m1_causes_tombstone(s, &detail) {
                artifact.get_or_insert(detail);
            } else {
                return Err(detail);
            }
        }
        if proj.armed != r.armed && r.tombstone.is_none() {
            return Err(format!("armed: model {} rust {}", proj.armed, r.armed));
        }
        if proj.rotated != (self.board.epoch == 2) {
            return Err(format!(
                "rotated: model {} rust {}",
                proj.rotated,
                self.board.epoch == 2
            ));
        }
        let freeze = r.freeze.as_ref();
        if r.spec.rotation == Rotation::Reshare && r.tombstone.is_none() {
            let ho = freeze.is_some_and(|f| f.handed_over);
            if proj.handover != ho {
                return Err(format!("handover: model {} rust {ho}", proj.handover));
            }
            if let Some(f) = freeze.filter(|f| !f.handed_over) {
                let q: BTreeSet<Int> = f
                    .dealers
                    .iter()
                    .filter(|d| !f.complained.contains(d))
                    .take(usize::from(r.threshold))
                    .map(|d| Int::from(*d))
                    .collect();
                let q = if q.len() == usize::from(r.threshold) {
                    q
                } else {
                    BTreeSet::new()
                };
                if r.armed && proj.armed && q != proj.q {
                    return Err(format!("reshare Q: model {:?} rust {q:?}", proj.q));
                }
            }
        }
        if r.tombstone.is_some() {
            return Ok(());
        }
        for g in GENS {
            let gp = &proj.gens[&Int::from(g)];
            let gen = &r.generations[&g];
            if gp.lock_or_rel != gen.in_flight() {
                return Err(format!(
                    "g={g} lock/release: model {} rust {}",
                    gp.lock_or_rel,
                    gen.in_flight()
                ));
            }
            if let Some(l) = &gen.lock {
                if dec(&l.candidate.digest) != gp.lock_dg {
                    return Err(format!(
                        "g={g} lock digest: model {} rust {}",
                        gp.lock_dg,
                        dec(&l.candidate.digest)
                    ));
                }
                if l.candidate.attempt != self.ra(l.epoch as Int, g, gp.lock_a) {
                    return Err(format!(
                        "g={g} lock attempt: model {} rust {}",
                        gp.lock_a, l.candidate.attempt
                    ));
                }
            }
            let rf = freeze.is_some_and(|f| f.in_flight.contains(&g));
            if gp.in_flight != rf {
                return Err(format!(
                    "g={g} in flight at ROTATE: model {} rust {rf}",
                    gp.in_flight
                ));
            }
            let frozen = freeze.is_some_and(|f| !f.handed_over && !f.in_flight.contains(&g));
            let rust_active = if !r.armed || frozen {
                0
            } else {
                gen.epoch as Int
            };
            if gp.active != rust_active {
                return Err(format!(
                    "g={g} active epoch: model {} rust {rust_active}",
                    gp.active
                ));
            }
            for ((e, a), ap) in &gp.att {
                let rust_epoch_attempts = if *e == 1 {
                    !gen.transferred
                } else {
                    gen.transferred
                };
                if !rust_epoch_attempts {
                    continue;
                }
                let ra = self.ra(*e, g, *a);
                let att = gen.attempts.get(&ra);
                let done = att.is_some_and(|x| x.anchor.is_some());
                if done != ap.done {
                    return Err(format!(
                        "g={g} e={e} a={a} anchored: model {} rust {done}",
                        ap.done
                    ));
                }
                if let Some(x) = att.filter(|_| done) {
                    let h = x.anchor.as_ref().unwrap().height as Int;
                    if h != ap.h || x.failed != ap.failed {
                        return Err(format!(
                            "g={g} e={e} a={a} anchor/failed: model ({}, {}) rust ({h}, {})",
                            ap.h, ap.failed, x.failed
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// The five model invariants evaluated on the Rust state, plus negative probes
    /// of local rules 1 to 4 on every honest node.
    fn invariants(&self, s: &State, stats: &mut Stats) -> Result<(), String> {
        let rid = self.rid;
        // NoNonceReuse: one digest (open) or variant (sealed) per generation over all honest partials.
        for g in GENS {
            let vals: BTreeSet<Int> = self
                .honest_partials
                .iter()
                .filter(|((_, _, pg), _)| *pg == g)
                .map(|(_, v)| *v)
                .collect();
            if vals.len() > 1 {
                return Err(format!("Rust NoNonceReuse violated: g={g} values {vals:?}"));
            }
        }
        // AtMostOneExecution.
        if self.executions > 1 {
            return Err("Rust AtMostOneExecution violated".into());
        }
        let Ok(r) = self.board.request(&rid) else {
            return Ok(());
        };
        // NoTransientTombstone: every tombstone has its cause.
        match &r.tombstone {
            Some(Tombstone::Final(txid)) => {
                if !s
                    .chain
                    .iter()
                    .any(|b| b.tx_kind == "TxReq" && b.tx_val == dec(txid))
                {
                    return Err("Rust FINAL without the transaction on chain".into());
                }
            }
            Some(Tombstone::Void) => {
                let rot_void = r.spec.rotation == Rotation::Void && self.board.epoch == 2;
                let foreign = s.chain.iter().any(|b| b.tx_kind == "TxForeign");
                if !(self.valid_complaint || rot_void || foreign) {
                    return Err("Rust VOID without a cause".into());
                }
            }
            Some(Tombstone::Expired) if self.board.height <= r.spec.expires => {
                return Err("Rust EXPIRED before exp".into());
            }
            Some(Tombstone::Expired) | None => {}
        }
        // FreezeSafety: a transferred generation has no honest old-committee partial.
        for (g, gen) in &r.generations {
            if gen.transferred
                && self
                    .honest_partials
                    .keys()
                    .any(|(e, _, pg)| *e == 1 && pg == g)
            {
                return Err(format!("Rust FreezeSafety violated for g={g}"));
            }
        }
        // Probes: a node whose ledger holds digest d never signs another digest
        // (rules 1-3), and an abstaining node never signs (rule 4).
        for ((e, i), node) in &self.nodes {
            if Self::is_byz(s, *e as Int, Int::from(*i)) {
                continue;
            }
            for g in GENS {
                let Some(gen) = r.generations.get(&g) else {
                    continue;
                };
                let Some(lock) = &gen.lock else { continue };
                let slot = node.slot_digest(rid, g);
                let other = slot.is_some_and(|d| d != lock.candidate.digest);
                if !(other || node.abstains(rid, g)) {
                    continue;
                }
                stats.probes += 1;
                let build = LocalBuild {
                    rid,
                    epoch: *e,
                    generation: g,
                    candidate: lock.candidate.clone(),
                    pin: self.pin,
                    txid: lock.candidate.digest,
                    variant: None,
                };
                if node.clone().partial(&self.board, &build).is_ok() {
                    return Err(format!(
                        "Rust would let ({e},{i}) sign locked digest of g={g} (slot {:?}, abstain {})",
                        slot.map(|d| dec(&d)),
                        node.abstains(rid, g)
                    ));
                }
            }
        }
        Ok(())
    }

    fn note_status(&mut self) {
        if let Ok(r) = self.board.request(&self.rid) {
            if r.armed {
                self.reached.insert("armed");
            }
            if r.generations.values().any(|g| g.lock.is_some()) {
                self.reached.insert("lock certificate");
            }
            if r.generations.values().any(|g| g.release.is_some()) {
                self.reached.insert("sealed release");
            }
            let own = || r.generations.values().filter(|g| !g.transferred);
            if own().any(|g| g.attempts.values().any(|a| a.failed)) {
                self.reached.insert("failed attempt (NACK)");
            }
            if own().any(|g| {
                g.attempts
                    .iter()
                    .any(|(n, a)| *n >= 2 && a.anchor.is_some())
            }) {
                self.reached.insert("attempt-2 anchor");
            }
            if r.freeze.as_ref().is_some_and(|f| f.handed_over) {
                self.reached.insert("handover");
            }
            if r.freeze.as_ref().is_some_and(|f| !f.in_flight.is_empty()) {
                self.reached.insert("freeze with in-flight generation");
            }
            match r.tombstone {
                Some(Tombstone::Final(_)) => self.reached.insert("FINAL"),
                Some(Tombstone::Void) => self.reached.insert("VOID"),
                Some(Tombstone::Expired) => self.reached.insert("EXPIRED"),
                None => false,
            };
        }
    }
}

fn run_trace(inst: Instance, trace: &Trace, stats: &mut Stats) -> Outcome {
    let mut rp = Replay::new(inst);
    let outcome = replay_trace(&mut rp, trace, stats);
    if !rp.unregistered_posts.is_empty() {
        stats.m1_traces += 1;
    }
    for (k, v) in &rp.ignored {
        *stats.ignored.entry(k).or_default() += v;
    }
    outcome
}

fn replay_trace(rp: &mut Replay, trace: &Trace, stats: &mut Stats) -> Outcome {
    let states = &trace.states;
    let classify = |step: usize, err: (Option<BoardError>, String)| match err {
        (Some(error), _) => Outcome::Refused {
            step,
            action: states[step].action.clone(),
            error,
        },
        (None, detail) => Outcome::Mismatch {
            step,
            action: states[step].action.clone(),
            detail,
        },
    };
    if let Err(e) = rp.initial(&states[0]) {
        return classify(0, e);
    }
    let check = |rp: &Replay,
                 k: usize,
                 stats: &mut Stats,
                 artifact: &mut Option<String>|
     -> Result<(), String> {
        let proj = states.get(k + 1).and_then(|s| s.proj.as_ref());
        rp.compare(&states[k], proj, stats, artifact)?;
        rp.invariants(&states[k], stats)
    };
    let mut initial_artifact = None;
    if let Err(d) = check(rp, 0, stats, &mut initial_artifact) {
        return classify(0, (None, d));
    }
    let mut first_artifact = initial_artifact.map(|detail| (0, detail));
    for k in 1..states.len() {
        *stats.actions.entry(states[k].action.clone()).or_default() += 1;
        stats.steps += 1;
        rp.step_no = k;
        if let Err(e) = rp.step(&states[k - 1], &states[k]) {
            return classify(k, e);
        }
        rp.note_status();
        let mut artifact = None;
        if let Err(d) = check(rp, k, stats, &mut artifact) {
            return classify(k, (None, d));
        }
        if let Some(detail) = artifact {
            first_artifact.get_or_insert((k, detail));
        }
    }
    for r in &rp.reached {
        *stats.reached.entry(r).or_default() += 1;
    }
    if let Some((step, detail)) = first_artifact {
        Outcome::ModelArtifact { step, detail }
    } else {
        Outcome::Conformed
    }
}

/// Model NoNonceReuse on a trace state: honest open digests or sealed variants per g.
fn model_nonce_reuse(s: &State) -> bool {
    GENS.iter().any(|g| {
        let mut open = BTreeSet::new();
        let mut sealed = BTreeSet::new();
        for p in &s.board {
            if p.g != Int::from(*g) || Replay::is_byz(s, p.epoch, p.node) {
                continue;
            }
            if p.kind == "P_PARTIAL" {
                open.insert(p.dg);
            } else if p.kind == "P_SEALED_PARTIAL" {
                sealed.insert(p.variant);
            }
        }
        open.len() > 1 || sealed.len() > 1
    })
}

fn corpus_root() -> PathBuf {
    std::env::var_os("QUINT_TRACES")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../formal/quint/conformance/traces")
        })
}

fn trace_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.to_string_lossy().ends_with(".itf.json"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

#[test]
fn quint_traces_conform() {
    let root = corpus_root();
    let mut failures = Vec::new();
    let mut total = 0;
    let mut n4_reached: BTreeSet<&'static str> = BTreeSet::new();
    for inst in INSTANCES {
        let files = trace_files(&root.join(inst.name));
        assert!(
            !files.is_empty(),
            "no traces for instance {} under {}",
            inst.name,
            root.display()
        );
        let mut stats = Stats::default();
        let mut refused: BTreeMap<String, usize> = BTreeMap::new();
        let mut artifacts = 0;
        for file in &files {
            let trace = itf::load(file);
            stats.traces += 1;
            let outcome = run_trace(inst, &trace, &mut stats);
            let name = file.file_name().unwrap().to_string_lossy().to_string();
            match (inst.broken, outcome) {
                (Broken::None, Outcome::Conformed) => stats.conformed += 1,
                (Broken::None, Outcome::ModelArtifact { step, detail }) => {
                    artifacts += 1;
                    println!("  {}/{name} step {step}: {M2}: {detail}", inst.name);
                }
                (Broken::None, o) => failures.push(format!("{}/{name}: {o:?}", inst.name)),
                (
                    _,
                    Outcome::Refused {
                        step,
                        action,
                        error,
                    },
                ) => {
                    let expected = match inst.broken {
                        Broken::Prevote => {
                            matches!(error, BoardError::AlreadyVoted | BoardError::Digest)
                        }
                        _ => matches!(error, BoardError::ReplayAbstention),
                    };
                    let violation = trace.states.iter().position(model_nonce_reuse);
                    if !expected || violation.is_none_or(|v| step > v) {
                        failures.push(format!(
                            "{}/{name}: refusal {error:?} at step {step} ({action}) does not precede the model violation {violation:?}",
                            inst.name
                        ));
                    }
                    *refused.entry(format!("{error:?} on {action}")).or_default() += 1;
                }
                (_, o @ Outcome::Mismatch { .. }) => {
                    failures.push(format!("{}/{name}: {o:?}", inst.name))
                }
                (_, Outcome::Conformed) => {
                    // Every mutant trace is a NoNonceReuse counterexample; one that the
                    // model does not violate is a generator failure, not a pass.
                    let why = if trace.states.iter().any(model_nonce_reuse) {
                        "violates NoNonceReuse but Rust accepted every step"
                    } else {
                        "does not violate NoNonceReuse (not a counterexample)"
                    };
                    failures.push(format!("{}/{name}: mutant trace {why}", inst.name));
                }
                (_, o @ Outcome::ModelArtifact { .. }) => {
                    failures.push(format!("{}/{name}: mutant artifact {o:?}", inst.name));
                }
            }
        }
        if inst.name == "n4" {
            n4_reached = stats.reached.keys().copied().collect();
        }
        total += stats.traces;
        println!(
            "instance {}: {} traces, {} steps replayed, {} projections compared, {} negative probes",
            inst.name, stats.traces, stats.steps, stats.projections, stats.probes
        );
        if inst.broken == Broken::None {
            println!("  conformed to the last step: {}", stats.conformed);
        }
        println!("  actions: {:?}", stats.actions);
        println!("  traces reaching: {:?}", stats.reached);
        println!("  gap hits: 0 (no gap tolerances)");
        println!(
            "  {M2}: {} traces recorded, {artifacts} causal divergences",
            stats.m1_traces
        );
        if !refused.is_empty() {
            println!("  mutant steps refused by Rust: {refused:?}");
        }
        if !stats.ignored.is_empty() {
            println!(
                "  honest posts the Rust board ignored as redundant: {:?}",
                stats.ignored
            );
        }
        if !stats.erase_beyond_model.is_empty() {
            println!(
                "  Rust erasures the model does not make (state-steps): {:?}",
                stats.erase_beyond_model
            );
        }
    }
    assert!(total > 0);
    // The scripted trace keeps failed attempts and attempt 2 in the corpus.
    for label in ["failed attempt (NACK)", "attempt-2 anchor"] {
        assert!(n4_reached.contains(label), "no n4 trace reaches {label}");
    }
    assert!(
        failures.is_empty(),
        "{} conformance failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn m1_classifies_only_a_causal_tombstone_divergence() {
    let trace = itf::load(
        &corpus_root().join("n4/cInitArmedOpenReshare_cStepAdversarial_s1022_1.itf.json"),
    );
    let mut rp = Replay::new(INSTANCES[0]);
    let mut stats = Stats::default();
    let outcome = replay_trace(&mut rp, &trace, &mut stats);
    assert!(matches!(outcome, Outcome::ModelArtifact { step: 30, .. }));
    assert_eq!(stats.steps, trace.states.len() - 1);
    // Continuing after the artifact also checks the eventual Rust expiration.
    assert_eq!(
        rp.board.request(&rp.rid).unwrap().tombstone,
        Some(Tombstone::Expired)
    );
    let mut rp = Replay::new(INSTANCES[0]);
    let prefix = Trace {
        states: trace.states[..=30].to_vec(),
    };
    assert!(matches!(
        replay_trace(&mut rp, &prefix, &mut Stats::default()),
        Outcome::ModelArtifact { step: 30, .. }
    ));
    let state = &trace.states[30];
    assert!(rp.m1_causes_tombstone(state, "model erased (2,1) g=1, Rust kept the share"));
    assert!(rp.m1_causes_tombstone(state, "status: model StVoid rust StArmed"));
    assert!(!rp.m1_causes_tombstone(state, "status: model StFinal rust StArmed"));
    assert!(!rp.m1_causes_tombstone(state, "ledger (2,1) g=1: model 42 rust 0"));
    assert!(!rp.m1_causes_tombstone(state, "abstain (2,1) g=1: model true rust false"));
    assert!(!rp.m1_causes_tombstone(&trace.states[6], "status: model StVoid rust StArmed"));
    let mut authenticated = state.clone();
    let mut post = state.board[*rp.unregistered_posts.iter().next().unwrap()].clone();
    post.node = 1;
    authenticated.board.push(post);
    assert!(!rp.m1_causes_tombstone(&authenticated, "status: model StVoid rust StArmed"));

    // An erasure discrepancy at node 1 must not mask a later ledger mismatch.
    let mut corrupted = state.clone();
    corrupted.nodes2.get_mut(&4).unwrap().ledger.insert(1, 42);
    let mut artifact = None;
    let error = rp
        .compare(&corrupted, None, &mut Stats::default(), &mut artifact)
        .unwrap_err();
    assert!(artifact.is_some());
    assert!(error.starts_with("ledger (2,4)"), "{error}");
    rp.unregistered_posts.clear();
    assert!(!rp.m1_causes_tombstone(state, "status: model StVoid rust StArmed"));
}

fn regressions_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/quint-regressions")
}

/// Expectation stored in the trace's `#meta.regression` object.
fn regression_meta(path: &Path) -> serde_json::Value {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["#meta"]["regression"].clone()
}

/// Replays one regression trace with the driver: every step is driven on the Rust
/// code and the state is checked after every step. Returns the replay for extra checks.
fn replay_regression(path: &Path) -> Replay {
    let meta = regression_meta(path);
    let name = path.display();
    let inst = INSTANCES
        .iter()
        .find(|i| meta["instance"].as_str() == Some(i.name))
        .copied()
        .unwrap_or_else(|| panic!("{name}: #meta.regression.instance missing or unknown"));
    let trace = itf::load(path);
    let mut rp = Replay::new(inst);
    for flag in meta["flags"].as_array().into_iter().flatten() {
        match flag.as_str() {
            Some("old_model_deal_after_handover") => rp.old_model_deal_after_handover = true,
            other => panic!("{name}: unknown flag {other:?}"),
        }
    }
    let mut stats = Stats::default();
    let outcome = replay_trace(&mut rp, &trace, &mut stats);
    let expect = &meta["expect"];
    match (expect["outcome"].as_str(), &outcome) {
        (Some("conformed"), Outcome::Conformed) => {
            assert_eq!(
                stats.steps,
                trace.states.len() - 1,
                "{name}: not every step replayed"
            );
            for (label, n) in expect["ignored"].as_object().into_iter().flatten() {
                let got = rp
                    .ignored
                    .iter()
                    .find(|(l, _)| **l == label.as_str())
                    .map_or(0, |(_, c)| *c);
                assert_eq!(Some(got as u64), n.as_u64(), "{name}: ignored {label}");
            }
        }
        (Some("refused"), Outcome::Refused { error, .. }) => {
            assert_eq!(
                Some(format!("{error:?}").as_str()),
                expect["error"].as_str(),
                "{name}"
            );
        }
        _ => panic!("{name}: expected {expect}, got {outcome:?}"),
    }
    rp
}

/// Every trace in tests/quint-regressions/ is a regression test: adding a file adds a case.
#[test]
fn quint_regressions_replay() {
    let files = trace_files(&regressions_dir());
    assert!(
        !files.is_empty(),
        "no regression traces in {}",
        regressions_dir().display()
    );
    for f in &files {
        replay_regression(f);
    }
}

/// Finding M1 (model fix). The pre-fix model let an honest old-committee node post
/// RS_DEAL after HANDOVER, although HANDOVER had erased the shares it would deal
/// (SCHEME section 5). First seen in the n = 4 instance (mbt_n4, cInitArmedOpenReshare,
/// cStepAdversarial, seed 1022). The saved trace is the minimal scenario of the Quint
/// test `dealAfterHandoverTest` run on the pre-fix model: MSG, 3 ACKs, ROTATE,
/// 2 deals, 3 READY (HANDOVER), then node 3 deals. Every step is driven on the Rust
/// code; the board must ignore the late deal (Handover) and leave HANDOVER, Q and
/// every node record unchanged.
#[test]
fn regression_m1_old_node_cannot_deal_after_handover() {
    let path = regressions_dir().join("deal-after-handover.itf.json");
    let rp = replay_regression(&path);
    let trace = itf::load(&path);
    let last = trace.states.last().unwrap().board.last().unwrap();
    assert_eq!((last.kind.as_str(), last.node), ("P_RS_DEAL", 3));
    let r = rp.board.request(&rp.rid).unwrap();
    let f = r.freeze.as_ref().unwrap();
    assert!(f.handed_over);
    assert_eq!(f.dealers, vec![1, 2]);
    assert!(rp.erased[&(1, 3)].contains(&1) && rp.erased[&(1, 3)].contains(&2));

    // Before the model fix this trace did not conform: replayed as an ordinary
    // trace of the current model, the late honest deal is a mismatch at the last step.
    let inst = INSTANCES[0];
    let mut strict = Replay::new(inst);
    let outcome = replay_trace(&mut strict, &trace, &mut Stats::default());
    match outcome {
        Outcome::Mismatch { step, detail, .. } => {
            assert_eq!(step, trace.states.len() - 1);
            assert!(
                detail.contains("RS_DEAL") && detail.contains("Handover"),
                "{detail}"
            );
        }
        o => panic!("pre-fix trace must not conform without the flag, got {o:?}"),
    }
}
