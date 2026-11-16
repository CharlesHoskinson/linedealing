use crate::board::{pending_root, Board, Entry};
use crate::ledger::{Checkpoint, Ledger, Refusal};
use crate::node::*;
use crate::oracle::{Event, Oracle};
use crate::*;
use std::collections::{BTreeMap, BTreeSet};

// SS-120..125 and SS-128..132 each have one mutation gate for the whole rule family.
enum MarkerRule {
    Statement(bool),
    Checkpoint(Purpose),
    LateOpen(Purpose),
    Bind(Purpose),
}
enum PutAction {
    Create,
    Check,
    Submit,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub purpose: Purpose,
    pub index: u64,
    pub digest: Digest,
    pub ends: u64,
}
#[derive(Clone, Debug)]
pub struct Sim {
    pub params: Params,
    pub knobs: Knobs,
    pub nodes: Vec<Node>,
    pub ledger: Ledger,
    pub board: Board,
    pub oracle: Oracle,
    pub trace: Vec<Event>,
    pub rng: Rng,
    pub step: u64,
    pub crash_point: Option<CrashPoint>,
    /// Optional deterministic delivery subset for experiments; None sends to all.
    pub witness_peers: Option<BTreeSet<usize>>,
    pub sync_peers: Option<BTreeSet<usize>>,
    /// Delivery order for a seeded adversarial first response. No source is omitted.
    pub first_sync_peer: Option<usize>,
    pub requests: Vec<Request>,
    pub h_next: u64,
    pub account_next: u64,
}
impl Sim {
    pub fn new(params: Params, seed: u64) -> Self {
        Self::new_with_knobs(params, seed, Knobs::default())
    }
    pub fn new_with_knobs(params: Params, seed: u64, knobs: Knobs) -> Self {
        let n = params.n;
        let mut s = Self {
            params,
            knobs,
            nodes: (0..n).map(|_| Node::new()).collect(),
            ledger: Ledger::new(n),
            board: Board::new(n),
            oracle: Oracle::default(),
            trace: vec![],
            rng: Rng(seed),
            step: 0,
            crash_point: None,
            witness_peers: None,
            sync_peers: None,
            first_sync_peer: None,
            requests: vec![],
            h_next: 0,
            account_next: 0,
        };
        for j in 0..n {
            s.sync(j).unwrap();
            for p in Purpose::ALL {
                s.open(j, p).unwrap();
            }
        }
        s.post_checkpoint().unwrap();
        s
    }
    fn restart_marker(&self, j: usize, rule: MarkerRule) -> bool {
        if self.knobs.old_no_restart_marker {
            return false;
        }
        let ram = &self.nodes[j].ram;
        match rule {
            MarkerRule::Statement(whole) => whole,
            MarkerRule::Checkpoint(p) => {
                !p.sequential()
                    && ram.whole_restart == Some(true)
                    && self
                        .ledger
                        .cp
                        .as_ref()
                        .zip(ram.cp_boot.as_ref())
                        .is_some_and(|(cp, boot)| cp.restart_seq > boot.seq)
            }
            MarkerRule::LateOpen(p) => {
                !p.sequential()
                    && ram.whole_restart == Some(false)
                    && self
                        .ledger
                        .cp
                        .as_ref()
                        .is_some_and(|cp| self.session(j, p).work.restart_mark < cp.restart_seq)
            }
            MarkerRule::Bind(p) => {
                !p.sequential()
                    && ram.whole_restart == Some(true)
                    && self
                        .ledger
                        .cp
                        .as_ref()
                        .zip(ram.cp_boot.as_ref())
                        .is_some_and(|(cp, boot)| cp.seq <= boot.seq || cp.restart_seq <= boot.seq)
            }
        }
    }
    fn account_put(
        &mut self,
        j: usize,
        p: Purpose,
        i: u64,
        share: &[u8],
        action: PutAction,
    ) -> Result<(), Error> {
        if self.knobs.old_no_put_record || p.sequential() {
            return Ok(());
        }
        let log = self
            .board
            .verified(j, &self.ledger)
            .ok_or(Error::LogUnavailable)?;
        let digest = put_digest(share);
        let covered = self.board.covered_position();
        let first = log.iter().find_map(|e| match e.entry {
            Entry::Put { digest: d, tag } if d == digest && e.position <= covered => Some(tag),
            _ => None,
        });
        let exists = log
            .iter()
            .any(|e| matches!(e.entry, Entry::Put { digest: d, .. } if d == digest));
        match action {
            PutAction::Create => {
                if exists {
                    return Err(Error::SlotUsed);
                }
                let mut tag = [0; 16];
                tag[..8].copy_from_slice(&self.rng.next_u64().to_be_bytes());
                tag[8..].copy_from_slice(&self.rng.next_u64().to_be_bytes());
                self.session_mut(j, p).work.put_tags.insert(i, tag);
                self.submit_put(j, digest, tag);
            }
            PutAction::Check => {
                if first.is_some_and(|tag| self.session(j, p).work.put_tags.get(&i) != Some(&tag)) {
                    return Err(Error::SlotUsed);
                }
            }
            PutAction::Submit => {
                if first.is_none() {
                    if !exists {
                        let tag = self.session(j, p).work.put_tags[&i];
                        self.submit_put(j, digest, tag);
                    }
                    return Err(Error::PutPending);
                }
            }
        }
        Ok(())
    }
    pub fn in_bound(&self) -> bool {
        self.oracle.in_bound(self.params.c(), self.params.f)
    }
    pub fn session(&self, j: usize, p: Purpose) -> &Session {
        &self.nodes[j].ram.sessions[&p]
    }
    fn session_mut(&mut self, j: usize, p: Purpose) -> &mut Session {
        self.nodes[j].ram.sessions.get_mut(&p).unwrap()
    }
    fn current(&self, j: usize) -> bool {
        self.nodes[j].up && self.nodes[j].ram.boot_counter == self.ledger.boots[j]
    }
    fn available(&self, j: usize) -> bool {
        self.current(j) && !self.nodes[j].ram.fetching
    }
    fn ready(&self, j: usize) -> Result<(), Error> {
        if self.oracle.halted() {
            return Err(Error::OracleViolation);
        }
        if !self.nodes[j].up {
            return Err(Error::NotReady);
        }
        // SS-082: old boot cannot perform app operations.
        if !self.current(j) {
            return Err(Error::Fenced);
        }
        // SS-083/106: first sync and verified snapshot precede app operations.
        if !self.nodes[j].ram.synced {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    fn opened(&self, j: usize, p: Purpose) -> Result<(), Error> {
        self.ready(j)?;
        if !self.nodes[j].ram.sessions.get(&p).is_some_and(|s| s.open) {
            return Err(Error::NotOpen);
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot(
            self.nodes
                .iter()
                .map(|n| (n.tier0.clone(), n.disk.clone()))
                .collect(),
        )
    }
    fn reboot(&mut self, j: usize, blank: bool) {
        let blank = blank || !self.nodes[j].tier0.log_initialized;
        // SS-014/102, design G1: count this outage together with existing
        // unavailable or Byzantine peers, even though reboot is synchronous.
        let down = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(k, n)| *k == j || !n.up || n.byzantine || n.ram.fetching)
            .count();
        self.oracle.max_down = self.oracle.max_down.max(down);
        let boot = self.ledger.reboot(j);
        self.nodes[j].ram = Ram {
            boot_counter: boot,
            fetching: blank,
            ..Ram::default()
        };
        self.nodes[j].up = true;
    }
    pub fn inject(&mut self, fault: Fault) {
        // Keep traces small: snapshots themselves are not printed.
        let label = match &fault {
            Fault::CoordinatedRollback(_) => "CoordinatedRollback".into(),
            Fault::RollbackSeat(j, _) => format!("RollbackSeat({j})"),
            x => format!("{x:?}"),
        };
        self.trace.push(Event::Fault(label));
        match fault {
            Fault::SealdCrash(j) | Fault::VmReboot(j) => self.reboot(j, false),
            Fault::ReplaceSlot(j) => {
                self.oracle.lost(j);
                self.nodes[j].tier0 = Tier0::default();
                self.nodes[j].disk = Persist::default();
                self.reboot(j, true);
            }
            Fault::WholeCommitteeRestart => {
                self.oracle.max_down = self.params.n;
                for j in 0..self.params.n {
                    self.reboot(j, false);
                }
            }
            Fault::CoordinatedRollback(s) => {
                self.oracle.max_down = self.params.n;
                for (j, (t, d)) in s.0.into_iter().enumerate() {
                    self.oracle.lost_permanently(j);
                    self.nodes[j].tier0 = t;
                    self.nodes[j].disk = d;
                    self.reboot(j, false);
                }
            }
            Fault::RollbackSeat(j, s) => {
                self.oracle.lost_permanently(j);
                self.nodes[j].tier0 = s.0[j].0.clone();
                self.nodes[j].disk = s.0[j].1.clone();
                self.reboot(j, false);
            }
            Fault::ByzantinePeer(j) => {
                self.nodes[j].byzantine = true;
                self.oracle.lost_permanently(j);
            }
            Fault::LedgerReadFailure(j) => self.nodes[j].ledger_read_failure = true,
            Fault::LedgerReadRecovered(j) => self.nodes[j].ledger_read_failure = false,
            Fault::Withhold(j) => self.board.withhold(j),
            Fault::ServeLog(j) => self.board.serve(j),
            Fault::LoseTail => self.board.lose_tail(),
            Fault::LoseCovered(j) => self.board.lose_covered(j),
            Fault::Down(j) => self.nodes[j].up = false,
            Fault::Up(j) => self.nodes[j].up = true,
        }
        self.oracle.max_down = self
            .oracle
            .max_down
            .max(self.nodes.iter().filter(|n| !n.up || n.byzantine).count());
    }
    fn crash_at_cut(&mut self, j: usize) {
        let point = self.crash_point.take().expect("armed crash cut");
        self.trace.push(Event::CrashCut {
            seat: j,
            step: self.step,
            point,
        });
        self.inject(Fault::SealdCrash(j));
    }
    fn valid(&self, st: &Statement, seat: usize, sid: Sid) -> bool {
        // SS-111: historical boot tickets are valid for stored reports.
        st.valid
            && st.seat == seat
            && st.sid == sid
            && self.ledger.tickets.contains(&(seat, st.boot))
    }
    // SS-111: the receiver validates statements, not the identity of their carrier.
    // Byzantine behavior adds a forged high report alongside its old signed one.
    fn reports(&mut self, peer: usize, owner: usize, id: Sid) -> Vec<Statement> {
        let mut reports: Vec<_> = self.nodes[peer]
            .tier0
            .peers
            .get(&(owner, id))
            .map(|e| e.statement.clone())
            .into_iter()
            .collect();
        if self.nodes[peer].byzantine {
            self.oracle.byzantine_fired[1] += 1;
            reports.push(Statement {
                seat: owner,
                boot: self.ledger.boots[owner],
                sid: id,
                v: 999999,
                epoch: 1,
                digest: hash(b"forged"),
                valid: false,
            });
        }
        reports
    }
    fn sync_sources(&self, j: usize) -> Vec<usize> {
        let mut peers: Vec<_> = (0..self.params.n)
            .filter(|&k| {
                k != j
                    && self.available(k)
                    && self.sync_peers.as_ref().is_none_or(|s| s.contains(&k))
            })
            .collect();
        peers.sort_by_key(|k| (Some(*k) != self.first_sync_peer, *k));
        peers
    }
    fn merge_slot(&mut self, j: usize, key: SlotKey, d: Digest) {
        // SS-116: retain conflict even if later answers agree; sync still completes.
        let t = &mut self.nodes[j].tier0;
        if t.slots.get(&key).is_some_and(|old| *old != d) {
            t.conflicted.insert(key);
        } else {
            t.slots.insert(key, d);
        }
    }
    pub fn sync(&mut self, j: usize) -> Result<(), Error> {
        if !self.current(j) {
            return Err(Error::NotReady);
        }
        let mut peers = self.sync_sources(j);
        // SS-102: extend the experiment's sources in seat order for a blank fetch.
        let (required, exclude_owner) =
            if self.nodes[j].ram.fetching && !self.knobs.old_fetch_w_sources {
                for k in 0..self.params.n {
                    if peers.len() > self.params.w {
                        break;
                    }
                    if k != j && self.available(k) && !peers.contains(&k) {
                        peers.push(k);
                    }
                }
                (self.params.w + 1, true)
            } else {
                (self.params.w, false)
            };
        if peers.len() < required {
            return Err(Error::NoQuorum);
        }
        if self.nodes[j].ram.fetching {
            // SS-102: reconstruct OTHER seats' fences before witness/partial service.
            if !self.knobs.no_blank_fetch {
                for &k in &peers {
                    let mut entries = self.nodes[k].tier0.peers.clone();
                    // SS-102 candidate: the owner supplies its signed latest
                    // durable statement. No ciphertext transfer is implied.
                    if self.knobs.fetch_owner_statement && !self.nodes[k].byzantine {
                        for (&id, records) in &self.nodes[k].disk.local {
                            if let Some(r) = records.iter().max_by_key(|r| r.v) {
                                let st = Statement::signed(r, self.nodes[k].ram.boot_counter);
                                entries.insert(
                                    (k, id),
                                    PeerEntry {
                                        pv: r.v,
                                        pe: r.epoch,
                                        pd: r.digest(),
                                        statement: st,
                                    },
                                );
                            }
                        }
                    }
                    for (key, e) in entries {
                        if key.0 != j
                            && (!exclude_owner || key.0 != k || self.knobs.fetch_owner_statement)
                            && self.valid(&e.statement, key.0, key.1)
                            && e.pv == e.statement.v
                            && e.pe == e.statement.epoch
                            && e.pd == e.statement.digest
                        {
                            let old = self.nodes[j].tier0.peers.get(&key).map_or(0, |x| x.pv);
                            if e.pv > old {
                                self.nodes[j].tier0.peers.insert(key, e);
                            }
                        }
                    }
                    let slots = self.nodes[k].tier0.slots.clone();
                    for (key, d) in slots {
                        if key.0 != j && (key.0 != k || self.knobs.fetch_owner_statement) {
                            self.merge_slot(j, key, d);
                        }
                    }
                    let conflicts = self.nodes[k].tier0.conflicted.clone();
                    self.nodes[j]
                        .tier0
                        .conflicted
                        .extend(conflicts.into_iter().filter(|key| {
                            key.0 != j && (key.0 != k || self.knobs.fetch_owner_statement)
                        }));
                }
                // SS-126/127: rebuild each retained replica from answering non-owners.
                if !self.knobs.old_no_replica_fetch {
                    let entries = self.nodes[j].tier0.peers.clone();
                    for ((owner, id), e) in entries {
                        let replica = peers.iter().filter(|&&k| k != owner).find_map(|&k| {
                            self.fetch_for(k, j, owner, id)
                                .ok()
                                .filter(|r| r.digest() == e.pd)
                        });
                        if let Some(r) = replica {
                            self.nodes[j].disk.replicas.insert((owner, id), r);
                        } else {
                            self.nodes[j].disk.replicas.remove(&(owner, id));
                        }
                    }
                }
            }
            // SS-102 / concurrent G2 reading: completed fetch retires this loss.
            if !self.oracle.permanent_lost.contains(&j) {
                self.oracle.active_lost.remove(&j);
            }
            self.nodes[j].ram.fetching = false;
            self.nodes[j].tier0.log_initialized = true;
        }
        // SS-030/111: sync own reports and slots. Unsigned Byzantine inflation is ignored.
        for p in Purpose::ALL {
            let id = sid(j, p);
            let mut max = 0;
            for &k in &peers {
                for st in self.reports(k, j, id) {
                    if self.valid(&st, j, id) {
                        max = max.max(st.v);
                    } else {
                        self.trace.push(Event::IgnoredReport(k));
                    }
                }
            }
            if let Some(records) = self.nodes[j].disk.local.get(&id) {
                for r in records {
                    max = max.max(r.v);
                }
            }
            let session = self.nodes[j]
                .ram
                .sessions
                .entry(p)
                .or_insert_with(|| Session::new(j, p));
            session.v_max = session.v_max.max(max);
        }
        for &k in &peers {
            let entries = self.nodes[k].tier0.slots.clone();
            for (key, mut d) in entries {
                if key.0 == j {
                    if self.nodes[k].byzantine {
                        self.oracle.byzantine_fired[0] += 1;
                        d = hash(b"Byzantine conflicting slot");
                    }
                    self.merge_slot(j, key, d);
                }
            }
            let conflicts = self.nodes[k].tier0.conflicted.clone();
            self.nodes[j]
                .tier0
                .conflicted
                .extend(conflicts.into_iter().filter(|key| key.0 == j));
        }
        if !self.nodes[j].ram.synced {
            // SS-106: don't turn an unreadable snapshot into an empty checkpoint.
            if self.nodes[j].ledger_read_failure {
                return Err(Error::NotReady);
            }
            let cp = self.ledger.cp.clone();
            let whole = cp
                .as_ref()
                .is_some_and(|cp| self.ledger.continuous(cp) < self.params.w + 1);
            // SS-067: retain the first verified decision for this boot.
            // SS-098: absent checkpoint gives false and an empty cp_boot.
            self.nodes[j].ram.whole_restart = Some(whole);
            self.nodes[j].ram.cp_boot = cp.clone();
            self.nodes[j].ram.synced = true;
            self.restore_done(
                j,
                self.nodes[j].ram.boot_counter,
                cp.as_ref().map_or(0, |c| c.seq),
                self.restart_marker(j, MarkerRule::Statement(whole)),
            );
        }
        self.retry_restore(j);
        self.trace.push(Event::Sync(j));
        Ok(())
    }
    pub fn partial(&mut self, peer: usize, j: usize, id: Sid, v: u64) -> Result<(), Error> {
        // SS-014/017/019: only current requester, distinct current peer.
        if peer == j {
            return Err(Error::BadRecord);
        }
        if !self.current(j) {
            return Err(Error::NotCurrent);
        }
        if !self.current(peer) {
            return Err(Error::Fenced);
        }
        if self.nodes[peer].ram.fetching {
            return Err(Error::Unavailable);
        }
        if self.nodes[peer].byzantine {
            self.oracle.byzantine_fired[3] += 1;
            return Err(Error::Unavailable);
        }
        // SS-016: version floor applies independently at every peer.
        if !self.knobs.no_version_fence
            && self.nodes[peer]
                .tier0
                .peers
                .get(&(j, id))
                .is_some_and(|e| v < e.pv)
        {
            return Err(Error::StaleVersion);
        }
        // SS-018/074: abstract valid share only.
        if !self.nodes[peer].tier0.share {
            return Err(Error::GroupUnavailable);
        }
        Ok(())
    }
    pub fn derive(&mut self, j: usize, id: Sid, v: u64) -> Result<Digest, Error> {
        if self.oracle.halted() {
            return Err(Error::OracleViolation);
        }
        if !self.current(j) {
            return Err(Error::NotCurrent);
        }
        let mut partials = vec![];
        // SS-009: own share counts; exactly t DISTINCT partials are combined.
        if self.nodes[j].tier0.share {
            partials.push(j);
        }
        for peer in 0..self.params.n {
            if partials.len() == self.params.t {
                break;
            }
            if self.partial(peer, j, id, v).is_ok() {
                partials.push(peer);
            }
        }
        if partials.len() != self.params.t {
            return Err(Error::GroupUnavailable);
        }
        self.trace.push(Event::Derived {
            seat: j,
            sid: id,
            v,
            partials,
        });
        let bound = self.in_bound();
        self.oracle.derive(j, id, v, bound, &mut self.trace);
        if self.oracle.halted() {
            return Err(Error::OracleViolation);
        }
        // SS-007/011: task-authorized abstract K; no key is stored in node state.
        let mut bytes = b"K".to_vec();
        bytes.extend((j as u32).to_be_bytes());
        bytes.extend(id);
        bytes.extend(v.to_be_bytes());
        Ok(hash(&bytes))
    }
    pub fn witness(
        &mut self,
        peer: usize,
        j: usize,
        r: &Record,
        st: &Statement,
    ) -> Result<(), Error> {
        if peer == j {
            return Err(Error::BadRecord);
        }
        if !self.available(peer) {
            return Err(Error::Unavailable);
        }
        // SS-028/029: request signature is current; header and signed payload agree.
        if !self.current(j) || st.boot != self.ledger.boots[j] || !self.valid(st, j, r.sid) {
            return Err(Error::NotCurrent);
        }
        if r.node != j || st.v != r.v || st.digest != r.digest() || st.epoch != r.epoch {
            return Err(Error::BadRecord);
        }
        self.trace.push(Event::Witness {
            seat: j,
            peer,
            v: r.v,
        });
        if self.nodes[peer].byzantine {
            return Ok(());
        }
        let key = (j, r.sid);
        if let Some(e) = self.nodes[peer].tier0.peers.get(&key).cloned() {
            if r.v < e.pv || (r.v == e.pv && r.digest() != e.pd) {
                // SS-027/030/095: only signed refusals raise v_max.
                if self.valid(&e.statement, j, r.sid) {
                    let s = self.session_mut(j, r.purpose);
                    s.v_max = s.v_max.max(e.pv);
                }
                return Err(if r.v < e.pv {
                    Error::StaleVersion
                } else {
                    // SS-095: refuse a different record at the retained version.
                    Error::Conflict
                });
            }
        }
        // SS-025/026: store replica even on re-ack after replica loss.
        self.nodes[peer].disk.replicas.insert(key, r.clone());
        self.nodes[peer].tier0.peers.insert(
            key,
            PeerEntry {
                pv: r.v,
                pe: r.epoch,
                pd: r.digest(),
                statement: st.clone(),
            },
        );
        Ok(())
    }
    pub fn checkpoint(&mut self, j: usize, p: Purpose) -> Result<u64, Error> {
        self.opened(j, p)?;
        self.seal(j, p)
    }
    fn seal(&mut self, j: usize, p: Purpose) -> Result<u64, Error> {
        // SS-125: a burned account body carries the ledger's restart generation.
        if self.restart_marker(j, MarkerRule::Checkpoint(p)) {
            self.session_mut(j, p).work.restart_mark = self.ledger.cp.as_ref().unwrap().restart_seq;
        }
        // SS-020/107: synchronous operations seal one fixed work snapshot.
        let s = self.session(j, p);
        let v = s.v_max + 1;
        let body = s.work.clone();
        self.session_mut(j, p).v_max = v;
        let key = self.derive(j, sid(j, p), v)?;
        let nonce = self.rng.nonce();
        let r = Record::seal(j, p, v, body.clone(), nonce, key);
        let st = Statement::signed(&r, self.nodes[j].ram.boot_counter);
        // SS-021: durability happens before any witness traffic.
        self.nodes[j]
            .disk
            .local
            .entry(r.sid)
            .or_default()
            .push(r.clone());
        self.trace.push(Event::Fsync { seat: j, v });
        if self.crash_point == Some(CrashPoint::AfterFsync) {
            self.crash_at_cut(j);
            return Err(Error::Crashed);
        }
        let cut = match &self.crash_point {
            Some(CrashPoint::AfterWitnessAcks { peers }) => Some(peers.clone()),
            _ => None,
        };
        let destinations: Vec<_> = cut.clone().unwrap_or_else(|| {
            (0..self.params.n)
                .filter(|k| self.witness_peers.as_ref().is_none_or(|s| s.contains(k)))
                .collect()
        });
        let mut acks = BTreeSet::new();
        // SS-022: all n-1 peers are sent the same durable record (unless fault cuts delivery).
        for peer in destinations {
            if peer != j && self.witness(peer, j, &r, &st).is_ok() && self.current(peer) {
                acks.insert(peer);
            }
        }
        // SS-024: a cut below quorum keeps only durable records and peer acks.
        if acks.len() < self.params.w {
            if cut.is_some() {
                self.crash_at_cut(j);
                return Err(Error::Crashed);
            }
            return Err(Error::NoQuorum);
        }
        // SS-023: only this transition makes a version current.
        let s = self.session_mut(j, p);
        s.v = v;
        s.epoch = 1;
        s.dirty = false;
        s.unsealed.clear();
        self.nodes[j]
            .disk
            .local
            .get_mut(&r.sid)
            .unwrap()
            .retain(|old| old.v >= v);
        self.oracle.commit(j, r.sid, p, v, &body);
        self.trace.push(Event::Committed {
            seat: j,
            v,
            digest: body.digest(p),
        });
        if cut.is_some() {
            self.crash_at_cut(j);
            return Err(Error::Crashed);
        }
        Ok(v)
    }
    pub fn fetch(&mut self, peer: usize, j: usize, id: Sid) -> Result<Record, Error> {
        self.fetch_for(peer, j, j, id)
    }
    fn fetch_for(
        &mut self,
        peer: usize,
        requester: usize,
        j: usize,
        id: Sid,
    ) -> Result<Record, Error> {
        // SS-038/039: current peer/requester; only a replica matching pd is served.
        if !self.current(requester) {
            return Err(Error::NotCurrent);
        }
        if peer == j || !self.available(peer) {
            return Err(Error::Unavailable);
        }
        let r = self.nodes[peer]
            .disk
            .replicas
            .get(&(j, id))
            .ok_or(Error::NotFound)?;
        if self.nodes[peer].byzantine {
            // SS-033: count actual stale responses, not an unused fault flag.
            if self.nodes[j]
                .ram
                .sessions
                .get(&r.purpose)
                .is_some_and(|s| s.v_max > r.v)
            {
                self.oracle.byzantine_fired[2] += 1;
            }
            return Ok(r.clone());
        } // deliberately stale, digest checked by caller
        let e = self.nodes[peer]
            .tier0
            .peers
            .get(&(j, id))
            .ok_or(Error::NotFound)?;
        if r.digest() != e.pd {
            return Err(Error::NotFound);
        }
        Ok(r.clone())
    }
    fn burn_restart(&mut self, j: usize, p: Purpose) -> Vec<u64> {
        // SS-123: a late account open burns even when continuity has recovered.
        let late = self.restart_marker(j, MarkerRule::LateOpen(p));
        if self.nodes[j].ram.whole_restart != Some(true) && !late {
            return vec![];
        }
        let mut burned = BTreeSet::new();
        // SS-068: burn absent indices too, using the boot snapshot, never live h.
        if p.sequential() && !self.knobs.no_restart_burn {
            if let Some(cp) = &self.nodes[j].ram.cp_boot {
                burned.extend(cp.pending_min..=cp.h.saturating_add(self.params.b));
            }
        }
        // SS-114: account burn once per session per boot, only on whole restart.
        if !p.sequential()
            && !self.knobs.no_account_burn
            && (late || !self.nodes[j].ram.account_burned.contains(&p))
        {
            burned.extend(
                self.session(j, p)
                    .work
                    .slots
                    .iter()
                    .filter_map(|(i, s)| (*s != Slot::Burned).then_some(*i)),
            );
        }
        let marker = self.ledger.cp.as_ref().map_or(0, |cp| cp.restart_seq);
        let s = self.session_mut(j, p);
        if late {
            s.work.restart_mark = marker;
            s.dirty = true;
        }
        for i in &burned {
            s.work.slots.insert(*i, Slot::Burned);
            s.work.put_tags.remove(i);
            s.unsealed.remove(i);
            s.dirty = true;
        }
        let indices: Vec<_> = burned.into_iter().collect();
        if !indices.is_empty() {
            self.trace.push(Event::Burned {
                seat: j,
                purpose: p,
                indices: indices.clone(),
            });
        }
        indices
    }
    pub fn open(&mut self, j: usize, p: Purpose) -> Result<Vec<u64>, Error> {
        if !self.nodes[j].ram.synced {
            self.sync(j)?;
        }
        self.ready(j)?;
        // SS-042: already-open is idempotent.
        if self.session(j, p).open {
            return Ok(vec![]);
        }
        // SS-030/036: interrupt restore after sync, before candidate recovery.
        // This cut also applies when no candidate can obtain enough partials.
        if self.crash_point == Some(CrashPoint::DuringRestore) {
            self.crash_at_cut(j);
            return Err(Error::Crashed);
        }
        let id = sid(j, p);
        let peers = self.sync_sources(j);
        if peers.len() < self.params.w {
            return Err(Error::NoQuorum);
        }
        let mut candidates: BTreeMap<(u64, Digest), usize> = BTreeMap::new();
        for &peer in &peers {
            for st in self.reports(peer, j, id) {
                if self.valid(&st, j, id) {
                    *candidates.entry((st.v, st.digest)).or_default() += 1;
                } else {
                    self.trace.push(Event::IgnoredReport(peer));
                }
            }
        }
        // SS-094: even an unwitnessed durable local record is a candidate.
        let local = self.nodes[j]
            .disk
            .local
            .get(&id)
            .cloned()
            .unwrap_or_default();
        for r in &local {
            candidates.entry((r.v, r.digest())).or_default();
        }
        let mut order: Vec<_> = candidates.into_iter().collect();
        // SS-031/032: descending version/count, ascending digest.
        order
            .sort_by(|((va, da), ca), ((vb, db), cb)| vb.cmp(va).then(cb.cmp(ca)).then(da.cmp(db)));
        if let Some(((max, _), _)) = order.first() {
            self.session_mut(j, p).v_max = self.session(j, p).v_max.max(*max);
        }
        let mut source = 0;
        let mut authenticated = false;
        let mut last = Error::RecordUnavailable;
        for ((v, d), count) in order.iter().copied() {
            self.trace.push(Event::Candidate {
                seat: j,
                v,
                digest: d,
                reports: count,
            });
            // SS-033: accept only a byte digest match, including Byzantine fetches.
            let r = local.iter().find(|r| r.digest() == d).cloned().or_else(|| {
                peers
                    .iter()
                    .find_map(|&k| self.fetch(k, j, id).ok().filter(|r| r.digest() == d))
            });
            let Some(r) = r else {
                last = Error::RecordUnavailable;
                continue;
            };
            let key = match self.derive(j, id, v) {
                Ok(k) => k,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            // SS-037: authentication and identity checked before touching work/peers.
            if !r.authenticates(key) || r.sid != id || r.node != j || r.v != v || r.purpose != p {
                last = Error::Corrupt;
                continue;
            }
            self.trace.push(Event::Authenticated { seat: j, v });
            let bound = self.in_bound();
            self.oracle
                .restored((j, id), p, v, &r.body, bound, &mut self.trace);
            if self.oracle.halted() {
                return Err(Error::OracleViolation);
            }
            self.session_mut(j, p).work = r.body;
            // SS-036: restored work has no unsealed bindings before restart burns.
            self.session_mut(j, p).unsealed.clear();
            source = v;
            authenticated = true;
            break;
        }
        // SS-034/010/037: last candidate's failure is the returned error.
        if !order.is_empty() && !authenticated {
            return Err(last);
        }
        if !authenticated {
            let bound = self.in_bound();
            self.oracle
                .restored((j, id), p, 0, &Body::default(), bound, &mut self.trace);
            if self.oracle.halted() {
                return Err(Error::OracleViolation);
            }
        }
        let burned = self.burn_restart(j, p);
        // SS-036: an authenticated restore must seal with w acks before opening.
        // SS-041: a new empty session seals only if restart handling burns slots.
        if authenticated || !burned.is_empty() || self.session(j, p).dirty {
            self.seal(j, p)?;
        }
        self.session_mut(j, p).open = true;
        if !p.sequential() && self.nodes[j].ram.whole_restart == Some(true) {
            self.nodes[j].ram.account_burned.insert(p);
        }
        if !burned.is_empty() {
            self.oracle.problem(
                format!("G1: seat {j} restart loses {p:?} slots {burned:?}"),
                true,
                &mut self.trace,
            );
        }
        self.trace.push(Event::Opened {
            seat: j,
            purpose: p,
            source,
            burned: burned.clone(),
        });
        Ok(burned)
    }
    pub fn put(&mut self, j: usize, p: Purpose, name: &str, value: Vec<u8>) -> Result<(), Error> {
        self.opened(j, p)?; // SS-043: volatile until checkpoint.
        let s = self.session_mut(j, p);
        s.work.entries.insert(name.into(), value);
        s.dirty = true;
        Ok(())
    }
    pub fn get(&self, j: usize, p: Purpose, name: &str) -> Result<Vec<u8>, Error> {
        self.opened(j, p)?;
        self.session(j, p)
            .work
            .entries
            .get(name)
            .cloned()
            .ok_or(Error::NotFound) // SS-044
    }
    pub fn destroy(&mut self, j: usize, p: Purpose, name: &str) -> Result<u64, Error> {
        self.opened(j, p)?;
        let s = self.session_mut(j, p);
        // SS-046/086/118: absent+dirty retry must seal the outstanding erasure.
        if s.work.entries.remove(name).is_some() {
            s.dirty = true;
        }
        if s.dirty {
            self.seal(j, p)
        } else {
            Ok(s.v)
        }
    }
    pub fn close(&mut self, j: usize, p: Purpose) -> Result<(), Error> {
        self.opened(j, p)?;
        let s = self.session_mut(j, p); // SS-047
        s.work = Body::default();
        s.unsealed.clear();
        s.open = false;
        s.dirty = false;
        Ok(())
    }
    pub fn slot_put(&mut self, j: usize, p: Purpose, i: u64, share: Vec<u8>) -> Result<(), Error> {
        self.opened(j, p)?;
        self.require_log(j, p)?;
        // SS-048/060/061: only absent -> free.
        // SS-059: no app operation moves an existing slot back to free.
        match self.session(j, p).work.slots.get(&i) {
            Some(Slot::Burned) => Err(Error::SlotBurned),
            Some(_) => Err(Error::SlotExists),
            None => {
                // SS-128/129: seat-log uniqueness is by share, independent of index.
                self.account_put(j, p, i, &share, PutAction::Create)?;
                let s = self.session_mut(j, p);
                s.work.slots.insert(i, Slot::Free(share.clone()));
                s.dirty = true;
                self.oracle.first_shares.entry((j, p, i)).or_insert(share);
                if !p.sequential() && self.knobs.old_per_event_ledger {
                    self.ledger.midnight.put_records += 1;
                    self.ledger.midnight.bytes += 146;
                }
                Ok(())
            }
        }
    }
    pub fn slot_get(&self, j: usize, p: Purpose, i: u64) -> Result<Vec<u8>, Error> {
        self.opened(j, p)?; // SS-049/061/062
        match self.session(j, p).work.slots.get(&i) {
            Some(Slot::Free(s) | Slot::Bound(s, _)) => Ok(s.clone()),
            Some(Slot::Burned) => Err(Error::SlotBurned),
            None => Err(Error::NotFound), // SS-062: absent slot_get refuses.
        }
    }
    pub fn slot_bind(&mut self, j: usize, p: Purpose, i: u64, d: Digest) -> Result<u64, Error> {
        // SS-065/113/133: the bind's ledger read also observes restart generations.
        self.observe_ledger(j)?;
        let result = self.bind_inner(j, p, i, d);
        if let Err(reason) = result {
            if reason != Error::PutPending {
                self.trace.push(Event::BindRefused { reason });
            }
        }
        result
    }
    fn bind_inner(&mut self, j: usize, p: Purpose, i: u64, d: Digest) -> Result<u64, Error> {
        self.opened(j, p)?;
        self.require_log(j, p)?;
        let slot = self.session(j, p).work.slots.get(&i).cloned();
        // SS-061/062/053: requested refusal precedence before window/log checks.
        let (share, free) = match slot {
            Some(Slot::Burned) => return Err(Error::SlotBurned),
            None => return Err(Error::NotFound),
            // SS-053: a bound slot cannot change digest.
            Some(Slot::Bound(_, old)) if old != d => return Err(Error::SlotBoundOther),
            Some(Slot::Bound(s, _)) => (s, false),
            Some(Slot::Free(s)) => (s, true),
        };
        if free {
            // SS-090/131: slot_used precedes no_checkpoint and log conflict.
            self.account_put(j, p, i, &share, PutAction::Check)?;
            // SS-065/066: always the latest ledger checkpoint at call time.
            let cp = self.ledger.cp.as_ref().ok_or(Error::NoCheckpoint)?;
            // SS-124: a free account slot waits for its restart checkpoint.
            if self.restart_marker(j, MarkerRule::Bind(p)) {
                return Err(Error::NoCheckpoint);
            }
            if p.sequential() {
                // SS-063/081: upper bound saturates.
                if i > cp.h.saturating_add(self.params.b) {
                    return Err(Error::WindowExceeded);
                }
                // SS-064: only free slots have the lower-bound test.
                if !self.knobs.no_slot_stale
                    && (i < cp.pending_min
                        || (i <= cp.h
                            && (!self.board.pending.contains(&i)
                                || pending_root(&self.board.pending) != cp.pending_root
                                || self.board.pending.len() != cp.pending_count as usize)))
                {
                    return Err(Error::SlotStale);
                }
            }
        }
        let key = (j, p, i);
        let t = &self.nodes[j].tier0;
        // SS-054/116: own log conflicts, including same-digest rebinds.
        if t.conflicted.contains(&key) || t.slots.get(&key).is_some_and(|old| *old != d) {
            return Err(Error::Conflict);
        }
        if !free {
            // SS-052/093: repeat seal only for an unsealed binding.
            return if self.session(j, p).unsealed.contains(&i) {
                self.seal(j, p)
            } else {
                // SS-093: a sealed same-digest bind returns without traffic.
                Ok(self.session(j, p).v)
            };
        }
        // SS-130/089: put_pending is a submission, not a refusal. All refusals precede it.
        self.account_put(j, p, i, &share, PutAction::Submit)?;
        // SS-050: own entry precedes peer acks; free state survives until quorum.
        self.nodes[j].tier0.slots.insert(key, d);
        if !self.knobs.no_witness_before_bind {
            let mut acks = 0;
            for peer in 0..self.params.n {
                if peer == j
                    || !self.available(peer)
                    || self
                        .witness_peers
                        .as_ref()
                        .is_some_and(|s| !s.contains(&peer))
                {
                    continue;
                }
                let t = &mut self.nodes[peer].tier0;
                if t.conflicted.contains(&key) || t.slots.get(&key).is_some_and(|old| *old != d) {
                    continue;
                }
                t.slots.insert(key, d);
                acks += 1;
                self.trace.push(Event::SlotAck {
                    seat: j,
                    peer,
                    index: i,
                });
            }
            if acks < self.params.w {
                return Err(Error::NoQuorum);
            }
        }
        if self.crash_point == Some(CrashPoint::AfterSlotAcks) {
            self.crash_at_cut(j);
            return Err(Error::Crashed);
        }
        // SS-051: only a bound body committed by a second quorum can release.
        let s = self.session_mut(j, p);
        s.work.slots.insert(i, Slot::Bound(share, d));
        s.unsealed.insert(i);
        s.dirty = true;
        self.seal(j, p)
    }
    pub fn slot_release_ok(&self, j: usize, p: Purpose, i: u64, d: Digest) -> bool {
        if self.opened(j, p).is_err() || self.require_log(j, p).is_err() {
            return false;
        }
        let s = self.session(j, p);
        let key = (j, p, i);
        // SS-055/056: all four conditions, including own log and conflict marker.
        // SS-056: any false conjunct makes the release check false.
        matches!(s.work.slots.get(&i),Some(Slot::Bound(_,old)) if *old==d)
            && !s.unsealed.contains(&i)
            && self.nodes[j].tier0.slots.get(&key) == Some(&d)
            && !self.nodes[j].tier0.conflicted.contains(&key)
    }
    pub fn release(&mut self, j: usize, p: Purpose, i: u64, d: Digest) -> bool {
        if !self.slot_release_ok(j, p, i, d) {
            return false;
        }
        let share = self.slot_get(j, p, i).expect("releasable slot has a share");
        self.oracle.release((j, p, i), d, share, &mut self.trace);
        true
    }
    pub fn slot_burn(&mut self, j: usize, p: Purpose, i: u64) -> Result<u64, Error> {
        self.opened(j, p)?;
        let s = self.session_mut(j, p);
        // SS-057/058/118: clean repeated burn is idempotent; dirty one retries.
        if s.work.slots.get(&i) != Some(&Slot::Burned) {
            s.work.slots.insert(i, Slot::Burned);
            s.work.put_tags.remove(&i);
            s.unsealed.remove(&i);
            s.dirty = true;
            self.trace.push(Event::Burned {
                seat: j,
                purpose: p,
                indices: vec![i],
            });
        }
        if self.session(j, p).dirty {
            // SS-118: a repeated dirty burn succeeds only after a quorum seal.
            self.seal(j, p)
        } else {
            // SS-058: a clean repeated burn preserves the current version.
            Ok(self.session(j, p).v)
        }
    }
    pub fn observe_ledger(&mut self, j: usize) -> Result<(), Error> {
        self.ready(j)?;
        if self.nodes[j].ledger_read_failure {
            return Err(Error::NotReady);
        }
        // SS-133: retire this generation only after both marker and continuity recover.
        if !self.knobs.old_no_restart_rearm && self.nodes[j].ram.whole_restart == Some(true) {
            if let (Some(cp), Some(boot)) = (&self.ledger.cp, &self.nodes[j].ram.cp_boot) {
                if cp.restart_seq > boot.seq && self.ledger.continuous(cp) > self.params.w {
                    let marker = cp.restart_seq;
                    for s in self.nodes[j].ram.sessions.values_mut() {
                        if s.open && !s.purpose.sequential() {
                            s.work.restart_mark = marker;
                            s.dirty = true;
                        }
                    }
                    self.nodes[j].ram.account_burned.clear();
                    self.nodes[j].ram.whole_restart = Some(false);
                }
            }
        }
        // SS-113: a new loss after SS-133 burns the next generation.
        if self.nodes[j].ram.whole_restart == Some(false) {
            if let Some(cp) = self.ledger.cp.clone() {
                if self.ledger.continuous(&cp) < self.params.w + 1 {
                    self.nodes[j].ram.whole_restart = Some(true);
                    self.nodes[j].ram.cp_boot = Some(cp.clone());
                    // SS-120: a running node repeats its current boot counter.
                    if self.restart_marker(j, MarkerRule::Statement(true)) {
                        self.restore_done(j, self.nodes[j].ram.boot_counter, cp.seq, true);
                    }
                    // SS-113: suspend ALL affected sessions before a fallible seal.
                    // A failure in one pool must not leave another pool releasable.
                    let mut work = vec![];
                    for p in Purpose::ALL {
                        if self.session(j, p).open {
                            let burned = self.burn_restart(j, p);
                            if !burned.is_empty() {
                                self.session_mut(j, p).open = false;
                                work.push((p, burned));
                            } else if !p.sequential() {
                                self.nodes[j].ram.account_burned.insert(p);
                            }
                        }
                    }
                    let mut failure = None;
                    for (p, burned) in work {
                        match self.seal(j, p) {
                            Ok(_) => {
                                self.session_mut(j, p).open = true;
                                if !p.sequential() {
                                    self.nodes[j].ram.account_burned.insert(p);
                                }
                                self.oracle.problem(
                                    format!("G1: running seat {j} restart burn {burned:?}"),
                                    true,
                                    &mut self.trace,
                                );
                            }
                            Err(e) => {
                                failure.get_or_insert(e);
                            }
                        }
                    }
                    if let Some(e) = failure {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
    pub fn recover_all(&mut self) {
        if self.oracle.halted() {
            return;
        }
        // First let all peers rebuild, then open sessions. Replacements without a
        // share can use t peer shares; repair installs an abstract share only after
        // t existing holders are reachable (SS-074, outside repair protocol scope).
        for _ in 0..2 {
            for j in 0..self.params.n {
                if self.nodes[j].up && !self.nodes[j].ram.synced {
                    let _ = self.sync(j);
                }
            }
            for j in 0..self.params.n {
                if self.available(j)
                    && !self.nodes[j].tier0.share
                    && self
                        .nodes
                        .iter()
                        .enumerate()
                        .filter(|(k, n)| {
                            *k != j && self.available(*k) && n.tier0.share && !n.byzantine
                        })
                        .count()
                        >= self.params.t
                {
                    self.nodes[j].tier0.share = true;
                }
            }
        }
        for j in 0..self.params.n {
            if self.nodes[j].up {
                let _ = self.observe_ledger(j);
                self.retry_restore(j);
                for p in Purpose::ALL {
                    let _ = self.open(j, p);
                    if self.oracle.halted() {
                        return;
                    }
                }
            }
        }
        self.check_recovery();
    }
    pub fn check_recovery(&mut self) {
        // G1 is a recovery/liveness assertion, not an assertion while nodes are down.
        let healthy = self.nodes.iter().filter(|n| n.up && !n.byzantine).count();
        if healthy < self.params.t {
            return;
        }
        let keys: Vec<_> = self.oracle.committed.keys().copied().collect();
        for (j, id) in keys {
            if !self.nodes[j].up || self.nodes[j].byzantine || self.nodes[j].ledger_read_failure {
                continue;
            }
            if !self.nodes[j]
                .ram
                .sessions
                .values()
                .any(|s| s.sid == id && s.open)
            {
                let bound = self.in_bound();
                self.oracle.problem(
                    format!("G1: seat {j} cannot reopen committed session"),
                    !bound,
                    &mut self.trace,
                );
                if bound {
                    return;
                }
            }
        }
    }
    pub fn collect_covered(&mut self) {
        let Some(cp) = self.ledger.cp.clone() else {
            return;
        };
        for j in 0..self.params.n {
            if !self.available(j) {
                continue;
            }
            // SS-108: peer entries delete at the floor; own entries wait for burned/absent.
            let remove: Vec<_> = self.nodes[j]
                .tier0
                .slots
                .keys()
                .copied()
                .filter(|(owner, p, i)| {
                    p.sequential()
                        && *i < cp.pending_min
                        && (*owner != j
                            || self.nodes[j].ram.sessions.get(p).is_some_and(|s| {
                                s.open
                                    && s.work.slots.get(i).is_none_or(|slot| *slot == Slot::Burned)
                            }))
                })
                .collect();
            for key in remove {
                self.nodes[j].tier0.slots.remove(&key);
                self.nodes[j].tier0.conflicted.remove(&key);
            }
        }
    }
    fn require_log(&self, j: usize, p: Purpose) -> Result<(), Error> {
        if !p.sequential()
            && !self.knobs.old_no_put_record
            && self.board.verified(j, &self.ledger).is_none()
        {
            return Err(Error::LogUnavailable);
        }
        Ok(())
    }
    pub fn post_checkpoint(&mut self) -> Result<(), Refusal> {
        // All seats must extend the landed roots before any checkpoint side effect.
        let (batch_root, restores) = self
            .board
            .batches(&self.ledger)
            .ok_or(Refusal::LogUnavailable)?;
        let mut cp = Checkpoint {
            seq: self.ledger.cp.as_ref().map_or(1, |c| c.seq + 1),
            restart_seq: self.ledger.cp.as_ref().map_or(0, |c| c.restart_seq),
            h: self.h_next,
            pending_min: 0,
            pending_root: [0; 32],
            pending_count: 0,
            boot_counters: self.ledger.latest_done(&restores),
            batch_root,
            seat_root: vec![],
            restores,
        };
        if let Some(old) = self.ledger.cp.clone() {
            if self.ledger.restart_pending(&old, &cp.restores) {
                cp.restart_seq = cp.seq;
            }
            cp.h = cp.h.max(old.h);
            let same = old
                .boot_counters
                .iter()
                .zip(&cp.boot_counters)
                .filter(|(a, b)| a == b)
                .count();
            if same < self.params.w + 1 {
                cp.h = cp.h.max(old.h.saturating_add(self.params.b));
                let voided: Vec<_> = self
                    .requests
                    .iter()
                    .filter(|r| {
                        r.purpose.sequential() && r.index <= old.h.saturating_add(self.params.b)
                    })
                    .cloned()
                    .collect();
                for r in voided {
                    self.finish(&r, true);
                }
            }
        }
        let pending: BTreeSet<_> = self
            .requests
            .iter()
            .filter(|r| r.purpose.sequential())
            .map(|r| r.index)
            .collect();
        cp.pending_min = pending
            .iter()
            .copied()
            .chain([cp.h.saturating_add(1)])
            .min()
            .unwrap();
        cp.pending_root = pending_root(&pending);
        cp.pending_count = pending.len().try_into().expect("pending count fits u32");
        self.ledger.old_per_event_ledger = self.knobs.old_per_event_ledger;
        self.ledger.post(cp.clone(), &self.params)?;
        self.board.landed(&cp, pending);
        self.h_next = self.h_next.max(cp.h);
        self.collect_covered();
        self.trace.push(Event::Checkpoint {
            seq: cp.seq,
            h: cp.h,
        });
        Ok(())
    }
    fn submit_put(&mut self, j: usize, digest: Digest, tag: [u8; 16]) {
        self.board.post(j, Entry::Put { digest, tag });
    }
    fn restore_done(&mut self, seat: usize, boot: u64, seq: u64, whole_restart: bool) {
        let entry = Entry::Restore {
            boot,
            seq,
            whole_restart,
        };
        self.nodes[seat].ram.restore_statement = Some(entry.clone());
        self.post_restore(seat, entry);
    }
    fn post_restore(&mut self, seat: usize, entry: Entry) {
        self.board.post(seat, entry);
        if self.knobs.old_per_event_ledger {
            self.ledger.midnight.restore_transactions += 1;
            self.ledger.midnight.bytes += 115;
        }
    }
    fn retry_restore(&mut self, seat: usize) {
        if !self.available(seat) {
            return;
        }
        let Some(entry) = self.nodes[seat].ram.restore_statement.clone() else {
            return;
        };
        if self
            .board
            .verified(seat, &self.ledger)
            .is_some_and(|log| !log.iter().any(|posted| posted.entry == entry))
        {
            self.post_restore(seat, entry);
        }
    }
    pub fn request(&mut self, p: Purpose) -> Option<Request> {
        let index = if p.sequential() {
            let next = self.h_next + 1;
            if next > self.ledger.cp.as_ref()?.h.saturating_add(self.params.b) {
                return None;
            }
            self.h_next = next;
            next
        } else {
            self.account_next += 1;
            self.account_next
        };
        // Ticket comes from seeded RNG. A repost always gets a new ticket/index.
        let d = hash(&self.rng.next_u64().to_be_bytes());
        let r = Request {
            purpose: p,
            index,
            digest: d,
            ends: self.step + 3,
        };
        self.requests.push(r.clone());
        Some(r)
    }
    fn drive_request(&mut self, r: &Request) {
        for j in 0..self.params.n {
            if self.opened(j, r.purpose).is_err() {
                continue;
            }
            let _ = self.slot_put(j, r.purpose, r.index, vec![j as u8, r.index as u8]);
            let _ = self.slot_bind(j, r.purpose, r.index, r.digest);
            self.release(j, r.purpose, r.index, r.digest);
            if self.oracle.halted() {
                return;
            }
        }
    }
    fn finish(&mut self, r: &Request, void: bool) {
        for j in 0..self.params.n {
            let _ = self.slot_burn(j, r.purpose, r.index);
        }
        self.requests
            .retain(|x| x.purpose != r.purpose || x.index != r.index);
        self.trace.push(Event::End {
            index: r.index,
            void,
        });
    }
    pub fn tick(&mut self) {
        if self.oracle.halted() {
            return;
        }
        self.step += 1;
        self.recover_all();
        if self.oracle.halted() {
            return;
        }
        let ended: Vec<_> = self
            .requests
            .iter()
            .filter(|r| r.ends <= self.step)
            .cloned()
            .collect();
        for r in ended {
            self.finish(&r, false);
        }
        if self.step.is_multiple_of(self.params.cp_every) {
            let _ = self.post_checkpoint();
        }
        let p = if self.step.is_multiple_of(3) {
            Purpose::Ecdsa
        } else {
            Purpose::Schnorr
        };
        self.request(p);
        for r in self.requests.clone() {
            self.drive_request(&r);
            if self.oracle.halted() {
                return;
            }
        }
        // SS-043/045/046: entries have content and successful erasures to audit.
        let j = (self.step as usize) % self.params.n;
        let name = format!("entry-{}", self.step);
        if self
            .put(j, Purpose::Schnorr, &name, self.step.to_be_bytes().to_vec())
            .is_ok()
        {
            let _ = self.checkpoint(j, Purpose::Schnorr);
            if self.step.is_multiple_of(2) {
                let _ = self.destroy(j, Purpose::Schnorr, &name);
            }
        }
    }
    pub fn run(&mut self, steps: u64) -> Vec<Event> {
        for _ in 0..steps {
            self.tick();
            if self.oracle.halted() {
                break;
            }
        }
        self.trace.clone()
    }
}
