/-!
# Checkpoint oracle (split-checkpoint, CP-001 to CP-043)

The executable reference semantics of the OpenSpec capability `split-checkpoint`
(`openspec/changes/add-split-line-dealing/specs/split-checkpoint/spec.md`).

The state has two parts:
* the committee contract and the Recovery contract on Midnight: the chain of
  landed checkpoints (newest first) with the landing refusals CP-007 to CP-011,
  CP-040 and CP-041,
  the Midnight height of the latest landing, the recovery transition and the
  log of committee writes (CP-003, CP-005, CP-006, CP-034, CP-035);
* one committee node's restart view: its readiness, the boot tickets it read,
  its committee-pool burn ranges, its account pools, the pool sessions it
  created, the restart it classified and its marker (CP-017 to CP-029, CP-033),
  and the `RestoreDone` statements on the board's uncovered tail (CP-042).

The signer rules (CP-012 to CP-015), the replay floor (CP-036), the release
anchor (CP-037), seat-log coverage (CP-016) and the recovery reshare (CP-031,
CP-032) are pure functions, exposed as operations that keep no state.

Abstractions (formal plugin, practice 11):
* A Merkle root is the list it commits (collision free): `pending_root` is the
  sorted pending list, `settle_root` the `(auth, outcome)` leaves, `bf_root` the
  `(auth, nf)` leaves, a seat root the seat-log entries.
* Boot tickets, `RestoreDone` statements, seat-log entries, the requests live at
  a checkpoint, Midnight block heights and signature counts are inputs.
* A committee pool `(s, e)` is a number `pool`; an account pool is a number and
  its slots are its list positions.
-/

namespace SplitCheckpoint

/-! ## Domains -/

inductive Mode where
  | TEE | NON_TEE
  deriving Repr, DecidableEq, BEq

structure Params where
  n : Nat
  f : Nat
  mode : Mode
  /-- the reservation window `B` (Q-005: set by measurement, at least 1) -/
  B : Nat
  slotAnchor : Bool
  /-- `Δ_rec` in Midnight blocks (CP-034) -/
  dRec : Nat
  deriving Repr, DecidableEq

/-- RQ-001: `w = n − 1 − f`, `t = n − f`, `q = ⌈(n + f + 1)/2⌉`. -/
def Params.w (p : Params) : Nat := p.n - 1 - p.f
def Params.t (p : Params) : Nat := p.n - p.f
def Params.q (p : Params) : Nat := (p.n + p.f + 2) / 2

/-- The parameter domain: `f ≥ 1`, `n ≥ 3f + 1` (RQ-001) and `B ≥ 1` (SL-012). -/
def paramsOk (p : Params) : Bool := decide (1 ≤ p.f) && decide (3 * p.f + 1 ≤ p.n) && decide (1 ≤ p.B)

/-- CP-002: 52 bytes per pool. -/
def poolBytes : Nat := 52

/-- CP-003: one checkpoint every 60 s of board time. -/
def interval : Nat := 60

/-- CP-002: the fields of one committee pool of a checkpoint. `pending` is the
sorted list that `pending_root` commits. -/
structure Pool where
  pool : Nat
  h : Nat
  pendingMin : Nat
  pending : List Nat
  pendingCount : Nat
  deriving Repr, DecidableEq

/-- CP-016: `RestoreDone(committee, node_index, boot_ctr, cp.seq, whole_restart)`.
`seat` is the node index (one node per seat; JSON `node_index`, DECISIONS 69
item 8). -/
structure Restore where
  seat : Nat
  bootCtr : Nat
  cpSeq : Nat
  whole : Bool
  deriving Repr, DecidableEq

inductive Outcome where
  | FINAL | VOID | RELEASED
  deriving Repr, DecidableEq, BEq

/-- Seat-log entries (CP-015, CP-016): a slot-anchor binding entry `(nf, e)` (the
slot nullifier under `k_nf` and the hidden digest, DECISIONS 69 item 1), a put of
a share digest, a `RestoreDone`, a `release` entry. -/
inductive Entry where
  | bind (nf e : Nat)
  | put (digest : Nat)
  | restore (r : Restore)
  | release (eid g : Nat)
  deriving Repr, DecidableEq

/-- CP-001: the fields of a checkpoint. In a landed checkpoint `restartSeq` is
the value the contract set (CP-011); the value a candidate carries is not read
(ledger 4). -/
structure Cp where
  seq : Nat
  epoch : Nat
  boardHeight : Nat
  boardRoot : Nat
  witnessRoot : Nat
  pools : List Pool
  settle : List (Nat × Outcome)
  bf : List (Nat × Nat)
  bootCounters : List (Nat × Nat)
  restartSeq : Nat
  seatRoots : List (Nat × List Entry)
  restores : List Restore
  deriving Repr, DecidableEq

/-- An account-pool slot as a node holds it. -/
inductive ASlot where
  | free | bound (d : Nat) | burned
  deriving Repr, DecidableEq

structure Acct where
  id : Nat
  slots : List ASlot
  /-- the recorded restart mark (CP-025, CP-026) -/
  mark : Nat
  /-- marked for refill by a new session (CP-033) -/
  refill : Bool
  deriving Repr, DecidableEq

inductive Write where
  | checkpoint | eks (e : Nat) | event
  deriving Repr, DecidableEq

structure St where
  params : Params
  -- the contracts
  chain : List Cp
  lastLandMh : Nat
  recovered : Bool
  writes : List Write
  -- the node
  ready : Bool
  tickets : List (Nat × Nat)
  /-- committee-pool burn ranges `(pool, lo, hi)`, both ends included -/
  burnC : List (Nat × Nat × Nat)
  accts : List Acct
  /-- pool sessions the node created, with the burn ranges each opened with -/
  sessions : List (Nat × List (Nat × Nat × Nat))
  restartOpen : Bool
  /-- `restart_seq` of the latest landed checkpoint when the restart was classified -/
  markerPrev : Nat
  /-- a checkpoint with `restart_seq` above `markerPrev` has landed (CP-025) -/
  markerLanded : Bool
  /-- `RestoreDone` statements appended and not yet carried, kept in RAM (CP-004, CP-042) -/
  pendingRestores : List Restore
  /-- the `RestoreDone` statements on the board's uncovered tail (CP-042) -/
  board : List Restore
  coldStarted : Bool
  newPool : Bool
  deriving Repr, DecidableEq

def init (p : Params) : St :=
  { params := p, chain := [], lastLandMh := 0, recovered := false, writes := [],
    ready := false, tickets := [], burnC := [], accts := [], sessions := [],
    restartOpen := false, markerPrev := 0, markerLanded := false, pendingRestores := [],
    board := [], coldStarted := false, newPool := false }

/-! ## Refusals

| Code | IDs |
|---|---|
| `below_floor` | CP-036 |
| `h_lowered` | CP-007 |
| `ledger_unverified` | CP-019, CP-043 (and a node that is not ready, ledger 6) |
| `no_restore_statement` | CP-010 |
| `pending_gap` | CP-008 |
| `pending_min_lowered` | CP-040 |
| `recovery_early` | CP-035 |
| `restart_jump` | CP-009, CP-041 |
| `no-rule` | an event that no requirement defines, or a stated prohibition without a code (ledger 2, 3, 5, 7, 8, 9) |
| `outside-capability` | a value outside a domain sentence |
| `outside-state-domain` | a `--step` state outside `validState` |

The constructor order is the code order. -/

inductive Refusal where
  | belowFloor | hLowered | ledgerUnverified | noRule | noRestoreStatement | outsideCapability
  | outsideStateDomain | pendingGap | pendingMinLowered | recoveryEarly | restartJump
  deriving Repr, DecidableEq, BEq

def Refusal.code : Refusal → String
  | .belowFloor => "below_floor"
  | .hLowered => "h_lowered"
  | .ledgerUnverified => "ledger_unverified"
  | .noRestoreStatement => "no_restore_statement"
  | .pendingGap => "pending_gap"
  | .pendingMinLowered => "pending_min_lowered"
  | .recoveryEarly => "recovery_early"
  | .restartJump => "restart_jump"
  | .noRule => "no-rule"
  | .outsideCapability => "outside-capability"
  | .outsideStateDomain => "outside-state-domain"

def opt (b : Bool) (r : Refusal) : List Refusal := if b then [r] else []

def lookup (xs : List (Nat × Nat)) (k : Nat) : Nat := ((xs.find? (·.1 == k)).map (·.2)).getD 0

def poolOf (c : Cp) (pid : Nat) : Option Pool := c.pools.find? (·.pool == pid)

/-! ## Landing rules of the committee contract (CP-007 to CP-011) -/

/-- CP-007: `h` below the previous `h` for a pool of both checkpoints. -/
def lowered (c1 c2 : Cp) : Bool :=
  c2.pools.any (fun p => match poolOf c1 p.pool with
    | some p1 => decide (p.h < p1.h)
    | none => false)

/-- CP-008: `pending_min > h + 1` for a pool. -/
def gap (c2 : Cp) : Bool := c2.pools.any (fun p => decide (p.h + 1 < p.pendingMin))

/-- CP-009: seats whose boot counter `c2` keeps from `c1`. -/
def kept (n : Nat) (c1 c2 : Cp) : Nat :=
  ((List.range n).filter (fun s => lookup c1.bootCounters s == lookup c2.bootCounters s)).length

/-- CP-009, CP-041: for a pool of both, `cp2.h < cp1.h + B` or
`cp2.pending_min ≤ cp1.h + B` (the window was not jumped). -/
def noJump (p : Params) (c1 c2 : Cp) : Bool :=
  c2.pools.any (fun q => match poolOf c1 q.pool with
    | some q1 => decide (q.h < q1.h + p.B) || decide (q.pendingMin ≤ q1.h + p.B)
    | none => false)

/-- CP-009: with `slot_anchor` off, fewer than `w + 1` kept counters and no jump. -/
def jumpBad (p : Params) (c1 c2 : Cp) : Bool :=
  !p.slotAnchor && decide (kept p.n c1 c2 < p.w + 1) && noJump p c1 c2

-- CP-040 (DECISIONS 69 item 6): `pending_min` below the previous `pending_min`
-- for a pool of both checkpoints (ledger 11).
def pminLowered (c1 c2 : Cp) : Bool :=
  c2.pools.any (fun p => match poolOf c1 p.pool with
    | some p1 => decide (p.pendingMin < p1.pendingMin)
    | none => false)

/-- CP-010: a boot counter without the seat's `RestoreDone` for that counter in
this or an earlier landed checkpoint. -/
def noStatement (chain : List Cp) (c2 : Cp) : Bool :=
  let rs := c2.restores ++ chain.flatMap (·.restores)
  c2.bootCounters.any (fun (s, c) => !rs.any (fun r => r.seat == s && r.bootCtr == c))

/-- CP-011 (DECISIONS 69 item 6): the `restart_seq` the contract sets: this
checkpoint's `seq` when it carries, or follows a landed checkpoint that carries,
a `RestoreDone` with `whole_restart = true` that names a checkpoint at or above
the current `restart_seq`, else the current value. A carrier counts only while
its `seq` is above the current `restart_seq`: once the marker moved at or after
it, the checkpoint that moved it was the first (ledger 15). -/
def nextRestartSeq (chain : List Cp) (c2 : Cp) : Nat :=
  let cur := match chain with
    | [] => 0
    | c1 :: _ => c1.restartSeq
  let carriers := (c2 :: chain).filter (fun c => decide (cur < c.seq))
  if carriers.any (fun c => c.restores.any (fun r => r.whole && decide (cur ≤ r.cpSeq))) then c2.seq else cur

-- CP-041 (DECISIONS 69 item 6): with `slot_anchor` off, a `restart_seq` that the
-- contract sets (ledger 4) other than that of `cp1`, and no jump.
def movedJump (p : Params) (chain : List Cp) (c1 c2 : Cp) : Bool :=
  !p.slotAnchor && (nextRestartSeq chain c2 != c1.restartSeq) && noJump p c1 c2

/-- The refusals of a candidate checkpoint, in code order. The first checkpoint
has no predecessor; a checkpoint's `seq` follows the latest by one (ledger 2). -/
def landRefusals (p : Params) (chain : List Cp) (c2 : Cp) : List Refusal :=
  match chain with
  | [] => opt (c2.seq != 0) .noRule ++ opt (noStatement chain c2) .noRestoreStatement
            ++ opt (gap c2) .pendingGap
  | c1 :: _ =>
    opt (lowered c1 c2) .hLowered ++ opt (c2.seq != c1.seq + 1) .noRule
      ++ opt (noStatement chain c2) .noRestoreStatement ++ opt (gap c2) .pendingGap
      ++ opt (pminLowered c1 c2) .pendingMinLowered
      ++ opt (jumpBad p c1 c2 || movedJump p chain c1 c2) .restartJump

def latestRestartSeq (s : St) : Nat :=
  match s.chain with
  | [] => 0
  | c :: _ => c.restartSeq

/-! ## Signer rules (CP-012 to CP-015) -/

def nodupB {α : Type} [BEq α] : List α → Bool
  | [] => true
  | x :: xs => !xs.contains x && nodupB xs

/-- CP-012: no two leaves hold one `nf`, and none holds an `nf` of a landed `bf_root`. -/
def signBf (chain : List Cp) (leaves : List (Nat × Nat)) : Bool :=
  let landed := chain.flatMap (fun c => c.bf.map (·.2))
  nodupB (leaves.map (·.2)) && leaves.all (fun l => !landed.contains l.2)

/-- CP-013: exactly the leaves of the requests that ended in the interval, each
with its board outcome, and no leaf that gives an `auth` that Midnight records
as VOID another outcome. -/
def signSettle (leaves ended : List (Nat × Outcome)) (midnightVoid : List Nat) : Bool :=
  nodupB leaves && leaves.length == ended.length && leaves.all ended.contains
    && leaves.all (fun l => !(midnightVoid.contains l.1 && l.2 != .VOID))

/-- CP-014 (and CP-002): the pending fields for the indices that live requests
hold: the sorted list, its lowest entry or `h + 1`, its length. -/
def insertSorted (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys => if x ≤ y then x :: y :: ys else y :: insertSorted x ys

/-- Insertion sort, by structural recursion. -/
def sortNat : List Nat → List Nat
  | [] => []
  | x :: xs => insertSorted x (sortNat xs)

/-- CP-014 (DECISIONS 71): the floor of pool `pid`: "the `pending_min` of the
previous landed checkpoint for that pool". "A pool that the previous landed
checkpoint does not list has no floor" (0), and so has every pool before the
first landing. -/
def floorOf (chain : List Cp) (pid : Nat) : Nat :=
  match chain with
  | [] => 0
  | c :: _ => match poolOf c pid with
    | some q => q.pendingMin
    | none => 0

/-- CP-014: the sorted list of the live indices at or above the floor `lo`, its
lowest entry or `h + 1`, its length. -/
def pendingFields (lo h : Nat) (live : List Nat) : Nat × List Nat × Nat :=
  let l := sortNat (live.filter (fun i => decide (lo ≤ i)))
  (l.head?.getD (h + 1), l, l.length)

/-- CP-014: a signer signs the pool fields `p` for the indices `live` that live
requests hold only when they equal the fields over the list above the floor of
the latest landed checkpoint, the previous one for the checkpoint being signed. -/
def signPending (chain : List Cp) (p : Pool) (live : List Nat) : Bool :=
  pendingFields (floorOf chain p.pool) p.h live == (p.pendingMin, p.pending, p.pendingCount)

/-- CP-015: no second binding for one slot key (one slot nullifier `nf` of the
entry `(nf, e)`, CP-016) and no second put of one digest. -/
def signSeatRoot (log : List Entry) : Bool :=
  nodupB (log.filterMap (fun x => match x with | .bind nf _ => some nf | _ => none))
    && nodupB (log.filterMap (fun x => match x with | .put d => some d | _ => none))

/-! ## The node: continuity, classification and burns (CP-017 to CP-029) -/

/-- CP-017: the seats whose latest boot ticket has the counter that `c` records. -/
def continuous (n : Nat) (tickets : List (Nat × Nat)) (c : Cp) : Nat :=
  ((List.range n).filter (fun s => lookup tickets s == lookup c.bootCounters s)).length

/-- CP-018: fewer than `w + 1` continuous seats is a whole-committee restart. -/
def wholeRestart (p : Params) (tickets : List (Nat × Nat)) (c : Cp) : Bool :=
  decide (continuous p.n tickets c < p.w + 1)

/-- CP-020: the burn range `[pending_min, h + B]` of each pool of `c`. -/
def burnRanges (B : Nat) (c : Cp) : List (Nat × Nat × Nat) :=
  c.pools.map (fun q => (q.pool, q.pendingMin, q.h + B))

def inRanges (rs : List (Nat × Nat × Nat)) (pid i : Nat) : Bool :=
  rs.any (fun r => r.1 == pid && decide (r.2.1 ≤ i) && decide (i ≤ r.2.2))

def burned (s : St) (pid i : Nat) : Bool := inRanges s.burnC pid i

def burnSlot : ASlot → ASlot
  | .free => .burned
  | .bound _ => .burned
  | .burned => .burned

/-- CP-021: burn every `free` and `bound` slot of an account pool. -/
def burnAcct (a : Acct) : Acct := { a with slots := a.slots.map burnSlot }

/-- CP-029: a `free` slot with a covered binding becomes `bound` to its digest. -/
def anchorSlot (cov : List (Nat × Nat × Nat)) (aid : Nat) (i : Nat) : ASlot → ASlot
  | .free => match cov.find? (fun c => c.1 == aid && c.2.1 == i) with
    | some c => .bound c.2.2
    | none => .free
  | x => x

def anchorAcct (cov : List (Nat × Nat × Nat)) (a : Acct) : Acct :=
  { a with slots := (List.range a.slots.length).zip a.slots |>.map (fun (i, x) => anchorSlot cov a.id i x) }

/-- CP-022 (DECISIONS 69 item 7): each open session takes the burn ranges of its
pool at once, in its RAM view; the next seal records them (ledger 16). -/
def burnSessions (rs : List (Nat × Nat × Nat)) (ss : List (Nat × List (Nat × Nat × Nat))) :
    List (Nat × List (Nat × Nat × Nat)) :=
  ss.map (fun x => (x.1, rs.filter (·.1 == x.1) ++ x.2))

/-- CP-021 (DECISIONS 69 item 7): the account pools burn once per restart
generation; a read inside an open restart (one generation, CP-027) burns them no
second time (ledger 12). -/
def genBurn (s : St) : List Acct := if s.restartOpen then s.accts else s.accts.map burnAcct

/-- The ledger read of CP-018 to CP-023 and CP-028, CP-029 with a verified
snapshot: the boot tickets and the latest landed checkpoint `c`. -/
def readLedger (s : St) (c : Cp) (tickets : List (Nat × Nat)) (cov : List (Nat × Nat × Nat)) : St :=
  if wholeRestart s.params tickets c then
    { s with ready := true, tickets, restartOpen := true,
             markerPrev := if s.restartOpen then s.markerPrev else c.restartSeq,
             markerLanded := if s.restartOpen then s.markerLanded else false,
             -- CP-020, CP-023: the union of the ranges of every checkpoint read;
             -- CP-029: with slot anchors nothing burns
             burnC := if s.params.slotAnchor then s.burnC else burnRanges s.params.B c ++ s.burnC,
             -- CP-022: the open sessions burn the same ranges at once
             sessions := if s.params.slotAnchor then s.sessions else burnSessions (burnRanges s.params.B c) s.sessions,
             -- CP-021 burns the account pools; CP-029 binds free slots to covered digests
             accts := if s.params.slotAnchor then s.accts.map (anchorAcct cov) else genBurn s }
  else
    -- CP-028: a partial restart burns nothing
    { s with ready := true, tickets }

/-- CP-025 and CP-027 at a landing: the marker checkpoint writes the marker into
each account pool; the restart ends when the landed checkpoint also shows
`w + 1` continuous seats. -/
def landNode (s : St) (c : Cp) : St :=
  if s.restartOpen && decide (s.markerPrev < c.restartSeq) then
    { s with markerLanded := true, accts := s.accts.map (fun a => { a with mark := c.restartSeq }),
             restartOpen := !decide (s.params.w + 1 ≤ continuous s.params.n s.tickets c) }
  else s

-- CP-042 (DECISIONS 69 item 4): at a verified ledger read the node appends again
-- each statement it keeps in RAM that the board lost before a landed checkpoint
-- carried it.
def reappend (s : St) : List Restore :=
  s.board ++ s.pendingRestores.filter (fun r => !s.board.contains r)

/-! ## Recovery (CP-030 to CP-035) and other node rules -/

/-- CP-031, CP-032: the ECDSA slots the recovery group reshares. A slot is
`(seat, slot, covered binding, seat log read in full)`. -/
def reshare (slotAnchor : Bool) (slots : List (Nat × Nat × Bool × Bool)) : List (Nat × Nat) :=
  if slotAnchor then (slots.filter (fun x => !x.2.2.1 && x.2.2.2)).map (fun x => (x.1, x.2.1)) else []

/-- CP-036: ordered below `max(peer heights, latest checkpoint height)` with no
proof of non-service. -/
def belowFloor (s : St) (orderH : Nat) (peers : List Nat) (proof : Bool) : Bool :=
  let cpH := match s.chain with
    | [] => 0
    | c :: _ => c.boardHeight
  decide (orderH < max (peers.foldl max 0) cpH) && !proof

/-- CP-016: a seat-log entry at board height `h` counts once a landed root covers it. -/
def covered (s : St) (h : Nat) : Bool :=
  match s.chain with
  | [] => false
  | c :: _ => decide (h ≤ c.boardHeight)

/-- CP-037: release under an `anchor_before_release` charter waits for coverage. -/
def releaseOk (s : St) (anchor : Bool) (entryH : Nat) : Bool := !anchor || covered s entryH

/-- CP-003: a checkpoint is due when 60 s of board time passed. -/
def due (last now : Nat) : Bool := decide (last + interval ≤ now)

/-! ## Operations -/

inductive Op where
  /-- a candidate checkpoint lands at Midnight height `mh` (CP-007 to CP-011) -/
  | land (c : Cp) (mh : Nat)
  /-- the node boots and is not ready (CP-019) -/
  | boot
  /-- the node reads the ledger: `ok` is the snapshot verification, `tickets`
  the boot tickets, `cov` the covered bindings `(account, slot, digest)` -/
  | readLedger (ok : Bool) (tickets : List (Nat × Nat)) (cov : List (Nat × Nat × Nat))
  /-- the node creates a pool session (CP-024) -/
  | openSession (pool : Nat)
  /-- the node opens an account pool restored with these slots and mark (CP-026) -/
  | openAcct (a : Acct)
  /-- the node binds a slot of an account pool (CP-025) -/
  | bindAcct (aid i d : Nat)
  /-- the seat appends a `RestoreDone` to its seat log (CP-004, CP-016) -/
  | restoreDone (r : Restore)
  /-- the board loses its uncovered tail (CP-042) -/
  | loseTail
  /-- `recover(committee_id)` at Midnight height `mh` (CP-034, CP-035) -/
  | recover (mh : Nat)
  /-- a `coldStart` record with `signers` operator signatures, `intact` nodes with tier 0 (CP-030) -/
  | coldStart (intact signers : Nat)
  /-- the epoch key set of epoch `e`: acks per node, signatures (CP-006) -/
  | eks (e : Nat) (acks : List Nat) (sigs : Nat)
  /-- a non-TEE committee restarts at once (CP-033) -/
  | nonTeeRestart
  /-- queries that keep no state -/
  | signBf (leaves : List (Nat × Nat))
  | signSettle (leaves ended : List (Nat × Outcome)) (midnightVoid : List Nat)
  | signPending (p : Pool) (live : List Nat)
  | signSeatRoot (log : List Entry)
  | orderReq (orderH : Nat) (peers : List Nat) (proof : Bool)
  | covered (h : Nat)
  | releaseAnchor (anchor : Bool) (entryH : Nat)
  | reshare (slots : List (Nat × Nat × Bool × Bool))
  | due (last now : Nat)
  | mayReboot
  deriving Repr, DecidableEq

inductive Obs where
  | ok
  | refused (codes : List Refusal)
  | bool (b : Bool)
  | slots (xs : List (Nat × Nat))
  deriving Repr, DecidableEq

def hasAcct (s : St) (aid : Nat) : Bool := s.accts.any (·.id == aid)

def slotFree (s : St) (aid i : Nat) : Bool :=
  s.accts.any (fun a => a.id == aid && (a.slots[i]? == some .free))

def opRefusals (s : St) : Op → List Refusal
  | .land c _ => landRefusals s.params s.chain c
  | .boot => []
  | .readLedger ok tk _ =>
    -- CP-018 is a TEE rule; the non-TEE restart is CP-033 (ledger 3); with no
    -- landed checkpoint there is nothing to read (ledger 3)
    -- CP-019: a node with no verified view stays not ready; CP-043: a ready node
    -- goes not ready in `exec`, since a refusal changes nothing (ledger 6)
    opt (!ok && !s.ready) .ledgerUnverified
      ++ opt (s.params.mode == .NON_TEE || s.chain.isEmpty) .noRule
      ++ opt (tk.any (fun x => decide (s.params.n ≤ x.1)) || !nodupB (tk.map (·.1))) .outsideCapability
  | .openSession pid =>
    opt (!s.ready) .ledgerUnverified ++ opt (s.sessions.any (·.1 == pid)) .noRule
  -- CP-043: a release that needs a verified view (CP-037) waits while the node is not ready (ledger 6)
  | .releaseAnchor anchor _ => opt (anchor && !s.ready) .ledgerUnverified
  | .openAcct a => opt (!s.ready) .ledgerUnverified ++ opt (hasAcct s a.id) .noRule
  | .bindAcct aid i _ =>
    opt (!s.ready) .ledgerUnverified
      -- CP-025 forbids the bind and names no code (ledger 5); a slot that is not free (ledger 5)
      ++ opt ((s.restartOpen && !s.markerLanded) || !slotFree s aid i) .noRule
  | .restoreDone r => opt (decide (s.params.n ≤ r.seat)) .outsideCapability
  | .recover mh =>
    match s.chain with
    | [] => [.noRule]
    | _ => opt s.recovered .noRule ++ opt (decide (mh < s.lastLandMh + s.params.dRec)) .recoveryEarly
  | .coldStart intact signers =>
    opt (decide (s.params.t ≤ intact) || decide (signers < s.params.q) || s.coldStarted) .noRule
  | .eks _ acks sigs =>
    opt (acks.length != s.params.n || acks.any (fun a => decide (a < s.params.w)) || decide (sigs < s.params.q)) .noRule
  | .nonTeeRestart => opt (s.params.mode == .TEE) .noRule
  | .orderReq orderH peers proof => opt (belowFloor s orderH peers proof) .belowFloor
  | _ => []

def exec (s : St) : Op → St × Obs
  | .land c mh =>
    -- CP-011: the contract sets `restart_seq`; CP-003, CP-005: one checkpoint write
    let c' := { c with restartSeq := nextRestartSeq s.chain c }
    let s1 := { s with chain := c' :: s.chain, lastLandMh := mh, writes := .checkpoint :: s.writes,
                       pendingRestores := s.pendingRestores.filter (fun r => !c.restores.contains r),
                       board := s.board.filter (fun r => !c.restores.contains r) }
    (landNode s1 c', .ok)
  | .boot => ({ s with ready := false }, .ok)
  | .readLedger ok tk cov =>
    if ok then
      match s.chain with
      -- CP-042: the lost statements are appended again
      | c :: _ => (readLedger { s with board := reappend s } c tk cov, .ok)
      | [] => (s, .ok)
    -- CP-043: a later view that does not verify: keep the last verified view, not ready
    else ({ s with ready := false }, .ok)
  -- CP-024: a session created while the restart is open opens with the burns
  | .openSession pid =>
    let rs := if s.restartOpen then s.burnC.filter (·.1 == pid) else []
    ({ s with sessions := (pid, rs) :: s.sessions }, .ok)
  -- CP-026: a pool with a mark below `restart_seq` burns before any bind
  -- CP-021: before the marker lands every pool predates the restart and burns in this generation
  | .openAcct a =>
    let rsq := latestRestartSeq s
    let a' := if decide (a.mark < rsq) then { burnAcct a with mark := rsq }
      else if s.restartOpen && !s.markerLanded && !s.params.slotAnchor then burnAcct a else a
    ({ s with accts := a' :: s.accts }, .ok)
  | .bindAcct aid i d =>
    ({ s with accts := s.accts.map (fun a => if a.id == aid then { a with slots := a.slots.set i (.bound d) } else a) }, .ok)
  -- CP-004: the statement waits for a checkpoint that carries it
  | .restoreDone r => ({ s with pendingRestores := r :: s.pendingRestores, board := s.board ++ [r] }, .ok)
  -- CP-042: the board loses the statements of its uncovered tail; the RAM copies stay
  | .loseTail => ({ s with board := [] }, .ok)
  -- CP-034: the recovery transition, one record
  | .recover _ => ({ s with recovered := true, writes := .event :: s.writes }, .ok)
  -- CP-030: the cold start record; `E` reshares `x_f` and a new nonce pool is dealt
  | .coldStart _ _ => ({ s with coldStarted := true, newPool := true, writes := .event :: s.writes }, .ok)
  -- CP-006: one `EKS_e` record
  | .eks e _ _ => ({ s with writes := .eks e :: s.writes }, .ok)
  -- CP-033: no slot share is kept, a new nonce pool is dealt, every address refills
  | .nonTeeRestart =>
    ({ s with newPool := true, accts := s.accts.map (fun a => { burnAcct a with refill := true }) }, .ok)
  | .signBf leaves => (s, .bool (signBf s.chain leaves))
  | .signSettle leaves ended mv => (s, .bool (signSettle leaves ended mv))
  | .signPending p live => (s, .bool (signPending s.chain p live))
  | .signSeatRoot log => (s, .bool (signSeatRoot log))
  | .orderReq _ _ _ => (s, .ok)
  | .covered h => (s, .bool (covered s h))
  | .releaseAnchor a h => (s, .bool (releaseOk s a h))
  | .reshare xs => (s, .slots (reshare s.params.slotAnchor xs))
  | .due last now => (s, .bool (due last now))
  | .mayReboot => (s, .bool s.pendingRestores.isEmpty)

def apply (s : St) (op : Op) : St × Obs :=
  match opRefusals s op with
  | [] => exec s op
  | rs => (s, .refused rs)

def runOps : St → List Op → St × List Obs
  | s, [] => (s, [])
  | s, op :: ops =>
    let (s1, o) := apply s op
    let (s2, os) := runOps s1 ops
    (s2, o :: os)

def run (s : St) (ops : List Op) : St := (runOps s ops).1

/-! ## The state domain -/

/-- `chainOk`: consecutive landed checkpoints never lower `h` (CP-007) or
`pending_min` (CP-040), and no landed pool has `pending_min > h + 1` (CP-008). -/
def chainOk : List Cp → Bool
  | [] => true
  | [c] => !gap c
  | c2 :: c1 :: rest => !lowered c1 c2 && !gap c2 && !pminLowered c1 c2 && chainOk (c1 :: rest)

def validState (s : St) : Bool := paramsOk s.params && chainOk s.chain

def stepRefusals (s : St) : List Refusal := opt (!validState s) .outsideStateDomain

theorem stepRefusals_nil_iff (s : St) : stepRefusals s = [] ↔ validState s = true := by
  unfold stepRefusals opt; cases validState s <;> simp

/-! ## Theorems: the contract -/

theorem apply_refused (s : St) (op : Op) (h : opRefusals s op ≠ []) : (apply s op).1 = s := by
  unfold apply; split
  · contradiction
  · rfl

theorem landNode_chain (s : St) (c : Cp) : (landNode s c).chain = s.chain := by
  unfold landNode; split <;> rfl

theorem landNode_params (s : St) (c : Cp) : (landNode s c).params = s.params := by
  unfold landNode; split <;> rfl

theorem landNode_burnC (s : St) (c : Cp) : (landNode s c).burnC = s.burnC := by
  unfold landNode; split <;> rfl

theorem readLedger_chain (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat)) :
    (readLedger s c tk cov).chain = s.chain := by
  unfold readLedger; split <;> rfl

theorem readLedger_params (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat)) :
    (readLedger s c tk cov).params = s.params := by
  unfold readLedger; split <;> rfl

theorem gap_nextRestart (chain : List Cp) (c : Cp) :
    gap { c with restartSeq := nextRestartSeq chain c } = gap c := rfl

theorem lowered_nextRestart (c1 : Cp) (chain : List Cp) (c : Cp) :
    lowered c1 { c with restartSeq := nextRestartSeq chain c } = lowered c1 c := rfl

theorem pminLowered_nextRestart (c1 : Cp) (chain : List Cp) (c : Cp) :
    pminLowered c1 { c with restartSeq := nextRestartSeq chain c } = pminLowered c1 c := rfl

theorem opt_nil (b : Bool) (r : Refusal) : opt b r = [] ↔ b = false := by
  cases b <;> simp [opt]

/-- The landing checks that hold when a candidate after `c1` lands. -/
theorem land_ok (p : Params) (c1 : Cp) (rest : List Cp) (c : Cp)
    (h : landRefusals p (c1 :: rest) c = []) :
    lowered c1 c = false ∧ gap c = false ∧ pminLowered c1 c = false
      ∧ jumpBad p c1 c = false ∧ movedJump p (c1 :: rest) c1 c = false := by
  simp only [landRefusals, List.append_eq_nil_iff, opt_nil, Bool.or_eq_false_iff] at h
  exact ⟨h.1.1.1.1.1, h.1.1.2, h.1.2, h.2.1, h.2.2⟩

/-- Every step keeps the contract's chain rules (CP-007, CP-008) and the parameters. -/
theorem apply_chainOk (s : St) (op : Op) (h : chainOk s.chain = true) :
    chainOk (apply s op).1.chain = true ∧ (apply s op).1.params = s.params := by
  unfold apply
  split
  · rename_i hr
    cases op with
    | land c mh =>
      simp only [exec]
      rw [landNode_chain, landNode_params]
      refine ⟨?_, rfl⟩
      simp only [opRefusals] at hr
      cases hc : s.chain with
      | nil =>
        rw [hc] at hr
        simp [landRefusals, opt] at hr
        simp [chainOk, gap_nextRestart, hr.2.2]
      | cons c1 rest =>
        rw [hc] at hr h
        have k := land_ok s.params c1 rest c hr
        simp only [chainOk, gap_nextRestart, lowered_nextRestart, pminLowered_nextRestart, k.1, k.2.1,
          k.2.2.1, h]
        rfl
    | readLedger ok tk cov =>
      cases ok with
      | true =>
        simp only [exec, ↓reduceIte]
        split
        · exact ⟨by rw [readLedger_chain]; exact h, readLedger_params _ _ _ _⟩
        · exact ⟨h, rfl⟩
      | false => exact ⟨h, rfl⟩
    | _ => exact ⟨h, rfl⟩
  · exact ⟨h, rfl⟩

theorem runOps_chainOk (s : St) (ops : List Op) (h : chainOk s.chain = true) :
    chainOk (runOps s ops).1.chain = true ∧ (runOps s ops).1.params = s.params := by
  induction ops generalizing s with
  | nil => exact ⟨h, rfl⟩
  | cons op ops ih =>
    have h1 := apply_chainOk s op h
    have h2 := ih _ h1.1
    exact ⟨h2.1, h2.2.trans h1.2⟩

/-- CP-007 and CP-008 over every run from `init`: the landed chain never lowers a
floor and no landed pool has `pending_min > h + 1`. -/
theorem cp007_cp008_run_chainOk (p : Params) (ops : List Op) : chainOk (run (init p) ops).chain = true :=
  (runOps_chainOk _ ops rfl).1

theorem chainOk_head_nogap (c : Cp) (rest : List Cp) (h : chainOk (c :: rest) = true) : gap c = false := by
  cases rest with
  | nil => simpa [chainOk] using h
  | cons c1 r =>
    simp only [chainOk, Bool.and_eq_true, Bool.not_eq_true'] at h
    exact h.1.1.2

/-- CP-008 as a pool fact: a pool of the latest landed checkpoint has `pending_min ≤ h + 1`. -/
theorem gap_false_pool (c : Cp) (h : gap c = false) (q : Pool) (hq : q ∈ c.pools) :
    q.pendingMin ≤ q.h + 1 := by
  simp [gap] at h
  have := h q hq; omega

theorem mem_insertSorted (x y : Nat) (l : List Nat) (h : y ∈ insertSorted x l) : y = x ∨ y ∈ l := by
  induction l with
  | nil => simp [insertSorted] at h; exact Or.inl h
  | cons z zs ih =>
    unfold insertSorted at h
    split at h
    · simp at h; rcases h with h | h | h
      · exact Or.inl h
      · exact Or.inr (by simp [h])
      · exact Or.inr (by simp [h])
    · simp at h; rcases h with h | h
      · exact Or.inr (by simp [h])
      · rcases ih h with h' | h'
        · exact Or.inl h'
        · exact Or.inr (by simp [h'])

theorem mem_sortNat (y : Nat) (l : List Nat) (h : y ∈ sortNat l) : y ∈ l := by
  induction l with
  | nil => simp [sortNat] at h
  | cons x xs ih =>
    simp only [sortNat] at h
    rcases mem_insertSorted x y _ h with h' | h'
    · simp [h']
    · simp [ih h']

/-- CP-014 (DECISIONS 71): the `pending_min` of the list above the floor `lo` is
never below `lo` when `lo ≤ h + 1`. -/
theorem cp014_pmin_floor (lo h : Nat) (live : List Nat) (hlo : lo ≤ h + 1) :
    lo ≤ (pendingFields lo h live).1 := by
  unfold pendingFields
  generalize hl : sortNat (live.filter (fun i => decide (lo ≤ i))) = l
  cases l with
  | nil => simpa using hlo
  | cons x xs =>
    have hx : x ∈ live.filter (fun i => decide (lo ≤ i)) := mem_sortNat x _ (by rw [hl]; simp)
    simp at hx ⊢; exact hx.2

/-- CP-014 with CP-040 (DECISIONS 71, finding F7): on a landed chain, pool fields
that a signer signs for any live indices, with `h` not below the landed `h`,
never lower the landed `pending_min`, so CP-040 never refuses them. -/
theorem cp014_cp040_floor_kept (c : Cp) (rest : List Cp) (q p : Pool) (live : List Nat)
    (hok : chainOk (c :: rest) = true) (hq : poolOf c p.pool = some q) (hh : q.h ≤ p.h)
    (hs : signPending (c :: rest) p live = true) : q.pendingMin ≤ p.pendingMin := by
  have hmem : q ∈ c.pools := List.mem_of_find?_eq_some hq
  have hgap := gap_false_pool c (chainOk_head_nogap c rest hok) q hmem
  have hfl : floorOf (c :: rest) p.pool = q.pendingMin := by simp [floorOf, hq]
  simp only [signPending, hfl, beq_iff_eq] at hs
  have := cp014_pmin_floor q.pendingMin p.h live (by omega)
  rw [hs] at this
  exact this

/-! ## Theorems: the restart (C16) -/

theorem inRanges_append_left (a b : List (Nat × Nat × Nat)) (pid i : Nat) (h : inRanges a pid i = true) :
    inRanges (a ++ b) pid i = true := by
  unfold inRanges at *; rw [List.any_append, h, Bool.true_or]

theorem inRanges_append_right (a b : List (Nat × Nat × Nat)) (pid i : Nat) (h : inRanges b pid i = true) :
    inRanges (a ++ b) pid i = true := by
  unfold inRanges at *; rw [List.any_append, h, Bool.or_true]

/-- CP-020: after a whole-committee restart without slot anchors, every index in
`[pending_min, h + B]` of each pool of the checkpoint read is burned. -/
theorem C16_restart_burns_range (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat))
    (hw : wholeRestart s.params tk c = true) (ha : s.params.slotAnchor = false)
    (q : Pool) (hq : q ∈ c.pools) (i : Nat) (h1 : q.pendingMin ≤ i) (h2 : i ≤ q.h + s.params.B) :
    burned (readLedger s c tk cov) q.pool i = true := by
  have hin : inRanges (burnRanges s.params.B c) q.pool i = true := by
    simp only [inRanges, burnRanges, List.any_map, List.any_eq_true]
    exact ⟨q, hq, by simp [h1, h2]⟩
  unfold readLedger burned
  simp only [hw, ite_true, ha, Bool.false_eq_true, ite_false]
  exact inRanges_append_left _ _ _ _ hin

theorem readLedger_burn_mono (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat))
    (pid i : Nat) (h : burned s pid i = true) : burned (readLedger s c tk cov) pid i = true := by
  unfold readLedger burned
  split
  · simp only
    split
    · exact h
    · exact inRanges_append_right _ _ _ _ h
  · exact h

/-- CP-023: the burns only grow, so the node burns the union over every checkpoint read. -/
theorem apply_burn_mono (s : St) (op : Op) (pid i : Nat) (h : burned s pid i = true) :
    burned (apply s op).1 pid i = true := by
  unfold apply
  split
  · cases op with
    | land c mh =>
      simp only [exec, burned, landNode_burnC]
      exact h
    | readLedger ok tk cov =>
      cases ok with
      | true =>
        simp only [exec, ↓reduceIte]
        split
        · exact readLedger_burn_mono _ _ _ _ _ _ h
        · exact h
      | false => exact h
    | _ => exact h
  · exact h

theorem runOps_burn_mono (s : St) (ops : List Op) (pid i : Nat) (h : burned s pid i = true) :
    burned (runOps s ops).1 pid i = true := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_burn_mono s op pid i h)

/-- SL-012 window of checkpoint `c` for pool `q`: `h < ℓ ≤ h + B`, or
`pending_min ≤ ℓ ≤ h` (the pending proof only narrows the second part). -/
def inWindow (B : Nat) (q : Pool) (l : Nat) : Bool :=
  (decide (q.h < l) && decide (l ≤ q.h + B)) || (decide (q.pendingMin ≤ l) && decide (l ≤ q.h))

/-- C16 (CP-020, CP-023, CP-038, the state part of one nonce use): in every run
from `init`, when the node then classifies a whole-committee restart without
slot anchors, every index that could pass the window of the latest landed
checkpoint is burned, and stays burned over any later operations. -/
theorem C16_run_window_burned (p : Params) (ops : List Op) (tk : List (Nat × Nat))
    (cov : List (Nat × Nat × Nat)) (later : List Op) (ha : p.slotAnchor = false) (c : Cp) (rest : List Cp)
    (hc : (run (init p) ops).chain = c :: rest)
    (hw : wholeRestart p tk c = true)
    (q : Pool) (hq : q ∈ c.pools) (l : Nat) (hl : inWindow p.B q l = true) :
    burned (run (readLedger (run (init p) ops) c tk cov) later) q.pool l = true := by
  have hok := runOps_chainOk (init p) ops rfl
  have hp : (run (init p) ops).params = p := hok.2
  have hg : gap c = false := chainOk_head_nogap c rest (by
    have := hok.1; unfold run at hc; rw [hc] at this; exact this)
  have hpm := gap_false_pool c hg q hq
  simp [inWindow] at hl
  apply runOps_burn_mono
  apply C16_restart_burns_range _ c tk cov (by rw [hp]; exact hw) (by rw [hp]; exact ha) q hq l
  · omega
  · rw [hp]; omega

/-- CP-024: a session created while the restart is open holds every burned index of its pool. -/
theorem C16_session_burned (s : St) (pid i : Nat) (hr : s.restartOpen = true) (hready : s.ready = true)
    (hnew : s.sessions.any (·.1 == pid) = false) (hb : burned s pid i = true) :
    ∃ rs, ((pid, rs) ∈ (apply s (.openSession pid)).1.sessions) ∧ inRanges rs pid i = true := by
  have hrf : opRefusals s (.openSession pid) = [] := by simp [opRefusals, opt, hready, hnew]
  refine ⟨s.burnC.filter (·.1 == pid), ?_, ?_⟩
  · simp [apply, hrf, exec, hr]
  · simp only [burned, inRanges, List.any_eq_true] at hb ⊢
    obtain ⟨r, hr1, hr2⟩ := hb
    refine ⟨r, ?_, hr2⟩
    simp only [Bool.and_eq_true, beq_iff_eq] at hr2
    simp [List.mem_filter, hr1, hr2.1.1]

/-- CP-021: when a node classifies a whole-committee restart without slot anchors
and no restart is open (the first read of a restart generation), no account slot
is `free` or `bound` after the read. -/
theorem C16_acct_burned (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat))
    (hw : wholeRestart s.params tk c = true) (ha : s.params.slotAnchor = false)
    (hg : s.restartOpen = false) :
    ∀ a ∈ (readLedger s c tk cov).accts, ∀ x ∈ a.slots, x = .burned := by
  unfold readLedger genBurn
  simp only [hw, ite_true, ha, hg, Bool.false_eq_true, ite_false]
  intro a hA x hx
  simp only [List.mem_map] at hA
  obtain ⟨b, _, rfl⟩ := hA
  simp only [burnAcct, List.mem_map] at hx
  obtain ⟨y, _, rfl⟩ := hx
  cases y <;> rfl

/-- CP-028: a boot with `w + 1` continuous seats burns nothing. -/
theorem cp028_partial_no_burn (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat))
    (hw : wholeRestart s.params tk c = false) :
    (readLedger s c tk cov).burnC = s.burnC ∧ (readLedger s c tk cov).accts = s.accts := by
  unfold readLedger; simp [hw]

/-- CP-025: while the restart is open and no marker checkpoint has landed, no
account-pool slot is bound. -/
theorem cp025_no_bind (s : St) (aid i d : Nat) (h1 : s.restartOpen = true) (h2 : s.markerLanded = false) :
    (apply s (.bindAcct aid i d)).1 = s :=
  apply_refused s _ (by simp [opRefusals, opt, h1, h2])

/-- CP-032: without slot anchors the recovery group reshares no ECDSA slot. -/
theorem cp032_no_reshare (xs : List (Nat × Nat × Bool × Bool)) : reshare false xs = [] := rfl

/-- CP-031: with slot anchors no reshared slot has a covered binding, and every
reshared slot's seat log was read in full. -/
theorem cp031_reshare_safe (xs : List (Nat × Nat × Bool × Bool)) (sl : Nat × Nat) (h : sl ∈ reshare true xs) :
    ∃ x ∈ xs, (x.1, x.2.1) = sl ∧ x.2.2.1 = false ∧ x.2.2.2 = true := by
  simp only [reshare, ite_true, List.mem_map, List.mem_filter] at h
  obtain ⟨x, ⟨hx, hb⟩, rfl⟩ := h
  simp only [Bool.and_eq_true, Bool.not_eq_true'] at hb
  exact ⟨x, hx, rfl, hb.1, hb.2⟩

/-! ## Theorems: DECISIONS 69 (CP-022, CP-039 to CP-043) -/

/-- CP-040 over every run from `init`: no landed checkpoint lowers the
`pending_min` of a pool of its predecessor. -/
theorem cp040_run_pmin (p : Params) (ops : List Op) (c2 c1 : Cp) (rest : List Cp)
    (h : (run (init p) ops).chain = c2 :: c1 :: rest) : pminLowered c1 c2 = false := by
  have := cp007_cp008_run_chainOk p ops
  rw [h] at this
  simp only [chainOk, Bool.and_eq_true, Bool.not_eq_true'] at this
  exact this.1.2

theorem noJump_false_pool (p : Params) (c1 c2 : Cp) (h : noJump p c1 c2 = false) (q : Pool) (hq : q ∈ c2.pools)
    (q1 : Pool) (h1 : poolOf c1 q.pool = some q1) : q1.h + p.B ≤ q.h ∧ q1.h + p.B < q.pendingMin := by
  simp only [noJump, List.any_eq_false] at h
  have := h q hq
  rw [h1] at this
  simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at this
  omega

/-- CP-041 (and the jump of CP-039): with slot anchors off, a checkpoint that
lands after `c1` and moves `restart_seq` has, for each pool of both,
`h ≥ c1.h + B` and `pending_min > c1.h + B`: it retires one window. -/
theorem cp041_jump (s : St) (c : Cp) (mh : Nat) (c1 : Cp) (rest : List Cp) (hc : s.chain = c1 :: rest)
    (ha : s.params.slotAnchor = false) (hacc : opRefusals s (.land c mh) = [])
    (hm : nextRestartSeq s.chain c ≠ c1.restartSeq)
    (q : Pool) (hq : q ∈ c.pools) (q1 : Pool) (h1 : poolOf c1 q.pool = some q1) :
    q1.h + s.params.B ≤ q.h ∧ q1.h + s.params.B < q.pendingMin := by
  simp only [opRefusals, hc] at hacc
  have k := (land_ok _ _ _ _ hacc).2.2.2.2
  rw [hc] at hm
  simp only [movedJump, ha, Bool.not_false, Bool.true_and, bne_iff_ne, ne_eq, hm, not_false_eq_true,
    Bool.and_eq_false_imp, forall_const] at k
  exact noJump_false_pool _ _ _ k q hq q1 h1

/-- CP-022: when a node reads a whole-committee restart without slot anchors,
each of its open sessions holds at once every index of `[pending_min, h + B]` of
its pool of the checkpoint read. -/
theorem cp022_sessions_burned (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat))
    (hw : wholeRestart s.params tk c = true) (ha : s.params.slotAnchor = false)
    (q0 : Nat) (rs : List (Nat × Nat × Nat)) (hs : (q0, rs) ∈ s.sessions)
    (q : Pool) (hq : q ∈ c.pools) (hp : q.pool = q0) (i : Nat) (h1 : q.pendingMin ≤ i) (h2 : i ≤ q.h + s.params.B) :
    ∃ rs', (q0, rs') ∈ (readLedger s c tk cov).sessions ∧ inRanges rs' q0 i = true := by
  unfold readLedger
  simp only [hw, ite_true, ha, Bool.false_eq_true, ite_false]
  refine ⟨(burnRanges s.params.B c).filter (·.1 == q0) ++ rs, ?_, ?_⟩
  · simp only [burnSessions, List.mem_map]
    exact ⟨(q0, rs), hs, rfl⟩
  · apply inRanges_append_left
    simp only [inRanges, List.any_eq_true, List.mem_filter, burnRanges, List.mem_map]
    exact ⟨(q.pool, q.pendingMin, q.h + s.params.B), ⟨⟨q, hq, rfl⟩, by simp [hp]⟩, by simp [hp, h1, h2]⟩

theorem readLedger_board (s : St) (c : Cp) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat)) :
    (readLedger s c tk cov).board = s.board := by
  unfold readLedger; split <;> rfl

/-- CP-042: at a verified ledger read every statement the node keeps in RAM
(appended and not yet carried) is on the board again. -/
theorem cp042_reappend (s : St) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat)) (c : Cp) (rest : List Cp)
    (hc : s.chain = c :: rest) (hacc : opRefusals s (.readLedger true tk cov) = [])
    (r : Restore) (hr : r ∈ s.pendingRestores) :
    r ∈ (apply s (.readLedger true tk cov)).1.board := by
  simp only [apply, hacc, exec, ↓reduceIte, hc, readLedger_board, reappend, List.mem_append, List.mem_filter,
    Bool.not_eq_true', List.contains_eq_mem, decide_eq_false_iff_not]
  by_cases hb : r ∈ s.board
  · exact Or.inl hb
  · exact Or.inr ⟨hr, hb⟩

/-- CP-043: a ready node whose later ledger view does not verify keeps the last
verified view (every other field) and goes not ready. -/
theorem cp043_keep_view (s : St) (tk : List (Nat × Nat)) (cov : List (Nat × Nat × Nat))
    (hacc : opRefusals s (.readLedger false tk cov) = []) :
    (apply s (.readLedger false tk cov)).1 = { s with ready := false } := by
  simp [apply, hacc, exec]

/-- CP-043: a node that is not ready binds nothing and answers `ledger_unverified`
to an anchored release, until a new view verifies. -/
theorem cp043_not_ready (s : St) (hr : s.ready = false) (aid i d e : Nat) :
    (apply s (.bindAcct aid i d)).1 = s ∧ (apply s (.releaseAnchor true e)).2 = .refused [.ledgerUnverified] := by
  refine ⟨apply_refused s _ (by simp [opRefusals, opt, hr]), ?_⟩
  simp [apply, opRefusals, opt, hr]

/-! ## Bounded loss (CP-039) -/

/-- The number of `i` in `[lo, lo + k)` with `p i`. -/
def cnt (p : Nat → Bool) : Nat → Nat → Nat
  | _, 0 => 0
  | lo, k + 1 => (p lo).toNat + cnt p (lo + 1) k

theorem cnt_or (p r : Nat → Bool) (lo k : Nat) :
    cnt (fun i => p i || r i) lo k ≤ cnt p lo k + cnt r lo k := by
  induction k generalizing lo with
  | zero => simp [cnt]
  | succ k ih =>
    simp only [cnt]
    have := ih (lo + 1)
    cases p lo <;> cases r lo <;> simp [Bool.toNat] <;> omega

theorem cnt_above (h lo k : Nat) : cnt (fun i => decide (h < i)) lo k ≤ min k (lo + k - (h + 1)) := by
  induction k generalizing lo with
  | zero => simp [cnt]
  | succ k ih =>
    simp only [cnt]
    have := ih (lo + 1)
    by_cases hl : h < lo
    · simp [hl, Bool.toNat]; omega
    · simp [hl, Bool.toNat]; omega

theorem cnt_zero (x lo k : Nat) (h : x < lo) : cnt (fun i => i == x) lo k = 0 := by
  induction k generalizing lo with
  | zero => rfl
  | succ k ih =>
    simp only [cnt]
    have h1 : (lo == x) = false := by simp; omega
    simp only [h1, ih (lo + 1) (by omega)]; rfl

theorem cnt_eq (x lo k : Nat) : cnt (fun i => i == x) lo k ≤ 1 := by
  induction k generalizing lo with
  | zero => simp [cnt]
  | succ k ih =>
    simp only [cnt]
    by_cases hx : lo = x
    · subst hx; simp [cnt_zero lo (lo + 1) k (by omega)]
    · have h1 : (lo == x) = false := by simp [hx]
      simp only [h1]; have := ih (lo + 1); simp [Bool.toNat]; omega

theorem cnt_congr (p r : Nat → Bool) (h : ∀ i, p i = r i) (lo k : Nat) : cnt p lo k = cnt r lo k := by
  have : p = r := funext h
  rw [this]

theorem cnt_false (lo k : Nat) : cnt (fun _ => false) lo k = 0 := by
  induction k generalizing lo with
  | zero => rfl
  | succ k ih => simp only [cnt, ih]; rfl

theorem cnt_mem (xs : List Nat) (lo k : Nat) : cnt (fun i => xs.contains i) lo k ≤ xs.length := by
  induction xs with
  | nil => rw [cnt_congr _ (fun _ => false) (by intro i; rfl), cnt_false]; simp
  | cons x xs ih =>
    rw [cnt_congr _ (fun i => (i == x) || xs.contains i) (by intro i; simp only [List.contains_cons])]
    have := cnt_or (fun i => i == x) (fun i => xs.contains i) lo k
    have := cnt_eq x lo k
    simp only [List.length_cons]; omega

/-- A burned index is usable when it lies above `h` or a live request holds it. -/
def usable (q : Pool) (i : Nat) : Bool := decide (q.h < i) || q.pending.contains i

/-- C16, CP-039 (bounded loss): the burn range `[pending_min, h + B]` of one
pool of one checkpoint read holds at most `B` usable indices plus its pending
indices, for every landed pool (`pending_min ≤ h + 1`, CP-008). -/
theorem C16_bounded_loss (B : Nat) (q : Pool) (hg : q.pendingMin ≤ q.h + 1) :
    cnt (usable q) q.pendingMin (q.h + B + 1 - q.pendingMin) ≤ B + q.pending.length := by
  have h1 := cnt_or (fun i => decide (q.h < i)) (fun i => q.pending.contains i) q.pendingMin (q.h + B + 1 - q.pendingMin)
  have h2 := cnt_above q.h q.pendingMin (q.h + B + 1 - q.pendingMin)
  have h3 := cnt_mem q.pending q.pendingMin (q.h + B + 1 - q.pendingMin)
  have : cnt (usable q) q.pendingMin (q.h + B + 1 - q.pendingMin)
      = cnt (fun i => decide (q.h < i) || q.pending.contains i) q.pendingMin (q.h + B + 1 - q.pendingMin) := rfl
  omega

end SplitCheckpoint
