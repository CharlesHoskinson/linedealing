/-!
# Handoff oracle (split-handoff, HO-001 to HO-068)

The executable reference semantics of the OpenSpec capability `split-handoff`
(`openspec/changes/add-split-line-dealing/specs/split-handoff/spec.md`), the
committee handoff of LOOP item 41.

The state is the board's and the committee contract's view of one committee
line: the epochs with roster, parameters and status, the sharings of the
standing secrets (`x_f` per curve and every ECDSA committee slot) per epoch,
the one open or last handoff record, the requests with their binding epoch and
sweep position, the board's slot states, the public keys `X_f`, the user state,
the addresses, the history of activations (board validator sets), the landed
epoch of the committee contract, and the whole-committee restart flag.

Two clocks (ledger 2): `mh` is the latest final Midnight height (every
deadline, window and grace end counts Midnight blocks: `m_R`, `m_D`, `Δ_rot`,
`Δ_grace`, `Δ_sweep`, `Δ_cw`), and `pos` is the board position (validator
sets, sweep positions and request ownership count board positions).

Abstractions (formal plugin, practice 11):
* A sharing is a record `{secret, const, epoch, holders, st}`: `const` stands for
  the public constant term (the Feldman commitment's constant), `holders` for
  the seats that hold a share. Shares themselves, polynomials and ciphertexts
  are outside the state; the hiding of a dealing is an exception (O5).
* A carry dealing is accepted or refused by its constant-term check (HO-019),
  which enters as a flag. A complaint is a valid complaint.
* `H(Q)` is `Q` itself (collision free). The arm heartbeat is the number of
  target partials it carries; its verification under `X_f` is a flag of the
  activation record.
* Operator keys are seat numbers.
-/

namespace SplitHandoff

/-! ## Domains -/

/-- The two curves of `x_f`: secp256k1 and edwards25519 (HO-056). -/
inductive Curve where
  | secp | ed
  deriving Repr, DecidableEq

/-- `X_f` per curve (HO-056). -/
structure XF where
  secp : Nat
  ed : Nat
  deriving Repr, DecidableEq

def XF.get (x : XF) : Curve → Nat
  | .secp => x.secp
  | .ed => x.ed

/-- A standing secret: `x_f` of a curve, or ECDSA committee slot `i` of address `a` (HO-018). -/
inductive SecretId where
  | xf (c : Curve)
  | slot (a i : Nat)
  deriving Repr, DecidableEq

/-- The state of a committee slot (HO-044): `free`, `bound` to a ticket, or `burned`. -/
inductive SlotSt where
  | free
  | bound (tk : Nat)
  | burned
  deriving Repr, DecidableEq

/-- One Shamir sharing of one secret among one roster (HO-018, HO-055). -/
structure Sharing where
  secret : SecretId
  /-- the public constant term: `X_f` for `x_f`, the slot's commitment for a slot -/
  const : Nat
  epoch : Nat
  holders : List Nat
  /-- the state of this epoch's copy of a slot (HO-024, HO-044); `free` for `x_f` -/
  st : SlotSt
  deriving Repr, DecidableEq

/-- `CLOSED` of HO-001 is the status `closed`. -/
inductive EStatus where
  | current | grace | closed
  deriving Repr, DecidableEq

/-- One epoch: roster, `(n, f, q, t)`, status, grace end (Midnight) and the sweep flag. -/
structure EpochRec where
  id : Nat
  roster : List Nat
  n : Nat
  f : Nat
  q : Nat
  t : Nat
  status : EStatus
  graceEnd : Nat
  swept : Bool
  deriving Repr, DecidableEq

/-- HO-001: the phases of a target epoch. -/
inductive Phase where
  | IDLE | QUEUED | ROTATING | ARMED | HANDED_OVER | ABORTED
  deriving Repr, DecidableEq

/-- HO-002: the fields of a ROTATE, with the count of its valid governance signatures (HO-003). -/
structure Rotate where
  target : Nat
  source : Nat
  roster : List Nat
  n : Nat
  f : Nat
  q : Nat
  t : Nat
  emergency : Bool
  sigs : Nat
  deriving Repr, DecidableEq

/-- The handoff record of the last ROTATE (HO-001, HO-002, HO-012, HO-015, HO-020,
HO-021, HO-030, HO-064). `srcRoster` and `tQ` are the source roster and `t` at the order. -/
structure Handoff where
  phase : Phase
  rot : Rotate
  srcRoster : List Nat
  tQ : Nat
  mR : Nat
  mD : Nat
  eks : Bool
  /-- carry dealers in board order, each with the Midnight height of its batch -/
  dealt : List (Nat × Nat)
  disq : List Nat
  /-- READY posts `(seat, Q, h_S)` -/
  readys : List (Nat × List Nat × Nat)
  lastBatch : Nat
  /-- the board height of the block that commits the arm heartbeat (HO-064) -/
  H : Nat
  deriving Repr, DecidableEq

/-- A request: binding epoch, sweep position (HO-036, HO-043), whether it is live,
and the committee slots it names. -/
structure Req where
  id : Nat
  bind : Nat
  sweep : Option Nat
  live : Bool
  slots : List (Nat × Nat)
  deriving Repr, DecidableEq

/-- HO-057: the user state the handoff never touches. -/
structure User where
  id : Nat
  shard : Nat
  tweak : Nat
  pool : Nat
  sealed : Nat
  slotRoot : Nat
  asset : Nat
  deriving Repr, DecidableEq

/-- An address `X = X_f + tw·G + Σ X_a` of a user on a curve, with its ECDSA slot indices. -/
structure Addr where
  id : Nat
  curve : Curve
  user : Nat
  shard : Nat
  ecdsa : Bool
  slots : List Nat
  deriving Repr, DecidableEq

/-- `Δ_rot`, `Δ_grace`, `Δ_sweep` and `Δ_cw`, all in Midnight blocks (HO-012, HO-020, HO-042). -/
structure Params where
  deltaRot : Nat
  deltaGrace : Nat
  deltaSweep : Nat
  deltaCw : Nat
  deriving Repr, DecidableEq

structure St where
  params : Params
  /-- the latest final Midnight height -/
  mh : Nat
  /-- the board position -/
  pos : Nat
  cur : Nat
  epochs : List EpochRec
  sharings : List Sharing
  ho : Handoff
  requests : List Req
  /-- the board's slot states; a slot it does not name is `free` -/
  board : List ((Nat × Nat) × SlotSt)
  xf : XF
  users : List User
  addrs : List Addr
  /-- activations `(H, target)`, newest first (HO-032) -/
  handovers : List (Nat × Nat)
  /-- the epoch of the latest landed checkpoint (HO-003, HO-050) -/
  landed : Nat
  /-- a whole-committee restart is open (HO-010) -/
  restart : Bool
  /-- joining seats pending in the Node Registry (HO-013) -/
  pending : List Nat
  deriving Repr, DecidableEq

/-! ## Lookups -/

def lookupE : List EpochRec → Nat → Option EpochRec
  | [], _ => none
  | r :: rs, e => if r.id = e then some r else lookupE rs e

def statusOf (s : St) (e : Nat) : Option EStatus := (lookupE s.epochs e).map (·.status)
def rosterOf (s : St) (e : Nat) : List Nat := ((lookupE s.epochs e).map (·.roster)).getD []
def tOf (s : St) (e : Nat) : Nat := ((lookupE s.epochs e).map (·.t)).getD 0
def fOf (s : St) (e : Nat) : Nat := ((lookupE s.epochs e).map (·.f)).getD 0
def qOf (s : St) (e : Nat) : Nat := ((lookupE s.epochs e).map (·.q)).getD 0
def graceEndOf (s : St) (e : Nat) : Nat := ((lookupE s.epochs e).map (·.graceEnd)).getD 0
def sweptOf (s : St) (e : Nat) : Bool := ((lookupE s.epochs e).map (·.swept)).getD false

/-- HO-055: an epoch is live when it is current or in grace. -/
def live (s : St) (e : Nat) : Prop := statusOf s e = some .current ∨ statusOf s e = some .grace

instance (s : St) (e : Nat) : Decidable (live s e) := by unfold live; infer_instance

/-- The board's state of a slot (HO-044). -/
def boardSlot (s : St) (k : Nat × Nat) : SlotSt :=
  match s.board.find? (fun x => x.1 == k) with
  | some x => x.2
  | none => .free

def shardOf (s : St) (u : Nat) : Option Nat := (s.users.find? (fun x => x.id == u)).map (·.shard)

def liveReq (s : St) (rid : Nat) : Option Req := s.requests.find? (fun r => r.id == rid && r.live)

/-- HO-032, HO-066: the validator epoch at board position `p`: the target of the newest
activation with `H < p`, else the genesis epoch 0. -/
def validatorAt (s : St) (p : Nat) : Nat :=
  match s.handovers.find? (fun x => decide (x.1 < p)) with
  | some x => x.2
  | none => 0

/-- HO-036: the owning epoch of a request at board position `p`: the binding epoch
below the sweep position, its successor from that position (ledger 6). -/
def owner (r : Req) (p : Nat) : Nat :=
  match r.sweep with
  | some w => if p < w then r.bind else r.bind + 1
  | none => r.bind

/-- HO-059: `e` owns `r` at `p`, as a relation. -/
def ownsAt (r : Req) (p e : Nat) : Prop :=
  (e = r.bind ∧ ∀ w, r.sweep = some w → p < w) ∨ (e = r.bind + 1 ∧ ∃ w, r.sweep = some w ∧ w ≤ p)

/-! ## Refusals

One constructor for each distinct response, in code order, so a list built in
constructor order is sorted. When several apply, the answer holds every code
(ledger 1).

| Code | IDs |
|---|---|
| `activation_late` | HO-065 |
| `bad_activation` | HO-048 |
| `bad_epoch` | HO-007 |
| `bad_params` | HO-004 (and a roster that is not `n'` distinct seats, ledger 4) |
| `bad_source` | HO-008 |
| `carry_mismatch` | HO-019 |
| `epoch_closed` | HO-041, HO-053 |
| `epoch_superseded` | HO-046, HO-051 |
| `no-rule` | an event no requirement defines, or an op whose actor tag is not its actor (ledger 3) |
| `not_owner` | HO-038 |
| `operator_not_disjoint` | HO-049 |
| `outside-capability` | a genesis outside the domain (harness code) |
| `outside-state-domain` | a `--step` state outside `validState` (harness code) |
| `pool_epoch_mismatch` | HO-039 |
| `rotate_unauthorized` | HO-003 |
| `rotation_open` | HO-009 (ARMED counts as open, ledger 7) |
| `seat_unknown` | HO-014 |
| `too_few_signers` | HO-068 |
| `too_many_seats` | HO-005, HO-006 |
-/

inductive Refusal where
  | activationLate | badActivation | badEpoch | badParams | badSource | carryMismatch | epochClosed
  | epochSuperseded | noRule | notOwner | operatorNotDisjoint | outsideCapability | outsideStateDomain
  | poolEpochMismatch
  | rotateUnauthorized | rotationOpen | seatUnknown | tooFewSigners | tooManySeats
  deriving Repr, DecidableEq

def Refusal.code : Refusal → String
  | .activationLate => "activation_late"
  | .badActivation => "bad_activation"
  | .badEpoch => "bad_epoch"
  | .badParams => "bad_params"
  | .badSource => "bad_source"
  | .carryMismatch => "carry_mismatch"
  | .epochClosed => "epoch_closed"
  | .epochSuperseded => "epoch_superseded"
  | .noRule => "no-rule"
  | .notOwner => "not_owner"
  | .operatorNotDisjoint => "operator_not_disjoint"
  | .outsideCapability => "outside-capability"
  | .outsideStateDomain => "outside-state-domain"
  | .poolEpochMismatch => "pool_epoch_mismatch"
  | .rotateUnauthorized => "rotate_unauthorized"
  | .rotationOpen => "rotation_open"
  | .seatUnknown => "seat_unknown"
  | .tooFewSigners => "too_few_signers"
  | .tooManySeats => "too_many_seats"

def opt (c : Prop) [Decidable c] (r : Refusal) : List Refusal := if c then [r] else []

/-! ## Operations and actors (HO-058, HO-067) -/

/-- Who takes an operation. `source` and `target` are seats of the source and target
epochs, `seat` a committee seat in another role, `contract` the committee contract
on Midnight, `time` Midnight time. -/
inductive Actor where
  | governance | source | target | seat | board | contract | time | user
  deriving Repr, DecidableEq

inductive Act where
  /-- HO-002 to HO-012 -/
  | rotate (r : Rotate)
  /-- HO-015: every target seat has `w'` acks for its `NodeKeys` -/
  | eks
  /-- HO-018, HO-019: a carry dealing of one source seat, `ok` its constant-term check -/
  | carry (dealer : Nat) (ok : Bool)
  /-- HO-020 -/
  | complaint (dealer : Nat)
  /-- HO-029, HO-030 -/
  | ready (seat : Nat) (q : List Nat) (hs : Nat)
  /-- HO-031, HO-064: the board block that commits the arm heartbeat with `sigs` partials -/
  | arm (sigs : Nat)
  /-- HO-047 to HO-050, HO-065: the activation record reaches the committee contract -/
  | activate (gov : Bool) (sigs : Nat) (heartbeat : Bool) (boots : Bool) (disjoint : Bool)
  /-- HO-012, HO-033, HO-045: Midnight height `m` is final -/
  | midnightTick (m : Nat)
  /-- the board commits its next block (HO-032: none between `H` and the activation) -/
  | block
  | restartBegin
  | restartEnd
  /-- HO-013, HO-014 -/
  | admitBoot (seat : Nat) (withRotate : Bool)
  /-- the board orders a request (HO-041 at its public check) -/
  | order (rid bind : Nat) (slots : List (Nat × Nat))
  | endReq (rid : Nat)
  /-- HO-024: the board shows a request use slot `(a, i)` with ticket `tk` -/
  | useSlot (rid a i tk : Nat)
  /-- HO-042, HO-043: the `n' − f'`-th READY for the sweep batch of epoch `e` commits -/
  | sweepReady (e : Nat)
  /-- HO-037, HO-038: an OPENED, ADMIT or RELEASE entry of a member of epoch `e` -/
  | entry (rid e : Nat)
  /-- HO-039: a header of request `rid` names a slot of a pool of epoch `pe` -/
  | header (rid pe : Nat)
  /-- HO-040, HO-041: the public check of an envelope that binds epoch `e` -/
  | envelope (e : Nat)
  /-- HO-046: a node of epoch `e` is asked to sign a checkpoint at board height `bh` -/
  | signCheckpoint (e bh : Nat)
  /-- HO-050, HO-051, HO-068: a checkpoint of epoch `e` with `sigs` valid signatures -/
  | submitCheckpoint (e sigs : Nat)
  /-- HO-052, HO-053: a committee certificate that names epoch `e` -/
  | cert (e : Nat)
  /-- a user acknowledgement, re-deal or re-post: no handoff transition takes it (HO-058) -/
  | userAck (u : Nat)
  deriving Repr, DecidableEq

/-- HO-058, HO-067: the actor of each operation. -/
def Act.actor : Act → Actor
  | .rotate _ => .governance
  | .eks => .target
  | .carry _ _ => .source
  | .complaint _ => .target
  | .ready _ _ _ => .target
  | .arm _ => .board
  | .activate _ _ _ _ _ => .contract
  | .midnightTick _ => .time
  | .block => .board
  | .restartBegin => .seat
  | .restartEnd => .seat
  | .admitBoot _ _ => .seat
  | .order _ _ _ => .board
  | .endReq _ => .board
  | .useSlot _ _ _ _ => .board
  | .sweepReady _ => .board
  | .entry _ _ => .seat
  | .header _ _ => .seat
  | .envelope _ => .seat
  | .signCheckpoint _ _ => .seat
  | .submitCheckpoint _ _ => .contract
  | .cert _ => .contract
  | .userAck _ => .user

/-- An operation carries its actor tag; a tag that is not the operation's actor is refused. -/
structure Op where
  actor : Actor
  act : Act
  deriving Repr, DecidableEq

/-- The operation with its own actor tag. -/
def Act.op (a : Act) : Op := { actor := a.actor, act := a }

/-! ## Guards -/

/-- HO-004 -/
def paramsOk (n f q t : Nat) : Prop := 1 ≤ f ∧ 3 * f + 1 ≤ n ∧ q = (n + f + 2) / 2 ∧ t = n - f

instance (n f q t : Nat) : Decidable (paramsOk n f q t) := by unfold paramsOk; infer_instance

/-- HO-009 (with ARMED, ledger 7) -/
def rotationOpenP (s : St) : Prop :=
  s.ho.phase = .QUEUED ∨ s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED

instance (s : St) : Decidable (rotationOpenP s) := by unfold rotationOpenP; infer_instance

/-- HO-010 fact 2: the epoch before the current epoch is not in grace (an epoch before
genesis counts as closed, ledger 5). -/
def prevClosed (s : St) : Prop := statusOf s (s.cur - 1) ≠ some .grace

/-- HO-008, HO-010 fact 4 -/
def sourceOk (s : St) (e : Nat) : Prop := statusOf s e = some .current ∨ statusOf s e = some .grace

instance (s : St) (e : Nat) : Decidable (sourceOk s e) := by unfold sourceOk; infer_instance

/-- HO-010: the preconditions of a ROTATE (fact 1 with ARMED, ledger 7). -/
def pre (s : St) (r : Rotate) : Prop :=
  ¬ (s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED) ∧ prevClosed s ∧ s.restart = false ∧ sourceOk s r.source

instance (s : St) (r : Rotate) : Decidable (pre s r) := by
  unfold pre prevClosed sourceOk; infer_instance

/-- HO-005, HO-006: the seats of the source roster the ROTATE replaces. -/
def replaced (s : St) (r : Rotate) : Nat :=
  ((rosterOf s r.source).filter (fun x => decide (x ∉ r.roster))).length

def seatLimit (s : St) (r : Rotate) : Nat :=
  if r.emergency then fOf s r.source else fOf s r.source / 2

/-- HO-003 to HO-009, in code order. -/
def rotateRefusals (s : St) (r : Rotate) : List Refusal :=
  opt (r.target ≠ s.cur + 1) .badEpoch
    ++ opt (¬ (paramsOk r.n r.f r.q r.t ∧ r.roster.length = r.n ∧ r.roster.Nodup)) .badParams
    ++ opt (¬ sourceOk s r.source) .badSource
    ++ opt (r.sigs < qOf s s.landed) .rotateUnauthorized
    ++ opt (rotationOpenP s) .rotationOpen
    ++ opt (seatLimit s r < replaced s r) .tooManySeats

/-- HO-021: the first `t` source dealers in board order with no valid complaint. -/
def qualified (s : St) : List Nat :=
  ((s.ho.dealt.map Prod.fst).filter (fun d => decide (d ∉ s.ho.disq))).take s.ho.tQ

/-- HO-030: READY posts of one pair. -/
def readyCount (s : St) (q : List Nat) (hs : Nat) : Nat :=
  (s.ho.readys.filter (fun x => decide (x.2 = (q, hs)))).length

def need (s : St) : Nat := s.ho.rot.n - s.ho.rot.f

/-- HO-031, HO-064: the arm heartbeat can commit: ROTATING, `Q` complete, the last
complaint window closed, no restart open, and `n' − f'` READY posts for one pair
`(Q, h_S)` (ledger 8). -/
def armReady (s : St) : Prop :=
  s.ho.phase = .ROTATING ∧ (qualified s).length = s.ho.tQ ∧ s.ho.lastBatch + s.params.deltaCw < s.mh
    ∧ s.restart = false ∧ ∃ x ∈ s.ho.readys, x.2.1 = qualified s ∧ need s ≤ readyCount s x.2.1 x.2.2

instance (s : St) : Decidable (armReady s) := by unfold armReady; infer_instance

/-- HO-065: the record reaches the contract after `m_D` of a ROTATE that was ordered. -/
def lateP (s : St) : Prop :=
  (s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED ∨ s.ho.phase = .ABORTED) ∧ s.ho.mD < s.mh

instance (s : St) : Decidable (lateP s) := by unfold lateP; infer_instance

def closedFor (s : St) (e : Nat) : Prop :=
  statusOf s e = some .closed ∨ (statusOf s e = some .grace ∧ sweptOf s e = true)

/-- HO-040: current for the public check from the activation until the sweep. -/
def openFor (s : St) (e : Nat) : Prop :=
  statusOf s e = some .current ∨ (statusOf s e = some .grace ∧ sweptOf s e = false)

instance (s : St) (e : Nat) : Decidable (closedFor s e) := by unfold closedFor; infer_instance
instance (s : St) (e : Nat) : Decidable (openFor s e) := by unfold openFor; infer_instance

/-- HO-046: a checkpoint of epoch `e` above the `H` of its successor. -/
def superseded (s : St) (e bh : Nat) : Prop :=
  (∃ x ∈ s.handovers, x.2 = e + 1 ∧ x.1 < bh) ∨ (s.ho.phase = .ARMED ∧ s.ho.rot.source = e ∧ s.ho.H < bh)

instance (s : St) (e bh : Nat) : Decidable (superseded s e bh) := by unfold superseded; infer_instance

def useOk (s : St) (rid a i : Nat) : Bool :=
  match liveReq s rid with
  | some r => r.slots.contains (a, i) && boardSlot s (a, i) == .free
  | none => false

/-- The refusals of each operation, in code order. -/
def actRefusals (s : St) : Act → List Refusal
  | .rotate r => rotateRefusals s r
  | .eks => opt (s.ho.phase ≠ .ROTATING) .noRule
  | .carry d ok =>
    -- HO-018, HO-019: a dealing of a source seat after `EKS_{e+1}` is complete, once per seat
    let c := s.ho.phase = .ROTATING ∧ s.ho.eks = true ∧ d ∈ s.ho.srcRoster ∧ d ∉ s.ho.dealt.map Prod.fst
    opt (c ∧ ok = false) .carryMismatch ++ opt (¬ c) .noRule
  | .complaint d =>
    -- HO-020: within `Δ_cw` Midnight blocks after the dealing's batch
    opt (¬ (s.ho.phase = .ROTATING ∧ d ∉ s.ho.disq
      ∧ ∃ x ∈ s.ho.dealt, x.1 = d ∧ s.mh ≤ x.2 + s.params.deltaCw)) .noRule
  | .ready seat q hs =>
    opt (¬ (s.ho.phase = .ROTATING ∧ seat ∈ s.ho.rot.roster ∧ (seat, q, hs) ∉ s.ho.readys)) .noRule
  | .arm sigs => opt (¬ (armReady s ∧ s.ho.rot.t ≤ sigs)) .noRule
  | .activate gov sigs hb boots disj =>
    -- HO-048, HO-049, HO-065
    opt (lateP s) .activationLate
      ++ opt (gov = false ∨ sigs < s.ho.rot.t ∨ hb = false ∨ boots = false) .badActivation
      ++ opt (¬ lateP s ∧ s.ho.phase ≠ .ARMED) .noRule
      ++ opt (disj = false) .operatorNotDisjoint
  | .midnightTick m => opt (m < s.mh) .noRule
  | .block => opt (s.ho.phase = .ARMED) .noRule
  | .restartBegin => opt (s.restart = true) .noRule
  | .restartEnd => opt (s.restart = false) .noRule
  | .admitBoot seat _ =>
    -- HO-014
    opt (¬ (seat ∈ rosterOf s s.cur ∨ (s.ho.phase = .ROTATING ∧ seat ∈ s.ho.rot.roster))) .seatUnknown
  | .order rid bind _ =>
    -- HO-041
    opt (closedFor s bind) .epochClosed
      ++ opt ((¬ closedFor s bind ∧ ¬ openFor s bind) ∨ (s.requests.any (fun r => r.id == rid)) = true) .noRule
  | .endReq rid => opt (liveReq s rid = none) .noRule
  | .useSlot rid a i _ => opt (useOk s rid a i = false) .noRule
  | .sweepReady e =>
    opt (¬ (statusOf s e = some .grace ∧ sweptOf s e = false
      ∧ graceEndOf s e ≤ s.mh + s.params.deltaSweep)) .noRule
  | .entry rid e =>
    match liveReq s rid with
    | none => [.noRule]
    | some r => opt (owner r s.pos ≠ e) .notOwner
  | .header rid pe =>
    match liveReq s rid with
    | none => [.noRule]
    | some r => opt (pe ≠ r.bind) .poolEpochMismatch
  | .envelope e => opt (closedFor s e) .epochClosed ++ opt (¬ closedFor s e ∧ ¬ openFor s e) .noRule
  | .signCheckpoint e bh => opt (superseded s e bh) .epochSuperseded
  | .submitCheckpoint e sigs =>
    opt (e < s.landed) .epochSuperseded ++ opt (s.landed < e) .noRule
      ++ opt (e = s.landed ∧ sigs < tOf s e) .tooFewSigners
  | .cert e =>
    opt (statusOf s e = some .closed) .epochClosed
      ++ opt (statusOf s e ≠ some .closed ∧ ¬ live s e) .noRule
  | .userAck _ => [.noRule]

def refusals (s : St) (op : Op) : List Refusal :=
  if op.actor ≠ op.act.actor then [.noRule] else actRefusals s op.act

/-! ## Transitions -/

/-- HO-045, HO-001: close every epoch whose grace end has passed. -/
def closeRec (m : Nat) (r : EpochRec) : EpochRec :=
  if r.status = .grace ∧ r.graceEnd ≤ m then { r with status := .closed } else r

def closingE (s : St) (e : Nat) : Bool :=
  match lookupE s.epochs e with
  | some r => decide (r.status = .grace ∧ r.graceEnd ≤ s.mh)
  | none => false

/-- HO-045: at grace end the epoch is CLOSED and its sharings are erased. A QUEUED ROTATE
whose source closes is ABORTED (ledger 9). -/
def closeGraces (s : St) : St :=
  { s with
    epochs := s.epochs.map (closeRec s.mh)
    sharings := s.sharings.filter (fun sh => !closingE s sh.epoch)
    ho := if s.ho.phase = .QUEUED ∧ closingE s s.ho.rot.source = true then
            { s.ho with phase := .ABORTED } else s.ho }

/-- HO-012: a QUEUED ROTATE whose preconditions are met starts. -/
def release (s : St) : St :=
  if s.ho.phase = .QUEUED ∧ pre s s.ho.rot then
    { s with ho := { s.ho with phase := .ROTATING, mR := s.mh, mD := s.mh + s.params.deltaRot } }
  else s

/-- HO-033, HO-034: abort; the target material is erased. -/
def abortHo (h : Handoff) : Handoff := { h with phase := .ABORTED, eks := false, dealt := [], readys := [] }

def slotState (s : St) : SecretId → SlotSt
  | .xf _ => .free
  | .slot a i => boardSlot s (a, i)

/-- HO-044: a carried sharing installed in epoch `e` among `ros`, with the board's slot state. -/
def install (s : St) (e : Nat) (ros : List Nat) (sh : Sharing) : Sharing :=
  { sh with epoch := e, holders := ros, st := slotState s sh.secret }

/-- HO-018: the standing secrets: `x_f`, and every slot that no request has used. -/
def standing (s : St) (sh : Sharing) : Bool :=
  match sh.secret with
  | .xf _ => true
  | .slot a i => boardSlot s (a, i) == .free

/-- HO-018, HO-029: the sharings of the target, one per standing sharing of the source. -/
def carried (s : St) : List Sharing :=
  (s.sharings.filter (fun sh => decide (sh.epoch = s.ho.rot.source) && standing s sh)).map
    (install s s.ho.rot.target s.ho.rot.roster)

/-- HO-032, HO-047, HO-050: the activation record is final. The target becomes current
with its roster; the source goes into grace until `mh + Δ_grace`; the board takes the
target as validator set from `H + 1`; the contract's landed epoch is the target. -/
def activateEff (s : St) : St :=
  let r := s.ho.rot
  { s with
    cur := r.target
    epochs := { id := r.target, roster := r.roster, n := r.n, f := r.f, q := r.q, t := r.t,
                status := .current, graceEnd := 0, swept := false } ::
              s.epochs.map (fun e => if e.id = s.cur then
                { e with status := .grace, graceEnd := s.mh + s.params.deltaGrace } else e)
    sharings := s.sharings ++ carried s
    handovers := (s.ho.H, r.target) :: s.handovers
    landed := r.target
    ho := { s.ho with phase := .HANDED_OVER } }

def slotIn : SecretId → List (Nat × Nat) → Bool
  | .slot a i, ks => ks.contains (a, i)
  | .xf _, _ => false

def sweepSet (s : St) (e : Nat) : List Req :=
  s.requests.filter (fun r => r.live && r.bind == e && r.sweep.isNone)

/-- HO-042, HO-043, HO-044: the sweep of epoch `e` at board position `pos`. -/
def sweepEff (s : St) (e : Nat) : St :=
  let keys := (sweepSet s e).flatMap (·.slots)
  { s with
    requests := s.requests.map (fun r =>
      if r.live = true ∧ r.bind = e ∧ r.sweep = none then { r with sweep := some s.pos } else r)
    epochs := s.epochs.map (fun r => if r.id = e then { r with swept := true } else r)
    sharings := s.sharings ++
      (s.sharings.filter (fun sh => decide (sh.epoch = e) && slotIn sh.secret keys)).map
        (install s (e + 1) (rosterOf s (e + 1))) }

/-- HO-024: the copy of the using epoch is bound to the ticket, every other copy is burned. -/
def useEff (s : St) (rid a i tk : Nat) : St :=
  match liveReq s rid with
  | none => s
  | some r =>
    let e := owner r s.pos
    { s with
      board := ((a, i), .bound tk) :: s.board
      sharings := s.sharings.map (fun sh =>
        if sh.secret = .slot a i then { sh with st := if sh.epoch = e then .bound tk else .burned } else sh) }

/-- The effect of an accepted operation. -/
def effect (s : St) : Act → St
  | .rotate r =>
    -- HO-002, HO-011, HO-012
    { s with ho := { phase := if pre s r then .ROTATING else .QUEUED, rot := r,
                     srcRoster := rosterOf s r.source, tQ := tOf s r.source,
                     mR := s.mh, mD := s.mh + s.params.deltaRot, eks := false, dealt := [], disq := [],
                     readys := [], lastBatch := s.mh, H := 0 } }
  | .eks => { s with ho := { s.ho with eks := true } }
  | .carry d _ => { s with ho := { s.ho with dealt := s.ho.dealt ++ [(d, s.mh)], lastBatch := s.mh } }
  | .complaint d => { s with ho := { s.ho with disq := d :: s.ho.disq } }
  | .ready seat q hs => { s with ho := { s.ho with readys := s.ho.readys ++ [(seat, q, hs)] } }
  | .arm _ => { s with ho := { s.ho with phase := .ARMED, H := s.pos } }
  | .activate _ _ _ _ _ => activateEff s
  | .midnightTick m =>
    let s1 := { s with mh := m }
    if (s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED) ∧ s.ho.mD < m then { s1 with ho := abortHo s.ho }
    else release (closeGraces s1)
  | .block => { s with pos := s.pos + 1 }
  | .restartBegin => { s with restart := true }
  | .restartEnd => { s with restart := false }
  | .admitBoot seat w =>
    -- HO-013
    if s.ho.phase = .ROTATING ∧ seat ∈ s.ho.rot.roster ∧ w = true ∧ seat ∉ s.pending then
      { s with pending := seat :: s.pending } else s
  | .order rid bind slots =>
    { s with requests := s.requests ++ [{ id := rid, bind, sweep := none, live := true, slots }] }
  | .endReq rid => { s with requests := s.requests.map (fun r => if r.id = rid then { r with live := false } else r) }
  | .useSlot rid a i tk => useEff s rid a i tk
  | .sweepReady e => sweepEff s e
  | .entry _ _ => s
  | .header _ _ => s
  | .envelope _ => s
  | .signCheckpoint _ _ => s
  | .submitCheckpoint _ _ => s
  | .cert _ => s
  | .userAck _ => s

/-- One operation: refused operations leave the state unchanged. -/
def next (s : St) (op : Op) : St := if refusals s op = [] then effect s op.act else s

def run (s : St) (ops : List Op) : St := ops.foldl next s

inductive Obs where
  | ok
  | refused (rs : List Refusal)
  deriving Repr, DecidableEq

def apply (s : St) (op : Op) : St × Obs :=
  match refusals s op with
  | [] => (effect s op.act, .ok)
  | rs => (s, .refused rs)

def runOps : St → List Op → St × List Obs
  | s, [] => (s, [])
  | s, op :: ops =>
    let (s', o) := apply s op
    let (s'', os) := runOps s' ops
    (s'', o :: os)

/-! ## Signable addresses (HO-063) -/

/-- Epoch `e` holds a sharing of secret `k`. -/
def heldBy (s : St) (e : Nat) (k : SecretId) : Prop := ∃ sh ∈ s.sharings, sh.secret = k ∧ sh.epoch = e

/-- HO-063: the current epoch holds a sharing of `x_f` of the address's curve with constant
term `X_f`, the user shard is the address's, and on ECDSA every unused (board `free`) slot of
the address is held by the current epoch. -/
def signable (s : St) (a : Addr) : Prop :=
  (∃ sh ∈ s.sharings, sh.secret = .xf a.curve ∧ sh.epoch = s.cur ∧ sh.const = s.xf.get a.curve)
    ∧ shardOf s a.user = some a.shard
    ∧ (a.ecdsa = true → ∀ i ∈ a.slots, boardSlot s (a.id, i) = .free → heldBy s s.cur (.slot a.id i))

/-! ## Initial state -/

structure Genesis where
  roster : List Nat
  n : Nat
  f : Nat
  q : Nat
  t : Nat
  xf : XF
  users : List User
  addrs : List Addr
  deriving Repr, DecidableEq

/-- The domain of the genesis committee (HO-004 at genesis). -/
def validGenesis (g : Genesis) : Prop := paramsOk g.n g.f g.q g.t ∧ g.roster.length = g.n ∧ g.roster.Nodup

instance (g : Genesis) : Decidable (validGenesis g) := by unfold validGenesis; infer_instance

def idleRotate : Rotate :=
  { target := 0, source := 0, roster := [], n := 0, f := 0, q := 0, t := 0, emergency := false, sigs := 0 }

def idleHo : Handoff :=
  { phase := .IDLE, rot := idleRotate, srcRoster := [], tQ := 0, mR := 0, mD := 0, eks := false,
    dealt := [], disq := [], readys := [], lastBatch := 0, H := 0 }

def genesisSharings (g : Genesis) : List Sharing :=
  [{ secret := .xf .secp, const := g.xf.secp, epoch := 0, holders := g.roster, st := .free },
   { secret := .xf .ed, const := g.xf.ed, epoch := 0, holders := g.roster, st := .free }]
  ++ g.addrs.flatMap (fun a => if a.ecdsa then
      a.slots.map (fun i => { secret := .slot a.id i, const := 0, epoch := 0, holders := g.roster, st := .free })
    else [])

/-- Epoch 0 is current with the genesis roster and every standing sharing. -/
def init (p : Params) (g : Genesis) : St :=
  { params := p, mh := 0, pos := 0, cur := 0,
    epochs := [{ id := 0, roster := g.roster, n := g.n, f := g.f, q := g.q, t := g.t,
                 status := .current, graceEnd := 0, swept := false }],
    sharings := genesisSharings g, ho := idleHo, requests := [], board := [], xf := g.xf,
    users := g.users, addrs := g.addrs, handovers := [], landed := 0, restart := false, pending := [] }

/-- A `--step` state: the cheap structural checks of `Inv`. Not reachability. -/
def validState (s : St) : Bool :=
  statusOf s s.cur == some .current
    && s.epochs.all (fun r => (r.status != .current || r.id == s.cur) && (r.status != .grace || r.id + 1 == s.cur))
    && decide (s.ho.lastBatch ≤ s.mh)
    && s.sharings.all (fun sh => decide (sh.epoch ≤ s.cur))

end SplitHandoff
