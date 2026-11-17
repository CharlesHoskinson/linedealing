/-!
# Slot oracle (split-slots, SL-001 to SL-030)

The executable reference semantics of the OpenSpec capability `split-slots`
(`openspec/changes/add-split-line-dealing/specs/split-slots/spec.md`).

The state is the slot ledger as the board fixes it: the committee slots of each
pool `(suite, epoch)`, the ECDSA slots of each account pool, the requests whose
authorization is in force (with the slot root their source opens), the lapsed
and the ended requests; and, in TEE mode, the slot shares of one seat with
their states `free`, `bound(d)` and `burned`.

Facts from the other capabilities are operations or fields of operations
(formal plugin, practice 11): a header opens with its board position
(split-request), an authorization comes into force (split-authorization), a
precedence lapses, `q` votes commit, a request reaches ADMITTED or ends
(split-request), a whole-committee restart burns a range or an account pool
(split-checkpoint), a bind round has its ack counts (Sessions). The window
judge, the batch check, the qualified dealers and the slot-anchor gate keep no
state and are pure functions over their inputs.
-/

namespace SplitSlots

/-! ## Domains -/

inductive Mode where
  | TEE | NON_TEE
  deriving Repr, DecidableEq

/-- SL-001: the Schnorr suites of the committee pools. -/
inductive Suite where
  | BIP340 | ED25519
  deriving Repr, DecidableEq

/-- SL-002: `bstat`. -/
inductive BStat where
  | UNNAMED | NAMED | RESERVED | CLAIMED | BURNED
  deriving Repr, DecidableEq

/-- SL-017: the order of `bstat`; BURNED is last. -/
def BStat.rank : BStat → Nat
  | .UNNAMED => 0
  | .NAMED => 1
  | .RESERVED => 2
  | .CLAIMED => 3
  | .BURNED => 4

/-- SL-003: the root an ECDSA slot lies under. -/
inductive Root where
  | OWN | G
  deriving Repr, DecidableEq

/-- SL-002: a committee slot `(s, e, ℓ)`; `namers` holds `(eid, board position)`. -/
structure CSlot where
  suite : Suite
  epoch : Nat
  idx : Nat
  bstat : BStat
  prec : Option Nat
  namers : List (Nat × Nat)
  deriving Repr, DecidableEq

def CSlot.key (x : CSlot) : Suite × Nat × Nat := (x.suite, x.epoch, x.idx)

/-- SL-003: an ECDSA slot `(pool, ℓ)`; `leafSet` stands for `H(T_ℓ)`. -/
structure ESlot where
  pool : Nat
  idx : Nat
  leafSet : Nat
  root : Root
  bstat : BStat
  prec : Option Nat
  reserver : Option Nat
  namers : List (Nat × Nat)
  deriving Repr, DecidableEq

def ESlot.key (x : ESlot) : Nat × Nat := (x.pool, x.idx)

/-- SL-018: the state of one slot share of the seat. -/
inductive SeatSt where
  | free
  | bound (d : Nat)
  | burned
  deriving Repr, DecidableEq

/-- A slot share of the seat. `current`: a sealed version that records the
binding has `w` acks (SL-019). `signed`: the ticket digests for which the seat
released a partial on this slot, newest first (SL-021, SL-027). -/
structure SeatSlot where
  key : Nat
  st : SeatSt
  current : Bool
  signed : List Nat
  deriving Repr, DecidableEq

structure Params where
  mode : Mode
  -- `w = n − 1 − f` (RQ-001)
  w : Nat
  deriving Repr, DecidableEq

structure St where
  params : Params
  cslots : List CSlot
  eslots : List ESlot
  seat : List SeatSlot
  -- requests whose authorization is in force, with the root their source opens (SL-006)
  inForce : List (Nat × Root)
  -- requests whose header opened
  opened : List Nat
  -- the highest board position of an opened header (Q-003)
  lastPos : Option Nat
  lapsed : List Nat
  ended : List Nat
  deriving Repr, DecidableEq

def init (p : Params) : St :=
  { params := p, cslots := [], eslots := [], seat := [], inForce := [], opened := [], lastPos := none,
    lapsed := [], ended := [] }

/-! ## Helpers -/

def nodupB {α : Type} [BEq α] : List α → Bool
  | [] => true
  | x :: xs => !xs.contains x && nodupB xs

def maxL : List Nat → Nat
  | [] => 0
  | x :: xs => max x (maxL xs)

/-- The namer with the lowest board position (SL-004, SL-006). -/
def lowestPair : List (Nat × Nat) → Option (Nat × Nat)
  | [] => none
  | a :: rest =>
    match lowestPair rest with
    | none => some a
    | some b => if b.2 < a.2 then some b else some a

def lowest (ns : List (Nat × Nat)) : Option Nat := (lowestPair ns).map (·.1)

def inForceAny (s : St) (e : Nat) : Bool := s.inForce.any (·.1 == e)

/-! ## Committee slot transitions -/

/-- SL-010, SL-011: a burn, used or not. -/
def burnC (x : CSlot) : CSlot := { x with bstat := .BURNED }

/-- SL-004: a header opens and names `x`: record the namer; a slot with
`prec = none` and `bstat = UNNAMED` gets the namer with the lowest board
position and NAMED. SL-017: a BURNED slot, or a slot with a precedence, gets
no new `prec`. -/
def openSlot (eid pos : Nat) (x : CSlot) : CSlot :=
  let ns := x.namers ++ [(eid, pos)]
  if x.prec = none ∧ x.bstat = .UNNAMED then { x with namers := ns, prec := lowest ns, bstat := .NAMED }
  else { x with namers := ns }

inductive Op where
  -- SL-001, SL-022: deal `k` committee slots into pool `(s, e)`
  | dealC (su : Suite) (e k : Nat)
  -- SL-003, SL-022: deal `k` ECDSA slots into account pool `p` with leaf set and root
  | dealE (p leafSet : Nat) (root : Root) (k : Nat)
  -- SL-004, SL-016: the header of `eid` at board position `pos` opens and names committee slots
  | openC (eid pos : Nat) (names : List (Suite × Nat × Nat))
  -- SL-006, SL-007, SL-016: the header of `eid` opens and names ECDSA slots
  | openE (eid pos : Nat) (names : List (Nat × Nat))
  -- SL-006: the authorization of `eid` comes into force; its source opens `root`
  | inForce (eid : Nat) (root : Root)
  -- SL-005: the authorization of `eid` is not in force at `b + Δ_c`
  | lapse (eid : Nat)
  -- SL-008: `q` votes with one header hash commit for `eid`
  | reserve (eid : Nat)
  -- SL-009: `eid` reaches ADMITTED
  | claim (eid : Nat)
  -- SL-010, SL-011: `eid` reaches FINAL, VOID or EXPIRED
  | endReq (eid : Nat)
  -- a whole-committee restart burns the committee indices `lo..hi` of a pool (CP-020; SL-028)
  | burnRange (su : Suite) (e lo hi : Nat)
  -- a whole-committee restart burns an account pool (CP-021; SL-028)
  | burnPool (p : Nat)
  -- TEE: a slot share enters the seat `free`
  | seatPut (key : Nat)
  -- SL-018, SL-019: one batched `slot_bind` of `key` to ticket digest `d`, with the
  -- acks of its `slot` entries and of the sealed version that records it
  | seatBind (key d slotAcks sealedAcks : Nat)
  -- SL-019 to SL-021: a release on `key` for the ticket with digest `d`
  | seatRelease (key d : Nat)
  -- SL-030: `slot_burn`
  | seatBurn (key : Nat)
  -- SL-012 to SL-015: judge the committee indices `idxs` of a header of `eid`
  -- against the latest landed checkpoint of the pool (`listed`: some landed checkpoint lists it)
  | judge (listed : Bool) (h pendingMin : Nat) (pending : List (Nat × Nat)) (B eid : Nat) (idxs : List Nat)
  -- SL-023, SL-024: the batch equation over the polynomials of a dealer message
  -- (`true`: the polynomial is good)
  | batch (polys : List Bool)
  -- SL-025: the dealers of one slot in board order, each with a valid complaint or not
  | qualify (t : Nat) (dealers : List (Nat × Bool))
  -- SL-026: the slot-anchor gate for nullifier `nf` and ticket digest `d`
  | anchorGate (on : Bool) (covered : List (Nat × Nat)) (nf d : Nat)
  deriving Repr, DecidableEq

/-- SL-005, SL-010 (DECISIONS 63): a precedence that a lapsed request takes is
lapsed at once, so the slot burns. -/
def burnIfLapsed (lapsed : List Nat) (x : CSlot) : CSlot :=
  match x.prec with
  | some e => if lapsed.contains e then burnC x else x
  | none => x

/-- The committee-slot part of one operation; `lapsed` lists the requests whose
precedence is lapsed before it (SL-005). -/
def cstep (lapsed : List Nat) : Op → CSlot → CSlot
  -- SL-004; SL-005: a header that opens after its lapse takes a lapsed precedence
  | .openC eid pos names, x => if names.contains x.key then burnIfLapsed lapsed (openSlot eid pos x) else x
  -- SL-005, SL-010: the lapse burns every slot where the request holds `prec`
  | .lapse eid, x => if x.prec == some eid then burnC x else x
  -- SL-008: NAMED with `prec` of the request becomes RESERVED
  | .reserve eid, x => if x.prec == some eid && x.bstat == .NAMED then { x with bstat := .RESERVED } else x
  -- SL-009: a reserved slot of the request becomes CLAIMED
  | .claim eid, x => if x.prec == some eid && x.bstat == .RESERVED then { x with bstat := .CLAIMED } else x
  -- SL-010: the end of the request with `prec` burns the slot, used or not
  | .endReq eid, x => if x.prec == some eid then burnC x else x
  | .burnRange su e lo hi, x =>
    if x.suite == su && x.epoch == e && decide (lo ≤ x.idx) && decide (x.idx ≤ hi) then burnC x else x
  | _, x => x

/-- SL-001, SL-022: the next dealing of a pool starts above its highest dealt index. -/
def cnew (s : St) : Op → List CSlot
  | .dealC su e k =>
    let top := maxL ((s.cslots.filter (fun x => x.suite == su && x.epoch == e)).map (·.idx))
    (List.range k).map (fun i =>
      { suite := su, epoch := e, idx := top + i + 1, bstat := .UNNAMED, prec := none, namers := [] })
  | _ => []

/-! ## ECDSA slot transitions -/

def burnE (x : ESlot) : ESlot := { x with bstat := .BURNED }

/-- SL-006: the earliest namer in board order whose authorization is in force and
whose source opens the slot's root. -/
def earliest (inf : List (Nat × Root)) (x : ESlot) : Option Nat :=
  lowest (x.namers.filter (fun n => inf.contains (n.1, x.root)))

/-- SL-006: a slot with `prec = none` and `bstat ≠ BURNED` gets the earliest
namer in force; it moves to NAMED (ledger 3). -/
def assignE (inf : List (Nat × Root)) (x : ESlot) : ESlot :=
  if x.prec = none ∧ x.bstat ≠ .BURNED then
    match earliest inf x with
    | some e => { x with prec := some e, bstat := if x.bstat == .UNNAMED then .NAMED else x.bstat }
    | none => x
  else x

/-- The ECDSA-slot part of one operation. -/
def estep (s : St) : Op → ESlot → ESlot
  -- SL-006, SL-007: the namer is recorded; only a namer in force for the slot's
  -- root takes precedence (ledger 2), an unauthorized namer changes nothing else
  | .openE eid pos names, x =>
    if names.contains x.key then
      let x1 := { x with namers := x.namers ++ [(eid, pos)] }
      if s.inForce.contains (eid, x.root) then assignE s.inForce x1 else x1
    else x
  -- SL-006: the authorization comes into force
  | .inForce eid r, x =>
    if x.namers.any (·.1 == eid) && x.root == r then assignE (s.inForce ++ [(eid, r)]) x else x
  -- SL-008: reserve, and `reserver` is the request
  | .reserve eid, x =>
    if x.prec == some eid && x.bstat == .NAMED then { x with bstat := .RESERVED, reserver := some eid } else x
  -- SL-009
  | .claim eid, x => if x.reserver == some eid && x.bstat == .RESERVED then { x with bstat := .CLAIMED } else x
  -- SL-011: the end of the request in `reserver` burns the slot
  | .endReq eid, x => if x.reserver == some eid then burnE x else x
  | .burnPool p, x => if x.pool == p then burnE x else x
  | _, x => x

def enew (s : St) : Op → List ESlot
  | .dealE p ls r k =>
    let top := maxL ((s.eslots.filter (fun x => x.pool == p)).map (·.idx))
    (List.range k).map (fun i =>
      { pool := p, idx := top + i + 1, leafSet := ls, root := r, bstat := .UNNAMED, prec := none,
        reserver := none, namers := [] })
  | _ => []

/-! ## Seat slot transitions (TEE) -/

/-- The seat part of one operation on the slot share `x`. -/
def sstep (w : Nat) : Op → SeatSlot → SeatSlot
  -- SL-018, SL-019: `free` becomes `bound(d)`; the version is current once both
  -- the `slot` entries and the sealed version have `w` acks
  | .seatBind key d sa va, x =>
    if x.key == key then
      match x.st with
      | .free => { x with st := .bound d, current := decide (w ≤ sa) && decide (w ≤ va) }
      | .bound d' => if d' == d then { x with current := x.current || (decide (w ≤ sa) && decide (w ≤ va)) } else x
      | .burned => x
    else x
  -- SL-019 to SL-021: a partial only on a current `bound(d)` and only for `d`
  | .seatRelease key d, x =>
    if x.key == key then
      match x.st with
      | .bound d' => if d' == d && x.current then { x with signed := if x.signed.contains d then x.signed else d :: x.signed } else x
      | _ => x
    else x
  -- SL-018, SL-030: `free` and `bound` move to `burned`
  | .seatBurn key, x => if x.key == key then { x with st := .burned } else x
  | _, x => x

def snew : Op → List SeatSlot
  | .seatPut key => [{ key, st := .free, current := false, signed := [] }]
  | _ => []

/-! ## Pure checks -/

/-- SL-012 to SL-015: the verdict on one committee index of a header. -/
inductive Verdict where
  -- SL-012: in the window
  | inWindow
  -- SL-013: VOID with reason SLOT_TAKEN
  | slotTaken
  -- SL-014: refuse to vote, `above_window`
  | aboveWindow
  -- SL-015: refuse to vote, `pool_unlisted`
  | poolUnlisted
  deriving Repr, DecidableEq

def Verdict.code : Verdict → String
  | .inWindow => "in_window"
  | .slotTaken => "SLOT_TAKEN"
  | .aboveWindow => "above_window"
  | .poolUnlisted => "pool_unlisted"

/-- SL-012 to SL-015. `pending` is the pending list that opens `cp.pending_root`,
as `(index, eid)`. -/
def verdict (listed : Bool) (h pmin : Nat) (pending : List (Nat × Nat)) (B eid l : Nat) : Verdict :=
  if !listed then .poolUnlisted
  else if h + B < l then .aboveWindow
  else if h < l then .inWindow
  else if pmin ≤ l ∧ pending.contains (l, eid) then .inWindow
  else .slotTaken

/-- SL-023, SL-024: the batch equation accepts a message whose polynomials are
all good; otherwise the complaint names each failing dealing (from 1). -/
def batchCheck (polys : List Bool) : List Nat :=
  ((polys.zip (List.range polys.length)).filter (fun p => !p.1)).map (·.2 + 1)

/-- SL-025: the first `t` dealers in board order without a valid complaint;
`none` while fewer than `t` exist. -/
def qualified (t : Nat) (dealers : List (Nat × Bool)) : Option (List Nat) :=
  let ok := (dealers.filter (fun d => !d.2)).map (·.1)
  if ok.length < t then none else some (ok.take t)

/-- SL-026: with `slot_anchor` on, a release on nullifier `nf` for ticket `d`
needs a covered entry `nf → d` and no covered entry `nf → d'` with `d' ≠ d`. -/
def anchorOk (on : Bool) (covered : List (Nat × Nat)) (nf d : Nat) : Bool :=
  !on || (covered.contains (nf, d) && !covered.any (fun c => c.1 == nf && c.2 != d))

/-! ## Refusals

| Code | IDs |
|---|---|
| `no-rule` | an event that no requirement defines, or a stated prohibition with no code (ledger 1, 4 to 8) |
| `outside-capability` | a value outside a domain sentence (ledger 9) |
| `outside-state-domain` | a `--step` state outside `validState` |
| `slot_bound` | SL-020 |

`above_window` and `pool_unlisted` (SL-014, SL-015) are verdicts of `judge`, the
refusal of a vote that the request state machine casts; SLOT_TAKEN (SL-013,
SL-016) is a VOID reason, an observation. -/

inductive Refusal where
  | noRule | outsideCapability | outsideStateDomain | slotBound
  deriving Repr, DecidableEq

def Refusal.code : Refusal → String
  | .noRule => "no-rule"
  | .outsideCapability => "outside-capability"
  | .outsideStateDomain => "outside-state-domain"
  | .slotBound => "slot_bound"

def opt (b : Bool) (r : Refusal) : List Refusal := if b then [r] else []

def seatFind (s : St) (key : Nat) : Option SeatSlot := s.seat.find? (·.key == key)

def headerOrder (s : St) (eid pos : Nat) : Bool :=
  s.opened.contains eid || (match s.lastPos with | some p => decide (pos ≤ p) | none => false)

def opRefusals (s : St) : Op → List Refusal
  | .dealC _ _ _ => []
  | .dealE _ _ _ _ => []
  -- Q-003: headers are judged in board order; a header opens once; a named slot exists
  | .openC eid pos names =>
    opt (headerOrder s eid pos || !names.all (fun k => s.cslots.any (·.key == k))) .noRule
      ++ opt (!nodupB names) .outsideCapability
  | .openE eid pos names =>
    opt (headerOrder s eid pos || !names.all (fun k => s.eslots.any (·.key == k))) .noRule
      ++ opt (!nodupB names) .outsideCapability
  | .inForce eid _ => opt (inForceAny s eid || s.lapsed.contains eid || s.ended.contains eid) .noRule
  | .lapse eid => opt (inForceAny s eid || s.lapsed.contains eid || s.ended.contains eid) .noRule
  | .reserve eid => opt (!inForceAny s eid || s.ended.contains eid) .noRule
  | .claim eid => opt (s.ended.contains eid) .noRule
  | .endReq eid => opt (s.ended.contains eid) .noRule
  | .burnRange _ _ lo hi => opt (decide (hi < lo)) .outsideCapability
  | .burnPool _ => []
  | .seatPut key => opt (s.params.mode == .NON_TEE || s.seat.any (·.key == key)) .noRule
  | .seatBind key d _ _ =>
    opt (s.params.mode == .NON_TEE ||
      match seatFind s key with
      | some x => (match x.st with | .free => false | .bound d' => d' != d | .burned => true)
      | none => true) .noRule
  -- SL-020: a release for another digest than the bound one: `slot_bound`
  | .seatRelease key d =>
    if s.params.mode == .NON_TEE then [.noRule] else
    match seatFind s key with
    | some x =>
      match x.st with
      | .bound d' => if d' != d then [.slotBound] else opt (!x.current) .noRule
      | _ => [.noRule]
    | none => [.noRule]
  | .seatBurn key =>
    opt (s.params.mode == .NON_TEE ||
      match seatFind s key with
      | some x => x.st == .burned
      | none => true) .noRule
  | .judge _ _ _ _ B _ _ => opt (B == 0) .outsideCapability
  | .batch _ => []
  | .qualify t _ => opt (t == 0) .outsideCapability
  | .anchorGate _ _ _ _ => []

/-! ## Observations -/

inductive Obs where
  | ok
  | refused (rs : List Refusal)
  -- SL-016: the node posts VOID for the request with reason SLOT_TAKEN
  | voidSlotTaken
  -- a partial left on the seat slot for ticket `d`
  | released (d : Nat)
  | verdicts (vs : List Verdict)
  -- SL-023, SL-024: `[]` accepts; otherwise the complaint names these dealings
  | batched (failing : List Nat)
  | qualifiedDealers (ds : Option (List Nat))
  | gate (ok : Bool)
  deriving Repr, DecidableEq

/-- The non-slot fields of one operation. -/
def metaStep (s : St) : Op → St
  | .openC eid pos _ => { s with opened := eid :: s.opened, lastPos := some pos }
  | .openE eid pos _ => { s with opened := eid :: s.opened, lastPos := some pos }
  | .inForce eid r => { s with inForce := s.inForce ++ [(eid, r)] }
  | .lapse eid => { s with lapsed := eid :: s.lapsed }
  | .endReq eid => { s with ended := eid :: s.ended }
  | _ => s

def exec (s : St) (op : Op) : St :=
  let m := metaStep s op
  { m with cslots := s.cslots.map (cstep s.lapsed op) ++ cnew s op,
           eslots := s.eslots.map (estep s op) ++ enew s op,
           seat := s.seat.map (sstep s.params.w op) ++ snew op }

/-- SL-016: a slot that the header of `eid` names and another request holds: a committee
slot whose `prec` is another request, or an ECDSA slot whose `prec` is another request with
an authorization in force. The `prec` of an ECDSA slot is always a request in force for its
root (`eInv`, SL-006), so the in-force test restates the sentence and changes no answer. -/
def takenFor (s : St) (eid : Nat) : Bool :=
  s.cslots.any (fun x => x.namers.any (·.1 == eid) && x.prec.isSome && x.prec != some eid)
    || s.eslots.any (fun x => x.namers.any (·.1 == eid) &&
        match x.prec with | some e => e != eid && inForceAny s e | none => false)

/-- SL-016 (DECISIONS 68): SLOT_TAKEN is an admission check. It is read while the authorization
of the opened request is in force: at the open of a request already in force, and at the
`in_force` of a request already opened. A header whose authorization never comes into force
gets no SLOT_TAKEN; it lapses (SL-005). -/
def slotTakenAt (s : St) (eid : Nat) : Obs :=
  if inForceAny s eid && s.opened.contains eid && takenFor s eid then .voidSlotTaken else .ok

/-- The observation of an operation that no refusal stops (computed on the state before it). -/
def obsOf (s : St) : Op → Obs
  -- SL-016: the open of a request whose authorization is in force
  | .openC eid pos names => slotTakenAt (exec s (.openC eid pos names)) eid
  | .openE eid pos names => slotTakenAt (exec s (.openE eid pos names)) eid
  -- SL-016: the authorization of an opened request comes into force
  | .inForce eid r => slotTakenAt (exec s (.inForce eid r)) eid
  | .seatRelease _ d => .released d
  | .judge listed h pmin pending B eid idxs => .verdicts (idxs.map (verdict listed h pmin pending B eid))
  | .batch ps => .batched (batchCheck ps)
  | .qualify t ds => .qualifiedDealers (qualified t ds)
  | .anchorGate on cov nf d => .gate (anchorOk on cov nf d)
  | _ => .ok

/-- One operation: a refused operation leaves the state unchanged. -/
def apply (s : St) (op : Op) : St × Obs :=
  match opRefusals s op with
  | [] => (exec s op, obsOf s op)
  | rs => (s, .refused rs)

def runOps : St → List Op → St × List Obs
  | s, [] => (s, [])
  | s, op :: ops =>
    let (s1, o) := apply s op
    let (s2, os) := runOps s1 ops
    (s2, o :: os)

def run (s : St) (ops : List Op) : St := (runOps s ops).1

/-! ## Invariants and the state domain -/

/-- SL-021, SL-027: at most one ticket. -/
def oneTicket : List Nat → Bool
  | [] => true
  | d :: ds => ds.all (· == d)

/-- The seat-slot invariant: a free slot has released nothing, a bound slot only
for its own ticket. -/
def seatInv (x : SeatSlot) : Bool :=
  match x.st with
  | .free => x.signed == []
  | .bound d => x.signed.all (· == d)
  | .burned => oneTicket x.signed

/-- SL-006, SL-008: the precedence and the reserver of an ECDSA slot are requests
in force for the slot's root. -/
def eInv (inf : List (Nat × Root)) (x : ESlot) : Bool :=
  (match x.prec with | some e => inf.contains (e, x.root) | none => true)
    && (match x.reserver with | some e => inf.contains (e, x.root) | none => true)

/-- The state domain of `--step`: distinct slot keys, the seat invariant and the
ECDSA invariant. It is not a reachability check. -/
def validState (s : St) : Bool :=
  nodupB (s.cslots.map (·.key)) && nodupB (s.eslots.map (·.key)) && nodupB (s.seat.map (·.key))
    && s.seat.all seatInv && s.eslots.all (eInv s.inForce)

def stepRefusals (s : St) : List Refusal := opt (!validState s) .outsideStateDomain

theorem stepRefusals_nil_iff (s : St) : stepRefusals s = [] ↔ validState s = true := by
  unfold stepRefusals opt; cases validState s <;> simp

/-! ## Theorems -/

theorem apply_refused (s : St) (op : Op) (h : opRefusals s op ≠ []) : (apply s op).1 = s := by
  unfold apply; split
  · contradiction
  · rfl

theorem apply_fst (s : St) (op : Op) : (apply s op).1 = s ∨ (apply s op).1 = exec s op := by
  unfold apply; split
  · exact Or.inr rfl
  · exact Or.inl rfl

/-! ### C12: one ticket per seat slot (SL-021, SL-027) -/

theorem all_eq_oneTicket (d : Nat) (ds : List Nat) (h : ds.all (· == d) = true) : oneTicket ds = true := by
  cases ds with
  | nil => rfl
  | cons e es =>
    simp only [List.all_cons, Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨rfl, h⟩ := h
    simpa [oneTicket] using h

theorem seatInv_oneTicket (x : SeatSlot) (h : seatInv x = true) : oneTicket x.signed = true := by
  unfold seatInv at h
  split at h
  · simp at h; simp [h, oneTicket]
  · exact all_eq_oneTicket _ _ h
  · exact h

theorem sstep_inv (w : Nat) (op : Op) (x : SeatSlot) (h : seatInv x = true) : seatInv (sstep w op x) = true := by
  cases op <;> simp only [sstep] <;> try exact h
  case seatBind key d sa va =>
    split
    · split
      · rename_i hst; simp [seatInv, hst] at h ⊢; simp [h]
      · rename_i d' hst
        split
        · simp [seatInv, hst] at h ⊢; exact h
        · exact h
      · exact h
    · exact h
  case seatRelease key d =>
    split
    · split
      · rename_i d' hst
        split
        · rename_i hc
          simp only [Bool.and_eq_true, beq_iff_eq] at hc
          obtain ⟨rfl, _⟩ := hc
          simp only [seatInv, hst] at h ⊢
          split
          · exact h
          · simp [h]
        · exact h
      · exact h
    · exact h
  case seatBurn key =>
    split
    · simp only [seatInv]; exact seatInv_oneTicket x h
    · exact h

theorem exec_seat (s : St) (op : Op) : (exec s op).seat = s.seat.map (sstep s.params.w op) ++ snew op := by
  cases op <;> rfl

theorem exec_seat_inv (s : St) (op : Op) (h : s.seat.all seatInv = true) : (exec s op).seat.all seatInv = true := by
  rw [exec_seat]
  simp only [List.all_append, Bool.and_eq_true, List.all_eq_true, List.mem_map] at h ⊢
  refine ⟨?_, ?_⟩
  · rintro _ ⟨x, hx, rfl⟩; exact sstep_inv _ _ x (h x hx)
  · intro y hy
    cases op <;> simp [snew] at hy
    subst hy; simp [seatInv]

theorem runOps_seat_inv (s : St) (ops : List Op) (h : s.seat.all seatInv = true) :
    (runOps s ops).1.seat.all seatInv = true := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih =>
    simp only [runOps]
    apply ih
    rcases apply_fst s op with h1 | h1 <;> rw [h1]
    · exact h
    · exact exec_seat_inv s op h

/-- C12 (SL-021, SL-027): in every run from `init`, no slot share of the seat has
released partials for two tickets. -/
theorem C12_run_one_ticket (p : Params) (ops : List Op) :
    ∀ x ∈ (run (init p) ops).seat, oneTicket x.signed = true := by
  intro x hx
  have h := runOps_seat_inv (init p) ops rfl
  simp only [List.all_eq_true] at h
  exact seatInv_oneTicket x (h x hx)

/-! ### SL-017: forward only, one precedence -/

/-- One step of SL-017 on one slot: `bstat` stays, moves one place along
UNNAMED → NAMED → RESERVED → CLAIMED, or moves to BURNED. -/
def fwdStep (a b : BStat) : Bool := a == b || b == .BURNED || b.rank == a.rank + 1

/-- SL-017 on one committee slot: the step relation, and BURNED keeps the slot
and its `prec`. -/
def cfwd (x y : CSlot) : Prop :=
  y.key = x.key ∧ (∀ e, x.prec = some e → y.prec = some e)
    ∧ (x.bstat = .BURNED → y.bstat = .BURNED ∧ y.prec = x.prec)

theorem openSlot_fwd (e p : Nat) (x : CSlot) : fwdStep x.bstat (openSlot e p x).bstat = true ∧ cfwd x (openSlot e p x) := by
  unfold cfwd openSlot
  split <;> simp_all [fwdStep, BStat.rank, CSlot.key]

theorem burnIfLapsed_fwd (l : List Nat) (x y : CSlot) (h1 : fwdStep x.bstat y.bstat = true) (h2 : cfwd x y) :
    fwdStep x.bstat (burnIfLapsed l y).bstat = true ∧ cfwd x (burnIfLapsed l y) := by
  obtain ⟨hk, hp, hb⟩ := h2
  unfold burnIfLapsed
  split
  · split
    · exact ⟨by simp [burnC, fwdStep], hk, hp, fun hx => ⟨rfl, (hb hx).2⟩⟩
    · exact ⟨h1, hk, hp, hb⟩
  · exact ⟨h1, hk, hp, hb⟩

theorem cstep_fwd (l : List Nat) (op : Op) (x : CSlot) :
    fwdStep x.bstat (cstep l op x).bstat = true ∧ cfwd x (cstep l op x) := by
  cases op
  case openC eid pos names =>
    simp only [cstep]
    split
    · exact burnIfLapsed_fwd l x _ (openSlot_fwd eid pos x).1 (openSlot_fwd eid pos x).2
    · exact ⟨by simp [fwdStep], rfl, fun _ h => h, fun h => ⟨h, rfl⟩⟩
  all_goals unfold cfwd
  all_goals simp only [cstep]
  all_goals (try simp [fwdStep])
  all_goals ((repeat' split) <;> simp_all [burnC, BStat.rank, CSlot.key] <;> (try split) <;> simp_all)

theorem fwdStep_rank (a b : BStat) (h : fwdStep a b = true) : a.rank ≤ b.rank := by
  cases a <;> cases b <;> simp_all [fwdStep, BStat.rank]

theorem exec_cslots (s : St) (op : Op) : (exec s op).cslots = s.cslots.map (cstep s.lapsed op) ++ cnew s op := by
  cases op <;> rfl

/-- SL-017 for one operation: every committee slot keeps its key, `bstat` moves
one place forward or to BURNED, a set `prec` stays, and a BURNED slot keeps its
`prec` (also `none`). -/
theorem sl017_step (s : St) (op : Op) (x : CSlot) (hx : x ∈ s.cslots) :
    ∃ y ∈ (apply s op).1.cslots, fwdStep x.bstat y.bstat = true ∧ cfwd x y := by
  rcases apply_fst s op with h | h <;> rw [h]
  · exact ⟨x, hx, by simp [fwdStep], rfl, fun _ h => h, fun h => ⟨h, rfl⟩⟩
  · refine ⟨cstep s.lapsed op x, ?_, cstep_fwd s.lapsed op x⟩
    rw [exec_cslots]
    exact List.mem_append_left _ (List.mem_map_of_mem hx)

/-- SL-017 over a whole run: `bstat` never goes back, BURNED is never left and a
burned slot gets no `prec`, and no committee slot's `prec` passes to a second
request. -/
theorem sl017_run (s : St) (ops : List Op) (x : CSlot) (hx : x ∈ s.cslots) :
    ∃ y ∈ (runOps s ops).1.cslots, x.bstat.rank ≤ y.bstat.rank ∧ cfwd x y := by
  induction ops generalizing s x with
  | nil => exact ⟨x, hx, Nat.le_refl _, rfl, fun _ h => h, fun h => ⟨h, rfl⟩⟩
  | cons op ops ih =>
    obtain ⟨y, hy, hf, hk, hp, hb⟩ := sl017_step s op x hx
    obtain ⟨z, hz, hr, hk2, hp2, hb2⟩ := ih (apply s op).1 y hy
    refine ⟨z, hz, Nat.le_trans (fwdStep_rank _ _ hf) hr, hk2.trans hk, fun e he => hp2 e (hp e he), ?_⟩
    intro hxb
    obtain ⟨hyb, hyp⟩ := hb hxb
    obtain ⟨hzb, hzp⟩ := hb2 hyb
    exact ⟨hzb, hzp.trans hyp⟩

/-! ### SL-005 and SL-010: a lapsed precedence burns (DECISIONS 63) -/

/-- SL-005, SL-010 on one committee slot: when a lapsed request holds `prec`,
the slot is BURNED. -/
def lapP (l : List Nat) (x : CSlot) : Bool :=
  match x.prec with
  | some e => !l.contains e || x.bstat == .BURNED
  | none => true

/-- SL-005, SL-010 on the state: every slot under a lapsed precedence is BURNED,
also a slot whose header opened after the lapse. -/
def lapsedBurned (s : St) : Bool := s.cslots.all (lapP s.lapsed)

theorem lapP_burnC (l : List Nat) (x : CSlot) : lapP l (burnC x) = true := by
  cases hp : x.prec <;> simp [lapP, burnC, hp]

theorem lapP_burnIfLapsed (l : List Nat) (y : CSlot) : lapP l (burnIfLapsed l y) = true := by
  unfold burnIfLapsed
  cases hp : y.prec with
  | none => simp [lapP, hp]
  | some e =>
    simp only
    split
    · exact lapP_burnC l y
    · simp_all [lapP]

theorem lapP_bstat (l : List Nat) (x : CSlot) (b : BStat) (h : lapP l x = true) (hb : x.bstat ≠ .BURNED) :
    lapP l { x with bstat := b } = true := by
  cases hp : x.prec <;> simp_all [lapP]

theorem lapP_cstep (l : List Nat) (op : Op) (x : CSlot) (h : lapP l x = true) (hop : ∀ e, op ≠ .lapse e) :
    lapP l (cstep l op x) = true := by
  cases op
  case lapse e => exact absurd rfl (hop e)
  case openC eid pos names =>
    simp only [cstep]; split
    · exact lapP_burnIfLapsed _ _
    · exact h
  case reserve eid =>
    simp only [cstep]; split
    · rename_i hc; exact lapP_bstat l x _ h (by intro hb; simp [hb] at hc)
    · exact h
  case claim eid =>
    simp only [cstep]; split
    · rename_i hc; exact lapP_bstat l x _ h (by intro hb; simp [hb] at hc)
    · exact h
  case endReq eid =>
    simp only [cstep]; split
    · exact lapP_burnC _ _
    · exact h
  case burnRange su e lo hi =>
    simp only [cstep]; split
    · exact lapP_burnC _ _
    · exact h
  all_goals exact h

theorem lapP_lapse (l : List Nat) (e : Nat) (x : CSlot) (h : lapP l x = true) :
    lapP (e :: l) (cstep l (.lapse e) x) = true := by
  simp only [cstep]
  split
  · exact lapP_burnC _ _
  · rename_i hne
    cases hp : x.prec with
    | none => simp [lapP, hp]
    | some e' =>
      have : e' ≠ e := by intro he; simp [hp, he] at hne
      simp_all [lapP]

theorem lapP_cnew (l : List Nat) (s : St) (op : Op) : ∀ x ∈ cnew s op, lapP l x = true := by
  intro x hx
  cases op <;> simp [cnew] at hx
  obtain ⟨_, _, rfl⟩ := hx
  rfl

theorem apply_lapsedBurned (s : St) (op : Op) (h : lapsedBurned s = true) : lapsedBurned (apply s op).1 = true := by
  rcases apply_fst s op with h1 | h1 <;> rw [h1]
  · exact h
  · unfold lapsedBurned at h ⊢
    rw [exec_cslots]
    simp only [List.all_append, List.all_map, Bool.and_eq_true, List.all_eq_true, Function.comp_def] at h ⊢
    cases op with
    | lapse e =>
      exact ⟨fun x hx => lapP_lapse s.lapsed e x (h x hx), fun x hx => lapP_cnew _ s _ x hx⟩
    | _ =>
      exact ⟨fun x hx => lapP_cstep s.lapsed _ x (h x hx) (by intro e he; cases he),
             fun x hx => lapP_cnew _ s _ x hx⟩

theorem runOps_lapsedBurned (s : St) (ops : List Op) (h : lapsedBurned s = true) :
    lapsedBurned (runOps s ops).1 = true := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_lapsedBurned s op h)

/-- C13 (SL-005, SL-010, DECISIONS 63): in every run from `init`, a committee slot
whose `prec` is a request with a lapsed precedence is BURNED, also when its header
opened after the lapse (`burnIfLapsed`). -/
theorem C13_run_lapsed_burned (p : Params) (ops : List Op) : lapsedBurned (run (init p) ops) = true :=
  runOps_lapsedBurned (init p) ops rfl

/-! ### SL-028 and SL-007: ECDSA burns need a reservation -/

theorem assignE_bstat (inf : List (Nat × Root)) (x : ESlot) (h : (assignE inf x).bstat = .BURNED) :
    x.bstat = .BURNED := by
  unfold assignE at h
  split at h
  · split at h
    · rename_i hc _ _
      cases hb : x.bstat <;> simp_all
    · exact h
  · exact h

theorem assignE_reserver (inf : List (Nat × Root)) (x : ESlot) : (assignE inf x).reserver = x.reserver := by
  unfold assignE; split
  · split <;> rfl
  · rfl

theorem assignE_root (inf : List (Nat × Root)) (x : ESlot) : (assignE inf x).root = x.root := by
  unfold assignE; split
  · split <;> rfl
  · rfl

theorem exec_eslots (s : St) (op : Op) : (exec s op).eslots = s.eslots.map (estep s op) ++ enew s op := by
  cases op <;> rfl

/-- C13 (SL-028, DECISIONS 54): outside a whole-committee restart burn, an ECDSA
slot turns BURNED only at the end of the request in its `reserver`. -/
theorem C13_ecdsa_burn_only_if_reserved (s : St) (op : Op) (x : ESlot) (hb : x.bstat ≠ .BURNED)
    (h : (estep s op x).bstat = .BURNED) :
    (∃ e, op = .endReq e ∧ x.reserver = some e) ∨ (∃ p, op = .burnPool p ∧ x.pool = p) := by
  cases op <;> simp only [estep] at h <;> (try exact absurd h hb)
  case openE eid pos names =>
    split at h
    · split at h
      · exact absurd (assignE_bstat _ _ h) hb
      · exact absurd h hb
    · exact absurd h hb
  case inForce eid r =>
    split at h
    · exact absurd (assignE_bstat _ _ h) hb
    · exact absurd h hb
  case reserve eid =>
    split at h
    · simp at h
    · exact absurd h hb
  case claim eid =>
    split at h
    · simp at h
    · exact absurd h hb
  case endReq eid =>
    split at h
    · rename_i hr; left; exact ⟨eid, rfl, by simpa using hr⟩
    · exact absurd h hb
  case burnPool p =>
    split at h
    · rename_i hp; right; exact ⟨p, rfl, by simpa using hp⟩
    · exact absurd h hb

theorem lowestPair_mem (ns : List (Nat × Nat)) (a : Nat × Nat) (h : lowestPair ns = some a) : a ∈ ns := by
  induction ns with
  | nil => simp [lowestPair] at h
  | cons b rest ih =>
    simp only [lowestPair] at h
    split at h
    · simp at h; simp [h]
    · rename_i c hc
      split at h
      · simp at h; subst h; exact List.mem_cons_of_mem _ (ih hc)
      · simp at h; simp [h]

theorem earliest_inForce (inf : List (Nat × Root)) (x : ESlot) (e : Nat) (h : earliest inf x = some e) :
    inf.contains (e, x.root) = true := by
  unfold earliest lowest at h
  simp only [Option.map_eq_some_iff] at h
  obtain ⟨a, ha, rfl⟩ := h
  have := lowestPair_mem _ _ ha
  simpa using (List.mem_filter.mp this).2

theorem eInv_mono (inf inf' : List (Nat × Root)) (x : ESlot) (hs : ∀ a, a ∈ inf → a ∈ inf')
    (h : eInv inf x = true) : eInv inf' x = true := by
  unfold eInv at *
  simp only [Bool.and_eq_true] at *
  constructor
  · cases hp : x.prec <;> simp_all
  · cases hr : x.reserver <;> simp_all

theorem assignE_inv (inf : List (Nat × Root)) (x : ESlot) (h : eInv inf x = true) : eInv inf (assignE inf x) = true := by
  unfold assignE
  split
  · split
    · rename_i hc e he
      have hi := earliest_inForce inf x e he
      unfold eInv at *
      simp only [Bool.and_eq_true] at *
      exact ⟨by simpa using hi, h.2⟩
    · exact h
  · exact h

theorem meta_inForce_sub (s : St) (op : Op) : ∀ a, a ∈ s.inForce → a ∈ (exec s op).inForce := by
  intro a ha; cases op <;> simp [exec, metaStep, ha]

theorem estep_inv (s : St) (op : Op) (x : ESlot) (h : eInv s.inForce x = true) :
    eInv (exec s op).inForce (estep s op x) = true := by
  have mono := meta_inForce_sub s op
  cases op <;> simp only [estep] <;> (try exact eInv_mono _ _ _ mono h)
  case openE eid pos names =>
    have h1 : eInv s.inForce { x with namers := x.namers ++ [(eid, pos)] } = true := h
    split
    · split
      · exact eInv_mono _ _ _ mono (assignE_inv _ _ h1)
      · exact eInv_mono _ _ _ mono h1
    · exact eInv_mono _ _ _ mono h
  case inForce eid r =>
    have hm : (exec s (.inForce eid r)).inForce = s.inForce ++ [(eid, r)] := rfl
    rw [hm]
    split
    · exact assignE_inv _ _ (eInv_mono _ _ _ (fun a ha => List.mem_append_left _ ha) h)
    · exact eInv_mono _ _ _ (fun a ha => List.mem_append_left _ ha) h
  case reserve eid =>
    split
    · rename_i hc
      simp only [Bool.and_eq_true, beq_iff_eq] at hc
      apply eInv_mono _ _ _ mono
      unfold eInv at *
      simp only [Bool.and_eq_true] at *
      rw [hc.1] at h
      exact ⟨by simp [hc.1]; simpa using h.1, by simpa using h.1⟩
    · exact eInv_mono _ _ _ mono h
  all_goals (split <;> exact eInv_mono _ _ _ mono h)

theorem exec_eInv (s : St) (op : Op) (h : s.eslots.all (eInv s.inForce) = true) :
    (exec s op).eslots.all (eInv (exec s op).inForce) = true := by
  rw [exec_eslots]
  simp only [List.all_append, Bool.and_eq_true, List.all_eq_true, List.mem_map] at h ⊢
  refine ⟨?_, ?_⟩
  · rintro _ ⟨x, hx, rfl⟩; exact estep_inv s op x (h x hx)
  · intro y hy
    cases op <;> simp [enew] at hy
    obtain ⟨i, _, rfl⟩ := hy
    simp [eInv]

theorem runOps_eInv (s : St) (ops : List Op) (h : s.eslots.all (eInv s.inForce) = true) :
    (runOps s ops).1.eslots.all (eInv (runOps s ops).1.inForce) = true := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih =>
    simp only [runOps]
    apply ih
    rcases apply_fst s op with h1 | h1 <;> rw [h1]
    · exact h
    · exact exec_eInv s op h

/-- C13 and C6 (SL-006, SL-008, DECISIONS 54): in every run from `init`, the
`prec` and the `reserver` of every ECDSA slot are requests whose authorization is
in force for the slot's root. A copy of a header takes no ECDSA slot. -/
theorem C13_ecdsa_prec_in_force (p : Params) (ops : List Op) :
    ∀ x ∈ (run (init p) ops).eslots, eInv (run (init p) ops).inForce x = true := by
  intro x hx
  have h := runOps_eInv (init p) ops rfl
  simp only [List.all_eq_true] at h
  exact h x hx

def eProj (x : ESlot) : (Nat × Nat) × Option Nat × BStat × Option Nat := (x.key, x.prec, x.bstat, x.reserver)

/-- SL-007: a header of a request with no authorization in force that names
ECDSA slots leaves `prec`, `bstat` and `reserver` of every ECDSA slot unchanged. -/
theorem sl007_unauthorized_namer (s : St) (eid pos : Nat) (names : List (Nat × Nat))
    (hn : ∀ r, (eid, r) ∉ s.inForce) :
    (apply s (.openE eid pos names)).1.eslots.map eProj = s.eslots.map eProj := by
  rcases apply_fst s (.openE eid pos names) with h | h <;> rw [h]
  rw [exec_eslots]
  simp only [enew, List.append_nil, List.map_map]
  apply List.map_congr_left
  intro x _
  simp only [Function.comp, estep]
  split
  · have : (eid, x.root) ∉ s.inForce := hn x.root
    simp [this, eProj, ESlot.key]
  · rfl

/-- SL-007 (scenario "Spam envelope ends"): the end of a request with no
authorization in force burns no ECDSA slot, in any state of the domain. -/
theorem sl007_unauthorized_end (s : St) (eid : Nat) (hv : s.eslots.all (eInv s.inForce) = true)
    (hn : ∀ r, (eid, r) ∉ s.inForce) :
    (apply s (.endReq eid)).1.eslots = s.eslots := by
  rcases apply_fst s (.endReq eid) with h | h <;> rw [h]
  rw [exec_eslots]
  simp only [enew, List.append_nil]
  conv => rhs; rw [← List.map_id s.eslots]
  apply List.map_congr_left
  intro x hx
  simp only [estep, id]
  split
  · rename_i hr
    simp only [List.all_eq_true] at hv
    have := hv x hx
    simp only [eInv, Bool.and_eq_true] at this
    have hr' : x.reserver = some eid := by simpa using hr
    rw [hr'] at this
    exact absurd (by simpa using this.2) (hn x.root)
  · rfl

/-! ### SL-012 to SL-014: the window -/

/-- SL-012: an index is in the window exactly for `cp.h < ℓ ≤ cp.h + B`, or for
`cp.pending_min ≤ ℓ ≤ cp.h` with `ℓ` pending for the same request, in a pool that
a landed checkpoint lists. -/
theorem sl012_window_iff (listed : Bool) (h pmin : Nat) (pending : List (Nat × Nat)) (B eid l : Nat) :
    verdict listed h pmin pending B eid l = .inWindow ↔
      listed = true ∧ ((h < l ∧ l ≤ h + B) ∨ (pmin ≤ l ∧ l ≤ h ∧ pending.contains (l, eid) = true)) := by
  unfold verdict
  cases listed
  · simp
  · by_cases h1 : h + B < l <;> by_cases h2 : h < l <;> by_cases h3 : pmin ≤ l <;>
      by_cases h4 : pending.contains (l, eid) = true <;> simp [*] <;> omega

/-- SL-013, SL-014: an index above `cp.h + B` is `above_window`; one at or below
`cp.h` is SLOT_TAKEN unless it lies in `[pending_min, cp.h]` pending for the same request. -/
theorem sl013_sl014_outside (h pmin : Nat) (pending : List (Nat × Nat)) (B eid l : Nat) :
    (h + B < l → verdict true h pmin pending B eid l = .aboveWindow)
      ∧ (l ≤ h → ¬ (pmin ≤ l ∧ pending.contains (l, eid) = true) → verdict true h pmin pending B eid l = .slotTaken) := by
  constructor
  · intro h1; simp [verdict, h1]
  · intro h1 h2
    have : ¬ h + B < l := by omega
    have b : ¬ h < l := by omega
    simp [verdict, this, b]
    intro hp hm
    exact h2 ⟨hp, by simpa using hm⟩

/-- SL-025: the qualified dealers are dealers without a valid complaint, at most `t`. -/
theorem sl025_no_complained (t : Nat) (ds : List (Nat × Bool)) (q : List Nat) (h : qualified t ds = some q) :
    q.length = t ∧ ∀ d ∈ q, (d, false) ∈ ds := by
  unfold qualified at h
  simp only at h
  split at h
  · simp at h
  · rename_i hl
    simp at h; subst h
    refine ⟨by simp only [List.length_take]; omega, ?_⟩
    intro d hd
    have := List.mem_of_mem_take hd
    simp only [List.mem_map, List.mem_filter] at this
    obtain ⟨⟨a, b⟩, ⟨hm, hb⟩, rfl⟩ := this
    simp at hb; subst hb; exact hm

/-- SL-026: with `slot_anchor` on, the gate passes only for the ticket of a
covered binding, and never for two tickets of one nullifier. -/
theorem sl026_one_ticket (cov : List (Nat × Nat)) (nf d d' : Nat)
    (h1 : anchorOk true cov nf d = true) (h2 : anchorOk true cov nf d' = true) : d = d' := by
  simp only [anchorOk, Bool.not_true, Bool.false_or, Bool.and_eq_true, Bool.not_eq_true',
    List.any_eq_false, List.contains_iff_mem] at h1 h2
  have := h1.2 (nf, d') h2.1
  simp at this
  exact this.symm

end SplitSlots
