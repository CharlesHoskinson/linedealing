/-!
# Authorization oracle (split-authorization, AU-001 to AU-028)

The executable reference semantics of the OpenSpec capability
`split-authorization`
(`openspec/changes/add-split-line-dealing/specs/split-authorization/spec.md`).

The state is the FenrirAssets contract (charters, asset records with their
authorizations, the used nullifiers, the hold accumulator, the recovery
transition) together with one committee node's board-first view (the pending
set and the in-force board-first calls, AU-013 to AU-016).

Abstractions (formal plugin, practice 11):
* Hashes are collision free and are inputs: `auth`, `rh`, `cm_addr`, the hold
  tag and the slot roots are numbers.
* A nullifier is `fresh n` (a record birth) or `ofSettle auth outcome`, the
  nullifier `N(nsk, auth, outcome)` of a settlement successor (AU-023). So two
  successors never share a nullifier, and none equals a fresh one.
* The `authorize` proof is the statement it proves: the call carries the
  record, the nullifier, the source, the named ECDSA slot root and the outcomes
  of the item checks that read data outside the contract (inputs and fee
  ceiling, owner-chosen predicates and approvers, `S ∈ Γ`, the registry
  blacklist, the ticket proof). The hold accumulator, the record fields and the
  recovery transition are contract state and are read from the state.
* A checkpoint landing (`settle_root` leaves, `bf_root` tuples), a carried VOID
  leaf with its signature count, Midnight finality heights and the recovery
  transition enter as operations.
-/

namespace SplitAuthorization

/-! ## Domains -/

inductive Mode where
  | TEE | NON_TEE
  deriving Repr, DecidableEq

inductive Profile where
  | P0 | P1 | P2
  deriving Repr, DecidableEq

/-- AU-001 -/
inductive RState where
  | UNSPENT | PENDING | LOCKED
  deriving Repr, DecidableEq

/-- AU-002 -/
inductive Status where
  | SUBMITTED | FINAL | REVOKED
  deriving Repr, DecidableEq

/-- AU-002: `settled ∈ {NONE, FINAL, VOID, RELEASED}` -/
inductive Settled where
  | NONE | FINAL | VOID | RELEASED
  deriving Repr, DecidableEq

def Settled.isNone : Settled → Bool
  | .NONE => true
  | _ => false

def Settled.isFinal : Settled → Bool
  | .FINAL => true
  | _ => false

def Settled.isRel : Settled → Bool
  | .RELEASED => true
  | _ => false

/-- AU-006: the owner or initiator source, the seizure-order source, the recovery-exit source. -/
inductive Source where
  | OWNER | SEIZURE | RECOVERY
  deriving Repr, DecidableEq

/-- AU-001, AU-006: an ECDSA slot lies under `slr_own` or `slr_G`. -/
inductive Root where
  | OWN | G
  deriving Repr, DecidableEq

/-- A nullifier: fresh at birth (AU-001), or `N(nsk, auth, outcome)` of a
settlement successor (AU-023). -/
inductive Nf where
  | fresh (n : Nat)
  | ofSettle (auth : Nat) (o : Settled)
  deriving Repr, DecidableEq

def Nf.isFresh : Nf → Bool
  | .fresh _ => true
  | _ => false

/-! ## State -/

/-- AU-002: an authorization. `source` and `pin` (the pinned input or nonce that
its intent spends) are known for a Midnight-first call; `direct` says the call
came by `authorize` (AU-004) and not by a `bf_root` (AU-026). -/
structure Auth where
  auth : Nat
  nf : Nf
  rh : Nat
  status : Status
  finalHeight : Option Nat
  settled : Settled
  source : Option Source
  pin : Option Nat
  direct : Bool
  deriving Repr, DecidableEq

/-- AU-001: an asset record. `spent` marks a record whose authorization settled
FINAL: its successor is the change record (AU-023), which lands as a record of
its own (ledger 3). `auths` are the authorizations of the record. -/
structure Rec where
  rid : Nat
  cmAddr : Nat
  profile : Profile
  boardFirst : Bool
  rstate : RState
  nf : Nf
  pin : Option Nat
  holdTag : Nat
  slrOwn : Option Nat
  slrG : Option Nat
  spent : Bool
  auths : List Auth
  deriving Repr, DecidableEq

/-- AU-011: a registered charter. -/
structure Charter where
  cid : Nat
  profile : Profile
  boardFirst : Bool
  deriving Repr, DecidableEq

/-- The node's board-first view (AU-013 to AU-016): the pending set, the
in-force calls `(auth, nf)` and the nullifiers of landed `bf_root` leaves. -/
structure Node where
  pending : List Nf
  inForce : List (Nat × Nf)
  landed : List Nf
  deriving Repr, DecidableEq

structure Params where
  mode : Mode
  /-- the quorum `q` of the epoch key set `EKS_e` (AU-021, AU-022) -/
  q : Nat
  deriving Repr, DecidableEq

structure St where
  params : Params
  charters : List Charter
  records : List Rec
  /-- `(nf, auth)` of every accepted `authorize`, newest first (AU-008) -/
  used : List (Nf × Nat)
  /-- the hold accumulator (AU-018) -/
  holds : List Nat
  /-- a recovery transition is recorded on Midnight (AU-027) -/
  recovered : Bool
  node : Node
  deriving Repr, DecidableEq

def init (p : Params) : St :=
  { params := p, charters := [], records := [], used := [], holds := [], recovered := false,
    node := { pending := [], inForce := [], landed := [] } }

/-! ## Calls -/

/-- AU-021: a carried settlement leaf `(auth_0, outcome)` with the number of its
signatures that verify against `EKS_e`. -/
structure Carry where
  auth0 : Nat
  outcome : Settled
  sigs : Nat
  deriving Repr, DecidableEq

/-- An `authorize` call (AU-003 to AU-009, AU-012, AU-021, AU-022, AU-027).
`slot` is the ECDSA slot root the call names, as `(record, root)`, or none. -/
structure Call where
  rid : Nat
  nf : Nf
  auth : Nat
  rh : Nat
  source : Source
  slot : Option (Nat × Root)
  inputsOk : Bool
  predOk : Bool
  inGamma : Bool
  blacklisted : Bool
  ticketOk : Bool
  pin : Nat
  toExit : Bool
  carry : Option Carry
  deriving Repr, DecidableEq

/-- AU-026: a tuple `(auth, nf, rh, root)` of a `bf_root`. -/
structure BfTuple where
  auth : Nat
  nf : Nf
  rh : Nat
  root : Nat
  deriving Repr, DecidableEq

/-- AU-013: a board-first call as the node checks it. `rootAge` is the age of
its state root; `bound`, `interval` and `fM` are the charter bound, the
checkpoint interval and `F_M`. `carrySigs` is the number of the `q` signatures
on a carried VOID leaf that verify, for a reissue. -/
structure BfCall where
  auth : Nat
  nf : Nf
  proofOk : Bool
  rootFinal : Bool
  rootAge : Nat
  bound : Nat
  interval : Nat
  fM : Nat
  carrySigs : Option Nat
  deriving Repr, DecidableEq

/-! ## Refusals

One constructor for each distinct response, in code order; several codes that
apply together are all returned (ledger 1).

| Code | IDs |
|---|---|
| `bad_carry` | AU-022 |
| `board_first_forbidden` | AU-011 |
| `board_first_record` | AU-012 |
| `nf_pending` | AU-015 |
| `nf_used` | AU-008 |
| `no-rule` | the statement of AU-005 to AU-007 fails, AU-013 fails, or no requirement defines the event (ledger 2) |
| `no_recovery` | AU-027 |
| `not_revocable` | AU-019 |
| `outside-capability` | a value outside a domain sentence (ledger 5) |
| `outside-state-domain` | a `--step` state outside `validState` |
| `pin_mismatch` | AU-009 |
-/

inductive Refusal where
  | badCarry | boardFirstForbidden | boardFirstRecord | nfPending | nfUsed | noRule | noRecovery
  | notRevocable | outsideCapability | outsideStateDomain | pinMismatch
  deriving Repr, DecidableEq

def Refusal.code : Refusal → String
  | .badCarry => "bad_carry"
  | .boardFirstForbidden => "board_first_forbidden"
  | .boardFirstRecord => "board_first_record"
  | .nfPending => "nf_pending"
  | .nfUsed => "nf_used"
  | .noRule => "no-rule"
  | .noRecovery => "no_recovery"
  | .notRevocable => "not_revocable"
  | .outsideCapability => "outside-capability"
  | .outsideStateDomain => "outside-state-domain"
  | .pinMismatch => "pin_mismatch"

def opt (b : Bool) (r : Refusal) : List Refusal := if b then [r] else []

/-! ## The statement (AU-005 to AU-007) -/

/-- AU-006: owner or initiator for P0, P1 and P2; seizure for P2 only; recovery
exit for P1 and P2 only. -/
def sourceOk : Profile → Source → Bool
  | _, .OWNER => true
  | .P2, .SEIZURE => true
  | .P1, .RECOVERY => true
  | .P2, .RECOVERY => true
  | _, _ => false

/-- AU-007: owner-chosen predicates and approvers (and `S ∈ Γ`, AU-006) for the
owner source of P1 and P2; the registry blacklist for that source in P2; the
hold accumulator for the owner and recovery sources in P2; no check for a P1
recovery exit, and none for the seizure source. -/
def checksOk (held : Bool) (p : Profile) (c : Call) : Bool :=
  match c.source, p with
  | .OWNER, .P0 => true
  | .OWNER, .P1 => c.predOk && c.inGamma
  | .OWNER, .P2 => c.predOk && c.inGamma && !c.blacklisted && !held
  | .RECOVERY, .P2 => !held
  | _, _ => true

/-- AU-006: the root that a source opens. -/
def rootOf : Source → Root
  | .SEIZURE => .G
  | _ => .OWN

/-- AU-005 item 4 and AU-006: a named ECDSA slot lies under the record's own
root that the source opens. -/
def slotOk (r : Rec) (c : Call) : Bool :=
  match c.slot with
  | none => true
  | some (rid', root) =>
    rid' == r.rid && root == rootOf c.source
      && (match root with
          | .OWN => r.slrOwn.isSome
          | .G => r.slrG.isSome)

/-- AU-005: items 1 to 4, and item 5 in NON_TEE mode. Item 1 here is the
record's current nullifier on a record that is not spent; that the nullifier is
unused is AU-008 (`nf_used`) and that a LOCKED record spends its pin is AU-009
(`pin_mismatch`). -/
def statementOk (m : Mode) (held : Bool) (r : Rec) (c : Call) : Bool :=
  c.nf == r.nf && !r.spent && c.inputsOk && sourceOk r.profile c.source
    && checksOk held r.profile c && slotOk r c && (m == .TEE || c.ticketOk)

/-! ## Settlement (AU-020, AU-021, AU-023) -/

def sel (a : Nat) (b : Auth) : Bool := b.auth == a && b.settled.isNone

def upd (a : Nat) (o : Settled) (b : Auth) : Auth :=
  if sel a b then { b with settled := o } else b

/-- AU-029: an authorization accepted on a LOCKED record. A record holds a pin
exactly from a RELEASED settlement on (AU-023), and keeps it while LOCKED,
PENDING under a later authorization, or LOCKED again after its VOID settlement,
so the pin marks the records whose current authorization was accepted LOCKED. -/
def lockedAtAccept (r : Rec) : Bool := r.pin.isSome

/-- AU-020, AU-023 and AU-029: settle authorization `a` of the record with
`outcome`, when it has `settled = NONE`, and make the successor: the record is
spent (its change record lands by itself) for FINAL; under `N(nsk, auth, VOID)`
for VOID, UNSPENT when the authorization was accepted on an UNSPENT record and
LOCKED to the same pin when it was accepted on a LOCKED one (AU-029, DECISIONS
60); LOCKED to the pinned input or nonce for RELEASED (ledger 4). -/
def settleIn (a : Nat) (o : Settled) (r : Rec) : Rec :=
  if r.auths.any (sel a) then
    let pinOf := ((r.auths.find? (sel a)).bind (·.pin))
    let r1 := { r with auths := r.auths.map (upd a o) }
    match o with
    | .FINAL => { r1 with spent := true }
    | .VOID => { r1 with nf := .ofSettle a .VOID, rstate := if lockedAtAccept r then .LOCKED else .UNSPENT }
    | .RELEASED => { r1 with nf := .ofSettle a .RELEASED, rstate := .LOCKED, pin := pinOf }
    | .NONE => r
  else r

def settleAll (s : St) (a : Nat) (o : Settled) : St :=
  { s with records := s.records.map (settleIn a o) }

/-- every authorization of the state -/
def allAuths (s : St) : List Auth := s.records.flatMap (·.auths)

def authExists (s : St) (a : Nat) : Bool := (allAuths s).any (·.auth == a)

/-- AU-021: a valid carried leaf `(auth_0, VOID)` with `q` signatures. -/
def carryOk (q : Nat) (k : Carry) : Bool := k.outcome == .VOID && decide (q ≤ k.sigs)

/-- The state after the carried settlement of a call, when the carry is valid. -/
def afterCarry (s : St) (c : Call) : St :=
  match c.carry with
  | some k => if carryOk s.params.q k then settleAll s k.auth0 .VOID else s
  | none => s

/-! ## Operations -/

inductive Op where
  /-- AU-011: a charter registers -/
  | charter (cid : Nat) (profile : Profile) (boardFirst stateful : Bool)
  /-- AU-001: a record with its birth certificate lands under a charter -/
  | record (rid cid cmAddr : Nat) (nf : Nf) (holdTag : Nat) (slrOwn slrG : Option Nat)
  /-- AU-004: an `authorize` call reaches Midnight -/
  | authorize (c : Call)
  /-- AU-002, AU-010: the `authorize` transaction of `auth` is final at Midnight height `h` -/
  | finalize (auth h : Nat)
  /-- AU-018, AU-019: `revoke(auth)` with `SetHold(tag)` -/
  | revoke (auth tag : Nat)
  /-- AU-020: a checkpoint lands with a `settle_root` over these leaves -/
  | settleRoot (leaves : List (Nat × Settled))
  /-- AU-026: a checkpoint lands with a `bf_root` over these tuples -/
  | bfRoot (ts : List BfTuple)
  /-- AU-027: a recovery transition is recorded on Midnight -/
  | recover
  /-- AU-013 to AU-015: the board orders a board-first call -/
  | bfCall (c : BfCall)
  /-- AU-010, AU-016: is `auth` in force for the node at Midnight height `h` -/
  | query (auth h : Nat)
  /-- AU-028: admission of a seizure request; does every output pay `D_reg` -/
  | seizure (auth : Nat) (allToDreg : Bool)
  deriving Repr, DecidableEq

inductive Obs where
  | accepted
  | refused (codes : List Refusal)
  | ok
  | inForce (b : Bool)
  /-- the committee node posts VOID with this reason (AU-028: AUTH_REFUSED) -/
  | void (reason : String)
  deriving Repr, DecidableEq

def recOf (s : St) (rid : Nat) : List Rec := s.records.filter (·.rid == rid)

/-- AU-008, AU-009, AU-012, AU-022, AU-027 and the statement, over the state
after a valid carry. -/
def authorizeRefusals (s : St) (c : Call) : List Refusal :=
  let s1 := afterCarry s c
  let rs := recOf s1 c.rid
  let held (r : Rec) := s1.holds.contains r.holdTag
  let badCarry := match c.carry with
    | some k => !carryOk s.params.q k
    | none => false
  -- a valid carry whose `auth_0` has no unsettled authorization (ledger 6)
  let carryNoRule := match c.carry with
    | some k => carryOk s.params.q k && !(allAuths s).any (sel k.auth0)
    | none => false
  let fresh := !authExists s c.auth && (match c.carry with
    | some k => k.auth0 != c.auth
    | none => true)
  opt badCarry .badCarry ++ opt (rs.any (·.boardFirst)) .boardFirstRecord
    ++ opt ((s1.used.map (·.1)).contains c.nf) .nfUsed
    ++ opt (rs.isEmpty || carryNoRule || rs.any (fun r => !statementOk s.params.mode (held r) r c)) .noRule
    ++ opt (c.source == .RECOVERY && (!s1.recovered || !c.toExit)) .noRecovery
    ++ opt (!fresh) .outsideCapability
    ++ opt (rs.any (fun r => r.rstate == .LOCKED && r.pin != some c.pin)) .pinMismatch

def newAuth (c : Call) : Auth :=
  { auth := c.auth, nf := c.nf, rh := c.rh, status := .SUBMITTED, finalHeight := none,
    settled := .NONE, source := some c.source, pin := some c.pin, direct := true }

/-- AU-004: the record goes PENDING and the authorization is added SUBMITTED. -/
def addAuth (c : Call) (r : Rec) : Rec :=
  if r.rid == c.rid then { r with rstate := .PENDING, auths := newAuth c :: r.auths } else r

/-- AU-018: P2, `status` SUBMITTED or FINAL, `settled = NONE`, the record's tag.
AU-019: a P0 or P1 record, or `settled ≠ NONE`. -/
def revokeRefusals (s : St) (a tag : Nat) : List Refusal :=
  let hits := s.records.filter (fun r => r.auths.any (·.auth == a))
  let bs := (allAuths s).filter (·.auth == a)
  opt (hits.isEmpty
        || hits.any (fun r => r.holdTag != tag)
        || bs.any (fun b => b.status == .REVOKED)) .noRule
    ++ opt (hits.any (fun r => r.profile != .P2) || bs.any (fun b => !b.settled.isNone)) .notRevocable

def revokeIn (a : Nat) (b : Auth) : Auth := if b.auth == a then { b with status := .REVOKED } else b

def finalIn (a h : Nat) (b : Auth) : Auth :=
  if b.auth == a && b.status == .SUBMITTED then { b with status := .FINAL, finalHeight := some h } else b

/-- AU-026: move a board-first record whose current nullifier is the tuple's to
PENDING under its `auth`. -/
def bfIn (t : BfTuple) (r : Rec) : Rec :=
  if r.boardFirst && r.nf == t.nf then
    { r with rstate := .PENDING,
             auths := { auth := t.auth, nf := t.nf, rh := t.rh, status := .SUBMITTED, finalHeight := none,
                        settled := .NONE, source := none, pin := none, direct := false } :: r.auths }
  else r

def bfAll (ts : List BfTuple) (r : Rec) : Rec := ts.foldl (fun r t => bfIn t r) r

def settleLeaves (leaves : List (Nat × Settled)) (r : Rec) : Rec :=
  leaves.foldl (fun r l => settleIn l.1 l.2 r) r

def nodupB {α : Type} [BEq α] : List α → Bool
  | [] => true
  | x :: xs => !xs.contains x && nodupB xs

/-- AU-013: the checks of a board-first call at the node. -/
def bfChecks (s : St) (c : BfCall) : Bool :=
  c.proofOk && c.rootFinal && decide (c.rootAge + c.interval + c.fM ≤ c.bound)
    && !s.node.landed.contains c.nf
    && (match c.carrySigs with
        | some k => decide (s.params.q ≤ k)
        | none => true)

/-- AU-010: a Midnight-first authorization is in force from the Midnight block at
which its transaction is final. -/
def finalAt (h : Nat) (b : Auth) : Bool :=
  match b.finalHeight with
  | some f => decide (f ≤ h)
  | none => false

def inForceMidnight (s : St) (a h : Nat) : Bool := (allAuths s).any (fun b => b.auth == a && finalAt h b)

/-- AU-016: a board-first authorization is in force once verified and ordered first for its `nf`. -/
def inForceBoard (s : St) (a : Nat) : Bool := s.node.inForce.any (·.1 == a)

def opRefusals (s : St) : Op → List Refusal
  | .charter cid p bf stateful =>
    opt (bf && (p == .P2 || stateful)) .boardFirstForbidden
      ++ opt (s.charters.any (·.cid == cid)) .outsideCapability
  | .record rid cid _ nf _ _ slrG =>
    match s.charters.find? (·.cid == cid) with
    | none => [.noRule]
    | some ch =>
      opt (s.records.any (·.rid == rid) || !nf.isFresh || (s.used.map (·.1)).contains nf
            || s.records.any (·.nf == nf) || (slrG.isSome && ch.profile != .P2)) .outsideCapability
  | .authorize c => authorizeRefusals s c
  | .finalize a _ => opt (!(allAuths s).any (fun b => b.auth == a && b.status == .SUBMITTED)) .noRule
  | .revoke a tag => revokeRefusals s a tag
  | .settleRoot leaves => opt (leaves.any (·.2.isNone)) .outsideCapability
  | .bfRoot ts =>
    opt (!ts.all (fun t => s.records.any (fun r => r.boardFirst && r.nf == t.nf))) .noRule
      ++ opt (ts.any (fun t => authExists s t.auth) || !nodupB (ts.map (·.auth))) .outsideCapability
  | .recover => []
  | .bfCall c =>
    -- AU-015 applies to a verified call only
    opt (!bfChecks s c) .noRule ++ opt (bfChecks s c && s.node.pending.contains c.nf) .nfPending
  | .query _ _ => []
  | .seizure a _ => opt (!(allAuths s).any (fun b => b.auth == a && b.source == some .SEIZURE)) .noRule

/-- AU-001: a new record is UNSPENT with a fresh `nf`, under its charter's profile and `board_first`. -/
def newRec (rid cmAddr : Nat) (ch : Charter) (nf : Nf) (tag : Nat) (slrOwn slrG : Option Nat) : Rec :=
  { rid := rid, cmAddr := cmAddr, profile := ch.profile, boardFirst := ch.boardFirst, rstate := .UNSPENT,
    nf := nf, pin := none, holdTag := tag, slrOwn := slrOwn, slrG := slrG, spent := false, auths := [] }

def exec (s : St) : Op → St × Obs
  | .charter cid p bf _ => ({ s with charters := s.charters ++ [{ cid, profile := p, boardFirst := bf }] }, .accepted)
  | .record rid cid cmAddr nf tag slrOwn slrG =>
    match s.charters.find? (·.cid == cid) with
    | none => (s, .refused [.noRule])
    | some ch =>
      ({ s with records := s.records ++ [newRec rid cmAddr ch nf tag slrOwn slrG] }, .accepted)
  | .authorize c =>
    -- AU-021: the carried VOID leaf settles `auth_0`; AU-004: the record goes PENDING
    let s1 := afterCarry s c
    ({ s1 with records := s1.records.map (addAuth c), used := (c.nf, c.auth) :: s1.used }, .accepted)
  | .finalize a h => ({ s with records := s.records.map (fun r => { r with auths := r.auths.map (finalIn a h) }) }, .ok)
  | .revoke a tag =>
    -- AU-018: REVOKED, and `tag` joins the hold accumulator
    ({ s with records := s.records.map (fun r => { r with auths := r.auths.map (revokeIn a) }),
              holds := tag :: s.holds }, .ok)
  | .settleRoot leaves => ({ s with records := s.records.map (settleLeaves leaves) }, .ok)
  | .bfRoot ts =>
    let nfs := ts.map (·.nf)
    ({ s with records := s.records.map (bfAll ts),
              node := { s.node with pending := s.node.pending.filter (fun x => !nfs.contains x),
                                    landed := s.node.landed ++ nfs } }, .ok)
  | .recover => ({ s with recovered := true }, .ok)
  -- AU-014, AU-016: the first verified call for `nf` is pending and in force
  | .bfCall c => ({ s with node := { s.node with pending := c.nf :: s.node.pending,
                                                   inForce := (c.auth, c.nf) :: s.node.inForce } }, .accepted)
  | .query a h => (s, .inForce (inForceMidnight s a h || inForceBoard s a))
  -- AU-028: a seizure output that does not pay `D_reg` is VOID AUTH_REFUSED
  | .seizure _ allToDreg => (s, if allToDreg then .ok else .void "AUTH_REFUSED")

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

/-- The state domain of `--step`: distinct charters, records and authorizations,
distinct used nullifiers. It is not a reachability check. -/
def validState (s : St) : Bool :=
  nodupB (s.charters.map (·.cid)) && nodupB (s.records.map (·.rid))
    && nodupB ((allAuths s).map (·.auth)) && nodupB (s.used.map (·.1))

def stepRefusals (s : St) : List Refusal := opt (!validState s) .outsideStateDomain

theorem stepRefusals_nil_iff (s : St) : stepRefusals s = [] ↔ validState s = true := by
  unfold stepRefusals opt; cases validState s <;> simp

/-- A refused operation leaves the state unchanged. -/
theorem apply_refused (s : St) (op : Op) (h : opRefusals s op ≠ []) : (apply s op).1 = s := by
  unfold apply; split
  · contradiction
  · rfl

end SplitAuthorization
