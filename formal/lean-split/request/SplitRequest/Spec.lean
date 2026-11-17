/-!
# Request oracle (split-request, RQ-001 to RQ-074)

The executable reference semantics of the OpenSpec capability `split-request`
(`openspec/changes/add-split-line-dealing/specs/split-request/spec.md`).

Two parts:

* The request state machine (MOD-001): the board's record of every request,
  changed by board events (post, order, open, votes, frames, complaints,
  release records, FINAL and VOID posts, the board height, rotations,
  checkpoints, restart burns). `apply` runs one event.
* The honest committee node's decision (`nodeAct`): from the board record of a
  request and the node's local view (its share check, its header open, the
  authorization as it reads Midnight, the slot judge, release checks, acks), the
  messages the node sends, the votes and posts it makes, and the refusals it
  gives. The node rules RQ-008 to RQ-061 that say "the committee node SHALL"
  are branches of `nodeAct`.

Abstractions (formal plugin, practice 11):
* Cryptographic outcomes (share check, header open, release check, combined
  signature, contribution equation) and other capabilities' facts
  (authorization in force or refused, revocation height, slot judge of
  SL-012 to SL-016, acks of the witness, slot bind) enter as fields of the
  node's view or of an event.
* The host chain enters as the fee median at each host height (`hostMed`, for
  the selection rule of RQ-027) and as a confirmation fact per request
  (`confirm`).
* A request's settlement leaf `(auth, outcome)` is held by Midnight when a
  landed checkpoint covers its end (`endHeight ≤ cpHeight`) or when a reissue
  carried it (`carried`) (RQ-054, D-058).
-/

namespace SplitRequest

/-! ## Domains (RQ-001, RQ-064 to RQ-067) -/

inductive Mode where
  | TEE | NON_TEE
  deriving Repr, DecidableEq

/-- RQ-064 -/
inductive Phase where
  | POSTED | ORDERED | OPENED | COLLECTING | ADMITTED | FINAL | VOID | EXPIRED
  deriving Repr, DecidableEq

/-- RQ-064 -/
inductive Outcome where
  | NONE | FINAL | VOID | RELEASED
  deriving Repr, DecidableEq

/-- RQ-065 -/
inductive Reason where
  | NONE | SHARE_COMPLAINT | MALFORMED | AUTH_REFUSED | REVOKED | RELEASE_CHECK | CONTRIBUTION
  | DEALER_FAULT | PIN_SPENT | SLOT_TAKEN | STALLED | RESTART
  /-- RQ-065, RQ-072: the reason of a VOID tombstone whose posts name no common
  reason; no node posts it. -/
  | MIXED
  deriving Repr, DecidableEq

/-- RQ-066 -/
inductive RType where
  | SPEND | EXIT | SEIZURE | BIRTH | REFILL | P0 | CONTRIB
  deriving Repr, DecidableEq

/-- RQ-066 -/
inductive Profile where
  | P0 | P1 | P2
  deriving Repr, DecidableEq

/-- RQ-001: the committee parameters. `deltaHold` is `Δ_hold` of RQ-033. -/
structure Params where
  n : Nat
  f : Nat
  deltaC : Nat
  deltaHold : Nat
  mode : Mode
  deriving Repr, DecidableEq

/-- RQ-001: `q = ⌈(n + f + 1)/2⌉`. -/
def qOf (n f : Nat) : Nat := (n + f + 2) / 2
def Params.q (p : Params) : Nat := qOf p.n p.f
/-- RQ-001: `t = n − f`. -/
def Params.t (p : Params) : Nat := p.n - p.f
/-- RQ-001: `w = n − 1 − f`. -/
def Params.w (p : Params) : Nat := p.n - 1 - p.f
/-- RQ-001, RQ-067: `G_max = 2`, `K_max = 8`. -/
def gMax : Nat := 2
def kMax : Nat := 8

/-- RQ-001: the domain `n ≥ 3f + 1` and `f ≥ 1`. -/
def committeeOk (n f : Nat) : Bool := decide (1 ≤ f) && decide (3 * f + 1 ≤ n)

def Phase.terminal : Phase → Bool
  | .FINAL | .VOID | .EXPIRED => true
  | _ => false

/-- RQ-056: the order of the live phases. -/
def Phase.rank : Phase → Nat
  | .POSTED => 0 | .ORDERED => 1 | .OPENED => 2 | .COLLECTING => 3 | .ADMITTED => 4
  | .FINAL => 5 | .VOID => 5 | .EXPIRED => 5

/-- RQ-062: request types that keep no signing state. -/
def RType.signing : RType → Bool
  | .BIRTH | .REFILL | .CONTRIB => false
  | _ => true

/-! ## The request record (RQ-002) -/

/-- A contribution frame (RQ-018 to RQ-021): its position in the actor slot
table, whether its token opens `H(τ_a)` of that position, whether it holds one
sealed contribution of the right length for every variant body, the board
height it was ordered at, and an id for the contribution. -/
structure Frame where
  position : Nat
  tokenOk : Bool
  lengthsOk : Bool
  height : Nat
  cid : Nat
  deriving Repr, DecidableEq

structure Req where
  eid : Nat
  epoch : Nat
  exp : Nat
  rtype : RType
  profile : Profile
  orderPos : Option Nat
  expC : Option Nat
  phase : Phase
  reason : Reason
  collecting : Bool
  K : Nat
  L : Nat
  G : Nat
  /-- `anchor[1]`, `anchor[2]` -/
  anchor1 : Option Nat
  anchor2 : Option Nat
  /-- `released[1]`, `released[2]` -/
  released1 : Option Nat
  released2 : Option Nat
  anyRelease : Bool
  restartEnd : Bool
  outcome : Outcome
  /-- the board record the counting and order rules read -/
  rates : List Nat
  positions : List (Option Nat)
  held : List Frame
  openedVotes : List (Nat × Nat)
  admitVotes : List (Nat × Nat × Nat)
  earlyComplaint : Bool
  dealerFault : Bool
  finalPosts : List (Nat × Nat × Nat)
  voidPosts : List (Nat × Nat × Reason)
  endHeight : Option Nat
  confirmed : Bool
  carried : Bool
  deriving Repr, DecidableEq

/-- RQ-002, RQ-003: a new request. The header values `K`, `L`, `G` are unknown
until OPENED and are 0 (ledger 3). -/
def newReq (eid epoch exp : Nat) (rtype : RType) (profile : Profile) : Req :=
  { eid, epoch, exp, rtype, profile, orderPos := none, expC := none, phase := .POSTED,
    reason := .NONE, collecting := false, K := 0, L := 0, G := 0, anchor1 := none, anchor2 := none,
    released1 := none, released2 := none, anyRelease := false, restartEnd := false,
    outcome := .NONE, rates := [], positions := [], held := [], openedVotes := [], admitVotes := [],
    earlyComplaint := false, dealerFault := false, finalPosts := [], voidPosts := [],
    endHeight := none, confirmed := false, carried := false }

/-! ## State -/

/-- The board context of every request. `epochs` holds `(e, n_e, f_e)` of each
registered epoch (RQ-042, RQ-043). `hostMed` holds the host chain's fee median
at each host height (RQ-027). `cpHeight` is the board height of the latest
landed checkpoint (RQ-054, RQ-068). -/
structure Ctx where
  params : Params
  height : Nat
  cpHeight : Nat
  epochs : List (Nat × Nat × Nat)
  hostMed : List (Nat × Nat)
  deriving Repr, DecidableEq

structure St where
  ctx : Ctx
  reqs : List Req
  deriving Repr, DecidableEq

def init (p : Params) (epochs : List (Nat × Nat × Nat)) : St :=
  { ctx := { params := p, height := 0, cpHeight := 0, epochs, hostMed := [] }, reqs := [] }

/-! ## Refusals

| Code | IDs |
|---|---|
| `exp_c_not_below_exp` | EN-023 (the ordering block, RQ-006 scenario) |
| `late_contribution` | RQ-020 |
| `no_qc` | RQ-007 |
| `not_in_force` | RQ-024 (node) |
| `position_filled` | RQ-019 |
| `settled` | RQ-061 (node); a restart burn of a carried leaf (ledger 12) |
| `terminal` | RQ-005 |
| `unknown_epoch` | RQ-043 |
| `unknown_request` | RQ-004 |
| `above_window`, `pool_unlisted` | SL-014, SL-015 (node, read through the slot judge) |
| `no-rule` | an event that no requirement gives a transition (ledger) |
| `outside-capability` | a value outside a domain sentence |
| `outside-state-domain` | a `--step` state outside `validState` |

The constructor order is the code order. Several spec codes that apply together
are all returned (ledger 1). `no-rule` is returned only when no spec code
applies. -/

inductive Refusal where
  | aboveWindow | expCNotBelowExp | lateContribution | noRule | noQc | notInForce | outsideCapability
  | outsideStateDomain | poolUnlisted | positionFilled | settled | terminal | unknownEpoch
  | unknownRequest
  deriving Repr, DecidableEq

def Refusal.code : Refusal → String
  | .aboveWindow => "above_window"
  | .expCNotBelowExp => "exp_c_not_below_exp"
  | .lateContribution => "late_contribution"
  | .noRule => "no-rule"
  | .noQc => "no_qc"
  | .notInForce => "not_in_force"
  | .outsideCapability => "outside-capability"
  | .outsideStateDomain => "outside-state-domain"
  | .poolUnlisted => "pool_unlisted"
  | .positionFilled => "position_filled"
  | .settled => "settled"
  | .terminal => "terminal"
  | .unknownEpoch => "unknown_epoch"
  | .unknownRequest => "unknown_request"

def opt (b : Bool) (r : Refusal) : List Refusal := if b then [r] else []

/-- The spec codes, or `no-rule` when none applies and `ok` is false. -/
def orNoRule (spec : List Refusal) (ok : Bool) : List Refusal :=
  if spec.isEmpty then opt (!ok) .noRule else spec

/-! ## Helpers -/

def nodupB {α : Type} [BEq α] : List α → Bool
  | [] => true
  | x :: xs => !xs.contains x && nodupB xs

def insertDesc (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys => if y ≤ x then x :: y :: ys else y :: insertDesc x ys

/-- The heights sorted highest first (RQ-027, SCHEME §3.6 by reference). An
insertion sort, so the kernel evaluates the pins. -/
def sortDesc : List Nat → List Nat
  | [] => []
  | x :: xs => insertDesc x (sortDesc xs)

/-- RQ-027: the anchor height is entry `f + 1` of the heights sorted highest first. -/
def anchorHeight (f : Nat) (hs : List Nat) : Nat := (sortDesc hs).getD f 0

/-- The first variant (from 1) whose fee rate meets the median. -/
def firstMeet (m : Nat) : List Nat → Option Nat
  | [] => none
  | r :: rs => if m ≤ r then some 1 else (firstMeet m rs).map (· + 1)

/-- RQ-027: "first variant whose fee rate meets the anchored median, else the
highest" (DESIGN §4.6 by reference); the highest is variant `K` (ledger 6). -/
def select (k : Nat) (rates : List Nat) (m : Nat) : Nat :=
  match firstMeet m rates with
  | some i => i
  | none => k

def lookupMed (c : Ctx) (h : Nat) : Option Nat := (c.hostMed.find? (·.1 == h)).map (·.2)

def epochOf (c : Ctx) (e : Nat) : Option (Nat × Nat) :=
  (c.epochs.find? (·.1 == e)).map (·.2)

/-- RQ-050 to RQ-052: the outcome of a VOID or EXPIRED end. -/
def endOutcome (r : Req) : Outcome :=
  if r.restartEnd then (if r.confirmed then .FINAL else .RELEASED)
  else if r.anyRelease then .RELEASED else .VOID

/-- RQ-054, D-058: Midnight holds the leaf of an ended request when a landed
checkpoint covers its end or a reissue carried it. -/
def leafHeld (c : Ctx) (r : Req) : Bool :=
  r.carried || (match r.endHeight with
    | some h => decide (h ≤ c.cpHeight)
    | none => false)

def countWith {α : Type} (p : α → Bool) (xs : List α) : Nat := (xs.filter p).length

/-! ## Events -/

inductive Op where
  /-- RQ-003: an envelope passed the public checks (EN-004 to EN-008) -/
  | post (eid epoch exp : Nat) (rtype : RType) (profile : Profile)
  /-- RQ-006, RQ-007: a block at board position `p` names the envelope; `qc` -/
  | order (eid : Nat) (qc : Bool) (p : Nat)
  /-- RQ-013: `t` header partials open the header and EN-009 to EN-012 pass -/
  | openHdr (eid K L : Nat) (collecting : Bool) (nPositions : Nat) (rates : List Nat)
  /-- RQ-011, RQ-012: a verified share complaint against the request is ordered -/
  | complaint (eid : Nat)
  /-- RQ-018 to RQ-021: a contribution frame for the request is ordered -/
  | frame (eid : Nat) (fr : Frame)
  /-- RQ-022: a verified share complaint against the frame at a position -/
  | detach (eid position : Nat)
  /-- RQ-017: an OPENED vote `(node, H(header))` commits -/
  | voteOpened (eid node hash : Nat)
  /-- RQ-026, RQ-027: an ADMIT vote `(node, H(header), h)` commits -/
  | voteAdmit (eid node hash h : Nat)
  /-- RQ-028: generation 1 missed its deadline and the board commits a
  generation 2 OBS set with these host heights -/
  | obs2 (eid : Nat) (gen1Missed : Bool) (heights : List Nat)
  /-- RQ-037: a RELEASE of generation `g` with variant `j` commits or is acked -/
  | release (eid g j : Nat)
  /-- RQ-042 to RQ-044: a FINAL post `(epoch, member, Enc_{k_fin}(txid))` -/
  | postFinal (eid epoch member ct : Nat)
  /-- RQ-042, RQ-043, RQ-045: a VOID post `(epoch, member, reason)` -/
  | postVoid (eid epoch member : Nat) (reason : Reason)
  /-- RQ-046: the board reaches height `h` -/
  | tick (h : Nat)
  /-- RQ-042: a ROTATE registers epoch `e` with `n_e`, `f_e` -/
  | rotate (e n f : Nat)
  /-- a checkpoint lands; `h` is its board height (RQ-054, RQ-068) -/
  | landCp (h : Nat)
  /-- RQ-048, RQ-068: a whole-committee restart burns a slot the request holds -/
  | restartBurn (eid : Nat)
  /-- the host chain shows a variant transaction of the request at confirmation depth -/
  | confirm (eid : Nat)
  /-- a reissue's `authorize` carried the VOID leaf of the request (AU-021, RQ-060) -/
  | carry (eid : Nat)
  /-- the host chain's fee median at host height `h` -/
  | hostFee (h m : Nat)
  deriving Repr, DecidableEq

def Op.target : Op → Option Nat
  | .order e _ _ | .openHdr e _ _ _ _ _ | .complaint e | .frame e _ | .detach e _
  | .voteOpened e _ _ | .voteAdmit e _ _ _ | .obs2 e _ _ | .release e _ _ | .postFinal e _ _ _
  | .postVoid e _ _ _ | .restartBurn e | .confirm e | .carry e => some e
  | _ => none

inductive Obs where
  | ok
  | refused (codes : List Refusal)
  | phase (p : Phase)
  deriving Repr, DecidableEq

/-! ## The transition of one request -/

/-- RQ-021: apply RQ-018 to the held frames, in order, at the event that sets the
target to COLLECTING. A held frame that fails RQ-018 does not attach (ledger 9). -/
def attachHeld (expC : Nat) : List (Option Nat) → List Frame → List (Option Nat)
  | ps, [] => ps
  | ps, fr :: frs =>
    let ok := decide (fr.height ≤ expC) && fr.tokenOk && fr.lengthsOk && ps.getD fr.position none == none
      && decide (fr.position < ps.length)
    attachHeld expC (if ok then ps.set fr.position (some fr.cid) else ps) frs

/-- RQ-074: the reason posts of a VOID tombstone are its counted posts, less
the STALLED posts once a RELEASE has committed (`any_release = true`). -/
def reasonPosts (anyRel : Bool) (counted : List Reason) : List Reason :=
  if anyRel then counted.filter (· != .STALLED) else counted

/-- RQ-065: the reasons a VOID post can carry (every reason but NONE and MIXED). -/
def postReasons : List Reason :=
  [.SHARE_COMPLAINT, .MALFORMED, .AUTH_REFUSED, .REVOKED, .RELEASE_CHECK, .CONTRIBUTION, .DEALER_FAULT,
   .PIN_SPENT, .SLOT_TAKEN, .STALLED, .RESTART]

/-- RQ-045, RQ-072, RQ-073: the tombstone reason is the reason that at least
`f + 1` reason posts carry; when no reason has `f + 1` reason posts it is MIXED. -/
def tombReason (f : Nat) (anyRel : Bool) (counted : List Reason) : Reason :=
  match postReasons.find? (fun x => decide (f + 1 ≤ countWith (· == x) (reasonPosts anyRel counted))) with
  | some x => x
  | none => .MIXED

/-- RQ-071: how a rule that reads a tombstone reason (the SLOT_TAKEN half of
RQ-063, the stalled gate of AU-021 and RQ-060, the revocation cause of RQ-034
and AU-019) reads `reason`: MIXED reads as none of STALLED, SLOT_TAKEN and
REVOKED, and as no other named reason. -/
def readsAs (reason x : Reason) : Bool := reason != .MIXED && reason == x

/-- RQ-045, RQ-050 to RQ-052: the request ends VOID with the reason. -/
def endVoid (c : Ctx) (r : Req) (reason : Reason) : Req :=
  { r with phase := .VOID, reason, outcome := endOutcome r, endHeight := some c.height }

/-- RQ-044, RQ-049: the request ends FINAL. The FINAL tombstone shows the
variant at confirmation depth (ledger 11). -/
def endFinal (c : Ctx) (r : Req) : Req :=
  { r with phase := .FINAL, outcome := .FINAL, endHeight := some c.height, confirmed := true }

/-- RQ-046, RQ-050 to RQ-052: the request expires at height `h`. -/
def expire (h : Nat) (r : Req) : Req :=
  if !r.phase.terminal && decide (r.exp < h) then
    { r with phase := .EXPIRED, outcome := endOutcome r, endHeight := some h }
  else r

/-- One event on the request it names: the refusals, or the new record. -/
def reqStep (c : Ctx) (r : Req) : Op → Except (List Refusal) Req
  -- RQ-006, RQ-007; EN-023 for the ordering block: `exp_c = b + Δ_c` must lie below `exp`
  | .order _ qc p =>
    let spec := opt (decide (r.exp ≤ c.height + c.params.deltaC)) .expCNotBelowExp ++ opt (!qc) .noQc
      ++ opt r.phase.terminal .terminal
    match orNoRule spec (r.phase == .POSTED) with
    | [] => .ok { r with phase := .ORDERED, orderPos := some p, expC := some (c.height + c.params.deltaC) }
    | rs => .error rs
  -- RQ-013, RQ-062
  | .openHdr _ k l coll npos rates =>
    if r.phase.terminal then .error [.terminal]
    else if !(decide (1 ≤ k) && decide (k ≤ kMax) && decide (1 ≤ l) && decide (l ≤ 2) && rates.length == k) then
      .error [.outsideCapability]
    else if r.phase != .ORDERED then .error [.noRule]
    else if r.rtype.signing then
      .ok { r with phase := .OPENED, K := k, L := l, G := min k gMax, collecting := coll,
                   positions := List.replicate npos none, rates }
    -- RQ-062: BIRTH, REFILL and CONTRIB keep no signing state
    else .ok { r with phase := .OPENED, K := k, L := l, G := min k gMax, collecting := false, rates }
  -- RQ-011 (before the first ADMIT vote), RQ-012 (after it)
  | .complaint _ =>
    if r.phase.terminal then .error [.terminal]
    else if r.phase == .POSTED then .error [.noRule]
    else if r.admitVotes.isEmpty then .ok { r with earlyComplaint := true }
    else .ok { r with dealerFault := true }
  -- RQ-018 to RQ-021
  | .frame _ fr =>
    let late := match r.expC with
      | some e => decide (e < c.height)
      | none => false
    if r.phase.terminal then .error [.terminal]
    -- RQ-020 in every live phase: a frame ordered above `exp_c` is refused; a frame for
    -- a request in OPENED or ADMITTED is refused the same way (RQ-075, DECISIONS 70, ledger 8)
    else if r.phase != .COLLECTING && (late || decide (2 ≤ r.phase.rank)) then .error [.lateContribution]
    -- RQ-021: held until the target reaches COLLECTING
    else if r.phase == .POSTED || r.phase == .ORDERED then .ok { r with held := r.held ++ [{ fr with height := c.height }] }
    else if r.phase != .COLLECTING then .error [.noRule]
    else if !decide (fr.position < r.positions.length) then .error [.outsideCapability]
    else
      let filled := r.positions.getD fr.position none != none
      let spec := opt late .lateContribution ++ opt filled .positionFilled
      match orNoRule spec (fr.tokenOk && fr.lengthsOk) with
      | [] => .ok { r with positions := r.positions.set fr.position (some fr.cid) }
      | rs => .error rs
  -- RQ-022
  | .detach _ pos =>
    if r.phase.terminal then .error [.terminal]
    else if r.positions.getD pos none == none then .error [.noRule]
    else .ok { r with positions := r.positions.set pos none }
  -- RQ-017
  | .voteOpened _ node hash =>
    if r.phase.terminal then .error [.terminal]
    else if !decide (node < c.params.n) then .error [.outsideCapability]
    else if !(r.phase == .OPENED && r.collecting && r.rtype.signing)
        || r.openedVotes.any (·.1 == node) then .error [.noRule]
    else
      let vs := r.openedVotes ++ [(node, hash)]
      if c.params.q ≤ countWith (·.2 == hash) vs then
        let e := r.expC.getD 0
        .ok { r with openedVotes := vs, phase := .COLLECTING, positions := attachHeld e r.positions r.held,
                     held := [] }
      else .ok { r with openedVotes := vs }
  -- RQ-026, RQ-027
  | .voteAdmit _ node hash h =>
    if r.phase.terminal then .error [.terminal]
    else if !decide (node < c.params.n) then .error [.outsideCapability]
    else if !((r.phase == .OPENED || r.phase == .COLLECTING) && r.rtype.signing)
        || r.admitVotes.any (·.1 == node) then .error [.noRule]
    else
      let vs := r.admitVotes ++ [(node, hash, h)]
      let mine := vs.filter (·.2.1 == hash)
      if c.params.q ≤ mine.length then
        match lookupMed c (anchorHeight c.params.f (mine.map (·.2.2))) with
        -- the host fee median at the anchor height is not in the view (ledger 7)
        | none => .error [.noRule]
        | some m => .ok { r with admitVotes := vs, phase := .ADMITTED, anchor1 := some (select r.K r.rates m) }
      else .ok { r with admitVotes := vs }
  -- RQ-028, RQ-029
  | .obs2 _ missed hs =>
    if r.phase.terminal then .error [.terminal]
    else if !decide (c.params.f < hs.length) then .error [.outsideCapability]
    else if !(r.phase == .ADMITTED && r.G == 2 && r.anchor2 == none && missed) then .error [.noRule]
    else
      match lookupMed c (anchorHeight c.params.f hs), r.anchor1 with
      | some m, some a =>
        let j := select r.K r.rates m
        -- RQ-029: generation 2 must select a variant above `anchor[1]`
        if a < j then .ok { r with anchor2 := some j } else .error [.noRule]
      | _, _ => .error [.noRule]
  -- RQ-037
  | .release _ g j =>
    if r.phase.terminal then .error [.terminal]
    else if r.phase != .ADMITTED then .error [.noRule]
    else if !(decide (1 ≤ g) && decide (g ≤ r.G) && decide (1 ≤ j) && decide (j ≤ r.K)) then
      .error [.outsideCapability]
    else
      let prev := if g == 1 then r.released1 else r.released2
      if prev != none && prev != some j then .error [.noRule]
      else if g == 1 then .ok { r with released1 := some j, anyRelease := true }
      else .ok { r with released2 := some j, anyRelease := true }
  -- RQ-042 to RQ-044, RQ-049
  | .postFinal _ e m ct =>
    let spec := opt r.phase.terminal .terminal ++ opt (epochOf c e == none) .unknownEpoch
    match spec, epochOf c e with
    | [], some (ne, fe) =>
      if !decide (m < ne) then .error [.outsideCapability]
      -- an epoch that does not serve the request, or a second post of a member (ledger 10)
      else if decide (e < r.epoch) || r.finalPosts.any (fun x => x.1 == e && x.2.1 == m) then .error [.noRule]
      else
        let ps := r.finalPosts ++ [(e, m, ct)]
        let r1 := { r with finalPosts := ps }
        if qOf ne fe ≤ countWith (fun x => x.1 == e && x.2.2 == ct) ps then .ok (endFinal c r1) else .ok r1
    | [], none => .error [.unknownEpoch]
    | rs, _ => .error rs
  -- RQ-042, RQ-043, RQ-045, RQ-050 to RQ-052
  | .postVoid _ e m reason =>
    let spec := opt r.phase.terminal .terminal ++ opt (epochOf c e == none) .unknownEpoch
    match spec, epochOf c e with
    | [], some (ne, fe) =>
      -- NONE and MIXED are no post reasons (RQ-065, RQ-072)
      if !decide (m < ne) || reason == .NONE || reason == .MIXED then .error [.outsideCapability]
      else if decide (e < r.epoch) || r.voidPosts.any (fun x => x.1 == e && x.2.1 == m) then .error [.noRule]
      else
        let ps := r.voidPosts ++ [(e, m, reason)]
        let r1 := { r with voidPosts := ps }
        -- RQ-045, RQ-072 to RQ-074: the counted posts are those of epoch `e`
        if fe + 1 ≤ countWith (·.1 == e) ps then
          .ok (endVoid c r1 (tombReason fe r.anyRelease ((ps.filter (·.1 == e)).map (·.2.2))))
        else .ok r1
    | [], none => .error [.unknownEpoch]
    | rs, _ => .error rs
  -- RQ-048 (live request), RQ-068 (ended after the latest landed checkpoint), RQ-005, RQ-054;
  -- RQ-076: the burn keeps `anyRelease` and `released1`, `released2` (ledger 28)
  | .restartBurn _ =>
    if !r.phase.terminal then .ok { r with restartEnd := true }
    else if r.carried then .error [.settled]
    else if leafHeld c r then .error [.terminal]
    else .ok { r with restartEnd := true, outcome := if r.confirmed then .FINAL else .RELEASED }
  | .confirm _ => .ok { r with confirmed := true }
  -- AU-021, RQ-060, RQ-071: only the VOID leaf of a stalled request is carried; a
  -- MIXED tombstone does not read as STALLED
  | .carry _ =>
    if r.outcome == .VOID && readsAs r.reason .STALLED then .ok { r with carried := true } else .error [.noRule]
  | _ => .error [.noRule]

/-! ## The state machine -/

def replace (e : Nat) (r' : Req) (rs : List Req) : List Req :=
  rs.map (fun x => if x.eid == e then r' else x)

def find (s : St) (e : Nat) : Option Req := s.reqs.find? (·.eid == e)

/-- One event: the refusals, or the next state. -/
def step (s : St) (op : Op) : Except (List Refusal) St :=
  let c := s.ctx
  match op with
  -- RQ-003; a second post of an `eid` the machine holds (ledger 2)
  | .post e ep x ty pr =>
    if (find s e).isSome then .error [.noRule]
    else .ok { s with reqs := s.reqs ++ [newReq e ep x ty pr] }
  -- RQ-046; the board height does not go down (ledger 4)
  | .tick h =>
    if h < c.height then .error [.noRule]
    else .ok { ctx := { c with height := h }, reqs := s.reqs.map (expire h) }
  -- RQ-042; a ROTATE of a registered epoch (ledger 5)
  | .rotate e n f =>
    if !committeeOk n f then .error [.outsideCapability]
    else if epochOf c e != none then .error [.noRule]
    else .ok { s with ctx := { c with epochs := c.epochs ++ [(e, n, f)] } }
  -- a checkpoint covers the board up to its height; it never goes back (ledger 4)
  | .landCp h =>
    if h < c.cpHeight || c.height < h then .error [.noRule]
    else .ok { s with ctx := { c with cpHeight := h } }
  | .hostFee h m =>
    match lookupMed c h with
    | some m' => if m' == m then .ok s else .error [.noRule]
    | none => .ok { s with ctx := { c with hostMed := c.hostMed ++ [(h, m)] } }
  | op =>
    match op.target with
    | none => .error [.noRule]
    | some e =>
      match find s e with
      -- RQ-004
      | none => .error [.unknownRequest]
      | some r =>
        match reqStep c r op with
        | .ok r' => .ok { s with reqs := replace e r' s.reqs }
        | .error rs => .error rs

/-- One event: a refused event leaves the state unchanged. -/
def apply (s : St) (op : Op) : St × Obs :=
  match step s op with
  | .ok s' =>
    match op.target with
    | some e => (s', match find s' e with
        | some r => .phase r.phase
        | none => .ok)
    | none => (s', .ok)
  | .error rs => (s, .refused rs)

def runOps : St → List Op → St × List Obs
  | s, [] => (s, [])
  | s, op :: ops =>
    let (s1, o) := apply s op
    let (s2, os) := runOps s1 ops
    (s2, o :: os)

def run (s : St) (ops : List Op) : St := (runOps s ops).1

/-! ## The state domain -/

def inRange (k : Nat) : Option Nat → Bool
  | none => true
  | some j => decide (1 ≤ j) && decide (j ≤ k)

/-- RQ-029: `anchor[1] < anchor[2]`, and generation 2 exists only for `G = 2`. -/
def anchorsOk (g : Nat) (a1 a2 : Option Nat) : Bool :=
  match a2 with
  | none => true
  | some j => g == 2 && (match a1 with
      | some a => decide (a < j)
      | none => false)

/-- The invariant domain of one request (RQ-029, RQ-049 to RQ-052, RQ-056,
RQ-057, RQ-064 to RQ-067). Every reachable request satisfies it
(`run_reqInv`); `--step` accepts exactly the states whose requests do. -/
def reqInv (r : Req) : Bool :=
  -- RQ-067: grid domains; `rates` has one entry per variant
  decide (r.K ≤ kMax) && decide (r.L ≤ 2) && r.G == min r.K gMax && r.rates.length == r.K
    && (decide (r.phase.rank < 2) || r.phase.terminal || (decide (1 ≤ r.K) && decide (1 ≤ r.L)))
    && inRange r.K r.anchor1 && inRange r.K r.anchor2 && inRange r.K r.released1 && inRange r.K r.released2
    && anchorsOk r.G r.anchor1 r.anchor2
    && (r.released2 == none || r.G == 2)
    -- RQ-057, C20: no anchor or release before admission; admission sets `anchor[1]`
    && (decide (4 ≤ r.phase.rank) || (r.anchor1 == none && r.anchor2 == none && !r.anyRelease))
    && (!r.anyRelease || r.anchor1 != none)
    && (r.phase != .ADMITTED || r.anchor1 != none)
    && (r.anyRelease || (r.released1 == none && r.released2 == none))
    -- RQ-049 to RQ-052: an outcome exactly for an ended request
    && (r.phase.terminal == (r.outcome != .NONE))
    && (r.phase.terminal == r.endHeight.isSome)
    && (r.phase != .FINAL || (r.outcome == .FINAL && r.confirmed))
    -- C11: a request that released, or that a restart ended, never settles VOID
    && (r.outcome != .VOID || (!r.anyRelease && !r.restartEnd))
    -- RQ-065: a reason exactly for a VOID request
    && ((r.phase == .VOID) == (r.reason != .NONE))
    && (!r.carried || r.outcome == .VOID)
    -- RQ-073, C20: a request with a committed RELEASE never has reason STALLED
    && (r.reason != .STALLED || !r.anyRelease)

def validState (s : St) : Bool :=
  committeeOk s.ctx.params.n s.ctx.params.f && s.ctx.epochs.all (fun x => committeeOk x.2.1 x.2.2)
    && nodupB (s.ctx.epochs.map (·.1)) && nodupB (s.reqs.map (·.eid)) && s.reqs.all reqInv
    && decide (s.ctx.cpHeight ≤ s.ctx.height)

def stepRefusals (s : St) : List Refusal := opt (!validState s) .outsideStateDomain

/-- The input domain of a run: RQ-001 for the committee and each registered epoch. -/
def paramRefusals (p : Params) (epochs : List (Nat × Nat × Nat)) : List Refusal :=
  opt (!committeeOk p.n p.f || !epochs.all (fun x => committeeOk x.2.1 x.2.2) || !nodupB (epochs.map (·.1)))
    .outsideCapability

/-! ## The honest node (RQ-008 to RQ-061) -/

/-- The node's view of the authorization of `auth_ref` (RQ-024, RQ-025, DECISIONS 68):
not in force yet; in force and its record opens to the `hd` and `tkc` of the header; in
force and its record does not open to them (`inForceMismatch`); or Midnight refused the
`authorize` call. The match is an admission check: it is read only once in force. -/
inductive AuthView where
  | notInForce | inForce | refused | inForceMismatch
  deriving Repr, DecidableEq

/-- The slot judge of SL-012 to SL-016 for every slot the header names. -/
inductive SlotView where
  | ok | taken | aboveWindow | poolUnlisted
  deriving Repr, DecidableEq

inductive HdrView where
  | notOpen | ok | malformed | dealerFault
  deriving Repr, DecidableEq

/-- What one node knows beside the board record. Heights are Midnight heights. -/
structure View where
  shareOk : Bool
  sentHeader : Bool
  hdr : HdrView
  auth : AuthView
  /-- the finalized Midnight height of a revocation the node reads, if any -/
  revokedAt : Option Nat
  /-- the node's finalized Midnight height -/
  midFinal : Nat
  /-- per generation, the newest Midnight height in its OBS set (RQ-032) -/
  obsMid1 : Nat
  obsMid2 : Nat
  /-- Midnight blocks since the authorization became final (RQ-033) -/
  holdAge : Nat
  slots : SlotView
  admissionOk : Bool
  votedOpened : Bool
  votedAdmit : Bool
  relCheck : Bool
  /-- peers that acked the `release` entry and whether `slot_bind` is current (RQ-035) -/
  acks1 : Nat
  acks2 : Nat
  bound : Bool
  sentGens : List Nat
  contribFail : Bool
  seesConfirm : Bool
  postedFinal : Bool
  pinSpent : Bool
  settled : Bool
  signedLeaf : Option Outcome
  deriving Repr, DecidableEq

inductive Act where
  | headerPartial
  | ack
  | complain
  | voteOpened
  | voteAdmit
  | postVoid (r : Reason)
  | release (g j : Nat)
  /-- RQ-069: in NON_TEE mode, the node's board vote posts RELEASE for `(g, j)` -/
  | recordRelease (g j : Nat)
  | evidence
  | postFinal
  | signLeaf (o : Outcome)
  | erase
  | handoff
  | refuse (c : Refusal)
  deriving Repr, DecidableEq

/-- RQ-036: the number of nodes that get the release partials. -/
def combinerCount (p : Params) : Nat := if p.mode == .TEE then p.n else p.f + 1

/-- RQ-032, RQ-059: the node reads a height at least as new as every OBS
report of generation `g`, and finds no revocation at or below it. -/
def revocationClear (v : View) (g : Nat) : Bool :=
  let obs := if g == 1 then v.obsMid1 else v.obsMid2
  decide (obs ≤ v.midFinal) && (match v.revokedAt with
    | some h => decide (v.midFinal < h)
    | none => true)

/-- RQ-030 to RQ-035: the release checks of generation `g`. -/
def releaseOk (p : Params) (r : Req) (v : View) (g : Nat) : Bool :=
  v.auth == .inForce && revocationClear v g && v.relCheck
    && (r.profile != .P2 || g != 1 || decide (p.deltaHold ≤ v.holdAge))
    && (p.mode != .TEE || (decide (p.w ≤ (if g == 1 then v.acks1 else v.acks2)) && v.bound))

def anchorOf (r : Req) (g : Nat) : Option Nat := if g == 1 then r.anchor1 else r.anchor2
def releasedOf (r : Req) (g : Nat) : Option Nat := if g == 1 then r.released1 else r.released2

/-- The voids an honest node posts for a live, ordered request. -/
def voids (c : Ctx) (r : Req) (v : View) : List Act :=
  (if r.earlyComplaint then [.postVoid .SHARE_COMPLAINT] else [])           -- RQ-011
  ++ (if r.phase == .ORDERED && v.hdr == .malformed then [.postVoid .MALFORMED] else [])     -- RQ-014
  ++ (if r.phase == .ORDERED && v.hdr == .dealerFault then [.postVoid .DEALER_FAULT] else [])  -- RQ-015
  -- RQ-025 (DECISIONS 68): Midnight refused the call, or the authorization is in force and its
  -- record does not open to the header's `hd` and `tkc`
  ++ (if decide (2 ≤ r.phase.rank) && (v.auth == .refused || v.auth == .inForceMismatch)
      then [.postVoid .AUTH_REFUSED] else [])
  ++ (if decide (2 ≤ r.phase.rank) && v.revokedAt != none && !r.anyRelease then [.postVoid .REVOKED] else [])  -- RQ-034
  ++ (if decide (2 ≤ r.phase.rank) && v.slots == .taken then [.postVoid .SLOT_TAKEN] else [])  -- SL-013, SL-016
  ++ (if r.phase == .ADMITTED && !v.relCheck then [.postVoid .RELEASE_CHECK] else [])        -- RQ-031
  ++ (if r.phase == .ADMITTED && v.contribFail then [.postVoid .CONTRIBUTION] else [])       -- RQ-038
  ++ (if c.params.mode == .TEE && v.pinSpent && !r.anyRelease then [.postVoid .PIN_SPENT] else [])  -- RQ-041
  -- RQ-047: the board reached `exp_c` with no `q` ADMIT votes
  ++ (if r.collecting && (r.phase == .OPENED || r.phase == .COLLECTING)
        && (match r.expC with
            | some e => decide (e ≤ c.height)
            | none => false) then [.postVoid .STALLED] else [])
  ++ (if r.restartEnd then [.postVoid .RESTART] else [])                   -- RQ-048

/-- The votes of a request with an opened header (RQ-016, RQ-023, RQ-024,
RQ-061, SL-014, SL-015). -/
def votes (r : Req) (v : View) : List Act :=
  if v.settled then [.refuse .settled]                                     -- RQ-061
  else if v.auth == .notInForce then [.refuse .notInForce]                 -- RQ-024
  else if v.slots == .aboveWindow then [.refuse .aboveWindow]              -- SL-014
  else if v.slots == .poolUnlisted then [.refuse .poolUnlisted]            -- SL-015
  else if v.auth == .inForce && v.slots == .ok then
    -- RQ-016
    (if r.phase == .OPENED && r.collecting && !v.votedOpened then [.voteOpened] else [])
    -- RQ-023
    ++ (if ((r.phase == .OPENED && !r.collecting)
            || (r.phase == .COLLECTING && r.positions.all (· != none)))
          && v.admissionOk && !v.votedAdmit then [.voteAdmit] else [])
  else []

/-- RQ-030, RQ-058, RQ-069: the release of each generation whose anchor is set.
In NON_TEE mode the node first posts RELEASE in its board vote and sends the
partials only once that RELEASE has committed (`released[g] = j`). -/
def releases (p : Params) (r : Req) (v : View) : List Act :=
  [1, 2].filterMap (fun g =>
    match anchorOf r g with
    | some j =>
      if decide (g ≤ r.G) && !v.sentGens.contains g && releaseOk p r v g then
        if p.mode == .NON_TEE && releasedOf r g != some j then
          (if releasedOf r g == none then some (.recordRelease g j) else none)
        else some (.release g j)
      else none
    | none => none)

/-- The acts of an honest node for one request. -/
def nodeAct (c : Ctx) (r : Req) (v : View) : List Act :=
  if r.phase.terminal then
    -- RQ-053, RQ-054, RQ-055
    let sign : Bool := match v.signedLeaf with
      | none => r.outcome != .NONE
      | some o => o != r.outcome && r.restartEnd && !leafHeld c r
    (if sign then [.signLeaf r.outcome] else []) ++ [.erase]
  -- RQ-008: nothing leaves before order
  else if r.phase == .POSTED then []
  else
    let base := voids c r v
      ++ (if v.seesConfirm && !v.postedFinal then [.postFinal] else [])     -- RQ-040
    match r.phase with
    -- RQ-009, RQ-010
    | .ORDERED =>
      (if v.sentHeader then [] else if v.shareOk then [.headerPartial, .ack] else [.complain]) ++ base
    | .OPENED | .COLLECTING =>
      -- RQ-062: BIRTH, REFILL and CONTRIB go to their own checks
      if !r.rtype.signing then [.handoff] ++ base else votes r v ++ base
    | .ADMITTED =>
      releases c.params r v
        ++ (if c.params.mode == .NON_TEE && v.contribFail then [.evidence] else [])  -- RQ-039
        ++ base
    | _ => base

/-! ## Theorems -/

theorem orNoRule_nil (spec : List Refusal) (ok : Bool) (h : orNoRule spec ok = []) : spec = [] ∧ ok = true := by
  unfold orNoRule opt at h
  cases spec with
  | nil => cases ok <;> simp_all
  | cons _ _ => simp at h

/-- RQ-005, RQ-056: an event on a terminal request is refused, except the
restart re-end of RQ-068 and the host and Midnight facts. -/
theorem terminal_refused (c : Ctx) (r : Req) (op : Op) (ht : r.phase.terminal = true)
    (hop : ∀ e, op ≠ .restartBurn e ∧ op ≠ .confirm e ∧ op ≠ .carry e) :
    ∃ rs, reqStep c r op = .error rs := by
  cases op with
  | restartBurn e => exact absurd rfl (hop e).1
  | confirm e => exact absurd rfl (hop e).2.1
  | carry e => exact absurd rfl (hop e).2.2
  | order _ _ _ =>
    simp only [reqStep]
    split
    · rename_i h; have := (orNoRule_nil _ _ h).1; simp [opt, ht] at this
    · exact ⟨_, rfl⟩
  | postFinal _ _ _ _ =>
    simp only [reqStep, ht, opt, ite_true]
    split <;> simp_all
  | postVoid _ _ _ _ =>
    simp only [reqStep, ht, opt, ite_true]
    split <;> simp_all
  | _ => simp [reqStep, ht]

/-- RQ-056: the phase moves only forward, and never out of a terminal phase. -/
def phaseMove (a b : Phase) : Bool :=
  a == b || (!a.terminal && (b.terminal || decide (a.rank < b.rank)))

theorem expire_forward (h : Nat) (r : Req) : phaseMove r.phase (expire h r).phase = true := by
  unfold expire phaseMove
  split <;> simp_all [Phase.terminal]

theorem reqStep_forward (c : Ctx) (r r' : Req) (op : Op) (h : reqStep c r op = .ok r') :
    phaseMove r.phase r'.phase = true := by
  cases op with
  | order _ qc p =>
    simp only [reqStep] at h
    split at h
    · rename_i hn
      have hp := (orNoRule_nil _ _ hn).2
      cases h; cases hq : r.phase <;> simp_all [phaseMove, Phase.terminal, Phase.rank]
    · simp at h
  | _ =>
    simp only [reqStep] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; simp_all [phaseMove, Phase.terminal, Phase.rank, endFinal, endVoid, opt, orNoRule]; done)
    | (cases h; cases hp : r.phase <;>
        simp_all [phaseMove, Phase.terminal, Phase.rank, endFinal, endVoid, opt]; done)

theorem firstMeet_range (m : Nat) (rs : List Nat) (i : Nat) (h : firstMeet m rs = some i) :
    1 ≤ i ∧ i ≤ rs.length := by
  induction rs generalizing i with
  | nil => simp [firstMeet] at h
  | cons x xs ih =>
    simp only [firstMeet] at h
    split at h
    · cases h; simp
    · cases hf : firstMeet m xs with
      | none => simp [hf] at h
      | some k =>
        simp [hf] at h
        have := ih k hf
        simp; omega

/-- RQ-027, RQ-029: the selection rule gives a variant in `1..K`. -/
theorem select_range (k : Nat) (rates : List Nat) (m : Nat) (hk : 1 ≤ k) (hl : rates.length = k) :
    1 ≤ select k rates m ∧ select k rates m ≤ k := by
  unfold select
  split
  · rename_i i hi; have := firstMeet_range m rates i hi; omega
  · omega

theorem countWith_stalled_filter (l : List Reason) :
    countWith (· == Reason.STALLED) (l.filter (· != .STALLED)) = 0 := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    unfold countWith at *
    cases x <;> simp_all

/-- RQ-065, RQ-072: a tombstone reason is a post reason or MIXED, never NONE. -/
theorem tombReason_ne_none (f : Nat) (a : Bool) (l : List Reason) : (tombReason f a l != .NONE) = true := by
  unfold tombReason
  split
  · rename_i x hf
    have hm := List.mem_of_find?_eq_some hf
    simp only [postReasons, List.mem_cons, List.not_mem_nil, or_false] at hm
    rcases hm with h | h | h | h | h | h | h | h | h | h | h <;> subst h <;> rfl
  · rfl

/-- RQ-073, RQ-074: after a RELEASE the tombstone reason is never STALLED. -/
theorem tombReason_ne_stalled (f : Nat) (l : List Reason) : (tombReason f true l != .STALLED) = true := by
  unfold tombReason
  split
  · rename_i x hf
    have hp := List.find?_some hf
    have hc := countWith_stalled_filter l
    cases x <;> simp_all [reasonPosts]
  · rfl

theorem endOutcome_ne_none (r : Req) : endOutcome r ≠ .NONE := by
  unfold endOutcome; split <;> (try split) <;> simp

theorem endOutcome_void (r : Req) (h : endOutcome r = .VOID) : r.anyRelease = false ∧ r.restartEnd = false := by
  unfold endOutcome at h
  cases hr : r.restartEnd <;> cases ha : r.anyRelease <;> cases hc : r.confirmed <;> simp_all


end SplitRequest
