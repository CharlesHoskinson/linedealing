import SplitShardHolders.Spec

/-!
# Known answers, written from the requirement sentences and their scenarios

Each answer is pinned twice: `decide +kernel` checks it against the definitions
the theorems describe, and `#guard` checks it with the compiled evaluator.
Expected values come from the spec text and the formulas it states.
-/

namespace SplitShardHolders

/-! ## Access structures -/

/-- SH-001 scenario: `user AND (custodian OR G)` with `G` 3-of-5. user = 1,
custodian = 2, guardians 10 to 14. -/
def regulated : Gate :=
  .and_ 0 [.leaf 0 1, .or_ 0 (.leaf 0 2) (.group 0 3 [.leaf 1 10, .leaf 2 11, .leaf 3 12, .leaf 4 13, .leaf 5 14])]

/-- SH-003 scenario: a 2-of-3 treasury of officers 21, 22, 23. -/
def treasury : Gate := .group 0 2 [.leaf 1 21, .leaf 2 22, .leaf 3 23]

/-- SH-004 scenario: a 2-of-3 group nested in a 2-of-3 group. -/
def nested : Gate := .group 0 2 [.group 1 2 [.leaf 1 31, .leaf 2 32, .leaf 3 33], .leaf 2 34, .leaf 3 35]

/-- SH-019 scenario: a user that is the primary of an OR with a guardian group. -/
def userOrG : Gate := .or_ 0 (.leaf 0 1) (.group 0 3 [.leaf 1 10, .leaf 2 11, .leaf 3 12, .leaf 4 13, .leaf 5 14])

-- SH-001: the signing sets are {user, custodian} and user with any three guardians
theorem pin_regulated_sets :
    admitted regulated [1, 2] 1 = true ∧ admitted regulated [1, 10, 12, 14] 1 = true
      ∧ admitted regulated [1, 10, 12] 1 = false ∧ admitted regulated [1, 2, 10, 11, 12] 1 = false
      ∧ admitted regulated [2, 10, 11, 12] 2 = false := by decide +kernel
#guard admitted regulated [1, 2] 1 && admitted regulated [1, 10, 12, 14] 1 && !admitted regulated [1, 10, 12] 1
  && !admitted regulated [1, 2, 10, 11, 12] 1 && !admitted regulated [2, 10, 11, 12] 2

theorem pin_valid : validCharter regulated = true ∧ validCharter treasury = true ∧ validCharter nested = true := by
  decide +kernel
#guard validCharter regulated && validCharter treasury && validCharter nested

-- SH-002: the same issuer leaf under two gates; a member id 0; a member id twice
theorem pin_repeated_leaf : validCharter (.and_ 0 [.leaf 0 5, .or_ 0 (.leaf 0 5) (.leaf 0 6)]) = false ∧
    leavesOk (.group 0 1 [.leaf 0 5, .leaf 1 6]) = false ∧ leavesOk (.group 0 1 [.leaf 1 5, .leaf 1 6]) = false := by
  decide +kernel
#guard !validCharter (.and_ 0 [.leaf 0 5, .or_ 0 (.leaf 0 5) (.leaf 0 6)]) && !leavesOk (.group 0 1 [.leaf 0 5, .leaf 1 6])
  && !leavesOk (.group 0 1 [.leaf 1 5, .leaf 1 6])

-- SH-001: a group with k above its members is not a structure of the gates
theorem pin_bad_k : structureOk (.group 0 4 [.leaf 1 5, .leaf 2 6]) = false := by decide +kernel
#guard !structureOk (.group 0 4 [.leaf 1 5, .leaf 2 6])

-- SH-003: an officer of a 2-of-3 treasury names itself and one other officer
theorem pin_treasury : admitted treasury [21, 23] 21 = true ∧ admitted treasury [21] 21 = false
    ∧ admitted treasury [21, 22, 23] 21 = false ∧ admitted treasury [22, 23] 21 = false := by decide +kernel
#guard admitted treasury [21, 23] 21 && !admitted treasury [21] 21 && !admitted treasury [21, 22, 23] 21
  && !admitted treasury [22, 23] 21

-- SH-004: the weight of a member of the nested group is the product of two
-- Lagrange coefficients at zero: 2/(2−1) in the inner set {1, 2} and 2/(2−1) in
-- the outer set {1, 2}, so 4; the outer member with id 2 has 1/(1−2) = −1
theorem pin_nested_weight :
    ((weight [31, 32, 34] 31 nested).map (·.eqv ⟨4, 1⟩)) = some true
      ∧ ((weight [31, 32, 34] 31 nested).map (·.eqv ((lagrange0 1 [1, 2]).mul (lagrange0 1 [1, 2])))) = some true
      ∧ ((weight [31, 32, 34] 34 nested).map (·.eqv ⟨-1, 1⟩)) = some true := by decide +kernel
#guard (weight [31, 32, 34] 31 nested).map (·.eqv ⟨4, 1⟩) == some true
  && (weight [31, 32, 34] 34 nested).map (·.eqv ⟨-1, 1⟩) == some true

-- SH-004: a weight 1 for an AND or OR child
theorem pin_and_weight : (weight [1, 2] 1 regulated).map (·.eqv Q.one) = some true := by decide +kernel
#guard (weight [1, 2] 1 regulated).map (·.eqv Q.one) == some true

-- SH-038 scenario: two requests name member 21 of the 2-of-3 treasury, one with
-- member 22 as the initiator and one with member 23. The weights of member 21 are
-- 2/(2−1) = 2 and 3/(3−1) = 3/2. The other named actors are the same in both
-- requests, and the lists differ in the initiator
theorem pin_two_initiators :
    (weight [21, 22] 21 treasury).map (·.eqv ⟨2, 1⟩) = some true
      ∧ (weight [21, 23] 21 treasury).map (·.eqv ⟨3, 2⟩) = some true
      ∧ (clActors [21, 22] 22).2 = (clActors [21, 23] 23).2
      ∧ clActors [21, 22] 22 ≠ clActors [21, 23] 23 := by decide +kernel
#guard (weight [21, 22] 21 treasury).map (·.eqv ⟨2, 1⟩) == some true
  && (weight [21, 23] 21 treasury).map (·.eqv ⟨3, 2⟩) == some true
  && (clActors [21, 22] 22).2 == (clActors [21, 23] 23).2
  && clActors [21, 22] 22 != clActors [21, 23] 23

/-! ## Birth -/

def p0 : Params := { n := 9, f := 2, mode := .TEE, nH := 30 }

theorem pin_q : p0.q = 6 := by decide +kernel
#guard p0.q == 6

/-- SH-011 with RQ-001 at an even `n + f`: `q = ⌈(10 + 2 + 1)/2⌉ = 7`. -/
theorem pin_q_even : ({ n := 10, f := 2, mode := .TEE, nH := 30 } : Params).q = 7 := by decide +kernel

def ap (slot xa : Nat) : ActorProof :=
  { slot, xa, ctx := (5, xa, slot, 7, 1), valid := true, netCreated := false, popU := false, delta := false }

/-- A two-actor birth that passes every check. -/
def bc0 : BirthCheck :=
  { xf := 5, charterId := 7, chainId := 1, actors := [ap 1 50, ap 2 60], dealerOk := true, xRecomputed := true,
    encodingOk := true, openingOk := true }

def s0 : St := (runOps (init p0) [.fixCharter 7 regulated]).1

-- SH-009: a valid two-actor birth: the node signs BIRTH_OK
theorem pin_birth_ok : (apply s0 (.birthCheck 3 900 bc0)).2 = .birthOk := by decide +kernel
#guard (apply s0 (.birthCheck 3 900 bc0)).2 == .birthOk

-- SH-010: the last actor publishes a point without a valid proof of possession
theorem pin_rogue : (apply s0 (.birthCheck 3 900 { bc0 with actors := [ap 1 50, { ap 2 60 with valid := false }] })).2 =
    .refused [.birthRefused] := by decide +kernel
#guard (apply s0 (.birthCheck 3 900 { bc0 with actors := [ap 1 50, { ap 2 60 with valid := false }] })).2 == .refused [.birthRefused]

-- SH-007: a proof made for slot 1, copied to slot 2, does not verify
theorem pin_pop_copied : proofOk bc0 { ap 1 50 with slot := 2 } = false := by decide +kernel
#guard !proofOk bc0 { ap 1 50 with slot := 2 }

-- SH-008: a network-created shard needs `pop_U` and the proof of `δ`
theorem pin_network : proofOk bc0 { ap 1 50 with netCreated := true } = false ∧
    proofOk bc0 { ap 1 50 with netCreated := true, popU := true, delta := true } = true := by decide +kernel
#guard !proofOk bc0 { ap 1 50 with netCreated := true } && proofOk bc0 { ap 1 50 with netCreated := true, popU := true, delta := true }

/-- Nodes 0 to 5 sign BIRTH_OK on `cm_addr = 900`. -/
def s6 : St := (runOps s0 ((List.range 6).map (fun i => .birthCheck i 900 bc0))).1

def rec0 : RecordReq :=
  { cm := 900, profile := .P1, charter := 7, signers := [0, 1, 2, 3, 4, 5], ownerReg := false, escrowAcks := 3,
    escrowQuorum := 3, guardianAcks := 0, qg := 4, netCreated := false }

-- SH-011: six BIRTH_OK signatures at `q = 6` admit a P1 record; five do not
theorem pin_six : (apply s6 (.submitRecord rec0)).2 = .ok := by decide +kernel
#guard (apply s6 (.submitRecord rec0)).2 == .ok
theorem pin_five : (apply s6 (.submitRecord { rec0 with signers := [0, 1, 2, 3, 4] })).2 = .refused [.noBirthCertificate] := by
  decide +kernel
#guard (apply s6 (.submitRecord { rec0 with signers := [0, 1, 2, 3, 4] })).2 == .refused [.noBirthCertificate]
-- a signer with no BIRTH_OK does not count
theorem pin_forged : (apply s6 (.submitRecord { rec0 with signers := [0, 1, 2, 3, 4, 8] })).2 = .refused [.noBirthCertificate] := by
  decide +kernel
#guard (apply s6 (.submitRecord { rec0 with signers := [0, 1, 2, 3, 4, 8] })).2 == .refused [.noBirthCertificate]
-- SH-011: a P0 record needs the owner's registration
theorem pin_p0 : (apply s0 (.submitRecord { rec0 with profile := .P0, signers := [] })).2 = .refused [.noBirthCertificate] ∧
    (apply s0 (.submitRecord { rec0 with profile := .P0, signers := [], ownerReg := true })).2 = .ok := by decide +kernel
#guard (apply s0 (.submitRecord { rec0 with profile := .P0, signers := [], ownerReg := true })).2 == .ok

-- SH-012: a P2 record with three guardian ACKs at `q_g = 4`; an OR gate without its escrow quorum
theorem pin_guardians : (apply s6 (.submitRecord { rec0 with profile := .P2, guardianAcks := 3 })).2 =
    .refused [.noEscrowCertificate] := by decide +kernel
#guard (apply s6 (.submitRecord { rec0 with profile := .P2, guardianAcks := 3 })).2 == .refused [.noEscrowCertificate]
theorem pin_escrow : (apply s6 (.submitRecord { rec0 with escrowAcks := 2 })).2 = .refused [.noEscrowCertificate] := by
  decide +kernel
#guard (apply s6 (.submitRecord { rec0 with escrowAcks := 2 })).2 == .refused [.noEscrowCertificate]
-- both missing: both codes, sorted (ledger 2)
theorem pin_both_certs : (apply s6 (.submitRecord { rec0 with signers := [0], escrowAcks := 0 })).2 =
    .refused [.noBirthCertificate, .noEscrowCertificate] := by decide +kernel
#guard (apply s6 (.submitRecord { rec0 with signers := [0], escrowAcks := 0 })).2 == .refused [.noBirthCertificate, .noEscrowCertificate]

/-- C1 witness: from `init`, a record is admitted with six certified signers. -/
theorem witness_certified : ∃ ops, ((run (init p0) ops).records.map (·.sigs)) = [[0, 1, 2, 3, 4, 5]] :=
  ⟨[.fixCharter 7 regulated] ++ (List.range 6).map (fun i => .birthCheck i 900 bc0) ++ [.submitRecord rec0],
   by decide +kernel⟩

/-! ## Acknowledgement of a network-created shard (DECISIONS 67) -/

/-- The record of `cm_addr = 900` for an offline holder: a network-created shard. -/
def sR : St := (apply s6 (.submitRecord { rec0 with netCreated := true })).1

/-- The P1 record without a network-created shard. -/
def sP : St := (apply s6 (.submitRecord rec0)).1

-- SH-034: a payer registers the record of an address for an offline holder: `acked = false`
theorem pin_new_unacked : (apply s6 (.submitRecord { rec0 with netCreated := true })).2 = .ok ∧
    (findRec sR 900).map (·.acked) = some false := by decide +kernel
#guard (findRec sR 900).map (·.acked) == some false

-- SH-030: the holder of a correctly built record comes online: its wallet sends the ACK envelope
theorem pin_holder_ack : (apply sR (.holderOpen 900 true)).2 = .ackEnvelope := by decide +kernel
#guard (apply sR (.holderOpen 900 true)).2 == .ackEnvelope

-- SH-036: the creator put a point other than the `E_c` behind `δ` in the record:
-- `x_u·G ≠ X_u`, the holder wallet sends no ACK envelope
theorem pin_holder_wrong_ec : (apply sR (.holderOpen 900 false)).2 = .refused [.sh036] := by decide +kernel
#guard (apply sR (.holderOpen 900 false)).2 == .refused [.sh036]
-- a record without a network-created shard and an unknown record: no rule (ledger 14); both codes, sorted
theorem pin_holder_no_rule : (apply sP (.holderOpen 900 true)).2 = .refused [.noRule] ∧
    (apply sP (.holderOpen 900 false)).2 = .refused [.sh036, .noRule] ∧
    (apply sR (.holderOpen 901 true)).2 = .refused [.noRule] := by decide +kernel
#guard (apply sP (.holderOpen 900 false)).2 == .refused [.sh036, .noRule]

def ack0 : AckCheck := { xRecomputed := true, openingOk := true, popU := true }

-- SH-031: the holder sends a valid ACK envelope: the node signs ACK_OK
theorem pin_ack_ok : (apply sR (.ackCheck 3 900 ack0)).2 = .ackOk ∧
    (apply sR (.ackCheck 3 900 ack0)).1.ackOk = [(3, 900)] := by decide +kernel
#guard (apply sR (.ackCheck 3 900 ack0)).2 == .ackOk

-- SH-032: the creator sends an ACK envelope without a valid `pop_u`: no ACK_OK
theorem pin_ack_no_pop : (apply sR (.ackCheck 3 900 { ack0 with popU := false })).2 = .refused [.ackRefused] := by
  decide +kernel
#guard (apply sR (.ackCheck 3 900 { ack0 with popU := false })).2 == .refused [.ackRefused]
-- SH-032: the birth data do not recompute `X`; the opening of `cm_addr` fails
theorem pin_ack_bad_birth : (apply sR (.ackCheck 3 900 { ack0 with xRecomputed := false })).2 = .refused [.ackRefused] ∧
    (apply sR (.ackCheck 3 900 { ack0 with openingOk := false })).2 = .refused [.ackRefused] := by decide +kernel
#guard (apply sR (.ackCheck 3 900 { ack0 with xRecomputed := false })).2 == .refused [.ackRefused]
  && (apply sR (.ackCheck 3 900 { ack0 with openingOk := false })).2 == .refused [.ackRefused]
-- a node index outside `n` (ledger 4), with a failed check: both codes, sorted
theorem pin_ack_codes : (apply sR (.ackCheck 9 900 { ack0 with popU := false })).2 =
    .refused [.ackRefused, .outsideCapability] := by decide +kernel
#guard (apply sR (.ackCheck 9 900 { ack0 with popU := false })).2 == .refused [.ackRefused, .outsideCapability]

/-- Nodes 0 to 5 sign ACK_OK on `cm_addr = 900`. -/
def sA : St := (runOps sR ((List.range 6).map (fun i => .ackCheck i 900 ack0))).1

-- SH-033: an `acknowledge` call with five ACK_OK signatures at `q = 6` is refused
theorem pin_ack_five : (apply sA (.acknowledge 900 [0, 1, 2, 3, 4])).2 = .refused [.noAckCertificate] := by
  decide +kernel
#guard (apply sA (.acknowledge 900 [0, 1, 2, 3, 4])).2 == .refused [.noAckCertificate]
-- SH-033: a signer with no ACK_OK on the record does not count; a BIRTH_OK is not an ACK_OK
theorem pin_ack_forged : (apply sA (.acknowledge 900 [0, 1, 2, 3, 4, 8])).2 = .refused [.noAckCertificate] ∧
    (apply sR (.acknowledge 900 [0, 1, 2, 3, 4, 5])).2 = .refused [.noAckCertificate] := by decide +kernel
#guard (apply sA (.acknowledge 900 [0, 1, 2, 3, 4, 8])).2 == .refused [.noAckCertificate]
  && (apply sR (.acknowledge 900 [0, 1, 2, 3, 4, 5])).2 == .refused [.noAckCertificate]
-- an unknown record (ledger 3); a signer named twice (ledger 4)
theorem pin_ack_domain : (apply sA (.acknowledge 901 [0, 1, 2, 3, 4, 5])).2 = .refused [.noRule] ∧
    (apply sA (.acknowledge 900 [0, 0, 1, 2, 3, 4, 5])).2 = .refused [.outsideCapability] := by decide +kernel
#guard (apply sA (.acknowledge 900 [0, 0, 1, 2, 3, 4, 5])).2 == .refused [.outsideCapability]

/-- The holder's `acknowledge` call with six ACK_OK signatures has landed. -/
def sK : St := (apply sA (.acknowledge 900 [0, 1, 2, 3, 4, 5])).1

-- SH-037: the holder's `acknowledge` call with six ACK_OK signatures at `q = 6` lands: `acked = true`
theorem pin_acked : (apply sA (.acknowledge 900 [0, 1, 2, 3, 4, 5])).2 = .ok ∧
    (findRec sK 900).map (·.acked) = some true := by decide +kernel
#guard (apply sA (.acknowledge 900 [0, 1, 2, 3, 4, 5])).2 == .ok && (findRec sK 900).map (·.acked) == some true
/-- A second record with a network-created shard (`cm_addr = 902`, P0), then the
acknowledgement of 900. -/
def sK2 : St :=
  (runOps sA [.submitRecord { rec0 with cm := 902, profile := .P0, signers := [], ownerReg := true, netCreated := true },
    .acknowledge 900 [0, 1, 2, 3, 4, 5]]).1
-- SH-037: the call sets the flag on its own record only; another record stays unacknowledged
theorem pin_acked_own : (findRec sK2 900).map (·.acked) = some true ∧ (findRec sK2 902).map (·.acked) = some false := by
  decide +kernel
#guard (findRec sK2 900).map (·.acked) == some true && (findRec sK2 902).map (·.acked) == some false

-- SH-035: a payer wallet reads a record with `acked = false` and does not pay;
-- after the acknowledgement it pays; a record without a network-created shard needs none
theorem pin_pay : (apply sR (.pay 900)).2 = .refused [.sh035] ∧ (apply sA (.pay 900)).2 = .refused [.sh035] ∧
    (apply sK (.pay 900)).2 = .paid ∧ (apply sP (.pay 900)).2 = .paid ∧
    (apply sK (.pay 901)).2 = .refused [.noRule] := by decide +kernel
#guard (apply sR (.pay 900)).2 == .refused [.sh035] && (apply sK (.pay 900)).2 == .paid
  && (apply sP (.pay 900)).2 == .paid

/-- SH-037 witness: from `init`, a network-created record is born, acknowledged and paid. -/
theorem witness_acked : ∃ ops, ((runOps (init p0) ops).2.getLast? = some .paid) ∧
    (run (init p0) ops).records.map (·.acked) = [true] :=
  ⟨[.fixCharter 7 regulated] ++ (List.range 6).map (fun i => .birthCheck i 900 bc0)
     ++ [.submitRecord { rec0 with netCreated := true }, .holderOpen 900 true]
     ++ (List.range 6).map (fun i => .ackCheck i 900 ack0) ++ [.acknowledge 900 [0, 1, 2, 3, 4, 5], .pay 900],
   by decide +kernel⟩

/-! ## Pools and contributions -/

-- SH-013: a pool holds 64 pairs; a pool key is used once
def sp : St := (runOps s0 [.fixCharter 8 treasury, .fixCharter 9 userOrG, .postPool 1 0 0, .postPool 21 0 0,
  .postPool 10 0 0, .postPool 1 0 1]).1
theorem pin_pool : (unusedOf sp 1).length = 128 ∧ (unusedOf sp 21).length = 64 := by decide +kernel
#guard (unusedOf sp 1).length == 128 && (unusedOf sp 21).length == 64
theorem pin_pool_key : (apply sp (.postPool 1 0 1)).2 = .refused [.sh013] := by decide +kernel
#guard (apply sp (.postPool 1 0 1)).2 == .refused [.sh013]

-- SH-014: 30 halves at K = 8, L = 2; K·L on ECDSA
theorem pin_halves : halves false 8 2 = 30 ∧ halves true 3 2 = 6 := by decide +kernel
#guard halves false 8 2 == 30 && halves true 3 2 == 6

/-- A request of the user (1) on `user AND (custodian OR G)` with the custodian. -/
def c0 : Contrib :=
  { actor := 1, charter := 7, S := [1, 2], initiator := 1, weight := Q.one, pairs := List.range 30,
    slot := .committee, expC := 100, height := 50, policyOk := true, recomputeOk := true, seizureSettled := false }

theorem pin_contribute : (apply sp (.contribute c0)).2 = .contributed false := by decide +kernel
#guard (apply sp (.contribute c0)).2 == .contributed false

-- SH-014: 25 unused pairs remain and N_h = 30: the actor posts a new pool
def s25 : St := (apply (runOps s0 [.postPool 1 0 0]).1 (.contribute { c0 with pairs := List.range 39 })).1
theorem pin_refill : (unusedOf s25 1).length = 25 ∧ needsRefill s25 1 = true := by decide +kernel
#guard (unusedOf s25 1).length == 25 && needsRefill s25 1

-- SH-015, SH-022: a second request on a pair the actor already answered
def sc : St := (apply sp (.contribute c0)).1
theorem pin_pair_answered : (apply sc (.contribute { c0 with pairs := [29, 30] })).2 = .refused [.badRequest] := by
  decide +kernel
#guard (apply sc (.contribute { c0 with pairs := [29, 30] })).2 == .refused [.badRequest]
-- SH-015: no answer after `exp_c`; at `exp_c` it answers
theorem pin_after_expc : (apply sp (.contribute { c0 with height := 101 })).2 = .refused [.sh015] ∧
    (apply sp (.contribute { c0 with height := 100 })).2 = .contributed false := by decide +kernel
#guard (apply sp (.contribute { c0 with height := 101 })).2 == .refused [.sh015]

-- SH-022: one pair named for two halves
theorem pin_pair_twice : (apply sp (.contribute { c0 with pairs := [7, 7] })).2 = .refused [.badRequest] := by
  decide +kernel
#guard (apply sp (.contribute { c0 with pairs := [7, 7] })).2 == .refused [.badRequest]
-- SH-022: a signing set outside Γ, and a weight that does not follow from the set
theorem pin_not_in_gamma : (apply sp (.contribute { c0 with S := [1] })).2 = .refused [.badRequest] ∧
    (apply sp (.contribute { c0 with weight := ⟨2, 1⟩ })).2 = .refused [.badRequest] := by decide +kernel
#guard (apply sp (.contribute { c0 with S := [1] })).2 == .refused [.badRequest]

-- SH-023: the actor's own policy rejects the request
theorem pin_policy : (apply sp (.contribute { c0 with policyOk := false })).2 = .refused [.policyRefused] := by
  decide +kernel
#guard (apply sp (.contribute { c0 with policyOk := false })).2 == .refused [.policyRefused]

-- SH-021: a ticket's `R_A` differs from the sum the actor computes
theorem pin_recompute : (apply sp (.contribute { c0 with recomputeOk := false })).2 = .refused [.sh021] := by
  decide +kernel
#guard (apply sp (.contribute { c0 with recomputeOk := false })).2 == .refused [.sh021]

/-- Officer 21 of the treasury with officer 23: weight 3/(3 − 1). -/
def ct : Contrib :=
  { c0 with actor := 21, charter := 8, S := [21, 23], initiator := 21, weight := ⟨3, 2⟩, pairs := [0],
            slot := .ecdsa 5 [21, 23] false }

-- SH-018: a request with subset {A, C} on a slot bound to {A, B}
theorem pin_leaf_set : (apply sp (.contribute { ct with slot := .ecdsa 5 [21, 22] false })).2 = .refused [.sh018] ∧
    (apply sp (.contribute ct)).2 = .contributed false := by decide +kernel
#guard (apply sp (.contribute { ct with slot := .ecdsa 5 [21, 22] false })).2 == .refused [.sh018]
-- SH-018: at most once on one slot
theorem pin_slot_once : (apply (apply sp (.contribute ct)).1 (.contribute { ct with pairs := [1] })).2 = .refused [.sh018] := by
  decide +kernel
#guard (apply (apply sp (.contribute ct)).1 (.contribute { ct with pairs := [1] })).2 == .refused [.sh018]

-- SH-019: the user, primary of `user OR G`, on a slot under `slr_G`
def cu : Contrib := { c0 with charter := 9, S := [1], slot := .ecdsa 30 [1] true, pairs := [0] }
theorem pin_escrow_slot : (apply sp (.contribute cu)).2 = .refused [.sh019] ∧
    (apply sp (.contribute { cu with slot := .ecdsa 30 [1] false })).2 = .contributed false := by decide +kernel
#guard (apply sp (.contribute cu)).2 == .refused [.sh019]

-- SH-026: a guardian named in a seizure request whose order is not settled
def cg : Contrib :=
  { c0 with actor := 10, S := [1, 10, 11, 12], weight := ⟨6, 2⟩, pairs := [0] }
theorem pin_guardian : (apply sp (.contribute cg)).2 = .refused [.sh026] ∧
    (apply sp (.contribute { cg with seizureSettled := true })).2 = .contributed false := by decide +kernel
#guard (apply sp (.contribute cg)).2 == .refused [.sh026]

-- SH-020: 12 guardian slots on P2WPKH (K = 3, L_max = 2)
theorem pin_guardian_slots : guardianSlots 3 2 = 12 := by decide +kernel
#guard guardianSlots 3 2 == 12

-- SH-016: a slot whose correction fails the public check at node 3 is dropped
theorem pin_session : (apply sp (.session [(1, true), (2, false), (3, true)])).2 = .sessionEnd [1, 3] [2] := by
  decide +kernel
#guard (apply sp (.session [(1, true), (2, false), (3, true)])).2 == .sessionEnd [1, 3] [2]

-- SH-017: a birth session prepares 32 slots: 32 puts in TEE mode
theorem pin_puts : (putEntries .TEE (List.range 32)).length = 32 ∧ putEntries .NON_TEE (List.range 32) = [] := by
  decide +kernel
#guard (putEntries .TEE (List.range 32)).length == 32

/-! ## Codes and domains -/

theorem pin_codes : [Refusal.sh001, .sh002, .sh013, .sh015, .sh018, .sh019, .sh021, .sh026, .sh035, .sh036,
    .ackRefused, .badRequest, .birthRefused, .noRule, .noAckCertificate, .noBirthCertificate, .noEscrowCertificate,
    .outsideCapability, .outsideStateDomain, .policyRefused].map Refusal.code =
    ["SH-001", "SH-002", "SH-013", "SH-015", "SH-018", "SH-019", "SH-021", "SH-026", "SH-035", "SH-036",
     "ack_refused", "bad_request", "birth_refused", "no-rule", "no_ack_certificate", "no_birth_certificate",
     "no_escrow_certificate", "outside-capability", "outside-state-domain", "policy_refused"] := by decide +kernel
-- the constructor order is the sorted order of the codes
#guard (["SH-001", "SH-002", "SH-013", "SH-015", "SH-018", "SH-019", "SH-021", "SH-026", "SH-035", "SH-036",
     "ack_refused", "bad_request", "birth_refused", "no-rule", "no_ack_certificate", "no_birth_certificate",
     "no_escrow_certificate", "outside-capability", "outside-state-domain", "policy_refused"].mergeSort) ==
     ["SH-001", "SH-002", "SH-013", "SH-015", "SH-018", "SH-019", "SH-021", "SH-026", "SH-035", "SH-036",
     "ack_refused", "bad_request", "birth_refused", "no-rule", "no_ack_certificate", "no_birth_certificate",
     "no_escrow_certificate", "outside-capability", "outside-state-domain", "policy_refused"]

-- RQ-001 domain
theorem pin_params : paramsOk p0 = true ∧ paramsOk { p0 with n := 6 } = false ∧ paramsOk { p0 with f := 0 } = false := by
  decide +kernel
#guard paramsOk p0 && !paramsOk { p0 with n := 6 } && !paramsOk { p0 with f := 0 }

-- a charter id fixed twice; an invalid charter; a contribution on an unknown charter (ledger 3)
theorem pin_no_rule : (apply s0 (.fixCharter 7 treasury)).2 = .refused [.noRule] ∧
    (apply s0 (.fixCharter 1 (.group 0 1 [.leaf 1 5, .leaf 1 5]))).2 = .refused [.sh002] ∧
    (apply sp (.contribute { c0 with charter := 99 })).2 = .refused [.noRule] := by decide +kernel
#guard (apply s0 (.fixCharter 7 treasury)).2 == .refused [.noRule]

-- a refused operation leaves the state unchanged
theorem pin_unchanged : (apply sp (.contribute { c0 with policyOk := false })).1 = sp := by decide +kernel
#guard (apply sp (.contribute { c0 with policyOk := false })).1 == sp

end SplitShardHolders
