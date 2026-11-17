// -*- mode: Bluespec; -*-
// Birth of a network-created shard for an offline holder (DESIGN §3.1 steps 1, 3 and 4,
// §5.7, DECISIONS 67; REVIEW-17a finding 3, PA3). Written from the DESIGN text only.
//
// The creator picks e_c, sets X_u = U + Hq_st(e_c·U)·G and proves δ = Hq_st(e_c·U) for
// X_u − U at birth. The birth proofs bind X_u and δ. They do not bind the ciphertext of
// E_c that the asset record carries to the holder. A creator that encrypts another E_c'
// passes the birth check, and the holder then derives x_u' with x_u'·G ≠ X_u: nobody can
// sign for the address. The model abstracts the curve: `ecGood` is true when the record's
// ciphertext decrypts to the E_c behind δ.
//
// Design: the record is born unacknowledged. The holder, once online, derives x_u, checks
// x_u·G = X_u and sends an ACK envelope with a proof of possession under X_u. q nodes check
// it and sign ACK_OK; the holder's acknowledge transaction marks the record acknowledged.
// A payer wallet funds a network-created-shard address only once the record is acknowledged.
//
// Rules (constants): fundAfterAck (payer waits for the acknowledgement), ackChecksPop
// (nodes sign ACK_OK only for a proof of possession under X_u).

module splitline_birth_types {
  type BRules = { fundAfterAck: bool, ackChecksPop: bool }
  pure val BIRTH_RULES: BRules = { fundAfterAck: true, ackChecksPop: true }
}

module splitline_birth {
  import splitline_birth_types.*
  const BR: BRules
  const NB: int      // nodes
  const FB: int      // corrupt nodes, at most f

  pure val QB: int = (NB + FB + 2) / 2
  pure val HONEST_B: Set[int] = 1.to(NB - FB)

  type BS = {
    born: bool,            // birth certificate issued (q BIRTH_OK)
    ecGood: bool,          // the record's ciphertext opens to the E_c behind δ
    recFinal: bool,        // the asset record is final on Midnight
    holderOnline: bool,
    holderDerives: bool,   // the holder's x_u matches X_u
    ackSigners: Set[int],  // nodes that signed ACK_OK
    ackPopValid: bool,     // the ACK envelope carries a valid proof of possession under X_u
    acked: bool,           // the acknowledge transaction is final on Midnight
    payerFunded: bool,
    lastAction: str,
  }

  var b: BS

  action binit: bool = all {
    b' = { born: false, ecGood: true, recFinal: false, holderOnline: false, holderDerives: false,
           ackSigners: Set(), ackPopValid: false, acked: false, payerFunded: false, lastAction: "init" },
  }

  // §3.1 steps 1 and 3: the birth check verifies pop_U and the creator's proof of δ. Both
  // pass whatever ciphertext of E_c the creator puts in the record.
  action doBirth(good: bool): bool = all {
    not(b.born),
    b' = { ...b, born: true, ecGood: good, lastAction: if (good) "birthGood" else "birthBadEc" },
  }

  // §3.1 step 4: the record lands on Midnight with the encrypted E_c.
  action doRecord: bool = all {
    b.born, not(b.recFinal),
    b' = { ...b, recFinal: true, lastAction: "record" },
  }

  // The holder comes online, decrypts E_c and derives x_u = u + Hq_st(u·E_c).
  action doHolderOnline: bool = all {
    b.recFinal, not(b.holderOnline),
    b' = { ...b, holderOnline: true, holderDerives: b.ecGood, lastAction: "holderOnline" },
  }

  // The holder sends the ACK envelope only when x_u·G = X_u, with pop_u under X_u.
  action doHolderAck: bool = all {
    b.holderOnline, b.holderDerives, not(b.ackPopValid),
    b' = { ...b, ackPopValid: true, lastAction: "holderAck" },
  }

  // A corrupt creator posts an ACK envelope for the record without x_u: no valid pop_u.
  action doFakeAck: bool = all {
    b.recFinal, not(b.ackPopValid),
    b' = { ...b, lastAction: "fakeAck", ackSigners: b.ackSigners },
  }

  // An honest node signs ACK_OK after it checks pop_u against X_u of the birth context.
  action doSignAck(i: int): bool = all {
    HONEST_B.contains(i), b.recFinal, not(b.ackSigners.contains(i)),
    not(BR.ackChecksPop) or b.ackPopValid,
    b.ackPopValid or b.lastAction == "fakeAck" or b.ackSigners.size() > 0,
    b' = { ...b, ackSigners: b.ackSigners.union(Set(i)), lastAction: "signAck" },
  }

  // q ACK_OK signatures (corrupt nodes sign anything) form the acknowledgement certificate;
  // the acknowledge transaction marks the record.
  action doAcknowledge: bool = all {
    b.ackSigners.size() + FB >= QB, not(b.acked),
    b' = { ...b, acked: true, lastAction: "acknowledge" },
  }

  // A payer wallet funds the address of a network-created shard.
  action doPayerFund: bool = all {
    b.recFinal, not(b.payerFunded),
    not(BR.fundAfterAck) or b.acked,
    b' = { ...b, payerFunded: true, lastAction: "payerFund" },
  }

  action bstep: bool = any {
    nondet good = Bool.oneOf()
    doBirth(good),
    doRecord, doHolderOnline, doHolderAck, doFakeAck,
    nondet i = HONEST_B.oneOf()
    doSignAck(i),
    doAcknowledge, doPayerFund,
  }

  // C1 (DECISIONS 67): a payer funds only an address whose holder can derive its shard.
  val C1_FundedOnlyDerivable: bool = b.payerFunded implies b.ecGood
  // C1 (DECISIONS 67): a record is acknowledged only when its holder derived x_u.
  val C1_AckedOnlyDerivable: bool = b.acked implies b.ecGood
  val BirthInvariants: bool = C1_FundedOnlyDerivable and C1_AckedOnlyDerivable

  val BadEcBornReached: bool = b.born and not(b.ecGood)
  val FundedReached: bool = b.payerFunded
}

module bl_design {
  import splitline_birth_types.*
  import splitline_birth(BR = BIRTH_RULES, NB = 4, FB = 1).*
}
module bm_fund_on_final {
  import splitline_birth_types.*   // §3.1 step 4 before DECISIONS 67: fundable once the record is final
  import splitline_birth(BR = { ...BIRTH_RULES, fundAfterAck: false }, NB = 4, FB = 1).*
}
module bm_ack_no_pop {
  import splitline_birth_types.*      // nodes sign ACK_OK without the proof of possession under X_u
  import splitline_birth(BR = { ...BIRTH_RULES, ackChecksPop: false }, NB = 4, FB = 1).*
}

// Scripted runs: the mutant reaches the harm, the design refuses the step.
module birth_scenarios {
  import splitline_birth_types.*
  import splitline_birth(BR = BX, NB = 4, FB = 1).*
  const BX: BRules

  action badBirth: bool = binit.then(doBirth(false)).then(doRecord)

  // PA3: a bad E_c passes the birth check, and a payer funds the address on finality.
  run badEcFundBroken = badBirth.then(doPayerFund)
    .expect(b.born and not(b.ecGood) and not(C1_FundedOnlyDerivable))
  run badEcFundRefusedHolds = badBirth.then(doPayerFund.fail())
  // The holder comes online, cannot derive x_u, and sends no acknowledgement.
  run badEcNoAckHolds = badBirth.then(doHolderOnline)
    .expect(BirthInvariants and not(b.holderDerives))
    .then(doHolderAck.fail())
  // A corrupt creator posts an ACK without pop_u; honest nodes do not sign it.
  run fakeAckBroken = badBirth.then(doFakeAck).then(doSignAck(1)).then(doSignAck(2)).then(doAcknowledge)
    .expect(not(C1_AckedOnlyDerivable))
  run fakeAckRefusedHolds = badBirth.then(doFakeAck).then(doSignAck(1).fail())
  // A good E_c: the holder acknowledges and the payer funds.
  run goodAckFundHolds = binit.then(doBirth(true)).then(doRecord).then(doHolderOnline).then(doHolderAck)
    .then(doSignAck(1)).then(doSignAck(2)).then(doAcknowledge).then(doPayerFund)
    .expect(BirthInvariants and b.payerFunded)
}

module bt_design { import splitline_birth_types.*
  import birth_scenarios(BX = BIRTH_RULES).* }
module bt_fund_on_final { import splitline_birth_types.*
  import birth_scenarios(BX = { ...BIRTH_RULES, fundAfterAck: false }).* }
module bt_ack_no_pop { import splitline_birth_types.*
  import birth_scenarios(BX = { ...BIRTH_RULES, ackChecksPop: false }).* }
