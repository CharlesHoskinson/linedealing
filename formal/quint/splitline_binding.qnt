// -*- mode: Bluespec; -*-
// The binding of an actor's contribution to its weight (DESIGN §4.2 item 3, §2.4,
// DECISIONS 72; finding E1). Written from the DESIGN text only. It is the companion of
// splitline.qnt for the contribution step: `doContribute` there is one event per request,
// and this model opens it to the pool pair, the binding input and the weight.
//
// One 2-of-3 group with members 1, 2 and 3. Member 1 is honest and has a pool of pairs.
// The adversary holds members 2 and 3 and every node, and posts requests. A request names
// one pair of member 1, an initiator (member 2 or 3), the initiator's nonce R_0 and a
// message. Its signing set is {1, initiator}. The weight of member 1 is 2 beside member 2
// and 3/2 beside member 3 (§2.4), held here as twice the weight: 4 and 3.
//
// The model abstracts the hash: `bindKey` is the input of ρ_1, which is the commitment
// list CL with pm. Two requests have one ρ_1, one R and one c exactly when their keys are
// equal. The committee slot is fixed and is left out of the key.
//
// Rules (constants): clNamesInitiator (CL starts with the initiator's leaf id) and
// answerOnce (member 1 answers a pair once, §3.10). ROLLBACKS bounds the restores of
// member 1's pool from a copy made before its answers: a restored pool answers a pair again.
//
// Not modeled: curve arithmetic, the committee half, pools of members 2 and 3, and three
// answers on one pair under three binding factors, which also give the nonce pair.

module splitline_binding_types {
  type DRules = { clNamesInitiator: bool, answerOnce: bool }
  pure val BINDING_RULES: DRules = { clNamesInitiator: true, answerOnce: true }

  type BReq = { pair: int, initiator: int, r0: int, msg: int }
  // the input of ρ_1: the initiator's leaf id (0 when CL does not name it), R_0, the
  // pair of member 1 and pm
  type BKey = { init: int, r0: int, pair: int, pm: int }
  type BAnswer = { pair: int, key: BKey, weight2: int }
}

module splitline_binding {
  import splitline_binding_types.*
  const DR: DRules
  const ROLLBACKS: int

  pure val PAIRS: Set[int] = Set(1, 2)
  pure val INITIATORS: Set[int] = Set(2, 3)
  pure val NONCES: Set[int] = Set(1, 2)
  pure val MSGS: Set[int] = Set(1, 2)

  // §2.4: twice the Lagrange coefficient at zero of member 1 in {1, i}: i / (i − 1)
  pure def weight2(r: BReq): int = if (r.initiator == 2) 4 else 3

  // §4.2 item 3: CL = leaf_0 ‖ R_0 ‖ (leaf_1 ‖ pool ‖ pair ‖ D ‖ E) ‖ slot points, and pm
  pure def bindKey(r: BReq): BKey =
    { init: if (DR.clNamesInitiator) r.initiator else 0, r0: r.r0, pair: r.pair, pm: r.msg }

  type DS = {
    posted: Set[BReq],        // requests on the board
    used: Set[int],           // pairs that member 1's pool holds as answered
    answers: Set[BAnswer],    // answers that left member 1
    rollbacks: int,
    lastAction: str,
  }

  var d: DS

  action dinit: bool = all {
    d' = { posted: Set(), used: Set(), answers: Set(), rollbacks: 0, lastAction: "init" },
  }

  // The adversary posts a request that names a pair of member 1.
  action doPost(r: BReq): bool = all {
    not(d.posted.contains(r)),
    d' = { ...d, posted: d.posted.union(Set(r)), lastAction: "post" },
  }

  // §4.2 actor's rules: member 1 recomputes CL, ρ_1 and its weight from the request and
  // answers once per pair.
  action doAnswer(r: BReq): bool = all {
    d.posted.contains(r),
    not(DR.answerOnce) or not(d.used.contains(r.pair)),
    d' = { ...d,
      used: d.used.union(Set(r.pair)),
      answers: d.answers.union(Set({ pair: r.pair, key: bindKey(r), weight2: weight2(r) })),
      lastAction: "answer" },
  }

  // Member 1's pool is restored from a copy made before its answers. The answers that
  // left stay with the adversary.
  action doRollback: bool = all {
    d.rollbacks < ROLLBACKS, d.used.size() > 0,
    d' = { ...d, used: Set(), rollbacks: d.rollbacks + 1, lastAction: "rollback" },
  }

  action dstep: bool = any {
    nondet p = PAIRS.oneOf()
    nondet i = INITIATORS.oneOf()
    nondet k = NONCES.oneOf()
    nondet m = MSGS.oneOf()
    any { doPost({ pair: p, initiator: i, r0: k, msg: m }), doAnswer({ pair: p, initiator: i, r0: k, msg: m }) },
    doRollback,
  }

  // C19 (DECISIONS 72): one binding input fixes the weight. No two requests that the
  // adversary can post give member 1 one ρ_1 under two weights.
  val C19_BindingFixesWeight: bool =
    d.posted.forall(a => d.posted.forall(b => bindKey(a) == bindKey(b) implies weight2(a) == weight2(b)))

  // C17, C19: no two answers stand on one nonce d + ρ_1·e and one challenge under two
  // weights. Two such answers give x_1 = (s − s') / (c̃·(λ − λ')).
  val C19_OneNonceOneWeight: bool =
    d.answers.forall(a => d.answers.forall(b => (a.pair == b.pair and a.key == b.key) implies a.weight2 == b.weight2))

  // §3.10: without a restore, a pair has one answer.
  val C19_OneAnswerPerPair: bool =
    d.rollbacks == 0 implies d.answers.forall(a => d.answers.forall(b => a.pair == b.pair implies a == b))

  val BindingInvariants: bool = C19_BindingFixesWeight and C19_OneNonceOneWeight and C19_OneAnswerPerPair

  val TwoInitiatorsReached: bool =
    d.posted.exists(a => d.posted.exists(b => a.pair == b.pair and a.initiator != b.initiator))
  val AnswerReached: bool = d.answers.size() > 0
  val SecondAnswerReached: bool = d.answers.exists(a => d.answers.exists(b => a.pair == b.pair and a != b))
}

// ---- design instances: without and with one restore of the pool
module dl_design {
  import splitline_binding_types.*
  import splitline_binding(DR = BINDING_RULES, ROLLBACKS = 0).*
}
module dl_design_rollback {
  import splitline_binding_types.*
  import splitline_binding(DR = BINDING_RULES, ROLLBACKS = 1).*
}
// ---- mutants: CL as it was before DECISIONS 72, without the initiator's leaf id
module dm_no_initiator {
  import splitline_binding_types.*
  import splitline_binding(DR = { ...BINDING_RULES, clNamesInitiator: false }, ROLLBACKS = 0).*
}
module dm_no_initiator_rollback {
  import splitline_binding_types.*
  import splitline_binding(DR = { ...BINDING_RULES, clNamesInitiator: false }, ROLLBACKS = 1).*
}

// Scripted runs: the mutant reaches the harm, the design holds on the same schedule.
module binding_scenarios {
  import splitline_binding_types.*
  import splitline_binding(DR = DX, ROLLBACKS = 1).*
  const DX: DRules

  // one pair, one R_0 and one message, with member 2 and with member 3 as the initiator
  pure val reqA: BReq = { pair: 1, initiator: 2, r0: 1, msg: 1 }
  pure val reqB: BReq = { pair: 1, initiator: 3, r0: 1, msg: 1 }

  action twoInitiators: bool = dinit.then(doPost(reqA)).then(doPost(reqB))

  // E1: the two requests have one binding input and two weights.
  run twoInitiatorsBroken = twoInitiators
    .expect(bindKey(reqA) == bindKey(reqB) and weight2(reqA) != weight2(reqB) and not(C19_BindingFixesWeight))
  run twoInitiatorsHolds = twoInitiators
    .expect(bindKey(reqA) != bindKey(reqB) and BindingInvariants)
  // The rule that held before the fix: one pool answers a pair once.
  run secondAnswerRefusedHolds = twoInitiators.then(doAnswer(reqA))
    .expect(C19_OneNonceOneWeight and C19_OneAnswerPerPair)
    .then(doAnswer(reqB).fail())
  // A restored pool answers the pair again. Without the initiator's leaf id the two
  // answers stand on one nonce under two weights.
  action restoredPool: bool = twoInitiators.then(doAnswer(reqA)).then(doRollback).then(doAnswer(reqB))
  run restoredPoolBroken = restoredPool.expect(SecondAnswerReached and not(C19_OneNonceOneWeight))
  run restoredPoolHolds = restoredPool.expect(SecondAnswerReached and BindingInvariants)
}

module dt_design { import splitline_binding_types.*
  import binding_scenarios(DX = BINDING_RULES).* }
module dt_no_initiator { import splitline_binding_types.*
  import binding_scenarios(DX = { ...BINDING_RULES, clNamesInitiator: false }).* }
