// -*- mode: Bluespec; -*-
// Scripted regression runs for splitline_pools.qnt. Each scenario runs once on a mutant
// (the rule removed), where it reaches a state that breaks the target invariant, and once on
// the design instance, where the step that reuses the slot is refused and every invariant
// holds. Run: quint test splitline_pools_test.qnt --main <module>
// Export traces: add --out-itf '../../tests/quint-regressions/splitline/{test}.itf.json'

module pools_scenarios {
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = ANC, PR = RULESX).* from "./splitline_pools"
  const ANC: bool
  const RULESX: PRules

  // a request of suite su on index ix runs to its first partial at node 1
  action reqToPartial(r: int, su: int, ix: int): bool =
    doPost(r, su, ix).then(doOrder(r)).then(doVote(1, r)).then(doVote(2, r)).then(doAdmit(r))
      .then(doAnchor(r, 1)).then(doHeight)
      .then(if (ANC) doLog(1, if (su == 3) 3 else su).then(if (p.recovered) doSuccCheckpoint else doCheckpoint) else doIdle)
      .then(doBindBatch(1, if (su == 3) 3 else su, r)).then(doRelease(1, r))

  // up to the reuse: the request reaches the bind of node 1 on the old slot
  action reqToBind(r: int, su: int, ix: int): bool =
    doPost(r, su, ix).then(doOrder(r)).then(doVote(1, r)).then(doVote(2, r)).then(doAdmit(r))
      .then(doAnchor(r, 1)).then(doHeight)
      .then(if (ANC) doLog(1, if (su == 3) 3 else su).then(if (p.recovered) doSuccCheckpoint else doCheckpoint) else doIdle)

  // W1: window burn. r1 takes index 1 after checkpoint 1; the restart loses the board tail.
  run windowBurnBroken = pinit.then(doCheckpoint).then(reqToPartial(1, 1, 1)).then(doWholeRestart)
    .then(reqToBind(2, 1, 1)).then(doBindBatch(1, 1, 2)).then(doRelease(1, 2))
    .expect(not(C16_NoSlotTwice))
  run windowBurnHolds = pinit.then(doCheckpoint).then(reqToPartial(1, 1, 1)).then(doWholeRestart)
    .then(reqToBind(2, 1, 1))
    .expect(PoolInvariants)
    .then(doBindBatch(1, 1, 2).fail())

  // W2: pending burn. Checkpoint 2 lists r1 pending; after it r1 anchors and signs; the
  // restart restores r1 as admitted and its anchor picks variant 2.
  run pendingBurnBroken = pinit.then(doCheckpoint)
    .then(doPost(1, 1, 1)).then(doOrder(1)).then(doVote(1, 1)).then(doVote(2, 1)).then(doAdmit(1))
    .then(doCheckpoint).then(doAnchor(1, 1)).then(doBindBatch(1, 1, 1)).then(doRelease(1, 1))
    .then(doWholeRestart).then(doHeight).then(doAnchor(1, 2)).then(doBindBatch(1, 1, 1)).then(doRelease(1, 1))
    .expect(not(C16_NoSlotTwice))
  run pendingBurnHolds = pinit.then(doCheckpoint)
    .then(doPost(1, 1, 1)).then(doOrder(1)).then(doVote(1, 1)).then(doVote(2, 1)).then(doAdmit(1))
    .then(doCheckpoint).then(doAnchor(1, 1)).then(doBindBatch(1, 1, 1)).then(doRelease(1, 1))
    .then(doWholeRestart).then(doHeight)
    .expect(PoolInvariants and p.reqs.get(1).reason == "BURNED")
    .then(doAnchor(1, 2).fail())

  // W3: window vote and window bind. r1 names index 3 above h + B = 2.
  run windowVoteBroken = pinit.then(doCheckpoint).then(reqToPartial(1, 1, 3)).then(doWholeRestart)
    .then(reqToBind(2, 1, 3)).then(doBindBatch(1, 1, 2)).then(doRelease(1, 2))
    .expect(not(C16_NoSlotTwice))
  run windowVoteHolds = pinit.then(doCheckpoint).then(doPost(1, 1, 3)).then(doOrder(1))
    .expect(PoolInvariants)
    .then(doVote(1, 1).fail())

  // W4: account-pool burn. An ECDSA slot claimed after the checkpoint.
  run accountBurnBroken = pinit.then(doCheckpoint).then(reqToPartial(1, 3, 1)).then(doWholeRestart)
    .then(doCheckpoint).then(reqToBind(2, 3, 1)).then(doBindBatch(1, 3, 2)).then(doRelease(1, 2))
    .expect(not(C16_NoSlotTwice))
  run accountBurnHolds = pinit.then(doCheckpoint).then(reqToPartial(1, 3, 1)).then(doWholeRestart)
    .then(doCheckpoint).then(reqToBind(2, 3, 1))
    .expect(PoolInvariants)
    .then(doBindBatch(1, 3, 2).fail())

  // W5: account bind before the post-restart checkpoint (marker rule of §7.11).
  run accountMarkerHolds = pinit.then(doCheckpoint).then(doWholeRestart)
    .then(reqToBind(2, 3, 2))
    .expect(PoolInvariants)
    .then(doBindBatch(1, 3, 2).fail())

  // R1: E reshares from the checkpoint's board view without anchors.
  run reshareNoAnchorBroken = pinit.then(doCheckpoint).then(reqToPartial(1, 3, 1)).then(doRecover)
    .then(reqToBind(2, 3, 1)).then(doBindBatch(1, 3, 2)).then(doRelease(1, 2))
    .expect(not(C16_NoSlotTwice) and not(C15_NoEcdsaReshareWithoutAnchor))
  run reshareNoAnchorHolds = pinit.then(doCheckpoint).then(reqToPartial(1, 3, 1)).then(doRecover)
    .then(reqToBind(2, 3, 1))
    .expect(PoolInvariants and p.reshared == Set())
    .then(doBindBatch(1, 3, 2).fail())

  // R2: with anchors, E reshares a slot that a covered seat log binds.
  run reshareCoveredBroken = pinit.then(doCheckpoint).then(reqToPartial(1, 3, 1)).then(doRecover)
    .then(reqToBind(2, 3, 1)).then(doBindBatch(1, 3, 2)).then(doRelease(1, 2))
    .expect(not(C16_NoSlotTwice))
  run reshareCoveredHolds = pinit.then(doCheckpoint).then(reqToPartial(1, 3, 1)).then(doRecover)
    .then(doPost(2, 3, 1)).then(doOrder(2)).then(doVote(1, 2)).then(doVote(2, 2)).then(doAdmit(2))
    .then(doAnchor(2, 1)).then(doHeight)
    .expect(PoolInvariants and not(p.reshared.contains(1)) and p.reshared.contains(2))
    .then(doLog(1, 3).fail())

  // QA-4 (DECISIONS 54, §4.1): r1 is ordered first on account slot (3, 1) and r2 second.
  // r2 collects its votes first; its admission is refused and r1 is admitted.
  run acctEarliestHolds = pinit
    .then(doPost(1, 3, 1)).then(doOrder(1)).then(doPost(2, 3, 1)).then(doOrder(2))
    .then(doVote(1, 2)).then(doVote(2, 2)).then(doAdmit(2).fail())
  run acctEarliestBroken = pinit
    .then(doPost(1, 3, 1)).then(doOrder(1)).then(doPost(2, 3, 1)).then(doOrder(2))
    .then(doVote(1, 2)).then(doVote(2, 2)).then(doAdmit(2)).then(doVoidAcctTaken(1))
    .expect(p.reqs.get(1).reason == "SLOT_TAKEN" and not(C13_AcctEarliestHolds))
  run acctEarliestAdmitsHolds = pinit
    .then(doPost(1, 3, 1)).then(doOrder(1)).then(doPost(2, 3, 1)).then(doOrder(2))
    .then(doVote(1, 2)).then(doVote(2, 2)).then(doVote(1, 1)).then(doVote(2, 1)).then(doAdmit(1))
    .then(doVoidAcctTaken(2))
    .expect(PoolInvariants and p.reqs.get(1).held and p.reqs.get(2).reason == "SLOT_TAKEN")

  // QA-5 (§7.11 item 1): after the restart burns (h, h + B], a request on a burned index
  // gets no vote and ends VOID; a request ordered before the checkpoint on a burned index
  // ends VOID at the restart.
  run burnedIndexVoteRefusedHolds = pinit.then(doCheckpoint).then(doWholeRestart)
    .then(doPost(1, 1, 1)).then(doOrder(1)).then(doVote(1, 1).fail())
  run burnedIndexVoidHolds = pinit.then(doCheckpoint).then(doWholeRestart)
    .then(doPost(1, 1, 1)).then(doOrder(1)).then(doVoidBurned(1))
    .expect(PoolInvariants and p.reqs.get(1).reason == "BURNED")
  run restartEndsOrderedHolds = pinit.then(doPost(1, 1, 1)).then(doOrder(1)).then(doCheckpoint)
    .then(doWholeRestart)
    .expect(PoolInvariants and p.reqs.get(1).st == "V" and p.reqs.get(1).reason == "BURNED")

  // QA-14: the bind check alone. Votes arrive before a checkpoint raises the floor past
  // index 1; without windowBind the late bind of index 1 goes through.
  run windowBindBroken = pinit.then(doCheckpoint)
    .then(doPost(1, 1, 1)).then(doOrder(1)).then(doVote(1, 1)).then(doVote(2, 1))
    .then(doPost(2, 1, 2)).then(doOrder(2)).then(doVote(1, 2)).then(doVote(2, 2)).then(doAdmit(2))
    .then(doCheckpoint).then(doAdmit(1)).then(doAnchor(1, 1)).then(doBindBatch(1, 1, 1))
    .expect(C13_VoteInWindow and not(C13_BindInWindow))
  run windowBindHolds = pinit.then(doCheckpoint)
    .then(doPost(1, 1, 1)).then(doOrder(1)).then(doVote(1, 1)).then(doVote(2, 1))
    .then(doPost(2, 1, 2)).then(doOrder(2)).then(doVote(1, 2)).then(doVote(2, 2)).then(doAdmit(2))
    .then(doCheckpoint).then(doAdmit(1)).then(doAnchor(1, 1)).then(doBindBatch(1, 1, 1))
    .expect(PoolInvariants and p.nodes.get(1).sl.get((1, 1)) == Free)

}

module pt_design { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = POOL_RULES).* }
module pt_anchor { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = true, RULESX = POOL_RULES).* }
module pt_no_window_burn { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, burnWindow: false }).* }
module pt_no_pending_burn { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, burnPending: false }).* }
module pt_window { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, windowVote: false, windowBind: false }).* }
module pt_no_account_burn { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, burnAccounts: false }).* }
module pt_reshare_no_anchor { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, reshareNoAnchor: true }).* }
module pt_reshare_all { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = true, RULESX = { ...POOL_RULES, reshareCoveredOnly: false }).* }
module pt_window_bind { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, windowBind: false }).* }
module pt_seald { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, voteStale: false }).* }
module pt_acct_named { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, acctBurnAll: false }).* }
module pt_acct_race { import splitline_pools_types.* from "./splitline_pools"
  import pools_scenarios(ANC = false, RULESX = { ...POOL_RULES, acctPrec: false }).* }
