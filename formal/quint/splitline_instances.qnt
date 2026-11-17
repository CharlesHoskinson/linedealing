// -*- mode: Bluespec; -*-
// Instances of splitline.qnt: design instances at each claim's adversary, the
// adversary sweeps of Q1 and §7.7, and one mutant per rule (one Rules field flipped).
// TEE instances with NBYZ = 0 model intact enclaves under malicious operators (NCOLL
// roll back or clone); NBYZ > 0 with TEE models broken enclaves.

// ---- design instances
module sl_n4 {          // non-TEE, |C| = f
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n4_tee {      // TEE, enclaves intact, c = n - 1 - 2f = 1
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 0, NCOLL = 1, TEE = true, WACK = 2, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n7 {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 7, F = 2, NBYZ = 2, NCOLL = 0, TEE = false, WACK = 4, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n7_tee {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 7, F = 2, NBYZ = 0, NCOLL = 2, TEE = true, WACK = 4, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9 {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 2, NCOLL = 0, TEE = false, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 0, NCOLL = 4, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}

// ---- Q1 sweep: non-TEE, f < |C| < t, without and with slot_anchor
module sl_n4_b2 {  // |C| = 2, no slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 2, NCOLL = 0, TEE = false, WACK = 2, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n4_b2_anchor {  // |C| = 2, slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 2, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, slotAnchor: true }).* from "./splitline"
}
module sl_n7_b3 {  // |C| = 3, no slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 7, F = 2, NBYZ = 3, NCOLL = 0, TEE = false, WACK = 4, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n7_b3_anchor {  // |C| = 3, slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 7, F = 2, NBYZ = 3, NCOLL = 0, TEE = false, WACK = 4, RULES = { ...DESIGN_RULES, slotAnchor: true }).* from "./splitline"
}
module sl_n7_b4 {  // |C| = 4, no slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 7, F = 2, NBYZ = 4, NCOLL = 0, TEE = false, WACK = 4, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n7_b4_anchor {  // |C| = 4, slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 7, F = 2, NBYZ = 4, NCOLL = 0, TEE = false, WACK = 4, RULES = { ...DESIGN_RULES, slotAnchor: true }).* from "./splitline"
}
module sl_n9_b3 {  // |C| = 3, no slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 3, NCOLL = 0, TEE = false, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_b3_anchor {  // |C| = 3, slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 3, NCOLL = 0, TEE = false, WACK = 6, RULES = { ...DESIGN_RULES, slotAnchor: true }).* from "./splitline"
}
module sl_n9_b4 {  // |C| = 4, no slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 4, NCOLL = 0, TEE = false, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_b4_anchor {  // |C| = 4, slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 4, NCOLL = 0, TEE = false, WACK = 6, RULES = { ...DESIGN_RULES, slotAnchor: true }).* from "./splitline"
}
module sl_n9_b5 {  // |C| = 5, no slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 5, NCOLL = 0, TEE = false, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_b5_anchor {  // |C| = 5, slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 5, NCOLL = 0, TEE = false, WACK = 6, RULES = { ...DESIGN_RULES, slotAnchor: true }).* from "./splitline"
}
module sl_n9_b6 {  // |C| = 6, no slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 6, NCOLL = 0, TEE = false, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_b6_anchor {  // |C| = 6, slot_anchor
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 6, NCOLL = 0, TEE = false, WACK = 6, RULES = { ...DESIGN_RULES, slotAnchor: true }).* from "./splitline"
}

// ---- §7.7 sweep: TEE with b broken enclaves and c rollback colluders at n = 9
module sl_n9_tee_b0_c4 {  // broken 0, colluders 4
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 0, NCOLL = 4, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee_b0_c5 {  // broken 0, colluders 5
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 0, NCOLL = 5, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee_b3_c1 {  // broken 3, colluders 1
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 3, NCOLL = 1, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee_b3_c2 {  // broken 3, colluders 2
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 3, NCOLL = 2, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee_b4_c0 {  // broken 4, colluders 0
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 4, NCOLL = 0, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee_b4_c1 {  // broken 4, colluders 1
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 4, NCOLL = 1, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee_b5_c0 {  // broken 5, colluders 0
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 5, NCOLL = 0, TEE = true, WACK = 6, RULES = DESIGN_RULES).* from "./splitline"
}
module sl_n9_tee_b3_c1_w5 {  // mutant: w = n - 2 - f
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 3, NCOLL = 1, TEE = true, WACK = 5, RULES = DESIGN_RULES).* from "./splitline"
}

// ---- mutants: one rule flipped
module m_burn {  // mutant burnAtEnd: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, burnAtEnd: false }).* from "./splitline"
}
module m_precedence {  // mutant slotPrecedence: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, slotPrecedence: false }).* from "./splitline"
}
module m_distinct {  // mutant checkDistinctSlots: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, checkDistinctSlots: false }).* from "./splitline"
}
module m_gens3 {  // mutant maxGens: 3
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, maxGens: 3 }).* from "./splitline"
}
module m_ecdsa_shared {  // mutant ecdsaSlotPerVariant: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, ecdsaSlotPerVariant: false }).* from "./splitline"
}
module m_bf_p2 {  // mutant boardFirstP2: true
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, boardFirstP2: true }).* from "./splitline"
}
module m_inclusion {  // mutant releaseAtInclusion: true
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, releaseAtInclusion: true }).* from "./splitline"
}
module m_direct_call {  // mutant directCallBF: true
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, directCallBF: true }).* from "./splitline"
}
module m_partial_qc {  // mutant partialBeforeQC: true
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, partialBeforeQC: true }).* from "./splitline"
}
module m_no_collect {  // mutant admitWithoutContrib: true
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, admitWithoutContrib: true }).* from "./splitline"
}
module m_leafset {  // mutant leafSetCheck: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, leafSetCheck: false }).* from "./splitline"
}
module m_cold_old {  // mutant coldBurnUnclaimed: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, coldBurnUnclaimed: false }).* from "./splitline"
}
module m_dd {  // mutant ddUnique: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, ddUnique: false }).* from "./splitline"
}
module m_ra {  // mutant actorChecksRA: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, actorChecksRA: false }).* from "./splitline"
}
module m_slot_root {  // mutant slotRootCheck: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, slotRootCheck: false }).* from "./splitline"
}
module m_settle_unspent {  // mutant releasedStaysLocked: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, releasedStaysLocked: false }).* from "./splitline"
}
module m_auth_ref {  // mutant piBindsAuthRef: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, piBindsAuthRef: false }).* from "./splitline"
}
module m_stall_local {  // mutant stallBoardPredicate: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, stallBoardPredicate: false }).* from "./splitline"
}
module m_hold0 {  // mutant holdDelay: 0
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, holdDelay: 0 }).* from "./splitline"
}
module m_bf_pending {  // mutant bfPendingAfterVerify: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, bfPendingAfterVerify: false }).* from "./splitline"
}
module m_witkey {  // mutant witnessKeyFull: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 0, NCOLL = 1, TEE = true, WACK = 2, RULES = { ...DESIGN_RULES, witnessKeyFull: false }).* from "./splitline"
}
module m_open_final {  // mutant openProvisional: false
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 0, NCOLL = 1, TEE = true, WACK = 2, RULES = { ...DESIGN_RULES, openProvisional: false }).* from "./splitline"
}

module m_cold_void {   // DECISIONS 53 reverted: a request a restart ends settles VOID when its input is unspent
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, coldSettleLocked: false }).* from "./splitline"
}
module m_g5 {  // mutant ecdsaPrecInForce: false (finding G5: precedence and burn before the authorization)
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = { ...DESIGN_RULES, ecdsaPrecInForce: false }).* from "./splitline"
}
