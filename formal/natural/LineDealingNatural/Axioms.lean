import LineDealingNatural.Basic
import LineDealingNatural.Ecdsa
import LineDealingNatural.Sealed
import LineDealingNatural.NonceReuse
import LineDealingNatural.Pad
import LineDealingNatural.Reshare
import LineDealingNatural.Bip340
import LineDealingNatural.Quorum
import LineDealingNatural.Anchor
import LineDealingNatural.Votes
import LineDealingNatural.Impossibility
import LineDealingNatural.Gaps
import LineDealingNatural.Split

/-!
# Axiom check

`#assert_std_axioms` fails the build if a listed theorem depends on an axiom other than
`propext`, `Classical.choice` and `Quot.sound`. An unfinished proof depends on a fourth axiom, so
it fails too. The command prints one line per
module with the number of theorems checked and the axioms they use.
-/

open Lean Elab Command in
/-- Checks the axioms of the listed theorems. -/
elab "#assert_std_axioms " label:str ids:ident+ : command => do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  let mut used : Array Name := #[]
  for id in ids do
    let n ← liftCoreM <| realizeGlobalConstNoOverloadWithInfo id
    let ax ← collectAxioms n
    let bad := ax.filter (fun a => !allowed.contains a)
    unless bad.isEmpty do throwErrorAt id "{n} depends on {bad}"
    for a in ax do
      unless used.contains a do used := used.push a
  logInfo m!"{label.getString}: {ids.size} theorems, axioms used: {used.qsort Name.lt}"

#assert_std_axioms "Basic"
  LineDealingNatural.smul_eq_zero_of_ne_zero
  LineDealingNatural.smul_left_inj'
  LineDealingNatural.sum_lam_mul_eval
  LineDealingNatural.sum_lam_mul_pow
  LineDealingNatural.sum_lam_smul_feldmanEval
  LineDealingNatural.feldmanEval_commit

#assert_std_axioms "Ecdsa"
  LineDealingNatural.partial_combine
  LineDealingNatural.open_ecdsa_binding
  LineDealingNatural.open_ecdsa_equation
  LineDealingNatural.ecdsaVerify_iff
  LineDealingNatural.open_ecdsa_verifies
  LineDealingNatural.sum_lam_mul_smul
  LineDealingNatural.partial_check_sound
  LineDealingNatural.partial_check_verifies
  LineDealingNatural.partial_check_complete

#assert_std_axioms "Sealed"
  LineDealingNatural.sealed_release_sound
  LineDealingNatural.feldman_binds_constant
  LineDealingNatural.sealed_schnorr_binding
  LineDealingNatural.sealed_schnorr_release
  LineDealingNatural.sealed_ecdsa_binding
  LineDealingNatural.sealed_ecdsa_release
  LineDealingNatural.sealed_ecdsa_honest

#assert_std_axioms "NonceReuse"
  LineDealingNatural.ecdsa_nonce_reuse
  LineDealingNatural.schnorr_one_nonce_reuse
  LineDealingNatural.schnorr_two_sigs_family
  LineDealingNatural.schnorr_two_sigs_not_determine
  LineDealingNatural.schnorr_two_sigs_no_extractor
  LineDealingNatural.det3_eq_det
  LineDealingNatural.schnorr_three_sigs_determine
  LineDealingNatural.schnorr_three_sigs_unique

#assert_std_axioms "Pad"
  LineDealingNatural.padDelta_shared_pad
  LineDealingNatural.pad_reuse_recovers_key
  LineDealingNatural.pad_bijective
  LineDealingNatural.pad_count_eq_one
  LineDealingNatural.pad_pair_unique
  LineDealingNatural.pad_diff_count

#assert_std_axioms "Reshare"
  LineDealingNatural.resharePoly_eval
  LineDealingNatural.reshare_constant
  LineDealingNatural.resharePoly_degree_lt
  LineDealingNatural.reshare_commit_constant
  LineDealingNatural.reshare_keeps_g_and_X
  LineDealingNatural.feldmanEval_reshareCommit
  LineDealingNatural.reshare_share_check
  LineDealingNatural.reshare_then_sign_sound

#assert_std_axioms "Bip340"
  LineDealingNatural.bip340_negate
  LineDealingNatural.schnorr_honest
  LineDealingNatural.bip340_even_nonce
  LineDealingNatural.open_schnorr_partial_sound

#assert_std_axioms "Quorum"
  LineDealingNatural.card_add_card_le_card_add_inter
  LineDealingNatural.quorum_inter_card_general
  LineDealingNatural.exists_not_mem_of_card_lt
  LineDealingNatural.quorum_spec
  LineDealingNatural.lt_two_mul_quorum
  LineDealingNatural.quorum_le_of_lt_two_mul
  LineDealingNatural.quorum_three_mul_add_one
  LineDealingNatural.quorum_add_le
  LineDealingNatural.two_mul_add_one_le_quorum
  LineDealingNatural.quorum_inter_card_q
  LineDealingNatural.quorum_inter_honest_q
  LineDealingNatural.quorum_inter_honest_univ_q
  LineDealingNatural.quorum_le_card_honest
  LineDealingNatural.quorum_honest_card
  LineDealingNatural.quorum_inter_fails_below
  LineDealingNatural.quorum_inter_card
  LineDealingNatural.quorum_inter_honest
  LineDealingNatural.quorum_inter_honest_univ
  LineDealingNatural.quorum_inter_fails_of_large
  LineDealingNatural.quorum_inter_fails_of_small

#assert_std_axioms "Anchor"
  LineDealingNatural.sorted_split_count
  LineDealingNatural.sorted_getElem?_count
  LineDealingNatural.anchor_between_honest_of_sorted_index
  LineDealingNatural.anchor_between_honest_of_sorted_ge
  LineDealingNatural.anchor_between_honest_of_sorted
  LineDealingNatural.anchor_between_honest_ge
  LineDealingNatural.anchor_between_honest
  LineDealingNatural.anchor_exists_ge
  LineDealingNatural.anchor_exists
  LineDealingNatural.anchor_between_honest_nodes_ge
  LineDealingNatural.anchor_between_honest_nodes_quorum
  LineDealingNatural.anchor_between_honest_nodes
  LineDealingNatural.anchor_fails_with_f_add_one_byzantine

#assert_std_axioms "Votes"
  LineDealingNatural.Votes.locked_unique_of_prevote_once
  LineDealingNatural.Votes.Step.prevotes_mono
  LineDealingNatural.Votes.Locked.mono
  LineDealingNatural.Votes.Step.nodeInv
  LineDealingNatural.Votes.Reachable.nodeInv
  LineDealingNatural.Votes.honest_prevotes_once
  LineDealingNatural.Votes.locked_unique
  LineDealingNatural.Votes.one_digest_per_slot
  LineDealingNatural.Votes.two_digests_without_rule4

#assert_std_axioms "Impossibility"
  LineDealingNatural.Impossibility.coalition_outputs_both
  LineDealingNatural.Impossibility.not_signsBoth_and_confines
  LineDealingNatural.Impossibility.erasure_does_not_bind
  LineDealingNatural.Impossibility.confines_imp_not_signsBoth
  LineDealingNatural.Impossibility.open_ecdsa_coalition_gets_key

#assert_std_axioms "Gaps"
  LineDealingNatural.dleq_complete
  LineDealingNatural.dleq_special_sound
  LineDealingNatural.dh_from_enc_proof
  LineDealingNatural.dh_comm
  LineDealingNatural.decryption_value_from_transcripts
  LineDealingNatural.rerand_mul_equation
  LineDealingNatural.rerand_mul_verifies
  LineDealingNatural.rerand_mul_partial_check


#assert_std_axioms "Split"
  LineDealingNatural.Split.D21_address_point
  LineDealingNatural.Split.D21_reconstruct
  LineDealingNatural.Split.C1_address_key_unique
  LineDealingNatural.Split.C4_schnorr_combine
  LineDealingNatural.Split.D24_ecdsa_split_sign
  LineDealingNatural.Split.D22_threshold_gate
  LineDealingNatural.Split.D43_line_gives_key
  LineDealingNatural.Split.D21_actor_part
  LineDealingNatural.Split.D21_reconstruct_point
  LineDealingNatural.Split.C2_rogue_key_without_pop
  LineDealingNatural.Split.C2_extraction
  LineDealingNatural.Split.C4_tweak_twice_fails
  LineDealingNatural.Split.D22_and_gate
  LineDealingNatural.Split.D22_or_gate
  LineDealingNatural.Split.D22_access_weighted_sum
  LineDealingNatural.Split.D22_access_weighted_point
  LineDealingNatural.Split.D22_address_key
  LineDealingNatural.Split.D22_reach_covers
  LineDealingNatural.Split.D22_covers_reach
  LineDealingNatural.Split.C17_threshold_secrecy
  LineDealingNatural.Split.C17_access_secrecy
  LineDealingNatural.Split.D22_user_or_G
  LineDealingNatural.Split.C17_user_or_G_coalition
  LineDealingNatural.Split.C12_one_digest_per_slot
  LineDealingNatural.Split.D43_two_subsets_reveal_line
  LineDealingNatural.Split.D43_bound_slot_refuses
  LineDealingNatural.Split.D43_one_full_request
  LineDealingNatural.Split.D43_without_binding_two_full
  LineDealingNatural.Split.D44_prec_first_namer
  LineDealingNatural.Split.D44_honest_vote_first_namer
  LineDealingNatural.Split.D44_one_request_per_slot
  LineDealingNatural.Split.D44_later_never_reserves
  LineDealingNatural.Split.D44_burn_persists
  LineDealingNatural.Split.D44_in_force_rule_takes_later
  LineDealingNatural.Split.C16_cold_start_no_reuse
  LineDealingNatural.Split.C16_without_burn_reuse
  LineDealingNatural.Split.D19_signing_profile_free
  LineDealingNatural.Split.D19_user_signs
  LineDealingNatural.Split.D19_P2_extends_P1
  LineDealingNatural.Split.D19_P2_signing_sets
  LineDealingNatural.Split.D19_P1_no_seizure
  LineDealingNatural.Split.D19_P2_guardians_seize
  LineDealingNatural.Split.C17_threshold_completions_equiv
  LineDealingNatural.Split.Gate.Covers.mono
  LineDealingNatural.Split.Gate.Dealt.congr
  LineDealingNatural.Split.zeroBasis_eval_zero
  LineDealingNatural.Split.zeroBasis_eval_of_mem
  LineDealingNatural.Split.zeroBasis_degree
  LineDealingNatural.Split.shift_eval_zero
  LineDealingNatural.Split.shift_eval_of_mem
  LineDealingNatural.Split.shift_degree_lt
  LineDealingNatural.Split.Precedence.inv_init
  LineDealingNatural.Split.Precedence.inv_step
  LineDealingNatural.Split.Precedence.inv_of_reachable
  LineDealingNatural.Split.Precedence.ordInv_step
  LineDealingNatural.Split.Precedence.ordInv_of_reachable
  LineDealingNatural.Split.Precedence.ord_inj
  LineDealingNatural.Split.reach_leaf
