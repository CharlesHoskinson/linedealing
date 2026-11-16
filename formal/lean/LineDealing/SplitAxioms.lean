import LineDealing.KeySplit
import LineDealing.Access
import LineDealing.Slots
import LineDealing.Profiles

/-!
# Axiom report for the split-line theorems

`#print axioms` for every declaration of `KeySplit`, `Access`, `Slots` and `Profiles`. The build
prints one line per declaration.
-/

#print axioms LineDealing.Split.D21_address_point
#print axioms LineDealing.Split.D21_actor_part
#print axioms LineDealing.Split.D21_reconstruct
#print axioms LineDealing.Split.D21_reconstruct_point
#print axioms LineDealing.Split.C1_address_key_unique
#print axioms LineDealing.Split.C2_rogue_key_without_pop
#print axioms LineDealing.Split.C2_extraction
#print axioms LineDealing.Split.C4_schnorr_combine
#print axioms LineDealing.Split.C4_tweak_twice_fails
#print axioms LineDealing.Split.D24_ecdsa_split_sign
#print axioms LineDealing.Split.Gate.Covers.mono
#print axioms LineDealing.Split.Gate.Dealt.congr
#print axioms LineDealing.Split.D22_and_gate
#print axioms LineDealing.Split.D22_threshold_gate
#print axioms LineDealing.Split.D22_or_gate
#print axioms LineDealing.Split.D22_access_weighted_sum
#print axioms LineDealing.Split.D22_access_weighted_point
#print axioms LineDealing.Split.D22_address_key
#print axioms LineDealing.Split.D22_reach_covers
#print axioms LineDealing.Split.D22_covers_reach
#print axioms LineDealing.Split.zeroBasis_eval_zero
#print axioms LineDealing.Split.zeroBasis_eval_of_mem
#print axioms LineDealing.Split.zeroBasis_degree
#print axioms LineDealing.Split.shift_eval_zero
#print axioms LineDealing.Split.shift_eval_of_mem
#print axioms LineDealing.Split.shift_degree_lt
#print axioms LineDealing.Split.C17_threshold_secrecy
#print axioms LineDealing.Split.C17_threshold_completions_equiv
#print axioms LineDealing.Split.C17_access_secrecy
#print axioms LineDealing.Split.D22_user_or_G
#print axioms LineDealing.Split.C17_user_or_G_coalition
#print axioms LineDealing.Split.C12_one_digest_per_slot
#print axioms LineDealing.Split.D43_two_subsets_reveal_line
#print axioms LineDealing.Split.D43_line_gives_key
#print axioms LineDealing.Split.D43_bound_slot_refuses
#print axioms LineDealing.Split.D43_one_full_request
#print axioms LineDealing.Split.D43_without_binding_two_full
#print axioms LineDealing.Split.Precedence.inv_init
#print axioms LineDealing.Split.Precedence.D44_prec_first_namer
#print axioms LineDealing.Split.Precedence.inv_step
#print axioms LineDealing.Split.Precedence.inv_of_reachable
#print axioms LineDealing.Split.Precedence.D44_honest_vote_first_namer
#print axioms LineDealing.Split.Precedence.ordInv_step
#print axioms LineDealing.Split.Precedence.ordInv_of_reachable
#print axioms LineDealing.Split.Precedence.ord_inj
#print axioms LineDealing.Split.Precedence.D44_one_request_per_slot
#print axioms LineDealing.Split.Precedence.D44_later_never_reserves
#print axioms LineDealing.Split.Precedence.D44_burn_persists
#print axioms LineDealing.Split.Precedence.D44_in_force_rule_takes_later
#print axioms LineDealing.Split.ColdStart.C16_cold_start_no_reuse
#print axioms LineDealing.Split.ColdStart.C16_without_burn_reuse
#print axioms LineDealing.Split.D19_signing_profile_free
#print axioms LineDealing.Split.D19_user_signs
#print axioms LineDealing.Split.D19_P2_extends_P1
#print axioms LineDealing.Split.reach_leaf
#print axioms LineDealing.Split.D19_P2_signing_sets
#print axioms LineDealing.Split.D19_P1_no_seizure
#print axioms LineDealing.Split.D19_P2_guardians_seize
