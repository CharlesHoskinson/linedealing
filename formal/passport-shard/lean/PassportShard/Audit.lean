import SplitCodec.AuditCmd
import PassportShard.Spec
import PassportShard.Theorems
import PassportShard.Tests

/-!
# Audit

The build checks every pin.

* The namespace audit lists every `implemented_by`, `extern`, `csimp`,
  `unsafe`, `partial`, `partial_fixpoint`, `opaque` and `axiom` declaration of
  the namespace and of its modules. It is pinned at `[]`.
* `#print axioms` of each theorem, pinned. Only `propext`, `Classical.choice`
  and `Quot.sound` occur. The cryptographic hypotheses are rules of
  `Spec.lean`, not axioms.

`Main` does not import this module, so `import Lean` here does not change the
oracle binary.
-/

/-- info: [] -/
#guard_msgs in
#audit_ns PassportShard

/-- info: 'PassportShard.inv_reach' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.inv_reach

/-- info: 'PassportShard.inv2_reach' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.inv2_reach

/-- info: 'PassportShard.cfg_reach' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.cfg_reach

/-- info: 'PassportShard.via_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.via_sound

/-- info: 'PassportShard.root_needs_leaf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.root_needs_leaf

/-- info: 'PassportShard.no_signature_outside_access_structure' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.no_signature_outside_access_structure

/-- info: 'PassportShard.fully_corrupt_committee_cannot_forge' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.fully_corrupt_committee_cannot_forge

/-- info: 'PassportShard.no_signature_without_committee' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.no_signature_without_committee

/-- info: 'PassportShard.stolen_root_needs_user_approval' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.stolen_root_needs_user_approval

/-- info: 'PassportShard.committee_half_source' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.committee_half_source

/-- info: 'PassportShard.signature_needs_user_verification' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.signature_needs_user_verification

/-- info: 'PassportShard.signature_needs_user_verification_strict' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.signature_needs_user_verification_strict

/-- info: 'PassportShard.recovery_keeps_committee_half' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.recovery_keeps_committee_half

/-- info: 'PassportShard.recovery_gives_no_root' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.recovery_gives_no_root

/-- info: 'PassportShard.eReprovision_frame' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.eReprovision_frame

/-- info: 'PassportShard.hijack_needs_corrupt_origin' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.hijack_needs_corrupt_origin

/-- info: 'PassportShard.valid_cfg_no_overlap' depends on axioms: [propext] -/
#guard_msgs in
#print axioms PassportShard.valid_cfg_no_overlap

/-- info: 'PassportShard.assertion_binds_intent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.assertion_binds_intent

/-- info: 'PassportShard.authorize_needs_exact_assertion' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.authorize_needs_exact_assertion

/-- info: 'PassportShard.nf_authorizes_one_intent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.nf_authorizes_one_intent

/-- info: 'PassportShard.authorization_is_user_approved' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.authorization_is_user_approved

/-- info: 'PassportShard.apply_refused' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.apply_refused

/-- info: 'PassportShard.enroll_refuses_pending_successor' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.enroll_refuses_pending_successor

/-- info: 'PassportShard.pending_successor_fresh' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.pending_successor_fresh

/-- info: 'PassportShard.enrolled_never_adv_successor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms PassportShard.enrolled_never_adv_successor
