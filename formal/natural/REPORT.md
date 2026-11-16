# Natural Lean port of the line-dealing proofs

This folder holds the port of `formal/lean/LineDealing/` to Natural Lean. The port covers all 161 theorems of the 16 native modules. 103 are the line-dealing theorems of the 12 modules `Basic` to `Gaps`. 58 are the split-line theorems of `KeySplit`, `Access`, `Slots` and `Profiles`, ported in one file, `LineDealingNatural/Split.lean`.

## 1. Result

| | fully natural | partly native | native only | total |
|---|---|---|---|---|
| Line dealing, first seven modules | 7 | 37 | 4 | 48 |
| Line dealing, `Quorum` to `Gaps` | 9 | 25 | 21 | 55 |
| Line dealing, all | 16 | 62 | 25 | 103 |
| Split-line dealing (`Split.lean`) | 4 | 9 | 45 | 58 |
| All | 20 | 71 | 70 | 161 |

- The build passes with the command of the task. Section 7 gives the complete output.
- `grep -rn sorry LineDealingNatural LineDealingNatural.lean` prints nothing.
- Every one of the 161 theorems depends only on `propext`, `Classical.choice` and `Quot.sound`. `LineDealingNatural/Axioms.lean` checks this in the build, and the build fails if a theorem uses another axiom.
- Each ported theorem has the name of its native counterpart in the namespace `LineDealingNatural`. Each one has a statement check against the native theorem in the same file.

## 2. Setting

The Mathlib setting is unchanged. Each file declares the same section variables as the native file: `{q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]`. A natural sentence writes the types as `ZMod(q)`, `G`, `Finset(ZMod(q))`, `Polynomial(ZMod(q))` and `Nat → G`. The natural theorems get the same section variables and the same instance arguments as the native ones.

The definitions stay native. Natural Lean can define a type, an operator, an adjective or a noun. It cannot define a function such as `lam`, `feldmanEval`, `commit`, `ecdsaVerify`, `schnorrVerify`, `det3`, `padDelta`, `padReuseExtract`, `resharePoly`, `reshareCommit` or `dleqVerify`. The natural files use the definitions of `formal/lean` directly.

### Changes to the project

- `lakefile.toml` has a second `[[lean_lib]]`, `name = "LineDealing"`, `srcDir = "../lean"`. Lake compiles the native sources into `formal/natural/.lake/build`. The natural files import them, so each check runs against the live source of truth and not against a copy. `lake-manifest.json` is unchanged (checked with `diff`).
- `import Mathlib` needs all of Batteries and ProofWidgets. The first build compiled the remaining modules of these two packages into `formal/natural/.lake/packages`. No Mathlib module was built. No file under the shared Mathlib path is newer than the start of this work (checked with `find -newer`).
- `lake update`, `lake clean` and other toolchains were not used. For the final build output, only `LineDealingNatural*` under `formal/natural/.lake/build` was deleted.

### The smoke file

`LineDealingNatural/Smoke.lean` failed with `unexpected token 'ℕ'; expected type`. The cause: Natural's `type` rule accepts an identifier. In Natural's examples `ℕ` is an identifier that the example declares. Mathlib declares `ℕ` as notation, so with Mathlib `ℕ` is a token. The fix: write the Lean name (`Nat`) or the natural name ("natural numbers a and b"). The file now holds both forms and builds.

### The prelude

`LineDealingNatural/Prelude.lean` is native Lean. It adds these forms to Natural's expression grammar, with the two extension points that Natural's own examples use (`syntax ... : expr` and `natural_elab`):

- `a - b`, `a / b`, `a⁻¹`, `a • P`
- `∑ i ∈ s, e`
- `#s` for the size of a finite set
- `f(a, b, c)` for a call with one or more arguments
- a repair for `⊆` (section 5, item 9)

It also defines the tactics `nl_same`, `nl_hyps` and `nl_apply` for the checks and for native proof steps.

## 3. Classes

- **Fully natural.** The statement and the proof are Natural Lean text. Each reason in the proof is the name of a theorem or a definition, or there is no reason. The text can use the expression forms of the prelude. Without the prelude almost no statement of this development parses, because Natural has no subtraction, inverse, scalar multiplication or sum.
- **Partly native.** The statement is Natural Lean text. The proof has native Lean in it. The table has two labels for this class. "proof natural with n native tactic steps" is a natural proof in which n steps have a Lean tactic as the reason (`by [tactic]`). "proof is one native tactic block" is `Proof. By [tactic].`
- **Native only.** Natural Lean cannot write the statement. The table has two labels. "statement and proof copied" is a native theorem with its proof in the natural file (5 theorems). "alias of the native theorem" is an `alias` of the theorem of `formal/lean` (20 theorems of line dealing, 45 of split-line dealing).

No natural proof uses its own native counterpart, and no natural step names a theorem of `formal/lean` as its reason. Three native blocks use a native-only theorem. The blocks of `anchor_between_honest_ge` and `anchor_between_honest` use the aliases `anchor_between_honest_of_sorted_ge` and `anchor_between_honest_of_sorted`. The block of `C17_threshold_secrecy` uses the native lemmas `LineDealing.Split.shift_degree_lt`, `shift_eval_zero` and `shift_eval_of_mem` and the definition `shift` by their native names.

## 4. Statement checks

Each natural theorem is followed by an `example` that compares its type with the type of the native theorem.

| Check | Count | Meaning |
|---|---|---|
| `rfl` | 5 | Native-only copies. The two types are the same term. |
| alias | 15 | The natural name is the native constant. |
| `Iff.rfl` | 17 | The two statements are definitionally equal. They differ only in names of bound variables and in which variables are implicit. |
| `nl_same` | 40 | The natural statement has one hypothesis `A and B and C`. The native statement has `A → B → C`. The order of the bound variables can differ. |
| hand-written `↔` | 8 | The natural statement is a restatement. The list is below. |

What `↔` shows: the two sides are proved theorems, so the equivalence alone is a weak fact. The evidence is in how each direction is closed. `nl_same` introduces the variables and hypotheses of one statement, applies the other statement, and closes each hypothesis with `assumption`. It uses no lemma and no automation. The hand-written checks do the same by hand.

The eight restatements:

| Theorem | Native form | Natural form | Reason |
|---|---|---|---|
| `sum_lam_mul_pow` | value `if u = 0 then 1 else 0` | two implications, `u = 0` and `u ≠ 0` | no conditional expression |
| `schnorr_two_sigs_family` | `∃! de : ZMod q × ZMod q` with `de.1`, `de.2` | two scalars `d`, `e`, and uniqueness in words | no `∃!`, no projections |
| `pad_pair_unique` | `∃! p : ZMod q × ZMod q` | two scalars `a`, `b`, and uniqueness in words | same |
| `padDelta_shared_pad` | two hypotheses `∀ i ∈ s` | one `for all i ∈ s, ... and ...` | a `for all` hypothesis runs to the end of the hypothesis list |
| `pad_reuse_recovers_key` | same | same | same |
| `reshare_keeps_g_and_X` | same | same | same |
| `reshare_then_sign_sound` | three hypotheses `∀` over two sets | `If ..., then if for all j ∈ S ..., then ...` | same |
| `Impossibility.not_signsBoth_and_confines` | `¬ (A ∧ B)` | `If A then B is false` | no negation of a compound proposition |

## 5. Theorem map

The line number is the line of the theorem in `LineDealingNatural/<Module>.lean`.

### Basic

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.smul_eq_zero_of_ne_zero` | `LineDealingNatural.smul_eq_zero_of_ne_zero` (19) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.smul_left_inj'` | `LineDealingNatural.smul_left_inj'` (34) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.sum_lam_mul_eval` | `LineDealingNatural.sum_lam_mul_eval` (50) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.sum_lam_mul_pow` | `LineDealingNatural.sum_lam_mul_pow` (64) | statement natural, proof is one native tactic block | equivalent (hand-written `↔`) |
| `LineDealing.sum_lam_smul_feldmanEval` | `LineDealingNatural.sum_lam_smul_feldmanEval` (94) | statement natural, proof natural with 4 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.feldmanEval_commit` | `LineDealingNatural.feldmanEval_commit` (114) | statement natural, proof is one native tactic block | regrouped hypotheses (`nl_same`) |

### Ecdsa

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.partial_combine` | `LineDealingNatural.partial_combine` (19) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.open_ecdsa_binding` | `LineDealingNatural.open_ecdsa_binding` (37) | statement natural, proof natural with 2 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.open_ecdsa_equation` | `LineDealingNatural.open_ecdsa_equation` (67) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.ecdsaVerify_iff` | `LineDealingNatural.ecdsaVerify_iff` (83) | statement natural, proof natural with 4 native tactic steps | definitionally equal (`Iff.rfl`) |
| `LineDealing.open_ecdsa_verifies` | `LineDealingNatural.open_ecdsa_verifies` (111) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.sum_lam_mul_smul` | `LineDealingNatural.sum_lam_mul_smul` (123) | statement natural, proof natural with 1 native tactic step | definitionally equal (`Iff.rfl`) |
| `LineDealing.partial_check_sound` | `LineDealingNatural.partial_check_sound` (134) | statement natural, proof natural with 3 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.partial_check_verifies` | `LineDealingNatural.partial_check_verifies` (162) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.partial_check_complete` | `LineDealingNatural.partial_check_complete` (177) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |

### Sealed

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.sealed_release_sound` | `LineDealingNatural.sealed_release_sound` (21) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.feldman_binds_constant` | `LineDealingNatural.feldman_binds_constant` (39) | statement natural, proof natural with 2 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.sealed_schnorr_binding` | `LineDealingNatural.sealed_schnorr_binding` (61) | fully natural | definitionally equal (`Iff.rfl`) |
| `LineDealing.sealed_schnorr_release` | `LineDealingNatural.sealed_schnorr_release` (70) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.sealed_ecdsa_binding` | `LineDealingNatural.sealed_ecdsa_binding` (85) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.sealed_ecdsa_release` | `LineDealingNatural.sealed_ecdsa_release` (98) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.sealed_ecdsa_honest` | `LineDealingNatural.sealed_ecdsa_honest` (114) | statement natural, proof natural with 2 native tactic steps | definitionally equal (`Iff.rfl`) |

### NonceReuse

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.ecdsa_nonce_reuse` | `LineDealingNatural.ecdsa_nonce_reuse` (19) | statement natural, proof natural with 2 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.schnorr_one_nonce_reuse` | `LineDealingNatural.schnorr_one_nonce_reuse` (56) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.schnorr_two_sigs_family` | `LineDealingNatural.schnorr_two_sigs_family` (68) | statement natural, proof is one native tactic block | equivalent (hand-written `↔`) |
| `LineDealing.schnorr_two_sigs_not_determine` | `LineDealingNatural.schnorr_two_sigs_not_determine` (104) | statement natural, proof natural with 3 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.schnorr_two_sigs_no_extractor` | `LineDealingNatural.schnorr_two_sigs_no_extractor` (126) | statement natural, proof natural with 3 native tactic steps | definitionally equal (`Iff.rfl`) |
| `LineDealing.det3_eq_det` | `LineDealingNatural.det3_eq_det` (153) | native only (statement and proof copied) | identical (`rfl`) |
| `LineDealing.schnorr_three_sigs_determine` | `LineDealingNatural.schnorr_three_sigs_determine` (161) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.schnorr_three_sigs_unique` | `LineDealingNatural.schnorr_three_sigs_unique` (185) | statement natural, proof natural with 2 native tactic steps | regrouped hypotheses (`nl_same`) |

### Pad

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.padDelta_shared_pad` | `LineDealingNatural.padDelta_shared_pad` (21) | statement natural, proof natural with 3 native tactic steps | equivalent (hand-written `↔`) |
| `LineDealing.pad_reuse_recovers_key` | `LineDealingNatural.pad_reuse_recovers_key` (51) | statement natural, proof natural with 5 native tactic steps | equivalent (hand-written `↔`) |
| `LineDealing.pad_bijective` | `LineDealingNatural.pad_bijective` (100) | native only (statement and proof copied) | identical (`rfl`) |
| `LineDealing.pad_count_eq_one` | `LineDealingNatural.pad_count_eq_one` (107) | native only (statement and proof copied) | identical (`rfl`) |
| `LineDealing.pad_pair_unique` | `LineDealingNatural.pad_pair_unique` (118) | statement natural, proof natural with 2 native tactic steps | equivalent (hand-written `↔`) |
| `LineDealing.pad_diff_count` | `LineDealingNatural.pad_diff_count` (144) | native only (statement and proof copied) | identical (`rfl`) |

### Reshare

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.resharePoly_eval` | `LineDealingNatural.resharePoly_eval` (21) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.reshare_constant` | `LineDealingNatural.reshare_constant` (31) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.resharePoly_degree_lt` | `LineDealingNatural.resharePoly_degree_lt` (49) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.reshare_commit_constant` | `LineDealingNatural.reshare_commit_constant` (63) | statement natural, proof natural with 2 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.reshare_keeps_g_and_X` | `LineDealingNatural.reshare_keeps_g_and_X` (80) | statement natural, proof natural with 2 native tactic steps | equivalent (hand-written `↔`) |
| `LineDealing.feldmanEval_reshareCommit` | `LineDealingNatural.feldmanEval_reshareCommit` (103) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.reshare_share_check` | `LineDealingNatural.reshare_share_check` (118) | statement natural, proof natural with 2 native tactic steps | definitionally equal (`Iff.rfl`) |
| `LineDealing.reshare_then_sign_sound` | `LineDealingNatural.reshare_then_sign_sound` (137) | statement natural, proof natural with 2 native tactic steps | equivalent (hand-written `↔`) |

### Bip340

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.bip340_negate` | `LineDealingNatural.bip340_negate` (19) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.schnorr_honest` | `LineDealingNatural.schnorr_honest` (34) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.bip340_even_nonce` | `LineDealingNatural.bip340_even_nonce` (49) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.open_schnorr_partial_sound` | `LineDealingNatural.open_schnorr_partial_sound` (74) | statement natural, proof natural with 3 native tactic steps | regrouped hypotheses (`nl_same`) |

### Quorum

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.card_add_card_le_card_add_inter` | `LineDealingNatural.card_add_card_le_card_add_inter` (18) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_inter_card_general` | `LineDealingNatural.quorum_inter_card_general` (29) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.exists_not_mem_of_card_lt` | `LineDealingNatural.exists_not_mem_of_card_lt` (41) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_spec` | `LineDealingNatural.quorum_spec` (58) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.lt_two_mul_quorum` | `LineDealingNatural.lt_two_mul_quorum` (66) | statement natural, proof natural with 1 native tactic step | definitionally equal (`Iff.rfl`) |
| `LineDealing.quorum_le_of_lt_two_mul` | `LineDealingNatural.quorum_le_of_lt_two_mul` (74) | statement natural, proof natural with 1 native tactic step | definitionally equal (`Iff.rfl`) |
| `LineDealing.quorum_three_mul_add_one` | `LineDealingNatural.quorum_three_mul_add_one` (83) | statement natural, proof natural with 2 native tactic steps | definitionally equal (`Iff.rfl`) |
| `LineDealing.quorum_add_le` | `LineDealingNatural.quorum_add_le` (93) | statement natural, proof natural with 1 native tactic step | definitionally equal (`Iff.rfl`) |
| `LineDealing.two_mul_add_one_le_quorum` | `LineDealingNatural.two_mul_add_one_le_quorum` (101) | statement natural, proof natural with 1 native tactic step | definitionally equal (`Iff.rfl`) |
| `LineDealing.quorum_inter_card_q` | `LineDealingNatural.quorum_inter_card_q` (110) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_inter_honest_q` | `LineDealingNatural.quorum_inter_honest_q` (123) | statement natural, proof natural with 2 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_inter_honest_univ_q` | `LineDealingNatural.quorum_inter_honest_univ_q` (141) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.quorum_le_card_honest` | `LineDealingNatural.quorum_le_card_honest` (144) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_honest_card` | `LineDealingNatural.quorum_honest_card` (156) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_inter_fails_below` | `LineDealingNatural.quorum_inter_fails_below` (168) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.quorum_inter_card` | `LineDealingNatural.quorum_inter_card` (193) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_inter_honest` | `LineDealingNatural.quorum_inter_honest` (205) | statement natural, proof natural with 2 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.quorum_inter_honest_univ` | `LineDealingNatural.quorum_inter_honest_univ` (223) | native only (statement and proof copied) | identical (`rfl`) |
| `LineDealing.quorum_inter_fails_of_large` | `LineDealingNatural.quorum_inter_fails_of_large` (232) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.quorum_inter_fails_of_small` | `LineDealingNatural.quorum_inter_fails_of_small` (253) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |

### Anchor

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.sorted_split_count` | `LineDealingNatural.sorted_split_count` (24) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.sorted_getElem?_count` | `LineDealingNatural.sorted_getElem?_count` (26) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.anchor_between_honest_of_sorted_index` | `LineDealingNatural.anchor_between_honest_of_sorted_index` (28) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.anchor_between_honest_of_sorted_ge` | `LineDealingNatural.anchor_between_honest_of_sorted_ge` (30) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.anchor_between_honest_ge` | `LineDealingNatural.anchor_between_honest_ge` (34) | statement natural, proof is one native tactic block | regrouped hypotheses (`nl_same`) |
| `LineDealing.anchor_exists_ge` | `LineDealingNatural.anchor_exists_ge` (48) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.anchor_between_honest_nodes_ge` | `LineDealingNatural.anchor_between_honest_nodes_ge` (90) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.anchor_between_honest_nodes_quorum` | `LineDealingNatural.anchor_between_honest_nodes_quorum` (92) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.anchor_between_honest_of_sorted` | `LineDealingNatural.anchor_between_honest_of_sorted` (32) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.anchor_between_honest` | `LineDealingNatural.anchor_between_honest` (60) | statement natural, proof is one native tactic block | regrouped hypotheses (`nl_same`) |
| `LineDealing.anchor_exists` | `LineDealingNatural.anchor_exists` (77) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.anchor_between_honest_nodes` | `LineDealingNatural.anchor_between_honest_nodes` (94) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.anchor_fails_with_f_add_one_byzantine` | `LineDealingNatural.anchor_fails_with_f_add_one_byzantine` (96) | native only (alias of the native theorem) | same constant (alias) |

### Votes

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.Votes.locked_unique_of_prevote_once` | `LineDealingNatural.Votes.locked_unique_of_prevote_once` (18) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.Step.prevotes_mono` | `LineDealingNatural.Votes.Step.prevotes_mono` (20) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.Locked.mono` | `LineDealingNatural.Votes.Locked.mono` (22) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.Step.nodeInv` | `LineDealingNatural.Votes.Step.nodeInv` (24) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.Reachable.nodeInv` | `LineDealingNatural.Votes.Reachable.nodeInv` (26) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.honest_prevotes_once` | `LineDealingNatural.Votes.honest_prevotes_once` (28) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.locked_unique` | `LineDealingNatural.Votes.locked_unique` (30) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.one_digest_per_slot` | `LineDealingNatural.Votes.one_digest_per_slot` (32) | native only (alias of the native theorem) | same constant (alias) |
| `LineDealing.Votes.two_digests_without_rule4` | `LineDealingNatural.Votes.two_digests_without_rule4` (34) | native only (alias of the native theorem) | same constant (alias) |

### Impossibility

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.Impossibility.coalition_outputs_both` | `LineDealingNatural.Impossibility.coalition_outputs_both` (23) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.Impossibility.not_signsBoth_and_confines` | `LineDealingNatural.Impossibility.not_signsBoth_and_confines` (35) | statement natural, proof is one native tactic block | equivalent (hand-written `↔`) |
| `LineDealing.Impossibility.erasure_does_not_bind` | `LineDealingNatural.Impossibility.erasure_does_not_bind` (51) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.Impossibility.confines_imp_not_signsBoth` | `LineDealingNatural.Impossibility.confines_imp_not_signsBoth` (66) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.Impossibility.open_ecdsa_coalition_gets_key` | `LineDealingNatural.Impossibility.open_ecdsa_coalition_gets_key` (85) | native only (alias of the native theorem) | same constant (alias) |

### Gaps

| formal/lean name | natural name (line) | class | statement check |
|---|---|---|---|
| `LineDealing.dleq_complete` | `LineDealingNatural.dleq_complete` (20) | statement natural, proof natural with 2 native tactic steps | definitionally equal (`Iff.rfl`) |
| `LineDealing.dleq_special_sound` | `LineDealingNatural.dleq_special_sound` (40) | statement natural, proof natural with 6 native tactic steps | regrouped hypotheses (`nl_same`) |
| `LineDealing.dh_from_enc_proof` | `LineDealingNatural.dh_from_enc_proof` (82) | statement natural, proof is one native tactic block | definitionally equal (`Iff.rfl`) |
| `LineDealing.dh_comm` | `LineDealingNatural.dh_comm` (92) | fully natural | definitionally equal (`Iff.rfl`) |
| `LineDealing.decryption_value_from_transcripts` | `LineDealingNatural.decryption_value_from_transcripts` (100) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.rerand_mul_equation` | `LineDealingNatural.rerand_mul_equation` (124) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |
| `LineDealing.rerand_mul_verifies` | `LineDealingNatural.rerand_mul_verifies` (140) | fully natural | regrouped hypotheses (`nl_same`) |
| `LineDealing.rerand_mul_partial_check` | `LineDealingNatural.rerand_mul_partial_check` (153) | statement natural, proof natural with 1 native tactic step | regrouped hypotheses (`nl_same`) |

### Split

`Split.lean` ports the four split-line modules. Eleven of the 13 natural statements are checked with `nl_same`. The check of `C4_schnorr_combine` is `Iff.rfl`. The check of `D43_two_subsets_reveal_line` is written out, because its two hypotheses of the shape `u = ∑ ...` defeat `nl_same` (section 6, item 23). The other 45 are aliases. Their statements use `Finsupp`, the inductive types and relations `Gate`, `Dealt`, `Reach`, `Covers` and `Step`, the structures `SlotAnswers` and `Precedence.State` with field access, `Function.update`, a `match`, an `if` expression, set images or an `Equiv` (items 4 to 6).

| formal/lean name (`LineDealing.Split.`) | class |
|---|---|
| `D21_address_point` | statement natural, proof is one native tactic block |
| `D21_actor_part` | statement natural, proof natural with 2 native tactic steps |
| `D21_reconstruct` | fully natural |
| `D21_reconstruct_point` | fully natural |
| `C1_address_key_unique` | fully natural |
| `C2_extraction` | statement natural, proof natural with 2 native tactic steps |
| `C4_schnorr_combine` | statement natural, proof is one native tactic block |
| `C4_tweak_twice_fails` | statement natural, proof is one native tactic block |
| `D24_ecdsa_split_sign` | statement natural, proof is one native tactic block |
| `D22_threshold_gate` | fully natural |
| `C17_threshold_secrecy` | statement natural, proof is one native tactic block |
| `D43_two_subsets_reveal_line` | statement natural, proof is one native tactic block |
| `D43_line_gives_key` | statement natural, proof natural with 1 native tactic step |
| `C2_rogue_key_without_pop`, `D22_and_gate`, `D22_or_gate`, `D22_access_weighted_sum`, `D22_access_weighted_point`, `D22_address_key`, `D22_reach_covers`, `D22_covers_reach`, `C17_threshold_completions_equiv`, `C17_access_secrecy`, `D22_user_or_G`, `C17_user_or_G_coalition`, `C12_one_digest_per_slot`, `D43_bound_slot_refuses`, `D43_one_full_request`, `D43_without_binding_two_full`, `Precedence.D44_*` (6), `ColdStart.C16_*` (2), `D19_*` (6) and the 15 lemmas `Gate.Covers.mono`, `Gate.Dealt.congr`, `zeroBasis_*` (3), `shift_*` (3), `Precedence.inv_*` (3), `Precedence.ordInv_*` (2), `Precedence.ord_inj`, `reach_leaf` | native only (alias of the native theorem) |

## 6. Natural Lean limitations found

All items are for natural_lean at `c9768172` with Lean 4.35.0 and this Mathlib.

Grammar:

1. **`ℕ` is not a type.** See section 2. The same holds for each name that Mathlib makes a notation.
2. **Small expression grammar.** There is no subtraction, division, inverse, scalar multiplication, sum, set size or call with two or more arguments. The prelude adds them.
3. **No type ascription.** `1 • g` elaborates with `1 : ℕ`. The proofs avoid a bare numeral next to `•`.
4. **No conditional expression, no `∃!`, no projections, no function literal, no list or matrix literal, no set given by a condition.** These cause the restatements of section 4 and most native-only theorems.
5. **No instance arguments.** A statement can bind variables and hypotheses only. `[Fintype ι]` cannot be written. The section variables of the file supply the instances of the setting.
6. **No structure, no inductive relation, no field access.** All of `Votes` is native only.
7. **No brackets around a proposition.** A `for all` or `there is` proposition runs to the end of the sentence part. The forms `P for all i ∈ s, and ...` and `P for some x ∈ H, and ...` give a quantifier that stops. A binder `i ∈ A ∩ B` does not parse, because the set must be a type name. Write `i : ι` and `i ∈ A ∩ B`.
8. **A predicate needs "is true".** `ecdsaVerify(g, X, R, h, r, s)` alone is not a proposition. Write `ecdsaVerify(g, X, R, h, r, s) is true`.

Clashes with Mathlib:

9. **`⊆` is wrong on `Finset`.** Natural builds core Lean's `«term_⊆_»` node, which means `HasSubset.Subset`. This Mathlib replaces the `⊆` notation, and `Finset` has no `HasSubset` instance. The statement elaborates to an error term. The prelude registers a node that elaborates as Mathlib's `⊆`.
10. **`C(` is a Mathlib token.** A variable `C` directly before a bracket does not parse. The commitment family is `K` in the natural text.
11. **`f(x)` fails for most functions.** Natural asks if the type of `f` is in `Mul`. The test throws for a function with implicit arguments (`lam`, `eval`, `card`) and for a local function whose type mentions `G`. In the prelude an identifier directly before a bracket is always a call. A product is `a · (b + c)`.
12. **Section variables are not visible to Natural's name resolution.** A sentence that names `q` or `G` only works with `set_option autoImplicit true` in the file. In the final theorem the names refer to the section variables.

Bugs at this revision:

13. **`i^u` and `i^0` panic.** The ASCII forms `^u` and `^0` are tokens of the superscript rule, and the translation looks them up in the Unicode table. Write `i ^ u` with spaces.
14. **`Let x. Assume P(x). Then Q.` drops `x`.** A `Let` variable that the conclusion does not mention is removed from the statement, and the assumption then has an undefined variable. The port writes every hypothesis inside the proposition: `If A and B then C`.
15. **`Let` scope closes early in a proof.** A block ends when the next steps do not mention its newest `Let` variable. A final sentence that does not mention it loses the hypotheses. Declare the variables of the conclusion last (`Quorum.lean`), and end each proof with the full conclusion.
16. **A chain as an assertion keeps only its end relation.** `Then 0 < t ≤ #s.` records `0 < #s`. Write `0 < t and t ≤ #s`.
17. **A proof that starts with `Assume` before a two-direction proof is read as part of it.** Start with `Let ... and suppose that ...` (`ecdsaVerify_iff`).

Automation:

18. **`by name` often does not find the instance.** The reason runs `apply`, `apply_rules`, `grind` and `aesop`. It fails when a hypothesis is a `for all` inside a conjunction, or when two hypotheses fit one argument. `nl_apply` replaces it in those steps.
19. **The default tactic does not find a witness** for a `there is` conclusion. Those steps have `by [exact ⟨...⟩]`.
20. **A timeout in the default tactic is not caught.** When `aesop` reaches the heartbeat limit, the step fails with a `simp` timeout and no goal. This occurred in `schnorr_two_sigs_no_extractor` and `schnorr_two_sigs_not_determine`.
21. **Rewriting under a sum, and field identities with an inverse, need a tactic.** These are most of the native tactic steps (`sum_congr`, `field_simp`, `module`, `linear_combination`).

22. **A reason cannot take one conjunct.** `by quorum_spec` does not prove `n + f + 1 ≤ 2 · quorum(n, f)` when `quorum_spec` concludes `A and B`. The step needs `by [exact (quorum_spec n f).1]`.

23. **`nl_same` and two hypotheses of one shape.** When two hypotheses have the shape `u = ∑ ...`, `nl_same` closes a hypothesis goal with the wrong one and fails. The check is written out.

## 7. Build

Command, run in `formal/natural`:

```
heavy-run --mem 16G --name mpc-natural -- lake build
```

Complete output after `LineDealingNatural*` was deleted from `.lake/build` (the dependency packages and the native `LineDealing` modules were built before and are replayed):

```
⚠ [7359/7639] Built LineDealingNatural.Smoke (1.9s)
warning: LineDealingNatural/Smoke.lean: imports `Mathlib.LinearAlgebra.Lagrange` from package `mathlib`, which is designed for use with the module system; consider adding `module` to the start of this file
warning: LineDealingNatural/Smoke.lean: imports `Mathlib.Data.ZMod.Basic` from package `mathlib`, which is designed for use with the module system; consider adding `module` to the start of this file
⚠ [9057/9084] Replayed LineDealing.Basic
warning: ../lean/LineDealing/Basic.lean: imports `Mathlib` from package `mathlib`, which is designed for use with the module system; consider adding `module` to the start of this file
⚠ [9069/9084] Built LineDealingNatural.Prelude (4.0s)
warning: LineDealingNatural/Prelude.lean: imports `Mathlib` from package `mathlib`, which is designed for use with the module system; consider adding `module` to the start of this file
✔ [9070/9084] Built LineDealingNatural.Anchor (3.4s)
✔ [9071/9084] Built LineDealingNatural.Basic (4.4s)
✔ [9072/9084] Built LineDealingNatural.Quorum (6.0s)
✔ [9073/9084] Built LineDealingNatural.Ecdsa (5.4s)
✔ [9074/9084] Built LineDealingNatural.Votes (4.7s)
✔ [9075/9084] Built LineDealingNatural.Gaps (5.5s)
✔ [9076/9084] Built LineDealingNatural.Sealed (5.7s)
✔ [9077/9084] Built LineDealingNatural.Reshare (5.7s)
✔ [9078/9084] Built LineDealingNatural.Pad (6.2s)
✔ [9079/9084] Built LineDealingNatural.NonceReuse (7.7s)
✔ [9080/9084] Built LineDealingNatural.Bip340 (4.7s)
✔ [9081/9084] Built LineDealingNatural.Impossibility (3.1s)
ℹ [9082/9084] Built LineDealingNatural.Axioms (2.9s)
info: LineDealingNatural/Axioms.lean:37:0: Basic: 6 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:45:0: Ecdsa: 9 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:56:0: Sealed: 7 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:65:0: NonceReuse: 8 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:75:0: Pad: 6 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:83:0: Reshare: 8 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:93:0: Bip340: 4 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:99:0: Quorum: 8 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:109:0: Anchor: 7 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:118:0: Votes: 9 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:129:0: Impossibility: 5 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:136:0: Gaps: 8 theorems, axioms used: [propext, Classical.choice, Quot.sound]
✔ [9083/9084] Built LineDealingNatural (4.9s)
Build completed successfully (9084 jobs).
exit code: 0
```

The warnings are Lake's note about the module system. They do not concern a proof.

Toolchain: `Lean (version 4.35.0, aarch64-unknown-linux-gnu, commit eb6cafb7290e8bd5f2937522d8d804f58f02bafc, Release)`, `Lake version 5.0.0-src+eb6cafb`. natural_lean is at `c9768172f244b36665563397d4acd170a8084816`.

### Rebuild for LOOP item 4b (2026-11-13)

The native `Quorum`, `Anchor` and `Votes` modules changed (`formal/lean/REPORT.md`, loop item 4b). The old theorems kept their statements, so their checks did not change. The 18 new theorems were added to `Quorum.lean` and `Anchor.lean` with statement checks and to `Axioms.lean`. `Votes.lean` holds aliases only, so it follows the native change (`Locked` counts `quorum n f` votes; three theorems lost the hypothesis on the number of nodes). `quorum(n, f)` in a natural statement is the native definition `LineDealing.quorum`. Statements with no hypothesis are written `Let n, f : Nat.  Then …`. The set difference in `quorum_le_card_honest` and `quorum_honest_card` is written as the call `SDiff.sdiff(U, Byz)`. Of the 18 new theorems 13 have a natural statement and 5 are aliases (`quorum_inter_honest_univ_q` and four anchor theorems with list or filter notation).

Command: `heavy-run --mem 16G --name ld-nat -- lake build` in `formal/natural`. Result: `Build completed successfully (9084 jobs).` The axiom lines that changed:

```
info: LineDealingNatural/Axioms.lean:99:0: Quorum: 20 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:121:0: Anchor: 13 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:136:0: Votes: 9 theorems, axioms used: [propext, Classical.choice, Quot.sound]
```

The output in the block above is the build of LOOP item 7 (85 theorems) and is kept as the record of that build.

### Build with the split-line port

Command: `heavy-run --mem 16G --name ld-nat-b5 -- lake build` in `formal/natural`. Lake compiles the four new native modules from `../lean` and the natural modules. The lines after the natural modules:

```
✔ [9086/9089] Built LineDealingNatural.Split (3.0s)
ℹ [9087/9089] Built LineDealingNatural.Axioms (3.3s)
info: LineDealingNatural/Axioms.lean:38:0: Basic: 6 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:46:0: Ecdsa: 9 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:57:0: Sealed: 7 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:66:0: NonceReuse: 8 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:76:0: Pad: 6 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:84:0: Reshare: 8 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:94:0: Bip340: 4 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:100:0: Quorum: 20 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:122:0: Anchor: 13 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:137:0: Votes: 9 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:148:0: Impossibility: 5 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:155:0: Gaps: 8 theorems, axioms used: [propext, Classical.choice, Quot.sound]
info: LineDealingNatural/Axioms.lean:166:0: Split: 58 theorems, axioms used: [propext, Classical.choice, Quot.sound]
✔ [9088/9089] Built LineDealingNatural (3.0s)
Build completed successfully (9089 jobs).
```

## 8. Files

| File | Content |
|---|---|
| `lakefile.toml` | adds the `LineDealing` library with `srcDir = "../lean"` |
| `LineDealingNatural.lean` | imports all modules |
| `LineDealingNatural/Smoke.lean` | the repaired smoke test |
| `LineDealingNatural/Prelude.lean` | grammar additions and check tactics (native) |
| `LineDealingNatural/<Module>.lean` | one file for each of the 12 line-dealing modules |
| `LineDealingNatural/Split.lean` | the four split-line modules |
| `LineDealingNatural/Axioms.lean` | the axiom check for all 161 theorems |

## 9. The native parts of the 103 line-dealing theorems

No proof of the 103 uses its own native counterpart. Of the 103, 16 are fully natural. The other 87 keep native Lean, for the reasons below. The item numbers refer to section 6.

Native only (25):

| Theorems | Reason |
|---|---|
| the 9 theorems of `Votes` | structure, inductive step relation and field access (item 6) |
| `sorted_split_count`, `sorted_getElem?_count`, `anchor_between_honest_of_sorted_index`, `anchor_between_honest_of_sorted_ge`, `anchor_between_honest_of_sorted`, `anchor_between_honest_nodes_ge`, `anchor_between_honest_nodes_quorum`, `anchor_between_honest_nodes`, `anchor_fails_with_f_add_one_byzantine` | list notation, counting with a function literal, a cast of a list to a multiset, a filter with a section (item 4) |
| `quorum_inter_honest_univ`, `quorum_inter_honest_univ_q` | instance argument `[Fintype ι]` and `Fintype.card ι` (item 5) |
| `det3_eq_det` | matrix literal (item 4) |
| `pad_bijective`, `pad_count_eq_one` | function literal, `Fintype` and `DecidableEq` instances, size of a set given by a condition (items 4, 5) |
| `pad_diff_count` | size of a set of pairs given by a condition (item 4) |
| `Impossibility.open_ecdsa_coalition_gets_key` | function literal as a predicate and `let` in the statement (item 4) |

Natural statement with native proof parts (62):

| Module | Theorem | Class | What the native part does |
|---|---|---|---|
| Basic | `smul_eq_zero_of_ne_zero` | natural, 1 native step | rewrite with several lemmas in one step (item 21) |
| Basic | `sum_lam_mul_eval` | one native block | interpolation through Mathlib's `Lagrange.eq_interpolate` with `conv` (item 21) |
| Basic | `sum_lam_mul_pow` | one native block | case split on the restated conditional value (item 4) |
| Basic | `sum_lam_smul_feldmanEval` | natural, 4 native steps | rewrite under a sum (item 21) |
| Basic | `feldmanEval_commit` | one native block | case split on the zero polynomial and a sum over coefficients (item 21) |
| Ecdsa | `partial_combine` | natural, 1 native step | rewrite under a sum (item 21) |
| Ecdsa | `open_ecdsa_binding` | natural, 2 native steps | rewrite with several lemmas in one step (item 21) |
| Ecdsa | `open_ecdsa_equation` | natural, 1 native step | rewrite with several lemmas in one step (item 21) |
| Ecdsa | `ecdsaVerify_iff` | natural, 4 native steps | rewrite with several lemmas in one step (item 21) |
| Ecdsa | `sum_lam_mul_smul` | natural, 1 native step | rewrite with several lemmas in one step (item 21) |
| Ecdsa | `partial_check_sound` | natural, 3 native steps | rewrite under a sum (item 21) |
| Ecdsa | `partial_check_complete` | natural, 1 native step | rewrite with several lemmas in one step (item 21) |
| Sealed | `sealed_release_sound` | natural, 1 native step | rewrite under a sum (item 21) |
| Sealed | `feldman_binds_constant` | natural, 2 native steps | rewrite under a sum (item 21) |
| Sealed | `sealed_schnorr_release` | natural, 1 native step | a `by name` reason does not find the instance (item 18) |
| Sealed | `sealed_ecdsa_release` | natural, 1 native step | a `by name` reason does not find the instance (item 18) |
| Sealed | `sealed_ecdsa_honest` | natural, 2 native steps | field or module identity (item 21) |
| NonceReuse | `ecdsa_nonce_reuse` | natural, 2 native steps | rewrite with several lemmas in one step (item 21) |
| NonceReuse | `schnorr_two_sigs_family` | one native block | witness and uniqueness for the `∃!` restatement (items 4, 19) |
| NonceReuse | `schnorr_two_sigs_not_determine` | natural, 3 native steps | witness for a `there is` step (item 19) |
| NonceReuse | `schnorr_two_sigs_no_extractor` | natural, 3 native steps | rewrite with several lemmas in one step (item 21) |
| NonceReuse | `schnorr_three_sigs_determine` | natural, 1 native step | field or module identity (item 21) |
| NonceReuse | `schnorr_three_sigs_unique` | natural, 2 native steps | a `by name` reason does not find the instance (item 18) |
| Pad | `padDelta_shared_pad` | natural, 3 native steps | rewrite under a sum (item 21) |
| Pad | `pad_reuse_recovers_key` | natural, 5 native steps | a `by name` reason does not find the instance (item 18); field or module identity (item 21) |
| Pad | `pad_pair_unique` | natural, 2 native steps | witness for a `there is` step (item 19) |
| Reshare | `resharePoly_eval` | one native block | unfolds the native definition `resharePoly` |
| Reshare | `reshare_constant` | natural, 1 native step | rewrite under a sum (item 21) |
| Reshare | `resharePoly_degree_lt` | one native block | degree bound of a sum of scaled polynomials; unfolds the native definition `resharePoly` |
| Reshare | `reshare_commit_constant` | natural, 2 native steps | rewrite under a sum (item 21) |
| Reshare | `reshare_keeps_g_and_X` | natural, 2 native steps | a `by name` reason does not find the instance (item 18) |
| Reshare | `feldmanEval_reshareCommit` | one native block | unfolds the native definition `reshareCommit` and exchanges two sums (item 21) |
| Reshare | `reshare_share_check` | natural, 2 native steps | rewrite under a sum (item 21) |
| Reshare | `reshare_then_sign_sound` | natural, 2 native steps | a `by name` reason does not find the instance (item 18) |
| Bip340 | `bip340_negate` | natural, 1 native step | rewrite with several lemmas in one step (item 21) |
| Bip340 | `schnorr_honest` | natural, 1 native step | rewrite with several lemmas in one step (item 21) |
| Bip340 | `open_schnorr_partial_sound` | natural, 3 native steps | rewrite under a sum (item 21); field or module identity (item 21) |
| Quorum | `quorum_spec` | one native block | unfolds the native definition `quorum` |
| Quorum | `lt_two_mul_quorum` | natural, 1 native step | one conjunct of a theorem (item 22) |
| Quorum | `quorum_le_of_lt_two_mul` | natural, 1 native step | one conjunct of a theorem (item 22) |
| Quorum | `quorum_three_mul_add_one` | natural, 2 native steps | one conjunct of a theorem (item 22) |
| Quorum | `quorum_add_le` | natural, 1 native step | one conjunct of a theorem (item 22) |
| Quorum | `two_mul_add_one_le_quorum` | natural, 1 native step | one conjunct of a theorem (item 22) |
| Quorum | `quorum_inter_card_q` | natural, 1 native step | a `by name` reason does not find the instance (item 18) |
| Quorum | `quorum_inter_honest_q` | natural, 2 native steps | a `by name` reason does not find the instance (item 18) |
| Quorum | `quorum_inter_fails_below` | one native block | explicit witness sets `range` and `Ico` (item 19) |
| Quorum | `quorum_inter_card` | natural, 1 native step | a `by name` reason does not find the instance (item 18) |
| Quorum | `quorum_inter_honest` | natural, 2 native steps | a `by name` reason does not find the instance (item 18) |
| Quorum | `quorum_inter_fails_of_large` | one native block | explicit witness sets `range` and `Ico` (item 19) |
| Quorum | `quorum_inter_fails_of_small` | one native block | explicit witness sets `range` and `Ico` (item 19) |
| Anchor | `anchor_between_honest_ge` | one native block | list and multiset lemmas on `Multiset.sort` (item 4) |
| Anchor | `anchor_exists_ge` | one native block | index into a sorted list with a length proof (item 4) |
| Anchor | `anchor_between_honest` | one native block | list and multiset lemmas on `Multiset.sort` (item 4) |
| Anchor | `anchor_exists` | one native block | index into a sorted list with a length proof (item 4) |
| Gaps | `dleq_complete` | natural, 2 native steps | rewrite with several lemmas in one step (item 21) |
| Gaps | `dleq_special_sound` | natural, 6 native steps | field or module identity (item 21) |
| Gaps | `dh_from_enc_proof` | one native block | module identity (`module`, item 21) |
| Gaps | `decryption_value_from_transcripts` | natural, 1 native step | a `by name` reason does not find the instance (item 18) |
| Gaps | `rerand_mul_equation` | natural, 1 native step | field or module identity (item 21) |
| Gaps | `rerand_mul_partial_check` | natural, 1 native step | field or module identity (item 21) |
| Impossibility | `coalition_outputs_both` | one native block | function-valued witness `runTwice P S0 S1` (item 19) |
| Impossibility | `not_signsBoth_and_confines` | one native block | applies a hypothesis to a function-valued witness (item 19) |
