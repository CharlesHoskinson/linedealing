# Lean 4 proofs of the line-dealing algebra

This folder holds a Lean 4 (v4.35.0, Mathlib) development that proves the algebraic claims of `design/SCHEME.md` and the counting claims behind its board rules. All eight items of the lane prompt are proved, and so are the five items of loop item 5 (quorum intersection, the anchor rule, one digest per slot, claim 5 in abstract form, and the algebra behind two gaps of `design/PROOF-CHECK.md`). Four further modules prove the split-line design of `design/enhancement/DESIGN.md` and `DECISIONS.md`: the key split, access structures, the slot rules and the custody profiles (section 2, "Split-line dealing"). The sources contain no `sorry`, no `axiom` declaration and no `native_decide`. No theorem depends on an axiom other than `propext`, `Classical.choice` and `Quot.sound`. No theorem was weakened; section 4 lists the places where a statement differs in form from the prompt.

## 1. Model

- The scalar field is `ZMod q` with `[Fact q.Prime]`.
- The group `G` is any `AddCommGroup` with `Module (ZMod q) G`. It is not assumed cyclic and no elliptic curve is modelled.
- The generator `g : G` enters as a hypothesis `g ≠ 0`. `smul_eq_zero_of_ne_zero` derives `a • g = 0 → a = 0` from it, and `smul_left_inj'` derives `a • g = b • g → a = b`.
- Node ids are the elements of a `Finset (ZMod q)`, so they are distinct by construction. The prompt specifies distinct nonzero ids; the proofs do not need the nonzero part, so no theorem carries it.
- `lam s i` is the Lagrange coefficient at zero, `(Lagrange.basis s id i).eval 0`, from Mathlib.
- A Feldman commitment is an arbitrary family of points `C : ℕ → G`. `feldmanEval t C i = Σ_{u<t} i^u • C u` is `Eval(C_0, C, i)` of SCHEME 3.1, with `C 0` the implied constant term. `commit B p` is the honest commitment `u ↦ p.coeff u • B`.
- `ecdsaVerify g X R h r s` is `s ≠ 0 ∧ (h/s) • g + (r/s) • X = R`. `schnorrVerify g X R c s` is `s • g = R + c • X`.

Two lemmas in `LineDealing/Basic.lean` carry most of the development.

- `sum_lam_mul_eval`: for a polynomial `p` with `p.degree < #s`, `Σ_{i∈s} lam s i * p(i) = p(0)`.
- `sum_lam_smul_feldmanEval`: for any family of points `C`, `0 < t ≤ #s`, `Σ_{i∈s} lam s i • Eval(C, i) = C 0`. This is Lagrange interpolation in the exponent. It needs no discrete-log relation between the points, which is why the soundness theorems below make no assumption about the dealer.

`feldmanEval_commit` links the two: for an honest commitment, `feldmanEval t (commit B p) i = p(i) • B`.

## 2. Theorems

### Item 1, Lagrange linearity (`LineDealing/Ecdsa.lean`)

- `partial_combine`. For a set `s` of `t` ids and polynomials `w`, `μ` of degree below `t`, `Σ lam_i (h w_i + r μ_i) = h w(0) + r μ(0)`. Supports SCHEME 3.8 ("the combiner interpolates `t` partials") and ledger check T2d.

### Item 2, open ECDSA binding (`LineDealing/Ecdsa.lean`)

- `open_ecdsa_binding`. If `R = k • g`, `k ≠ 0`, `X = x • g`, `w0 • R = g` and `μ0 • R = X`, then `w0 = k⁻¹` and `μ0 = x k⁻¹`. Supports SCHEME 3.3 ("they hold exactly when `w(0) = k⁻¹` and `μ(0) = x·k⁻¹`").
- `open_ecdsa_equation`. With those two constant terms, `(h w0 + r μ0) • R = h • g + r • X` for every `h`. Supports claim 1 in SCHEME 6.2 for open ECDSA.
- `ecdsaVerify_iff`. For `s ≠ 0`, the verifier form `(h/s) • g + (r/s) • X = R` is equivalent to `s • R = h • g + r • X`.
- `open_ecdsa_verifies`. The combined scalar passes `ecdsaVerify` when it is nonzero. SCHEME 3.8 kills the generation when `s = 0`, so the hypothesis matches the scheme.

### Item 3, public partial check (`LineDealing/Ecdsa.lean`)

- `partial_check_sound`. `Cw`, `Cm` are arbitrary point families with `Cw 0 = g`, `Cm 0 = X`. If every released `σ i` (for `i` in a set of at least `t` ids) passes `σ i • R = h • W_i + r • M_i`, then `s = Σ lam_i σ_i` satisfies `s • R = h • g + r • X`. No share is assumed honest, no dealt polynomial is assumed to exist, and `R` is not assumed to be a multiple of `g`. Supports SCHEME 3.8 ("check by others") and 6.2.
- `partial_check_verifies`. The same in verifier form for `s ≠ 0`.
- `partial_check_complete`. Honest partials from honest commitments in base `R` pass the check (ledger check T2c).
- `open_schnorr_partial_sound` (`LineDealing/Bip340.lean`). The same soundness for the open Schnorr check `σ i • g = sg • (D_i + ρ • E'_i) + c • X_i`; the result is a Schnorr signature for the nonce point `sg • (D + ρ • E')`.

### Item 4, sealed binding (`LineDealing/Sealed.lean`)

- `sealed_schnorr_binding`. `p0 • g = R + c • X` implies `schnorrVerify g X R c p0`. This is the definition unfolded; the content is in the next theorems.
- `sealed_release_sound`. Shares that pass `σ i • B = Eval(F_0, C, i)` at `t` or more ids interpolate to `s` with `s • B = C 0`, for any point family `C`.
- `feldman_binds_constant`. If the shares of a degree-below-`t` polynomial `p` pass the check at `t` ids, then `p(0) • B = C 0`. Supports "Feldman commitments in base `B` fix a polynomial" in SCHEME 6.2.
- `sealed_schnorr_release`. With `C 0 = R + c • X` in base `g`, the interpolated scalar is a Schnorr signature.
- `sealed_ecdsa_binding`. If `p0 • R = h • g + r • X ≠ 0`, then `p0 ≠ 0` and `ecdsaVerify g X R h r p0`. The hypothesis `≠ 0` is Step A check 6 (`F_0 ≠ O`, ledger check T6).
- `sealed_ecdsa_release`. The share-level form in base `R`.
- `sealed_ecdsa_honest`. `(k⁻¹ (h + r x)) • (k • g) = h • g + r • (x • g)`, the remark "this equals `s·R`" in SCHEME 3.3.

### Item 5, nonce reuse (`LineDealing/NonceReuse.lean`)

- `ecdsa_nonce_reuse`. Two signatures with the same `R` and `r ≠ 0` on `h1 ≠ h2` have `s1 ≠ s2`, `k = (h1 − h2)/(s1 − s2)` and `x = (s1 k − h1)/r`. `s1 ≠ s2` is derived, not assumed. Supports SCHEME 6.6 ("two points determine the line, and the line is the key"), section 10 and ledger check T7a.
- `schnorr_one_nonce_reuse`. One-nonce contrast: `x = (s1 − s2)/(c1 − c2)` (T7c).
- Two-nonce Schnorr writes a signature on a slot as `s_j = a_j d + b_j e + c_j x`, with public `a_j = σ_j`, `b_j = σ_j ρ_j`, `c_j`, as in `checks.py` T7b.
  - `schnorr_two_sigs_family`. If `a1 b2 − a2 b1 ≠ 0`, then for every candidate key `x'` there is exactly one pair `(d', e')` consistent with both signatures. This is the one-parameter family.
  - `schnorr_two_sigs_not_determine`. For the real `(d, e, x)` there is a triple with `x' ≠ x` and the same two signatures.
  - `schnorr_two_sigs_no_extractor`. No function of the two signature scalars returns `x` for all `(d, e, x)`.
  - `schnorr_three_sigs_determine`. If the 3×3 determinant `det3` of the rows `(a_j, b_j, c_j)` is nonzero, `x` equals the Cramer quotient of public values. "Generic" means this determinant condition. `det3_eq_det` shows `det3` is `Matrix.det`.
  - `schnorr_three_sigs_unique`. Two explanations of the same three signatures have the same `x`.

  These support SCHEME 6.5 and ledger checks T7b and T7b2.

### Item 6, pad reuse (`LineDealing/Pad.lean`)

- `padReuseExtract` is the observer's computation of ledger check D1 as a definition over public values: `δ = Σ lam_i (ct_μ,i − ct_w,i)`, `w' = (sig − r δ)/(h + r)`, `x' = 1 + δ/w'`.
- `padDelta_shared_pad`. With one pad for both components, `δ = μ(0) − w(0)`.
- `pad_reuse_recovers_key`. With one pad, `t` nodes' ciphertexts, one signature `sig = h w(0) + r μ(0)` and `h + r ≠ 0`, `padReuseExtract` returns `x`. Supports the slot-label rule of SCHEME 3.1 and ledger check D1/T1a.
- Independent pads, in counting form:
  - `pad_bijective`. For any index set (node and component) and any shares `v`, `pad ↦ v + pad` is a bijection.
  - `pad_count_eq_one`. Every ciphertext vector arises from exactly one pad vector, for every `v`. Under uniform independent pads the ciphertext vector is therefore uniform with the same law for every `v`, which is independence from the shares.
  - `pad_pair_unique`. The same for one node's pair `(w_i, μ_i)`.
  - `pad_diff_count`. The difference `μ_i − w_i + (p'_i − p_i)` takes each value for exactly `q` of the `q²` pad pairs, for every `(w_i, μ_i)`.

  These support "the difference of two ciphertexts of one node reveals nothing" in SCHEME 10. The probability measure is not formalized; the step from the count to the distribution is the sentence above.

### Item 7, resharing (`LineDealing/Reshare.lean`)

- `reshare_constant`. If each dealer `i ∈ Q` (`#Q = t`) shares its own share `p(i)`, the combined polynomial `Σ lam_i g_i` has constant term `p(0)`.
- `resharePoly_eval`, `resharePoly_degree_lt`. New shares are `Σ lam_i g_i(j)`; the combined degree is below `t'`.
- `reshare_commit_constant`. Each dealer's constant-term commitment is forced to `Eval(C_old, i)`; then the combined constant-term commitment equals `C_old 0`. This holds for arbitrary point families and makes no assumption about what the dealers shared.
- `reshare_keeps_g_and_X`. For open ECDSA the new constant terms are `g` and `X` in base `R`.
- `feldmanEval_reshareCommit`, `reshare_share_check`. Sub-shares that pass each dealer's check combine to a share that passes the check of the combined commitment.
- `reshare_then_sign_sound`. Partials checked against the reshared commitments interpolate to `s` with `s • R = h • g + r • X`.

These support SCHEME section 5 ("the new constant terms equal the old ones") and ledger check T14.

### Item 8, BIP340 even-y (`LineDealing/Bip340.lean`)

- `bip340_negate`. With `R = k • g`, `X = x • g`, the scalar `−k + c x` satisfies `s • g = (−R) + c • X`.
- `schnorr_honest`. The unnegated case.
- `bip340_even_nonce`. `evenY` is an abstract predicate with `evenY (−P) ↔ ¬ evenY P` for `P ≠ 0`. For every `k ≠ 0` one of `k`, `−k` gives an even-y nonce point, and `k' + c x` verifies against it for every challenge `c`. Supports SCHEME 3.4 check 6 and ledger checks T5d and T8.

### Loop item 5.1, quorum intersection (`LineDealing/Quorum.lean`)

- `card_add_card_le_card_add_inter`. For `A, B ⊆ U`, `#A + #B ≤ #U + #(A ∩ B)`.
- `quorum_inter_card_general`. With `#U + f < 2k` and two sets of at least `k` nodes, the intersection has at least `f + 1` nodes.
- `exists_not_mem_of_card_lt`. A set of at least `f + 1` nodes has a node outside every set of at most `f` nodes.
- `quorum_inter_card`. With `#U ≤ 3f + 1`, two sets of at least `2f + 1` nodes share at least `f + 1` nodes.
- `quorum_inter_honest`. With at most `f` Byzantine nodes they share a node that is not Byzantine. `quorum_inter_honest_univ` is the same over a finite node type; `Votes.lean` uses it.
- `quorum_inter_fails_of_large`. For every `n ≥ 3f + 2` there are two sets of exactly `2f + 1` of the nodes `0, …, n − 1` whose intersection lies inside a set of exactly `f` nodes. With quorums of `2f + 1`, more than `3f + 1` nodes lose the honest overlap.
- `quorum_inter_fails_of_small`. For every `n ≤ 3f` there are two sets of exactly `n − f` nodes whose intersection lies inside a set of at most `f` nodes. `n − f` is the largest quorum that the honest nodes can fill alone, so with fewer than `3f + 1` nodes no quorum size gives both progress and an honest overlap.

These support the case `n = 3f + 1`, `q = 2f + 1` of SCHEME 2 and the lock certificate of 3.8. The theorems for `n ≥ 3f + 1` are listed under loop item 4b below.

### Loop item 5.2, anchor rule (`LineDealing/Anchor.lean`)

Reports are natural numbers. `H` is the multiset of honest reports and `B` the multiset of Byzantine reports, which are arbitrary.

- `sorted_split_count`, `sorted_getElem?_count`. In a list sorted highest first, entry `k` (from zero) has at least `k + 1` entries at or above it and at least `length − k` entries at or below it.
- `anchor_between_honest_of_sorted`. For any list `l` that is sorted highest first and is an arrangement of `H + B`, with `#H + #B = 2f + 1` and `#B ≤ f`: if `l[f] = a` then some honest report is at or below `a` and some honest report is at or above `a`.
- `anchor_between_honest`. The same for `l = (H + B).sort (· ≥ ·)`, Mathlib's sort. This is the rule of SCHEME 3.6: entry number `f + 1` lies between the lowest and the highest honest report.
- `anchor_exists`. The entry exists when there are `2f + 1` reports.
- `anchor_between_honest_nodes`. The node form: an OBS set `S` of `2f + 1` distinct nodes, a report function `h`, at most `f` Byzantine nodes in `S`; the conclusion names two honest nodes of `S`.
- `anchor_fails_with_f_add_one_byzantine`. With `f = 1` and two Byzantine reports among three (`9, 9` Byzantine, `5` honest), entry number `f + 1` is `9`, above every honest report.

These support "`f` Byzantine reports cannot move it outside the range of honest reports" in SCHEME 3.6. Finality of the block at `h*` is the chain's property and is not modelled.

### Loop item 5.3, one digest per slot (`LineDealing/Votes.lean`)

The model is a step relation for one slot `(rid, g)`. A state has a durable ledger entry per node (`Option D`), and the PREVOTE and PARTIAL posts of each node on the append-only board. `Locked f s d` says that `quorum n f` distinct nodes have a PREVOTE for `d`, where `n` is the number of nodes (`2f + 1` for `n = 3f + 1`; changed by loop item 4b). The steps are:

- `prevote`: an honest node with an empty ledger writes `d` and posts its PREVOTE (rule 1 of SCHEME 3.9);
- `signVoted`: an honest node posts a PARTIAL for a locked digest equal to its ledger entry (rules 2 and 3);
- `signLate`: an honest node that has not voted writes a locked digest and posts a PARTIAL (SCHEME 3.8);
- `restore`: any node loses its ledger entry, and the board keeps its posts;
- `byzPrevote`, `byzPartial`: a Byzantine node posts anything.

Rule 4 is the guard `Rule4Guard rule4 s i` on `prevote` and `signLate`: with `rule4` on, a node acts on an empty ledger only if the board shows no PREVOTE and no PARTIAL of its own. `rule4` is a parameter of the relation.

- `locked_unique_of_prevote_once`. Static core: if each honest node has at most one PREVOTE digest on the board, `#Byz ≤ f`, two locked digests are equal, for any number of nodes. It calls `quorum_inter_honest_univ_q`.
- `Step.prevotes_mono`, `Locked.mono`. The board grows, so a lock stays.
- `Step.nodeInv`, `Reachable.nodeInv`. With rule 4 on, every reachable state satisfies at every honest node: all its posts carry one digest, that digest is its ledger entry if it has one, and every digest it posted a PARTIAL for is locked.
- `honest_prevotes_once`. With rule 4 on, an honest node has at most one PREVOTE digest on the board in every reachable state. This is derived from the guards across restores; it is not a hypothesis.
- `locked_unique`. With rule 4 on and `#Byz ≤ f`, no two different digests are both locked.
- `one_digest_per_slot`. Under the same conditions the PARTIAL posts of honest nodes all carry one digest.
- `two_digests_without_rule4`. With rule 4 off the theorem fails. Four nodes, `f = 1`, node 3 Byzantine: nodes 0, 1, 3 prevote `false` and node 1 signs it; node 0 is restored and prevotes `true` with nodes 2 and 3, and node 2 signs it. The reachable state has both digests locked and an honest PARTIAL on each. The trace is built from the constructors of the same step relation; side conditions are closed by `decide`.

These support SCHEME 3.8 ("at most one PREVOTE per `(rid, g)`, ever"), the local rules of 3.9, and step 1 of claim 4 in 6.5. For open ECDSA, two honest partial sets on one slot would give the key (`ecdsa_nonce_reuse`), so `two_digests_without_rule4` is the reason for rule 4.

### Loop item 5.4, claim 5 (`LineDealing/Impossibility.lean`)

`Continuation σ Chain Sig` holds `step : σ → Chain → σ × Sig`: from the coalition's joint state and a chain state to the state kept after the step and a signature. `SignsBoth` says the step signs `m0` under `S0` and `m1` under `S1` from the state `st`. `Confines` says that no function `σ → Sig × Sig` outputs valid signatures on both from `st`. `runTwice` runs the step on a copy of the state for each chain state.

- `coalition_outputs_both`. One strategy, independent of the state and the messages, outputs both signatures from every state from which the protocol signs both.
- `not_signsBoth_and_confines`. No continuation both signs `m0` under `S0` and `m1` under `S1` and confines the coalition.
- `erasure_does_not_bind`. The same when the honest step erases everything (the state after a step is a constant).
- `confines_imp_not_signsBoth`. A confining protocol does not sign `m0` and `m1` under any pair of chain states.
- `open_ecdsa_coalition_gets_key`. For an open ECDSA slot the two outputs of `runTwice` on sighashes `h0 ≠ h1` under one `R` give `x` by the formula of `ecdsa_nonce_reuse`.

These support SCHEME 6.6. The abstract form is close to a definition unfolded, which is the point of the claim: the argument uses only that the continuation is a function of state the coalition holds.

### Loop item 5.5, algebra behind PROOF-CHECK section 8 (`LineDealing/Gaps.lean`)

Entries 3 and 4 of PROOF-CHECK section 8 have an algebraic core. Entries 1, 2 and 5 are reductions and text corrections and have none.

- Entry 3, the ephemeral-key proof of ePrint 2022/506 section 4.1 (`v = β • g`, `v' = β • g'`, `g' = H_G(ad, v)`). The statements were taken from the local text `research/sources/shoup-tecdsa.txt`, section 4.1 and the proof of Theorem 2 up to Game 4; the rest of the paper was not read for this item:
  - `dleq_complete`. The honest prover passes `dleqVerify` for every challenge.
  - `dleq_special_sound`. Two accepting transcripts with one commitment and `c1 ≠ c2` give `β = (z1 − z2)/(c1 − c2)` with `v = β • g` and `v' = β • g'`. No relation between `g` and `g'` is assumed.
  - `dh_from_enc_proof`. With `g' = ustar + λ • g` and `u = ustar + σ • g`, `β • u = v' + (σ − λ) • v`. This is the identity `w = v'·v^{σ−λ}` of the proof of Theorem 2 (Game 3).
  - `dh_comm`. `α • (β • g) = β • (α • g)`.
  - `decryption_value_from_transcripts`. From two accepting transcripts and `u = α • g = ustar + σ • g`, the decryption value `α • v` equals `v' + (σ − λ) • v`.
- Entry 4, multiplicative re-randomization `R = δ • R'`:
  - `rerand_mul_equation`. With `w0 • R' = g`, `μ0 • R' = X` and `δ ≠ 0`, `s = δ⁻¹ (h w0 + r μ0)` satisfies `s • R = h • g + r • X`.
  - `rerand_mul_verifies`. The verifier form for `s ≠ 0`.
  - `rerand_mul_partial_check`. A partial that passes the public check in base `R'` passes it in base `R` after scaling by `δ⁻¹`.

These are calculations. They do not close the gaps: entry 3 still needs the scheme to adopt the proof and the reduction to be written, and entry 4 still needs a Theorem 5 style bound.

### Loop item 4b, general committee sizes (`Quorum.lean`, `Anchor.lean`, `Votes.lean`)

SCHEME 2 now allows any `n ≥ 3f + 1` with the quorum `q = ⌈(n + f + 1)/2⌉`. The definition is `quorum n f := (n + f + 2) / 2`. The theorems for `2f + 1` keep their names and statements; the anchor theorems for `2f + 1` are now corollaries of the general ones.

`Quorum.lean`, new:

- `quorum_spec`. `n + f + 1 ≤ 2·quorum n f ≤ n + f + 2`, so `quorum n f` is the ceiling.
- `lt_two_mul_quorum`. `n + f < 2·quorum n f`, for every `n` and `f`.
- `quorum_le_of_lt_two_mul`. If `n + f < 2k` then `quorum n f ≤ k`: `q` is the least size with the intersection property.
- `quorum_three_mul_add_one`. `quorum (3f + 1) f = 2f + 1`.
- `quorum_add_le`. If `3f + 1 ≤ n` then `quorum n f + f ≤ n` (the honest nodes alone form a quorum).
- `two_mul_add_one_le_quorum`. If `3f + 1 ≤ n` then `2f + 1 ≤ quorum n f` (what the anchor rule needs).
- `quorum_inter_card_q`, `quorum_inter_honest_q`, `quorum_inter_honest_univ_q`. Among at most `n` nodes two sets of `quorum n f` nodes share `f + 1` nodes, hence a node outside any set of at most `f`. No bound on `n` is needed.
- `quorum_le_card_honest`. With `3f + 1 ≤ #U` and `#Byz ≤ f`, `quorum #U f ≤ #(U \ Byz)`.
- `quorum_honest_card`. With `3f + 1 ≤ n`, a set of `quorum n f` nodes has `f + 1` nodes outside `Byz`.
- `quorum_inter_fails_below`. For `f ≤ n` there are two sets of exactly `quorum n f − 1` nodes whose intersection lies inside a set of at most `f` nodes.

`Anchor.lean`, new:

- `anchor_between_honest_of_sorted_index`. With `#B ≤ f`, every index `k` with `f ≤ k` and `k + f < #H + #B` gives an entry between two honest reports. This is the statement "every entry number from `f + 1` to `q − f` works".
- `anchor_between_honest_of_sorted_ge`, `anchor_between_honest_ge`, `anchor_exists_ge`, `anchor_between_honest_nodes_ge`. The four anchor theorems with "at least `2f + 1` reports" in place of "exactly `2f + 1`".
- `anchor_between_honest_nodes_quorum`. With `3f + 1 ≤ n`, an OBS set of `quorum n f` nodes and at most `f` Byzantine nodes in it, entry `f + 1` exists and lies between the reports of two honest nodes of the set.

`Votes.lean`, changed: `Locked` counts `quorum (Fintype.card ι) f` votes. `locked_unique_of_prevote_once`, `locked_unique` and `one_digest_per_slot` no longer take the hypothesis `Fintype.card ι ≤ 3 * f + 1`; they hold for every number of nodes. `two_digests_without_rule4` is unchanged (`quorum 4 1 = 3`).

Build on 2026-11-13 with `heavy-run --mem 16G --name ld-lean -- lake build` in `formal/lean`: `Build completed successfully (9060 jobs).` `#print axioms` on the 18 new theorems and on the changed ones: `lt_two_mul_quorum`, `quorum_le_of_lt_two_mul`, `quorum_three_mul_add_one`, `quorum_add_le`, `two_mul_add_one_le_quorum`, `anchor_exists_ge` and `anchor_exists` read `[propext, Quot.sound]`; all others read `[propext, Classical.choice, Quot.sound]`. `grep -rnE "sorry|axiom|admit|native_decide" LineDealing LineDealing.lean` returns nothing. The library now has 103 theorems.

### Split-line dealing (`KeySplit.lean`, `Access.lean`, `Slots.lean`, `Profiles.lean`)

These modules prove the split-line design of `design/enhancement/DESIGN.md` and `design/enhancement/DECISIONS.md`. Every theorem is in the namespace `LineDealing.Split`, and its name starts with the claim (`C*`) or decision (`D*`) it supports. The model adds the following to section 1.

- An actor is an element of a type `ι`. The top-level shard of actor `a` is `x a : ZMod q`, the tweak is `tw`, and the address key is `x_f + tw + Σ_a x_a`.
- An access formula is an inductive `Gate q ι`: a leaf (one actor), `and2`, `or2`, and a threshold gate `thr ids k child` over a `Finset (ZMod q)` of member ids. `Dealt F s x` says that the leaf secrets `x` deal the secret `s` through `F`: an AND gate splits additively, an OR gate gives the same secret to both branches, and a threshold gate is a Shamir polynomial of degree below `k` with `s` at zero. `Reach F w A` says that the signing set `A` with weights `w : ι →₀ ZMod q` satisfies `F`. `Covers C F` says that a set `C` of leaves satisfies `F`. `WF F` says that no leaf occurs twice and no member id is zero.
- A slot of the ECDSA pool is modelled by its answers: which requests got a contribution from which committee member. `BoundRule` binds a slot to one leaf set, `OnceRule` lets a member answer one request per slot.
- Precedence (D44) is a step relation over a board of requests in board order. `n ≥ 3f + 1` nodes vote, and at most `f` of them are Byzantine. A slot is burned once a request in board order that named it has ended.
- A profile is `P0`, `P1` or `P2`. It chooses the access formula of the charter and nothing else.

| Theorem | Claim or decision | Statement |
|---|---|---|
| `D21_address_point` | D21, §3.1 | `X_f + tw • g + Σ_a X_a = (x_f + tw + Σ_a x_a) • g` |
| `D21_actor_part` | D21 | `Y_A = X − X_f = (tw + Σ_a x_a) • g` |
| `D21_reconstruct` | D21 | `t` Shamir shares of `x_f` with the tweak and the shards give the address key |
| `D21_reconstruct_point` | D21 | the same in the exponent from any Feldman commitment, with no honest dealer |
| `C1_address_key_unique` | C1 | one address point has one key |
| `C2_rogue_key_without_pop` | C2 (negative) | without proofs of possession the last actor to publish sets the address point to `z • g` for any `z` it picks |
| `C2_extraction` | C1, C2 | with the corrupt shards extracted, `x_f + Σ_Hon x_a = z − tw − Σ_Cor x_a` |
| `C4_schnorr_combine` | C4, C17, §4.3 | weighted leaf contributions, the tweak term once and the committee half verify as a Schnorr signature |
| `C4_tweak_twice_fails` | C4 (negative) | with the tweak term in two contributions the signature fails |
| `D24_ecdsa_split_sign` | D24, §3.6 | additive halves with `w_f + Σ w_p = k⁻¹` and `μ_f + Σ μ_p = k⁻¹ x` give `s • R = h • g + r • X` |
| `D22_and_gate`, `D22_or_gate`, `D22_threshold_gate` | D22, §2.4 | each gate reconstructs its secret from a satisfying set |
| `D22_access_weighted_sum`, `D22_access_weighted_point` | D22 | for any nesting, the weighted leaf secrets of a signing set sum to the secret, in scalars and in points |
| `D22_address_key` | D22, D21 | the committee half, the tweak and the weighted leaves give the address key |
| `D22_reach_covers`, `D22_covers_reach` | D22 | a set is a signing set exactly when it satisfies the formula |
| `C17_threshold_secrecy`, `C17_threshold_completions_equiv` | C17 | fewer than `k` shares of a threshold gate are consistent with every secret, with the same number of completions for each |
| `C17_access_secrecy` | C17 | for a well-formed formula, a coalition that does not satisfy it has leaf secrets consistent with every secret |
| `D22_user_or_G`, `C17_user_or_G_coalition` | D22, C17, §3.8 | `user OR G` gives the secret to the user and to any `k` guardians; a coalition without the user and with fewer than `k` guardians does not satisfy it, so `C17_access_secrecy` applies |
| `C12_one_digest_per_slot` | C12, D43 | one digest per slot, restated for the split board |
| `D43_two_subsets_reveal_line`, `D43_line_gives_key` | D43, §3.6 step 7 | two answered requests on one slot with different leaf sets reveal the line, and with every other half of the slot the line gives `x` |
| `D43_bound_slot_refuses`, `D43_one_full_request` | D43 | a slot bound to one leaf set refuses any other set; with leaf sets of size `k` and fewer than `k` Byzantine members, at most one request on the slot is fully answered |
| `D43_without_binding_two_full` | D43 (negative) | without the binding, two requests on one slot are fully answered |
| `Precedence.D44_prec_first_namer`, `Precedence.D44_honest_vote_first_namer` | D44, §4.1 | precedence goes to the first request in board order that names the slot, and an honest node votes only for it |
| `Precedence.D44_one_request_per_slot` | D44, C12 | at most one request per slot gets a quorum |
| `Precedence.D44_later_never_reserves`, `Precedence.D44_burn_persists` | D44 | a later request never reserves a named slot, and a burn stays |
| `Precedence.D44_in_force_rule_takes_later` | D44 (negative) | under the rule "earliest request in force wins" a later request takes the slot (4 nodes, `f = 1`) |
| `ColdStart.C16_cold_start_no_reuse` | C16, D46, §7.11 | after a cold start, every slot kept was claimed by no request up to the outage |
| `ColdStart.C16_without_burn_reuse` | C16, D46 (negative) | a cold start that keeps the slots of the last checkpoint reuses one |
| `D19_signing_profile_free` | D19 | in every profile every signing set verifies under the same address key, by one signing algebra that takes no profile |
| `D19_user_signs` | D19 | the user alone signs in every profile |
| `D19_P2_extends_P1`, `D19_P2_signing_sets` | D19 | `P2` adds the guardian branch and changes nothing else |
| `D19_P1_no_seizure`, `D19_P2_guardians_seize` | D19, §5.8 | nobody without the user covers a `P0` or `P1` charter; `k` guardians cover a `P2` charter |

The helpers `Gate.Covers.mono`, `Gate.Dealt.congr`, `zeroBasis_*`, `shift_*`, `Precedence.inv_*`, `Precedence.ordInv_*`, `Precedence.ord_inj` and `reach_leaf` carry the proofs. `SplitAxioms.lean` prints the axioms of all 58 declarations.

#### What the proofs show about the design

- **§3.6 step 7 and D43.** "Two evaluations give `w_γ`, `μ_γ`, and with the committee's halves `x`" needs every other half of the slot. The two evaluations give the line of the committee half. The key `x` follows only when the coalition also holds the halves of every other actor of the slot (`D43_line_gives_key`). In `user AND group` an honest user's halves stop the recovery of `x`, though the coalition still gets the group's half line. §4.4 states this correctly. Recovery of `μ_γ` needs `r ≠ 0`.
- **§2.4 and C17.** Secrecy holds for a formula with no repeated leaf and no zero member id (`WF`). §2.4 does not exclude a formula that names one leaf twice. `C17_access_secrecy` assumes both, and §2.4 should state them.
- **§4.1 and D44.** With the burn rule, "the earliest live request has precedence" is the same as "the first request in board order that names the slot, while it is live". Precedence never passes to a later request (`D44_prec_first_namer`, `D44_later_never_reserves`). The rule "the earliest request still in force wins" lets a later request take the slot (`D44_in_force_rule_takes_later`).
- **§7.11 item 2 and C16.** The first sentence says that E reshares "unused ECDSA slot shares". Without a verified board record E keeps no old ECDSA slot, because the cold start burns all of them. The theorem proves the rule of the second sentence.
- **D19.** `P0` is modelled by its access formula only (the user's leaf). A `P0` key has no committee half, so its signing algebra is the algebra of `SCHEME.md`, which the first twelve modules cover. `D19_signing_profile_free` still holds for `P0`, because it takes the committee half as a free scalar and covers the case without one.

## 3. What is not proved

- **The group.** No curve, no point encoding, no `x(R)`, no `lift_x`. `r` is a free scalar; the rule `r = x(R) mod q` and the check `r ≠ 0` at the verifier are not modelled. Low-s normalization and `yParity` (SCHEME 3.7) are not modelled. Parity is an abstract predicate.
- **Hashing.** Sighashes `h`, challenges `c`, the binding factor `ρ` and the pads are free scalars. Tagged hashes, injective encodings and the random oracle are not modelled.
- **Security.** Unforgeability of ECDSA, BIP340 or Ed25519, the [GS22] presignature result, the two-nonce Schnorr game, gap Diffie-Hellman, the simulations of claims 2 to 4 and claim 6, the ICDH reduction for share encryption, and liveness are outside this development. The theorems here are the "direct calculation" part of claim 1, the algebra behind the attacks in section 10, the counting behind quorums, anchors and the vote rules, and claim 5 in abstract form.
- **The board.** `Votes.lean` models one slot. Attempts, the board cut, NACKs, the expiry rule 5, generations and resharing are not modelled. Chain finality is not modelled, so `Anchor.lean` proves the range statement only. Signatures on board posts are not modelled: a post is attributed to its node by construction.
- **PROOF-CHECK internal point 1.** The count `2t + b < 3t` for a coalition of `b < t` nodes against two-nonce Schnorr is not proved as a rank statement.
- **Information-theoretic scope.** In this model `X = x • g` already determines `x`, and a Feldman evaluation determines the share. `schnorr_two_sigs_*` and the `pad_*` counting theorems are statements about signature scalars and ciphertext scalars alone. They do not say the full public view hides `x`; that needs the discrete-log assumption, which is not formalized.
- **Ed25519.** Suite 3 has a cofactor; the model is a prime-order module and does not cover it.
- **Split-line secrecy.** `C17_*` are statements about the scalars that a coalition holds. In this model the public points fix the secrets, so the theorems do not say the public view hides them. Proofs of possession, the DKG of the committee and the encryption of shards to actors are not modelled. The board of the precedence model has no expiry and no generations.

## 4. Differences in form from the prompt

- Item 2: verification in the verifier's own form needs `s ≠ 0`; the equation `s • R = h • g + r • X` is proved without it.
- Item 4: the literal statement is definitional for Schnorr, so the share-level theorems were added.
- Item 5: "generic" is the explicit condition `det3 ≠ 0`; "do not determine" is proved in three forms (unique family, second explanation, no extractor).
- Item 6: independence is in counting form, which the prompt allows.
- Nonzero ids are not assumed anywhere.
- Loop item 5.1: "`n < 3f + 1` fails" is read as: with `n ≤ 3f` nodes no quorum size works, because a quorum must fit in `n − f` nodes (`quorum_inter_fails_of_small`). With quorums fixed at `2f + 1` a smaller `n` only enlarges the overlap; what fails for that size is `n ≥ 3f + 2` (`quorum_inter_fails_of_large`). Both are proved. The positive theorems take `#U ≤ 3f + 1`, which includes `n = 3f + 1`.
- Loop item 5.2: the reports are two multisets, honest and Byzantine, and the sort is Mathlib's `Multiset.sort`; the list form holds for every sorted arrangement.
- Loop item 5.3: one slot is modelled. A restore resets the ledger entry to empty; for one slot this is every backup that differs from the current state. Rule 4 is a guard of the step relation and its effect (one PREVOTE digest per honest node) is a theorem.
- Loop item 5.4: the continuation is deterministic and its randomness is part of the state. `coalition_outputs_both` carries the claim: one strategy, fixed for every state and every pair of messages. `Confines` quantifies over all functions `σ → Sig × Sig`, constant functions included, so it is false whenever a valid pair of signatures exists at all; `not_signsBoth_and_confines` is therefore a weak form and is stated only to match the wording of the claim. `erasure_does_not_bind` carries its erasure hypothesis for the statement and the proof does not use it, because the strategy reads only the state before the step.

## 5. Build

Command, run in this folder:

```
heavy-run --mem 16G --name mpc-lean -- lake build
```

Output after deleting the `LineDealing` build products (dependency packages were already built and print nothing):

```
⚠ [9047/9060] Built LineDealing.Basic (3.9s)
warning: LineDealing/Basic.lean: imports `Mathlib` from package `mathlib`, which is designed for use with the module system; consider adding `module` to the start of this file
✔ [9048/9060] Built LineDealing.Ecdsa (3.7s)
✔ [9049/9060] Built LineDealing.Quorum (4.2s)
✔ [9050/9060] Built LineDealing.Reshare (3.6s)
✔ [9051/9060] Built LineDealing.Gaps (3.6s)
✔ [9052/9060] Built LineDealing.Pad (3.7s)
✔ [9053/9060] Built LineDealing.Sealed (4.0s)
✔ [9054/9060] Built LineDealing.NonceReuse (3.0s)
✔ [9055/9060] Built LineDealing.Anchor (3.6s)
✔ [9056/9060] Built LineDealing.Votes (5.3s)
✔ [9057/9060] Built LineDealing.Impossibility (4.2s)
✔ [9058/9060] Built LineDealing.Bip340 (4.3s)
✔ [9059/9060] Built LineDealing (3.3s)
Build completed successfully (9060 jobs).
```

The one warning is Lake's note about the module system. It does not concern a proof.

Toolchain: `Lean (version 4.35.0, aarch64-unknown-linux-gnu, commit eb6cafb7290e8bd5f2937522d8d804f58f02bafc, Release)`, `Lake version 5.0.0-src+eb6cafb`. Mathlib is the local path in `lakefile.toml`. The first build compiled some dependency modules (Batteries and ProofWidgets appeared in the output) into this folder's `.lake/packages`, which holds real directories and no symlinks. Mathlib's own build products were reused: no file under the Mathlib path's `.lake/packages` is newer than `PROMPT.md`.

Axiom check: `#print axioms` was run on all 48 theorems of the first seven modules. Every line reads `depends on axioms: [propext, Classical.choice, Quot.sound]`. It was run again on the 37 theorems of the five modules of loop item 5: 31 read `[propext, Classical.choice, Quot.sound]`; `sorted_split_count` and `anchor_exists` read `[propext, Quot.sound]`; `coalition_outputs_both`, `not_signsBoth_and_confines`, `erasure_does_not_bind` and `confines_imp_not_signsBoth` read `does not depend on any axioms`. `grep -rnE "sorry|axiom|admit|native_decide" LineDealing LineDealing.lean` returns nothing.

### Build with the split-line modules

Command: `heavy-run --mem 16G --name ld-lean-b2 -- lake build` in this folder. `LineDealing/SplitAxioms.lean` prints `#print axioms` for each of the 58 declarations of the four modules. The end of the output:

```
ℹ [9063/9065] Built LineDealing.SplitAxioms (3.0s)
info: LineDealing/SplitAxioms.lean:13:0: 'LineDealing.Split.D21_address_point' depends on axioms: [propext, Classical.choice, Quot.sound]
...
info: LineDealing/SplitAxioms.lean:70:0: 'LineDealing.Split.D19_P2_guardians_seize' depends on axioms: [propext, Classical.choice, Quot.sound]
✔ [9064/9065] Built LineDealing (2.5s)
Build completed successfully (9065 jobs).
```

All 58 lines read `depends on axioms: [propext, Classical.choice, Quot.sound]`. `grep -rnE "sorry|axiom|admit|native_decide"` on the four modules returns nothing. The library has 161 theorems.

## 6. Files

| File | Content |
|---|---|
| `LineDealing.lean` | imports the sixteen modules and the axiom check |
| `LineDealing/Basic.lean` | group lemmas, `lam`, the two Lagrange lemmas, `feldmanEval`, `commit` |
| `LineDealing/Ecdsa.lean` | items 1, 2, 3 |
| `LineDealing/Sealed.lean` | item 4 |
| `LineDealing/NonceReuse.lean` | item 5 |
| `LineDealing/Pad.lean` | item 6 |
| `LineDealing/Reshare.lean` | item 7 |
| `LineDealing/Bip340.lean` | item 8, open Schnorr partial check |
| `LineDealing/Quorum.lean` | loop item 5.1, quorum intersection and tightness |
| `LineDealing/Anchor.lean` | loop item 5.2, anchor rule |
| `LineDealing/Votes.lean` | loop item 5.3, slot step relation, one digest per slot, counterexample without rule 4 |
| `LineDealing/Impossibility.lean` | loop item 5.4, claim 5 |
| `LineDealing/Gaps.lean` | loop item 5.5, equal-exponent proof and multiplicative re-randomization |
| `LineDealing/KeySplit.lean` | split-line key split, Schnorr and ECDSA combine (C1, C2, C4, D21, D24) |
| `LineDealing/Access.lean` | access formulas, reconstruction and secrecy (D22, C17) |
| `LineDealing/Slots.lean` | ECDSA slot binding, precedence and cold start (C12, C16, D43, D44) |
| `LineDealing/Profiles.lean` | custody profiles P0, P1, P2 (D19) |
| `LineDealing/SplitAxioms.lean` | `#print axioms` for the 58 split-line declarations |
