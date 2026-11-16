VERDICT: changes_requested

1. **BLOCKING — Theorem B’s explicit error bound is too small.**  
   **Location:** §4.2, [PROOFS.md:235](design/proofs-review/bundle/PROOFS.md:235), especially lines 238, 248–251.  
   **Claim:** The simulation loses at most `δ_B`.

   **Reason:** Two probability calculations omit events:
   - `Sign` can invoke `H_b` internally, but the `Pre` bound counts only `Q_b`. With no adversarial `H_b` queries, an internally generated nonce can still hit a previously queried signature-hash input; line 248 assigns this event probability zero.
   - In suite 2, normalization identifies `R` and `−R`. A simulated `PlainSign` nonce hits any particular nonidentity even-y representative with probability `2/q`, not `1/q`. For example, prequerying `K` distinct nonce inputs for one message and then requesting `PlainSign(m)` gives programming-abort probability `2K/q`. With `U = Q_b = Q_pr = Q_auth = Q_dg = 0` and `Q_ps = 1`, the entire stated `δ_B` is only `(K + 2)/q`.

   These invalidate the stated simulation-loss calculation, although they do not refute the underlying two-nonce security approach.

   **Suggested fix:** Recalculate `δ_B` using total internal and external oracle evaluations and the two-to-one BIP340 normalization. Propagate the corrected bound to B′ and E(a).

2. **BLOCKING — The outer reductions omit valid copies with unchanged ciphertexts and altered proofs.**  
   **Location:** §1.1, [PROOFS.md:26](design/proofs-review/bundle/PROOFS.md:26); Theorem C, lines 110 and 129; Theorem A, line 179; B′, line 296; D, lines 315–316.  
   **Claim:** Every non-owner-written message can be decrypted normally because its shares were supplied by the adversary; authorization is therefore unnecessary for these reductions.

   **Reason:** Consider `M′` with an honest message’s exact `(hdr, deal, ct)` but a different valid `π`. Theorem C’s `Reuse` event excludes this case because `(hd, ct)` is unchanged. Its ideal experiment must use the original dealt shares. However, A, B′ and D classify the byte-distinct message as adversarial and decrypt its randomized ciphertexts normally. That produces unrelated scalars instead of the original shares.

   Excluding such a valid `π` requires an authorization argument. It cannot simply be assumed while claiming independence from claim 6. Under the written definition, releases through `M′` also add nothing to `Auth`, so treating the copy as honest requires changing the security experiment.

   **Suggested fix:** Either define owner-authored dealings and authorization modulo proof-only changes, or stop at the first such proof forgery and supply an explicit reduction and loss. For D, explain whether that repair requires the stronger assumption used by E(c).

3. **BLOCKING — The ciphertext-hash fix relies on an unstated SHA-256 assumption.**  
   **Location:** §1.2, [PROOFS.md:37](design/proofs-review/bundle/PROOFS.md:37); Theorem C, lines 113–119; Theorem E, line 352.  
   **Claim:** Collisions involving `SHA-256(ct)` cost at most `Q_H²/2^256`.

   **Reason:** The assumptions idealize the **labelled** hashes and specified suite challenges. They do not idealize unlabelled `SHA-256(ct)` or assume its collision resistance. A birthday bound does not follow merely from its output length. This assumption is essential: a distinct canonical `ct′` with the same hash preserves both proof challenges and the hash-to-curve input, defeating the claimed binding of the ciphertexts.

   **Suggested fix:** Explicitly model this hash as a random oracle, or replace its birthday-bound contribution with a concrete collision-resistance advantage. Apply the correction throughout C and E and their dependent theorems.

4. **BLOCKING — B′ does not justify the transition from uniform TNS keys to clamped Ed25519 keys.**  
   **Location:** TNS key generation, [PROOFS.md:219](design/proofs-review/bundle/PROOFS.md:219); B′, lines 285–298; [SCHEME.md:129](design/proofs-review/bundle/SCHEME.md:129).  
   **Claim:** The uniform-key TNS theorem directly bounds suite 3.

   **Reason:** TNS samples `x` uniformly from `Z_q*`. The scheme instead specifies the clamped Ed25519 scalar. Clamping leaves 251 free bits, producing scalars of the form `2^254 + 8u`, with `0 ≤ u < 2^251`, before reduction modulo the subgroup order. This is not uniform over `Z_q*`; its support occupies approximately half that space. The pruning operation is specified in [RFC 8032 §5.1.5](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5).

   **Suggested fix:** State and prove a key-distribution reduction. Under an idealized uniform seed-hash output, a density argument can introduce approximately a factor-two loss. Alternatively, explicitly restrict B′ to uniformly generated scalar keys. Account separately for the seed-hash assumption.

5. **BLOCKING — Theorem A’s rejection sampling exceeds its stated query budget without a corresponding loss.**  
   **Location:** §3.2, [PROOFS.md:175](design/proofs-review/bundle/PROOFS.md:175), and lines 161–163, 185.  
   **Claim:** The reduction makes at most `3S + 2Q_w` presignature/signing requests, with retries covered by `δ_A`.

   **Reason:** Figure 4 of the frozen 2021/1330 paper, printed p. 22, rejects zero reduced conversion values; it does not impose the scheme’s additional `x(R) < q` restriction. The reduction therefore closes and retries points with `x(R) ≥ q`.

   Already with `S = 1`, one such rejection followed by signing the replacement consumes four requests: rejected presignature, closing signature, replacement presignature, actual signature. The stated budget is three. The relevant rejection probability is
   `|{R ∈ E*: x(R) ≥ q}|/(q−1)`;
   no bound for this event appears in `δ_A`. The paper’s Theorem 3 requires an adversary making **at most** `N` queries, not merely an expected query count.

   **Suggested fix:** Cap retries and include the resulting abort probability, or increase the query budget and prove a tail bound. Include all closing requests in the fresh-message accounting.

6. **BLOCKING — E(c) omits the extracted-signature collision loss acknowledged by its proof.**  
   **Location:** §6.1, [PROOFS.md:346](design/proofs-review/bundle/PROOFS.md:346), and line 358.  
   **Claim:** The fork-success expression directly lower-bounds SUF-CMA advantage.

   **Reason:** Extraction gives the signature associated with the selected sealed nonce. It is a strong forgery only if it is not equivalent to a signing-oracle answer. Line 358 explicitly excludes a nonce-collision event of probability `Q/q`, but the theorem subtracts no such term. For ECDSA strong unforgeability **up to sign**, excluding only the exact point `R` is also insufficient: `−R` must be included in the equivalence check.

   **Suggested fix:** Define the relevant signing-query count across both continuations, bound the collision event under the specified signing algorithm, and subtract it in the final advantage inequality.

7. **NON-BLOCKING — The central forking and symbolic arguments survive this review within their stated scope.**  
   **Location:** Lemma 4, [PROOFS.md:73](design/proofs-review/bundle/PROOFS.md:73); Theorem B, lines 260–277; Lemma 5, lines 362–370.  
   **Claim:** Fresh-continuation forking supports the two-nonce extraction; Lemma 5 bounds authorship proofs beside the ECDSA presignature oracle.

   **Reason:** I found no blocking defect in these core arguments. In B, a successful forgery excludes signing the pair at the fork, preserving the two-equation-per-slot accounting outside the stated binding-factor collision event. In Lemma 5, the commitment polynomial is fixed before `c`; the last necessary substitution has a fresh uniform `s_k`, leaving at most one satisfying inverse value. This matches Figure 5, printed p. 23, and the independence argument in Appendix B, printed pp. 42–45, of the frozen 2021/1330 paper.

   **Suggested fix:** Retain these arguments, correct B’s surrounding probability accounting, and distinguish standalone Lemma 5 from the protocol-level simulation issues above.

8. **NON-BLOCKING — The principal paper citations and the associated-data construction are accurately identified.**  
   **Location:** §§2.1–2.3 and 3.1–3.4, [PROOFS.md:89](design/proofs-review/bundle/PROOFS.md:89).  
   **Claim:** The ECDSA reductions invoke the appropriate published results, and C adapts the MEGa game sequence rather than using it unchanged.

   **Reason:** The frozen 2021/1330 Theorem 3, printed p. 24, contains all four stated hash-property terms, `U·N`, and the stated reduction-time overhead. Figure 4 and printed p. 21 impose one signing request per presignature; printed p. 26 confirms the raw-hash limitation and strong unforgeability up to sign. Theorem 4, printed p. 27, matches the quoted derived-key bound.

   The frozen 2022/506 paper imposes the associated-data restriction on printed p. 27, gives the ephemeral-key construction on p. 28, and presents the cited game sequence on pp. 29–31. Its p. 32 note 1 supports omitting associated data from the original construction’s pad hash. Binding `SHA-256(ct)` inside `HG_eph` addresses the identified ciphertext-modification problem, subject to finding 3.

   **Suggested fix:** Preserve these citations and construction choices. They do not resolve the missing assumptions, simulation cases, and quantitative losses above.